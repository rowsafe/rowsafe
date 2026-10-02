package mysql

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The index advisor for MySQL (protocol.TaskIndexAdvisor): the busiest
// statement digests that read far more rows than they return, turned into
// index ideas (advisorshape.go), each tested on a private copy restored
// from the latest backup, like Proof: EXPLAIN the statement's sample
// (performance_schema keeps one real run of each digest, with its values),
// CREATE INDEX on the copy, EXPLAIN again, and time plain SELECTs before and
// after. Only indexes the optimizer then uses and that make a statement at
// least twice as fast are recommended. The samples are only read on this
// server and run on the copy; they never leave it. Production is only read.
//
// MariaDB and MySQL 5.7 keep no sample of a digest's values: there the
// samples come from the slow query log, read on this server
// (slowsamples.go), never sent.

const (
	ixTopDigests    = 200
	ixMaxIdeas      = 12
	ixMinExamined   = 1000 // rows read per call
	ixMinRatio      = 10.0 // rows read per row returned
	ixMinSpeedup    = 2.0
	ixQueryTimeout  = 10 * time.Second
	ixBuildTimeout  = 30 * time.Minute
	ixCopyStartTime = 15 * time.Minute
)

// ixStatement is a digest with its sample.
type ixStatement struct {
	id, digest, sample, schema string
	calls                      int64
	totalMs                    float64
	shape                      stmtShape
}

// ixIdea is an index to test and the statements it is for.
type ixIdea struct {
	spec  protocol.IndexSpec
	key   string
	stmts []*ixStatement
}

func (s *server) indexAdvisor(ctx context.Context, taskID string, p protocol.IndexAdvisorParams, log agent.TaskLogger) (*protocol.IndexAdvisorResult, error) {
	start := time.Now()
	res := &protocol.IndexAdvisorResult{Generated: []string{}, Recommendations: []protocol.IndexRecommendation{}}
	done := func() (*protocol.IndexAdvisorResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		if res.Summary == "" {
			switch {
			case res.Skipped != "":
				res.Summary = res.Skipped
			case len(res.Recommendations) > 0:
				res.Summary = fmt.Sprintf("%s proven on a copy.", plural(int64(len(res.Recommendations)), "index", "indexes"))
			default:
				res.Summary = fmt.Sprintf("No index would help: %s looked at, %s tested on a copy.",
					plural(int64(res.Statements), "statement", "statements"), plural(int64(res.Tested), "idea", "ideas"))
			}
		}
		return res, nil
	}
	prod, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	usage(ctx, prod, p.Track, res)
	// Samples: performance_schema's (MySQL 8.0+), else the slow query log's
	// (MariaDB, MySQL 5.7).
	var stmts []*ixStatement
	if !s.flavor.mariadb() {
		stmts, err = s.advisorStatements(ctx, prod, p)
	}
	if s.flavor.mariadb() || err != nil && strings.Contains(err.Error(), "query_sample_text") {
		stmts, err = s.slowLogStatements(ctx, prod)
		switch {
		case errors.Is(err, errSlowLogOff):
			res.Skipped = s.flavor.display() + " keeps no sample of each query's values except in its slow query log, which is off: turn it on (Pulse, Health: Turn on the slow query log) so Rowsafe can test index ideas on a copy."
			return done()
		case err != nil:
			res.Skipped = "Reading the slow query log failed: " + firstLine(err.Error())
			return done()
		}
		stmts = slowStatementsFor(stmts, p)
	}
	if err != nil {
		res.Skipped = "Reading the statement statistics failed: " + firstLine(err.Error())
		return done()
	}
	res.Statements = len(stmts)
	ideas := s.indexIdeas(ctx, prod, stmts, res)
	known := map[string]bool{}
	for _, k := range p.Known {
		known[k] = true
	}
	var test []*ixIdea
	for _, x := range ideas {
		res.Generated = append(res.Generated, x.key)
		if known[x.key] {
			res.Unchanged = append(res.Unchanged, x.key)
		} else if len(test) < ixMaxIdeas {
			test = append(test, x)
		}
	}
	if len(test) == 0 {
		return done()
	}
	err = s.withCopy(ctx, taskID, log, res, func(copyDB *sql.DB) error {
		for _, x := range test {
			if err := ctx.Err(); err != nil {
				return err
			}
			s.testIdea(ctx, prod, copyDB, x, res, log)
		}
		return nil
	})
	if err != nil && res.Skipped == "" {
		res.Skipped = "Testing on a copy failed: " + firstLine(err.Error())
	}
	slices.SortFunc(res.Recommendations, func(a, b protocol.IndexRecommendation) int { return cmp.Compare(b.Speedup, a.Speedup) })
	return done()
}

// advisorStatements reads the digests worth an index: the ones the control
// plane listed (by query ID), or the busiest, that read far more rows than
// they return and have a usable sample.
func (s *server) advisorStatements(ctx context.Context, db *sql.DB, p protocol.IndexAdvisorParams) ([]*ixStatement, error) {
	want := map[string]protocol.AdvisorStatement{}
	for _, st := range p.Statements {
		want[st.QueryID] = st
	}
	var maxText int
	_ = db.QueryRowContext(ctx, "SELECT @@performance_schema_max_sql_text_length").Scan(&maxText)
	rows, err := db.QueryContext(ctx, `
		SELECT digest, digest_text, COALESCE(query_sample_text, ''), COALESCE(schema_name, ''), count_star,
		       sum_timer_wait / 1000000000, sum_rows_sent + sum_rows_affected, sum_rows_examined
		FROM performance_schema.events_statements_summary_by_digest
		WHERE digest IS NOT NULL AND digest_text IS NOT NULL ORDER BY sum_timer_wait DESC LIMIT ?`, ixTopDigests)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ixStatement
	for rows.Next() {
		x := &ixStatement{}
		var digest string
		var returned, examined int64
		if err := rows.Scan(&digest, &x.digest, &x.sample, &x.schema, &x.calls, &x.totalMs, &returned, &examined); err != nil {
			return nil, err
		}
		x.id = digestID(digest)
		if w, ok := want[x.id]; ok { // the control plane's figures cover the window it looked at
			x.calls, x.totalMs = w.Calls, w.TotalTimeMs
		} else if len(want) > 0 {
			continue
		}
		if x.calls == 0 || examined/x.calls < ixMinExamined || float64(examined) < ixMinRatio*float64(max(returned, x.calls)) {
			continue
		}
		// A sample cut at performance_schema_max_sql_text_length can't run.
		if x.sample == "" || maxText > 0 && len(x.sample) >= maxText || ownStatement(x.digest) {
			continue
		}
		shape, ok := parseShape(x.digest, x.schema)
		if !ok || isSystemSchema(shape.Schema) {
			continue
		}
		x.shape = shape
		out = append(out, x)
	}
	return out, rows.Err()
}

// indexIdeas parses the statements and builds one idea per distinct index,
// leaving out what an existing index already covers.
func (s *server) indexIdeas(ctx context.Context, db *sql.DB, stmts []*ixStatement, res *protocol.IndexAdvisorResult) []*ixIdea {
	idx, err := readIndexes(ctx, db)
	if err != nil {
		res.Notes = append(res.Notes, "Reading the indexes failed: "+firstLine(err.Error()))
		return nil
	}
	byKey := map[string]*ixIdea{}
	var order []*ixIdea
	for _, st := range stmts {
		cols := st.shape.candidate()
		if len(cols) == 0 {
			continue
		}
		res.Analyzed++
		info, ok, err := loadTableInfo(ctx, db, st.shape.Schema, st.shape.Table)
		if err != nil || !ok {
			continue
		}
		missing := false
		for _, c := range cols {
			if !slices.Contains(info.Columns, c) {
				missing = true
			}
		}
		if missing {
			continue
		}
		covered := false
		for _, x := range idx[tableKey{st.shape.Schema, st.shape.Table}] {
			if len(x.columns) >= len(cols) && slices.Equal(x.columns[:len(cols)], quotedAll(cols)) {
				covered = true
			}
		}
		if covered {
			continue
		}
		spec := protocol.IndexSpec{DB: st.shape.Schema, Schema: st.shape.Schema, Table: st.shape.Table, Columns: cols}
		if st.shape.OrderDesc && len(st.shape.Range) == 0 {
			for _, c := range st.shape.Order {
				if slices.Contains(cols, c) {
					spec.Descending = append(spec.Descending, c)
				}
			}
		}
		spec.Name = protocol.IndexName(spec)
		key := spec.Key()
		x := byKey[key]
		if x == nil {
			x = &ixIdea{spec: spec, key: key}
			byKey[key] = x
			order = append(order, x)
		}
		x.stmts = append(x.stmts, st)
	}
	return order
}

// withCopy restores a private copy of the latest backup, runs fn on it and
// removes it.
func (s *server) withCopy(ctx context.Context, taskID string, log agent.TaskLogger, res *protocol.IndexAdvisorResult, fn func(*sql.DB) error) error {
	began := time.Now()
	prod, err := s.open(ctx)
	if err != nil {
		return err
	}
	source, _, err := schemaSizes(ctx, prod)
	prod.Close()
	if err != nil {
		return err
	}
	var size int64
	for _, d := range source {
		size += d.SizeBytes
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return err
	}
	root := s.env.Config.DrillDir
	name := "mysql-advisor-" + taskID
	dir, err := safeDir(root, name)
	if err != nil {
		return err
	}
	if err := checkSpace(root, size); err != nil {
		res.Skipped = "Not enough free disk for a copy to test the indexes on: " + err.Error()
		return nil
	}
	cs := rewinds(s.env)
	cs.drillBusy(name, true)
	defer cs.drillBusy(name, false)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	r, err := s.restoreData(ctx, st, dir, restoreTarget{}, log)
	if err != nil {
		if errors.Is(err, errNoBackup) {
			res.Skipped = "There is no backup yet to restore a copy from."
			return nil
		}
		return err
	}
	sc, err := s.startScratch(ctx, dir, r.Backup, ixCopyStartTime)
	if err != nil {
		return err
	}
	defer sc.stop(context.WithoutCancel(ctx))
	if err := s.replay(ctx, sc, r, restoreTarget{}, log); err != nil {
		return err
	}
	copyDB, err := sc.connect(ctx)
	if err != nil {
		return err
	}
	defer copyDB.Close()
	copyDB.SetMaxOpenConns(1) // session settings (max_execution_time) stay on one connection
	res.CopySeconds = time.Since(began).Seconds()
	log.Printf("copy restored in %s", time.Since(began).Round(time.Second))
	return fn(copyDB)
}

// testIdea measures the idea's statements on the copy without and with the
// index.
func (s *server) testIdea(ctx context.Context, prod, copyPool *sql.DB, x *ixIdea, res *protocol.IndexAdvisorResult, log agent.TaskLogger) {
	res.Tested++
	// One connection: statements from the slow query log name their tables
	// in the schema they ran in (USE), and session settings stay.
	copyDB, err := copyPool.Conn(ctx)
	if err != nil {
		res.Rejected = append(res.Rejected, protocol.RejectedIndex{Spec: x.spec, Key: x.key, Reason: "connecting to the copy failed: " + firstLine(err.Error())})
		return
	}
	defer copyDB.Close()
	reject := func(reason string) {
		log.Printf("%s: %s", x.spec.Name, reason)
		res.Rejected = append(res.Rejected, protocol.RejectedIndex{Spec: x.spec, Key: x.key, Reason: reason})
	}
	_, _ = copyDB.ExecContext(ctx, fmt.Sprintf("SET SESSION max_execution_time = %d", ixQueryTimeout.Milliseconds()))
	type before struct {
		cost, ms float64
		ok       bool
	}
	pre := make([]before, len(x.stmts))
	for i, st := range x.stmts {
		c, _, err := explainCost(ctx, copyDB, st)
		if err != nil {
			continue
		}
		pre[i] = before{cost: c, ms: timeSelect(ctx, copyDB, st), ok: true}
	}
	cols := make([]string, len(x.spec.Columns))
	for i, c := range x.spec.Columns {
		cols[i] = quoteIdent(c)
		if slices.Contains(x.spec.Descending, c) {
			cols[i] += " DESC"
		}
	}
	table := quoteIdent(x.spec.Schema) + "." + quoteIdent(x.spec.Table)
	bctx, cancel := context.WithTimeout(ctx, ixBuildTimeout)
	defer cancel()
	began := time.Now()
	if _, err := copyDB.ExecContext(bctx, fmt.Sprintf("CREATE INDEX %s ON %s (%s)", quoteIdent(x.spec.Name), table, strings.Join(cols, ", "))); err != nil {
		reject("building it on the copy failed: " + firstLine(err.Error()))
		return
	}
	buildMs := time.Since(began).Milliseconds()
	defer copyDB.ExecContext(context.WithoutCancel(ctx), fmt.Sprintf("DROP INDEX %s ON %s", quoteIdent(x.spec.Name), table))
	_, _ = copyDB.ExecContext(ctx, "ANALYZE TABLE "+table)
	rec := protocol.IndexRecommendation{Spec: x.spec, Key: x.key, BuildMs: buildMs}
	var page int64 = 16384
	_ = copyDB.QueryRowContext(ctx, "SELECT @@innodb_page_size").Scan(&page)
	var pages int64
	if copyDB.QueryRowContext(ctx, `SELECT stat_value FROM mysql.innodb_index_stats WHERE database_name = ? AND table_name = ? AND index_name = ? AND stat_name = 'size'`,
		x.spec.Schema, x.spec.Table, x.spec.Name).Scan(&pages) == nil {
		rec.SizeBytes = pages * page
	}
	var weighted, timeSum float64
	for i, st := range x.stmts {
		if !pre[i].ok {
			continue
		}
		after, plan, err := explainCost(ctx, copyDB, st)
		if err != nil || !strings.Contains(plan, `"key": "`+x.spec.Name+`"`) {
			continue // the optimizer doesn't use it for this statement
		}
		g := protocol.IndexGain{QueryID: st.id, CostBefore: pre[i].cost, CostAfter: after, Calls: st.calls, TotalTimeMs: st.totalMs}
		if pre[i].ms > 0 {
			if ms := timeSelect(ctx, copyDB, st); ms > 0 {
				g.MsBefore, g.MsAfter = pre[i].ms, ms
			}
		}
		switch {
		case g.MsBefore > 0 && g.MsAfter > 0:
			g.Speedup = g.MsBefore / g.MsAfter
		case after > 0:
			g.Speedup = pre[i].cost / after
		}
		if g.Speedup < ixMinSpeedup {
			continue
		}
		rec.Statements = append(rec.Statements, g)
		weighted += g.Speedup * st.totalMs
		timeSum += st.totalMs
	}
	if len(rec.Statements) == 0 {
		reject(fmt.Sprintf("on the copy, the optimizer either didn't use it or it made no statement at least %.0f times faster", ixMinSpeedup))
		return
	}
	rec.Speedup = weighted / max(timeSum, 1e-9)
	if info, ok, err := loadTableInfo(ctx, prod, x.spec.Schema, x.spec.Table); err == nil && ok {
		rec.TableBytes, rec.TableRows = info.Size, info.Rows
	}
	rec.WritesPerSecond = tableWriteRate(ctx, prod, x.spec.Schema, x.spec.Table)
	log.Printf("%s: %.1fx faster for %s", x.spec.Name, rec.Speedup, plural(int64(len(rec.Statements)), "statement", "statements"))
	res.Recommendations = append(res.Recommendations, rec)
}

// explainCost is the optimizer's cost of a statement's sample, and its plan.
func explainCost(ctx context.Context, db *sql.Conn, st *ixStatement) (float64, string, error) {
	var plan string
	cctx, cancel := context.WithTimeout(ctx, ixQueryTimeout)
	defer cancel()
	if st.schema != "" {
		if _, err := db.ExecContext(cctx, "USE "+quoteIdent(st.schema)); err != nil {
			return 0, "", err
		}
	}
	if err := db.QueryRowContext(cctx, "EXPLAIN FORMAT=JSON "+st.sample).Scan(&plan); err != nil {
		return 0, "", err
	}
	var v struct {
		QueryBlock struct {
			CostInfo struct {
				QueryCost json.Number `json:"query_cost"`
			} `json:"cost_info"`
			Cost json.Number `json:"cost"` // MariaDB 11+
		} `json:"query_block"`
	}
	if err := json.Unmarshal([]byte(plan), &v); err != nil {
		return 0, "", err
	}
	c, err := v.QueryBlock.CostInfo.QueryCost.Float64()
	if err != nil {
		c, err = v.QueryBlock.Cost.Float64()
	}
	if err != nil {
		return 0, plan, nil // UPDATE and DELETE plans have no total cost
	}
	return c, plan, nil
}

// timeSelect runs a SELECT sample on the copy and returns its time (the best
// of two runs; 0 for other statements or when it fails or times out).
func timeSelect(ctx context.Context, db *sql.Conn, st *ixStatement) float64 {
	if !kw(firstWord(st.sample), "SELECT") || strings.Contains(strings.ToUpper(st.sample), " FOR UPDATE") {
		return 0
	}
	best := 0.0
	for range 2 {
		began := time.Now()
		rows, err := db.QueryContext(ctx, st.sample)
		if err != nil {
			return 0
		}
		for rows.Next() {
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return 0
		}
		ms := float64(time.Since(began).Microseconds()) / 1000
		if best == 0 || ms < best {
			best = ms
		}
	}
	return best
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t\n("); i > 0 {
		return s[:i]
	}
	return s
}

// tableWriteRate is a table's writes per second since the server started.
func tableWriteRate(ctx context.Context, db *sql.DB, schema, table string) float64 {
	var writes, uptime float64
	if db.QueryRowContext(ctx, `SELECT count_write FROM performance_schema.table_io_waits_summary_by_table WHERE object_schema = ? AND object_name = ?`,
		schema, table).Scan(&writes) != nil {
		return 0
	}
	var name string
	if db.QueryRowContext(ctx, "SHOW GLOBAL STATUS LIKE 'Uptime'").Scan(&name, &uptime) != nil || uptime <= 0 {
		return 0
	}
	return writes / uptime
}

// usage reports the tracked indexes (ones Rowsafe created) as they are now.
func usage(ctx context.Context, db *sql.DB, track []protocol.TrackedIndex, res *protocol.IndexAdvisorResult) {
	if len(track) == 0 {
		return
	}
	idx, err := readIndexes(ctx, db)
	if err != nil {
		return
	}
	for _, t := range track {
		u := protocol.IndexUsage{TrackedIndex: t}
		for k, xs := range idx {
			if k.schema != t.Schema {
				continue
			}
			for _, x := range xs {
				if x.name != t.Index {
					continue
				}
				u.Exists, u.Valid, u.SizeBytes = true, true, x.bytes
				_ = db.QueryRowContext(ctx, `SELECT count_read FROM performance_schema.table_io_waits_summary_by_index_usage
					WHERE object_schema = ? AND object_name = ? AND index_name = ?`, k.schema, k.table, x.name).Scan(&u.Scans)
			}
		}
		res.Usage = append(res.Usage, u)
	}
}
