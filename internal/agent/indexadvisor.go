package agent

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// The index advisor (protocol.TaskIndexAdvisor): read the busiest
// statements' text from pg_stat_statements, parse them with PostgreSQL's own
// parser, turn what they ask of each table into index ideas (skipping what
// existing indexes already cover), and test every new idea on a copy
// restored from the latest backup, like Proof: EXPLAIN each statement,
// CREATE INDEX on the copy, EXPLAIN again. Only indexes the planner uses and
// that make a statement at least twice as cheap are recommended. Production
// is only read (catalogs and statistics, with short timeouts); the copy is
// deleted when the task ends.

// advisorAppName is the application_name of the advisor's sessions.
const advisorAppName = "rowsafe-agent-advisor"

// Limits of one advisor run.
const (
	advisorTopStatements = 30 // without a list from the control plane
	advisorMaxStatements = 60
	advisorStmtTimeout   = "10s" // catalog reads on production
	advisorExplainTime   = "30s" // one EXPLAIN on the copy
	advisorAnalyzeTime   = "10s" // one EXPLAIN ANALYZE on the copy
	advisorMaxAnalyze    = 6     // statements measured with EXPLAIN ANALYZE
	advisorMaxTested     = 24    // index ideas tested per run
	advisorBuildTimeout  = 45 * time.Minute
	advisorMinVersion    = 120000
)

// shapeParser turns statements into shapes. It runs the parser in a child
// process (see sqlshape); tests replace it with the in-process parser.
var shapeParser = parseShapesInChild

// parseShapesInChild runs "rowsafe-agent sql-shapes": JSON statements on
// stdin, JSON shapes on stdout.
func parseShapesInChild(ctx context.Context, queries []string) ([]indexadvisor.Shape, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	in, err := json.Marshal(queries)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "sql-shapes")
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("the SQL parser failed: %w: %s", err, strings.TrimSpace(tailString(stderr.String(), 500)))
	}
	var shapes []indexadvisor.Shape
	if err := json.Unmarshal(out.Bytes(), &shapes); err != nil {
		return nil, fmt.Errorf("reading the SQL parser's output: %w", err)
	}
	if len(shapes) != len(queries) {
		return nil, fmt.Errorf("the SQL parser returned %d results for %d statements", len(shapes), len(queries))
	}
	return shapes, nil
}

func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// advisorStatement is a statement with its text.
type advisorStatement struct {
	indexadvisor.Statement
	text string
}

// indexAdvisor runs one advisor task.
func (a *Agent) indexAdvisor(ctx context.Context, db protocol.DatabaseSpec, taskID string, p protocol.IndexAdvisorParams, tl *taskLog) (*protocol.IndexAdvisorResult, error) {
	start := time.Now()
	res := &protocol.IndexAdvisorResult{Generated: []string{}, Recommendations: []protocol.IndexRecommendation{}}
	finish := func(err error) (*protocol.IndexAdvisorResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		if res.Summary == "" {
			res.Summary = advisorSummary(res)
		}
		if err != nil {
			tl.Printf("failed: %v", err)
		} else {
			tl.Printf("%s", res.Summary)
		}
		return res, err
	}
	prod := a.target(db)
	prod.AppName = advisorAppName

	// Usage of the indexes Rowsafe created (cheap; always).
	res.Usage = indexUsage(ctx, prod, p.Track, tl)

	var in struct {
		VersionNum    int
		ServerVersion string
		InRecovery    bool
	}
	if err := func() error {
		conn, err := prod.Connect(ctx, "postgres")
		if err != nil {
			return fmt.Errorf("connecting to PostgreSQL: %w", err)
		}
		defer closeConn(ctx, conn)
		return conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int, current_setting('server_version'), pg_is_in_recovery()`).
			Scan(&in.VersionNum, &in.ServerVersion, &in.InRecovery)
	}(); err != nil {
		return finish(err)
	}
	if in.VersionNum < advisorMinVersion {
		res.Skipped = fmt.Sprintf("Index recommendations need PostgreSQL 12 or newer; this server runs %s.", in.ServerVersion)
		return finish(nil)
	}
	if in.InRecovery {
		res.Skipped = "This PostgreSQL is a read-only replica; index recommendations are made for the primary."
		return finish(nil)
	}

	stmts, err := readAdvisorStatements(ctx, prod, p, tl)
	if err != nil {
		return finish(err)
	}
	res.Statements = len(stmts)
	if len(stmts) == 0 {
		res.Summary = "There were no statements to look at yet: Rowsafe needs a few hours of query statistics (pg_stat_statements)."
		return finish(nil)
	}
	texts := make([]string, len(stmts))
	for i, s := range stmts {
		texts[i] = s.text
	}
	shapes, err := shapeParser(ctx, texts)
	if err != nil {
		return finish(err)
	}
	for i := range stmts {
		stmts[i].Shape = shapes[i]
		if shapes[i].Error == "" && shapes[i].Kind != "other" && len(shapes[i].Relations) > 0 {
			res.Analyzed++
		}
	}
	tl.Printf("analyzed %d of %d statements", res.Analyzed, len(stmts))

	// Ideas per database of the cluster.
	byDB := map[string][]advisorStatement{}
	var dbs []string
	for _, s := range stmts {
		if s.Shape.Error != "" || s.DB == "" {
			continue
		}
		if _, ok := byDB[s.DB]; !ok {
			dbs = append(dbs, s.DB)
		}
		byDB[s.DB] = append(byDB[s.DB], s)
	}
	type dbWork struct {
		db    string
		stmts []advisorStatement
		cands []*indexadvisor.Candidate
	}
	var work []dbWork
	known := map[string]bool{}
	for _, k := range p.Known {
		known[k] = true
	}
	for _, name := range dbs {
		cands, err := advisorCandidates(ctx, prod, name, byDB[name], tl)
		if err != nil {
			res.Notes = append(res.Notes, fmt.Sprintf("Database %s: %v", name, sentence(err)))
			tl.Printf("database %s: %v", name, err)
			continue
		}
		var fresh []*indexadvisor.Candidate
		for _, c := range cands {
			res.Generated = append(res.Generated, c.Key())
			if known[c.Key()] {
				res.Unchanged = append(res.Unchanged, c.Key())
				continue
			}
			fresh = append(fresh, c)
		}
		if len(fresh) > 0 {
			work = append(work, dbWork{db: name, stmts: byDB[name], cands: fresh})
		}
	}
	total := 0
	for _, w := range work {
		total += len(w.cands)
	}
	if total == 0 {
		return finish(nil)
	}

	// Test the new ideas on a copy.
	var results []*indexadvisor.Result
	err = a.withAdvisorCopy(ctx, db, taskID, res, tl, func(copyT pginspect.Target) error {
		budget := advisorMaxTested
		for _, w := range work {
			if budget <= 0 || ctx.Err() != nil {
				break
			}
			cands := w.cands[:min(len(w.cands), budget)]
			budget -= len(cands)
			conn, err := copyT.Connect(ctx, copyDBName(w.db))
			if err != nil {
				res.Notes = append(res.Notes, fmt.Sprintf("Database %s: the copy didn't open it (%v).", w.db, err))
				continue
			}
			rs, err := testCandidates(ctx, conn, in.VersionNum, w.stmts, cands, tl)
			closeConn(ctx, conn)
			results = append(results, rs...)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return finish(err)
	}
	res.Tested = len(results)
	recs, rejected := indexadvisor.Choose(results)
	for _, r := range recs {
		res.Recommendations = append(res.Recommendations, r.Recommendation())
	}
	for _, r := range results {
		if why, ok := rejected[r.Candidate.Key()]; ok {
			res.Rejected = append(res.Rejected, protocol.RejectedIndex{Spec: r.Candidate.Spec, Key: r.Candidate.Key(), Reason: why})
		}
	}
	return finish(nil)
}

// advisorSummary: "Looked at 24 busy queries and tested 3 index ideas on a
// copy of your database: 1 makes 2 queries about 40x faster."
func advisorSummary(r *protocol.IndexAdvisorResult) string {
	switch {
	case r.Skipped != "" && r.Tested == 0:
		return r.Skipped
	case r.Statements == 0:
		return "There were no statements to look at."
	case len(r.Generated) == 0:
		return fmt.Sprintf("Looked at %s: your indexes already cover what they need.", countNoun(r.Statements, "busy query", "busy queries"))
	case r.Tested == 0:
		return fmt.Sprintf("Looked at %s: nothing new since the last check (%s still recommended).",
			countNoun(r.Statements, "busy query", "busy queries"), countNoun(len(r.Unchanged), "index is", "indexes are"))
	}
	s := fmt.Sprintf("Looked at %s and tested %s on a copy of your database",
		countNoun(r.Statements, "busy query", "busy queries"), countNoun(r.Tested, "index idea", "index ideas"))
	if len(r.Recommendations) == 0 {
		return s + ": none made a real difference, so there is nothing to add."
	}
	best := r.Recommendations[0]
	for _, x := range r.Recommendations {
		if x.Speedup > best.Speedup {
			best = x
		}
	}
	return s + fmt.Sprintf(": %d %s worth adding; the best makes %s about %s faster.", len(r.Recommendations),
		plural(len(r.Recommendations), "is", "are"), countNoun(len(best.Statements), "query", "queries"), timesFaster(best.Speedup))
}

func timesFaster(x float64) string { return protocol.TimesFaster(x) }

// ---- statements ----

// readAdvisorStatements is advisorStatements (tests replace it: the
// developer's PostgreSQL usually has no pg_stat_statements).
var readAdvisorStatements = advisorStatements

// advisorStatements reads the statements' text from pg_stat_statements:
// the ones the control plane named (busiest first), or the busiest ones.
func advisorStatements(ctx context.Context, t pginspect.Target, p protocol.IndexAdvisorParams, tl *taskLog) ([]advisorStatement, error) {
	conn, schema, err := findStatementsView(ctx, t)
	if err != nil {
		return nil, err
	}
	defer closeConn(ctx, conn)
	v, err := serverVersionNum(ctx, conn)
	if err != nil {
		return nil, err
	}
	total, toplevel := "total_exec_time", " AND toplevel"
	if v < 130000 {
		total = "total_time"
	}
	if v < 140000 {
		toplevel = ""
	}
	view := pgx.Identifier{schema}.Sanitize() + ".pg_stat_statements(true)"
	var rows pgx.Rows
	want := map[int64]protocol.AdvisorStatement{}
	var order []int64
	if len(p.Statements) > 0 {
		ids := make([]int64, 0, len(p.Statements))
		for _, s := range p.Statements[:min(len(p.Statements), advisorMaxStatements)] {
			id, err := strconv.ParseInt(s.QueryID, 10, 64)
			if err != nil {
				continue
			}
			if _, dup := want[id]; !dup {
				ids = append(ids, id)
				order = append(order, id)
			}
			want[id] = s
		}
		rows, err = conn.Query(ctx, fmt.Sprintf(`
			SELECT s.queryid, s.query, coalesce(d.datname::text, ''), s.calls, s.%s, s.rows
			FROM %s s LEFT JOIN pg_database d ON d.oid = s.dbid
			WHERE s.queryid = ANY($1)%s`, total, view, toplevel), ids)
	} else {
		rows, err = conn.Query(ctx, fmt.Sprintf(`
			SELECT s.queryid, s.query, coalesce(d.datname::text, ''), s.calls, s.%s, s.rows
			FROM %s s LEFT JOIN pg_database d ON d.oid = s.dbid
			WHERE s.queryid IS NOT NULL%s ORDER BY s.%s DESC LIMIT %d`, total, view, toplevel, total, advisorTopStatements))
	}
	if err != nil {
		return nil, fmt.Errorf("reading pg_stat_statements: %w", err)
	}
	type row struct {
		id           int64
		text, db     string
		calls, nrows int64
		totalMs      float64
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.text, &x.db, &x.calls, &x.totalMs, &x.nrows)
		return x, err
	})
	if err != nil {
		return nil, fmt.Errorf("reading pg_stat_statements: %w", err)
	}
	// One entry per query ID: the same statement run by several users adds up.
	merged := map[int64]*advisorStatement{}
	best := map[int64]float64{}
	for _, x := range all {
		s := merged[x.id]
		if s == nil {
			s = &advisorStatement{Statement: indexadvisor.Statement{QueryID: strconv.FormatInt(x.id, 10)}, text: x.text}
			merged[x.id] = s
			if len(p.Statements) == 0 {
				order = append(order, x.id)
			}
		}
		s.Calls += x.calls
		s.TotalTimeMs += x.totalMs
		s.Rows += x.nrows
		if x.totalMs >= best[x.id] {
			best[x.id], s.DB = x.totalMs, x.db
		}
	}
	var out []advisorStatement
	for _, id := range order {
		s := merged[id]
		if s == nil {
			continue // no longer in pg_stat_statements
		}
		if w, ok := want[id]; ok {
			// The control plane's numbers cover a known window.
			s.Calls, s.TotalTimeMs, s.Rows = w.Calls, w.TotalTimeMs, w.Rows
			if w.Database != "" {
				s.DB = w.Database
			}
		}
		out = append(out, *s)
	}
	tl.Printf("read %d statements from pg_stat_statements", len(out))
	return out, nil
}

// findStatementsView connects to the database that has pg_stat_statements
// (postgres first, then the others).
func findStatementsView(ctx context.Context, t pginspect.Target) (*pgx.Conn, string, error) {
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return nil, "", fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	if err := setTimeouts(ctx, conn, advisorStmtTimeout); err != nil {
		closeConn(ctx, conn)
		return nil, "", err
	}
	names := []string{"postgres"}
	rows, err := conn.Query(ctx, `SELECT datname::text FROM pg_database
		WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres' ORDER BY datname LIMIT 20`)
	if err == nil {
		if more, err := pgx.CollectRows(rows, pgx.RowTo[string]); err == nil {
			names = append(names, more...)
		}
	}
	for _, name := range names {
		c := conn
		if name != "postgres" {
			if c, err = t.Connect(ctx, name); err != nil {
				continue
			}
			if err := setTimeouts(ctx, c, advisorStmtTimeout); err != nil {
				closeConn(ctx, c)
				continue
			}
		}
		var schema string
		err := c.QueryRow(ctx, `SELECT n.nspname::text FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
			WHERE e.extname = 'pg_stat_statements'`).Scan(&schema)
		if err == nil {
			if c != conn {
				closeConn(ctx, conn)
			}
			return c, schema, nil
		}
		if c != conn {
			closeConn(ctx, c)
		}
	}
	closeConn(ctx, conn)
	return nil, "", errors.New("the pg_stat_statements extension is not installed, so Rowsafe can't see which queries are slow " +
		"(add pg_stat_statements to shared_preload_libraries and run CREATE EXTENSION pg_stat_statements)")
}

func setTimeouts(ctx context.Context, conn *pgx.Conn, stmt string) error {
	_, err := conn.Exec(ctx, `SELECT set_config('statement_timeout', $1, false), set_config('lock_timeout', '2s', false)`, stmt)
	return err
}

// ---- catalogs ----

// advisorCandidates reads the catalogs of dbname for the tables the
// statements use and builds the index ideas.
func advisorCandidates(ctx context.Context, t pginspect.Target, dbname string, stmts []advisorStatement, tl *taskLog) ([]*indexadvisor.Candidate, error) {
	conn, err := t.Connect(ctx, dbname)
	if err != nil {
		return nil, fmt.Errorf("connecting: %w", err)
	}
	defer closeConn(ctx, conn)
	if err := setTimeouts(ctx, conn, advisorStmtTimeout); err != nil {
		return nil, err
	}
	var rels []indexadvisor.Relation
	for _, s := range stmts {
		rels = append(rels, s.Shape.Relations...)
	}
	cat, err := loadCatalog(ctx, conn, rels)
	if err != nil {
		return nil, err
	}
	plain := make([]indexadvisor.Statement, len(stmts))
	for i, s := range stmts {
		plain[i] = s.Statement
	}
	cands := indexadvisor.Generate(dbname, plain, cat.lookup)
	tl.Printf("database %s: %d tables, %d index ideas", dbname, len(cat.tables), len(cands))
	return cands, nil
}

// catalog is the tables of one database the statements use.
type catalog struct {
	tables map[uint32]*indexadvisor.Table
	byName map[[2]string]*indexadvisor.Table // {schema as written, name}
}

func (c *catalog) lookup(schema, name string) *indexadvisor.Table {
	return c.byName[[2]string{schema, name}]
}

// loadCatalog resolves the relations (unqualified ones on the search path)
// and reads their size, write rate, columns with planner statistics, and
// indexes.
func loadCatalog(ctx context.Context, conn *pgx.Conn, rels []indexadvisor.Relation) (*catalog, error) {
	cat := &catalog{tables: map[uint32]*indexadvisor.Table{}, byName: map[[2]string]*indexadvisor.Table{}}
	var schemas, names []string
	seen := map[[2]string]bool{}
	for _, r := range rels {
		k := [2]string{r.Schema, r.Name}
		if !seen[k] && len(r.Name) <= 63 && len(r.Schema) <= 63 {
			seen[k] = true
			schemas, names = append(schemas, r.Schema), append(names, r.Name)
		}
	}
	if len(names) == 0 {
		return cat, nil
	}
	rows, err := conn.Query(ctx, `
		SELECT r.s, r.n, c.oid, n.nspname::text, c.relname::text, c.relkind::text,
		       CASE WHEN c.reltuples >= 0 THEN c.reltuples::float8 ELSE coalesce(st.n_live_tup, 0)::float8 END,
		       pg_table_size(c.oid),
		       coalesce(st.n_tup_ins + st.n_tup_upd + st.n_tup_del, 0)::float8
		FROM unnest($1::text[], $2::text[]) AS r(s, n)
		CROSS JOIN LATERAL (SELECT to_regclass(CASE WHEN r.s = '' THEN quote_ident(r.n)
		                                            ELSE quote_ident(r.s) || '.' || quote_ident(r.n) END) AS oid) x
		JOIN pg_class c ON c.oid = x.oid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stat_all_tables st ON st.relid = c.oid`, schemas, names)
	if err != nil {
		return nil, fmt.Errorf("reading tables: %w", err)
	}
	var writes = map[uint32]float64{}
	for rows.Next() {
		var s, n string
		t := &indexadvisor.Table{Columns: map[string]indexadvisor.Column{}}
		var w float64
		if err := rows.Scan(&s, &n, &t.OID, &t.Schema, &t.Name, &t.Kind, &t.Rows, &t.Bytes, &w); err != nil {
			rows.Close()
			return nil, err
		}
		if have, ok := cat.tables[t.OID]; ok {
			t = have
		} else {
			cat.tables[t.OID] = t
			writes[t.OID] = w
		}
		cat.byName[[2]string{s, n}] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cat.tables) == 0 {
		return cat, nil
	}
	var window float64
	if err := conn.QueryRow(ctx, `SELECT greatest(extract(epoch FROM now() - coalesce(
			(SELECT stats_reset FROM pg_stat_database WHERE datname = current_database()), pg_postmaster_start_time())), 1)::float8`).
		Scan(&window); err != nil {
		return nil, err
	}
	oids := make([]uint32, 0, len(cat.tables))
	for oid, t := range cat.tables {
		oids = append(oids, oid)
		t.WritesPerSecond = writes[oid] / window
	}
	rows, err = conn.Query(ctx, `
		SELECT a.attrelid, a.attname::text, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       s.null_frac IS NOT NULL, coalesce(s.n_distinct, 0)::float8, coalesce(s.null_frac, 0)::float8, coalesce(s.avg_width, 0)
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname AND s.attname = a.attname AND NOT s.inherited
		WHERE a.attrelid = ANY($1) AND a.attnum > 0 AND NOT a.attisdropped`, oids)
	if err != nil {
		return nil, fmt.Errorf("reading columns: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var name string
		var col indexadvisor.Column
		if err := rows.Scan(&oid, &name, &col.Type, &col.NotNull, &col.HasStats, &col.NDistinct, &col.NullFrac, &col.AvgWidth); err != nil {
			rows.Close()
			return nil, err
		}
		cat.tables[oid].Columns[name] = col
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = conn.Query(ctx, `
		SELECT x.indrelid, i.relname::text, am.amname::text, x.indisvalid AND x.indisready, x.indisunique, x.indnkeyatts::int,
		       coalesce(pg_get_expr(x.indpred, x.indrelid), ''), k.ord::int, coalesce(a.attname::text, ''),
		       coalesce((k.opt & 1) = 1, false),
		       coalesce(oc.opcdefault, false) AND (coalesce(k.coll, 0) = 0 OR k.coll = a.attcollation)
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_am am ON am.oid = i.relam
		CROSS JOIN LATERAL unnest(x.indkey::int2[], x.indoption::int2[], x.indclass::oid[], x.indcollation::oid[])
		     WITH ORDINALITY AS k(att, opt, cls, coll, ord)
		LEFT JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.att AND k.att > 0
		LEFT JOIN pg_opclass oc ON oc.oid = k.cls
		WHERE x.indrelid = ANY($1)
		ORDER BY x.indrelid, i.relname, k.ord`, oids)
	if err != nil {
		return nil, fmt.Errorf("reading indexes: %w", err)
	}
	var cur *indexadvisor.Index
	var curRel uint32
	flush := func() {
		if cur != nil {
			t := cat.tables[curRel]
			t.Indexes = append(t.Indexes, *cur)
		}
	}
	for rows.Next() {
		var rel uint32
		var name, method, pred, col string
		var valid, unique, desc, plainKey bool
		var nkey, ord int
		if err := rows.Scan(&rel, &name, &method, &valid, &unique, &nkey, &pred, &ord, &col, &desc, &plainKey); err != nil {
			rows.Close()
			return nil, err
		}
		if cur == nil || curRel != rel || cur.Name != name {
			flush()
			cur = &indexadvisor.Index{Name: name, Method: method, Valid: valid, Unique: unique, Predicate: pred}
			curRel = rel
		}
		if ord <= nkey {
			cur.Keys = append(cur.Keys, indexadvisor.IndexKey{Col: col, Desc: desc, Plain: plainKey && col != ""})
		} else if col != "" {
			cur.Include = append(cur.Include, col)
		}
	}
	flush()
	rows.Close()
	return cat, rows.Err()
}

// ---- usage of indexes Rowsafe created ----

func indexUsage(ctx context.Context, t pginspect.Target, track []protocol.TrackedIndex, tl *taskLog) []protocol.IndexUsage {
	byDB := map[string][]protocol.TrackedIndex{}
	for _, x := range track {
		if validDatName(x.DB) == nil && x.Schema != "" && x.Index != "" {
			byDB[x.DB] = append(byDB[x.DB], x)
		}
	}
	var out []protocol.IndexUsage
	for name, list := range byDB {
		conn, err := t.Connect(ctx, name)
		if err != nil {
			tl.Printf("usage of indexes in %s: %v", name, err)
			continue
		}
		if err := setTimeouts(ctx, conn, advisorStmtTimeout); err != nil {
			closeConn(ctx, conn)
			continue
		}
		for _, x := range list {
			u := protocol.IndexUsage{TrackedIndex: x}
			err := conn.QueryRow(ctx, `
				SELECT true, x.indisvalid, coalesce(s.idx_scan, 0), pg_relation_size(c.oid)
				FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_index x ON x.indexrelid = c.oid
				LEFT JOIN pg_stat_all_indexes s ON s.indexrelid = c.oid
				WHERE n.nspname = $1 AND c.relname = $2`, x.Schema, x.Index).Scan(&u.Exists, &u.Valid, &u.Scans, &u.SizeBytes)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				tl.Printf("usage of %s.%s: %v", x.Schema, x.Index, err)
				continue
			}
			out = append(out, u)
		}
		closeConn(ctx, conn)
	}
	slices.SortFunc(out, func(a, b protocol.IndexUsage) int {
		return cmp.Or(strings.Compare(a.DB, b.DB), strings.Compare(a.Schema, b.Schema), strings.Compare(a.Index, b.Index))
	})
	return out
}

// ---- the copy ----

// advisorCopyName names the copy's cluster (rowsafe-advisor). It lives in
// the drill directory with the drill marker, so an agent that died mid-run
// removes it at start like a drill.
const advisorCopyName = "advisor"

// advisorTestCopy, when set (tests), is used instead of restoring a copy:
// a server where dbName(production database) is a copy of it.
var advisorTestCopy *struct {
	target pginspect.Target
	dbName func(string) string
}

// copyDBName is the name of a production database on the copy.
func copyDBName(db string) string {
	if advisorTestCopy != nil && advisorTestCopy.dbName != nil {
		return advisorTestCopy.dbName(db)
	}
	return db
}

// withAdvisorCopy restores the latest backup plus all archived WAL into a
// scratch cluster (Proof's machinery: private socket, no archiving, no
// background workers, low priority), runs fn against it and deletes it.
// When a copy can't be made for a plain reason (no backup yet, not enough
// disk), it sets res.Skipped and returns nil.
func (a *Agent) withAdvisorCopy(ctx context.Context, db protocol.DatabaseSpec, taskID string,
	res *protocol.IndexAdvisorResult, tl *taskLog, fn func(pginspect.Target) error) error {
	if advisorTestCopy != nil {
		return fn(advisorTestCopy.target) // tests: a second database stands in for the copy
	}
	start := time.Now()
	prod, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return err
	}
	if err := a.writeConfig(db, prod); err != nil {
		return err
	}
	cli := a.cli(db)
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return fmt.Errorf("Rowsafe can't reach the backup repository from this server: %w", err)
	}
	backup, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		res.Skipped = "Rowsafe tests index ideas on a copy restored from your backups, and there is no backup yet."
		return nil
	}
	dir, err := a.drillDir("advisor-"+taskID, prod.DataDirectory)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.cfg.DrillDir, 0o700); err != nil {
		return err
	}
	need := int64(float64(prod.TotalSizeBytes)*drillSpaceFactor) + 1<<30
	if free, err := freeBytes(a.cfg.DrillDir); err == nil && free < need {
		res.Skipped = fmt.Sprintf("Rowsafe tests index ideas on a copy of your database, and there isn't enough free disk for one: %s free in %s, a copy needs about %s.",
			humanBytes(free), a.cfg.DrillDir, humanBytes(need))
		return nil
	}
	dataDir := filepath.Join(dir, "data")
	socketDir := filepath.Join(dir, "socket")
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(a.cfg.DrillPort)); n > maxSocketPath {
		return fmt.Errorf("the copy's socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_DRILL_DIR", n, maxSocketPath)
	}
	pgCtl := a.cfg.pgBin(prod.Major(), "pg_ctl")
	defer func() {
		if err := a.removeDrill(dir, pgCtl); err != nil {
			tl.Printf("deleting the copy at %s failed: %v", dir, err)
		} else {
			tl.Printf("deleted the copy")
		}
	}()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, drillMarker), []byte(taskID+"\n"), 0o600); err != nil {
		return err
	}
	for _, d := range []string{dataDir, socketDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	cli.Wrap = niceWrap()
	tl.Printf("restoring backup %s and the archived changes into a copy at %s to test index ideas", backup.Label, dataDir)
	out, err := cli.Restore(ctx, dataDir, filepath.Join(dir, "tablespaces"))
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fmt.Errorf("restoring the copy: %w", err)
	}
	spec := scratchSpec{Name: advisorCopyName, Port: a.cfg.DrillPort, SocketDir: socketDir, Major: prod.Major()}
	if a.cfg.DrillPreload == DrillPreloadProduction {
		spec.Preload = prod.SharedPreloadLibraries
	}
	if err := a.writeScratchConf(dataDir, spec); err != nil {
		return err
	}
	timeout := 4 * time.Hour
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-30*time.Minute, time.Minute)
	}
	t := pginspect.Target{SocketDir: socketDir, Port: a.cfg.DrillPort, User: a.cfg.PGUser, AppName: advisorAppName}
	conn, _, err := a.startScratchFallback(ctx, tl, spec, t, pgCtl, dir, timeout, prod.SharedPreloadLibraries)
	if err != nil {
		if data, rerr := os.ReadFile(filepath.Join(dir, "postgres.log")); rerr == nil {
			tl.Output("copy postgres.log (tail)", tail(data, 8000))
		}
		return fmt.Errorf("starting the copy: %w", err)
	}
	err = checkScratchIsolation(ctx, conn, tl)
	closeConn(ctx, conn)
	if err != nil {
		return err
	}
	res.CopySeconds = time.Since(start).Seconds()
	tl.Printf("the copy is ready (%s)", plainDuration(time.Since(start)))
	return fn(t)
}

// ---- testing ideas on the copy ----

// explainer runs EXPLAIN on the copy.
type explainer struct {
	conn    *pgx.Conn
	version int
	n       int
	scs     bool // standard_conforming_strings: literals can be quoted simply
}

// planCost returns the generic plan's total cost and whether it uses the
// index named index ("" to skip that check).
func (e *explainer) planCost(ctx context.Context, sql string, nparams int, index string) (float64, bool, error) {
	var plan string
	var err error
	if e.version >= 160000 {
		plan, err = rawQuery(ctx, e.conn, "EXPLAIN (GENERIC_PLAN, FORMAT JSON) "+sql)
	} else {
		plan, err = e.viaPrepare(ctx, sql, "EXPLAIN (FORMAT JSON) ", nullArgs(nparams), "force_generic_plan")
	}
	if err != nil {
		return 0, false, err
	}
	return parsePlan(plan, index)
}

// measure runs the statement with sample values (EXPLAIN ANALYZE, in a
// read-only transaction that is rolled back) and returns its time in ms.
func (e *explainer) measure(ctx context.Context, sql string, args []string) (float64, error) {
	if _, err := e.conn.Exec(ctx, "BEGIN READ ONLY"); err != nil {
		return 0, err
	}
	defer e.conn.Exec(context.WithoutCancel(ctx), "ROLLBACK") //nolint:errcheck
	if _, err := e.conn.Exec(ctx, `SELECT set_config('statement_timeout', $1, true)`, advisorAnalyzeTime); err != nil {
		return 0, err
	}
	plan, err := e.viaPrepare(ctx, sql, "EXPLAIN (ANALYZE, FORMAT JSON) ", args, "force_custom_plan")
	if err != nil {
		return 0, err
	}
	var doc []struct {
		ExecutionTime float64 `json:"Execution Time"`
		PlanningTime  float64 `json:"Planning Time"`
	}
	if err := json.Unmarshal([]byte(plan), &doc); err != nil || len(doc) == 0 {
		return 0, fmt.Errorf("unexpected EXPLAIN output")
	}
	return doc[0].ExecutionTime, nil
}

// viaPrepare prepares sql, runs prefix+EXECUTE with args under
// plan_cache_mode, and deallocates.
func (e *explainer) viaPrepare(ctx context.Context, sql, prefix string, args []string, mode string) (string, error) {
	e.n++
	name := fmt.Sprintf("rowsafe_advisor_%d", e.n)
	if _, err := rawQuery(ctx, e.conn, "PREPARE "+name+" AS "+sql); err != nil {
		return "", err
	}
	defer rawQuery(context.WithoutCancel(ctx), e.conn, "DEALLOCATE "+name) //nolint:errcheck
	if _, err := e.conn.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, false)`, mode); err != nil {
		return "", err
	}
	exec := prefix + "EXECUTE " + name
	if len(args) > 0 {
		exec += "(" + strings.Join(args, ", ") + ")"
	}
	return rawQuery(ctx, e.conn, exec)
}

// rawQuery sends sql as a simple query, untouched (statement texts carry
// $1 placeholders that must reach PostgreSQL as they are), and returns the
// first column of the first row ("" when there is none).
func rawQuery(ctx context.Context, conn *pgx.Conn, sql string) (string, error) {
	res, err := conn.PgConn().Exec(ctx, sql).ReadAll()
	if err != nil {
		return "", err
	}
	for _, r := range res {
		if r.Err != nil {
			return "", r.Err
		}
	}
	for _, r := range res {
		if len(r.Rows) > 0 && len(r.Rows[0]) > 0 {
			return string(r.Rows[0][0]), nil
		}
	}
	return "", nil
}

func nullArgs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "NULL"
	}
	return out
}

// parsePlan reads EXPLAIN (FORMAT JSON): the total cost, and whether any
// node scans the index named index.
func parsePlan(plan, index string) (float64, bool, error) {
	var doc []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal([]byte(plan), &doc); err != nil || len(doc) == 0 {
		return 0, false, fmt.Errorf("unexpected EXPLAIN output")
	}
	cost, _ := doc[0].Plan["Total Cost"].(float64)
	uses := false
	var walk func(n map[string]any)
	walk = func(n map[string]any) {
		if name, _ := n["Index Name"].(string); index != "" && name == index {
			uses = true
		}
		if subs, ok := n["Plans"].([]any); ok {
			for _, s := range subs {
				if m, ok := s.(map[string]any); ok {
					walk(m)
				}
			}
		}
	}
	walk(doc[0].Plan)
	return cost, uses, nil
}

// safeFuncs may appear in a statement run with EXPLAIN ANALYZE on the copy:
// they only compute (no side effects, no network, no sleeping).
var safeFuncs = map[string]bool{
	"count": true, "sum": true, "avg": true, "min": true, "max": true, "coalesce": true, "nullif": true,
	"greatest": true, "least": true, "lower": true, "upper": true, "length": true, "char_length": true,
	"abs": true, "round": true, "floor": true, "ceil": true, "now": true, "date_trunc": true, "date_part": true,
	"extract": true, "to_char": true, "array_agg": true, "string_agg": true, "json_agg": true, "jsonb_agg": true,
	"json_build_object": true, "jsonb_build_object": true, "bool_or": true, "bool_and": true, "concat": true,
	"substring": true, "substr": true, "trim": true, "btrim": true, "array_length": true, "cardinality": true,
	"row_number": true, "rank": true, "dense_rank": true, "timezone": true, "make_interval": true,
}

// measurable reports whether a statement may be run on the copy with
// EXPLAIN ANALYZE: a plain read-only SELECT calling only harmless functions.
func measurable(s indexadvisor.Shape) bool {
	if s.Kind != "select" || !s.ReadOnly {
		return false
	}
	for _, f := range s.Funcs {
		if !safeFuncs[f] {
			return false
		}
	}
	return true
}

// testCandidates tests the ideas of one database on the copy: EXPLAIN
// every statement that uses an idea's table without it, then for each idea
// CREATE INDEX, EXPLAIN those statements again, and DROP INDEX.
func testCandidates(ctx context.Context, conn *pgx.Conn, version int, stmts []advisorStatement,
	cands []*indexadvisor.Candidate, tl *taskLog) ([]*indexadvisor.Result, error) {
	if _, err := conn.Exec(ctx, `SELECT set_config('statement_timeout', $1, false), set_config('lock_timeout', '10s', false),
		set_config('maintenance_work_mem', '128MB', false), set_config('default_transaction_read_only', 'off', false)`, advisorExplainTime); err != nil {
		return nil, err
	}
	var scs string
	_ = conn.QueryRow(ctx, `SHOW standard_conforming_strings`).Scan(&scs)
	e := &explainer{conn: conn, version: version, scs: scs == "on"}

	// Which statements use which table (by OID on the copy).
	var rels []indexadvisor.Relation
	for _, s := range stmts {
		rels = append(rels, s.Shape.Relations...)
	}
	cat, err := loadCatalog(ctx, conn, rels)
	if err != nil {
		return nil, err
	}
	uses := map[string][]int{} // "schema.table" -> statement indexes
	usage := map[int][]*indexadvisor.Usage{}
	for i, s := range stmts {
		for _, u := range indexadvisor.Resolve(s.Shape, cat.lookup) {
			k := u.Table.Schema + "." + u.Table.Name
			uses[k] = append(uses[k], i)
			usage[i] = append(usage[i], u)
		}
	}

	// Baselines, and sample values for the statements worth measuring.
	type base struct {
		cost    float64
		ms      float64
		args    []string
		err     error
		measure bool
	}
	baseline := map[int]*base{}
	measured := 0
	order := make([]int, len(stmts))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(stmts[b].TotalTimeMs, stmts[a].TotalTimeMs) })
	for _, i := range order {
		s := stmts[i]
		used := false
		for _, c := range cands {
			if slices.Contains(uses[c.Spec.Schema+"."+c.Spec.Table], i) {
				used = true
			}
		}
		if !used {
			continue
		}
		b := &base{}
		baseline[i] = b
		b.cost, _, b.err = e.planCost(ctx, s.text, s.Shape.MaxParam, "")
		if b.err != nil {
			tl.Printf("query %s: EXPLAIN on the copy failed: %v", s.QueryID, plainPGError(b.err))
			continue
		}
		if measured < advisorMaxAnalyze && e.scs && measurable(s.Shape) {
			if args, ok := sampleArgs(ctx, conn, s.Shape, usage[i]); ok {
				ms, err := e.measure(ctx, s.text, args)
				if err == nil {
					b.ms, b.args, b.measure = ms, args, true
					measured++
				} else {
					tl.Printf("query %s: measuring on the copy failed: %v", s.QueryID, plainPGError(err))
				}
			}
		}
	}

	var out []*indexadvisor.Result
	for _, c := range cands {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		r := &indexadvisor.Result{Candidate: c, Used: map[string]bool{}}
		out = append(out, r)
		stmt := copyIndexStatement(c.Spec)
		bctx, cancel := context.WithTimeout(ctx, advisorBuildTimeout)
		t0 := time.Now()
		_, err := conn.Exec(bctx, `SELECT set_config('statement_timeout', '0', false)`)
		if err == nil {
			_, err = conn.Exec(bctx, stmt)
		}
		cancel()
		r.BuildMs = time.Since(t0).Milliseconds()
		if _, serr := conn.Exec(ctx, `SELECT set_config('statement_timeout', $1, false)`, advisorExplainTime); serr != nil && err == nil {
			err = serr
		}
		if err != nil {
			r.Err = "Building it on the copy failed: " + plainPGError(err).Error()
			tl.Printf("idea %s: %s", c.Spec.Name, r.Err)
			_, _ = conn.Exec(ctx, "DROP INDEX IF EXISTS "+pgx.Identifier{c.Spec.Schema, c.Spec.Name}.Sanitize())
			continue
		}
		_ = conn.QueryRow(ctx, `SELECT pg_relation_size(to_regclass($1))`, pgx.Identifier{c.Spec.Schema, c.Spec.Name}.Sanitize()).Scan(&r.SizeBytes)
		for _, i := range uses[c.Spec.Schema+"."+c.Spec.Table] {
			b := baseline[i]
			if b == nil || b.err != nil || b.cost <= 0 {
				continue
			}
			s := stmts[i]
			cost, used, err := e.planCost(ctx, s.text, s.Shape.MaxParam, c.Spec.Name)
			if err != nil {
				continue
			}
			g := protocol.IndexGain{QueryID: s.QueryID, CostBefore: b.cost, CostAfter: cost, Calls: s.Calls, TotalTimeMs: s.TotalTimeMs}
			if used && b.measure {
				if ms, err := e.measure(ctx, s.text, b.args); err == nil && ms > 0 {
					g.MsBefore, g.MsAfter = b.ms, ms
				}
			}
			g.Speedup = indexadvisor.GainSpeedup(g)
			if used {
				r.Used[s.QueryID] = true
			}
			r.Gains = append(r.Gains, g)
		}
		tl.Printf("idea %s: %s on the copy, built in %s, used by %d of %d queries",
			c.Spec.Name, humanBytes(r.SizeBytes), plainDuration(time.Duration(r.BuildMs)*time.Millisecond), len(r.Used), len(r.Gains))
		if _, err := conn.Exec(ctx, "DROP INDEX "+pgx.Identifier{c.Spec.Schema, c.Spec.Name}.Sanitize()); err != nil {
			return out, fmt.Errorf("removing a test index from the copy: %w", err)
		}
	}
	return out, nil
}

// copyIndexStatement builds the test index on the copy (not CONCURRENTLY:
// nothing else uses the copy). Names are quoted by pgx.
func copyIndexStatement(s protocol.IndexSpec) string {
	return "CREATE INDEX " + pgx.Identifier{s.Name}.Sanitize() + " ON " + pgx.Identifier{s.Schema, s.Table}.Sanitize() + indexBody(s)
}

// indexBody is " (cols) INCLUDE (...) WHERE ...", every name quoted.
func indexBody(s protocol.IndexSpec) string {
	cols := make([]string, len(s.Columns))
	for i, c := range s.Columns {
		cols[i] = pgx.Identifier{c}.Sanitize()
		if slices.Contains(s.Descending, c) {
			cols[i] += " DESC"
		}
	}
	b := " (" + strings.Join(cols, ", ") + ")"
	if len(s.Include) > 0 {
		inc := make([]string, len(s.Include))
		for i, c := range s.Include {
			inc[i] = pgx.Identifier{c}.Sanitize()
		}
		b += " INCLUDE (" + strings.Join(inc, ", ") + ")"
	}
	var where []string
	for _, c := range sortedStrings(s.WhereNull) {
		where = append(where, pgx.Identifier{c}.Sanitize()+" IS NULL")
	}
	for _, c := range sortedStrings(s.WhereNotNull) {
		where = append(where, pgx.Identifier{c}.Sanitize()+" IS NOT NULL")
	}
	if len(where) > 0 {
		b += " WHERE " + strings.Join(where, " AND ")
	}
	return b
}

func sortedStrings(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// sampleArgs picks a value for every parameter of a statement from the
// copy's planner statistics (a typical value for equality, a recent one for
// ranges; LIMIT 20, OFFSET 0). The values stay on the server: they are only
// used on the copy.
func sampleArgs(ctx context.Context, conn *pgx.Conn, s indexadvisor.Shape, us []*indexadvisor.Usage) ([]string, bool) {
	if s.MaxParam == 0 {
		return nil, true
	}
	args := make([]string, s.MaxParam)
	for p := 1; p <= s.MaxParam; p++ {
		switch p {
		case s.LimitParam:
			args[p-1] = "20"
			continue
		case s.OffsetParam:
			args[p-1] = "0"
			continue
		}
		var col indexadvisor.ColRef
		kind := ""
		for _, pr := range s.Preds {
			if pr.Param == p {
				col, kind = pr.Col, pr.Kind
				break
			}
		}
		if kind == "" {
			return nil, false
		}
		var t *indexadvisor.Table
		for _, u := range us {
			if _, ok := u.Table.Columns[col.Col]; ok && (col.Qual == "" || col.Qual == u.Table.Name || t == nil) {
				t = u.Table
			}
		}
		if t == nil {
			return nil, false
		}
		pos := 0.5
		if kind == indexadvisor.PredRange {
			pos = 0.9
		}
		var v *string
		err := conn.QueryRow(ctx, `
			SELECT coalesce(
			  (SELECT h[greatest(1, ceil(array_length(h, 1) * $4::float8)::int)] FROM (SELECT histogram_bounds::text::text[] AS h) x WHERE h IS NOT NULL),
			  (SELECT m[greatest(1, ceil(array_length(m, 1) * $4::float8)::int)] FROM (SELECT most_common_vals::text::text[] AS m) y WHERE m IS NOT NULL))
			FROM pg_stats WHERE schemaname = $1 AND tablename = $2 AND attname = $3 AND NOT inherited`,
			t.Schema, t.Name, col.Col, pos).Scan(&v)
		if err != nil || v == nil || strings.ContainsRune(*v, 0) {
			return nil, false
		}
		args[p-1] = "'" + strings.ReplaceAll(*v, "'", "''") + "'"
	}
	return args, true
}

// runIndexAdvisor decodes the params and runs the advisor.
func (a *Agent) runIndexAdvisor(ctx context.Context, task *protocol.Task, db protocol.DatabaseSpec, tl *taskLog) (any, error) {
	var p protocol.IndexAdvisorParams
	if len(task.Params) > 0 {
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
		}
	}
	res, err := a.indexAdvisor(ctx, db, task.ID, p, tl)
	if res == nil {
		return nil, err
	}
	return res, err
}
