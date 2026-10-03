package clickhouse

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The index advisor for ClickHouse (protocol.TaskIndexAdvisor). The
// statements that take the most time in system.query_log, and read far more
// rows than they return, are read with one real run each (the query log
// keeps the text with its values; it is only read on this server and run on
// the copy, never sent). Their WHERE and GROUP BY (advisorshape.go) give
// ideas: a skipping index on a column the sorting key doesn't start with, a
// projection sorted by it or pre-aggregating the GROUP BY, and for a table
// with no sorting key at all, one (advice only). Each idea is tested on a
// copy of the tables involved, restored from the latest backup into a
// temporary server: run the samples, add the index or projection and
// MATERIALIZE it, run them again, and keep it only when the rows read drop
// at least 2 times and the queries get faster. Production is only read.

const (
	chAdvisorWindow  = 7 * 24 * time.Hour
	chTopStatements  = 200
	chMaxIdeas       = 12
	chMinReadPerCall = 100_000 // rows read per run
	chMinReadRatio   = 50.0    // rows read per row returned
	chMinGain        = 2.0     // rows read before / after
	chMinMsGain      = 1.5     // time before / after, when measurable
	chMeasurableMs   = 20.0    // runs faster than this are noise
	chRunTimeout     = 60 * time.Second
	chBuildTimeout   = 30 * time.Minute
	chMaxSampleBytes = 64 << 10
)

// chStatement is one normalized query with a real run of it.
type chStatement struct {
	ID       string   `json:"id"`
	Sample   string   `json:"sample"`
	DB       string   `json:"db"`
	Calls    int64    `json:"calls"`
	Ms       float64  `json:"ms"`
	Read     int64    `json:"read"`
	Returned int64    `json:"returned"`
	Tables   []string `json:"tables"`
	Columns  []string `json:"columns"`
	shape    chShape
	table    *advTable
}

// advTable is a MergeTree table as the advisor needs it.
type advTable struct {
	DB           string            `json:"database"`
	Name         string            `json:"name"`
	Engine       string            `json:"engine"`
	SortingKey   string            `json:"sorting_key"`
	PartitionKey string            `json:"partition_key"`
	Rows         int64             `json:"rows"`
	Bytes        int64             `json:"bytes"`
	Columns      map[string]string `json:"-"` // name -> type
	colNames     []string
	skips        []string // expressions of its skipping indexes
	projections  []string
}

func (t *advTable) key() string { return t.DB + "." + t.Name }

// firstKey is the first column of its sorting key ("" for none).
func (t *advTable) firstKey() string {
	k, _, _ := strings.Cut(t.SortingKey, ",")
	return strings.Trim(strings.TrimSpace(k), "`")
}

// plainMergeTree: projections are only suggested for (Replicated)MergeTree
// (on the other engines ClickHouse refuses or rebuilds them on merges).
func (t *advTable) plainMergeTree() bool {
	return t.Engine == "MergeTree" || t.Engine == "ReplicatedMergeTree"
}

// chIdea is one thing to test and the statements it is for.
type chIdea struct {
	spec  protocol.IndexSpec
	key   string
	table *advTable
	stmts []*chStatement
	// fallback: test it only if the idea with this key isn't recommended
	// (a projection sorted by a column is the costly way to do what a
	// skipping index on it may do).
	fallback string
}

func (e *Engine) indexAdvisor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.IndexAdvisorParams, tl agent.TaskLogger) (*protocol.IndexAdvisorResult, error) {
	start := time.Now()
	res := &protocol.IndexAdvisorResult{Generated: []string{}, Recommendations: []protocol.IndexRecommendation{}}
	done := func() (*protocol.IndexAdvisorResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		if res.Summary == "" {
			switch {
			case res.Skipped != "":
				res.Summary = res.Skipped
			case len(res.Recommendations) > 0:
				res.Summary = fmt.Sprintf("%s proven on a copy.", plural(len(res.Recommendations), "idea", "ideas"))
			default:
				res.Summary = fmt.Sprintf("Nothing would help: %s looked at, %s tested on a copy.",
					plural(res.Statements, "query", "queries"), plural(res.Tested, "idea", "ideas"))
			}
		}
		return res, nil
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	login, _, _ := loadLogin(env, db.Port)
	trackUsage(ctx, c, login.User, p.Track, res)
	stmts, err := advisorStatements(ctx, c, login.User, p)
	if err != nil {
		res.Skipped = "Reading the query log (system.query_log) failed: " + shortError(err)
		if errCode(err) == 60 {
			res.Skipped = "ClickHouse's query log is off (log_queries = 0): Rowsafe needs it to find the slow queries to test ideas for."
		}
		return done()
	}
	res.Statements = len(stmts)
	tables, err := advisorTables(ctx, c)
	if err != nil {
		res.Skipped = "Reading the tables failed: " + shortError(err)
		return done()
	}
	ideas := chIdeas(ctx, c, stmts, tables, res)
	known := map[string]bool{}
	for _, k := range p.Known {
		known[k] = true
	}
	var test []*chIdea
	for _, x := range ideas {
		res.Generated = append(res.Generated, x.key)
		if known[x.key] {
			res.Unchanged = append(res.Unchanged, x.key)
		} else if len(test) < chMaxIdeas {
			test = append(test, x)
		}
	}
	if len(test) == 0 {
		return done()
	}
	err = e.withAdvisorCopy(ctx, env, db, taskID, test, res, tl, func(cp *client) {
		recommended := map[string]bool{}
		for _, x := range test {
			if ctx.Err() != nil {
				return
			}
			if x.fallback != "" && (recommended[x.fallback] || known[x.fallback]) {
				continue
			}
			if testChIdea(ctx, cp, x, res, tl) {
				recommended[x.key] = true
			}
		}
	})
	if err != nil && res.Skipped == "" {
		res.Skipped = "Testing on a copy failed: " + firstLine(err.Error())
	}
	slices.SortFunc(res.Recommendations, func(a, b protocol.IndexRecommendation) int { return cmp.Compare(b.Speedup, a.Speedup) })
	return done()
}

// advisorStatements reads the SELECTs worth an idea from the query log:
// the ones the control plane listed (by query ID), or the busiest of the
// last week, that read far more rows than they return; each with its
// slowest run as the sample.
func advisorStatements(ctx context.Context, c *client, self string, p protocol.IndexAdvisorParams) ([]*chStatement, error) {
	want := map[string]protocol.AdvisorStatement{}
	for _, st := range p.Statements {
		want[st.QueryID] = st
	}
	rows, err := query[chStatement](ctx, c, `
		SELECT toString(reinterpretAsInt64(normalized_query_hash)) AS id, argMax(query, query_duration_ms) AS sample,
		       any(current_database) AS db, toInt64(count()) AS calls, toFloat64(sum(query_duration_ms)) AS ms,
		       toInt64(sum(read_rows)) AS read, toInt64(sum(result_rows)) AS returned,
		       arrayDistinct(flatten(groupArray(tables))) AS tables, arrayDistinct(flatten(groupArray(columns))) AS columns
		FROM system.query_log
		WHERE type = 'QueryFinish' AND is_initial_query AND query_kind = 'Select' AND user != {user:String}
		  AND http_user_agent != {agent:String} AND event_time >= now() - INTERVAL {days:UInt32} DAY
		  AND length(query) < {max:UInt32}
		GROUP BY normalized_query_hash
		ORDER BY ms DESC LIMIT {top:UInt32}`,
		map[string]string{"user": self, "agent": userAgent, "days": strconv.Itoa(int(chAdvisorWindow.Hours() / 24)),
			"max": strconv.Itoa(chMaxSampleBytes), "top": strconv.Itoa(chTopStatements)},
		"max_execution_time", "120")
	if err != nil {
		return nil, err
	}
	var out []*chStatement
	for i := range rows {
		x := &rows[i]
		if w, ok := want[x.ID]; ok { // the control plane's figures cover the window it looked at
			x.Calls, x.Ms = w.Calls, w.TotalTimeMs
		} else if len(want) > 0 {
			continue
		}
		if x.Calls == 0 || x.Read/max(x.Calls, 1) < chMinReadPerCall || float64(x.Read) < chMinReadRatio*float64(max(x.Returned, x.Calls)) {
			continue
		}
		out = append(out, x)
	}
	return out, nil
}

// advisorTables reads every user MergeTree table with its columns, skipping
// indexes and projections.
func advisorTables(ctx context.Context, c *client) (map[string]*advTable, error) {
	rows, err := query[advTable](ctx, c, `
		SELECT database, name, engine, sorting_key, partition_key, toInt64(ifNull(total_rows, 0)) AS rows,
		       toInt64(ifNull(total_bytes, 0)) AS bytes
		FROM system.tables
		WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') AND engine LIKE '%MergeTree' AND NOT is_temporary`, nil)
	if err != nil {
		return nil, err
	}
	out := map[string]*advTable{}
	for i := range rows {
		t := &rows[i]
		t.Columns = map[string]string{}
		out[t.key()] = t
	}
	type colRow struct {
		DB    string `json:"database"`
		Table string `json:"table"`
		Name  string `json:"name"`
		Type  string `json:"type"`
		Kind  string `json:"default_kind"`
	}
	cols, err := query[colRow](ctx, c, `SELECT database, table, name, type, default_kind FROM system.columns
		WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') ORDER BY database, table, position`, nil)
	if err != nil {
		return nil, err
	}
	for _, col := range cols {
		if t := out[col.DB+"."+col.Table]; t != nil {
			t.Columns[col.Name] = col.Type
			t.colNames = append(t.colNames, col.Name)
		}
	}
	type skipRow struct {
		DB    string `json:"database"`
		Table string `json:"table"`
		Expr  string `json:"expr"`
	}
	skips, err := query[skipRow](ctx, c, `SELECT database, table, expr FROM system.data_skipping_indices`, nil)
	if err != nil {
		return nil, err
	}
	for _, s := range skips {
		if t := out[s.DB+"."+s.Table]; t != nil {
			t.skips = append(t.skips, strings.Trim(s.Expr, "`"))
		}
	}
	projs, err := listProjections(ctx, c)
	if err != nil {
		return nil, err
	}
	for k, names := range projs {
		if t := out[k]; t != nil {
			t.projections = names
		}
	}
	return out, nil
}

// listProjections are the projections defined on each table ("db.name"),
// read from the tables' definitions (system.projections only exists from
// 25.x).
func listProjections(ctx context.Context, c *client) (map[string][]string, error) {
	type row struct {
		DB     string `json:"database"`
		Name   string `json:"name"`
		Create string `json:"create_table_query"`
	}
	rows, err := query[row](ctx, c, `SELECT database, name, create_table_query FROM system.tables
		WHERE engine LIKE '%MergeTree' AND position(create_table_query, 'PROJECTION') > 0`, nil)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, r := range rows {
		toks, ok := tokenize(r.Create)
		if !ok {
			continue
		}
		for i := 0; i+1 < len(toks); i++ {
			if toks[i].is("projection") && (toks[i+1].kind == tIdent || toks[i+1].kind == tQIdent) && i+2 < len(toks) && toks[i+2].op("(") {
				out[r.DB+"."+r.Name] = append(out[r.DB+"."+r.Name], toks[i+1].text)
			}
		}
	}
	return out, nil
}

// chIdeas parses the statements and builds the ideas, leaving out what
// the table already has.
func chIdeas(ctx context.Context, c *client, stmts []*chStatement, tables map[string]*advTable, res *protocol.IndexAdvisorResult) []*chIdea {
	byKey := map[string]*chIdea{}
	var order []*chIdea
	add := func(st *chStatement, spec protocol.IndexSpec, fallback string) string {
		spec.DB, spec.Schema, spec.Table = st.table.DB, st.table.DB, st.table.Name
		spec.Name = protocol.IndexName(spec)
		key := spec.Key()
		x := byKey[key]
		if x == nil {
			x = &chIdea{spec: spec, key: key, table: st.table, fallback: fallback}
			byKey[key] = x
			order = append(order, x)
		}
		if !slices.Contains(x.stmts, st) {
			x.stmts = append(x.stmts, st)
		}
		return key
	}
	for _, st := range stmts {
		text := st.Sample
		// ClickHouse's own formatting, when it has it (23.10+): one way of
		// writing every query. Read on this server only.
		if f, err := c.scalar(ctx, "SELECT formatQuery({q:String})", map[string]string{"q": st.Sample}); err == nil && f != "" {
			text = f
		}
		shape, ok := parseShape(text, func(db, name string) []string {
			if t := tables[cmpOr(db, st.DB)+"."+name]; t != nil {
				return t.colNames
			}
			return nil
		})
		if !ok {
			continue
		}
		t := tables[cmpOr(shape.DB, st.DB)+"."+shape.Table]
		if t == nil {
			continue
		}
		st.shape, st.table = shape, t
		res.Analyzed++
		// Skipping indexes, one per column the sorting key doesn't start with.
		skipFor := map[string]string{}
		for _, col := range shape.filterColumns() {
			if col == t.firstKey() || slices.Contains(t.skips, col) {
				continue
			}
			typ, gran := skipType(shape, col, t.Columns[col])
			if typ == "" {
				continue
			}
			skipFor[col] = add(st, protocol.IndexSpec{Kind: protocol.IndexKindSkip, Columns: []string{col}, Type: typ, Granularity: gran}, "")
		}
		if t.SortingKey == "" && t.Engine == "MergeTree" && len(shape.Eq)+len(shape.Range) > 0 {
			// No sorting key: say which one it should have (advice only).
			key := slices.Concat(shape.Eq, shape.Range)
			add(st, protocol.IndexSpec{Kind: protocol.IndexKindOrderBy, Columns: key[:min(len(key), 3)]}, "")
		}
		if !t.plainMergeTree() || shape.Final {
			continue
		}
		if shape.Agg {
			// A projection that keeps the aggregates by the GROUP BY and
			// filter columns.
			group := slices.Clone(shape.GroupBy)
			for _, col := range slices.Concat(shape.Eq, shape.Range) {
				if !slices.Contains(group, col) {
					group = append(group, col)
				}
			}
			if len(shape.Like)+len(shape.Token) == 0 && len(group) <= 6 {
				add(st, protocol.IndexSpec{Kind: protocol.IndexKindProjection, GroupBy: group, Aggregates: shape.Aggregates}, "")
			}
			continue
		}
		// A projection sorted by the most selective filter column, keeping
		// only the columns the query uses: tested only when the skipping
		// index on it didn't do the job.
		var sortBy []string
		if len(shape.Eq) > 0 {
			sortBy = []string{shape.Eq[0]}
		} else if len(shape.Range) > 0 {
			sortBy = []string{shape.Range[0]}
		}
		if len(sortBy) == 0 || sortBy[0] == t.firstKey() {
			continue
		}
		var keep []string
		prefix := t.key() + "."
		for _, col := range st.Columns {
			if name, ok := strings.CutPrefix(col, prefix); ok && t.Columns[name] != "" && !slices.Contains(keep, name) {
				keep = append(keep, name)
			}
		}
		if len(keep) == 0 || len(keep) >= len(t.colNames) {
			keep = nil // every column
		} else {
			slices.SortFunc(keep, func(a, b string) int { return cmp.Compare(slices.Index(t.colNames, a), slices.Index(t.colNames, b)) })
		}
		add(st, protocol.IndexSpec{Kind: protocol.IndexKindProjection, Columns: sortBy, Include: keep}, skipFor[sortBy[0]])
	}
	// Bigger wins first: the ideas for the busiest statements.
	weight := func(x *chIdea) float64 {
		var ms float64
		for _, st := range x.stmts {
			ms += st.Ms
		}
		return ms
	}
	slices.SortStableFunc(order, func(a, b *chIdea) int {
		// A fallback after the idea it backs up.
		if a.fallback == b.key {
			return 1
		}
		if b.fallback == a.key {
			return -1
		}
		return cmp.Compare(weight(b), weight(a))
	})
	return order
}

// skipType picks the skipping index for a condition on col of type typ:
// minmax for ranges, set for few distinct values, bloom_filter for
// equality and has(), tokenbf_v1 for hasToken, ngrambf_v1 for LIKE.
func skipType(s chShape, col, typ string) (string, int) {
	base := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(typ, "Nullable("), ")"), "LowCardinality("), ")")
	base = strings.TrimSuffix(strings.TrimPrefix(base, "Nullable("), ")")
	text := base == "String" || strings.HasPrefix(base, "FixedString")
	switch {
	case slices.Contains(s.Token, col) && text:
		return "tokenbf_v1(8192, 3, 0)", 1
	case slices.Contains(s.Like, col) && text:
		return "ngrambf_v1(3, 8192, 3, 0)", 1
	case slices.Contains(s.Eq, col):
		if strings.HasPrefix(typ, "LowCardinality(") || strings.HasPrefix(base, "Enum") || base == "Bool" || base == "UInt8" || base == "Int8" {
			return "set(100)", 4
		}
		if strings.HasPrefix(base, "Map(") || strings.HasPrefix(base, "Tuple(") || strings.HasPrefix(base, "Nested") {
			return "", 0
		}
		return "bloom_filter(0.01)", 4
	case slices.Contains(s.Range, col):
		if text || strings.HasPrefix(base, "Array(") || strings.HasPrefix(base, "Map(") {
			return "", 0
		}
		return "minmax", 1
	}
	return "", 0
}

// withAdvisorCopy restores the tables the ideas need into a temporary
// server, runs fn on it and removes it.
func (e *Engine) withAdvisorCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, ideas []*chIdea, res *protocol.IndexAdvisorResult, tl agent.TaskLogger, fn func(*client)) error {
	if _, _, err := clickhouseBinary(); err != nil {
		res.Skipped = "Rowsafe can't start a temporary ClickHouse server here to test ideas on: " + err.Error()
		return nil
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	b, err := pickBackup(ctx, r, restoreTarget{Latest: true})
	if err != nil {
		res.Skipped = "There is no backup yet to restore a copy from."
		return nil
	}
	need, sized := map[string]bool{}, map[string]bool{}
	var bytes int64
	for _, x := range ideas {
		for _, st := range x.stmts {
			for _, t := range st.Tables {
				need[t] = true
			}
		}
		if !sized[x.table.key()] {
			sized[x.table.key()] = true
			bytes += x.table.Bytes
		}
	}
	missing := 0
	for _, x := range ideas {
		found := false
		for _, t := range b.Tables {
			found = found || t.key() == x.table.key()
		}
		if !found {
			missing++
		}
	}
	if missing == len(ideas) {
		res.Skipped = "The tables to test ideas on aren't in the latest backup yet."
		return nil
	}
	root := filepath.Join(env.Config.DrillDir, "clickhouse")
	// Each idea is built once on the copy: room for the tables, twice over.
	if err := ensureSpace(filepath.Dir(root), bytes*2+512<<20); err != nil {
		res.Skipped = "Not enough free disk for a copy to test the ideas on: " + err.Error()
		return nil
	}
	began := time.Now()
	s, err := newScratch(root, "advisor-"+taskID, b.Macros, b.needsKeeper())
	if err != nil {
		return err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the index advisor's copy failed", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("starting a temporary ClickHouse server in %s (127.0.0.1 only) to test %s", s.Dir, plural(len(ideas), "idea", "ideas"))
	cp, err := s.start(ctx, env)
	if err != nil {
		return err
	}
	if err := restoreOnly(ctx, env, r, b, cp, need, tl); err != nil {
		return err
	}
	res.CopySeconds = time.Since(began).Seconds()
	tl.Printf("copy restored from backup %s in %s", b.Label, time.Since(began).Round(time.Second))
	fn(cp)
	return nil
}

// chRun is one measured run of a sample on the copy.
type chRun struct {
	rows int64
	ms   float64
}

// runSample runs a statement's sample on the copy and returns the best of
// three runs (the first one warms the cache).
func runSample(ctx context.Context, cp *client, st *chStatement) (chRun, error) {
	var best chRun
	for i := range 3 {
		r, err := runOnce(ctx, cp, st)
		if err != nil {
			return chRun{}, err
		}
		if i == 0 || r.ms < best.ms {
			best.ms = r.ms
		}
		best.rows = r.rows
	}
	return best, nil
}

func runOnce(ctx context.Context, cp *client, st *chStatement) (chRun, error) {
	rctx, cancel := context.WithTimeout(ctx, chRunTimeout+10*time.Second)
	defer cancel()
	began := time.Now()
	resp, err := cp.request(rctx, st.Sample, nil, map[string]string{"wait_end_of_query": "1", "database": st.DB,
		"max_execution_time": strconv.Itoa(int(chRunTimeout.Seconds())), "use_query_cache": "0",
		"default_format": "Null", "log_queries": "0"}, nil)
	if err != nil {
		return chRun{}, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if err := midStreamError(b); err != nil {
		return chRun{}, err
	}
	run := chRun{ms: float64(time.Since(began).Microseconds()) / 1000}
	var sum struct {
		ReadRows  string `json:"read_rows"`
		ElapsedNs string `json:"elapsed_ns"`
	}
	if json.Unmarshal([]byte(resp.Header.Get("X-ClickHouse-Summary")), &sum) == nil {
		run.rows, _ = strconv.ParseInt(sum.ReadRows, 10, 64)
		if ns, err := strconv.ParseInt(sum.ElapsedNs, 10, 64); err == nil && ns > 0 {
			run.ms = float64(ns) / 1e6
		}
	}
	return run, nil
}

// testChIdea measures the idea's statements on the copy without and with
// it; true when it is recommended.
func testChIdea(ctx context.Context, cp *client, x *chIdea, res *protocol.IndexAdvisorResult, tl agent.TaskLogger) bool {
	res.Tested++
	reject := func(reason string) bool {
		tl.Printf("%s: %s", describeSpec(x.spec), reason)
		res.Rejected = append(res.Rejected, protocol.RejectedIndex{Spec: x.spec, Key: x.key, Reason: reason})
		return false
	}
	pre := make([]*chRun, len(x.stmts))
	ran := 0
	for i, st := range x.stmts {
		r, err := runSample(ctx, cp, st)
		if err != nil {
			tl.Printf("query %s doesn't run on the copy: %s", st.ID, shortError(err))
			continue
		}
		pre[i] = &r
		ran++
	}
	if ran == 0 {
		return reject("its queries don't run on the copy")
	}
	bctx, cancel := context.WithTimeout(ctx, chBuildTimeout)
	defer cancel()
	began := time.Now()
	undo, err := buildOnCopy(bctx, cp, x)
	if undo != nil {
		defer undo(context.WithoutCancel(ctx))
	}
	if err != nil {
		return reject("building it on the copy failed: " + shortError(err))
	}
	rec := protocol.IndexRecommendation{Spec: x.spec, Key: x.key, BuildMs: time.Since(began).Milliseconds(),
		TableBytes: x.table.Bytes, TableRows: x.table.Rows}
	rec.SizeBytes = sizeOnCopy(ctx, cp, x.spec)
	var weighted, timeSum float64
	for i, st := range x.stmts {
		if pre[i] == nil {
			continue
		}
		if x.spec.Kind != protocol.IndexKindOrderBy {
			plan, err := cp.scalar(ctx, "EXPLAIN indexes = 1 "+st.Sample, nil, "database", st.DB)
			if err != nil || !strings.Contains(plan, x.spec.Name) {
				tl.Printf("query %s: ClickHouse doesn't use %s for it", st.ID, x.spec.Name)
				continue
			}
		}
		after, err := runSample(ctx, cp, st)
		if err != nil {
			continue
		}
		g := protocol.IndexGain{QueryID: st.ID, RowsBefore: pre[i].rows, RowsAfter: after.rows, MsBefore: pre[i].ms, MsAfter: after.ms,
			Calls: st.Calls, TotalTimeMs: st.Ms}
		tl.Printf("query %s on the copy: %s rows read in %.1f ms before, %s rows in %.1f ms after", st.ID, commas(g.RowsBefore), g.MsBefore,
			commas(g.RowsAfter), g.MsAfter)
		rowsGain := float64(max(g.RowsBefore, 1)) / float64(max(g.RowsAfter, 1))
		msGain := g.MsBefore / max(g.MsAfter, 1) // under a millisecond is noise
		measurable := g.MsBefore >= chMeasurableMs
		if rowsGain < chMinGain || measurable && msGain < chMinMsGain {
			continue
		}
		g.Speedup = min(rowsGain, 100) // an estimate from the rows read alone
		if measurable {
			g.Speedup = msGain
		}
		rec.Statements = append(rec.Statements, g)
		weighted += g.Speedup * st.Ms
		timeSum += st.Ms
	}
	if len(rec.Statements) == 0 {
		return reject(fmt.Sprintf("on the copy, ClickHouse either didn't use it or it didn't cut the rows read at least %.0f times", chMinGain))
	}
	rec.Speedup = weighted / max(timeSum, 1e-9)
	tl.Printf("%s: %.1fx faster for %s", describeSpec(x.spec), rec.Speedup, plural(len(rec.Statements), "query", "queries"))
	res.Recommendations = append(res.Recommendations, rec)
	return true
}

// buildOnCopy adds the idea to the copy's table; undo removes it.
func buildOnCopy(ctx context.Context, cp *client, x *chIdea) (undo func(context.Context), err error) {
	s := x.spec
	t := tableName(s.DB, s.Table)
	// Merges are stopped on a copy; mutations (MATERIALIZE) need them.
	_ = cp.exec(ctx, "SYSTEM START MERGES "+t, nil)
	stop := func(ctx context.Context) { _ = cp.exec(ctx, "SYSTEM STOP MERGES "+t, nil) }
	switch s.Kind {
	case protocol.IndexKindSkip, protocol.IndexKindProjection:
		stmts := s.ClickHouseStatements()
		drop := "ALTER TABLE " + t + " DROP INDEX " + quoteIdent(s.Name)
		if s.Kind == protocol.IndexKindProjection {
			drop = "ALTER TABLE " + t + " DROP PROJECTION " + quoteIdent(s.Name)
		}
		if err := cp.exec(ctx, stmts[0], nil); err != nil {
			stop(ctx)
			return nil, err
		}
		undo = func(ctx context.Context) {
			_ = cp.exec(ctx, drop, nil, "mutations_sync", "1")
			stop(ctx)
		}
		return undo, cp.exec(ctx, stmts[1], nil, "mutations_sync", "1")
	case protocol.IndexKindOrderBy:
		sorted, orig := tableName(s.DB, s.Table+"__rs_sorted"), tableName(s.DB, s.Table+"__rs_orig")
		create := fmt.Sprintf("CREATE TABLE %s AS %s ENGINE = MergeTree", sorted, t)
		if x.table.PartitionKey != "" {
			create += " PARTITION BY " + x.table.PartitionKey // the server's own expression, on the copy only
		}
		cols := make([]string, len(s.Columns))
		for i, c := range s.Columns {
			cols[i] = quoteIdent(c)
		}
		create += " ORDER BY (" + strings.Join(cols, ", ") + ")"
		stop(ctx)
		if err := cp.exec(ctx, create, nil); err != nil {
			return nil, err
		}
		undo = func(ctx context.Context) { _ = cp.exec(ctx, "DROP TABLE IF EXISTS "+sorted+" SYNC", nil) }
		if err := cp.exec(ctx, "INSERT INTO "+sorted+" SELECT * FROM "+t, nil); err != nil {
			return undo, err
		}
		if err := cp.exec(ctx, "OPTIMIZE TABLE "+sorted+" FINAL", nil); err != nil {
			return undo, err
		}
		if err := cp.exec(ctx, fmt.Sprintf("RENAME TABLE %s TO %s, %s TO %s", t, orig, sorted, t), nil); err != nil {
			return undo, err
		}
		return func(ctx context.Context) {
			_ = cp.exec(ctx, fmt.Sprintf("RENAME TABLE %s TO %s, %s TO %s", t, sorted, orig, t), nil)
			_ = cp.exec(ctx, "DROP TABLE IF EXISTS "+sorted+" SYNC", nil)
		}, nil
	}
	return nil, errors.New("unknown idea")
}

// sizeOnCopy is the disk the index or projection takes on the copy.
func sizeOnCopy(ctx context.Context, cp *client, s protocol.IndexSpec) int64 {
	var q string
	switch s.Kind {
	case protocol.IndexKindSkip:
		q = `SELECT toInt64(sum(data_compressed_bytes)) FROM system.data_skipping_indices WHERE database = {db:String} AND table = {t:String} AND name = {n:String}`
	case protocol.IndexKindProjection:
		q = `SELECT toInt64(sum(bytes_on_disk)) FROM system.projection_parts WHERE database = {db:String} AND table = {t:String} AND name = {n:String} AND active`
	default:
		return 0
	}
	v, err := cp.scalar(ctx, q, map[string]string{"db": s.DB, "t": s.Table, "n": s.Name})
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(v, 10, 64)
	return n
}

// describeSpec names an idea in the task log.
func describeSpec(s protocol.IndexSpec) string {
	switch s.Kind {
	case protocol.IndexKindSkip:
		return fmt.Sprintf("skipping index %s (%s on %s.%s.%s)", s.Name, s.Type, s.DB, s.Table, strings.Join(s.Columns, ","))
	case protocol.IndexKindProjection:
		return fmt.Sprintf("projection %s on %s.%s (%s)", s.Name, s.DB, s.Table, s.ProjectionQuery())
	case protocol.IndexKindOrderBy:
		return fmt.Sprintf("sorting %s.%s by (%s)", s.DB, s.Table, strings.Join(s.Columns, ", "))
	}
	return s.Name
}

// trackUsage reports the indexes and projections Rowsafe created: whether
// they exist, their size, and how many queries of the last week they helped
// (projections: from the query log; skipping indexes: the runs of the
// queries on their table whose plan skips data with it).
func trackUsage(ctx context.Context, c *client, self string, track []protocol.TrackedIndex, res *protocol.IndexAdvisorResult) {
	if len(track) == 0 {
		return
	}
	found, err := rowsafeObjects(ctx, c)
	if err != nil {
		return
	}
	for _, t := range track {
		u := protocol.IndexUsage{TrackedIndex: t}
		if o, ok := found[t.DB+"."+t.Index]; ok {
			u.Exists, u.Valid, u.SizeBytes = true, true, o.bytes
			if n, ok := objectUse(ctx, c, self, o); ok {
				u.Scans = n
			}
		}
		res.Usage = append(res.Usage, u)
	}
}

// chObject is a skipping index or projection.
type chObject struct {
	db, table, name string
	projection      bool
	bytes           int64
	definition      string
}

// rowsafeObjects are the skipping indexes and projections whose names
// Rowsafe would give ("rs_..."), by "db.name".
func rowsafeObjects(ctx context.Context, c *client) (map[string]chObject, error) {
	all, err := skipAndProjections(ctx, c)
	if err != nil {
		return nil, err
	}
	out := map[string]chObject{}
	for _, o := range all {
		if protocol.ValidIndexName(o.name) {
			out[o.db+"."+o.name] = o
		}
	}
	return out, nil
}

// skipAndProjections lists every skipping index and projection of user
// tables with its size.
func skipAndProjections(ctx context.Context, c *client) ([]chObject, error) {
	type skipRow struct {
		DB    string `json:"database"`
		Table string `json:"table"`
		Name  string `json:"name"`
		Type  string `json:"type_full"`
		Expr  string `json:"expr"`
		Gran  int64  `json:"granularity"`
		Bytes int64  `json:"bytes"`
	}
	skips, err := query[skipRow](ctx, c, `SELECT database, table, name, type_full, expr, toInt64(granularity) AS granularity,
		toInt64(data_compressed_bytes) AS bytes FROM system.data_skipping_indices
		WHERE database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')`, nil)
	if err != nil {
		return nil, err
	}
	var out []chObject
	for _, s := range skips {
		out = append(out, chObject{db: s.DB, table: s.Table, name: s.Name, bytes: s.Bytes,
			definition: fmt.Sprintf("INDEX %s %s TYPE %s GRANULARITY %d", quoteIdent(s.Name), s.Expr, s.Type, s.Gran)})
	}
	projs, err := listProjections(ctx, c)
	if err != nil {
		return nil, err
	}
	type sizeRow struct {
		DB    string `json:"database"`
		Table string `json:"table"`
		Name  string `json:"name"`
		Bytes int64  `json:"bytes"`
	}
	sizes, err := query[sizeRow](ctx, c, `SELECT database, table, name, toInt64(sum(bytes_on_disk)) AS bytes
		FROM system.projection_parts WHERE active GROUP BY database, table, name`, nil)
	if err != nil {
		return nil, err
	}
	for k, names := range projs {
		db, table, _ := strings.Cut(k, ".")
		for _, n := range names {
			o := chObject{db: db, table: table, name: n, projection: true, definition: "PROJECTION " + quoteIdent(n)}
			for _, s := range sizes {
				if s.DB == db && s.Table == table && s.Name == n {
					o.bytes = s.Bytes
				}
			}
			out = append(out, o)
		}
	}
	return out, nil
}

// objectUse counts the runs of the last week that used o: from the query
// log's projections for a projection; for a skipping index, the runs of the
// queries on its table whose plan skips granules with it (ok is false when
// there are too many different queries to check).
func objectUse(ctx context.Context, c *client, self string, o chObject) (int64, bool) {
	params := map[string]string{"t": o.db + "." + o.table, "p": o.db + "." + o.table + "." + o.name, "user": self, "agent": userAgent,
		"days": strconv.Itoa(int(chAdvisorWindow.Hours() / 24))}
	if o.projection {
		v, err := c.scalar(ctx, `SELECT count() FROM system.query_log WHERE type = 'QueryFinish' AND has(projections, {p:String})
			AND event_time >= now() - INTERVAL {days:UInt32} DAY`, params, "max_execution_time", "60")
		if err != nil {
			return 0, false
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		return n, true
	}
	type row struct {
		Sample string `json:"sample"`
		DB     string `json:"db"`
		Calls  int64  `json:"calls"`
	}
	rows, err := query[row](ctx, c, `SELECT any(query) AS sample, any(current_database) AS db, toInt64(count()) AS calls
		FROM system.query_log
		WHERE type = 'QueryFinish' AND is_initial_query AND query_kind = 'Select' AND has(tables, {t:String})
		  AND user != {user:String} AND http_user_agent != {agent:String} AND event_time >= now() - INTERVAL {days:UInt32} DAY
		GROUP BY normalized_query_hash ORDER BY calls DESC LIMIT 51`, params, "max_execution_time", "60")
	if err != nil || len(rows) > 50 {
		return 0, false
	}
	var used int64
	for _, r := range rows {
		plan, err := c.scalar(ctx, "EXPLAIN indexes = 1 "+r.Sample, nil, "database", r.DB, "max_execution_time", "30")
		if err != nil {
			return 0, false // can't tell: never call it unused
		}
		if skipsWith(plan, o.name) {
			used += r.Calls
		}
	}
	return used, true
}

// skipsWith reports whether an EXPLAIN indexes = 1 plan has the skipping
// index name select fewer granules than it was given.
func skipsWith(plan, name string) bool {
	lines := strings.Split(plan, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "Name: "+name {
			continue
		}
		for _, next := range lines[i+1 : min(i+6, len(lines))] {
			if g, ok := strings.CutPrefix(strings.TrimSpace(next), "Granules: "); ok {
				a, b, _ := strings.Cut(g, "/")
				x, _ := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
				y, _ := strconv.ParseInt(strings.TrimSpace(b), 10, 64)
				return x < y
			}
		}
	}
	return false
}

// unusedObjects are the skipping indexes and projections no query used in
// the last week (at least 10 MB each, at most 20 checked). Nothing is
// reported unless the query log covers that whole week, and a projection
// only when its table's definition is older than that.
func unusedObjects(ctx context.Context, c *client, self string, now time.Time) []protocol.UnusedIndex {
	out := []protocol.UnusedIndex{}
	v, err := c.scalar(ctx, "SELECT toUnixTimestamp(min(event_time)) FROM system.query_log", nil, "max_execution_time", "60")
	if err != nil {
		return out
	}
	first, _ := strconv.ParseInt(v, 10, 64)
	since := time.Unix(first, 0).UTC()
	if first == 0 || now.Sub(since) < chAdvisorWindow {
		return out
	}
	objs, err := skipAndProjections(ctx, c)
	if err != nil {
		return out
	}
	type changed struct {
		DB   string `json:"database"`
		Name string `json:"name"`
	}
	recent, _ := query[changed](ctx, c, `SELECT database, name FROM system.tables
		WHERE metadata_modification_time >= now() - INTERVAL {days:UInt32} DAY`, map[string]string{"days": strconv.Itoa(int(chAdvisorWindow.Hours() / 24))})
	young := map[string]bool{}
	for _, r := range recent {
		young[r.DB+"."+r.Name] = true
	}
	slices.SortFunc(objs, func(a, b chObject) int { return cmp.Compare(b.bytes, a.bytes) })
	checked := 0
	windowStart := now.Add(-chAdvisorWindow)
	for _, o := range objs {
		if o.bytes < 10<<20 || checked >= 20 || o.projection && young[o.db+"."+o.table] {
			continue
		}
		checked++
		if n, ok := objectUse(ctx, c, self, o); ok && n == 0 {
			out = append(out, protocol.UnusedIndex{Database: o.db, Schema: o.db, Table: o.table, Index: o.name, Bytes: o.bytes,
				Definition: o.definition, StatsSince: &windowStart})
		}
	}
	return out
}
