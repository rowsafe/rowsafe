package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The index advisor for SQLite (protocol.TaskIndexAdvisor). SQLite keeps
// no query statistics, so the ideas come from the schema: one index for
// each foreign key whose child columns no index starts with. Each new idea
// is built on a copy restored from the backups (never production): its
// build time and size are measured, and SQLite must use it for the key's
// lookup (the child rows with one key, which a delete of a parent row
// makes when the app turns foreign keys on) and make it faster. Sample key
// values are read on the copy and never leave the server.

const (
	// adviceSamples is how many keys the lookups are timed with.
	adviceSamples = 10
	// adviceMaxIdeas bounds the ideas tested in one run.
	adviceMaxIdeas = 20
)

func (e *Engine) indexAdvisor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.IndexAdvisorParams, tl agent.TaskLogger) (*protocol.IndexAdvisorResult, error) {
	start := time.Now()
	// SQLite keeps no query statistics: one idea for each foreign key
	// without an index, from the whole schema.
	res := &protocol.IndexAdvisorResult{Generated: []string{}, Recommendations: []protocol.IndexRecommendation{}, SchemaBased: true}
	done := func() (*protocol.IndexAdvisorResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		res.Summary = adviceSummary(res)
		tl.Printf("%s", res.Summary)
		return res, nil
	}
	c, err := openDB(ctx, db.SocketDir, openOpts{Busy: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	restore := withInterrupt(ctx, c)
	journal, _ := journalMode(c)
	budget := 5 * time.Second
	if journal != "wal" {
		budget = 0
	}
	schema, err := readSchema(ctx, c, budget)
	if err == nil {
		res.Usage = trackedUsage(c, p.Track)
	}
	restore()
	c.Close()
	if err != nil {
		e.busyFor(db.ID).note(err)
		return nil, fmt.Errorf("reading the schema: %w", err)
	}
	known := map[string]bool{}
	for _, k := range p.Known {
		known[k] = true
	}
	var todo []fkIdea
	for _, x := range schema.unindexedFKs() {
		if x.table.Rows >= 0 && x.table.Rows < fkMinRows {
			continue // read in a moment without an index
		}
		spec := x.spec()
		key := spec.Key()
		res.Generated = append(res.Generated, key)
		if known[key] {
			res.Unchanged = append(res.Unchanged, key)
			continue
		}
		if len(todo) < adviceMaxIdeas {
			todo = append(todo, x)
		}
	}
	tl.Printf("%s without an index on tables of %d rows or more; %d to test on a copy", plural(len(res.Generated), "foreign key", "foreign keys"), fkMinRows, len(todo))
	if len(todo) == 0 {
		return done()
	}

	// The copy: the newest point in the bucket, in the agent's drill folder.
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	if _, _, err := pickSnapshot(ctx, r, restoreTarget{Latest: true}); err != nil {
		res.Skipped = "Rowsafe tests each index on a copy restored from your backups, and there is no backup of this database yet."
		tl.Printf("not tested: %v", err)
		return done()
	}
	if s := e.existingShipper(db.ID); s != nil {
		if _, err := s.flush(ctx, time.Minute); err != nil {
			tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", err)
		}
	}
	dir := filepath.Join(drillRoot(env), "index-"+safeName(taskID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "copy.db")
	t0 := time.Now()
	if _, err := restoreTo(ctx, r, restoreTarget{Latest: true}, path, tl); err != nil {
		if strings.Contains(err.Error(), "not enough room") {
			res.Skipped = "There isn't enough free disk on the server for a copy of the database to test the indexes on: " + err.Error()
			return done()
		}
		return nil, fmt.Errorf("restoring a copy to test the indexes on: %w", err)
	}
	res.CopySeconds = time.Since(t0).Seconds()
	cp, err := openDB(ctx, path, openOpts{Scratch: true, Busy: time.Second})
	if err != nil {
		return nil, err
	}
	defer cp.Close()
	defer withInterrupt(ctx, cp)()
	// The copy is private: no journal to keep, and a cache big enough.
	_ = cp.Exec(`PRAGMA journal_mode = OFF`)
	_ = cp.Exec(`PRAGMA synchronous = OFF`)
	for _, x := range todo {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res.Tested++
		testIdea(cp, x, res, tl)
	}
	return done()
}

// testIdea builds x's index on the copy and measures it.
func testIdea(cp *sqlite3.Conn, x fkIdea, res *protocol.IndexAdvisorResult, tl agent.TaskLogger) {
	spec := x.spec()
	reject := func(why string) {
		tl.Printf("%s (%s): %s", x.table.Name, strings.Join(spec.Columns, ", "), why)
		res.Rejected = append(res.Rejected, protocol.RejectedIndex{Spec: spec, Key: spec.Key(), Reason: why})
	}
	tbl := "main." + quoteIdent(spec.Table)
	var where []string
	quoted := make([]string, len(spec.Columns))
	for i, col := range spec.Columns {
		quoted[i] = quoteIdent(col)
		where = append(where, quoted[i]+" = ?")
	}
	lookup := "SELECT count(*) FROM " + tbl + " WHERE " + strings.Join(where, " AND ")
	rows, err := queryInt(cp, "SELECT count(*) FROM "+tbl)
	if err != nil {
		reject("the table isn't in the copy as it is in production (changed since the newest backup?)")
		return
	}
	if rows < fkMinRows {
		reject(fmt.Sprintf("the table has %d rows on the copy: SQLite reads it in a moment without an index", rows))
		return
	}
	keys, err := sampleKeys(cp, tbl, quoted, rows)
	if err != nil || len(keys) == 0 {
		reject("no row of the table points to another row, so there is nothing to look up")
		return
	}
	before, matches, err := timeLookups(cp, lookup, keys)
	if err != nil {
		reject("the lookup failed on the copy: " + firstLine(err.Error()))
		return
	}
	used := func() (int64, error) {
		free, err := queryInt(cp, `PRAGMA main.freelist_count`)
		if err != nil {
			return 0, err
		}
		pages, err := queryInt(cp, `PRAGMA main.page_count`)
		return pages - free, err
	}
	pageSize, _ := queryInt(cp, `PRAGMA main.page_size`)
	pagesBefore, _ := used()
	t0 := time.Now()
	if err := cp.Exec(spec.DefinitionFor(protocol.EngineSQLite)); err != nil {
		reject("building it failed on the copy: " + firstLine(err.Error()))
		return
	}
	build := time.Since(t0)
	pagesAfter, _ := used()
	defer func() { _ = cp.Exec("DROP INDEX IF EXISTS main." + quoteIdent(spec.Name)) }()
	plan, err := queryPlan(cp, lookup, keys[0])
	if err != nil || !strings.Contains(plan, spec.Name) {
		reject("SQLite doesn't use it for the key's lookups")
		return
	}
	after, _, err := timeLookups(cp, lookup, keys)
	if err != nil {
		reject("the lookup failed on the copy: " + firstLine(err.Error()))
		return
	}
	speedup := before / max(after, 0.001)
	if speedup < 2 {
		reject(fmt.Sprintf("lookups were only %s faster with it on the copy", protocol.TimesFaster(speedup)))
		return
	}
	rec := protocol.IndexRecommendation{Spec: spec, Key: spec.Key(), SizeBytes: max(pagesAfter-pagesBefore, 1) * pageSize,
		BuildMs: max(build.Milliseconds(), 1), TableRows: rows, Statements: []protocol.IndexGain{}, Speedup: speedup,
		ForeignKey: &protocol.IndexForeignKey{RefTable: x.fk.RefTable, RefColumns: x.fk.RefColumns,
			LookupMsBefore: before, LookupMsAfter: after, Samples: len(keys)}}
	tl.Printf("%s (%s): built in %s on the copy, %s; a key's lookup %.2f ms -> %.3f ms (%s faster, %.0f rows per key on average)",
		spec.Table, strings.Join(spec.Columns, ", "), build.Round(time.Millisecond), humanBytes(rec.SizeBytes), before, after,
		protocol.TimesFaster(speedup), matches)
	res.Recommendations = append(res.Recommendations, rec)
}

// sampleKeys are up to adviceSamples distinct non-empty key values spread
// over the table (values stay in memory, on the server).
func sampleKeys(cp *sqlite3.Conn, tbl string, cols []string, rows int64) ([][]any, error) {
	var notNull []string
	for _, c := range cols {
		notNull = append(notNull, c+" IS NOT NULL")
	}
	q := "SELECT " + strings.Join(cols, ", ") + " FROM " + tbl + " WHERE " + strings.Join(notNull, " AND ") + " LIMIT 1 OFFSET ?"
	var out [][]any
	seen := map[string]bool{}
	step := max(rows/adviceSamples, 1)
	for i := int64(0); i < adviceSamples && i*step < rows; i++ {
		var key []any
		err := queryRows(cp, q, func(s *sqlite3.Stmt) error {
			key = make([]any, len(cols))
			return s.Columns(key...)
		}, i*step)
		if err != nil {
			return nil, err
		}
		if key == nil {
			break
		}
		id := fmt.Sprint(key...)
		if !seen[id] {
			seen[id] = true
			out = append(out, key)
		}
	}
	return out, nil
}

// timeLookups runs the lookup for each key (at least 3 rounds, at least
// 50 ms in all) and returns the average time per lookup in ms and the
// average rows per key.
func timeLookups(cp *sqlite3.Conn, q string, keys [][]any) (ms, rowsPerKey float64, err error) {
	s, _, err := cp.Prepare(q)
	if err != nil {
		return 0, 0, err
	}
	defer s.Close()
	var n, rows int64
	t0 := time.Now()
	for round := 0; round < 3 || time.Since(t0) < 50*time.Millisecond && round < 1000; round++ {
		for _, k := range keys {
			if err := s.Reset(); err != nil {
				return 0, 0, err
			}
			if err := bind(s, k...); err != nil {
				return 0, 0, err
			}
			if s.Step() {
				if round == 0 {
					rows += s.ColumnInt64(0)
				}
			}
			if err := s.Err(); err != nil {
				return 0, 0, err
			}
			n++
		}
	}
	took := time.Since(t0)
	return float64(took.Microseconds()) / 1000 / float64(n), float64(rows) / float64(len(keys)), nil
}

// queryPlan is EXPLAIN QUERY PLAN of q with args, as one line.
func queryPlan(c *sqlite3.Conn, q string, args []any) (string, error) {
	var parts []string
	err := queryRows(c, "EXPLAIN QUERY PLAN "+q, func(s *sqlite3.Stmt) error {
		parts = append(parts, s.ColumnText(3))
		return nil
	}, args...)
	return strings.Join(parts, "; "), err
}

// trackedUsage reports whether the indexes Rowsafe created still exist.
// SQLite counts no index use, so Scans stays 0.
func trackedUsage(c *sqlite3.Conn, track []protocol.TrackedIndex) []protocol.IndexUsage {
	var out []protocol.IndexUsage
	for _, t := range track {
		n, err := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE type = 'index' AND name = ?`, t.Index)
		if err != nil {
			continue
		}
		out = append(out, protocol.IndexUsage{TrackedIndex: t, Exists: n > 0, Valid: n > 0})
	}
	return out
}

func adviceSummary(r *protocol.IndexAdvisorResult) string {
	switch {
	case len(r.Generated) == 0:
		return "Every foreign key has an index: no index to suggest."
	case r.Skipped != "":
		return fmt.Sprintf("%s without an index; not tested yet: %s", plural(len(r.Generated), "foreign key", "foreign keys"), r.Skipped)
	case r.Tested == 0:
		return fmt.Sprintf("%s without an index, tested on a copy recently; nothing new to test.", plural(len(r.Generated), "foreign key", "foreign keys"))
	}
	return fmt.Sprintf("Tested %s for foreign keys on a copy: %d made lookups faster, %d didn't.",
		plural(r.Tested, "index", "indexes"), len(r.Recommendations), len(r.Rejected))
}

// tookWords: "under a second", "3s", "2m10s".
func tookWords(d time.Duration) string {
	if d < time.Second {
		return "under a second"
	}
	return d.Round(time.Second).String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// ---- create_index (Apply fix) ----

// fixCreateIndex creates an index the advisor proved on a copy: CREATE
// INDEX IF NOT EXISTS, names checked against the file and quoted. SQLite
// builds it in one write transaction: the app's writes wait until it is
// done (reads go on in WAL mode).
func (e *Engine) fixCreateIndex(ctx context.Context, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, []string, error) {
	if p.CreateIndex == nil {
		return "", nil, errors.New("no index given")
	}
	spec := p.CreateIndex.IndexSpec
	switch {
	case spec.DB != "" && spec.DB != "main", spec.Schema != "" && spec.Schema != "main":
		return "", nil, fmt.Errorf("a SQLite database has no %s.%s: only main", spec.DB, spec.Schema)
	case len(spec.Columns) == 0 || len(spec.Columns) > 16:
		return "", nil, errors.New("an index needs 1 to 16 columns")
	case len(spec.Include) > 0 || len(spec.Descending) > 0 || spec.Predicate() != "" || spec.Kind != "":
		return "", nil, errors.New("Rowsafe only creates plain indexes on SQLite")
	case !protocol.ValidIndexName(spec.Name) || strings.HasSuffix(spec.Name, "_proj"):
		return "", nil, fmt.Errorf("invalid index name %q", spec.Name)
	}
	c, err := openDB(ctx, db.SocketDir, openOpts{Busy: 30 * time.Second})
	if err != nil {
		return "", nil, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	schema, err := readSchema(ctx, c, 0)
	if err != nil {
		return "", nil, err
	}
	t := schema.table(spec.Table)
	if t == nil || t.Name != spec.Table {
		return fmt.Sprintf("The table %s no longer exists: nothing to do.", spec.Table), nil, nil
	}
	for _, col := range spec.Columns {
		if cc, ok := t.column(col); !ok || cc.Name != col {
			return "", nil, fmt.Errorf("the table %s has no column %q (changed since the index was tested?)", spec.Table, col)
		}
	}
	for _, ix := range t.Indexes {
		if ix.Name == spec.Name {
			return fmt.Sprintf("The index %s already exists: nothing to do.", spec.Name), nil, nil
		}
	}
	if t.covered(spec.Columns) {
		return fmt.Sprintf("%s already has an index that starts with (%s): nothing to do.", spec.Table, strings.Join(spec.Columns, ", ")), nil, nil
	}
	need := max(p.CreateIndex.EstimatedBytes, 1<<20)
	if err := ensureSpace(filepath.Dir(db.SocketDir), 2*need, "the new index (written to the -wal file, then into the database)"); err != nil {
		return "", nil, err
	}
	if err := ensureSpace(os.TempDir(), need, "the new index (SQLite sorts its keys in the temporary folder)"); err != nil {
		return "", nil, err
	}
	stmt := spec.DefinitionFor(protocol.EngineSQLite)
	tl.Printf("%s", stmt)
	tl.Printf("your app's writes wait until it is built; reads go on")
	t0 := time.Now()
	if err := c.Exec(stmt); err != nil {
		e.busyFor(db.ID).note(err)
		if isBusy(err) {
			return "", nil, errors.New("your app kept a write transaction open for over 30 seconds, so the index couldn't be built; nothing changed. Try again in a quieter moment")
		}
		return "", nil, fmt.Errorf("creating the index failed (nothing changed): %w", err)
	}
	took := tookWords(time.Since(t0))
	n, err := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE type = 'index' AND name = ?`, spec.Name)
	if err != nil || n == 0 {
		return "", nil, fmt.Errorf("the index %s isn't in the database after CREATE INDEX", spec.Name)
	}
	return fmt.Sprintf("Created the index %s on %s (%s) in %s; your app's writes waited while it was built.",
			spec.Name, spec.Table, strings.Join(spec.Columns, ", "), took),
		[]string{stmt}, nil
}
