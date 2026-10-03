package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Index fixes for ClickHouse (protocol/indexadvisor_clickhouse.go):
//
//   - create_index: a skipping index or projection the index advisor proved
//     on a copy. ALTER TABLE ... ADD (a change of the table's definition
//     only), then MATERIALIZE: a mutation that builds it for the parts
//     already on disk, in the background, part by part, while queries and
//     inserts go on. The task follows it for a few minutes and then leaves
//     it running; Pulse shows its progress with a Cancel button
//     (kill_mutation, which also removes what was added).
//   - drop_index: a skipping index or projection by name on Tables[0];
//     with Unused, refused once a query has used it since.
//
// Both need ALTER TABLE, which Rowsafe's login has since rewinds in place.

const (
	// buildFollow is how long create_index follows the build before
	// leaving it to run in the background.
	buildFollow = 3 * time.Minute
	// mutationPoll is how often the build's progress is read.
	mutationPoll = 5 * time.Second
)

// noAlterGrant turns a refused ALTER into plain words.
func noAlterGrant(err error) error {
	if errCode(err) == codeAccessDenied {
		return errors.New("Rowsafe's ClickHouse login may not change table definitions (ALTER TABLE): run the Rowsafe installer on the server again to update its login, then try again")
	}
	return err
}

// tableColumns are a table's engine and columns (nil when it is gone).
func tableColumns(ctx context.Context, c *client, db, table string) (engine string, cols []string, err error) {
	params := map[string]string{"db": db, "t": table}
	engine, err = c.scalar(ctx, "SELECT engine FROM system.tables WHERE database = {db:String} AND name = {t:String}", params)
	if err != nil || engine == "" {
		return "", nil, err
	}
	type row struct {
		Name string `json:"name"`
	}
	rows, err := query[row](ctx, c, "SELECT name FROM system.columns WHERE database = {db:String} AND table = {t:String} ORDER BY position", params)
	if err != nil {
		return "", nil, err
	}
	for _, r := range rows {
		cols = append(cols, r.Name)
	}
	return engine, cols, nil
}

// checkSpec checks a spec against the table as it is now.
func checkSpec(s protocol.IndexSpec, engine string, cols []string) error {
	has := func(c string) bool { return slices.Contains(cols, c) }
	if !protocol.ValidIndexName(s.Name) {
		return fmt.Errorf("invalid name %q", s.Name)
	}
	if !strings.HasSuffix(engine, "MergeTree") {
		return fmt.Errorf("%s.%s is a %s table: only MergeTree tables have skipping indexes and projections", s.DB, s.Table, engine)
	}
	switch s.Kind {
	case protocol.IndexKindSkip:
		if len(s.Columns) != 1 || !has(s.Columns[0]) {
			return fmt.Errorf("%s.%s has no column %q", s.DB, s.Table, strings.Join(s.Columns, ","))
		}
		if !protocol.ValidSkipIndexType(s.Type) || s.Granularity < 1 || s.Granularity > 1000 {
			return fmt.Errorf("unsupported skipping index %s GRANULARITY %d", s.Type, s.Granularity)
		}
	case protocol.IndexKindProjection:
		if engine != "MergeTree" && engine != "ReplicatedMergeTree" {
			return fmt.Errorf("%s.%s is a %s table: Rowsafe only adds projections to MergeTree tables", s.DB, s.Table, engine)
		}
		for _, c := range slices.Concat(s.Columns, s.Include, s.GroupBy) {
			if !has(c) {
				return fmt.Errorf("%s.%s has no column %q", s.DB, s.Table, c)
			}
		}
		for _, a := range s.Aggregates {
			_, col, ok := protocol.ParseAggregate(a)
			if !ok || col != "" && !has(col) {
				return fmt.Errorf("unsupported aggregate %q", a)
			}
		}
		if len(s.Aggregates) == 0 && len(s.Columns) == 0 {
			return errors.New("a projection needs a sort order or aggregates")
		}
	case protocol.IndexKindOrderBy:
		return errors.New("a new sorting key means rebuilding the table: Rowsafe gives it as advice, it doesn't change it")
	default:
		return fmt.Errorf("unknown kind %q", s.Kind)
	}
	return nil
}

func (e *Engine) createIndex(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	if p.CreateIndex == nil {
		return "", errors.New("create_index needs the index the advisor proved")
	}
	s := p.CreateIndex.IndexSpec
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	engine, cols, err := tableColumns(ctx, c, s.DB, s.Table)
	if err != nil {
		return "", err
	}
	if engine == "" {
		return fmt.Sprintf("%s.%s no longer exists; nothing to do.", s.DB, s.Table), nil
	}
	if err := checkSpec(s, engine, cols); err != nil {
		return "", err
	}
	what := whatSpec(s)
	objs, err := skipAndProjections(ctx, c)
	if err != nil {
		return "", err
	}
	for _, o := range objs {
		if o.db == s.DB && o.table == s.Table && o.name == s.Name {
			return fmt.Sprintf("%s.%s already has %s; nothing to do.", s.DB, s.Table, s.Name), nil
		}
	}
	// Room for it, twice over (parts are rewritten with it, then the old
	// ones removed).
	if free, err := c.scalar(ctx, "SELECT toInt64(min(unreserved_space)) FROM system.disks WHERE type = 'Local' OR type = 'local'", nil); err == nil {
		n, _ := strconv.ParseInt(free, 10, 64)
		if need := 2*p.CreateIndex.EstimatedBytes + 1<<30; n > 0 && n < need {
			return "", fmt.Errorf("not enough free disk to build %s on %s.%s: about %s needed, %s free", what, s.DB, s.Table, humanBytes(need), humanBytes(n))
		}
	}
	stmts := s.ClickHouseStatements()
	tl.Printf("%s", stmts[0])
	if err := c.exec(ctx, stmts[0], nil); err != nil {
		return "", fmt.Errorf("adding %s: %w", what, noAlterGrant(err))
	}
	tl.Printf("%s", stmts[1])
	if err := c.exec(ctx, stmts[1], nil, "mutations_sync", "0"); err != nil {
		drop(context.WithoutCancel(ctx), c, s, tl)
		return "", fmt.Errorf("building %s for the existing data: %w", what, noAlterGrant(err))
	}
	return followBuild(ctx, c, s, tl)
}

// whatSpec: "the skipping index rs_..." / "the projection rs_...".
func whatSpec(s protocol.IndexSpec) string {
	if s.Kind == protocol.IndexKindProjection {
		return "the projection " + s.Name
	}
	return "the skipping index " + s.Name
}

// drop removes a skipping index or projection Rowsafe added (after a
// failed or cancelled build).
func drop(ctx context.Context, c *client, s protocol.IndexSpec, tl agent.TaskLogger) {
	stmt := "ALTER TABLE " + tableName(s.DB, s.Table) + " DROP INDEX IF EXISTS " + quoteIdent(s.Name)
	if s.Kind == protocol.IndexKindProjection {
		stmt = "ALTER TABLE " + tableName(s.DB, s.Table) + " DROP PROJECTION IF EXISTS " + quoteIdent(s.Name)
	}
	if err := c.exec(ctx, stmt, nil); err != nil {
		tl.Printf("removing %s failed: %s", s.Name, shortError(err))
		return
	}
	tl.Printf("removed %s", s.Name)
}

// buildMutation is the MATERIALIZE mutation of a Rowsafe index or
// projection.
type buildMutation struct {
	ID     string `json:"mutation_id"`
	Done   uint8  `json:"is_done"`
	ToDo   int64  `json:"parts_to_do"`
	Killed uint8  `json:"is_killed"`
	Fail   string `json:"latest_fail_reason"`
}

func findBuild(ctx context.Context, c *client, s protocol.IndexSpec) (*buildMutation, error) {
	rows, err := query[buildMutation](ctx, c, `SELECT mutation_id, is_done, toInt64(parts_to_do) AS parts_to_do, is_killed, latest_fail_reason
		FROM system.mutations WHERE database = {db:String} AND table = {t:String}
		  AND position(command, 'MATERIALIZE') > 0 AND position(command, {n:String}) > 0
		ORDER BY create_time DESC LIMIT 1`, map[string]string{"db": s.DB, "t": s.Table, "n": s.Name})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// followBuild follows the MATERIALIZE mutation for up to buildFollow,
// logging its progress, then leaves it to finish in the background.
func followBuild(ctx context.Context, c *client, s protocol.IndexSpec, tl agent.TaskLogger) (string, error) {
	what := whatSpec(s)
	started := time.Now()
	var total int64
	lastLog := time.Now()
	for {
		m, err := findBuild(ctx, c, s)
		switch {
		case err != nil:
			return "", err
		case m == nil || m.Done != 0:
			return fmt.Sprintf("Added %s on %s.%s and built it for the existing data in %s. ClickHouse uses it for the queries it helps; new data gets it as it is written.",
				what, s.DB, s.Table, time.Since(started).Round(time.Second)), nil
		case m.Killed != 0:
			drop(context.WithoutCancel(ctx), c, s, tl)
			return "", fmt.Errorf("the build of %s was cancelled; Rowsafe removed it", s.Name)
		}
		if total == 0 {
			total = m.ToDo
		}
		if time.Since(lastLog) >= 30*time.Second {
			lastLog = time.Now()
			tl.Printf("building: %d of %d parts to go", m.ToDo, total)
			if m.Fail != "" {
				tl.Printf("ClickHouse retries a part that failed: %s", truncate(m.Fail, 300))
			}
		}
		if time.Since(started) >= buildFollow {
			tl.Printf("mutation %s goes on in the background", m.ID)
			return fmt.Sprintf("Added %s on %s.%s. ClickHouse is building it for the existing data in the background (mutation %s, %s to go); queries and inserts go on meanwhile. Pulse shows its progress and can cancel it.",
				what, s.DB, s.Table, m.ID, plural(int(m.ToDo), "part", "parts")), nil
		}
		select {
		case <-ctx.Done():
			// Stopped before the end: leave nothing half done.
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			_ = c.exec(sctx, "KILL MUTATION WHERE database = {db:String} AND table = {t:String} AND mutation_id = {id:String}",
				map[string]string{"db": s.DB, "t": s.Table, "id": m.ID})
			drop(sctx, c, s, tl)
			return "", ctx.Err()
		case <-time.After(mutationPoll):
		}
	}
}

// rowsafeBuild reads a mutation's command as the build of a Rowsafe
// skipping index or projection ("MATERIALIZE INDEX rs_..."); ok is false
// for anything else.
func rowsafeBuild(db, table, command string) (protocol.IndexSpec, bool) {
	cmd := strings.Trim(strings.TrimSpace(command), "()")
	for _, k := range []struct{ word, kind string }{{"MATERIALIZE INDEX ", protocol.IndexKindSkip}, {"MATERIALIZE PROJECTION ", protocol.IndexKindProjection}} {
		if rest, ok := strings.CutPrefix(cmd, k.word); ok {
			name := strings.Trim(strings.Fields(rest + " ")[0], "`")
			if protocol.ValidIndexName(name) {
				return protocol.IndexSpec{DB: db, Schema: db, Table: table, Name: name, Kind: k.kind}, true
			}
		}
	}
	return protocol.IndexSpec{}, false
}

func (e *Engine) dropIndex(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	if p.DB == "" || len(p.Tables) != 1 || p.Index == "" {
		return "", errors.New("drop_index needs the database, the table and the index")
	}
	table := p.Tables[0]
	if _, t, ok := strings.Cut(table, "."); ok && strings.HasPrefix(table, p.DB+".") {
		table = t
	}
	name := p.Index
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	objs, err := skipAndProjections(ctx, c)
	if err != nil {
		return "", err
	}
	var found *chObject
	for i, o := range objs {
		if o.db == p.DB && o.table == table && o.name == name {
			found = &objs[i]
		}
	}
	if found == nil {
		return fmt.Sprintf("%s on %s.%s no longer exists; nothing to do.", name, p.DB, table), nil
	}
	kind := "skipping index"
	if found.projection {
		kind = "projection"
	}
	if p.Unused {
		login, _, _ := loadLogin(env, db.Port)
		if n, ok := objectUse(ctx, c, login.User, *found); ok && n > 0 {
			return "", fmt.Errorf("the %s %s has been used since it was found unused (%d queries): it was kept", kind, name, n)
		}
	}
	tl.Printf("dropping the %s %s on %s.%s; its definition, to add it again: %s", kind, name, p.DB, table, found.definition)
	stmt := "ALTER TABLE " + tableName(p.DB, table) + " DROP INDEX " + quoteIdent(name)
	if found.projection {
		stmt = "ALTER TABLE " + tableName(p.DB, table) + " DROP PROJECTION " + quoteIdent(name)
	}
	if err := c.exec(ctx, stmt, nil, "mutations_sync", "1"); err != nil {
		return "", fmt.Errorf("dropping the %s: %w", kind, noAlterGrant(err))
	}
	return fmt.Sprintf("Dropped the %s %s on %s.%s (%s); inserts and merges no longer build it.", kind, name, p.DB, table, humanBytes(found.bytes)), nil
}
