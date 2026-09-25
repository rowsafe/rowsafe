package agent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Maintenance tasks run one fixed action that the control plane proposed as
// a health fix. The control plane sends names and ids, never SQL: every
// object is looked up again in the catalogs with query parameters, the
// conditions that made the fix safe are checked again, and statements are
// built only from identifiers PostgreSQL itself quoted (format('%I.%I')).

// fixAppName is the application_name of the agent's maintenance sessions
// (and "rowsafe%" sessions are never ended by a fix).
const fixAppName = "rowsafe-agent-fix"

// maxMaintenanceTables caps how many tables one vacuum or analyze touches.
const maxMaintenanceTables = 100

// Overall time limits per action. VACUUM and REINDEX run without a
// statement timeout (a large table takes a while); the task's own timeout
// (protocol.TaskTimeout) is the outer bound.
var maintenanceTimeouts = map[string]time.Duration{
	protocol.MaintVacuum:              2 * time.Hour,
	protocol.MaintAnalyze:             2 * time.Hour,
	protocol.MaintReindexIndex:        2 * time.Hour,
	protocol.MaintDropIndex:           30 * time.Minute,
	protocol.MaintCancelQuery:         30 * time.Second,
	protocol.MaintTerminateSession:    30 * time.Second,
	protocol.MaintDropReplicationSlot: 30 * time.Second,
	protocol.MaintCreateIndex:         110 * time.Minute, // within the task's 2 hours
}

// ddlLockTimeout keeps DDL from queueing behind long transactions (and
// making every other query queue behind it).
const ddlLockTimeout = "5s"

// lockRetries is how often a CONCURRENTLY operation that hit the lock
// timeout is tried again, and lockRetryWait the pause before each retry.
var (
	lockRetries   = 3
	lockRetryWait = 10 * time.Second
)

// slotNameRE is PostgreSQL's rule for replication slot names.
var slotNameRE = regexp.MustCompile(`^[a-z0-9_]{1,63}$`)

// systemSchemas are never touched by index fixes.
var systemSchemas = []string{"pg_catalog", "information_schema", "pg_toast"}

// validateMaintenance checks params before anything connects: the action is
// known and carries what it needs, and names are plausible.
func validateMaintenance(p protocol.MaintenanceParams) error {
	if _, ok := maintenanceTimeouts[p.Action]; !ok {
		return fmt.Errorf("unknown maintenance action %q (agent %s)", p.Action, Version)
	}
	switch p.Action {
	case protocol.MaintVacuum, protocol.MaintAnalyze:
		if err := validDatName(p.DB); err != nil {
			return err
		}
		if len(p.Tables) == 0 {
			return fmt.Errorf("no tables given")
		}
		if len(p.Tables) > maxMaintenanceTables {
			return fmt.Errorf("too many tables (%d, at most %d at a time)", len(p.Tables), maxMaintenanceTables)
		}
		for _, t := range p.Tables {
			if len(nameCandidates(t)) == 0 {
				return fmt.Errorf("invalid table name %q", t)
			}
		}
	case protocol.MaintReindexIndex, protocol.MaintDropIndex:
		if err := validDatName(p.DB); err != nil {
			return err
		}
		if len(nameCandidates(p.Index)) == 0 {
			return fmt.Errorf("invalid index name %q", p.Index)
		}
	case protocol.MaintCancelQuery, protocol.MaintTerminateSession:
		if p.PID <= 0 {
			return fmt.Errorf("no session (pid) given")
		}
		if p.BackendStart == nil || p.BackendStart.IsZero() {
			return fmt.Errorf("the session's start time is missing, so Rowsafe can't be sure it is the same session")
		}
	case protocol.MaintDropReplicationSlot:
		if !slotNameRE.MatchString(p.Slot) {
			return fmt.Errorf("invalid replication slot name %q", p.Slot)
		}
	case protocol.MaintCreateIndex:
		if err := validDatName(p.DB); err != nil {
			return err
		}
		return validateCreateIndex(p.CreateIndex)
	}
	return nil
}

func validDatName(name string) error {
	if name == "" {
		return fmt.Errorf("no database given")
	}
	if len(name) > 63 || strings.ContainsRune(name, 0) || !utf8.ValidString(name) {
		return fmt.Errorf("invalid database name %q", name)
	}
	return nil
}

// qualName is a schema-qualified name as the catalogs store it (unquoted).
type qualName struct{ schema, name string }

// nameCandidates lists the ways s can name an object: "schema.name" split
// at any dot (names may contain dots themselves), or a quoted SQL name such
// as "My.Schema"."t". A bare name means the public schema. The catalog
// lookup decides which reading exists; names are never pasted into SQL.
func nameCandidates(s string) []qualName {
	if s == "" || len(s) > 300 || strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
		return nil
	}
	var out []qualName
	add := func(q qualName) {
		if q.schema == "" || q.name == "" || len(q.schema) > 63 || len(q.name) > 63 || slices.Contains(out, q) {
			return
		}
		out = append(out, q)
	}
	if strings.Contains(s, `"`) {
		if parts, ok := parseSQLName(s); ok && len(parts) == 2 {
			add(qualName{parts[0], parts[1]})
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			add(qualName{s[:i], s[i+1:]})
		}
	}
	if !strings.Contains(s, ".") {
		add(qualName{"public", s})
	}
	return out
}

// parseSQLName splits a possibly quoted, dot-separated SQL name the way
// PostgreSQL does: "quoted" parts keep their case ("" is a quote), bare
// parts are folded to lower case.
func parseSQLName(s string) ([]string, bool) {
	var parts []string
	for i := 0; ; {
		if i >= len(s) {
			return nil, false
		}
		var part strings.Builder
		if s[i] == '"' {
			i++
			for {
				if i >= len(s) {
					return nil, false // unterminated
				}
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						part.WriteByte('"')
						i += 2
						continue
					}
					i++
					break
				}
				part.WriteByte(s[i])
				i++
			}
			if part.Len() == 0 {
				return nil, false
			}
		} else {
			start := i
			for i < len(s) && s[i] != '.' && s[i] != '"' {
				i++
			}
			bare := s[start:i]
			if bare == "" || !bareIdentRE.MatchString(bare) {
				return nil, false
			}
			part.WriteString(strings.ToLower(bare))
		}
		parts = append(parts, part.String())
		if i == len(s) {
			return parts, true
		}
		if s[i] != '.' {
			return nil, false
		}
		i++
	}
}

var bareIdentRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

// relation is a table or index found in the catalogs.
type relation struct {
	oid   uint32
	ident string // quoted by PostgreSQL: format('%I.%I', schema, name)
	qualName
	kind string // pg_class.relkind
}

// display is the name shown to people: schema.name, quoted only when needed.
func (r relation) display() string { return r.ident }

var errNotFound = errors.New("not found")

// lookupRelation finds the one relation that s names. kinds limits the
// relkinds accepted; what is the word used in messages ("table", "index").
func lookupRelation(ctx context.Context, conn *pgx.Conn, s string, kinds []string, what string) (relation, error) {
	cands := nameCandidates(s)
	if len(cands) == 0 {
		return relation{}, fmt.Errorf("invalid %s name %q", what, s)
	}
	nsps := make([]string, len(cands))
	rels := make([]string, len(cands))
	for i, c := range cands {
		nsps[i], rels[i] = c.schema, c.name
	}
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT c.oid, format('%I.%I', n.nspname, c.relname), n.nspname::text, c.relname::text, c.relkind::text
		FROM unnest($1::text[], $2::text[]) AS k(nsp, rel)
		JOIN pg_namespace n ON n.nspname = k.nsp
		JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = k.rel`, nsps, rels)
	if err != nil {
		return relation{}, err
	}
	found, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (relation, error) {
		var r relation
		err := row.Scan(&r.oid, &r.ident, &r.schema, &r.name, &r.kind)
		return r, err
	})
	if err != nil {
		return relation{}, err
	}
	switch {
	case len(found) == 0:
		return relation{}, fmt.Errorf("%w: the %s %s no longer exists", errNotFound, what, s)
	case len(found) > 1:
		return relation{}, fmt.Errorf("the name %q matches more than one object (%s and %s), so Rowsafe didn't guess",
			s, found[0].ident, found[1].ident)
	}
	if !slices.Contains(kinds, found[0].kind) {
		return relation{}, fmt.Errorf("the name %s belongs to something that isn't %s", found[0].ident, withArticle(what))
	}
	return found[0], nil
}

func (a *Agent) fixTarget(db protocol.DatabaseSpec) pginspect.Target {
	t := a.target(db)
	t.AppName = fixAppName
	return t
}

// maintenance runs one maintenance action.
func (a *Agent) maintenance(ctx context.Context, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl *taskLog) (*protocol.MaintenanceResult, error) {
	if err := validateMaintenance(p); err != nil {
		return nil, err
	}
	start := time.Now()
	limit := maintenanceTimeouts[p.Action]
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	m := &maint{t: a.fixTarget(db), p: p, tl: tl, res: &protocol.MaintenanceResult{Action: p.Action}}
	var err error
	switch p.Action {
	case protocol.MaintVacuum, protocol.MaintAnalyze:
		err = m.vacuumOrAnalyze(ctx)
	case protocol.MaintReindexIndex:
		err = m.reindex(ctx)
	case protocol.MaintDropIndex:
		err = m.dropIndex(ctx)
	case protocol.MaintCancelQuery, protocol.MaintTerminateSession:
		err = m.signalBackend(ctx)
	case protocol.MaintDropReplicationSlot:
		err = m.dropSlot(ctx)
	case protocol.MaintCreateIndex:
		err = m.createIndex(ctx)
	}
	m.res.DurationMs = time.Since(start).Milliseconds()
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("it didn't finish within %s, so Rowsafe stopped it (nothing is left half-done): %w", plainDuration(limit), err)
	}
	if err != nil {
		err = sentence(err)
		tl.Printf("failed: %v", err)
	} else {
		tl.Printf("%s", m.res.Summary)
	}
	return m.res, err
}

type maint struct {
	t   pginspect.Target
	p   protocol.MaintenanceParams
	tl  *taskLog
	res *protocol.MaintenanceResult
}

// connect opens a session to dbname with the given settings, each applied
// with set_config so values are parameters too.
func (m *maint) connect(ctx context.Context, dbname string, settings map[string]string) (*pgx.Conn, error) {
	conn, err := m.t.Connect(ctx, dbname)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "3D000" {
			return nil, fmt.Errorf("the database %q no longer exists", dbname)
		}
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if _, err := conn.Exec(ctx, `SELECT set_config($1, $2, false)`, k, settings[k]); err != nil {
			conn.Close(context.WithoutCancel(ctx))
			return nil, fmt.Errorf("setting %s: %w", k, err)
		}
	}
	return conn, nil
}

func closeConn(ctx context.Context, conn *pgx.Conn) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	conn.Close(cctx)
}

// requirePrimary refuses changes on a read-only standby.
func requirePrimary(ctx context.Context, conn *pgx.Conn) error {
	var inRecovery bool
	if err := conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery); err != nil {
		return err
	}
	if inRecovery {
		return fmt.Errorf("this PostgreSQL is a read-only replica; this has to be done on the primary")
	}
	return nil
}

func serverVersionNum(ctx context.Context, conn *pgx.Conn) (int, error) {
	var v int
	err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&v)
	return v, err
}

// ---- vacuum, analyze ----

func (m *maint) vacuumOrAnalyze(ctx context.Context) error {
	vacuum := m.p.Action == protocol.MaintVacuum
	conn, err := m.connect(ctx, m.p.DB, map[string]string{
		"statement_timeout": "0",
		"lock_timeout":      ddlLockTimeout,
		// Gentle: VACUUM pauses 2ms after each batch of pages, like
		// autovacuum does by default.
		"vacuum_cost_delay": "2",
	})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}

	var done, missing, busy []string
	var deadBefore, deadAfter int64
	var ageBefore, ageAfter int64
	for _, name := range m.p.Tables {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rel, err := lookupRelation(ctx, conn, name, []string{"r", "m", "p"}, "table")
		if errors.Is(err, errNotFound) {
			missing = append(missing, name)
			m.tl.Printf("%s: skipped, it no longer exists", name)
			continue
		}
		if err != nil {
			return err
		}
		dead, age, err := tableState(ctx, conn, rel.oid)
		if err != nil {
			return err
		}
		stmt := "ANALYZE " + rel.ident
		if vacuum {
			stmt = "VACUUM (ANALYZE) " + rel.ident
			if m.p.Freeze {
				stmt = "VACUUM (FREEZE, ANALYZE) " + rel.ident
			}
		}
		m.tl.Printf("%s: %s (%d dead rows)", rel.display(), stmt, dead)
		t0 := time.Now()
		if _, err := conn.Exec(ctx, stmt); err != nil {
			if isLockTimeout(err) {
				busy = append(busy, rel.display())
				m.tl.Printf("%s: skipped, another operation (often autovacuum) holds it", rel.display())
				continue
			}
			return fmt.Errorf("%s of %s failed: %w", strings.Fields(stmt)[0], rel.display(), plainPGError(err))
		}
		_, _ = conn.Exec(ctx, `SELECT pg_stat_clear_snapshot()`)
		deadNow, ageNow, err := tableState(ctx, conn, rel.oid)
		if err != nil {
			return err
		}
		m.tl.Printf("%s: done in %s, %d dead rows left", rel.display(), time.Since(t0).Round(time.Millisecond), deadNow)
		done = append(done, rel.display())
		deadBefore += dead
		deadAfter += deadNow
		ageBefore = max(ageBefore, age)
		ageAfter = max(ageAfter, ageNow)
	}

	for _, t := range missing {
		m.res.Details = append(m.res.Details, "Skipped "+t+": it no longer exists.")
	}
	for _, t := range busy {
		m.res.Details = append(m.res.Details, "Skipped "+t+": another operation (often PostgreSQL's own autovacuum) was working on it; try again later.")
	}
	if len(done) == 0 {
		if len(busy) > 0 {
			return fmt.Errorf("the %s %s busy (another operation, often PostgreSQL's own autovacuum, was working on %s), so nothing was done; try again later",
				plural(len(busy), "table", "tables"), isAre(len(busy)), itThem(len(busy)))
		}
		m.res.Summary = "There was nothing to do: the " + plural(len(missing), "table", "tables") + " no longer " + existExists(len(missing)) + "."
		return nil
	}
	removed := max(deadBefore-deadAfter, 0)
	switch {
	case vacuum && m.p.Freeze:
		m.res.Summary = fmt.Sprintf("Froze %s", countNoun(len(done), "table", "tables"))
		if ageBefore >= 1_000_000 && ageAfter < ageBefore {
			m.res.Summary += fmt.Sprintf("; the oldest transaction age went from %s to %s", plainCount(ageBefore), plainCount(ageAfter))
		}
		m.res.Summary += "."
	case vacuum:
		m.res.Summary = fmt.Sprintf("Cleaned up %s", countNoun(len(done), "table", "tables"))
		if removed > 0 {
			m.res.Summary += fmt.Sprintf("; about %s dead %s removed", plainCount(removed), plural(int(min(removed, 2)), "row", "rows"))
		}
		m.res.Summary += "."
	default:
		m.res.Summary = fmt.Sprintf("Refreshed the statistics of %s, so PostgreSQL can plan queries on %s well again.",
			countNoun(len(done), "table", "tables"), itThem(len(done)))
	}
	if n := len(missing) + len(busy); n > 0 {
		m.res.Summary += fmt.Sprintf(" Skipped %s (see details).", countNoun(n, "table", "tables"))
	}
	if len(done) <= 10 {
		m.res.Details = append([]string{"Tables: " + strings.Join(done, ", ") + "."}, m.res.Details...)
	}
	return nil
}

// tableState reads a table's dead rows and transaction ID age (0 for a
// partitioned table, which has none of its own).
func tableState(ctx context.Context, conn *pgx.Conn, oid uint32) (dead, age int64, err error) {
	err = conn.QueryRow(ctx, `
		SELECT coalesce((SELECT n_dead_tup FROM pg_stat_all_tables WHERE relid = c.oid), 0),
		       CASE WHEN c.relkind IN ('r', 'm', 't') THEN age(c.relfrozenxid) ELSE 0 END
		FROM pg_class c WHERE c.oid = $1`, oid).Scan(&dead, &age)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, nil // dropped meanwhile
	}
	return dead, age, err
}

// ---- reindex ----

func (m *maint) reindex(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{
		"statement_timeout": "0",
		"lock_timeout":      ddlLockTimeout,
	})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	v, err := serverVersionNum(ctx, conn)
	if err != nil {
		return err
	}
	if v < 120000 {
		return fmt.Errorf("rebuilding an index without blocking writes needs PostgreSQL 12 or newer (this server runs %d), so Rowsafe didn't do it", v/10000)
	}
	idx, err := m.lookupIndex(ctx, conn)
	if err != nil {
		return err
	}
	var tableOID uint32
	var table string
	var sizeBefore int64
	if err := conn.QueryRow(ctx, `
		SELECT x.indrelid, format('%I.%I', n.nspname, t.relname), pg_relation_size(x.indexrelid)
		FROM pg_index x JOIN pg_class t ON t.oid = x.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE x.indexrelid = $1`, idx.oid).Scan(&tableOID, &table, &sizeBefore); err != nil {
		return err
	}
	if err := refuseIfIndexBuilding(ctx, conn, v, tableOID, table); err != nil {
		return err
	}
	// Copies left behind by an earlier failed rebuild of this index.
	m.cleanupReindex(ctx, conn, tableOID, idx, nil)
	before, err := indexOIDs(ctx, conn, tableOID)
	if err != nil {
		return err
	}
	stmt := "REINDEX INDEX CONCURRENTLY " + idx.ident
	leftBehind := false
	err = retryOnLock(ctx, m.tl, func() error {
		m.tl.Printf("%s (%s)", stmt, humanBytes(sizeBefore))
		_, err := conn.Exec(ctx, stmt)
		if err != nil && !m.cleanupReindex(ctx, conn, tableOID, idx, before) {
			// Don't pile up unfinished copies: stop here.
			leftBehind = true
			return noRetry{err}
		}
		return err
	})
	if err != nil {
		outcome := "nothing changed"
		if leftBehind {
			outcome = "an unfinished copy of the index was left behind (PostgreSQL doesn't use it; Rowsafe removes it the next time this fix runs)"
		}
		if isLockTimeout(err) {
			return fmt.Errorf("the table %s stayed busy with other work, so Rowsafe couldn't rebuild the index %s without getting in the way; %s. Try again later", table, idx.display(), outcome)
		}
		return fmt.Errorf("rebuilding the index %s failed (%s): %w", idx.display(), outcome, plainPGError(err))
	}
	var sizeAfter int64
	if err := conn.QueryRow(ctx, `
		SELECT pg_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2`, idx.schema, idx.name).Scan(&sizeAfter); err != nil {
		return err
	}
	m.res.Summary = fmt.Sprintf("Rebuilt the index %s", idx.display())
	if sizeAfter < sizeBefore {
		m.res.Summary += fmt.Sprintf("; it went from %s to %s (freed %s)", humanBytes(sizeBefore), humanBytes(sizeAfter), humanBytes(sizeBefore-sizeAfter))
	}
	m.res.Summary += "."
	return nil
}

// cleanupReindex drops what a failed REINDEX CONCURRENTLY of idx leaves
// behind: an invalid copy named <index>_ccnew[N], or the invalid old index
// renamed <index>_ccold[N]. Only invalid indexes of this table with such a
// name are considered, and only when they carry the index's name (which
// PostgreSQL may shorten), are the index itself, or appeared since before
// (nil: nothing is known to be new). It reports whether none is left.
func (m *maint) cleanupReindex(ctx context.Context, conn *pgx.Conn, tableOID uint32, idx relation, before []uint32) bool {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	prefix := idx.name[:min(len(idx.name), 40)]
	rows, err := conn.Query(cctx, `
		SELECT c.oid, format('%I.%I', n.nspname, c.relname), c.relname::text
		FROM pg_index x JOIN pg_class c ON c.oid = x.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE x.indrelid = $1 AND NOT x.indisvalid`, tableOID)
	if err != nil {
		m.tl.Printf("looking for leftovers of a failed rebuild: %v", err)
		return false
	}
	type left struct {
		oid         uint32
		ident, name string
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (left, error) {
		var l left
		return l, row.Scan(&l.oid, &l.ident, &l.name)
	})
	if err != nil {
		m.tl.Printf("looking for leftovers of a failed rebuild: %v", err)
		return false
	}
	clean := true
	for _, l := range all {
		if !strings.Contains(l.name, "_ccnew") && !strings.Contains(l.name, "_ccold") {
			continue
		}
		isNew := before != nil && !slices.Contains(before, l.oid)
		if !isNew && l.oid != idx.oid && !strings.HasPrefix(l.name, prefix) {
			continue
		}
		m.tl.Printf("removing %s, left behind by a failed rebuild", l.ident)
		if _, err := conn.Exec(cctx, "DROP INDEX CONCURRENTLY IF EXISTS "+l.ident); err != nil {
			m.tl.Printf("could not remove %s: %v", l.ident, err)
			clean = false
		}
	}
	return clean
}

func indexOIDs(ctx context.Context, conn *pgx.Conn, tableOID uint32) ([]uint32, error) {
	rows, err := conn.Query(ctx, `SELECT indexrelid FROM pg_index WHERE indrelid = $1`, tableOID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uint32])
}

func refuseIfIndexBuilding(ctx context.Context, conn *pgx.Conn, versionNum int, tableOID uint32, table string) error {
	if versionNum < 120000 {
		return nil // no progress view before 12
	}
	var building bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_progress_create_index WHERE relid = $1)`,
		tableOID).Scan(&building); err != nil {
		return err
	}
	if building {
		return fmt.Errorf("an index on %s is being built or rebuilt right now, so Rowsafe left it alone; try again when that is done", table)
	}
	return nil
}

func (m *maint) lookupIndex(ctx context.Context, conn *pgx.Conn) (relation, error) {
	idx, err := lookupRelation(ctx, conn, m.p.Index, []string{"i", "I"}, "index")
	if err != nil {
		return idx, err
	}
	if idx.kind == "I" {
		return idx, fmt.Errorf("the index %s is the parent index of a partitioned table; Rowsafe only changes the indexes of single tables", idx.display())
	}
	if slices.Contains(systemSchemas, idx.schema) || strings.HasPrefix(idx.schema, "pg_temp") || strings.HasPrefix(idx.schema, "pg_toast_temp") {
		return idx, fmt.Errorf("the index %s belongs to PostgreSQL itself; Rowsafe leaves it alone", idx.display())
	}
	return idx, nil
}

// ---- drop index ----

// indexFacts are what makes dropping an index safe or not.
type indexFacts struct {
	table                              string
	primary, unique, exclusion, replID bool
	constraint, covered                bool
	scans, bytes                       int64
	valid                              bool
}

// dropRefusal says why an index must not be dropped ("" when it may be).
func dropRefusal(f indexFacts, unused bool, name string) string {
	switch {
	case f.primary:
		return fmt.Sprintf("the index %s is the table's primary key, so Rowsafe didn't remove it", name)
	case f.constraint:
		return fmt.Sprintf("the index %s enforces a constraint (or a foreign key depends on it), so Rowsafe didn't remove it", name)
	case f.unique:
		return fmt.Sprintf("the index %s keeps values unique, so Rowsafe didn't remove it", name)
	case f.exclusion:
		return fmt.Sprintf("the index %s enforces an exclusion constraint, so Rowsafe didn't remove it", name)
	case f.replID:
		return fmt.Sprintf("the index %s identifies rows for logical replication (REPLICA IDENTITY), so Rowsafe didn't remove it", name)
	case unused && f.scans > 0:
		return fmt.Sprintf("the index %s is now used by queries, so Rowsafe didn't remove it", name)
	case !unused && !f.covered:
		return fmt.Sprintf("the index that made %s unnecessary is gone or changed, so Rowsafe didn't remove it", name)
	}
	return ""
}

func (m *maint) dropIndex(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{
		"statement_timeout": "0",
		"lock_timeout":      ddlLockTimeout,
	})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	v, err := serverVersionNum(ctx, conn)
	if err != nil {
		return err
	}
	idx, err := m.lookupIndex(ctx, conn)
	if errors.Is(err, errNotFound) {
		m.res.Summary = fmt.Sprintf("The index %s was already removed; there was nothing to do.", m.p.Index)
		return nil
	}
	if err != nil {
		return err
	}
	var f indexFacts
	var tableOID uint32
	if err := conn.QueryRow(ctx, `
		SELECT a.indrelid, format('%I.%I', tn.nspname, t.relname),
		       a.indisprimary, a.indisunique, a.indisexclusion, a.indisreplident, a.indisvalid,
		       EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = a.indexrelid),
		       coalesce((SELECT s.idx_scan FROM pg_stat_all_indexes s WHERE s.indexrelid = a.indexrelid), 0),
		       pg_relation_size(a.indexrelid),
		       EXISTS (
		         SELECT 1 FROM pg_index b JOIN pg_class bc ON bc.oid = b.indexrelid
		         WHERE b.indrelid = a.indrelid AND b.indexrelid <> a.indexrelid AND b.indisvalid
		           AND bc.relam = ac.relam AND b.indexprs IS NULL AND a.indexprs IS NULL
		           AND coalesce(pg_get_expr(b.indpred, b.indrelid), '') = coalesce(pg_get_expr(a.indpred, a.indrelid), '')
		           AND (b.indnkeyatts = a.indnkeyatts
		                OR b.indnkeyatts > a.indnkeyatts AND a.indnatts = a.indnkeyatts
		                   AND ac.relam = (SELECT oid FROM pg_am WHERE amname = 'btree'))
		           AND (b.indkey::int2[])[0:a.indnkeyatts - 1] = (a.indkey::int2[])[0:a.indnkeyatts - 1]
		           AND (b.indclass::oid[])[0:a.indnkeyatts - 1] = (a.indclass::oid[])[0:a.indnkeyatts - 1]
		           AND (b.indcollation::oid[])[0:a.indnkeyatts - 1] = (a.indcollation::oid[])[0:a.indnkeyatts - 1]
		           AND (b.indoption::int2[])[0:a.indnkeyatts - 1] = (a.indoption::int2[])[0:a.indnkeyatts - 1])
		FROM pg_index a JOIN pg_class ac ON ac.oid = a.indexrelid
		JOIN pg_class t ON t.oid = a.indrelid JOIN pg_namespace tn ON tn.oid = t.relnamespace
		WHERE a.indexrelid = $1`, idx.oid).Scan(&tableOID, &f.table,
		&f.primary, &f.unique, &f.exclusion, &f.replID, &f.valid, &f.constraint, &f.scans, &f.bytes, &f.covered); err != nil {
		return err
	}
	m.tl.Printf("index %s on %s: %s, %d scans, valid=%v, primary=%v unique=%v exclusion=%v constraint=%v replica_identity=%v covered=%v",
		idx.display(), f.table, humanBytes(f.bytes), f.scans, f.valid, f.primary, f.unique, f.exclusion, f.constraint, f.replID, f.covered)
	if why := dropRefusal(f, m.p.Unused, idx.display()); why != "" {
		return errors.New(why)
	}
	if err := refuseIfIndexBuilding(ctx, conn, v, tableOID, f.table); err != nil {
		return err
	}
	stmt := "DROP INDEX CONCURRENTLY " + idx.ident
	err = retryOnLock(ctx, m.tl, func() error {
		// The name must still be this index (not one created since).
		var same bool
		if err := conn.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			               WHERE n.nspname = $1 AND c.relname = $2 AND c.oid = $3)`,
			idx.schema, idx.name, idx.oid).Scan(&same); err != nil {
			return err
		}
		if !same {
			return errIndexGone
		}
		m.tl.Printf("%s", stmt)
		_, err := conn.Exec(ctx, stmt)
		return err
	})
	switch {
	case errors.Is(err, errIndexGone):
		m.res.Summary = fmt.Sprintf("The index %s was already removed; there was nothing to do.", idx.display())
		return nil
	case err != nil && isLockTimeout(err):
		return fmt.Errorf("the table %s stayed busy with long-running work, so Rowsafe couldn't remove the index %s without getting in the way; "+
			"if it is now marked invalid, PostgreSQL no longer uses it and applying the fix again finishes the job", f.table, idx.display())
	case err != nil:
		return fmt.Errorf("removing the index %s failed: %w", idx.display(), plainPGError(err))
	}
	adj := "unused"
	if !m.p.Unused {
		adj = "duplicate"
	}
	m.res.Summary = fmt.Sprintf("Removed the %s index %s (freed %s).", adj, idx.display(), humanBytes(f.bytes))
	return nil
}

var errIndexGone = errors.New("index gone")

// noRetry wraps an error retryOnLock must not retry.
type noRetry struct{ err error }

func (e noRetry) Error() string { return e.err.Error() }
func (e noRetry) Unwrap() error { return e.err }

// retryOnLock runs fn, trying again a few times after a lock timeout.
func retryOnLock(ctx context.Context, tl *taskLog, fn func() error) error {
	var err error
	for attempt := 1; attempt <= lockRetries; attempt++ {
		var stop noRetry
		if err = fn(); err == nil || !isLockTimeout(err) || attempt == lockRetries || errors.As(err, &stop) {
			return err
		}
		wait := time.Duration(attempt) * lockRetryWait
		tl.Printf("another session holds a conflicting lock; trying again in %s", wait)
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
	}
	return err
}

// ---- cancel query, terminate session ----

// session is a row of pg_stat_activity.
type session struct {
	backendStart time.Time
	backendType  string
	appName      string
	user, db     string
	state        string
	stateSecs    float64 // since the current query (active) or the last state change
	xactSecs     float64
	self         bool
}

// signalRefusal says why a session must not be cancelled or ended ("" when
// it may be).
func signalRefusal(s session, action string) string {
	verb := "end"
	if action == protocol.MaintCancelQuery {
		verb = "cancel"
	}
	app := strings.ToLower(s.appName)
	switch {
	case s.self:
		return "that is Rowsafe's own session"
	case strings.HasPrefix(app, "rowsafe") || strings.HasPrefix(app, "pgbackrest"):
		return fmt.Sprintf("that session belongs to Rowsafe itself (%s), so Rowsafe didn't %s it", s.appName, verb)
	case s.backendType == "walsender" || strings.Contains(s.backendType, "wal"):
		return fmt.Sprintf("that session is streaming replication, so Rowsafe didn't %s it", verb)
	case strings.Contains(s.backendType, "autovacuum"):
		return fmt.Sprintf("that is PostgreSQL's own autovacuum, so Rowsafe didn't %s it", verb)
	case s.backendType != "client backend":
		return fmt.Sprintf("that is one of PostgreSQL's own processes (%s), so Rowsafe didn't %s it", s.backendType, verb)
	}
	return ""
}

func (m *maint) signalBackend(ctx context.Context) error {
	conn, err := m.connect(ctx, "postgres", map[string]string{"statement_timeout": "10s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	s, found, err := readSession(ctx, conn, m.p.PID)
	if err != nil {
		return err
	}
	cancel := m.p.Action == protocol.MaintCancelQuery
	if !found || !sameInstant(s.backendStart, *m.p.BackendStart) {
		if cancel {
			m.res.Summary = "The query had already finished (its session has ended), so there was nothing to cancel."
		} else {
			m.res.Summary = "The session had already ended, so there was nothing to do."
		}
		m.tl.Printf("pid %d: found=%v, backend_start %v (expected %v)", m.p.PID, found, s.backendStart, m.p.BackendStart.UTC())
		return nil
	}
	if why := signalRefusal(s, m.p.Action); why != "" {
		return errors.New(why)
	}
	who := describeSession(s)
	if cancel {
		if s.state != "active" {
			m.res.Summary = fmt.Sprintf("The query of %s had already finished, so there was nothing to cancel.", sessionOwner(s))
			return nil
		}
		var ok bool
		if err := conn.QueryRow(ctx, `SELECT pg_cancel_backend($1)`, m.p.PID).Scan(&ok); err != nil {
			return fmt.Errorf("PostgreSQL refused to cancel the query: %w", plainPGError(err))
		}
		if !ok {
			m.res.Summary = "The query had already finished, so there was nothing to cancel."
			return nil
		}
		m.tl.Printf("cancelled the query of pid %d (%s)", m.p.PID, who)
		m.res.Summary = fmt.Sprintf("Cancelled the query of %s; it had been running for %s. The session stays connected, and the application gets an error for that query.",
			sessionOwner(s), plainDuration(time.Duration(s.stateSecs*float64(time.Second))))
		return nil
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, m.p.PID).Scan(&ok); err != nil {
		return fmt.Errorf("PostgreSQL refused to end the session: %w", plainPGError(err))
	}
	if !ok {
		m.res.Summary = "The session had already ended, so there was nothing to do."
		return nil
	}
	m.tl.Printf("ended pid %d (%s)", m.p.PID, who)
	// Wait briefly until it is gone (it rolls back its transaction first).
	gone := false
	for i := 0; i < 50 && ctx.Err() == nil; i++ {
		_, still, err := readSession(ctx, conn, m.p.PID)
		if err != nil || !still {
			gone = err == nil
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	m.res.Summary = fmt.Sprintf("Ended the session of %s.", who)
	if s.state == "idle in transaction" || s.state == "idle in transaction (aborted)" || s.xactSecs > 0 {
		m.res.Summary += " Its unfinished transaction was rolled back."
	}
	if !gone {
		m.res.Details = append(m.res.Details, "PostgreSQL is still rolling back its work; the session disappears when that is done.")
	}
	return nil
}

func readSession(ctx context.Context, conn *pgx.Conn, pid int) (session, bool, error) {
	var s session
	err := conn.QueryRow(ctx, `
		SELECT backend_start, coalesce(backend_type, ''), coalesce(application_name, ''),
		       coalesce(usename::text, ''), coalesce(datname::text, ''), coalesce(state, ''),
		       coalesce(extract(epoch FROM clock_timestamp() - CASE WHEN state = 'active' THEN query_start ELSE state_change END), 0)::float8,
		       coalesce(extract(epoch FROM clock_timestamp() - xact_start), 0)::float8,
		       pid = pg_backend_pid()
		FROM pg_stat_activity WHERE pid = $1`, pid).Scan(&s.backendStart, &s.backendType, &s.appName,
		&s.user, &s.db, &s.state, &s.stateSecs, &s.xactSecs, &s.self)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, false, nil
	}
	return s, err == nil, err
}

// sameInstant compares backend_start values to the microsecond (what
// PostgreSQL stores).
func sameInstant(a, b time.Time) bool {
	return a.Truncate(time.Microsecond).Equal(b.Truncate(time.Microsecond))
}

func sessionOwner(s session) string {
	switch {
	case s.user != "" && s.db != "":
		return fmt.Sprintf("%s (database %s)", s.user, s.db)
	case s.user != "":
		return s.user
	}
	return "a session"
}

// describeSession: "app_user (database shop) that was idle in a
// transaction for 3h 12m".
func describeSession(s session) string {
	d := plainDuration(time.Duration(s.stateSecs * float64(time.Second)))
	who := sessionOwner(s)
	switch s.state {
	case "idle in transaction", "idle in transaction (aborted)":
		return fmt.Sprintf("%s that was idle in a transaction for %s", who, d)
	case "active":
		return fmt.Sprintf("%s that had been running a query for %s", who, d)
	case "idle":
		return fmt.Sprintf("%s that was idle for %s", who, d)
	}
	return who
}

// ---- replication slot ----

func (m *maint) dropSlot(ctx context.Context) error {
	conn, err := m.connect(ctx, "postgres", map[string]string{"statement_timeout": "10s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	var active bool
	var slotType, slotDB string
	var retained *int64
	err = conn.QueryRow(ctx, `
		SELECT active, slot_type, coalesce(database::text, ''),
		       CASE WHEN restart_lsn IS NULL THEN NULL
		            WHEN pg_is_in_recovery() THEN pg_wal_lsn_diff(pg_last_wal_replay_lsn(), restart_lsn)::int8
		            ELSE pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::int8 END
		FROM pg_replication_slots WHERE slot_name = $1`, m.p.Slot).Scan(&active, &slotType, &slotDB, &retained)
	if errors.Is(err, pgx.ErrNoRows) {
		m.res.Summary = fmt.Sprintf("The replication slot %s was already removed; there was nothing to do.", m.p.Slot)
		return nil
	}
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("the replication slot %s is in use again (a replica or subscriber is connected), so Rowsafe didn't remove it", m.p.Slot)
	}
	m.tl.Printf("dropping inactive %s slot %s (retaining %v bytes of WAL)", slotType, m.p.Slot, retained)
	if _, err := conn.Exec(ctx, `SELECT pg_drop_replication_slot($1)`, m.p.Slot); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "55006" { // object_in_use: became active
			return fmt.Errorf("the replication slot %s became active while Rowsafe was removing it, so it was left alone", m.p.Slot)
		}
		if errors.As(err, &pe) && pe.Code == "42704" { // undefined_object
			m.res.Summary = fmt.Sprintf("The replication slot %s was already removed; there was nothing to do.", m.p.Slot)
			return nil
		}
		return fmt.Errorf("removing the replication slot %s failed: %w", m.p.Slot, plainPGError(err))
	}
	m.res.Summary = fmt.Sprintf("Removed the inactive replication slot %s", m.p.Slot)
	if retained != nil && *retained > 0 {
		m.res.Summary += fmt.Sprintf("; PostgreSQL can now recycle the %s of WAL it was keeping for it", humanBytes(*retained))
	}
	m.res.Summary += "."
	if slotType == "logical" {
		m.res.Details = append(m.res.Details, fmt.Sprintf("It was a logical slot of database %s; a subscriber that used it has to be set up again.", slotDB))
	} else {
		m.res.Details = append(m.res.Details, "A replica that used it has to be re-synced if it comes back.")
	}
	return nil
}

// ---- errors and words ----

func isLockTimeout(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

// plainPGError keeps PostgreSQL's message but drops the "ERROR: ... (SQLSTATE
// ...)" wrapping.
func plainPGError(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		msg := pe.Message
		if pe.Detail != "" {
			msg += " (" + pe.Detail + ")"
		}
		return errors.New(msg)
	}
	return err
}

// plainCount: 812, 8,120, 120 thousand, 1.2 million, 1.2 billion.
func plainCount(n int64) string {
	switch {
	case n < 10_000:
		s := fmt.Sprint(n)
		if n >= 1000 {
			s = s[:len(s)-3] + "," + s[len(s)-3:]
		}
		return s
	case n < 1_000_000:
		return fmt.Sprintf("%d thousand", (n+500)/1000)
	case n < 1_000_000_000:
		return trimZero(fmt.Sprintf("%.1f", float64(n)/1e6)) + " million"
	}
	return trimZero(fmt.Sprintf("%.1f", float64(n)/1e9)) + " billion"
}

// sentence makes an error message a sentence: capitalized, with a period.
func sentence(err error) error {
	msg := strings.TrimSpace(err.Error())
	if msg == "" {
		return err
	}
	r, n := utf8.DecodeRuneInString(msg)
	msg = strings.ToUpper(string(r)) + msg[n:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return errors.New(msg)
}

func withArticle(noun string) string {
	if strings.ContainsRune("aeiou", rune(noun[0])) {
		return "an " + noun
	}
	return "a " + noun
}

func trimZero(s string) string { return strings.TrimSuffix(s, ".0") }

// plainDuration: 45s, 12m, 3h 12m, 2d 4h.
func plainDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		h := int(d.Hours())
		if m := int(d.Minutes()) % 60; m > 0 {
			return fmt.Sprintf("%dh %dm", h, m)
		}
		return fmt.Sprintf("%dh", h)
	}
	days := int(d.Hours()) / 24
	if h := int(d.Hours()) % 24; h > 0 {
		return fmt.Sprintf("%dd %dh", days, h)
	}
	return fmt.Sprintf("%dd", days)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func countNoun(n int, one, many string) string { return fmt.Sprintf("%d %s", n, plural(n, one, many)) }

func isAre(n int) string { return plural(n, "was", "were") }

func itThem(n int) string { return plural(n, "it", "them") }

func existExists(n int) string { return plural(n, "exists", "exist") }
