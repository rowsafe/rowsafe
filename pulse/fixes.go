package pulse

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Fixes: what Rowsafe can do about a finding. Each carries its full
// parameters (protocol.MaintenanceParams or SettingsParams); the code that
// runs it looks every name up again in the catalogs and checks again that
// it is safe, so a fix built from an older reading can only be refused,
// never do something else. Fix IDs are the dashboard's:
//
//	end:<pid>:<backend_start unix>        end a session
//	cancel:<pid>:<backend_start unix>     cancel its query
//	vacuum:<db>, freeze:<db>
//	reindex:<db>.<schema>.<index>, drop:<db>.<schema>.<index>
//	drop_slot:<slot>
//	tune, enable_pg_stat_statements      (settings.go)

const (
	maxSessionFixes   = 5
	maxBlockerFixes   = 3
	maxIndexFixes     = 10
	maxReindexFixes   = 5
	maxSlotFixes      = 5
	maxTablesPerFix   = 20
	maxFreezeTables   = 5
	maxDiskIndexFixes = 3
)

// fix builds a fix; Input.Fix says whether it can run now.
func (e *evaluator) fix(id, kind, label, desc string, params any) protocol.FindingFix {
	fx := protocol.FindingFix{ID: id, Kind: kind, Label: label, Description: desc, Available: true}
	if params != nil {
		fx.Params, _ = json.Marshal(params)
	}
	if e.in.Fix != nil {
		fx = e.in.Fix(fx)
	}
	return fx
}

// availableFixes are the fixes that can run now.
func availableFixes(fixes []protocol.FindingFix) []protocol.FindingFix {
	var out []protocol.FindingFix
	for _, f := range fixes {
		if f.Available {
			out = append(out, f)
		}
	}
	return out
}

// confirm makes a fix ask before it runs.
func confirm(fx protocol.FindingFix, warning string, destructive bool) protocol.FindingFix {
	fx.Confirm, fx.Destructive = warning, destructive
	return fx
}

// withFixes picks the action (or command) for a finding with fixes and
// without: with a fix, the command is only the "Do it yourself".
func withFixes(fixes []protocol.FindingFix, with, without string) string {
	if len(fixes) > 0 {
		return with
	}
	return without
}

// ---- sessions ----

// activity returns the activity snapshot if recent enough to act on.
func (e *evaluator) activity() *protocol.Activity {
	a := e.in.Activity
	if a == nil || a.CollectedAt.IsZero() || e.now.Sub(a.CollectedAt) > activityFresh {
		return nil
	}
	return a
}

// ownSession: Rowsafe's own and backup sessions are never offered.
func ownSession(app string) bool {
	a := strings.ToLower(app)
	return strings.HasPrefix(a, "rowsafe") || strings.HasPrefix(a, "pgbackrest")
}

// session is what a session fix needs from ActivityQuery or LockSession.
type session struct {
	pid                  int
	start                *time.Time
	state, app, user, db string
	duration, xact       float64 // seconds
}

func (s session) who() string {
	var parts []string
	if s.user != "" {
		parts = append(parts, "user "+s.user)
	}
	if s.db != "" {
		parts = append(parts, "database "+s.db)
	}
	app := "A session"
	if s.app != "" {
		app = s.app
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s (session %d)", app, s.pid)
	}
	return fmt.Sprintf("%s (session %d, %s)", app, s.pid, strings.Join(parts, ", "))
}

func idleInXact(state string) bool { return strings.HasPrefix(state, "idle in transaction") }

// doing describes what a session is doing, for a fix description.
func (s session) doing() string {
	if idleInXact(s.state) {
		return fmt.Sprintf("opened a transaction %s ago and has been idle for %s", secsAgo(max(s.xact, s.duration)), secsAgo(s.duration))
	}
	if s.xact > s.duration+60 {
		return fmt.Sprintf("has been running a query for %s, in a transaction open for %s", secsAgo(s.duration), secsAgo(s.xact))
	}
	return fmt.Sprintf("has been running a query for %s", secsAgo(s.duration))
}

func fromQuery(q protocol.ActivityQuery) session {
	return session{pid: q.PID, start: q.BackendStart, state: q.State, app: q.ApplicationName, user: q.User, db: q.Database,
		duration: q.DurationSeconds, xact: q.XactSeconds}
}

func fromLock(q protocol.LockSession) session {
	return session{pid: q.PID, start: q.BackendStart, state: q.State, app: q.ApplicationName, user: q.User, db: q.Database,
		duration: q.DurationSeconds, xact: q.XactSeconds}
}

// endFix ends a session (pg_terminate_backend), identified by PID and
// backend start so a reused PID is never hit.
func (e *evaluator) endFix(s session, why string) protocol.FindingFix {
	desc := fmt.Sprintf("%s %s. %sEnding it rolls back its open transaction. Takes a few seconds; the app that opened it gets an error and should reconnect.",
		s.who(), s.doing(), why)
	fx := e.fix(fmt.Sprintf("end:%d:%d", s.pid, s.start.Unix()), protocol.FixMaintenance, fmt.Sprintf("End session %d", s.pid), desc,
		protocol.MaintenanceParams{Action: protocol.MaintTerminateSession, PID: s.pid, BackendStart: s.start})
	return confirm(fx, fmt.Sprintf("End session %d? Its open transaction is rolled back, and the app that opened it gets an error.", s.pid), true)
}

// cancelFix cancels a session's running query (pg_cancel_backend).
func (e *evaluator) cancelFix(s session) protocol.FindingFix {
	desc := fmt.Sprintf("%s %s. Stopping the query keeps the session connected; the app gets an error for that query. Takes a second.",
		s.who(), s.doing())
	return e.fix(fmt.Sprintf("cancel:%d:%d", s.pid, s.start.Unix()), protocol.FixMaintenance, fmt.Sprintf("Stop the query of session %d", s.pid), desc,
		protocol.MaintenanceParams{Action: protocol.MaintCancelQuery, PID: s.pid, BackendStart: s.start})
}

// sessionFixes offer ending (and, for a running query, first cancelling)
// the sessions of the activity snapshot that match, longest first.
func (e *evaluator) sessionFixes(match func(session) bool, by func(session) float64, limit int, why string) []protocol.FindingFix {
	a := e.activity()
	if a == nil {
		return nil
	}
	var ss []session
	for _, q := range a.Queries {
		if s := fromQuery(q); s.start != nil && !ownSession(s.app) && match(s) {
			ss = append(ss, s)
		}
	}
	slices.SortStableFunc(ss, func(x, y session) int { return cmp.Compare(by(y), by(x)) })
	var out []protocol.FindingFix
	for _, s := range ss[:min(len(ss), limit)] {
		if s.state == "active" {
			out = append(out, e.cancelFix(s))
		}
		out = append(out, e.endFix(s, why))
	}
	return out
}

func (e *evaluator) idleSessionFixes(minAge time.Duration) []protocol.FindingFix {
	return e.sessionFixes(func(s session) bool { return idleInXact(s.state) && s.duration >= minAge.Seconds() },
		func(s session) float64 { return s.duration }, maxSessionFixes, "")
}

// blockerFixes offer ending the sessions at the root of lock chains.
func (e *evaluator) blockerFixes() []protocol.FindingFix {
	a := e.activity()
	if a == nil {
		return nil
	}
	var roots []protocol.LockSession
	for _, s := range a.Blocking {
		if s.Blocking > 0 && len(s.BlockedBy) == 0 && s.BackendStart != nil && !ownSession(s.ApplicationName) {
			roots = append(roots, s)
		}
	}
	slices.SortStableFunc(roots, func(x, y protocol.LockSession) int { return cmp.Compare(y.Blocking, x.Blocking) })
	var out []protocol.FindingFix
	for _, r := range roots[:min(len(roots), maxBlockerFixes)] {
		s := fromLock(r)
		why := fmt.Sprintf("%s waiting for it. ", plural(r.Blocking, "session is", "sessions are"))
		if s.state == "active" {
			out = append(out, e.cancelFix(s))
		}
		out = append(out, e.endFix(s, why))
	}
	return out
}

// ---- tables and indexes ----

// table is one table of a database of the cluster.
type table struct{ db, schema, name string }

func (t table) qualified() string { return t.schema + "." + t.name }

// byDatabase groups tables by database, in order of first appearance.
func byDatabase(ts []table) (dbs []string, tables map[string][]table) {
	tables = map[string][]table{}
	for _, t := range ts {
		if t.db == "" || t.schema == "" || t.name == "" {
			continue
		}
		if _, ok := tables[t.db]; !ok {
			dbs = append(dbs, t.db)
		}
		tables[t.db] = append(tables[t.db], t)
	}
	return dbs, tables
}

// names lists up to three tables for a description.
func names(ts []table) string {
	var n []string
	for _, t := range ts[:min(len(ts), 3)] {
		n = append(n, qualified(t.schema, t.name))
	}
	s := strings.Join(n, ", ")
	if len(ts) > 3 {
		s += fmt.Sprintf(" and %d more", len(ts)-3)
	}
	return s
}

// tableFixes builds one maintenance fix per database.
func (e *evaluator) tableFixes(ts []table, build func(db string, ts []table, several bool) protocol.FindingFix) []protocol.FindingFix {
	dbs, tables := byDatabase(ts)
	var out []protocol.FindingFix
	for _, db := range dbs {
		out = append(out, build(db, tables[db][:min(len(tables[db]), maxTablesPerFix)], len(dbs) > 1))
	}
	return out
}

func tableList(ts []table) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.qualified()
	}
	return out
}

func inDB(label, db string, several bool) string {
	if several {
		return label + " in " + db
	}
	return label
}

// vacuumFixes clean up dead rows (VACUUM ANALYZE).
func (e *evaluator) vacuumFixes(ts []table, verb, what string) []protocol.FindingFix {
	return e.tableFixes(ts, func(db string, ts []table, several bool) protocol.FindingFix {
		return e.fix("vacuum:"+db, protocol.FixMaintenance, inDB(fmt.Sprintf("%s %s", verb, plural(len(ts), "table", "tables")), db, several),
			fmt.Sprintf("Runs VACUUM on %s %s. Your app keeps working while it runs; it goes easy on the server and can take a few minutes on big tables.", names(ts), what),
			protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: db, Tables: tableList(ts)})
	})
}

// freezeFixes freeze the oldest tables (VACUUM FREEZE).
func (e *evaluator) freezeFixes(ts []table) []protocol.FindingFix {
	return e.tableFixes(ts, func(db string, ts []table, several bool) protocol.FindingFix {
		return e.fix("freeze:"+db, protocol.FixMaintenance, inDB("Freeze the "+plural(len(ts), "oldest table", "oldest tables"), db, several),
			fmt.Sprintf("Runs VACUUM (FREEZE) on %s, the tables with the oldest rows, which gives PostgreSQL back its transaction numbers. Your app keeps working; on big tables it can take a while.", names(ts)),
			protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: db, Tables: tableList(ts), Freeze: true})
	})
}

// oldestTables are the tables with the oldest unfrozen rows, per database.
func (e *evaluator) oldestTables() []table {
	ins := e.insights()
	if ins == nil {
		return nil
	}
	n := map[string]int{}
	var out []table
	for _, t := range ins.FreezeAge {
		if n[t.Database] >= maxFreezeTables {
			continue
		}
		n[t.Database]++
		out = append(out, table{t.Database, t.Schema, t.Table})
	}
	return out
}

// dropIndexFix drops an unused or duplicate index, after a Mark when the
// database is backed up (Input.MarkFirst).
func (e *evaluator) dropIndexFix(db, schema, tbl, index string, bytes int64, unused bool, why string) protocol.FindingFix {
	desc := fmt.Sprintf("%s Dropping it gives back %s of disk and makes writes to %s a little faster. Your app keeps working while it is dropped.",
		why, Bytes(float64(bytes)), qualified(schema, tbl))
	switch {
	case e.in.MarkFirst:
		desc += " Rowsafe saves a Mark first, and the task log keeps the index's definition to recreate it."
	case e.in.Dashboard:
		desc += " The task log keeps the index's definition to recreate it."
	default:
		desc += " Rowsafe shows its definition afterwards, to create it again if needed."
	}
	fx := e.fix("drop:"+db+"."+schema+"."+index, protocol.FixMaintenance, "Drop "+index, desc,
		protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: db, Index: schema + "." + index, Unused: unused})
	fx = confirm(fx, fmt.Sprintf("Drop the index %s on %s? Any query that needs it would be slower until it is created again.", index, qualified(schema, tbl)), true)
	fx.MarkFirst = e.in.MarkFirst
	return fx
}

// inDatabases adds "in DB" to index fix labels when they span databases
// (a cluster can have an index of the same name in several).
func inDatabases(fixes []protocol.FindingFix, dbs []string) []protocol.FindingFix {
	several := false
	for _, db := range dbs {
		several = several || db != dbs[0]
	}
	if several {
		for i := range fixes {
			fixes[i].Label += " in " + dbs[i]
		}
	}
	return fixes
}

func (e *evaluator) unusedIndexFixes(limit int) []protocol.FindingFix {
	ins := e.insights()
	if ins == nil {
		return nil
	}
	var out []protocol.FindingFix
	var dbs []string
	for _, x := range ins.UnusedIndexes {
		if x.Bytes < 10<<20 || x.Database == "" || x.Schema == "" || len(out) >= limit {
			continue
		}
		out = append(out, e.dropIndexFix(x.Database, x.Schema, x.Table, x.Index, x.Bytes, true,
			strings.Replace(unusedSince, "them", x.Index, 1)))
		dbs = append(dbs, x.Database)
	}
	return inDatabases(out, dbs)
}

func (e *evaluator) duplicateIndexFixes() []protocol.FindingFix {
	ins := e.insights()
	if ins == nil {
		return nil
	}
	var out []protocol.FindingFix
	var dbs []string
	for _, d := range ins.DuplicateIndexes {
		if d.Database == "" || d.Schema == "" || len(out) >= maxIndexFixes {
			continue
		}
		out = append(out, e.dropIndexFix(d.Database, d.Schema, d.Table, d.Index, d.Bytes, false,
			fmt.Sprintf("%s already does the job of %s.", d.CoveredBy, d.Index)))
		dbs = append(dbs, d.Database)
	}
	return inDatabases(out, dbs)
}

// reindexFix rebuilds a bloated index (REINDEX INDEX CONCURRENTLY).
func (e *evaluator) reindexFix(x protocol.IndexBloat) protocol.FindingFix {
	fx := e.fix("reindex:"+x.Database+"."+x.Schema+"."+x.Index, protocol.FixMaintenance, "Rebuild "+x.Index,
		fmt.Sprintf("Builds a fresh copy of %s next to the old one and swaps them, giving back about %s. Reads and writes keep working; it needs about %s of free disk while it runs.",
			x.Index, Bytes(float64(x.BloatBytes)), Bytes(float64(x.IndexBytes-x.BloatBytes))),
		protocol.MaintenanceParams{Action: protocol.MaintReindexIndex, DB: x.Database, Index: x.Schema + "." + x.Index})
	if e.in.VersionNum > 0 && e.in.VersionNum < 120000 && fx.Available {
		fx.Available, fx.Reason = false, "Rebuilding an index without blocking your app needs PostgreSQL 12 or newer."
	}
	return fx
}

// ---- replication slots ----

// slotFixes drop inactive replication slots holding at least minBytes.
func (e *evaluator) slotFixes(minBytes int64) []protocol.FindingFix {
	var slots []protocol.ReplicationSlot
	for _, s := range e.in.Slots {
		if !s.Active && s.Name != "" && s.RetainedBytes != nil && *s.RetainedBytes >= minBytes {
			slots = append(slots, s)
		}
	}
	slices.SortStableFunc(slots, func(a, b protocol.ReplicationSlot) int { return cmp.Compare(*b.RetainedBytes, *a.RetainedBytes) })
	var out []protocol.FindingFix
	for _, s := range slots[:min(len(slots), maxSlotFixes)] {
		out = append(out, e.dropSlotFix(s, fmt.Sprintf("The %s replication slot %s has no consumer and holds %s of change log. Dropping it lets PostgreSQL delete that log.",
			s.Type, s.Name, Bytes(float64(*s.RetainedBytes)))))
	}
	return out
}

// dropSlotFix drops an inactive replication slot; why says what it holds.
func (e *evaluator) dropSlotFix(s protocol.ReplicationSlot, why string) protocol.FindingFix {
	fx := e.fix("drop_slot:"+s.Name, protocol.FixMaintenance, "Drop slot "+s.Name,
		why+" Takes a second; nothing else is affected.",
		protocol.MaintenanceParams{Action: protocol.MaintDropReplicationSlot, Slot: s.Name})
	return confirm(fx, fmt.Sprintf("Drop the replication slot %s? If the replica or tool that used it comes back, it has to be set up again from scratch.", s.Name), true)
}

// spaceFixes are the fixes that give disk space back: abandoned
// replication slots and the largest unused indexes.
func (e *evaluator) spaceFixes() []protocol.FindingFix {
	if e.mysqlFamily() || e.mongodb() || e.redisFamily() {
		return nil // MySQL: OPTIMIZE TABLE, with its own finding (mysql.go); MongoDB: its index findings (mongodb.go)
	}
	return append(e.slotFixes(64<<20), e.unusedIndexFixes(maxDiskIndexFixes)...)
}
