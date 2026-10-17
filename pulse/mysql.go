package pulse

import (
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// MySQL and MariaDB (Input.Engine): sessions, InnoDB's old row versions,
// free space inside tables, locks, the buffer pool and the slow query log,
// with the fixes the MySQL code runs over a connection (stop a query, end
// a session, OPTIMIZE TABLE, turn on the slow query log, drop an index).
// The dashboard runs these too (it adds binary log shipping); without it,
// unused and duplicate indexes and tables without a primary key are
// findings here (the dashboard lists them under Recommendations).

func (e *evaluator) mysqlFamily() bool {
	eng := protocol.NormalizeEngine(e.in.Engine)
	return eng == protocol.EngineMySQL || eng == protocol.EngineMariaDB
}

func (e *evaluator) mariadb() bool {
	return protocol.NormalizeEngine(e.in.Engine) == protocol.EngineMariaDB
}

// engineName is the database's engine for people: PostgreSQL, MySQL,
// MariaDB, MongoDB.
func (e *evaluator) engineName() string {
	if e.mysqlFamily() || e.mongodb() {
		return protocol.EngineDisplayName(e.in.Engine)
	}
	return "PostgreSQL"
}

// Thresholds.
const (
	// optimizeMin: free space inside a table worth a rebuild.
	optimizeMin = 256 << 20
	// noPKMinRows: a table without a primary key worth a finding.
	noPKMinRows = 1_000
)

// MySQL runs the MySQL and MariaDB rules on their own (connections,
// maintenance, performance): their findings in order, and the sections'
// status lines.
func (r *Rules) MySQL(fresh bool) ([]protocol.Finding, []protocol.HealthCheck) {
	r.e.findings, r.e.checks = nil, map[string]*protocol.HealthCheck{}
	r.e.mysql(fresh)
	var checks []protocol.HealthCheck
	for _, cat := range []string{CatConnections, CatMaintenance, CatPerformance} {
		if c, ok := r.e.checks[cat]; ok {
			checks = append(checks, *c)
		}
	}
	return r.e.findings, checks
}

func (e *evaluator) mysql(fresh bool) {
	name := e.engineName()
	m := e.in.Metrics
	if !fresh {
		e.check(CatConnections, "Connections", "unknown", "No readings.")
		return
	}

	// Connections.
	if used, ok := m[collect.MConnUsedPct]; ok {
		total, maxc := m[collect.MConnTotal], m[collect.MConnMax]
		idle := e.idleSessionFixes(idleSessionMin)
		detail := fmt.Sprintf("%.0f of %.0f in use.", total, maxc)
		switch {
		case used >= 95:
			e.add(protocol.Finding{ID: "connections_exhausted", Category: CatConnections, Severity: protocol.SeverityCritical, Penalty: 15,
				Title:       fmt.Sprintf("Almost out of connections (%.0f of %.0f)", total, maxc),
				Explanation: fmt.Sprintf("%s allows a fixed number of connections (max_connections). When they run out, your application gets errors connecting.", name),
				Action:      connAction(idle, "A connection pool in the application usually fixes this for good."),
				Fixes:       idle})
			e.check(CatConnections, "Connections", "critical", detail)
		case used >= 80:
			e.add(protocol.Finding{ID: "connections_high", Category: CatConnections, Severity: protocol.SeverityWarning, Penalty: 8,
				Title:       fmt.Sprintf("Most connections are in use (%.0f of %.0f)", total, maxc),
				Explanation: "Over 80% of the allowed connections are taken. A traffic spike could use up the rest, and new connections would fail.",
				Action:      connAction(idle, "Look for idle connections held open by applications, or use a connection pool."),
				Fixes:       idle})
			e.check(CatConnections, "Connections", "warning", detail)
		default:
			e.check(CatConnections, "Connections", "ok", detail)
		}
	}

	// Long and idle transactions.
	maint := "ok"
	if secs, ok := m[collect.MLongestXactSeconds]; ok && secs >= 30*60 {
		fixes := e.sessionFixes(func(s session) bool { return s.xact >= 30*60 || idleInXact(s.state) && s.duration >= 30*60 },
			func(s session) float64 { return s.xact }, maxSessionFixes, "")
		e.add(protocol.Finding{ID: "long_transaction", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 8,
			Title:       fmt.Sprintf("A transaction has been open for %s", Ago(time.Duration(secs*float64(time.Second)))),
			Explanation: "While it stays open, InnoDB keeps every old row version it might read: queries slow down and the data files grow. It may also hold row locks others wait for.",
			Action:      withFixes(fixes, "End it if nobody needs it; its changes are rolled back.", "Find the session "+e.on("activity")+" and end it if nobody needs it."),
			Fixes:       fixes})
		maint = "warning"
	} else if secs, ok := m[collect.MIdleInXactOldest]; ok && secs >= 10*60 {
		fixes := e.idleSessionFixes(10 * time.Minute)
		e.add(protocol.Finding{ID: "idle_in_transaction", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("A session has sat idle in a transaction for %s", Ago(time.Duration(secs*float64(time.Second)))),
			Explanation: "The application opened a transaction and never finished it. It holds its row locks and keeps old row versions around.",
			Action:      withFixes(fixes, "End the session, then fix the application's transaction handling.", "Find the session "+e.on("activity")+" and end it."),
			Fixes:       fixes})
		maint = "warning"
	}
	if v, ok := m[collect.MHistoryListLength]; ok && v >= 1_000_000 {
		e.add(protocol.Finding{ID: "innodb_history_long", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("%s old row versions are piling up", commas(v)),
			Explanation: "InnoDB cleans up old row versions once no transaction can read them. Something (usually a transaction left open) keeps it from doing that: queries slow down and files grow.",
			Action:      "End the oldest open transaction if nobody needs it (" + e.where("activity") + ").",
		})
		maint = "warning"
	}
	if ins := e.insights(); ins != nil {
		var fixes []protocol.FindingFix
		var total int64
		for _, b := range ins.TableBloat {
			if b.BloatBytes < optimizeMin || b.BloatPct < 30 || len(fixes) >= maxTablesPerFix {
				continue
			}
			total += b.BloatBytes
			fixes = append(fixes, e.optimizeFix(b))
		}
		if len(fixes) > 0 {
			e.add(protocol.Finding{ID: "table_free_space", Category: CatMaintenance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       fmt.Sprintf("%s of free space inside %s", Bytes(float64(total)), plural(len(fixes), "table", "tables")),
				Explanation: "Deleted rows leave space inside InnoDB tables that the table reuses but the disk doesn't get back. Rebuilding the table returns it.",
				Action:      "Rebuild the tables when the disk space matters (a quiet hour is best).",
				Fixes:       fixes})
		}
	}
	e.check(CatMaintenance, "Maintenance", maint, map[string]string{"ok": "Nothing to do.", "warning": "See the findings."}[maint])

	// Locks and cache.
	perf := "ok"
	if secs, ok := m[collect.MLongestBlockedSeconds]; ok && secs >= 60 {
		blockers := e.blockerFixes()
		e.add(protocol.Finding{ID: "blocked_queries", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("Queries are stuck waiting for a lock (%s)", Ago(time.Duration(secs*float64(time.Second)))),
			Explanation: fmt.Sprintf("%s waiting for a row lock another session holds. The application may be slow or timing out.", plural(int(m[collect.MBlockedSessions]), "session is", "sessions are")),
			Action:      withFixes(blockers, "End the session holding the lock if it is safe to (or stop just its query); the sessions waiting for it then continue.", "See who is blocking whom "+e.on("activity")+"."),
			Fixes:       blockers})
		perf = "warning"
	}
	if v, ok := m[collect.MCacheHitPct]; ok && v < 90 {
		action := "Look for queries scanning whole large tables (Top queries), or give the buffer pool more memory (innodb_buffer_pool_size)."
		if !e.in.Dashboard {
			action = "Look for queries scanning whole large tables (" + e.cmd("top") + "), or give the buffer pool more memory (innodb_buffer_pool_size; " + e.cmd("tune") + " suggests a size)."
		}
		e.add(protocol.Finding{ID: "cache_hit_low", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 3,
			Title:       fmt.Sprintf("Only %.0f%% of reads come from memory", v),
			Explanation: fmt.Sprintf("Most reads should come from InnoDB's buffer pool. Reading from disk this often makes queries slower; the data in use may not fit in %s's memory.", name),
			Action:      action})
	}
	if !e.in.Dashboard {
		e.mysqlIndexes(name)
	}
	e.check(CatPerformance, "Performance", perf, map[string]string{"ok": "No stuck queries.", "warning": "Queries are waiting for locks."}[perf])
	e.mysqlSlowLog(name)
}

// where names the place to look for something, in brackets: "Activity
// page" in the dashboard, the command in a terminal.
func (e *evaluator) where(place string) string {
	if e.in.Dashboard {
		return map[string]string{"activity": "Activity page"}[place]
	}
	return e.cmd(place)
}

// optimizeFix rebuilds a table with free space inside (OPTIMIZE TABLE).
// It needs room for another copy of the table, which the code that runs it
// checks on the server's disk: from a connection to another machine it
// can't, so it doesn't run.
func (e *evaluator) optimizeFix(b protocol.TableBloat) protocol.FindingFix {
	fx := e.fix("optimize:"+b.Database+"."+b.Table, protocol.FixMaintenance, fmt.Sprintf("Rebuild %s.%s", b.Database, b.Table),
		fmt.Sprintf("Runs OPTIMIZE TABLE on %s.%s, which rebuilds it to give %s of free space back to the disk. It copies the table (Rowsafe checks there is room), and writes to it may wait briefly at the start and end; on a big table it takes a while.",
			b.Database, b.Table, Bytes(float64(b.BloatBytes))),
		protocol.MaintenanceParams{Action: protocol.MaintOptimize, DB: b.Database, Tables: []string{b.Table}})
	fx = confirm(fx, fmt.Sprintf("Rebuild %s.%s now? It copies the table; writes to it may wait briefly.", b.Database, b.Table), false)
	if !e.in.Dashboard && !e.in.Local && fx.Available {
		fx.Available = false
		fx.Reason = fmt.Sprintf("Rebuilding copies the table, and Rowsafe can't see the server's disk from here (another machine or a container) to check there is room. Check the disk has %s free, then run OPTIMIZE TABLE %s.%s yourself.",
			Bytes(float64(2*b.TableBytes+1<<30)), b.Database, b.Table)
	}
	return fx
}

// mysqlSlowLog: the slow query log off (Logs can't show slow queries, and
// the index check on MariaDB and MySQL 5.7 takes its samples from it), or
// growing with nothing rotating it.
func (e *evaluator) mysqlSlowLog(name string) {
	ins := e.insights()
	if ins == nil || ins.Advisor == nil || ins.Advisor.SlowLog == nil {
		return
	}
	sl := ins.Advisor.SlowLog
	if !sl.On {
		desc := "Turns on " + name + "'s slow query log for statements over 1 second, " +
			map[bool]string{true: "with SET PERSIST, so it stays on after a restart. ", false: "with SET GLOBAL: it lasts until the next restart unless the configuration file sets it too. "}[sl.Persist] +
			"Nothing restarts; it costs very little."
		if !sl.Rotated {
			if e.in.Dashboard || e.in.Local {
				desc += " " + name + " doesn't rotate the file by itself; Pulse warns if it grows past 1 GB."
			} else {
				desc += " " + name + " doesn't rotate the file by itself: set up logrotate for it on the server."
			}
		}
		var fixes []protocol.FindingFix
		if sl.CanSet && protocol.EngineHas(e.in.Engine, protocol.FeatureFixes) {
			fx := e.fix("slow_log", protocol.FixMaintenance, "Turn on the slow query log", desc, protocol.MaintenanceParams{Action: protocol.MaintSlowLog})
			fixes = append(fixes, confirm(fx, fmt.Sprintf("Turn on %s's slow query log (statements over 1 second)?", name), false))
		}
		explanation := name + "'s slow query log is off, so Logs can't show slow statements" + map[bool]string{true: ", and Rowsafe can't test index ideas (it takes a run of each slow query from that log).", false: "."}[e.mariadb() || !sl.Persist]
		account := "Rowsafe's database account"
		if !e.in.Dashboard {
			explanation = name + "'s slow query log is off, so there is no record of the statements that took long."
			account = "this connection's account"
		}
		e.add(protocol.Finding{ID: "mysql_slow_log_off", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 1,
			Title:       "Slow queries aren't logged",
			Explanation: explanation,
			Action:      withFixes(fixes, "Turn it on for statements over 1 second.", "Turn it on for statements over 1 second ("+account+" may not change server settings)."),
			Command:     withFixes(fixes, "", "SET GLOBAL long_query_time = 1; SET GLOBAL slow_query_log = ON;  # and slow_query_log = ON, long_query_time = 1 under [mysqld]"),
			Fixes:       fixes})
		return
	}
	if !sl.Rotated && sl.Bytes >= 1<<30 {
		e.add(protocol.Finding{ID: "mysql_slow_log_big", Category: CatDisk, Severity: protocol.SeverityWarning, Penalty: 3,
			Title:       fmt.Sprintf("The slow query log has grown to %s", Bytes(float64(sl.Bytes))),
			Explanation: fmt.Sprintf("%s keeps adding to %s and nothing rotates it, so it keeps taking disk space.", name, sl.File),
			Action:      "Rotate it with logrotate (copytruncate), or raise long_query_time so fewer statements are logged.",
			Command:     fmt.Sprintf("sudo tee /etc/logrotate.d/rowsafe-mysql-slow <<'EOF'\n%s {\n  weekly\n  rotate 4\n  compress\n  missingok\n  copytruncate\n}\nEOF", sl.File)})
	}
}

// mysqlIndexes: unused and duplicate indexes, and large tables without a
// primary key (without the dashboard, whose Recommendations list them).
func (e *evaluator) mysqlIndexes(name string) {
	ins := e.insights()
	if ins == nil {
		return
	}
	since := fmt.Sprintf("No query has used them since %s last started.", name)
	var unusedBytes int64
	var unused []protocol.UnusedIndex
	for _, x := range ins.UnusedIndexes {
		if x.Bytes >= 10<<20 {
			unusedBytes += x.Bytes
			unused = append(unused, x)
		}
	}
	if len(unused) > 0 {
		var drops []protocol.FindingFix
		for _, x := range unused[:min(len(unused), maxIndexFixes)] {
			drops = append(drops, e.mysqlDropIndexFix(x.Database, x.Table, x.Index, x.Bytes, true, strings.Replace(since, "them", x.Index, 1)))
		}
		e.add(protocol.Finding{ID: "unused_indexes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
			Title:       fmt.Sprintf("%s never used (%s)", plural(len(unused), "index is", "indexes are"), Bytes(float64(unusedBytes))),
			Explanation: fmt.Sprintf("%s Each one slows down every write and takes disk space; the largest is %s. Index use is only counted while the server runs: check that no monthly job or report needs them, and if you run reports on a replica, check there first.", since, unused[0].Index),
			Action:      "Drop the ones you are sure you don't need.",
			Fixes:       drops})
	}
	if len(ins.DuplicateIndexes) > 0 {
		d := ins.DuplicateIndexes[0]
		var drops []protocol.FindingFix
		for _, x := range ins.DuplicateIndexes[:min(len(ins.DuplicateIndexes), maxIndexFixes)] {
			drops = append(drops, e.mysqlDropIndexFix(x.Database, x.Table, x.Index, x.Bytes, false, fmt.Sprintf("%s already does the job of %s.", x.CoveredBy, x.Index)))
		}
		e.add(protocol.Finding{ID: "duplicate_indexes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
			Title:       fmt.Sprintf("%s another index already covers", plural(len(ins.DuplicateIndexes), "index repeats what", "indexes repeat what")),
			Explanation: fmt.Sprintf("%s on %s.%s is not needed: %s does the same job. Extra indexes slow down writes and take space.", d.Index, d.Database, d.Table, d.CoveredBy),
			Action:      "Drop the redundant index; the one that covers it stays.",
			Fixes:       drops})
	}
	if ins.Advisor == nil {
		return
	}
	var nopk []protocol.TableWithoutPK
	for _, t := range ins.Advisor.NoPrimaryKey {
		if t.RowsEstimate >= noPKMinRows {
			nopk = append(nopk, t)
		}
	}
	if len(nopk) > 0 {
		t := nopk[0]
		tbl := t.Database + "." + t.Table
		title := tbl + " has no primary key"
		if len(nopk) > 1 {
			title = fmt.Sprintf("%d tables have no primary key", len(nopk))
		}
		e.add(protocol.Finding{ID: "no_primary_key", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 1,
			Title: title,
			Explanation: fmt.Sprintf("%s (about %s rows) has no primary key, nor a unique index on columns that can't be empty, so InnoDB orders its rows by a hidden key and they can't be told apart reliably. "+
				"Replicas apply each update or delete on it by scanning the table, and Group Replication and many online migration tools refuse it.", tbl, count(t.RowsEstimate)),
			Action:  "Add a primary key: on a column that is already unique and never empty, or a new id column. Rowsafe doesn't change your tables' structure; on a big table this rebuilds it (online: writes continue).",
			Command: fmt.Sprintf("ALTER TABLE %s ADD COLUMN id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, ALGORITHM=INPLACE, LOCK=NONE;", mysqlName(t.Database, t.Table))})
	}
}

// mysqlDropIndexFix drops an unused or duplicate index online
// (ALGORITHM=INPLACE, LOCK=NONE); never a primary key or unique index.
func (e *evaluator) mysqlDropIndexFix(db, tbl, index string, bytes int64, unused bool, why string) protocol.FindingFix {
	desc := fmt.Sprintf("%s Dropping it gives back %s of disk and makes writes to %s.%s a little faster. Reads and writes go on while it is dropped.",
		why, Bytes(float64(bytes)), db, tbl)
	switch {
	case e.in.MarkFirst:
		desc += " Rowsafe saves a Mark first, and the task log keeps the index's definition to recreate it."
	case e.in.Dashboard:
		desc += " The task log keeps the index's definition to recreate it."
	default:
		desc += " Rowsafe shows its definition afterwards, to create it again if needed."
	}
	fx := e.fix("drop:"+db+"."+db+"."+index, protocol.FixMaintenance, "Drop "+index, desc,
		protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: db, Tables: []string{tbl}, Index: db + "." + index, Unused: unused})
	fx = confirm(fx, fmt.Sprintf("Drop the index %s on %s.%s? Any query that needs it would be slower until it is created again.", index, db, tbl), true)
	fx.MarkFirst = e.in.MarkFirst
	return fx
}

// mysqlName quotes db.table for MySQL.
func mysqlName(db, table string) string {
	q := func(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }
	return q(db) + "." + q(table)
}

// commas renders a count with thousands separators: 1,234,567.
func commas(v float64) string {
	s := fmt.Sprintf("%.0f", v)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}
