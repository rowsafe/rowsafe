package pulse

import (
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// "Do it yourself" SQL for what has no fix right now.
const (
	connectionsSQL = "SELECT application_name, state, count(*) FROM pg_stat_activity GROUP BY 1, 2 ORDER BY 3 DESC;"
	longXactSQL    = "SELECT pid, now() - xact_start AS open_for, application_name, state, left(query, 80) FROM pg_stat_activity WHERE xact_start IS NOT NULL ORDER BY xact_start LIMIT 5; -- then SELECT pg_terminate_backend(PID);"
	idleXactSQL    = "SELECT pid, now() - state_change AS idle_for, application_name, usename FROM pg_stat_activity WHERE state LIKE 'idle in transaction%' ORDER BY state_change; -- then SELECT pg_terminate_backend(PID);"
	blockedSQL     = "SELECT pid, pg_blocking_pids(pid) AS blocked_by, left(query, 80) FROM pg_stat_activity WHERE cardinality(pg_blocking_pids(pid)) > 0;"
)

// idleSessionMin: an idle transaction older than this is offered for
// ending when connections run out.
const idleSessionMin = 5 * time.Minute

// ---- disk (only when the database runs on this machine) ----

func (e *evaluator) disk(fresh bool) {
	const label = "Disk space"
	freePct, ok := e.in.Metrics[collect.MDiskFreePct]
	if !fresh || !ok {
		why := "No disk readings (PostgreSQL shows its data directory only to superusers)."
		if e.mysqlFamily() || e.mongodb() || e.redisFamily() {
			why = "No disk readings (the data directory isn't on this machine's disk)."
		}
		e.check(CatDisk, label, "unknown", why)
		return
	}
	freeBytes := e.in.Metrics[collect.MDiskFreeBytes]
	name := e.engineName()
	space := e.spaceFixes()
	full, cmd := "Free up or add disk space now. The change log folder (pg_wal) grows when archiving or a replication slot holds it back.", "df -h; du -sh $PGDATA/pg_wal"
	if e.mysqlFamily() {
		full, cmd = "Free up or add disk space now. Old binary logs (binlog_expire_logs_seconds) and tables with free space inside are the usual places to look.", "df -h; du -sh /var/lib/mysql"
	}
	if e.redisFamily() {
		full, cmd = "Free up or add disk space now: "+name+" can no longer save its snapshots and may refuse writes. Old snapshot or append-only files and other programs' files are the usual places to look.", "df -h; redis-cli CONFIG GET dir"
	}
	if e.mongodb() {
		full, cmd = "Free up or add disk space now. Unused indexes and collections nobody needs any more are the usual places to look; MongoDB gives the space of deleted documents back only when a collection is compacted.", "df -h; du -sh /var/lib/mongodb"
	}
	switch {
	case freePct < 5:
		e.add(protocol.Finding{ID: "disk_almost_full", Category: CatDisk, Severity: protocol.SeverityCritical, Penalty: 30,
			Title:       fmt.Sprintf("The disk is almost full (%s free)", Bytes(freeBytes)),
			Explanation: map[bool]string{false: "When the disk fills up, " + name + " stops accepting changes and may shut down.", true: "When the disk fills up, " + name + " can no longer save its snapshots and may refuse writes."}[e.redisFamily()],
			Action:      diskAction(full, space),
			Command:     cmd,
			Fixes:       space})
	case freePct < 15:
		e.add(protocol.Finding{ID: "disk_low", Category: CatDisk, Severity: protocol.SeverityWarning, Penalty: 15,
			Title:       fmt.Sprintf("Disk space is running low (%.0f%% free)", freePct),
			Explanation: "Less than 15% of the disk is free. When it fills up, " + name + map[bool]string{false: " stops accepting changes.", true: " can no longer save its snapshots and may refuse writes."}[e.redisFamily()],
			Action:      diskAction(map[bool]string{false: "Plan more disk space, or reclaim space from bloated tables and unused indexes.", true: "Plan more disk space, or reclaim space from old data and unused indexes."}[e.mongodb()], space),
			Fixes:       space})
	}
	status, _ := e.statusOf(CatDisk, "ok", "")
	e.check(CatDisk, label, status, fmt.Sprintf("%.0f%% free (%s).", freePct, Bytes(freeBytes)))
}

func diskAction(base string, fixes []protocol.FindingFix) string {
	if len(fixes) > 0 {
		return base + " Rowsafe can give some space back right away: see the fixes below."
	}
	return base
}

// ---- connections ----

func (e *evaluator) connections(fresh bool) {
	const label = "Connections"
	m := e.in.Metrics
	used, ok := m[collect.MConnUsedPct]
	if !fresh || !ok {
		e.check(CatConnections, label, "unknown", "No connection readings.")
		return
	}
	total, maxc := m[collect.MConnTotal], m[collect.MConnMax]
	detail := fmt.Sprintf("%.0f of %.0f in use.", total, maxc)
	if maxc <= 0 {
		detail = fmt.Sprintf("%.0f%% in use.", used)
	}
	idle := e.idleSessionFixes(idleSessionMin)
	fixes := append(idle[:len(idle):len(idle)], e.in.ConnectionFixes...)
	switch {
	case used >= 95:
		e.add(protocol.Finding{ID: "connections_exhausted", Category: CatConnections, Severity: protocol.SeverityCritical, Penalty: 15,
			Title:       fmt.Sprintf("Almost out of connections (%.0f of %.0f)", total, maxc),
			Explanation: "PostgreSQL allows a fixed number of connections. When they run out, your application gets errors connecting.",
			Action:      connAction(idle, "A connection pooler such as PgBouncer usually fixes this for good."),
			Command:     connectionsSQL,
			Fixes:       fixes})
		e.check(CatConnections, label, "critical", detail)
	case used >= 80:
		e.add(protocol.Finding{ID: "connections_high", Category: CatConnections, Severity: protocol.SeverityWarning, Penalty: 8,
			Title:       fmt.Sprintf("Most connections are in use (%.0f of %.0f)", total, maxc),
			Explanation: "Over 80% of the allowed connections are taken. A traffic spike could use up the rest, and new connections would fail.",
			Action:      connAction(idle, "Look for idle connections held open by applications, or add a connection pooler."),
			Command:     connectionsSQL,
			Fixes:       fixes})
		e.check(CatConnections, label, "warning", detail)
	default:
		e.check(CatConnections, label, "ok", detail)
	}
}

func connAction(fixes []protocol.FindingFix, base string) string {
	if len(fixes) > 0 {
		return "End the sessions that sit idle inside a transaction to free their connections. " + base
	}
	return base
}

// ---- maintenance: vacuum, wraparound, bloat, long transactions ----

func (e *evaluator) maintenance(fresh bool) {
	const label = "Maintenance"
	m := e.in.Metrics
	if fresh {
		if h, ok := m[collect.MXIDHeadroomPct]; ok {
			freeze := append(e.freezeFixes(e.oldestTables()), e.slotFixes(1)...)
			switch {
			case h < 20:
				e.add(protocol.Finding{ID: "xid_wraparound", Category: CatMaintenance, Severity: protocol.SeverityCritical, Penalty: 30,
					Title:       "Close to a forced write stop (transaction ID wraparound)",
					Explanation: fmt.Sprintf("PostgreSQL numbers every transaction and must regularly \"freeze\" old rows. Only %.0f%% of the numbers are left; at zero, PostgreSQL refuses all writes until a long cleanup finishes.", h),
					Action:      withFixes(freeze, "Freeze the oldest tables now; this gives PostgreSQL back its transaction numbers. Long transactions and abandoned replication slots hold the cleanup back: end or drop them.", "Vacuum the oldest tables now; end long transactions and remove unused replication slots that hold cleanup back."),
					Command:     withFixes(freeze, "", "SELECT relname, age(relfrozenxid) FROM pg_class WHERE relkind = 'r' ORDER BY 2 DESC LIMIT 10; -- then VACUUM (FREEZE, VERBOSE) the table"),
					Fixes:       freeze})
			case h < 50:
				e.add(protocol.Finding{ID: "xid_wraparound", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 15,
					Title:       "Old rows are not being frozen fast enough",
					Explanation: fmt.Sprintf("Only %.0f%% of transaction ID headroom is left. Autovacuum normally keeps this far higher; something is holding it back.", h),
					Action:      withFixes(freeze, "Freeze the oldest tables, and end long transactions and drop abandoned replication slots, which hold the cleanup back.", "Look for long transactions and abandoned replication slots, and vacuum the oldest tables."),
					Fixes:       freeze})
			}
		}
		e.multixact()           // autovacuum.go
		e.autovacuumSaturated() // autovacuum.go
		// A session holding back cleanup is named by cleanup_blocked
		// (cleanup.go), with its dead rows: no second finding for it.
		named := e.cleanupBlocked(fresh)
		if s, ok := m[collect.MLongestXactSeconds]; ok && s >= 30*60 && !named {
			pen := 5
			if s >= 6*3600 {
				pen = 10
			}
			long := e.sessionFixes(func(x session) bool { return x.xact >= 30*60 }, func(x session) float64 { return x.xact }, 3, "")
			e.add(protocol.Finding{ID: "long_transaction", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: pen,
				Title:       "A transaction has been open for " + secsAgo(s),
				Explanation: "While a transaction stays open, PostgreSQL can't clean up rows changed since it began, so tables grow and slow down. It may also hold locks others wait for.",
				Action:      withFixes(long, "If nobody needs it, end it: its changes are rolled back.", "Find it "+e.on("activity")+" and, if nobody needs it, end it."),
				Command:     withFixes(long, "", longXactSQL),
				Fixes:       long})
		} else if s, ok := m[collect.MIdleInXactOldest]; ok && s >= 10*60 && !named {
			idle := e.idleSessionFixes(10 * time.Minute)
			e.add(protocol.Finding{ID: "idle_in_transaction", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 5,
				Title:       "An application left a transaction open and idle",
				Explanation: fmt.Sprintf("A session started a transaction %s ago and has done nothing since, usually an application that forgot to commit. It blocks cleanup and may hold locks.", secsAgo(s)),
				Action:      withFixes(idle, "End the idle session now, then fix the application's transaction handling. The idle_in_transaction_session_timeout setting ends such sessions automatically.", "Find the application "+e.on("activity")+" and fix its transaction handling; the idle_in_transaction_session_timeout setting ends such sessions automatically."),
				Command:     withFixes(idle, "", idleXactSQL),
				Fixes:       idle})
		}
	}
	ins := e.insights()
	if ins != nil {
		if behind := e.vacuumBehind(ins); len(behind) > 0 {
			t := behind[0]
			var ts []table
			for _, b := range behind {
				ts = append(ts, table{b.Database, b.Schema, b.Table})
			}
			fixes := e.vacuumFixes(ts, "Clean up", "to clear out their dead rows so the space is reused")
			e.add(protocol.Finding{ID: "vacuum_behind", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 5,
				Title:       fmt.Sprintf("Cleanup is falling behind on %s", plural(len(behind), "table", "tables")),
				Explanation: fmt.Sprintf("%s is %.0f%% dead rows (%s) that autovacuum has not cleaned up in over a day. Dead rows waste space and slow down queries.", qualified(t.Schema, t.Table), t.DeadPct, count(t.DeadRows)),
				Action:      withFixes(fixes, "Clean them up now. If it keeps happening, autovacuum needs to run more often on these busy tables.", "Vacuum it now, and make autovacuum run more often on busy tables."),
				Command:     withFixes(fixes, "", fmt.Sprintf("VACUUM (VERBOSE, ANALYZE) %s;", qualified(t.Schema, t.Table))),
				Fixes:       fixes})
		}
		e.bloat(ins)
	}
	status, detail := "ok", "Cleanup is keeping up."
	if h, ok := m[collect.MXIDHeadroomPct]; ok && fresh {
		detail = fmt.Sprintf("Cleanup is keeping up; %.0f%% transaction ID headroom.", h)
	}
	if !fresh && ins == nil {
		status, detail = "unknown", e.noReadings()
	}
	status, detail = e.statusOf(CatMaintenance, status, detail)
	e.check(CatMaintenance, label, status, detail)
}

func (e *evaluator) bloat(ins *protocol.Insights) {
	var worst *protocol.TableBloat
	var wasted int64
	var fixes []protocol.FindingFix
	var bloated []table
	var bloatedTables []protocol.TableBloat
	for i, t := range ins.TableBloat {
		if t.BloatPct >= 30 && t.BloatBytes >= 256<<20 {
			wasted += t.BloatBytes
			bloated = append(bloated, table{t.Database, t.Schema, t.Table})
			bloatedTables = append(bloatedTables, t)
			if worst == nil {
				worst = &ins.TableBloat[i]
			}
		}
	}
	// pg_repack gives a table's space back without a long lock (tools.go).
	repack := e.repackFixes(ins, bloatedTables)
	fixes = append(fixes, repack...)
	for _, x := range ins.IndexBloat {
		if x.BloatPct >= 30 && x.BloatBytes >= 256<<20 {
			wasted += x.BloatBytes
			if x.Database != "" && x.Schema != "" && len(fixes) < maxReindexFixes {
				fixes = append(fixes, e.reindexFix(x))
			}
		}
	}
	tidy := "so the space inside them is reused and they stop growing (giving it back to the disk needs a full rebuild; see Do it yourself)"
	if len(repack) > 0 {
		tidy = "so the space inside them is reused and they stop growing"
	}
	fixes = append(fixes, e.vacuumFixes(bloated, "Tidy up", tidy)...)
	if wasted == 0 {
		return
	}
	sev, pen := protocol.SeverityInfo, 2
	if wasted >= 1<<30 {
		sev, pen = protocol.SeverityWarning, 5
	}
	what := "Indexes waste"
	command := "REINDEX INDEX CONCURRENTLY <index>;"
	if worst != nil {
		what = fmt.Sprintf("%s alone wastes an estimated %s (%.0f%%); in all, tables and indexes waste", qualified(worst.Schema, worst.Table), Bytes(float64(worst.BloatBytes)), worst.BloatPct)
		command = "pg_repack, or VACUUM FULL " + qualified(worst.Schema, worst.Table) + " in a maintenance window (it locks the table)"
	}
	action := withFixes(fixes, "Rebuild the bloated indexes and tidy up the tables now. Giving a table's space back to the disk needs a full rebuild that locks it, so that is for a maintenance window (see Do it yourself).", "Rebuild the worst tables and indexes when convenient; this gives the space back.")
	if len(repack) > 0 {
		action = "Rebuild the bloated tables with pg_repack: it gives their space back to the disk while your app keeps working, with only a brief lock at the start and the end."
		command = ""
	}
	e.add(protocol.Finding{ID: "bloat", Category: CatMaintenance, Severity: sev, Penalty: pen,
		Title:       fmt.Sprintf("About %s of disk is wasted space (estimate)", Bytes(float64(wasted))),
		Explanation: fmt.Sprintf("%s about %s on space left behind by updates and deletes. It is an estimate from PostgreSQL's statistics.", what, Bytes(float64(wasted))),
		Action:      action,
		Command:     command,
		Fixes:       fixes})
}

// insights returns the insights if recent enough to act on.
func (e *evaluator) insights() *protocol.Insights {
	ins := e.in.Insights
	if ins == nil || e.now.Sub(ins.CollectedAt) > insightsFresh {
		return nil
	}
	return ins
}

// vacuumBehind are the tables whose dead rows autovacuum has not cleaned
// up in over a day.
func (e *evaluator) vacuumBehind(ins *protocol.Insights) []protocol.TableVacuum {
	var behind []protocol.TableVacuum
	for _, t := range ins.VacuumStats {
		last := latest(t.LastVacuum, t.LastAutovacuum)
		if t.DeadPct >= 20 && t.DeadRows >= 100_000 && (last == nil || e.now.Sub(*last) > 24*time.Hour) {
			behind = append(behind, t)
		}
	}
	return behind
}

// ---- performance ----

func (e *evaluator) performance(fresh bool) {
	const label = "Performance"
	m := e.in.Metrics
	if fresh {
		if s, ok := m[collect.MLongestBlockedSeconds]; ok && s >= 60 {
			pen := 5
			if s >= 300 {
				pen = 10
			}
			blockers := e.blockerFixes()
			e.add(protocol.Finding{ID: "blocked_queries", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: pen,
				Title:       fmt.Sprintf("Queries are stuck waiting for a lock (%s)", secsAgo(s)),
				Explanation: fmt.Sprintf("%s waiting for a lock another session holds. The application may be slow or timing out.", plural(int(m[collect.MBlockedSessions]), "session is", "sessions are")),
				Action:      withFixes(blockers, "End the session holding the lock if it is safe to (or stop just its query); the sessions waiting for it then continue.", "See who is blocking whom "+e.on("activity")+" and end the blocking session if it is safe to."),
				Command:     withFixes(blockers, "", blockedSQL),
				Fixes:       blockers})
		}
		if v, ok := m[collect.MCacheHitPct]; ok && v < 90 {
			if more, ok := e.memoryAwaitingRestart(); ok {
				restart := e.in.RestartFixes
				e.add(protocol.Finding{ID: "cache_hit_low", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 3,
					Title:       fmt.Sprintf("Only %.0f%% of reads come from memory", v),
					Explanation: fmt.Sprintf("Most reads should be served from PostgreSQL's memory cache. More memory for it (%s) is already set and takes effect when PostgreSQL restarts.", more),
					Action:      "Restart PostgreSQL when a few seconds of disconnection suit your apps.",
					Command:     withFixes(availableFixes(restart), "", e.restartCommand()),
					Fixes:       restart})
			} else {
				fix := e.memoryTuneFix()
				top, tuning := e.cmd("top"), "("+e.cmd("tune")+")"
				if e.in.Dashboard {
					top, tuning = "Top queries and Recommendations", "on the Tuning page"
				}
				e.add(protocol.Finding{ID: "cache_hit_low", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 3,
					Title:       fmt.Sprintf("Only %.0f%% of reads come from memory", v),
					Explanation: "Most reads should be served from PostgreSQL's memory cache. Reading from disk this often makes queries slower; the data in use may not fit in memory. Right after a restart this is normal and clears up by itself.",
					Action: withFixes(fix, "Give PostgreSQL more of this server's memory (Tune for this server), and look at "+top+" for queries that read whole tables.",
						"Look at "+top+" for queries that read whole tables; if the server has memory to spare, raise shared_buffers "+tuning+"."),
					Fixes: fix})
			}
		}
	}
	e.extra(PointAfterCache)
	if ins := e.insights(); ins != nil {
		var unusedBytes int64
		var unused int
		for _, x := range ins.UnusedIndexes {
			if x.Bytes >= 10<<20 {
				unusedBytes += x.Bytes
				unused++
			}
		}
		if unused > 0 {
			ex := ins.UnusedIndexes[0]
			drops := e.unusedIndexFixes(maxIndexFixes)
			e.add(protocol.Finding{ID: "unused_indexes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       fmt.Sprintf("%s never used (%s)", plural(unused, "index is", "indexes are"), Bytes(float64(unusedBytes))),
				Explanation: fmt.Sprintf("%s Each one slows down every write and takes disk space; the largest is %s. If you run reports on a replica, check there first.", unusedSince, ex.Index),
				Action:      "Drop the ones you are sure you don't need.",
				Command:     withFixes(drops, "", fmt.Sprintf("DROP INDEX CONCURRENTLY %s;", qualified(ex.Schema, ex.Index))),
				Fixes:       drops})
		}
		if len(ins.DuplicateIndexes) > 0 {
			d := ins.DuplicateIndexes[0]
			drops := e.duplicateIndexFixes()
			e.add(protocol.Finding{ID: "duplicate_indexes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       fmt.Sprintf("%s another index already covers", plural(len(ins.DuplicateIndexes), "index repeats what", "indexes repeat what")),
				Explanation: fmt.Sprintf("%s on %s is not needed: %s does the same job. Extra indexes slow down writes and take space.", d.Index, d.Table, d.CoveredBy),
				Action:      "Drop the redundant index.",
				Command:     withFixes(drops, "", fmt.Sprintf("DROP INDEX CONCURRENTLY %s;", qualified(d.Schema, d.Index))),
				Fixes:       drops})
		}
		if len(ins.SeqScanTables) > 0 {
			t := ins.SeqScanTables[0]
			e.add(protocol.Finding{ID: "missing_index", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       fmt.Sprintf("%s may be missing an index", qualified(t.Schema, t.Table)),
				Explanation: fmt.Sprintf("Queries read this %s-row table from start to finish %s times, about %s rows each time. An index on the columns they filter by would usually make them much faster.", count(t.LiveRows), count(t.SeqScans), count(t.SeqRows/max(t.SeqScans, 1))),
				Action:      e.missingIndexAction(),
				Command:     fmt.Sprintf("CREATE INDEX CONCURRENTLY ON %s (<column>);", qualified(t.Schema, t.Table))})
		}
	}
	e.extra(PointAfterIndexes)
	e.settingsFindings() // settings.go
	e.extra(PointEnd)
	status, detail := "ok", "No problems found."
	if !fresh {
		status, detail = "unknown", e.noReadings()
	}
	for _, x := range e.findings {
		if x.Category != CatPerformance {
			continue
		}
		if x.Severity == protocol.SeverityWarning {
			status, detail = "warning", x.Title+"."
			break
		}
		if detail == "No problems found." {
			detail = "Suggestions: " + lowerFirst(x.Title) + "."
		}
	}
	e.check(CatPerformance, label, status, detail)
}

const unusedSince = "No query has used them since statistics were last reset."

func (e *evaluator) missingIndexAction() string {
	if e.in.Dashboard {
		return "Pulse, Recommendations finds the indexes your busiest queries need, tests each one on a copy of your database, and creates the ones you pick."
	}
	return "Find the queries that read it with " + e.cmd("top") + ", then index the columns they filter by."
}

// on says where people find something: "on the Activity page" in the
// dashboard, "with rowsafe activity ..." in a terminal.
func (e *evaluator) on(place string) string {
	if e.in.Dashboard {
		return map[string]string{"activity": "on the Activity page"}[place]
	}
	return "with " + e.cmd(place)
}

// ---- replication ----

func (e *evaluator) replication(fresh bool) {
	const label = "Replication"
	m := e.in.Metrics
	rs := e.in.Replication
	if fresh {
		if v, ok := m[collect.MSlotInactiveRetain]; ok && v > 1<<30 {
			drops := e.slotFixes(1 << 20)
			e.add(protocol.Finding{ID: "inactive_slot", Category: CatReplication, Severity: protocol.SeverityWarning, Penalty: 10,
				Title:       fmt.Sprintf("An unused replication slot is holding %s of disk", Bytes(v)),
				Explanation: "A replication slot keeps PostgreSQL's change log until its consumer reads it. Its consumer is gone, so the log grows until the disk is full.",
				Action:      "If the replica or tool that used it is gone for good, drop the slot.",
				Command:     withFixes(drops, "", "SELECT slot_name, active FROM pg_replication_slots; SELECT pg_drop_replication_slot('NAME');"),
				Fixes:       drops})
		}
		if v, ok := m[collect.MLogicalSlotLagBytes]; ok && v > 1<<30 {
			e.add(protocol.Finding{ID: "logical_slot_lag", Category: CatReplication, Severity: protocol.SeverityWarning, Penalty: 5,
				Title:       fmt.Sprintf("A logical replication consumer is %s behind", Bytes(v)),
				Explanation: "A tool reading changes from this database (logical replication, change data capture) has fallen behind. The unread changes stay on disk.",
				Action:      "Check that the subscriber or CDC tool is running and keeping up.",
				Command:     "SELECT slot_name, active, confirmed_flush_lsn FROM pg_replication_slots WHERE slot_type = 'logical';"})
		}
		if lag, ok := m[collect.MReplicationLagSeconds]; ok && lag >= 300 {
			sev, pen := protocol.SeverityWarning, 10
			if lag >= 1800 {
				sev, pen = protocol.SeverityCritical, 20
			}
			who := "A replica is"
			if rs != nil && rs.Role == "replica" {
				who = "This replica is"
			}
			e.add(protocol.Finding{ID: "replication_lag", Category: CatReplication, Severity: sev, Penalty: pen,
				Title:       fmt.Sprintf("%s %s behind", who, secsAgo(lag)),
				Explanation: "Reads from the replica return old data, and switching over to it now would lose the most recent changes.",
				Action:      "Check the replica's network, disk and load, and long queries on it that pause replay.",
				Command:     "SELECT application_name, state, replay_lag FROM pg_stat_replication;"})
		}
	}
	if rs != nil && rs.Role == "replica" && rs.Receiver != nil && rs.Receiver.Status != "streaming" && fresh {
		e.add(protocol.Finding{ID: "replica_disconnected", Category: CatReplication, Severity: protocol.SeverityCritical, Penalty: 20,
			Title:       "This replica is not connected to its primary",
			Explanation: "It is not receiving changes, so it falls further behind every minute.",
			Action:      "Check the network to the primary and the replica's PostgreSQL log.",
			Command:     "SELECT * FROM pg_stat_wal_receiver;"})
	}
	status, detail := "ok", "No replicas."
	switch {
	case !fresh && rs == nil:
		status, detail = "unknown", e.noReadings()
	case rs != nil && rs.Role == "replica":
		detail = "This server is a replica."
		if rs.ReplayLagSeconds != nil {
			detail = fmt.Sprintf("This server is a replica, %s behind.", secs(*rs.ReplayLagSeconds))
		}
	case rs != nil && len(rs.Replicas) > 0:
		var worst float64
		for _, r := range rs.Replicas {
			if r.ReplayLagSeconds != nil {
				worst = max(worst, *r.ReplayLagSeconds)
			}
		}
		detail = fmt.Sprintf("%s, at most %s behind.", plural(len(rs.Replicas), "replica", "replicas"), secs(worst))
	}
	for _, x := range e.findings {
		if x.Category == CatReplication {
			if x.Severity == protocol.SeverityCritical {
				status = "critical"
			} else if status != "critical" {
				status = "warning"
			}
			detail = x.Title + "."
		}
	}
	e.check(CatReplication, label, status, detail)
}
