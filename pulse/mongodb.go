package pulse

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// MongoDB (Input.Engine): connections, operations running for long (with a
// fix to stop them), the WiredTiger cache, queued operations, the oplog's
// reach, replication lag and the profiler (with a fix to turn it on). The
// dashboard runs these too (internal/health in the control plane, with the
// same IDs and wording); without it, unused and redundant indexes are
// findings here, with a fix to drop them.

// Thresholds.
const (
	mongoLongOp       = 5 * time.Minute // an operation this long gets a finding
	mongoMaxKillFixes = 5
)

func (e *evaluator) mongodb() bool {
	return protocol.NormalizeEngine(e.in.Engine) == protocol.EngineMongoDB
}

// MongoDB runs the MongoDB rules on their own: their findings in order,
// and the sections' status lines.
func (r *Rules) MongoDB(fresh bool) ([]protocol.Finding, []protocol.HealthCheck) {
	r.e.findings, r.e.checks = nil, map[string]*protocol.HealthCheck{}
	r.e.mongo(fresh)
	var checks []protocol.HealthCheck
	for _, cat := range []string{CatConnections, CatPerformance, CatReplication} {
		if c, ok := r.e.checks[cat]; ok {
			checks = append(checks, *c)
		}
	}
	return r.e.findings, checks
}

func (e *evaluator) mongo(fresh bool) {
	m := e.in.Metrics
	if !fresh {
		e.check(CatConnections, "Connections", "unknown", "No connection readings.")
		return
	}
	// Connections.
	if used, ok := m[collect.MConnUsedPct]; ok {
		total, maxc := m[collect.MConnTotal], m[collect.MConnMax]
		detail := fmt.Sprintf("%.0f of %.0f in use.", total, maxc)
		switch {
		case used >= 80:
			sev, pen, status := protocol.SeverityWarning, 8, "warning"
			if used >= 95 {
				sev, pen, status = protocol.SeverityCritical, 15, "critical"
			}
			e.add(protocol.Finding{ID: "mongodb_connections_high", Category: CatConnections, Severity: sev, Penalty: pen,
				Title:       fmt.Sprintf("Most connections are in use (%.0f of %.0f)", total, maxc),
				Explanation: "MongoDB accepts a limited number of connections (net.maxIncomingConnections, and the server's open files limit). When they run out, your application gets errors connecting.",
				Action:      "Look for applications opening too many connections: every process's driver keeps its own pool (maxPoolSize), and they add up.",
				Command:     "mongosh --quiet --eval 'db.currentOp(true).inprog.reduce((a, o) => (a[o.appName || o.client] = (a[o.appName || o.client] || 0) + 1, a), {})'"})
			e.check(CatConnections, "Connections", status, detail)
		default:
			e.check(CatConnections, "Connections", "ok", detail)
		}
	}
	// Long operations, with a fix to stop them.
	perf := "ok"
	perfDetail := "No long-running operations."
	if a := e.activity(); a != nil {
		var long []protocol.ActivityQuery
		for _, q := range a.Queries {
			if q.DurationSeconds >= mongoLongOp.Seconds() && q.BackendStart != nil && !ownSession(q.ApplicationName) {
				long = append(long, q)
			}
		}
		slices.SortFunc(long, func(x, y protocol.ActivityQuery) int { return cmp.Compare(y.DurationSeconds, x.DurationSeconds) })
		if len(long) > 0 {
			var fixes []protocol.FindingFix
			for _, q := range long[:min(len(long), mongoMaxKillFixes)] {
				fixes = append(fixes, e.killOpFix(q))
			}
			e.add(protocol.Finding{ID: "mongodb_long_operation", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 8,
				Title:       fmt.Sprintf("%s running for over %s", plural(len(long), "operation", "operations"), Ago(mongoLongOp)),
				Explanation: fmt.Sprintf("The longest has been running for %s. Long operations hold resources and can slow everything else down; often it is a query without a matching index, or a job nobody is waiting for any more.", secsAgo(long[0].DurationSeconds)),
				Action:      withFixes(fixes, "Stop it if nobody is waiting for it; the app that started it gets an error for that operation.", "Find out what started it; stop it if nobody is waiting for it."),
				Command:     "mongosh --quiet --eval 'db.currentOp({secs_running: {$gte: 300}})'",
				Fixes:       fixes})
			perf, perfDetail = "warning", fmt.Sprintf("%s running for over %s.", plural(len(long), "operation", "operations"), Ago(mongoLongOp))
		}
	}
	if dirty, ok := m[collect.MMongoCacheDirtyPct]; ok && dirty >= 20 {
		e.add(protocol.Finding{ID: "mongodb_cache_pressure", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("MongoDB can't keep up writing changes to disk (%.0f%% of its cache waits)", dirty),
			Explanation: "Over 20% of the WiredTiger cache holds changes not yet written to disk. MongoDB then makes client writes help, which slows them down.",
			Action:      "Look at the disk's write speed and at bursts of writes; a larger cache (storage.wiredTiger.engineConfig.cacheSizeGB) or a faster disk helps."})
		if perf == "ok" {
			perf, perfDetail = "warning", "Writes are waiting for the disk."
		}
	}
	if q, ok := m[collect.MMongoQueuedOps]; ok && q >= 20 {
		where := "in Pulse"
		if !e.in.Dashboard {
			where = "(" + e.cmd("activity") + ", " + e.cmd("insights") + ")"
		}
		e.add(protocol.Finding{ID: "mongodb_queued_ops", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("%.0f operations are waiting their turn", q),
			Explanation: "Operations queue when MongoDB is busy with others (locks or storage tickets). Queues that last mean the server is overloaded.",
			Action:      "Look for long operations and missing indexes " + where + "; the slowest operations usually cause the queue."})
		if perf == "ok" {
			perf, perfDetail = "warning", "Operations are queueing."
		}
	}
	if wc, ok := m[collect.MMongoWriteConflicts]; ok && wc >= 100 {
		e.add(protocol.Finding{ID: "mongodb_write_conflicts", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("Writes keep colliding on the same documents (%.0f a minute)", wc),
			Explanation: "Two operations tried to change the same document at the same moment, and MongoDB had to retry one of them. A few are normal; this many usually means many clients update one hot document (a counter, a shared status), which slows those writes down and costs CPU.",
			Action:      "Spread hot counters over several documents, or use $inc on fields instead of read-modify-write; keep multi-document transactions short."})
		if perf == "ok" {
			perf, perfDetail = "warning", "Writes collide on the same documents."
		}
	}
	if !e.in.Dashboard {
		e.mongoIndexes()
	}
	e.check(CatPerformance, "Operations", perf, perfDetail)
	e.mongoProfiler()

	// The oplog window: how long the agent may stop without losing changes.
	if w, ok := m[collect.MMongoOplogWindow]; ok {
		window := Ago(time.Duration(w * float64(time.Hour)))
		switch {
		case w < 12:
			explanation := "Rowsafe copies MongoDB's changes (the oplog) about every minute, so nothing is lost while it runs. But if the agent or the storage were down for longer than the oplog reaches back, changes from that time couldn't be restored."
			if !e.in.Dashboard {
				explanation = "The oplog is MongoDB's record of recent changes: continuous backups and replicas read it. If one of them stops for longer than it reaches back, it has to start over from a full copy, and changes from that gap can't be restored."
			}
			e.add(protocol.Finding{ID: "mongodb_oplog_window", Category: CatReplication, Severity: protocol.SeverityWarning, Penalty: 8,
				Title:       fmt.Sprintf("MongoDB keeps only %s of changes", window),
				Explanation: explanation,
				Action:      "Give the oplog more room: MongoDB can resize it without a restart (replSetResizeOplog), e.g. to 5% of the disk.",
				Command:     "mongosh --quiet admin --eval 'db.adminCommand({replSetResizeOplog: 1, size: 16384})'  # size in MB"})
			e.check(CatReplication, "Change log (oplog)", "warning", "Reaches back "+window+".")
		default:
			e.check(CatReplication, "Change log (oplog)", "ok", "Reaches back "+window+".")
		}
	}
	if n := m[collect.MReplicasConnected]; n > 0 {
		if lag := m[collect.MReplicationLagSeconds]; lag >= 60 {
			e.add(protocol.Finding{ID: "mongodb_replication_lag", Category: CatReplication, Severity: protocol.SeverityWarning, Penalty: 8,
				Title:       fmt.Sprintf("A secondary is %s behind", secsAgo(lag)),
				Explanation: "A member of the replica set is behind the primary. Reads from it are stale, and if the primary failed now, the most recent writes could be rolled back.",
				Action:      "Look at the secondary's disk and network; rs.printSecondaryReplicationInfo() shows each member's delay."})
		}
	}
}

// mongoProfiler: query statistics come from MongoDB's profiler; off, the
// query statistics stay empty. The fix turns it on for slow operations (a
// runtime setting, nothing restarts).
func (e *evaluator) mongoProfiler() {
	ins := e.insights()
	if ins == nil || ins.Advisor == nil || ins.Advisor.Profiler == nil || len(ins.Advisor.Profiler.Off) == 0 {
		return
	}
	off := ins.Advisor.Profiler.Off
	var fixes []protocol.FindingFix
	if protocol.EngineHas(e.in.Engine, protocol.FeatureRecommendations) {
		fixes = append(fixes, e.fix("profile", protocol.FixMaintenance, "Turn on query statistics",
			fmt.Sprintf("Turns MongoDB's profiler on for slow operations (over %d ms) in %s. MongoDB then notes each slow operation in a small capped collection that Rowsafe reads. Nothing restarts; it costs very little.",
				max(ins.Advisor.Profiler.SlowMs, 100), strings.Join(off, ", ")),
			protocol.MaintenanceParams{Action: protocol.MaintMongoProfile, Tables: off}))
	}
	explanation := fmt.Sprintf("MongoDB's profiler is off in %s, so Rowsafe can't show which operations take the most time or which got slower.", strings.Join(off, ", "))
	if !e.in.Dashboard {
		explanation = fmt.Sprintf("MongoDB's profiler is off in %s, so %s can't show which operations take the most time.", strings.Join(off, ", "), e.cmd("top"))
	}
	e.add(protocol.Finding{ID: "mongodb_profiler_off", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
		Title:       fmt.Sprintf("Query statistics are off (MongoDB's profiler, in %s)", plural(len(off), "database", "databases")),
		Explanation: explanation,
		Action:      withFixes(fixes, "Turn it on for slow operations; it takes effect right away and resets at the next restart unless the configuration file sets it.", "Turn the profiler on for slow operations (level 1)."),
		Command:     "mongosh --quiet <database> --eval 'db.setProfilingLevel(1)'",
		Fixes:       fixes})
}

// killOpFix stops a MongoDB operation (killOp), identified by its opid and
// start so a reused opid is never hit.
func (e *evaluator) killOpFix(q protocol.ActivityQuery) protocol.FindingFix {
	who := "An operation"
	if q.ApplicationName != "" {
		who = q.ApplicationName + "'s operation"
	}
	where := ""
	if q.Database != "" {
		where = " on database " + q.Database
	}
	desc := fmt.Sprintf("%s %d%s has been running for %s. Stopping it ends only that operation; the app gets an error for it. Takes a second.",
		who, q.PID, where, secsAgo(q.DurationSeconds))
	fx := e.fix(fmt.Sprintf("kill:%d:%d", q.PID, q.BackendStart.Unix()), protocol.FixMaintenance, fmt.Sprintf("Stop operation %d", q.PID), desc,
		protocol.MaintenanceParams{Action: protocol.MaintKillOp, PID: q.PID, BackendStart: q.BackendStart})
	return confirm(fx, fmt.Sprintf("Stop operation %d? The app that started it gets an error for it.", q.PID), true)
}

// mongoIndexes: indexes nothing has used for a week and indexes another
// one makes unnecessary (without the dashboard, whose Recommendations list
// them), with a fix to drop each. Unique indexes and _id are never offered.
func (e *evaluator) mongoIndexes() {
	ins := e.insights()
	if ins == nil {
		return
	}
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
			drops = append(drops, e.mongoDropIndexFix(x.Database, x.Table, x.Index, x.Bytes, true,
				fmt.Sprintf("No query has used %s for over a week.", x.Index)))
		}
		e.add(protocol.Finding{ID: "unused_indexes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
			Title:       fmt.Sprintf("%s never used (%s)", plural(len(unused), "index is", "indexes are"), Bytes(float64(unusedBytes))),
			Explanation: fmt.Sprintf("No query has used them for over a week. Each one slows down every write and takes memory and disk; the largest is %s. Use is only counted since MongoDB last started: check that no monthly job or report needs them, and if you read from secondaries, check there first.", unused[0].Index),
			Action:      "Drop the ones you are sure you don't need.",
			Fixes:       drops})
	}
	if len(ins.DuplicateIndexes) > 0 {
		d := ins.DuplicateIndexes[0]
		var drops []protocol.FindingFix
		for _, x := range ins.DuplicateIndexes[:min(len(ins.DuplicateIndexes), maxIndexFixes)] {
			drops = append(drops, e.mongoDropIndexFix(x.Database, x.Table, x.Index, x.Bytes, false, fmt.Sprintf("%s already does the job of %s.", x.CoveredBy, x.Index)))
		}
		e.add(protocol.Finding{ID: "duplicate_indexes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
			Title:       fmt.Sprintf("%s another index already covers", plural(len(ins.DuplicateIndexes), "index repeats what", "indexes repeat what")),
			Explanation: fmt.Sprintf("%s on %s.%s is not needed: %s starts with the same keys. Extra indexes slow down writes and take memory.", d.Index, d.Database, d.Table, d.CoveredBy),
			Action:      "Drop the redundant index; the one that covers it stays.",
			Fixes:       drops})
	}
}

// mongoDropIndexFix drops an unused or redundant index (dropIndexes); the
// code that runs it refuses _id and unique indexes, and an unused one that
// has been used since.
func (e *evaluator) mongoDropIndexFix(db, coll, index string, bytes int64, unused bool, why string) protocol.FindingFix {
	desc := fmt.Sprintf("%s Dropping it gives back %s and makes writes to %s.%s a little faster. Reads and writes go on while it is dropped; Rowsafe shows its definition afterwards, to create it again if needed.",
		why, Bytes(float64(bytes)), db, coll)
	fx := e.fix("drop:"+db+"."+coll+"."+index, protocol.FixMaintenance, "Drop "+index, desc,
		protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: db, Tables: []string{coll}, Index: db + "." + index, Unused: unused})
	return confirm(fx, fmt.Sprintf("Drop the index %s on %s.%s? Any query that needs it would be slower until it is created again.", index, db, coll), true)
}
