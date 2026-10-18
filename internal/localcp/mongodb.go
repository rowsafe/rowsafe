package localcp

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// MongoDB on a server on its own. As on the hosted control plane, it runs
// PostgreSQL's task flow (adopt, check, backup, drill, restore_point,
// rewind_*): the agent copies the oplog where PostgreSQL archives WAL and
// reports it as the archiver, a Mark is an oplog position, and every
// backup is a full one (mongodump), so it runs every day with no
// differential in between (the hosted engineScheduleDefaults). MongoDB
// needs a replica set for its oplog: the plan says so on a standalone
// server, and the installer turns one on (one restart, when root says yes).

// mongoScheduleFull: a full backup every day; oplog copying covers the time
// between.
const mongoScheduleFull = "0 1 * * *"

func isMongo(engine string) bool { return protocol.NormalizeEngine(engine) == protocol.EngineMongoDB }

// mongoDefaults are a new MongoDB database's schedules.
func mongoDefaults(db *dbRec) {
	db.ScheduleFull, db.ScheduleDiff = mongoScheduleFull, ""
}

// mongoReasons words protection reasons for MongoDB, as the hosted control
// plane does: it copies the oplog where PostgreSQL archives WAL.
func mongoReasons(reasons []string) []string {
	r := strings.NewReplacer("WAL archiving to the repository", "copying MongoDB's changes (the oplog) to the bucket",
		"WAL archiving", "oplog copying", "from PostgreSQL", "from MongoDB")
	for i := range reasons {
		reasons[i] = r.Replace(reasons[i])
	}
	return reasons
}

// mongoAlert words a firing shared rule for a MongoDB database.
func mongoAlert(rule string, st *state, d *dbRec, r ruleResult, now time.Time) ruleResult {
	switch rule {
	case "wal_archiving_failing":
		r.summary = fmt.Sprintf("Rewind is failing for %s: MongoDB's changes aren't reaching storage", d.Name)
		r.description = fmt.Sprintf("Copying MongoDB's changes (the oplog) for %s on %s to your storage keeps failing. Restores to any second stop at the last change copied; "+
			"once MongoDB's oplog overwrites what wasn't copied, those changes can't be restored.", d.Name, st.hostname())
		if a := d.Archiver; a != nil && a.Error != "" {
			r.description += " Error: " + clip(a.Error, 300)
		}
	case "postgres_unreachable":
		r.summary = "Rowsafe can't reach MongoDB for " + d.Name
		r.description = strings.ReplaceAll(r.description, "PostgreSQL", "MongoDB")
		r.next = fmt.Sprintf("Check that MongoDB is running on %s (systemctl status mongod) and its log (journalctl -u mongod).", st.hostname())
	case "awaiting_restart":
		r.summary = fmt.Sprintf("%s has waited %s for a MongoDB restart", d.Name, human(now.Sub(d.StatusSince)))
		r.description = fmt.Sprintf("%s on %s is not protected until MongoDB restarts as a replica set. Rowsafe notices the restart and finishes by itself.", d.Name, st.hostname())
		r.next = "Restart MongoDB when it suits you: sudo rowsafe restart " + d.Name
	case "verify_failed":
		r.description = strings.ReplaceAll(r.description, "backups reach", "changes (the oplog) reach")
	case "disk_free_low":
		r.description = "When the disk fills up, MongoDB stops accepting writes and may shut down."
	}
	return r
}

// mongoTables checks the collections of a compare or a bring-back: a
// database ("db") and a collection ("table"), never MongoDB's own.
func mongoTables(tables []protocol.RewindTable, limit int) error {
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d collections at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		if t.DB == "" || t.Table == "" || len(t.DB) > 64 || len(t.Table) > 255 || strings.ContainsAny(t.DB, "/\\. \"$\x00") ||
			strings.ContainsRune(t.Table, 0) || strings.HasPrefix(t.Table, "system.") ||
			t.DB == "admin" || t.DB == "config" || t.DB == "local" {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q in %q isn't a collection: give "db" (the database) and "table" (the collection).`, t.Table, t.DB)}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s is listed twice.", t.Table)}
		}
		seen[t] = true
	}
	return nil
}

// mongoMetrics are the readings MongoDB's rules look at (kept from each
// monitoring report).
var mongoMetrics = []string{collect.MConnUsedPct, collect.MConnTotal, collect.MConnMax, collect.MMongoOplogWindow,
	collect.MLongestQuerySeconds, collect.MReplicasConnected, collect.MReplicationLagSeconds, collect.MMongoCacheDirtyPct,
	collect.MMongoQueuedOps, collect.MMongoWriteConflicts}

// mongoRules are MongoDB's own rules, the hosted control plane's
// (internal/alerting/mongodb.go): connections, the oplog's reach, long
// operations, lag, the cache, queues and write conflicts. Its rules for
// continuous backup and an unreachable server are the shared ones, in
// MongoDB's words (mongoAlert).
var mongoRules = []localRule{
	{name: "mongodb_connections_high", title: "Many connections (MongoDB)", severity: protocol.SeverityWarning,
		description: "Client connections are above 80% of what MongoDB accepts. New connections fail once it is reached.",
		threshold:   f64(80), unit: "%", forDur: 5 * time.Minute,
		eval: metricRule(collect.MConnUsedPct, 80, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s is using %.0f%% of its connections (%.0f of %.0f)", d.Name, v, m[collect.MConnTotal], m[collect.MConnMax]),
				"When MongoDB runs out of connections (net.maxIncomingConnections, or the open files limit), new connections are refused.",
				"Look for applications opening too many connections (a driver's maxPoolSize per process adds up), or raise the limit.")
		})},
	{name: "mongodb_oplog_window", title: "Short oplog window", severity: protocol.SeverityWarning,
		description: "MongoDB's oplog reaches back less than 12 hours. If the agent is stopped for longer, changes from that time can't be restored.",
		threshold:   f64(12), unit: "hours", forDur: 30 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			m := st.freshMetrics(d, now)
			v, ok := m[collect.MMongoOplogWindow]
			if !ok {
				return ruleResult{}
			}
			if v >= 12 {
				return okResult
			}
			r := fire(fmt.Sprintf("MongoDB for %s keeps only %s of changes", d.Name, human(time.Duration(v*float64(time.Hour)))),
				"Rowsafe copies the oplog about every minute, so this only matters if the agent or the storage is down for longer than the window: changes from that time couldn't be restored.",
				"Give the oplog more room (replSetResizeOplog, e.g. 5% of the disk; no restart). rowsafe pulse "+d.Name+" shows the command.")
			r.value, r.threshold, r.unit = f64(float64(int(v*10))/10), f64(12), "hours"
			return r
		}},
	{name: "mongodb_long_operation", title: "Long-running operation (MongoDB)", severity: protocol.SeverityWarning,
		description: "A client operation has been running for over 30 minutes.",
		threshold:   f64(30), unit: "minutes", forDur: 2 * time.Minute,
		eval: metricRule(collect.MLongestQuerySeconds, 30*60, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("An operation on %s has been running for %.0f minutes", d.Name, v/60),
				"Long operations hold resources and can slow everything else down.",
				fmt.Sprintf("Stop it if nobody is waiting for it: sudo rowsafe fix %s", d.Name))
		})},
	{name: "mongodb_replication_lag", title: "Secondary behind (MongoDB)", severity: protocol.SeverityWarning,
		description: "A secondary of the replica set is over 60 seconds behind the primary.",
		threshold:   f64(60), unit: "seconds", forDur: 5 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if m := st.freshMetrics(d, now); m != nil && m[collect.MReplicasConnected] <= 0 {
				return okResult
			}
			return metricRule(collect.MReplicationLagSeconds, 60, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
				return fire(fmt.Sprintf("A secondary of %s is %s behind", d.Name, human(time.Duration(v*float64(time.Second)))),
					"Reads from it are stale, and if the primary failed now, the most recent writes could be rolled back.",
					"Look at the secondary's disk and network.")
			})(st, d, p, now)
		}},
	{name: "mongodb_cache_pressure", title: "Writes waiting for the disk (MongoDB)", severity: protocol.SeverityWarning,
		description: "Changes not yet written to disk fill over 20% of the WiredTiger cache: MongoDB then makes client writes wait.",
		threshold:   f64(20), unit: "%", forDur: 10 * time.Minute,
		eval: metricRule(collect.MMongoCacheDirtyPct, 20, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%.0f%% of MongoDB's cache on %s waits to be written to disk", v, d.Name),
				"MongoDB writes changes from its cache to disk in the background; when they pile up, client writes have to help and slow down.",
				"Look at the disk's write speed and at bursts of writes; a larger cache or a faster disk helps.")
		})},
	{name: "mongodb_queued_ops", title: "Operations queueing (MongoDB)", severity: protocol.SeverityWarning,
		description: "Over 20 operations are waiting for a lock or a storage ticket.",
		threshold:   f64(20), unit: "operations", forDur: 5 * time.Minute,
		eval: metricRule(collect.MMongoQueuedOps, 20, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%.0f operations are waiting their turn on %s", v, d.Name),
				"Operations queue when MongoDB is busy with others. Queues that last mean the server is overloaded.",
				fmt.Sprintf("Look for long operations and slow queries: sudo rowsafe pulse %s", d.Name))
		})},
	{name: "mongodb_write_conflicts", title: "Write conflicts (MongoDB)", severity: protocol.SeverityWarning,
		description: "Writes collide on the same documents and are retried over 100 times a minute.",
		threshold:   f64(100), unit: "/min", forDur: 10 * time.Minute,
		eval: metricRule(collect.MMongoWriteConflicts, 100, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%.0f write conflicts a minute on %s", v, d.Name),
				"Many clients are changing the same documents at the same moment; MongoDB retries the losers, which slows those writes down.",
				"Spread hot counters over several documents, use $inc instead of read-modify-write, and keep transactions short.")
		})},
}
