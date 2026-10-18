package localcp

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Redis and Valkey on a server on its own. As on the hosted control plane
// (protocol/redis.go), they run PostgreSQL's task flow: the agent follows
// the server as a replica that serves nothing and records every change
// (its archiver), a Mark is a position in that stream, and every backup is
// a full snapshot, every day. When the server won't be followed
// (replication refused, min-replicas-to-write), the agent says so in its
// archiver report (ArchiveMode "snapshots", Error why): not a failure to
// read the status, but backups are then the scheduled snapshots only, so
// restores go back to them and Marks can't be taken.

// redisScheduleFull: a snapshot every day; the recorded changes cover the
// time between.
const redisScheduleFull = "0 1 * * *"

func redisFamily(engine string) bool {
	e := protocol.NormalizeEngine(engine)
	return e == protocol.EngineRedis || e == protocol.EngineValkey
}

// redisDefaults are a new Redis or Valkey database's schedules.
func redisDefaults(db *dbRec) {
	db.ScheduleFull, db.ScheduleDiff = redisScheduleFull, ""
}

// redisSnapshotsOnly: Rowsafe can't follow this server's changes.
func redisSnapshotsOnly(d *dbRec) bool {
	return redisFamily(d.Engine) && d.Archiver != nil && d.Archiver.ArchiveMode == protocol.RedisArchiveSnapshots
}

// redisMarksRefusal says why a database can't take a Mark ("" when it can):
// a Mark is a point in the changes Rowsafe records, and a server it can't
// follow has none. The Marks Rowsafe saves on its own first (before
// bringing keys back) are skipped instead.
func redisMarksRefusal(d *dbRec) string {
	if !redisSnapshotsOnly(d) {
		return ""
	}
	msg := "Marks need Rowsafe to follow the server's changes, which it can't"
	if why := strings.TrimSuffix(strings.TrimSpace(d.Archiver.Error), "."); why != "" {
		return msg + ": " + why + "."
	}
	return msg + "."
}

// redisReasons words protection reasons for Redis or Valkey, as the hosted
// control plane does (its changes are the replication stream the agent
// records), and adds why a server Rowsafe can't follow isn't protected to
// any second.
func redisReasons(d *dbRec, reasons []string) []string {
	name := protocol.EngineDisplayName(d.Engine)
	r := strings.NewReplacer(
		"WAL archiving to the repository", "recording of "+name+"'s changes to the bucket",
		"WAL archiving status from PostgreSQL", "the status of recording "+name+"'s changes",
		"WAL archiving status", "status of recording "+name+"'s changes",
		"WAL archiving", "Recording "+name+"'s changes",
		"PostgreSQL", name)
	for i := range reasons {
		reasons[i] = r.Replace(reasons[i])
	}
	if redisSnapshotsOnly(d) {
		s := fmt.Sprintf("Rowsafe can't follow every change of this %s server, so restores go back to its scheduled snapshots, not to any second", name)
		if why := strings.TrimSpace(d.Archiver.Error); why != "" {
			s += ": " + strings.TrimSuffix(why, ".")
		}
		reasons = append(reasons, s)
	}
	return reasons
}

// redisAlert words a shared rule for a Redis or Valkey database.
func redisAlert(rule string, st *state, d *dbRec, r ruleResult, now time.Time) ruleResult {
	name := protocol.EngineDisplayName(d.Engine)
	if rule == "wal_archiving_failing" && redisSnapshotsOnly(d) {
		return okResult // redis_snapshots_only says it
	}
	if !r.firing {
		return r
	}
	switch rule {
	case "wal_archiving_failing":
		r.summary = fmt.Sprintf("Rewind is failing for %s: %s's changes aren't reaching storage", d.Name, name)
		r.description = fmt.Sprintf("Saving %s's changes for %s on %s keeps failing. Restoring to a moment stops at the last change saved; the agent keeps recording meanwhile and catches up once storage answers.",
			name, d.Name, st.hostname())
		if a := d.Archiver; a != nil && a.Error != "" {
			r.description += " Error: " + clip(a.Error, 300)
		}
	case "postgres_unreachable":
		r.summary = fmt.Sprintf("Rowsafe can't reach %s for %s", name, d.Name)
		r.description = strings.ReplaceAll(r.description, "PostgreSQL", name)
		r.next = fmt.Sprintf("Check that %s is running on %s (systemctl status %s) and its log.", name, st.hostname(), unitName(d.Engine))
	case "backup_stale":
		if redisSnapshotsOnly(d) {
			r.description += " Rowsafe can't follow this server's changes: a restore today would lose everything written since the newest snapshot."
		}
	case "verify_failed":
		r.description = strings.Replace(r.description, "the check that its backups reach your storage failed", "the check that a snapshot of "+name+" reaches your storage failed", 1)
	case "disk_free_low":
		r.description = fmt.Sprintf("When the disk holding %s's files fills up, it can no longer save its snapshots or append-only file, and by default it then refuses writes.", name)
	}
	r.summary = strings.ReplaceAll(r.summary, "PostgreSQL", name)
	r.description = strings.ReplaceAll(r.description, "PostgreSQL", name)
	r.next = strings.ReplaceAll(r.next, "PostgreSQL", name)
	return r
}

// redisDBRE: a logical database is its number (16 by default; the
// "databases" setting can allow more).
var redisDBRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,3})$`)

// redisTables checks Rewind's (logical database, key pattern) pairs: the
// database is a number, the pattern a Redis glob ("*" for every key).
func redisTables(tables []protocol.RewindTable, limit int) error {
	if len(tables) > limit {
		return &httpErr{http.StatusBadRequest, fmt.Sprintf("Pick at most %d key patterns at a time.", limit)}
	}
	seen := map[protocol.RewindTable]bool{}
	for _, t := range tables {
		if !redisDBRE.MatchString(t.DB) {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q isn't a logical database: give its number ("0" to "15" by default).`, t.DB)}
		}
		if t.Table == "" || len(t.Table) > 200 || strings.ContainsAny(t.Table, "\x00\r\n") {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf(`%q isn't a key pattern: give one like "user:*", or "*" for every key.`, t.Table)}
		}
		if seen[t] {
			return &httpErr{http.StatusBadRequest, fmt.Sprintf("%s in logical database %s is listed twice.", t.Table, t.DB)}
		}
		seen[t] = true
	}
	return nil
}

// Readings Redis's rules look at that aren't metrics: from its health
// detail (DatabaseMonitoring.Redis).
const (
	valueRedisNoEviction = "redis_policy_noeviction" // 1 when it refuses writes when full
	valueRedisLinkDown   = "redis_primary_link_down" // 1 when this replica can't reach its primary
)

// redisMetrics are the readings Redis's rules look at.
var redisMetrics = []string{collect.MConnUsedPct, collect.MConnTotal, collect.MConnMax, collect.MRedisRejectedConnsRate,
	collect.MRedisMemoryUsedPct, collect.MRedisEvictedKeysRate, collect.MRedisBgsaveFailed, collect.MRedisAOFWriteFailed,
	collect.MReplicationLagSeconds}

// redisValues are the readings taken from Redis's health detail.
func redisValues(st *protocol.RedisStatus) map[string]float64 {
	if st == nil {
		return nil
	}
	out := map[string]float64{valueRedisNoEviction: 0, valueRedisLinkDown: 0}
	if st.MaxMemoryPolicy == "noeviction" {
		out[valueRedisNoEviction] = 1
	}
	if st.Primary != nil && !st.Primary.LinkUp {
		out[valueRedisLinkDown] = 1
	}
	return out
}

// redisRules are Redis's and Valkey's own rules, the hosted control
// plane's (internal/alerting/redis.go).
var redisRules = []localRule{
	{name: "redis_snapshots_only", title: "Rewind limited to snapshots (Redis)", severity: protocol.SeverityWarning,
		description: "Rowsafe can't follow every change of the server (replication refused, or min-replicas-to-write in use): restores go back to the scheduled snapshots, not to any second.",
		forDur:      30 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			if !activated(d) || d.Archiver == nil || d.ArchiverAt == nil || now.Sub(*d.ArchiverAt) > archiverFreshness || !redisSnapshotsOnly(d) {
				return okResult
			}
			desc := fmt.Sprintf("Rowsafe can't follow every change of %s on %s, so its backups are snapshots on the schedule and a restore brings back one of them; changes since the newest snapshot can't be restored.", d.Name, st.hostname())
			if why := strings.TrimSpace(d.Archiver.Error); why != "" {
				desc += " Why: " + clip(why, 300)
			}
			return fire(fmt.Sprintf("Restores of %s go back to snapshots only, not to any second", d.Name), desc,
				fmt.Sprintf("Let Rowsafe's user follow %s as a replica (sudo rowsafe pulse %s says how), or take snapshots more often.", protocol.EngineDisplayName(d.Engine), d.Name))
		}},
	{name: "redis_connections_high", title: "Many connections (Redis)", severity: protocol.SeverityWarning,
		description: "Client connections are above 80% of what the server accepts (maxclients). New connections are refused once it is reached.",
		threshold:   f64(80), unit: "%", forDur: 5 * time.Minute,
		eval: metricRule(collect.MConnUsedPct, 80, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s is using %.0f%% of its connections (%.0f of %.0f)", d.Name, v, m[collect.MConnTotal], m[collect.MConnMax]),
				fmt.Sprintf("When %s reaches maxclients, it refuses new connections.", protocol.EngineDisplayName(d.Engine)),
				"Look for applications opening a connection per request instead of reusing a pool.")
		})},
	{name: "redis_rejected_connections", title: "Refusing connections (Redis)", severity: protocol.SeverityCritical,
		description: "The server reached maxclients and is refusing new connections: applications trying to connect get errors.",
		forDur:      2 * time.Minute,
		eval: metricRule(collect.MRedisRejectedConnsRate, 0, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s is refusing connections (maxclients reached)", d.Name),
				fmt.Sprintf("%s refused about %.1f connections a second because all of its clients (maxclients) are in use.", protocol.EngineDisplayName(d.Engine), v),
				fmt.Sprintf("Find the application holding too many connections (sudo rowsafe pulse %s shows the clients) and make it reuse a pool.", d.Name))
		})},
	{name: "redis_memory_high", title: "Memory nearly full (Redis)", severity: protocol.SeverityWarning,
		description: "The server uses more than 90% of its memory limit (maxmemory) and is set to refuse writes when full (noeviction).",
		threshold:   f64(90), unit: "%", forDur: 10 * time.Minute,
		eval: func(st *state, d *dbRec, p protocol.Protection, now time.Time) ruleResult {
			m := st.freshMetrics(d, now)
			v, ok := m[collect.MRedisMemoryUsedPct]
			if !ok {
				return ruleResult{}
			}
			if v <= 90 || m[valueRedisNoEviction] < 1 {
				return okResult // with an eviction policy, a full cache is how it works
			}
			name := protocol.EngineDisplayName(d.Engine)
			r := fire(fmt.Sprintf("%s for %s uses %.0f%% of its memory limit and will refuse writes when full", name, d.Name, v),
				fmt.Sprintf("Once %s reaches maxmemory with the noeviction policy, every write fails with an \"OOM\" error.", name),
				fmt.Sprintf("If it is a cache, let it evict old keys (sudo rowsafe fix %s); otherwise give it more memory.", d.Name))
			r.value, r.threshold = f64(float64(int(v*10))/10), f64(90)
			return r
		}},
	{name: "redis_evicting", title: "Evicting keys (Redis)", severity: protocol.SeverityWarning,
		description: "The server deletes more than 100 keys a second to stay under its memory limit.",
		threshold:   f64(100), unit: "/s", forDur: 15 * time.Minute,
		eval: metricRule(collect.MRedisEvictedKeysRate, 100, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("%s is evicting %.0f keys a second", d.Name, v),
				fmt.Sprintf("%s reached maxmemory and deletes keys to make room. For a cache that's expected, but this many means it is too small for its load; for data you need to keep, keys are being lost.", protocol.EngineDisplayName(d.Engine)),
				"Give it more memory, or store less in it (shorter expiry times).")
		})},
	{name: "redis_bgsave_failed", title: "Snapshot to disk failing (Redis)", severity: protocol.SeverityCritical,
		description: "The server's last snapshot to its own disk (BGSAVE) failed; by default it then refuses writes.",
		forDur:      5 * time.Minute,
		eval: metricRule(collect.MRedisBgsaveFailed, 0, func(st *state, d *dbRec, m map[string]float64, _ float64) ruleResult {
			name := protocol.EngineDisplayName(d.Engine)
			return fire(fmt.Sprintf("%s can't save its snapshot to disk for %s", name, d.Name),
				fmt.Sprintf("%s's last snapshot to its own disk failed, and by default it refuses every write until one succeeds. Rowsafe's backups are separate and keep running.", name),
				fmt.Sprintf("Check the disk space and the data folder on %s, and %s's log for the reason.", st.hostname(), name))
		})},
	{name: "redis_aof_write_failed", title: "Append-only file failing (Redis)", severity: protocol.SeverityCritical,
		description: "The server's last write to its append-only file failed: writes can fail or wait.",
		forDur:      5 * time.Minute,
		eval: metricRule(collect.MRedisAOFWriteFailed, 0, func(st *state, d *dbRec, m map[string]float64, _ float64) ruleResult {
			name := protocol.EngineDisplayName(d.Engine)
			return fire(fmt.Sprintf("%s can't write its append-only file for %s", name, d.Name),
				fmt.Sprintf("%s logs every write to its append-only file and the last write failed; if it stopped now, the newest changes wouldn't be in the file. Rowsafe's backups are separate and keep running.", name),
				fmt.Sprintf("Check the disk on %s.", st.hostname()))
		})},
	{name: "redis_replication_lag", title: "Replica behind (Redis)", severity: protocol.SeverityWarning,
		description: "A replica (of this server, or this replica itself) is over 60 seconds behind.",
		threshold:   f64(60), unit: "seconds", forDur: 10 * time.Minute,
		eval: metricRule(collect.MReplicationLagSeconds, 60, func(st *state, d *dbRec, m map[string]float64, v float64) ruleResult {
			return fire(fmt.Sprintf("A replica of %s is %s behind", d.Name, human(time.Duration(v*float64(time.Second)))),
				"Reads from the replica miss the newest writes, and switching to it now would lose them.",
				fmt.Sprintf("Look at the replica's network and memory; sudo rowsafe pulse %s shows each replica.", d.Name))
		})},
	{name: "redis_link_down", title: "Replica lost its primary (Redis)", severity: protocol.SeverityCritical,
		description: "This server is a replica and can't reach its primary: it serves older and older data.",
		forDur:      5 * time.Minute,
		eval: metricRule(valueRedisLinkDown, 0, func(st *state, d *dbRec, m map[string]float64, _ float64) ruleResult {
			return fire(fmt.Sprintf("%s lost its primary", d.Name),
				fmt.Sprintf("%s on %s is a replica and can't reach its primary: it gets no new writes.", d.Name, st.hostname()),
				"Check that the primary is running and reachable from this server (network, firewall, masterauth).")
		})},
}
