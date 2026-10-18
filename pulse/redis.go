package pulse

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Redis and Valkey (Input.Engine): connections, memory (its limit and
// fragmentation), stuck clients, slow commands, latency spikes, saving to
// its own disk, replication and a default user without a password, with
// the fixes the agent's code runs over a connection (evict instead of
// refusing writes, give memory back, defragment, disconnect a client,
// turn on snapshots). The dashboard runs these too (internal/health in the
// control plane, with the same IDs and wording); what is about Rowsafe's
// own replication link (snapshots only, whole resyncs) needs the agent.

// Thresholds.
const (
	redisStatusFresh = 15 * time.Minute
	redisMaxFixes    = 5 // Disconnect fixes per finding
	redisMemoryFull  = 90
	redisFragRatio   = 1.5
	redisFragBytes   = 100 << 20
	redisReplicaLag  = 30 * time.Second
	redisLatencyMs   = 100
	redisRecent      = time.Hour
)

// CatAvailability is a category only Redis's findings use here (CatSecurity
// is in security.go).
const CatAvailability = "availability"

func (e *evaluator) redisFamily() bool {
	n := protocol.NormalizeEngine(e.in.Engine)
	return n == protocol.EngineRedis || n == protocol.EngineValkey
}

// redisStatus returns Redis's health detail if recent enough to act on.
func (e *evaluator) redisStatus() *protocol.RedisStatus {
	st := e.in.Redis
	if st == nil || st.CollectedAt.IsZero() || e.now.Sub(st.CollectedAt) > redisStatusFresh {
		return nil
	}
	return st
}

// Redis runs the Redis and Valkey rules on their own: their findings in
// order, and the sections' status lines.
func (r *Rules) Redis(fresh bool) ([]protocol.Finding, []protocol.HealthCheck) {
	r.e.findings, r.e.checks = nil, map[string]*protocol.HealthCheck{}
	r.e.redis(fresh)
	var checks []protocol.HealthCheck
	for _, cat := range []string{CatConnections, CatMaintenance, CatPerformance, CatReplication} {
		if c, ok := r.e.checks[cat]; ok {
			checks = append(checks, *c)
		}
	}
	return r.e.findings, checks
}

func (e *evaluator) redis(fresh bool) {
	m := e.in.Metrics
	name := e.engineName()
	st := e.redisStatus()
	if !fresh && st == nil {
		e.check(CatConnections, "Connections", "unknown", "No connection readings.")
		return
	}
	e.redisKeepsNothing(st)

	// Connections.
	conn, connDetail := "", ""
	if used, ok := m[collect.MConnUsedPct]; ok {
		total, maxc := m[collect.MConnTotal], m[collect.MConnMax]
		conn, connDetail = "ok", fmt.Sprintf("%.0f of %.0f in use.", total, maxc)
		if used >= 80 {
			sev, pen := protocol.SeverityWarning, 8
			conn = "warning"
			if used >= 95 {
				sev, pen, conn = protocol.SeverityCritical, 15, "critical"
			}
			e.add(protocol.Finding{ID: "redis_connections_high", Category: CatConnections, Severity: sev, Penalty: pen,
				Title:       fmt.Sprintf("Most connections are in use (%.0f of %.0f)", total, maxc),
				Explanation: fmt.Sprintf("%s accepts a limited number of clients (maxclients). Once they are all in use, new connections are refused and your application gets errors.", name),
				Action:      "Look for applications opening a connection per request instead of reusing a pool, or clients that never close their connections.",
				Command:     "redis-cli INFO clients; redis-cli CONFIG GET maxclients"})
		}
	}
	if rej := m[collect.MRedisRejectedConnsRate]; rej > 0 {
		e.add(protocol.Finding{ID: "redis_rejected_connections", Category: CatConnections, Severity: protocol.SeverityCritical, Penalty: 15,
			Title:       fmt.Sprintf("%s is refusing connections", name),
			Explanation: fmt.Sprintf("%s reached its limit of clients (maxclients) and refused new connections (about %s a second): applications trying to connect get errors.", name, rate(rej)),
			Action:      "Find the application holding too many connections and make it reuse a pool; raise maxclients only if the server has the memory and open files for it.",
			Command:     "redis-cli INFO stats | grep rejected_connections; redis-cli CLIENT LIST | awk '{print $2}' | cut -d: -f1 | sort | uniq -c | sort -rn | head"})
		conn, connDetail = "critical", "Connections are being refused."
	}
	if conn != "" {
		e.check(CatConnections, "Connections", conn, connDetail)
	}

	perf, perfDetail := "ok", "Memory and commands look normal."
	worse := func(status, detail string) {
		if statusRank(status) > statusRank(perf) {
			perf, perfDetail = status, detail
		}
	}
	if st != nil {
		e.redisMemory(st, worse)
		e.redisStuckClients(st, worse)
		e.redisSlowLog(st)
		e.redisLatency(st)
		e.redisPersistence(st)
		e.redisReplication(st)
		if st.NoPassword {
			e.add(protocol.Finding{ID: "redis_no_password", Category: CatSecurity, Severity: protocol.SeverityWarning, Penalty: 10,
				Title:       fmt.Sprintf("%s has no password", name),
				Explanation: fmt.Sprintf("%s's default user signs in without a password: anyone who can reach its port can read, change and delete everything in it.", name),
				Action:      fmt.Sprintf("Give the default user a password (or turn it off and use your own users), update your applications' connection settings, and keep %s's port closed to the internet.", name),
				Command:     "redis-cli ACL SETUSER default on '>A-LONG-RANDOM-PASSWORD'   # then put it in your apps' REDIS_URL"})
		}
	}
	if fresh {
		if ev := m[collect.MRedisEvictedKeysRate]; ev > 0 {
			e.add(protocol.Finding{ID: "redis_evictions", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       fmt.Sprintf("%s is evicting keys to stay under its memory limit (%s a second)", name, rate(ev)),
				Explanation: fmt.Sprintf("%s reached maxmemory and deletes keys to make room, as its eviction policy says. That's expected for a cache; for data you need to keep, it means keys are being lost.", name),
				Action:      "If this is a cache, nothing to do (a low hit rate says it's too small). If not, give it more memory or store less in it."})
		}
		if hit, ok := m[collect.MRedisHitRatePct]; ok && hit < 80 && m[collect.MRedisOpsRate] >= 100 {
			e.add(protocol.Finding{ID: "redis_hit_rate_low", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
				Title:       fmt.Sprintf("Only %.0f%% of reads find their key", hit),
				Explanation: fmt.Sprintf("Of the reads sent to %s, %.0f%% asked for a key that isn't there. For a cache, that means most requests still go to the slower source behind it: the cache may be too small (evicting keys), or keys expire too soon.", name, 100-hit),
				Action:      "If this is a cache, look at evictions and expiry times; if keys are looked up before they are written on purpose, nothing to do."})
		}
	}
	e.check(CatPerformance, "Memory and commands", perf, perfDetail)
}

// redisKeepsNothing: a server with neither snapshots nor an append-only
// file comes back empty from a restart; the fix turns on snapshots. No
// penalty: a cache the app fills again may be meant that way.
func (e *evaluator) redisKeepsNothing(st *protocol.RedisStatus) {
	off := func(save string) bool {
		save = strings.TrimSpace(save)
		return save == "" || save == tune.RedisSaveOff || save == "''"
	}
	nothing := st != nil && off(st.Persistence.SaveRules) && !st.Persistence.AOFEnabled
	if snap := e.in.Settings; snap != nil && (st == nil || snap.CollectedAt.After(st.CollectedAt)) {
		for _, s := range snap.Settings {
			if s.Name == "save" {
				aof := ""
				for _, a := range snap.Settings {
					if a.Name == "appendonly" {
						aof = a.Setting
					}
				}
				nothing = off(s.Setting) && !strings.EqualFold(strings.TrimSpace(aof), "yes")
			}
		}
	}
	if !nothing {
		return
	}
	name := e.engineName()
	fix := e.fix("redis_snapshots_on", protocol.FixTune, "Turn on snapshots",
		fmt.Sprintf("Sets %s's snapshots to its own defaults (after 1 hour if a key changed, 5 minutes if 100 did, 1 minute if 10,000 did), so it keeps its data on its own disk and comes back with it after a restart. Nothing restarts.", name),
		protocol.SettingsParams{Kind: protocol.SettingsKindFix, Changes: []protocol.SettingChange{{Name: "save", Value: tune.RedisSaveDefault}}})
	explanation := fmt.Sprintf("Snapshots and the append-only file are both off, so %s keeps nothing on its own disk and starts empty after a restart or a crash.", name)
	if e.in.Dashboard {
		explanation = fmt.Sprintf("Snapshots and the append-only file are both off, so %s keeps nothing on its own disk and starts empty after a restart. Rowsafe doesn't restart, update or upgrade it until it keeps its data; a crash would still empty it (Rowsafe's backups can bring the data back).", name)
	}
	e.add(protocol.Finding{ID: "redis_restart_empties", Category: CatProtection, Severity: protocol.SeverityInfo,
		Title:       fmt.Sprintf("A restart would empty %s", name),
		Explanation: explanation,
		Action:      fmt.Sprintf("Turn on snapshots. If %s is only a cache your app fills again, you can leave it as it is.", name),
		Fixes:       []protocol.FindingFix{fix}})
}

// redisMemory: near maxmemory, fragmentation, no limit on a full server.
func (e *evaluator) redisMemory(st *protocol.RedisStatus, worse func(status, detail string)) {
	name := e.engineName()
	if st.MaxMemoryBytes > 0 {
		pct := float64(st.UsedMemoryBytes) * 100 / float64(st.MaxMemoryBytes)
		if pct >= redisMemoryFull && st.MaxMemoryPolicy == "noeviction" {
			sev, pen, status := protocol.SeverityWarning, 15, "warning"
			if pct >= 98 {
				sev, pen, status = protocol.SeverityCritical, 25, "critical"
			}
			fixes := []protocol.FindingFix{e.redisEvictionFix()}
			e.add(protocol.Finding{ID: "redis_memory_noeviction", Category: CatAvailability, Severity: sev, Penalty: pen,
				Title:       fmt.Sprintf("%s is nearly full and will refuse writes (%.0f%% of its memory limit)", name, pct),
				Explanation: fmt.Sprintf("%s uses %s of its %s limit (maxmemory), and its policy is to evict nothing (noeviction): once full, every write fails with an \"OOM\" error until keys expire or are deleted.", name, Bytes(float64(st.UsedMemoryBytes)), Bytes(float64(st.MaxMemoryBytes))),
				Action:      withFixes(fixes, fmt.Sprintf("If %s is a cache, let it evict the least recently used keys when full. If it holds data you can't lose, give it more memory instead.", name), "Give it more memory, or let it evict keys if it is a cache."),
				Command:     "redis-cli CONFIG SET maxmemory 2gb && redis-cli CONFIG REWRITE   # a limit the server's memory allows",
				Fixes:       fixes})
			worse(status, "Nearly full, and set to refuse writes when full.")
		} else if pct >= redisMemoryFull {
			worse("ok", fmt.Sprintf("%.0f%% of the memory limit; keys are evicted when full (%s).", pct, st.MaxMemoryPolicy))
		}
	} else if st.TotalSystemMemoryBytes > 0 && float64(st.UsedMemoryBytes) >= 0.75*float64(st.TotalSystemMemoryBytes) {
		e.add(protocol.Finding{ID: "redis_memory_high", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 8,
			Title:       fmt.Sprintf("%s has no memory limit and uses %s of the server's %s", name, Bytes(float64(st.UsedMemoryBytes)), Bytes(float64(st.TotalSystemMemoryBytes))),
			Explanation: fmt.Sprintf("Without maxmemory, %s grows until the server runs out of memory, and the system then kills it (or something else). Saving a snapshot also needs spare memory for the copy it forks.", name),
			Action:      "Set a memory limit below the server's memory (with room for snapshots), and an eviction policy if it is a cache.",
			Command:     "redis-cli CONFIG SET maxmemory 2gb && redis-cli CONFIG SET maxmemory-policy allkeys-lru && redis-cli CONFIG REWRITE"})
		worse("warning", "No memory limit, and most of the server's memory is used.")
	}

	if st.FragmentationRatio > redisFragRatio && st.FragmentationBytes > redisFragBytes {
		jemalloc := strings.HasPrefix(strings.ToLower(st.Allocator), "jemalloc")
		var fixes []protocol.FindingFix
		if jemalloc {
			fixes = append(fixes, e.fix("redis_memory_purge", protocol.FixMaintenance, "Give memory back",
				fmt.Sprintf("Asks %s's memory allocator to return the memory it no longer uses to the system (MEMORY PURGE). Harmless and instant; your data doesn't change.", name),
				protocol.MaintenanceParams{Action: protocol.MaintRedisMemoryPurge}))
			if !st.ActiveDefrag {
				fx := e.fix("redis_active_defrag", protocol.FixMaintenance, "Turn on defragmentation",
					fmt.Sprintf("If giving memory back didn't help: turns on %s's active defragmentation (activedefrag yes), which compacts memory in the background at a small CPU cost. Rowsafe keeps the setting in the configuration file when %s can write it.", name, name),
					protocol.MaintenanceParams{Action: protocol.MaintRedisActiveDefrag})
				fixes = append(fixes, confirm(fx, fmt.Sprintf("Turn on active defragmentation for %s? It uses a little CPU in the background while memory is fragmented.", e.in.Database), false))
			}
		}
		e.add(protocol.Finding{ID: "redis_fragmented", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("%s of memory is wasted by fragmentation", Bytes(float64(st.FragmentationBytes))),
			Explanation: fmt.Sprintf("The system gave %s %.1f times the memory its data needs: after many keys were deleted or changed size, freed memory is scattered in pieces the server can't hand back.", name, st.FragmentationRatio),
			Action:      withFixes(fixes, "Give the unused memory back first; if that isn't enough, turn on active defragmentation.", "A restart at a quiet time compacts the memory (this allocator can't defragment while running)."),
			Command:     "redis-cli INFO memory | grep -E 'mem_fragmentation|allocator'",
			Fixes:       fixes})
		worse("warning", "Memory is fragmented.")
	}
}

// redisEvictionFix lets a server near maxmemory evict the least recently
// used keys instead of refusing writes.
func (e *evaluator) redisEvictionFix() protocol.FindingFix {
	name := e.engineName()
	fx := e.fix("redis_eviction_policy", protocol.FixMaintenance, "Evict old keys when full",
		fmt.Sprintf("Sets %s's eviction policy to allkeys-lru: when full, it deletes the keys used least recently to make room, instead of refusing writes. Right for a cache; not for data you can't lose. Takes effect at once, no restart; Rowsafe keeps it in the configuration file when %s can write it.", name, name),
		protocol.MaintenanceParams{Action: protocol.MaintRedisEvictionPolicy, Settings: map[string]string{"maxmemory-policy": "allkeys-lru"}})
	return confirm(fx, fmt.Sprintf("Let %s delete the least recently used keys when it is full? Only do this if %s is a cache: those keys are gone for good.", e.in.Database, e.in.Database), true)
}

// redisStuckClients: connections blocked for long or holding a large
// output buffer, with a Disconnect fix each.
func (e *evaluator) redisStuckClients(st *protocol.RedisStatus, worse func(status, detail string)) {
	var stuck []protocol.RedisClient
	for _, c := range st.Clients {
		if c.ID <= 0 || c.ConnectedAt.IsZero() || strings.EqualFold(c.User, "rowsafe") || ownSession(c.Name) {
			continue
		}
		stuck = append(stuck, c)
	}
	if len(stuck) == 0 {
		return
	}
	var fixes []protocol.FindingFix
	for _, c := range stuck[:min(len(stuck), redisMaxFixes)] {
		fixes = append(fixes, e.redisKillFix(c))
	}
	c := stuck[0]
	why := strings.TrimSpace(c.Reason)
	if why == "" {
		why = fmt.Sprintf("idle for %s", secsAgo(float64(c.IdleSeconds)))
	}
	e.add(protocol.Finding{ID: "redis_stuck_client", Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5,
		Title:       plural(len(stuck), "connection looks", "connections look") + " stuck",
		Explanation: fmt.Sprintf("%s: %s. A client stuck in a blocking command, or one that doesn't read its replies (its output buffer keeps growing), holds a connection and memory for nothing.", redisClientName(c), strings.TrimSuffix(why, ".")),
		Action:      withFixes(fixes, "Disconnect it if nothing is waiting on it; a well-behaved client reconnects by itself.", "Find the application behind it."),
		Command:     "redis-cli CLIENT LIST   # then CLIENT KILL ID <id>",
		Fixes:       fixes})
	worse("warning", plural(len(stuck), "connection looks", "connections look")+" stuck.")
}

func redisClientName(c protocol.RedisClient) string {
	switch {
	case c.Name != "":
		return fmt.Sprintf("Client %s (%s)", c.Name, c.Addr)
	case c.Addr != "":
		return "Client " + c.Addr
	}
	return fmt.Sprintf("Client %d", c.ID)
}

// redisKillFix disconnects one client (CLIENT KILL ID), identified by its
// id and the moment it connected so it is never another connection.
func (e *evaluator) redisKillFix(c protocol.RedisClient) protocol.FindingFix {
	at := c.ConnectedAt.UTC()
	what := ""
	if c.Command != "" {
		what = fmt.Sprintf(", last command %s", c.Command)
	}
	who := strings.ToLower(redisClientName(c)[:1]) + redisClientName(c)[1:]
	desc := fmt.Sprintf("Disconnects %s (connected %s ago%s). Only that connection closes; the application behind it gets an error and usually reconnects. Takes a second.",
		who, Ago(e.now.Sub(at)), what)
	fx := e.fix(fmt.Sprintf("redis_kill:%d:%d", c.ID, at.Unix()), protocol.FixMaintenance, "Disconnect", desc,
		protocol.MaintenanceParams{Action: protocol.MaintRedisKillClient, PID: int(c.ID), BackendStart: &at})
	return confirm(fx, fmt.Sprintf("Disconnect %s? The application behind it gets an error and has to reconnect.", who), true)
}

// redisSlowLog: commands slower than slowlog-log-slower-than in the last
// hour, by name (never their arguments).
func (e *evaluator) redisSlowLog(st *protocol.RedisStatus) {
	count := map[string]int{}
	var slowest int64
	n := 0
	for _, s := range st.SlowLog {
		if s.At.IsZero() || e.now.Sub(s.At) > redisRecent || s.Command == "" {
			continue
		}
		count[strings.ToUpper(s.Command)]++
		slowest = max(slowest, s.DurationMicros)
		n++
	}
	if n < 5 {
		return
	}
	cmds := make([]string, 0, len(count))
	for c := range count {
		cmds = append(cmds, c)
	}
	slices.SortFunc(cmds, func(a, b string) int { return cmp.Or(cmp.Compare(count[b], count[a]), cmp.Compare(a, b)) })
	var parts []string
	for _, c := range cmds[:min(len(cmds), 3)] {
		parts = append(parts, fmt.Sprintf("%s (%d)", c, count[c]))
	}
	advice := "Commands that touch many keys or large values at once block every other client while they run: read large sets, lists and hashes in pages, and keep values small."
	if count["KEYS"] > 0 {
		advice = "KEYS goes through every key and blocks every other client meanwhile: use SCAN instead. " + advice
	}
	e.add(protocol.Finding{ID: "redis_slow_commands", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 3,
		Title:       fmt.Sprintf("%s were slow in the last hour", plural(n, "command", "commands")),
		Explanation: fmt.Sprintf("Redis runs one command at a time, so a slow one makes every client wait. The slowest took %s. Most often: %s.", millis(slowest), strings.Join(parts, ", ")),
		Action:      advice})
}

// redisLatency: spikes the latency monitor recorded in the last hour.
func (e *evaluator) redisLatency(st *protocol.RedisStatus) {
	var spikes []protocol.RedisLatencyEvent
	for _, l := range st.Latency {
		if !l.At.IsZero() && e.now.Sub(l.At) <= redisRecent && l.LatestMs >= redisLatencyMs {
			spikes = append(spikes, l)
		}
	}
	if len(spikes) == 0 {
		return
	}
	slices.SortFunc(spikes, func(a, b protocol.RedisLatencyEvent) int { return cmp.Compare(b.LatestMs, a.LatestMs) })
	l := spikes[0]
	why := "Look at the slow commands and at what else runs on the server at those moments."
	switch {
	case strings.HasPrefix(l.Event, "fork"):
		why = "Saving a snapshot forks the server, which pauses it for a moment; the more memory it uses, the longer. Large servers pause less with less frequent snapshots, or on a server without memory overcommit limits."
	case strings.HasPrefix(l.Event, "aof"):
		why = "Writing the append-only file to disk took long: the disk is slow or busy (another process, a backup)."
	case strings.HasPrefix(l.Event, "expire"):
		why = "Many keys expired at the same moment: spread expiry times with a little randomness."
	case strings.HasPrefix(l.Event, "eviction"):
		why = "Evicting keys to stay under maxmemory took long: give it more memory, or evict earlier."
	}
	e.add(protocol.Finding{ID: "redis_latency_spikes", Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 2,
		Title:       fmt.Sprintf("%s paused for %s (%s)", e.engineName(), millis(l.LatestMs*1000), l.Event),
		Explanation: fmt.Sprintf("The latency monitor recorded %s over %d ms in the last hour; while it pauses, every client waits.", plural(len(spikes), "spike", "spikes"), redisLatencyMs),
		Action:      why})
}

// redisPersistence: the server's own snapshot and append-only file. By
// default Redis refuses writes once saving to its disk fails.
func (e *evaluator) redisPersistence(st *protocol.RedisStatus) {
	name := e.engineName()
	p := st.Persistence
	status, detail := "ok", "Saving to its own disk works."
	switch {
	case p.SaveRules == "" && !p.AOFEnabled:
		detail = "Not saving to its own disk."
	case p.AOFEnabled:
		detail = "Saving to its own disk (append-only file) works."
	}
	m := e.in.Metrics
	if !p.LastBgsaveOK && (p.SaveRules != "" || p.LastSaveAt != nil) || m[collect.MRedisBgsaveFailed] >= 1 {
		e.add(protocol.Finding{ID: "redis_bgsave_failed", Category: CatAvailability, Severity: protocol.SeverityCritical, Penalty: 20,
			Title:       fmt.Sprintf("%s can't save its snapshot to its own disk", name),
			Explanation: fmt.Sprintf("%s's last snapshot to its own disk (BGSAVE) failed. By default it then refuses every write (stop-writes-on-bgsave-error) until a snapshot succeeds. Usually the disk is full, the data folder isn't writable, or the server lacks memory to fork.", name),
			Action:      "Check the disk space and the data folder's permissions, and the server's log for the reason; the next snapshot clears this by itself.",
			Command:     "redis-cli INFO persistence | grep rdb_; df -h; sudo tail -n 50 /var/log/redis/redis-server.log"})
		status, detail = "critical", "Saving its snapshot to disk fails."
	}
	if p.AOFEnabled && !p.AOFLastWriteOK || m[collect.MRedisAOFWriteFailed] >= 1 {
		e.add(protocol.Finding{ID: "redis_aof_write_failed", Category: CatAvailability, Severity: protocol.SeverityCritical, Penalty: 20,
			Title:       fmt.Sprintf("%s can't write its append-only file", name),
			Explanation: fmt.Sprintf("%s logs every write to its append-only file, and the last write to it failed: writes can fail or wait, and if the server stopped now, the newest changes wouldn't be in the file. Usually the disk is full or failing.", name),
			Action:      "Check the disk space and the server's log for the reason; once writing works again it clears by itself.",
			Command:     "redis-cli INFO persistence | grep aof_; df -h"})
		status, detail = "critical", "Writing the append-only file fails."
	} else if p.AOFEnabled && !p.AOFLastRewriteOK {
		e.add(protocol.Finding{ID: "redis_aof_rewrite_failed", Category: CatMaintenance, Severity: protocol.SeverityWarning, Penalty: 5,
			Title:       fmt.Sprintf("%s couldn't compact its append-only file", name),
			Explanation: fmt.Sprintf("%s rewrites its append-only file now and then so it doesn't grow forever, and the last rewrite failed: the file keeps growing and restarts get slower. Usually disk space or memory to fork.", name),
			Action:      "Check the disk space and the server's log; the next rewrite clears this by itself.",
			Command:     "redis-cli INFO persistence | grep aof_; df -h"})
		if status == "ok" {
			status, detail = "warning", "Compacting the append-only file failed."
		}
	}
	e.check(CatMaintenance, "Saving to disk", status, detail)
}

// redisReplication: a replica's link to its primary, and the server's own
// replicas.
func (e *evaluator) redisReplication(st *protocol.RedisStatus) {
	name := e.engineName()
	status, detail := "", ""
	if p := st.Primary; p != nil {
		status, detail = "ok", fmt.Sprintf("Following its primary %s:%d.", p.Host, p.Port)
		if !p.LinkUp {
			down := ""
			if p.DownSeconds > 0 {
				down = " for " + secsAgo(float64(p.DownSeconds))
			}
			e.add(protocol.Finding{ID: "redis_primary_link_down", Category: CatReplication, Severity: protocol.SeverityCritical, Penalty: 20,
				Title:       fmt.Sprintf("This replica lost its primary%s", down),
				Explanation: fmt.Sprintf("This %s server is a replica of %s:%d and can't reach it: it serves data that gets older every second, and gets no new writes.", name, p.Host, p.Port),
				Action:      "Check that the primary is running and reachable from this server (network, firewall, its password in masterauth).",
				Command:     "redis-cli INFO replication"})
			status, detail = "critical", "Lost its primary"+down+"."
		} else if p.SyncInProgress {
			status, detail = "ok", "Copying a fresh snapshot from its primary."
		}
	}
	var behind []protocol.RedisReplica
	for _, r := range st.Replicas {
		if r.LagSeconds >= int64(redisReplicaLag.Seconds()) || (r.State != "" && r.State != "online") {
			behind = append(behind, r)
		}
	}
	if len(st.Replicas) > 0 && status == "" {
		status, detail = "ok", plural(len(st.Replicas), "replica", "replicas")+" following."
	}
	if len(behind) > 0 {
		r := behind[0]
		what := fmt.Sprintf("%s behind", secsAgo(float64(r.LagSeconds)))
		if r.State != "" && r.State != "online" {
			what = "not online (" + r.State + ")"
		}
		e.add(protocol.Finding{ID: "redis_replica_lag", Category: CatReplication, Severity: protocol.SeverityWarning, Penalty: 8,
			Title:       fmt.Sprintf("A replica is %s", what),
			Explanation: fmt.Sprintf("The replica %s isn't keeping up with this server: reads from it are stale, and if you switched to it now, the newest writes would be missing.", r.Addr),
			Action:      "Look at the replica's network and memory; a replica that keeps reconnecting may need a larger replication backlog here.",
			Command:     "redis-cli INFO replication"})
		if statusRank("warning") > statusRank(status) {
			status, detail = "warning", "A replica is "+what+"."
		}
	}
	if status != "" {
		e.check(CatReplication, "Replication", status, detail)
	}
}

func rate(v float64) string {
	if v >= 10 {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// millis: 1.2 s, 250 ms, 0.4 ms (from microseconds).
func millis(us int64) string {
	switch {
	case us >= 1_000_000:
		return fmt.Sprintf("%.1f s", float64(us)/1e6)
	case us >= 1000:
		return fmt.Sprintf("%d ms", us/1000)
	}
	return fmt.Sprintf("%.1f ms", float64(us)/1000)
}
