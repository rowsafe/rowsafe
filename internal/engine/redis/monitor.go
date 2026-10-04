package redis

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for Redis and Valkey: INFO (memory against maxmemory, evictions,
// hit rate, commands, clients, fragmentation, persistence, replication),
// the slow log (command names only) and the latency monitor, all read
// only and cheap. Rowsafe's own replication link is left out of every
// replica count. The detailed status comes every 5 minutes.

const statusEvery = 5 * time.Minute

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	mu       sync.Mutex
	c        *conn
	prev     map[string]float64
	prevAt   time.Time
	statusAt time.Time
	slowID   int64 // the newest slow log entry already counted

	adv advisorState // the recommendations' key sample (insights.go)
}

func (e *Engine) monitorFor(id string) *dbMonitor {
	e.mon.mu.Lock()
	defer e.mon.mu.Unlock()
	if e.mon.dbs == nil {
		e.mon.dbs = map[string]*dbMonitor{}
	}
	m := e.mon.dbs[id]
	if m == nil {
		m = &dbMonitor{slowID: -1}
		e.mon.dbs[id] = m
	}
	return m
}

// Monitor collects one sample of db.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: db.ID}
	m := e.monitorFor(db.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.c == nil {
		c, err := connectDB(ctx, env, db)
		if err != nil {
			dm.Error = err.Error()
			return dm, nil
		}
		m.c = c
	}
	if err := e.sample(ctx, env, db, m, dm); err != nil {
		m.c.Close()
		m.c = nil
		dm.Error = "can't read " + e.display() + "'s status: " + firstLine(plainConnError(err).Error())
	}
	return dm, nil
}

// replicaLine is one slaveN line of INFO replication.
type replicaLine struct {
	Addr   string
	State  string
	Offset int64
	Lag    int64
	Ours   bool
}

// replicas reads the replicas from INFO replication, telling Rowsafe's
// own link (ip=rowsafe-agent) apart.
func replicas(m infoMap) []replicaLine {
	var out []replicaLine
	for i := 0; ; i++ {
		v, ok := m["slave"+strconv.Itoa(i)]
		if !ok {
			break
		}
		f := fields(v)
		off, _ := strconv.ParseInt(f["offset"], 10, 64)
		lag, _ := strconv.ParseInt(f["lag"], 10, 64)
		out = append(out, replicaLine{Addr: f["ip"] + ":" + f["port"], State: f["state"], Offset: off, Lag: lag, Ours: f["ip"] == linkAddr})
	}
	return out
}

func (e *Engine) sample(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m *dbMonitor, dm *protocol.DatabaseMonitoring) error {
	c := m.c
	now := time.Now()
	info, err := c.info(ctx, "all")
	if err != nil {
		return err
	}
	in := infoFrom(info)
	metrics := map[string]float64{}
	clients := float64(info.int("connected_clients"))
	metrics[collect.MConnTotal] = clients
	maxClients := int64(0)
	if v, err := c.configGet(ctx, "maxclients"); err == nil {
		maxClients, _ = strconv.ParseInt(v, 10, 64)
	}
	if maxClients > 0 {
		metrics[collect.MConnMax] = float64(maxClients)
		metrics[collect.MConnUsedPct] = 100 * clients / float64(maxClients)
	}
	metrics[collect.MRedisUsedMemoryBytes] = float64(in.UsedMemory)
	metrics[collect.MDatabaseSizeBytes] = float64(in.UsedMemoryDataset)
	if in.MaxMemory > 0 {
		metrics[collect.MRedisMemoryUsedPct] = 100 * float64(in.UsedMemory) / float64(in.MaxMemory)
	}
	if r := info.float("mem_fragmentation_ratio"); r > 0 {
		metrics[collect.MRedisFragmentationRatio] = r
	}
	metrics[collect.MRedisKeys] = float64(in.totalKeys())
	metrics[collect.MRedisBlockedClients] = float64(info.int("blocked_clients"))
	metrics[collect.MRedisChangesSinceSave] = float64(info.int("rdb_changes_since_last_save"))
	if t := info.int("rdb_last_save_time"); t > 0 {
		metrics[collect.MRedisLastSaveAgeSeconds] = max(now.Sub(time.Unix(t, 0)).Seconds(), 0)
	}
	metrics[collect.MRedisBgsaveFailed] = boolMetric(info["rdb_last_bgsave_status"] != "" && info["rdb_last_bgsave_status"] != "ok")
	metrics[collect.MRedisAOFWriteFailed] = boolMetric(info["aof_enabled"] == "1" && info["aof_last_write_status"] != "" && info["aof_last_write_status"] != "ok")

	// Replication, without Rowsafe's link.
	reps := replicas(info)
	var real int
	var worst int64
	for _, r := range reps {
		if r.Ours {
			continue
		}
		real++
		if b := in.ReplOffset - r.Offset; b > worst {
			worst = b
		}
		metrics[collect.MReplicationLagSeconds] = max(metrics[collect.MReplicationLagSeconds], float64(r.Lag))
	}
	metrics[collect.MRedisConnectedReplicas] = float64(real)
	if real > 0 {
		metrics[collect.MRedisReplicationLagBytes] = float64(worst)
	}
	if in.isReplica() {
		if info["master_link_status"] == "up" {
			metrics[collect.MReplicationLagSeconds] = float64(info.int("master_last_io_seconds_ago"))
		} else if d := info.int("master_link_down_since_seconds"); d > 0 {
			metrics[collect.MReplicationLagSeconds] = float64(d)
		}
		if mo := info.int("master_repl_offset"); mo > 0 {
			metrics[collect.MRedisReplicationLagBytes] = float64(max(mo-info.int("slave_repl_offset"), 0))
		}
	}

	// Rates since the previous reading.
	hits, misses := float64(info.int("keyspace_hits")), float64(info.int("keyspace_misses"))
	counters := map[string]float64{
		collect.MRedisOpsRate:           float64(info.int("total_commands_processed")),
		collect.MRedisEvictedKeysRate:   float64(info.int("evicted_keys")),
		collect.MRedisExpiredKeysRate:   float64(info.int("expired_keys")),
		collect.MRedisRejectedConnsRate: float64(info.int("rejected_connections")),
		collect.MRedisNetInputRate:      float64(info.int("total_net_input_bytes")),
		collect.MRedisNetOutputRate:     float64(info.int("total_net_output_bytes")),
		"hits":                          hits,
		"misses":                        misses,
	}
	if m.prev != nil {
		secs := now.Sub(m.prevAt).Seconds()
		for k, v := range counters {
			if p, ok := m.prev[k]; ok && secs > 0 && v >= p && k != "hits" && k != "misses" {
				metrics[k] = (v - p) / secs
			}
		}
		dh, dmiss := hits-m.prev["hits"], misses-m.prev["misses"]
		if dh >= 0 && dmiss >= 0 && dh+dmiss > 0 {
			metrics[collect.MRedisHitRatePct] = 100 * dh / (dh + dmiss)
		}
	}
	m.prev, m.prevAt = counters, now

	// Slow log: new entries per second; latency monitor: the newest spike.
	if v, err := c.do(ctx, "SLOWLOG", "GET", 128); err == nil {
		entries := asArray(v)
		var newest int64 = -1
		n := 0
		for _, ent := range entries {
			f := asArray(ent)
			if len(f) == 0 {
				continue
			}
			id := asInt(f[0])
			newest = max(newest, id)
			if m.slowID >= 0 && id > m.slowID {
				n++
			}
		}
		if m.slowID >= 0 && !m.prevAt.IsZero() {
			metrics[collect.MRedisSlowlogRate] = float64(n) / 60
		}
		if newest >= 0 {
			m.slowID = newest
		} else if m.slowID < 0 {
			m.slowID = 0
		}
	}
	lat := latencyEvents(ctx, c)
	for _, l := range lat {
		if now.Sub(l.At) < 2*time.Minute {
			metrics[collect.MRedisLatencyMaxSeconds] = max(metrics[collect.MRedisLatencyMaxSeconds], float64(l.LatestMs)/1000)
		}
	}
	// Disk: only where the agent sees the server's data folder.
	if !inDocker() && in.Dir != "" {
		if total, free, err := diskUsage(in.Dir); err == nil && total > 0 {
			metrics[collect.MDiskTotalBytes] = float64(total)
			metrics[collect.MDiskFreeBytes] = float64(free)
			metrics[collect.MDiskFreePct] = 100 * float64(free) / float64(total)
		}
	}
	if now.Sub(m.statusAt) >= statusEvery {
		dm.Sizes = sizesOf(in)
		dm.Redis = e.status(ctx, db, c, info, in, reps, lat, maxClients)
		m.statusAt = now
	}
	dm.Insights = e.advisorInsights(env, db, &m.adv) // insights.go
	dm.Metrics = metrics
	return nil
}

func boolMetric(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// sizesOf shares the dataset out by keys per logical database.
func sizesOf(in serverInfo) []protocol.DatabaseSize {
	var out []protocol.DatabaseSize
	for _, d := range in.dbInfos() {
		out = append(out, protocol.DatabaseSize{Name: d.Name, SizeBytes: d.SizeBytes})
	}
	return out
}

// latencyEvents reads LATENCY LATEST.
func latencyEvents(ctx context.Context, c *conn) []protocol.RedisLatencyEvent {
	v, err := c.do(ctx, "LATENCY", "LATEST")
	if err != nil {
		return nil
	}
	var out []protocol.RedisLatencyEvent
	for _, ent := range asArray(v) {
		f := asArray(ent)
		if len(f) < 4 {
			continue
		}
		out = append(out, protocol.RedisLatencyEvent{Event: asString(f[0]), At: time.Unix(asInt(f[1]), 0).UTC(),
			LatestMs: asInt(f[2]), MaxMs: asInt(f[3])})
	}
	return out
}

// status is the detailed health (DatabaseMonitoring.Redis).
func (e *Engine) status(ctx context.Context, db protocol.DatabaseSpec, c *conn, info infoMap, in serverInfo, reps []replicaLine,
	lat []protocol.RedisLatencyEvent, maxClients int64) *protocol.RedisStatus {
	st := &protocol.RedisStatus{CollectedAt: time.Now().UTC(), Version: in.Version, Role: info["role"],
		UsedMemoryBytes: in.UsedMemory, MaxMemoryBytes: in.MaxMemory, MaxMemoryPolicy: in.MaxMemoryPolicy,
		Allocator: info["mem_allocator"], FragmentationRatio: info.float("mem_fragmentation_ratio"),
		FragmentationBytes: max(info.int("used_memory_rss")-in.UsedMemory, 0), TotalSystemMemoryBytes: in.TotalSystemMemory,
		EvictedKeys: info.int("evicted_keys"), MaxClients: maxClients, ReplBacklogBytes: in.BacklogSize,
		FullSyncs: info.int("sync_full"), MinReplicasToWrite: in.MinReplicasToWrite, Latency: lat}
	if st.Role == "slave" {
		st.Role = "replica"
	}
	if v, err := c.configGet(ctx, "activedefrag"); err == nil {
		st.ActiveDefrag = v == "yes"
	}
	save, _ := c.configGet(ctx, "save")
	st.Persistence = protocol.RedisPersistence{SaveRules: save, LastBgsaveOK: info["rdb_last_bgsave_status"] == "ok",
		ChangesSinceSave: info.int("rdb_changes_since_last_save"), AOFEnabled: info["aof_enabled"] == "1",
		AOFLastWriteOK: info["aof_last_write_status"] != "err", AOFLastRewriteOK: info["aof_last_bgrewrite_status"] != "err",
		Loading: info["loading"] == "1", ForkMicroseconds: info.int("latest_fork_usec")}
	if t := info.int("rdb_last_save_time"); t > 0 {
		at := time.Unix(t, 0).UTC()
		st.Persistence.LastSaveAt = &at
	}
	for _, r := range reps {
		if r.Ours {
			continue
		}
		st.Replicas = append(st.Replicas, protocol.RedisReplica{Addr: r.Addr, State: r.State, LagSeconds: r.Lag,
			BehindBytes: max(in.ReplOffset-r.Offset, 0)})
	}
	if in.isReplica() {
		port, _ := strconv.Atoi(info["master_port"])
		st.Primary = &protocol.RedisPrimaryLink{Host: info["master_host"], Port: port, LinkUp: info["master_link_status"] == "up",
			DownSeconds: max(info.int("master_link_down_since_seconds"), 0), LastIOSeconds: max(info.int("master_last_io_seconds_ago"), 0),
			SyncInProgress: info["master_sync_in_progress"] == "1"}
	}
	if v, err := c.do(ctx, "SLOWLOG", "GET", 20); err == nil {
		for _, ent := range asArray(v) {
			f := asArray(ent)
			if len(f) < 4 {
				continue
			}
			se := protocol.RedisSlowEntry{ID: asInt(f[0]), At: time.Unix(asInt(f[1]), 0).UTC(), DurationMicros: asInt(f[2])}
			if args := asArray(f[3]); len(args) > 0 {
				se.Command = strings.ToUpper(asString(args[0])) // the name only: arguments hold keys and values
			}
			if len(f) >= 6 {
				se.Client = asString(f[5])
			}
			st.SlowLog = append(st.SlowLog, se)
		}
	}
	st.Clients = stuckClients(ctx, c)
	st.NoPassword = defaultNoPassword(ctx, c)
	if f := e.existingFollower(db.ID); f != nil {
		ls := f.snapshot()
		st.Link, st.LinkProblem = ls.Mode, ls.Problem
		cut := time.Now().Add(-24 * time.Hour)
		for _, t := range ls.FullSyncs {
			if t.After(cut) {
				st.AgentFullSyncs24h++
			}
		}
	}
	return st
}

// stuckClients lists connections that look stuck: blocked for over 5
// minutes, or holding over 32 MiB of replies they don't read. Replicas,
// Rowsafe's own connections and pub/sub subscribers (blocked by design)
// are left out.
func stuckClients(ctx context.Context, c *conn) []protocol.RedisClient {
	s, err := c.str(ctx, "CLIENT", "LIST")
	if err != nil {
		return nil
	}
	now := time.Now()
	var out []protocol.RedisClient
	for _, line := range strings.Split(s, "\n") {
		f := map[string]string{}
		for _, kv := range strings.Fields(line) {
			k, v, ok := strings.Cut(kv, "=")
			if ok {
				f[k] = v
			}
		}
		if f["id"] == "" {
			continue
		}
		flags := f["flags"]
		name := f["name"]
		if strings.ContainsAny(flags, "SMP") || strings.HasPrefix(name, "rowsafe-") {
			continue // replicas, primaries, pub/sub, Rowsafe
		}
		id, _ := strconv.ParseInt(f["id"], 10, 64)
		age, _ := strconv.ParseInt(f["age"], 10, 64)
		idle, _ := strconv.ParseInt(f["idle"], 10, 64)
		omem, _ := strconv.ParseInt(f["omem"], 10, 64)
		blocked := strings.Contains(flags, "b")
		var reason string
		switch {
		case omem > 32<<20:
			reason = "it holds " + humanBytes(omem) + " of replies it doesn't read, in the server's memory"
		case blocked && idle > 300:
			reason = "it has waited in a blocking command (" + strings.ToUpper(f["cmd"]) + ") for " + (time.Duration(idle) * time.Second).String()
		default:
			continue
		}
		out = append(out, protocol.RedisClient{ID: id, Addr: f["addr"], Name: name, User: f["user"],
			ConnectedAt: now.Add(-time.Duration(age) * time.Second).UTC().Truncate(time.Minute), IdleSeconds: idle,
			Command: strings.ToUpper(f["cmd"]), Blocked: blocked, OutputBufferBytes: omem, Reason: reason})
	}
	slices.SortFunc(out, func(a, b protocol.RedisClient) int {
		return cmpInt(b.OutputBufferBytes+b.IdleSeconds, a.OutputBufferBytes+a.IdleSeconds)
	})
	if len(out) > 20 {
		out = out[:20]
	}
	return out
}

// defaultNoPassword: the default user is on and needs no password.
func defaultNoPassword(ctx context.Context, c *conn) bool {
	conn2, err := dial(ctx, c.nc.RemoteAddr().String())
	if err != nil {
		return false
	}
	defer conn2.Close()
	_, err = conn2.do(ctx, "PING")
	return err == nil
}
