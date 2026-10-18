package pulse

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

func redisInput(engine string) Input {
	return Input{Database: "cache", Host: "cache.example.com", Engine: engine,
		Command: func(sub string) string { return "rowsafe " + sub + " redis://cache.example.com" },
		Metrics: map[string]float64{collect.MConnUsedPct: 1, collect.MConnTotal: 100, collect.MConnMax: 10000},
		Redis: &protocol.RedisStatus{CollectedAt: now, UsedMemoryBytes: 100 << 20, MaxMemoryBytes: 1 << 30, MaxMemoryPolicy: "noeviction",
			Persistence: protocol.RedisPersistence{SaveRules: "3600 1", LastBgsaveOK: true, AOFLastWriteOK: true, AOFLastRewriteOK: true}}}
}

func TestRedisHealthy(t *testing.T) {
	for _, engine := range []string{protocol.EngineRedis, protocol.EngineValkey} {
		h := Evaluate(redisInput(engine), now)
		if h.Score != 100 || len(h.Findings) != 0 {
			t.Errorf("%s: %d %v", engine, h.Score, ids(h))
		}
		if c := check(t, h, CatMaintenance); c.Status != "ok" || c.Label != "Saving to disk" {
			t.Errorf("%s: %+v", engine, c)
		}
	}
}

func TestRedisFindings(t *testing.T) {
	connected := now.Add(-2 * time.Hour)
	in := redisInput(protocol.EngineValkey)
	st := in.Redis
	st.UsedMemoryBytes = 1010 << 20
	st.Allocator, st.FragmentationRatio, st.FragmentationBytes = "jemalloc-5.3.0", 2.1, 500<<20
	st.NoPassword = true
	st.Persistence = protocol.RedisPersistence{SaveRules: "", AOFEnabled: false, LastBgsaveOK: true, AOFLastWriteOK: true, AOFLastRewriteOK: true}
	st.Clients = []protocol.RedisClient{{ID: 42, Addr: "10.0.0.5:5000", Name: "worker", ConnectedAt: connected, IdleSeconds: 900, Blocked: true, Reason: "it has waited in a blocking command (BLPOP) for 15m0s"},
		{ID: 43, Name: "rowsafe", ConnectedAt: connected}}
	for i := range 6 {
		st.SlowLog = append(st.SlowLog, protocol.RedisSlowEntry{ID: int64(i), At: now.Add(-time.Minute), DurationMicros: 250_000, Command: "KEYS"})
	}
	st.Latency = []protocol.RedisLatencyEvent{{Event: "fork", At: now.Add(-5 * time.Minute), LatestMs: 300}}
	st.Replicas = []protocol.RedisReplica{{Addr: "10.0.0.9:6379", State: "online", LagSeconds: 120}}
	h := Evaluate(in, now)
	got := ids(h)
	for _, want := range []string{"redis_memory_noeviction", "redis_fragmented", "redis_no_password", "redis_stuck_client",
		"redis_slow_commands", "redis_latency_spikes", "redis_replica_lag", "redis_restart_empties"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	mem := finding(t, h, "redis_memory_noeviction")
	if mem.Severity != protocol.SeverityCritical || mem.Category != CatAvailability || !strings.Contains(mem.Title, "Valkey") || len(mem.Fixes) != 1 || !mem.Fixes[0].Destructive {
		t.Errorf("memory %+v", mem)
	}
	stuck := finding(t, h, "redis_stuck_client")
	if len(stuck.Fixes) != 1 || stuck.Fixes[0].ID != "redis_kill:42:"+itoa(connected.Unix()) {
		t.Fatalf("stuck fixes %+v", stuck.Fixes)
	}
	var p protocol.MaintenanceParams
	_ = json.Unmarshal(stuck.Fixes[0].Params, &p)
	if p.Action != protocol.MaintRedisKillClient || p.PID != 42 || !p.BackendStart.Equal(connected) {
		t.Errorf("kill params %+v", p)
	}
	if f := finding(t, h, "redis_fragmented"); len(f.Fixes) != 2 {
		t.Errorf("fragmented fixes %+v", f.Fixes)
	}
	empties := finding(t, h, "redis_restart_empties")
	var sp protocol.SettingsParams
	if len(empties.Fixes) != 1 || empties.Fixes[0].Kind != protocol.FixTune || json.Unmarshal(empties.Fixes[0].Params, &sp) != nil ||
		len(sp.Changes) != 1 || sp.Changes[0].Name != "save" || strings.Contains(empties.Explanation, "Rowsafe doesn't restart") {
		t.Errorf("restart empties %+v", empties)
	}
	if !strings.Contains(finding(t, h, "redis_slow_commands").Action, "SCAN") {
		t.Error("KEYS advice")
	}
	if h.Score > capCritical {
		t.Errorf("score %d", h.Score)
	}
	// Snapshots turned on since (a newer settings reading): no finding.
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now.Add(time.Second), Settings: []protocol.PGSetting{{Name: "save", Setting: "3600 1 300 100 60 10000"}, {Name: "appendonly", Setting: "no"}}}
	if slices.Contains(ids(Evaluate(in, now)), "redis_restart_empties") {
		t.Error("snapshots on")
	}
}

func TestRedisPersistenceFailing(t *testing.T) {
	in := redisInput(protocol.EngineRedis)
	in.Local = true
	in.Metrics[collect.MDiskFreePct], in.Metrics[collect.MDiskFreeBytes] = 2, 1<<30
	in.Redis.Persistence.LastBgsaveOK = false
	h := Evaluate(in, now)
	if c := check(t, h, CatMaintenance); c.Status != "critical" {
		t.Errorf("%+v", c)
	}
	disk := finding(t, h, "disk_almost_full")
	if !strings.Contains(disk.Explanation, "can no longer save its snapshots") || disk.Command != "df -h; redis-cli CONFIG GET dir" {
		t.Errorf("disk %+v", disk)
	}
	finding(t, h, "redis_bgsave_failed")
}
