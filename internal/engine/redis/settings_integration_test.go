//go:build redis_integration

package redis

import (
	"context"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// TestRedisSettings: Tuning on a real server: the snapshot, a change
// applied live and kept (CONFIG REWRITE: the test server can write its
// file), refusals that change nothing, undo and reset.
func TestRedisSettings(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	cfg := func(name string) string {
		v, err := a.configGet(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	rd(t, a, "CONFIG", "SET", "maxmemory", "0", "maxmemory-policy", "noeviction", "save", "", "latency-monitor-threshold", "0")

	c, err := connectDB(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	snap, err := e.settingsSnapshot(ctx, env, c)
	if err != nil {
		t.Fatal(err)
	}
	byName := tune.SettingsMap(snap.Settings)
	for _, name := range []string{"maxmemory", "maxmemory-policy", "save", "appendonly", "timeout", "slowlog-log-slower-than", "latency-tracking"} {
		if _, ok := byName[name]; !ok {
			t.Errorf("snapshot lacks %s", name)
		}
	}
	if _, ok := byName["requirepass"]; ok {
		t.Fatal("the snapshot holds the password")
	}
	if byName["save"].Setting != tune.RedisSaveOff || snap.Redis == nil || snap.Redis.Keys < 2000 || snap.Redis.ExpiringKeys != 300 ||
		snap.Redis.UsedMemoryBytes == 0 || snap.Host.MemoryBytes == 0 || snap.VersionNum == 0 {
		t.Fatalf("snapshot %+v %+v", snap.Redis, snap)
	}
	if snap.Redis.Kept != protocol.RedisKeptRewrite || snap.Redis.LiveOnly == "" {
		t.Errorf("kept %q %q", snap.Redis.Kept, snap.Redis.LiveOnly)
	}
	t.Logf("live only: %s", snap.Redis.LiveOnly)
	// "Tune for this server" passes the agent's own checks.
	recs := tune.For(e.name).Recommend(tune.InputFrom(*snap, protocol.RedisWorkloadStore, ""))
	if len(recs) == 0 {
		t.Fatal("no recommendations for an untuned server")
	}
	var changes []protocol.SettingChange
	for _, r := range recs {
		changes = append(changes, protocol.SettingChange{Name: r.Name, Value: r.Value})
	}
	res := mustRun[protocol.SettingsResult](t, e, env, db, protocol.TaskSettings, protocol.SettingsParams{Kind: protocol.SettingsKindTune, Changes: changes})
	t.Log(res.Summary)
	if len(res.Applied) != len(recs) || res.Snapshot == nil {
		t.Fatalf("tune: %+v", res)
	}

	// A person's change, applied live and kept in the configuration file.
	res = mustRun[protocol.SettingsResult](t, e, env, db, protocol.TaskSettings, protocol.SettingsParams{Kind: protocol.SettingsKindSet,
		Changes: []protocol.SettingChange{{Name: "maxmemory", Value: "256mb"}, {Name: "maxmemory-policy", Value: "allkeys-lru"},
			{Name: "save", Value: "3600 1"}, {Name: "slowlog-log-slower-than", Value: "off"}, {Name: "timeout", Value: "5min"}}})
	t.Log(res.Summary)
	if !strings.Contains(res.Summary, "keeps them in its configuration file") {
		t.Errorf("not kept: %s", res.Summary)
	}
	if cfg("maxmemory") != "268435456" || cfg("maxmemory-policy") != "allkeys-lru" || cfg("save") != "3600 1" ||
		cfg("slowlog-log-slower-than") != "-1" || cfg("timeout") != "300" {
		t.Fatalf("live values: %s %s %q %s %s", cfg("maxmemory"), cfg("maxmemory-policy"), cfg("save"), cfg("slowlog-log-slower-than"), cfg("timeout"))
	}
	after := tune.SettingsMap(res.Snapshot.Settings)
	if after["maxmemory"].Setting != "268435456" || after["maxmemory"].Source == "default" {
		t.Errorf("snapshot after: %+v", after["maxmemory"])
	}

	// Refused: nothing changes.
	for _, bad := range [][]protocol.SettingChange{
		{{Name: "maxmemory", Value: "1mb"}},
		{{Name: "requirepass", Value: "x"}},
		{{Name: "repl-backlog-size", Value: "64mb"}},
		{{Name: "timeout", Value: "1"}, {Name: "maxmemory", Value: "512mb"}},
	} {
		if _, err := run[protocol.SettingsResult](t, e, env, db, protocol.TaskSettings, protocol.SettingsParams{Kind: protocol.SettingsKindSet, Changes: bad}); err == nil {
			t.Errorf("%+v accepted", bad)
		} else {
			t.Logf("refused: %v", err)
		}
	}
	if cfg("maxmemory") != "268435456" || cfg("timeout") != "300" {
		t.Fatal("a refused change changed something")
	}
	// Undo: the previous values come back.
	var undo []protocol.SettingChange
	for _, ap := range res.Applied {
		if ap.Previous == nil {
			t.Fatalf("%s: no previous value", ap.Name)
		}
		undo = append(undo, protocol.SettingChange{Name: ap.Name, Value: *ap.Previous})
	}
	mustRun[protocol.SettingsResult](t, e, env, db, protocol.TaskSettings, protocol.SettingsParams{Kind: protocol.SettingsKindRevert, Changes: undo})
	if cfg("maxmemory-policy") != "noeviction" || cfg("slowlog-log-slower-than") != "10000" || cfg("timeout") != "0" {
		t.Errorf("after undo: %s %s %s", cfg("maxmemory-policy"), cfg("slowlog-log-slower-than"), cfg("timeout"))
	}
	// Reset: back to the default.
	mustRun[protocol.SettingsResult](t, e, env, db, protocol.TaskSettings, protocol.SettingsParams{Kind: protocol.SettingsKindSet,
		Changes: []protocol.SettingChange{{Name: "maxmemory", Reset: true}, {Name: "latency-monitor-threshold", Reset: true}}})
	if cfg("maxmemory") != "0" || cfg("latency-monitor-threshold") != "0" {
		t.Errorf("after reset: %s %s", cfg("maxmemory"), cfg("latency-monitor-threshold"))
	}
	// Monitoring carries the snapshot.
	dm, _ := e.Monitor(ctx, env, db)
	if dm.Settings == nil || len(dm.Settings.Settings) < 10 {
		t.Errorf("monitoring settings: %+v (%s)", dm.Settings, dm.Error)
	}
	rd(t, a, "CONFIG", "SET", "save", "")
}
