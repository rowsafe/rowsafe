package tune

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func redisSet(kv ...string) map[string]protocol.PGSetting {
	var list []protocol.PGSetting
	for i := 0; i+1 < len(kv); i += 2 {
		list = append(list, RedisPGSetting(kv[i], kv[i+1]))
	}
	return SettingsMap(list)
}

func TestRedisValue(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"maxmemory", "4gb", "4294967296"},
		{"maxmemory", "4GB", "4294967296"},
		{"maxmemory", "2g", "2000000000"},
		{"maxmemory", "1073741824", "1073741824"},
		{"maxmemory", "off", "0"},
		{"maxmemory-policy", "ALLKEYS-LRU", "allkeys-lru"},
		{"appendonly", "on", "yes"},
		{"activedefrag", "false", "no"},
		{"save", "", RedisSaveOff},
		{"save", "off", RedisSaveOff},
		{"save", ` 3600  1 300 100 `, "3600 1 300 100"},
		{"timeout", "5min", "300"},
		{"timeout", "300", "300"},
		{"slowlog-log-slower-than", "10ms", "10000"},
		{"slowlog-log-slower-than", "off", "-1"},
		{"latency-monitor-threshold", "100", "100"},
	} {
		got, ok := RedisValue(RedisPGSetting(c.name, ""), c.in)
		if !ok || got != c.want {
			t.Errorf("%s %q = %q %v, want %q", c.name, c.in, got, ok, c.want)
		}
	}
	for _, c := range []struct{ name, in string }{
		{"maxmemory", "lots"}, {"maxmemory-policy", "allkeys-everything"}, {"save", "3600"}, {"save", "1 2\nport 1"},
		{"save", "a b"}, {"appendonly", "maybe"}, {"timeout", "1.5"},
	} {
		if got, ok := RedisValue(RedisPGSetting(c.name, ""), c.in); ok {
			t.Errorf("%s %q accepted as %q", c.name, c.in, got)
		}
	}
	if !RedisSame(RedisPGSetting("maxmemory", "1073741824"), "1gb") || RedisSame(RedisPGSetting("maxmemory", "0"), "1gb") {
		t.Error("RedisSame sizes")
	}
	if s := RedisPGSetting("save", ""); s.Setting != RedisSaveOff || s.Source != "set at runtime" {
		t.Errorf("save off: %+v", s)
	}
	if s := RedisPGSetting("tcp-keepalive", "300"); s.Source != "default" || s.Context != "sighup" {
		t.Errorf("default: %+v", s)
	}
	tu := For(protocol.EngineValkey)
	if got := tu.Display("save", RedisSaveOff, "", "string"); got != "off" {
		t.Errorf("display save off = %q", got)
	}
	if got := tu.Display("maxmemory", "4294967296", "B", "integer"); got != "4 GB" {
		t.Errorf("display maxmemory = %q", got)
	}
	if v, _ := EngineValue(protocol.EngineRedis, RedisPGSetting("appendonly", "no"), "on"); v != "yes" {
		t.Errorf("EngineValue = %q", v)
	}
}

func TestRedisValidate(t *testing.T) {
	tu := For(protocol.EngineRedis)
	host := protocol.SettingsHost{MemoryBytes: 8 * gib, CPUs: 4}
	f := Facts{Host: host, Settings: redisSet("maxmemory", "0", "maxmemory-policy", "noeviction", "timeout", "0",
		"slowlog-log-slower-than", "10000", "repl-backlog-size", "1048576", "save", "3600 1", "maxclients", "10000",
		"latency-monitor-threshold", "0"),
		Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: 2 * gib}}
	ok := [][]protocol.SettingChange{
		{{Name: "maxmemory", Value: "6gb"}, {Name: "maxmemory-policy", Value: "allkeys-lru"}},
		{{Name: "maxmemory", Value: "0"}},
		{{Name: "save", Value: "off"}},
		{{Name: "timeout", Value: "off"}},
		{{Name: "latency-monitor-threshold", Value: "100"}},
		{{Name: "maxmemory", Reset: true}},
	}
	for _, c := range ok {
		if err := tu.Validate(Normalize(c), f); err != nil {
			t.Errorf("%+v refused: %v", c, err)
		}
	}
	bad := map[string][]protocol.SettingChange{
		"above 90%":     {{Name: "maxmemory", Value: "7.5gb"}},
		"below used":    {{Name: "maxmemory", Value: "1gb"}},
		"tiny":          {{Name: "maxmemory", Value: "1mb"}},
		"locked":        {{Name: "repl-backlog-size", Value: "64mb"}},
		"unknown":       {{Name: "requirepass", Value: "x"}},
		"tiny timeout":  {{Name: "timeout", Value: "2"}},
		"every command": {{Name: "slowlog-log-slower-than", Value: "0"}},
		"few clients":   {{Name: "maxclients", Value: "5"}},
		"bad policy":    {{Name: "maxmemory-policy", Value: "random"}},
		"latency 1ms":   {{Name: "latency-monitor-threshold", Value: "1"}},
	}
	for what, c := range bad {
		if err := tu.Validate(Normalize(c), f); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
}

func TestRedisRecommend(t *testing.T) {
	tu := For(protocol.EngineRedis)
	host := protocol.SettingsHost{MemoryBytes: 8 * gib, CPUs: 4}
	base := []string{"maxmemory", "0", "maxmemory-policy", "noeviction", "save", "", "appendonly", "no",
		"tcp-keepalive", "300", "latency-monitor-threshold", "0", "slowlog-log-slower-than", "10000"}
	byName := func(recs []protocol.SettingRecommendation) map[string]protocol.SettingRecommendation {
		m := map[string]protocol.SettingRecommendation{}
		for _, r := range recs {
			m[r.Name] = r
		}
		return m
	}

	// A cache, alone on the server.
	recs := byName(tu.Recommend(Input{Host: host, Workload: protocol.RedisWorkloadCache, Settings: redisSet(base...),
		Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: gib, Keys: 1000, ExpiringKeys: 10}}))
	if r := recs["maxmemory"]; r.Value != "6442450944" || r.Display != "6 GB" {
		t.Errorf("maxmemory %+v", r)
	}
	if r := recs["maxmemory-policy"]; r.Value != "allkeys-lru" || r.Optional {
		t.Errorf("policy %+v", r)
	}
	if _, ok := recs["save"]; ok {
		t.Error("save proposed for a cache")
	}
	if r := recs["latency-monitor-threshold"]; r.Value != "100" {
		t.Errorf("latency %+v", r)
	}

	// A store sharing the server with two other databases.
	set := redisSet(append(append([]string{}, base...), "maxmemory-policy", "allkeys-lru")...)
	recs = byName(tu.Recommend(Input{Host: host, Workload: protocol.RedisWorkloadStore, OtherDatabases: 2, Settings: set,
		Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: 512 * mib}}))
	if r := recs["maxmemory"]; r.Value != "2147483648" || !strings.Contains(r.Why, "2 other databases") {
		t.Errorf("shared maxmemory %+v", r)
	}
	if r := recs["maxmemory-policy"]; r.Value != "noeviction" {
		t.Errorf("store policy %+v", r)
	}
	if r := recs["save"]; r.Value != RedisSaveDefault || r.Optional {
		t.Errorf("store save %+v", r)
	}
	if err := tu.Validate([]protocol.SettingChange{{Name: "save", Value: recs["save"].Value}}, Facts{Host: host, Settings: set}); err != nil {
		t.Error(err)
	}

	// Not sure: almost every key expires, so it looks like a cache (optional).
	recs = byName(tu.Recommend(Input{Host: host, Workload: protocol.WorkloadMixed, Settings: redisSet(base...),
		Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: gib, Keys: 1000, ExpiringKeys: 990}}))
	if r := recs["maxmemory-policy"]; r.Value != "allkeys-lru" || !r.Optional {
		t.Errorf("inferred cache %+v", r)
	}
	// Used memory too close to the share: no limit proposed.
	recs = byName(tu.Recommend(Input{Host: host, Settings: redisSet(base...), Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: 5 * gib}}))
	if _, ok := recs["maxmemory"]; ok {
		t.Error("maxmemory proposed below what the data needs")
	}
	// Every recommendation passes validation.
	for _, r := range tu.Recommend(Input{Host: host, Workload: protocol.RedisWorkloadStore, Settings: redisSet(base...),
		Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: gib}}) {
		if err := tu.Validate([]protocol.SettingChange{{Name: r.Name, Value: r.Value}},
			Facts{Host: host, Settings: redisSet(base...), Redis: &protocol.RedisSettingsFacts{UsedMemoryBytes: gib}}); err != nil {
			t.Errorf("%s = %s refused: %v", r.Name, r.Value, err)
		}
	}
}
