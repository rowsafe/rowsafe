//go:build redis_integration

package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisRecommendations: the recommendations' facts, through the
// monitor as the agent runs it, as Rowsafe's own user, hold patterns and
// counts only: no key name or value of the seeded data.
func TestRedisRecommendations(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()

	var names, values []string
	var cmds [][]any
	val := func(i int, what string) string {
		v := fmt.Sprintf("secret-%s-value-%06d", what, i)
		values = append(values, v)
		return v
	}
	for i := range 600 {
		k := fmt.Sprintf("session:%08x-1a2b-4c3d-8e9f-%012x", i*7919, i)
		names = append(names, k)
		cmds = append(cmds, []any{"SET", k, val(i, "session"), "EX", 3600})
	}
	for i := range 400 {
		k := fmt.Sprintf("user:%d:cart", 1000+i)
		names = append(names, k)
		cmds = append(cmds, []any{"HSET", k, "item", val(i, "cart"), "qty", "2"})
	}
	for i := range 300 {
		k := fmt.Sprintf("cache:page:/a/%d", i)
		names = append(names, k)
		cmds = append(cmds, []any{"SET", k, val(i, "page")})
	}
	// A few keys of one customer: never named.
	for i := range 3 {
		k := fmt.Sprintf("tenant:wombatcorp:doc:%d", i)
		names = append(names, k)
		cmds = append(cmds, []any{"SET", k, val(i, "doc")})
	}
	if _, errs, err := a.pipeline(ctx, cmds); err != nil || slices.ContainsFunc(errs, func(e error) bool { return e != nil }) {
		t.Fatalf("seeding: %v %v", err, errs)
	}
	// Two big keys with random names.
	for i := range 2 {
		k := fmt.Sprintf("blob:%x", time.Now().UnixNano()+int64(i))
		names = append(names, k)
		rd(t, a, "SET", k, strings.Repeat("b", 11<<20))
	}
	rd(t, a, "SELECT", 1)
	for i := range 50 {
		k := fmt.Sprintf("queue:jobs:%d", i)
		names = append(names, k)
		rd(t, a, "RPUSH", k, val(i, "job"), val(i+1000, "job"))
	}
	rd(t, a, "SELECT", 0)
	// Commands for the statistics and the slow log.
	rd(t, a, "CONFIG", "SET", "slowlog-log-slower-than", "0")
	rd(t, a, "KEYS", "*")
	for i := range 5 {
		rd(t, a, "HGETALL", fmt.Sprintf("user:%d:cart", 1000+i))
	}
	rd(t, a, "CONFIG", "SET", "slowlog-log-slower-than", "10000")

	// The monitor starts the sample in the background and reports it later.
	var ins *protocol.Insights
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		dm, err := e.Monitor(ctx, env, db)
		if err != nil || dm.Error != "" {
			t.Fatalf("monitor: %v %s", err, dm.Error)
		}
		if dm.Insights != nil {
			ins = dm.Insights
			break
		}
	}
	if ins == nil || ins.Advisor == nil || ins.Advisor.Redis == nil {
		t.Fatalf("no insights: %+v", ins)
	}
	f := ins.Advisor.Redis
	raw, _ := json.Marshal(ins)
	t.Logf("facts (%d bytes, %d ms): %s", len(raw), f.SampleMs, raw)

	pat := map[string]protocol.RedisKeyPattern{}
	for _, p := range f.Patterns {
		pat[fmt.Sprintf("%d %s", p.DB, p.Pattern)] = p
	}
	check := func(key string, keys, noTTL int64, typ string) {
		t.Helper()
		p, ok := pat[key]
		if !ok || p.SampledKeys != keys || p.NoTTL != noTTL || p.Type != typ || p.SampledBytes <= 0 {
			t.Errorf("pattern %s: %+v (found: %v)", key, p, ok)
		}
	}
	check("0 session:*", 600, 0, "string")
	check("0 user:*:cart", 400, 400, "hash")
	check("0 cache:page:/a/*", 300, 300, "string")
	check("1 queue:jobs:*", 50, 50, "list")
	if len(f.DBs) != 2 || f.DBs[0].DB != 0 || f.DBs[0].Keys != 1305 || f.DBs[0].Expires != 600 || f.DBs[0].SampledKeys != 1305 ||
		f.DBs[0].BigKeys != 2 || f.DBs[0].BiggestKeyBytes < 11<<20 || f.DBs[0].OtherKeys != 5 || f.DBs[1].SampledKeys != 50 {
		t.Errorf("dbs: %+v", f.DBs)
	}
	if f.Partial || f.Role != "master" || f.Databases != 16 || f.Version == "" || f.UptimeSeconds <= 0 || f.AppendOnly || f.Save != "" {
		t.Errorf("server facts: %+v", f)
	}
	cmd := map[string]protocol.RedisCommandStat{}
	for _, c := range f.Commands {
		cmd[c.Name] = c
	}
	if cmd["keys"].Calls < 1 || cmd["hgetall"].Calls < 5 {
		t.Errorf("commands: %+v", f.Commands)
	}
	slow := map[string]int{}
	for _, s := range f.SlowCommands {
		slow[s.Name] = s.Count
	}
	if slow["keys"] < 1 || slow["hgetall"] < 1 {
		t.Errorf("slow commands: %+v", f.SlowCommands)
	}

	// Nothing of the data leaves the server.
	js := string(raw)
	for _, s := range append(names, values...) {
		if strings.Contains(js, s) {
			t.Fatalf("the facts hold %q", s)
		}
	}
	for _, w := range []string{"wombatcorp", "secret-", "blob:", "1a2b-4c3d"} {
		if strings.Contains(js, w) {
			t.Fatalf("the facts hold %q", w)
		}
	}

	// The next report doesn't repeat it; the next sample waits 30 minutes.
	if dm, _ := e.Monitor(ctx, env, db); dm.Insights != nil {
		t.Fatal("the insights came twice")
	}
}
