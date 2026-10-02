package tuneroot

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const mongodConf = `# mongod.conf
storage:
  dbPath: /var/lib/mongodb   # data
  wiredTiger:
    engineConfig:
      cacheSizeGB: 1
net:
  port: 27017
  bindIp: 127.0.0.1
`

func TestMongo(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "mongod.conf")
	if err := os.WriteFile(file, []byte(mongodConf), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &Applier{StateDir: filepath.Join(dir, "state"), Now: time.Now}
	res := a.Apply(Request{ID: "r1", Engine: "mongodb", Settings: map[string]string{"wiredtiger_cache_size": "4294967296", "slow_op_threshold_ms": "200"}}, file)
	if !res.OK {
		t.Fatal(res.Error)
	}
	got, _ := os.ReadFile(file)
	s := string(got)
	for _, want := range []string{"cacheSizeGB: 4", "slowOpThresholdMs: 200", "# data", "bindIp: 127.0.0.1", "# mongod.conf"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	// Undo: the original values come back.
	res = a.Apply(Request{ID: "r2", Engine: "mongodb", Settings: map[string]string{"wiredtiger_cache_size": "", "slow_op_threshold_ms": ""}}, file)
	if !res.OK || res.Previous["wiredtiger_cache_size"] != "4294967296" {
		t.Fatalf("%+v", res)
	}
	got, _ = os.ReadFile(file)
	if !strings.Contains(string(got), "cacheSizeGB: 1") || strings.Contains(string(got), "operationProfiling") {
		t.Errorf("after undo:\n%s", got)
	}
	if res := a.Apply(Request{ID: "r3", Engine: "mongodb", Settings: map[string]string{"storage.dbPath": "/tmp"}}, file); res.OK {
		t.Error("accepted an unknown setting")
	}
	if res := a.Apply(Request{ID: "r4", Engine: "mongodb", Settings: map[string]string{"profiling_mode": "all"}}, file); res.OK {
		t.Error("accepted profiling all")
	}
}

func TestClickHouse(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"config.d", "users.d"} {
		_ = os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	a := &Applier{StateDir: filepath.Join(dir, "state"), Now: time.Now}
	res := a.Apply(Request{ID: "c1", Engine: "clickhouse", Settings: map[string]string{"max_memory_usage": "8589934592", "max_concurrent_queries": "200"}}, dir)
	if !res.OK || len(res.Files) != 2 {
		t.Fatalf("%+v", res)
	}
	users, _ := os.ReadFile(filepath.Join(dir, "users.d", "rowsafe-tuning.xml"))
	server, _ := os.ReadFile(filepath.Join(dir, "config.d", "rowsafe-tuning.xml"))
	if !strings.Contains(string(users), "<profiles>") || !strings.Contains(string(users), "<max_memory_usage>8589934592</max_memory_usage>") ||
		!strings.Contains(string(server), "<max_concurrent_queries>200</max_concurrent_queries>") {
		t.Errorf("files:\n%s\n%s", users, server)
	}
	res = a.Apply(Request{ID: "c2", Engine: "clickhouse", Settings: map[string]string{"max_concurrent_queries": ""}}, dir)
	if !res.OK || res.Previous["max_concurrent_queries"] != "200" {
		t.Fatalf("%+v", res)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.d", "rowsafe-tuning.xml")); !os.IsNotExist(err) {
		t.Error("empty server file kept")
	}
	if res := a.Apply(Request{ID: "c3", Engine: "clickhouse", Settings: map[string]string{"max_memory_usage": "1<x/>"}}, dir); res.OK {
		t.Error("accepted markup")
	}
}
