package redis

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestPersistenceOff(t *testing.T) {
	for _, c := range []struct {
		save, aof string
		off       bool
	}{
		{"", "no", true},
		{" ", "NO", true},
		{"3600 1 300 100 60 10000", "no", false},
		{"", "yes", false},
		{"3600 1", "yes", false},
	} {
		if got := persistenceOff(c.save, c.aof); got != c.off {
			t.Errorf("save %q appendonly %q: %v", c.save, c.aof, got)
		}
	}
	for _, name := range []string{protocol.EngineRedis, protocol.EngineValkey} {
		msg := (&Engine{name: name}).emptyRefusal()
		if !strings.Contains(msg, protocol.EngineDisplayName(name)+": it keeps nothing on its own disk") || !strings.Contains(msg, "Turn on snapshots first") {
			t.Errorf("%s: %q", name, msg)
		}
	}
}

func TestReplayedCounts(t *testing.T) {
	res := &protocol.DrillResult{Databases: []protocol.DrillDatabase{
		{Name: "db0", SourceTables: 250, RestoredTables: 250, Present: true},
		{Name: "db1", SourceTables: 3, RestoredTables: 3, Present: true},
	}}
	// After the backup: db0 grew, db2 was made.
	replayedCounts(map[int]dbKeys{0: {Keys: 354}, 1: {Keys: 3}, 2: {Keys: 5}},
		map[int]dbKeys{0: {Keys: 354}, 1: {Keys: 3}, 2: {Keys: 5}}, res)
	got := fmt.Sprint(res.Databases)
	want := "[{db0 true 354 354} {db1 true 3 3} {db2 true 5 5}]"
	if got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestTargetsSig(t *testing.T) {
	env := agent.EngineEnv{StateDir: t.TempDir()}
	os.MkdirAll(loginsDir(env), 0o700)
	a := targetsSig(env, []serverProc{{Port: 6379}})
	if b := targetsSig(env, []serverProc{{Port: 6379}, {Port: 6381}}); a == b {
		t.Error("a new server keeps the cached list")
	}
	time.Sleep(10 * time.Millisecond)
	if err := saveLogin(env, 6381, Login{User: "rowsafe", Password: "x", Target: targetAll}); err != nil {
		t.Fatal(err)
	}
	if b := targetsSig(env, []serverProc{{Port: 6379}}); a == b {
		t.Error("a new login keeps the cached list")
	}
}

// Redis reports used_memory_dataset unsigned: on a tiny dataset it wraps
// around (Redis 8 with its modules). It must not read as exabytes.
func TestUsedMemoryDatasetWraps(t *testing.T) {
	in := infoFrom(parseInfo("redis_version:8.2.1\r\nused_memory:2097152\r\nused_memory_dataset:18446744073709550000\r\n"))
	if in.UsedMemoryDataset != 2097152 {
		t.Fatalf("dataset %d", in.UsedMemoryDataset)
	}
	if in = infoFrom(parseInfo("redis_version:8.2.1\r\nused_memory:2097152\r\nused_memory_dataset:13674\r\n")); in.UsedMemoryDataset != 13674 {
		t.Fatalf("dataset %d", in.UsedMemoryDataset)
	}
}
