package redis

import (
	"fmt"
	"strings"
	"testing"

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
