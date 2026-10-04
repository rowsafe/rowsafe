package redis

import (
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
