package redis

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestLogSourceFor(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "redis.log"), []byte("1:M 04 Oct 2026 00:48:28.601 * Ready to accept connections tcp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name     string
		settings map[string]string
		sidecar  bool
		dataDir  string
		problem  string
		path     string
	}{
		{"stdout natively", map[string]string{"logfile": ""}, false, "", protocol.LogProblemJournal, ""},
		{"stdout in Docker", map[string]string{"logfile": ""}, true, "", protocol.LogProblemDockerStdout, ""},
		{"syslog", map[string]string{"logfile": "", "syslog-enabled": "yes"}, false, "", protocol.LogProblemSyslog, ""},
		{"logfmt", map[string]string{"logfile": "/x.log", "log-format": "logfmt"}, false, "", protocol.LogProblemUnsupported, ""},
		{"file", map[string]string{"logfile": filepath.Join(dir, "redis.log")}, false, "", "", filepath.Join(dir, "redis.log")},
		{"relative to dir", map[string]string{"logfile": "redis.log", "dir": dir}, false, "", "", filepath.Join(dir, "redis.log")},
		{"in the data volume", map[string]string{"logfile": "/data/redis.log", "dir": "/data"}, true, dir, "", filepath.Join(dir, "redis.log")},
		{"missing", map[string]string{"logfile": filepath.Join(dir, "nope.log")}, false, "", protocol.LogProblemNotFound, filepath.Join(dir, "nope.log")},
	} {
		src := logSourceFor("Redis", c.settings, c.sidecar, c.dataDir)
		if src.Status.Problem != c.problem || src.Path != c.path || src.Status.Readable != (c.problem == "") || src.Format != "redis" {
			t.Errorf("%s: %+v", c.name, src)
		}
	}
}
