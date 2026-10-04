package pglog

import (
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Real lines from Redis 8.2 and Valkey 9.0 (loglevel verbose), a Lua
// script's redis.log(), a module's line, and a crash report's shape.
const redisFixture = `13:C 04 Oct 2026 00:48:28.595 * oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
13:C 04 Oct 2026 00:48:28.595 * Redis version=8.2.10, bits=64, commit=00000000, modified=1, pid=13, just started
13:M 04 Oct 2026 00:48:28.600 - <vectorset> Successfully loaded default module configuration
13:M 04 Oct 2026 00:48:28.601 * Ready to accept connections tcp
13:M 04 Oct 2026 00:48:30.487 - Accepted 127.0.0.1:41344
13:M 04 Oct 2026 00:48:30.487 - Client closed connection id=4 addr=10.0.0.5:41344 laddr=127.0.0.1:6379 fd=12 name= age=0 idle=0 flags=A db=0 cmd=set user=app redir=-1 resp=2
13:M 04 Oct 2026 00:48:30.488 - Client closed connection id=5 addr=127.0.0.1:41345 laddr=127.0.0.1:6379 fd=12 name=rowsafe-agent age=0 idle=0 flags=N db=0 cmd=info user=rowsafe redir=-1 resp=2
13:M 04 Oct 2026 00:48:30.580 * Background saving started by pid 40
40:C 04 Oct 2026 00:48:30.585 * DB saved on disk
13:M 04 Oct 2026 00:48:30.653 * Background saving terminated with success
13:M 04 Oct 2026 00:48:31.821 * Replica 10.0.0.9:6380 asks for synchronization
13:M 04 Oct 2026 00:48:31.821 * Partial resynchronization not accepted: Replication ID mismatch (Replica asked for '9a86810780c65d079c3fdf8f461fd0da2267e14b', my replication IDs are '54e324f869b560070744bde994766a7ead9472d0' and '0000000000000000000000000000000000000000')
13:M 04 Oct 2026 00:48:34.226 # processing user:1234 for bob@example.com 42
13:M 04 Oct 2026 00:48:35.584 * Connection with replica (rdbchannel) 10.0.0.9:6380 lost.
13:M 04 Oct 2026 00:48:35.600 * Replica rowsafe-agent:6379 asks for synchronization
13:M 04 Oct 2026 00:48:36.000 # WARNING Memory overcommit must be enabled! Without it, a background save or replication may fail under low memory condition.
13:M 04 Oct 2026 00:48:37.000 # Can't save in background: fork: Cannot allocate memory
13:M 04 Oct 2026 00:48:38.000 # Background saving error
12:M 04 Oct 2026 00:49:06.957 * User requested shutdown... (user request from 'id=7 addr=127.0.0.1:49644 laddr=127.0.0.1:6379 fd=10 name=*redacted* user=*redacted* lib-name= lib-ver=')
12:M 04 Oct 2026 00:49:06.964 # Valkey is now ready to exit, bye bye...

                _._
13:M 04 Oct 2026 00:50:00.000 # === REDIS BUG REPORT START: Cut & paste starting from here ===
13:M 04 Oct 2026 00:50:00.000 # Redis 8.2.10 crashed by signal: 11, si_code: 0
13:M 04 Oct 2026 00:50:00.000 # argv[1]: '"user:1"'
13:M 04 Oct 2026 00:50:00.000 # client: id=7 addr=10.0.0.5:1234 cmd=get
13:M 04 Oct 2026 00:50:00.000 # === REDIS BUG REPORT END. Make sure to include from START to END. ===
14:C 04 Oct 2026 00:50:01.000 * oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo`

func TestRedisLog(t *testing.T) {
	es := ParseEngineLog(FormatRedis, redisFixture)
	type want struct {
		msg, kind, sev, client string
	}
	wants := []want{
		{"oO0OoO0OoO0Oo Redis is starting", protocol.LogKindServer, "LOG", ""},
		{"Redis version=", protocol.LogKindServer, "LOG", ""},
		{"<vectorset> Successfully loaded default module configuration", protocol.LogKindOther, "DEBUG", ""},
		{"Ready to accept connections", protocol.LogKindServer, "LOG", ""},
		{"Accepted 127.0.0.1:41344", protocol.LogKindConnection, "DEBUG", "127.0.0.1"},
		{"Client closed connection", protocol.LogKindConnection, "DEBUG", "10.0.0.5"},
		{"Background saving started", protocol.LogKindCheckpoint, "LOG", ""},
		{"DB saved on disk", protocol.LogKindCheckpoint, "LOG", ""},
		{"Background saving terminated with success", protocol.LogKindCheckpoint, "LOG", ""},
		{"Replica 10.0.0.9:6380 asks", protocol.LogKindOther, "LOG", "10.0.0.9"},
		{"Partial resynchronization not accepted", protocol.LogKindOther, "LOG", ""},
		{"processing " + Hidden + " for " + Hidden + " " + Hidden, protocol.LogKindOther, "WARNING", ""},
		{"Connection with replica (rdbchannel)", protocol.LogKindConnection, "LOG", "10.0.0.9"},
		{"Replica rowsafe-agent:6379", protocol.LogKindOther, "LOG", ""},
		{"WARNING Memory overcommit", protocol.LogKindOther, "WARNING", ""},
		{"Can't save in background", protocol.LogKindError, "ERROR", ""},
		{"Background saving error", protocol.LogKindError, "ERROR", ""},
		{"User requested shutdown", protocol.LogKindServer, "LOG", "127.0.0.1"},
		{"Valkey is now ready to exit", protocol.LogKindServer, "WARNING", ""},
		{"The server crashed", protocol.LogKindError, "FATAL", ""},
		{"oO0OoO0OoO0Oo Redis is starting", protocol.LogKindServer, "LOG", ""},
	}
	if len(es) != len(wants) {
		for _, e := range es {
			t.Logf("%s %s %s", e.Severity, e.Kind, e.Message)
		}
		t.Fatalf("got %d entries, want %d", len(es), len(wants))
	}
	for i, w := range wants {
		e := es[i]
		if !strings.Contains(e.Message, w.msg) || e.Kind != w.kind || e.Severity != w.sev || e.Client != w.client {
			t.Errorf("%d: got %s %s %q client %q, want %+v", i, e.Severity, e.Kind, e.Message, e.Client, w)
		}
	}
	all := ""
	for _, e := range es {
		all += e.Message + "|" + e.Detail + "|" + e.Statement + "\n"
	}
	for _, leak := range []string{"bob@example.com", "user:1234", "user:1", "9a86810780c65d079c3fdf8f461fd0da2267e14b", "1234"} {
		if strings.Contains(all, leak) {
			t.Errorf("%q leaked:\n%s", leak, all)
		}
	}
	if es[5].User != "app" || es[18].User != "" || es[13].Application != "rowsafe-agent" || es[2].Application != "vectorset" {
		t.Errorf("user/application: %+v %+v %+v %+v", es[5], es[18], es[13], es[2])
	}
	if !strings.Contains(es[19].Detail, "crashed by signal: 11") {
		t.Errorf("crash detail: %q", es[19].Detail)
	}
	if es[0].PID != 13 || es[0].Time.Format("2006-01-02 15:04:05.000") != "2026-10-04 00:48:28.595" || es[0].Time.Location() != time.Local {
		t.Errorf("time/pid: %+v", es[0])
	}
}

func TestRedisTimestampFormats(t *testing.T) {
	for _, line := range []string{
		"1:M 2026-10-04T00:48:28.595+00:00 * Ready to accept connections tcp", // Valkey log-timestamp-format iso8601
		"1:M 1790988508595 * Ready to accept connections tcp",                 // milliseconds
		"1:S 4 Oct 2026 00:48:28.595 * Ready to accept connections tcp",
	} {
		es := ParseEngineLog(FormatRedis, line)
		if len(es) != 1 || es[0].Time.IsZero() || es[0].Kind != protocol.LogKindServer {
			t.Errorf("%s: %+v", line, es)
		}
	}
}
