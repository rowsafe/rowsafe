//go:build redis_integration

package redis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/pglog"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisLogs: where the log is (stdout: the journal natively, the
// container's output in a sidecar), and natively a second server with a
// log file, read and parsed as the collector does: real lines from this
// version, a Lua script's line redacted, the permission problem.
func TestRedisLogs(t *testing.T) {
	e, env, db, _ := setup(t)
	ctx := context.Background()

	// The test servers write to their standard output (no logfile).
	src := e.LogSource(ctx, env, db)
	want := protocol.LogProblemJournal
	if inDocker() {
		want = protocol.LogProblemDockerStdout
	}
	if src.Status.Problem != want || src.Format != pglog.FormatRedis || src.Status.Settings["version"] == "" {
		t.Fatalf("stdout: %+v", src.Status)
	}
	if inDocker() {
		return // the second server runs next to the test, natively only
	}

	bin := cmpOr(os.Getenv("ROWSAFE_TEST_SERVER_BIN"), "redis-server")
	dir := t.TempDir()
	const port, pass = 6391, "rowsafe-test-log-password"
	logPath := filepath.Join(dir, "server.log")
	out, err := exec.Command(bin, "--port", "6391", "--bind", "127.0.0.1", "--requirepass", pass, "--dir", dir, "--logfile", "server.log",
		"--save", "", "--appendonly", "no", "--daemonize", "yes", "--pidfile", filepath.Join(dir, "server.pid")).CombinedOutput()
	if err != nil {
		t.Fatalf("starting a server with a log file: %v %s", err, out)
	}
	a, err := connectAddr(ctx, addrOf(Login{}, port), "", pass, "rowsafe-test")
	for i := 0; err != nil && i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		a, err = connectAddr(ctx, addrOf(Login{}, port), "", pass, "rowsafe-test")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = a.do(ctx, "SHUTDOWN", "NOSAVE")
		a.Close()
	})
	if _, err := CreateLogin(ctx, env, port, "default", pass); err != nil {
		t.Fatal(err)
	}
	ldb := protocol.DatabaseSpec{ID: "db_log", Name: "logs", Port: port, Engine: e.name}

	src = e.LogSource(ctx, env, ldb)
	if !src.Status.Readable || src.Path != logPath {
		t.Fatalf("log file: %+v (%s)", src.Status, src.Path)
	}

	// A save, a Lua script's line with customer data, a client error.
	rd(t, a, "SET", "user:1234", "bob")
	rd(t, a, "BGSAVE")
	deadline := time.Now().Add(20 * time.Second)
	for {
		b, _ := os.ReadFile(logPath)
		if strings.Contains(string(b), "Background saving terminated") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no save in the log:\n%s", b)
		}
		time.Sleep(200 * time.Millisecond)
	}
	rd(t, a, "EVAL", "redis.log(redis.LOG_WARNING, 'processing user:1234 for bob@example.com 42') return 1", 0)

	// Not readable by the agent's user: the permission problem.
	if err := os.Chmod(logPath, 0); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if src := e.LogSource(ctx, env, ldb); src.Status.Problem != protocol.LogProblemPermission {
			t.Errorf("permission: %+v", src.Status)
		}
	}
	_ = os.Chmod(logPath, 0o644)

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the server's log:\n%s", b)
	es := pglog.ParseEngineLog(pglog.FormatRedis, string(b))
	kinds := map[string]bool{}
	all := ""
	for _, x := range es {
		kinds[x.Kind+":"+firstWords(x.Message)] = true
		all += x.Message + "\n"
		if x.Time.IsZero() || time.Since(x.Time) > time.Hour || time.Until(x.Time) > time.Minute {
			t.Errorf("time: %+v", x)
		}
	}
	t.Logf("parsed:\n%s", all)
	for _, k := range []string{
		protocol.LogKindServer + ":Ready to accept",
		protocol.LogKindCheckpoint + ":Background saving started",
		protocol.LogKindCheckpoint + ":DB saved on",
		protocol.LogKindCheckpoint + ":Background saving terminated",
		protocol.LogKindOther + ":processing " + pglog.Hidden + " for",
	} {
		if !kinds[k] {
			t.Errorf("missing %q in %v", k, kinds)
		}
	}
	if strings.Contains(all, "bob@example.com") || strings.Contains(all, "user:1234") {
		t.Errorf("customer data in the parsed log:\n%s", all)
	}
}

func firstWords(s string) string {
	f := strings.Fields(s)
	return strings.Join(f[:min(3, len(f))], " ")
}
