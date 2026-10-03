//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/chproxyroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestClickHousePooling turns pooling on with chproxy (the real release,
// downloaded and checked against its pinned SHA-256), sends an app's
// queries through it with the app's own login, points it elsewhere and
// turns it off. Root's helper runs in the test, with systemctl played by
// the test (no systemd in the container). Needs network access to GitHub.
func TestClickHousePooling(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 || os.Getenv("ROWSAFE_TEST_CLICKHOUSE_POOLING") == "" {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT or ROWSAFE_TEST_CLICKHOUSE_POOLING not set")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env, _ := testEnv(t)
	e := &Engine{}
	adminUser, adminPass := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD")
	admin := newClient(serverURL(port), Login{User: cmpOr(adminUser, "default"), Password: adminPass})
	_ = admin.exec(ctx, "DROP USER IF EXISTS rowsafe", nil)
	if err := CreateLogin(ctx, env, port, adminUser, adminPass); err != nil {
		t.Skip("no SQL-made login here (users.d mode):", err)
	}
	must(t, admin, "DROP USER IF EXISTS pool_app")
	must(t, admin, "CREATE USER pool_app IDENTIFIED WITH sha256_password BY 'app-secret-1'")
	must(t, admin, "GRANT SELECT ON system.* TO pool_app")

	// Root's side, in the test.
	dir := t.TempDir()
	reqDir, resDir := filepath.Join(dir, "pooler"), filepath.Join(dir, "result")
	_ = os.MkdirAll(reqDir, 0o700)
	_ = os.MkdirAll(resDir, 0o755)
	allow := filepath.Join(dir, "pooler-allowed")
	_ = os.WriteFile(allow, []byte(fmt.Sprintf("%d\n", port)), 0o644)
	env.Config.Pooler.Dir, env.Config.Pooler.AllowFile = reqDir, allow
	chproxyResultDir = resDir
	var mu sync.Mutex
	var proc *exec.Cmd
	a := &chproxyroot.Applier{StateDir: filepath.Join(dir, "state"), Binary: filepath.Join(dir, "bin", "chproxy"),
		ConfigFile: filepath.Join(dir, "chproxy.yml"), UnitFile: filepath.Join(dir, "rowsafe-chproxy.service"),
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			if name != "systemctl" {
				return exec.CommandContext(ctx, name, args...).CombinedOutput()
			}
			mu.Lock()
			defer mu.Unlock()
			stop := func() {
				if proc != nil {
					_ = proc.Process.Kill()
					_ = proc.Wait()
					proc = nil
				}
			}
			switch args[0] {
			case "restart":
				stop()
				proc = exec.Command(filepath.Join(dir, "bin", "chproxy"), "-config", filepath.Join(dir, "chproxy.yml"))
				proc.Stdout, proc.Stderr = os.Stderr, os.Stderr
				return nil, proc.Start()
			case "reload":
				if proc != nil {
					return nil, proc.Process.Signal(syscall.SIGHUP)
				}
			case "disable":
				stop()
			}
			return nil, nil
		}}
	defer func() {
		mu.Lock()
		if proc != nil {
			_ = proc.Process.Kill()
		}
		mu.Unlock()
	}()
	go func() {
		for ctx.Err() == nil {
			time.Sleep(200 * time.Millisecond)
			data, err := os.ReadFile(filepath.Join(reqDir, chproxyroot.RequestName))
			if err != nil {
				continue
			}
			_ = os.Remove(filepath.Join(reqDir, chproxyroot.RequestName))
			var r chproxyroot.Request
			_ = json.Unmarshal(data, &r)
			ports, public, _ := chproxyroot.Allowed(allow)
			res := a.Apply(ctx, r, ports, public)
			out, _ := json.Marshal(res)
			_ = os.WriteFile(filepath.Join(resDir, chproxyroot.ResultName), out, 0o644)
		}
	}()

	db := protocol.DatabaseSpec{ID: "db_pool", Name: "pool", Stanza: "pool-ch", Port: port, Engine: protocol.EngineClickHouse}
	on, err := run[protocol.PoolingResult](t, e, env, db, protocol.TaskPooling, protocol.PoolingParams{Action: protocol.PoolingOn,
		Settings: protocol.PoolingSettings{PoolSize: 2, MaxClientConn: 20, Port: 19090}})
	if err != nil {
		t.Fatal("on:", err)
	}
	t.Log(on.Summary, on.Warnings)
	if !on.On || on.Version != chproxyroot.Version || !on.Installed {
		t.Fatalf("on: %+v", on)
	}
	// An app's queries through chproxy, with its own login; a wrong
	// password is refused by ClickHouse.
	q := func(user, pw, sql string) (string, int) {
		req, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:19090/", strings.NewReader(sql))
		req.SetBasicAuth(user, pw)
		var resp *http.Response
		for i := 0; i < 50; i++ { // chproxy starts
			if resp, err = http.DefaultClient.Do(req); err == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
			req, _ = http.NewRequest(http.MethodPost, "http://127.0.0.1:19090/", strings.NewReader(sql))
			req.SetBasicAuth(user, pw)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return strings.TrimSpace(string(b)), resp.StatusCode
	}
	if got, code := q("pool_app", "app-secret-1", "SELECT currentUser()"); code != 200 || got != "pool_app" {
		t.Fatalf("through chproxy: %d %q", code, got)
	}
	if _, code := q("pool_app", "wrong", "SELECT 1"); code == 200 {
		t.Fatal("a wrong password got through")
	}
	// Two queries at once per user: four 1-second queries take about 2.
	start := time.Now()
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, code := q("pool_app", "app-secret-1", "SELECT sleep(1)"); code != 200 {
				t.Errorf("queued query: %d", code)
			}
		}()
	}
	wg.Wait()
	if d := time.Since(start); d < 1900*time.Millisecond {
		t.Errorf("4 queries took %s: not limited to 2 at once", d)
	}
	st := e.PoolerStatus(ctx, env, db)
	if st == nil || !st.Running || st.Settings.PoolSize != 2 {
		t.Fatalf("status: %+v", st)
	}
	m := &dbMonitor{}
	_ = m.poolerStats(ctx, env, db, time.Now())
	ps := m.poolerStats(ctx, env, db, time.Now().Add(time.Minute))
	if ps == nil || len(ps.Pools) != 1 || ps.Pools[0].PoolSize != 2 {
		t.Fatalf("stats: %+v", ps)
	}
	// Retarget (same port: a reload), then off.
	rt, err := run[protocol.PoolerRetargetResult](t, e, env, db, protocol.TaskPoolerRetarget, protocol.PoolerRetargetParams{Host: "127.0.0.1", Port: port})
	if err != nil {
		t.Fatal("retarget:", err)
	}
	t.Log(rt.Summary)
	if _, code := q("pool_app", "app-secret-1", "SELECT 1"); code != 200 {
		t.Fatalf("after retarget: %d", code)
	}
	off, err := run[protocol.PoolingResult](t, e, env, db, protocol.TaskPooling, protocol.PoolingParams{Action: protocol.PoolingOff})
	if err != nil || !off.Removed {
		t.Fatalf("off: %v %+v", err, off)
	}
	if e.PoolerStatus(ctx, env, db) != nil {
		t.Error("still managed after off")
	}
	must(t, admin, "DROP USER pool_app")
}
