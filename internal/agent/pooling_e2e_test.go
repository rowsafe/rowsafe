//go:build pooling_e2e

package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestRealPooling runs on a Debian server with systemd (scripts/test-pooling.sh):
// the real root helper installs PgBouncer from apt, writes its configuration and
// runs it under systemd; the agent's own code does everything else, as postgres.
func TestRealPooling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cfg := Config{StateDir: "/var/lib/rowsafe", Mode: ModeNative, PGUser: "postgres"}
	if err := poolerConfigFromEnv(&cfg); err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: cfg, log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	db := protocol.DatabaseSpec{ID: "db_shop", Name: "shop", Port: 5432, SocketDir: "/var/run/postgresql"}
	other := protocol.DatabaseSpec{ID: "db_other", Port: 5433, SocketDir: "/var/run/postgresql"}
	sql := func(spec protocol.DatabaseSpec, dbname, stmt string, args ...any) {
		t.Helper()
		conn, err := a.target(spec).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, stmt, args...); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	for _, s := range []protocol.DatabaseSpec{db, other} {
		sql(s, "postgres", `CREATE ROLE app LOGIN PASSWORD 'app-secret'`)
		sql(s, "postgres", `CREATE DATABASE shop OWNER app`)
	}
	// The other cluster stands in for a promoted standby: same role secrets.
	copySecret := func(role string) {
		conn, _ := a.target(db).Connect(ctx, "postgres")
		var secret string
		if err := conn.QueryRow(ctx, `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, role).Scan(&secret); err != nil {
			t.Fatal(err)
		}
		conn.Close(ctx)
		if role == poolerRole {
			if err := ensureLookupRole(ctx, a.connectAs(other), secret, []string{"postgres"}); err != nil {
				t.Fatal(err)
			}
			return
		}
		sql(other, "postgres", fmt.Sprintf(`ALTER ROLE %s PASSWORD '%s'`, role, secret))
	}
	copySecret("app")

	// Turn pooling on: the helper installs PgBouncer from apt.
	tl := &taskLog{}
	res, err := a.pooling(ctx, db, protocol.PoolingParams{Action: protocol.PoolingOn,
		Settings: protocol.PoolingSettings{Listen: protocol.PoolerListenLocal}}, "task_on", tl)
	t.Logf("pooling on:\n%s", tl)
	if err != nil {
		t.Fatalf("pooling on: %v", err)
	}
	if !res.On || !res.Installed || res.Settings.Port != 6432 {
		t.Fatalf("result %+v", res)
	}
	t.Logf("%s (warnings: %v)", res.Summary, res.Warnings)
	if out, err := exec.Command("pgbouncer", "--version").CombinedOutput(); err != nil {
		t.Fatalf("pgbouncer not installed: %v %s", err, out)
	}
	ini, err := os.ReadFile("/etc/pgbouncer/pgbouncer.ini")
	if err != nil || !strings.HasPrefix(string(ini), ";; Managed by Rowsafe\n") || !strings.Contains(string(ini), "listen_addr = 127.0.0.1\n") {
		t.Fatalf("config: %v\n%s", err, ini)
	}
	if err := os.WriteFile("/etc/pgbouncer/pgbouncer.ini", []byte("x"), 0o640); err == nil {
		t.Fatal("the agent user can write PgBouncer's configuration")
	}

	// An app logs in through PgBouncer with its own password; light load.
	app, err := appConnect(ctx, 6432, "shop")
	if err != nil {
		t.Fatalf("through PgBouncer: %v", err)
	}
	// PgBouncer replays the client's application_name, so the server's own
	// port tells the clusters apart.
	var port int
	if err := app.QueryRow(ctx, `SELECT inet_server_port()`).Scan(&port); err != nil || port != 5432 {
		t.Fatalf("connected to port %d: %v", port, err)
	}
	app.Close(ctx)
	c := collect.New(collect.Options{PGUser: "postgres", Databases: func() []protocol.DatabaseSpec { return []protocol.DatabaseSpec{db} },
		Poolers: a.poolerSources})
	c.Collect(ctx)
	runLoad(ctx, t, 6432, 20, 100)
	time.Sleep(2 * time.Second)
	rep := c.Collect(ctx)
	m := rep.Databases[0].Metrics
	if m[collect.PPoolerUp] != 1 || m[collect.PXactRate] <= 0 || rep.Databases[0].Pooler == nil {
		t.Fatalf("pooler metrics %v", m)
	}
	t.Logf("stats: %.0f transactions/s, pools %+v", m[collect.PXactRate], rep.Databases[0].Pooler.Pools)
	if st := a.poolerStatus(ctx); st == nil || !st.Managed || !st.Running || !st.Allowed {
		t.Fatalf("heartbeat status %+v", st)
	}

	// Retarget to the "new primary" under load: nobody gets an error.
	copySecret(poolerRole)
	var failed atomic.Int32
	loadCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := appConnect(ctx, 6432, "shop")
			if err != nil {
				failed.Add(1)
				return
			}
			defer conn.Close(ctx)
			for loadCtx.Err() == nil {
				if _, err := conn.Exec(ctx, `SELECT pg_sleep(0.005)`); err != nil {
					t.Logf("query failed: %v", err)
					failed.Add(1)
					return
				}
			}
		}()
	}
	time.Sleep(time.Second)
	tl = &taskLog{}
	rr, err := a.poolerRetarget(ctx, db, protocol.PoolerRetargetParams{Host: "127.0.0.1", Port: 5433}, "task_retarget", tl)
	time.Sleep(time.Second)
	stop()
	wg.Wait()
	t.Logf("retarget:\n%s", tl)
	if err != nil || !rr.Paused || failed.Load() != 0 {
		t.Fatalf("retarget %+v %v, %d failed queries", rr, err, failed.Load())
	}
	app, _ = appConnect(ctx, 6432, "shop")
	port = 0
	if err := app.QueryRow(ctx, `SELECT inet_server_port()`).Scan(&port); err != nil || port != 5433 {
		t.Fatalf("after the switch: port %d: %v", port, err)
	}
	app.Close(ctx)

	// Change settings: a reload, not a restart.
	pid := func() string {
		b, _ := os.ReadFile("/var/run/postgresql/pgbouncer.pid")
		return strings.TrimSpace(string(b))
	}
	before := pid()
	res, err = a.pooling(ctx, db, protocol.PoolingParams{Action: protocol.PoolingOn, Settings: protocol.PoolingSettings{
		Mode: protocol.PoolModeSession, PoolSize: 15, Listen: protocol.PoolerListenLocal}}, "task_change", &taskLog{})
	if err != nil || res.Settings.Mode != protocol.PoolModeSession {
		t.Fatalf("change: %+v %v", res, err)
	}
	if after := pid(); before == "" || after != before {
		t.Fatalf("changing the mode restarted PgBouncer (%s -> %s)", before, after)
	}
	// Session mode: a session keeps its settings across transactions.
	conn, err := pgx.Connect(ctx, "postgres://app:app-secret@127.0.0.1:6432/shop?sslmode=disable&default_query_exec_mode=simple_protocol")
	if err != nil {
		t.Fatal(err)
	}
	var tz string
	conn.Exec(ctx, `SET TimeZone = 'Asia/Tokyo'`)
	conn.QueryRow(ctx, `SELECT current_setting('TimeZone')`).Scan(&tz)
	conn.Close(ctx)
	if tz != "Asia/Tokyo" {
		t.Fatalf("session mode lost a SET: %q", tz)
	}

	// Off: PgBouncer removed, role and function gone from the cluster it was on.
	tl = &taskLog{}
	res, err = a.pooling(ctx, db, protocol.PoolingParams{Action: protocol.PoolingOff}, "task_off", tl)
	t.Logf("off:\n%s", tl)
	if err != nil || !res.Removed {
		t.Fatalf("off: %+v %v", res, err)
	}
	if _, err := exec.LookPath("pgbouncer"); err == nil {
		t.Fatal("pgbouncer still installed")
	}
	if _, err := appConnect(ctx, 6432, "shop"); err == nil {
		t.Fatal("PgBouncer still answers")
	}
	cn, _ := a.target(db).Connect(ctx, "postgres")
	var n int
	cn.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname = 'rowsafe_pgbouncer'`).Scan(&n)
	cn.Close(ctx)
	if n != 0 {
		t.Fatal("rowsafe_pgbouncer left behind")
	}
}
