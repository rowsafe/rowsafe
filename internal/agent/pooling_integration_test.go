package agent

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/pgbouncer"
	"github.com/rowsafe/rowsafe/protocol"
)

// A real PgBouncer in front of real PostgreSQL clusters (password logins
// over TCP with SCRAM), with a stand-in for the root helper that writes the
// same configuration: turn pooling on, log in through it with an app's own
// password, read its stats, switch it to another server under load with no
// failed query, change settings, turn it off.
//
//	ROWSAFE_TEST_PGBOUNCER=1 go test ./internal/agent -run TestPoolingReal
//
// Needs initdb, pg_ctl and pgbouncer on the PATH.

type tempCluster struct {
	dir, sock string
	port      int
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startCluster(t *testing.T, base, name string) tempCluster {
	t.Helper()
	c := tempCluster{dir: filepath.Join(base, name), sock: base, port: freePort(t)}
	u, _ := user.Current()
	out, err := exec.Command("initdb", "-D", c.dir, "-U", u.Username, "--auth-local=trust", "--auth-host=scram-sha-256", "-E", "UTF8", "--no-locale").CombinedOutput()
	if err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	opts := fmt.Sprintf("-p %d -k %s -c listen_addresses=127.0.0.1 -c max_connections=60", c.port, c.sock)
	start := exec.Command("pg_ctl", "-D", c.dir, "-o", opts, "-l", filepath.Join(base, name+".log"), "-w", "start")
	start.Env = append(os.Environ(), "LC_ALL=en_US.UTF-8")
	if out, err := start.CombinedOutput(); err != nil {
		t.Fatalf("pg_ctl start: %v\n%s", err, out)
	}
	t.Cleanup(func() { exec.Command("pg_ctl", "-D", c.dir, "-m", "immediate", "stop").Run() })
	return c
}

// fakePgbHelper stands in for rowsafe-pg-restart in PgBouncer mode: it
// writes the configuration the real one writes (scripts/rowsafe-pg-restart)
// and runs PgBouncer.
type fakePgbHelper struct {
	t                        *testing.T
	dir, resultDir, confDir  string
	sockDir                  string
	mu                       sync.Mutex
	cmd                      *exec.Cmd
	requests                 atomic.Int32
	lastAction, lastListen   string
	lastTarget               string
	stop                     chan struct{}
	allowedPort              int
	installedNow, removedNow bool
}

func (h *fakePgbHelper) run() {
	for {
		select {
		case <-h.stop:
			return
		case <-time.After(20 * time.Millisecond):
		}
		data, err := os.ReadFile(filepath.Join(h.dir, "request"))
		if err != nil {
			continue
		}
		os.Remove(filepath.Join(h.dir, "request"))
		h.requests.Add(1)
		f := strings.Fields(strings.TrimSpace(string(data)))
		kv := map[string]string{}
		for _, p := range f[2:] {
			k, v, _ := strings.Cut(p, "=")
			kv[k] = v
		}
		action := strings.TrimPrefix(f[1], "pooler-")
		res := map[string]string{"ok": "1", "version": pgbouncerVersion(h.t)}
		if err := h.handle(action, kv); err != nil {
			res["ok"], res["error"] = "0", err.Error()
		}
		h.lastAction = action
		var sb strings.Builder
		sb.WriteString("id=" + f[0] + "\n")
		for k, v := range res {
			sb.WriteString(k + "=" + v + "\n")
		}
		os.WriteFile(filepath.Join(h.resultDir, "result"), []byte(sb.String()), 0o644)
	}
}

func pgbouncerVersion(t *testing.T) string {
	out, err := exec.Command("pgbouncer", "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	return pgbouncer.ParseVersion(strings.SplitN(string(out), "\n", 2)[0])
}

func (h *fakePgbHelper) handle(action string, kv map[string]string) error {
	ini := filepath.Join(h.confDir, "pgbouncer.ini")
	userlist := filepath.Join(h.confDir, "userlist.txt")
	switch action {
	case "install":
		return nil
	case "configure":
		if kv["dbport"] != strconv.Itoa(h.allowedPort) {
			return fmt.Errorf("port %s is not allowed", kv["dbport"])
		}
		if pw := kv["password"]; pw != "" {
			os.WriteFile(userlist, []byte(";; Managed by Rowsafe\n\"rowsafe_pgbouncer\" \""+pw+"\"\n"), 0o640)
		}
		var b strings.Builder
		b.WriteString(";; Managed by Rowsafe\n[databases]\n")
		for _, d := range strings.Split(kv["dbs"], ",") {
			if d != "" {
				fmt.Fprintf(&b, "%s = host=%s port=%s auth_user=rowsafe_pgbouncer\n", d, kv["target_host"], kv["target_port"])
			}
		}
		fmt.Fprintf(&b, "* = host=%s port=%s auth_user=rowsafe_pgbouncer\n\n[pgbouncer]\n", kv["target_host"], kv["target_port"])
		fmt.Fprintf(&b, "listen_addr = %s\nlisten_port = %s\nunix_socket_dir = %s\n", kv["listen"], kv["port"], h.sockDir)
		fmt.Fprintf(&b, "auth_type = scram-sha-256\nauth_file = %s\nauth_user = rowsafe_pgbouncer\n", userlist)
		b.WriteString("auth_query = SELECT uname, phash FROM rowsafe_pgbouncer.user_lookup($1)\nadmin_users = rowsafe_pgbouncer\n")
		if kv["auth_dbname"] != "" {
			fmt.Fprintf(&b, "auth_dbname = %s\n", kv["auth_dbname"])
		}
		fmt.Fprintf(&b, "pool_mode = %s\ndefault_pool_size = %s\nreserve_pool_size = %s\nreserve_pool_timeout = 3\nmax_db_connections = %s\nmax_client_conn = %s\n",
			kv["mode"], kv["pool_size"], kv["reserve_pool"], kv["max_db_conn"], kv["max_client_conn"])
		if kv["prepared"] != "0" {
			fmt.Fprintf(&b, "max_prepared_statements = %s\n", kv["prepared"])
		}
		b.WriteString("server_reset_query = DISCARD ALL\nignore_startup_parameters = extra_float_digits\nserver_lifetime = 3600\nserver_idle_timeout = 600\n")
		os.WriteFile(ini, []byte(b.String()), 0o640)
		h.lastListen, h.lastTarget = kv["listen"], kv["target_host"]+":"+kv["target_port"]
		h.mu.Lock()
		defer h.mu.Unlock()
		if kv["restart"] == "1" || h.cmd == nil {
			h.stopLocked()
			h.cmd = exec.Command("pgbouncer", ini)
			if logf, err := os.OpenFile(filepath.Join(h.confDir, "pgbouncer.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				h.cmd.Stdout, h.cmd.Stderr = logf, logf
			}
			if err := h.cmd.Start(); err != nil {
				return err
			}
		}
		return nil
	case "reload":
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.cmd != nil {
			return h.cmd.Process.Signal(syscall.SIGHUP)
		}
		return fmt.Errorf("not running")
	case "off":
		h.mu.Lock()
		h.stopLocked()
		h.mu.Unlock()
		os.Remove(ini)
		os.Remove(userlist)
		return nil
	}
	return fmt.Errorf("unknown action %s", action)
}

func (h *fakePgbHelper) stopLocked() {
	if h.cmd != nil {
		h.cmd.Process.Signal(syscall.SIGINT)
		h.cmd.Wait()
		h.cmd = nil
	}
}

func appConnect(ctx context.Context, port int, db string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://app:app-secret@127.0.0.1:%d/%s?sslmode=disable", port, db))
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.RuntimeParams["client_encoding"] = "UTF8" // SQL_ASCII clusters
	return pgx.ConnectConfig(ctx, cfg)
}

func TestPoolingReal(t *testing.T) {
	if os.Getenv("ROWSAFE_TEST_PGBOUNCER") != "1" {
		t.Skip("set ROWSAFE_TEST_PGBOUNCER=1 (needs initdb, pg_ctl and pgbouncer)")
	}
	for _, bin := range []string{"initdb", "pg_ctl", "pgbouncer"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not found", bin)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Unix socket paths must stay short.
	base, err := os.MkdirTemp("/tmp", "rsp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if !t.Failed() {
			os.RemoveAll(base)
		}
	})
	primary := startCluster(t, base, "a")
	other := startCluster(t, base, "b")
	u, _ := user.Current()

	for _, c := range []tempCluster{primary, other} {
		conn, err := pginspectConnect(ctx, c, u.Username)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range []string{`SET password_encryption = 'scram-sha-256'`, `CREATE ROLE app LOGIN PASSWORD 'app-secret'`,
			`CREATE DATABASE shop OWNER app`, `CREATE ROLE old_app LOGIN PASSWORD 'md56dc6778f8043b52609eecb6171b32009'`} {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		conn.Close(ctx)
	}
	state := filepath.Join(base, "state")
	h := &fakePgbHelper{t: t, dir: filepath.Join(state, "pooler"), resultDir: filepath.Join(base, "run"), confDir: filepath.Join(base, "etc"),
		sockDir: base, stop: make(chan struct{}), allowedPort: primary.port}
	for _, d := range []string{h.dir, h.resultDir, h.confDir} {
		os.MkdirAll(d, 0o700)
	}
	go h.run()
	t.Cleanup(func() {
		close(h.stop)
		h.mu.Lock()
		h.stopLocked()
		h.mu.Unlock()
	})
	allow := filepath.Join(base, "pooler-allowed")
	os.WriteFile(allow, []byte(fmt.Sprintf("%d\n%d\n", primary.port, other.port)), 0o644)
	a := &Agent{cfg: Config{StateDir: state, Mode: ModeNative, PGUser: u.Username, Pooler: PoolerConfig{
		AllowFile: allow, Dir: h.dir, ResultDir: h.resultDir, SocketDir: base, Userlist: filepath.Join(h.confDir, "userlist.txt")}}}
	db := protocol.DatabaseSpec{ID: "db_1", Name: "shop", Port: primary.port, SocketDir: primary.sock}
	poolerPort := freePort(t)

	// Turn pooling on.
	tl := &taskLog{}
	res, err := a.pooling(ctx, db, protocol.PoolingParams{Action: protocol.PoolingOn,
		Settings: protocol.PoolingSettings{Listen: protocol.PoolerListenLocal, Port: poolerPort}}, "task_on", tl)
	if err != nil {
		t.Fatalf("pooling on: %v\n%s", err, tl)
	}
	if !res.On || res.Settings.Mode != protocol.PoolModeTransaction || res.Target != net.JoinHostPort("127.0.0.1", strconv.Itoa(primary.port)) ||
		!strings.Contains(strings.Join(res.Warnings, " "), "old_app") {
		t.Fatalf("result %+v", res)
	}
	t.Logf("on: %s", res.Summary)
	// The password is only in the userlist; PostgreSQL has a SCRAM verifier.
	pw, _ := readUserlistPassword(a.cfg.Pooler.Userlist)
	conn, _ := pginspectConnect(ctx, primary, u.Username)
	var stored string
	conn.QueryRow(ctx, `SELECT rolpassword FROM pg_authid WHERE rolname = 'rowsafe_pgbouncer'`).Scan(&stored)
	var superHash *string
	conn.QueryRow(ctx, `SELECT phash FROM rowsafe_pgbouncer.user_lookup($1)`, u.Username).Scan(&superHash)
	conn.Close(ctx)
	if !strings.HasPrefix(stored, "SCRAM-SHA-256$") || strings.Contains(stored, pw) {
		t.Fatalf("stored password %q", stored)
	}
	if superHash != nil {
		t.Fatal("the lookup function returned a superuser's password")
	}

	// An app logs in through PgBouncer with its own password.
	app, err := appConnect(ctx, poolerPort, "shop")
	if err != nil {
		t.Fatalf("app through PgBouncer: %v", err)
	}
	// PgBouncer replays the client's application_name: the server's port
	// tells the clusters apart.
	var port int
	if err := app.QueryRow(ctx, `SELECT inet_server_port()`).Scan(&port); err != nil || port != primary.port {
		t.Fatalf("app on port %d %v", port, err)
	}
	app.Close(ctx)
	if _, err := appConnectWrong(ctx, poolerPort); err == nil {
		t.Fatal("a wrong password logged in")
	}

	// Load, then stats.
	c := collect.New(collect.Options{PGUser: u.Username, Databases: func() []protocol.DatabaseSpec { return []protocol.DatabaseSpec{db} },
		Poolers: a.poolerSources})
	c.Collect(ctx)
	runLoad(ctx, t, poolerPort, 8, 50)
	time.Sleep(1100 * time.Millisecond)
	rep := c.Collect(ctx)
	m := rep.Databases[0].Metrics
	if m[collect.PPoolerUp] != 1 || m[collect.PXactRate] <= 0 || rep.Databases[0].Pooler == nil || len(rep.Databases[0].Pooler.Pools) == 0 {
		t.Fatalf("pooler metrics %v, snapshot %+v", m, rep.Databases[0].Pooler)
	}
	t.Logf("pooler metrics: xact/s %.1f, clients %v, pool used %.0f%%", m[collect.PXactRate], m[collect.PClientsActive], m[collect.PPoolUsedPct])
	if st := a.poolerStatus(ctx); st == nil || !st.Managed || !st.Running || st.DatabaseID != "db_1" {
		t.Fatalf("status %+v", st)
	}
	// A PgBouncer Rowsafe doesn't manage (Docker): monitored through
	// ROWSAFE_POOLER_STATS_URL.
	ext := &Agent{cfg: Config{StateDir: t.TempDir(), Mode: ModeDockerSidecar, PGUser: u.Username, Pooler: PoolerConfig{
		StatsURL: fmt.Sprintf("postgres://rowsafe_pgbouncer:%s@127.0.0.1:%d/pgbouncer?sslmode=disable", pw, poolerPort)}},
		monitored: []protocol.DatabaseSpec{db}}
	if st := ext.poolerStatus(ctx); st == nil || !st.External || !st.Running || st.Managed || st.Version == "" {
		t.Fatalf("external status %+v", st)
	}
	extRep := collect.New(collect.Options{PGUser: u.Username, Databases: ext.monitoredDatabases, Poolers: ext.poolerSources}).Collect(ctx)
	if extRep.Databases[0].Metrics[collect.PPoolerUp] != 1 || extRep.Databases[0].Pooler == nil {
		t.Fatalf("external pooler metrics %v", extRep.Databases[0].Metrics)
	}
	bad := &Agent{cfg: Config{Mode: ModeDockerSidecar, Pooler: PoolerConfig{StatsURL: fmt.Sprintf("postgres://rowsafe_pgbouncer:wrong@127.0.0.1:%d/pgbouncer?sslmode=disable", poolerPort)}}}
	if st := bad.poolerStatus(ctx); st.Running || st.Error == "" || strings.Contains(st.Error, "wrong") {
		t.Fatalf("a wrong stats password: %+v", st)
	}

	// Switch to the other cluster (as if it were the promoted standby: the
	// role and function replicated, with the same password) under load.
	var appSecret string
	conn, _ = pginspectConnect(ctx, primary, u.Username)
	conn.QueryRow(ctx, `SELECT rolpassword FROM pg_authid WHERE rolname = 'app'`).Scan(&appSecret)
	conn.Close(ctx)
	conn, _ = pginspectConnect(ctx, other, u.Username)
	if _, err := conn.Exec(ctx, `ALTER ROLE app PASSWORD '`+appSecret+`'`); err != nil {
		t.Fatal(err)
	}
	if err := ensureLookupRole(ctx, func(ctx context.Context, name string) (*pgx.Conn, error) {
		return pginspectConnectDB(ctx, other, u.Username, name)
	}, stored, []string{"postgres"}); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	var failed atomic.Int32
	loadCtx, stopLoad := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			app, err := appConnect(ctx, poolerPort, "shop")
			if err != nil {
				failed.Add(1)
				return
			}
			defer app.Close(ctx)
			for loadCtx.Err() == nil {
				if _, err := app.Exec(ctx, `SELECT pg_sleep(0.01)`); err != nil {
					failed.Add(1)
					t.Logf("query failed: %v", err)
					return
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	tl = &taskLog{}
	rr, err := a.poolerRetarget(ctx, db, protocol.PoolerRetargetParams{Host: "127.0.0.1", Port: other.port}, "task_retarget", tl)
	time.Sleep(300 * time.Millisecond)
	stopLoad()
	wg.Wait()
	if err != nil {
		t.Fatalf("retarget: %v\n%s", err, tl)
	}
	if !rr.Paused || failed.Load() != 0 {
		t.Fatalf("retarget %+v, %d failed queries\n%s", rr, failed.Load(), tl)
	}
	t.Logf("retarget: %s", rr.Summary)
	app, err = appConnect(ctx, poolerPort, "shop")
	if err != nil {
		t.Fatal(err)
	}
	app.QueryRow(ctx, `SELECT inet_server_port()`).Scan(&port)
	app.Close(ctx)
	if port != other.port {
		t.Fatalf("after the switch, connections go to port %d", port)
	}

	// Change settings: session mode, bigger pool (a reload, no restart).
	before := h.cmd.Process.Pid
	res, err = a.pooling(ctx, db, protocol.PoolingParams{Action: protocol.PoolingOn,
		Settings: protocol.PoolingSettings{Mode: protocol.PoolModeSession, PoolSize: 20, Listen: protocol.PoolerListenLocal, Port: poolerPort}}, "task_change", &taskLog{})
	if err != nil || res.Settings.Mode != protocol.PoolModeSession || h.cmd.Process.Pid != before {
		t.Fatalf("change: %+v %v (pid %d -> %d)", res, err, before, h.cmd.Process.Pid)
	}
	if h.lastTarget != net.JoinHostPort("127.0.0.1", strconv.Itoa(other.port)) {
		t.Fatalf("changing settings lost the target: %s", h.lastTarget)
	}

	// Turn it off: the role and function are gone.
	res, err = a.pooling(ctx, db, protocol.PoolingParams{Action: protocol.PoolingOff}, "task_off", &taskLog{})
	if err != nil || res.On {
		t.Fatalf("off: %+v %v", res, err)
	}
	conn, _ = pginspectConnect(ctx, primary, u.Username)
	var n int
	conn.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname = 'rowsafe_pgbouncer'`).Scan(&n)
	conn.Close(ctx)
	if n != 0 {
		t.Fatal("the role is still there")
	}
	if st, _ := a.loadPoolerState(); st != nil {
		t.Fatal("state left")
	}
}

func pginspectConnect(ctx context.Context, c tempCluster, user string) (*pgx.Conn, error) {
	return pginspectConnectDB(ctx, c, user, "postgres")
}

func pginspectConnectDB(ctx context.Context, c tempCluster, user, db string) (*pgx.Conn, error) {
	return (&Agent{cfg: Config{PGUser: user}}).target(protocol.DatabaseSpec{SocketDir: c.sock, Port: c.port}).Connect(ctx, db)
}

func appConnectWrong(ctx context.Context, port int) (*pgx.Conn, error) {
	cfg, _ := pgx.ParseConfig(fmt.Sprintf("postgres://app:wrong@127.0.0.1:%d/shop?sslmode=disable", port))
	return pgx.ConnectConfig(ctx, cfg)
}

// runLoad runs clients x queries short transactions through PgBouncer.
func runLoad(ctx context.Context, t *testing.T, port, clients, queries int) {
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			app, err := appConnect(ctx, port, "shop")
			if err != nil {
				t.Error(err)
				return
			}
			defer app.Close(ctx)
			for j := 0; j < queries; j++ {
				if _, err := app.Exec(ctx, `SELECT 1`); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
