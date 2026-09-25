package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// A real move-in between two private PostgreSQL clusters this test starts:
// a "managed" source (wal_level = logical, password auth over TCP) and the
// target the agent looks after (Unix socket). It runs the agent's own code
// for every step: key, check, fix, live sync with writes during the copy,
// switchover, credentials, rollback, finish, a one-time copy and a cancel.
//
// It needs initdb: set ROWSAFE_TEST_PG_BIN to a PostgreSQL bin directory
// (default: `pg_config --bindir`); skipped without one.

type testCluster struct {
	bin, data, sock string
	port            int
}

func pgBinDir(t *testing.T) string {
	if d := os.Getenv("ROWSAFE_TEST_PG_BIN"); d != "" {
		return d
	}
	out, err := exec.Command("pg_config", "--bindir").Output()
	if err != nil {
		t.Skip("no PostgreSQL binaries (set ROWSAFE_TEST_PG_BIN)")
	}
	return strings.TrimSpace(string(out))
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startCluster(t *testing.T, bin string, conf string, initArgs ...string) *testCluster {
	t.Helper()
	sock, err := os.MkdirTemp("/tmp", "rsm")
	if err != nil {
		t.Fatal(err)
	}
	c := &testCluster{bin: bin, data: filepath.Join(t.TempDir(), "data"), sock: sock, port: freePort(t)}
	args := append([]string{"-D", c.data, "-U", "postgres", "--no-sync", "-E", "UTF8", "--locale=C"}, initArgs...)
	if out, err := exec.Command(filepath.Join(bin, "initdb"), args...).CombinedOutput(); err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	conf = fmt.Sprintf("port = %d\nunix_socket_directories = '%s'\nlisten_addresses = '127.0.0.1'\nfsync = off\n", c.port, sock) + conf
	f, _ := os.OpenFile(filepath.Join(c.data, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(conf)
	f.Close()
	start := exec.Command(filepath.Join(bin, "pg_ctl"), "-D", c.data, "-l", filepath.Join(c.data, "log"), "-w", "start")
	start.Env = append(os.Environ(), "LC_ALL=C") // macOS: the postmaster refuses an unset locale
	if out, err := start.CombinedOutput(); err != nil {
		t.Fatalf("pg_ctl start: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		exec.Command(filepath.Join(bin, "pg_ctl"), "-D", c.data, "-m", "immediate", "stop").Run()
		os.RemoveAll(sock)
	})
	return c
}

func (c *testCluster) exec(t *testing.T, db, sql string, args ...any) {
	t.Helper()
	conn := c.conn(t, db)
	defer conn.Close(context.Background())
	if _, err := conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (c *testCluster) conn(t *testing.T, db string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), fmt.Sprintf("host=%s port=%d user=postgres dbname=%s", c.sock, c.port, db))
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func (c *testCluster) int(t *testing.T, db, sql string) int64 {
	t.Helper()
	conn := c.conn(t, db)
	defer conn.Close(context.Background())
	var n int64
	if err := conn.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func TestMigratePostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two PostgreSQL clusters")
	}
	bin := pgBinDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	src := startCluster(t, bin, "wal_level = logical\nmax_replication_slots = 10\nmax_wal_senders = 10\n",
		"--auth-local=trust", "--auth-host=scram-sha-256")
	tgt := startCluster(t, bin, "max_logical_replication_workers = 4\n", "--auth-local=trust", "--auth-host=scram-sha-256")

	// The source: a database owned by a non-superuser with REPLICATION, as
	// providers give out; a password with characters that need escaping.
	const pw = `p@ss:w'rd\x`
	src.exec(t, "postgres", `CREATE ROLE shopowner LOGIN REPLICATION PASSWORD 'p@ss:w''rd\x'`)
	src.exec(t, "postgres", `CREATE DATABASE shop OWNER shopowner`)
	owner, err := pgx.Connect(ctx, fmt.Sprintf("host=127.0.0.1 port=%d user=shopowner password='p@ss:w\\'rd\\\\x' dbname=shop", src.port))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE customers (id bigserial PRIMARY KEY, name text NOT NULL)`,
		`CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id bigint REFERENCES customers, total numeric NOT NULL)`,
		`CREATE TABLE events (at timestamptz NOT NULL DEFAULT now(), what text)`, // no primary key
		`CREATE TYPE mood AS ENUM ('happy', 'sad')`,
		`CREATE TABLE notes (id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY, m mood)`,
		`CREATE MATERIALIZED VIEW order_totals AS SELECT customer_id, sum(total) AS total FROM orders GROUP BY 1`,
		`CREATE FUNCTION double(x int) RETURNS int LANGUAGE sql AS 'SELECT x * 2'`,
		`INSERT INTO customers (name) SELECT 'c' || g FROM generate_series(1, 2000) g`,
		`INSERT INTO orders (customer_id, total) SELECT 1 + g % 2000, g FROM generate_series(1, 20000) g`,
		`INSERT INTO events (what) SELECT 'e' || g FROM generate_series(1, 500) g`,
		`INSERT INTO notes (m) VALUES ('happy'), ('sad')`,
	} {
		if _, err := owner.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	owner.Close(ctx)

	stateDir := t.TempDir()
	cfg := Config{StateDir: stateDir, PGUser: "postgres", PGBinDir: bin}
	a := &Agent{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	db := protocol.DatabaseSpec{ID: "db_t", Name: "target", Port: tgt.port, SocketDir: tgt.sock}
	sourceURL := fmt.Sprintf("postgres://shopowner:%s@127.0.0.1:%d/shop?sslmode=disable", strings.NewReplacer("@", "%40", ":", "%3A", "'", "%27", `\`, "%5C").Replace(pw), src.port)

	run := func(typ string, p protocol.MigrateParams, out any) error {
		t.Helper()
		params, _ := json.Marshal(p)
		tl := &taskLog{}
		res, err := a.runMigrate(ctx, &protocol.Task{Type: typ, Params: params}, db, tl)
		t.Logf("---- %s %s%s\n%s", typ, p.Action, p.Method, tl.String())
		if strings.Contains(tl.String(), "w'rd") {
			t.Fatalf("the source password reached the task log")
		}
		if res != nil && out != nil {
			b, _ := json.Marshal(res)
			if strings.Contains(string(b), "w'rd") || strings.Contains(string(b), `w'rd`) {
				t.Fatalf("the source password reached the task result: %s", b)
			}
			json.Unmarshal(b, out)
		}
		return err
	}
	seal := func(id, s string) *e2e.Box {
		t.Helper()
		var k protocol.MigrateKeyResult
		if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateKey}, &k); err != nil {
			t.Fatal(err)
		}
		pub, err := e2e.ParsePublicKey(k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(id), []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return &box
	}
	browser, _ := e2e.GenerateKey()
	browserKey := e2e.PublicKeyString(browser.PublicKey())
	openCreds := func(id string, box *e2e.Box) string {
		t.Helper()
		if box == nil {
			t.Fatal("no credentials")
		}
		plain, err := e2e.Open(browser, protocol.MigrateInfo, protocol.MigrateCredentialsAAD(id), *box)
		if err != nil {
			t.Fatal(err)
		}
		return string(plain)
	}
	check := func(res protocol.MigrateCheckResult, id string) *protocol.MigrateCheckItem {
		for i := range res.Checks {
			if res.Checks[i].ID == id {
				return &res.Checks[i]
			}
		}
		return nil
	}

	// ---- live sync ----
	const id = "mig_live1"
	// A box sealed for another migration is refused.
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateKey}, nil); err != nil {
		t.Fatal(err)
	}
	other := seal("mig_other", sourceURL)
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateCheck, Source: other}, nil); err == nil {
		t.Fatal("check accepted a box sealed for another migration")
	}
	box := seal(id, sourceURL)
	var chk protocol.MigrateCheckResult
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateCheck, Source: box}, &chk); err != nil {
		t.Fatal(err)
	}
	if c := check(chk, "identity"); c == nil || c.Status != protocol.CheckFail || strings.Join(c.Items, ",") != "public.events" {
		t.Fatalf("identity check = %+v", c)
	}
	if chk.LiveSync || !chk.DumpOK || chk.Method != protocol.MigrateMethodDump || chk.Source.Tables != 4 || chk.AppUser != "shopowner" ||
		chk.Target.Database != "shop" || chk.Target.Exists {
		t.Fatalf("check = %+v", chk)
	}
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateFixIdentity}, nil); err != nil {
		t.Fatal(err)
	}
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateCheck, Source: box}, &chk); err != nil {
		t.Fatal(err)
	}
	if !chk.LiveSync || chk.Method != protocol.MigrateMethodLive {
		t.Fatalf("after the fix, check = %s %+v", chk.Summary, chk.Checks)
	}
	if info, err := os.Stat(filepath.Join(stateDir, "migrate", id, "pgpass")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("pgpass: %v %v", info, err)
	}

	// Writes keep coming while the first copy runs.
	var stop atomic.Bool
	var wg sync.WaitGroup
	var written atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		// The app writes as the provider's user, as apps do.
		conn, err := pgx.Connect(ctx, fmt.Sprintf("host=127.0.0.1 port=%d user=shopowner password='p@ss:w\\'rd\\\\x' dbname=shop", src.port))
		if err != nil {
			t.Errorf("writer: %v", err)
			return
		}
		defer conn.Close(ctx)
		for !stop.Load() {
			if _, err := conn.Exec(ctx, `INSERT INTO orders (customer_id, total) VALUES (1, 1); UPDATE customers SET name = name || '.' WHERE id = 7; INSERT INTO events (what) VALUES ('w'); DELETE FROM events WHERE ctid = (SELECT ctid FROM events LIMIT 1)`); err != nil {
				return
			}
			written.Add(1)
			time.Sleep(5 * time.Millisecond)
		}
	}()
	var cp protocol.MigrateCopyResult
	if err := run(protocol.TaskMigrateCopy, protocol.MigrateParams{MigrationID: id, Method: protocol.MigrateMethodLive}, &cp); err != nil {
		t.Fatal(err)
	}
	if cp.TablesTotal != 4 || !cp.CreatedDatabase {
		t.Fatalf("copy = %+v", cp)
	}
	st, _ := a.loadMigState(id)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		status := a.liveSyncStatus(ctx, st, map[string]*pgx.Conn{})
		if status.Phase == protocol.MigratePhaseSyncing && status.LagBytes != nil {
			t.Logf("syncing: %d/%d tables, %d bytes behind", status.TablesCopied, status.TablesTotal, *status.LagBytes)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sync never caught up: %+v", status)
		}
		time.Sleep(500 * time.Millisecond)
	}
	time.Sleep(time.Second)
	// Switch over: Rowsafe makes the source read-only; the writer stops.
	var sw protocol.MigrateSwitchoverResult
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateSwitchover, ReadOnly: true,
		BrowserKey: browserKey, Host: "127.0.0.1"}, &sw); err != nil {
		t.Fatal(err)
	}
	stop.Store(true)
	wg.Wait()
	if written.Load() == 0 {
		t.Fatal("no writes happened during the copy")
	}
	if sw.Mismatches != 0 || len(sw.Tables) != 4 || !sw.SourceReadOnly || sw.SequencesSynced < 2 {
		t.Fatalf("switchover = %+v", sw)
	}
	for _, tb := range []string{"customers", "orders", "events", "notes"} {
		s, d := src.int(t, "shop", "SELECT count(*) FROM "+tb), tgt.int(t, "shop", "SELECT count(*) FROM "+tb)
		if s != d {
			t.Errorf("%s: %d rows at the source, %d here", tb, s, d)
		}
	}
	if s, d := src.int(t, "shop", "SELECT last_value FROM orders_id_seq"), tgt.int(t, "shop", "SELECT last_value FROM orders_id_seq"); s != d {
		t.Errorf("orders_id_seq: %d vs %d", s, d)
	}
	if n := tgt.int(t, "shop", "SELECT count(*) FROM order_totals"); n != 2000 {
		t.Errorf("order_totals has %d rows (not refreshed?)", n)
	}
	if n := tgt.int(t, "shop", "SELECT count(*) FROM pg_subscription"); n != 0 {
		t.Error("the subscription is still there")
	}
	if n := src.int(t, "shop", "SELECT count(*) FROM pg_replication_slots"); n != 0 {
		t.Error("the replication slot is still at the source")
	}
	if n := src.int(t, "shop", "SELECT count(*) FROM pg_publication"); n != 0 {
		t.Error("the publication is still at the source")
	}
	// The source refuses writes from new sessions.
	sconn, _ := pgx.Connect(ctx, fmt.Sprintf("host=%s port=%d user=postgres dbname=shop", src.sock, src.port))
	if _, err := sconn.Exec(ctx, `INSERT INTO events (what) VALUES ('late')`); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Errorf("the source still accepts writes: %v", err)
	}
	sconn.Close(ctx)
	// The app's new login works, owns its tables, and nextval continues.
	url := openCreds(id, sw.Credentials)
	if !strings.HasPrefix(url, "postgresql://shopowner:") || !strings.Contains(url, "@127.0.0.1:") || strings.Contains(sw.ConnectionHint, url[len("postgresql://shopowner:"):strings.Index(url, "@")]) {
		t.Fatalf("credentials %q, hint %q", url, sw.ConnectionHint)
	}
	app, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatalf("connecting with the new credentials: %v", err)
	}
	var next int64
	if err := app.QueryRow(ctx, `INSERT INTO orders (customer_id, total) VALUES (1, 5) RETURNING id`).Scan(&next); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Exec(ctx, `ALTER TABLE customers ADD COLUMN email text`); err != nil {
		t.Errorf("the app login doesn't own its tables: %v", err)
	}
	if _, err := app.Exec(ctx, `SELECT double(2)`); err != nil {
		t.Error(err)
	}
	app.Close(ctx)
	if next <= src.int(t, "shop", "SELECT max(id) FROM orders") {
		t.Errorf("nextval %d would collide with the source's ids", next)
	}
	// A new password; the old one stops working.
	var cr protocol.MigrateSwitchoverResult
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateCredentials, BrowserKey: browserKey, Host: "127.0.0.1"}, &cr); err != nil {
		t.Fatal(err)
	}
	if _, err := pgx.Connect(ctx, url); err == nil {
		t.Error("the old password still works")
	}
	if c, err := pgx.Connect(ctx, openCreds(id, cr.Credentials)); err != nil {
		t.Errorf("the new password: %v", err)
	} else {
		c.Close(ctx)
	}
	// Roll back: the source accepts writes again.
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateSourceWritable}, nil); err != nil {
		t.Fatal(err)
	}
	src.exec(t, "shop", `INSERT INTO events (what) VALUES ('after rollback')`)
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id, Action: protocol.MigrateFinish}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "migrate", id)); !os.IsNotExist(err) {
		t.Error("finish left the migration's directory (source connection string) behind")
	}

	// ---- one-time copy into another database ----
	const id2 = "mig_dump1"
	box2 := seal(id2, sourceURL)
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id2, Action: protocol.MigrateCheck, Source: box2, TargetDB: "shop"}, &chk); err != nil {
		t.Fatal(err)
	}
	if c := check(chk, "target_db"); c == nil || c.Status != protocol.CheckFail {
		t.Fatalf("a non-empty target database wasn't refused: %+v", c)
	}
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id2, Action: protocol.MigrateCheck, Source: box2, TargetDB: "shop_copy"}, &chk); err != nil {
		t.Fatal(err)
	}
	if !chk.DumpOK {
		t.Fatalf("dump not possible: %+v", chk.Checks)
	}
	var cp2 protocol.MigrateCopyResult
	if err := run(protocol.TaskMigrateCopy, protocol.MigrateParams{MigrationID: id2, Method: protocol.MigrateMethodDump, ReadOnly: true,
		BrowserKey: browserKey, AppUser: "shop_app", Host: "127.0.0.1"}, &cp2); err != nil {
		t.Fatal(err)
	}
	if cp2.Switchover == nil || cp2.Switchover.Mismatches != 0 || cp2.TablesTotal != 4 {
		t.Fatalf("one-time copy = %+v", cp2)
	}
	if s, d := src.int(t, "shop", "SELECT count(*) FROM orders"), tgt.int(t, "shop_copy", "SELECT count(*) FROM orders"); s != d {
		t.Errorf("orders: %d vs %d", s, d)
	}
	c2, err := pgx.Connect(ctx, openCreds(id2, cp2.Switchover.Credentials))
	if err != nil {
		t.Fatal(err)
	}
	c2.Close(ctx)
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id2, Action: protocol.MigrateSourceWritable}, nil); err != nil {
		t.Fatal(err)
	}

	// ---- cancel a live sync and drop its copy ----
	const id3 = "mig_cancel1"
	box3 := seal(id3, sourceURL)
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id3, Action: protocol.MigrateCheck, Source: box3, TargetDB: "shop_three"}, &chk); err != nil {
		t.Fatal(err)
	}
	if err := run(protocol.TaskMigrateCopy, protocol.MigrateParams{MigrationID: id3, Method: protocol.MigrateMethodLive}, nil); err != nil {
		t.Fatal(err)
	}
	if err := run(protocol.TaskMigrate, protocol.MigrateParams{MigrationID: id3, Action: protocol.MigrateCancel, DropTarget: true}, nil); err != nil {
		t.Fatal(err)
	}
	if n := tgt.int(t, "postgres", "SELECT count(*) FROM pg_database WHERE datname = 'shop_three'"); n != 0 {
		t.Error("cancel kept the copy")
	}
	if n := src.int(t, "shop", "SELECT count(*) FROM pg_replication_slots"); n != 0 {
		t.Error("cancel left the replication slot at the source")
	}
	if n := src.int(t, "shop", "SELECT count(*) FROM pg_publication"); n != 0 {
		t.Error("cancel left the publication at the source")
	}
}
