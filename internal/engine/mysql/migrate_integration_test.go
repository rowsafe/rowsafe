package mysql

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// TestMoveInIntegration moves a database from the first server (playing a
// managed provider) into the second (the server Rowsafe protects): a live
// sync with a switchover, then a one-time copy (MYSQL_IT_RUN=MoveIn).
func TestMoveInIntegration(t *testing.T) {
	engine := os.Getenv("ROWSAFE_MYSQL_IT")
	sbSocket := os.Getenv("ROWSAFE_MYSQL_IT_STANDBY_SOCKET")
	if engine == "" || sbSocket == "" {
		t.Skip("set ROWSAFE_MYSQL_IT and ROWSAFE_MYSQL_IT_STANDBY_SOCKET (MYSQL_IT_RUN=MoveIn sh scripts/test-mysql.sh)")
	}
	ctx := context.Background()
	srcHost, tgtHost := os.Getenv("ROWSAFE_MYSQL_IT_PRIMARY_HOST"), os.Getenv("ROWSAFE_MYSQL_IT_STANDBY_HOST")
	state := t.TempDir()
	cfg := agent.Config{Mode: agent.ModeDockerSidecar, StateDir: state, RewindDir: filepath.Join(state, "rewind")}
	env := agent.EngineEnv{Config: cfg, StateDir: filepath.Join(state, "engines", engine), Repo: pgbackrest.Repo{}, Runner: pgbackrest.ExecRunner{},
		Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})), Notes: io.Discard}
	e := &Engine{flavor: flavor(engine)}
	spec := protocol.DatabaseSpec{ID: "db_target", Name: "target", Stanza: "target", Port: 3306, SocketDir: sbSocket, Engine: engine}
	tl := &testLog{t: t}
	pw, err := readSecretFile(os.Getenv("ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	src, err := openWith(ctx, account{User: "root", Password: pw}, os.Getenv("ROWSAFE_MYSQL_IT_SOCKET"), 3306)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	tgt, err := openWith(ctx, account{User: "root", Password: pw}, sbSocket, 3306)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	exec := func(db *sql.DB, q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(db *sql.DB, q string) int64 {
		t.Helper()
		var n int64
		if err := db.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	if ok, err := e.server(env, spec).createAccountAsAdmin(ctx); err != nil || !ok {
		t.Fatalf("account: %v %v", ok, err)
	}
	exec(tgt, standbyGrant)
	exec(tgt, "SET GLOBAL server_id = 2")
	exec(src, "CREATE DATABASE shop")
	exec(src, "CREATE TABLE shop.orders (id INT PRIMARY KEY, note VARCHAR(50))")
	exec(src, "CREATE TABLE shop.events (n INT)") // no primary key
	for i := 1; i <= 300; i++ {
		exec(src, "INSERT INTO shop.orders VALUES (?, 'before')", i)
	}
	exec(src, "INSERT INTO shop.events VALUES (1), (2)")
	exec(src, "CREATE DATABASE other")
	exec(src, "CREATE TABLE other.t (id INT PRIMARY KEY)")

	run := func(m *agent.MigrateEnv, typ string, p protocol.MigrateParams) any {
		t.Helper()
		p.MigrationID = m.ID
		res, err := e.Migrate(ctx, env, spec, *m, typ, p, tl)
		if err != nil {
			t.Fatalf("%s %s: %v", typ, p.Action, err)
		}
		return res
	}
	newMig := func(id string) *agent.MigrateEnv {
		m := &agent.MigrateEnv{ID: id, Dir: filepath.Join(state, "migrate", id), Progress: func(protocol.MigrationStatus) {}}
		m.SetPhase = func(p string) { m.Phase = p }
		return m
	}
	browser, _ := e2e.GenerateKey()
	seal := func(id, s string) *e2e.Box {
		key := run(newMigKeyOnly(id, state), protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateKey}).(*protocol.MigrateKeyResult)
		pub, err := e2e.ParsePublicKey(key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		b, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(id), []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		return &b
	}
	sourceURL := (&url.URL{Scheme: "mysql", User: url.UserPassword("root", pw), Host: srcHost + ":3306", Path: "/shop"}).String() + "?ssl-mode=REQUIRED"

	// Live sync.
	m := newMig("mig1")
	box := seal(m.ID, sourceURL)
	check := run(m, protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: box}).(*protocol.MigrateCheckResult)
	t.Logf("check: %s %+v", check.Summary, check.Checks)
	if !check.LiveSync || !check.DumpOK || check.Source.Tables != 2 {
		t.Fatalf("check: %+v", check)
	}
	cp := run(m, protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodLive}).(*protocol.MigrateCopyResult)
	t.Logf("copy: %s", cp.Summary)
	if n := count(tgt, "SELECT COUNT(*) FROM shop.orders"); n != 300 {
		t.Fatalf("copied %d orders", n)
	}
	exec(src, "INSERT INTO shop.orders VALUES (301, 'during the sync')")
	exec(src, "UPDATE shop.orders SET note = 'changed' WHERE id = 5")
	exec(src, "INSERT INTO shop.events VALUES (3)")
	exec(src, "INSERT INTO other.t VALUES (1)") // another database: not synced
	var status protocol.MigrationStatus
	for i := 0; i < 30; i++ {
		status, _ = e.MigrateStatus(ctx, env, spec, *m)
		if m.Phase == protocol.MigratePhaseSyncing && count(tgt, "SELECT COUNT(*) FROM shop.orders") == 301 {
			break
		}
		time.Sleep(time.Second)
	}
	t.Logf("status: %+v", status)
	if m.Phase != protocol.MigratePhaseSyncing || status.Error != "" || count(tgt, "SELECT COUNT(*) FROM shop.events") != 3 {
		t.Fatalf("sync: phase %s, %+v", m.Phase, status)
	}
	if n := count(tgt, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'other'"); n != 0 {
		t.Fatal("another database of the source came along")
	}
	sw := run(m, protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateSwitchover, BrowserKey: e2e.PublicKeyString(browser.PublicKey()),
		Host: tgtHost}).(*protocol.MigrateSwitchoverResult)
	t.Logf("switchover: %s", sw.Summary)
	if sw.Mismatches != 0 || sw.Credentials == nil || m.Phase != protocol.MigratePhaseSwitched {
		t.Fatalf("switchover: %+v", sw)
	}
	plain, err := e2e.Open(browser, protocol.MigrateInfo, protocol.MigrateCredentialsAAD(m.ID), *sw.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	cu, _ := url.Parse(string(plain))
	apw, _ := cu.User.Password()
	app, err := openWith(ctx, account{User: cu.User.Username(), Password: apw}, "", 3306)
	if err != nil {
		t.Logf("app login over 127.0.0.1 (the agent runs next to the server): %v", err)
	} else {
		defer app.Close()
	}
	if n := count(tgt, "SELECT COUNT(*) FROM shop.orders WHERE note = 'changed'"); n != 1 {
		t.Fatal("the update didn't come along")
	}
	cs, err := e.server(env, spec).channelStatus(ctx, tgt, channelName(m.ID))
	if err == nil && cs.Configured {
		t.Fatal("the channel is still there after the switchover")
	}

	// One-time copy, under another name.
	m2 := newMig("mig2")
	box2 := seal(m2.ID, strings.Replace(sourceURL, "/shop", "/other", 1))
	check2 := run(m2, protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: box2, TargetDB: "other_copy"}).(*protocol.MigrateCheckResult)
	if !check2.DumpOK {
		t.Fatalf("check 2: %+v", check2)
	}
	cp2 := run(m2, protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump, TargetDB: "other_copy",
		BrowserKey: e2e.PublicKeyString(browser.PublicKey()), AppUser: "other_app"}).(*protocol.MigrateCopyResult)
	if cp2.Switchover == nil || cp2.Switchover.AppUser != "other_app" || count(tgt, "SELECT COUNT(*) FROM other_copy.t") != 1 {
		t.Fatalf("one-time copy: %+v", cp2)
	}
	// Cancel drops what it created.
	m3 := newMig("mig3")
	box3 := seal(m3.ID, sourceURL)
	run(m3, protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: box3, TargetDB: "shop_again"})
	if e.flavor.mariadb() { // a live sync into MariaDB keeps the name
		run(m3, protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump, TargetDB: "shop_again",
			BrowserKey: e2e.PublicKeyString(browser.PublicKey())})
	} else {
		run(m3, protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodLive, TargetDB: "shop_again"})
	}
	run(m3, protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCancel, DropTarget: true})
	if n := count(tgt, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = 'shop_again'"); n != 0 {
		t.Fatal("cancel left the database it created")
	}
}

// newMigKeyOnly is a MigrateEnv for the key step of a migration.
func newMigKeyOnly(id, state string) *agent.MigrateEnv {
	m := &agent.MigrateEnv{ID: id, Dir: filepath.Join(state, "migrate", id), Progress: func(protocol.MigrationStatus) {}}
	m.SetPhase = func(p string) { m.Phase = p }
	return m
}
