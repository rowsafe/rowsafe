package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	gomysql "github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestIntegration runs a real MySQL or MariaDB server through everything
// the engine does. It runs inside the agent's Docker image next to the
// server (scripts/test-mysql.sh sets it up):
//
//	ROWSAFE_MYSQL_IT=mysql|mariadb     the engine
//	ROWSAFE_MYSQL_IT_SOCKET            the server's socket
//	ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE  root's password (the agent creates its account)
//	ROWSAFE_REPO_S3_*, ROWSAFE_REPO_CIPHER_PASS
func TestIntegration(t *testing.T) {
	engine := os.Getenv("ROWSAFE_MYSQL_IT")
	if engine == "" {
		t.Skip("set ROWSAFE_MYSQL_IT (see scripts/test-mysql.sh)")
	}
	ctx := context.Background()
	state := t.TempDir()
	if d := os.Getenv("ROWSAFE_MYSQL_IT_STATE"); d != "" {
		state = d
	}
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_REPO_S3_PORT"))
	cfg := agent.Config{Mode: agent.ModeDockerSidecar, StateDir: state, DrillDir: filepath.Join(state, "drills"),
		RewindDir: filepath.Join(state, "rewind")}
	env := agent.EngineEnv{
		Config: cfg, StateDir: filepath.Join(state, "engines", engine),
		Repo: pgbackrest.Repo{
			Endpoint: os.Getenv("ROWSAFE_REPO_S3_ENDPOINT"), Bucket: os.Getenv("ROWSAFE_REPO_S3_BUCKET"),
			Region: "us-east-1", Key: os.Getenv("ROWSAFE_REPO_S3_KEY"), KeySecret: os.Getenv("ROWSAFE_REPO_S3_KEY_SECRET"),
			CipherPass: os.Getenv("ROWSAFE_REPO_CIPHER_PASS"), PathPrefix: "/rowsafe-it-" + strconv.FormatInt(time.Now().Unix(), 10),
			URIStyle: "path", Port: port, CAFile: os.Getenv("ROWSAFE_REPO_S3_CA_FILE"),
		},
		Runner: pgbackrest.ExecRunner{}, Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Notes: io.Discard,
	}
	e := &Engine{flavor: flavor(engine)}
	spec := protocol.DatabaseSpec{ID: "db_it_" + engine, Name: "shop", Stanza: "shop", Port: 3306,
		SocketDir: os.Getenv("ROWSAFE_MYSQL_IT_SOCKET"), Engine: engine, RetentionFull: 2}
	shipPoll, shipMaxDelay = 2*time.Second, 5*time.Second

	run := func(typ string, params any) (any, string, error) {
		t.Helper()
		var raw json.RawMessage
		if params != nil {
			raw, _ = json.Marshal(params)
		}
		tl := &testLog{t: t}
		res, err := e.Run(ctx, env, &protocol.Task{ID: fmt.Sprintf("t%d", time.Now().UnixNano()), Type: typ, Database: &spec, Params: raw}, tl)
		return res, tl.b.String(), err
	}
	must := func(typ string, params any) any {
		t.Helper()
		res, log, err := run(typ, params)
		if err != nil {
			t.Fatalf("%s: %v\n%s", typ, err, log)
		}
		return res
	}
	admin := func() *sql.DB {
		t.Helper()
		pw, err := readSecretFile(os.Getenv("ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE"))
		if err != nil {
			t.Fatal(err)
		}
		db, err := openWith(ctx, account{User: "root", Password: pw}, spec.SocketDir, 3306)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(4)
		return db
	}
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

	// Plan (read-only), then apply: the agent creates its own account.
	plan := must(protocol.TaskAdopt, protocol.AdoptParams{}).(*protocol.AdoptResult)
	t.Logf("plan: %+v warnings: %v", plan.Plan, plan.Warnings)
	if plan.Inspect.MySQL == nil || plan.Inspect.MySQL.BackupTool == "" {
		t.Fatalf("inspect: %+v", plan.Inspect.MySQL)
	}
	applied := must(protocol.TaskAdopt, protocol.AdoptParams{Apply: true}).(*protocol.AdoptResult)
	if !applied.Applied || applied.RestartRequired {
		t.Fatalf("apply: %+v", applied)
	}
	if _, err := os.Stat(accountPath(env.StateDir, 3306)); err != nil {
		t.Fatalf("no account file: %v", err)
	}
	// The heartbeat starts shipping; check proves it.
	must(protocol.TaskCheck, nil)
	st, _ := e.Archiver(ctx, env, spec)
	for i := 0; st == nil && i < 20; i++ {
		time.Sleep(time.Second)
		st, _ = e.Archiver(ctx, env, spec)
	}
	if st == nil || st.ArchiveMode != "on" || st.Error != "" {
		t.Fatalf("archiver: %+v", st)
	}

	adb := admin()
	defer adb.Close()
	exec(adb, "CREATE DATABASE IF NOT EXISTS shop")
	exec(adb, "CREATE TABLE shop.orders (id INT PRIMARY KEY AUTO_INCREMENT, customer VARCHAR(100) NOT NULL, amount DECIMAL(10,2), note TEXT, created DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6))")
	exec(adb, "CREATE TABLE shop.items (id INT PRIMARY KEY AUTO_INCREMENT, order_id INT NOT NULL, sku VARCHAR(20), FOREIGN KEY (order_id) REFERENCES shop.orders(id))")
	exec(adb, "CREATE TABLE shop.nokey (a INT, b INT)")
	insert := func(from, to int) {
		for i := from; i <= to; i += 100 {
			var vals, items []string
			for j := i; j < i+100 && j <= to; j++ {
				vals = append(vals, fmt.Sprintf("(%d, 'customer %d', %d.50, NULL)", j, j, j))
				items = append(items, fmt.Sprintf("(%d, 'sku-%d')", j, j))
			}
			exec(adb, "INSERT INTO shop.orders (id, customer, amount, note) VALUES "+strings.Join(vals, ","))
			exec(adb, "INSERT INTO shop.items (order_id, sku) VALUES "+strings.Join(items, ","))
		}
	}
	insert(1, 1000)

	full := must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}).(*protocol.BackupResult)
	t.Logf("full: %+v", full)
	insert(1001, 1500)
	exec(adb, "UPDATE shop.orders SET note = 'important' WHERE id = 1400")
	time.Sleep(1100 * time.Millisecond)
	before := time.Now().UTC().Truncate(time.Second)
	time.Sleep(2 * time.Second)
	// The accident.
	exec(adb, "DELETE FROM shop.items WHERE order_id <= 300")
	exec(adb, "DELETE FROM shop.orders WHERE id <= 300")
	exec(adb, "UPDATE shop.orders SET note = 'oops' WHERE id = 1400")
	markRes := must(protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "after-accident"}).(*protocol.RestorePointResult)
	if !markRes.Archived {
		t.Fatalf("mark: %+v", markRes)
	}
	insert(1501, 1600)
	diff := must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff}).(*protocol.BackupResult)
	incr := must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupIncr}).(*protocol.BackupResult)
	if diff.Type != protocol.BackupDiff || incr.Type != protocol.BackupIncr || !strings.HasPrefix(incr.Label, full.Label+"_") {
		t.Fatalf("diff %+v incr %+v", diff, incr)
	}
	insert(1601, 1650)

	// Proof: the latest backup (full + incr chain) and every binary log since.
	dr := must(protocol.TaskDrill, nil).(*protocol.DrillResult)
	if !dr.Passed || dr.RecoveredTo == nil || len(dr.Databases) == 0 {
		t.Fatalf("drill: %+v", dr)
	}
	t.Logf("drill: %+v", dr)

	// Guard: a migration preview on a copy; production is untouched.
	pv := must(protocol.TaskPreviewMigration, protocol.PreviewParams{PreviewID: "p1", SQL: "-- add a column\n" +
		"ALTER TABLE orders ADD COLUMN status VARCHAR(10) DEFAULT 'new';\n" +
		"ALTER TABLE orders MODIFY COLUMN amount DECIMAL(14,3);\n" +
		"UPDATE orders SET status = 'old' WHERE id < 1000;\n" +
		"CREATE INDEX orders_status ON orders (status);\n" +
		"DROP TABLE nokey;\n" +
		"GRANT SELECT ON shop.* TO 'reporting'@'%';\n" +
		"ALTER TABLE items ADD COLUMN sku VARCHAR(5);\n"}).(*protocol.PreviewResult)
	t.Logf("preview: %s", pv.Summary)
	if pv.DB != "shop" || pv.Verdict != protocol.PreviewFailed || pv.Error == nil || pv.Error.Statement != 7 || pv.Error.Code != "1060" {
		t.Fatalf("preview: %+v %+v", pv, pv.Error)
	}
	if s := pv.Statements[1]; len(s.Rewrites) != 1 || s.Rewrites[0].Name != "shop.orders" || len(s.Locks) != 1 || s.Locks[0].Blocks != "writes" {
		t.Errorf("modify column: %+v", s)
	}
	if s := pv.Statements[2]; s.Rows == nil || *s.Rows == 0 {
		t.Errorf("update: %+v", s)
	}
	if s := pv.Statements[3]; len(s.IndexBuilds) != 1 {
		t.Errorf("create index: %+v", s)
	}
	if s := pv.Statements[4]; len(s.Dropped) != 1 || s.Dropped[0].Name != "shop.nokey" {
		t.Errorf("drop table: %+v", s)
	}
	if s := pv.Statements[5]; s.Ran {
		t.Errorf("grant ran on the copy: %+v", s)
	}
	if !slices.ContainsFunc(pv.Findings, func(f protocol.PreviewFinding) bool { return f.Rule == "partial_ddl" }) {
		t.Errorf("findings: %+v", pv.Findings)
	}
	var cols int
	if err := adb.QueryRow("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = 'shop' AND table_name = 'orders' AND column_name = 'status'").Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("the preview changed production: %v %d", err, cols)
	}

	safeCopyIntegration(t, ctx, e, env, spec, adb)

	// Rewind: a copy as it was before the accident.
	cr := must(protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c1",
		Target: protocol.RewindTarget{Time: &before, BackupSet: full.Label}}).(*protocol.RewindCopyResult)
	t.Logf("copy: %s", cr.Summary)
	if cr.RecoveredTo == nil || cr.RecoveredTo.After(before) {
		t.Fatalf("copy recovered to %v, want <= %v", cr.RecoveredTo, before)
	}
	states := e.RewindStates(env)
	if len(states) != 1 || states[0].Status != protocol.RewindCopyReady {
		t.Fatalf("states: %+v", states)
	}
	cmp := must(protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1"}).(*protocol.RewindCompareResult)
	t.Logf("compare: %s", cmp.Summary)
	got := map[string]protocol.RewindTableDiff{}
	for _, d := range cmp.Tables {
		got[d.Table] = d
	}
	if o := got["orders"]; o.MissingInProduction != 300 || o.Changed != 1 || o.OnlyInProduction != 150 {
		t.Fatalf("orders diff: %+v", o)
	}
	if got["nokey"].Skipped == "" || got["items"].MissingInProduction != 300 {
		t.Fatalf("diffs: %+v", cmp.Tables)
	}
	rows := must(protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "c1", IncludeChanged: true,
		Tables: []protocol.RewindTable{{DB: "shop", Table: "items"}, {DB: "shop", Table: "orders"}}}).(*protocol.RewindRowsResult)
	t.Logf("rows: %s", rows.Summary)
	if n := count(adb, "SELECT COUNT(*) FROM shop.orders"); n != 1650 {
		t.Fatalf("orders after bringing rows back: %d", n)
	}
	var note sql.NullString
	_ = adb.QueryRowContext(ctx, "SELECT note FROM shop.orders WHERE id = 1400").Scan(&note)
	if note.String != "important" {
		t.Fatalf("changed row not set back: %q", note.String)
	}
	if n := count(adb, "SELECT COUNT(*) FROM shop.items"); n != 1650 {
		t.Fatalf("items: %d", n)
	}
	// A second compare finds nothing missing.
	cmp2 := must(protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1",
		Tables: []protocol.RewindTable{{DB: "shop", Table: "orders"}}}).(*protocol.RewindCompareResult)
	if cmp2.Tables[0].MissingInProduction != 0 || cmp2.Tables[0].Changed != 0 {
		t.Fatalf("compare after: %+v", cmp2.Tables)
	}
	if _, _, err := run(protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c2", Target: protocol.RewindTarget{Time: &before}}); err == nil {
		t.Fatal("a second copy of the same database was allowed")
	}
	drop := must(protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"}).(*protocol.RewindDropResult)
	if !drop.Removed {
		t.Fatalf("drop: %+v", drop)
	}

	// A copy at the Mark: right after the accident.
	cr2 := must(protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c3",
		Target: protocol.RewindTarget{Mark: "after-accident", BackupSet: full.Label}}).(*protocol.RewindCopyResult)
	rec, _ := rewinds(env).get("c3")
	cdb, err := rec.scratch().connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(cdb, "SELECT COUNT(*) FROM shop.orders"); n != 1200 {
		t.Fatalf("copy at the Mark has %d orders, want 1200 (%s)", n, cr2.Summary)
	}
	cdb.Close()
	must(protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c3"})

	// Disaster recovery without the service: restore-mysql into a folder.
	rdir := filepath.Join(state, "restored")
	got2, err := RestoreTo(ctx, RestoreOptions{Engine: engine, Database: "shop", Dir: rdir, At: &before, Env: env, Log: &testLog{t: t}})
	if err != nil || got2.After(before) {
		t.Fatalf("RestoreTo: %v %v", got2, err)
	}
	s2 := e.server(env, spec)
	sc, err := s2.startScratch(ctx, rdir, manifest{Version: "8.4.0", LowerCase: 0}, time.Minute*5)
	if err != nil {
		t.Fatal(err)
	}
	rdb, err := sc.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := count(rdb, "SELECT COUNT(*) FROM shop.orders"); n != 1500 {
		t.Fatalf("restored folder has %d orders, want 1500", n)
	}
	rdb.Close()
	sc.stop(ctx)

	// Pulse.
	dm, err := e.Monitor(ctx, env, spec)
	if err != nil || dm.Metrics["connections_total"] == 0 || dm.Metrics["disk_free_pct"] == 0 {
		t.Fatalf("monitor: %v %+v", err, dm)
	}
	if dm.Insights == nil || len(dm.Insights.LargestTables) == 0 || dm.Activity == nil || dm.Statements == nil {
		t.Fatalf("monitor details: insights %+v activity %+v statements %+v", dm.Insights, dm.Activity, dm.Statements)
	}
	time.Sleep(6 * time.Second)
	dm, _ = e.Monitor(ctx, env, spec)
	t.Logf("metrics: %v", dm.Metrics)

	// Fixes.
	must(protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintAnalyze, DB: "shop", Tables: []string{"orders"}})
	must(protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintOptimize, DB: "shop", Tables: []string{"items"}})
	exec(adb, "CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'app-password-1A!'")
	exec(adb, "GRANT SELECT ON shop.* TO 'app'@'%'")
	sleeper, err := openWith(ctx, account{User: "app", Password: "app-password-1A!"}, spec.SocketDir, 3306)
	if err != nil {
		t.Fatal(err)
	}
	conn, _ := sleeper.Conn(ctx)
	var id int
	_ = conn.QueryRowContext(ctx, "SELECT CONNECTION_ID()").Scan(&id)
	done := make(chan error, 1)
	go func() { _, err := conn.ExecContext(ctx, "SELECT SLEEP(60)"); done <- err }()
	time.Sleep(time.Second)
	kr := must(protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintCancelQuery, PID: id}).(*protocol.MaintenanceResult)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the query wasn't cancelled")
	}
	t.Logf("kill: %s", kr.Summary)
	conn.Close()
	sleeper.Close()

	// Retention: two more fulls with RetentionFull 2 drop the first chain.
	must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	s := e.server(env, spec)
	store, _ := openStore(env.Repo, engine, "shop", 64)
	ms, _ := store.manifests(ctx)
	for _, m := range ms {
		if fullOf(m.Label) == full.Label {
			t.Fatalf("retention kept %s", m.Label)
		}
	}
	_ = s
}

type testLog struct {
	t *testing.T
	b strings.Builder
}

func (l *testLog) Printf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	l.b.WriteString(line + "\n")
	l.t.Log(line)
}

func (l *testLog) Output(label string, out []byte) {
	if s := strings.TrimSpace(string(out)); s != "" {
		l.Printf("%s output:\n%s", label, s)
	}
}


// safeCopyIntegration makes a masked safe copy, connects to it over TLS
// with the password made here, sets a new password and deletes it.
func safeCopyIntegration(t *testing.T, ctx context.Context, e *Engine, env agent.EngineEnv, spec protocol.DatabaseSpec, adb *sql.DB) {
	t.Helper()
	// Safe copies need a native agent (the test runs in the sidecar image).
	env.Config.Mode = agent.ModeNative
	env.Config.Copies = agent.CopiesConfig{Dir: filepath.Join(env.Config.StateDir, "copies"), PortMin: 55440, PortMax: 55460}
	env.Copies = agent.NewCopyTools(env.Config)
	run := func(typ string, params any) (any, error) {
		raw, _ := json.Marshal(params)
		return e.Run(ctx, env, &protocol.Task{ID: fmt.Sprintf("t%d", time.Now().UnixNano()), Type: typ, Database: &spec, Params: raw}, &testLog{t: t})
	}
	schema, err := run(protocol.TaskCopySchema, nil)
	if err != nil {
		t.Fatal("copy_schema:", err)
	}
	sr := schema.(*protocol.CopySchemaResult)
	if !slices.ContainsFunc(sr.Databases, func(d protocol.SchemaDatabase) bool {
		return d.Name == "shop" && slices.ContainsFunc(d.Tables, func(t protocol.SchemaTable) bool { return t.Name == "orders" && len(t.Columns) >= 5 })
	}) {
		t.Fatalf("copy_schema: %+v", sr)
	}
	pw, verifier, err := client.NewCopyPasswordFor(string(e.flavor))
	if err != nil {
		t.Fatal(err)
	}
	res, err := run(protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc1",
		Masking: protocol.MaskingPlan{Mode: protocol.MaskingRules, Rules: []protocol.MaskingRule{{DB: "shop", Table: "orders", Column: "customer", Strategy: "full_name"}}},
		Access:  protocol.CopyAccess{Listen: "*", AllowFrom: []string{"127.0.0.1"}, Role: "dev_ana", PasswordVerifier: verifier}})
	if err != nil {
		t.Fatal("safe copy:", err)
	}
	sc := res.(*protocol.SafeCopyResult)
	t.Logf("safe copy: %s", sc.Summary)
	if sc.Masking.Columns == 0 || sc.Port == 0 || !strings.Contains(sc.TLSCert, "BEGIN CERTIFICATE") {
		t.Fatalf("safe copy: %+v", sc)
	}
	connect := func(user, pass string, tls bool) (*sql.DB, error) {
		c := gomysql.NewConfig()
		c.User, c.Passwd, c.Net, c.Addr, c.DBName = user, pass, "tcp", "127.0.0.1:"+strconv.Itoa(sc.Port), "shop"
		c.Timeout = 5 * time.Second
		if tls {
			c.TLSConfig = "skip-verify"
		}
		db, err := sql.Open("mysql", c.FormatDSN())
		if err != nil {
			return nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, err
		}
		return db, nil
	}
	cdb, err := connect("dev_ana", pw, true)
	if err != nil {
		t.Fatal("connecting to the safe copy:", err)
	}
	var customer string
	if err := cdb.QueryRowContext(ctx, "SELECT customer FROM orders WHERE id = 1400").Scan(&customer); err != nil || customer == "" || customer == "customer 1400" {
		t.Fatalf("not masked: %q %v", customer, err)
	}
	if _, err := cdb.ExecContext(ctx, "UPDATE orders SET note = 'dev' WHERE id = 1400"); err != nil {
		t.Errorf("the copy should be writable: %v", err)
	}
	cdb.Close()
	if db, err := connect("dev_ana", pw, false); err == nil {
		db.Close()
		t.Error("the copy accepted a connection without TLS")
	}
	if db, err := connect("dev_ana", "wrong", true); err == nil {
		db.Close()
		t.Error("the copy accepted a wrong password")
	}
	// A new password (version 2) replaces the first.
	pw2, v2, _ := client.NewCopyPasswordFor(string(e.flavor))
	if !e.SetCopyPassword(ctx, env, protocol.CopyPassword{ID: "sc1", Version: 2, Verifier: v2}) {
		t.Fatal("SetCopyPassword: not the engine's copy")
	}
	if db, err := connect("dev_ana", pw2, true); err != nil {
		t.Fatal("new password:", err)
	} else {
		db.Close()
	}
	states := e.CopyStates(env)
	if len(states) != 1 || states[0].PasswordVersion != 2 || states[0].Status != protocol.CopyReady {
		t.Fatalf("states: %+v", states)
	}
	if !e.DropCopy(ctx, env, "sc1") || len(e.CopyStates(env)) != 0 {
		t.Fatal("drop")
	}
	var n int
	if err := adb.QueryRowContext(ctx, "SELECT COUNT(*) FROM shop.orders WHERE customer = 'customer 1400'").Scan(&n); err != nil || n != 1 {
		t.Fatalf("production changed: %d %v", n, err)
	}
}
