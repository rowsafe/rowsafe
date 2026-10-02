//go:build clickhouse_integration

// Integration test against a real ClickHouse server on this host, with the
// clickhouse program installed (Proof and copies start their own). Run it
// with scripts/test-clickhouse.sh, which runs it inside the official
// clickhouse/clickhouse-server images:
//
//	ROWSAFE_TEST_CLICKHOUSE_PORT=8123 go test -tags clickhouse_integration ./internal/engine/clickhouse/
//
// ROWSAFE_TEST_CLICKHOUSE_USERSD, when set, is a users.d directory the test
// may write: the login is then made the --users-xml way; otherwise with SQL
// as ROWSAFE_TEST_CLICKHOUSE_ADMIN (_PASSWORD), or "default" without a
// password. ROWSAFE_TEST_CLICKHOUSE_REPLICATED=1 says the server has a
// Keeper (replicated tables are tested). With ROWSAFE_CLICKHOUSE_URL and
// the gateway variables set, it tests a Docker sidecar (the server in
// another container).
package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type testLog struct {
	t  *testing.T
	mu sync.Mutex
	b  strings.Builder
}

func (l *testLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := fmt.Sprintf(format, args...)
	l.b.WriteString(s + "\n")
	l.t.Log(s)
}

func (l *testLog) Output(label string, out []byte) {
	if len(out) > 0 {
		l.Printf("%s output:\n%s", label, out)
	}
}

func testEnv(t *testing.T) (agent.EngineEnv, *fakes3.Server) {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	env := agent.EngineEnv{
		Config: agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind"),
			RestorePointTimeout: 60 * time.Second},
		StateDir: filepath.Join(dir, "engines", "clickhouse"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Notes: os.Stderr,
	}
	return env, srv
}

func run[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) (*T, error) {
	t.Helper()
	return runCtx[T](context.Background(), t, e, env, db, typ, params)
}

func runCtx[T any](ctx context.Context, t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) (*T, error) {
	t.Helper()
	raw, _ := json.Marshal(params)
	task := &protocol.Task{ID: "task_" + strconv.FormatInt(time.Now().UnixNano(), 36), Type: typ, Database: &db, Params: raw}
	res, err := e.Run(ctx, env, task, &testLog{t: t})
	if res == nil {
		return nil, err
	}
	return res.(*T), err
}

func must(t *testing.T, c *client, q string) {
	t.Helper()
	if err := c.exec(context.Background(), q, nil); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
}

func count(t *testing.T, c *client, q string) int64 {
	t.Helper()
	s, err := c.scalar(context.Background(), q, nil)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

func TestClickHouseEndToEnd(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT not set")
	}
	ctx := context.Background()
	env, srv := testEnv(t)
	e := &Engine{}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.Start(sctx, env)
	adminUser, adminPass := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD")
	admin := newClient(serverURL(port), Login{User: cmpOr(adminUser, "default"), Password: adminPass})
	admin.ua = "rowsafe-test" // not the agent's own queries

	// The installer's login step.
	_ = admin.exec(ctx, "DROP USER IF EXISTS rowsafe", nil) // fails for a users.d user (read-only)
	if dir := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_USERSD"); dir != "" {
		x, err := UsersXML(env, port)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(x)
		if err := os.WriteFile(filepath.Join(dir, "rowsafe.xml"), []byte(x), 0o640); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(60 * time.Second)
		for {
			st, err := ServerStatus(ctx, env, port)
			if err == nil && st.Login == "ok" {
				var b bytes.Buffer
				st.WriteTo(&b)
				t.Log("status:\n" + b.String())
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("users.d login never worked: %+v %v", st, err)
			}
			time.Sleep(time.Second)
		}
		// SQL can't change a user defined in a file: exit 13 for the installer.
		if err := CreateLogin(ctx, env, port, "", ""); !errors.Is(err, ErrCantManageUsers) {
			t.Fatalf("CreateLogin over a users.d user: %v", err)
		}
		// That failed attempt mustn't have broken the saved login.
		x, _ = UsersXML(env, port)
		_ = os.WriteFile(filepath.Join(dir, "rowsafe.xml"), []byte(x), 0o640)
		time.Sleep(6 * time.Second)
	} else {
		if err := CreateLogin(ctx, env, port, "nobody", "wrong"); !errors.Is(err, ErrAdminRefused) {
			t.Fatalf("a wrong admin login: %v", err)
		}
		if adminUser != "" {
			// Docker: "default" without a password is refused, an admin is needed.
			if err := CreateLogin(ctx, env, port, "", ""); !errors.Is(err, ErrNeedAdmin) {
				t.Fatalf("CreateLogin without an admin: %v", err)
			}
		}
		if err := CreateLogin(ctx, env, port, adminUser, adminPass); err != nil {
			t.Fatal("CreateLogin:", err)
		}
	}
	st, err := ServerStatus(ctx, env, port)
	if err != nil || st.Login != "ok" || st.Version == "" {
		t.Fatalf("status: %+v %v", st, err)
	}
	l, _, _ := loadLogin(env, port)
	if err := SaveLogin(ctx, env, port, l.User+":wrong"); !errors.Is(err, ErrAdminRefused) {
		t.Fatalf("save-login with a wrong password: %v", err)
	}
	if err := SaveLogin(ctx, env, port, cmpOr(adminUser, "default")+":"+adminPass); err != nil {
		t.Fatalf("save-login as an admin: %v", err)
	}
	_ = saveLogin(env, port, l)

	db := protocol.DatabaseSpec{ID: "db_ch", Name: "analytics", Stanza: "analytics-ch", Port: port, RetentionFull: 2, Engine: protocol.EngineClickHouse}
	must(t, admin, "DROP DATABASE IF EXISTS shop SYNC")
	must(t, admin, "CREATE DATABASE shop")
	must(t, admin, "CREATE TABLE shop.orders (id UInt64, email String, total Nullable(Int64), tags Array(String)) ENGINE = MergeTree ORDER BY id")
	must(t, admin, "CREATE TABLE shop.prices (sku UInt32, price Float64, ver UInt32) ENGINE = ReplacingMergeTree(ver) ORDER BY sku")
	must(t, admin, "CREATE TABLE shop.notes (id UInt32, body String) ENGINE = ReplacingMergeTree ORDER BY id")
	must(t, admin, "CREATE TABLE shop.totals (bucket UInt64, n UInt64) ENGINE = SummingMergeTree ORDER BY bucket")
	must(t, admin, "CREATE MATERIALIZED VIEW shop.orders_mv TO shop.totals AS SELECT intDiv(id, 100) AS bucket, count() AS n FROM shop.orders GROUP BY bucket")
	must(t, admin, "CREATE VIEW shop.big_orders AS SELECT * FROM shop.orders WHERE total > 5000")
	insertOrders := func(from, to int) {
		must(t, admin, fmt.Sprintf("INSERT INTO shop.orders SELECT number, concat('u', toString(number), '@example.com'), "+
			"if(number %% 7 = 0, NULL, number * 10), [toString(number %% 3)] FROM numbers(%d, %d)", from, to-from))
	}
	insertOrders(0, 1000)
	must(t, admin, "INSERT INTO shop.prices SELECT number, number * 1.5, 1 FROM numbers(100)")
	must(t, admin, "INSERT INTO shop.notes SELECT number, concat('note ', toString(number)) FROM numbers(50)")
	kafka := admin.exec(ctx, "CREATE TABLE shop.queue (x String) ENGINE = Kafka SETTINGS kafka_broker_list = '127.0.0.1:1', "+
		"kafka_topic_list = 't', kafka_group_name = 'g', kafka_format = 'JSONEachRow'", nil) == nil
	if kafka {
		must(t, admin, "CREATE TABLE shop.raw (x String) ENGINE = MergeTree ORDER BY x")
		must(t, admin, "CREATE MATERIALIZED VIEW shop.queue_mv TO shop.raw AS SELECT x FROM shop.queue")
	} else {
		t.Log("no Kafka engine here: not testing tables that reach another system")
	}
	replicated := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_REPLICATED") == "1"
	if replicated {
		must(t, admin, "CREATE TABLE shop.rep (id UInt64, v String) ENGINE = ReplicatedMergeTree('/clickhouse/tables/{shard}/shop/rep', '{replica}') ORDER BY id")
		must(t, admin, "INSERT INTO shop.rep SELECT number, toString(number) FROM numbers(500)")
	}

	// Plan, apply, check.
	plan, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{})
	if err != nil || plan.Applied || plan.Inspect.ArchiveMode != "off" || len(plan.Plan) == 0 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	t.Logf("plan warnings: %q", plan.Warnings)
	applied, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if err != nil || !applied.Applied {
		t.Fatalf("apply: %+v %v", applied, err)
	}
	check, err := run[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	if err != nil || !check.OK {
		t.Fatalf("check: %+v %v", check, err)
	}
	for _, k := range srv.Keys() {
		if strings.Contains(k, "/check/") {
			t.Fatalf("the check left %s behind", k)
		}
	}

	// A full backup, more orders, a differential one, a Mark.
	b1, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil || b1.RepoSizeBytes == 0 || b1.Type != protocol.BackupFull || !fullLabelRE.MatchString(b1.Label) {
		t.Fatalf("backup: %+v %v", b1, err)
	}
	time.Sleep(1100 * time.Millisecond)
	between := time.Now().UTC()
	time.Sleep(1100 * time.Millisecond)
	insertOrders(1000, 1200)
	b2, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff})
	if err != nil || b2.Type != protocol.BackupDiff || baseOf(b2.Label) != b1.Label {
		t.Fatalf("diff backup: %+v %v", b2, err)
	}
	if b2.RepoSizeBytes >= b1.RepoSizeBytes {
		t.Errorf("the differential backup (%d bytes) isn't smaller than the full one (%d)", b2.RepoSizeBytes, b1.RepoSizeBytes)
	}
	// Restore without Rowsafe: download-backup decrypts the differential
	// backup and its full one into folders ClickHouse restores from.
	if dl := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_DOWNLOAD_DIR"); dl != "" {
		list, err := Backups(ctx, env, db.Stanza)
		if err != nil || len(list) != 2 || list[1].Label != b2.Label || list[1].Base != b1.Label {
			t.Fatalf("Backups: %+v %v", list, err)
		}
		dirs, err := DownloadBackup(ctx, env, db.Stanza, b2.Label, dl, io.Discard)
		if err != nil || len(dirs) != 2 {
			t.Fatalf("DownloadBackup: %v %v", dirs, err)
		}
		if _, err := DownloadBackup(ctx, env, db.Stanza, b2.Label, dl, io.Discard); err == nil {
			t.Error("DownloadBackup into a folder that isn't empty")
		}
		must(t, admin, "DROP DATABASE IF EXISTS shop_diy SYNC")
		must(t, admin, "CREATE DATABASE shop_diy")
		must(t, admin, fmt.Sprintf("RESTORE TABLE shop.orders AS shop_diy.orders FROM File('%s/') SETTINGS base_backup = File('%s/')", dirs[1], dirs[0]))
		if n := count(t, admin, "SELECT count() FROM shop_diy.orders"); n != 1200 {
			t.Errorf("restored without Rowsafe: %d orders, want 1200", n)
		}
		must(t, admin, "DROP DATABASE shop_diy SYNC")
	}
	time.Sleep(1100 * time.Millisecond)
	mark, err := run[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-cleanup"})
	if err != nil || !mark.Archived || !diffLabelRE.MatchString(mark.LSN) {
		t.Fatalf("mark: %+v %v", mark, err)
	}

	// The accident: deleted orders, changed rows, new orders.
	must(t, admin, "ALTER TABLE shop.orders DELETE WHERE id >= 100 AND id < 130 SETTINGS mutations_sync = 2")
	must(t, admin, "INSERT INTO shop.notes VALUES (3, 'rewritten')")
	must(t, admin, "INSERT INTO shop.prices VALUES (5, 99.0, 2)")
	insertOrders(5000, 5003)

	// Proof: the newest backup (the Mark's) restored and checked.
	dr, err := run[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if err != nil || !dr.Passed || dr.BackupLabel != mark.LSN || dr.RestoredBytes == 0 {
		t.Fatalf("drill: %+v %v", dr, err)
	}
	t.Logf("drill: %+v", dr)
	if left, _ := os.ReadDir(drillRoot(env)); len(left) != 0 {
		t.Fatalf("drill left %d entries", len(left))
	}

	// Rewind: a copy at the Mark (1200 orders).
	cp, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "copy1", Target: protocol.RewindTarget{Mark: "before-cleanup"}})
	if err != nil {
		t.Fatal("copy:", err)
	}
	t.Log(cp.Summary)
	if states := e.RewindStates(env); len(states) != 1 || states[0].Status != protocol.RewindCopyReady {
		t.Fatalf("states: %+v", states)
	}
	cc, _ := scratchAt(filepath.Join(copyRoot(env), "copy1")).client()
	if n := count(t, cc, "SELECT count() FROM shop.orders"); n != 1200 {
		t.Fatalf("the copy at the Mark has %d orders, want 1200", n)
	}
	if kafka {
		if n := count(t, cc, "SELECT count() FROM system.tables WHERE database = 'shop' AND name IN ('queue', 'queue_mv')"); n != 0 {
			t.Fatalf("the copy has the Kafka table or its view (%d)", n)
		}
	}
	if replicated {
		if n := count(t, cc, "SELECT count() FROM shop.rep"); n != 500 {
			t.Fatalf("the copy's replicated table has %d rows", n)
		}
	}
	cmp, err := run[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "copy1"})
	if err != nil {
		t.Fatal("compare:", err)
	}
	t.Log(cmp.Summary)
	got := map[string]protocol.RewindTableDiff{}
	for _, d := range cmp.Tables {
		got[d.Table] = d
		t.Logf("%+v", d)
	}
	if d := got["orders"]; d.MissingInProduction != 30 || d.Changed != 0 || d.OnlyInProduction != 3 || d.Note == "" {
		t.Fatalf("orders diff: %+v", d)
	}
	if d := got["notes"]; d.MissingInProduction != 0 || d.Changed != 1 || d.OnlyInProduction != 0 {
		t.Fatalf("notes diff: %+v", d)
	}
	if d := got["prices"]; d.Changed != 1 || d.MissingInProduction != 0 {
		t.Fatalf("prices diff: %+v", d)
	}
	if d := got["big_orders"]; d.Skipped == "" {
		t.Fatalf("a view was compared: %+v", d)
	}
	if _, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "copy1",
		Tables: []protocol.RewindTable{{DB: "shop", Table: "totals"}}}); err == nil || !strings.Contains(err.Error(), "SummingMergeTree") {
		t.Fatalf("rows into a SummingMergeTree: %v", err)
	}
	rows, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "copy1",
		Tables: []protocol.RewindTable{{DB: "shop", Table: "orders"}, {DB: "shop", Table: "notes"}}})
	if err != nil {
		t.Fatal("rows:", err)
	}
	t.Log(rows.Summary)
	if n := count(t, admin, "SELECT count() FROM shop.orders"); n != 1203 {
		t.Fatalf("orders after bringing back: %d", n)
	}
	if n := count(t, admin, "SELECT count() FROM shop.orders WHERE id >= 100 AND id < 130 AND email LIKE '%@example.com' AND tags = [toString(id % 3)]"); n != 30 {
		t.Fatalf("brought-back orders: %d", n)
	}
	if b, _ := admin.scalar(ctx, "SELECT body FROM shop.notes FINAL WHERE id = 3", nil); b != "rewritten" {
		t.Fatalf("a changed row was put back without include_changed: %q", b)
	}
	// Again, with changed rows: nothing more inserted, the note goes back,
	// the price keeps production's newer version.
	rows2, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "copy1",
		Tables: []protocol.RewindTable{{DB: "shop", Table: "orders"}, {DB: "shop", Table: "notes"}, {DB: "shop", Table: "prices"}}, IncludeChanged: true})
	if err != nil || rows2.Tables[0].Inserted != 0 || rows2.Tables[1].Updated != 1 || rows2.Tables[2].Conflicts != 1 {
		t.Fatalf("rows again: %+v %v", rows2, err)
	}
	t.Log(rows2.Summary)
	if b, _ := admin.scalar(ctx, "SELECT body FROM shop.notes FINAL WHERE id = 3", nil); b != "note 3" {
		t.Fatalf("the changed note wasn't put back: %q", b)
	}
	drop, err := run[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "copy1"})
	if err != nil || !drop.Removed {
		t.Fatalf("drop: %+v %v", drop, err)
	}

	// A copy at a moment (the full backup: 1000 orders), started again
	// after an agent restart.
	cp2, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "copy2", Target: protocol.RewindTarget{Time: &between}})
	if err != nil {
		t.Fatal("copy at a moment:", err)
	}
	s2 := scratchAt(filepath.Join(copyRoot(env), "copy2"))
	c2, _ := s2.client()
	if n := count(t, c2, "SELECT count() FROM shop.orders"); n != 1000 {
		t.Fatalf("copy at a moment has %d orders, want 1000", n)
	}
	if err := s2.stop(); err != nil {
		t.Fatal(err)
	}
	e2 := &Engine{}
	e2.Start(sctx, env)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if res, err := e2.copyResult(ctx, e2.copyState(env).records["copy2"]); err == nil {
			t.Log("after a restart:", res.Summary, "port", res.Port, "was", cp2.Port)
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the copy wasn't started again after a restart")
		}
		time.Sleep(time.Second)
	}
	if _, err := run[protocol.RewindDropResult](t, e2, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "copy2"}); err != nil {
		t.Fatal(err)
	}

	// Monitoring.
	if _, err := e.Monitor(ctx, env, db); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	dm, _ := e.Monitor(ctx, env, db)
	if dm.Error != "" || dm.Metrics["connections_total"] == 0 || dm.Metrics["clickhouse_parts_active"] == 0 ||
		dm.Metrics["clickhouse_memory_bytes"] == 0 || dm.Metrics["database_size_bytes"] == 0 {
		t.Fatalf("monitoring: %+v", dm)
	}
	first := e.monitorFor(db.ID)
	first.lastSizes = time.Time{}
	dm, _ = e.Monitor(ctx, env, db)
	if dm.ClickHouse == nil || len(dm.ClickHouse.Parts) == 0 || dm.ClickHouse.PartsToThrowInsert == 0 || len(dm.Sizes) == 0 {
		t.Fatalf("status: %+v", dm.ClickHouse)
	}
	t.Logf("metrics: %v", dm.Metrics)

	// Stopping a long query (Apply fix).
	qid := "rowsafe-test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	done := make(chan error, 1)
	go func() {
		_, err := admin.request(ctx, "SELECT count() FROM numbers(100000000000000) WHERE NOT ignore(sipHash64(number))",
			nil, map[string]string{"query_id": qid, "wait_end_of_query": "1"}, nil)
		done <- err
	}()
	var victim *protocol.ActivityQuery
	for range 100 {
		ps, _ := query[struct {
			Elapsed float64 `json:"elapsed"`
		}](ctx, admin, "SELECT elapsed FROM system.processes WHERE query_id = {id:String}", map[string]string{"id": qid})
		if len(ps) == 1 {
			start := time.Now().Add(-time.Duration(ps[0].Elapsed * float64(time.Second)))
			victim = &protocol.ActivityQuery{QueryID: qid, BackendStart: &start}
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if victim == nil {
		t.Fatal("the long query never showed up")
	}
	if _, longest, running := runningQueries(ctx, admin, "rowsafe", true, nil); running < 1 || longest <= 0 {
		t.Fatalf("running queries: %v %v", running, longest)
	}
	mr, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
		protocol.MaintenanceParams{Action: protocol.MaintKillQuery, QueryID: victim.QueryID, BackendStart: victim.BackendStart})
	if err != nil {
		t.Fatalf("kill query: %v", err)
	}
	t.Log(mr.Summary)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the query wasn't stopped")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the query is still running")
	}

	// Cancelling a mutation that can't finish.
	must(t, admin, "ALTER TABLE shop.orders UPDATE total = toInt64(throwIf(id >= 0)) WHERE 1 SETTINGS mutations_sync = 0")
	var mid string
	for range 50 {
		mid, _ = admin.scalar(ctx, "SELECT mutation_id FROM system.mutations WHERE database = 'shop' AND table = 'orders' AND NOT is_done", nil)
		if mid != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	km, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
		protocol.MaintenanceParams{Action: protocol.MaintKillMutation, DB: "shop", Tables: []string{"orders"}, MutationID: mid})
	if err != nil || mid == "" {
		t.Fatalf("kill mutation %q: %v", mid, err)
	}
	t.Log(km.Summary)
	if n := count(t, admin, "SELECT count() FROM system.mutations WHERE database = 'shop' AND NOT is_done"); n != 0 {
		t.Fatalf("%d mutations still pending", n)
	}

	// A backup stopped halfway (the task cancelled) leaves nothing behind.
	// Many parts: ClickHouse notices a stop request between files.
	must(t, admin, "CREATE TABLE shop.big (a UInt64, b String) ENGINE = MergeTree ORDER BY a")
	must(t, admin, "SYSTEM STOP MERGES shop.big")
	for i := range 30 {
		must(t, admin, fmt.Sprintf("INSERT INTO shop.big SELECT number, randomPrintableASCII(100) FROM numbers(%d, 10000)", i*10000))
	}
	t.Setenv(bandwidthEnv, "200000")
	cctx, ccancel := context.WithTimeout(ctx, 3*time.Second)
	started := time.Now()
	_, err = runCtx[protocol.BackupResult](cctx, t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	ccancel()
	if err == nil || time.Since(started) > 90*time.Second {
		t.Fatalf("cancelled backup: %v after %s", err, time.Since(started))
	}
	t.Logf("cancelled backup: %v after %s", err, time.Since(started).Round(time.Second))
	t.Setenv(bandwidthEnv, "")
	for deadline := time.Now().Add(2 * time.Minute); ; {
		if count(t, admin, "SELECT count() FROM system.backups WHERE status = 'CREATING_BACKUP'") == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("ClickHouse is still running the cancelled backup")
		}
		time.Sleep(time.Second)
	}
	t.Logf("ClickHouse gave the backup up %s after it was cancelled", time.Since(started).Round(time.Second))
	must(t, admin, "DROP TABLE shop.big SYNC")
	r, _ := openRepo(env, db)
	if _, unfinished, err := r.listBackups(ctx); err != nil || len(unfinished) != 0 {
		t.Fatalf("a cancelled backup left %v (%v)", unfinished, err)
	}

	// Two more full backups: retention 2 removes the first with its
	// differential backups and the Mark.
	b3, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	b4, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	keys := strings.Join(srv.Keys(), " ")
	for _, gone := range []string{"/backup/" + b1.Label + "/", "/backup/" + b2.Label + "/", "/backup/" + mark.LSN + "/", "/marks/before-cleanup.json"} {
		if strings.Contains(keys, gone) {
			t.Fatalf("%s kept after retention", gone)
		}
	}
	for _, kept := range []string{b3.Label, b4.Label} {
		if !strings.Contains(keys, "/backup/"+kept+"/backup.json") {
			t.Fatalf("backup %s missing", kept)
		}
	}
	// Nothing readable in the bucket, contents or names.
	for _, k := range srv.Keys() {
		b, _ := srv.Object(k)
		if bytes.Contains(b, []byte("example.com")) || bytes.Contains(b, []byte("CREATE TABLE")) {
			t.Fatalf("%s holds plaintext", k)
		}
		if strings.Contains(k, "shop") || strings.Contains(k, "orders") || strings.Contains(k, "/data/") || strings.Contains(k, "/metadata/") {
			t.Fatalf("a name in the bucket says what: %s", k)
		}
	}
	// Discovery sees the server.
	found, err := e.Discover(ctx, env)
	if err != nil || len(found) == 0 || found[0].Port != port || found[0].Version == "" || found[0].Major < 24 {
		t.Fatalf("discover: %+v %v", found, err)
	}
	t.Logf("discover: %+v", found)

	// A broken backup fails Proof, plainly.
	var victimKey string
	folder := "rowsafe/" + db.Stanza + "/"
	for _, k := range srv.Keys() {
		rel := strings.TrimPrefix(k, folder)
		plain, err := s3gw.PlainName(env.Repo.CipherPass, backupDir(b4.Label), rel)
		if err == nil && strings.HasSuffix(plain, "/data.bin") && strings.Contains(plain, "/orders/") {
			victimKey = k
		}
	}
	if victimKey == "" {
		t.Fatalf("no data file of orders in %s", b4.Label)
	}
	obj, _ := srv.Object(victimKey)
	obj[len(obj)/2] ^= 0xff
	started = time.Now()
	bad, err := run[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if err == nil || bad == nil || bad.Passed || len(bad.Failures) == 0 {
		t.Fatalf("a broken backup passed Proof: %+v %v", bad, err)
	}
	if !strings.Contains(bad.Failures[0], "/orders/") || !strings.Contains(bad.Failures[0], "can't be decrypted") || time.Since(started) > time.Minute {
		t.Fatalf("a broken backup failed Proof unclearly or slowly (%s): %q", time.Since(started).Round(time.Second), bad.Failures)
	}
	t.Logf("broken backup, in %s: %q", time.Since(started).Round(time.Second), bad.Failures)
	if left, _ := os.ReadDir(drillRoot(env)); len(left) != 0 {
		t.Fatalf("drill left %d entries", len(left))
	}
}
