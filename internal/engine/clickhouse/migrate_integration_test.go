//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// TestClickHouseMoveIn copies a database from the first server (playing
// ClickHouse Cloud) into the second (CLICKHOUSE_CLONE=1).
func TestClickHouseMoveIn(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT"))
	if port == 0 || port2 == 0 {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT and ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	if err := CreateLoginWith(ctx, env, port2, "", "", true); err != nil {
		t.Fatal("login:", err)
	}
	src := newClient(serverURL(port), Login{User: "default"})
	tgt := newClient(serverURL(port2), Login{User: "default"})
	must(t, src, "DROP DATABASE IF EXISTS cloud SYNC")
	must(t, src, "CREATE DATABASE cloud")
	must(t, src, "CREATE TABLE cloud.events (id UInt64, v String) ENGINE = MergeTree ORDER BY id")
	must(t, src, "CREATE TABLE cloud.latest (id UInt64, ver UInt32) ENGINE = ReplacingMergeTree(ver) ORDER BY id")
	must(t, src, "CREATE VIEW cloud.recent AS SELECT * FROM cloud.events WHERE id > 100")
	must(t, src, "INSERT INTO cloud.events SELECT number, toString(number) FROM numbers(5000)")
	must(t, src, "INSERT INTO cloud.latest SELECT number, 1 FROM numbers(10)")
	spec := protocol.DatabaseSpec{ID: "db_target", Name: "target", Port: port2, Engine: protocol.EngineClickHouse}
	m := agent.MigrateEnv{ID: "mig1", Dir: filepath.Join(t.TempDir(), "mig1"), Progress: func(protocol.MigrationStatus) {}}
	phase := ""
	m.SetPhase = func(p string) { phase = p }
	tl := &testLog{t: t}
	run := func(typ string, p protocol.MigrateParams) any {
		t.Helper()
		p.MigrationID = m.ID
		m.Phase = phase
		res, err := e.Migrate(ctx, env, spec, m, typ, p, tl)
		if err != nil {
			t.Fatalf("%s %s: %v", typ, p.Action, err)
		}
		return res
	}
	key := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateKey}).(*protocol.MigrateKeyResult)
	pub, _ := e2e.ParsePublicKey(key.PublicKey)
	box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(m.ID), []byte("http://default:@127.0.0.1:"+strconv.Itoa(port)+"/cloud"))
	if err != nil {
		t.Fatal(err)
	}
	check := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: &box, TargetDB: "moved"}).(*protocol.MigrateCheckResult)
	t.Logf("check: %s %+v", check.Summary, check.Checks)
	if !check.DumpOK || check.LiveSync || check.Source.Tables != 3 {
		t.Fatalf("check: %+v", check)
	}
	browser, _ := e2e.GenerateKey()
	cp := run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump, TargetDB: "moved",
		BrowserKey: e2e.PublicKeyString(browser.PublicKey())}).(*protocol.MigrateCopyResult)
	t.Logf("copy: %s %+v", cp.Summary, cp.Switchover)
	if cp.Switchover == nil || cp.Switchover.Mismatches != 0 || len(cp.Warnings) != 0 || phase != protocol.MigratePhaseSwitched {
		t.Fatalf("copy: %+v", cp)
	}
	if n := count(t, tgt, "SELECT count() FROM moved.events"); n != 5000 {
		t.Fatalf("moved %d events", n)
	}
	if n := count(t, tgt, "SELECT count() FROM moved.recent"); n != 4899 {
		t.Fatalf("the view gives %d", n)
	}
	run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCancel, DropTarget: true})
	if n := count(t, tgt, "SELECT count() FROM system.databases WHERE name = 'moved'"); n != 0 {
		t.Fatal("cancel left the database")
	}
	must(t, src, "DROP DATABASE cloud SYNC")
}
