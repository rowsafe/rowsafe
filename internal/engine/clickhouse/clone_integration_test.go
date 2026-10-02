//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestClickHouseClone restores a backup of one server into a second, empty
// one (a clone), as of the backup picked. scripts/test-clickhouse.sh with
// CLICKHOUSE_CLONE=1 starts the second server.
func TestClickHouseClone(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT"))
	if port == 0 || port2 == 0 {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT and ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.Start(sctx, env)
	admin := newClient(serverURL(port), Login{User: "default"})
	admin.ua = "rowsafe-test"
	admin2 := newClient(serverURL(port2), Login{User: "default"})
	admin2.ua = "rowsafe-test"
	if err := CreateLoginWith(ctx, env, port, "", "", false); err != nil {
		t.Fatal("login:", err)
	}
	// The second server can't take a clone until its login may create databases.
	if err := CreateLoginWith(ctx, env, port2, "", "", false); err != nil {
		t.Fatal("login 2:", err)
	}
	c2, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: port2})
	if err != nil {
		t.Fatal(err)
	}
	in2, err := inspect(ctx, c2)
	if err != nil {
		t.Fatal(err)
	}
	if r := cloneTargetReason(in2); !strings.Contains(r, "may not create") {
		t.Fatalf("a login without clone rights: %q", r)
	}
	if err := CreateLoginWith(ctx, env, port2, "", "", true); err != nil {
		t.Fatal("login 2 with clones:", err)
	}

	must(t, admin, "DROP DATABASE IF EXISTS shop SYNC")
	must(t, admin, "CREATE DATABASE shop")
	must(t, admin, "CREATE TABLE shop.orders (id UInt64, note String) ENGINE = MergeTree ORDER BY id")
	must(t, admin, "INSERT INTO shop.orders SELECT number, 'x' FROM numbers(100)")
	spec := protocol.DatabaseSpec{ID: "db_ch_clone", Name: "shop", Stanza: "shop", Port: port, Engine: protocol.EngineClickHouse, RetentionFull: 2}
	if _, err := run[protocol.AdoptResult](t, e, env, spec, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal("adopt:", err)
	}
	full, err := run[protocol.BackupResult](t, e, env, spec, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil {
		t.Fatal("backup:", err)
	}
	must(t, admin, "INSERT INTO shop.orders SELECT number + 100, 'y' FROM numbers(50)")
	if _, err := run[protocol.BackupResult](t, e, env, spec, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff}); err != nil {
		t.Fatal("diff:", err)
	}

	targets := e.StandbyTargets(ctx, env)
	t.Logf("targets: %+v", targets)

	major, size, _, err := e.ForkFacts(ctx, env, spec)
	if err != nil || major == 0 {
		t.Fatalf("facts: %d %v", major, err)
	}
	tl := &testLog{t: t}
	res, err := e.ForkRestore(ctx, env, protocol.ForkRestoreParams{ForkID: "fork_ch", Name: "shop-staging", Source: spec,
		Target: protocol.RewindTarget{BackupSet: full.Label}, Placement: protocol.ForkEmptyServer, Port: port2, Major: major, SizeBytes: size}, tl)
	if err != nil {
		t.Fatal("clone:", err)
	}
	t.Logf("clone: %+v", res)
	if n := count(t, admin2, "SELECT count() FROM shop.orders"); n != 100 {
		t.Fatalf("the clone has %d rows, want 100 (as of the full backup)", n)
	}
	// Merges run on a clone (it is a real server, not a copy).
	must(t, admin2, "INSERT INTO shop.orders VALUES (1000, 'z')")
	must(t, admin2, "OPTIMIZE TABLE shop.orders FINAL")
	if res.RecoveredTo == nil || len(res.Databases) != 1 || time.Since(*res.RecoveredTo) > time.Hour {
		t.Fatalf("result: %+v", res)
	}
	// Not empty any more: a second clone is refused.
	if _, err := e.ForkRestore(ctx, env, protocol.ForkRestoreParams{ForkID: "fork_ch2", Name: "x", Source: spec,
		Target: protocol.RewindTarget{BackupSet: full.Label}, Placement: protocol.ForkEmptyServer, Port: port2}, tl); err == nil ||
		!strings.Contains(err.Error(), "isn't empty") {
		t.Fatalf("second clone: %v", err)
	}
	must(t, admin2, "DROP DATABASE shop SYNC")
}
