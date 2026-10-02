//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestClickHouseInPlace rewinds a real server's tables in place to a
// backup, undoes it and deletes what was kept.
func TestClickHouseInPlace(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 || os.Getenv("ROWSAFE_TEST_CLICKHOUSE_USERSD") != "" {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT not set, or a users.d login (made by TestClickHouseEndToEnd)")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.Start(sctx, env)
	adminUser, adminPass := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD")
	admin := newClient(serverURL(port), Login{User: cmpOr(adminUser, "default"), Password: adminPass})
	admin.ua = "rowsafe-test"
	if err := CreateLogin(ctx, env, port, adminUser, adminPass); err != nil {
		t.Fatal("CreateLogin:", err)
	}
	db := protocol.DatabaseSpec{ID: "db_chip", Name: "ev", Stanza: "ev-ch", Port: port, RetentionFull: 2, Engine: protocol.EngineClickHouse}
	for _, q := range []string{
		"DROP DATABASE IF EXISTS rw SYNC",
		"CREATE DATABASE rw",
		"CREATE TABLE rw.events (ts DateTime, k UInt32, v UInt64) ENGINE = MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (k, ts)",
		"CREATE TABLE rw.totals (k UInt32, n UInt64) ENGINE = SummingMergeTree ORDER BY k",
		"CREATE MATERIALIZED VIEW rw.to_totals TO rw.totals AS SELECT k, count() AS n FROM rw.events GROUP BY k",
		"CREATE MATERIALIZED VIEW rw.sums ENGINE = SummingMergeTree ORDER BY k AS SELECT k, sum(v) AS s FROM rw.events GROUP BY k",
		"CREATE TABLE rw.lg (x UInt32) ENGINE = Log",
		"CREATE TABLE rw.gone (x UInt32) ENGINE = MergeTree ORDER BY x",
		"INSERT INTO rw.events SELECT toDateTime('2026-01-01 00:00:00') + number, number % 10, number FROM numbers(1000)",
		"INSERT INTO rw.lg VALUES (1), (2)",
		"INSERT INTO rw.gone VALUES (7)",
	} {
		must(t, admin, q)
	}
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	b1, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil {
		t.Fatal(err)
	}
	// After the backup: a new day, more rows, a dropped table, a new one.
	for _, q := range []string{
		"INSERT INTO rw.events SELECT toDateTime('2026-01-02 00:00:00') + number, number % 10, 1 FROM numbers(500)",
		"INSERT INTO rw.events SELECT toDateTime('2026-01-01 12:00:00'), 3, 1000000",
		"INSERT INTO rw.lg VALUES (3)",
		"DROP TABLE rw.gone SYNC",
		"CREATE TABLE rw.newt (x UInt32) ENGINE = MergeTree ORDER BY x",
		"INSERT INTO rw.newt VALUES (1), (2), (3)",
	} {
		must(t, admin, q)
	}
	state := func() string {
		t.Helper()
		var out []string
		for _, q := range []string{"SELECT count() FROM rw.events", "SELECT sum(n) FROM rw.totals", "SELECT sum(s) FROM rw.sums",
			"SELECT count() FROM rw.lg", "SELECT count() FROM system.tables WHERE database = 'rw' AND name = 'gone'",
			"SELECT count() FROM rw.newt"} {
			out = append(out, strconv.FormatInt(count(t, admin, q), 10))
		}
		return joinComma(out)
	}
	before := state()
	if before != "1501,1501,1500000,3,0,3" {
		t.Fatalf("before: %s", before)
	}

	res, err := run[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
		protocol.RewindInPlaceParams{RewindID: "rwd_ch1", Target: protocol.RewindTarget{BackupSet: b1.Label}, KeepDays: 7})
	if err != nil {
		t.Fatal("rewind:", err)
	}
	if got := state(); got != "1000,1000,499500,2,1,0" {
		t.Fatalf("after the rewind: %s (%+v)", got, res)
	}
	// The views still feed the same tables.
	must(t, admin, "INSERT INTO rw.events VALUES ('2026-01-01 00:00:00', 1, 5)")
	if got := state(); got != "1001,1001,499505,2,1,0" {
		t.Fatalf("an insert after the rewind: %s", got)
	}
	if st := e.RewindStates(env); len(st) != 1 || st[0].Status != protocol.RewindKeptBefore {
		t.Fatalf("states %+v", st)
	}
	// Kept data is never backed up.
	in, err := inspect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range in.Databases {
		if isRewindDB(d.Name) {
			t.Fatalf("a rewind's database is in the backup list: %s", d.Name)
		}
	}

	if _, err := run[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "rwd_ch1"}); err != nil {
		t.Fatal("undo:", err)
	}
	if got := state(); got != before {
		t.Fatalf("after the undo: %s, want %s", got, before)
	}
	if st := e.RewindStates(env); len(st) != 1 || st[0].Status != protocol.RewindKeptAfterUndo {
		t.Fatalf("states after undo %+v", st)
	}
	if _, err := run[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rwd_ch1"}); err != nil {
		t.Fatal(err)
	}
	if n := count(t, admin, "SELECT count() FROM system.databases WHERE name LIKE 'rowsafe\\_%'"); n != 0 {
		t.Fatalf("%d rowsafe databases left", n)
	}
	time.Sleep(10 * time.Millisecond)
}

func joinComma(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}
