//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestClickHousePointInTime: changes after a backup (inserts, merges,
// mutations, lightweight deletes, TRUNCATE, new, altered and dropped
// tables) are copied as they happen, and copies, rewinds in place and Proof
// bring back the server exactly as it was at moments between them. The
// test user must be able to read ClickHouse's data folder (the clickhouse
// group).
func TestClickHousePointInTime(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 || os.Getenv("ROWSAFE_TEST_CLICKHOUSE_USERSD") != "" {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT not set, or a users.d login (made by TestClickHouseEndToEnd)")
	}
	t.Setenv("ROWSAFE_CLICKHOUSE_ARCHIVE_INTERVAL", "2s")
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
	db := protocol.DatabaseSpec{ID: "db_pit", Name: "pit", Stanza: "pit-ch", Port: port, RetentionFull: 2, Engine: protocol.EngineClickHouse}
	for _, q := range []string{
		"DROP DATABASE IF EXISTS pit SYNC",
		"DROP DATABASE IF EXISTS `pit-2` SYNC",
		"CREATE DATABASE pit",
		"CREATE TABLE pit.ev (ts DateTime, k UInt32, v UInt64) ENGINE = MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (k, ts)",
		"CREATE TABLE pit.`my-prices` (sku UInt32, price Float64, ver UInt32) ENGINE = ReplacingMergeTree(ver) ORDER BY sku",
		"CREATE MATERIALIZED VIEW pit.sums ENGINE = SummingMergeTree ORDER BY k AS SELECT k, sum(v) AS s FROM pit.ev GROUP BY k",
		"CREATE TABLE pit.lg (x UInt32) ENGINE = Log",
		"INSERT INTO pit.ev SELECT toDateTime('2026-01-01 00:00:00') + number, number % 10, number FROM numbers(1000)",
		"INSERT INTO pit.`my-prices` SELECT number, number * 1.5, 1 FROM numbers(50)",
		"INSERT INTO pit.lg VALUES (1), (2)",
	} {
		must(t, admin, q)
	}
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	// The copier starts with the heartbeat; changes are recorded from here.
	if st, err := e.Archiver(ctx, env, db); err != nil || st == nil {
		t.Fatalf("archiver: %+v %v", st, err)
	}
	waitRecord(t, e, db)
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}

	// A moment is taken after each step; what each table holds then is what
	// a restore to that moment must give back.
	type moment struct {
		at   time.Time
		want map[string]string
	}
	probes := map[string]string{
		"ev":     "SELECT count(), sum(v) FROM pit.ev",
		"prices": "SELECT count(), sum(price) FROM pit.`my-prices` FINAL",
		"sums":   "SELECT sum(s) FROM pit.sums",
		"new":    "SELECT count() FROM system.tables WHERE database = 'pit' AND name = 'fresh'",
		"fresh":  "SELECT if(count() = 0, '-', toString(count())) FROM system.tables WHERE database = 'pit' AND name = 'fresh'",
		"cols":   "SELECT count() FROM system.columns WHERE database = 'pit' AND table = 'ev'",
		"db2":    "SELECT count() FROM system.databases WHERE name = 'pit-2'",
	}
	snap := func(c *client) map[string]string {
		out := map[string]string{}
		for k, q := range probes {
			v, err := c.scalar(ctx, q, nil)
			if err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			out[k] = v
		}
		if out["new"] == "1" {
			v, _ := c.scalar(ctx, "SELECT count() FROM pit.fresh", nil)
			out["fresh"] = v
		}
		return out
	}
	var moments []moment
	take := func(what string) {
		time.Sleep(1100 * time.Millisecond)
		now, err := serverNow(ctx, admin)
		if err != nil {
			t.Fatal(err)
		}
		m := moment{at: now, want: snap(admin)}
		t.Logf("moment %d (%s) at %s: %v", len(moments), what, now.Format(time.RFC3339Nano), m.want)
		moments = append(moments, m)
		time.Sleep(1100 * time.Millisecond)
	}
	steps := []struct {
		what string
		qs   []string
	}{
		{"inserts", []string{
			"INSERT INTO pit.ev SELECT toDateTime('2026-01-02 00:00:00') + number, number % 10, 1 FROM numbers(500)",
			"INSERT INTO pit.ev SELECT toDateTime('2026-01-02 00:00:00') + number, 3, 7 FROM numbers(20)",
			"INSERT INTO pit.`my-prices` SELECT number, 99, 2 FROM numbers(10)",
		}},
		{"a merge", []string{
			"INSERT INTO pit.ev SELECT toDateTime('2026-01-02 06:00:00') + number, 4, 2 FROM numbers(30)",
			"OPTIMIZE TABLE pit.ev FINAL",
			"OPTIMIZE TABLE pit.`my-prices` FINAL",
		}},
		{"a mutation and a lightweight delete", []string{
			"ALTER TABLE pit.ev UPDATE v = v + 1 WHERE k = 5 SETTINGS mutations_sync = 2",
			"DELETE FROM pit.ev WHERE k = 6",
		}},
		{"new table, new database, new column", []string{
			"CREATE TABLE pit.fresh (id UInt64) ENGINE = MergeTree ORDER BY id",
			"INSERT INTO pit.fresh SELECT number FROM numbers(77)",
			"CREATE DATABASE `pit-2`",
			"ALTER TABLE pit.ev ADD COLUMN note String DEFAULT 'n'",
			"INSERT INTO pit.ev (ts, k, v, note) VALUES ('2026-01-03 00:00:00', 1, 5, 'x')",
		}},
		{"truncate and drop", []string{
			"TRUNCATE TABLE pit.`my-prices`",
			"DROP TABLE pit.fresh SYNC",
			"ALTER TABLE pit.ev DROP PARTITION 20260101",
		}},
	}
	for _, s := range steps {
		for _, q := range s.qs {
			must(t, admin, q)
		}
		take(s.what)
	}

	// What the record holds.
	if now, err := serverNow(ctx, admin); err == nil {
		e.flushTo(ctx, env, db, now, &testLog{t: t})
	}
	if r, err := openRepo(env, db); err == nil {
		refs, _ := r.listLogs(ctx)
		for _, ref := range refs {
			var l pitLog
			if err := r.getJSON(ctx, ref.Key, &l); err != nil {
				t.Fatal(err)
			}
			for _, ev := range l.Events {
				what := ev.Table
				if ev.Part != nil {
					what += " " + ev.Part.Name + fmt.Sprintf(" files=%d", len(ev.Part.Files))
				}
				if ev.Def != nil {
					what += " " + ev.Def.Name
				}
				if ev.DB != nil {
					what += " db " + ev.DB.Name
				}
				t.Logf("log %s..%s: %s %s %s", l.From.Format("15:04:05.000000"), l.To.Format("15:04:05.000000"), ev.At.Format("15:04:05.000000"), ev.Kind, what)
			}
		}
	}

	// Copies at every moment.
	for i, m := range moments {
		at := m.at
		id := fmt.Sprintf("pit%d", i)
		cp, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
			protocol.RewindCopyParams{CopyID: id, Target: protocol.RewindTarget{Time: &at}})
		if err != nil {
			t.Fatalf("copy at moment %d: %v", i, err)
		}
		if cp.RecoveredTo == nil || !cp.RecoveredTo.Equal(at) {
			t.Fatalf("copy at moment %d recovered to %v, want %v (exact)", i, cp.RecoveredTo, at)
		}
		cc, _ := scratchAt(filepath.Join(copyRoot(env), id)).client()
		got := snap(cc)
		for k, v := range m.want {
			if got[k] != v {
				t.Errorf("copy at moment %d: %s = %s, want %s", i, k, got[k], v)
			}
		}
		if _, err := run[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: id}); err != nil {
			t.Fatal(err)
		}
	}
	if t.Failed() {
		return
	}

	// Proof restores the newest moment.
	dr, err := run[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if err != nil || dr == nil || !dr.Passed {
		t.Fatalf("Proof: %+v %v", dr, err)
	}

	// Rewind in place to the moment after the merge.
	target := moments[1].at
	res, err := run[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
		protocol.RewindInPlaceParams{RewindID: "rwpit", Target: protocol.RewindTarget{Time: &target}, KeepDays: 1})
	if err != nil {
		t.Fatalf("rewind in place: %v", err)
	}
	t.Log(res.Summary)
	got := snap(admin)
	for _, k := range []string{"ev", "prices", "sums", "cols"} {
		if got[k] != moments[1].want[k] {
			t.Errorf("after the rewind in place: %s = %s, want %s", k, got[k], moments[1].want[k])
		}
	}
	if _, err := run[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rwpit"}); err != nil {
		t.Log("cleanup:", err)
	}
}

// waitRecord waits until the copier has started its record.
func waitRecord(t *testing.T, e *Engine, db protocol.DatabaseSpec) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		e.mu.Lock()
		s := e.shippers[db.ID]
		e.mu.Unlock()
		if s != nil {
			if st, err := s.snapshot(); st.Record != "" {
				return
			} else if err != nil {
				t.Logf("copier: %v", err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatal("the copier never started its record")
}
