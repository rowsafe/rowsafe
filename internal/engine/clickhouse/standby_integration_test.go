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

// TestClickHouseStandby: a second, empty server follows the first through
// the bucket (inserts, merges, mutations, lightweight deletes, TRUNCATE,
// new, altered and dropped tables), is read-only, and takes over when the
// first is fenced and the standby promoted.
func TestClickHouseStandby(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT"))
	if port == 0 || port2 == 0 {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT and ROWSAFE_TEST_CLICKHOUSE_CLONE_PORT not set")
	}
	t.Setenv("ROWSAFE_CLICKHOUSE_ARCHIVE_INTERVAL", "2s")
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
	if err := CreateLoginWith(ctx, env, port2, "", "", true); err != nil {
		t.Fatal("login 2:", err)
	}
	for _, q := range []string{
		"DROP DATABASE IF EXISTS sb SYNC",
		"CREATE DATABASE sb",
		"CREATE TABLE sb.ev (ts DateTime, k UInt32, v UInt64) ENGINE = MergeTree PARTITION BY toYYYYMMDD(ts) ORDER BY (k, ts)",
		"CREATE TABLE sb.gone (x UInt32) ENGINE = MergeTree ORDER BY x",
		"CREATE MATERIALIZED VIEW sb.sums ENGINE = SummingMergeTree ORDER BY k AS SELECT k, sum(v) AS s FROM sb.ev GROUP BY k",
		"INSERT INTO sb.ev SELECT toDateTime('2026-01-01 00:00:00') + number, number % 10, number FROM numbers(1000)",
		"INSERT INTO sb.gone VALUES (1), (2)",
		"SYSTEM FLUSH LOGS",
	} {
		must(t, admin, q)
	}
	spec := protocol.DatabaseSpec{ID: "db_ch_sb", Name: "sb", Stanza: "sb", Port: port, Engine: protocol.EngineClickHouse, RetentionFull: 2}
	if _, err := run[protocol.AdoptResult](t, e, env, spec, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal("adopt:", err)
	}
	if _, err := e.Archiver(ctx, env, spec); err != nil {
		t.Fatal(err)
	}
	waitRecord(t, e, spec)
	if _, err := run[protocol.BackupResult](t, e, env, spec, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal("backup:", err)
	}
	tl := &testLog{t: t}
	var sec protocol.StandbySecrets
	var prep protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, env, spec, protocol.StandbyPrepareParams{StandbyID: "sb1"}, &sec, &prep, tl); err != nil {
		t.Fatal("prepare:", err)
	}
	flush := func() {
		now, err := serverNow(ctx, admin)
		if err != nil {
			t.Fatal(err)
		}
		e.flushTo(ctx, env, spec, now, tl)
	}
	flush()
	sbSpec := spec
	sbSpec.Port = port2
	cr, err := e.StandbyCreate(ctx, env, sbSpec, protocol.StandbyCreateParams{StandbyID: "sb1", Port: port2, Major: prep.Major, SystemID: prep.SystemID}, sec, tl)
	if err != nil {
		t.Fatal("create:", err)
	}
	t.Log(cr.Summary)

	probes := []string{
		"SELECT count(), sum(v) FROM sb.ev",
		"SELECT sum(s) FROM sb.sums",
		"SELECT count() FROM system.tables WHERE database = 'sb' AND name = 'fresh'",
		"SELECT count() FROM system.columns WHERE database = 'sb' AND table = 'ev'",
		"SELECT count() FROM system.tables WHERE database = 'sb' AND name = 'gone'",
	}
	snap := func(c *client) []string {
		var out []string
		for _, q := range probes {
			v, err := c.scalar(ctx, q, nil)
			if err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			out = append(out, v)
		}
		if n, _ := c.scalar(ctx, "SELECT count() FROM system.tables WHERE database = 'sb' AND name = 'fresh'", nil); strings.TrimSpace(n) == "1" {
			v, _ := c.scalar(ctx, "SELECT count() FROM sb.fresh", nil)
			out = append(out, v)
		}
		return out
	}
	same := func(what string) {
		t.Helper()
		flush()
		e.applyStandby(ctx, env, "sb1")
		if r, _ := e.standbyStore(env).get("sb1"); r.Error != "" {
			t.Fatalf("%s: applying: %s", what, r.Error)
		}
		a, b := snap(admin), snap(admin2)
		if strings.Join(a, "|") != strings.Join(b, "|") {
			t.Fatalf("%s: the standby has %q, the primary %q", what, b, a)
		}
		t.Logf("%s: standby = primary %q", what, a)
	}
	same("created")

	// Read-only for everyone but Rowsafe.
	if err := admin2.exec(ctx, "INSERT INTO sb.ev (ts, k, v) VALUES ('2026-01-09 00:00:00', 1, 1)", nil); err == nil {
		t.Fatal("the standby took a write")
	}
	steps := []struct {
		what string
		qs   []string
	}{
		{"inserts", []string{
			"INSERT INTO sb.ev SELECT toDateTime('2026-01-02 00:00:00') + number, number % 10, 1 FROM numbers(500)",
			"INSERT INTO sb.ev SELECT toDateTime('2026-01-02 00:00:00') + number, 3, 7 FROM numbers(20)",
		}},
		{"a merge", []string{"OPTIMIZE TABLE sb.ev FINAL"}},
		{"mutations", []string{
			"ALTER TABLE sb.ev UPDATE v = v + 1 WHERE k = 5 SETTINGS mutations_sync = 2",
			"DELETE FROM sb.ev WHERE k = 6",
		}},
		{"tables", []string{
			"CREATE TABLE sb.fresh (id UInt64) ENGINE = MergeTree ORDER BY id",
			"INSERT INTO sb.fresh SELECT number FROM numbers(77)",
			"ALTER TABLE sb.ev ADD COLUMN note String DEFAULT 'n'",
			"INSERT INTO sb.ev (ts, k, v, note) VALUES ('2026-01-03 00:00:00', 1, 5, 'x')",
			"DROP TABLE sb.gone SYNC",
		}},
		{"truncate", []string{"ALTER TABLE sb.ev DROP PARTITION 20260101", "TRUNCATE TABLE sb.fresh"}},
	}
	for _, s := range steps {
		for _, q := range s.qs {
			must(t, admin, q)
		}
		time.Sleep(1100 * time.Millisecond)
		same(s.what)
	}
	states := e.StandbyStates(ctx, env)
	if len(states) != 1 || !states[0].InRecovery || !states[0].Running || states[0].LastReplayAt == nil {
		t.Fatalf("states: %+v", states)
	}

	// Switch over: fence the primary, promote the standby.
	must(t, admin, "INSERT INTO sb.ev (ts, k, v) VALUES ('2026-01-04 00:00:00', 2, 9)")
	fr, err := e.StandbyFence(ctx, env, spec, protocol.StandbyFenceParams{FenceID: "f1", StandbyID: "sb1", SystemID: prep.SystemID}, tl)
	if err != nil {
		t.Fatal("fence:", err)
	}
	defer func() { _, _ = e.StandbyUnfence(ctx, env, spec, protocol.Fence{ID: "f1", Port: port}, tl) }()
	if err := admin.exec(ctx, "INSERT INTO sb.ev (ts, k, v) VALUES ('2026-01-09 00:00:00', 1, 1)", nil); err == nil {
		t.Fatal("the fenced primary took a write")
	}
	if enforced, other, err := e.HoldFence(ctx, env, protocol.Fence{ID: "f1", Port: port, SystemID: prep.SystemID}); enforced || other || err != nil {
		t.Fatalf("hold fence: %v %v %v", enforced, other, err)
	}
	pr, err := e.StandbyPromote(ctx, env, sbSpec, protocol.StandbyPromoteParams{StandbyID: "sb1", WaitForLSN: fr.CheckpointLSN}, tl)
	if err != nil || !pr.Promoted || !pr.CaughtUp {
		t.Fatalf("promote: %+v %v", pr, err)
	}
	if a, b := snap(admin), snap(admin2); strings.Join(a, "|") != strings.Join(b, "|") {
		t.Fatalf("after the promotion: the new primary has %q, the old one %q", b, a)
	}
	must(t, admin2, "INSERT INTO sb.ev (ts, k, v) VALUES ('2026-01-09 00:00:00', 1, 1)")
	if len(e.StandbyStates(ctx, env)) != 0 {
		t.Fatal("the promoted standby is still reported")
	}
	must(t, admin2, "DROP DATABASE sb SYNC")
}
