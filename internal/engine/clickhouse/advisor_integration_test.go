//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestClickHouseIndexAdvisor runs the index advisor against a real server
// (ROWSAFE_TEST_CLICKHOUSE_PORT): slow queries in the query log, ideas
// tested on a copy restored from a backup, then the fix that adds the
// skipping index, and dropping it.
func TestClickHouseIndexAdvisor(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	adminUser, adminPass := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD")
	admin := newClient(serverURL(port), Login{User: cmpOr(adminUser, "default"), Password: adminPass})
	admin.ua = "rowsafe-test"
	_ = admin.exec(ctx, "DROP USER IF EXISTS rowsafe", nil)
	if err := CreateLogin(ctx, env, port, adminUser, adminPass); err != nil {
		t.Skip("no SQL-made login here (users.d mode):", err)
	}
	db := protocol.DatabaseSpec{ID: "db_adv", Name: "adv", Stanza: "adv-ch", Port: port, RetentionFull: 2, Engine: protocol.EngineClickHouse}
	for _, q := range []string{
		"DROP DATABASE IF EXISTS adv SYNC",
		"CREATE DATABASE adv",
		// trace_id is unique and spread over the table: a bloom filter
		// finds the few granules that hold one.
		"CREATE TABLE adv.events (ts DateTime, trace_id String, user_id UInt64, kind LowCardinality(String), amount Float64) ENGINE = MergeTree ORDER BY ts SETTINGS index_granularity = 8192",
		"INSERT INTO adv.events SELECT toDateTime('2026-01-01 00:00:00') + number, hex(cityHash64(number)), number % 50000, ['a','b','c','d'][number % 4 + 1], number % 1000 FROM numbers(2000000)",
		// No sorting key at all.
		"CREATE TABLE adv.logs (at DateTime, account UInt64, msg String) ENGINE = MergeTree ORDER BY tuple()",
		"INSERT INTO adv.logs SELECT toDateTime('2026-01-01 00:00:00') + number, intDiv(number, 2000), concat('line ', toString(number)) FROM numbers(1000000)",
	} {
		must(t, admin, q)
	}
	trace := strings.TrimSpace(func() string {
		s, _ := admin.scalar(ctx, "SELECT hex(cityHash64(1234567))", nil)
		return s
	}())
	for range 3 {
		for _, q := range []string{
			"SELECT * FROM adv.events WHERE trace_id = '" + trace + "'",
			"SELECT kind, sum(amount), count() FROM adv.events GROUP BY kind",
			"SELECT count() FROM adv.logs WHERE account = 42",
		} {
			must(t, admin, q)
		}
	}
	must(t, admin, "SYSTEM FLUSH LOGS")
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal("backup:", err)
	}
	res, err := run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{})
	if err != nil {
		t.Fatal("advisor:", err)
	}
	t.Logf("advisor: %s (statements %d, analyzed %d, tested %d, copy %.0fs)", res.Summary, res.Statements, res.Analyzed, res.Tested, res.CopySeconds)
	var skip, proj *protocol.IndexRecommendation
	for i, r := range res.Recommendations {
		t.Logf("recommended: %s %.1fx %s, %d statements, rows %d -> %d", r.Spec.Kind, r.Speedup, r.Spec.ClickHouseDefinition(), len(r.Statements),
			r.Statements[0].RowsBefore, r.Statements[0].RowsAfter)
		switch {
		case r.Spec.Kind == protocol.IndexKindSkip && r.Spec.Table == "events" && r.Spec.Columns[0] == "trace_id":
			skip = &res.Recommendations[i]
		case r.Spec.Kind == protocol.IndexKindProjection && r.Spec.Table == "events" && len(r.Spec.Aggregates) > 0:
			proj = &res.Recommendations[i]
		}
	}
	for _, r := range res.Rejected {
		t.Logf("rejected: %s: %s", describeSpec(r.Spec), r.Reason)
	}
	if skip == nil || proj == nil {
		t.Fatalf("want a skipping index on events.trace_id and an aggregating projection; got %d recommendations", len(res.Recommendations))
	}
	if skip.Spec.Type != "bloom_filter(0.01)" || skip.Statements[0].RowsAfter*2 > skip.Statements[0].RowsBefore || skip.SizeBytes == 0 {
		t.Errorf("skip index: %+v", skip)
	}
	foundOrder := false
	for _, k := range res.Generated {
		foundOrder = foundOrder || strings.Contains(k, "kind:order_by") && strings.Contains(k, "logs")
	}
	if !foundOrder {
		t.Errorf("no sorting key advice for adv.logs: %v", res.Generated)
	}
	// Known ideas aren't tested again.
	again, err := run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{Known: res.Generated})
	if err != nil || again.Tested != 0 || len(again.Unchanged) != len(res.Generated) {
		t.Errorf("second run: tested %d, unchanged %d of %d: %v", again.Tested, len(again.Unchanged), len(res.Generated), err)
	}

	// The fix: add the skipping index and the projection on production.
	for _, r := range []*protocol.IndexRecommendation{skip, proj} {
		mr, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintCreateIndex,
			DB: "adv", CreateIndex: &protocol.CreateIndexParams{IndexSpec: r.Spec, EstimatedBytes: r.SizeBytes}})
		if err != nil {
			t.Fatal("create:", err)
		}
		t.Log(mr.Summary)
	}
	if n := count(t, admin, "SELECT count() FROM system.data_skipping_indices WHERE database = 'adv' AND name = '"+skip.Spec.Name+"'"); n != 1 {
		t.Fatalf("skipping index not on production")
	}
	if n := count(t, admin, "SELECT count() FROM system.mutations WHERE database = 'adv' AND NOT is_done"); n != 0 {
		t.Errorf("%d builds not done", n)
	}
	// Usage of what Rowsafe created.
	must(t, admin, "SELECT kind, sum(amount), count() FROM adv.events GROUP BY kind")
	must(t, admin, "SELECT * FROM adv.events WHERE trace_id = '"+trace+"'")
	must(t, admin, "SYSTEM FLUSH LOGS")
	u, err := run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{Known: res.Generated,
		Track: []protocol.TrackedIndex{{DB: "adv", Schema: "adv", Index: skip.Spec.Name}, {DB: "adv", Schema: "adv", Index: proj.Spec.Name}}})
	if err != nil || len(u.Usage) != 2 {
		t.Fatalf("usage: %v %+v", err, u)
	}
	for _, x := range u.Usage {
		t.Logf("usage %s: exists %v, %d uses, %d bytes", x.Index, x.Exists, x.Scans, x.SizeBytes)
		if !x.Exists || x.Scans == 0 {
			t.Errorf("usage of %s: %+v", x.Index, x)
		}
	}
	// Dropping it (refused while used, with Unused).
	if _, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintDropIndex,
		DB: "adv", Tables: []string{"events"}, Index: "adv." + proj.Spec.Name, Unused: true}); err == nil {
		t.Error("dropping a used projection as unused worked")
	}
	for _, name := range []string{skip.Spec.Name, proj.Spec.Name} {
		mr, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintDropIndex,
			DB: "adv", Tables: []string{"events"}, Index: "adv." + name})
		if err != nil {
			t.Fatal("drop:", err)
		}
		t.Log(mr.Summary)
	}
	if n := count(t, admin, "SELECT count() FROM system.data_skipping_indices WHERE database = 'adv'"); n != 0 {
		t.Errorf("skipping index still there")
	}
	// A build cancelled from Pulse removes what was added.
	mr, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintKillMutation,
		DB: "adv", Tables: []string{"events"}, MutationID: "mutation_missing.txt"})
	if err != nil || !strings.Contains(mr.Summary, "nothing to cancel") {
		t.Errorf("kill of a missing mutation: %v %+v", err, mr)
	}
	if s, ok := rowsafeBuild("adv", "events", "(MATERIALIZE INDEX "+skip.Spec.Name+")"); !ok || s.Name != skip.Spec.Name {
		t.Errorf("rowsafeBuild: %+v %v", s, ok)
	}
	must(t, admin, "DROP DATABASE adv SYNC")
}
