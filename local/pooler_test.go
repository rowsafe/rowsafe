package local

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestThroughPooler reads a database and applies a fix through a real
// PgBouncer in transaction mode (scripts/test-no-account-pooler.sh starts
// one; skips without it).
func TestThroughPooler(t *testing.T) {
	pooledURL, directURL := os.Getenv("ROWSAFE_TEST_POOLER_URL"), os.Getenv("ROWSAFE_TEST_DIRECT_URL")
	if pooledURL == "" || directURL == "" {
		t.Skip("no pooler: run scripts/test-no-account-pooler.sh")
	}
	ctx := t.Context()
	conn, err := pgx.Connect(ctx, directURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, sql := range []string{
		`DROP TABLE IF EXISTS orders`,
		`CREATE TABLE orders (id int PRIMARY KEY, customer int, note text) WITH (autovacuum_enabled = off)`,
		`CREATE INDEX orders_id_again ON orders (id)`,
		`INSERT INTO orders SELECT g, g % 1000, repeat('x', 50) FROM generate_series(1, 300000) g`,
		`DELETE FROM orders WHERE id % 3 <> 0`,
		`SELECT count(*) FROM orders WHERE customer = 7`,
		`SELECT pg_stat_force_next_flush()`,
	} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	pooled, err := Open(pooledURL)
	if err != nil {
		t.Fatal(err)
	}
	h, err := pooled.Health(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	vacuum := fixOf(h, "vacuum_behind", protocol.FixMaintenance)
	if vacuum == nil {
		t.Fatalf("no vacuum fix through the pooler: %+v", h.Findings)
	}
	if vacuum.Available || !strings.Contains(vacuum.Reason, "direct connection string") {
		t.Errorf("vacuum through the pooler: available %v, reason %q", vacuum.Available, vacuum.Reason)
	}
	if _, err := pooled.ApplyFix(ctx, "vacuum_behind", vacuum.ID, Options{}); err == nil || !strings.Contains(err.Error(), "not the pooler's") {
		t.Errorf("vacuum through the pooler ran: %v", err)
	}
	if _, err := pooled.Apply(ctx, protocol.FindingFix{ID: vacuum.ID, Kind: vacuum.Kind, Label: vacuum.Label, Params: vacuum.Params, Available: true}); err == nil {
		t.Error("a fix said available still runs through the pooler")
	}

	ins, err := pooled.Insights(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ins.Databases) != 1 || len(ins.LargestTables) == 0 || len(ins.DuplicateIndexes) == 0 || len(ins.Notes) > 0 {
		t.Errorf("insights through the pooler: %+v", ins)
	}
	st, err := pooled.Statements(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Available || len(st.Statements) == 0 {
		t.Errorf("top queries through the pooler: %+v", st)
	}
	if a, err := pooled.Activity(ctx); err != nil || a == nil {
		t.Errorf("activity through the pooler: %+v %v", a, err)
	}
	ov, err := pooled.Settings(ctx, Options{MemoryBytes: 4 << 30, CPUs: 2})
	if err != nil {
		t.Fatal(err)
	}
	if !ov.Available || len(ov.Settings) == 0 {
		t.Errorf("settings through the pooler: %+v", ov)
	}
	for _, s := range ov.Settings {
		if (s.Name == "statement_timeout" || s.Name == "lock_timeout") && s.Setting != "0" {
			t.Errorf("settings show Rowsafe's own %s: %s", s.Name, s.Setting)
		}
	}

	// Nothing stays behind on PgBouncer's server connections.
	plain, err := pgx.ParseConfig(pooledURL)
	if err != nil {
		t.Fatal(err)
	}
	plain.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	pc, err := pgx.ConnectConfig(ctx, plain)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close(ctx)
	for range 5 {
		var timeout, lock, ro string
		if err := pc.QueryRow(ctx, `SELECT current_setting('statement_timeout'), current_setting('lock_timeout'), current_setting('transaction_read_only')`).Scan(&timeout, &lock, &ro); err != nil {
			t.Fatal(err)
		}
		if timeout != "0" || lock != "0" || ro != "off" {
			t.Fatalf("left behind on a server connection: statement_timeout %s, lock_timeout %s, read only %s", timeout, lock, ro)
		}
	}
	// The same fix on the direct connection.
	direct, err := Open(directURL)
	if err != nil {
		t.Fatal(err)
	}
	h, err = direct.Health(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	vacuum = fixOf(h, "vacuum_behind", protocol.FixMaintenance)
	if vacuum == nil || !vacuum.Available {
		t.Fatalf("vacuum on the direct connection: %+v", vacuum)
	}
	res, err := direct.Apply(ctx, *vacuum)
	if err != nil || !strings.Contains(res.Summary, "Cleaned up 1 table") {
		t.Errorf("vacuum on the direct connection: %+v %v", res, err)
	}
}

func fixOf(h protocol.DatabaseHealth, finding, kind string) *protocol.FindingFix {
	for _, f := range h.Findings {
		if f.ID != finding {
			continue
		}
		for i := range f.Fixes {
			if f.Fixes[i].Kind == kind {
				return &f.Fixes[i]
			}
		}
	}
	return nil
}
