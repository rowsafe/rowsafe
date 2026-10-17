package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestHypoIndexStatement(t *testing.T) {
	s := protocol.IndexSpec{Schema: "Shop", Table: "orders", Columns: []string{"customer_id", "created_at"}, Descending: []string{"created_at"},
		Include: []string{"total"}, WhereNull: []string{"deleted_at"}}
	want := `CREATE INDEX ON "Shop"."orders" ("customer_id", "created_at" DESC) INCLUDE ("total") WHERE "deleted_at" IS NULL`
	if got := hypoIndexStatement(s); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestAdvisorSummaryHypothetical(t *testing.T) {
	r := &protocol.IndexAdvisorResult{Statements: 12, Hypothetical: 5, Generated: []string{"a"},
		Recommendations: []protocol.IndexRecommendation{{Method: protocol.IndexMethodHypothetical}},
		Skipped:         "There isn't enough free disk for a copy."}
	if s := advisorSummary(r); !strings.Contains(s, "checked 5 index ideas with hypothetical indexes, without a copy: 1 is worth adding.") ||
		!strings.Contains(s, "enough free disk") {
		t.Errorf("summary: %s", s)
	}
}

// TestIndexAdvisorHypoPG runs the advisor with a stand-in for hypopg: the
// developer's PostgreSQL usually lacks the extension, so functions of the
// same names build real indexes (the advisor's read-only session is off for
// it). It checks the flow: ideas planned with "hypothetical" indexes first,
// only those the planner uses go to the copy, and without a copy they are
// recommended as checked without one.
func TestIndexAdvisorHypoPG(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	e := newFixEnv(t)
	e.exec(`CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id int NOT NULL, status text NOT NULL, created_at timestamptz NOT NULL)`)
	e.exec(`INSERT INTO orders (customer_id, status, created_at)
		SELECT (random() * 20000)::int, (ARRAY['new','paid','shipped'])[1 + (g % 3)], now() - (g || ' seconds')::interval
		FROM generate_series(1, 300000) g`)
	e.exec(`ANALYZE orders`)
	e.exec(`CREATE SCHEMA fakehypo`)
	e.exec(`CREATE SEQUENCE fakehypo.n`)
	e.exec(`CREATE FUNCTION fakehypo.hypopg_reset() RETURNS void LANGUAGE plpgsql AS $$
		DECLARE r record;
		BEGIN
		  FOR r IN SELECT c.oid FROM pg_class c WHERE c.relname LIKE 'fakehypo\_%' AND c.relkind = 'i' LOOP
		    EXECUTE 'DROP INDEX ' || r.oid::regclass;
		  END LOOP;
		END $$`)
	e.exec(`CREATE FUNCTION fakehypo.hypopg_create_index(stmt text, OUT indexrelid oid, OUT indexname text) LANGUAGE plpgsql AS $$
		BEGIN
		  indexname := 'fakehypo_' || nextval('fakehypo.n');
		  EXECUTE replace(stmt, 'CREATE INDEX ON', 'CREATE INDEX ' || indexname || ' ON');
		  indexrelid := indexname::regclass::oid;
		END $$`)
	e.exec(`CREATE FUNCTION fakehypo.hypopg_relation_size(oid) RETURNS bigint LANGUAGE sql AS $$ SELECT pg_relation_size($1) $$`)
	e.exec(`CREATE FUNCTION fakehypo.hypopg_drop_index(oid) RETURNS bool LANGUAGE plpgsql AS $$
		BEGIN EXECUTE 'DROP INDEX ' || $1::regclass; RETURN true; END $$`)

	oldParser, oldRead, oldSchema, oldRO := shapeParser, readAdvisorStatements, hypoSchema, hypoReadOnly
	t.Cleanup(func() {
		shapeParser, readAdvisorStatements, hypoSchema, hypoReadOnly = oldParser, oldRead, oldSchema, oldRO
		advisorTestCopy, advisorTestNoCopy = nil, ""
	})
	shapeParser = inProcessShapes
	hypoReadOnly = false
	hypoSchema = func(ctx context.Context, conn *pgx.Conn) (string, error) { return "fakehypo", nil }
	texts := map[string]string{
		"201": "SELECT id, status FROM orders WHERE customer_id = $1",
		"202": "SELECT count(*) FROM orders WHERE status = $1",
	}
	readAdvisorStatements = func(_ context.Context, _ pginspect.Target, p protocol.IndexAdvisorParams, _ *taskLog) ([]advisorStatement, error) {
		var out []advisorStatement
		for _, s := range p.Statements {
			out = append(out, advisorStatement{Statement: indexadvisor.Statement{QueryID: s.QueryID, DB: e.db,
				Calls: s.Calls, TotalTimeMs: s.TotalTimeMs, Rows: s.Rows}, text: texts[s.QueryID]})
		}
		return out, nil
	}
	params := protocol.IndexAdvisorParams{Statements: []protocol.AdvisorStatement{
		{QueryID: "201", Calls: 50_000, TotalTimeMs: 4_000_000, Rows: 50_000},
		{QueryID: "202", Calls: 100, TotalTimeMs: 20_000, Rows: 100},
	}}
	run := func() *protocol.IndexAdvisorResult {
		t.Helper()
		tl := &taskLog{}
		res, err := e.a.indexAdvisor(t.Context(), e.spec, "task_hypo", params, tl)
		if err != nil {
			t.Fatalf("advisor: %v\n%s", err, tl)
		}
		t.Logf("log:\n%s", tl)
		return res
	}
	check := func(res *protocol.IndexAdvisorResult, method string) {
		t.Helper()
		if res.Hypothetical == 0 || res.HypoPG != "on" || len(res.Recommendations) == 0 {
			t.Fatalf("result: %+v", res)
		}
		for _, r := range res.Recommendations {
			if r.Spec.Columns[0] != "customer_id" || r.Method != method || r.SizeBytes == 0 || r.Speedup < 2 {
				t.Errorf("recommendation: %+v", r)
			}
		}
		// Nothing is left behind.
		var left int
		_ = e.conn.QueryRow(t.Context(), `SELECT count(*) FROM pg_class WHERE relname LIKE 'fakehypo\_%'`).Scan(&left)
		if left != 0 {
			t.Errorf("%d stand-in indexes left", left)
		}
	}

	// No copy: the planner's word stands, marked as such.
	advisorTestNoCopy = "There is no backup yet."
	res := run()
	check(res, protocol.IndexMethodHypothetical)
	if res.Tested != 0 || !strings.Contains(res.Summary, "without a copy") || !strings.Contains(res.Summary, "no backup yet") {
		t.Errorf("summary %q, tested %d", res.Summary, res.Tested)
	}

	// With a copy (here: production itself), only what passed is built there.
	advisorTestNoCopy = ""
	advisorTestCopy = &struct {
		target pginspect.Target
		dbName func(string) string
	}{target: e.tg, dbName: func(db string) string { return db }}
	res = run()
	check(res, protocol.IndexMethodCopy)
	if res.Tested == 0 || res.Tested >= len(res.Generated) {
		t.Errorf("tested %d of %d ideas on the copy (hypothetical %d)", res.Tested, len(res.Generated), res.Hypothetical)
	}

	// Without hypopg the copy tests every idea, and a missing copy says so.
	hypoSchema = func(context.Context, *pgx.Conn) (string, error) { return "", nil }
	advisorTestCopy, advisorTestNoCopy = nil, "There is no backup yet."
	res = run()
	if res.Hypothetical != 0 || len(res.Recommendations) != 0 || !strings.Contains(res.Skipped, "hypopg") {
		t.Errorf("without hypopg: %+v", res)
	}
}
