package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
	"github.com/rowsafe/rowsafe/internal/indexadvisor/sqlshape"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func inProcessShapes(_ context.Context, qs []string) ([]indexadvisor.Shape, error) {
	out := make([]indexadvisor.Shape, len(qs))
	for i, q := range qs {
		out[i] = sqlshape.Parse(q)
	}
	return out, nil
}

func TestParsePlan(t *testing.T) {
	plan := `[{"Plan": {"Node Type": "Limit", "Total Cost": 12.5, "Plans": [
		{"Node Type": "Index Scan", "Index Name": "rs_orders_customer_id_idx", "Total Cost": 12}]}}]`
	cost, uses, err := parsePlan(plan, "rs_orders_customer_id_idx")
	if err != nil || cost != 12.5 || !uses {
		t.Fatalf("parsePlan = %v %v %v", cost, uses, err)
	}
	if _, uses, _ := parsePlan(plan, "other"); uses {
		t.Error("found an index that isn't there")
	}
	if _, _, err := parsePlan("nope", ""); err == nil {
		t.Error("accepted garbage")
	}
}

func TestMeasurable(t *testing.T) {
	for q, want := range map[string]bool{
		"SELECT id FROM t WHERE a = $1":                                       true,
		"SELECT count(*), max(b) FROM t WHERE a = $1":                         true,
		"SELECT id FROM t WHERE a = $1 FOR UPDATE":                            false,
		"UPDATE t SET b = 1 WHERE a = $1":                                     false,
		"SELECT pg_sleep(10) FROM t WHERE a = $1":                             false,
		"SELECT dblink('host=x', 'select 1') FROM t":                          false,
		"SELECT nextval('s') FROM t WHERE a = $1":                             false,
		"WITH d AS (DELETE FROM t WHERE a = $1 RETURNING id) SELECT * FROM d": false,
	} {
		if got := measurable(sqlshape.Parse(q)); got != want {
			t.Errorf("measurable(%s) = %v, want %v", q, got, want)
		}
	}
}

func TestValidateCreateIndex(t *testing.T) {
	good := &protocol.CreateIndexParams{IndexSpec: protocol.IndexSpec{DB: "shop", Schema: "public", Table: "orders",
		Columns: []string{"customer_id", "created_at"}, Name: "rs_orders_customer_id_created_at_idx"}}
	if err := validateMaintenance(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop", CreateIndex: good}); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*protocol.CreateIndexParams){
		"foreign name": func(c *protocol.CreateIndexParams) { c.Name = "orders_idx" },
		"no columns":   func(c *protocol.CreateIndexParams) { c.Columns = nil },
		"dup column":   func(c *protocol.CreateIndexParams) { c.Include = []string{"customer_id"} },
		"nul":          func(c *protocol.CreateIndexParams) { c.Columns = []string{"a\x00"} },
		"long table":   func(c *protocol.CreateIndexParams) { c.Table = strings.Repeat("t", 64) },
		"stray desc":   func(c *protocol.CreateIndexParams) { c.Descending = []string{"total"} },
	}
	for name, mutate := range bad {
		c := *good
		c.Columns = slices.Clone(good.Columns)
		mutate(&c)
		if err := validateMaintenance(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop", CreateIndex: &c}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validateMaintenance(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: "shop"}); err == nil {
		t.Error("accepted no index")
	}
}

// Against a real PostgreSQL: a 1M-row table with slow queries. A second
// database created from the first stands in for the restored copy. The
// advisor must recommend an index led by customer_id for the queries that
// filter on it (with ~20 rows per customer, (customer_id) alone does as
// well as (customer_id, created_at) and is smaller), measured on the copy;
// create_index then builds it on production, and the next run no longer
// suggests it.
func TestIndexAdvisorAgainstPostgres(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	e := newFixEnv(t)
	e.exec(`CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id int NOT NULL, status text NOT NULL,
		created_at timestamptz NOT NULL, total numeric(10,2) NOT NULL, sent_at timestamptz)`)
	e.exec(`INSERT INTO orders (customer_id, status, created_at, total, sent_at)
		SELECT (random() * 50000)::int, (ARRAY['new','paid','shipped'])[1 + (g % 3)],
		       now() - (g || ' seconds')::interval, (random() * 500)::numeric(10,2),
		       CASE WHEN g % 50 = 0 THEN NULL ELSE now() END
		FROM generate_series(1, 1000000) g`)
	e.exec(`ANALYZE orders`)

	// The copy: a database made from production's.
	admin, err := e.tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	copyDB := e.db + "_copy"
	e.conn.Close(context.Background())
	if _, err := admin.Exec(t.Context(), `CREATE DATABASE `+copyDB+` TEMPLATE `+e.db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // admin is closed by then: connect again to drop the copy
		c, err := e.tg.Connect(context.Background(), "postgres")
		if err != nil {
			t.Logf("dropping %s: %v", copyDB, err)
			return
		}
		defer c.Close(context.Background())
		if _, err := c.Exec(context.Background(), `DROP DATABASE IF EXISTS `+copyDB+` WITH (FORCE)`); err != nil {
			t.Logf("dropping %s: %v", copyDB, err)
		}
	})
	if e.conn, err = e.tg.Connect(t.Context(), e.db); err != nil {
		t.Fatal(err)
	}

	advisorTestCopy = &struct {
		target pginspect.Target
		dbName func(string) string
	}{target: e.tg, dbName: func(string) string { return copyDB }}
	oldParser, oldRead := shapeParser, readAdvisorStatements
	t.Cleanup(func() { advisorTestCopy, shapeParser, readAdvisorStatements = nil, oldParser, oldRead })
	shapeParser = inProcessShapes
	texts := map[string]string{
		"101": "SELECT id, total FROM orders WHERE customer_id = $1 ORDER BY created_at DESC LIMIT $2",
		"102": "SELECT count(*) FROM orders WHERE status = $1",
		"103": "SELECT * FROM orders WHERE id = $1",
		"104": "UPDATE orders SET status = $1 WHERE customer_id = $2 AND created_at > $3",
		"105": "SELECT id FROM orders WHERE sent_at IS NULL ORDER BY created_at LIMIT 100",
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
		{QueryID: "101", Calls: 50_000, TotalTimeMs: 4_000_000, Rows: 1_000_000},
		{QueryID: "104", Calls: 2_000, TotalTimeMs: 900_000, Rows: 10_000},
		{QueryID: "102", Calls: 100, TotalTimeMs: 20_000, Rows: 100},
		{QueryID: "105", Calls: 3_000, TotalTimeMs: 300_000, Rows: 300_000},
		{QueryID: "103", Calls: 90_000, TotalTimeMs: 9_000, Rows: 90_000},
	}}

	run := func(p protocol.IndexAdvisorParams) *protocol.IndexAdvisorResult {
		t.Helper()
		tl := &taskLog{}
		res, err := e.a.indexAdvisor(t.Context(), e.spec, "task_test", p, tl)
		if err != nil {
			t.Fatalf("advisor: %v\n%s", err, tl)
		}
		t.Logf("log:\n%s", tl)
		return res
	}
	res := run(params)
	t.Logf("summary: %s", res.Summary)
	for _, r := range res.Rejected {
		t.Logf("rejected %s: %s", r.Spec.Name, r.Reason)
	}
	if res.Statements != 5 || res.Analyzed != 5 || res.Tested == 0 {
		t.Fatalf("result: %+v", res)
	}
	var rec *protocol.IndexRecommendation
	for i, r := range res.Recommendations {
		t.Logf("recommended %s (%s, speedup %.1f): %+v", r.Spec.Definition(), humanBytes(r.SizeBytes), r.Speedup, r.Statements)
		if r.Spec.Columns[0] == "customer_id" {
			rec = &res.Recommendations[i]
		}
	}
	if rec == nil {
		t.Fatalf("no customer_id recommendation: %+v", res.Recommendations)
	}
	if rec.Speedup < 10 || rec.SizeBytes == 0 || rec.TableRows < 900_000 || !strings.HasPrefix(rec.Spec.Name, "rs_orders_customer_id") {
		t.Errorf("recommendation: %+v", rec)
	}
	helps := map[string]protocol.IndexGain{}
	for _, g := range rec.Statements {
		helps[g.QueryID] = g
	}
	if g, ok := helps["101"]; !ok || g.MsBefore == 0 || g.MsAfter == 0 || g.MsAfter >= g.MsBefore {
		t.Errorf("query 101 not measured faster: %+v", helps)
	}
	if _, ok := helps["102"]; ok {
		t.Error("the status count can't use it")
	}
	for _, r := range res.Recommendations {
		if slices.Equal(r.Spec.Columns, []string{"status"}) || slices.Equal(r.Spec.Columns, []string{"id"}) {
			t.Errorf("useless recommendation %s", r.Spec.Name)
		}
	}
	// The copy has no test index left.
	cc, err := e.tg.Connect(t.Context(), copyDB)
	if err != nil {
		t.Fatal(err)
	}
	var left int
	_ = cc.QueryRow(t.Context(), `SELECT count(*) FROM pg_indexes WHERE indexname LIKE 'rs\_%'`).Scan(&left)
	cc.Close(context.Background())
	if left != 0 {
		t.Errorf("%d test indexes left on the copy", left)
	}

	// Known ideas aren't tested again.
	again := params
	again.Known = res.Generated
	res2 := run(again)
	if res2.Tested != 0 || len(res2.Unchanged) != len(res.Generated) {
		t.Errorf("known ideas: tested %d, unchanged %d of %d", res2.Tested, len(res2.Unchanged), len(res.Generated))
	}

	// Create it on production.
	create := protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db,
		CreateIndex: &protocol.CreateIndexParams{IndexSpec: rec.Spec, EstimatedBytes: rec.SizeBytes}}
	e.mustRun(create, "Created the index public."+rec.Spec.Name+" on public.orders")
	e.mustRun(create, "already exists")

	// A leftover invalid index of the same name is replaced.
	e.exec(`DROP INDEX ` + rec.Spec.Name)
	e.exec(`CREATE INDEX ` + rec.Spec.Name + ` ON orders (status)`)
	e.exec(`UPDATE pg_index SET indisvalid = false WHERE indexrelid = $1::regclass`, rec.Spec.Name)
	e.mustRun(create, "Created the index")
	var def string
	if err := e.conn.QueryRow(t.Context(), `SELECT pg_get_indexdef($1::regclass)`, rec.Spec.Name).Scan(&def); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(def, "(customer_id") {
		t.Errorf("definition %s", def)
	}
	// A column that is gone.
	gone := *create.CreateIndex
	gone.Columns = []string{"missing_col"}
	gone.Name = "rs_orders_missing_col_idx"
	e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db, CreateIndex: &gone}, "no longer exists")
	// Something else with the name.
	e.exec(`CREATE TABLE rs_orders_total_idx (x int)`)
	other := *create.CreateIndex
	other.Columns, other.Name = []string{"total"}, "rs_orders_total_idx"
	e.mustRefuse(protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, DB: e.db, CreateIndex: &other}, "already exists in public")

	// The next run sees it covered, and reports its use.
	e.exec(`SELECT id FROM orders WHERE customer_id = 7 ORDER BY created_at DESC LIMIT 5`)
	time.Sleep(600 * time.Millisecond) // statistics are flushed at most every 500ms... or at the end of the transaction
	e.exec(`SELECT pg_stat_force_next_flush()`)
	again = params
	again.Track = []protocol.TrackedIndex{{DB: e.db, Schema: "public", Index: rec.Spec.Name}, {DB: e.db, Schema: "public", Index: "rs_gone_idx"}}
	res3 := run(again)
	if slices.Contains(res3.Generated, rec.Key) {
		t.Errorf("still suggested after creating it: %v", res3.Generated)
	}
	if len(res3.Usage) != 2 {
		t.Fatalf("usage: %+v", res3.Usage)
	}
	for _, u := range res3.Usage {
		switch u.Index {
		case rec.Spec.Name:
			if !u.Exists || !u.Valid || u.SizeBytes == 0 {
				t.Errorf("usage of the new index: %+v", u)
			}
		case "rs_gone_idx":
			if u.Exists {
				t.Errorf("gone index exists: %+v", u)
			}
		}
	}
	fmt.Println(res3.Summary)
}
