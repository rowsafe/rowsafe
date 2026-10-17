package local

import (
	"slices"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/internal/indexadvisor"
)

func TestReadStatement(t *testing.T) {
	ok := map[string]statementText{
		"SELECT 1;": {SQL: "SELECT 1", FirstWord: "SELECT"},
		"  select * from t where a = $1 and b = $12 ;  ":                      {SQL: "select * from t where a = $1 and b = $12", MaxParam: 12, FirstWord: "SELECT"},
		"-- what\n/* x; */ (SELECT ';', \"a;b\", $$;$$, $q$ $1 ; $q$) -- ;\n": {MaxParam: 0, FirstWord: "SELECT"},
		"SELECT E'it\\'s; fine', 'a''b;'":                                     {FirstWord: "SELECT"},
		"WITH x AS (SELECT 1) SELECT * FROM x; -- done":                       {FirstWord: "WITH"},
		"select price$1 from t":                                               {FirstWord: "SELECT"},
	}
	for in, want := range ok {
		got, err := readStatement(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got.MaxParam != want.MaxParam || got.FirstWord != want.FirstWord || (want.SQL != "" && got.SQL != want.SQL) {
			t.Errorf("%q: got %+v, want %+v", in, got, want)
		}
	}
	for _, in := range []string{"", "  ;", "SELECT 1; DROP TABLE t", "SELECT 1; 'x'", "SELECT 'open", "SELECT $$ open", "SELECT 1 /* open"} {
		if _, err := readStatement(in); err == nil {
			t.Errorf("%q: want an error", in)
		}
	}
	for in, refuse := range map[string]bool{
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity": true,
		"select PG_SLEEP (1)":                         true,
		"SELECT nextval('s')":                         true,
		"SELECT * FROM orders WHERE note = 'sleep'":   false,
		"SELECT my_pg_sleep_counter FROM stats":       false,
		"DELETE FROM t":                               true,
		"SELECT * FROM t WHERE id = $1":               true,
		"(SELECT 1) UNION (SELECT 2)":                 false,
		"TABLE orders":                                false,
		"INSERT INTO t SELECT * FROM t":               true,
		"SELECT lo_unlink(1)":                         true,
		"SELECT * FROM t WHERE set_configured = true": false,
	} {
		st, err := readStatement(in)
		if err != nil {
			t.Fatal(err)
		}
		if err := analyzable(st); (err != nil) != refuse {
			t.Errorf("analyzable(%q) = %v, want refused %v", in, err, refuse)
		}
	}
}

func TestConditions(t *testing.T) {
	kinds := func(ps []indexadvisor.Pred) []string {
		var out []string
		for _, p := range ps {
			s := p.Kind + ":" + p.Col.Col
			if p.Other != nil {
				s += "=" + p.Other.Qual + "." + p.Other.Col
			}
			out = append(out, s)
		}
		return out
	}
	cases := map[string][]string{
		"((o.customer_id = 42) AND (o.status = 'paid'::order_status))":               {"eq:customer_id", "eq:status"},
		"((o.shipped_at IS NULL) AND ((o.note)::text = 'a.b AND o.x = 1'::text))":    {"isnull:shipped_at", "eq:note"},
		"(o.created_at > (now() - '1 day'::interval))":                               {"range:created_at"},
		"((o.total >= 10) AND (o.total <= 20))":                                      {"range:total", "range:total"},
		"(o.customer_id = c.id)":                                                     {"join:customer_id=c.id"},
		"(c.id = o.customer_id)":                                                     {"join:customer_id=c.id"},
		"((o.status = 'new'::order_status) OR (o.status = 'paid'::order_status))":    {"eq:status"},
		"((o.status = 'new'::order_status) OR (o.total > 5))":                        nil,
		"(o.id = ANY ('{1,2,3}'::bigint[]))":                                         {"eq:id"},
		"((o.created_at)::date = CURRENT_DATE)":                                      nil,
		"(o.a = o.b)":                                                                nil,
		"(lower(o.email) = 'x'::text)":                                               nil,
		"(NOT o.archived)":                                                           {"eq:archived"},
		`(o."Customer Id" = $1)`:                                                     {"eq:Customer Id"},
		"((o.customer_id = $1) AND (o.created_at < $2) AND (o.note ~~ 'ab%'::text))": {"eq:customer_id", "range:created_at"},
		"(o.amount > c.limit_amount)":                                                nil,
		"((events_1.at > '2026-09-15 00:00:00+03'::timestamp with time zone) AND (events_1.account_id = 7))": nil,
	}
	for expr, want := range cases {
		if got := kinds(conditions(expr, "o")); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", expr, got, want)
		}
	}
	if got := kinds(conditions("((events_1.at > '2026-09-15'::timestamptz) AND (events_1.account_id = 7))", "events_1")); !slices.Equal(got, []string{"range:at", "eq:account_id"}) {
		t.Errorf("partition alias: %v", got)
	}
}

func TestShortType(t *testing.T) {
	for in, want := range map[string]string{
		"timestamp with time zone":       "timestamptz",
		"timestamp(3) with time zone":    "timestamptz(3)",
		"timestamp(3) without time zone": "timestamp(3)",
		"character varying(255)":         "varchar(255)",
		"character varying[]":            "varchar[]",
		"character(2)":                   "char(2)",
		"double precision":               "float8",
		"integer":                        "integer",
	} {
		if got := shortType(in); got != want {
			t.Errorf("shortType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSchemaLocalPostgres(t *testing.T) {
	d, conn := testDB(t)
	for _, sql := range []string{
		`CREATE TYPE order_status AS ENUM ('new', 'paid', 'shipped')`,
		`CREATE TYPE unused_mood AS ENUM ('ok')`,
		`CREATE SCHEMA billing`,
		`CREATE TABLE customers (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, email text NOT NULL UNIQUE, name varchar(200))`,
		`COMMENT ON COLUMN customers.email IS 'lower case'`,
		`CREATE TABLE orders (id bigserial PRIMARY KEY, customer_id bigint NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
			status order_status NOT NULL DEFAULT 'new', number int NOT NULL, total numeric(10,2) CHECK (total >= 0),
			total_cents bigint GENERATED ALWAYS AS ((total * 100)::bigint) STORED, created_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (customer_id, number))`,
		`CREATE INDEX orders_status_idx ON orders (status) WHERE status <> 'shipped'`,
		`CREATE TABLE billing.invoices (order_id bigint, line int, amount numeric, PRIMARY KEY (order_id, line),
			FOREIGN KEY (order_id) REFERENCES orders(id))`,
		`CREATE TABLE events (id bigint NOT NULL, at timestamptz NOT NULL, kind text) PARTITION BY RANGE (at)`,
		`CREATE TABLE events_2026 PARTITION OF events FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')`,
		`CREATE TABLE events_2027 PARTITION OF events FOR VALUES FROM ('2027-01-01') TO ('2028-01-01')`,
		`CREATE INDEX events_kind_idx ON events (kind)`,
		`INSERT INTO events SELECT g, '2026-03-01'::timestamptz + g * interval '1 minute', 'k' FROM generate_series(1, 2000) g`,
		`ANALYZE events`,
		`CREATE VIEW paid_orders AS SELECT id, customer_id, status FROM orders WHERE status = 'paid'`,
		`CREATE MATERIALIZED VIEW order_counts AS SELECT customer_id, count(*) AS n FROM orders GROUP BY 1`,
		`CREATE FUNCTION touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`,
		`CREATE TRIGGER orders_touch BEFORE UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION touch()`,
	} {
		if _, err := conn.Exec(t.Context(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	s, err := d.Schema(t.Context(), SchemaOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	byName := map[string]Table{}
	for _, tb := range s.Tables {
		names = append(names, tb.Schema+"."+tb.Name)
		byName[tb.Name] = tb
	}
	if !slices.Equal(names, []string{"billing.invoices", "public.customers", "public.events", "public.orders"}) {
		t.Fatalf("tables %v (partitions belong under their parent)", names)
	}
	o := byName["orders"]
	if !slices.Equal(o.PrimaryKey, []string{"id"}) || len(o.ForeignKeys) != 1 || o.ForeignKeys[0].Table != "customers" ||
		o.ForeignKeys[0].OnDelete != "cascade" || len(o.ReferencedBy) != 1 || o.ReferencedBy[0].Schema != "billing" ||
		len(o.Unique) != 1 || !slices.Equal(o.Unique[0].Columns, []string{"customer_id", "number"}) || len(o.Checks) != 1 || len(o.Triggers) != 1 {
		t.Errorf("orders %+v", o)
	}
	var gen, def bool
	for _, c := range o.Columns {
		gen = gen || (c.Name == "total_cents" && strings.Contains(c.Generated, "total"))
		def = def || (c.Name == "id" && strings.Contains(c.Default, "nextval('orders_id_seq')"))
	}
	if !gen || !def {
		t.Errorf("generated %v, serial default %v: %+v", gen, def, o.Columns)
	}
	if c := byName["customers"]; c.Columns[0].Identity != "always" || len(c.ReferencedBy) != 1 || c.Columns[1].Comment != "lower case" {
		t.Errorf("customers %+v", c)
	}
	ev := byName["events"]
	if ev.Kind != "partitioned table" || ev.Partitions != 2 || ev.PartitionKey != "RANGE (at)" || ev.RowsEstimate != 2000 || ev.SizeBytes == 0 {
		t.Errorf("events %+v", ev)
	}
	if len(ev.Indexes) != 1 || ev.Indexes[0].Name != "events_kind_idx" {
		t.Errorf("events indexes %+v", ev.Indexes)
	}
	if len(s.Views) != 2 || s.Views[0].Name != "order_counts" || !s.Views[0].Materialized || s.Views[1].Definition == "" {
		t.Errorf("views %+v", s.Views)
	}
	if len(s.Enums) != 2 || !slices.Equal(s.Enums[0].Values, []string{"new", "paid", "shipped"}) {
		t.Errorf("enums %+v", s.Enums)
	}

	text := s.Text()
	for _, want := range []string{
		"orders (~0 rows",
		"  id bigint PK default nextval('orders_id_seq')",
		"  customer_id bigint not null -> customers(id) on delete cascade",
		"  status order_status not null default 'new'::order_status",
		"  created_at timestamptz not null default now()",
		"  unique (customer_id, number)",
		"  index orders_status_idx (status) WHERE (status <> 'shipped'::order_status): unused",
		"  referenced by billing.invoices(order_id)",
		"  trigger orders_touch BEFORE UPDATE FOR EACH ROW EXECUTE FUNCTION touch()",
		"  email text not null unique  -- lower case",
		"  id bigint PK identity always",
		"events (partitioned table, by RANGE (at), 2 partitions, ~2,000 rows",
		"billing.invoices (",
		"  primary key (order_id, line)",
		"  order_id bigint not null -> orders(id)",
		"materialized view order_counts (customer_id bigint, n bigint)",
		"view paid_orders (id bigint, customer_id bigint, status order_status)",
		"enum order_status: new, paid, shipped",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}

	// Zoom in: patterns, schema-qualified, and only the enums they use.
	s, err = d.Schema(t.Context(), SchemaOptions{Tables: []string{"ord*", "billing.*"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Tables) != 2 || s.Tables[0].Name != "invoices" || s.Tables[1].Name != "orders" || len(s.Views) != 1 ||
		len(s.Enums) != 1 || s.Enums[0].Name != "order_status" {
		t.Errorf("zoomed: tables %d views %d enums %+v", len(s.Tables), len(s.Views), s.Enums)
	}
	// The cap keeps the largest and says how to see the rest.
	s, err = d.Schema(t.Context(), SchemaOptions{Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Tables) != 1 || s.Tables[0].Name != "events" || s.MatchingTables != 4 || !strings.Contains(s.Note, "--table") {
		t.Errorf("capped: %d tables (%d matching), note %q", len(s.Tables), s.MatchingTables, s.Note)
	}
}

func TestExplainLocalPostgres(t *testing.T) {
	d, conn := testDB(t)
	for _, sql := range []string{
		`CREATE TABLE customers (id bigint PRIMARY KEY, email text NOT NULL)`,
		`CREATE TABLE orders (id bigint PRIMARY KEY, customer_id bigint NOT NULL REFERENCES customers(id), status text NOT NULL,
			created_at timestamptz NOT NULL, note text)`,
		`INSERT INTO customers SELECT g, 'c' || g || '@example.com' FROM generate_series(1, 2000) g`,
		`INSERT INTO orders SELECT g, 1 + g % 2000, (ARRAY['new', 'paid', 'shipped'])[1 + g % 3], now() - g * interval '1 minute', NULL
			FROM generate_series(1, 60000) g`,
		`ANALYZE`,
	} {
		if _, err := conn.Exec(t.Context(), sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	const q = `SELECT id, created_at FROM orders WHERE customer_id = 42 ORDER BY created_at DESC LIMIT 5`
	e, err := d.Explain(t.Context(), q, ExplainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Analyzed || len(e.Findings) == 0 || e.Findings[0].Kind != "seq_scan" || len(e.Indexes) != 1 {
		t.Fatalf("explain: %s", e.Text())
	}
	idea := e.Indexes[0]
	if idea.Table != "orders" || !slices.Equal(idea.Columns, []string{"customer_id", "created_at"}) ||
		!strings.HasPrefix(idea.Statement, `CREATE INDEX CONCURRENTLY orders_customer_id_created_at_idx ON public.orders (customer_id, created_at)`) {
		t.Fatalf("index idea %+v", idea)
	}
	if !strings.Contains(e.Text(), "reads all of orders (~60,000 rows)") {
		t.Errorf("text:\n%s", e.Text())
	}

	// Measured: real rows and times, still the same advice.
	e, err = d.Explain(t.Context(), q, ExplainOptions{Analyze: true, Plan: true})
	if err != nil {
		t.Fatal(err)
	}
	if !e.Analyzed || e.ExecutionMs == nil || e.ActualRows == nil || *e.ActualRows != 5 || len(e.Indexes) != 1 || len(e.Plan) == 0 {
		t.Fatalf("analyzed: %s", e.Text())
	}

	// A join reading a whole table for a few rows: an index on the join column.
	e, err = d.Explain(t.Context(), `SELECT o.* FROM orders o JOIN customers c ON c.id = o.customer_id WHERE c.email = 'c7@example.com'`, ExplainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Indexes) != 1 || !slices.Equal(e.Indexes[0].Columns, []string{"customer_id"}) {
		t.Errorf("join: %s", e.Text())
	}

	// $1 placeholders: the generic plan.
	e, err = d.Explain(t.Context(), `SELECT * FROM orders WHERE customer_id = $1`, ExplainOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !e.GenericPlan || len(e.Indexes) != 1 {
		t.Errorf("generic: %s", e.Text())
	}

	// Never runs what changes data, even when asked to.
	for _, sql := range []string{
		`DELETE FROM orders`,
		`WITH gone AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM gone`,
		`SELECT * FROM orders FOR UPDATE`,
		`SELECT pg_sleep(5)`,
		`SELECT 1; DELETE FROM orders`,
	} {
		if _, err := d.Explain(t.Context(), sql, ExplainOptions{Analyze: true}); err == nil {
			t.Errorf("%s: ran with --analyze", sql)
		}
	}
	if _, err := d.Explain(t.Context(), `DELETE FROM orders WHERE id < 10`, ExplainOptions{}); err != nil {
		t.Errorf("plan of a DELETE without running it: %v", err)
	}
	var n int
	if err := conn.QueryRow(t.Context(), `SELECT count(*) FROM orders`).Scan(&n); err != nil || n != 60000 {
		t.Fatalf("orders has %d rows (%v)", n, err)
	}

	// Once the index exists, the plan uses it and nothing is suggested.
	if _, err := conn.Exec(t.Context(), strings.Replace(idea.Statement, " CONCURRENTLY", "", 1)); err != nil {
		t.Fatal(err)
	}
	e, err = d.Explain(t.Context(), q, ExplainOptions{Analyze: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Findings) != 0 || len(e.Indexes) != 0 || !strings.Contains(e.Text(), "orders_customer_id_created_at_idx") {
		t.Errorf("with the index: %s", e.Text())
	}

	// The MCP tools answer in compact text.
	srv := NewMCPServer(d, MCPOptions{})
	st, ct := sdk.NewInMemoryTransports()
	if _, err := srv.Connect(t.Context(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	for tool, args := range map[string]map[string]any{
		"describe_schema": {"tables": []string{"orders"}},
		"explain_query":   {"query": "SELECT * FROM orders WHERE status = 'paid' AND note IS NOT NULL"},
	} {
		res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: tool, Arguments: args})
		if err != nil || res.IsError || len(res.Content) != 1 {
			t.Fatalf("%s: %v %+v", tool, err, res)
		}
		text := res.Content[0].(*sdk.TextContent).Text
		if want := map[string]string{"describe_schema": "  customer_id bigint not null -> customers(id)", "explain_query": "Seq Scan on orders"}[tool]; !strings.Contains(text, want) {
			t.Errorf("%s lacks %q:\n%s", tool, want, text)
		}
	}
}
