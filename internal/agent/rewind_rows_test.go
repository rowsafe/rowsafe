package agent

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestPlanTable(t *testing.T) {
	col := func(name, typ string) column { return column{name: name, ident: name, typ: typ} }
	prod := tableMeta{pk: []string{"id"}, cols: []column{col("id", "bigint"), col("name", "text"), col("added", "text"),
		{name: "upper", ident: "upper", typ: "text", generated: true}, {name: "mood", ident: "mood", typ: "public.mood", userType: true}}}
	cp := tableMeta{cols: []column{col("id", "bigint"), col("name", "text"), col("dropped", "int"),
		{name: "upper", ident: "upper", typ: "text", generated: true}, {name: "mood", ident: "mood", typ: "public.mood", userType: true}}}
	p, why := planTable(prod, cp, true)
	if why != "" {
		t.Fatal(why)
	}
	var names []string
	for _, c := range p.common {
		names = append(names, c.name)
	}
	if !slices.Equal(names, []string{"id", "name", "mood"}) || p.format != "text" || len(p.key) != 1 {
		t.Errorf("common %v, format %s, key %v", names, p.format, p.key)
	}
	if n := strings.Join(p.notes, "; "); !strings.Contains(n, "added was added since") || !strings.Contains(n, "dropped no longer exists") {
		t.Errorf("notes %q", n)
	}

	// Refusals.
	if _, why := planTable(tableMeta{cols: prod.cols}, cp, false); !strings.Contains(why, "no primary key") {
		t.Errorf("no pk: %q", why)
	}
	strict := prod
	strict.cols = append(slices.Clone(prod.cols), column{name: "required", ident: "required", typ: "text", notNull: true})
	if _, why := planTable(strict, cp, true); !strings.Contains(why, "required was added since and needs a value") {
		t.Errorf("new NOT NULL column: %q", why)
	}
	if _, why := planTable(strict, cp, false); why != "" {
		t.Errorf("compare should not mind a new column: %q", why)
	}
	retyped := cp
	retyped.cols = []column{col("id", "integer"), col("name", "text")}
	if _, why := planTable(prod, retyped, false); !strings.Contains(why, "key column id changed") {
		t.Errorf("key type change: %q", why)
	}
}

func TestRowsSummary(t *testing.T) {
	got := rowsSummary([]protocol.RewindTableRows{
		{RewindTable: protocol.RewindTable{Table: "public.applications"}, Inserted: 1204},
		{RewindTable: protocol.RewindTable{Table: "public.application_notes"}, Inserted: 3310, Updated: 2, Conflicts: 1,
			SequencesAdvanced: []string{"public.application_notes_id_seq"}},
	})
	want := "Brought back 1,204 rows in public.applications and 3,310 in public.application_notes. Set 2 changed rows back to the copy's values. " +
		"1 row was left out because another row now has the same unique value. Moved a sequence forward so new rows don't collide (public.application_notes_id_seq)."
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := rowsSummary(nil); got != "No missing rows to bring back." {
		t.Error(got)
	}
}

// rewindEnv is a "production" database and a "copy" database in the local
// PostgreSQL, set up identically; the test then changes production.
type rewindEnv struct {
	t          *testing.T
	sides      rewindSides
	prod, copy string
	pc, cc     *pgx.Conn
}

const rewindSchema = `
CREATE TYPE mood AS ENUM ('ok', 'bad');
CREATE TABLE customers (
	id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	email text NOT NULL UNIQUE,
	name text,
	total numeric(10,2),
	seen timestamptz,
	score double precision,
	name_upper text GENERATED ALWAYS AS (upper(name)) STORED);
CREATE TABLE orders (
	id serial PRIMARY KEY,
	customer_id bigint NOT NULL REFERENCES customers (id),
	note text,
	tags text[],
	kind mood NOT NULL DEFAULT 'ok',
	data jsonb);
CREATE TABLE accounts (id int PRIMARY KEY, email text UNIQUE);
CREATE TABLE nopk (a int, b text);
CREATE TABLE "Odd ""Name""" ("Key" int PRIMARY KEY, "v a l" text);
CREATE TABLE audit (id serial PRIMARY KEY, msg text);
CREATE FUNCTION audit_it() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN INSERT INTO audit (msg) VALUES (TG_OP || ' ' || TG_TABLE_NAME); RETURN NEW; END $$;
CREATE TRIGGER customers_audit AFTER INSERT OR UPDATE ON customers FOR EACH ROW EXECUTE FUNCTION audit_it();
CREATE TRIGGER orders_audit AFTER INSERT OR UPDATE ON orders FOR EACH ROW EXECUTE FUNCTION audit_it();
INSERT INTO customers (email, name, total, seen, score)
	SELECT 'c' || i || '@x.test', 'Name ' || i, i * 1.5, '2026-09-24 12:00:00+00'::timestamptz + i * interval '1 minute', i / 3.0
	FROM generate_series(1, 20) i;
INSERT INTO orders (customer_id, note, tags, kind, data)
	SELECT (i + 1) / 2, 'order ' || i, ARRAY['a', 'b' || i], CASE WHEN i % 2 = 0 THEN 'bad'::mood ELSE 'ok' END, jsonb_build_object('i', i)
	FROM generate_series(1, 40) i;
INSERT INTO accounts SELECT i, 'a' || i || '@x.test' FROM generate_series(1, 5) i;
INSERT INTO nopk SELECT i, 'x' FROM generate_series(1, 3) i;
INSERT INTO "Odd ""Name""" SELECT i, 'v' || i FROM generate_series(1, 4) i;
CREATE TABLE gone (id int PRIMARY KEY);
TRUNCATE audit;
`

func newRewindEnv(t *testing.T) *rewindEnv {
	tg := fixTestTarget(t)
	admin, err := tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close(context.Background()) })
	n := time.Now().UnixNano() % 1e9
	e := &rewindEnv{t: t, prod: fmt.Sprintf("rowsafe_rw_prod_%d", n), copy: fmt.Sprintf("rowsafe_rw_copy_%d", n)}
	for _, db := range []string{e.prod, e.copy} {
		if _, err := admin.Exec(t.Context(), `CREATE DATABASE `+db); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			admin.Exec(ctx, `DROP DATABASE IF EXISTS `+db+` WITH (FORCE)`)
		})
		c, err := tg.Connect(t.Context(), db)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close(context.Background()) })
		if _, err := c.Exec(t.Context(), rewindSchema); err != nil {
			t.Fatal(err)
		}
		if db == e.prod {
			e.pc = c
		} else {
			e.cc = c
		}
	}
	e.sides = rewindSides{prod: tg, copy: tg, copyDB: func(db string) string {
		if db == e.prod {
			return e.copy
		}
		return db
	}, onlyDB: e.prod}
	// What happened in production since the copy's point in time.
	e.exec(`
		DELETE FROM orders WHERE customer_id IN (5, 6, 7) OR customer_id = 12;  -- 6 + 2 orders
		DELETE FROM customers WHERE id IN (5, 6, 7);
		UPDATE customers SET name = 'Changed', total = 0 WHERE id = 10;
		INSERT INTO customers (email, name) VALUES ('new@x.test', 'New');         -- id 21
		DELETE FROM accounts WHERE id = 3;
		INSERT INTO accounts VALUES (99, 'a3@x.test');                            -- takes 3's email
		DELETE FROM "Odd ""Name""" WHERE "Key" = 2;
		DROP TABLE gone;
		SELECT setval('orders_id_seq', 1);                                        -- behind (e.g. a restore)
		SELECT setval(pg_get_serial_sequence('customers', 'id'), 3);
		TRUNCATE audit;`)
	return e
}

func (e *rewindEnv) exec(sql string) {
	e.t.Helper()
	if _, err := e.pc.Exec(e.t.Context(), sql); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *rewindEnv) count(sql string) int64 {
	e.t.Helper()
	var n int64
	if err := e.pc.QueryRow(e.t.Context(), sql).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (e *rewindEnv) tables(names ...string) []protocol.RewindTable {
	var out []protocol.RewindTable
	for _, n := range names {
		out = append(out, protocol.RewindTable{DB: e.prod, Table: n})
	}
	return out
}

func (e *rewindEnv) rows(p protocol.RewindRowsParams) (*protocol.RewindRowsResult, error, string) {
	tl := &taskLog{}
	res, err := bringBackRows(e.t.Context(), e.sides, p, tl)
	return res, err, tl.String()
}

func TestRewindCompareAndRowsAgainstPostgres(t *testing.T) {
	start := time.Now()
	e := newRewindEnv(t)
	t.Logf("setup took %s", time.Since(start))
	tl := &taskLog{}
	defer func() { t.Logf("total %s\n%s", time.Since(start), tl.String()) }()

	// Compare everything: counts per table, related tables, plain skips.
	diffs, err := compareTables(t.Context(), e.sides, nil, tl)
	if err != nil {
		t.Fatal(err, tl.String())
	}
	byName := map[string]protocol.RewindTableDiff{}
	for _, d := range diffs {
		byName[d.Table] = d
		t.Logf("%s: missing %d changed %d only-in-prod %d related %v skipped %q note %q", d.Table, d.MissingInProduction, d.Changed,
			d.OnlyInProduction, d.Related, d.Skipped, d.Note)
	}
	check := func(name string, missing, changed, only int64) {
		t.Helper()
		d, ok := byName[name]
		if !ok || d.Skipped != "" || d.MissingInProduction != missing || d.Changed != changed || d.OnlyInProduction != only {
			t.Errorf("%s: %+v; want missing %d, changed %d, only in production %d", name, d, missing, changed, only)
		}
	}
	check("public.customers", 3, 1, 1)
	check("public.orders", 8, 0, 0)
	check("public.accounts", 1, 0, 1)
	check(`public.Odd "Name"`, 1, 0, 0)
	check("public.audit", 0, 0, 0)
	if d := byName["public.customers"]; !slices.Contains(d.Related, protocol.RewindTable{DB: e.prod, Table: "public.orders"}) {
		t.Errorf("customers related %v", d.Related)
	}
	if d := byName["public.orders"]; !slices.Contains(d.Related, protocol.RewindTable{DB: e.prod, Table: "public.customers"}) {
		t.Errorf("orders related %v", d.Related)
	}
	if !strings.Contains(byName["public.nopk"].Skipped, "no primary key") {
		t.Errorf("nopk: %+v", byName["public.nopk"])
	}
	if !strings.Contains(byName["public.gone"].Skipped, "no longer exists in production") {
		t.Errorf("gone: %+v", byName["public.gone"])
	}
	sum := compareSummary(diffs)
	if !strings.Contains(sum, "13 rows are missing in production") || !strings.Contains(sum, "2 tables were skipped") {
		t.Errorf("summary %q", sum)
	}
	// Named tables, quoted or not.
	diffs, err = compareTables(t.Context(), e.sides, e.tables(`public."Odd ""Name"""`, "missing_table"), tl)
	if err != nil || len(diffs) != 2 || diffs[0].MissingInProduction != 1 || !strings.Contains(diffs[1].Skipped, "isn't in the copy") {
		t.Fatalf("named compare: %+v %v", diffs, err)
	}
	if e.count(`SELECT count(*) FROM pg_class WHERE relname LIKE 'rowsafe\_%' AND relpersistence = 'p'`) != 0 {
		t.Error("compare left tables behind in production")
	}

	// Orders alone would point to customers production doesn't have:
	// refused, nothing changed.
	before := e.count(`SELECT count(*) FROM orders`)
	if _, err, log := e.rows(protocol.RewindRowsParams{Tables: e.tables("orders")}); err == nil ||
		!strings.Contains(err.Error(), "point to rows of public.customers") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("orphans: %v\n%s", err, log)
	}
	if e.count(`SELECT count(*) FROM orders`) != before {
		t.Fatal("a refused run changed production")
	}
	// A table without a primary key is refused.
	if _, err, _ := e.rows(protocol.RewindRowsParams{Tables: e.tables("orders", "nopk")}); err == nil || !strings.Contains(err.Error(), "no primary key") {
		t.Fatalf("nopk: %v", err)
	}
	// Over the row limit: refused before anything changes.
	if _, err, _ := e.rows(protocol.RewindRowsParams{Tables: e.tables("customers", "orders"), MaxRows: 5}); err == nil ||
		!strings.Contains(err.Error(), "over the limit of 5") {
		t.Fatalf("limit: %v", err)
	}
	if e.count(`SELECT count(*) FROM orders`) != before {
		t.Fatal("a refused run changed production")
	}

	// Children listed before parents: parents go first; missing rows come
	// back with their identity values, generated columns are recomputed,
	// triggers don't fire, changed rows stay as they are, sequences catch up.
	res, err, log := e.rows(protocol.RewindRowsParams{Tables: e.tables("orders", "customers")})
	if err != nil {
		t.Fatal(err, log)
	}
	t.Log(res.Summary)
	if len(res.Tables) != 2 || res.Tables[0].Table != "public.customers" || res.Tables[0].Inserted != 3 || res.Tables[0].Updated != 0 ||
		res.Tables[1].Table != "public.orders" || res.Tables[1].Inserted != 8 {
		t.Fatalf("result %+v\n%s", res.Tables, log)
	}
	if res.Summary != "Brought back 3 rows in public.customers and 8 in public.orders. Moved sequences forward so new rows don't collide "+
		"(public.customers_id_seq, public.orders_id_seq)." {
		t.Errorf("summary %q", res.Summary)
	}
	if e.count(`SELECT count(*) FROM customers WHERE id IN (5, 6, 7) AND name_upper = upper(name) AND email = 'c' || id || '@x.test'`) != 3 {
		t.Error("customers 5-7 not back with their ids and computed columns")
	}
	if e.count(`SELECT count(*) FROM orders WHERE customer_id IN (5, 6, 7, 12) AND kind = CASE WHEN id % 2 = 0 THEN 'bad'::mood ELSE 'ok' END
		AND tags = ARRAY['a', 'b' || id] AND data = jsonb_build_object('i', id)`) != 8 {
		t.Error("orders not back with their values")
	}
	var seen time.Time
	var score float64
	if err := e.pc.QueryRow(t.Context(), `SELECT seen, score FROM customers WHERE id = 5`).Scan(&seen, &score); err != nil ||
		!seen.Equal(time.Date(2026, 9, 24, 12, 5, 0, 0, time.UTC)) || score != 5/3.0 {
		t.Errorf("customer 5: seen %v score %v (%v)", seen, score, err)
	}
	if e.count(`SELECT count(*) FROM audit`) != 0 {
		t.Error("triggers fired for rows brought back")
	}
	if e.count(`SELECT count(*) FROM customers WHERE id = 10 AND name = 'Changed'`) != 1 {
		t.Error("a changed row was restored without include_changed")
	}
	if e.count(`SELECT last_value FROM orders_id_seq`) != 40 || e.count(`SELECT last_value FROM customers_id_seq`) != 21 {
		t.Errorf("sequences: orders %d customers %d", e.count(`SELECT last_value FROM orders_id_seq`), e.count(`SELECT last_value FROM customers_id_seq`))
	}
	e.exec(`INSERT INTO customers (email) VALUES ('after@x.test')`) // the sequence doesn't collide
	e.exec(`TRUNCATE audit`)

	// Again: nothing missing any more.
	res, err, _ = e.rows(protocol.RewindRowsParams{Tables: e.tables("customers", "orders")})
	if err != nil || res.Tables[0].Inserted != 0 || res.Tables[1].Inserted != 0 {
		t.Fatalf("second run: %+v %v", res, err)
	}

	// Changed rows, on request.
	res, err, log = e.rows(protocol.RewindRowsParams{Tables: e.tables("customers"), IncludeChanged: true})
	if err != nil || res.Tables[0].Updated != 1 || res.Tables[0].Inserted != 0 {
		t.Fatalf("include_changed: %+v %v\n%s", res, err, log)
	}
	if e.count(`SELECT count(*) FROM customers WHERE id = 10 AND name = 'Name 10' AND total = 15 AND name_upper = 'NAME 10'`) != 1 {
		t.Error("customer 10 not set back")
	}
	if e.count(`SELECT count(*) FROM customers WHERE id IN (21, 22)`) != 2 {
		t.Error("rows added since were touched")
	}
	if e.count(`SELECT count(*) FROM audit`) != 0 {
		t.Error("triggers fired for rows set back")
	}

	// A unique value taken since: the row stays out and is counted.
	res, err, _ = e.rows(protocol.RewindRowsParams{Tables: e.tables("accounts", `public."Odd ""Name"""`)})
	if err != nil || res.Tables[0].Inserted != 0 || res.Tables[0].Conflicts != 1 || res.Tables[1].Inserted != 1 {
		t.Fatalf("conflict: %+v %v", res, err)
	}
	if !strings.Contains(res.Summary, "1 row was left out because another row now has the same unique value") {
		t.Errorf("summary %q", res.Summary)
	}
	if e.count(`SELECT count(*) FROM "Odd ""Name""" WHERE "Key" = 2 AND "v a l" = 'v2'`) != 1 {
		t.Error("odd name row not back")
	}
	if e.count(`SELECT count(*) FROM pg_class WHERE relname LIKE 'rowsafe\_%' AND relpersistence = 'p'`) != 0 {
		t.Error("tables left behind in production")
	}

	// Compare again: only what was added since remains.
	diffs, err = compareTables(t.Context(), e.sides, e.tables("customers", "orders"), tl)
	if err != nil || diffs[0].MissingInProduction != 0 || diffs[0].Changed != 0 || diffs[0].OnlyInProduction != 2 || diffs[1].MissingInProduction != 0 {
		t.Fatalf("after: %+v %v", diffs, err)
	}
}

func TestRewindRowsLockTimeout(t *testing.T) {
	e := newRewindEnv(t)
	old := rewindRowsLockTimout
	rewindRowsLockTimout = "200ms"
	defer func() { rewindRowsLockTimout = old }()
	blocker, err := e.sides.prod.Connect(t.Context(), e.prod)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close(context.Background())
	tx, err := blocker.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), `LOCK TABLE accounts IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	_, err, _ = e.rows(protocol.RewindRowsParams{Tables: e.tables("accounts")})
	if err == nil || !strings.Contains(err.Error(), "held a lock") {
		t.Fatalf("err = %v", err)
	}
}
