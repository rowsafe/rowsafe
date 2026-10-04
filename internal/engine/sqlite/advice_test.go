package sqlite

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/protocol"
)

// adviceDB creates a database with the given statements and returns its
// schema facts as monitoring reads them.
func adviceDB(t *testing.T, stmts ...string) (*sqlite3.Conn, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "advice.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	for _, q := range stmts {
		if err := c.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	return c, path
}

func adviceFacts(t *testing.T, c *sqlite3.Conn) *protocol.Insights {
	t.Helper()
	ins, err := schemaInsights(context.Background(), c, "wal")
	if err != nil {
		t.Fatal(err)
	}
	if ins.Advisor == nil || ins.Advisor.SQLite == nil {
		t.Fatalf("no advisor facts: %+v", ins)
	}
	return ins
}

func fill(table string, n int, cols string) string {
	return "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < " + strconv.Itoa(n) + ") INSERT INTO " + table + " SELECT " + cols + " FROM n"
}

func TestAdviceForeignKeys(t *testing.T) {
	c, _ := adviceDB(t,
		`CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT)`,
		`CREATE TABLE regions (code TEXT, sub TEXT, PRIMARY KEY (code, sub)) WITHOUT ROWID`,
		// No index on customer_id: reported.
		`CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers(id), note TEXT)`,
		// Covered by an index whose leading columns are the key in another order.
		`CREATE TABLE shipments (id INTEGER PRIMARY KEY, rcode TEXT, rsub TEXT, FOREIGN KEY (rcode, rsub) REFERENCES regions(code, sub))`,
		`CREATE INDEX shipments_region ON shipments (rsub, rcode, id)`,
		// A partial index doesn't count.
		`CREATE TABLE invoices (id INTEGER PRIMARY KEY, customer_id INTEGER REFERENCES customers, paid INTEGER)`,
		`CREATE INDEX invoices_unpaid ON invoices (customer_id) WHERE paid = 0`,
		// The child column is the rowid itself.
		`CREATE TABLE profiles (customer_id INTEGER PRIMARY KEY REFERENCES customers(id), bio TEXT)`,
		// A WITHOUT ROWID primary key serves the lookup.
		`CREATE TABLE tags (customer_id INTEGER REFERENCES customers(id), tag TEXT, PRIMARY KEY (customer_id, tag)) WITHOUT ROWID`,
		// Only the second column of an index: not served.
		`CREATE TABLE notes (id INTEGER PRIMARY KEY, author TEXT, customer_id INTEGER REFERENCES customers(id))`,
		`CREATE INDEX notes_author ON notes (author, customer_id)`,
		fill("customers", 50, "i, 'c' || i"),
		fill("orders", 1200, "i, i % 50 + 1, 'x'"),
	)
	a := adviceFacts(t, c).Advisor
	var got []string
	for _, fk := range a.ForeignKeys {
		got = append(got, fk.Table+":"+strings.Join(fk.Columns, ","))
		if fk.Database != "main" || fk.Schema != "main" || fk.RefTable != "customers" {
			t.Errorf("foreign key: %+v", fk)
		}
	}
	slices.Sort(got)
	want := []string{"invoices:customer_id", "notes:customer_id", "orders:customer_id"}
	if !slices.Equal(got, want) {
		t.Fatalf("foreign keys without an index: %v, want %v", got, want)
	}
	if a.ForeignKeys[0].Table != "orders" || a.ForeignKeys[0].RowsEstimate != 1200 || a.ForeignKeys[0].Constraint != "orders(customer_id) -> customers" {
		t.Errorf("biggest first, with its rows and name: %+v", a.ForeignKeys[0])
	}

	// The index advisor's idea for it: a safe, quoted name.
	s, err := readSchema(context.Background(), c, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ideas := s.unindexedFKs()
	spec := ideas[0].spec()
	if spec.Name != "rs_orders_customer_id_idx" || !protocol.ValidIndexName(spec.Name) {
		t.Errorf("index name %q", spec.Name)
	}
	if def := spec.DefinitionFor(protocol.EngineSQLite); def != `CREATE INDEX IF NOT EXISTS "rs_orders_customer_id_idx" ON "orders" ("customer_id")` {
		t.Errorf("definition %q", def)
	}
}

func TestAdviceNoPrimaryKey(t *testing.T) {
	c, _ := adviceDB(t,
		`CREATE TABLE logs (at TEXT, line TEXT)`,                              // no key at all
		`CREATE TABLE users (email TEXT NOT NULL UNIQUE, name TEXT)`,          // a unique NOT NULL column is a key
		`CREATE TABLE maybe (email TEXT UNIQUE, name TEXT)`,                   // unique but may be empty: no key
		`CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT) WITHOUT ROWID`,          // has one
		`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT)`, // has one
		fill("logs", 30, "datetime('now'), 'l' || i"),
	)
	a := adviceFacts(t, c).Advisor
	var got []string
	for _, x := range a.NoPrimaryKey {
		got = append(got, x.Table)
	}
	if !slices.Equal(got, []string{"logs", "maybe"}) {
		t.Fatalf("tables without a key: %v", got)
	}
	if a.NoPrimaryKey[0].RowsEstimate != 30 {
		t.Errorf("rows from the highest rowid: %+v", a.NoPrimaryKey[0])
	}
}

func TestAdviceAutoincrement(t *testing.T) {
	c, _ := adviceDB(t,
		`CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT)`,
		`CREATE TABLE plain (id INTEGER PRIMARY KEY, at TEXT)`,
		`CREATE TABLE "Odd ""name""" (id integer primary key autoincrement)`,
		fill("events", 7, "NULL, 'x'"),
		`DELETE FROM events WHERE id > 5`,
	)
	a := adviceFacts(t, c).Advisor.SQLite
	if len(a.Autoincrement) != 2 {
		t.Fatalf("autoincrement tables: %+v", a.Autoincrement)
	}
	var ev protocol.SQLiteAutoincrement
	for _, x := range a.Autoincrement {
		if x.Table == "events" {
			ev = x
		}
	}
	if ev.Column != "id" || ev.Seq != 7 || ev.RowsEstimate != 5 {
		t.Errorf("events: %+v (seq 7 from sqlite_sequence, 5 rows from the highest rowid)", ev)
	}
}

func TestAdviceStatistics(t *testing.T) {
	c, _ := adviceDB(t,
		`CREATE TABLE a (id INTEGER PRIMARY KEY, x TEXT)`,
		`CREATE INDEX a_x ON a (x)`,
		`CREATE TABLE b (id INTEGER PRIMARY KEY, y TEXT)`, // no index: statistics don't matter
		fill("a", 100, "i, 'x' || (i % 7)"),
	)
	s := adviceFacts(t, c).Advisor.SQLite
	if s.Stat1 || s.IndexedTables != 1 || !slices.Equal(s.Unanalyzed, []string{"a"}) || s.Tables != 2 {
		t.Fatalf("before ANALYZE: %+v", s)
	}
	if err := c.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	if err := c.Exec(`CREATE TABLE c (id INTEGER PRIMARY KEY, z TEXT UNIQUE)`); err != nil {
		t.Fatal(err)
	}
	s = adviceFacts(t, c).Advisor.SQLite
	if !s.Stat1 || s.IndexedTables != 2 || !slices.Equal(s.Unanalyzed, []string{"c"}) {
		t.Fatalf("after ANALYZE and a new indexed table: %+v", s)
	}
	// Rows come from sqlite_stat1 now.
	ss, _ := readSchema(context.Background(), c, 0)
	if n := ss.table("a").Rows; n != 100 {
		t.Errorf("rows of a from sqlite_stat1: %d", n)
	}
}

func TestAdviceWithoutRowidCountBudget(t *testing.T) {
	c, _ := adviceDB(t,
		`CREATE TABLE p (id INTEGER PRIMARY KEY)`,
		`CREATE TABLE w (k INTEGER PRIMARY KEY, pid INTEGER REFERENCES p(id), v TEXT) WITHOUT ROWID`,
		`INSERT INTO p VALUES (1)`,
		fill("w", 40, "i, 1, 'v'"),
	)
	s, err := readSchema(context.Background(), c, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := s.table("w").Rows; n != -1 {
		t.Errorf("no budget: rows of a WITHOUT ROWID table should be unknown, got %d", n)
	}
	s, _ = readSchema(context.Background(), c, time.Second)
	if n := s.table("w").Rows; n != 40 {
		t.Errorf("counted rows: %d", n)
	}
	// Rollback-journal databases are never counted (their reads block writes).
	ins, _ := schemaInsights(context.Background(), c, "delete")
	if fk := ins.Advisor.ForeignKeys; len(fk) != 1 || fk[0].RowsEstimate != -1 {
		t.Errorf("rollback journal: %+v", fk)
	}
}

func TestAdviceCreateIndexRefusals(t *testing.T) {
	env, _ := testEnv(t)
	_, path := adviceDB(t, `CREATE TABLE o (id INTEGER PRIMARY KEY, cid INTEGER)`)
	db := testSpec(path)
	e := &Engine{}
	ok := protocol.IndexSpec{DB: "main", Schema: "main", Table: "o", Columns: []string{"cid"}}
	ok.Name = protocol.IndexName(ok)
	for name, spec := range map[string]protocol.IndexSpec{
		"bad name":     {DB: "main", Schema: "main", Table: "o", Columns: []string{"cid"}, Name: `x"; DROP TABLE o; --`},
		"other schema": {DB: "temp", Schema: "main", Table: "o", Columns: []string{"cid"}, Name: ok.Name},
		"no column":    {DB: "main", Schema: "main", Table: "o", Columns: []string{"nope"}, Name: "rs_o_nope_idx"},
		"partial":      {DB: "main", Schema: "main", Table: "o", Columns: []string{"cid"}, WhereNull: []string{"cid"}, Name: ok.Name},
	} {
		_, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
			protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, CreateIndex: &protocol.CreateIndexParams{IndexSpec: spec}})
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	res, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
		protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, CreateIndex: &protocol.CreateIndexParams{IndexSpec: ok}})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Summary)
	res, err = run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
		protocol.MaintenanceParams{Action: protocol.MaintCreateIndex, CreateIndex: &protocol.CreateIndexParams{IndexSpec: ok}})
	if err != nil || !strings.Contains(res.Summary, "already exists") {
		t.Errorf("twice: %+v %v", res, err)
	}
}

// Recommendations and index advice on a real WAL database with backups:
// the schema facts monitoring sends, an index for a foreign key tested on
// a restored copy (time, size, the lookup before and after), the fix that
// creates it on production, and the next run finding nothing left to do.
func TestSQLiteAdvice(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	env, _ := testEnv(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "shop.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"PRAGMA journal_mode=WAL",
		"CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
		"CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER NOT NULL REFERENCES customers(id), total REAL)",
		"CREATE TABLE audit (at TEXT, what TEXT)",
		fill("customers", 500, "i, 'customer ' || i"),
		fill("orders", 30000, "NULL, i % 500 + 1, i * 1.5"),
		fill("audit", 10, "datetime('now'), 'x'"),
	} {
		if err := c.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	c.Close()
	db := testSpec(path)
	e := startEngine(t, env)
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Archiver(context.Background(), env, db); err != nil {
		t.Fatal(err)
	}

	// Monitoring sends the schema facts.
	dm, err := e.Monitor(context.Background(), env, db)
	if err != nil || dm.Insights == nil || dm.Insights.Advisor == nil {
		t.Fatalf("monitor: %+v %v", dm, err)
	}
	a := dm.Insights.Advisor
	if len(a.ForeignKeys) != 1 || a.ForeignKeys[0].Table != "orders" || a.ForeignKeys[0].RowsEstimate != 30000 {
		t.Errorf("foreign keys: %+v", a.ForeignKeys)
	}
	if len(a.NoPrimaryKey) != 1 || a.NoPrimaryKey[0].Table != "audit" {
		t.Errorf("tables without a key: %+v", a.NoPrimaryKey)
	}
	if len(a.SQLite.Autoincrement) != 1 || a.SQLite.Autoincrement[0].Seq != 30000 {
		t.Errorf("autoincrement: %+v", a.SQLite.Autoincrement)
	}
	if dm2, _ := e.Monitor(context.Background(), env, db); dm2.Insights != nil {
		t.Error("the schema facts are sent about every 30 minutes, not every minute")
	}

	// No backup yet: nothing tested, and it says why.
	res, err := run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{})
	if err != nil || res.Skipped == "" || len(res.Generated) != 1 {
		t.Fatalf("before a backup: %+v %v", res, err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}

	res, err = run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", res.Summary)
	if res.Tested != 1 || len(res.Recommendations) != 1 || res.CopySeconds <= 0 {
		t.Fatalf("advisor: %+v", res)
	}
	rec := res.Recommendations[0]
	fk := rec.ForeignKey
	if rec.Spec.Table != "orders" || !slices.Equal(rec.Spec.Columns, []string{"customer_id"}) || rec.Spec.Name != "rs_orders_customer_id_idx" ||
		rec.BuildMs <= 0 || rec.SizeBytes < 4096 || rec.TableRows != 30000 || fk == nil || fk.RefTable != "customers" ||
		fk.Samples == 0 || fk.LookupMsAfter >= fk.LookupMsBefore || rec.Speedup < 2 {
		t.Fatalf("recommendation: %+v %+v", rec, fk)
	}
	if entries, _ := filepathGlob(drillRoot(env)); len(entries) != 0 {
		t.Errorf("the copy was left behind: %v", entries)
	}
	if n := indexCount(t, path, rec.Spec.Name); n != 0 {
		t.Fatal("the advisor touched production")
	}

	// Known: not tested again.
	res, err = run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{Known: []string{rec.Key}})
	if err != nil || res.Tested != 0 || !slices.Equal(res.Unchanged, []string{rec.Key}) {
		t.Fatalf("known: %+v %v", res, err)
	}

	// Apply fix: created on production, while the app keeps writing.
	stop := make(chan struct{})
	wrote := make(chan int)
	go func() {
		c, _ := sqlite3.Open(path)
		defer c.Close()
		_ = c.BusyTimeout(10 * time.Second)
		n := 0
		for {
			select {
			case <-stop:
				wrote <- n
				return
			default:
			}
			if c.Exec("INSERT INTO orders (customer_id, total) VALUES (1, 1)") == nil {
				n++
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
	mr, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintCreateIndex,
		DB: "main", CreateIndex: &protocol.CreateIndexParams{IndexSpec: rec.Spec, EstimatedBytes: rec.SizeBytes}})
	close(stop)
	n := <-wrote
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s (the app wrote %d rows meanwhile)", mr.Summary, n)
	if indexCount(t, path, rec.Spec.Name) != 1 {
		t.Fatal("the index isn't on production")
	}

	// Next run: nothing left to suggest; the created index is tracked.
	res, err = run[protocol.IndexAdvisorResult](t, e, env, db, protocol.TaskIndexAdvisor, protocol.IndexAdvisorParams{
		Track: []protocol.TrackedIndex{{DB: "main", Schema: "main", Index: rec.Spec.Name}}})
	if err != nil || len(res.Generated) != 0 || len(res.Usage) != 1 || !res.Usage[0].Exists {
		t.Fatalf("after creating it: %+v %v", res, err)
	}
}

func indexCount(t *testing.T, path, name string) int64 {
	t.Helper()
	c := mustOpen(t, path)
	defer c.Close()
	n, err := queryInt(c, `SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name = ?`, name)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func filepathGlob(dir string) ([]string, error) { return filepath.Glob(filepath.Join(dir, "index-*")) }
