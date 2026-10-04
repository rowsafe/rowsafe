package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestPrimaryKeyColumns(t *testing.T) {
	for sql, want := range map[string]int{
		"CREATE TABLE kv (k TEXT PRIMARY KEY, v) WITHOUT ROWID":                                    1,
		"CREATE TABLE t (a, b, c, PRIMARY KEY (a, b)) WITHOUT ROWID":                               2,
		"CREATE TABLE t (a, \"b,c\" TEXT, CONSTRAINT pk PRIMARY KEY(a, \"b,c\", d)) without rowid": 3,
		"CREATE TABLE t (a TEXT DEFAULT 'PRIMARY KEY (x, y)' PRIMARY KEY, b) WITHOUT ROWID":        1,
	} {
		if got := primaryKeyColumns(sql); got != want {
			t.Errorf("%s: %d primary key columns, want %d", sql, got, want)
		}
	}
	for sql, want := range map[string]bool{
		"CREATE TABLE kv (k TEXT PRIMARY KEY, v) WITHOUT ROWID":   true,
		"CREATE TABLE kv (k TEXT PRIMARY KEY, v) without rowid ;": true,
		"CREATE TABLE kv (k TEXT PRIMARY KEY, v), STRICT":         false,
		"CREATE TABLE kv (without_rowid TEXT)":                    false,
	} {
		if got := withoutRowid(sql); got != want {
			t.Errorf("%s: without rowid %v, want %v", sql, got, want)
		}
	}
}

// TestBtreeReader reads a real file's tables at the page level: every row
// of each table, with overflow pages and a WITHOUT ROWID table.
func TestBtreeReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"PRAGMA page_size=1024",
		"CREATE TABLE big (id INTEGER PRIMARY KEY, note TEXT)",
		"CREATE TABLE kv (k TEXT, n INTEGER, v BLOB, PRIMARY KEY (k, n)) WITHOUT ROWID",
		"WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 3000) INSERT INTO big SELECT i, printf('%.*c', 10 + (i % 7) * 400, 'x') FROM s",
		"WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 800) INSERT INTO kv SELECT printf('k%05d', i), i % 3, randomblob(50 + i % 900) FROM s",
	} {
		if err := c.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	c.Close()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, _ := f.Stat()
	v := fileView(f, 1024, 1024, uint32(fi.Size()/1024))
	schema, _, err := v.readSchema()
	if err != nil {
		t.Fatal(err)
	}
	if !schema["kv"].WithoutRowid || schema["kv"].PKCols != 2 || schema["big"].WithoutRowid {
		t.Fatalf("schema: %+v", schema)
	}
	for name, want := range map[string]int{"big": 3000, "kv": 800} {
		tp, err := v.walk(schema[name].Root)
		if err != nil {
			t.Fatal(name, err)
		}
		keys := map[string]bool{}
		for pg := range tp.rows {
			rs, err := v.rows(pg, schema[name].PKCols)
			if err != nil {
				t.Fatal(name, err)
			}
			for _, r := range rs {
				keys[r.key] = true
			}
		}
		if len(keys) != want {
			t.Errorf("%s: %d distinct rows read, want %d (%d pages)", name, len(keys), want, len(tp.rows))
		}
	}
}

// TestSQLiteFindMoment: deletes, updates (with overflow pages), a WITHOUT
// ROWID table, a DROP, a table emptied, a rename and inserts, each found
// with the right counts, and "just before" each one restores the rows.
func TestSQLiteFindMoment(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	env, _ := testEnv(t)
	appDir := t.TempDir()
	if d := os.Getenv("ROWSAFE_TEST_SQLITE_DIR"); d != "" {
		appDir = d
	}
	path := filepath.Join(appDir, fmt.Sprintf("moment-%d.sqlite3", time.Now().UnixNano()))
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exec := func(qs ...string) time.Time {
		t.Helper()
		if err := c.Exec("BEGIN IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		for _, q := range qs {
			if err := c.Exec(q); err != nil {
				t.Fatal(q, err)
			}
		}
		if err := c.Exec("COMMIT"); err != nil {
			t.Fatal(err)
		}
		at := time.Now()
		time.Sleep(700 * time.Millisecond) // a poll of the copier apart
		return at
	}
	for _, q := range []string{
		"PRAGMA journal_mode=WAL",
		"CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, note TEXT)",
		"CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, total REAL)",
		"CREATE TABLE kv (k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID",
		"CREATE TABLE tmp (x)",
		"WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 2000) INSERT INTO customers SELECT i, 'c' || i || '@example.com', printf('%.*c', CASE WHEN i % 20 = 0 THEN 9000 ELSE 40 END, 'n') FROM s",
		"WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 5000) INSERT INTO orders SELECT i, i % 2000, i * 1.5 FROM s",
		"WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 300) INSERT INTO kv SELECT printf('k%04d', i), i FROM s",
		"WITH RECURSIVE s(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM s WHERE i < 123) INSERT INTO tmp SELECT i FROM s",
	} {
		if err := c.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	db := testSpec(path)
	e := startEngine(t, env)
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	atDelete := exec("DELETE FROM orders WHERE id % 10 = 0")
	atUpdate := exec("UPDATE customers SET note = note || 'x' WHERE id <= 60")
	exec("UPDATE kv SET v = v + 1 WHERE k < 'k0100'", "DELETE FROM kv WHERE k > 'k0290'")
	exec("DROP TABLE tmp")
	// VACUUM moves every row to other pages and shrinks the file: no row
	// changed.
	if err := c.Exec("VACUUM"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	exec("UPDATE orders SET total = total WHERE id < 50") // rewrites pages, changes nothing
	exec("INSERT INTO orders VALUES (9001, 1, 1.0), (9002, 2, 2.0)")
	exec("ALTER TABLE orders RENAME TO orders2")
	exec("DELETE FROM orders2 WHERE id < 100")
	atEmpty := exec("DELETE FROM customers")
	if _, err := shipperOf(e, db).flush(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}

	res, err := run[protocol.FindMomentResult](t, e, env, db, protocol.TaskFindMoment, protocol.FindMomentParams{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("summary: %s; notes: %v", res.Summary, res.Notes)
	got := map[string]int64{}
	byKey := map[string]protocol.Moment{}
	for _, m := range res.Moments {
		k := m.Kind + " " + m.Table
		got[k] += m.Rows
		byKey[k] = m
		t.Logf("%s %s: %s (%s)", m.Time.Format(time.StampMilli), m.LSN, m.Summary, m.Note)
	}
	want := map[string]int64{
		"delete orders":    500,
		"update customers": 60,
		"update kv":        99,
		"delete kv":        10,
		"drop tmp":         123,
		"delete orders2":   90, // 1..99 less the 9 deleted before
		"delete customers": 2000,
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s: %d rows, want %d", k, got[k], n)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected change %s (%d rows)", k, got[k])
		}
	}
	for k, at := range map[string]time.Time{"delete orders": atDelete, "update customers": atUpdate, "delete customers": atEmpty} {
		if m := byKey[k]; m.Time.Before(at.Add(-time.Second)) || m.Time.After(at.Add(2*time.Second)) {
			t.Errorf("%s at %s, committed at %s", k, m.Time.Format(time.StampMilli), at.Format(time.StampMilli))
		}
	}

	// Filters: one table, one kind.
	res2, err := run[protocol.FindMomentResult](t, e, env, db, protocol.TaskFindMoment, protocol.FindMomentParams{Tables: []string{"orders2"}, Kinds: []string{protocol.MomentDelete}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Moments) != 1 || res2.Moments[0].Table != "orders2" || res2.Moments[0].Rows != 90 {
		t.Errorf("filtered search: %+v", res2.Moments)
	}

	// Just before the delete: every order is there; at it, 500 are gone.
	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	count := func(at time.Time, q string) int64 {
		dst := filepath.Join(t.TempDir(), "at.db")
		if _, err := restoreTo(context.Background(), r, restoreTarget{Time: at}, dst, testLog{t}); err != nil {
			t.Fatal(err)
		}
		cc, err := openDB(context.Background(), dst, openOpts{Scratch: true})
		if err != nil {
			t.Fatal(err)
		}
		defer cc.Close()
		n, err := queryInt(cc, q)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	m := byKey["delete orders"]
	justBefore := m.Time.Truncate(time.Millisecond).Add(-time.Millisecond)
	if n := count(justBefore, "SELECT count(*) FROM orders"); n != 5000 {
		t.Errorf("just before the delete: %d orders, want 5000", n)
	}
	if n := count(m.Time, "SELECT count(*) FROM orders"); n != 4500 {
		t.Errorf("at the delete: %d orders, want 4500", n)
	}
	m = byKey["delete customers"]
	if n := count(m.Time.Truncate(time.Millisecond).Add(-time.Millisecond), "SELECT count(*) FROM customers"); n != 2000 {
		t.Errorf("just before customers were emptied: %d, want 2000", n)
	}
}
