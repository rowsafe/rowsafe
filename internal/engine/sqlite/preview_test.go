package sqlite

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/protocol"
)

// The b-tree walk accounts for every page of a file: each b-tree's pages
// (overflow included) plus the free pages are the file's pages, and a
// table's entries are its rows.
func TestBtreeSizes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sizes.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"PRAGMA page_size = 1024",
		"CREATE TABLE big (id INTEGER PRIMARY KEY, body BLOB, note TEXT)",
		"CREATE TABLE kv (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID",
		"CREATE INDEX big_note ON big (note)",
		"CREATE VIEW v AS SELECT id FROM big",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 3000) INSERT INTO big SELECT i, randomblob(i % 5000), printf('note %d %s', i, hex(randomblob(i % 700))) FROM n",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 2000) INSERT INTO kv SELECT printf('%0300d', i), randomblob(i % 3000) FROM n",
		"DELETE FROM big WHERE id % 7 = 0",
	} {
		if err := c.Exec(q); err != nil {
			t.Fatal(q, err)
		}
	}
	snap, err := readSchema(c)
	if err != nil {
		t.Fatal(err)
	}
	pages, _ := queryInt(c, "PRAGMA page_count")
	free, _ := queryInt(c, "PRAGMA freelist_count")
	rows, _ := queryInt(c, "SELECT count(*) FROM big")
	kvRows, _ := queryInt(c, "SELECT count(*) FROM kv")
	c.Close()
	roots := []int64{1}
	for _, o := range snap {
		roots = append(roots, o.Root)
	}
	sizes, pageSize, err := btreeSizes(path, roots)
	if err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, s := range sizes {
		sum += s.Pages
	}
	if pageSize != 1024 || sum+free != pages {
		t.Errorf("page size %d; b-trees %d + free %d pages, the file has %d", pageSize, sum, free, pages)
	}
	if got := sizes[snap["big"].Root].Entries; got != rows {
		t.Errorf("big: %d entries, %d rows", got, rows)
	}
	if got := sizes[snap["kv"].Root].Entries; got != kvRows {
		t.Errorf("kv: %d entries, %d rows", got, kvRows)
	}
	if got := sizes[snap["big_note"].Root].Entries; got != rows {
		t.Errorf("big_note: %d entries, %d rows", got, rows)
	}
}

// A preview on real files: the newest point restored into a preview copy,
// kept and reused, migrations in one transaction and as written, a table
// rebuild, an index build on a big table, DROP COLUMN, VACUUM and a failing
// statement; production untouched.
func TestSQLitePreview(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	env, _ := testEnv(t)
	env.Config.Copies.PreviewKeep = time.Hour
	dir := t.TempDir()
	if d := os.Getenv("ROWSAFE_TEST_SQLITE_DIR"); d != "" {
		dir = d // the app's own folder (scripts/test-sqlite.sh)
	}
	path := filepath.Join(dir, "shop-"+time.Now().Format("150405.000")+".db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"PRAGMA journal_mode = WAL",
		"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL, legacy TEXT, created INTEGER)",
		"CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users (id), ref TEXT, note TEXT, payload BLOB)",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 3000) INSERT INTO users SELECT i, printf('u%d@example.com', i), 'old', i FROM n",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 30000) INSERT INTO orders SELECT i, 1 + i % 3000, hex(randomblob(8)), NULL, randomblob(400) FROM n",
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
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	// A change after the backup: the preview copy is the newest point.
	c = mustOpen(t, path)
	if err := c.Exec("INSERT INTO users VALUES (5000, 'late@example.com', 'old', 0)"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	before := prodState(t, path)

	preview := func(sql string, fresh int) *protocol.PreviewResult {
		t.Helper()
		res, err := run[protocol.PreviewResult](t, e, env, db, protocol.TaskPreviewMigration,
			protocol.PreviewParams{PreviewID: "p" + time.Now().Format("150405.000000")[7:], SQL: sql, FreshMinutes: fresh})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s (%s, reused %v, restore %d ms, %d ms)", res.Summary, res.Mode, res.CopyReused, res.RestoreMs, res.DurationMs)
		for _, s := range res.Statements {
			t.Logf("  %d L%d %s ran=%v %d ms rows=%v locks=%+v rewrites=%+v drops=%+v indexes=%+v risk=%s %s %s",
				s.N, s.Line, s.Command, s.Ran, s.DurationMs, derefRows(s.Rows), s.Locks, s.Rewrites, s.Dropped, s.IndexBuilds, s.Risk, s.Impact, s.Error)
		}
		for _, f := range res.Findings {
			t.Logf("  finding %s %s #%d: %s", f.Severity, f.Rule, f.Statement, f.Title)
		}
		return res
	}
	rules := func(res *protocol.PreviewResult) []string {
		var out []string
		for _, f := range res.Findings {
			out = append(out, f.Rule)
		}
		return out
	}

	// 1. One transaction: ADD COLUMN, an index on a big table, a rebuild.
	res := preview(`ALTER TABLE users ADD COLUMN nickname TEXT;
CREATE INDEX orders_ref ON orders (ref);
-- the rebuild SQLite needs to change a column
CREATE TABLE "new_users" (id INTEGER PRIMARY KEY, email TEXT NOT NULL, created INTEGER);
INSERT INTO "new_users" (id, email, created) SELECT id, email, created FROM users;
DROP TABLE users;
ALTER TABLE "new_users" RENAME TO users;
UPDATE orders SET note = 'x' WHERE id < 100;`, 0)
	if res.Mode != protocol.PreviewInTransaction || res.CopyReused || res.RestoreMs <= 0 || res.DataAsOf == nil || res.Error != nil || res.DB != "main" {
		t.Fatalf("first preview: %+v", res)
	}
	st := res.Statements
	if len(st) != 7 || st[2].Line != 4 {
		t.Fatalf("statements: %+v", st)
	}
	if len(st[0].Locks) != 1 || st[0].Locks[0].HeldMs < res.DurationMs-st[0].DurationMs || st[0].Locks[0].Blocks != "writes" || !strings.Contains(st[0].Locks[0].Mode, "reads continue") {
		t.Errorf("the write lock from the first statement to the commit: %+v (migration %d ms)", st[0].Locks, res.DurationMs)
	}
	if len(st[1].IndexBuilds) != 1 || st[1].IndexBuilds[0].Table != "orders" || st[1].IndexBuilds[0].Rows != 30000 || st[1].IndexBuilds[0].SizeBytes < 10<<20 {
		t.Errorf("index build: %+v", st[1].IndexBuilds)
	}
	if len(st[3].Rewrites) != 1 || st[3].Rewrites[0].Name != "users" || st[3].Rewrites[0].Rows != 3001 || st[3].Rows != nil {
		t.Errorf("the rebuild's copy: rewrites %+v rows %v", st[3].Rewrites, st[3].Rows)
	}
	if len(st[4].Dropped) != 0 {
		t.Errorf("a rebuilt table reported as dropped: %+v", st[4].Dropped)
	}
	if st[6].Rows == nil || *st[6].Rows != 99 {
		t.Errorf("UPDATE rows: %v", st[6].Rows)
	}
	if !strings.Contains(st[1].Impact, "Builds orders_ref on orders") {
		t.Errorf("index build impact: %q", st[1].Impact)
	}
	if slices.Contains(rules(res), "drop_table") || slices.Contains(rules(res), "rename") || res.Verdict != protocol.PreviewSafe {
		t.Errorf("a small, quick rebuild is neither a dropped table nor a rename that breaks code: %s %v", res.Verdict, rules(res))
	}
	states := e.previewCopyStates(env)
	if len(states) != 1 || states[0].Kind != protocol.CopyKindPreview || states[0].Status != protocol.CopyReady || states[0].Expires == nil || states[0].DatabaseID != db.ID {
		t.Fatalf("preview copy states: %+v", states)
	}

	// 2. As written (VACUUM), reusing the clean copy: DROP COLUMN of the
	// column the first preview's rebuild removed, then a failure.
	res = preview(`CREATE TABLE t2 (x);
VACUUM;
ALTER TABLE users DROP COLUMN legacy;
ALTER TABLE orders
  ADD COLUMN must INTEGER NOT NULL;
SELECT 1;`, 0)
	if res.Mode != protocol.PreviewAsWritten || !res.CopyReused || res.Verdict != protocol.PreviewFailed {
		t.Fatalf("second preview: %+v", res)
	}
	st = res.Statements
	if st[2].Error != "" || len(st[2].Rewrites) != 1 || st[2].Rewrites[0].Name != "users" {
		t.Errorf("DROP COLUMN on the kept copy (was it changed by the first preview?): %+v", st[2])
	}
	if res.Error == nil || res.Error.Statement != 4 || res.Error.Line != 4 || !strings.Contains(res.Error.Message, "NOT NULL") || res.Error.Hint == "" || st[4].Ran {
		t.Errorf("the failure: %+v", res.Error)
	}
	if len(st[1].Locks) != 1 || len(st[0].Locks) != 1 {
		t.Errorf("as written, each write holds the lock: %+v %+v", st[0].Locks, st[1].Locks)
	}
	for _, want := range []string{"vacuum", "partial_migration", "drop_column"} {
		if !slices.Contains(rules(res), want) {
			t.Errorf("missing finding %s: %v", want, rules(res))
		}
	}

	// 3. A new copy on request; a rebuild the other way round (rename the
	// old table away first) and a trigger with a body.
	res = preview(`BEGIN;
ALTER TABLE users RENAME TO users_old;
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, created INTEGER);
INSERT INTO users SELECT id, email, created FROM users_old;
DROP TABLE users_old;
CREATE TRIGGER users_touch AFTER INSERT ON users BEGIN
  UPDATE users SET created = CASE WHEN new.created IS NULL THEN 1 ELSE new.created END WHERE id = new.id;
END;
COMMIT;
SELECT count(*) FROM users;`, -1)
	if res.CopyReused || res.Error != nil || res.Mode != protocol.PreviewAsWritten {
		t.Fatalf("third preview: %+v", res)
	}
	st = res.Statements
	if len(st) != 8 || len(st[3].Rewrites) != 1 || st[3].Rewrites[0].Name != "users" || len(st[4].Dropped) != 0 {
		t.Errorf("rename-first rebuild: %+v", st)
	}
	if len(st[1].Locks) != 1 || len(st[2].Locks) != 0 || len(st[7].Locks) != 0 {
		t.Errorf("the transaction's lock from its first write to COMMIT: %+v / %+v / %+v", st[1].Locks, st[2].Locks, st[7].Locks)
	}
	// Renaming users away rewrote orders' reference to users_old, which is
	// then dropped: SQLite's foreign_key_check finds every order.
	if !slices.Contains(rules(res), "foreign_key_check") || slices.Contains(rules(res), "rename") {
		t.Errorf("rename-first rebuild findings: %v", rules(res))
	}

	// Production untouched.
	if after := prodState(t, path); after != before {
		t.Errorf("production changed:\n%s\n%s", before, after)
	}
	// One copy kept (the third replaced the first), deleted when it
	// expires; nothing left behind.
	if n := len(e.previewCopyStates(env)); n != 1 {
		t.Errorf("%d preview copies kept, want 1", n)
	}
	if e.dropPreviewCopy(env, "pv_nope") {
		t.Error("dropping an unknown copy")
	}
	e.expirePreviewCopies(env, time.Now().Add(2*time.Hour))
	if n := len(e.previewCopyStates(env)); n != 0 {
		t.Errorf("%d preview copies after they expired", n)
	}
	if entries, _ := os.ReadDir(previewRoot(env)); len(entries) != 0 {
		t.Errorf("left in the preview folder: %v", entries)
	}
	// A copy found in use when the agent starts was interrupted: deleted.
	pc := e.previewCopies(env)
	stale := previewCopy{ID: "pv_stale", DatabaseID: db.ID, Dir: filepath.Join(previewRoot(env), "pv_stale"), Status: protocol.CopyReady, InUse: true, CreatedAt: time.Now()}
	_ = os.MkdirAll(stale.Dir, 0o700)
	_ = pc.put(stale)
	e.recoverPreviewCopies(env)
	if _, err := os.Stat(stale.Dir); err == nil || len(e.previewCopyStates(env)) != 0 {
		t.Error("an interrupted preview copy survived the agent's start")
	}
}

func derefRows(n *int64) any {
	if n == nil {
		return nil
	}
	return *n
}

// prodState is production's schema and row counts.
func prodState(t *testing.T, path string) string {
	t.Helper()
	c := mustOpen(t, path)
	defer c.Close()
	schema, err := queryText(c, "SELECT group_concat(sql, ';') FROM (SELECT sql FROM sqlite_schema ORDER BY name)")
	if err != nil {
		t.Fatal(err)
	}
	users, _ := queryInt(c, "SELECT count(*) FROM users")
	orders, _ := queryInt(c, "SELECT count(*) FROM orders")
	notes, _ := queryInt(c, "SELECT count(note) FROM orders")
	return fmt.Sprintf("%s | %d %d %d", schema, users, orders, notes)
}
