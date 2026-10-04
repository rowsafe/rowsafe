package sqlite

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/ext/fts5"

	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// richSchema is an app's database with every kind of object a copy must
// handle: rowid, WITHOUT ROWID and STRICT tables, AUTOINCREMENT, a
// generated column, unique, expression and partial indexes, views on
// views, AFTER and INSTEAD OF triggers (one writing an audit log), FTS5
// tables (external content, own text, contentless) and a virtual table of
// a module the agent doesn't have (R*Tree, declared by hand).
const richSchema = `
PRAGMA user_version = 7;
CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, full_name VARCHAR(100), phone TEXT,
	notes CLOB, created_at DATETIME, score REAL, flags, lower_email TEXT GENERATED ALWAYS AS (lower(email)) VIRTUAL);
CREATE TABLE audit (id INTEGER PRIMARY KEY, what TEXT);
CREATE TABLE tags (user_id INTEGER NOT NULL REFERENCES users(id) ON UPDATE CASCADE, tag TEXT NOT NULL, PRIMARY KEY (user_id, tag)) WITHOUT ROWID;
CREATE TABLE settings (k TEXT PRIMARY KEY, v ANY) STRICT;
CREATE INDEX users_name ON users(full_name);
CREATE INDEX users_lower ON users(lower(email));
CREATE INDEX users_recent ON users(created_at) WHERE created_at IS NOT NULL;
CREATE VIEW active_users AS SELECT id, email FROM users WHERE flags IS NULL;
CREATE VIEW active_count AS SELECT count(*) AS n FROM active_users;
CREATE TRIGGER users_audit AFTER UPDATE ON users BEGIN INSERT INTO audit(what) VALUES ('changed ' || old.email); END;
CREATE TRIGGER active_users_ins INSTEAD OF INSERT ON active_users BEGIN INSERT INTO users(email) VALUES (new.email); END;
CREATE VIRTUAL TABLE users_fts USING fts5(full_name, email, content=users, content_rowid=id);
CREATE TRIGGER users_fts_ai AFTER INSERT ON users BEGIN INSERT INTO users_fts(rowid, full_name, email) VALUES (new.id, new.full_name, new.email); END;
CREATE VIRTUAL TABLE notes_fts USING fts5(body);
CREATE VIRTUAL TABLE words USING fts5(w, content='');
CREATE TABLE geo_node(nodeno INTEGER PRIMARY KEY, data);
CREATE TABLE geo_rowid(rowid INTEGER PRIMARY KEY, nodeno);
CREATE TABLE geo_parent(nodeno INTEGER PRIMARY KEY, parentnode);
PRAGMA writable_schema = ON;
INSERT INTO sqlite_schema VALUES ('table', 'geo', 'geo', 0, 'CREATE VIRTUAL TABLE geo USING rtree(id, minx, maxx)');
PRAGMA writable_schema = OFF;
CREATE TRIGGER users_geo AFTER DELETE ON users BEGIN DELETE FROM geo WHERE id = old.id; END;
`

// createRichDB makes the database at path (WAL or rollback journal) with
// n users.
func createRichDB(t *testing.T, path string, wal bool, n int) {
	t.Helper()
	c := openFTS(t, path)
	defer c.Close()
	mode := "DELETE"
	if wal {
		mode = "WAL"
	}
	if err := c.Exec("PRAGMA journal_mode=" + mode + ";" + richSchema); err != nil {
		t.Fatal(err)
	}
	c.Close()
	addRichUsers(t, path, 1, n)
}

func openFTS(t *testing.T, path string) *sqlite3.Conn {
	t.Helper()
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.BusyTimeout(10e9)
	if err := fts5.Register(c); err != nil {
		t.Fatal(err)
	}
	return c
}

// addRichUsers inserts users from..to (as the app does), then refreshes
// the statistics (sqlite_stat4 keeps sample emails).
func addRichUsers(t *testing.T, path string, from, to int) {
	t.Helper()
	c := openFTS(t, path)
	defer c.Close()
	var b strings.Builder
	b.WriteString("BEGIN;")
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, `INSERT INTO users (id, email, full_name, phone, notes, created_at, score) VALUES (%d, 'user%d@corp.example', 'Person Number%d', '+1 555 01%02d', 'secret note %d', '2024-01-%02d 10:00:00', %d.5);`,
			i, i, i, i%100, i, 1+i%28, i)
		fmt.Fprintf(&b, `INSERT INTO tags VALUES (%d, 'vip');`, i)
		fmt.Fprintf(&b, `INSERT INTO notes_fts (body) VALUES ('confidential memo %d');`, i)
		fmt.Fprintf(&b, `INSERT INTO words (w) VALUES ('hiddenword%d');`, i)
	}
	fmt.Fprintf(&b, `INSERT OR REPLACE INTO settings VALUES ('theme', 'dark'); COMMIT; ANALYZE;`)
	if err := c.Exec(b.String()); err != nil {
		t.Fatal(err)
	}
}

func TestParseVirtual(t *testing.T) {
	for _, tc := range []struct {
		sql, module, content string
		args                 int
	}{
		{`CREATE VIRTUAL TABLE users_fts USING fts5(full_name, email, content=users, content_rowid=id)`, "fts5", ftsExternal, 4},
		{`CREATE VIRTUAL TABLE "my ""docs""" USING FTS5 (body, tokenize = 'porter unicode61')`, "fts5", ftsInternal, 2},
		{`CREATE VIRTUAL TABLE IF NOT EXISTS main.w USING fts5(w, content='')`, "fts5", ftsContentless, 2},
		{`create virtual table [w] using fts5(w, content="")`, "fts5", ftsContentless, 2},
		{`CREATE VIRTUAL TABLE geo USING rtree(id, minx, maxx)`, "rtree", ftsInternal, 3},
		{`CREATE VIRTUAL TABLE t USING mymodule`, "mymodule", ftsInternal, 0},
		{`CREATE TABLE plain (x)`, "", ftsInternal, 0},
	} {
		v := parseVirtual("x", tc.sql)
		if v.Module != tc.module || v.ftsContent() != tc.content || len(v.Args) != tc.args {
			t.Errorf("%s: module %q content %q args %q", tc.sql, v.Module, v.ftsContent(), v.Args)
		}
	}
	if got := splitArgs(`a, b('x,y'), "c,d", [e,f], g`); len(got) != 5 || got[1] != "b('x,y')" {
		t.Errorf("splitArgs: %q", got)
	}
}

func TestSQLiteType(t *testing.T) {
	for decl, want := range map[string]string{
		"TEXT": "text", "VARCHAR(255)": "varchar(255)", "INTEGER": "integer", "unsigned big int": "integer", "CLOB": "text",
		"NATIVE CHARACTER(70)": "text", "DOUBLE": "double", "REAL": "real", "FLOAT": "float", "DATETIME": "datetime",
		"datetime(6)": "datetime(6)", "BOOLEAN": "boolean", "JSON": "json", "": "", "BLOB": "blob", "decimal(10,2)": "decimal(10,2)",
	} {
		if got := sqliteType(decl, false); got != want {
			t.Errorf("sqliteType(%q) = %q, want %q", decl, got, want)
		}
	}
	if got := sqliteType("", true); got != "text" {
		t.Errorf("an FTS5 column: %q", got)
	}
	if masking.Class(sqliteType("NVARCHAR(20)", false)) != masking.ClassText || masking.MaxLen(sqliteType("varchar(20)", false)) != 20 {
		t.Error("text classes")
	}
}

func TestSQLiteCopySchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	createRichDB(t, path, true, 20)
	c := mustOpenScratch(t, path)
	defer c.Close()
	res, err := readCopySchema(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Databases) != 1 || res.Databases[0].Name != "main" {
		t.Fatalf("%+v", res)
	}
	tables := map[string]protocol.SchemaTable{}
	var names []string
	for _, tb := range res.Databases[0].Tables {
		tables[tb.Name] = tb
		names = append(names, tb.Name)
	}
	if want := []string{"audit", "notes_fts", "settings", "tags", "users"}; !slices.Equal(names, want) {
		t.Fatalf("tables %v, want %v (no views, shadow tables, external or contentless FTS, unknown modules)", names, want)
	}
	cols := map[string]protocol.SchemaColumn{}
	for _, col := range tables["users"].Columns {
		cols[col.Name] = col
	}
	switch {
	case !cols["email"].Unique || cols["email"].Nullable || cols["email"].Type != "text":
		t.Errorf("email: %+v", cols["email"])
	case !cols["id"].Unique || cols["id"].Type != "integer":
		t.Errorf("id: %+v", cols["id"])
	case !cols["lower_email"].Generated:
		t.Errorf("lower_email: %+v", cols["lower_email"])
	case cols["notes"].Type != "text" || !cols["notes"].Nullable || cols["full_name"].Type != "varchar(100)" || cols["flags"].Type != "":
		t.Errorf("types: %+v", cols)
	case tables["users"].Rows != 20:
		t.Errorf("users rows: %d", tables["users"].Rows)
	}
	if body := tables["notes_fts"].Columns; len(body) != 1 || body[0].Type != "text" {
		t.Errorf("notes_fts: %+v", body)
	}
	for _, col := range tables["tags"].Columns {
		if col.Unique {
			t.Errorf("tags.%s is only unique with the other column", col.Name)
		}
	}
	plan := masking.Plan(res, protocol.MaskingPlan{Mode: protocol.MaskingRules}, &protocol.MaskingReport{})
	got := map[string]string{}
	for _, tp := range plan {
		for _, col := range tp.Columns {
			got[tp.Table+"."+col.Name] = col.Strategy
		}
	}
	if got["users.email"] != masking.Email || got["users.full_name"] != masking.FullName || got["users.phone"] != masking.Format {
		t.Errorf("suggestions: %v", got)
	}
}

func mustOpenScratch(t *testing.T, path string) *sqlite3.Conn {
	t.Helper()
	c, err := openDB(context.Background(), path, openOpts{Scratch: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := fts5.Register(c); err != nil {
		t.Fatal(err)
	}
	return c
}

// maskRules are the saved rules the tests use besides the suggestions.
var maskRules = []protocol.MaskingRule{
	{DB: "main", Table: "users", Column: "notes", Strategy: masking.Lorem},
	{DB: "main", Table: "notes_fts", Column: "body", Strategy: masking.Lorem},
	{DB: "main", Table: "users", Column: "flags", Strategy: masking.Email}, // doesn't fit: the suggestion is used
}

func TestSQLiteMaskCopy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	createRichDB(t, path, true, 40)
	report, err := maskCopy(context.Background(), path, protocol.MaskingPlan{Mode: protocol.MaskingRules, Rules: maskRules},
		bytes.Repeat([]byte{7}, 32), testLog{t})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("report: %+v", report)
	checkMaskedCopy(t, path, report, 40)
}

// checkMaskedCopy checks a masked copy of a rich database with n users.
func checkMaskedCopy(t *testing.T, path string, report protocol.MaskingReport, n int) {
	t.Helper()
	if report.Tables < 2 || report.Columns < 4 || report.Strategies[masking.Email] != 1 || report.Rows < int64(n) {
		t.Errorf("report: %+v", report)
	}
	skipped := strings.Join(report.Skipped, "\n")
	for _, want := range []string{"geo: a virtual table of the SQLite extension rtree", "words: a full-text search table without its text", "flags"} {
		if !strings.Contains(skipped, want) {
			t.Errorf("skipped should mention %q: %s", want, skipped)
		}
	}
	for _, side := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Stat(path + side); err == nil {
			t.Errorf("the copy has a %s file: it should be one file", side)
		}
	}
	c := mustOpenScratch(t, path)
	defer c.Close()
	if m, _ := journalMode(c); m != "delete" {
		t.Errorf("journal mode %s", m)
	}
	masked := 0
	err := queryRows(c, `SELECT id, email, full_name, phone, notes, lower_email FROM users`, func(s *sqlite3.Stmt) error {
		id := s.ColumnInt(0)
		email, name, phone, notes, lower := s.ColumnText(1), s.ColumnText(2), s.ColumnText(3), s.ColumnText(4), s.ColumnText(5)
		switch {
		case email == fmt.Sprintf("user%d@corp.example", id) || !exampleEmailRE.MatchString(email):
			t.Errorf("user %d: email %q", id, email)
		case name == fmt.Sprintf("Person Number%d", id) || len(strings.Fields(name)) < 2:
			t.Errorf("user %d: name %q", id, name)
		case phone == fmt.Sprintf("+1 555 01%02d", id%100) || len(phone) != len("+1 555 0100") || !strings.HasPrefix(phone, "+"):
			t.Errorf("user %d: phone %q", id, phone)
		case strings.Contains(notes, "secret"):
			t.Errorf("user %d: notes %q", id, notes)
		case lower != strings.ToLower(email):
			t.Errorf("user %d: the generated column %q doesn't follow %q", id, lower, email)
		default:
			masked++
		}
		return nil
	})
	if err != nil || masked != n {
		t.Fatalf("masked %d of %d users: %v", masked, n, err)
	}
	count := func(q string) int64 {
		t.Helper()
		v, err := queryInt(c, q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return v
	}
	for q, want := range map[string]int64{
		`SELECT count(*) FROM audit`:                                          0, // the audit trigger didn't run during masking
		`SELECT count(*) FROM users_fts WHERE users_fts MATCH 'corp'`:         0,
		`SELECT count(*) FROM users_fts WHERE users_fts MATCH 'number1'`:      0,
		`SELECT count(*) FROM notes_fts WHERE notes_fts MATCH 'confidential'`: 0,
		`SELECT count(*) FROM notes_fts`:                                      int64(n),
		`SELECT count(*) FROM words WHERE words MATCH 'hiddenword1'`:          0,
		`SELECT count(*) FROM sqlite_stat4`:                                   0,
		`SELECT count(*) FROM tags`:                                           int64(n),
		`SELECT count(*) FROM sqlite_schema WHERE name IN ('geo', 'geo_node', 'geo_rowid', 'geo_parent', 'users_geo')`:              0,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'trigger' AND name IN ('users_audit', 'active_users_ins', 'users_fts_ai')`: 3,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name IN ('users_name', 'users_lower', 'users_recent')`:         3,
		`SELECT n FROM active_count`: int64(n),
		`PRAGMA user_version`:        7,
	} {
		if got := count(q); got != want {
			t.Errorf("%s = %d, want %d", q, got, want)
		}
	}
	if got := count(`SELECT count(*) FROM users_fts WHERE users_fts MATCH 'example'`); got != int64(n) {
		t.Errorf("the search index wasn't rebuilt from the masked emails: %d", got)
	}
	if r, _ := queryText(c, `PRAGMA integrity_check`); r != "ok" {
		t.Errorf("integrity: %s", r)
	}
	c.Close()
	// No original value is left anywhere in the file: not in free pages,
	// the search indexes or the statistics.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"corp.example", "Person Number", "secret note", "confidential", "hiddenword", "+1 555 01"} {
		if bytes.Contains(data, []byte(s)) {
			t.Errorf("the masked file still contains %q", s)
		}
	}
}

var exampleEmailRE = regexp.MustCompile(`^[a-z][a-z-]*\.[0-9a-f]{8,}@example\.(com|net|org)$`)

func TestSQLiteMaskNoneKeepsData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	createRichDB(t, path, true, 5)
	report, err := maskCopy(context.Background(), path, protocol.MaskingPlan{Mode: protocol.MaskingNone}, bytes.Repeat([]byte{1}, 32), testLog{t})
	if err != nil || report.Columns != 0 || report.Mode != protocol.MaskingNone {
		t.Fatalf("%+v %v", report, err)
	}
	c := mustOpenScratch(t, path)
	defer c.Close()
	if e, _ := queryText(c, `SELECT email FROM users WHERE id = 3`); e != "user3@corp.example" {
		t.Errorf("email %q", e)
	}
}

func TestSQLiteMaskConstraintFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.db")
	c, err := sqlite3.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Exec(`CREATE TABLE p (id INTEGER PRIMARY KEY, phone TEXT CHECK (phone LIKE '555-%'), email TEXT NOT NULL CHECK (email LIKE '%@corp.example'));
		INSERT INTO p VALUES (1, '555-1234', 'a@corp.example')`); err != nil {
		t.Fatal(err)
	}
	c.Close()
	key := bytes.Repeat([]byte{2}, 32)
	_, err = maskCopy(context.Background(), path, protocol.MaskingPlan{Mode: protocol.MaskingRules}, key, testLog{t})
	if err == nil || !strings.Contains(err.Error(), "can't be emptied") {
		t.Fatalf("a NOT NULL column whose masked values break a CHECK should fail the copy: %v", err)
	}
	// Without the email rule clash: phone (nullable) is emptied instead.
	report, err := maskCopy(context.Background(), path, protocol.MaskingPlan{Mode: protocol.MaskingRules,
		Rules: []protocol.MaskingRule{{DB: "main", Table: "p", Column: "email", Strategy: masking.Keep}, {DB: "main", Table: "p", Column: "phone", Strategy: masking.Lorem}}}, key, testLog{t})
	if err != nil || report.Strategies[masking.Null] != 1 || len(report.Skipped) != 1 {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestSQLiteSchemaOnlyCopy(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "app.db")
	createRichDB(t, src, true, 30)
	dst := filepath.Join(dir, "structure.db")
	out, err := schemaOnlyCopy(context.Background(), src, dst, testLog{t})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s; left out: %v", out.describe(), out.LeftOut)
	checkSchemaOnly(t, src, dst, out)
}

// checkSchemaOnly checks that dst has every object of src (but the
// unknown virtual table) and no row.
func checkSchemaOnly(t *testing.T, src, dst string, out schemaOut) {
	t.Helper()
	if len(out.LeftOut) != 2 || !strings.Contains(strings.Join(out.LeftOut, "\n"), "trigger users_geo: it uses geo") {
		t.Errorf("left out: %v", out.LeftOut)
	}
	if fi, err := os.Stat(dst); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", fi.Mode(), err)
	}
	objects := func(path string) []string {
		c := mustOpenScratch(t, path)
		defer c.Close()
		var out []string
		_ = queryRows(c, `SELECT type || ' ' || name FROM sqlite_schema WHERE name NOT IN ('geo', 'geo_node', 'geo_rowid', 'geo_parent', 'users_geo') ORDER BY 1`,
			func(s *sqlite3.Stmt) error { out = append(out, s.ColumnText(0)); return nil })
		return out
	}
	want, got := objects(src), objects(dst)
	want = slices.DeleteFunc(want, func(s string) bool { return strings.Contains(s, "sqlite_stat") })
	if !slices.Equal(want, got) {
		t.Errorf("objects:\n got %v\nwant %v", got, want)
	}
	c := mustOpenScratch(t, dst)
	defer c.Close()
	var tables []string
	_ = queryRows(c, `SELECT name FROM pragma_table_list WHERE schema = 'main' AND type IN ('table', 'virtual') AND name NOT LIKE 'sqlite_%'`,
		func(s *sqlite3.Stmt) error { tables = append(tables, s.ColumnText(0)); return nil })
	if len(tables) < 7 {
		t.Errorf("tables: %v", tables)
	}
	for _, tb := range tables {
		if n, err := queryInt(c, `SELECT count(*) FROM `+quoteIdent(tb)); err != nil || n != 0 {
			t.Errorf("%s: %d rows %v", tb, n, err)
		}
	}
	if v, _ := queryInt(c, `PRAGMA user_version`); v != 7 {
		t.Errorf("user_version %d", v)
	}
	if m, _ := journalMode(c); m != "delete" {
		t.Errorf("journal mode %s", m)
	}
	// It works as the app's database: the triggers and search run.
	if err := c.Exec(`PRAGMA foreign_keys = ON; INSERT INTO users (email, full_name) VALUES ('new@example.com', 'New Person'); UPDATE users SET full_name = 'x';
		INSERT INTO users (email) VALUES ('gone@example.com'); DELETE FROM users WHERE email = 'gone@example.com'`); err != nil {
		t.Fatal(err)
	}
	if n, _ := queryInt(c, `SELECT count(*) FROM users_fts WHERE users_fts MATCH 'new'`); n != 1 {
		t.Errorf("search in the new file: %d", n)
	}
	if n, _ := queryInt(c, `SELECT count(*) FROM audit`); n != 1 {
		t.Errorf("audit trigger: %d", n)
	}
}
