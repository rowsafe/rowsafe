package preview

import (
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestSplitSQLite(t *testing.T) {
	sql := "-- migration 7; with a semicolon\n" +
		".read other.sql\n" +
		"CREATE TABLE \"we;ird\" (id INTEGER PRIMARY KEY, note TEXT DEFAULT 'it''s;', [odd;name] INT, `b;q` INT);\n" +
		"/* block ; comment */\n" +
		"ALTER TABLE orders ADD COLUMN x INT -- trailing; comment\n" +
		"  DEFAULT 0;\n" +
		"CREATE TEMP TRIGGER t AFTER INSERT ON orders WHEN new.x > 0 BEGIN\n" +
		"  UPDATE orders SET x = CASE WHEN new.x > 9 THEN 9 ELSE new.x END WHERE id = new.id;\n" +
		"  INSERT INTO log VALUES ('a;b');\n" +
		"END;\n" +
		";;\n" +
		"CREATE TRIGGER u BEFORE DELETE ON orders BEGIN SELECT RAISE(ABORT, 'no; deletes'); END;\n" +
		"SELECT 1"
	got, err := SplitSQLite(sql)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		line int
		cmd  string
		meta bool
	}{{2, "", true}, {3, "CREATE TABLE", false}, {5, "ALTER TABLE", false}, {7, "CREATE TRIGGER", false}, {12, "CREATE TRIGGER", false}, {13, "SELECT", false}}
	if len(got) != len(want) {
		for _, s := range got {
			t.Logf("%d %v %q", s.Line, s.Meta, s.Text)
		}
		t.Fatalf("%d statements, want %d", len(got), len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.Line != w.line || g.Meta != w.meta || (!w.meta && Command(g.Text) != w.cmd) {
			t.Errorf("statement %d = line %d meta %v %q (%s), want line %d meta %v %s", i, g.Line, g.Meta, g.Text, Command(g.Text), w.line, w.meta, w.cmd)
		}
	}
	if !strings.HasSuffix(got[3].Text, "END") || !strings.Contains(got[3].Text, "'a;b'") {
		t.Errorf("the trigger's body was cut: %q", got[3].Text)
	}
	for _, bad := range []string{"SELECT 'open", "SELECT [open", "SELECT 1 /* open"} {
		if _, err := SplitSQLite(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
	if s, _ := SplitFor("sqlite", "SELECT 1; SELECT 2"); len(s) != 2 {
		t.Errorf("SplitFor(sqlite) = %v", s)
	}
}

func TestModeAndSkipSQLite(t *testing.T) {
	mode := func(sql string) string {
		s, err := SplitSQLite(sql)
		if err != nil {
			t.Fatal(err)
		}
		return ModeSQLite(s)
	}
	for sql, want := range map[string]string{
		"ALTER TABLE a ADD COLUMN b INT; CREATE INDEX i ON a(b)":             "transaction",
		"BEGIN; ALTER TABLE a ADD COLUMN b INT; COMMIT":                      "as_written",
		"CREATE INDEX i ON a(b); VACUUM":                                     "as_written",
		"PRAGMA foreign_keys=OFF; CREATE TABLE n(x); PRAGMA foreign_keys=ON": "as_written",
		"PRAGMA user_version = 3; CREATE TABLE n(x)":                         "transaction",
		"CREATE TRIGGER t AFTER INSERT ON a BEGIN UPDATE a SET b = 1; END":   "transaction",
	} {
		if got := mode(sql); got != want {
			t.Errorf("ModeSQLite(%q) = %s, want %s", sql, got, want)
		}
	}
	for text, skip := range map[string]bool{
		"ATTACH DATABASE '/etc/x.db' AS x": true, "DETACH x": true, "VACUUM INTO '/tmp/x.db'": true, "VACUUM": false,
		"SELECT load_extension('x')": true, "PRAGMA temp_store_directory = '/tmp'": true, "CREATE TABLE t(x)": false,
	} {
		if got := SkipSQLite(Stmt{Text: text}) != ""; got != skip {
			t.Errorf("SkipSQLite(%q) = %v, want %v", text, got, skip)
		}
	}
	if SkipSQLite(Stmt{Text: ".tables", Meta: true}) == "" {
		t.Error("a shell command should be skipped")
	}
}

func TestSQLiteLocks(t *testing.T) {
	wal := SQLiteContext{JournalMode: "wal", File: "app.db", FileBytes: 1 << 30}
	rollback := SQLiteContext{JournalMode: "delete", File: "wiki.db", FileBytes: 1 << 20}
	if l := SQLiteLock(wal, 5); l.Blocks != "writes" || !strings.Contains(l.Mode, "reads continue") || l.Relation != "app.db" {
		t.Errorf("WAL lock: %+v", l)
	}
	if l := SQLiteLock(rollback, 5); !strings.Contains(l.Mode, "reads also wait while it commits") {
		t.Errorf("rollback-journal lock: %+v", l)
	}

	// One transaction: the first write holds the lock until the commit.
	texts := []string{"SELECT 1", "CREATE TABLE n(x)", "CREATE INDEX i ON a(b)"}
	res := &protocol.PreviewResult{Mode: protocol.PreviewInTransaction, DurationMs: 3100, Statements: []protocol.PreviewStatement{
		stmt(1, texts[0], 100), stmt(2, texts[1], 1000), stmt(3, texts[2], 1900)}}
	AssignSQLiteLocks(res, texts, []bool{false, true, true}, wal)
	if len(res.Statements[0].Locks) != 0 || len(res.Statements[2].Locks) != 0 || len(res.Statements[1].Locks) != 1 || res.Statements[1].Locks[0].HeldMs != 3000 {
		t.Errorf("transaction locks: %+v", res.Statements)
	}

	// As written: each write alone, and a BEGIN ... COMMIT span as one.
	texts = []string{"CREATE TABLE n(x)", "BEGIN", "SELECT 1", "INSERT INTO n VALUES (1)", "UPDATE n SET x = 2", "COMMIT", "VACUUM"}
	res = &protocol.PreviewResult{Mode: protocol.PreviewAsWritten, Statements: []protocol.PreviewStatement{
		stmt(1, texts[0], 10), stmt(2, texts[1], 1), stmt(3, texts[2], 5), stmt(4, texts[3], 200), stmt(5, texts[4], 300), stmt(6, texts[5], 50), stmt(7, texts[6], 4000)}}
	AssignSQLiteLocks(res, texts, []bool{true, false, false, true, true, false, true}, rollback)
	held := func(i int) int64 {
		if len(res.Statements[i].Locks) == 0 {
			return -1
		}
		return res.Statements[i].Locks[0].HeldMs
	}
	if held(0) != 10 || held(1) != -1 || held(3) != 550 || held(4) != -1 || held(6) != 4000 {
		t.Errorf("as written locks: %d %d %d %d %d", held(0), held(1), held(3), held(4), held(6))
	}
}

func TestAssessSQLite(t *testing.T) {
	c := SQLiteContext{JournalMode: "delete", File: "app.db", FileBytes: 2 << 30, DiskFreeBytes: 1 << 30}
	texts := []string{
		"CREATE INDEX orders_ref ON orders (ref)",
		"ALTER TABLE users ADD COLUMN nick TEXT",
		"ALTER TABLE users DROP COLUMN legacy",
		"DELETE FROM sessions",
		"VACUUM",
	}
	rows := int64(120_000)
	res := &protocol.PreviewResult{Mode: protocol.PreviewAsWritten, DB: "main", Statements: []protocol.PreviewStatement{
		stmt(1, texts[0], 12_000), stmt(2, texts[1], 2), stmt(3, texts[2], 1500), stmt(4, texts[3], 900), stmt(5, texts[4], 30_000)}}
	res.Statements[0].IndexBuilds = []protocol.PreviewRelation{{Name: "orders_ref", Table: "orders", SizeBytes: 300 << 20, Rows: 2_000_000}}
	res.Statements[2].Rewrites = []protocol.PreviewRelation{{Name: "users", SizeBytes: 40 << 20, Rows: 50_000}}
	res.Statements[3].Rows = &rows
	AssignSQLiteLocks(res, texts, []bool{true, true, true, true, true}, c)
	AssessSQLite(res, texts, c)
	got := rulesOf(res)
	for _, want := range []string{"create_index_blocks_writes", "vacuum", "table_rewrite", "drop_column", "update_without_where", "large_data_change", "rollback_journal_reads"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing finding %s in %v", want, got)
		}
	}
	for _, f := range res.Findings {
		if (f.Statement == 1 || f.Statement == 5) && (f.Rule == "lock" || f.Rule == "long_lock") {
			t.Errorf("a generic lock finding next to the index build or VACUUM: %+v", f)
		}
		if f.Rule == "vacuum" && (f.Severity != protocol.PreviewDangerous || !strings.Contains(f.Detail, "isn't enough")) {
			t.Errorf("VACUUM without room on the disk: %+v", f)
		}
		if strings.Contains(f.Suggestion+f.Detail, "lock_timeout") || strings.Contains(f.Detail, "replicas") {
			t.Errorf("PostgreSQL wording in a SQLite finding: %+v", f)
		}
	}
	if res.Verdict != protocol.PreviewDangerous || res.Statements[0].Risk != protocol.PreviewDangerous || res.Statements[1].Risk != protocol.PreviewSafe {
		t.Errorf("verdict %s, risks %s %s: %s", res.Verdict, res.Statements[0].Risk, res.Statements[1].Risk, res.Summary)
	}
	if !strings.HasPrefix(res.Summary, "Dangerous: ") {
		t.Errorf("summary: %s", res.Summary)
	}

	// PRAGMA foreign_keys inside the script's own transaction.
	texts = []string{"BEGIN", "PRAGMA foreign_keys = OFF", "CREATE TABLE n(x)", "COMMIT"}
	res = &protocol.PreviewResult{Mode: protocol.PreviewAsWritten, Statements: []protocol.PreviewStatement{
		stmt(1, texts[0], 1), stmt(2, texts[1], 1), stmt(3, texts[2], 1), stmt(4, texts[3], 1)}}
	AssignSQLiteLocks(res, texts, []bool{false, false, true, false}, SQLiteContext{JournalMode: "wal", File: "app.db"})
	AssessSQLite(res, texts, SQLiteContext{JournalMode: "wal", File: "app.db"})
	if !slices.Contains(rulesOf(res), "foreign_keys_in_transaction") || res.Verdict != protocol.PreviewCareful {
		t.Errorf("foreign_keys in a transaction: %v %s", rulesOf(res), res.Verdict)
	}

	// As written, a failure after committed changes leaves them applied.
	texts = []string{"CREATE TABLE n(x)", "ALTER TABLE nope ADD COLUMN y INT"}
	res = &protocol.PreviewResult{Mode: protocol.PreviewAsWritten, Statements: []protocol.PreviewStatement{stmt(1, texts[0], 1), stmt(2, texts[1], 1)},
		Error: &protocol.PreviewError{Statement: 2, Line: 1, Message: "no such table: nope"}}
	res.Statements[1].Error = "no such table: nope"
	AssignSQLiteLocks(res, texts, []bool{true, false}, SQLiteContext{JournalMode: "wal"})
	AssessSQLite(res, texts, SQLiteContext{JournalMode: "wal"})
	if res.Verdict != protocol.PreviewFailed || !slices.Contains(rulesOf(res), "partial_migration") {
		t.Errorf("partial migration: %v %s", rulesOf(res), res.Verdict)
	}

	// Small and quick: safe.
	texts = []string{"ALTER TABLE users ADD COLUMN nick TEXT", "CREATE INDEX i ON users(nick)"}
	res = &protocol.PreviewResult{Mode: protocol.PreviewInTransaction, DB: "main", DurationMs: 30, Statements: []protocol.PreviewStatement{stmt(1, texts[0], 2), stmt(2, texts[1], 20)}}
	res.Statements[1].IndexBuilds = []protocol.PreviewRelation{{Name: "i", Table: "users", SizeBytes: 64 << 10}}
	AssignSQLiteLocks(res, texts, []bool{true, true}, SQLiteContext{JournalMode: "wal", File: "app.db"})
	AssessSQLite(res, texts, SQLiteContext{JournalMode: "wal", File: "app.db"})
	if res.Verdict != protocol.PreviewSafe || len(res.Findings) != 0 {
		t.Errorf("a small migration: %s %v %s", res.Verdict, rulesOf(res), res.Summary)
	}
}
