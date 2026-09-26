package preview

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestSplit(t *testing.T) {
	sql := `-- migration 42
BEGIN;
CREATE TABLE a (id int, note text DEFAULT 'semi;colon');
/* block ; comment /* nested ; */ still */
CREATE FUNCTION f() RETURNS trigger AS $body$
BEGIN
  RAISE NOTICE 'x;y';
  RETURN NEW;
END;
$body$ LANGUAGE plpgsql;
INSERT INTO "we;ird" VALUES (E'it\'s;', $$a;b$$);
\set ON_ERROR_STOP on
COMMIT;
;;
SELECT 1`
	got, err := Split(sql)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		line int
		cmd  string
		meta bool
	}{{2, "BEGIN", false}, {3, "CREATE TABLE", false}, {5, "CREATE FUNCTION", false}, {11, "INSERT", false},
		{12, "", true}, {13, "COMMIT", false}, {15, "SELECT", false}}
	if len(got) != len(want) {
		for _, s := range got {
			t.Logf("%d %q", s.Line, s.Text)
		}
		t.Fatalf("%d statements, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Line != w.line || got[i].Meta != w.meta || (!w.meta && Command(got[i].Text) != w.cmd) {
			t.Errorf("statement %d: line %d meta %v cmd %q (%q), want %+v", i, got[i].Line, got[i].Meta, Command(got[i].Text), got[i].Text, w)
		}
	}
	if !strings.Contains(got[2].Text, "RAISE NOTICE 'x;y'") || !strings.HasSuffix(got[2].Text, "LANGUAGE plpgsql") {
		t.Errorf("function body split: %q", got[2].Text)
	}
	for _, bad := range []string{"SELECT 'x", "SELECT $$x", "/* x", `SELECT "x`} {
		if _, err := Split(bad); err == nil {
			t.Errorf("Split(%q): no error", bad)
		}
	}
	if s, _ := Split("  \n-- only a comment\n"); len(s) != 0 {
		t.Errorf("comment-only script: %v", s)
	}
}

func TestModeAndCommand(t *testing.T) {
	for sql, want := range map[string]string{
		"ALTER TABLE a ADD COLUMN b int; CREATE INDEX i ON a (b);": "transaction",
		"CREATE INDEX CONCURRENTLY i ON a (b);":                    "as_written",
		"BEGIN; ALTER TABLE a ADD b int; COMMIT;":                  "as_written",
		"VACUUM ANALYZE a;":                                        "as_written",
	} {
		stmts, _ := Split(sql)
		if got := Mode(stmts); got != want {
			t.Errorf("Mode(%q) = %s, want %s", sql, got, want)
		}
	}
	for stmt, want := range map[string]string{
		"create unique index concurrently x on y (z)": "CREATE INDEX",
		"CREATE OR REPLACE FUNCTION f()":              "CREATE FUNCTION",
		"CREATE MATERIALIZED VIEW v AS SELECT 1":      "CREATE MATERIALIZED VIEW",
		"ALTER TABLE t ADD c int":                     "ALTER TABLE",
		"WITH x AS (SELECT 1) UPDATE t SET a = 1":     "UPDATE",
		"start transaction":                           "BEGIN",
		"refresh materialized view v":                 "REFRESH MATERIALIZED VIEW",
	} {
		if got := Command(stmt); got != want {
			t.Errorf("Command(%q) = %q, want %q", stmt, got, want)
		}
	}
}

func TestParseCreateExtension(t *testing.T) {
	e, ok := ParseCreateExtension(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public VERSION '1.1' CASCADE`)
	if !ok || e.Name != "uuid-ossp" || !e.IfNotExists || e.Schema != "public" || e.Version != "1.1" || !e.Cascade {
		t.Fatalf("%+v %v", e, ok)
	}
	if e, ok := ParseCreateExtension("create extension pgcrypto"); !ok || e.Name != "pgcrypto" {
		t.Fatalf("%+v", e)
	}
	for _, bad := range []string{"CREATE EXTENSION x; DROP TABLE y", "CREATE EXTENSION x SCHEMA a b", "CREATE TABLE x ()"} {
		if _, ok := ParseCreateExtension(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func stmt(n int, sql string, ms int64) protocol.PreviewStatement {
	return protocol.PreviewStatement{N: n, Line: n, SQL: Shorten(sql, 300), Command: Command(sql), Ran: true, DurationMs: ms}
}

func TestAssessRewrite(t *testing.T) {
	texts := []string{
		"ALTER TABLE orders ADD COLUMN ref uuid DEFAULT gen_random_uuid()",
		"CREATE INDEX orders_ref ON orders (ref)",
		"CREATE TABLE new_things (id int)",
	}
	s1 := stmt(1, texts[0], 130_000)
	s1.Locks = []protocol.PreviewLock{{Relation: "public.orders", Mode: "AccessExclusiveLock", Blocks: "reads and writes", HeldMs: 190_000, SizeBytes: 3_300_000_000}}
	s1.Rewrites = []protocol.PreviewRelation{{Name: "public.orders", SizeBytes: 3_300_000_000, Rows: 21_000_000}}
	s2 := stmt(2, texts[1], 60_000)
	s2.Locks = []protocol.PreviewLock{{Relation: "public.orders", Mode: "ShareLock", Blocks: "writes", HeldMs: 60_000, SizeBytes: 3_300_000_000}}
	s2.IndexBuilds = []protocol.PreviewRelation{{Name: "public.orders_ref", Table: "public.orders", SizeBytes: 3_300_000_000}}
	s3 := stmt(3, texts[2], 5)
	res := &protocol.PreviewResult{Mode: protocol.PreviewInTransaction, DB: "app", DurationMs: 190_000,
		Statements: []protocol.PreviewStatement{s1, s2, s3}}
	Assess(res, texts)
	if res.Verdict != protocol.PreviewDangerous {
		t.Fatalf("verdict %s", res.Verdict)
	}
	st := res.Statements
	if st[0].Risk != protocol.PreviewDangerous || !strings.Contains(st[0].Impact, "Blocks reads and writes on public.orders for about 3 min") ||
		!strings.Contains(st[0].Impact, "rewrites public.orders (3.1 GB)") || !strings.Contains(st[0].Impact, "until the migration commits") {
		t.Errorf("statement 1: %s %q", st[0].Risk, st[0].Impact)
	}
	if st[2].Risk != protocol.PreviewSafe || st[2].Impact != "" {
		t.Errorf("statement 3: %s %q", st[2].Risk, st[2].Impact)
	}
	rules := map[string]bool{}
	for _, f := range res.Findings {
		rules[f.Rule] = true
	}
	for _, r := range []string{"long_lock", "table_rewrite", "no_lock_timeout", "create_index_blocks_writes"} {
		if !rules[r] {
			t.Errorf("missing finding %s in %+v", r, res.Findings)
		}
	}
	if res.Findings[0].Severity != protocol.PreviewDangerous {
		t.Errorf("findings not sorted: %+v", res.Findings[0])
	}
	if !strings.HasPrefix(res.Summary, "Dangerous: on production, statement 1 (ALTER TABLE) blocks reads and writes on public.orders") ||
		!strings.Contains(res.Summary, "Add the column without a default") {
		t.Errorf("summary %q", res.Summary)
	}
}

func TestAssessSafeAndFailed(t *testing.T) {
	texts := []string{"SET lock_timeout = '5s'", "ALTER TABLE users ADD COLUMN nickname text", "CREATE INDEX CONCURRENTLY ON users (nickname)"}
	s2 := stmt(2, texts[1], 3)
	s2.Locks = []protocol.PreviewLock{{Relation: "public.users", Mode: "AccessExclusiveLock", Blocks: "reads and writes", HeldMs: 3, SizeBytes: 1 << 20}}
	res := &protocol.PreviewResult{Mode: protocol.PreviewAsWritten, DB: "app", DurationMs: 40,
		Statements: []protocol.PreviewStatement{stmt(1, texts[0], 0), s2, stmt(3, texts[2], 30)}}
	Assess(res, texts)
	if res.Verdict != protocol.PreviewSafe || len(res.Findings) != 0 || !strings.HasPrefix(res.Summary, "Safe: 3 statements ran in under a second on a copy of app") {
		t.Fatalf("%s %+v %q", res.Verdict, res.Findings, res.Summary)
	}

	fail := stmt(2, texts[1], 1)
	fail.Error = `column "nickname" of relation "users" already exists`
	res = &protocol.PreviewResult{DB: "app", Statements: []protocol.PreviewStatement{stmt(1, texts[0], 0), fail, {N: 3, Command: "CREATE INDEX"}},
		Error: &protocol.PreviewError{Statement: 2, Line: 2, Code: "42701", Message: fail.Error}}
	Assess(res, texts)
	if res.Verdict != protocol.PreviewFailed || !strings.Contains(res.Summary, "fails at statement 2 (line 2)") {
		t.Fatalf("%s %q", res.Verdict, res.Summary)
	}
}

func TestAssessDataLoss(t *testing.T) {
	texts := []string{"DROP TABLE legacy_events", "TRUNCATE audit_log", "DELETE FROM sessions", "UPDATE users SET plan = 'free'"}
	s1 := stmt(1, texts[0], 20)
	s1.Dropped = []protocol.PreviewRelation{{Name: "public.legacy_events", SizeBytes: 50 << 20, Rows: 400_000}}
	s2 := stmt(2, texts[1], 20)
	s2.Rewrites = []protocol.PreviewRelation{{Name: "public.audit_log", SizeBytes: 8 << 20}}
	s3 := stmt(3, texts[2], 900)
	n3 := int64(250_000)
	s3.Rows = &n3
	s4 := stmt(4, texts[3], 90)
	n4 := int64(12)
	s4.Rows = &n4
	res := &protocol.PreviewResult{Mode: protocol.PreviewInTransaction, Statements: []protocol.PreviewStatement{s1, s2, s3, s4}}
	Assess(res, texts)
	got := map[string]string{}
	for _, f := range res.Findings {
		got[f.Rule] = f.Severity
	}
	if got["drop_table"] != protocol.PreviewDangerous || got["truncate"] != protocol.PreviewDangerous ||
		got["large_data_change"] != protocol.PreviewCareful || got["update_without_where"] != protocol.PreviewCareful {
		t.Fatalf("findings %v", got)
	}
	if res.Statements[1].Rewrites == nil || strings.Contains(res.Statements[1].Impact, "rewrites") {
		t.Errorf("truncate impact %q", res.Statements[1].Impact)
	}
}

func TestHuman(t *testing.T) {
	for ms, want := range map[int64]string{400: "under a second", 2400: "about 2 s", 125_000: "about 2 min", 3_900_000: "about 1 h 5 min", 7_200_000: "about 2 h"} {
		if got := humanDuration(ms); got != want {
			t.Errorf("humanDuration(%d) = %q, want %q", ms, got, want)
		}
	}
	for n, want := range map[int64]string{512: "512 B", 3_300_000_000: "3.1 GB", 50 << 20: "50 MB", 1023 << 20: "1.0 GB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
	for n, want := range map[int64]string{1204: "1,204", 250_000: "250,000", 3_100_000: "3.1 million"} {
		if got := humanCount(n); got != want {
			t.Errorf("humanCount(%d) = %q, want %q", n, got, want)
		}
	}
}
