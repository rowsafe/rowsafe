package preview

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// testCatalog is a production database for the corpus in
// testdata/migrations: Rails/Alembic tables, Prisma's quoted names and a
// Django app.
func testCatalog() *Catalog {
	const mb = 1 << 20
	rels := map[string]Relation{}
	add := func(name string, kind byte, size, rows int64, table string) {
		rels[name] = Relation{Name: name, Kind: kind, SizeBytes: size, Rows: rows, Table: table}
	}
	add("public.users", 'r', 5000*mb, 20_000_000, "")
	add("public.users_pkey", 'i', 400*mb, 0, "public.users")
	add("public.orders", 'r', 2000*mb, 9_000_000, "")
	add("public.User", 'r', 200*mb, 800_000, "")
	add("public.Order", 'r', 1000*mb, 4_000_000, "")
	add("public.shop_customer", 'r', 300*mb, 1_000_000, "")
	add("public.shop_order", 'r', 3000*mb, 12_000_000, "")
	add("public.audit_log", 'r', 800*mb, 6_000_000, "")
	add("public.legacy_events", 'r', 50*mb, 400_000, "")
	add("public.alembic_version", 'r', 8192, 1, "")
	types := map[string]string{
		"public.shop_order.total": "numeric(10,2)",
		"public.User.age":         "integer",
	}
	return &Catalog{DB: "app", VersionNum: 160004, SearchPath: []string{"public"}, Relations: rels,
		ColumnType: func(table, column string) string { return types[table+"."+column] }}
}

func TestStaticCorpus(t *testing.T) {
	cases := []struct {
		file    string
		verdict string
		rules   []string // findings that must be there
		not     []string // findings that must not
		check   func(t *testing.T, res *protocol.PreviewResult)
	}{
		{file: "rails_add_index_and_fk.sql", verdict: protocol.PreviewDangerous,
			rules: []string{"create_index_blocks_writes", "foreign_key_validation", "no_lock_timeout", "long_lock"},
			not:   []string{"table_rewrite"},
			check: func(t *testing.T, res *protocol.PreviewResult) {
				ix := res.Statements[0]
				if len(ix.Locks) != 1 || ix.Locks[0].Mode != "ShareLock" || ix.Locks[0].Relation != "public.users" || ix.Locks[0].Blocks != "writes" {
					t.Errorf("CREATE INDEX locks: %+v", ix.Locks)
				}
				if len(ix.IndexBuilds) != 1 || ix.IndexBuilds[0].Name != "public.index_users_on_email" {
					t.Errorf("index builds: %+v", ix.IndexBuilds)
				}
				fk := res.Statements[2]
				// users is already locked harder by statement 2, until the commit.
				if len(fk.Locks) != 1 || fk.Locks[0].Mode != "ShareRowExclusiveLock" || fk.Locks[0].Relation != "public.orders" {
					t.Errorf("FK locks: %+v", fk.Locks)
				}
			}},
		{file: "rails_safe.sql", verdict: protocol.PreviewSafe, not: []string{"no_lock_timeout", "create_index_blocks_writes", "foreign_key_validation"},
			check: func(t *testing.T, res *protocol.PreviewResult) {
				if res.Mode != protocol.PreviewAsWritten || !strings.HasPrefix(res.Summary, "Safe: 6 statements, with no long locks") {
					t.Errorf("mode %s, summary %q", res.Mode, res.Summary)
				}
				if v := res.Statements[5]; len(v.Locks) != 1 || v.Locks[0].Mode != "ShareUpdateExclusiveLock" {
					t.Errorf("VALIDATE locks: %+v", v.Locks)
				}
			}},
		{file: "prisma_migration.sql", verdict: protocol.PreviewDangerous,
			rules: []string{"table_rewrite", "create_index_blocks_writes", "foreign_key_validation"},
			check: func(t *testing.T, res *protocol.PreviewResult) {
				if r := res.Statements[0].Rewrites; len(r) != 0 {
					t.Errorf("a constant default rewrote the table on PostgreSQL 16: %+v", r)
				}
				if r := res.Statements[3].Rewrites; len(r) != 1 || r[0].Name != "public.User" {
					t.Errorf("integer to BIGINT: %+v", r)
				}
			}},
		{file: "django_sqlmigrate.sql", verdict: protocol.PreviewDangerous, rules: []string{"long_lock", "create_index_blocks_writes"},
			not: []string{"table_rewrite"},
			check: func(t *testing.T, res *protocol.PreviewResult) {
				if res.Mode != protocol.PreviewAsWritten {
					t.Errorf("mode %s", res.Mode)
				}
				// The index's lock lasts until COMMIT, the next statement.
				ix := res.Statements[4]
				if len(ix.Locks) != 1 || ix.Locks[0].HeldMs < 10_000 {
					t.Errorf("index lock: %+v", ix.Locks)
				}
			}},
		{file: "alembic_offline.sql", verdict: protocol.PreviewDangerous,
			rules: []string{"table_rewrite", "large_data_change", "update_without_where"},
			check: func(t *testing.T, res *protocol.PreviewResult) {
				if l := res.Statements[1].Locks; len(l) != 1 || l[0].Relation != "public.users" || l[0].Mode != "ShareRowExclusiveLock" {
					t.Errorf("CREATE TABLE ... REFERENCES users: %+v", l)
				}
				if r := res.Statements[3].Rows; r == nil || *r != 20_000_000 {
					t.Errorf("UPDATE without WHERE rows: %v", r)
				}
				if r := res.Statements[5].Rows; r != nil {
					t.Errorf("UPDATE with WHERE rows: %v", *r)
				}
			}},
		{file: "drop_and_truncate.sql", verdict: protocol.PreviewDangerous, rules: []string{"drop_table", "truncate"}, not: []string{"drop_cascade"}},
		{file: "not_null_without_default.sql", verdict: protocol.PreviewDangerous, rules: []string{"not_null_without_default"}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			sql, err := os.ReadFile(filepath.Join("testdata", "migrations", c.file))
			if err != nil {
				t.Fatal(err)
			}
			stmts, err := Split(string(sql))
			if err != nil {
				t.Fatal(err)
			}
			res := Static(stmts, testCatalog())
			var rules []string
			for _, f := range res.Findings {
				rules = append(rules, f.Rule)
			}
			if res.Verdict != c.verdict {
				t.Errorf("verdict %s, want %s (findings %v; %s)", res.Verdict, c.verdict, rules, res.Summary)
			}
			for _, r := range c.rules {
				if !slices.Contains(rules, r) {
					t.Errorf("no %s finding in %v", r, rules)
				}
			}
			for _, r := range c.not {
				if slices.Contains(rules, r) {
					t.Errorf("unexpected %s finding in %v", r, rules)
				}
			}
			if res.Checked != protocol.PreviewCheckedStatic || res.DB != "app" {
				t.Errorf("checked %q db %q", res.Checked, res.DB)
			}
			if c.check != nil {
				c.check(t, res)
			}
			out := Text(res)
			if !strings.Contains(out, "nothing ran") {
				t.Errorf("text report doesn't say nothing ran:\n%s", out)
			}
			if t.Failed() {
				t.Log(out)
			}
		})
	}
}

func TestStaticNames(t *testing.T) {
	e := NewEstimator(testCatalog())
	// A rename is followed: the next statement finds the table by its new name.
	e.Statement(`ALTER TABLE users RENAME TO accounts`)
	est := e.Statement(`CREATE INDEX ON accounts (email)`)
	if len(est.locks) != 1 || est.locks[0].rel.Name != "public.accounts" || est.locks[0].rel.SizeBytes == 0 {
		t.Errorf("after rename: %+v", est.locks)
	}
	if est := e.Statement(`CREATE INDEX ON users (email)`); len(est.locks) != 0 {
		t.Errorf("old name still found: %+v", est.locks)
	}
	// Quoted, qualified, unknown and new tables.
	e = NewEstimator(testCatalog())
	if est := e.Statement(`ALTER TABLE ONLY "public"."User" ADD COLUMN x int`); len(est.locks) != 1 || est.locks[0].rel.Name != "public.User" {
		t.Errorf("quoted name: %+v", est.locks)
	}
	if est := e.Statement(`ALTER TABLE "user" ADD COLUMN x int`); len(est.locks) != 0 {
		t.Errorf("quoted names are case-sensitive: %+v", est.locks)
	}
	if est := e.Statement(`LOCK TABLE orders, users IN SHARE ROW EXCLUSIVE MODE NOWAIT`); len(est.locks) != 2 || est.locks[0].mode != "ShareRowExclusiveLock" {
		t.Errorf("LOCK: %+v", est.locks)
	}
	if est := e.Statement(`DROP INDEX CONCURRENTLY IF EXISTS users_pkey`); len(est.locks) != 1 || est.locks[0].mode != "ShareUpdateExclusiveLock" || est.locks[0].rel.Name != "public.users" {
		t.Errorf("DROP INDEX: %+v", est.locks)
	}
	if est := e.Statement(`VACUUM (FULL, ANALYZE) audit_log`); len(est.rewrites) != 1 {
		t.Errorf("VACUUM FULL: %+v", est)
	}
	if est := e.Statement(`ALTER TABLE orders ADD COLUMN check_in timestamptz`); len(est.scans) != 0 || len(est.rewrites) != 0 {
		t.Errorf("a column named check_in: %+v", est)
	}
	if est := e.Statement(`ALTER TABLE orders ADD COLUMN n bigserial`); len(est.rewrites) != 1 {
		t.Errorf("bigserial: %+v", est)
	}
	old := NewEstimator(&Catalog{VersionNum: 100012, Relations: testCatalog().Relations})
	if est := old.Statement(`ALTER TABLE orders ADD COLUMN flag boolean DEFAULT false`); len(est.rewrites) != 1 {
		t.Errorf("PostgreSQL 10 rewrites for any default: %+v", est)
	}
	if est := e.Statement(`DROP SCHEMA public CASCADE`); len(est.dropped) < 5 {
		t.Errorf("DROP SCHEMA CASCADE: %+v", est.dropped)
	}
}

func TestBinaryCompatible(t *testing.T) {
	for _, c := range []struct {
		old, typ string
		ok       bool
	}{
		{"character varying(20)", "varchar(50)", true},
		{"character varying(50)", "varchar(20)", false},
		{"character varying(20)", "text", true},
		{"text", "varchar", true},
		{"numeric(10,2)", "numeric(12, 2)", true},
		{"numeric(10,2)", "numeric(12,3)", false},
		{"integer", "bigint", false},
		{"integer", "int4", true},
		{"", "text", false},
		{"timestamp without time zone", "timestamptz", false},
	} {
		if got := binaryCompatible(c.old, c.typ); got != c.ok {
			t.Errorf("binaryCompatible(%q, %q) = %v", c.old, c.typ, got)
		}
	}
}

func TestHoldTimes(t *testing.T) {
	stmts, _ := Split("SELECT 1; BEGIN; ALTER TABLE a ADD b int; UPDATE a SET b = 1; COMMIT; SELECT 2")
	ms := []int64{1, 0, 10, 100, 0, 5}
	got := HoldTimes(stmts, ms, protocol.PreviewAsWritten)
	if want := []int64{1, 110, 110, 100, 0, 5}; !slices.Equal(got, want) {
		t.Errorf("as written: %v, want %v", got, want)
	}
	got = HoldTimes(stmts, ms, protocol.PreviewInTransaction)
	if want := []int64{116, 115, 115, 105, 5, 5}; !slices.Equal(got, want) {
		t.Errorf("in a transaction: %v, want %v", got, want)
	}
}
