package pginspect

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
)

// ReadRLS on a database shaped like a Supabase app: an API role with
// every privilege on public, a table without row-level security, one with
// it but no policies, always-true policies and a large table whose policy
// column has no index.
func TestReadRLS(t *testing.T) {
	tg := localTarget(t)
	ctx := t.Context()
	admin, err := tg.Connect(ctx, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	suffix := fmt.Sprintf("%d", rand.N(1_000_000))
	db, role := "rowsafe_rls_"+suffix, "rowsafe_rls_api_"+suffix
	exec := func(c *pgx.Conn, sql string) {
		t.Helper()
		if _, err := c.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	// admin stays open for the cleanup (a deferred Close would run first and
	// leave the database behind).
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
		_, _ = admin.Exec(ctx, "DROP ROLE IF EXISTS "+role)
		admin.Close(ctx)
	})
	exec(admin, "CREATE DATABASE "+db)
	exec(admin, "CREATE ROLE "+role+" NOLOGIN")

	conn, err := tg.Connect(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	// Nothing that looks like row-level security yet: nil.
	exec(conn, "CREATE TABLE plain (id int)")
	if d, err := ReadRLS(ctx, conn); err != nil || d != nil {
		t.Fatalf("plain database: %+v, %v", d, err)
	}

	old := apiRoleNames
	apiRoleNames = append(slices.Clone(old), role)
	defer func() { apiRoleNames = old }()
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA public TO " + role,
		"CREATE TABLE profiles (id int, user_id int)",
		"CREATE TABLE secrets (id int)",
		"ALTER TABLE secrets ENABLE ROW LEVEL SECURITY",
		"CREATE TABLE posts (id int, user_id int)",
		"ALTER TABLE posts ENABLE ROW LEVEL SECURITY",
		"CREATE POLICY read_all ON posts FOR SELECT TO " + role + " USING (true)",
		"CREATE POLICY write_any ON posts FOR UPDATE TO " + role + " USING (user_id = 1) WITH CHECK ((1 = 1))",
		"CREATE POLICY own ON posts FOR DELETE TO " + role + " USING (user_id = 1)",
		"CREATE POLICY admin_only ON posts FOR SELECT TO pg_monitor USING (true)", // not an API role
		"GRANT SELECT, INSERT ON profiles TO " + role,
		"GRANT ALL ON secrets, posts TO " + role,
		"INSERT INTO posts SELECT g, g FROM generate_series(1, 20000) g",
		"ANALYZE posts",
		"CREATE SCHEMA auth", "CREATE SCHEMA storage",
		"CREATE TABLE storage.buckets (id text, name text, public boolean)",
		"INSERT INTO storage.buckets VALUES ('a', 'avatars', true), ('d', 'documents', false)",
	} {
		exec(conn, sql)
	}
	d, err := ReadRLS(ctx, conn)
	if err != nil || d == nil {
		t.Fatalf("ReadRLS: %+v, %v", d, err)
	}
	if d.Database != db || !d.Supabase || !slices.Contains(d.APIRoles, role) {
		t.Fatalf("database facts: %+v", d)
	}
	if len(d.Exposed) != 2 || d.Exposed[0].Name != "profiles" || d.Exposed[0].RLS || d.Exposed[1].Name != "secrets" || !d.Exposed[1].RLS {
		t.Fatalf("exposed: %+v", d.Exposed)
	}
	if a := d.Exposed[0].Access; len(a) != 1 || a[0].Role != role || !slices.Equal(a[0].Privileges, []string{"select", "insert"}) {
		t.Fatalf("profiles access: %+v", a)
	}
	var names []string
	for _, p := range d.OpenPolicies {
		names = append(names, fmt.Sprintf("%s:%s:%v:%v:%v", p.Name, p.Command, p.Using, p.Check, p.TableRLS))
	}
	if !slices.Equal(names, []string{"read_all:select:true:false:true", "write_any:update:false:true:true"}) {
		t.Fatalf("open policies: %v", names)
	}
	if len(d.SlowPolicies) != 1 || d.SlowPolicies[0].Table != "posts" || d.SlowPolicies[0].Column != "user_id" ||
		!slices.Equal(d.SlowPolicies[0].Policies, []string{"own", "write_any"}) {
		t.Fatalf("slow policies: %+v", d.SlowPolicies)
	}
	if !slices.Equal(d.PublicBuckets, []string{"avatars"}) {
		t.Fatalf("public buckets: %v", d.PublicBuckets)
	}

	// An index on the column and row-level security on profiles clear them.
	exec(conn, "CREATE INDEX ON posts (user_id)")
	exec(conn, "ALTER TABLE profiles ENABLE ROW LEVEL SECURITY")
	exec(conn, "CREATE POLICY p ON profiles USING (user_id = 1)")
	if d, err = ReadRLS(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if len(d.SlowPolicies) != 0 || len(d.Exposed) != 1 || d.Exposed[0].Name != "secrets" {
		t.Fatalf("after fixing: %+v", d)
	}
}
