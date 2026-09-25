package agent

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestParseConninfo(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]string
	}{
		{"postgres://doadmin:p%40ss%3Aw@db-1.db.ondigitalocean.com:25060/defaultdb?sslmode=require",
			map[string]string{"user": "doadmin", "password": "p@ss:w", "host": "db-1.db.ondigitalocean.com", "port": "25060", "dbname": "defaultdb", "sslmode": "require"}},
		{"postgresql://postgres.abc:secret@aws-0-eu-central-1.pooler.supabase.com:5432/postgres",
			map[string]string{"user": "postgres.abc", "password": "secret", "host": "aws-0-eu-central-1.pooler.supabase.com", "port": "5432", "dbname": "postgres"}},
		{"postgres://u:p@[2001:db8::1]:5433/app", map[string]string{"user": "u", "password": "p", "host": "2001:db8::1", "port": "5433", "dbname": "app"}},
		{"postgres://u@h1:5432,h2:5433/app?target_session_attrs=read-write",
			map[string]string{"user": "u", "host": "h1,h2", "port": "5432,5433", "dbname": "app", "target_session_attrs": "read-write"}},
		{"host=db.example.com port=5432 user=app password='it\\'s \\\\ q' dbname=shop sslmode=verify-full",
			map[string]string{"host": "db.example.com", "port": "5432", "user": "app", "password": `it's \ q`, "dbname": "shop", "sslmode": "verify-full"}},
		{"postgres://neondb_owner:npg@ep-x-123.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require",
			map[string]string{"user": "neondb_owner", "password": "npg", "host": "ep-x-123.eu-central-1.aws.neon.tech", "dbname": "neondb", "sslmode": "require", "channel_binding": "require"}},
		{"postgres://app@db.example.com", map[string]string{"user": "app", "host": "db.example.com", "dbname": "app"}},
	}
	for _, c := range cases {
		got, err := parseConninfo(c.in)
		if err != nil {
			t.Errorf("parseConninfo(%q): %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("parseConninfo(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for k, v := range c.want {
			if got[k] != v {
				t.Errorf("parseConninfo(%q)[%s] = %q, want %q", c.in, k, got[k], v)
			}
		}
	}
	for _, bad := range []string{"", "not a connection string", "postgres://u:p@/db", "host=/var/run/postgresql user=x",
		"postgres://u:p@h/db?passfile=/etc/shadow", "postgres://u:p@h/db?sslkey=/etc/shadow", "postgres://:p@h:99999/db",
		"postgres://h/db", "host=h user='unterminated"} {
		if _, err := parseConninfo(bad); err == nil {
			t.Errorf("parseConninfo(%q) accepted", bad)
		}
	}
}

func TestConninfoRoundTrip(t *testing.T) {
	ci, err := parseConninfo(`postgres://o%27brien:pa%5Css%27word@db.example.com:6543/sh%20op?sslmode=require`)
	if err != nil {
		t.Fatal(err)
	}
	back, err := parseConninfo(ci.String())
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range ci {
		if back[k] != v {
			t.Errorf("%s: %q != %q", k, back[k], v)
		}
	}
	lib := ci.libpqConninfo("/var/lib/rowsafe/migrate/m1/pgpass")
	if strings.Contains(lib, "word") || !strings.Contains(lib, "passfile='/var/lib/rowsafe/migrate/m1/pgpass'") {
		t.Errorf("libpqConninfo leaks the password or lacks the passfile: %s", lib)
	}
	// pgx understands what the agent's own connections get.
	if _, err := pgx.ParseConfig(ci.without(libpqOnly...).String()); err != nil {
		t.Fatal(err)
	}
}

func TestPlainRestoreWarnings(t *testing.T) {
	got := plainRestoreWarnings([]string{
		`pg_restore: error: could not execute query: ERROR:  extension "pgsodium" is not available`,
		`pg_restore: error: could not execute query: ERROR:  role "authenticated" does not exist`,
		`pg_restore: error: could not execute query: ERROR:  role "authenticated" does not exist`,
		`pg_restore: error: could not execute query: ERROR:  schema "public" already exists`,
		`pg_restore: warning: errors ignored on restore: 4`,
		`pg_restore: error: could not execute query: ERROR:  type "vector" does not exist`,
	})
	want := []string{
		"The extension pgsodium isn't installed on this server, so what depends on it was skipped.",
		"The role authenticated only exists at your provider; statements that name it (policies, grants) were skipped.",
		`type "vector" does not exist`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("plainRestoreWarnings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDefaultAppUserAndNames(t *testing.T) {
	for in, want := range map[string]string{"doadmin": "app", "postgres": "app", "shop_owner": "shop_owner", "Shop": "shop",
		"postgres.abcdef": "app", "neondb_owner": "neondb_owner", "rds_admin": "app", "9lives": "app"} {
		if got := defaultAppUser(in); got != want {
			t.Errorf("defaultAppUser(%q) = %q, want %q", in, got, want)
		}
	}
	for name, ok := range map[string]bool{"shop": true, "app_2": true, "postgres": false, "pg_x": false, "Shop": false,
		"a-b": false, "": false, "template1": false, strings.Repeat("a", 64): false} {
		if validTargetDB(name) != ok {
			t.Errorf("validTargetDB(%q) = %v", name, !ok)
		}
	}
	if !migrationIDRE.MatchString("mig_5k2m9x7q4t1v") || migrationIDRE.MatchString("../etc") {
		t.Error("migrationIDRE")
	}
}

func TestScramVerifierShape(t *testing.T) {
	v, err := scramVerifier("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(v, "SCRAM-SHA-256$4096:") || strings.Count(v, "$") != 2 || strings.Contains(v, "hunter2") {
		t.Errorf("verifier %q", v)
	}
	p, _ := randomPassword()
	if len(p) != 32 {
		t.Errorf("password %q", p)
	}
}

func TestListensRemotely(t *testing.T) {
	for in, want := range map[string]bool{"localhost": false, "127.0.0.1,::1": false, "*": true, "10.0.0.5": true, "": false} {
		if listensRemotely(in) != want {
			t.Errorf("listensRemotely(%q) != %v", in, want)
		}
	}
}
