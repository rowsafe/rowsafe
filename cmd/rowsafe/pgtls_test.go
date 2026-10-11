package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestProjectPGClient(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  pgClient
	}{
		{"nothing", nil, pgClientLibpq},
		{"node", map[string]string{"package.json": `{"dependencies":{"pg":"^8"}}`}, pgClientBuiltin},
		{"go", map[string]string{"go.mod": "module x\nrequire github.com/jackc/pgx/v5 v5.7.0\n"}, pgClientBuiltin},
		{"rust", map[string]string{"Cargo.toml": "[dependencies]\nsqlx = \"0.8\"\n"}, pgClientBuiltin},
		{"django", map[string]string{"requirements.txt": "Django==5.1\npsycopg[binary]==3.2\n", "package.json": "{}"}, pgClientLibpq},
		{"asyncpg", map[string]string{"pyproject.toml": "dependencies = [\"SQLAlchemy\", \"asyncpg>=0.30\"]\n"}, pgClientAsyncpg},
		{"requirements-dev", map[string]string{"requirements-dev.txt": "AsyncPG\n"}, pgClientAsyncpg},
		{"rails", map[string]string{"Gemfile": "gem \"pg\"\n", "package.json": "{}"}, pgClientLibpq},
		{"laravel", map[string]string{"composer.json": "{}", "package.json": "{}"}, pgClientLibpq},
	} {
		dir := t.TempDir()
		for n, data := range tc.files {
			if err := os.WriteFile(filepath.Join(dir, n), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if got := projectPGClient(dir); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
		conn := protocol.DBConnection{User: "app", Database: "app", Host: "x7kq2mfa3pzd.cloud.rowsafe.sh", Port: 5432, SSLMode: "verify-full"}
		note := appTLS(&conn, dir)
		want := map[pgClient]string{
			pgClientLibpq:   "?sslmode=verify-full&sslrootcert=system",
			pgClientBuiltin: "?sslmode=verify-full",
			pgClientAsyncpg: "?sslmode=require",
		}[tc.want]
		if got := protocol.ConnectionURL(conn, "pw"); got != "postgresql://app:pw@x7kq2mfa3pzd.cloud.rowsafe.sh:5432/app"+want {
			t.Errorf("%s: %s", tc.name, got)
		}
		if (note == "") != (tc.want == pgClientBuiltin) {
			t.Errorf("%s: note %q", tc.name, note)
		}
	}
}

func TestParsePSQLMajor(t *testing.T) {
	for in, want := range map[string]int{
		"psql (PostgreSQL) 16.4\n":                       16,
		"psql (PostgreSQL) 17.2 (Homebrew)\n":            17,
		"psql (PostgreSQL) 15.8 (Debian 15.8-0+deb12u1)": 15,
		"psql (PostgreSQL) 18beta1":                      18,
		"nonsense":                                       0,
	} {
		if got := parsePSQLMajor(in); got != want {
			t.Errorf("%q: %d, want %d", in, got, want)
		}
	}
}

func TestPSQLTLS(t *testing.T) {
	oldMajor, oldBundles := psqlMajor, caBundles
	t.Cleanup(func() { psqlMajor, caBundles = oldMajor, oldBundles })
	bundle := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(bundle, []byte("certs"), 0o644); err != nil {
		t.Fatal(err)
	}
	vf := protocol.DBConnection{Host: "x7kq2mfa3pzd.cloud.rowsafe.sh", SSLMode: "verify-full"}
	for _, tc := range []struct {
		name               string
		major              int
		bundles            []string
		in                 protocol.DBConnection
		wantMode, wantRoot string
	}{
		{"the system's certificate file, any psql", 14, []string{"/nonexistent/ca.crt", bundle}, vf, "verify-full", bundle},
		{"psql 16 without a file", 16, []string{"/nonexistent/ca.crt"}, vf, "verify-full", protocol.SSLRootCertSystem},
		{"older psql without a file", 15, nil, vf, "require", ""},
		{"not verify-full: untouched", 17, []string{bundle}, protocol.DBConnection{SSLMode: "require"}, "require", ""},
	} {
		psqlMajor = func(string) int { return tc.major }
		caBundles = tc.bundles
		c := tc.in
		psqlTLS(&c, "/usr/bin/psql")
		if c.SSLMode != tc.wantMode || c.SSLRootCert != tc.wantRoot {
			t.Errorf("%s: sslmode=%s sslrootcert=%s", tc.name, c.SSLMode, c.SSLRootCert)
		}
	}
}
