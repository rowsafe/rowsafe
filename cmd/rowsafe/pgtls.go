package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Checking a Rowsafe Cloud server's certificate. Its name has a public
// (Let's Encrypt) certificate, so apps connect with sslmode=verify-full. A
// libpq client (psql, psycopg, Ruby's pg, PHP) then needs to be told which
// certificates to trust, or it looks for ~/.postgresql/root.crt and refuses
// to connect: sslrootcert=system (libpq 16 and later) says the system's.
// Node's pg and postgres.js, Go's lib/pq and Rust's sqlx trust public
// certificates already and read sslrootcert as a file name (so "system"
// breaks them), and asyncpg can only take a file. There is no one string for
// every driver: `rowsafe env` looks at the app's project files, and
// `rowsafe connect` gives psql the system's certificate file.

// pgClient is the kind of PostgreSQL driver an app uses.
type pgClient int

const (
	pgClientLibpq   pgClient = iota // psql, psycopg, Ruby's pg, PHP, and anything unknown: sslrootcert=system
	pgClientBuiltin                 // Node, Go, Rust, Deno: their own trusted certificates, no sslrootcert
	pgClientAsyncpg                 // Python's asyncpg: no system certificates from a URL, so sslmode=require
)

// projectPGClient guesses the app's driver from the project files in dir.
// Python, Ruby and PHP apps come first: their projects often have a
// package.json for the front end only.
func projectPGClient(dir string) pgClient {
	read := func(names ...string) (string, bool) {
		var b strings.Builder
		found := false
		for _, n := range names {
			m, _ := filepath.Glob(filepath.Join(dir, n))
			for _, p := range m {
				if data, err := os.ReadFile(p); err == nil {
					found = true
					b.Write(data)
					b.WriteByte('\n')
				}
			}
		}
		return strings.ToLower(b.String()), found
	}
	if py, ok := read("requirements*.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg", "uv.lock", "poetry.lock"); ok {
		if strings.Contains(py, "asyncpg") {
			return pgClientAsyncpg
		}
		return pgClientLibpq
	}
	if _, ok := read("Gemfile", "composer.json"); ok {
		return pgClientLibpq
	}
	if _, ok := read("package.json", "deno.json", "deno.jsonc", "go.mod", "Cargo.toml"); ok {
		return pgClientBuiltin
	}
	return pgClientLibpq
}

// appTLS makes conn check a Rowsafe Cloud name's public certificate the way
// the app in dir can, and says what to know about it ("" for nothing).
func appTLS(conn *protocol.DBConnection, dir string) string {
	switch projectPGClient(dir) {
	case pgClientBuiltin:
		conn.SSLMode, conn.SSLRootCert = "verify-full", ""
		return ""
	case pgClientAsyncpg:
		conn.SSLMode, conn.SSLRootCert = "require", ""
		return "asyncpg can't check the server's certificate from a connection string, so it connects encrypted without checking it (sslmode=require)."
	}
	conn.SSLMode, conn.SSLRootCert = "verify-full", protocol.SSLRootCertSystem
	return "The connection checks the server's certificate against your system's (sslrootcert=system: libpq 16 or later). " +
		"With an older libpq, put the system's certificate file there instead (/etc/ssl/certs/ca-certificates.crt on Debian and Ubuntu); " +
		"Node, Go and Rust apps: remove &sslrootcert=system."
}

// Seams for tests.
var (
	// psqlMajor is psql's major version (0 when unknown). psql 16 comes
	// with libpq 16 or later.
	psqlMajor = func(psql string) int {
		out, err := exec.Command(psql, "--version").Output()
		if err != nil {
			return 0
		}
		return parsePSQLMajor(string(out))
	}
	// caBundles are where systems keep their trusted certificates in one
	// file (Debian/Ubuntu/Alpine, Fedora/RHEL, openSUSE, macOS/BSD).
	caBundles = []string{"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem"}
)

var psqlVersionRE = regexp.MustCompile(`\b(\d+)(?:\.\d+)?`)

// parsePSQLMajor reads "psql (PostgreSQL) 16.4" (or "... 17beta1 (Homebrew)").
func parsePSQLMajor(s string) int {
	_, rest, _ := strings.Cut(s, ")")
	if m := psqlVersionRE.FindStringSubmatch(rest); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

// psqlTLS makes conn (sslmode=verify-full) checkable by this psql: the
// system's certificate file (any libpq), else the system's certificates
// (psql 16 or later; not on Windows, where libpq's OpenSSL may have none),
// else encrypted without the check (said on stderr).
func psqlTLS(conn *protocol.DBConnection, psql string) {
	if conn.SSLMode != "verify-full" {
		return
	}
	for _, p := range caBundles {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			conn.SSLRootCert = p
			return
		}
	}
	if runtime.GOOS != "windows" && psqlMajor(psql) >= 16 {
		conn.SSLRootCert = protocol.SSLRootCertSystem
		return
	}
	conn.SSLMode = "require"
	fmt.Fprintln(os.Stderr, "(no system certificate file for psql to check the server's certificate with: the connection is encrypted, without that check)")
}
