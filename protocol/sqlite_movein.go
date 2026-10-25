package protocol

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// ---- Move in for SQLite: Turso (libSQL) and Cloudflare D1
//
// A one-time copy (MigrateMethodDump) of a Turso database or a Cloudflare
// D1 database onto the SQLite file Rowsafe protects (the migration's
// DatabaseSpec: SocketDir is the file). There is no live sync and no login
// to create: the app opens the same file path afterwards.
//
// The source "connection string" sealed to the migration's key (e2e,
// MigrateSourceAAD) is one of:
//
//	libsql://<database>-<organization>.turso.io?authToken=<database token>
//	d1://<account id>/<database id>?token=<API token>
//
// For Turso, https:// works as well as libsql:// (libsql:// means HTTPS),
// and http:// reaches a self-hosted libSQL server (sqld) without TLS. The
// token is a Turso database token (Bearer). For D1 the account ID is the
// Cloudflare account's 32-character ID, the database ID the D1 database's
// UUID, and the token a Cloudflare API token with the D1 Edit permission
// (the export is a POST to the D1 API). The dashboard and the CLI build it
// from plain fields; only the agent opens it.
//
// The agent fetches the provider's SQL export (Turso: GET <database
// URL>/dump; D1: the export API, polled until its SQL file is ready, then
// that file's signed URL), builds a fresh SQLite file from it in its own
// private folder (provider-internal tables skipped: D1's _cf_* tables,
// libSQL's libsql_* tables and vector indexes), checks it
// (integrity_check, row counts) and, when the file here already holds
// tables, saves its content first (a Mark, taken by the control plane before
// the copy, and the agent makes sure the change stream is in the bucket; a
// full backup in rollback-journal mode). Then it writes the new content
// into the live file with SQLite's online backup API, the way Rewind in
// place does: the app's open connections see the new content, nothing is
// restarted.

// SQLite move-in providers (MigrateSource.Provider).
const (
	SQLiteSourceTurso  = "turso"  // Turso Cloud (*.turso.io)
	SQLiteSourceLibSQL = "libsql" // a self-hosted libSQL server (sqld)
	SQLiteSourceD1     = "d1"     // Cloudflare D1
)

// SQLiteSource is a parsed Turso or D1 source. Token is secret: never log
// or report it.
type SQLiteSource struct {
	Provider string // SQLiteSourceTurso, SQLiteSourceLibSQL or SQLiteSourceD1
	// URL is the libSQL database's base URL (https://host or http://host),
	// without the token (Turso, libSQL).
	URL        string
	AccountID  string // D1
	DatabaseID string // D1
	Token      string
}

var (
	d1AccountRE  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	d1DatabaseRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	tokenRE      = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]{8,}$`)
)

// SQLiteSourceExample is the format, for error messages.
const SQLiteSourceExample = "libsql://<database>-<organization>.turso.io?authToken=<token> (Turso) or d1://<account id>/<database id>?token=<API token> (Cloudflare D1)"

// ParseSQLiteSource reads a sealed SQLite move-in source. Its errors never
// contain the token.
func ParseSQLiteSource(s string) (SQLiteSource, error) {
	s = strings.TrimSpace(s)
	bad := errors.New("that isn't a Turso or Cloudflare D1 source: use " + SQLiteSourceExample)
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return SQLiteSource{}, bad
	}
	q := u.Query()
	switch strings.ToLower(u.Scheme) {
	case "libsql", "https", "http":
		if p := strings.Trim(u.Path, "/"); p != "" {
			return SQLiteSource{}, errors.New("the Turso database URL has no path: libsql://<database>-<organization>.turso.io")
		}
		src := SQLiteSource{Provider: SQLiteSourceLibSQL, Token: q.Get("authToken")}
		scheme := "https"
		if strings.ToLower(u.Scheme) == "http" {
			scheme = "http"
		}
		host := strings.ToLower(u.Host)
		if strings.HasSuffix(u.Hostname(), ".turso.io") {
			src.Provider = SQLiteSourceTurso
			if scheme != "https" {
				return SQLiteSource{}, errors.New("Turso databases are reached over HTTPS: use libsql:// or https://")
			}
		}
		src.URL = scheme + "://" + host
		if src.Token == "" {
			return SQLiteSource{}, errors.New("the database token is missing: add ?authToken=<token> (Turso dashboard > your database > Create Token)")
		}
		if !tokenRE.MatchString(src.Token) || len(src.Token) > 8192 {
			return SQLiteSource{}, errors.New("the database token doesn't look right: copy it again from Turso")
		}
		return src, nil
	case "d1":
		src := SQLiteSource{Provider: SQLiteSourceD1, AccountID: strings.ToLower(u.Host), DatabaseID: strings.ToLower(strings.Trim(u.Path, "/")), Token: q.Get("token")}
		if !d1AccountRE.MatchString(src.AccountID) {
			return SQLiteSource{}, errors.New("the Cloudflare account ID is 32 letters and digits (Cloudflare dashboard > Account home > your account's menu > Copy account ID)")
		}
		if !d1DatabaseRE.MatchString(src.DatabaseID) {
			return SQLiteSource{}, errors.New("the D1 database ID is a UUID like 1b2c3d4e-...: Workers & Pages > D1 > your database (also database_id in wrangler.toml)")
		}
		if src.Token == "" {
			return SQLiteSource{}, errors.New("the Cloudflare API token is missing: add ?token=<API token> (with the D1 Edit permission)")
		}
		if !tokenRE.MatchString(src.Token) || len(src.Token) > 8192 {
			return SQLiteSource{}, errors.New("the Cloudflare API token doesn't look right: copy it again")
		}
		return src, nil
	}
	return SQLiteSource{}, bad
}

// String is the sealed form (with the token).
func (s SQLiteSource) String() string {
	if s.Provider == SQLiteSourceD1 {
		return "d1://" + s.AccountID + "/" + s.DatabaseID + "?" + url.Values{"token": {s.Token}}.Encode()
	}
	base := s.URL
	if strings.HasPrefix(base, "https://") {
		base = "libsql://" + strings.TrimPrefix(base, "https://")
	}
	return base + "?" + url.Values{"authToken": {s.Token}}.Encode()
}

// Host is where the source lives, safe to show (no token).
func (s SQLiteSource) Host() string {
	if s.Provider == SQLiteSourceD1 {
		return "api.cloudflare.com"
	}
	if u, err := url.Parse(s.URL); err == nil {
		return u.Hostname()
	}
	return s.URL
}

// Database names the source database, safe to show: Turso's database
// name (the host's first label, <database>-<organization>), D1's ID.
func (s SQLiteSource) Database() string {
	if s.Provider == SQLiteSourceD1 {
		return s.DatabaseID
	}
	h := s.Host()
	if i := strings.IndexByte(h, '.'); i > 0 && s.Provider == SQLiteSourceTurso {
		return h[:i]
	}
	return h
}

// SQLiteMigrateProviders are the SQLite sources, for display (the
// PostgreSQL ones are MigrateProviders).
var SQLiteMigrateProviders = []MigrateProvider{
	{ID: SQLiteSourceTurso, Name: "Turso", Hosts: []string{".turso.io"},
		Network: "Turso is reached over HTTPS from anywhere; nothing to open.",
		Docs:    "https://docs.turso.tech/sdk/http/reference"},
	{ID: SQLiteSourceLibSQL, Name: "libSQL server",
		Network: "Let this server reach the libSQL server's HTTP port.",
		Docs:    "https://docs.turso.tech/sdk/http/reference"},
	{ID: SQLiteSourceD1, Name: "Cloudflare D1",
		Network: "Cloudflare's API is reached over HTTPS from anywhere; nothing to open.",
		Docs:    "https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/export/"},
}
