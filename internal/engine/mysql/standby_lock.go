package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// MariaDB's read_only stops every login but those with READ_ONLY ADMIN
// (which ALL PRIVILEGES ON *.* includes, SUPER too before 10.11, directly
// or through a role the login may use), and 11.8 has no read_only that
// stops them too (NO_LOCK_NO_ADMIN comes later). So while a MariaDB server
// is read-only for Rowsafe (a standby, a fenced old primary), the logins
// that could still write are locked (ACCOUNT LOCK, outside the binary log)
// and their sessions ended; the list is kept, and exactly those are
// unlocked when it takes writes again.
//
// Locks only exist while the server is read-only: setting read_only and
// locking or unlocking happen under one lock per server (writerMu), a
// login is locked only after read_only was read as on, a login is written
// to the list before it is locked (and stays there until it was unlocked),
// and a server found writable with logins still on its list (an agent
// stopped between the two steps) has them unlocked on the next heartbeat.
//
// Not locked: Rowsafe's own login (setting read_only needs READ_ONLY
// ADMIN; the agent never writes on a read-only server), root through the
// server's socket (the server's own administrator, who can always still
// write: the summaries say so), MariaDB's system logins, and logins
// locked already (so the ones a person locked stay locked). MySQL needs
// none of this: super_read_only stops everyone.

// writerLockFile lists the logins Rowsafe locked on a port.
type writerLockFile struct {
	Port   int      `json:"port"`
	Socket string   `json:"socket,omitempty"`
	Locked []string `json:"locked"`
}

// writerLocks is the file listing the logins Rowsafe locked on a port.
func (s *server) writerLocks() string {
	return filepath.Join(s.env.StateDir, fmt.Sprintf("readonly-locks-%d.json", s.db.Port))
}

var (
	writerMusMu sync.Mutex
	writerMus   = map[string]*sync.Mutex{} // lock file -> its lock
)

// writerMu serializes read_only changes and login locks on one server.
func (s *server) writerMu() *sync.Mutex {
	writerMusMu.Lock()
	defer writerMusMu.Unlock()
	k := s.writerLocks()
	m, ok := writerMus[k]
	if !ok {
		m = &sync.Mutex{}
		writerMus[k] = m
	}
	return m
}

// errWritable: the server takes writes, so no login is locked.
var errWritable = errors.New("the server takes writes: no login is locked")

// lockWriters locks the logins that could write on this read-only MariaDB
// server and ends their sessions; it returns those it locked now. The
// caller holds writerMu.
func (s *server) lockWriters(ctx context.Context, db *sql.DB) ([]string, error) {
	if !s.flavor.mariadb() {
		return nil, nil
	}
	c, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return nil, err
	}
	accounts, targets, err := adminLogins(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("listing the logins that bypass read_only: %w", err)
	}
	if len(targets) == 0 {
		return nil, nil
	}
	f := s.readWriterLocks()
	var now []string
	for _, l := range targets {
		var ro int
		if err := c.QueryRowContext(ctx, "SELECT @@global.read_only").Scan(&ro); err != nil {
			return now, err
		}
		if ro != 1 {
			return now, errWritable
		}
		q := l.quoted()
		if !slices.Contains(f.Locked, q) {
			f.Locked = append(f.Locked, q)
			if err := s.saveWriterLocks(f); err != nil {
				return now, err
			}
		}
		if _, err := c.ExecContext(ctx, "ALTER USER "+q+" ACCOUNT LOCK"); err != nil {
			f.Locked = slices.DeleteFunc(f.Locked, func(x string) bool { return x == q })
			_ = s.saveWriterLocks(f)
			return now, fmt.Errorf("locking %s: %w", q, err)
		}
		now = append(now, q)
	}
	endSessionsOf(ctx, c, accounts, targets)
	return now, nil
}

// unlockWriters unlocks the logins lockWriters locked; a login it couldn't
// unlock stays on the list (and the error says which). The caller holds
// writerMu.
func (s *server) unlockWriters(ctx context.Context, db *sql.DB) ([]string, error) {
	f := s.readWriterLocks()
	if len(f.Locked) == 0 {
		return nil, nil
	}
	c, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return nil, err
	}
	var done, left []string
	var errs []error
	for _, q := range f.Locked {
		if !lockedLoginRE.MatchString(q) {
			continue // not something Rowsafe wrote
		}
		// IF EXISTS: dropped meanwhile, nothing to do.
		if _, err := c.ExecContext(ctx, "ALTER USER IF EXISTS "+q+" ACCOUNT UNLOCK"); err != nil {
			left = append(left, q)
			errs = append(errs, fmt.Errorf("unlocking %s: %w", q, err))
			continue
		}
		done = append(done, q)
	}
	f.Locked = left
	if len(left) == 0 {
		if err := os.Remove(s.writerLocks()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return done, err
		}
	} else if err := s.saveWriterLocks(f); err != nil {
		return done, err
	}
	return done, errors.Join(errs...)
}

// login is one 'user'@'host'.
type login struct{ User, Host string }

func (l login) quoted() string { return quoteString(l.User) + "@" + quoteString(l.Host) }

// lockedLoginRE checks entries of the locks file before they reach SQL.
var lockedLoginRE = regexp.MustCompile(`^'([^'\\]|\\.|'')*'@'([^'\\]|\\.|'')*'$`)

// querier is a *sql.DB or a *sql.Conn.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// adminLogins lists every login (accounts) and the unlocked ones that
// could write despite read_only (out): READ_ONLY ADMIN, ALL PRIVILEGES on
// everything or (before 10.11) SUPER, their own or through a role they
// may use (roles of roles too, and PUBLIC's).
func adminLogins(ctx context.Context, q querier) (accounts, out []login, err error) {
	var version string
	if err := q.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return nil, nil, err
	}
	_, n := numericVersion(version)
	superBypasses := n < 101100
	rows, err := q.QueryContext(ctx, `SELECT User, Host, IFNULL(JSON_VALUE(Priv, '$.account_locked'), 'false') IN ('true', '1')
		FROM mysql.global_priv WHERE IFNULL(JSON_VALUE(Priv, '$.is_role'), 'false') NOT IN ('true', '1') AND NOT (User = 'PUBLIC' AND Host = '')`)
	if err != nil {
		return nil, nil, err
	}
	var unlocked []login
	for rows.Next() {
		var l login
		var locked bool
		if err := rows.Scan(&l.User, &l.Host, &locked); err != nil {
			rows.Close()
			return nil, nil, err
		}
		accounts = append(accounts, l)
		if !locked {
			unlocked = append(unlocked, l)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	// Roles: who may use which (a role's own roles too).
	granted := map[login][]string{}
	if rows, err := q.QueryContext(ctx, "SELECT User, Host, Role FROM mysql.roles_mapping"); err == nil {
		for rows.Next() {
			var l login
			var role string
			if rows.Scan(&l.User, &l.Host, &role) == nil {
				granted[l] = append(granted[l], role)
			}
		}
		rows.Close()
	}
	roleBypass := map[string]bool{}
	var bypassRole func(role string, seen map[string]bool) bool
	bypassRole = func(role string, seen map[string]bool) bool {
		if v, ok := roleBypass[role]; ok {
			return v
		}
		if seen[role] {
			return false
		}
		seen[role] = true
		v := false
		if grants, err := showGrantsFor(ctx, q, quoteIdent(role)); err == nil && bypassesReadOnly(grants, superBypasses) {
			v = true
		}
		for _, r := range granted[login{User: role}] {
			if !v && bypassRole(r, seen) {
				v = true
			}
		}
		roleBypass[role] = v
		return v
	}
	public := false
	if grants, err := showGrantsFor(ctx, q, "PUBLIC"); err == nil { // 10.11+
		public = bypassesReadOnly(grants, superBypasses)
	}
	for _, l := range unlocked {
		switch {
		case l.User == rowsafeUser && l.Host == "localhost", l.User == "root" && l.Host == "localhost",
			l.User == "mariadb.sys", l.User == "", standbyUserRE.MatchString(l.User):
			continue
		}
		grants, err := showGrantsFor(ctx, q, l.quoted())
		if err != nil {
			continue // dropped meanwhile
		}
		bypass := public || bypassesReadOnly(grants, superBypasses)
		for _, r := range granted[l] {
			if !bypass && bypassRole(r, map[string]bool{}) {
				bypass = true
			}
		}
		if bypass {
			out = append(out, l)
		}
	}
	return accounts, out, nil
}

func showGrantsFor(ctx context.Context, q querier, who string) ([]string, error) {
	rows, err := q.QueryContext(ctx, "SHOW GRANTS FOR "+who)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// superRE finds SUPER among the privileges of a grant.
var superRE = regexp.MustCompile(`(^|[ ,])SUPER([ ,]|$)`)

// bypassesReadOnly: the grants include READ_ONLY ADMIN, ALL PRIVILEGES on
// everything, or SUPER on everything where it implies READ_ONLY ADMIN.
func bypassesReadOnly(grants []string, superBypasses bool) bool {
	for _, g := range grants {
		u := strings.ToUpper(g)
		if strings.Contains(u, "READ_ONLY ADMIN") || strings.Contains(u, "ALL PRIVILEGES ON *.*") {
			return true
		}
		if superBypasses {
			if privs, rest, ok := strings.Cut(strings.TrimPrefix(u, "GRANT "), " ON "); ok &&
				strings.HasPrefix(rest, "*.*") && superRE.MatchString(privs) {
				return true
			}
		}
	}
	return false
}

// endSessionsOf ends the sessions of the locked logins: a session is a
// login's when that login is the most specific of the accounts with its
// user name whose host matches the session's (as MariaDB picks it), so
// root@localhost's sessions stay when root@'%' is locked.
func endSessionsOf(ctx context.Context, c *sql.Conn, accounts, locked []login) {
	names := map[string]bool{}
	for _, l := range locked {
		names[l.User] = true
	}
	rows, err := c.QueryContext(ctx, "SELECT ID, USER, HOST FROM information_schema.PROCESSLIST WHERE ID <> CONNECTION_ID()")
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		var user, host string
		if rows.Scan(&id, &user, &host) != nil || !names[user] {
			continue
		}
		if l, ok := sessionLogin(accounts, user, host); ok && slices.Contains(locked, l) {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_, _ = c.ExecContext(ctx, fmt.Sprintf("KILL CONNECTION %d", id))
	}
}

// sessionLogin is the account a session of user from host (PROCESSLIST's
// HOST: a name or address, with :port over TCP) signed in as.
func sessionLogin(accounts []login, user, host string) (login, bool) {
	h := host
	if hh, _, err := net.SplitHostPort(host); err == nil {
		h = hh
	} else if i := strings.LastIndexByte(host, ':'); i > 0 && strings.Count(host, ":") == 1 {
		if _, err := strconv.Atoi(host[i+1:]); err == nil {
			h = host[:i]
		}
	}
	best, bestRank, found := login{}, -1, false
	for _, a := range accounts {
		if a.User != user || !hostMatches(a.Host, h) {
			continue
		}
		if r := hostRank(a.Host); r > bestRank {
			best, bestRank, found = a, r, true
		}
	}
	return best, found
}

// hostMatches: the account host pattern (% and _ wildcards) matches h.
func hostMatches(pattern, h string) bool {
	if pattern == "" {
		pattern = "%"
	}
	var re strings.Builder
	re.WriteString("(?i)^")
	for _, r := range pattern {
		switch r {
		case '%':
			re.WriteString(".*")
		case '_':
			re.WriteString(".")
		default:
			re.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	re.WriteString("$")
	ok, err := regexp.MatchString(re.String(), h)
	return err == nil && ok
}

// hostRank orders host patterns as MariaDB does: exact before wildcards,
// more literal characters before the first wildcard first.
func hostRank(p string) int {
	if p == "" {
		return 0
	}
	i := strings.IndexAny(p, "%_")
	if i < 0 {
		return 1 << 20
	}
	return i
}

func (s *server) readWriterLocks() writerLockFile {
	f := writerLockFile{Port: s.db.Port, Socket: s.db.SocketDir}
	b, err := os.ReadFile(s.writerLocks())
	if err != nil {
		return f
	}
	if json.Unmarshal(b, &f) != nil {
		var list []string // the first format: the list alone
		if json.Unmarshal(b, &list) == nil {
			f.Locked = list
		}
	}
	return f
}

func (s *server) saveWriterLocks(f writerLockFile) error {
	f.Port, f.Socket = s.db.Port, s.db.SocketDir
	b, _ := json.Marshal(f)
	if err := os.MkdirAll(filepath.Dir(s.writerLocks()), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.writerLocks(), b, 0o600)
}

var (
	writerChecksMu sync.Mutex
	writerChecks   = map[string]time.Time{} // lock file -> last check
)

// writerCheckDue: at most one check a minute per server.
func (s *server) writerCheckDue() bool {
	k := s.writerLocks()
	writerChecksMu.Lock()
	defer writerChecksMu.Unlock()
	if time.Since(writerChecks[k]) < time.Minute {
		return false
	}
	writerChecks[k] = time.Now()
	return true
}

// keepWritersLocked keeps the locks right on a MariaDB server Rowsafe
// holds read-only: logins that appeared since (a login made on the
// primary reaches its standby) are locked; if it takes writes after all,
// the logins on the list are unlocked. At most once a minute per server.
func (s *server) keepWritersLocked(ctx context.Context, db *sql.DB) {
	if !s.flavor.mariadb() || !s.writerCheckDue() {
		return
	}
	mu := s.writerMu()
	mu.Lock()
	defer mu.Unlock()
	ro, err := s.isReadOnly(ctx, db)
	if err != nil {
		return
	}
	if !ro {
		s.healWritable(ctx, db)
		return
	}
	if _, err := s.lockWriters(ctx, db); err != nil && !errors.Is(err, errWritable) && s.env.Log != nil {
		s.env.Log.Warn("locking logins that bypass read_only", "port", s.db.Port, "err", err)
	}
}

// healWritable unlocks the logins left on the list of a server that takes
// writes. The caller holds writerMu.
func (s *server) healWritable(ctx context.Context, db *sql.DB) {
	done, err := s.unlockWriters(ctx, db)
	if s.env.Log == nil {
		return
	}
	if len(done) > 0 {
		s.env.Log.Warn("unlocked logins Rowsafe had locked on a server that takes writes again", "port", s.db.Port, "logins", strings.Join(done, ", "))
	}
	if err != nil {
		s.env.Log.Warn("unlocking logins Rowsafe had locked", "port", s.db.Port, "err", err)
	}
}

// healWriterLocks checks every server with logins on its list (once a
// minute each): one that takes writes gets them unlocked.
func (e *Engine) healWriterLocks(ctx context.Context, env agent.EngineEnv) {
	if !e.flavor.mariadb() || env.StateDir == "" {
		return
	}
	files, _ := filepath.Glob(filepath.Join(env.StateDir, "readonly-locks-*.json"))
	for _, path := range files {
		port, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "readonly-locks-"), ".json"))
		if err != nil || port <= 0 {
			continue
		}
		s := e.server(env, protocol.DatabaseSpec{Engine: string(e.flavor), Port: port})
		f := s.readWriterLocks()
		if len(f.Locked) == 0 || !s.writerCheckDue() {
			continue
		}
		s.db.SocketDir = f.Socket
		func() {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			conn, err := s.open(cctx)
			if err != nil {
				return
			}
			defer conn.Close()
			mu := s.writerMu()
			mu.Lock()
			defer mu.Unlock()
			if ro, err := s.isReadOnly(cctx, conn); err == nil && !ro {
				s.healWritable(cctx, conn)
			}
		}()
	}
}

// lockNote says, for a summary, which logins are locked on a read-only
// MariaDB server and that the server's own root can still write.
func (s *server) lockNote() string {
	if !s.flavor.mariadb() {
		return ""
	}
	note := " Root on the server itself (through its socket) can still write: Rowsafe never locks the server's own administrator."
	if l := s.readWriterLocks().Locked; len(l) > 0 {
		note = fmt.Sprintf(" Logins that could write despite read-only are locked until it takes writes again: %s.", strings.Join(l, ", ")) + note
	}
	return note
}
