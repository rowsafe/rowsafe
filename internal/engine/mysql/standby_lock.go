package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// MariaDB's read_only stops every login but those with READ_ONLY ADMIN
// (which ALL PRIVILEGES ON *.* includes: an app login made that way, root),
// and 11.8 has no read_only that stops them too (NO_LOCK_NO_ADMIN comes
// later). So while a MariaDB server is read-only for Rowsafe (a standby,
// a fenced old primary), the logins that could still write are locked
// (ACCOUNT LOCK, outside the binary log) and their sessions ended; the
// list is kept, and exactly those are unlocked when it takes writes again.
// Not locked: Rowsafe's own login (setting read_only needs READ_ONLY
// ADMIN; the agent never writes on a read-only server), root through the
// server's socket (the server's own administrator, not reachable from the
// network) and MariaDB's system logins. Logins locked by someone else stay
// as they are. MySQL needs none of this: super_read_only stops everyone.

// writerLocks is the file listing the logins Rowsafe locked on a port.
func (s *server) writerLocks() string {
	return filepath.Join(s.env.StateDir, fmt.Sprintf("readonly-locks-%d.json", s.db.Port))
}

// lockWriters locks the logins that could write on this read-only MariaDB
// server and ends their sessions.
func (s *server) lockWriters(ctx context.Context, db *sql.DB) error {
	if !s.flavor.mariadb() {
		return nil
	}
	targets, err := s.adminLogins(ctx, db)
	if err != nil {
		return fmt.Errorf("listing the logins that bypass read_only: %w", err)
	}
	if len(targets) == 0 {
		return nil
	}
	locked := s.readWriterLocks()
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return err
	}
	for _, l := range targets {
		if _, err := c.ExecContext(ctx, "ALTER USER "+l.quoted()+" ACCOUNT LOCK"); err != nil {
			return fmt.Errorf("locking %s: %w", l.quoted(), err)
		}
		if !slices.Contains(locked, l.quoted()) {
			locked = append(locked, l.quoted())
		}
		if err := s.saveWriterLocks(locked); err != nil {
			return err
		}
		rows, err := c.QueryContext(ctx, "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = ?", l.User)
		if err != nil {
			continue
		}
		var ids []int64
		for rows.Next() {
			var id int64
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			_, _ = c.ExecContext(ctx, fmt.Sprintf("KILL CONNECTION %d", id))
		}
	}
	return nil
}

// unlockWriters unlocks the logins lockWriters locked.
func (s *server) unlockWriters(ctx context.Context, db *sql.DB) error {
	locked := s.readWriterLocks()
	if len(locked) == 0 {
		return nil
	}
	c, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return err
	}
	for _, q := range locked {
		if !lockedLoginRE.MatchString(q) {
			continue
		}
		_, _ = c.ExecContext(ctx, "ALTER USER IF EXISTS "+q+" ACCOUNT UNLOCK") // dropped meanwhile: nothing to do
	}
	if err := os.Remove(s.writerLocks()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// login is one 'user'@'host'.
type login struct{ User, Host string }

func (l login) quoted() string { return quoteString(l.User) + "@" + quoteString(l.Host) }

// lockedLoginRE checks entries of the locks file before they reach SQL.
var lockedLoginRE = regexp.MustCompile(`^'([^'\\]|\\.|'')*'@'([^'\\]|\\.|'')*'$`)

// adminLogins are the unlocked logins that could write despite read_only.
func (s *server) adminLogins(ctx context.Context, db *sql.DB) ([]login, error) {
	rows, err := db.QueryContext(ctx, `SELECT User, Host FROM mysql.global_priv
		WHERE IFNULL(JSON_VALUE(Priv, '$.account_locked'), 'false') NOT IN ('true', '1') AND IFNULL(JSON_VALUE(Priv, '$.is_role'), 'false') NOT IN ('true', '1')`)
	if err != nil {
		return nil, err
	}
	var all []login
	for rows.Next() {
		var l login
		if err := rows.Scan(&l.User, &l.Host); err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, l)
	}
	rows.Close()
	var out []login
	for _, l := range all {
		switch {
		case l.User == rowsafeUser && l.Host == "localhost", l.User == "root" && l.Host == "localhost",
			l.User == "mariadb.sys", l.User == "", standbyUserRE.MatchString(l.User):
			continue
		}
		grants, err := showGrants(ctx, db, l)
		if err != nil {
			continue // dropped meanwhile
		}
		if bypassesReadOnly(grants) {
			out = append(out, l)
		}
	}
	return out, nil
}

func showGrants(ctx context.Context, db *sql.DB, l login) ([]string, error) {
	rows, err := db.QueryContext(ctx, "SHOW GRANTS FOR "+l.quoted())
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

// bypassesReadOnly: the grants include READ_ONLY ADMIN (directly or with
// ALL PRIVILEGES on everything).
func bypassesReadOnly(grants []string) bool {
	for _, g := range grants {
		u := strings.ToUpper(g)
		if strings.Contains(u, "READ_ONLY ADMIN") || strings.Contains(u, "ALL PRIVILEGES ON *.*") {
			return true
		}
	}
	return false
}

func (s *server) readWriterLocks() []string {
	var out []string
	if b, err := os.ReadFile(s.writerLocks()); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	return out
}

func (s *server) saveWriterLocks(l []string) error {
	b, _ := json.Marshal(l)
	if err := os.MkdirAll(filepath.Dir(s.writerLocks()), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.writerLocks(), b, 0o600)
}

var (
	writerChecksMu sync.Mutex
	writerChecks   = map[string]time.Time{} // state dir and port -> last check
)

// keepWritersLocked locks logins that appeared since (a login made on the
// primary reaches its standby), at most once a minute per server.
func (s *server) keepWritersLocked(ctx context.Context, db *sql.DB) {
	if !s.flavor.mariadb() {
		return
	}
	k := s.writerLocks()
	writerChecksMu.Lock()
	due := time.Since(writerChecks[k]) >= time.Minute
	if due {
		writerChecks[k] = time.Now()
	}
	writerChecksMu.Unlock()
	if due {
		if err := s.lockWriters(ctx, db); err != nil && s.env.Log != nil {
			s.env.Log.Warn("locking logins that bypass read_only", "port", s.db.Port, "err", err)
		}
	}
}
