package mysql

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Rowsafe's MySQL account. Created once, when backups are set up, by root
// through the local socket (MySQL's auth_socket and MariaDB's unix_socket
// let root in without a password on Debian and Ubuntu), or with an
// administrator password the person gives the installer (or, in Docker, the
// agent through ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE). Its password is random
// and stays on this server, in the agent's state directory (0600).
//
// It gets what backups, binary log shipping, monitoring, Marks, restore
// tests and Rewind need, and nothing to change users or the server's
// configuration:
//
//   - RELOAD, LOCK TABLES, PROCESS, BACKUP_ADMIN (MySQL): a consistent
//     physical backup (LOCK INSTANCE FOR BACKUP, a brief lock of non-InnoDB
//     tables, redo log copying);
//   - REPLICATION CLIENT (MySQL) / BINLOG MONITOR (MariaDB): the binary log
//     position of a backup or a Mark, and which binary logs to ship;
//   - SELECT, SHOW VIEW, TRIGGER: comparing a copy with production and
//     warning about triggers; monitoring's statistics;
//   - INSERT, UPDATE: bringing rows back from a copy, only when a person
//     asks for it in the dashboard;
//   - CONNECTION_ADMIN (MySQL) / CONNECTION ADMIN (MariaDB): ending a query
//     or session that blocks others, only when a person applies that fix.

// AccountOptions describe how to create Rowsafe's account.
type AccountOptions struct {
	Engine   string // protocol.EngineMySQL or protocol.EngineMariaDB
	Port     int
	Socket   string // the server's Unix socket file
	StateDir string // the agent's ROWSAFE_STATE_DIR
	// AdminUser and AdminPasswordFile log in as an administrator with a
	// password; without a password file the client logs in as root through
	// the socket (auth_socket / unix_socket).
	AdminUser         string
	AdminPasswordFile string
	// Owner owns the account file (the agent's OS user); -1 keeps the
	// current user.
	UID, GID int
}

// CreateAccount creates (or resets) Rowsafe's MySQL account with the
// server's own client and saves it for the agent. It prints nothing but
// returns what it did.
func CreateAccount(ctx context.Context, o AccountOptions) (string, error) {
	f := flavor(o.Engine)
	if f != flavorMySQL && f != flavorMariaDB {
		return "", fmt.Errorf("unknown engine %q", o.Engine)
	}
	stateDir := filepath.Join(o.StateDir, "engines", o.Engine)
	s := &server{flavor: f, cfg: config{BinDir: os.Getenv("ROWSAFE_MYSQL_BIN_DIR")}}
	client, err := s.tool("client")
	if err != nil {
		return "", fmt.Errorf("the %s client isn't installed: %w", f.display(), err)
	}
	password, err := randomPassword()
	if err != nil {
		return "", err
	}
	admin := account{User: o.AdminUser}
	if admin.User == "" {
		admin.User = "root"
	}
	if o.AdminPasswordFile != "" {
		if admin.Password, err = readSecretFile(o.AdminPasswordFile); err != nil {
			return "", fmt.Errorf("reading the administrator password: %w", err)
		}
	}
	tmp, err := os.MkdirTemp("", "rowsafe-mysql-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	opts, err := optionFile(admin, o.Socket)
	if err != nil {
		return "", err
	}
	if admin.Password == "" {
		// Socket authentication: no password line at all.
		opts = strings.Replace(opts, "password=\"\"\n", "", 1)
	}
	optPath := filepath.Join(tmp, "admin.cnf")
	if err := os.WriteFile(optPath, []byte(opts), 0o600); err != nil {
		return "", err
	}
	run := func(sqlText string) ([]byte, error) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		args := []string{"--defaults-extra-file=" + optPath, "--batch", "--skip-column-names"}
		if o.Socket == "" {
			args = append(args, "--protocol=tcp", "--host=127.0.0.1", fmt.Sprintf("--port=%d", o.Port))
		} else {
			args = append(args, "--protocol=socket")
		}
		cmd := exec.CommandContext(cctx, client, args...)
		cmd.Stdin = strings.NewReader(sqlText)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.Bytes(), err
	}
	out, err := run("SELECT VERSION();\n")
	if err != nil {
		return "", fmt.Errorf("logging in to %s as %s failed: %s", f.display(), admin.User, firstLine(string(out)))
	}
	version := strings.TrimSpace(string(out))
	stmts := accountSQL(f, version, password)
	if out, err := run(strings.Join(stmts, ";\n") + ";\n"); err != nil {
		return "", fmt.Errorf("creating the %s account failed: %s", rowsafeUser, firstLine(string(out)))
	}
	if err := saveAccount(stateDir, o.Port, account{User: rowsafeUser, Password: password}, o.UID, o.GID); err != nil {
		return "", err
	}
	return fmt.Sprintf("Created the %s account %s@localhost for Rowsafe on %s (its password is kept in %s).",
		f.display(), rowsafeUser, version, accountPath(stateDir, o.Port)), nil
}

// createAccountAsAdmin creates Rowsafe's account through the driver with
// the admin password file (Docker).
func (s *server) createAccountAsAdmin(ctx context.Context) (bool, error) {
	admin, ok, err := s.adminAccount()
	if err != nil || !ok {
		return false, err
	}
	db, err := openWith(ctx, admin, s.socketPath(), s.db.Port)
	if err != nil {
		return false, err
	}
	defer db.Close()
	var version string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return false, err
	}
	password, err := randomPassword()
	if err != nil {
		return false, err
	}
	for _, stmt := range accountSQL(s.flavor, version, password) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return false, fmt.Errorf("creating the %s account: %w", rowsafeUser, err)
		}
	}
	return true, saveAccount(s.env.StateDir, s.db.Port, account{User: rowsafeUser, Password: password}, -1, -1)
}

// accountSQL creates or resets Rowsafe's account and grants what it needs.
func accountSQL(f flavor, version, password string) []string {
	user := quoteString(rowsafeUser) + "@'localhost'"
	pw := quoteString(password)
	var grants []string
	if f.mariadb() {
		grants = []string{
			"GRANT SELECT, INSERT, UPDATE, SHOW VIEW, TRIGGER, RELOAD, PROCESS, LOCK TABLES, BINLOG MONITOR, CONNECTION ADMIN ON *.* TO " + user,
		}
	} else {
		grants = []string{
			"GRANT SELECT, INSERT, UPDATE, SHOW VIEW, TRIGGER, RELOAD, PROCESS, LOCK TABLES, REPLICATION CLIENT ON *.* TO " + user,
			"GRANT BACKUP_ADMIN, CONNECTION_ADMIN ON *.* TO " + user,
		}
	}
	_ = version
	return append([]string{
		"CREATE USER IF NOT EXISTS " + user + " IDENTIFIED BY " + pw,
		"ALTER USER " + user + " IDENTIFIED BY " + pw,
	}, grants...)
}

// saveAccount writes the account file (0600) and gives it to uid:gid.
func saveAccount(stateDir string, port int, a account, uid, gid int) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if uid >= 0 {
		// The engines directory and this engine's are the agent's.
		for _, d := range []string{filepath.Dir(stateDir), stateDir} {
			if err := os.Chown(d, uid, gid); err != nil {
				return err
			}
		}
	}
	content, err := optionFile(a, "")
	if err != nil {
		return err
	}
	path := accountPath(stateDir, port)
	if err := writeFileAtomic(path, []byte("# Rowsafe's MySQL account (created by the installer). Keep it private.\n"+content), 0o600); err != nil {
		return err
	}
	if uid >= 0 {
		return os.Chown(path, uid, gid)
	}
	return nil
}

// randomPassword is 32 random letters and digits with a fixed prefix that
// satisfies validate_password's strong policies (mixed case, a digit, a
// special character).
func randomPassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	var b strings.Builder
	b.WriteString("Rs9_")
	for range 32 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[n.Int64()])
	}
	return b.String(), nil
}

// ensureAccount makes sure the agent can log in, creating its account with
// the admin password file when there is none yet (Docker).
func (s *server) ensureAccount(ctx context.Context) (*sql.DB, error) {
	db, err := s.open(ctx)
	if err == nil || !errors.Is(err, errNoAccount) {
		return db, err
	}
	created, cerr := s.createAccountAsAdmin(ctx)
	if cerr != nil {
		return nil, cerr
	}
	if !created {
		if s.env.Config.Sidecar() {
			return nil, fmt.Errorf("%s: set ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE (the file with the root password) so the agent can create its own account, "+
				"or ROWSAFE_MYSQL_USER and ROWSAFE_MYSQL_PASSWORD_FILE", errNoAccount)
		}
		return nil, fmt.Errorf("%s: run the installer again, or: sudo rowsafe-agent setup mysql-account --engine %s --port %d",
			errNoAccount, s.flavor, s.db.Port)
	}
	return s.open(ctx)
}
