package mysql

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Accounts. The agent never uses a password it wasn't given: it logs in
// with the account Rowsafe created for itself (account-<port>.cnf in the
// engine's state directory, 0600, written by `rowsafe-agent setup
// mysql-account` as root, or by the agent in Docker with the admin password
// file), or with ROWSAFE_MYSQL_USER and ROWSAFE_MYSQL_PASSWORD_FILE.

func init() {
	// The driver logs connection hiccups (a private server shutting down)
	// on its own; errors are returned to the caller anyway.
	_ = mysql.SetLogger(log.New(io.Discard, "", 0))
}

// rowsafeUser is the account Rowsafe creates for itself.
const rowsafeUser = "rowsafe"

// account is a MySQL user and password.
type account struct {
	User, Password string
	// Source says where it came from, for messages.
	Source string
}

// accountPath is where Rowsafe's own account for the server on port is
// kept.
func accountPath(stateDir string, port int) string {
	return filepath.Join(stateDir, fmt.Sprintf("account-%d.cnf", port))
}

// errNoAccount: Rowsafe has no account on this server yet.
var errNoAccount = errors.New("Rowsafe has no MySQL account on this server yet")

// account returns the account the agent logs in with.
func (s *server) account() (account, error) {
	if s.cfg.User != "" {
		pw, err := readSecretFile(s.cfg.PasswordFile)
		if err != nil {
			return account{}, fmt.Errorf("ROWSAFE_MYSQL_PASSWORD_FILE: %w", err)
		}
		return account{User: s.cfg.User, Password: pw, Source: "ROWSAFE_MYSQL_USER"}, nil
	}
	return readAccountFile(accountPath(s.env.StateDir, s.db.Port))
}

// adminAccount is the administrator account for creating Rowsafe's own
// (Docker: ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE); ok is false without one.
func (s *server) adminAccount() (account, bool, error) {
	if s.cfg.AdminPasswordFile == "" {
		return account{}, false, nil
	}
	pw, err := readSecretFile(s.cfg.AdminPasswordFile)
	if err != nil {
		return account{}, false, fmt.Errorf("ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE: %w", err)
	}
	return account{User: s.cfg.AdminUser, Password: pw, Source: "ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE"}, true, nil
}

func readSecretFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// readAccountFile reads user and password from a [client] option file.
func readAccountFile(path string) (account, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return account{}, errNoAccount
	}
	if err != nil {
		return account{}, err
	}
	defer f.Close()
	a := account{Source: path}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		switch strings.TrimSpace(k) {
		case "user":
			a.User = v
		case "password":
			a.Password = v
		}
	}
	if a.User == "" {
		return account{}, fmt.Errorf("%s has no user", path)
	}
	return a, sc.Err()
}

// optionFile renders a [client] option file for the tools. Passwords
// Rowsafe generates are letters and digits; anything else is refused
// rather than escaped.
func optionFile(a account, socket string) (string, error) {
	for _, v := range []string{a.User, a.Password, socket} {
		if strings.ContainsAny(v, "\"\\\n\r\x00") {
			return "", errors.New("the MySQL account or socket contains characters Rowsafe can't pass to the tools (quotes, backslashes or newlines)")
		}
	}
	var b strings.Builder
	b.WriteString("[client]\n")
	fmt.Fprintf(&b, "user=\"%s\"\n", a.User)
	fmt.Fprintf(&b, "password=\"%s\"\n", a.Password)
	if socket != "" {
		fmt.Fprintf(&b, "socket=\"%s\"\n", socket)
	}
	return b.String(), nil
}

// socketPath is the server's Unix socket: DatabaseSpec.SocketDir holds the
// socket file (or its directory: mysqld.sock in it).
func (s *server) socketPath() string {
	p := s.db.SocketDir
	if p == "" {
		return ""
	}
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return filepath.Join(p, "mysqld.sock")
	}
	return p
}

// dsn builds a driver configuration for the server.
func dsn(a account, socket string, port int) *mysql.Config {
	c := mysql.NewConfig()
	c.User, c.Passwd = a.User, a.Password
	if socket != "" {
		c.Net, c.Addr = "unix", socket
	} else {
		c.Net, c.Addr = "tcp", "127.0.0.1:"+strconv.Itoa(port)
	}
	c.Timeout = 10 * time.Second
	c.ParseTime = true
	c.Loc = time.UTC
	c.AllowNativePasswords = true
	c.AllowCleartextPasswords = socket != "" // unix socket only (PAM, unix_socket fallbacks)
	c.Params = map[string]string{"time_zone": "'+00:00'"}
	return c
}

// open connects to the server with Rowsafe's account. The pool keeps one
// connection: statements that belong together (a transaction, session
// settings) run on it.
func (s *server) open(ctx context.Context) (*sql.DB, error) {
	a, err := s.account()
	if err != nil {
		return nil, err
	}
	return openWith(ctx, a, s.socketPath(), s.db.Port)
}

func openWith(ctx context.Context, a account, socket string, port int) (*sql.DB, error) {
	conn, err := mysql.NewConnector(dsn(a, socket, port))
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, connectError(err, a, socket, port)
	}
	return db, nil
}

// connectError explains a failed login in plain words.
func connectError(err error, a account, socket string, port int) error {
	where := fmt.Sprintf("port %d", port)
	if socket != "" {
		where = socket
	}
	var me *mysql.MySQLError
	if errors.As(err, &me) && (me.Number == 1045 || me.Number == 1698) {
		return fmt.Errorf("the server refused the login of %s (from %s) over %s: %s", a.User, a.Source, where, me.Message)
	}
	return fmt.Errorf("can't connect to the server over %s: %w", where, err)
}

// writeOptionFile writes the tools' option file for the current account
// (0600, in the engine's state directory) and returns its path.
func (s *server) writeOptionFile() (string, error) {
	a, err := s.account()
	if err != nil {
		return "", err
	}
	content, err := optionFile(a, s.socketPath())
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.env.StateDir, "run")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("client-%d.cnf", s.db.Port))
	return path, writeFileAtomic(path, []byte(content), 0o600)
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// quoteIdent quotes a MySQL identifier.
func quoteIdent(s string) string { return "`" + strings.ReplaceAll(s, "`", "``") + "`" }

// quoteString quotes a string literal (NO_BACKSLASH_ESCAPES or not).
func quoteString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
