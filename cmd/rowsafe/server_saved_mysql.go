package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
)

// MySQL and MariaDB on a server where the agent runs its own control plane:
// sudo rowsafe add NAME mysql://... protects them as it does PostgreSQL.
// The agent backs them up with its own MySQL account, which root creates
// once (as the installer does): through the server's socket, where root
// logs in without a password on Debian and Ubuntu, or with the
// administrator password in the connection string.

// agentBinary is the agent the installer puts in place.
var agentBinary = "/opt/rowsafe/rowsafe-agent"

// mysqlSockets are where MySQL and MariaDB listen on Debian and Ubuntu.
var mysqlSockets = []string{"/var/run/mysqld/mysqld.sock", "/run/mysqld/mysqld.sock"}

// serverTarget is the database server a connection string reaches on this
// machine.
type serverTarget struct {
	mysql  bool // MySQL or MariaDB; PostgreSQL otherwise
	mongo  bool // MongoDB (server_saved_mongodb.go)
	port   int
	socket string // PostgreSQL: the socket's directory; MySQL: the socket file ("" over TCP)
}

// localTarget is the server conn reaches on this machine (ok false for
// another machine).
func localTarget(conn string) (serverTarget, bool) {
	if port, sock, ok := localCluster(conn); ok {
		return serverTarget{port: port, socket: sock}, true
	}
	if port, ok := localMongo(conn); ok {
		return serverTarget{mongo: true, port: port}, true
	}
	port, sock, ok := localMySQL(conn)
	return serverTarget{mysql: true, port: port, socket: sock}, ok
}

// localMySQL is the MySQL or MariaDB a mysql:// (or mariadb://) string
// reaches on this machine: its port and, with ?socket=, its socket file.
func localMySQL(conn string) (port int, socket string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(conn))
	if err != nil || (u.Scheme != "mysql" && u.Scheme != "mariadb") {
		return 0, "", false
	}
	for k, v := range u.Query() {
		if strings.EqualFold(k, "socket") && len(v) > 0 && strings.HasPrefix(v[len(v)-1], "/") {
			socket = v[len(v)-1]
		}
	}
	switch h := u.Hostname(); {
	case socket != "":
	case h == "" || h == "localhost" || h == "127.0.0.1" || h == "::1":
	default:
		return 0, "", false
	}
	port = 3306
	if p := u.Port(); p != "" {
		if port, err = strconv.Atoi(p); err != nil || port <= 0 || port > 65535 {
			return 0, "", false
		}
	}
	return port, socket, true
}

// match is the server's database for the target, if any.
func (t serverTarget) match(dbs []protocol.Database) *protocol.Database {
	if t.mongo {
		for i, d := range dbs {
			if protocol.NormalizeEngine(d.Engine) == protocol.EngineMongoDB && d.Port == t.port {
				return &dbs[i]
			}
		}
		return nil
	}
	if !t.mysql {
		return clusterOf(dbs, t.port, t.socket)
	}
	for i, d := range dbs {
		if e := protocol.NormalizeEngine(d.Engine); (e == protocol.EngineMySQL || e == protocol.EngineMariaDB) && d.Port == t.port {
			return &dbs[i]
		}
	}
	return nil
}

// socketOrDefault is the MySQL socket the agent uses: the connection
// string's, else the one this machine has.
func (t serverTarget) socketOrDefault() string {
	if t.socket != "" {
		return t.socket
	}
	for _, p := range mysqlSockets {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p
		}
	}
	return ""
}

// mysqlEngine is the engine a MySQL connection reaches: read from the
// server (MariaDB says so in its version) unless rowsafe add already did.
var mysqlEngine = func(ctx context.Context, d *local.DB, checked bool) (string, error) {
	if !checked {
		if _, err := d.Check(ctx); err != nil {
			return "", err
		}
	}
	return d.Engine(), nil
}

// ensureMySQLAccount creates the agent's own MySQL account when it has
// none yet and this is root on the agent's server (the installer's
// rowsafe-agent setup mysql-account), after asking. It returns false when
// the person said no (or couldn't be asked).
func ensureMySQLAccount(ctx context.Context, s savedDB, engine string, t serverTarget, stateDir string, yes, asJSON bool) (bool, error) {
	account := filepath.Join(stateDir, "engines", engine, fmt.Sprintf("account-%d.cnf", t.port))
	if _, err := os.Stat(account); err == nil || !isRoot() {
		return true, nil // there, or the agent makes it (Docker: ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE)
	}
	if _, err := os.Stat(agentBinary); err != nil {
		return true, nil
	}
	name := protocol.EngineDisplayName(engine)
	q := fmt.Sprintf("Rowsafe needs its own %s account here (rowsafe@localhost, for backups, Marks and restore tests; its password stays on this server). Create it now?", name)
	if err := confirmChange(yes, q); err != nil {
		if errors.Is(err, errNoTerminal) || errors.Is(err, errCancelled) {
			say(asJSON, "Not protected yet: Rowsafe needs its own %s account first. Run again when you're ready: sudo rowsafe add %s ... --yes\n", name, s.Name)
			return false, nil
		}
		return false, err
	}
	args := []string{"setup", "mysql-account", "--engine", engine, "--port", strconv.Itoa(t.port), "--state-dir", stateDir}
	if sock := t.socketOrDefault(); sock != "" {
		args = append(args, "--socket", sock)
	}
	if fi, err := os.Stat(stateDir); err == nil {
		if uid, _, ok := fileOwner(fi); ok {
			if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
				args = append(args, "--owner", u.Username)
			}
		}
	}
	run := func(extra ...string) (string, error) {
		out, err := exec.CommandContext(ctx, agentBinary, append(args, extra...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	// Root through the socket first; then the connection string's user and
	// password (from a file only root reads, never the command line).
	out, err := run()
	if err != nil {
		if admin, pw := mysqlLogin(s.URL); pw != "" {
			f, ferr := os.CreateTemp("", "rowsafe-admin-")
			if ferr != nil {
				return false, ferr
			}
			defer os.Remove(f.Name())
			_, werr := f.WriteString(pw)
			if cerr := f.Close(); werr != nil || cerr != nil {
				return false, errors.Join(werr, cerr)
			}
			out, err = run("--admin-user", admin, "--admin-password-file", f.Name())
		}
	}
	if err != nil {
		return false, fmt.Errorf("creating Rowsafe's %s account failed: %s\nSaved, but not protected yet. Use a connection string with an administrator's password (rowsafe add %s mysql://root:PASSWORD@localhost:%d/), or run the installer again",
			name, out, s.Name, t.port)
	}
	say(asJSON, "%s\n", out)
	return true, nil
}

// mysqlLogin is the user and password in a mysql:// string.
func mysqlLogin(conn string) (user, password string) {
	u, err := url.Parse(strings.TrimSpace(conn))
	if err != nil || u.User == nil {
		return "", ""
	}
	pw, _ := u.User.Password()
	if user = u.User.Username(); user == "" {
		user = "root"
	}
	return user, pw
}

// mysqlSystemDBs are MySQL's and MariaDB's own databases.
var mysqlSystemDBs = []string{"mysql", "sys", "information_schema", "performance_schema"}
