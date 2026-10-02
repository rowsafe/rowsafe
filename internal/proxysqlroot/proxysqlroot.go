// Package proxysqlroot is the root side of connection pooling for MySQL and
// MariaDB: root's copy of the agent (rowsafe-permissions proxysql-apply,
// started by rowsafe-proxysql.path) installs and configures ProxySQL in
// front of a MySQL or MariaDB port root allowed (/etc/rowsafe/
// pooler-allowed, `rowsafe-allow pooler`), the way the PgBouncer helper
// does for PostgreSQL.
//
// ProxySQL's admin interface can change everything it does, so its
// credentials stay with root (a random password in root's state
// directory); the agent gets read-only statistics credentials. Apps log in
// with their own MySQL user and password: ProxySQL checks them against the
// password hashes the agent reads from mysql.user and hands over (they
// never leave the server), and is told about new users as they come.
//
// The agent is not trusted: every value is checked here, users are plain
// names with a password hash, and ProxySQL only ever points at 127.0.0.1 on
// an allowed port.
package proxysqlroot

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// Defaults (the systemd unit sets the directories).
const (
	DefaultRequestDir = "/var/lib/rowsafe/pooler"
	DefaultAnswerDir  = "/run/rowsafe-proxysql"
	DefaultStateDir   = "/var/lib/rowsafe-proxysql"
	DefaultAllowFile  = "/etc/rowsafe/pooler-allowed"
	// StatsFile holds the statistics credentials ("user:password"), root's
	// and readable by the agent's group.
	DefaultStatsFile = "/etc/rowsafe/proxysql-stats"
	RequestName      = "proxysql-request"
	ResultName       = "result"
	MaxRequest       = 1 << 20
	AdminAddr        = "127.0.0.1:6032"
	DefaultPort      = 6033
	statsUser        = "rowsafe_stats"
	userComment      = "rowsafe"
)

// Actions.
const (
	ActionOn       = "on"       // install if needed, configure, sync users
	ActionUsers    = "users"    // sync users only
	ActionRetarget = "retarget" // point at another allowed port
	ActionOff      = "off"      // stop and disable; remove the package Rowsafe installed
)

// User is one MySQL user ProxySQL lets in: its password hash as
// mysql.user has it (hex), and its authentication plugin.
type User struct {
	Name   string `json:"name"`
	Hash   string `json:"hash"` // hex of authentication_string
	Plugin string `json:"plugin"`
}

// Request is what the agent hands over.
type Request struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Flavor string `json:"flavor"` // mysql or mariadb
	// Target is the MySQL port (on 127.0.0.1).
	Target int `json:"target"`
	// Port and Listen are where ProxySQL listens for apps (addresses: the
	// server's own; "0.0.0.0" only with "public" allowed).
	Port          int      `json:"port,omitempty"`
	Listen        []string `json:"listen,omitempty"`
	MaxClientConn int      `json:"max_client_conn,omitempty"`
	PoolSize      int      `json:"pool_size,omitempty"`
	// Multiplex: transaction mode (ProxySQL reuses server connections
	// between transactions); false is session mode.
	Multiplex bool   `json:"multiplex"`
	Users     []User `json:"users,omitempty"`
}

// Result is root's answer.
type Result struct {
	ID          string    `json:"id"`
	OK          bool      `json:"ok"`
	Error       string    `json:"error,omitempty"`
	Version     string    `json:"version,omitempty"`
	Installed   bool      `json:"installed,omitempty"`
	Removed     bool      `json:"removed,omitempty"`
	Addresses   []string  `json:"addresses,omitempty"`
	Target      string    `json:"target,omitempty"`
	UsersSynced int       `json:"users_synced,omitempty"`
	Warnings    []string  `json:"warnings,omitempty"`
	FinishedAt  time.Time `json:"finished_at"`
}

var (
	idRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	userRE   = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,32}$`)
	hexRE    = regexp.MustCompile(`^[0-9A-Fa-f]{2,512}$`)
	pluginOK = []string{"mysql_native_password", "caching_sha2_password"}
)

// Allowed reads the allow file: ports, and whether ProxySQL may listen on
// public addresses.
func Allowed(path string) (ports map[int]bool, public bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	ports = map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if f[0] == "public" {
			public = true
			continue
		}
		if p, err := strconv.Atoi(f[0]); err == nil && p > 0 && p < 65536 {
			ports[p] = true
		}
	}
	return ports, public, nil
}

// Check validates a request.
func Check(r Request, ports map[int]bool, public bool) error {
	if !idRE.MatchString(r.ID) {
		return errors.New("invalid request id")
	}
	if r.Flavor != "mysql" && r.Flavor != "mariadb" {
		return fmt.Errorf("unknown flavor %q", r.Flavor)
	}
	switch r.Action {
	case ActionOn, ActionUsers, ActionRetarget, ActionOff:
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}
	if r.Action == ActionOff {
		return nil
	}
	if !ports[r.Target] {
		return fmt.Errorf("port %d is not in the allow list: pooling it from Rowsafe is not allowed", r.Target)
	}
	if r.Action == ActionOn {
		if r.Port < 1024 || r.Port > 65535 || r.Port == r.Target || r.Port == 6032 {
			return fmt.Errorf("ProxySQL's port must be between 1024 and 65535, and not MySQL's or ProxySQL's admin port")
		}
		if len(r.Listen) == 0 || len(r.Listen) > 16 {
			return errors.New("choose where ProxySQL listens")
		}
		for _, a := range r.Listen {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				return fmt.Errorf("invalid address %q", a)
			}
			if ip.IsUnspecified() && !public {
				return errors.New("listening on every address is not allowed on this server (root allows it with: sudo rowsafe-allow pooler-public)")
			}
		}
		if r.MaxClientConn < 10 || r.MaxClientConn > 100000 || r.PoolSize < 1 || r.PoolSize > 10000 {
			return errors.New("invalid connection limits")
		}
	}
	if len(r.Users) > 5000 {
		return errors.New("too many users")
	}
	for _, u := range r.Users {
		if !userRE.MatchString(u.Name) || !hexRE.MatchString(u.Hash) || !slices.Contains(pluginOK, u.Plugin) {
			return fmt.Errorf("invalid user %q", u.Name)
		}
	}
	return nil
}

// Runner runs a command as root and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Applier configures ProxySQL for root.
type Applier struct {
	StateDir  string
	StatsFile string
	// AgentGID owns the statistics file (group-readable).
	AgentGID int
	Run      Runner
	// AdminAddr is ProxySQL's admin interface, BackendHost where MySQL is
	// (tests; 127.0.0.1 otherwise).
	AdminAddr, BackendHost string
}

func (a *Applier) adminFile() string { return filepath.Join(a.StateDir, "admin") }
func (a *Applier) ownedFile() string { return filepath.Join(a.StateDir, "installed-by-rowsafe") }
func (a *Applier) ours() bool {
	_, err := os.Stat(a.adminFile())
	return err == nil
}

func randomSecret() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (a *Applier) admin(ctx context.Context, user, pw string) (*sql.DB, error) {
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr = user, pw, "tcp", cmpOr(a.AdminAddr, AdminAddr)
	c.Timeout = 5 * time.Second
	c.InterpolateParams = false
	conn, err := mysql.NewConnector(c)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// connect opens the admin interface with Rowsafe's credentials, taking a
// fresh ProxySQL over (its default admin:admin) the first time.
func (a *Applier) connect(ctx context.Context) (*sql.DB, error) {
	if data, err := os.ReadFile(a.adminFile()); err == nil {
		db, err := a.admin(ctx, "admin", strings.TrimSpace(string(data)))
		if err != nil {
			return nil, fmt.Errorf("ProxySQL's admin interface refused Rowsafe's credentials: %v", err)
		}
		return db, nil
	}
	db, err := a.admin(ctx, "admin", "admin")
	if err != nil {
		return nil, errors.New("ProxySQL on this server has its own admin password, so it has its own configuration; Rowsafe doesn't replace it")
	}
	pw, stats := randomSecret(), randomSecret()
	for _, q := range []string{
		fmt.Sprintf("UPDATE global_variables SET variable_value='admin:%s' WHERE variable_name='admin-admin_credentials'", pw),
		fmt.Sprintf("UPDATE global_variables SET variable_value='%s:%s' WHERE variable_name='admin-stats_credentials'", statsUser, stats),
		"UPDATE global_variables SET variable_value='127.0.0.1:6032' WHERE variable_name='admin-mysql_ifaces'",
		"LOAD ADMIN VARIABLES TO RUNTIME", "SAVE ADMIN VARIABLES TO DISK",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting ProxySQL's admin credentials: %v", err)
		}
	}
	db.Close()
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(a.adminFile(), []byte(pw+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := a.writeStats(stats); err != nil {
		return nil, err
	}
	return a.admin(ctx, "admin", pw)
}

func (a *Applier) writeStats(secret string) error {
	if a.StatsFile == "" {
		return nil
	}
	tmp := a.StatsFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(statsUser+":"+secret+"\n"), 0o640); err != nil {
		return err
	}
	if a.AgentGID >= 0 && os.Getuid() == 0 {
		if err := os.Chown(tmp, 0, a.AgentGID); err != nil {
			return err
		}
	}
	return os.Rename(tmp, a.StatsFile)
}

func (a *Applier) installed() bool {
	_, err := a.Run(context.Background(), "proxysql", "--version")
	return err == nil
}

func (a *Applier) version(ctx context.Context) string {
	out, err := a.Run(ctx, "proxysql", "--version")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "ProxySQL" && f[1] == "version" {
			v, _, _ := strings.Cut(f[2], "-")
			return strings.TrimSuffix(v, ",")
		}
	}
	return ""
}

// Apply runs a request.
func (a *Applier) Apply(ctx context.Context, r Request, ports map[int]bool, public bool) Result {
	res := Result{ID: r.ID}
	if err := Check(r, ports, public); err != nil {
		res.Error = err.Error()
		return res
	}
	var err error
	switch r.Action {
	case ActionOff:
		err = a.off(ctx, &res)
	case ActionOn:
		err = a.on(ctx, r, &res)
	default:
		var db *sql.DB
		if !a.ours() {
			err = errors.New("Rowsafe doesn't manage ProxySQL on this server (turn pooling on first)")
			break
		}
		db, err = a.connect(ctx)
		if err != nil {
			break
		}
		defer db.Close()
		if r.Action == ActionRetarget {
			err = a.servers(ctx, db, r)
		}
		if err == nil {
			res.UsersSynced, res.Warnings, err = a.users(ctx, db, r)
		}
		res.Target = fmt.Sprintf("127.0.0.1:%d", r.Target)
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	return res
}

func (a *Applier) on(ctx context.Context, r Request, res *Result) error {
	if !a.installed() {
		if out, err := a.Run(ctx, "apt-get", "install", "-y", "-q", "--no-install-recommends", "proxysql"); err != nil {
			return fmt.Errorf("ProxySQL isn't installed and couldn't be installed from this server's package sources (add ProxySQL's apt repository: https://proxysql.com/documentation/installing-proxysql/): %s",
				lastLine(out))
		}
		if !a.installed() {
			return errors.New("the proxysql package was installed but proxysql is not on the PATH")
		}
		res.Installed = true
		if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
			return err
		}
		_ = os.WriteFile(a.ownedFile(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	}
	if out, err := a.Run(ctx, "systemctl", "enable", "--now", "proxysql"); err != nil {
		return fmt.Errorf("starting ProxySQL failed: %s", lastLine(out))
	}
	var db *sql.DB
	var err error
	for i := 0; i < 20; i++ { // ProxySQL takes a moment to open its admin interface
		if db, err = a.connect(ctx); err == nil || strings.Contains(err.Error(), "its own") {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	defer db.Close()
	ifaces := make([]string, 0, len(r.Listen))
	for _, l := range r.Listen {
		ip := netip.MustParseAddr(l)
		ifaces = append(ifaces, netip.AddrPortFrom(ip, uint16(r.Port)).String())
	}
	plugin := "caching_sha2_password"
	if r.Flavor == "mariadb" {
		plugin = "mysql_native_password"
	}
	var cur string
	_ = db.QueryRowContext(ctx, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='mysql-interfaces'").Scan(&cur)
	want := strings.Join(ifaces, ";")
	vars := map[string]string{
		"mysql-interfaces":                    want,
		"mysql-max_connections":               strconv.Itoa(r.MaxClientConn),
		"mysql-multiplexing":                  strconv.FormatBool(r.Multiplex),
		"mysql-default_authentication_plugin": plugin,
		"mysql-monitor_enabled":               "false",
	}
	for k, v := range vars {
		if _, err := db.ExecContext(ctx, fmt.Sprintf("UPDATE global_variables SET variable_value='%s' WHERE variable_name='%s'", v, k)); err != nil {
			return fmt.Errorf("setting %s: %v", k, err)
		}
	}
	for _, q := range []string{"LOAD MYSQL VARIABLES TO RUNTIME", "SAVE MYSQL VARIABLES TO DISK"} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("%s: %v", q, err)
		}
	}
	if err := a.servers(ctx, db, r); err != nil {
		return err
	}
	if res.UsersSynced, res.Warnings, err = a.users(ctx, db, r); err != nil {
		return err
	}
	if cur != want { // ProxySQL opens new listeners only when it starts
		db.Close()
		if out, err := a.Run(ctx, "systemctl", "restart", "proxysql"); err != nil {
			return fmt.Errorf("restarting ProxySQL to listen on %s failed: %s", want, lastLine(out))
		}
	}
	res.Version, res.Addresses, res.Target = a.version(ctx), ifaces, fmt.Sprintf("127.0.0.1:%d", r.Target)
	return nil
}

func (a *Applier) servers(ctx context.Context, db *sql.DB, r Request) error {
	size := r.PoolSize
	if size == 0 { // retarget: keep the pool size
		_ = db.QueryRowContext(ctx, "SELECT max_connections FROM mysql_servers WHERE hostgroup_id = 0 LIMIT 1").Scan(&size)
	}
	for _, q := range []string{
		"DELETE FROM mysql_servers WHERE hostgroup_id = 0",
		fmt.Sprintf("INSERT INTO mysql_servers (hostgroup_id, hostname, port, max_connections, comment) VALUES (0, '%s', %d, %d, '%s')",
			cmpOr(a.BackendHost, "127.0.0.1"), r.Target, max(size, 2), userComment),
		"LOAD MYSQL SERVERS TO RUNTIME", "SAVE MYSQL SERVERS TO DISK",
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("pointing ProxySQL at port %d: %v", r.Target, err)
		}
	}
	return nil
}

// users replaces Rowsafe's users in ProxySQL with r.Users.
func (a *Applier) users(ctx context.Context, db *sql.DB, r Request) (int, []string, error) {
	if _, err := db.ExecContext(ctx, "DELETE FROM mysql_users WHERE comment = '"+userComment+"'"); err != nil {
		return 0, nil, err
	}
	n := 0
	for _, u := range r.Users {
		h, _ := hex.DecodeString(u.Hash)
		q := fmt.Sprintf("INSERT OR REPLACE INTO mysql_users (username, password, default_hostgroup, transaction_persistent, comment) VALUES ('%s', X'%s', 0, 1, '%s')",
			u.Name, strings.ToUpper(hex.EncodeToString(h)), userComment)
		if _, err := db.ExecContext(ctx, q); err != nil {
			return n, nil, fmt.Errorf("adding %s to ProxySQL: %v", u.Name, err)
		}
		n++
	}
	for _, q := range []string{"LOAD MYSQL USERS TO RUNTIME", "SAVE MYSQL USERS TO DISK"} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			return n, nil, err
		}
	}
	return n, nil, nil
}

func (a *Applier) off(ctx context.Context, res *Result) error {
	if !a.ours() {
		res.Removed = false
		return nil // nothing of Rowsafe's
	}
	_, _ = a.Run(ctx, "systemctl", "disable", "--now", "proxysql")
	if _, err := os.Stat(a.ownedFile()); err == nil {
		if out, err := a.Run(ctx, "apt-get", "purge", "-y", "-q", "proxysql"); err != nil {
			return fmt.Errorf("removing the proxysql package failed: %s", lastLine(out))
		}
		res.Removed = true
	}
	if a.StatsFile != "" {
		_ = os.Remove(a.StatsFile)
	}
	return os.RemoveAll(a.StateDir)
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	l := lines[len(lines)-1]
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}
