package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/pgbouncer"
	"github.com/rowsafe/rowsafe/protocol"
)

// Connection pooling: PgBouncer in front of one PostgreSQL cluster of this
// server.
//
// The agent never installs or configures PgBouncer itself: it hands a
// request to the root helper (rowsafe-pg-restart in PgBouncer mode, started
// by rowsafe-pooler.path), which the installer sets up only when root
// allowed it (--allow-pooler):
//
//	/etc/rowsafe/pooler-allowed      root, 0644: the PostgreSQL ports it may pool
//	<state dir>/pooler/request       written by the agent: "ID ACTION KEY=VALUE..."
//	/run/rowsafe-pooler/result       written by the helper: key=value lines
//	/etc/pgbouncer/userlist.txt      root:postgres 0640: rowsafe_pgbouncer's password
//	<state dir>/pooling.json         what the agent set up (database, settings, target)
//
// Clients log in with their own PostgreSQL user and password: PgBouncer
// looks passwords up with auth_query, as the role rowsafe_pgbouncer, through
// a SECURITY DEFINER function the agent creates (rowsafe_pgbouncer.
// user_lookup, which never returns superusers). That role's password is
// random; PostgreSQL only gets its SCRAM verifier, and the plain password
// lives only in PgBouncer's root-owned userlist.

// PoolerConfig is the agent's PgBouncer configuration.
type PoolerConfig struct {
	// AllowFile lists the ports root allowed PgBouncer in front of
	// (ROWSAFE_POOLER_ALLOW_FILE); written by the installer.
	AllowFile string
	// Dir is where the agent writes requests to the helper
	// (ROWSAFE_POOLER_DIR, default <state dir>/pooler).
	Dir string
	// ResultDir is the helper's own directory with its answer
	// (ROWSAFE_POOLER_RESULT_DIR).
	ResultDir string
	// SocketDir is where PgBouncer's Unix socket is (ROWSAFE_POOLER_SOCKET_DIR).
	SocketDir string
	// Userlist is PgBouncer's auth file (ROWSAFE_POOLER_USERLIST): the agent
	// reads rowsafe_pgbouncer's password from it to reach the admin console.
	Userlist string
	// StatsURL is a PgBouncer Rowsafe doesn't manage, to monitor
	// (ROWSAFE_POOLER_STATS_URL, e.g. a Docker service:
	// postgres://stats:secret@pgbouncer:6432/pgbouncer), and Database the
	// Rowsafe database it serves (ROWSAFE_POOLER_DATABASE; optional with a
	// single database).
	StatsURL string
	Database string
}

func poolerConfigFromEnv(c *Config) error {
	c.Pooler = PoolerConfig{
		AllowFile: env("ROWSAFE_POOLER_ALLOW_FILE", "/etc/rowsafe/pooler-allowed"),
		Dir:       env("ROWSAFE_POOLER_DIR", filepath.Join(c.StateDir, "pooler")),
		ResultDir: env("ROWSAFE_POOLER_RESULT_DIR", "/run/rowsafe-pooler"),
		SocketDir: env("ROWSAFE_POOLER_SOCKET_DIR", "/var/run/postgresql"),
		Userlist:  env("ROWSAFE_POOLER_USERLIST", "/etc/pgbouncer/userlist.txt"),
		StatsURL:  env("ROWSAFE_POOLER_STATS_URL", ""),
		Database:  env("ROWSAFE_POOLER_DATABASE", ""),
	}
	p := c.Pooler
	for _, path := range []string{p.AllowFile, p.Dir, p.ResultDir, p.SocketDir, p.Userlist} {
		if !filepath.IsAbs(path) {
			return fmt.Errorf("directory %q must be absolute", path)
		}
	}
	if p.StatsURL != "" && !strings.HasPrefix(p.StatsURL, "postgres://") && !strings.HasPrefix(p.StatsURL, "postgresql://") {
		return fmt.Errorf("ROWSAFE_POOLER_STATS_URL must be a postgres:// URL")
	}
	return nil
}

// poolerRole is PgBouncer's lookup role in PostgreSQL.
const poolerRole = "rowsafe_pgbouncer"

// Timings (variables for tests).
var (
	poolerInstallTimeout = 25 * time.Minute // installing or removing the package
	poolerHelperTimeout  = 3 * time.Minute  // writing the config, (re)starting
	poolerPauseTimeout   = 15 * time.Second // waiting for transactions to finish before a switch
	poolerTargetWait     = 45 * time.Second // the new primary answering and out of recovery
	poolerPoll           = 250 * time.Millisecond
)

// poolerState is what the agent set up, kept in <state dir>/pooling.json.
type poolerState struct {
	DatabaseID   string                   `json:"database_id"`
	DatabaseName string                   `json:"database_name"`
	DBPort       int                      `json:"db_port"` // the local cluster it was turned on for
	Settings     protocol.PoolingSettings `json:"settings"`
	Addresses    []string                 `json:"addresses"`
	TargetHost   string                   `json:"target_host"`
	TargetPort   int                      `json:"target_port"`
	Version      string                   `json:"version"`
	AuthDB       string                   `json:"auth_db,omitempty"` // "" : the lookup function is in every database
	Prepared     int                      `json:"prepared,omitempty"`
	// MaxDBConn caps PgBouncer's server connections (max_db_connections).
	MaxDBConn int `json:"max_db_conn"`
	// Databases where the lookup function was created (AuthDB "").
	FunctionDBs []string  `json:"function_dbs,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (s *poolerState) target() string {
	return net.JoinHostPort(s.TargetHost, strconv.Itoa(s.TargetPort))
}

func (a *Agent) poolerStatePath() string { return filepath.Join(a.cfg.StateDir, "pooling.json") }

func (a *Agent) loadPoolerState() (*poolerState, error) {
	data, err := os.ReadFile(a.poolerStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st poolerState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.poolerStatePath(), err)
	}
	return &st, nil
}

func (a *Agent) savePoolerState(st *poolerState) error {
	st.UpdatedAt = time.Now().UTC()
	data, _ := json.MarshalIndent(st, "", "  ")
	return writeFileAtomic(a.poolerStatePath(), data, 0o600)
}

// ReadPoolerAllowed reads the ports root allowed PgBouncer in front of. A
// missing file means pooling from Rowsafe is off.
func ReadPoolerAllowed(path string) (map[int]bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[int]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		if p, err := strconv.Atoi(fields[0]); err == nil && p >= 1 && p <= 65535 {
			out[p] = true
		}
	}
	return out, sc.Err()
}

// ---- the root helper ----

var poolerValueRE = regexp.MustCompile(`^[A-Za-z0-9.:,*_-]{0,300}$`)

// askPooler hands one request to the helper in PgBouncer mode and waits for
// its answer.
func (a *Agent) askPooler(ctx context.Context, action string, kv [][2]string, id string, timeout time.Duration) (map[string]string, error) {
	host, _ := os.Hostname()
	if st, err := os.Stat(a.cfg.Pooler.Dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("the PgBouncer helper is not set up on %s (%s is missing): run the Rowsafe installer there again with --allow-pooler", host, a.cfg.Pooler.Dir)
	}
	if !restartIDRE.MatchString(id) {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id = hex.EncodeToString(b)
	}
	var sb strings.Builder
	sb.WriteString(id + " pooler-" + action)
	for _, p := range kv {
		if !poolerValueRE.MatchString(p[1]) {
			return nil, fmt.Errorf("invalid value for %s", p[0])
		}
		sb.WriteString(" " + p[0] + "=" + p[1])
	}
	sb.WriteByte('\n')
	request := filepath.Join(a.cfg.Pooler.Dir, "request")
	if err := writeFileAtomic(request, []byte(sb.String()), 0o600); err != nil {
		return nil, err
	}
	res, err := waitHelperResult(ctx, filepath.Join(a.cfg.Pooler.ResultDir, "result"), id, timeout)
	if err != nil {
		_ = os.Remove(request)
		if errors.Is(err, errRestartNoAnswer) {
			return nil, fmt.Errorf("the PgBouncer helper on %s did not answer within %s; check `systemctl status rowsafe-pooler.path rowsafe-pooler.service`", host, timeout)
		}
		return nil, err
	}
	if res["ok"] != "1" {
		msg := res["error"]
		if msg == "" {
			msg = "unknown error"
		}
		return res, errors.New(msg)
	}
	return res, nil
}

// waitHelperResult waits for the helper's answer to request id.
func waitHelperResult(ctx context.Context, path, id string, timeout time.Duration) (map[string]string, error) {
	deadline := time.Now().Add(timeout)
	for {
		if data, err := os.ReadFile(path); err == nil {
			if res := parseKeyValues(string(data)); res["id"] == id {
				return res, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, errRestartNoAnswer
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poolerPoll):
		}
	}
}

// ---- settings ----

// PoolingDefaults are the settings Rowsafe picks (protocol.DefaultPoolingSettings).
func PoolingDefaults(cores, maxConnections, reserved int) protocol.PoolingSettings {
	return protocol.DefaultPoolingSettings(cores, maxConnections, reserved)
}

func headroom(maxConnections, reserved int) int {
	return protocol.PoolHeadroom(maxConnections, reserved)
}

// fillSettings completes settings with defaults and checks them.
func fillSettings(s, def protocol.PoolingSettings, maxConnections, reserved int) (protocol.PoolingSettings, error) {
	if s.Mode == "" {
		s.Mode = def.Mode
	}
	if s.Mode != protocol.PoolModeTransaction && s.Mode != protocol.PoolModeSession {
		return s, fmt.Errorf("pool mode must be %q or %q", protocol.PoolModeTransaction, protocol.PoolModeSession)
	}
	if s.PoolSize == 0 {
		s.PoolSize = def.PoolSize
	}
	if room := headroom(maxConnections, reserved); s.PoolSize < 1 || s.PoolSize > room {
		return s, fmt.Errorf("the pool size must be between 1 and %d: PostgreSQL allows %d connections (max_connections), and Rowsafe keeps some free for itself, admins and replication", room, maxConnections)
	}
	if s.MaxClientConn == 0 {
		s.MaxClientConn = def.MaxClientConn
	}
	if s.MaxClientConn < 10 || s.MaxClientConn > 100000 {
		return s, fmt.Errorf("max_client_conn must be between 10 and 100000")
	}
	if s.Listen == "" {
		s.Listen = def.Listen
	}
	switch s.Listen {
	case protocol.PoolerListenLocal, protocol.PoolerListenPrivate, protocol.PoolerListenPublic:
	default:
		return s, fmt.Errorf("listen must be local, private or public")
	}
	if s.Port == 0 {
		s.Port = def.Port
	}
	if s.Port < 1024 || s.Port > 65535 {
		return s, fmt.Errorf("the pooler's port must be between 1024 and 65535")
	}
	return s, nil
}

// interfaceAddrs is the host's addresses (a variable for tests).
var interfaceAddrs = net.InterfaceAddrs

var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// listenAddresses turns a listen choice into PgBouncer's listen_addr.
func listenAddresses(listen string) ([]string, error) {
	switch listen {
	case protocol.PoolerListenPublic:
		return []string{"*"}, nil
	case protocol.PoolerListenLocal:
		return []string{"127.0.0.1"}, nil
	}
	out := []string{"127.0.0.1"}
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, fmt.Errorf("listing this server's network addresses: %w", err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipn.IP.IsPrivate() || cgnat.Contains(ipn.IP) {
			if s := ipn.IP.String(); !slices.Contains(out, s) && len(out) < 16 {
				out = append(out, s)
			}
		}
	}
	return out, nil
}

// ---- PostgreSQL side ----

// clusterFacts is what turning pooling on needs to know about PostgreSQL.
type clusterFacts struct {
	maxConnections, reserved int
	inRecovery               bool
	md5Roles                 []string
	databases                []string // connectable, template1 included
}

func readClusterFacts(ctx context.Context, conn *pgx.Conn) (clusterFacts, error) {
	var f clusterFacts
	err := conn.QueryRow(ctx, `
		SELECT current_setting('max_connections')::int,
		       current_setting('superuser_reserved_connections')::int + coalesce(nullif(current_setting('reserved_connections', true), ''), '0')::int,
		       pg_is_in_recovery()`).Scan(&f.maxConnections, &f.reserved, &f.inRecovery)
	if err != nil {
		return f, err
	}
	rows, err := conn.Query(ctx, `SELECT rolname FROM pg_catalog.pg_authid
		WHERE rolcanlogin AND NOT rolsuper AND rolpassword LIKE 'md5%' ORDER BY 1 LIMIT 20`)
	if err != nil {
		return f, err
	}
	if f.md5Roles, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return f, err
	}
	rows, err = conn.Query(ctx, `SELECT datname FROM pg_catalog.pg_database WHERE datallowconn ORDER BY 1`)
	if err != nil {
		return f, err
	}
	f.databases, err = pgx.CollectRows(rows, pgx.RowTo[string])
	return f, err
}

// lookupFunctionSQL creates the function PgBouncer's auth_query calls. It
// runs as the superuser the agent connects as (SECURITY DEFINER: only it
// can read pg_authid), returns nothing for superusers and expired
// passwords, and only rowsafe_pgbouncer may call it.
var lookupFunctionSQL = []string{
	`CREATE SCHEMA IF NOT EXISTS rowsafe_pgbouncer`,
	`REVOKE ALL ON SCHEMA rowsafe_pgbouncer FROM PUBLIC`,
	`GRANT USAGE ON SCHEMA rowsafe_pgbouncer TO rowsafe_pgbouncer`,
	`CREATE OR REPLACE FUNCTION rowsafe_pgbouncer.user_lookup(i_username text, OUT uname text, OUT phash text)
RETURNS record LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
  SELECT rolname, CASE WHEN rolvaliduntil IS NULL OR rolvaliduntil > now() THEN rolpassword END
    INTO uname, phash
    FROM pg_catalog.pg_authid
   WHERE rolname = i_username AND rolcanlogin AND NOT rolsuper;
  RETURN;
END
$f$`,
	`COMMENT ON FUNCTION rowsafe_pgbouncer.user_lookup(text) IS 'Rowsafe: password lookup for PgBouncer (auth_query); removed when pooling is turned off'`,
	`REVOKE ALL ON FUNCTION rowsafe_pgbouncer.user_lookup(text) FROM PUBLIC`,
	`GRANT EXECUTE ON FUNCTION rowsafe_pgbouncer.user_lookup(text) TO rowsafe_pgbouncer`,
}

var scramVerifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+$`)

// ensureLookupRole creates or updates rowsafe_pgbouncer (with verifier as
// its password when set) and the lookup function in dbs.
func ensureLookupRole(ctx context.Context, connect func(context.Context, string) (*pgx.Conn, error), verifier string, dbs []string) error {
	conn, err := connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, `DO $$ BEGIN
		IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'rowsafe_pgbouncer') THEN
			CREATE ROLE rowsafe_pgbouncer LOGIN;
		END IF;
	END $$`); err != nil {
		return fmt.Errorf("creating the role %s: %w", poolerRole, err)
	}
	alter := `ALTER ROLE rowsafe_pgbouncer WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20`
	if verifier != "" {
		if !scramVerifierRE.MatchString(verifier) {
			return errors.New("invalid SCRAM verifier")
		}
		alter += ` PASSWORD '` + verifier + `'`
	}
	if _, err := conn.Exec(ctx, alter); err != nil {
		return fmt.Errorf("setting up the role %s: %w", poolerRole, err)
	}
	for _, db := range dbs {
		c := conn
		if db != "postgres" {
			if c, err = connect(ctx, db); err != nil {
				return fmt.Errorf("connecting to database %s: %w", db, err)
			}
		}
		for _, stmt := range lookupFunctionSQL {
			if _, err = c.Exec(ctx, stmt); err != nil {
				err = fmt.Errorf("creating PgBouncer's lookup function in database %s: %w", db, err)
				break
			}
		}
		if c != conn {
			c.Close(context.WithoutCancel(ctx))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// dropLookupRole removes the lookup function from dbs and the role.
func dropLookupRole(ctx context.Context, connect func(context.Context, string) (*pgx.Conn, error), dbs []string) error {
	for _, db := range dbs {
		c, err := connect(ctx, db)
		if err != nil {
			continue // a database dropped since
		}
		_, err = c.Exec(ctx, `DROP SCHEMA IF EXISTS rowsafe_pgbouncer CASCADE`)
		c.Close(context.WithoutCancel(ctx))
		if err != nil {
			return fmt.Errorf("removing PgBouncer's lookup function from database %s: %w", db, err)
		}
	}
	conn, err := connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, `DROP ROLE IF EXISTS rowsafe_pgbouncer`); err != nil {
		return fmt.Errorf("removing the role %s: %w", poolerRole, err)
	}
	return nil
}

// tcpConnect logs in as rowsafe_pgbouncer over TCP, like PgBouncer does.
func tcpConnect(ctx context.Context, host string, port int, password, db string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database = host, uint16(port), poolerRole, password, db
	cfg.ConnectTimeout = 5 * time.Second
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol // also through PgBouncer in transaction mode
	cfg.RuntimeParams["application_name"] = "rowsafe-agent"
	return pgx.ConnectConfig(ctx, cfg)
}

// checkTarget checks that PgBouncer can log in to host:port as
// rowsafe_pgbouncer and look a password up there; it reports whether that
// server is a standby.
func checkTarget(ctx context.Context, host string, port int, password, authDB string) (inRecovery bool, err error) {
	db := authDB
	if db == "" {
		db = "postgres"
	}
	conn, err := tcpConnect(ctx, host, port, password, db)
	if err != nil {
		return false, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var who string
	if err := conn.QueryRow(ctx, `SELECT coalesce(uname, '') FROM rowsafe_pgbouncer.user_lookup(current_user)`).Scan(&who); err != nil {
		return false, fmt.Errorf("PgBouncer's lookup function doesn't work there: %w", err)
	}
	err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery)
	return inRecovery, err
}

// hbaHint explains a refused password login from PgBouncer.
func hbaHint(err error, host string, port int) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "pg_hba.conf"):
		return fmt.Sprintf("PostgreSQL refuses password logins from PgBouncer (%s): add a line such as `host all all 127.0.0.1/32 scram-sha-256` to pg_hba.conf and reload PostgreSQL", msg)
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "dial"):
		return fmt.Sprintf("PostgreSQL doesn't accept TCP connections on %s (check listen_addresses): %s", net.JoinHostPort(host, strconv.Itoa(port)), msg)
	}
	return msg
}

// ---- passwords ----

func randomPassword() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// readUserlistPassword reads rowsafe_pgbouncer's password from PgBouncer's
// auth file.
func readUserlistPassword(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading PgBouncer's user list: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == `"`+poolerRole+`"` {
			return strings.Trim(f[1], `"`), nil
		}
	}
	return "", fmt.Errorf("%s has no password for %s", path, poolerRole)
}

// ---- tasks ----

// poolerMu serializes pooling tasks: there is one PgBouncer per server.
var poolerMu sync.Mutex

func (a *Agent) connectAs(db protocol.DatabaseSpec) func(context.Context, string) (*pgx.Conn, error) {
	return func(ctx context.Context, name string) (*pgx.Conn, error) { return a.target(db).Connect(ctx, name) }
}

// pooling runs a pooling task.
func (a *Agent) pooling(ctx context.Context, db protocol.DatabaseSpec, p protocol.PoolingParams, taskID string, tl *taskLog) (*protocol.PoolingResult, error) {
	if a.cfg.Sidecar() {
		return nil, errors.New("Rowsafe doesn't install PgBouncer next to PostgreSQL in Docker: run the official PgBouncer image as another service in your compose file, and set ROWSAFE_POOLER_STATS_URL for Rowsafe to monitor it (see https://rowsafe.sh/docs/guides/connection-pooling)")
	}
	poolerMu.Lock()
	defer poolerMu.Unlock()
	start := time.Now()
	var res *protocol.PoolingResult
	var err error
	switch p.Action {
	case protocol.PoolingOn:
		res, err = a.poolingOn(ctx, db, p.Settings, taskID, tl)
	case protocol.PoolingOff:
		res, err = a.poolingOff(ctx, db, taskID, tl)
	default:
		return nil, fmt.Errorf("unknown pooling action %q", p.Action)
	}
	if res != nil {
		res.DurationMs = time.Since(start).Milliseconds()
	}
	return res, err
}

func (a *Agent) poolingOn(ctx context.Context, db protocol.DatabaseSpec, want protocol.PoolingSettings, taskID string, tl *taskLog) (*protocol.PoolingResult, error) {
	host, _ := os.Hostname()
	allowed, err := ReadPoolerAllowed(a.cfg.Pooler.AllowFile)
	if err != nil {
		return nil, err
	}
	if !allowed[db.Port] {
		return nil, fmt.Errorf("installing and managing PgBouncer from Rowsafe isn't allowed for port %d on %s: run the Rowsafe installer there again with --allow-pooler", db.Port, host)
	}
	st, err := a.loadPoolerState()
	if err != nil {
		return nil, err
	}
	if st != nil && st.DatabaseID != db.ID {
		return nil, fmt.Errorf("PgBouncer on %s already pools %s; Rowsafe manages one pooler per server. Turn pooling off for %s first", host, st.DatabaseName, st.DatabaseName)
	}
	fresh := st == nil

	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, err
	}
	facts, err := readClusterFacts(ctx, conn)
	conn.Close(context.WithoutCancel(ctx))
	if err != nil {
		return nil, fmt.Errorf("reading PostgreSQL's settings: %w", err)
	}
	if facts.inRecovery && fresh {
		return nil, errors.New("this PostgreSQL is a standby: turn pooling on for the primary (the role PgBouncer uses is created there and replicated)")
	}
	settings, err := fillSettings(want, PoolingDefaults(numCPU(), facts.maxConnections, facts.reserved), facts.maxConnections, facts.reserved)
	if err != nil {
		return nil, err
	}
	addrs, err := listenAddresses(settings.Listen)
	if err != nil {
		return nil, err
	}

	tl.Printf("asking the root helper to install PgBouncer if needed")
	res := &protocol.PoolingResult{Action: protocol.PoolingOn, Settings: settings, Addresses: addrs}
	ans, err := a.askPooler(ctx, "install", nil, taskID, poolerInstallTimeout)
	if err != nil {
		return res, fmt.Errorf("installing PgBouncer: %w", err)
	}
	res.Version, res.Installed = ans["version"], ans["installed"] == "1"
	if res.Installed {
		tl.Printf("installed the pgbouncer package (PgBouncer %s)", res.Version)
	} else {
		tl.Printf("PgBouncer %s is installed", res.Version)
	}
	if !pgbouncer.AtLeast(res.Version, 1, 14) {
		return res, fmt.Errorf("PgBouncer %s is too old: Rowsafe needs 1.14 or newer (SCRAM passwords); install a newer pgbouncer package, e.g. from apt.postgresql.org", res.Version)
	}

	next := poolerState{DatabaseID: db.ID, DatabaseName: db.Name, DBPort: db.Port, Settings: settings, Addresses: addrs,
		TargetHost: "127.0.0.1", TargetPort: db.Port, Version: res.Version}
	if !fresh {
		next.TargetHost, next.TargetPort, next.FunctionDBs = st.TargetHost, st.TargetPort, st.FunctionDBs
	}
	// PgBouncer 1.20+ runs auth_query in one database; older ones in the
	// database the client asked for, which then needs the function too.
	dbs := []string{"postgres"}
	if pgbouncer.AtLeast(res.Version, 1, 20) {
		next.AuthDB = "postgres"
	} else {
		dbs = facts.databases
		next.FunctionDBs = dbs
		res.Warnings = append(res.Warnings, fmt.Sprintf("PgBouncer %s looks passwords up in the database each client connects to, so Rowsafe added its lookup function to every database. Databases created later need pooling turned on again (Change settings) to be reachable through PgBouncer; PgBouncer 1.20 or newer doesn't have this limit.", res.Version))
	}
	if settings.Mode == protocol.PoolModeTransaction && pgbouncer.AtLeast(res.Version, 1, 21) {
		next.Prepared = 200 // drivers' protocol-level prepared statements work in transaction mode
	}

	// The lookup role: a new random password on the first turn-on.
	password := ""
	verifier := ""
	if !fresh {
		password, err = readUserlistPassword(a.cfg.Pooler.Userlist)
	}
	if fresh || err != nil {
		password = randomPassword()
		if verifier, err = scramVerifier(password); err != nil {
			return res, err
		}
	}
	if facts.inRecovery {
		tl.Printf("PostgreSQL is a standby: using the replicated role %s", poolerRole)
	} else {
		tl.Printf("setting up the role %s and its lookup function (%s)", poolerRole, strings.Join(dbs, ", "))
		if err := ensureLookupRole(ctx, a.connectAs(db), verifier, dbs); err != nil {
			return res, err
		}
	}
	tl.Printf("checking that PgBouncer can log in to PostgreSQL at %s", next.target())
	if _, err := checkTarget(ctx, next.TargetHost, next.TargetPort, password, next.AuthDB); err != nil {
		return res, errors.New(hbaHint(err, next.TargetHost, next.TargetPort))
	}

	next.MaxDBConn = max(headroom(facts.maxConnections, facts.reserved)*3/4, settings.PoolSize)
	restart := fresh || st.Settings.Port != settings.Port || !slices.Equal(st.Addresses, addrs)
	kv := a.configureArgs(next, restart)
	if verifier != "" {
		kv = append(kv, [2]string{"password", password})
	}
	tl.Printf("asking the root helper to write PgBouncer's configuration (%s mode, %d connections per pool, listening on %s port %d)",
		settings.Mode, settings.PoolSize, strings.Join(addrs, ", "), settings.Port)
	if _, err := a.askPooler(ctx, "configure", kv, taskID, poolerHelperTimeout); err != nil {
		return res, fmt.Errorf("configuring PgBouncer: %w", err)
	}
	if err := a.savePoolerState(&next); err != nil {
		return res, err
	}
	if !restart {
		if err := a.reloadPooler(ctx, next, password, taskID, tl); err != nil {
			return res, err
		}
	}
	if err := a.verifyPooler(ctx, next, password); err != nil {
		return res, fmt.Errorf("PgBouncer is configured, but a test connection through it failed: %w", err)
	}
	tl.Printf("a test connection through PgBouncer on port %d works", settings.Port)
	if len(facts.md5Roles) > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("These roles have old md5 passwords and can't log in through PgBouncer until their password is set again (with password_encryption = scram-sha-256): %s.", strings.Join(facts.md5Roles, ", ")))
	}
	if settings.Mode == protocol.PoolModeTransaction {
		note := "Transaction mode: session state doesn't carry over between transactions (SET, LISTEN/NOTIFY, advisory locks, SQL PREPARE, temporary tables)."
		if next.Prepared > 0 {
			note += " Prepared statements made by drivers work."
		} else {
			note += " Turn off prepared statements in your driver, or use session mode."
		}
		res.Warnings = append(res.Warnings, note)
	}
	res.On, res.Target, res.Version = true, next.target(), next.Version
	res.Summary = fmt.Sprintf("Pooling is on: PgBouncer %s listens on %s, port %d, in %s mode, with up to %d server connections per pool.",
		next.Version, listenWords(addrs), settings.Port, settings.Mode, settings.PoolSize)
	tl.Printf("%s", res.Summary)
	return res, nil
}

func listenWords(addrs []string) string {
	if slices.Contains(addrs, "*") {
		return "every address"
	}
	return strings.Join(addrs, ", ")
}

// configureArgs are the helper's configure parameters.
func (a *Agent) configureArgs(st poolerState, restart bool) [][2]string {
	s, maxDB := st.Settings, st.MaxDBConn
	kv := [][2]string{
		{"dbport", strconv.Itoa(st.DBPort)},
		{"listen", strings.Join(st.Addresses, ",")},
		{"port", strconv.Itoa(s.Port)},
		{"mode", s.Mode},
		{"pool_size", strconv.Itoa(s.PoolSize)},
		{"reserve_pool", strconv.Itoa(max(s.PoolSize/4, 1))},
		{"max_db_conn", strconv.Itoa(maxDB)},
		{"max_client_conn", strconv.Itoa(s.MaxClientConn)},
		{"prepared", strconv.Itoa(st.Prepared)},
		{"target_host", st.TargetHost},
		{"target_port", strconv.Itoa(st.TargetPort)},
		{"restart", map[bool]string{true: "1", false: "0"}[restart]},
	}
	if st.AuthDB != "" {
		kv = append(kv, [2]string{"auth_dbname", st.AuthDB})
	}
	return kv
}

// adminTarget is PgBouncer's admin console for the agent.
func (a *Agent) adminTarget(st poolerState, password string) pgbouncer.Target {
	return pgbouncer.Target{Host: a.cfg.Pooler.SocketDir, Port: st.Settings.Port, User: poolerRole, Password: password}
}

// reloadPooler makes PgBouncer read its configuration again: RELOAD on the
// admin console, or the helper's systemctl reload.
func (a *Agent) reloadPooler(ctx context.Context, st poolerState, password, taskID string, tl *taskLog) error {
	conn, err := a.adminTarget(st, password).Connect(ctx)
	if err == nil {
		err = pgbouncer.Command(ctx, conn, "RELOAD")
		conn.Close(context.WithoutCancel(ctx))
		if err == nil {
			tl.Printf("PgBouncer reloaded its configuration")
			return nil
		}
	}
	tl.Printf("the admin console didn't take RELOAD (%v); asking the helper to reload PgBouncer", err)
	if _, err := a.askPooler(ctx, "reload", nil, taskID+"-reload", poolerHelperTimeout); err != nil {
		return fmt.Errorf("reloading PgBouncer: %w", err)
	}
	return nil
}

// verifyPooler connects through PgBouncer, retrying while it starts.
func (a *Agent) verifyPooler(ctx context.Context, st poolerState, password string) error {
	host := "127.0.0.1"
	if !slices.Contains(st.Addresses, "*") && !slices.Contains(st.Addresses, host) && len(st.Addresses) > 0 {
		host = st.Addresses[0]
	}
	db := st.AuthDB
	if db == "" {
		db = "postgres"
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		conn, err := tcpConnect(ctx, host, st.Settings.Port, password, db)
		if err == nil {
			var one int
			err = conn.QueryRow(ctx, `SELECT 1`).Scan(&one)
			conn.Close(context.WithoutCancel(ctx))
			if err == nil {
				return nil
			}
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

func (a *Agent) poolingOff(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.PoolingResult, error) {
	st, err := a.loadPoolerState()
	if err != nil {
		return nil, err
	}
	if st != nil && st.DatabaseID != db.ID {
		return nil, fmt.Errorf("PgBouncer on this server pools %s, not %s", st.DatabaseName, db.Name)
	}
	res := &protocol.PoolingResult{Action: protocol.PoolingOff}
	tl.Printf("asking the root helper to stop PgBouncer and put its own configuration back")
	ans, err := a.askPooler(ctx, "off", [][2]string{{"remove_package", "1"}}, taskID, poolerInstallTimeout)
	if err != nil {
		return res, fmt.Errorf("turning PgBouncer off: %w", err)
	}
	res.Removed = ans["removed"] == "1"
	if res.Removed {
		tl.Printf("removed the pgbouncer package Rowsafe had installed")
	}
	dbs := []string{"postgres"}
	if st != nil && len(st.FunctionDBs) > 0 {
		dbs = st.FunctionDBs
	}
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return res, err
	}
	var inRecovery bool
	err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery)
	conn.Close(context.WithoutCancel(ctx))
	if err != nil {
		return res, err
	}
	if !inRecovery {
		tl.Printf("removing the role %s and its lookup function", poolerRole)
		if err := dropLookupRole(ctx, a.connectAs(db), dbs); err != nil {
			return res, err
		}
	}
	if err := os.Remove(a.poolerStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return res, err
	}
	res.Summary = "Pooling is off: PgBouncer is stopped"
	if res.Removed {
		res.Summary += " and removed"
	}
	res.Summary += ". Apps must connect to PostgreSQL directly again."
	tl.Printf("%s", res.Summary)
	return res, nil
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// poolerRetarget points PgBouncer at another PostgreSQL server: the new
// configuration is written first, then PgBouncer is paused (clients wait,
// transactions in progress finish), reloaded and resumed.
func (a *Agent) poolerRetarget(ctx context.Context, db protocol.DatabaseSpec, p protocol.PoolerRetargetParams, taskID string, tl *taskLog) (*protocol.PoolerRetargetResult, error) {
	start := time.Now()
	if net.ParseIP(p.Host) == nil && !hostnameRE.MatchString(p.Host) {
		return nil, fmt.Errorf("invalid host %q", p.Host)
	}
	if p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", p.Port)
	}
	poolerMu.Lock()
	defer poolerMu.Unlock()
	st, err := a.loadPoolerState()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	if st == nil || st.DatabaseID != db.ID {
		return nil, fmt.Errorf("pooling isn't on for %s on %s", db.Name, host)
	}
	password, err := readUserlistPassword(a.cfg.Pooler.Userlist)
	if err != nil {
		return nil, err
	}
	next := *st
	next.TargetHost, next.TargetPort = p.Host, p.Port
	res := &protocol.PoolerRetargetResult{From: st.target(), To: next.target()}

	// The new primary may still be finishing its promotion.
	tl.Printf("checking that PgBouncer can log in to %s", res.To)
	deadline := time.Now().Add(poolerTargetWait)
	for {
		standby, err := checkTarget(ctx, p.Host, p.Port, password, st.AuthDB)
		if err == nil && !standby {
			break
		}
		if err == nil {
			err = errors.New("it is still a standby (in recovery)")
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return res, fmt.Errorf("PgBouncer still sends connections to %s: %s: %s", res.From, res.To, hbaHint(err, p.Host, p.Port))
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}

	tl.Printf("asking the root helper to point PgBouncer at %s", res.To)
	if _, err := a.askPooler(ctx, "configure", a.configureArgs(next, false), taskID, poolerHelperTimeout); err != nil {
		return res, fmt.Errorf("configuring PgBouncer: %w", err)
	}

	admin, err := a.adminTarget(next, password).Connect(ctx)
	if err != nil {
		tl.Printf("PgBouncer's admin console doesn't answer (%v): reloading without a pause", err)
		if err := a.reloadPooler(ctx, next, password, taskID, tl); err != nil {
			return res, err
		}
	} else {
		defer func() { admin.Close(context.WithoutCancel(ctx)) }()
		paused := time.Now()
		pctx, cancel := context.WithTimeout(ctx, poolerPauseTimeout)
		err := pgbouncer.Command(pctx, admin, "PAUSE")
		cancel()
		if err == nil {
			res.Paused = true
			tl.Printf("PgBouncer paused: clients wait for the switch")
		} else {
			tl.Printf("PgBouncer could not pause within %s (%v): switching without a pause", poolerPauseTimeout, err)
			admin.Close(context.WithoutCancel(ctx))
			if admin, err = a.adminTarget(next, password).Connect(ctx); err != nil {
				return res, fmt.Errorf("reconnecting to PgBouncer's admin console: %w", err)
			}
		}
		if err := pgbouncer.Command(ctx, admin, "RELOAD"); err != nil {
			_ = pgbouncer.Command(ctx, admin, "RESUME")
			return res, fmt.Errorf("reloading PgBouncer: %w", err)
		}
		if !res.Paused {
			// Close what still goes to the old server.
			_ = pgbouncer.Command(ctx, admin, "RECONNECT")
		}
		if err := pgbouncer.Command(ctx, admin, "RESUME"); err != nil && res.Paused {
			return res, fmt.Errorf("resuming PgBouncer: %w", err)
		}
		if res.Paused {
			res.PausedMs = time.Since(paused).Milliseconds()
			tl.Printf("PgBouncer resumed after %d ms", res.PausedMs)
		}
	}
	if err := a.savePoolerState(&next); err != nil {
		return res, err
	}
	if err := a.verifyPooler(ctx, next, password); err != nil {
		return res, fmt.Errorf("PgBouncer now points at %s, but a test connection through it failed: %w", res.To, err)
	}
	res.Summary = fmt.Sprintf("PgBouncer now sends connections to %s (was %s).", res.To, res.From)
	if res.Paused {
		res.Summary += fmt.Sprintf(" Clients waited %d ms; none got an error.", res.PausedMs)
	} else {
		res.Summary += " PgBouncer couldn't pause in time, so transactions open on the old server were ended."
	}
	res.DurationMs = time.Since(start).Milliseconds()
	tl.Printf("%s", res.Summary)
	return res, nil
}

// ---- heartbeat and monitoring ----

// poolerStatus is PgBouncer's state for the heartbeat.
func (a *Agent) poolerStatus(ctx context.Context) *protocol.PoolerStatus {
	out := &protocol.PoolerStatus{}
	if a.cfg.Pooler.StatsURL != "" {
		out.External = true
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		conn, err := pgbouncer.Target{URL: a.cfg.Pooler.StatsURL}.Connect(ctx)
		if err != nil {
			out.Error = redactErr(err, a.cfg.Pooler.StatsURL)
			return out
		}
		defer conn.Close(context.WithoutCancel(ctx))
		out.Version, err = pgbouncer.Version(ctx, conn)
		out.Running = err == nil
		return out
	}
	if a.cfg.Sidecar() {
		return nil
	}
	if allowed, err := ReadPoolerAllowed(a.cfg.Pooler.AllowFile); err == nil && len(allowed) > 0 {
		for p := range allowed {
			out.AllowedPorts = append(out.AllowedPorts, p)
		}
		slices.Sort(out.AllowedPorts)
		out.Allowed = true
	}
	st, err := a.loadPoolerState()
	if err != nil || st == nil {
		if err != nil {
			out.Error = err.Error()
		}
		return out // not managed; Allowed says whether it may be
	}
	out.Managed, out.DatabaseID, out.Settings, out.Addresses, out.Target, out.Version = true, st.DatabaseID, st.Settings, st.Addresses, st.target(), st.Version
	password, err := readUserlistPassword(a.cfg.Pooler.Userlist)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := a.adminTarget(*st, password).Connect(ctx)
	if err != nil {
		out.Error = "PgBouncer doesn't answer: " + err.Error()
		return out
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if v, err := pgbouncer.Version(ctx, conn); err == nil {
		out.Running, out.Version = true, v
	} else {
		out.Error = err.Error()
	}
	return out
}

func redactErr(err error, url string) string {
	return strings.ReplaceAll(err.Error(), url, pgbouncer.Redact(url))
}

// poolerSources are the PgBouncer admin consoles monitoring reads.
func (a *Agent) poolerSources() []collect.PoolerSource {
	if url := a.cfg.Pooler.StatsURL; url != "" {
		dbs := a.monitoredDatabases()
		for _, db := range dbs {
			if db.Name == a.cfg.Pooler.Database || a.cfg.Pooler.Database == "" && len(dbs) == 1 {
				return []collect.PoolerSource{{DatabaseID: db.ID, Target: pgbouncer.Target{URL: url}}}
			}
		}
		return nil
	}
	st, err := a.loadPoolerState()
	if err != nil || st == nil {
		return nil
	}
	password, err := readUserlistPassword(a.cfg.Pooler.Userlist)
	if err != nil {
		return nil
	}
	return []collect.PoolerSource{{DatabaseID: st.DatabaseID, Target: a.adminTarget(*st, password)}}
}
