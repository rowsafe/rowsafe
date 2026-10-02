package mysql

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"net"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/proxysqlroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// Connection pooling for MySQL and MariaDB: ProxySQL in front of the
// server, installed and configured by root's helper (internal/
// proxysqlroot) where root allowed pooling for the port. Apps log in with
// their own users: the agent reads their password hashes from mysql.user
// and hands them to root's helper, on this server only, when pooling is
// turned on and whenever the users change.

// proxysqlDefaultPort is where apps connect to ProxySQL.
const proxysqlDefaultPort = protocol.DefaultProxySQLPort

var proxysqlResultDir = envOr("ROWSAFE_PROXYSQL_RESULT_DIR", proxysqlroot.DefaultAnswerDir)

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// poolState is what the agent set up (<engine state>/proxysql.json).
type poolState struct {
	DatabaseID string                   `json:"database_id"`
	Settings   protocol.PoolingSettings `json:"settings"`
	Addresses  []string                 `json:"addresses"`
	Target     string                   `json:"target"`
	TargetPort int                      `json:"target_port"`
	// TargetHost is another server's address after a standby's promotion
	// ("" for this server).
	TargetHost string `json:"target_host,omitempty"`
	Version    string                   `json:"version"`
	Users      string                   `json:"users"` // fingerprint of the users handed over
}

func (s *server) poolStatePath() string { return filepath.Join(s.env.StateDir, "proxysql.json") }

func (s *server) loadPoolState() *poolState {
	data, err := os.ReadFile(s.poolStatePath())
	if err != nil {
		return nil
	}
	var st poolState
	if json.Unmarshal(data, &st) != nil || st.DatabaseID != s.db.ID {
		return nil
	}
	return &st
}

func (s *server) savePoolState(st *poolState) error {
	if err := os.MkdirAll(s.env.StateDir, 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(st, "", "  ")
	return writeFileAtomic(s.poolStatePath(), data, 0o600)
}

// askProxySQL hands a request to root's helper and waits for its answer.
func (s *server) askProxySQL(ctx context.Context, r proxysqlroot.Request, log agent.TaskLogger) (proxysqlroot.Result, error) {
	pc := agent.PoolerConfigOf(s.env.Config)
	if st, err := os.Stat(pc.Dir); err != nil || !st.IsDir() {
		return proxysqlroot.Result{}, fmt.Errorf("the pooling helper is not set up on this server: root allows it with %s", agent.AllowHint(protocol.PermPooler))
	}
	var id [6]byte
	_, _ = rand.Read(id[:])
	r.ID, r.Flavor = hex.EncodeToString(id[:]), string(s.flavor)
	data, _ := json.Marshal(r)
	req := filepath.Join(pc.Dir, proxysqlroot.RequestName)
	if err := writeFileAtomic(req, data, 0o600); err != nil {
		return proxysqlroot.Result{}, err
	}
	if log != nil {
		log.Printf("asking root's pooling helper to %s ProxySQL", map[string]string{proxysqlroot.ActionOn: "set up", proxysqlroot.ActionOff: "turn off",
			proxysqlroot.ActionUsers: "update the users of", proxysqlroot.ActionRetarget: "point"}[r.Action])
	}
	deadline := time.Now().Add(12 * time.Minute)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(filepath.Join(proxysqlResultDir, proxysqlroot.ResultName)); err == nil {
			var res proxysqlroot.Result
			if json.Unmarshal(b, &res) == nil && res.ID == r.ID {
				if !res.OK {
					return res, errors.New(res.Error)
				}
				return res, nil
			}
		}
		select {
		case <-ctx.Done():
			return proxysqlroot.Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	_ = os.Remove(req)
	return proxysqlroot.Result{}, errors.New("the pooling helper did not answer; check `systemctl status rowsafe-proxysql.path rowsafe-proxysql.service`")
}

// poolUsers lists the users ProxySQL lets in: those that may log in from
// this server (ProxySQL connects from 127.0.0.1) with a password stored in
// a way ProxySQL checks, never Rowsafe's or the server's own. warn lists
// the others.
func (s *server) poolUsers(ctx context.Context, db *sql.DB) (users []proxysqlroot.User, warn []string, err error) {
	locked := "'N'"
	if !s.flavor.mariadb() {
		locked = "account_locked"
	}
	rows, err := db.QueryContext(ctx, `SELECT User, Host, IFNULL(plugin, ''), HEX(IFNULL(authentication_string, '')), `+locked+`
		FROM mysql.user ORDER BY User, Host = '%' DESC`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var hostOnly, otherAuth []string
	for rows.Next() {
		var u dbaUser
		var plugin, hash, lockedV string
		if err := rows.Scan(&u.user, &u.host, &plugin, &hash, &lockedV); err != nil {
			return nil, nil, err
		}
		if u.user == "" || lockedV == "Y" || u.user == rowsafeUser || u.user == "root" || u.user == "debian-sys-maint" ||
			strings.HasPrefix(u.user, "mysql.") || u.user == "mariadb.sys" || seen[u.user] {
			continue
		}
		switch u.host {
		case "%", "localhost", "127.0.0.1", "::1":
		default:
			hostOnly = append(hostOnly, u.display())
			continue
		}
		if (plugin != "mysql_native_password" && plugin != "caching_sha2_password") || hash == "" {
			otherAuth = append(otherAuth, u.display())
			continue
		}
		seen[u.user] = true
		users = append(users, proxysqlroot.User{Name: u.user, Hash: hash, Plugin: plugin})
	}
	if len(hostOnly) > 0 {
		warn = append(warn, fmt.Sprintf("%s may log in only from other hosts, so ProxySQL (which connects from this server) can't log in as them: %s.",
			plural(int64(len(hostOnly)), "user", "users"), strings.Join(hostOnly[:min(5, len(hostOnly))], ", ")))
	}
	if len(otherAuth) > 0 {
		warn = append(warn, fmt.Sprintf("%s log in without a password ProxySQL can check (socket login, PAM, ed25519): connect them directly: %s.",
			plural(int64(len(otherAuth)), "user", "users"), strings.Join(otherAuth[:min(5, len(otherAuth))], ", ")))
	}
	return users, warn, rows.Err()
}

func usersFingerprint(users []proxysqlroot.User) string {
	h := sha256.New()
	for _, u := range users {
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", u.Name, u.Plugin, u.Hash)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *server) pooling(ctx context.Context, p protocol.PoolingParams, log agent.TaskLogger) (*protocol.PoolingResult, error) {
	start := time.Now()
	res := &protocol.PoolingResult{Action: p.Action}
	if p.Action == protocol.PoolingOff {
		r, err := s.askProxySQL(ctx, proxysqlroot.Request{Action: proxysqlroot.ActionOff}, log)
		if err != nil {
			return res, err
		}
		_ = os.Remove(s.poolStatePath())
		res.Removed = r.Removed
		res.Summary = "Pooling is off: ProxySQL is stopped" + map[bool]string{true: " and removed.", false: "."}[r.Removed] + " Apps connect to " +
			s.flavor.display() + " directly."
		res.DurationMs = time.Since(start).Milliseconds()
		return res, nil
	}
	if p.Action != protocol.PoolingOn {
		return nil, fmt.Errorf("unknown pooling action %q", p.Action)
	}
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var maxConn, ro int
	if err := db.QueryRowContext(ctx, "SELECT @@max_connections, @@read_only").Scan(&maxConn, &ro); err != nil {
		return nil, err
	}
	if ro != 0 {
		return nil, fmt.Errorf("this %s server is read-only (a replica?): turn pooling on for the primary", s.flavor.display())
	}
	def := protocol.DefaultPoolingSettings(runtime.NumCPU(), maxConn, 0)
	def.Port = proxysqlDefaultPort
	want := p.Settings
	if want.Mode == "" {
		want.Mode = def.Mode
	}
	if want.PoolSize == 0 {
		want.PoolSize = def.PoolSize
	}
	if want.MaxClientConn == 0 {
		want.MaxClientConn = def.MaxClientConn
	}
	if want.Listen == "" {
		want.Listen = def.Listen
	}
	if want.Port == 0 {
		want.Port = def.Port
	}
	if want.Mode != protocol.PoolModeTransaction && want.Mode != protocol.PoolModeSession {
		return nil, fmt.Errorf("mode must be transaction or session")
	}
	if want.PoolSize > max(maxConn-10, 2) {
		return nil, fmt.Errorf("a pool of %d connections is more than %s allows (max_connections %d, less 10 for administrators and Rowsafe)",
			want.PoolSize, s.flavor.display(), maxConn)
	}
	listen, err := agent.PoolerListenAddresses(want.Listen)
	if err != nil {
		return nil, err
	}
	users, warn, err := s.poolUsers(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading the users: %w", err)
	}
	r, err := s.askProxySQL(ctx, proxysqlroot.Request{Action: proxysqlroot.ActionOn, Target: s.db.Port, Port: want.Port, Listen: listen,
		MaxClientConn: want.MaxClientConn, PoolSize: want.PoolSize, Multiplex: want.Mode == protocol.PoolModeTransaction, Users: users}, log)
	if err != nil {
		return res, err
	}
	st := &poolState{DatabaseID: s.db.ID, Settings: want, Addresses: r.Addresses, Target: r.Target, TargetPort: s.db.Port, Version: r.Version,
		Users: usersFingerprint(users)}
	if err := s.savePoolState(st); err != nil {
		return res, err
	}
	res.On, res.Installed, res.Version, res.Settings, res.Addresses, res.Target = true, r.Installed, r.Version, want, r.Addresses, r.Target
	if !s.flavor.mariadb() {
		warn = append(warn, "Apps whose users have caching_sha2_password (MySQL's default) connect through ProxySQL with TLS, or with their driver's option to fetch the server's public key (get-server-public-key).")
	}
	res.Warnings = append(warn, r.Warnings...)
	res.Summary = fmt.Sprintf("Pooling is on: ProxySQL %s listens on %s, port %d, %s mode, up to %d connections to %s; %s can log in through it.",
		r.Version, strings.Join(r.Addresses, ", "), want.Port, want.Mode, want.PoolSize, s.flavor.display(), plural(int64(r.UsersSynced), "user", "users"))
	res.DurationMs = time.Since(start).Milliseconds()
	log.Printf("%s", res.Summary)
	return res, nil
}

func (s *server) poolerRetarget(ctx context.Context, p protocol.PoolerRetargetParams, log agent.TaskLogger) (*protocol.PoolerRetargetResult, error) {
	start := time.Now()
	st := s.loadPoolState()
	if st == nil {
		return nil, errors.New("Rowsafe doesn't run ProxySQL for this database")
	}
	host := p.Host
	switch {
	case host == "localhost" || host == "127.0.0.1":
		host = ""
	case net.ParseIP(host) == nil && !hostnameRE.MatchString(host):
		return nil, fmt.Errorf("invalid host %q", p.Host)
	}
	if p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", p.Port)
	}
	// The users as this server has them (the same on the new primary: they
	// replicate). When the server is down (the old primary after a
	// failover), ProxySQL keeps the users it has.
	var users []proxysqlroot.User
	if db, err := s.open(ctx); err == nil {
		users, _, err = s.poolUsers(ctx, db)
		db.Close()
		if err != nil {
			users = nil
		}
	}
	if users == nil {
		log.Printf("%s on this server can't be read; ProxySQL keeps the users it has", s.flavor.display())
	}
	from := st.Target
	r, err := s.askProxySQL(ctx, proxysqlroot.Request{Action: proxysqlroot.ActionRetarget, Target: p.Port, TargetHost: host, Users: users}, log)
	if err != nil {
		return nil, err
	}
	st.Target, st.TargetPort, st.TargetHost = r.Target, p.Port, host
	if users != nil {
		st.Users = usersFingerprint(users)
	}
	if err := s.savePoolState(st); err != nil {
		return nil, err
	}
	res := &protocol.PoolerRetargetResult{From: from, To: r.Target, Summary: fmt.Sprintf("ProxySQL now sends connections to %s.", r.Target),
		DurationMs: time.Since(start).Milliseconds()}
	log.Printf("%s", res.Summary)
	return res, nil
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// syncPoolUsers hands ProxySQL the users again when they changed (a user
// created or removed in Databases & users, a new password). It runs in the
// background, at most one at a time.
var poolSyncMu sync.Mutex

func (s *server) syncPoolUsers(ctx context.Context, db *sql.DB) {
	st := s.loadPoolState()
	if st == nil || !poolSyncMu.TryLock() {
		return
	}
	users, _, err := s.poolUsers(ctx, db)
	if err != nil || usersFingerprint(users) == st.Users {
		poolSyncMu.Unlock()
		return
	}
	go func() {
		defer poolSyncMu.Unlock()
		bctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if _, err := s.askProxySQL(bctx, proxysqlroot.Request{Action: proxysqlroot.ActionUsers, Target: st.TargetPort, TargetHost: st.TargetHost, Users: users}, nil); err != nil {
			s.env.Log.Warn("updating ProxySQL's users failed", "database_id", s.db.ID, "err", err)
			return
		}
		st.Users = usersFingerprint(users)
		_ = s.savePoolState(st)
	}()
}

// PoolerStatus reports ProxySQL for the heartbeat.
func (e *Engine) PoolerStatus(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) *protocol.PoolerStatus {
	s := e.server(env, db)
	st := s.loadPoolState()
	if st == nil {
		return nil
	}
	out := &protocol.PoolerStatus{Managed: true, DatabaseID: db.ID, Settings: st.Settings, Addresses: st.Addresses, Target: st.Target, Version: st.Version}
	sdb, err := openProxySQLStats(ctx)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer sdb.Close()
	var v string
	if err := sdb.QueryRowContext(ctx, "SELECT variable_value FROM stats_mysql_global WHERE variable_name = 'ProxySQL_Uptime'").Scan(&v); err != nil {
		out.Error = "ProxySQL doesn't answer: " + err.Error()
		return out
	}
	out.Running = true
	return out
}

var (
	_ agent.EnginePooler        = (*Engine)(nil)
	_ agent.EnginePoolerManaged = (*Engine)(nil)
)

// PoolerManages reports whether Rowsafe runs ProxySQL for db here.
func (e *Engine) PoolerManages(env agent.EngineEnv, db protocol.DatabaseSpec) bool {
	return e.server(env, db).loadPoolState() != nil
}

// openProxySQLStats opens ProxySQL's admin interface with the read-only
// statistics credentials root's helper gave the agent.
func openProxySQLStats(ctx context.Context) (*sql.DB, error) {
	data, err := os.ReadFile(envOr("ROWSAFE_PROXYSQL_STATS_FILE", proxysqlroot.DefaultStatsFile))
	if err != nil {
		return nil, fmt.Errorf("ProxySQL's statistics credentials can't be read: %w", err)
	}
	u, pw, _ := strings.Cut(strings.TrimSpace(string(data)), ":")
	return openWith(ctx, account{User: u, Password: pw, Source: "ProxySQL statistics"}, "", 6032)
}

// poolerStats reads ProxySQL's statistics for monitoring.
func (s *server) poolerStats(ctx context.Context, prevQuestions *float64, prevAt *time.Time) *protocol.PoolerStats {
	st := s.loadPoolState()
	if st == nil {
		return nil
	}
	sdb, err := openProxySQLStats(ctx)
	if err != nil {
		return nil
	}
	defer sdb.Close()
	g := map[string]float64{}
	rows, err := sdb.QueryContext(ctx, `SELECT variable_name, variable_value FROM stats_mysql_global
		WHERE variable_name IN ('Client_Connections_connected', 'Questions', 'Active_Transactions')`)
	if err != nil {
		return nil
	}
	for rows.Next() {
		var k string
		var v float64
		if rows.Scan(&k, &v) == nil {
			g[k] = v
		}
	}
	rows.Close()
	var used, free sql.NullFloat64
	_ = sdb.QueryRowContext(ctx, "SELECT SUM(ConnUsed), SUM(ConnFree) FROM stats_mysql_connection_pool").Scan(&used, &free)
	now := time.Now()
	qps := 0.0
	if !prevAt.IsZero() && g["Questions"] >= *prevQuestions {
		qps = (g["Questions"] - *prevQuestions) / now.Sub(*prevAt).Seconds()
	}
	*prevQuestions, *prevAt = g["Questions"], now
	return &protocol.PoolerStats{CollectedAt: now.UTC(), Version: st.Version, Pools: []protocol.PoolStat{{
		Database: "all", User: "all", Mode: st.Settings.Mode,
		ClientsActive: int(g["Client_Connections_connected"]), ServersActive: int(used.Float64), ServersIdle: int(free.Float64),
		PoolSize: st.Settings.PoolSize, QueryPerSecond: qps,
	}}}
}
