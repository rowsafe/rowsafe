package agent

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Security check: every 15 minutes (and on demand, as a security_scan
// task) the agent reads what decides who can reach each database and how
// they log in, and posts it to POST /v1/agent/security. Everything is
// read-only and cheap: a few catalog queries per cluster and one per
// database for schema privileges. Password hashes are never read: only
// which kind a role has.

// Timings of the security loop (variables for tests).
var (
	securityInterval   = 15 * time.Minute
	securityFirstDelay = 45 * time.Second // after the agent starts
	securityTimeout    = 30 * time.Second // one cluster
)

const (
	maxSecurityRoles   = 200
	maxSecurityClients = 50
	maxSecurityDBs     = 20
	securityAppName    = "rowsafe-agent-security"
)

// untrustedLanguages are procedural languages that run as the server's
// operating system user; only superusers may use them unless someone marks
// them trusted.
var untrustedLanguages = []string{"plperlu", "plpythonu", "plpython2u", "plpython3u", "pltclu", "pljavau", "plsh", "plshu", "plr", "plrubyu", "plluau", "plv8u"}

// securityLoop posts security reports for the monitored databases.
func (a *Agent) securityLoop(ctx context.Context) {
	wait := securityFirstDelay + rand.N(30*time.Second)
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = securityInterval
		dbs := a.monitoredDatabases()
		if len(dbs) == 0 {
			continue
		}
		batch := protocol.SecurityReportBatch{}
		for _, db := range dbs {
			if isPostgres(db) { // the security check reads PostgreSQL's own settings
				batch.Reports = append(batch.Reports, a.securityReport(ctx, db))
			}
		}
		if len(batch.Reports) == 0 {
			continue
		}
		var ack protocol.SecurityAck
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := a.client.post(sctx, "/v1/agent/security", batch, &ack)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			// An older control plane without the endpoint answers 404: try
			// again rarely, and say so once.
			wait = min(securityInterval*time.Duration(1<<min(failures, 4)), 4*time.Hour)
			if failures == 1 {
				a.log.Warn("sending the security report failed", "err", err, "retry_in", wait.String())
			}
			continue
		}
		failures = 0
		if ack.IntervalSeconds >= 60 && ack.IntervalSeconds <= 86400 {
			wait = time.Duration(ack.IntervalSeconds) * time.Second
		}
	}
}

// securityReport reads one cluster; a failure is reported in Error.
func (a *Agent) securityReport(ctx context.Context, db protocol.DatabaseSpec) protocol.SecurityReport {
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()
	rep, err := a.scanSecurity(ctx, db)
	rep.DatabaseID = db.ID
	rep.CollectedAt = time.Now().UTC()
	if err != nil {
		rep.Error = clipString(err.Error(), 1000)
	}
	return rep
}

func (a *Agent) securityTarget(db protocol.DatabaseSpec) pginspect.Target {
	t := a.target(db)
	t.AppName = securityAppName
	return t
}

// scanSecurity reads a cluster's security settings.
func (a *Agent) scanSecurity(ctx context.Context, db protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	rep := protocol.SecurityReport{Port: db.Port, Docker: a.cfg.Sidecar()}
	rep.Firewall = a.firewallState(db.Port)
	conn, err := a.securityTarget(db).Connect(ctx, "postgres")
	if err != nil {
		return rep, fmt.Errorf("connecting to PostgreSQL on port %d: %w", db.Port, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	var ssl, dataDir string
	var super bool
	err = conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int, current_setting('server_version'),
		current_setting('listen_addresses'), current_setting('port')::int, current_setting('ssl'),
		current_setting('ssl_cert_file'), current_setting('password_encryption'), current_setting('hba_file'),
		current_setting('data_directory'), (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)`).
		Scan(&rep.VersionNum, &rep.ServerVersion, &rep.ListenAddresses, &rep.Port, &ssl, &rep.SSLCertFile,
			&rep.PasswordEncryption, &rep.HBAFile, &dataDir, &super)
	if err != nil {
		return rep, fmt.Errorf("reading settings: %w", err)
	}
	rep.SSL = ssl == "on"
	if rows, err := conn.Query(ctx, `SELECT name FROM pg_settings WHERE pending_restart
		AND name IN ('listen_addresses', 'port', 'ssl', 'password_encryption') ORDER BY name`); err == nil {
		rep.PendingRestart, _ = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	note := func(format string, args ...any) { rep.Notes = append(rep.Notes, fmt.Sprintf(format, args...)) }

	// The certificate: from the file (the agent runs as PostgreSQL's user),
	// else through PostgreSQL (superuser).
	if rep.SSLCertFile != "" {
		path := rep.SSLCertFile
		if !filepath.IsAbs(path) {
			path = filepath.Join(dataDir, path)
		}
		data, err := os.ReadFile(path)
		if err != nil && super && rep.SSL {
			err = conn.QueryRow(ctx, `SELECT pg_read_binary_file($1)`, path).Scan(&data)
		}
		switch {
		case err == nil:
			if info, c := certInfo(data); c != nil || rep.SSL {
				rep.Cert = info
			}
		case rep.SSL:
			rep.Cert = &protocol.CertInfo{Error: "Rowsafe can't read the certificate " + path}
		}
	}

	if !super {
		note("The agent's PostgreSQL user %s is not a superuser, so pg_hba rules and password kinds can't be read.", a.cfg.PGUser)
	}
	if super && rep.VersionNum >= 100000 {
		if err := readHBARules(ctx, conn, &rep); err != nil {
			note("pg_hba rules could not be read: %v", err)
		}
		rep.HBABackups = hbaBackups(rep.HBAFile)
		if content, err := os.ReadFile(rep.HBAFile); err == nil {
			if _, err := parseHBA(string(content)); err != nil && strings.Contains(err.Error(), "include") {
				rep.HBAIncludes = true
			}
		}
	}
	if err := readRoles(ctx, conn, super, &rep); err != nil {
		note("roles could not be read: %v", err)
	}
	if err := readClients(ctx, conn, &rep); err != nil {
		note("connected clients could not be read: %v", err)
	}
	if err := a.readDatabasePrivileges(ctx, db, conn, &rep); err != nil {
		note("schema privileges could not be read: %v", err)
	}
	if !a.cfg.Sidecar() {
		for _, ip := range hostIPs() {
			rep.HostAddresses = append(rep.HostAddresses, ip.String())
		}
	}
	return rep, nil
}

func readHBARules(ctx context.Context, conn *pgx.Conn, rep *protocol.SecurityReport) error {
	rows, err := conn.Query(ctx, `SELECT coalesce(line_number, 0), coalesce(type, ''), coalesce(database, '{}'), coalesce(user_name, '{}'),
		coalesce(address, ''), coalesce(netmask, ''), coalesce(auth_method, ''), coalesce(error, '')
		FROM pg_hba_file_rules ORDER BY line_number LIMIT 500`)
	if err != nil {
		return err
	}
	rules, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (protocol.HBARule, error) {
		var h protocol.HBARule
		err := r.Scan(&h.Line, &h.Type, &h.Databases, &h.Users, &h.Address, &h.Netmask, &h.Method, &h.Error)
		return h, err
	})
	rep.HBA = rules
	return err
}

func readRoles(ctx context.Context, conn *pgx.Conn, super bool, rep *protocol.SecurityReport) error {
	// Only superusers can see which kind of password a role has
	// (pg_authid); the hash itself is never read.
	q := `SELECT rolname, rolsuper, rolcanlogin,
		CASE WHEN rolpassword IS NULL THEN 'none' WHEN rolpassword LIKE 'md5%' THEN 'md5'
		     WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'scram' ELSE 'other' END, rolvaliduntil
		FROM pg_authid WHERE (rolcanlogin OR rolsuper) AND rolname NOT LIKE 'pg\_%' ORDER BY rolname LIMIT $1`
	if !super {
		q = `SELECT rolname, rolsuper, rolcanlogin, '', rolvaliduntil FROM pg_roles
		     WHERE (rolcanlogin OR rolsuper) AND rolname NOT LIKE 'pg\_%' ORDER BY rolname LIMIT $1`
	}
	rows, err := conn.Query(ctx, q, maxSecurityRoles)
	if err != nil {
		return err
	}
	rep.Roles, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (protocol.RoleInfo, error) {
		var ri protocol.RoleInfo
		var until *time.Time
		err := r.Scan(&ri.Name, &ri.Superuser, &ri.CanLogin, &ri.Password, &until)
		if until != nil && until.Year() < 9000 {
			ri.ValidUntil = until
		}
		return ri, err
	})
	return err
}

// readClients lists the remote addresses with sessions now (client
// backends and replication connections).
func readClients(ctx context.Context, conn *pgx.Conn, rep *protocol.SecurityReport) error {
	rows, err := conn.Query(ctx, `SELECT host(a.client_addr), coalesce(a.usename, ''), coalesce(r.rolsuper, false),
		coalesce(s.ssl, false), a.backend_type = 'walsender'
		FROM pg_stat_activity a LEFT JOIN pg_stat_ssl s ON s.pid = a.pid LEFT JOIN pg_roles r ON r.oid = a.usesysid
		WHERE a.client_addr IS NOT NULL AND coalesce(a.application_name, '') NOT LIKE 'rowsafe%' LIMIT 2000`)
	if err != nil {
		return err
	}
	defer rows.Close()
	byAddr := map[string]*protocol.ClientAddr{}
	for rows.Next() {
		var addr, user string
		var super, tls, repl bool
		if err := rows.Scan(&addr, &user, &super, &tls, &repl); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(addr)
		if err != nil || ip.Unmap().IsLoopback() {
			continue
		}
		addr = ip.Unmap().String()
		c := byAddr[addr]
		if c == nil {
			c = &protocol.ClientAddr{Address: addr, TLS: true}
			byAddr[addr] = c
		}
		c.Sessions++
		c.Superuser = c.Superuser || super
		c.TLS = c.TLS && tls
		if repl {
			user += " (replication)"
		}
		if user != "" && !slices.Contains(c.Users, user) && len(c.Users) < 5 {
			c.Users = append(c.Users, user)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range byAddr {
		sort.Strings(c.Users)
		rep.Clients = append(rep.Clients, *c)
	}
	slices.SortFunc(rep.Clients, func(x, y protocol.ClientAddr) int {
		if x.Sessions != y.Sessions {
			return y.Sessions - x.Sessions
		}
		return strings.Compare(x.Address, y.Address)
	})
	if len(rep.Clients) > maxSecurityClients {
		rep.Clients = rep.Clients[:maxSecurityClients]
	}
	return nil
}

// readDatabasePrivileges checks, in each database, whether everyone may
// create objects in schema public, and for untrusted languages someone
// marked trusted.
func (a *Agent) readDatabasePrivileges(ctx context.Context, db protocol.DatabaseSpec, conn *pgx.Conn, rep *protocol.SecurityReport) error {
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname LIMIT $1`, maxSecurityDBs)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		c := conn
		if name != conn.Config().Database {
			if c, err = a.securityTarget(db).Connect(ctx, name); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", name, err))
				continue
			}
		}
		var public bool
		var langs []string
		err := c.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace n,
			aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) acl
			WHERE n.nspname = 'public' AND acl.grantee = 0 AND acl.privilege_type = 'CREATE'),
			coalesce((SELECT array_agg(lanname ORDER BY lanname) FROM pg_language WHERE lanpltrusted AND lanname = ANY($1)), '{}')`,
			untrustedLanguages).Scan(&public, &langs)
		if c != conn {
			c.Close(context.WithoutCancel(ctx))
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if public {
			rep.PublicCreate = append(rep.PublicCreate, name)
		}
		for _, l := range langs {
			rep.UntrustedLanguages = append(rep.UntrustedLanguages, name+": "+l)
		}
	}
	return errors.Join(errs...)
}

// hbaBackups lists Rowsafe's backups of pg_hba.conf, newest first.
func hbaBackups(hbaFile string) []string {
	if hbaFile == "" {
		return nil
	}
	matches, _ := filepath.Glob(hbaFile + hbaBackupSuffix + "*")
	var out []string
	for _, m := range matches {
		if hbaBackupRE.MatchString(filepath.Base(m)) {
			out = append(out, m)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

func clipString(s string, n int) string {
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}
