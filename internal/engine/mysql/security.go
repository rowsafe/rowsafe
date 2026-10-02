package mysql

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The security check for MySQL and MariaDB (agent.EngineSecurityChecker):
// where the server listens, TLS, accounts and the kind of their passwords
// (never a hash), anonymous accounts, the sample test database and the
// clients connected over the network. Two fixes are safe from a click:
// removing the anonymous accounts, and removing the test database while it
// is empty.

var _ agent.EngineSecurityChecker = (*Engine)(nil)

// SecurityReport reads the server's security settings.
func (e *Engine) SecurityReport(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec) (protocol.SecurityReport, error) {
	s := e.server(env, spec)
	rep := protocol.SecurityReport{Port: spec.Port, EngineSecurity: &protocol.EngineSecurity{}}
	db, err := s.open(ctx)
	if err != nil {
		return rep, err
	}
	defer db.Close()
	vars := map[string]string{}
	rows, err := db.QueryContext(ctx, `SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version', 'port', 'bind_address', 'skip_networking',
		'have_ssl', 'ssl_cert', 'require_secure_transport', 'local_infile', 'tls_version')`)
	if err != nil {
		return rep, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return rep, err
		}
		vars[strings.ToLower(k)] = v
	}
	rows.Close()
	es := rep.EngineSecurity
	rep.ServerVersion, rep.VersionNum = numericVersion(vars["version"])
	if _, err := fmt.Sscan(vars["port"], &rep.Port); err != nil || rep.Port == 0 {
		rep.Port = spec.Port
	}
	rep.ListenAddresses = vars["bind_address"]
	if rep.ListenAddresses == "" {
		rep.ListenAddresses = "*" // MariaDB: every address
	}
	if strings.EqualFold(vars["skip_networking"], "ON") {
		rep.ListenAddresses = "localhost"
	}
	rep.SSL = vars["have_ssl"] == "YES" || (vars["have_ssl"] == "" && vars["ssl_cert"] != "")
	es.RequireTLS = strings.EqualFold(vars["require_secure_transport"], "ON")
	es.LocalInfile = strings.EqualFold(vars["local_infile"], "ON")

	var note []string
	// Accounts.
	locked, role := "'N'", "'N'"
	if s.flavor.mariadb() {
		role = "is_role"
	} else {
		locked = "account_locked"
	}
	rows, err = db.QueryContext(ctx, `SELECT User, Host, IFNULL(plugin, ''), IFNULL(authentication_string, '') = '', `+locked+`, `+role+`, Super_priv
		FROM mysql.user ORDER BY User, Host LIMIT 200`)
	if err != nil {
		note = append(note, "accounts could not be read: "+err.Error())
	} else {
		for rows.Next() {
			var u dbaUser
			var plugin, lockedV, roleV, super string
			var empty bool
			if err := rows.Scan(&u.user, &u.host, &plugin, &empty, &lockedV, &roleV, &super); err != nil {
				rows.Close()
				return rep, err
			}
			if roleV == "Y" {
				continue
			}
			login := lockedV != "Y"
			kind := passwordKind(plugin, empty)
			rep.Roles = append(rep.Roles, protocol.RoleInfo{Name: u.display(), Superuser: super == "Y", CanLogin: login, Password: kind})
			remote := !localHost(u.host)
			switch {
			case !login:
			case u.user == "":
				es.AnonymousUsers = append(es.AnonymousUsers, u.display())
			case kind == protocol.PasswordNone && remote:
				es.OpenNoPassword = append(es.OpenNoPassword, u.display())
			}
			if login && super == "Y" && remote && u.user != "" {
				es.RemoteAdmins = append(es.RemoteAdmins, u.display())
			}
		}
		rows.Close()
	}

	// The sample test database.
	if ok, _ := (&dbaRun{db: db}).databaseExists(ctx, "test"); ok {
		es.TestDatabase = true
		_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'test'").Scan(&es.TestDatabaseTables)
	}

	// Clients over the network.
	clients := map[string]*protocol.ClientAddr{}
	if rows, err := db.QueryContext(ctx, `SELECT USER, HOST FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Daemon'`); err == nil {
		for rows.Next() {
			var u, h string
			if rows.Scan(&u, &h) != nil {
				continue
			}
			if i := strings.LastIndex(h, ":"); i > 0 {
				h = h[:i]
			}
			if h == "" || localHost(h) {
				continue
			}
			c := clients[h]
			if c == nil {
				if len(clients) >= 50 {
					continue
				}
				c = &protocol.ClientAddr{Address: h}
				clients[h] = c
			}
			c.Sessions++
			if !contains(c.Users, u) && len(c.Users) < 10 {
				c.Users = append(c.Users, u)
			}
			if u == "root" {
				c.Superuser = true
			}
		}
		rows.Close()
	}
	for _, c := range clients {
		rep.Clients = append(rep.Clients, *c)
	}
	sort.Slice(rep.Clients, func(i, j int) bool { return rep.Clients[i].Sessions > rep.Clients[j].Sessions })
	rep.Notes = note
	return rep, nil
}

func localHost(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// SecurityFix runs one fix.
func (e *Engine) SecurityFix(ctx context.Context, env agent.EngineEnv, spec protocol.DatabaseSpec, p protocol.SecurityFixParams, log agent.TaskLogger) (*protocol.SecurityFixResult, error) {
	s := e.server(env, spec)
	res := &protocol.SecurityFixResult{Action: p.Action}
	db, err := s.open(ctx)
	if err != nil {
		return res, err
	}
	defer db.Close()
	var ro int
	if err := db.QueryRowContext(ctx, "SELECT @@read_only").Scan(&ro); err == nil && ro != 0 {
		return res, fmt.Errorf("this %s server is read-only (a replica?): fix it on the primary", s.flavor.display())
	}
	switch p.Action {
	case protocol.SecDropAnonymous:
		rows, err := db.QueryContext(ctx, "SELECT Host FROM mysql.user WHERE User = ''")
		if err != nil {
			return res, err
		}
		var hosts []string
		for rows.Next() {
			var h string
			if rows.Scan(&h) == nil {
				hosts = append(hosts, h)
			}
		}
		rows.Close()
		if len(hosts) == 0 {
			res.Summary = "There are no anonymous accounts any more."
			return res, nil
		}
		for _, h := range hosts {
			if _, err := db.ExecContext(ctx, "DROP USER "+dbaUser{"", h}.sql()); err != nil {
				return res, fmt.Errorf("removing the anonymous account @%s: %w", h, plainError(err))
			}
			log.Printf("removed the anonymous account @%s", h)
		}
		res.Summary = fmt.Sprintf("Removed %s: logging in now needs a real user name.", plural(int64(len(hosts)), "anonymous account", "anonymous accounts"))
	case protocol.SecDropTestDatabase:
		var tables int
		if err := db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'test'").Scan(&tables); err != nil {
			return res, err
		}
		if tables > 0 {
			return res, fmt.Errorf("the test database has %s, so Rowsafe leaves it alone: if nothing uses it, remove it in Databases & users (a Mark is saved first)",
				plural(int64(tables), "table", "tables"))
		}
		if _, err := db.ExecContext(ctx, "DROP DATABASE IF EXISTS `test`"); err != nil {
			return res, fmt.Errorf("removing the test database: %w", plainError(err))
		}
		log.Printf("removed the empty test database")
		// The rule that lets every account use test and test_* databases.
		r, err := db.ExecContext(ctx, `DELETE FROM mysql.db WHERE Db = 'test' OR Db LIKE 'test\\_%'`)
		if err == nil {
			if n, _ := r.RowsAffected(); n > 0 {
				_, err = db.ExecContext(ctx, "FLUSH PRIVILEGES")
				log.Printf("removed %s that let every account use test databases", plural(n, "rule", "rules"))
			}
		}
		if err != nil {
			return res, fmt.Errorf("the test database is gone, but the rule letting everyone use test databases stays: %w", plainError(err))
		}
		res.Summary = "Removed the empty test database and the rule that let every account use test databases."
	default:
		return res, errors.New("this fix isn't available for " + s.flavor.display())
	}
	return res, nil
}
