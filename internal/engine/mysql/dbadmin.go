package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users (dbadmin tasks) for MySQL and MariaDB: create and
// remove databases (schemas) and users, and give users access to
// databases, when a person asks for it in the dashboard or the CLI. Names
// are checked by protocol.ValidateDBAdminFor (new names are lowercase
// letters, digits and underscores) and quoted; passwords are generated
// here and leave the server only sealed to the requester's key.
//
// MySQL has no database owners: the "owner" of a database is a user with
// every privilege on it (ownerPrivileges). New users may sign in from any
// host ('%'); who can reach the server at all is decided by where it
// listens and the firewall (the security check flags a server open to the
// internet).

// Privileges per access level, on `db`.*.
const (
	readOnlyPrivileges  = "SELECT, SHOW VIEW"
	readWritePrivileges = "SELECT, INSERT, UPDATE, DELETE, SHOW VIEW, CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE"
	ownerPrivileges     = "SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, REFERENCES, INDEX, ALTER, CREATE TEMPORARY TABLES, " +
		"LOCK TABLES, EXECUTE, CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE, EVENT, TRIGGER"
)

// adminNeeds are the global privileges Rowsafe's account needs to manage
// databases and users (granted by the installer since Databases & users
// came to MySQL; older accounts lack them).
var adminNeeds = []string{"CREATE USER", "CREATE", "DROP", "DELETE", "ALTER", "INDEX", "CREATE VIEW", "CREATE ROUTINE",
	"ALTER ROUTINE", "EVENT", "REFERENCES", "EXECUTE", "CREATE TEMPORARY TABLES"}

func privilegesFor(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return readOnlyPrivileges
	case protocol.DBAccessReadWrite:
		return readWritePrivileges
	}
	return ownerPrivileges
}

// dbaUser is a MySQL account: user@host. People see "app" for app@'%'.
type dbaUser struct{ user, host string }

func (u dbaUser) display() string {
	if u.host == "%" {
		return u.user
	}
	return u.user + "@" + u.host
}

func (u dbaUser) sql() string { return quoteString(u.user) + "@" + quoteString(u.host) }

// parseUser reads a name from the dashboard: "app" is app@'%', "app@host"
// is that account.
func parseUser(name string) dbaUser {
	if i := strings.LastIndex(name, "@"); i > 0 {
		return dbaUser{name[:i], name[i+1:]}
	}
	return dbaUser{name, "%"}
}

type dbaRun struct {
	s      *server
	db     *sql.DB
	p      protocol.DBAdminParams
	log    agent.TaskLogger
	res    *protocol.DBAdminResult
	me     dbaUser
	secret *protocol.DBConnection
	pw     string
}

func (s *server) dbadmin(ctx context.Context, taskID string, p protocol.DBAdminParams, log agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(string(s.flavor), p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	db, err := s.open(ctx)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	defer db.Close()
	d := &dbaRun{s: s, db: db, p: p, log: log, res: &protocol.DBAdminResult{Action: p.Action}}
	var cur string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&cur); err != nil {
		return nil, agent.Sentence(err)
	}
	d.me = parseUser(cur)

	if p.Action != protocol.DBAdminList {
		err = d.canManage(ctx)
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateDatabase:
			err = d.createDatabase(ctx)
		case protocol.DBAdminCreateUser:
			err = d.createUser(ctx)
		case protocol.DBAdminResetPassword:
			err = d.resetPassword(ctx)
		case protocol.DBAdminDropUser:
			err = d.dropUser(ctx)
		case protocol.DBAdminDropDatabase:
			err = d.dropDatabase(ctx)
		default:
			err = fmt.Errorf("%s has no %s", s.flavor.display(), p.Action)
		}
	}
	inv, ierr := d.inventory(ctx)
	if ierr != nil {
		log.Printf("couldn't read the databases and users afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		d.res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			d.res.Summary = fmt.Sprintf("%s and %s.", plural(int64(len(inv.Databases)), "database", "databases"),
				plural(int64(len(inv.Users)), "user", "users"))
		}
	}
	if err == nil && d.secret != nil {
		c := agent.DBConnectionFor(*d.secret, p.Host, inv, s.db.Port, inv != nil && inv.SSL)
		var sealed *protocol.SealedSecret
		if sealed, err = agent.SealDBSecret(p.PublicKey, taskID, c, d.pw); err == nil {
			d.res.Secret, d.res.Connection = sealed, &c
			log.Printf("the password for %s was encrypted for the person who asked; Rowsafe can't read it", c.User)
		}
	}
	d.res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		err = agent.Sentence(err)
		log.Printf("failed: %v", err)
	} else {
		log.Printf("%s", d.res.Summary)
	}
	return d.res, err
}

// grants are the current account's global privileges (and whether it may
// grant them).
func (d *dbaRun) grants(ctx context.Context) (map[string]bool, bool, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT PRIVILEGE_TYPE, IS_GRANTABLE FROM information_schema.USER_PRIVILEGES
		WHERE GRANTEE = CONCAT('''', SUBSTRING_INDEX(CURRENT_USER(), '@', 1), '''@''', SUBSTRING_INDEX(CURRENT_USER(), '@', -1), '''')`)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	have := map[string]bool{}
	grantable := false
	for rows.Next() {
		var p, g string
		if err := rows.Scan(&p, &g); err != nil {
			return nil, false, err
		}
		have[strings.ToUpper(p)] = true
		grantable = grantable || g == "YES"
	}
	return have, grantable, rows.Err()
}

// manageBlocked says why Rowsafe's account can't create databases and
// users ("" when it can).
func (d *dbaRun) manageBlocked(ctx context.Context) (string, error) {
	have, grantable, err := d.grants(ctx)
	if err != nil {
		return "", err
	}
	var missing []string
	for _, n := range adminNeeds {
		if !have[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) == 0 && grantable {
		return "", nil
	}
	return fmt.Sprintf("Rowsafe's %s account (%s) can list databases and users but not create or change them: it was set up before Databases & users came to %s. "+
		"Run the command below once on the server, as root, to give it the rights.", d.s.flavor.display(), d.me.user, d.s.flavor.display()), nil
}

func (d *dbaRun) manageCommand() string {
	if d.s.env.Config.Sidecar() {
		return "Set ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE for the agent container (the file with the root password) and restart it."
	}
	return fmt.Sprintf("sudo rowsafe-agent setup mysql-account --engine %s --port %d", d.s.flavor, d.s.db.Port)
}

// canManage refuses changes on a read-only server (a replica) or without
// the rights. In Docker, with the root password file, the agent gives its
// own account the rights first.
func (d *dbaRun) canManage(ctx context.Context) error {
	var ro int
	if err := d.db.QueryRowContext(ctx, "SELECT @@read_only").Scan(&ro); err != nil {
		return err
	}
	if ro != 0 {
		return fmt.Errorf("this %s server is read-only (a replica?): create databases and users on the primary", d.s.flavor.display())
	}
	why, err := d.manageBlocked(ctx)
	if err != nil || why == "" {
		return err
	}
	if _, ok, _ := d.s.adminAccount(); ok {
		if _, err := d.s.createAccountAsAdmin(ctx); err != nil {
			return err
		}
		db, err := d.s.open(ctx)
		if err != nil {
			return err
		}
		d.db.Close()
		d.db = db
		if why, err = d.manageBlocked(ctx); err != nil || why == "" {
			return err
		}
	}
	return errors.New(why)
}

func (d *dbaRun) exec(ctx context.Context, shown, stmt string) error {
	if _, err := d.db.ExecContext(ctx, stmt); err != nil {
		return fmt.Errorf("%s: %w", shown, plainError(err))
	}
	d.log.Printf("%s", shown)
	return nil
}

// plainError strips the driver's "Error 1234 (HY000): " prefix.
func plainError(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "): "); i > 0 && strings.HasPrefix(msg, "Error ") {
		return errors.New(msg[i+3:])
	}
	return err
}

func (d *dbaRun) databaseExists(ctx context.Context, name string) (bool, error) {
	var n int
	err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", name).Scan(&n)
	return n > 0, err
}

func (d *dbaRun) userExists(ctx context.Context, u dbaUser) (bool, error) {
	var n int
	err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM mysql.user WHERE User = ? AND Host = ?", u.user, u.host).Scan(&n)
	return n > 0, err
}

// protectedUser says why a user isn't changed from Rowsafe ("" when it
// may be).
func (d *dbaRun) protectedUser(ctx context.Context, u dbaUser) (string, error) {
	var super string
	err := d.db.QueryRowContext(ctx, "SELECT Super_priv FROM mysql.user WHERE User = ? AND Host = ?", u.user, u.host).Scan(&super)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	return d.protectedReason(u, super == "Y"), nil
}

func (d *dbaRun) protectedReason(u dbaUser, super bool) string {
	switch {
	case u == d.me || u.user == rowsafeUser:
		return "Rowsafe's own account"
	case u.user == "root" || u.user == "debian-sys-maint" || strings.HasPrefix(u.user, "mysql.") || u.user == "mariadb.sys":
		return d.s.flavor.display() + "'s own account"
	case u.user == "":
		return "an anonymous account"
	case super:
		return "an administrator"
	}
	return ""
}

func (d *dbaRun) newPassword() error {
	pw, err := randomPassword()
	d.pw = pw
	return err
}

func (d *dbaRun) createDatabase(ctx context.Context) error {
	p := d.p
	if ok, err := d.databaseExists(ctx, p.Database); err != nil || ok {
		if ok {
			return fmt.Errorf("a database named %s already exists", p.Database)
		}
		return err
	}
	owner := parseUser(p.Owner)
	if p.CreateOwner {
		owner = dbaUser{cmpOr(p.Owner, p.Database), "%"}
		if ok, err := d.userExists(ctx, owner); err != nil || ok {
			if ok {
				return fmt.Errorf("a user named %s already exists: choose it as the owner instead", owner.display())
			}
			return err
		}
	} else {
		if ok, err := d.userExists(ctx, owner); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("there is no user %s", owner.display())
			}
			return err
		}
		if why, err := d.protectedUser(ctx, owner); err != nil || why != "" {
			if err == nil {
				err = fmt.Errorf("%s is %s; choose another owner", owner.display(), why)
			}
			return err
		}
	}
	if err := d.exec(ctx, "created the database "+p.Database,
		"CREATE DATABASE "+quoteIdent(p.Database)+" CHARACTER SET utf8mb4"); err != nil {
		return err
	}
	undo := func() {
		if _, err := d.db.ExecContext(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+quoteIdent(p.Database)); err == nil {
			d.log.Printf("removed the new, empty database %s again", p.Database)
		}
	}
	if p.CreateOwner {
		if err := d.newPassword(); err != nil {
			undo()
			return err
		}
		if err := d.exec(ctx, "created the user "+owner.display(),
			"CREATE USER "+owner.sql()+" IDENTIFIED BY "+quoteString(d.pw)); err != nil {
			undo()
			return err
		}
	}
	if err := d.exec(ctx, fmt.Sprintf("gave %s every right on %s", owner.display(), p.Database),
		"GRANT "+ownerPrivileges+" ON "+quoteIdent(p.Database)+".* TO "+owner.sql()); err != nil {
		if p.CreateOwner {
			_, _ = d.db.ExecContext(context.WithoutCancel(ctx), "DROP USER IF EXISTS "+owner.sql())
		}
		undo()
		return err
	}
	if p.CreateOwner {
		d.secret = &protocol.DBConnection{Engine: string(d.s.flavor), User: owner.user, Database: p.Database}
		d.res.Summary = fmt.Sprintf("Created the database %s and its user %s.", p.Database, owner.display())
	} else {
		d.res.Summary = fmt.Sprintf("Created the database %s; %s has every right on it.", p.Database, owner.display())
	}
	return nil
}

func (d *dbaRun) createUser(ctx context.Context) error {
	p := d.p
	u := dbaUser{p.User, "%"}
	if ok, err := d.userExists(ctx, u); err != nil || ok {
		if ok {
			return fmt.Errorf("a user named %s already exists", p.User)
		}
		return err
	}
	for _, name := range p.Databases {
		if ok, err := d.databaseExists(ctx, name); err != nil || !ok {
			if err == nil {
				err = fmt.Errorf("there is no database %s", name)
			}
			return err
		}
	}
	if err := d.newPassword(); err != nil {
		return err
	}
	if err := d.exec(ctx, "created the user "+u.display(), "CREATE USER "+u.sql()+" IDENTIFIED BY "+quoteString(d.pw)); err != nil {
		return err
	}
	privs := privilegesFor(p.Access)
	for _, name := range p.Databases {
		if err := d.exec(ctx, fmt.Sprintf("gave %s %s access to %s", u.display(), accessWords(p.Access), name),
			"GRANT "+privs+" ON "+quoteIdent(name)+".* TO "+u.sql()); err != nil {
			_, _ = d.db.ExecContext(context.WithoutCancel(ctx), "DROP USER IF EXISTS "+u.sql())
			d.log.Printf("removed the new user %s again", u.display())
			return err
		}
	}
	d.secret = &protocol.DBConnection{Engine: string(d.s.flavor), User: u.user, Database: p.Databases[0]}
	d.res.Summary = fmt.Sprintf("Created the user %s with %s access to %s.", u.display(), accessWords(p.Access), joinAnd(listSome(p.Databases)))
	return nil
}

func accessWords(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return "read-only"
	case protocol.DBAccessReadWrite:
		return "read and write"
	}
	return "full"
}

// listSome keeps long lists short: the first four and "n more".
func listSome(xs []string) []string {
	if len(xs) > 5 {
		return append(append([]string(nil), xs[:4]...), fmt.Sprintf("%d more", len(xs)-4))
	}
	return xs
}

func (d *dbaRun) existingUser(ctx context.Context) (dbaUser, error) {
	u := parseUser(d.p.User)
	ok, err := d.userExists(ctx, u)
	if err == nil && !ok {
		err = fmt.Errorf("there is no user %s", u.display())
	}
	if err != nil {
		return u, err
	}
	why, err := d.protectedUser(ctx, u)
	if err == nil && why != "" {
		err = fmt.Errorf("%s is %s; Rowsafe doesn't change it", u.display(), why)
	}
	return u, err
}

func (d *dbaRun) resetPassword(ctx context.Context) error {
	u, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	if err := d.newPassword(); err != nil {
		return err
	}
	if err := d.exec(ctx, "gave "+u.display()+" a new password", "ALTER USER "+u.sql()+" IDENTIFIED BY "+quoteString(d.pw)); err != nil {
		return err
	}
	var dbname string
	_ = d.db.QueryRowContext(ctx, "SELECT Db FROM mysql.db WHERE User = ? AND Host = ? ORDER BY Db LIMIT 1", u.user, u.host).Scan(&dbname)
	d.secret = &protocol.DBConnection{Engine: string(d.s.flavor), User: u.user, Database: strings.ReplaceAll(dbname, `\_`, "_")}
	d.res.Summary = fmt.Sprintf("Gave %s a new password; the old one stops working for new connections.", u.display())
	return nil
}

func (d *dbaRun) dropUser(ctx context.Context) error {
	u, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	var defined int
	_ = d.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM information_schema.VIEWS WHERE DEFINER = ?) +
		(SELECT COUNT(*) FROM information_schema.ROUTINES WHERE DEFINER = ?)`, u.user+"@"+u.host, u.user+"@"+u.host).Scan(&defined)
	if err := d.exec(ctx, "removed the user "+u.display(), "DROP USER "+u.sql()); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the user %s.", u.display())
	if defined > 0 {
		d.res.Details = append(d.res.Details, fmt.Sprintf("%s defined %s; those that run with their definer's rights stop working until someone else redefines them.",
			u.display(), plural(int64(defined), "view or stored routine", "views or stored routines")))
	}
	return nil
}

func (d *dbaRun) dropDatabase(ctx context.Context) error {
	name := d.p.Database
	if ok, err := d.databaseExists(ctx, name); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("there is no database %s", name)
		}
		return err
	}
	// Users' rights on it would apply again to a new database of the same
	// name: take them back first.
	rows, err := d.db.QueryContext(ctx, "SELECT User, Host FROM mysql.db WHERE Db = ?", name)
	if err != nil {
		return err
	}
	var holders []dbaUser
	for rows.Next() {
		var u dbaUser
		if err := rows.Scan(&u.user, &u.host); err != nil {
			rows.Close()
			return err
		}
		holders = append(holders, u)
	}
	rows.Close()
	if err := d.exec(ctx, "removed the database "+name, "DROP DATABASE "+quoteIdent(name)); err != nil {
		return err
	}
	for _, u := range holders {
		if _, err := d.db.ExecContext(ctx, "REVOKE ALL PRIVILEGES ON "+quoteIdent(name)+".* FROM "+u.sql()); err == nil {
			d.log.Printf("took back %s's rights on %s", u.display(), name)
		}
	}
	d.res.Summary = fmt.Sprintf("Removed the database %s.", name)
	return nil
}

// inventory lists the databases and users. Names, sizes and settings only:
// password hashes are reduced to their kind in SQL and never read.
func (d *dbaRun) inventory(ctx context.Context) (*protocol.DBInventory, error) {
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: string(d.s.flavor), Port: d.s.db.Port, AgentUser: d.me.display()}
	vars := map[string]string{}
	rows, err := d.db.QueryContext(ctx, `SHOW GLOBAL VARIABLES WHERE Variable_name IN
		('version', 'have_ssl', 'ssl_cert', 'bind_address', 'skip_networking', 'character_set_server', 'collation_server')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		vars[strings.ToLower(k)] = v
	}
	rows.Close()
	inv.ServerVersion, _ = numericVersion(vars["version"])
	inv.SSL = vars["have_ssl"] == "YES" || (vars["have_ssl"] == "" && vars["ssl_cert"] != "")
	inv.DefaultLocale = vars["collation_server"]

	// Databases with their sizes and open connections.
	sizes := map[string]int64{}
	if rows, err := d.db.QueryContext(ctx, `SELECT TABLE_SCHEMA, CAST(IFNULL(SUM(DATA_LENGTH + INDEX_LENGTH), 0) AS SIGNED)
		FROM information_schema.TABLES GROUP BY TABLE_SCHEMA`); err == nil {
		for rows.Next() {
			var n string
			var b int64
			if rows.Scan(&n, &b) == nil {
				sizes[n] = b
			}
		}
		rows.Close()
	}
	conns := map[string]int{}
	userConns := map[string]int{}
	clients := map[string]int{}
	if rows, err := d.db.QueryContext(ctx, `SELECT IFNULL(DB, ''), USER, HOST FROM information_schema.PROCESSLIST WHERE COMMAND <> 'Daemon'`); err == nil {
		for rows.Next() {
			var n, u, h string
			if rows.Scan(&n, &u, &h) == nil {
				conns[n]++
				userConns[u]++
				if i := strings.LastIndex(h, ":"); i > 0 {
					h = h[:i]
				}
				if h != "" && h != "localhost" {
					clients[h]++
				}
			}
		}
		rows.Close()
	}
	rows, err = d.db.QueryContext(ctx, `SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME
		FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME LIMIT 501`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var x protocol.DBDatabase
		if err := rows.Scan(&x.Name, &x.Encoding, &x.Collation); err != nil {
			rows.Close()
			return nil, err
		}
		x.SizeBytes, x.Connections, x.AllowConnections = sizes[x.Name], conns[x.Name], true
		x.System = protocol.SystemDatabaseFor(string(d.s.flavor), x.Name)
		inv.Databases = append(inv.Databases, x)
	}
	rows.Close()
	if len(inv.Databases) > 500 {
		inv.Databases, inv.Truncated = inv.Databases[:500], true
	}

	// Which databases each user may use (database-level grants).
	type dbGrant struct{ db, create, sel, ins string }
	grants := map[dbaUser][]dbGrant{}
	if rows, err := d.db.QueryContext(ctx, "SELECT User, Host, Db, Create_priv, Select_priv, Insert_priv FROM mysql.db ORDER BY Db"); err == nil {
		for rows.Next() {
			var u dbaUser
			var g dbGrant
			if rows.Scan(&u.user, &u.host, &g.db, &g.create, &g.sel, &g.ins) == nil {
				g.db = strings.ReplaceAll(g.db, `\_`, "_")
				grants[u] = append(grants[u], g)
			}
		}
		rows.Close()
	}
	owners := map[string][]string{}

	locked := "'N'"
	role := "'N'"
	if d.s.flavor.mariadb() {
		role = "is_role"
	} else {
		locked = "account_locked"
	}
	rows, err = d.db.QueryContext(ctx, `SELECT User, Host, IFNULL(plugin, ''), IFNULL(authentication_string, '') = '', `+locked+`, `+role+`,
		Super_priv, Create_priv, Create_user_priv, Repl_slave_priv FROM mysql.user ORDER BY User, Host LIMIT 501`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var u dbaUser
		var plugin, lockedV, roleV, super, create, createUser, repl string
		var empty bool
		if err := rows.Scan(&u.user, &u.host, &plugin, &empty, &lockedV, &roleV, &super, &create, &createUser, &repl); err != nil {
			rows.Close()
			return nil, err
		}
		if roleV == "Y" {
			continue
		}
		x := protocol.DBUser{Name: u.display(), Login: lockedV != "Y", Superuser: super == "Y", CreateDB: create == "Y",
			CreateRole: createUser == "Y", Replication: repl == "Y", Connections: userConns[u.user]}
		x.Password = passwordKind(plugin, empty)
		for _, g := range grants[u] {
			x.Databases = append(x.Databases, g.db)
			if g.create == "Y" {
				x.Owns = append(x.Owns, g.db)
				owners[g.db] = append(owners[g.db], x.Name)
			}
		}
		if super == "Y" {
			x.Databases = []string{"every database"}
		}
		if why := d.protectedReason(u, super == "Y"); why != "" {
			x.System, x.SystemReason = true, upperFirst(why)
		}
		inv.Users = append(inv.Users, x)
	}
	rows.Close()
	if len(inv.Users) > 500 {
		inv.Users, inv.Truncated = inv.Users[:500], true
	}
	for i := range inv.Databases {
		o := owners[inv.Databases[i].Name]
		sort.Strings(o)
		inv.Databases[i].Owner = strings.Join(o, ", ")
	}

	listen := vars["bind_address"]
	if listen == "" {
		listen = "*" // MariaDB: every address
	}
	if strings.EqualFold(vars["skip_networking"], "ON") {
		listen = "localhost"
	}
	inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(listen, clients)
	if why, err := d.manageBlocked(ctx); err == nil && why != "" {
		inv.ManageBlocked, inv.ManageCommand = why, d.manageCommand()
	}
	return inv, nil
}

// passwordKind maps an authentication plugin to protocol.Password*.
func passwordKind(plugin string, empty bool) string {
	switch plugin {
	case "auth_socket", "unix_socket":
		return protocol.PasswordSocket
	case "mysql_native_password", "mysql_old_password":
		if empty {
			return protocol.PasswordNone
		}
		return protocol.PasswordWeak
	case "", "caching_sha2_password", "sha256_password", "ed25519", "parsec":
		if empty {
			return protocol.PasswordNone
		}
		return protocol.PasswordSet
	}
	return protocol.PasswordSet // PAM, LDAP...: someone else checks the password
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
