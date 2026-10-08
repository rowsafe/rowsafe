package clickhouse

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users (dbadmin tasks) for ClickHouse: create and remove
// databases and users, and give users access to databases, with SQL
// (CREATE DATABASE, CREATE USER, GRANT), when a person asks for it in the
// dashboard or the CLI. ClickHouse manages users with SQL only when it has
// a writable user directory (local_directory, on by default) and the
// signed-in user has access management; users defined in its
// configuration files (users.xml, users.d) are listed but never changed.
// Passwords are generated here, stored by ClickHouse as SHA-256, and leave
// the server only sealed to the requester's key.

// Privileges per access level, on `db`.*.
const (
	chReadOnly  = "SELECT, SHOW TABLES, SHOW COLUMNS"
	chReadWrite = "SELECT, SHOW TABLES, SHOW COLUMNS, INSERT, ALTER UPDATE, ALTER DELETE"
	chOwner     = "SELECT, SHOW TABLES, SHOW COLUMNS, SHOW DICTIONARIES, INSERT, ALTER, CREATE TABLE, CREATE VIEW, CREATE DICTIONARY, " +
		"DROP TABLE, DROP VIEW, DROP DICTIONARY, TRUNCATE, OPTIMIZE"
)

// adminGrantsSQL are what Rowsafe's user needs for Databases & users (on
// *.*, given at install since it came to ClickHouse): the owner's
// privileges and creating and dropping databases, all WITH GRANT OPTION
// so it can pass them on, and managing users.
func adminGrantsSQL(user string) []string {
	return []string{
		"GRANT " + chOwner + ", CREATE DATABASE, DROP DATABASE ON *.* TO " + user + " WITH GRANT OPTION",
		"GRANT ACCESS MANAGEMENT ON *.* TO " + user,
	}
}

func chPrivileges(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return chReadOnly
	case protocol.DBAccessReadWrite:
		return chReadWrite
	}
	return chOwner
}

type chdba struct {
	env    agent.EngineEnv
	spec   protocol.DatabaseSpec
	c      *client
	p      protocol.DBAdminParams
	log    agent.TaskLogger
	res    *protocol.DBAdminResult
	me     string
	secret *protocol.DBConnection
	pw     string
}

func (e *Engine) dbadmin(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, log agent.TaskLogger) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdminFor(protocol.EngineClickHouse, p); err != nil {
		return nil, agent.Sentence(err)
	}
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, agent.Sentence(err)
	}
	d := &chdba{env: env, spec: db, c: c, p: p, log: log, res: &protocol.DBAdminResult{Action: p.Action}}
	if d.me, err = c.scalar(ctx, "SELECT currentUser()", nil); err != nil {
		return nil, agent.Sentence(err)
	}
	if p.Action != protocol.DBAdminList {
		if why, _, berr := d.manageBlocked(ctx); berr != nil {
			err = berr
		} else if why != "" {
			err = errors.New(why)
		}
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
			err = fmt.Errorf("ClickHouse has no %s", p.Action)
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
			d.res.Summary = fmt.Sprintf("%s and %s.", plural(len(inv.Databases), "database", "databases"), plural(len(inv.Users), "user", "users"))
		}
	}
	if err == nil && d.secret != nil {
		port, tls := d.nativePort(ctx)
		cn := agent.DBConnectionFor(*d.secret, p.Host, inv, port, tls)
		var sealed *protocol.SealedSecret
		if sealed, err = agent.SealDBSecret(p.PublicKey, taskID, cn, d.pw); err == nil {
			d.res.Secret, d.res.Connection = sealed, &cn
			log.Printf("the password for %s was encrypted for the person who asked; Rowsafe can't read it", cn.User)
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

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// nativePort is the port apps connect to with ClickHouse's native
// protocol (clickhouse:// URLs), and whether it needs TLS.
func (d *chdba) nativePort(ctx context.Context) (int, bool) {
	if v, err := d.c.scalar(ctx, "SELECT getServerPort('tcp_port')", nil); err == nil {
		var n int
		if _, err := fmt.Sscan(strings.TrimSpace(v), &n); err == nil && n > 0 {
			return n, false
		}
	}
	if v, err := d.c.scalar(ctx, "SELECT getServerPort('tcp_port_secure')", nil); err == nil {
		var n int
		if _, err := fmt.Sscan(strings.TrimSpace(v), &n); err == nil && n > 0 {
			return n, true
		}
	}
	return 9000, false
}

// sqlUsersConfig is the config.d file that turns on users managed with
// SQL (ClickHouse's default configuration has it; some don't).
const sqlUsersConfig = `<clickhouse><user_directories><local_directory><path>/var/lib/clickhouse/access/</path></local_directory></user_directories></clickhouse>`

// manageBlocked says why Rowsafe can't create databases and users here
// ("" when it can) and what root runs to allow it.
func (d *chdba) manageBlocked(ctx context.Context) (why, command string, err error) {
	n, err := d.c.scalar(ctx, "SELECT count() FROM system.user_directories WHERE type IN ('local_directory', 'replicated')", nil)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(n) == "0" {
		return "This ClickHouse server keeps its users only in its configuration files, so Rowsafe can list them but not create any. " +
				"Turn on users managed with SQL (a small configuration file, then a restart of ClickHouse) to create databases and users here.",
			"printf '%s\\n' '" + sqlUsersConfig + "' | sudo tee /etc/clickhouse-server/config.d/rowsafe-sql-users.xml && sudo systemctl restart clickhouse-server", nil
	}
	out, err := d.c.scalar(ctx, "SHOW GRANTS", nil)
	if err != nil {
		return "", "", err
	}
	if adminGrantsOK(out) {
		return "", "", nil
	}
	cmd := fmt.Sprintf("clickhouse-client --user <an administrator> --ask-password --multiquery --query \"%s\"",
		strings.Join(adminGrantsSQL(quoteIdent(d.me)), "; "))
	return fmt.Sprintf("Rowsafe's ClickHouse user (%s) can list databases and users but not create or change them: it was set up before Databases & users came to ClickHouse. "+
		"An administrator runs the command below once to give it the rights.", d.me), cmd, nil
}

// adminGrantsOK reads SHOW GRANTS: user management, and creating
// databases and tables with the right to pass it on.
func adminGrantsOK(showGrants string) bool {
	access, grantable := false, map[string]bool{}
	for _, line := range strings.Split(showGrants, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "GRANT ")
		if !ok {
			continue
		}
		list, target, ok := strings.Cut(rest, " ON ")
		if !ok || !strings.HasPrefix(target, "*.* ") && !strings.HasPrefix(target, "* ") {
			continue
		}
		withGrant := strings.HasSuffix(target, "WITH GRANT OPTION")
		for _, p := range strings.Split(list, ",") {
			p = strings.ToUpper(strings.TrimSpace(p))
			if p == "ALL" || p == "ACCESS MANAGEMENT" || p == "CREATE USER" {
				access = true
			}
			if withGrant {
				grantable[p] = true
			}
		}
	}
	can := func(p, group string) bool { return grantable["ALL"] || grantable[p] || grantable[group] }
	return access && can("CREATE DATABASE", "CREATE") && can("DROP DATABASE", "DROP") && can("SELECT", "SELECT") && can("CREATE TABLE", "CREATE")
}

type chUser struct {
	Name      string   `json:"name"`
	Storage   string   `json:"storage"`
	Auth      string   `json:"auth"`
	HostIP    []string `json:"host_ip"`
	HostNames []string `json:"host_names"`
	Roles     []string `json:"roles"`
}

func (d *chdba) user(ctx context.Context, name string) (*chUser, error) {
	us, err := query[chUser](ctx, d.c, "SELECT name, storage, toString(auth_type) AS auth, host_ip, host_names, default_roles_list AS roles FROM system.users WHERE name = {n:String}",
		map[string]string{"n": name})
	if err != nil || len(us) == 0 {
		return nil, err
	}
	return &us[0], nil
}

// protectedReason says why a user isn't changed from Rowsafe ("" when it
// may be).
func (d *chdba) protectedReason(u chUser, all bool) string {
	switch {
	case u.Name == d.me || u.Name == LoginUser:
		return "Rowsafe's own user"
	case u.Name == "default":
		return "ClickHouse's own user"
	case u.Storage != "local_directory" && u.Storage != "local directory" && u.Storage != "replicated":
		return "defined in ClickHouse's configuration files"
	case all:
		return "an administrator"
	}
	return ""
}

func (d *chdba) databaseExists(ctx context.Context, name string) (bool, error) {
	n, err := d.c.scalar(ctx, "SELECT count() FROM system.databases WHERE name = {n:String}", map[string]string{"n": name})
	return strings.TrimSpace(n) != "0", err
}

func (d *chdba) exec(ctx context.Context, shown, q string) error {
	if err := d.c.exec(ctx, q, nil); err != nil {
		return fmt.Errorf("%s: %s", shown, shortError(err))
	}
	d.log.Printf("%s", shown)
	return nil
}

// AppProfile is the settings profile the installer's --install-clickhouse
// defines for apps' users (memory and threads a query may use, with
// constraints so they can't raise them): users made in Databases & users
// get it where it exists (servers Rowsafe created).
const AppProfile = "rowsafe_app"

// createUserSQL creates name with a new password, signing in from
// anywhere (where ClickHouse listens and the firewall decide who reaches
// it), with the apps' settings profile where the server has one.
func (d *chdba) createUserSQL(ctx context.Context, name string) error {
	pw, err := agent.NewDBPassword()
	if err != nil {
		return err
	}
	d.pw = pw
	profile := ""
	if n, err := d.c.scalar(ctx, "SELECT count() FROM system.settings_profiles WHERE name = {n:String}", map[string]string{"n": AppProfile}); err == nil && strings.TrimSpace(n) != "0" {
		profile = " SETTINGS PROFILE " + quoteString(AppProfile)
	}
	return d.exec(ctx, "created the user "+name, "CREATE USER "+quoteIdent(name)+" IDENTIFIED WITH sha256_password BY "+quoteString(pw)+" HOST ANY"+profile)
}

func (d *chdba) createDatabase(ctx context.Context) error {
	p := d.p
	if ok, err := d.databaseExists(ctx, p.Database); err != nil || ok {
		if ok {
			return fmt.Errorf("a database named %s already exists", p.Database)
		}
		return err
	}
	owner := p.Owner
	if p.CreateOwner {
		owner = cmpOr(p.Owner, p.Database)
		if u, err := d.user(ctx, owner); err != nil || u != nil {
			if u != nil {
				return fmt.Errorf("a user named %s already exists: choose it as the owner instead", owner)
			}
			return err
		}
	} else {
		u, err := d.user(ctx, owner)
		if err == nil && u == nil {
			err = fmt.Errorf("there is no user %s", owner)
		}
		if err != nil {
			return err
		}
		if why := d.protectedReason(*u, false); why != "" {
			return fmt.Errorf("%s is %s; choose another owner", owner, why)
		}
	}
	if err := d.exec(ctx, "created the database "+p.Database, "CREATE DATABASE "+quoteIdent(p.Database)); err != nil {
		return err
	}
	undo := func() {
		if d.c.exec(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+quoteIdent(p.Database), nil) == nil {
			d.log.Printf("removed the new, empty database %s again", p.Database)
		}
	}
	if p.CreateOwner {
		if err := d.createUserSQL(ctx, owner); err != nil {
			undo()
			return err
		}
	}
	if err := d.exec(ctx, fmt.Sprintf("gave %s every right on %s", owner, p.Database),
		"GRANT "+chOwner+" ON "+quoteIdent(p.Database)+".* TO "+quoteIdent(owner)); err != nil {
		if p.CreateOwner {
			_ = d.c.exec(context.WithoutCancel(ctx), "DROP USER IF EXISTS "+quoteIdent(owner), nil)
		}
		undo()
		return err
	}
	if p.CreateOwner {
		d.secret = &protocol.DBConnection{Engine: protocol.EngineClickHouse, User: owner, Database: p.Database}
		d.res.Summary = fmt.Sprintf("Created the database %s and its user %s.", p.Database, owner)
	} else {
		d.res.Summary = fmt.Sprintf("Created the database %s; %s has every right on it.", p.Database, owner)
	}
	return nil
}

func (d *chdba) createUser(ctx context.Context) error {
	p := d.p
	if u, err := d.user(ctx, p.User); err != nil || u != nil {
		if u != nil {
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
	if err := d.createUserSQL(ctx, p.User); err != nil {
		return err
	}
	for _, name := range p.Databases {
		if err := d.exec(ctx, fmt.Sprintf("gave %s %s access to %s", p.User, accessWords(p.Access), name),
			"GRANT "+chPrivileges(p.Access)+" ON "+quoteIdent(name)+".* TO "+quoteIdent(p.User)); err != nil {
			_ = d.c.exec(context.WithoutCancel(ctx), "DROP USER IF EXISTS "+quoteIdent(p.User), nil)
			d.log.Printf("removed the new user %s again", p.User)
			return err
		}
	}
	d.secret = &protocol.DBConnection{Engine: protocol.EngineClickHouse, User: p.User, Database: p.Databases[0]}
	d.res.Summary = fmt.Sprintf("Created the user %s with %s access to %s.", p.User, accessWords(p.Access), strings.Join(p.Databases, ", "))
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

func (d *chdba) existingUser(ctx context.Context) (*chUser, error) {
	u, err := d.user(ctx, d.p.User)
	if err == nil && u == nil {
		err = fmt.Errorf("there is no user %s", d.p.User)
	}
	if err != nil {
		return nil, err
	}
	all, _ := d.hasAll(ctx, u.Name)
	if why := d.protectedReason(*u, all); why != "" {
		return nil, fmt.Errorf("%s is %s; Rowsafe doesn't change it", u.Name, why)
	}
	return u, nil
}

func (d *chdba) hasAll(ctx context.Context, name string) (bool, error) {
	n, err := d.c.scalar(ctx, "SELECT count() FROM system.grants WHERE user_name = {n:String} AND access_type IN ('ALL', 'ACCESS MANAGEMENT', 'CREATE USER') AND database IS NULL",
		map[string]string{"n": name})
	return strings.TrimSpace(n) != "0", err
}

func (d *chdba) resetPassword(ctx context.Context) error {
	u, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	pw, err := agent.NewDBPassword()
	if err != nil {
		return err
	}
	if err := d.exec(ctx, "gave "+u.Name+" a new password", "ALTER USER "+quoteIdent(u.Name)+" IDENTIFIED WITH sha256_password BY "+quoteString(pw)); err != nil {
		return err
	}
	d.pw = pw
	dbname, _ := d.c.scalar(ctx, "SELECT any(database) FROM system.grants WHERE user_name = {n:String} AND database IS NOT NULL",
		map[string]string{"n": u.Name})
	d.secret = &protocol.DBConnection{Engine: protocol.EngineClickHouse, User: u.Name, Database: cmpOr(strings.TrimSpace(dbname), "default")}
	d.res.Summary = fmt.Sprintf("Gave %s a new password; the old one stops working for new connections.", u.Name)
	return nil
}

func (d *chdba) dropUser(ctx context.Context) error {
	u, err := d.existingUser(ctx)
	if err != nil {
		return err
	}
	if err := d.exec(ctx, "removed the user "+u.Name, "DROP USER "+quoteIdent(u.Name)); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the user %s.", u.Name)
	return nil
}

func (d *chdba) dropDatabase(ctx context.Context) error {
	name := d.p.Database
	if ok, err := d.databaseExists(ctx, name); err != nil || !ok {
		if err == nil {
			err = fmt.Errorf("there is no database %s", name)
		}
		return err
	}
	type holder struct {
		User string `json:"user_name"`
	}
	holders, _ := query[holder](ctx, d.c, "SELECT DISTINCT user_name FROM system.grants WHERE database = {n:String} AND user_name IS NOT NULL",
		map[string]string{"n": name})
	if err := d.exec(ctx, "removed the database "+name, "DROP DATABASE "+quoteIdent(name)+" SYNC"); err != nil {
		return err
	}
	// Users' rights on it would apply again to a new database of the same
	// name: take them back.
	for _, h := range holders {
		if u, _ := d.user(ctx, h.User); u != nil && d.protectedReason(*u, false) == "" {
			if d.c.exec(ctx, "REVOKE ALL ON "+quoteIdent(name)+".* FROM "+quoteIdent(h.User), nil) == nil {
				d.log.Printf("took back %s's rights on %s", h.User, name)
			}
		}
	}
	d.res.Summary = fmt.Sprintf("Removed the database %s.", name)
	return nil
}

func (d *chdba) inventory(ctx context.Context) (*protocol.DBInventory, error) {
	inv := &protocol.DBInventory{CollectedAt: time.Now().UTC(), Engine: protocol.EngineClickHouse, AgentUser: d.me}
	v, err := d.c.scalar(ctx, "SELECT version()", nil)
	if err != nil {
		return nil, err
	}
	inv.ServerVersion = strings.TrimSpace(v)
	inv.Port, inv.SSL = d.nativePort(ctx)

	type dbRow struct {
		Name   string `json:"name"`
		Engine string `json:"engine"`
		Bytes  int64  `json:"bytes"`
		Conns  int    `json:"conns"`
	}
	dbs, err := query[dbRow](ctx, d.c, `SELECT d.name AS name, d.engine AS engine,
		toInt64(ifNull((SELECT sum(bytes_on_disk) FROM system.parts p WHERE p.active AND p.database = d.name), 0)) AS bytes,
		toInt32((SELECT count() FROM system.processes q WHERE q.current_database = d.name)) AS conns
		FROM system.databases d ORDER BY name LIMIT 501`, nil)
	if err != nil {
		// Older servers: no correlated subqueries.
		dbs, err = query[dbRow](ctx, d.c, "SELECT name, engine, toInt64(0) AS bytes, toInt32(0) AS conns FROM system.databases ORDER BY name LIMIT 501", nil)
		if err != nil {
			return nil, err
		}
	}
	for _, x := range dbs {
		inv.Databases = append(inv.Databases, protocol.DBDatabase{Name: x.Name, Encoding: x.Engine, SizeBytes: x.Bytes, Connections: x.Conns,
			AllowConnections: true, System: protocol.SystemDatabaseFor(protocol.EngineClickHouse, x.Name)})
	}
	if len(inv.Databases) > 500 {
		inv.Databases, inv.Truncated = inv.Databases[:500], true
	}

	type grantRow struct {
		User     string  `json:"user_name"`
		Access   string  `json:"access_type"`
		Database *string `json:"database"`
	}
	grants, _ := query[grantRow](ctx, d.c, "SELECT user_name, access_type, database FROM system.grants WHERE user_name IS NOT NULL", nil)
	users, err := query[chUser](ctx, d.c, "SELECT name, storage, toString(auth_type) AS auth, host_ip, host_names, default_roles_list AS roles FROM system.users ORDER BY name LIMIT 501", nil)
	if err != nil {
		return nil, err
	}
	owners := map[string][]string{}
	for _, u := range users {
		x := protocol.DBUser{Name: u.Name, Login: true, MemberOf: u.Roles}
		x.Password = chPasswordKind(u.Auth)
		all := false
		for _, g := range grants {
			if g.User != u.Name {
				continue
			}
			if g.Database == nil {
				if g.Access == "ALL" || g.Access == "ACCESS MANAGEMENT" || g.Access == "CREATE USER" {
					all, x.Superuser = true, true
				}
				if g.Access == "CREATE DATABASE" || g.Access == "CREATE" || g.Access == "ALL" {
					x.CreateDB = true
				}
				if g.Access == "ACCESS MANAGEMENT" || g.Access == "CREATE USER" || g.Access == "ALL" {
					x.CreateRole = true
				}
				if !slices.Contains(x.Databases, "every database") && (g.Access == "ALL" || g.Access == "SELECT") {
					x.Databases = append(x.Databases, "every database")
				}
				continue
			}
			if !slices.Contains(x.Databases, *g.Database) {
				x.Databases = append(x.Databases, *g.Database)
			}
			if (g.Access == "CREATE TABLE" || g.Access == "ALL") && !slices.Contains(x.Owns, *g.Database) {
				x.Owns = append(x.Owns, *g.Database)
				owners[*g.Database] = append(owners[*g.Database], u.Name)
			}
		}
		if why := d.protectedReason(u, all); why != "" {
			x.System, x.SystemReason = true, strings.ToUpper(why[:1])+why[1:]
		}
		inv.Users = append(inv.Users, x)
	}
	if len(inv.Users) > 500 {
		inv.Users, inv.Truncated = inv.Users[:500], true
	}
	for i := range inv.Databases {
		o := owners[inv.Databases[i].Name]
		sort.Strings(o)
		inv.Databases[i].Owner = strings.Join(o, ", ")
	}
	clients := map[string]int{}
	type clientRow struct {
		Addr string `json:"addr"`
		N    int    `json:"n"`
	}
	if rows, err := query[clientRow](ctx, d.c, "SELECT IPv6NumToString(address) AS addr, toInt32(count()) AS n FROM system.processes GROUP BY addr", nil); err == nil {
		for _, r := range rows {
			clients[strings.TrimPrefix(r.Addr, "::ffff:")] += r.N
		}
	}
	inv.Addresses, inv.SuggestedHost, inv.LocalOnly = agent.DBServerAddresses(listenHosts(), clients)
	if why, cmd, err := d.manageBlocked(ctx); err == nil && why != "" {
		inv.ManageBlocked, inv.ManageCommand = why, cmd
	}
	return inv, nil
}

// chPasswordKind maps system.users.auth_type ("sha256_password",
// "['sha256_password']" on servers with several methods) to
// protocol.Password*.
func chPasswordKind(auth string) string {
	switch {
	case strings.Contains(auth, "no_password"):
		return protocol.PasswordNone
	case strings.Contains(auth, "plaintext_password"), strings.Contains(auth, "double_sha1_password"):
		return protocol.PasswordWeak
	}
	return protocol.PasswordSet
}

// listenHosts is where ClickHouse listens (comma-separated listen_host of
// its configuration; "*" in Docker, where its image listens on every
// address of its own network; "" is localhost, ClickHouse's default).
func listenHosts() string {
	if inDocker() {
		return "*"
	}
	files := []string{defaultConfig}
	m, _ := filepath.Glob(filepath.Join(filepath.Dir(defaultConfig), "config.d", "*.xml"))
	slices.Sort(m)
	files = append(files, m...)
	var hosts []string
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if h := xmlListenHosts(data); len(h) > 0 {
			hosts = h // a later file's listen_host replaces earlier ones
		}
	}
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		switch h {
		case "::", "0.0.0.0":
			h = "*"
		}
		out = append(out, h)
	}
	return strings.Join(out, ",")
}

// xmlListenHosts reads every <listen_host> directly under the root.
func xmlListenHosts(data []byte) []string {
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	depth := 0
	var out []string
	var cur string
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				cur = t.Name.Local
				text.Reset()
			}
		case xml.CharData:
			if depth == 2 {
				text.Write(t)
			}
		case xml.EndElement:
			if depth == 2 && cur == "listen_host" {
				if v := strings.TrimSpace(text.String()); v != "" {
					out = append(out, v)
				}
			}
			depth--
		}
	}
}
