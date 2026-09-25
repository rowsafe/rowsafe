package agent

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users (dbadmin tasks): create and remove databases, users and
// extensions inside the PostgreSQL server, when a person asks for it in the
// dashboard or the CLI. Like health fixes, the control plane sends names,
// never SQL: every name is checked (protocol.ValidateDBAdmin), looked up in
// the catalogs with query parameters, and statements are built by
// PostgreSQL itself with format('%I', ...) / format('%L', ...).
//
// Passwords are generated here, stored by PostgreSQL as a SCRAM-SHA-256
// verifier computed here (so the password is never in a statement, the
// server log or pg_stat_statements), and leave this host only sealed to the
// requester's public key (protocol.Seal).

// dbaAppName is the application_name of the agent's dbadmin sessions.
const dbaAppName = "rowsafe-agent-dbadmin"

// dbaSettings are applied to every dbadmin session: DDL never queues
// behind a long transaction (and makes everything else queue behind it).
var dbaSettings = map[string]string{
	"lock_timeout":      ddlLockTimeout,
	"statement_timeout": "2min",
}

// Inventory limits.
const (
	maxInventoryItems   = 500 // databases, users
	maxExtensionScans   = 100 // databases whose installed extensions are read
	extensionScanBudget = 5 * time.Second
)

// runDBAdmin decodes a dbadmin task and runs it, keeping a typed nil result
// out of the interface.
func (a *Agent) runDBAdmin(ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec) (any, error) {
	var p protocol.DBAdminParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid dbadmin params: %w", err)
	}
	res, err := a.dbadmin(ctx, db, task.ID, p, tl)
	if res == nil {
		return nil, err
	}
	return res, err
}

type dba struct {
	t      pginspect.Target
	spec   protocol.DatabaseSpec
	p      protocol.DBAdminParams
	tl     *taskLog
	res    *protocol.DBAdminResult
	me     string // the agent's own role
	vnum   int    // server_version_num
	ssl    bool
	secret *protocol.DBConnection // the user and database a new password is for
	pw     string
}

// dbadmin runs one Databases & users action.
func (a *Agent) dbadmin(ctx context.Context, db protocol.DatabaseSpec, taskID string, p protocol.DBAdminParams, tl *taskLog) (*protocol.DBAdminResult, error) {
	if err := protocol.ValidateDBAdmin(p); err != nil {
		return nil, sentence(err)
	}
	start := time.Now()
	t := a.target(db)
	t.AppName = dbaAppName
	d := &dba{t: t, spec: db, p: p, tl: tl, res: &protocol.DBAdminResult{Action: p.Action}}
	conn, err := d.connectAny(ctx)
	if err != nil {
		return nil, sentence(err)
	}
	defer closeConn(ctx, conn)
	if err := conn.QueryRow(ctx, `SELECT current_user::text, current_setting('server_version_num')::int, current_setting('ssl') = 'on'`).
		Scan(&d.me, &d.vnum, &d.ssl); err != nil {
		return nil, sentence(err)
	}
	if p.Action != protocol.DBAdminList {
		err = requirePrimary(ctx, conn)
	}
	if err == nil {
		switch p.Action {
		case protocol.DBAdminList:
		case protocol.DBAdminCreateDatabase:
			err = d.createDatabase(ctx, conn)
		case protocol.DBAdminCreateUser:
			err = d.createUser(ctx, conn)
		case protocol.DBAdminResetPassword:
			err = d.resetPassword(ctx, conn)
		case protocol.DBAdminDropUser:
			err = d.dropUser(ctx, conn)
		case protocol.DBAdminEnableExtension:
			err = d.enableExtension(ctx, conn)
		case protocol.DBAdminDisableExtension:
			err = d.disableExtension(ctx, conn)
		case protocol.DBAdminDropDatabase:
			err = d.dropDatabase(ctx, conn)
		}
	}

	// The list after the action, also after a failure, so the dashboard
	// shows what is there now.
	inv, ierr := dbInventory(ctx, t, conn, db.Port, d.me)
	if ierr != nil {
		tl.Printf("couldn't read the databases and users afterwards: %v", ierr)
		if p.Action == protocol.DBAdminList && err == nil {
			err = ierr
		}
	} else {
		d.res.Inventory = inv
		if p.Action == protocol.DBAdminList {
			d.res.Summary = fmt.Sprintf("%s and %s.", countNoun(len(inv.Databases), "database", "databases"),
				countNoun(len(inv.Users), "user", "users"))
		}
	}
	if err == nil && d.secret != nil {
		err = d.seal(taskID, inv)
	}
	d.res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		err = sentence(err)
		tl.Printf("failed: %v", err)
	} else {
		tl.Printf("%s", d.res.Summary)
	}
	return d.res, err
}

// connectAny opens the session actions start from: the postgres database,
// or template1 where postgres was removed.
func (d *dba) connectAny(ctx context.Context) (*pgx.Conn, error) {
	conn, err := d.connect(ctx, "postgres")
	var pe *pgconn.PgError
	if err != nil && errors.As(err, &pe) && pe.Code == "3D000" {
		conn, err = d.connect(ctx, "template1")
	}
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL: %w", err)
	}
	return conn, nil
}

// connect opens a session to dbname with dbaSettings (as parameters).
func (d *dba) connect(ctx context.Context, dbname string) (*pgx.Conn, error) {
	conn, err := d.t.Connect(ctx, dbname)
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"lock_timeout", "statement_timeout"} {
		if _, err := conn.Exec(ctx, `SELECT set_config($1, $2, false)`, k, dbaSettings[k]); err != nil {
			closeConn(ctx, conn)
			return nil, fmt.Errorf("setting %s: %w", k, err)
		}
	}
	return conn, nil
}

// connectDB opens a session to an existing database, in plain words when it
// is gone.
func (d *dba) connectDB(ctx context.Context, dbname string) (*pgx.Conn, error) {
	conn, err := d.connect(ctx, dbname)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "3D000" {
			return nil, fmt.Errorf("the database %s no longer exists", dbname)
		}
		return nil, fmt.Errorf("connecting to the database %s: %w", dbname, err)
	}
	return conn, nil
}

// querier is a session or a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// sqlf builds a statement with PostgreSQL's format(): %I quotes an
// identifier, %L a literal. Only constants are ever passed as the format.
func sqlf(ctx context.Context, q querier, format string, args ...string) (string, error) {
	if args == nil {
		args = []string{}
	}
	var s string
	err := q.QueryRow(ctx, `SELECT format($1::text, VARIADIC $2::text[])`, format, args).Scan(&s)
	return s, err
}

// exec builds a statement with sqlf, logs it (or shown instead, for
// statements with a password verifier) and runs it.
func (d *dba) exec(ctx context.Context, q querier, shown, format string, args ...string) error {
	stmt, err := sqlf(ctx, q, format, args...)
	if err != nil {
		return err
	}
	if shown == "" {
		shown = stmt
	}
	d.tl.Printf("%s", shown)
	if _, err := q.Exec(ctx, stmt); err != nil {
		if isLockTimeout(err) {
			return fmt.Errorf("something else is using it right now (another change is waiting on a lock); try again in a minute")
		}
		return plainPGError(err)
	}
	return nil
}

// withoutTimeout runs fn with statement_timeout off (CREATE and DROP
// DATABASE copy and delete files; the task's own timeout still applies).
func withoutTimeout(ctx context.Context, conn *pgx.Conn, fn func() error) error {
	if _, err := conn.Exec(ctx, `SELECT set_config('statement_timeout', '0', false)`); err != nil {
		return err
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT set_config('statement_timeout', $1, false)`, dbaSettings["statement_timeout"]) //nolint:errcheck
	return fn()
}

// ---- passwords ----

// passwordAlphabet: letters and digits only, so a password needs no
// escaping in a URL, a shell or a .env file. 32 of them are ~190 bits.
const passwordAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

const passwordLength = 32

// newPassword returns a random password (crypto/rand, no modulo bias).
func newPassword() (string, error) {
	out := make([]byte, 0, passwordLength)
	buf := make([]byte, 64)
	limit := byte(256 - 256%len(passwordAlphabet))
	for len(out) < passwordLength {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if b < limit && len(out) < passwordLength {
				out = append(out, passwordAlphabet[int(b)%len(passwordAlphabet)])
			}
		}
	}
	return string(out), nil
}

// scramIterations is PostgreSQL's default scram_iterations.
const scramIterations = 4096

// scramVerifier computes the SCRAM-SHA-256 verifier PostgreSQL stores for
// password (RFC 5802/7677, as libpq's PQencryptPasswordConn). PostgreSQL
// accepts it in CREATE/ALTER ROLE ... PASSWORD and stores it as is, so the
// password itself never reaches the server. Generated passwords are ASCII
// letters and digits, which SASLprep leaves unchanged.
func scramVerifier(password string, salt []byte) (string, error) {
	salted, err := pbkdf2.Key(sha256.New, password, salt, scramIterations, sha256.Size)
	if err != nil {
		return "", err
	}
	mac := func(key []byte, msg string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(msg))
		return h.Sum(nil)
	}
	stored := sha256.Sum256(mac(salted, "Client Key"))
	server := mac(salted, "Server Key")
	enc := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", scramIterations, enc(salt), enc(stored[:]), enc(server)), nil
}

// newCredential returns a new password and its verifier.
func newCredential() (password, verifier string, err error) {
	if password, err = newPassword(); err != nil {
		return "", "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	verifier, err = scramVerifier(password, salt)
	return password, verifier, err
}

// seal encrypts the new password and connection string to the requester's
// key, bound to the task.
func (d *dba) seal(taskID string, inv *protocol.DBInventory) error {
	c := *d.secret
	c.Port = d.spec.Port
	c.SSLMode = "prefer"
	if d.ssl {
		c.SSLMode = "require"
	}
	c.Host = d.p.Host
	if c.Host == "" && inv != nil {
		c.Host = inv.SuggestedHost
	}
	if c.Host == "" {
		c.Host = "localhost"
	}
	secret := protocol.DBSecret{DBConnection: c, Password: d.pw, URL: protocol.ConnectionURL(c, d.pw)}
	plain, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	sealed, err := protocol.Seal(d.p.PublicKey, []byte(taskID), plain)
	if err != nil {
		return fmt.Errorf("the password was set but couldn't be encrypted for you (%v); reset it to get a new one", err)
	}
	d.res.Secret = sealed
	d.res.Connection = &c
	d.tl.Printf("the password for %s was encrypted for the person who asked; Rowsafe can't read it", c.User)
	return nil
}

// ---- catalog lookups ----

type roleInfo struct {
	oid          uint32
	name         string
	super, login bool
	validUntil   *time.Time
}

func lookupRole(ctx context.Context, q querier, name string) (roleInfo, bool, error) {
	var r roleInfo
	err := q.QueryRow(ctx, `SELECT oid, rolname::text, rolsuper, rolcanlogin, CASE WHEN isfinite(rolvaliduntil) THEN rolvaliduntil END FROM pg_roles WHERE rolname = $1`, name).
		Scan(&r.oid, &r.name, &r.super, &r.login, &r.validUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, false, nil
	}
	return r, err == nil, err
}

// protectedRole says why Rowsafe leaves a role alone, or "".
func protectedRole(name string, super bool, me string) string {
	switch {
	case name == me:
		return "it is the user Rowsafe's agent connects as"
	case strings.HasPrefix(name, "pg_"):
		return "it is built into PostgreSQL"
	case strings.HasPrefix(name, "rowsafe"):
		return "it is Rowsafe's own"
	case super:
		return "it is a superuser"
	}
	return ""
}

type dbInfo struct {
	oid        uint32
	name       string
	allowConn  bool
	isTemplate bool
	owner      string
	ownerSuper bool
}

func lookupDatabase(ctx context.Context, q querier, name string) (dbInfo, bool, error) {
	var d dbInfo
	err := q.QueryRow(ctx, `
		SELECT d.oid, d.datname::text, d.datallowconn, d.datistemplate, r.rolname::text, r.rolsuper
		FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datname = $1`, name).
		Scan(&d.oid, &d.name, &d.allowConn, &d.isTemplate, &d.owner, &d.ownerSuper)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, false, nil
	}
	return d, err == nil, err
}

// usableDatabase finds a database users can be given access to.
func usableDatabase(ctx context.Context, q querier, name string) (dbInfo, error) {
	db, ok, err := lookupDatabase(ctx, q, name)
	switch {
	case err != nil:
		return db, err
	case !ok:
		return db, fmt.Errorf("there is no database named %s", name)
	case !db.allowConn || db.isTemplate:
		return db, fmt.Errorf("the database %s is a template or doesn't accept connections", name)
	}
	return db, nil
}

func availableExtensions(ctx context.Context, q querier) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT name::text, coalesce(default_version, '') FROM pg_available_extensions`)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var name, ver string
	_, err = pgx.ForEachRow(rows, []any{&name, &ver}, func() error {
		out[name] = ver
		return nil
	})
	return out, err
}

func installedExtensions(ctx context.Context, q querier) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT extname::text, extversion FROM pg_extension`)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	var name, ver string
	_, err = pgx.ForEachRow(rows, []any{&name, &ver}, func() error {
		out[name] = ver
		return nil
	})
	return out, err
}

func notAvailable(ext string) error {
	return fmt.Errorf("PostgreSQL on this server doesn't have the %s extension: it comes in a separate package that has to be installed on the server first", ext)
}

// userSchemas are a database's schemas other than PostgreSQL's own.
const userSchemaSQL = `n.nspname NOT LIKE 'pg\_%' AND n.nspname <> 'information_schema'`

// ---- create a database ----

func (d *dba) createDatabase(ctx context.Context, conn *pgx.Conn) error {
	p := d.p
	if _, exists, err := lookupDatabase(ctx, conn, p.Database); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("a database named %s already exists", p.Database)
	}
	owner := p.Owner
	if p.CreateOwner {
		if owner == "" {
			owner = p.Database
		}
		if _, exists, err := lookupRole(ctx, conn, owner); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("a user named %s already exists: choose it as the owner under More options, or pick another name", owner)
		}
	} else {
		r, ok, err := lookupRole(ctx, conn, owner)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("there is no user named %s to own the database", owner)
		}
		if strings.HasPrefix(r.name, "pg_") {
			return fmt.Errorf("the role %s is built into PostgreSQL and can't own a database", r.name)
		}
	}
	avail, err := availableExtensions(ctx, conn)
	if err != nil {
		return err
	}
	for _, e := range p.Extensions {
		if _, ok := avail[e]; !ok {
			return notAvailable(e)
		}
	}

	// UTF8, in the server's locale unless another is asked for. template1
	// can only be copied with its own encoding and locale.
	template := cmpOr(p.Template, protocol.DBTemplateDefault)
	var tmplEnc, tmplColl string
	if err := conn.QueryRow(ctx, `SELECT pg_encoding_to_char(encoding)::text, datcollate::text FROM pg_database WHERE datname = 'template1'`).
		Scan(&tmplEnc, &tmplColl); err != nil {
		return err
	}
	if template == protocol.DBTemplateDefault && (tmplEnc != "UTF8" || (p.Locale != "" && p.Locale != tmplColl)) {
		template = protocol.DBTemplateEmpty
		d.tl.Printf("using template0: template1 is %s/%s, the new database is UTF8/%s", tmplEnc, tmplColl, cmpOr(p.Locale, tmplColl))
	}

	var createdRole bool
	cleanup := func(dropDB bool) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		if dropDB {
			if err := withoutTimeout(cctx, conn, func() error {
				return d.exec(cctx, conn, "", `DROP DATABASE IF EXISTS %I`, p.Database)
			}); err != nil {
				d.tl.Printf("cleaning up: %v", err)
			}
		}
		if createdRole {
			if err := d.exec(cctx, conn, "", `DROP ROLE IF EXISTS %I`, owner); err != nil {
				d.tl.Printf("cleaning up: %v", err)
			}
		}
	}

	if p.CreateOwner {
		pw, verifier, err := newCredential()
		if err != nil {
			return err
		}
		if err := d.exec(ctx, conn, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '(encrypted)'", owner),
			`CREATE ROLE %I LOGIN PASSWORD %L`, owner, verifier); err != nil {
			return fmt.Errorf("creating the user %s: %w", owner, err)
		}
		createdRole = true
		d.pw = pw
	}

	format := `CREATE DATABASE %I OWNER %I TEMPLATE %I ENCODING 'UTF8'`
	args := []string{p.Database, owner, template}
	if p.Locale != "" {
		format += ` LC_COLLATE %L LC_CTYPE %L`
		args = append(args, p.Locale, p.Locale)
	}
	if err := withoutTimeout(ctx, conn, func() error { return d.exec(ctx, conn, "", format, args...) }); err != nil {
		cleanup(false)
		if createdRole {
			return fmt.Errorf("creating the database: %w. Rowsafe removed the new user again, so nothing was left behind", err)
		}
		return fmt.Errorf("creating the database: %w", err)
	}

	// Inside the new database: the owner owns the public schema and only
	// it may create objects there (PostgreSQL 15's default, also on older
	// versions); the extensions.
	var added []string
	err = func() error {
		nconn, err := d.connectDB(ctx, p.Database)
		if err != nil {
			return err
		}
		defer closeConn(ctx, nconn)
		tx, err := nconn.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
		var hasPublic bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'public')`).Scan(&hasPublic); err != nil {
			return err
		}
		if hasPublic {
			if err := d.exec(ctx, tx, "", `ALTER SCHEMA public OWNER TO %I`, owner); err != nil {
				return err
			}
			if err := d.exec(ctx, tx, "", `REVOKE CREATE ON SCHEMA public FROM PUBLIC`); err != nil {
				return err
			}
		}
		before, err := installedExtensions(ctx, tx)
		if err != nil {
			return err
		}
		for _, e := range p.Extensions {
			if err := d.exec(ctx, tx, "", `CREATE EXTENSION IF NOT EXISTS %I CASCADE`, e); err != nil {
				return fmt.Errorf("enabling %s: %w", e, err)
			}
		}
		after, err := installedExtensions(ctx, tx)
		if err != nil {
			return err
		}
		for name := range after {
			if _, ok := before[name]; !ok {
				added = append(added, name)
			}
		}
		slices.Sort(added)
		return tx.Commit(ctx)
	}()
	if err == nil {
		// Only the owner (and superusers) may connect.
		if err = d.exec(ctx, conn, "", `REVOKE CONNECT, TEMPORARY ON DATABASE %I FROM PUBLIC`, p.Database); err == nil {
			err = d.exec(ctx, conn, "", `GRANT CONNECT, TEMPORARY ON DATABASE %I TO %I`, p.Database, owner)
		}
	}
	if err != nil {
		cleanup(true)
		return fmt.Errorf("%w. Rowsafe removed the half-made database again, so nothing was left behind", err)
	}

	if p.CreateOwner {
		d.res.Summary = fmt.Sprintf("Created the database %s, owned by the new user %s. It is backed up with the rest of the server from now on.", p.Database, owner)
		d.secret = &protocol.DBConnection{User: owner, Database: p.Database}
		if others, err := publicDatabases(ctx, conn); err == nil && len(others) > 0 {
			d.res.Details = append(d.res.Details, fmt.Sprintf("Like every user, %s can also connect to %s, which %s open to everyone, but it can't read anything there it wasn't given.",
				owner, listSome(others, 3), plural(len(others), "is", "are")))
		}
	} else {
		d.res.Summary = fmt.Sprintf("Created the database %s, owned by %s. It is backed up with the rest of the server from now on.", p.Database, owner)
	}
	if len(added) > 0 {
		d.res.Details = append(d.res.Details, "Extensions enabled: "+strings.Join(added, ", ")+".")
	}
	return nil
}

// publicDatabases are the databases every user may connect to.
func publicDatabases(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT datname::text FROM pg_database
		WHERE datallowconn AND NOT datistemplate
		  AND (datacl IS NULL OR EXISTS (SELECT 1 FROM aclexplode(datacl) a WHERE a.grantee = 0 AND a.privilege_type = 'CONNECT'))
		ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- create a user ----

func (d *dba) createUser(ctx context.Context, conn *pgx.Conn) error {
	p := d.p
	if _, exists, err := lookupRole(ctx, conn, p.User); err != nil {
		return err
	} else if exists {
		return fmt.Errorf("a user named %s already exists", p.User)
	}
	var dbs []dbInfo
	for _, name := range p.Databases {
		db, err := usableDatabase(ctx, conn, name)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(dbs, func(x dbInfo) bool { return x.oid == db.oid }) {
			dbs = append(dbs, db)
		}
	}
	pw, verifier, err := newCredential()
	if err != nil {
		return err
	}
	if err := d.exec(ctx, conn, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '(encrypted)'", p.User),
		`CREATE ROLE %I LOGIN PASSWORD %L`, p.User, verifier); err != nil {
		return fmt.Errorf("creating the user %s: %w", p.User, err)
	}
	tables := 0
	var touched []string
	for _, db := range dbs {
		touched = append(touched, db.name)
		n, err := d.grantAccess(ctx, conn, db, p.User, p.Access)
		if err != nil {
			d.removeNewRole(ctx, conn, p.User, touched)
			return fmt.Errorf("giving %s access to %s: %w. Rowsafe removed the new user again, so nothing was left behind", p.User, db.name, err)
		}
		tables += n
	}
	d.pw = pw
	d.secret = &protocol.DBConnection{User: p.User, Database: dbs[0].name}
	names := make([]string, len(dbs))
	for i, db := range dbs {
		names[i] = db.name
	}
	d.res.Summary = fmt.Sprintf("Created the user %s with %s access to %s (%s).", p.User, accessWords(p.Access),
		joinAnd(names), countNoun(tables, "table", "tables"))
	d.res.Details = append(d.res.Details, accessDetail(p.Access))
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

func accessDetail(access string) string {
	switch access {
	case protocol.DBAccessReadOnly:
		return "It can read every table, including tables the database's owner creates later, and change nothing."
	case protocol.DBAccessReadWrite:
		return "It can read, add, change and delete rows in every table, including tables the database's owner creates later, but not change the tables themselves."
	}
	return "It can do everything the database's owner can: read and write rows, and create and change tables."
}

// listSome joins at most n names: "a, b, c and 4 more".
func listSome(xs []string, n int) string {
	if len(xs) <= n {
		return joinAnd(xs)
	}
	return strings.Join(xs[:n], ", ") + fmt.Sprintf(" and %d more", len(xs)-n)
}

func joinAnd(xs []string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " and " + xs[len(xs)-1]
}

// removeNewRole undoes a user created by this task.
func (d *dba) removeNewRole(ctx context.Context, conn *pgx.Conn, user string, dbs []string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	for _, name := range dbs {
		c, err := d.connectDB(cctx, name)
		if err != nil {
			d.tl.Printf("cleaning up: %v", err)
			continue
		}
		if err := d.exec(cctx, c, "", `DROP OWNED BY %I`, user); err != nil {
			d.tl.Printf("cleaning up: %v", err)
		}
		closeConn(cctx, c)
	}
	if err := d.exec(cctx, conn, "", `DROP OWNED BY %I`, user); err != nil {
		d.tl.Printf("cleaning up: %v", err)
	}
	if err := d.exec(cctx, conn, "", `DROP ROLE IF EXISTS %I`, user); err != nil {
		d.tl.Printf("cleaning up: %v", err)
	}
}

// Privileges per access level. Constants only: they are part of format
// strings.
var accessPrivileges = map[string]struct{ schema, tables, sequences string }{
	protocol.DBAccessReadOnly:  {"USAGE", "SELECT", "SELECT"},
	protocol.DBAccessReadWrite: {"USAGE", "SELECT, INSERT, UPDATE, DELETE", "USAGE, SELECT, UPDATE"},
	protocol.DBAccessOwner:     {"USAGE, CREATE", "ALL", "ALL"},
}

// maxCreators caps the roles whose future tables a new user gets access to.
const maxCreators = 20

// grantAccess gives user access to one database: CONNECT, and in every
// schema the privileges of its level on the tables and sequences there now
// and on those the database's owner (and the other roles that already
// create objects there) create later. It returns how many tables it
// covers.
func (d *dba) grantAccess(ctx context.Context, conn *pgx.Conn, db dbInfo, user, access string) (int, error) {
	dbPriv := "CONNECT, TEMPORARY"
	if access == protocol.DBAccessOwner {
		dbPriv = "CONNECT, TEMPORARY, CREATE"
	}
	if err := d.exec(ctx, conn, "", `GRANT `+dbPriv+` ON DATABASE %I TO %I`, db.name, user); err != nil {
		return 0, err
	}
	c, err := d.connectDB(ctx, db.name)
	if err != nil {
		return 0, err
	}
	defer closeConn(ctx, c)
	tx, err := c.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck

	rows, err := tx.Query(ctx, `SELECT n.nspname::text FROM pg_namespace n WHERE `+userSchemaSQL+` ORDER BY 1`)
	if err != nil {
		return 0, err
	}
	schemas, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	rows, err = tx.Query(ctx, `
		SELECT DISTINCT r.rolname::text FROM (
			SELECT datdba AS o FROM pg_database WHERE datname = current_database()
			UNION SELECT n.nspowner FROM pg_namespace n WHERE `+userSchemaSQL+`
			UNION SELECT c.relowner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			      WHERE `+userSchemaSQL+` AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
		) x JOIN pg_roles r ON r.oid = x.o
		WHERE r.rolname <> $1 AND r.rolname NOT LIKE 'pg\_%'
		ORDER BY 1 LIMIT $2`, user, maxCreators)
	if err != nil {
		return 0, err
	}
	creators, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	priv := accessPrivileges[access]
	for _, s := range schemas {
		for _, st := range []struct{ format string }{
			{`GRANT ` + priv.schema + ` ON SCHEMA %I TO %I`},
			{`GRANT ` + priv.tables + ` ON ALL TABLES IN SCHEMA %I TO %I`},
			{`GRANT ` + priv.sequences + ` ON ALL SEQUENCES IN SCHEMA %I TO %I`},
		} {
			if err := d.exec(ctx, tx, "", st.format, s, user); err != nil {
				return 0, err
			}
		}
		for _, r := range creators {
			if err := d.exec(ctx, tx, "", `ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT `+priv.tables+` ON TABLES TO %I`, r, s, user); err != nil {
				return 0, err
			}
			if err := d.exec(ctx, tx, "", `ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I GRANT `+priv.sequences+` ON SEQUENCES TO %I`, r, s, user); err != nil {
				return 0, err
			}
		}
	}
	// Full access to a database an ordinary user owns: membership in that
	// user, so existing tables can be changed too. Never a superuser's or
	// Rowsafe's role (that would reach far beyond this database).
	if access == protocol.DBAccessOwner && db.owner != user && protectedRole(db.owner, db.ownerSuper, d.me) == "" {
		if err := d.exec(ctx, tx, "", `GRANT %I TO %I`, db.owner, user); err != nil {
			return 0, err
		}
	}
	var tables int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE `+userSchemaSQL+` AND c.relkind IN ('r', 'p', 'v', 'm', 'f')`).Scan(&tables); err != nil {
		return 0, err
	}
	return tables, tx.Commit(ctx)
}

// ---- reset a password ----

func (d *dba) resetPassword(ctx context.Context, conn *pgx.Conn) error {
	r, ok, err := lookupRole(ctx, conn, d.p.User)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("there is no user named %s", d.p.User)
	}
	if why := protectedRole(r.name, r.super, d.me); why != "" {
		return fmt.Errorf("Rowsafe doesn't change the password of %s: %s", r.name, why)
	}
	if !r.login {
		return fmt.Errorf("the role %s can't log in (it is a group of users), so it has no password", r.name)
	}
	pw, verifier, err := newCredential()
	if err != nil {
		return err
	}
	if err := d.exec(ctx, conn, fmt.Sprintf("ALTER ROLE %s PASSWORD '(encrypted)'", r.name),
		`ALTER ROLE %I PASSWORD %L`, r.name, verifier); err != nil {
		return err
	}
	var dbname string
	err = conn.QueryRow(ctx, `
		SELECT datname::text FROM pg_database
		WHERE datallowconn AND NOT datistemplate AND has_database_privilege($1::oid, oid, 'CONNECT')
		ORDER BY datname = 'postgres', datname LIMIT 1`, r.oid).Scan(&dbname)
	if errors.Is(err, pgx.ErrNoRows) {
		dbname, err = "postgres", nil
	}
	if err != nil {
		return err
	}
	d.pw = pw
	d.secret = &protocol.DBConnection{User: r.name, Database: dbname}
	d.res.Summary = fmt.Sprintf("Gave %s a new password.", r.name)
	d.res.Details = append(d.res.Details, "Apps that are connected now stay connected; they need the new password the next time they connect.")
	if r.validUntil != nil && r.validUntil.Before(time.Now()) {
		d.res.Details = append(d.res.Details, fmt.Sprintf("Note: %s's login expired on %s (VALID UNTIL), so it still can't log in.", r.name, r.validUntil.UTC().Format("2006-01-02")))
	}
	return nil
}

// ---- remove a user ----

func (d *dba) dropUser(ctx context.Context, conn *pgx.Conn) error {
	p := d.p
	r, ok, err := lookupRole(ctx, conn, p.User)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("there is no user named %s", p.User)
	}
	if why := protectedRole(r.name, r.super, d.me); why != "" {
		return fmt.Errorf("Rowsafe doesn't remove %s: %s", r.name, why)
	}
	var to roleInfo
	if p.ReassignTo != "" {
		if to, ok, err = lookupRole(ctx, conn, p.ReassignTo); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("there is no user named %s to hand %s's objects to", p.ReassignTo, r.name)
		}
		if strings.HasPrefix(to.name, "pg_") {
			return fmt.Errorf("the role %s is built into PostgreSQL and can't own objects", to.name)
		}
	}

	// What it owns and where it has privileges, in every database.
	type deps struct {
		db       string // "" : shared objects (databases, privileges on them)
		allowed  bool
		owned    int
		anything int
	}
	var all []deps
	rows, err := conn.Query(ctx, `
		SELECT coalesce(db.datname::text, ''), coalesce(db.datallowconn, true),
		       count(*) FILTER (WHERE s.deptype = 'o'), count(*)
		FROM pg_shdepend s LEFT JOIN pg_database db ON db.oid = s.dbid
		WHERE s.refclassid = 'pg_authid'::regclass AND s.refobjid = $1
		GROUP BY 1, 2 ORDER BY 1`, r.oid)
	if err != nil {
		return err
	}
	var dep deps
	if _, err := pgx.ForEachRow(rows, []any{&dep.db, &dep.allowed, &dep.owned, &dep.anything}, func() error {
		all = append(all, dep)
		return nil
	}); err != nil {
		return err
	}
	rows, err = conn.Query(ctx, `SELECT datname::text FROM pg_database WHERE datdba = $1 ORDER BY 1`, r.oid)
	if err != nil {
		return err
	}
	ownedDBs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	owned := 0
	var ownedIn []string
	for _, x := range all {
		if x.db != "" && x.owned > 0 {
			owned += x.owned
			ownedIn = append(ownedIn, x.db)
		}
	}
	if (owned > 0 || len(ownedDBs) > 0) && p.ReassignTo == "" {
		var what []string
		if owned > 0 {
			what = append(what, fmt.Sprintf("%s in %s", plural(owned, "a table or other object", fmt.Sprintf("%d tables and other objects", owned)), joinAnd(ownedIn)))
		}
		if len(ownedDBs) > 0 {
			what = append(what, plural(len(ownedDBs), "the database ", "the databases ")+joinAnd(ownedDBs))
		}
		return fmt.Errorf("the user %s owns %s. Choose a user to hand them to, then remove it", r.name, joinAnd(what))
	}
	for _, x := range all {
		if x.db != "" && !x.allowed {
			return fmt.Errorf("the user %s has objects or rights in %s, which doesn't accept connections, so Rowsafe can't clean them up", r.name, x.db)
		}
	}

	// End its sessions, then in every database where it owns something or
	// has rights: hand over what it owns, and drop its rights (DROP OWNED
	// only revokes privileges once nothing is owned; checked again in the
	// same transaction). The session's own database also handles shared
	// objects: owned databases and privileges on databases.
	var ended int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM (SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usesysid = $1 AND pid <> pg_backend_pid()) x`, r.oid).Scan(&ended); err != nil {
		return err
	}
	if ended > 0 {
		d.tl.Printf("ended %s of %s", countNoun(ended, "connection", "connections"), r.name)
	}
	var here string
	if err := conn.QueryRow(ctx, `SELECT current_database()::text`).Scan(&here); err != nil {
		return err
	}
	dbs := []string{here}
	for _, x := range all {
		if x.db != "" && !slices.Contains(dbs, x.db) {
			dbs = append(dbs, x.db)
		}
	}
	for _, name := range dbs {
		c := conn
		if name != here {
			if c, err = d.connectDB(ctx, name); err != nil {
				return err
			}
		}
		err := func() error {
			tx, err := c.Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck
			if p.ReassignTo != "" {
				if err := d.exec(ctx, tx, "", `REASSIGN OWNED BY %I TO %I`, r.name, to.name); err != nil {
					return err
				}
			} else {
				var n int
				if err := tx.QueryRow(ctx, `
					SELECT count(*) FROM pg_shdepend
					WHERE refclassid = 'pg_authid'::regclass AND refobjid = $1 AND deptype = 'o'
					  AND dbid IN (0, (SELECT oid FROM pg_database WHERE datname = current_database()))`, r.oid).Scan(&n); err != nil {
					return err
				}
				if n > 0 {
					return fmt.Errorf("the user %s started owning something in %s meanwhile; Rowsafe stopped without removing anything there", r.name, name)
				}
			}
			if err := d.exec(ctx, tx, "", `DROP OWNED BY %I`, r.name); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}()
		if name != here {
			closeConn(ctx, c)
		}
		if err != nil {
			return fmt.Errorf("in %s: %w", name, err)
		}
	}
	if err := d.exec(ctx, conn, "", `DROP ROLE %I`, r.name); err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the user %s.", r.name)
	if p.ReassignTo != "" && (owned > 0 || len(ownedDBs) > 0) {
		var what []string
		if owned > 0 {
			what = append(what, plural(owned, "the object it owned", fmt.Sprintf("its %d objects", owned)))
		}
		if len(ownedDBs) > 0 {
			what = append(what, plural(len(ownedDBs), "the database ", "the databases ")+joinAnd(ownedDBs))
		}
		d.res.Summary += fmt.Sprintf(" %s now %s to %s.", upperFirst(joinAnd(what)), plural(owned+len(ownedDBs), "belongs", "belong"), to.name)
	}
	if ended > 0 {
		d.res.Details = append(d.res.Details, fmt.Sprintf("Its %s %s ended.", countNoun(ended, "open connection", "open connections"), isAre(ended)))
	}
	return nil
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---- extensions ----

func (d *dba) extensionDB(ctx context.Context, conn *pgx.Conn) (*pgx.Conn, error) {
	db, ok, err := lookupDatabase(ctx, conn, d.p.Database)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("there is no database named %s", d.p.Database)
	}
	if !db.allowConn || db.isTemplate {
		return nil, fmt.Errorf("the database %s is a template or doesn't accept connections", db.name)
	}
	return d.connectDB(ctx, db.name)
}

func (d *dba) enableExtension(ctx context.Context, conn *pgx.Conn) error {
	p := d.p
	if protocol.DBExtensionUntrusted(p.Extension) && !p.AllowUntrusted {
		return fmt.Errorf("the extension %s lets anyone who can use it run programs or read files on the server as PostgreSQL's system user; it needs an explicit confirmation", p.Extension)
	}
	c, err := d.extensionDB(ctx, conn)
	if err != nil {
		return err
	}
	defer closeConn(ctx, c)
	avail, err := availableExtensions(ctx, c)
	if err != nil {
		return err
	}
	if _, ok := avail[p.Extension]; !ok {
		return notAvailable(p.Extension)
	}
	before, err := installedExtensions(ctx, c)
	if err != nil {
		return err
	}
	if v, ok := before[p.Extension]; ok {
		d.res.Summary = fmt.Sprintf("%s is already on in %s (version %s).", p.Extension, p.Database, v)
		return nil
	}
	if err := d.exec(ctx, c, "", `CREATE EXTENSION IF NOT EXISTS %I CASCADE`, p.Extension); err != nil {
		return err
	}
	after, err := installedExtensions(ctx, c)
	if err != nil {
		return err
	}
	var also []string
	for name := range after {
		if _, ok := before[name]; !ok && name != p.Extension {
			also = append(also, name)
		}
	}
	slices.Sort(also)
	d.res.Summary = fmt.Sprintf("Turned on %s %s in %s.", p.Extension, after[p.Extension], p.Database)
	if len(also) > 0 {
		d.res.Details = append(d.res.Details, fmt.Sprintf("It needs %s, which %s turned on too.", joinAnd(also), plural(len(also), "was", "were")))
	}
	return nil
}

func (d *dba) disableExtension(ctx context.Context, conn *pgx.Conn) error {
	p := d.p
	c, err := d.extensionDB(ctx, conn)
	if err != nil {
		return err
	}
	defer closeConn(ctx, c)
	installed, err := installedExtensions(ctx, c)
	if err != nil {
		return err
	}
	if _, ok := installed[p.Extension]; !ok {
		d.res.Summary = fmt.Sprintf("%s is already off in %s.", p.Extension, p.Database)
		return nil
	}
	stmt, err := sqlf(ctx, c, `DROP EXTENSION %I`, p.Extension)
	if err != nil {
		return err
	}
	d.tl.Printf("%s", stmt)
	if _, err := c.Exec(ctx, stmt); err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "2BP01" { // dependent objects still exist
			return fmt.Errorf("something in %s still uses %s, so Rowsafe didn't turn it off (%s)", p.Database, p.Extension, firstLine(pe.Detail))
		}
		if isLockTimeout(err) {
			return fmt.Errorf("something is using %s right now; try again in a minute", p.Extension)
		}
		return plainPGError(err)
	}
	d.res.Summary = fmt.Sprintf("Turned off %s in %s.", p.Extension, p.Database)
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	return strings.TrimSuffix(s, ".")
}

// ---- remove a database ----

func (d *dba) dropDatabase(ctx context.Context, conn *pgx.Conn) error {
	p := d.p
	db, ok, err := lookupDatabase(ctx, conn, p.Database)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("there is no database named %s", p.Database)
	}
	if protocol.SystemDatabase(db.name) || db.isTemplate {
		return fmt.Errorf("the database %s is one of PostgreSQL's own or a template; Rowsafe doesn't remove it", db.name)
	}
	var here string
	var size int64
	var conns int
	var slots []string
	if err := conn.QueryRow(ctx, `
		SELECT current_database()::text, pg_database_size($1::oid),
		       (SELECT count(*) FROM pg_stat_activity WHERE datid = $1::oid AND pid <> pg_backend_pid()),
		       ARRAY(SELECT slot_name::text FROM pg_replication_slots WHERE datoid = $1::oid ORDER BY 1)`, db.oid).
		Scan(&here, &size, &conns, &slots); err != nil {
		return err
	}
	if here == db.name {
		return fmt.Errorf("Rowsafe can't remove the database it is connected to")
	}
	if len(slots) > 0 {
		return fmt.Errorf("the database %s is being replicated elsewhere (logical replication slot %s), so Rowsafe didn't remove it", db.name, strings.Join(slots, ", "))
	}
	err = withoutTimeout(ctx, conn, func() error {
		if d.vnum >= 130000 {
			return d.exec(ctx, conn, "", `DROP DATABASE %I WITH (FORCE)`, db.name)
		}
		// Before PostgreSQL 13: close it to new connections, end the open
		// ones, drop; open it again if the drop fails.
		if err := d.exec(ctx, conn, "", `ALTER DATABASE %I ALLOW_CONNECTIONS false`, db.name); err != nil {
			return err
		}
		if _, err := conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datid = $1::oid AND pid <> pg_backend_pid()`, db.oid); err != nil {
			return err
		}
		time.Sleep(200 * time.Millisecond)
		if err := d.exec(ctx, conn, "", `DROP DATABASE %I`, db.name); err != nil {
			if rerr := d.exec(context.WithoutCancel(ctx), conn, "", `ALTER DATABASE %I ALLOW_CONNECTIONS true`, db.name); rerr != nil {
				d.tl.Printf("reopening %s: %v", db.name, rerr)
			}
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	d.res.Summary = fmt.Sprintf("Removed the database %s (%s).", db.name, humanBytes(size))
	if conns > 0 {
		d.res.Details = append(d.res.Details, fmt.Sprintf("%s to it %s ended.", upperFirst(countNoun(conns, "open connection", "open connections")), isAre(conns)))
	}
	d.res.Details = append(d.res.Details, "The Mark Rowsafe saved just before lets you get it back: restore a copy at that Mark with Rewind.")
	return nil
}
