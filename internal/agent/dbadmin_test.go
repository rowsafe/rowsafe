package agent

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestNewPassword(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		pw, err := newPassword()
		if err != nil {
			t.Fatal(err)
		}
		if len(pw) != passwordLength || strings.Trim(pw, passwordAlphabet) != "" {
			t.Fatalf("password %q", pw)
		}
		if seen[pw] {
			t.Fatal("repeated password")
		}
		seen[pw] = true
	}
}

// RFC 7677's user "pencil" and salt; the expected verifier was computed
// independently (Python's hashlib, RFC 5802). The integration test also
// recomputes PostgreSQL's own stored verifiers.
func TestSCRAMVerifier(t *testing.T) {
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	got, err := scramVerifierWithSalt("pencil", salt)
	if err != nil {
		t.Fatal(err)
	}
	want := "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
	if got != want {
		t.Errorf("verifier\n got %s\nwant %s", got, want)
	}
}

func TestServerAddresses(t *testing.T) {
	_, priv, _ := net.ParseCIDR("10.0.0.5/24")
	priv.IP = net.ParseIP("10.0.0.5")
	_, pub, _ := net.ParseCIDR("203.0.113.7/24")
	pub.IP = net.ParseIP("203.0.113.7")
	nets := []*net.IPNet{pub, priv}

	// No clients: private first, then public, host name, localhost.
	addrs, host, local := serverAddresses(nets, "db1", "*", nil)
	if host != "10.0.0.5" || local || len(addrs) != 4 || addrs[1].Address != "203.0.113.7" || addrs[2].Kind != protocol.AddressHostname || addrs[3].Address != "localhost" {
		t.Errorf("no clients: %s %+v", host, addrs)
	}
	// Apps connect from the internet: the public address.
	addrs, host, _ = serverAddresses(nets, "db1", "*", map[string]int{"198.51.100.9": 3, "10.0.0.8": 1})
	if host != "203.0.113.7" || addrs[0].Clients != 3 || addrs[1].Clients != 1 {
		t.Errorf("internet clients: %s %+v", host, addrs)
	}
	// Apps on the same server.
	_, host, _ = serverAddresses(nets, "db1", "*", map[string]int{"127.0.0.1": 5, "10.0.0.8": 1})
	if host != "localhost" {
		t.Errorf("local clients: %s", host)
	}
	// Listening on one address only.
	addrs, host, _ = serverAddresses(nets, "db1", "10.0.0.5", nil)
	if host != "10.0.0.5" || len(addrs) != 2 {
		t.Errorf("one address: %s %+v", host, addrs)
	}
	// Local only.
	addrs, host, local = serverAddresses(nets, "db1", "localhost", map[string]int{"127.0.0.1": 1})
	if host != "localhost" || !local || len(addrs) != 1 {
		t.Errorf("local only: %s %+v", host, addrs)
	}
}

// ---- against a local PostgreSQL ----

type dbaEnv struct {
	t      *testing.T
	a      *Agent
	spec   protocol.DatabaseSpec
	admin  *pgx.Conn // to postgres, as the agent's superuser
	prefix string
	key    *ecdh.PrivateKey
	n      int
}

func newDBAEnv(t *testing.T) *dbaEnv {
	tg := fixTestTarget(t)
	admin, err := tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e := &dbaEnv{t: t, admin: admin, key: key,
		prefix: fmt.Sprintf("dbat%d_", time.Now().UnixNano()%1e8),
		a:      &Agent{cfg: Config{PGUser: tg.User}},
		spec:   protocol.DatabaseSpec{SocketDir: tg.SocketDir, Port: tg.Port}}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		defer admin.Close(ctx)
		rows, _ := admin.Query(ctx, `SELECT datname::text FROM pg_database WHERE datname LIKE $1`, e.prefix+"%")
		dbs, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, d := range dbs {
			if _, err := admin.Exec(ctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{d}.Sanitize()+` WITH (FORCE)`); err != nil {
				t.Logf("dropping %s: %v", d, err)
			}
		}
		rows, _ = admin.Query(ctx, `SELECT rolname::text FROM pg_roles WHERE rolname LIKE $1`, e.prefix+"%")
		roles, _ := pgx.CollectRows(rows, pgx.RowTo[string])
		for _, r := range roles {
			id := pgx.Identifier{r}.Sanitize()
			if _, err := admin.Exec(ctx, `DROP OWNED BY `+id+`; DROP ROLE IF EXISTS `+id); err != nil {
				t.Logf("dropping %s: %v", r, err)
			}
		}
	})
	return e
}

func (e *dbaEnv) name(s string) string { return e.prefix + s }

func (e *dbaEnv) run(p protocol.DBAdminParams) (*protocol.DBAdminResult, string, error) {
	e.t.Helper()
	if protocol.DBAdminMakesPassword(p) {
		p.PublicKey = protocol.EncodeSealKey(e.key.PublicKey())
	}
	e.n++
	tl := &taskLog{}
	res, err := e.a.dbadmin(e.t.Context(), e.spec, fmt.Sprintf("task_%d", e.n), p, tl)
	return res, tl.String(), err
}

func (e *dbaEnv) mustRun(p protocol.DBAdminParams, want string) *protocol.DBAdminResult {
	e.t.Helper()
	res, log, err := e.run(p)
	if err != nil {
		e.t.Fatalf("%s: %v\n%s", p.Action, err, log)
	}
	if !strings.Contains(res.Summary, want) {
		e.t.Fatalf("%s: summary %q, want %q\n%s", p.Action, res.Summary, want, log)
	}
	if res.Inventory == nil {
		e.t.Fatalf("%s: no inventory\n%s", p.Action, log)
	}
	if strings.Contains(log, "SCRAM-SHA-256$") {
		e.t.Fatalf("%s: the log has a password verifier:\n%s", p.Action, log)
	}
	e.t.Logf("%s: %s %q", p.Action, res.Summary, res.Details)
	return res
}

func (e *dbaEnv) mustRefuse(p protocol.DBAdminParams, want string) {
	e.t.Helper()
	_, log, err := e.run(p)
	if err == nil || !strings.Contains(err.Error(), want) {
		e.t.Fatalf("%s: err %v, want %q\n%s", p.Action, err, want, log)
	}
	e.t.Logf("%s refused: %v", p.Action, err)
}

// secret opens the sealed password (as the browser would) and checks it is
// the one PostgreSQL stores for the user.
func (e *dbaEnv) secret(res *protocol.DBAdminResult) protocol.DBSecret {
	e.t.Helper()
	plain, err := protocol.Open(e.key, []byte(fmt.Sprintf("task_%d", e.n)), res.Secret)
	if err != nil {
		e.t.Fatal(err)
	}
	var s protocol.DBSecret
	if err := json.Unmarshal(plain, &s); err != nil {
		e.t.Fatal(err)
	}
	if len(s.Password) != passwordLength || !strings.Contains(s.URL, s.Password) || s.User != res.Connection.User {
		e.t.Fatalf("secret %+v", s)
	}
	var stored string
	if err := e.admin.QueryRow(e.t.Context(), `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, s.User).Scan(&stored); err != nil {
		e.t.Fatal(err)
	}
	// SCRAM-SHA-256$4096:<salt>$<stored>:<server>
	parts := strings.SplitN(strings.TrimPrefix(stored, "SCRAM-SHA-256$"), "$", 2)
	iter, saltB64, _ := strings.Cut(parts[0], ":")
	salt, _ := base64.StdEncoding.DecodeString(saltB64)
	if n, _ := strconv.Atoi(iter); n != scramIterations {
		e.t.Fatalf("stored verifier %q", stored)
	}
	if again, _ := scramVerifierWithSalt(s.Password, salt); again != stored {
		e.t.Fatalf("the sealed password doesn't match what PostgreSQL stores for %s", s.User)
	}
	return s
}

// as connects as user (the local PostgreSQL trusts local connections; the
// password was checked in secret).
func (e *dbaEnv) as(user, db string) *pgx.Conn {
	e.t.Helper()
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		e.t.Fatal(err)
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Database = e.spec.SocketDir, uint16(e.spec.Port), user, db
	c, err := pgx.ConnectConfig(e.t.Context(), cfg)
	if err != nil {
		e.t.Fatalf("connecting as %s to %s: %v", user, db, err)
	}
	e.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func mustExec(t *testing.T, c *pgx.Conn, sql string) {
	t.Helper()
	if _, err := c.Exec(t.Context(), sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func mustDeny(t *testing.T, c *pgx.Conn, sql string) {
	t.Helper()
	_, err := c.Exec(t.Context(), sql)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "42501" {
		t.Fatalf("%s: err %v, want permission denied", sql, err)
	}
}

func findUser(inv *protocol.DBInventory, name string) *protocol.DBUser {
	for i := range inv.Users {
		if inv.Users[i].Name == name {
			return &inv.Users[i]
		}
	}
	return nil
}

func findDB(inv *protocol.DBInventory, name string) *protocol.DBDatabase {
	for i := range inv.Databases {
		if inv.Databases[i].Name == name {
			return &inv.Databases[i]
		}
	}
	return nil
}

func TestDBAdminAgainstPostgres(t *testing.T) {
	e := newDBAEnv(t)
	ctx := t.Context()
	shop, rw, ro, full := e.name("shop"), e.name("rw"), e.name("ro"), e.name("full")

	// A database with its own new owner and extensions (earthdistance needs cube).
	res := e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: shop, CreateOwner: true,
		Extensions: []string{"pg_trgm", "earthdistance"}}, "Created the database "+shop+", owned by the new user "+shop)
	if !strings.Contains(strings.Join(res.Details, " "), "cube") {
		t.Errorf("details %q don't say cube was enabled too", res.Details)
	}
	sec := e.secret(res)
	if sec.Database != shop || sec.Port != e.spec.Port || sec.SSLMode == "" || sec.Host == "" {
		t.Errorf("connection %+v", sec.DBConnection)
	}
	if db := findDB(res.Inventory, shop); db == nil || db.Owner != shop || db.Encoding != "UTF8" || len(db.Extensions) < 3 {
		t.Errorf("inventory database %+v", db)
	}
	if u := findUser(res.Inventory, shop); u == nil || !u.Login || u.Password != protocol.PasswordSCRAM || len(u.Databases) == 0 {
		t.Errorf("inventory user %+v", u)
	}
	// Only the owner (and superusers) may connect; the owner owns public.
	var publicConnect bool
	var schemaOwner string
	if err := e.admin.QueryRow(ctx, `SELECT has_database_privilege('public', $1, 'CONNECT')`, shop).Scan(&publicConnect); err != nil || publicConnect {
		t.Errorf("PUBLIC may connect to %s (%v)", shop, err)
	}
	owner := e.as(shop, shop)
	if err := owner.QueryRow(ctx, `SELECT pg_get_userbyid(nspowner)::text FROM pg_namespace WHERE nspname = 'public'`).Scan(&schemaOwner); err != nil || schemaOwner != shop {
		t.Errorf("public schema owner %q (%v)", schemaOwner, err)
	}
	mustExec(t, owner, `CREATE TABLE orders (id serial PRIMARY KEY, total int)`)
	mustExec(t, owner, `INSERT INTO orders (total) VALUES (10)`)

	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: shop, CreateOwner: true}, "already exists")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: e.name("x"), Owner: e.name("nobody")}, "no user named")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: e.name("x"), CreateOwner: true,
		Extensions: []string{"no_such_ext"}}, "doesn't have the no_such_ext extension")

	// Read-only: reads today's and tomorrow's tables, writes nothing.
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: ro, Access: protocol.DBAccessReadOnly,
		Databases: []string{shop}}, "read-only access to "+shop+" (1 table)")
	e.secret(res)
	roc := e.as(ro, shop)
	mustExec(t, roc, `SELECT * FROM orders`)
	mustDeny(t, roc, `INSERT INTO orders (total) VALUES (1)`)
	mustDeny(t, roc, `CREATE TABLE nope (id int)`)
	mustExec(t, owner, `CREATE TABLE later (id int)`)
	mustExec(t, roc, `SELECT * FROM later`)
	if _, err := e.as(ro, "postgres").Exec(ctx, `SELECT 1`); err != nil {
		t.Log("ro can't connect to postgres (fine)")
	}

	// Read and write rows, including the serial column's sequence.
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: rw, Access: protocol.DBAccessReadWrite,
		Databases: []string{shop}}, "read and write access")
	e.secret(res)
	rwc := e.as(rw, shop)
	mustExec(t, rwc, `INSERT INTO orders (total) VALUES (20)`)
	mustExec(t, rwc, `UPDATE orders SET total = total + 1`)
	mustExec(t, rwc, `DELETE FROM orders WHERE total > 100`)
	mustDeny(t, rwc, `CREATE TABLE nope (id int)`)
	mustDeny(t, rwc, `ALTER TABLE orders ADD COLUMN x int`)

	// Full access: may change the owner's tables and create its own.
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: full, Access: protocol.DBAccessOwner,
		Databases: []string{shop}}, "full access")
	e.secret(res)
	fc := e.as(full, shop)
	mustExec(t, fc, `ALTER TABLE orders ADD COLUMN note text`)
	mustExec(t, fc, `CREATE TABLE mine (id int)`)
	fc.Close(ctx)

	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: ro, Access: protocol.DBAccessReadOnly, Databases: []string{shop}}, "already exists")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: e.name("y"), Access: protocol.DBAccessReadOnly, Databases: []string{"template0"}}, "template")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: e.name("y"), Access: protocol.DBAccessReadOnly, Databases: []string{e.name("nope")}}, "no database named")

	// A new password.
	var before string
	_ = e.admin.QueryRow(ctx, `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, ro).Scan(&before)
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: ro}, "Gave "+ro+" a new password")
	if s := e.secret(res); s.Database != shop {
		t.Errorf("reset password: database %q", s.Database)
	}
	var after string
	_ = e.admin.QueryRow(ctx, `SELECT rolpassword FROM pg_authid WHERE rolname = $1`, ro).Scan(&after)
	if after == before {
		t.Error("the password didn't change")
	}
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: e.spec.SocketDir}, "no user named")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: e.a.cfg.PGUser}, "Rowsafe doesn't change the password")

	// Extensions: on, already on, off refused while used, off.
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: shop, Extension: "citext"}, "Turned on citext")
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: shop, Extension: "citext"}, "already on")
	mustExec(t, owner, `ALTER TABLE orders ADD COLUMN email citext`)
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminDisableExtension, Database: shop, Extension: "citext"}, "still uses citext")
	mustExec(t, owner, `ALTER TABLE orders DROP COLUMN email`)
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminDisableExtension, Database: shop, Extension: "citext"}, "Turned off citext")
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminDisableExtension, Database: shop, Extension: "citext"}, "already off")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: shop, Extension: "plpython3u"}, "explicit confirmation")

	// Remove users: refused while it owns something, then handed over.
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: full}, "Choose a user to hand them to")
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: full, ReassignTo: shop}, "now belongs to "+shop)
	var mineOwner string
	if err := owner.QueryRow(ctx, `SELECT tableowner::text FROM pg_tables WHERE tablename = 'mine'`).Scan(&mineOwner); err != nil || mineOwner != shop {
		t.Errorf("mine is owned by %q (%v)", mineOwner, err)
	}
	// A user with only privileges goes, and its open session is ended.
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: rw}, "Removed the user "+rw)
	if findUser(res.Inventory, rw) != nil {
		t.Error("rw is still listed")
	}
	if !strings.Contains(strings.Join(res.Details, " "), "open connection") {
		t.Errorf("details %q", res.Details)
	}
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: e.a.cfg.PGUser}, "Rowsafe doesn't remove")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: shop}, "the database "+shop)

	// The list.
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminList}, "databases and")
	inv := res.Inventory
	if inv.ServerVersion == "" || inv.SuggestedHost == "" || len(inv.Extensions) == 0 || inv.AgentUser != e.a.cfg.PGUser {
		t.Errorf("inventory %+v", inv)
	}
	if u := findUser(inv, e.a.cfg.PGUser); u == nil || !u.System {
		t.Errorf("agent user %+v", u)
	}
	if d := findDB(inv, "postgres"); d == nil || !d.System {
		t.Errorf("postgres %+v", d)
	}

	// Remove the database while someone is connected.
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: "postgres", Confirm: "postgres"}, "one of PostgreSQL's own")
	res = e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: shop, Confirm: shop}, "Removed the database "+shop)
	if findDB(res.Inventory, shop) != nil {
		t.Error("shop is still listed")
	}
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: shop, Confirm: shop}, "no database named")
}

// A failure half-way leaves nothing behind: the database and its new owner
// are removed again.
func TestDBAdminCreateDatabaseCleansUp(t *testing.T) {
	e := newDBAEnv(t)
	name := e.name("bad")
	e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: name, CreateOwner: true,
		Locale: "xx_NOPE.UTF-8"}, "nothing was left behind")
	var n int
	if err := e.admin.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM pg_database WHERE datname = $1) + (SELECT count(*) FROM pg_roles WHERE rolname = $1)`, name).Scan(&n); err != nil || n != 0 {
		t.Errorf("left behind: %d (%v)", n, err)
	}
}
