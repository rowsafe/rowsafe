package clickhouse

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Installer helpers (rowsafe-agent clickhouse ...). They run as the agent
// user on the server; the installer asks the questions. An administrator's
// password, when one is needed, arrives on stdin and is used once: it is
// never written anywhere.

// LoginUser is Rowsafe's ClickHouse user.
const LoginUser = "rowsafe"

var (
	// ErrNeedAdmin: "default" without a password can't sign in, so an
	// administrator must sign in once.
	ErrNeedAdmin = errors.New("ClickHouse needs an administrator's login once to create Rowsafe's user")
	// ErrAdminRefused: the login given was refused.
	ErrAdminRefused = errors.New("ClickHouse refused that login")
	// ErrCantManageUsers: that administrator can't create users with SQL.
	ErrCantManageUsers = errors.New("that ClickHouse login can't create users with SQL (no access management): " +
		"install Rowsafe's user as a users.d file instead (as root)")
)

// Status describes a local server for the installer (key=value lines).
type Status struct {
	Port       int
	Version    string
	Login      string // ok, missing, refused
	User       string // OS user running clickhouse-server
	DataDir    string
	Config     string
	UsersD     string
	Unit       string
	Binary     string // the clickhouse program the agent uses for restore tests and copies
	Replicated string // count of Replicated* tables ("" when unknown)
	Docker     bool
}

// WriteTo prints the status as key=value lines ("-" for empty).
func (s Status) WriteTo(w io.Writer) (int64, error) {
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	docker := "no"
	if s.Docker {
		docker = "yes"
	}
	n, err := fmt.Fprintf(w, "port=%d\nversion=%s\nlogin=%s\nuser=%s\ndatadir=%s\nconfig=%s\nusersd=%s\nunit=%s\nbinary=%s\nreplicated=%s\ndocker=%s\n",
		s.Port, dash(s.Version), dash(s.Login), dash(s.User), dash(s.DataDir), dash(s.Config), dash(s.UsersD), dash(s.Unit),
		dash(s.Binary), dash(s.Replicated), docker)
	return int64(n), err
}

// ServerStatus inspects the server on port for the installer. It fails
// only when nothing answers there.
func ServerStatus(ctx context.Context, env agent.EngineEnv, port int) (Status, error) {
	st := Status{Port: port, Docker: inDocker()}
	if bin, _, err := clickhouseBinary(); err == nil {
		st.Binary = bin
	}
	for _, p := range findServers() {
		if p.Port == port {
			st.User, st.DataDir, st.Config, st.UsersD, st.Unit = p.User, p.DataDir, p.ConfigFile, p.UsersD, p.Unit
		}
	}
	if err := pingServer(ctx, port); err != nil {
		return st, fmt.Errorf("can't connect to ClickHouse on port %d: %w", port, err)
	}
	l, ok, err := loadLogin(env, port)
	st.Version, _ = serverVersion(ctx, port, l, ok && err == nil)
	switch {
	case err != nil:
		st.Login = "refused"
	case !ok:
		st.Login = "missing"
	default:
		c := newClient(serverURL(port), l)
		if err := c.ping(ctx); err != nil {
			st.Login = "refused"
			break
		}
		st.Login = "ok"
		if in, err := inspect(ctx, c); err == nil {
			st.Replicated = strconv.Itoa(in.Replicated())
			if st.DataDir == "" {
				st.DataDir = in.DataPath
			}
		}
	}
	return st, nil
}

func randomPassword() string {
	b := make([]byte, 30)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// UsersXML makes a new random password for Rowsafe's user, saves the login
// for the agent and returns the users.d file that creates the user (root
// installs it as /etc/clickhouse-server/users.d/rowsafe.xml; ClickHouse
// reloads users within seconds). The file holds only the password's
// SHA-256.
func UsersXML(env agent.EngineEnv, port int) (string, error) { return UsersXMLWith(env, port, false) }

// UsersXMLWith is UsersXML; with clones the user may also create and drop
// databases and tables, so the (empty) server can receive clones.
func UsersXMLWith(env agent.EngineEnv, port int, clones bool) (string, error) {
	pw := randomPassword()
	if err := saveLogin(env, port, Login{User: LoginUser, Password: pw}); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(pw))
	return fmt.Sprintf(`<!-- Rowsafe's ClickHouse user (written by the Rowsafe installer). It signs in from this server only.
     SELECT, BACKUP: back up every database and compare tables with a copy; INSERT: bring rows back when you ask;
     KILL QUERY, ALTER UPDATE, ALTER DELETE: stop a query or cancel a stuck change when you ask;
     S3: write backups to the agent's encrypting gateway on this server;
     access management, and creating databases and tables WITH GRANT OPTION: Databases & users, only when you ask in the dashboard;
     CREATE, DROP (DATABASE, TABLE), ALTER TABLE: rewind the whole server in place when you ask (restore next to production, swap partitions). -->
<clickhouse>
  <users>
    <%[1]s>
      <password_sha256_hex>%[2]s</password_sha256_hex>
      <networks>
        <ip>127.0.0.1</ip>
        <ip>::1</ip>
      </networks>
      <profile>default</profile>
      <quota>default</quota>
      <grants>
        <query>GRANT %[3]s ON *.*</query>
        <query>GRANT %[4]s ON *.* WITH GRANT OPTION</query>
        <query>GRANT ACCESS MANAGEMENT ON *.*</query>
      </grants>
    </%[1]s>
  </users>
</clickhouse>
`, LoginUser, hex.EncodeToString(sum[:]), loginGrantsSQL(clones), chOwner+", CREATE DATABASE, DROP DATABASE"), nil
}

// cloneGrants are what receiving a clone needs beyond neededGrants: RESTORE
// creates the databases and tables (and drops them if it fails).
var cloneGrants = []string{"CREATE", "DROP"}

func loginGrantsSQL(clones bool) string {
	if !clones {
		return grantsSQL()
	}
	return grantsSQL() + ", " + strings.Join(cloneGrants, ", ")
}

// cloneRights reports whether the grants cover receiving a clone.
func cloneRights(have []string) bool {
	return len(missingGrants(have)) == 0 && len(missingOf(have, cloneGrants)) == 0
}

// CreateLogin creates (or refreshes) Rowsafe's user with SQL, with a new
// random password, and saves it for the agent. adminUser "" tries
// "default" without a password. In Docker (ROWSAFE_CLICKHOUSE_URL set) the
// user may sign in from any host (the agent is another container) and its
// password is long and random; elsewhere only from this server.
func CreateLogin(ctx context.Context, env agent.EngineEnv, port int, adminUser, adminPassword string) error {
	return CreateLoginWith(ctx, env, port, adminUser, adminPassword, false)
}

// CreateLoginWith is CreateLogin; with clones the user may also receive
// clones (UsersXMLWith).
func CreateLoginWith(ctx context.Context, env agent.EngineEnv, port int, adminUser, adminPassword string, clones bool) error {
	admin := Login{User: adminUser, Password: adminPassword}
	if adminUser == "" {
		admin = Login{User: "default"}
	}
	c := newClient(serverURL(port), admin)
	if err := c.ping(ctx); err != nil {
		switch errCode(err) {
		case codeAuthenticationFailed, codeRequiredPassword, codeUnknownUser:
			if adminUser == "" {
				return ErrNeedAdmin
			}
			return ErrAdminRefused
		}
		return fmt.Errorf("can't connect to ClickHouse on port %d: %w", port, err)
	}
	pw := randomPassword()
	hosts := "HOST IP '127.0.0.1', IP '::1'"
	if inDocker() {
		hosts = "HOST ANY"
	}
	ident := "IDENTIFIED WITH sha256_password BY " + quoteString(pw) + " " + hosts
	err := c.exec(ctx, "CREATE USER IF NOT EXISTS "+quoteIdent(LoginUser)+" "+ident, nil)
	if err == nil {
		err = c.exec(ctx, "ALTER USER "+quoteIdent(LoginUser)+" "+ident, nil)
	}
	if err == nil {
		err = c.exec(ctx, "GRANT "+loginGrantsSQL(clones)+" ON *.* TO "+quoteIdent(LoginUser), nil)
	}
	if err == nil {
		// Databases & users: best effort, the dashboard explains what is
		// missing when this administrator can't pass these rights on.
		for _, q := range adminGrantsSQL(quoteIdent(LoginUser)) {
			_ = c.exec(ctx, q, nil)
		}
	}
	if err != nil {
		if errCode(err) == codeAccessDenied || errCode(err) == 495 || strings.Contains(err.Error(), "readonly") ||
			strings.Contains(err.Error(), "access management") || strings.Contains(err.Error(), "storage") {
			return fmt.Errorf("%w (%s)", ErrCantManageUsers, shortError(err))
		}
		return fmt.Errorf("creating Rowsafe's ClickHouse user: %s", shortError(err))
	}
	l := Login{User: LoginUser, Password: pw}
	if err := saveLogin(env, port, l); err != nil {
		return err
	}
	return verifyLogin(ctx, port, l)
}

// verifyLogin checks a login signs in and has every grant it needs.
func verifyLogin(ctx context.Context, port int, l Login) error {
	c := newClient(serverURL(port), l)
	if err := c.ping(ctx); err != nil {
		switch errCode(err) {
		case codeAuthenticationFailed, codeRequiredPassword, codeUnknownUser:
			return ErrAdminRefused
		}
		return err
	}
	have, err := globalGrants(ctx, c)
	if err != nil {
		return err
	}
	if missing := missingGrants(have); len(missing) > 0 {
		return &MissingGrantsError{Missing: missing}
	}
	return nil
}

// MissingGrantsError lists the privileges a login lacks.
type MissingGrantsError struct{ Missing []string }

func (e *MissingGrantsError) Error() string {
	return "that ClickHouse login lacks " + strings.Join(e.Missing, ", ") + " ON *.* (Rowsafe needs " + grantsSQL() + ")"
}

// SaveLogin saves "user:password" as the agent's login for port, after
// checking it signs in and has the needed grants.
func SaveLogin(ctx context.Context, env agent.EngineEnv, port int, userPassword string) error {
	u, pw, ok := strings.Cut(strings.TrimSpace(userPassword), ":")
	if !ok || u == "" {
		return errors.New("give the login as user:password")
	}
	l := Login{User: u, Password: pw}
	if err := verifyLogin(ctx, port, l); err != nil {
		return err
	}
	return saveLogin(env, port, l)
}
