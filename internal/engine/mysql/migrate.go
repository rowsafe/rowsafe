package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Move in (protocol.FeatureMoveIn): one database (schema) of a MySQL or
// MariaDB server anywhere this server can reach (RDS, Cloud SQL, Azure,
// DigitalOcean...) copied into the MySQL server Rowsafe protects here.
//
//   - One-time copy: mysqldump from the source, loaded straight into a new
//     database here, while the source's writes are stopped.
//   - Live sync: the same copy taken in one consistent snapshot that
//     records the source's binary log position, then a replication channel
//     of its own ("rowsafe_<id>", filtered to that database) follows the
//     source's binary log until the switchover, which waits until
//     everything arrived, ends the channel, compares row counts and makes
//     the login apps use from now on.
//
// The source connection string reaches this server sealed to the
// migration's key and stays here (0600, next to the key). The loads are
// written to this server's own binary log, so its restores to any second
// include the moved data.

var _ agent.EngineMigrate = (*Engine)(nil)

// migSource is a parsed source connection string.
type migSource struct {
	User, Password, Host string
	Port                 int
	DB                   string
	SSLMode              string // DISABLED, PREFERRED (default), REQUIRED, VERIFY_IDENTITY
}

// parseMigSource reads mysql://user:password@host:port/database?ssl-mode=.
func parseMigSource(s string) (migSource, error) {
	s = strings.TrimSpace(s)
	example := "use mysql://user:password@host:3306/database (add ?ssl-mode=REQUIRED or DISABLED if needed)"
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "mysql" && u.Scheme != "mariadb") || u.Host == "" || u.User == nil {
		return migSource{}, errors.New("that isn't a MySQL connection string: " + example)
	}
	src := migSource{User: u.User.Username(), Host: u.Hostname(), Port: 3306, DB: strings.Trim(u.Path, "/"), SSLMode: "PREFERRED"}
	src.Password, _ = u.User.Password()
	if p := u.Port(); p != "" {
		if src.Port, err = strconv.Atoi(p); err != nil || src.Port < 1 || src.Port > 65535 {
			return migSource{}, errors.New("invalid port: " + example)
		}
	}
	if m := strings.ToUpper(u.Query().Get("ssl-mode")); m != "" {
		switch m {
		case "DISABLED", "PREFERRED", "REQUIRED", "VERIFY_CA", "VERIFY_IDENTITY":
			src.SSLMode = m
		default:
			return migSource{}, errors.New("ssl-mode must be DISABLED, PREFERRED, REQUIRED or VERIFY_IDENTITY")
		}
	}
	switch {
	case src.User == "":
		return migSource{}, errors.New("the connection string has no user: " + example)
	case src.DB == "" || strings.Contains(src.DB, "/"):
		return migSource{}, errors.New("name the database to move at the end: " + example)
	case isSystemSchema(src.DB):
		return migSource{}, fmt.Errorf("%s is a system database: name your own database", src.DB)
	}
	return src, nil
}

// dsn connects to the source (TLS when it offers it, unless DISABLED;
// verified only with VERIFY_*, since providers use their own CAs).
func (m migSource) dsn() *mysql.Config {
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = m.User, m.Password, "tcp", net.JoinHostPort(m.Host, strconv.Itoa(m.Port)), m.DB
	c.Timeout, c.ReadTimeout = 15*time.Second, 10*time.Minute
	c.ParseTime, c.Loc = true, time.UTC
	c.AllowNativePasswords = true
	switch m.SSLMode {
	case "DISABLED":
		c.TLSConfig = "false"
	case "REQUIRED":
		c.TLSConfig = "skip-verify"
	case "VERIFY_CA", "VERIFY_IDENTITY":
		c.TLSConfig = "true"
	default:
		c.TLSConfig = "preferred"
	}
	return c
}

func (m migSource) open(ctx context.Context) (*sql.DB, error) {
	conn, err := mysql.NewConnector(m.dsn())
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(2)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("can't connect to %s:%d as %s: %v", m.Host, m.Port, m.User, err)
	}
	return db, nil
}

// optionFile is a [client] option file for the tools (0600, in the
// migration's folder): values are quoted and escaped.
func (m migSource) optionFile(path string) error {
	esc := func(v string) string {
		v = strings.ReplaceAll(v, `\`, `\\`)
		return `"` + strings.ReplaceAll(v, `"`, `\"`) + `"`
	}
	for _, v := range []string{m.User, m.Password, m.Host} {
		if strings.ContainsAny(v, "\n\r\x00") {
			return errors.New("the connection string has a line break in it")
		}
	}
	body := fmt.Sprintf("[client]\nuser=%s\npassword=%s\nhost=%s\nport=%d\n", esc(m.User), esc(m.Password), esc(m.Host), m.Port)
	return writeFileAtomic(path, []byte(body), 0o600)
}

// migState is what this engine keeps for a migration (mysql.json in its
// folder).
type migState struct {
	SourceDB    string `json:"source_db"`
	TargetDB    string `json:"target_db"`
	Method      string `json:"method,omitempty"`
	CreatedDB   bool   `json:"created_db,omitempty"`
	Channel     string `json:"channel,omitempty"` // the live sync's replication channel
	AppUser     string `json:"app_user,omitempty"`
	Tables      int    `json:"tables,omitempty"`
	SourceBytes int64  `json:"source_bytes,omitempty"`
	Loaded      bool   `json:"loaded,omitempty"` // the first copy is in
}

func loadMigState(dir string) migState {
	var st migState
	if data, err := os.ReadFile(filepath.Join(dir, "mysql.json")); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func saveMigState(dir string, st migState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "mysql.json"), data, 0o600)
}

// source is the connection string a check kept.
func savedSource(dir string) (migSource, error) {
	data, err := os.ReadFile(filepath.Join(dir, "source"))
	if errors.Is(err, os.ErrNotExist) {
		return migSource{}, errors.New("this server doesn't have the source connection string (anymore): paste it again and check")
	}
	if err != nil {
		return migSource{}, err
	}
	return parseMigSource(string(data))
}

var targetDBRE = regexp.MustCompile(`^[A-Za-z0-9_$]{1,64}$`)

// Migrate runs one move-in step.
func (e *Engine) Migrate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, taskType string,
	p protocol.MigrateParams, log agent.TaskLogger) (any, error) {
	s := e.server(env, db)
	if p.TargetDB != "" && (!targetDBRE.MatchString(p.TargetDB) || isSystemSchema(p.TargetDB)) {
		return nil, fmt.Errorf("the database name %q isn't allowed: letters, digits and underscores (1-64)", p.TargetDB)
	}
	if taskType == protocol.TaskMigrateCopy {
		return nilable(s.migrateCopy(ctx, m, p, log))
	}
	switch p.Action {
	case protocol.MigrateKey:
		return nilable(s.migrateKey(ctx, m, log))
	case protocol.MigrateCheck:
		return nilable(s.migrateCheck(ctx, m, p, log))
	case protocol.MigrateFixIdentity:
		return nilable(s.migrateKeepBinlogs(ctx, m, log))
	case protocol.MigrateSwitchover:
		return nilable(s.migrateSwitchover(ctx, m, p, log))
	case protocol.MigrateCredentials:
		return nilable(s.migrateCredentials(ctx, m, p, log))
	case protocol.MigrateSourceWritable:
		return &protocol.MigrateActionResult{Summary: "Rowsafe never made the old database read-only, so there is nothing to undo."}, nil
	case protocol.MigrateCancel:
		return nilable(s.migrateCancel(ctx, m, p, log))
	}
	return nil, fmt.Errorf("unknown migrate action %q", p.Action)
}

func (s *server) migrateKey(ctx context.Context, m agent.MigrateEnv, log agent.TaskLogger) (*protocol.MigrateKeyResult, error) {
	pub, err := agent.MigratePublicKey(m.Dir)
	if err != nil {
		return nil, err
	}
	if m.Phase == "" || m.Phase == protocol.MigratePhaseNew {
		m.SetPhase(protocol.MigratePhaseReady)
	}
	res := &protocol.MigrateKeyResult{PublicKey: pub}
	if conn, err := s.open(ctx); err == nil {
		res.Target = s.migrateTarget(ctx, conn, "")
		conn.Close()
	}
	log.Printf("made the key the source connection string is sealed to; the private key stays on this server")
	return res, nil
}

// migrateTarget describes this server for the wizard.
func (s *server) migrateTarget(ctx context.Context, conn *sql.DB, name string) protocol.MigrateTarget {
	t := protocol.MigrateTarget{Database: name, Port: s.db.Port, Addresses: hostAddresses()}
	var version, bind string
	_ = conn.QueryRowContext(ctx, "SELECT VERSION(), @@global.bind_address").Scan(&version, &bind)
	t.ServerVersion = version
	_, t.VersionNum = numericVersion(version)
	t.ListensRemotely = !listensLocallyOnly(bind)
	t.SSL = s.tlsOn(ctx, conn)
	if name != "" {
		var n int
		_ = conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?", name).Scan(&n)
		t.Exists = n > 0
	}
	if f, err := s.readFacts(ctx, conn); err == nil && f.DataDir != "" {
		t.FreeBytes, _ = freeBytes(f.DataDir)
	}
	return t
}

// hostAddresses are this server's addresses apps could use (public first).
func hostAddresses() []string {
	addrs, _ := net.InterfaceAddrs()
	var pub, priv []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if ipn.IP.IsPrivate() {
			priv = append(priv, ipn.IP.String())
		} else {
			pub = append(pub, ipn.IP.String())
		}
	}
	out := append(pub, priv...)
	if h, err := os.Hostname(); err == nil {
		out = append(out, h)
	}
	return out
}
