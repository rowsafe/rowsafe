// Package local is Rowsafe on a database it reaches directly, with a
// connection string: no agent, no account, no control plane. PostgreSQL
// (postgres://), MySQL and MariaDB (mysql://, mariadb://: mysql.go),
// MongoDB (mongodb://, mongodb+srv://: mongodb.go), and Redis and Valkey
// (redis://, rediss://: redis.go).
// The CLI (rowsafe pulse postgres://...) and the local MCP server (rowsafe
// mcp postgres://...) use it for Pulse (health score, findings and fixes),
// tables and indexes, top queries, live activity and settings.
//
// Reads are read-only and bounded (statement and lock timeouts). Changes
// are the agent's own code with all its checks: a fix runs only once it is
// found again in a fresh evaluation (ApplyFix), every name is looked up
// again in the catalogs, and settings go through tune's validation, ALTER
// SYSTEM and a reload, never a restart. Nothing is sent anywhere.
package local

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/maintenance"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/pulse"
	"github.com/rowsafe/rowsafe/tune"
)

// IsConnString reports whether s is a connection URL Rowsafe reads:
// postgres:// or postgresql://, mysql:// or mariadb://, mongodb:// or
// mongodb+srv://, redis:// or rediss://.
func IsConnString(s string) bool {
	if isMySQLURL(s) || isMongoURL(s) || isRedisURL(s) {
		return true
	}
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(s, "postgres://") || strings.HasPrefix(s, "postgresql://")
}

// DB is a database reached through a connection string.
type DB struct {
	conn *pgx.ConnConfig
	// my is a MySQL or MariaDB server's instead (mysql.go), at myHost and
	// myPort; engine is which, once read.
	my             *mysqldriver.Config
	myHost, myPort string
	engine         string
	// mg is a MongoDB server's instead (mongodb.go).
	mg *mongoConn
	// rd is a Redis or Valkey server's instead (redis.go); engine is which,
	// once read.
	rd *redisConn
	// Ref is how commands name this database: the connection string
	// without its password, or "" when the commands find it by themselves
	// (DATABASE_URL).
	Ref string
	// PasswordInURL: the connection string carried a password, which Ref
	// leaves out.
	PasswordInURL bool
	// url is the connection string without its password, for pg_dump
	// (the password goes in its environment).
	url string

	mu     sync.Mutex
	pooler *string // the connection pooler in between, once known

	// engineMu guards engine: MCP tool calls read the database at the
	// same time.
	engineMu sync.Mutex
}

// setEngine records the engine a reading reported (MySQL or MariaDB,
// Redis or Valkey).
func (d *DB) setEngine(e string) {
	d.engineMu.Lock()
	d.engine = e
	d.engineMu.Unlock()
}

// Open parses a connection string. Like psql, it also reads PGPASSWORD,
// ~/.pgpass and the other PG* variables for what the string leaves out
// (MySQL: MYSQL_PWD).
func Open(connString string) (*DB, error) {
	connString = strings.TrimSpace(connString)
	if !IsConnString(connString) {
		return nil, errors.New("expected a connection string such as postgres://user@host:5432/dbname, mysql://user@host:3306/dbname, mongodb://user@host:27017/dbname or redis://host:6379")
	}
	if isMySQLURL(connString) {
		return openMySQL(connString)
	}
	if isMongoURL(connString) {
		return openMongo(connString)
	}
	if isRedisURL(connString) {
		return openRedis(connString)
	}
	cfg, err := pgx.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("reading the connection string: %w", err)
	}
	d := &DB{conn: cfg}
	d.Ref, d.PasswordInURL = pgRef(connString)
	d.url = d.Ref
	return d, nil
}

// pgRef is a PostgreSQL connection string without its password, whether
// it is in the user part or in the query (password=, sslpassword=), and
// whether one was there. It works on the text, not url.Parse: pgx reads
// strings url.Parse refuses (a password with ^ or a space), and those
// must not keep their password either.
func pgRef(connString string) (string, bool) {
	ref := withoutPassword(connString) // mongodb.go
	found := ref != connString
	base, query, ok := strings.Cut(ref, "?")
	if !ok {
		return ref, found
	}
	var kept []string
	for _, kv := range strings.Split(query, "&") {
		k, _, _ := strings.Cut(kv, "=")
		if k, err := url.QueryUnescape(k); err == nil && (strings.EqualFold(k, "password") || strings.EqualFold(k, "sslpassword")) {
			found = true
			continue
		}
		kept = append(kept, kv)
	}
	if len(kept) == 0 {
		return base, found
	}
	return base + "?" + strings.Join(kept, "&"), found
}

// Command is a rowsafe command for this database, ready to paste in a
// shell: "rowsafe fix 'postgres://app@db/app?sslmode=require'", or
// "rowsafe fix" when Ref is "".
func (d *DB) Command(sub string) string {
	if d.Ref == "" {
		return "rowsafe " + sub
	}
	return "rowsafe " + sub + " " + shellQuote(d.Ref)
}

// shellQuote quotes s for a POSIX shell when it needs it.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%_+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Engine is protocol.EnginePostgreSQL, EngineMySQL, EngineMariaDB (for
// mysql://, MySQL until a reading says MariaDB; mariadb:// says it first)
// or EngineMongoDB.
func (d *DB) Engine() string {
	d.engineMu.Lock()
	engine := d.engine
	d.engineMu.Unlock()
	switch {
	case d.mg != nil:
		return protocol.EngineMongoDB
	case d.rd != nil && engine != "":
		return engine
	case d.rd != nil && strings.HasPrefix(strings.ToLower(d.Ref), "valkey"):
		return protocol.EngineValkey
	case d.rd != nil:
		return protocol.EngineRedis
	case d.my == nil:
		return protocol.EnginePostgreSQL
	case engine != "":
		return engine
	case strings.HasPrefix(strings.ToLower(d.Ref), "mariadb://"):
		return protocol.EngineMariaDB
	}
	return protocol.EngineMySQL
}

// EngineName is the engine for people: PostgreSQL, MySQL, MariaDB, MongoDB.
func (d *DB) EngineName() string { return protocol.EngineDisplayName(d.Engine()) }

// Name is the database's name (its user's when the string names none).
func (d *DB) Name() string {
	if d.mg != nil {
		return d.mg.name()
	}
	if d.rd != nil {
		return d.rd.name()
	}
	if d.my != nil {
		if d.my.DBName != "" {
			return d.my.DBName
		}
		return d.my.User
	}
	if d.conn.Database != "" {
		return d.conn.Database
	}
	return d.conn.User
}

// Host is where it runs, for people: host or host:port.
func (d *DB) Host() string {
	if d.mg != nil {
		return d.mg.host
	}
	if d.rd != nil {
		return d.rd.hostPort()
	}
	if d.my != nil {
		if d.my.Net == "unix" || d.myPort == "3306" {
			return d.myHost
		}
		return net.JoinHostPort(d.myHost, d.myPort)
	}
	h := d.conn.Host
	if strings.HasPrefix(h, "/") {
		return "localhost"
	}
	if d.conn.Port != 0 && d.conn.Port != 5432 {
		return net.JoinHostPort(h, strconv.Itoa(int(d.conn.Port)))
	}
	return h
}

// Endpoint is the PostgreSQL host (or socket directory) and port the
// connection string reaches; "" and 0 for MySQL and MariaDB.
func (d *DB) Endpoint() (host string, port int) {
	if d.my != nil || d.conn == nil {
		return "", 0
	}
	return d.conn.Host, int(d.conn.Port)
}

func (d *DB) collectTarget() collect.Target   { return collect.Target{Conn: d.conn} }
func (d *DB) inspectTarget() pginspect.Target { return pginspect.Target{Conn: d.conn} }

// Local reports whether the database runs on this machine.
func (d *DB) Local() bool {
	if d.mg != nil {
		return d.mg.local()
	}
	if d.rd != nil {
		return d.rd.local()
	}
	if d.my != nil {
		return d.mysqlLocal()
	}
	return d.collectTarget().Local()
}

// Options refine a health evaluation or the settings recommendations.
type Options struct {
	// Workload and Disk: protocol.Workload*, protocol.Disk* ("" for the
	// defaults).
	Workload, Disk string
	// Memory and CPUs of the server, when it isn't this machine (Rowsafe
	// can't see another server's from a connection; 0: unknown).
	MemoryBytes int64
	CPUs        int
	// Forecast and Regressions come from the agent's history, on its
	// server (pulse.Input's).
	Forecast    *protocol.DiskForecast
	Regressions []pulse.Regression
}

// connectError says plainly that the database couldn't be reached.
func (d *DB) connectError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return err
	}
	return fmt.Errorf("can't read %s on %s as %s: %w", d.Name(), d.Host(), d.conn.User, err)
}

// read takes one reading.
func (d *DB) read(ctx context.Context, o collect.ReadOptions, opts Options) (*collect.Reading, error) {
	r, err := collect.Read(ctx, d.collectTarget(), o)
	if err != nil {
		return nil, d.connectError(err)
	}
	if r.Settings != nil {
		d.hostFacts(r.Settings, opts)
	}
	return r, nil
}

// hostFacts fills in the server's memory and CPUs: what the person said,
// else this machine's when the database runs here.
func (d *DB) hostFacts(s *protocol.SettingsSnapshot, opts Options) {
	if s.Host.MemoryBytes == 0 && d.Local() {
		s.Host.MemoryBytes = machineMemory()
	}
	if opts.MemoryBytes > 0 {
		s.Host.MemoryBytes = opts.MemoryBytes
	}
	if opts.CPUs > 0 {
		s.Host.CPUs = opts.CPUs
	}
}

// Health reads the database and evaluates it: the score, the findings and
// their fixes.
func (d *DB) Health(ctx context.Context, opts Options) (protocol.DatabaseHealth, error) {
	if d.mg != nil {
		return d.mongoHealth(ctx, opts)
	}
	if d.rd != nil {
		return d.redisHealth(ctx, opts)
	}
	if d.my != nil {
		return d.mysqlHealth(ctx, opts)
	}
	r, err := d.read(ctx, collect.ReadOptions{Insights: true, Settings: true, QueryText: true}, opts)
	if err != nil {
		return protocol.DatabaseHealth{}, err
	}
	in := d.input(r, opts)
	in.SettingsLocked = d.settingsLocked(ctx)
	in.RLS, in.RLSChecked = d.rls(ctx)
	h := pulse.Evaluate(in, time.Now())
	if why := d.needsSession(ctx); why != "" {
		for i := range h.Findings {
			for j, fx := range h.Findings[i].Fixes {
				if fx.Kind == protocol.FixMaintenance && fx.Available {
					h.Findings[i].Fixes[j].Available, h.Findings[i].Fixes[j].Reason = false, why
				}
			}
		}
	}
	return h, nil
}

// needsSession says why the fixes that run in PostgreSQL itself (vacuum,
// indexes, ending a session, ...) can't run through this connection: it
// goes through a connection pooler, where they can't keep one session
// with their own lock and statement timeouts ("" when they can, or when
// that can't be told: the fix then connects and says).
func (d *DB) needsSession(ctx context.Context) string {
	if d.conn == nil {
		return "" // MySQL, MongoDB, Redis: the fixes check their session themselves
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pooler == nil {
		p, err := d.inspectTarget().Pooler(ctx)
		if err != nil {
			return ""
		}
		d.pooler = &p
	}
	if *d.pooler == "" {
		return ""
	}
	return pginspect.PoolerReason(*d.pooler)
}

// rls reads the database's row-level security (false when it can't be
// read: the check is then left out).
func (d *DB) rls(ctx context.Context) ([]protocol.RLSDatabase, bool) {
	conn, err := d.inspectTarget().Connect(ctx, d.inspectTarget().MaintenanceDB())
	if err != nil {
		return nil, false
	}
	defer conn.Close(context.WithoutCancel(ctx))
	r, err := pginspect.ReadRLS(ctx, conn)
	switch {
	case err != nil:
		return nil, false
	case r == nil:
		return nil, true
	}
	return []protocol.RLSDatabase{*r}, true
}

// settingsLocked says why this connection can't change settings: ALTER
// SYSTEM needs a superuser, or from PostgreSQL 15 a grant on the setting
// ("" when it can, or when that can't be told: the change then says).
func (d *DB) settingsLocked(ctx context.Context) string {
	conn, err := d.inspectTarget().Connect(ctx, d.inspectTarget().MaintenanceDB())
	if err != nil {
		return ""
	}
	defer conn.Close(context.WithoutCancel(ctx))
	var super bool
	var version int
	if err := conn.QueryRow(ctx, `SELECT current_setting('is_superuser') = 'on', current_setting('server_version_num')::int`).Scan(&super, &version); err != nil || super {
		return ""
	}
	if version >= 150000 {
		var granted bool
		if err := conn.QueryRow(ctx, `SELECT has_parameter_privilege('shared_buffers', 'ALTER SYSTEM')`).Scan(&granted); err != nil || granted {
			return ""
		}
	}
	return fmt.Sprintf("Changing settings needs a superuser (ALTER SYSTEM), and %s isn't one. On a managed database, change them in your provider's console.", d.conn.User)
}

func (d *DB) input(r *collect.Reading, opts Options) pulse.Input {
	return pulse.Input{Database: d.Name(), Host: d.Host(), Metrics: r.Metrics, Activity: r.Activity,
		Slots: r.ReplicationSlots, Replication: r.Replication, Insights: r.Insights, Settings: r.Settings,
		VersionNum: r.VersionNum, Workload: opts.Workload, Disk: opts.Disk, Local: r.Local, Command: d.Command,
		Forecast: opts.Forecast, Regressions: opts.Regressions}
}

// Insights reads tables and indexes: sizes, estimated bloat, unused and
// duplicate indexes, sequential scans, dead rows and transaction ID age.
func (d *DB) Insights(ctx context.Context) (*protocol.Insights, error) {
	if d.mg != nil {
		return d.mongoInsights(ctx)
	}
	if d.rd != nil {
		return nil, errRedisNotHere("insights", d.Command("pulse")+" shows its memory, keys and slow commands")
	}
	if d.my != nil {
		return d.mysqlInsights(ctx)
	}
	ins, err := collect.CollectInsights(ctx, d.collectTarget())
	if err != nil {
		return nil, d.connectError(err)
	}
	ins.CollectedAt = time.Now().UTC()
	return ins, nil
}

// Statements reads the top of pg_stat_statements (MySQL, MariaDB:
// performance_schema's statement digests; MongoDB: the profiler's slow
// operations): totals since it was last reset.
func (d *DB) Statements(ctx context.Context) (*protocol.Statements, error) {
	if d.mg != nil {
		return d.mongoStatements(ctx)
	}
	if d.rd != nil {
		return nil, errRedisNotHere("top", d.Command("pulse")+" lists the slow commands of the last hour")
	}
	if d.my != nil {
		return d.mysqlStatements(ctx)
	}
	r, err := d.read(ctx, collect.ReadOptions{Statements: true, QueryText: true}, Options{})
	if err != nil {
		return nil, err
	}
	if r.Statements == nil {
		return &protocol.Statements{Statements: []protocol.StatementStat{}, Reason: "pg_stat_statements couldn't be read"}, nil
	}
	return r.Statements, nil
}

// Activity reads the sessions running one query, or idle in a
// transaction, for over a minute, and who blocks whom.
func (d *DB) Activity(ctx context.Context) (*protocol.Activity, error) {
	if d.mg != nil {
		return d.mongoActivity(ctx)
	}
	if d.rd != nil {
		return nil, errRedisNotHere("activity", d.Command("pulse")+" lists the connections that look stuck, with a fix to disconnect each")
	}
	if d.my != nil {
		return d.mysqlActivity(ctx)
	}
	r, err := d.read(ctx, collect.ReadOptions{QueryText: true}, Options{})
	if err != nil {
		return nil, err
	}
	return r.Activity, nil
}

// Settings reads the settings that matter and what would suit the server.
func (d *DB) Settings(ctx context.Context, opts Options) (protocol.SettingsOverview, error) {
	if d.mg != nil {
		return d.mongoSettings(ctx, opts)
	}
	if d.rd != nil {
		return d.redisSettings(ctx, opts)
	}
	if d.my != nil {
		return d.mysqlSettings(ctx, opts)
	}
	snap, err := collect.ReadSettings(ctx, d.collectTarget(), "")
	if err != nil {
		return protocol.SettingsOverview{}, d.connectError(err)
	}
	snap.CollectedAt = time.Now().UTC()
	d.hostFacts(snap, opts)
	ov := tune.Overview(protocol.EnginePostgreSQL, snap, opts.Workload, opts.Disk, 0)
	if why := d.settingsLocked(ctx); why != "" && ov.CanChange {
		ov.CanChange, ov.ChangeReason = false, why
	}
	return ov, nil
}

// FixResult is what applying a fix did.
type FixResult struct {
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
	// Log is the step-by-step log (the statements run).
	Log string `json:"log,omitempty"`
}

// ErrFixGone: the finding or fix isn't there any more (resolved, or the
// session ended).
var ErrFixGone = errors.New("not found")

// ApplyFix evaluates the database again and applies the fix fixID of the
// finding findingID only if that evaluation proposes it, with its fresh
// parameters.
func (d *DB) ApplyFix(ctx context.Context, findingID, fixID string, opts Options) (FixResult, error) {
	h, err := d.Health(ctx, opts)
	if err != nil {
		return FixResult{}, err
	}
	for _, f := range h.Findings {
		if f.ID != findingID {
			continue
		}
		for _, fx := range f.Fixes {
			if fx.ID == fixID {
				return d.run(ctx, fx)
			}
		}
		return FixResult{}, fmt.Errorf("%w: %q has no fix %q now", ErrFixGone, f.Title, fixID)
	}
	return FixResult{}, fmt.Errorf("%w: no finding %q now (it may have been resolved)", ErrFixGone, findingID)
}

// Apply applies a fix of an evaluation of this database (Health) that the
// person just chose; ApplyFix evaluates again first, for callers that only
// have IDs. Either way the fix's code checks every name and condition again
// before it changes anything.
func (d *DB) Apply(ctx context.Context, fx protocol.FindingFix) (FixResult, error) {
	return d.run(ctx, fx)
}

func (d *DB) run(ctx context.Context, fx protocol.FindingFix) (FixResult, error) {
	if !fx.Available {
		return FixResult{}, fmt.Errorf("%q can't run now: %s", fx.Label, fx.Reason)
	}
	switch fx.Kind {
	case protocol.FixMaintenance:
		if why := d.needsSession(ctx); why != "" {
			return FixResult{}, fmt.Errorf("%q can't run now: %s", fx.Label, why)
		}
		var p protocol.MaintenanceParams
		if err := json.Unmarshal(fx.Params, &p); err != nil {
			return FixResult{}, err
		}
		if d.my != nil {
			return d.mysqlMaintain(ctx, p)
		}
		if d.mg != nil {
			return d.mongoMaintain(ctx, p)
		}
		if d.rd != nil {
			return d.redisMaintain(ctx, p)
		}
		res, log, err := maintenance.Maintain(ctx, d.inspectTarget(), p)
		out := FixResult{Log: log}
		if res != nil {
			out.Summary, out.Details = res.Summary, res.Details
		}
		return out, err
	case protocol.FixTune:
		var p protocol.SettingsParams
		if err := json.Unmarshal(fx.Params, &p); err != nil {
			return FixResult{}, err
		}
		res, err := d.ChangeSettings(ctx, p)
		return res, err
	}
	return FixResult{}, fmt.Errorf("%q needs the Rowsafe agent on the server", fx.Label)
}

// ChangeSettings changes settings with ALTER SYSTEM and a reload (MySQL:
// SET PERSIST; nothing restarts), after checking the values against this
// server. MariaDB's are refused: they live in its configuration file.
func (d *DB) ChangeSettings(ctx context.Context, p protocol.SettingsParams) (FixResult, error) {
	if d.mg != nil {
		return FixResult{}, errors.New(mongoSettingsLocked)
	}
	if d.rd != nil {
		return d.redisChangeSettings(ctx, p)
	}
	if d.my != nil {
		return d.mysqlChangeSettings(ctx, p)
	}
	res, log, err := maintenance.ChangeSettings(ctx, d.inspectTarget(), d.collectTarget(), p)
	return settingsResult(res, log), err
}

// settingsResult is what a settings change did.
func settingsResult(res *protocol.SettingsResult, log string) FixResult {
	out := FixResult{Log: log}
	if res != nil {
		out.Summary = res.Summary
		for _, a := range res.Applied {
			line := fmt.Sprintf("%s: %s -> %s", a.Name, a.From, a.To)
			if a.Restart {
				line += " (after a restart)"
			}
			out.Details = append(out.Details, line)
		}
	}
	return out
}
