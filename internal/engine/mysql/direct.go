package mysql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Without the agent: a MySQL or MariaDB server reached with a connection
// string (rowsafe pulse mysql://...). The reads are the agent's monitoring
// queries, taken once; the fixes and settings changes are the agent's own
// code, with its checks, on that connection. What needs the server itself
// is left out or refused: the disk when the server isn't on this machine
// (and so rebuilding a table, which needs room checked), MariaDB's
// settings (kept in its configuration file), backups.

// Conn is a server reached with a connection string.
type Conn struct {
	// Config is the driver's configuration (user, password, address,
	// database, TLS).
	Config *mysqldriver.Config
	// Local: the server runs on this machine (localhost or a socket), so
	// its data directory's disk can be read here.
	Local bool
}

// Reading is one reading of the server.
type Reading struct {
	protocol.DatabaseMonitoring
	CollectedAt time.Time
	// Engine is protocol.EngineMySQL or EngineMariaDB, from its version.
	Engine     string
	Version    string
	VersionNum int
	// Notes say what this connection couldn't read, in plain words.
	Notes []string
	// SettingsLocked says why settings can't be changed with this
	// connection; "" when they can.
	SettingsLocked string
}

// ReadOptions says what a Reading includes besides the metrics, sessions
// and replication.
type ReadOptions struct {
	Statements, Insights, Settings bool
	// QueryText includes statement text in the activity.
	QueryText bool
}

// direct is the server for a connection.
func direct(ctx context.Context, c Conn) (*server, *sql.DB, error) {
	s := &server{direct: c.Config, local: c.Local}
	db, err := s.open(ctx)
	if err != nil {
		return nil, nil, err
	}
	var version string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		db.Close()
		return nil, nil, err
	}
	s.flavor = flavorMySQL
	if strings.Contains(strings.ToLower(version), "mariadb") {
		s.flavor = flavorMariaDB
	}
	return s, db, nil
}

// openDirect connects with the connection's own configuration. DDL waits
// at most 10 seconds for a table's metadata lock: a fix never queues the
// application's queries behind it for longer.
func (s *server) openDirect(ctx context.Context) (*sql.DB, error) {
	cfg := s.direct.Clone()
	cfg.ParseTime, cfg.Loc = true, time.UTC
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Params == nil {
		cfg.Params = map[string]string{}
	}
	cfg.Params["time_zone"] = "'+00:00'"
	cfg.Params["lock_wait_timeout"] = "10"
	conn, err := mysqldriver.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(conn)
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(time.Minute)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// account names the account the fixes run as, for errors.
func (s *server) accountWords() string {
	if s.direct != nil {
		return fmt.Sprintf("This connection's account (%s)", s.direct.User)
	}
	return "Rowsafe's database account"
}

// Read takes one reading. Rates (statements per second...) need two
// readings and are left out; the buffer pool's hit ratio is the one since
// the server started.
func Read(ctx context.Context, c Conn, o ReadOptions) (*Reading, error) {
	s, db, err := direct(ctx, c)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	// Reads stop after 30 seconds (SELECTs only: MySQL's
	// max_execution_time, MariaDB's max_statement_time).
	if s.flavor.mariadb() {
		_, _ = db.ExecContext(ctx, "SET SESSION max_statement_time = 30")
	} else {
		_, _ = db.ExecContext(ctx, "SET SESSION max_execution_time = 30000")
	}
	now := time.Now()
	out := &Reading{CollectedAt: now.UTC(), Engine: string(s.flavor)}
	dm := &out.DatabaseMonitoring
	dm.Metrics = map[string]float64{}
	m := dm.Metrics
	_ = db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&out.Version)
	_, out.VersionNum = numericVersion(out.Version)
	status, err := globalStatus(ctx, db)
	if err != nil {
		return nil, err
	}
	var maxConn float64
	_ = db.QueryRowContext(ctx, "SELECT @@max_connections").Scan(&maxConn)
	m[collect.MConnTotal] = status["Threads_connected"]
	m[collect.MConnMax] = maxConn
	if maxConn > 0 {
		m[collect.MConnUsedPct] = 100 * status["Threads_connected"] / maxConn
	}
	m[collect.MThreadsRunning] = status["Threads_running"]
	m[collect.MLocksWaiting] = status["Innodb_row_lock_current_waits"]
	if total := status["Innodb_buffer_pool_pages_total"]; total > 0 {
		m[collect.MBufferPoolUsedPct] = 100 * (total - status["Innodb_buffer_pool_pages_free"]) / total
	}
	if reqs, reads := status["Innodb_buffer_pool_read_requests"], status["Innodb_buffer_pool_reads"]; reqs > 1000 && reads >= 0 {
		m[collect.MCacheHitPct] = 100 * (1 - reads/reqs)
	}
	if v, ok := status["Innodb_history_list_length"]; ok { // MariaDB
		m[collect.MHistoryListLength] = v
	} else {
		var n float64
		if db.QueryRowContext(ctx, "SELECT count FROM information_schema.innodb_metrics WHERE name = 'trx_rseg_history_len'").Scan(&n) == nil {
			m[collect.MHistoryListLength] = n
		}
	}
	serverStart := now.Add(-time.Duration(status["Uptime"]) * time.Second).UTC().Truncate(time.Second)
	act, err := s.activity(ctx, db, serverStart, m)
	if err != nil {
		if isAccessDenied(err) {
			out.Notes = append(out.Notes, fmt.Sprintf("%s can't see the other sessions (it needs the PROCESS privilege): long transactions and locks aren't checked.", c.Config.User))
		} else {
			out.Notes = append(out.Notes, "Reading the sessions failed: "+firstLine(err.Error()))
		}
		for _, k := range []string{collect.MLongestXactSeconds, collect.MIdleInXactOldest, collect.MBlockedSessions, collect.MLongestBlockedSeconds, collect.MLongestQuerySeconds} {
			delete(m, k)
		}
		act = &protocol.Activity{CollectedAt: now.UTC(), Queries: []protocol.ActivityQuery{}}
	}
	if !o.QueryText {
		for i := range act.Queries {
			act.Queries[i].Query = ""
		}
		for i := range act.Blocking {
			act.Blocking[i].Query = ""
		}
	}
	act.QueryTextCollected = o.QueryText && act.QueryTextCollected
	dm.Activity = act
	s.replication(ctx, db, dm)
	var datadir string
	if c.Local && db.QueryRowContext(ctx, "SELECT @@datadir").Scan(&datadir) == nil {
		if free, err := freeBytes(datadir); err == nil {
			if total, err := totalBytes(datadir); err == nil && total > 0 {
				m[collect.MDiskTotalBytes], m[collect.MDiskFreeBytes] = float64(total), float64(free)
				m[collect.MDiskFreePct] = 100 * float64(free) / float64(total)
			}
		}
	}
	if dbs, _, err := schemaSizes(ctx, db); err == nil {
		var total int64
		for _, d := range dbs {
			dm.Sizes = append(dm.Sizes, protocol.DatabaseSize{Name: d.Name, SizeBytes: d.SizeBytes})
			total += d.SizeBytes
		}
		m[collect.MDatabaseSizeBytes] = float64(total)
	}
	if o.Statements {
		st := &monitorState{serverStart: serverStart}
		dm.Statements, _ = s.statements(ctx, db, st, now)
		if !o.QueryText {
			for i := range dm.Statements.Statements {
				dm.Statements.Statements[i].Query = ""
			}
		}
	}
	if o.Settings || o.Insights {
		snap, err := s.settingsSnapshot(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("reading settings: %w", err)
		}
		snap.CollectedAt = now.UTC()
		if o.Settings {
			dm.Settings = snap
		}
		out.SettingsLocked = s.settingsLocked(ctx, db)
	}
	if o.Insights {
		ins := s.insights(ctx, db, serverStart)
		if ins == nil {
			return nil, errors.New("reading tables and indexes failed")
		}
		dm.Insights = ins
	}
	return out, nil
}

// settingsLocked says why settings can't be changed over this connection.
func (s *server) settingsLocked(ctx context.Context, db *sql.DB) string {
	if s.flavor.mariadb() {
		return "MariaDB keeps lasting settings only in its configuration file on the server, which Rowsafe can't reach over a connection: " +
			"set them there (under [mariadb]) and restart MariaDB when it suits you, or let the Rowsafe agent on the server do it."
	}
	if !canSetVariables(ctx, db) {
		return fmt.Sprintf("Changing settings needs the SYSTEM_VARIABLES_ADMIN privilege (SET PERSIST), and %s doesn't have it. On a managed database, change them in your provider's console.", s.direct.User)
	}
	return ""
}

// Server is who and what a connection reaches.
type Server struct {
	Engine, Database, User, Version string
}

// Check connects once and reads who and what the connection reaches,
// changing nothing.
func Check(ctx context.Context, c Conn) (Server, error) {
	s, db, err := direct(ctx, c)
	if err != nil {
		return Server{}, err
	}
	defer db.Close()
	out := Server{Engine: string(s.flavor)}
	err = db.QueryRowContext(ctx, "SELECT COALESCE(DATABASE(), ''), CURRENT_USER(), VERSION()").Scan(&out.Database, &out.User, &out.Version)
	return out, err
}

// Maintain runs a fix (protocol.MaintenanceParams: stop a query, end a
// session, ANALYZE or OPTIMIZE TABLE, create or drop an index, turn on the
// slow query log) with the agent's checks. It returns the step-by-step log.
func Maintain(ctx context.Context, c Conn, p protocol.MaintenanceParams) (*protocol.MaintenanceResult, string, error) {
	s, db, err := direct(ctx, c)
	if err != nil {
		return nil, "", err
	}
	db.Close()
	tl := &textLog{}
	res, err := s.maintenance(ctx, p, tl)
	return res, tl.String(), err
}

// ChangeSettings changes MySQL's settings with SET PERSIST (they last
// across restarts; the ones read only at start wait for the next one,
// which Rowsafe never does). MariaDB's are refused: they live in its
// configuration file.
func ChangeSettings(ctx context.Context, c Conn, p protocol.SettingsParams) (*protocol.SettingsResult, string, error) {
	s, db, err := direct(ctx, c)
	if err != nil {
		return nil, "", err
	}
	why := s.settingsLocked(ctx, db)
	db.Close()
	if why != "" {
		return nil, "", errors.New(why)
	}
	tl := &textLog{}
	res, err := s.settings(ctx, p, tl)
	return res, tl.String(), err
}

// textLog collects a fix's log lines.
type textLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *textLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, "%s ", time.Now().UTC().Format("15:04:05"))
	fmt.Fprintf(&l.buf, format, args...)
	l.buf.WriteByte('\n')
}

func (l *textLog) Output(label string, out []byte) {
	if len(out) == 0 {
		return
	}
	l.Printf("%s:\n%s", label, out)
}

func (l *textLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// totalBytes is the size of the file system holding dir.
func totalBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Blocks) * int64(st.Bsize), nil
}
