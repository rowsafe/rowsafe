package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Engine runs tasks for a non-PostgreSQL database engine. PostgreSQL is
// built into the agent; every other engine registers itself (RegisterEngine,
// usually from an init function in its own package, which the agent binary
// imports). The agent routes a database's tasks, monitoring and discovery
// to the engine named by its DatabaseSpec.Engine.
type Engine interface {
	// Name is the engine: protocol.EngineMySQL, protocol.EngineMariaDB, ...
	Name() string
	// Tasks are the task types it handles (protocol.Task*). The agent fails
	// any other task for its databases with a plain "update the agent".
	Tasks() []string
	// Run runs one task; task.Database is set. The result is marshalled as
	// the task's result (return a nil interface, not a typed nil pointer,
	// when there is none). log is the log attached to the task.
	Run(ctx context.Context, env EngineEnv, task *protocol.Task, log TaskLogger) (any, error)
	// Monitor collects one monitoring sample of db, about once a minute,
	// with a 20-second deadline. DatabaseID may be left empty (the agent
	// fills it). nil, nil when the engine has no monitoring: db is then
	// left out of the report.
	Monitor(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error)
	// Discover finds the engine's running servers on this host for the
	// installer (rowsafe-agent setup discover). It may return nil. Servers
	// it skips are explained on env.Notes.
	Discover(ctx context.Context, env EngineEnv) ([]DiscoveredDatabase, error)
}

// EngineArchiver is optionally implemented by an engine with continuous
// archiving (binary log, oplog): the agent calls it with every heartbeat for
// each watched database and reports the result like PostgreSQL's
// pg_stat_archiver (ArchiveMode "on" once archiving works). nil, nil
// reports nothing.
type EngineArchiver interface {
	Archiver(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error)
}

// EngineRewinds is optionally implemented by an engine with Rewind copies:
// the agent reports them with every heartbeat next to PostgreSQL's (the
// control plane treats a copy it no longer hears about as gone) and hands
// it the expiries the control plane asks for (Extend).
type EngineRewinds interface {
	RewindStates(env EngineEnv) []protocol.RewindState
	SetRewindExpiries(env EngineEnv, exp []protocol.RewindExpiry)
}

// engineRewindStates are the registered engines' copies (heartbeat).
func (a *Agent) engineRewindStates() []protocol.RewindState {
	var out []protocol.RewindState
	for _, e := range registeredEngines() {
		if r, ok := e.(EngineRewinds); ok {
			out = append(out, r.RewindStates(a.engineEnv(e.Name()))...)
		}
	}
	return out
}

// setEngineRewindExpiries passes the heartbeat's expiries to the engines.
func (a *Agent) setEngineRewindExpiries(exp []protocol.RewindExpiry) {
	if len(exp) == 0 {
		return
	}
	for _, e := range registeredEngines() {
		if r, ok := e.(EngineRewinds); ok {
			r.SetRewindExpiries(a.engineEnv(e.Name()), exp)
		}
	}
}

// TaskLogger is the log attached to a task (what people see in the
// dashboard under the task).
type TaskLogger interface {
	// Printf adds a timestamped line.
	Printf(format string, args ...any)
	// Output adds a command's output under a label (nothing when empty).
	Output(label string, out []byte)
}

var _ TaskLogger = (*taskLog)(nil)

// CommandRunner runs a command and returns its combined output.
type CommandRunner = pgbackrest.Runner

// EngineEnv is what an engine gets from the agent.
type EngineEnv struct {
	// Config is the agent's configuration: ConfigDir, LogDir, DrillDir,
	// RewindDir, Mode, the restart helper's files... Engines read their own
	// settings (ROWSAFE_<ENGINE>_*) from the environment themselves.
	Config Config
	// StateDir is the engine's own state directory
	// (<ROWSAFE_STATE_DIR>/engines/<engine>). It is not created: MkdirAll
	// it (0700) before use.
	StateDir string
	// Repo is the backup storage (S3-compatible bucket, path prefix, keys,
	// client-side encryption passphrase), shared with PostgreSQL's
	// pgBackRest. Keep each engine's data under its own prefix.
	Repo pgbackrest.Repo
	// Runner runs commands (tests replace it).
	Runner CommandRunner
	// LowPriority prefixes a command to run it at low CPU and IO priority
	// (ionice/nice), like PostgreSQL backups and restore tests, so the
	// production database on the host comes first. Use RunLow.
	LowPriority []string
	// Log is the agent's log (not the task's).
	Log *slog.Logger
	// Notes takes side remarks for the person at the terminal during setup
	// discover (servers skipped and why); io.Discard elsewhere.
	Notes io.Writer
}

// RunLow runs a command at low CPU and IO priority (LowPriority).
func (e EngineEnv) RunLow(ctx context.Context, name string, args ...string) ([]byte, error) {
	if len(e.LowPriority) == 0 {
		return e.Runner.Run(ctx, name, args...)
	}
	full := append(append(slices.Clone(e.LowPriority[1:]), name), args...)
	return e.Runner.Run(ctx, e.LowPriority[0], full...)
}

// DiscoveredDatabase is one running database server an engine found on
// this host (Engine.Discover). The installer offers it like a PostgreSQL
// cluster.
type DiscoveredDatabase struct {
	Port      int
	SocketDir string   // Unix socket directory or path, "" when there is none
	Version   string   // server version, e.g. "8.4.3"
	Major     int      // major version, 0 when unknown
	Name      string   // instance name when the platform has one, "" elsewhere
	DataDir   string   // "" when unknown
	SizeBytes int64    // 0 when unknown
	Databases []string // user databases (schemas), without system ones
	Unit      string   // systemd unit running it, "" when unknown
}

var (
	enginesMu sync.RWMutex
	engines   = map[string]Engine{}
)

// RegisterEngine makes an engine available to the agent. It panics on a
// PostgreSQL, unknown or duplicate name: registration is a programming
// decision made at init time.
func RegisterEngine(e Engine) {
	name := e.Name()
	if name == protocol.EnginePostgreSQL || name != protocol.NormalizeEngine(name) || !protocol.ValidEngine(name) {
		panic(fmt.Sprintf("agent: RegisterEngine: invalid engine name %q", name))
	}
	enginesMu.Lock()
	defer enginesMu.Unlock()
	if _, dup := engines[name]; dup {
		panic(fmt.Sprintf("agent: RegisterEngine: %q registered twice", name))
	}
	engines[name] = e
}

// engineFor is the registered engine for name (nil when none is).
func engineFor(name string) Engine {
	enginesMu.RLock()
	defer enginesMu.RUnlock()
	return engines[name]
}

// registeredEngines lists the registered engines in protocol.Engines order.
func registeredEngines() []Engine {
	enginesMu.RLock()
	defer enginesMu.RUnlock()
	var out []Engine
	for _, name := range protocol.Engines {
		if e := engines[name]; e != nil {
			out = append(out, e)
		}
	}
	return out
}

// isPostgres reports whether db is a PostgreSQL database (the built-in
// engine).
func isPostgres(db protocol.DatabaseSpec) bool {
	return protocol.NormalizeEngine(db.Engine) == protocol.EnginePostgreSQL
}

// engineEnv is the EngineEnv the agent gives engine name.
func engineEnv(cfg Config, runner CommandRunner, log *slog.Logger, name string) EngineEnv {
	if runner == nil {
		runner = pgbackrest.ExecRunner{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return EngineEnv{
		Config:      cfg,
		StateDir:    filepath.Join(cfg.StateDir, "engines", name),
		Repo:        cfg.Repo,
		Runner:      runner,
		LowPriority: niceWrap(),
		Log:         log.With("engine", name),
		Notes:       io.Discard,
	}
}

func (a *Agent) engineEnv(name string) EngineEnv { return engineEnv(a.cfg, a.runner, a.log, name) }

// unsupportedEngine is the error for a database whose engine this agent
// doesn't have.
func unsupportedEngine(engine string) error {
	return fmt.Errorf("This agent doesn't support %s yet; update the agent (this is %s).",
		protocol.EngineDisplayName(engine), Version)
}

// runEngineTask runs a task for a non-PostgreSQL database on its engine.
func (a *Agent) runEngineTask(ctx context.Context, task *protocol.Task, tl *taskLog) (any, error) {
	name := protocol.NormalizeEngine(task.Database.Engine)
	e := engineFor(name)
	if e == nil {
		return nil, unsupportedEngine(name)
	}
	if !slices.Contains(e.Tasks(), task.Type) {
		return nil, fmt.Errorf("This agent can't run %s tasks for %s yet; update the agent (this is %s).",
			task.Type, protocol.EngineDisplayName(name), Version)
	}
	return e.Run(ctx, a.engineEnv(name), task, tl)
}

// monitorEngine collects a monitoring sample of a non-PostgreSQL database
// (collect.Options.Engine). An agent without the engine reports nothing
// for it.
func (a *Agent) monitorEngine(ctx context.Context, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	name := protocol.NormalizeEngine(db.Engine)
	e := engineFor(name)
	if e == nil {
		return nil, nil
	}
	dm, err := e.Monitor(ctx, a.engineEnv(name), db)
	if dm != nil && dm.DatabaseID == "" {
		dm.DatabaseID = db.ID
	}
	return dm, err
}

// engineArchiver reports a non-PostgreSQL database's continuous archiving
// for the heartbeat; ok is false when there is nothing to report.
func (a *Agent) engineArchiver(ctx context.Context, db protocol.DatabaseSpec) (stats protocol.ArchiverStats, ok bool) {
	name := protocol.NormalizeEngine(db.Engine)
	ar, _ := engineFor(name).(EngineArchiver)
	if ar == nil {
		return stats, false
	}
	st, err := ar.Archiver(ctx, a.engineEnv(name), db)
	switch {
	case err != nil:
		stats.Error = err.Error()
	case st == nil:
		return stats, false
	default:
		stats = *st
	}
	stats.DatabaseID = db.ID
	return stats, true
}

// ---- Optional engine hooks for background work and Rewind copies (MongoDB)

// EngineStarter is optionally implemented by an engine with work that runs
// beside tasks (continuous archiving, copies that outlive their task,
// housekeeping): Start is called once, when the agent starts, and must
// return quickly; ctx is cancelled when the agent stops.
type EngineStarter interface {
	Start(ctx context.Context, env EngineEnv)
}

// startEngines starts the registered engines' background work.
func (a *Agent) startEngines(ctx context.Context) {
	for _, e := range registeredEngines() {
		if s, ok := e.(EngineStarter); ok {
			s.Start(ctx, a.engineEnv(e.Name()))
		}
	}
}

// EngineEnvFor is the environment an engine gets, for commands outside the
// agent's run loop (installer helpers).
func EngineEnvFor(cfg Config, name string, notes io.Writer) EngineEnv {
	env := engineEnv(cfg, nil, nil, name)
	if notes != nil {
		env.Notes = notes
	}
	return env
}
