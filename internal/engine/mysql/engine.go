// Package mysql is the agent's MySQL and MariaDB engine: backups with
// Percona XtraBackup (MySQL) or mariadb-backup (MariaDB), streamed,
// compressed and encrypted on this server into the customer's bucket;
// continuous shipping of the binary logs for restores to any second;
// restore tests (Proof), copies to compare and bring rows back (Rewind),
// named points (Marks), monitoring (Pulse) and safe fixes.
//
// The package registers two engines, "mysql" and "mariadb", which share the
// code and differ only in their tools and SQL dialect (flavor). The agent
// binary imports it for its side effect:
//
//	import _ "github.com/rowsafe/rowsafe/internal/engine/mysql"
package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func init() {
	agent.RegisterEngine(&Engine{flavor: flavorMySQL})
	agent.RegisterEngine(&Engine{flavor: flavorMariaDB})
}

// flavor is MySQL or MariaDB.
type flavor string

const (
	flavorMySQL   flavor = protocol.EngineMySQL
	flavorMariaDB flavor = protocol.EngineMariaDB
)

func (f flavor) mariadb() bool { return f == flavorMariaDB }

// display is the engine's name for people.
func (f flavor) display() string { return protocol.EngineDisplayName(string(f)) }

// Engine is the MySQL or the MariaDB engine.
type Engine struct {
	flavor flavor
}

var (
	_ agent.Engine         = (*Engine)(nil)
	_ agent.EngineArchiver = (*Engine)(nil)
	_ agent.EngineRewinds  = (*Engine)(nil)
)

// Name is protocol.EngineMySQL or protocol.EngineMariaDB.
func (e *Engine) Name() string { return string(e.flavor) }

// Tasks are the task types the engine runs. Rewind in place and restart
// are not among them yet.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup,
		protocol.TaskDrill, protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
	}
}

// Run runs one task.
func (e *Engine) Run(ctx context.Context, env agent.EngineEnv, task *protocol.Task, log agent.TaskLogger) (any, error) {
	db := *task.Database
	s := e.server(env, db)
	switch task.Type {
	case protocol.TaskInspect:
		return nilable(s.inspect(ctx))
	case protocol.TaskAdopt:
		var p protocol.AdoptParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.adopt(ctx, p, log))
	case protocol.TaskCheck:
		return nilable(s.check(ctx, log))
	case protocol.TaskBackup:
		p := protocol.BackupParams{Type: protocol.BackupFull}
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.backup(ctx, p.Type, log))
	case protocol.TaskDrill:
		return nilable(s.drill(ctx, task.ID, log))
	case protocol.TaskRestorePoint:
		var p protocol.RestorePointParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.mark(ctx, p, log))
	case protocol.TaskMaintenance:
		var p protocol.MaintenanceParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.maintenance(ctx, p, log))
	case protocol.TaskRewindCopy:
		var p protocol.RewindCopyParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.rewindCopy(ctx, p, log))
	case protocol.TaskRewindDrop:
		var p protocol.RewindDropParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.rewindDrop(ctx, p, log))
	case protocol.TaskRewindCompare:
		var p protocol.RewindCompareParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.rewindCompare(ctx, p, log))
	case protocol.TaskRewindRows:
		var p protocol.RewindRowsParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilable(s.rewindRows(ctx, p, log))
	}
	return nil, fmt.Errorf("unsupported %s task %q", e.flavor.display(), task.Type)
}

// Monitor collects one monitoring sample.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	return e.server(env, db).monitor(ctx)
}

// Archiver reports binary log shipping for the heartbeat, and keeps the
// shipper and the copies' housekeeping running.
func (e *Engine) Archiver(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error) {
	s := e.server(env, db)
	rewinds(env).housekeeping(env)
	return s.archiver(ctx)
}

// RewindStates lists this engine's copies for the heartbeat.
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	return rewinds(env).states(string(e.flavor))
}

// SetRewindExpiries applies the expiries Rowsafe asks for (Extend).
func (e *Engine) SetRewindExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	rewinds(env).setExpiries(exp)
}

// server is the engine's view of one database server.
func (e *Engine) server(env agent.EngineEnv, db protocol.DatabaseSpec) *server {
	return &server{flavor: e.flavor, env: env, db: db, cfg: loadConfig(env)}
}

// server is one MySQL or MariaDB server (a Rowsafe database).
type server struct {
	flavor flavor
	env    agent.EngineEnv
	db     protocol.DatabaseSpec
	cfg    config
}

// nilable keeps a typed nil pointer out of the task result.
func nilable[R any](r *R, err error) (any, error) {
	if r == nil {
		return nil, err
	}
	return r, err
}

func decode(task *protocol.Task, v any) error {
	if len(task.Params) == 0 {
		return nil
	}
	if err := json.Unmarshal(task.Params, v); err != nil {
		return fmt.Errorf("invalid %s params: %w", task.Type, err)
	}
	return nil
}

// markNameRE is also enforced by the control plane (restore point names).
var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// idRE is the shape of copy IDs: they become directory names.
var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// stanzaRE is the shape of database names in Rowsafe (bucket paths).
var stanzaRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// plural: "1 table", "3 tables".
func plural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%s %s", commas(n), many)
}

// commas formats n with thousands separators: 1,204.
func commas(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
