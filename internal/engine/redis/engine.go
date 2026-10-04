// Package redis is Rowsafe's Redis and Valkey engine: snapshots taken over
// the replication handshake and the replication stream followed by a
// hidden replica, both encrypted on the server into the customer's bucket;
// Proof, Rewind (a copy at any second, compare, bring keys back, rewind in
// place with Undo), Marks, Pulse with fixes, restarts and discovery for the
// installer. It registers itself twice (agent.RegisterEngine): as "redis"
// and as "valkey", which speak the same protocol and keep the same files.
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func init() {
	agent.RegisterEngine(&Engine{name: protocol.EngineRedis})
	agent.RegisterEngine(&Engine{name: protocol.EngineValkey})
}

// Engine implements agent.Engine and its optional interfaces for Redis or
// Valkey.
type Engine struct {
	name string

	mu        sync.Mutex
	ctx       context.Context // the agent's lifetime (Start); Background before
	started   bool
	followers map[string]*follower
	copies    *copyStore
	mon       monitorState
	// copyMu serializes the restores into temporary servers (copies,
	// rewinds in place); Proof runs on the main lane too.
	copyMu sync.Mutex
}

var (
	_ agent.Engine          = (*Engine)(nil)
	_ agent.EngineArchiver  = (*Engine)(nil)
	_ agent.EngineStarter   = (*Engine)(nil)
	_ agent.EngineRewinds   = (*Engine)(nil)
	_ agent.EngineRestarter = (*Engine)(nil)
	_ agent.EngineStorage   = (*Engine)(nil)
)

// Name is protocol.EngineRedis or EngineValkey.
func (e *Engine) Name() string { return e.name }

func (e *Engine) display() string { return protocol.EngineDisplayName(e.name) }

// Tasks are the task types the engine runs.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill,
		protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
		protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup,
		protocol.TaskFindMoment,                        // moment.go
		protocol.TaskSafeCopy, protocol.TaskCopySchema, // copies_safe.go, copies_mask.go
		protocol.TaskDBAdmin,
		protocol.TaskSettings,
	}
}

func (e *Engine) baseCtx() context.Context {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx != nil {
		return e.ctx
	}
	return context.Background()
}

// Start runs the engine's background work: copies are started again after
// an agent restart, interrupted rewinds in place are finished, expired
// copies and kept data are deleted, and links of databases no longer
// watched are stopped.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started, e.ctx = true, ctx
	e.mu.Unlock()
	e.recoverCopies(ctx, env)
	go e.recoverInPlace(ctx, env)
	go e.recoverSafeCopies(ctx, env) // copies_safe.go
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			e.expireCopies(env, time.Now())
			e.expireSafeCopies(env, time.Now())
			e.expireKept(ctx, env, time.Now())
			e.stopIdleFollowers(10 * time.Minute)
		}
	}()
}

// Run runs one task.
func (e *Engine) Run(ctx context.Context, env agent.EngineEnv, task *protocol.Task, tl agent.TaskLogger) (any, error) {
	db := *task.Database
	switch task.Type {
	case protocol.TaskInspect:
		return nilIfNil(e.inspectTask(ctx, env, db))
	case protocol.TaskAdopt:
		var p protocol.AdoptParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.adopt(ctx, env, db, p, tl))
	case protocol.TaskCheck:
		return nilIfNil(e.check(ctx, env, db, tl))
	case protocol.TaskBackup:
		p := protocol.BackupParams{Type: protocol.BackupFull}
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.backup(ctx, env, db, p, tl))
	case protocol.TaskDrill:
		return nilIfNil(e.drill(ctx, env, db, task.ID, tl))
	case protocol.TaskRestorePoint:
		var p protocol.RestorePointParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.mark(ctx, env, db, p, tl))
	case protocol.TaskMaintenance:
		var p protocol.MaintenanceParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.maintenance(ctx, env, db, p, tl))
	case protocol.TaskRewindCopy:
		var p protocol.RewindCopyParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindCopy(ctx, env, db, p, tl))
	case protocol.TaskRewindDrop:
		var p protocol.RewindDropParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindDrop(ctx, env, db, p, tl))
	case protocol.TaskRewindCompare:
		var p protocol.RewindCompareParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindCompare(ctx, env, db, p, tl))
	case protocol.TaskRewindRows:
		var p protocol.RewindRowsParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindRows(ctx, env, db, p, tl))
	case protocol.TaskRewindInPlace:
		var p protocol.RewindInPlaceParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindInPlace(ctx, env, db, p, tl))
	case protocol.TaskRewindUndo:
		var p protocol.RewindUndoParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindUndo(ctx, env, db, p, tl))
	case protocol.TaskSafeCopy:
		var p protocol.SafeCopyParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.safeCopy(ctx, env, db, p, tl))
	case protocol.TaskCopySchema:
		return nilIfNil(e.copySchema(ctx, env, db))
	case protocol.TaskFindMoment:
		var p protocol.FindMomentParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.findMoment(ctx, env, db, p, tl))
	case protocol.TaskSettings:
		var p protocol.SettingsParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.settingsTask(ctx, env, db, p, tl))
	case protocol.TaskRewindCleanup:
		var p protocol.RewindCleanupParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.rewindCleanup(ctx, env, db, p, tl))
	case protocol.TaskDBAdmin:
		var p protocol.DBAdminParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.dbadmin(ctx, env, db, task.ID, p, tl))
	}
	return nil, fmt.Errorf("%s databases can't run %s tasks", e.display(), task.Type)
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

// nilIfNil keeps a typed nil pointer out of the result interface.
func nilIfNil[R any](r *R, err error) (any, error) {
	if r == nil {
		return nil, err
	}
	return r, err
}

func (e *Engine) inspectTask(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.InspectResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	r := in.inspectResult(e.name, db.Port, e.archiveMode(db))
	return &r, nil
}

// archiveMode is InspectResult.ArchiveMode: "on" while the link follows
// the server, "snapshots" when it can't.
func (e *Engine) archiveMode(db protocol.DatabaseSpec) string {
	e.mu.Lock()
	f := e.followers[db.ID]
	e.mu.Unlock()
	if f == nil {
		return "on"
	}
	st := f.snapshot()
	if st.Mode == modeSnapshots {
		return protocol.RedisArchiveSnapshots
	}
	return "on"
}
