// Package mongodb is Rowsafe's MongoDB engine: backups (mongodump) and
// continuous oplog copying into the customer's bucket, encrypted on the
// server; Proof (restore tests), Rewind (a copy at any second, compare,
// bring documents back), Marks, monitoring (Pulse) and discovery for the
// installer. It registers itself with the agent (agent.RegisterEngine);
// the agent binary imports it for that.
package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func init() { agent.RegisterEngine(&Engine{}) }

// Engine implements agent.Engine (and EngineArchiver, EngineStarter,
// EngineRewinder) for MongoDB.
type Engine struct {
	mu       sync.Mutex
	ctx      context.Context // the agent's lifetime (Start); Background before
	shippers map[string]*shipper
	copies   *copyStore
	started  bool
	mon      monitorState
	// copyMu serializes copy restores (at most one per database, and the
	// main lane runs one task at a time anyway).
	copyMu sync.Mutex
}

var (
	_ agent.Engine         = (*Engine)(nil)
	_ agent.EngineArchiver = (*Engine)(nil)
	_ agent.EngineStarter  = (*Engine)(nil)
	_ agent.EngineRewinds  = (*Engine)(nil)
)

// Name is protocol.EngineMongoDB.
func (e *Engine) Name() string { return protocol.EngineMongoDB }

// Tasks are the task types the engine runs.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill,
		protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
	}
}

func (e *Engine) baseCtx() context.Context {
	if e.ctx != nil {
		return e.ctx
	}
	return context.Background()
}

// Start runs the engine's background work: copies are started again after
// an agent restart, expired copies are deleted, and shippers of databases
// no longer watched are stopped.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started, e.ctx = true, ctx
	e.mu.Unlock()
	e.recoverCopies(ctx, env)
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
			e.stopIdleShippers(10 * time.Minute)
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
	}
	return nil, fmt.Errorf("MongoDB databases can't run %s tasks", task.Type)
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
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	r := in.inspectResult()
	return &r, nil
}

// Archiver reports continuous oplog copying for the heartbeat and keeps
// the database's shipper running.
func (e *Engine) Archiver(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error) {
	s, err := e.shipperFor(env, db)
	if err != nil {
		return nil, err
	}
	st, serr := s.snapshot()
	return archiverStats(st, serr, st.SetName), nil
}
