// Package qdrant is Rowsafe's Qdrant engine: Qdrant's own full storage
// snapshots, taken over its API and encrypted on the server into the
// customer's bucket; Proof and Rewind (a copy, rewind in place with Undo)
// on a private temporary Qdrant; Marks; Pulse with fixes; the security
// check; API keys in Databases & users; certificates for Rowsafe Cloud
// names; restarts and discovery for the installer (protocol/qdrant.go).
package qdrant

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func init() {
	agent.RegisterEngine(&Engine{})
}

// Engine implements agent.Engine and its optional interfaces for Qdrant.
type Engine struct {
	mu      sync.Mutex
	started bool
	copies  *copyStore
	mon     monitorState
	locks   map[string]*sync.Mutex
	// copyMu serializes the restores into temporary servers (Proof,
	// copies, rewinds in place).
	copyMu sync.Mutex
	// pending are full snapshots taken on the server and not deleted yet
	// (pending.json in the state directory).
	pendingPath string
	pending     []string
}

var (
	_ agent.Engine                = (*Engine)(nil)
	_ agent.EngineStarter         = (*Engine)(nil)
	_ agent.EngineRewinds         = (*Engine)(nil)
	_ agent.EngineRestarter       = (*Engine)(nil)
	_ agent.EngineStorage         = (*Engine)(nil)
	_ agent.EngineCertificates    = (*Engine)(nil)
	_ agent.EngineSecurityChecker = (*Engine)(nil)
)

// Name is protocol.EngineQdrant.
func (e *Engine) Name() string { return protocol.EngineQdrant }

// Tasks are the task types the engine runs.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill,
		protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop,
		protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup,
		protocol.TaskDBAdmin,
	}
}

// dbLock serializes snapshots of one database (a Mark and a backup at once
// would make Qdrant take two full snapshots side by side).
func (e *Engine) dbLock(id string) *sync.Mutex {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.locks == nil {
		e.locks = map[string]*sync.Mutex{}
	}
	l := e.locks[id]
	if l == nil {
		l = &sync.Mutex{}
		e.locks[id] = l
	}
	return l
}

// Start runs the engine's background work: copies are started again after
// an agent restart, interrupted rewinds in place settled, and expired
// copies and kept data deleted.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()
	e.loadPending(env)
	e.recoverCopies(ctx, env)
	go e.recoverInPlace(ctx, env)
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
			e.expireKept(ctx, env, time.Now())
		}
	}()
}

// ---- snapshots left on the server

func (e *Engine) loadPending(env agent.EngineEnv) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pendingPath = filepath.Join(env.StateDir, "pending-snapshots.json")
	_ = loadJSONFile(e.pendingPath, &e.pending)
}

func (e *Engine) savePendingLocked() {
	if e.pendingPath != "" {
		_ = saveJSONFile(e.pendingPath, e.pending)
	}
}

func (e *Engine) pendingAdd(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !slices.Contains(e.pending, name) {
		e.pending = append(e.pending, name)
	}
	e.savePendingLocked()
}

func (e *Engine) pendingDone(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending = slices.DeleteFunc(e.pending, func(s string) bool { return s == name })
	e.savePendingLocked()
}

// cleanPending deletes the full snapshots Rowsafe took and couldn't delete
// (an agent stopped in the middle, the server unreachable for a moment):
// they take room on the server's disk.
func (e *Engine) cleanPending(ctx context.Context, c *client, tl agent.TaskLogger) {
	e.mu.Lock()
	left := slices.Clone(e.pending)
	e.mu.Unlock()
	for _, name := range left {
		if err := c.deleteFullSnapshot(ctx, name); err == nil {
			e.pendingDone(name)
			tl.Printf("deleted snapshot %s, left on the server's disk by an earlier backup", name)
		}
	}
}

// Run runs one task.
func (e *Engine) Run(ctx context.Context, env agent.EngineEnv, task *protocol.Task, tl agent.TaskLogger) (any, error) {
	db := *task.Database
	if e.pendingPath == "" {
		e.loadPending(env)
	}
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
	return nil, fmt.Errorf("Qdrant databases can't run %s tasks", task.Type)
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
