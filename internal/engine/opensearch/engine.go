// Package opensearch is Rowsafe's OpenSearch engine: OpenSearch's own
// snapshots into a repository on the server's disk, copied to the
// customer's bucket encrypted on the server; Proof (restore tests in a
// temporary OpenSearch), Rewind (a copy at a snapshot, compare, bring
// documents back, rewind in place with Undo), Marks (snapshots on the
// spot), Pulse with fixes, Databases & users (the security plugin's users
// and roles), certificates for Rowsafe Cloud names, restarts and discovery
// for the installer. It registers itself with the agent
// (agent.RegisterEngine); the agent binary imports it for that.
package opensearch

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func init() { agent.RegisterEngine(&Engine{}) }

// Engine implements agent.Engine and its optional interfaces for
// OpenSearch.
type Engine struct {
	mu      sync.Mutex
	started bool
	copies  *copyStore
	mon     monitorState
	// locks serialize, per database, everything that writes to its snapshot
	// repository (snapshots, deletions, the copy to the bucket): a backup on
	// the main lane and a Mark on the side lane never overlap.
	locks sync.Map // database id -> *sync.Mutex
	// copyMu serializes restores into temporary servers (copies, Proof).
	copyMu sync.Mutex
}

var (
	_ agent.Engine          = (*Engine)(nil)
	_ agent.EngineStarter   = (*Engine)(nil)
	_ agent.EngineRewinds   = (*Engine)(nil)
	_ agent.EngineRestarter = (*Engine)(nil)
)

// Name is protocol.EngineOpenSearch.
func (e *Engine) Name() string { return protocol.EngineOpenSearch }

// repoLock is the database's repository lock.
func (e *Engine) repoLock(db protocol.DatabaseSpec) *sync.Mutex {
	l, _ := e.locks.LoadOrStore(db.ID, &sync.Mutex{})
	return l.(*sync.Mutex)
}

// Tasks are the task types the engine runs.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill,
		protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
		protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup,
		protocol.TaskDBAdmin,
	}
}

// Start runs the engine's background work: copies are started again after
// an agent restart, expired copies are removed and snapshots kept for Undo
// are deleted once their time is up.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()
	e.recoverCopies(ctx, env)
	go e.sweepDrills(env)
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
	return nil, fmt.Errorf("OpenSearch databases can't run %s tasks", task.Type)
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
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	r := in.inspectResult(db.Port)
	return &r, nil
}

// sweepDrills removes temporary servers a restore test left when the agent
// stopped in the middle of it (only folders with the scratch marker; the
// agent's own sweep of the drill folder looks at its top level only).
func (e *Engine) sweepDrills(env agent.EngineEnv) {
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	root := drillRoot(env)
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, d := range entries {
		dir := filepath.Join(root, d.Name())
		if !d.IsDir() || !idRE.MatchString(d.Name()) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, scratchMarker)); err != nil {
			continue
		}
		if _, err := scratchAt(dir).remove(); err != nil {
			env.Log.Error("removing a leftover restore test failed", "dir", dir, "err", err)
		} else {
			env.Log.Warn("removed a leftover restore test (decrypted copy) from an interrupted run", "dir", dir)
		}
	}
	_ = os.Remove(root)
}
