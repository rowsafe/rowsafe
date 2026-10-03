// Package clickhouse is Rowsafe's ClickHouse engine: backups (ClickHouse's
// own BACKUP, full and differential, through an encrypting gateway inside
// the agent, into the customer's bucket), Proof (restore tests in a
// temporary server), Rewind (a copy at a backup or a Mark, compare, bring
// rows back), Marks, monitoring (Pulse) with two fixes (stop a query,
// cancel a stuck mutation) and discovery for the installer. ClickHouse
// keeps no log of changes, so there are no restores to any second. It
// registers itself with the agent (agent.RegisterEngine); the agent binary
// imports it for that.
package clickhouse

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

// Engine implements agent.Engine (and EngineStarter, EngineRewinds) for
// ClickHouse.
type Engine struct {
	mu      sync.Mutex
	copies  *copyStore
	started bool
	mon     monitorState
	// copyMu serializes copy restores (at most one per database, and the
	// main lane runs one task at a time anyway).
	copyMu sync.Mutex
	// bases holds, per database, a read lock for every differential backup
	// (a Mark too) while it runs: retention, which takes the write lock,
	// never deletes the full backup one reads from.
	bases sync.Map // database id -> *sync.RWMutex
}

// baseLock is the database's lock between differential backups and
// retention (see bases).
func (e *Engine) baseLock(db protocol.DatabaseSpec) *sync.RWMutex {
	l, _ := e.bases.LoadOrStore(db.ID, &sync.RWMutex{})
	return l.(*sync.RWMutex)
}

var (
	_ agent.Engine        = (*Engine)(nil)
	_ agent.EngineStarter = (*Engine)(nil)
	_ agent.EngineRewinds = (*Engine)(nil)
)

// Name is protocol.EngineClickHouse.
func (e *Engine) Name() string { return protocol.EngineClickHouse }

// Tasks are the task types the engine runs.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill,
		protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
		protocol.TaskDBAdmin, protocol.TaskSettings,
		protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup,
		protocol.TaskPreviewMigration, protocol.TaskCopySchema, protocol.TaskSafeCopy,
		protocol.TaskIndexAdvisor, protocol.TaskPooling, protocol.TaskPoolerRetarget,
	}
}

// Start runs the engine's background work: copies are started again after
// an agent restart, and expired copies are deleted.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started = true
	e.mu.Unlock()
	e.recoverCopies(ctx, env)
	go e.recoverInPlace(ctx, env) // inplace.go
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
	case protocol.TaskPooling: // pooling.go
		var p protocol.PoolingParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.pooling(ctx, env, db, p, tl))
	case protocol.TaskPoolerRetarget:
		var p protocol.PoolerRetargetParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.poolerRetarget(ctx, env, db, p, tl))
	case protocol.TaskIndexAdvisor: // advisor.go
		var p protocol.IndexAdvisorParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.indexAdvisor(ctx, env, db, task.ID, p, tl))
	case protocol.TaskSafeCopy:
		var p protocol.SafeCopyParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.safeCopy(ctx, env, db, p, tl))
	case protocol.TaskCopySchema:
		return nilIfNil(e.copySchema(ctx, env, db))
	case protocol.TaskPreviewMigration:
		var p protocol.PreviewParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.previewMigration(ctx, env, db, task.ID, p, tl))
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
	case protocol.TaskSettings:
		var p protocol.SettingsParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.settingsTask(ctx, env, db, p, tl))
	case protocol.TaskDBAdmin:
		var p protocol.DBAdminParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.dbadmin(ctx, env, db, task.ID, p, tl))
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
	}
	return nil, fmt.Errorf("ClickHouse databases can't run %s tasks", task.Type)
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
