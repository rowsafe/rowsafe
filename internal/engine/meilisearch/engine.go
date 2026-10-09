// Package meilisearch is Rowsafe's Meilisearch engine (Community Edition):
// Meilisearch's own snapshots, encrypted on the server into the customer's
// bucket every hour; Proof; Rewind (a copy from a snapshot, compare and
// bring documents back, rewind in place through an atomic swap of indexes,
// with Undo); Marks; Pulse with fixes; Databases & users (indexes and API
// keys); certificates for Rowsafe Cloud names through Rowsafe's TLS front
// (tlsfront.go); restarts through root's helper. See protocol/meilisearch.go.
package meilisearch

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
	agent.RegisterEngine(&Engine{})
}

// Engine implements agent.Engine and its optional interfaces.
type Engine struct {
	mu      sync.Mutex
	ctx     context.Context // the agent's lifetime (Start); Background before
	started bool
	copies  *copyStore
	mon     monitorState
	// snapMu: one snapshot at a time (Meilisearch writes them to one file).
	snapMu sync.Mutex
	// copyMu serializes temporary instances' restores (Proof, copies,
	// rewinds in place).
	copyMu sync.Mutex
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

const display = "Meilisearch"

// Name is protocol.EngineMeilisearch.
func (e *Engine) Name() string { return protocol.EngineMeilisearch }

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

func (e *Engine) baseCtx() context.Context {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ctx != nil {
		return e.ctx
	}
	return context.Background()
}

// Start runs the engine's background work: copies are started again after
// an agent restart, and expired copies and kept indexes are deleted.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started, e.ctx = true, ctx
	e.mu.Unlock()
	go e.recoverCopies(ctx, env)
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				e.stopCopies(env)
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
		return nilIfNil(e.rewindDrop(env, db, p, tl))
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
	return nil, fmt.Errorf("%s databases can't run %s tasks", display, task.Type)
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
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	r := in.inspectResult(db.Port)
	return &r, nil
}

// Ready says whether Meilisearch answers again after a restart
// (agent.EngineRestarter).
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return "", err
	}
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s, %s, %s", display, in.Version, plural(int64(len(in.Indexes)), "index", "indexes"),
		plural(in.documents(), "document", "documents")), nil
}

// StoredObjects lists the database's objects in env's storage (backups
// under backup/, one folder per label; no continuous archive).
func (e *Engine) StoredObjects(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) ([]agent.StoredObject, string, string, error) {
	r, err := openRepo(env, db)
	if err != nil {
		return nil, "", "", err
	}
	objs, err := r.st.List(ctx, "")
	out := make([]agent.StoredObject, 0, len(objs))
	for _, o := range objs {
		out = append(out, agent.StoredObject{Key: o.Key, Size: o.Size, LastModified: o.LastModified})
	}
	return out, backupPrefix, "", err
}
