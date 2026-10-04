// Package sqlite is Rowsafe's SQLite engine. A SQLite database is a file an
// application opens itself; the agent opens it too, with SQLite's own
// locking, so it is safe next to the app: full copies through the online
// backup API, continuous archiving of the WAL (restores to any second,
// ship.go), Proof (restore, integrity_check, foreign_key_check, row
// counts), Rewind (a restored copy, compare, bring rows back, rewind in
// place with Undo), Marks, monitoring (Pulse) with fixes, and discovery
// for the installer. It registers itself with the agent
// (agent.RegisterEngine); the agent binary imports it for that.
package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

func init() { agent.RegisterEngine(&Engine{}) }

// Engine implements agent.Engine (and EngineArchiver, EngineStarter,
// EngineRewinds) for SQLite.
type Engine struct {
	mu        sync.Mutex
	ctx       context.Context // the agent's lifetime (Start); Background before
	started   bool
	stateRoot string
	shippers  map[string]*shipper
	copies    *copyStore
	safe      *safeStore // safe copies (copies.go)
	mon       monitorState
	copyMu    sync.Mutex
	busy      sync.Map // database id -> *busyCount
	snapMu    sync.Map // database id -> *sync.Mutex
}

var (
	_ agent.Engine         = (*Engine)(nil)
	_ agent.EngineArchiver = (*Engine)(nil)
	_ agent.EngineStarter  = (*Engine)(nil)
	_ agent.EngineRewinds  = (*Engine)(nil)
)

// copy2Suffix marks the second copy's database id (internal/agent).
const copy2Suffix = "~copy2"

func baseID(id string) string { return strings.TrimSuffix(id, copy2Suffix) }

// Name is protocol.EngineSQLite.
func (e *Engine) Name() string { return protocol.EngineSQLite }

// Tasks are the task types the engine runs.
func (e *Engine) Tasks() []string {
	return []string{
		protocol.TaskInspect, protocol.TaskAdopt, protocol.TaskCheck, protocol.TaskBackup, protocol.TaskDrill,
		protocol.TaskRestorePoint, protocol.TaskMaintenance,
		protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
		protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup,
		protocol.TaskFindMoment,
		protocol.TaskIndexAdvisor,                      // indexadvice.go
		protocol.TaskPreviewMigration,                  // preview.go
		protocol.TaskCopySchema, protocol.TaskSafeCopy, // copies*.go
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

// stateRootFor is the engine's state directory for the first storage
// (the second copy's environment points at a "copy2" folder inside it;
// the stream and its spool are shared).
func (e *Engine) stateRootFor(env agent.EngineEnv) string {
	e.mu.Lock()
	root := e.stateRoot
	e.mu.Unlock()
	if root != "" {
		return root
	}
	if filepath.Base(env.StateDir) == "copy2" {
		return filepath.Dir(env.StateDir)
	}
	return env.StateDir
}

func (e *Engine) busyFor(id string) *busyCount {
	b, _ := e.busy.LoadOrStore(baseID(id), &busyCount{})
	return b.(*busyCount)
}

// Start runs the engine's background work.
func (e *Engine) Start(ctx context.Context, env agent.EngineEnv) {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return
	}
	e.started, e.ctx = true, ctx
	if filepath.Base(env.StateDir) != "copy2" {
		e.stateRoot = env.StateDir
	}
	e.mu.Unlock()
	e.recoverCopies(env)
	e.recoverPreviewCopies(env)   // preview_copy.go
	e.recoverSafeCopies(env)      // copies.go
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
			e.expireSafeCopies(env, time.Now())
			e.expireKept(env, time.Now())
			e.expirePreviewCopies(env, time.Now())
			e.stopIdleShippers()
		}
	}()
}

// shipperFor returns the database's change copier (starting it when
// needed) and registers env's bucket with it; the second return is that
// bucket's sink name.
func (e *Engine) shipperFor(env agent.EngineEnv, db protocol.DatabaseSpec) (*shipper, string, error) {
	if !protocol.SQLitePath(db.SocketDir) {
		return nil, "", fmt.Errorf("invalid database path %q", db.SocketDir)
	}
	if err := allowed(env, db.SocketDir); err != nil {
		return nil, "", err
	}
	if !stanzaRE.MatchString(db.Stanza) {
		return nil, "", fmt.Errorf("invalid stanza %q", db.Stanza)
	}
	name := sinkPrimary
	if strings.HasSuffix(db.ID, copy2Suffix) {
		name = sinkCopy2
	}
	id := baseID(db.ID)
	e.mu.Lock()
	s := e.shippers[id]
	if s != nil && s.path != db.SocketDir {
		// The database's file moved: start over with the new path.
		e.mu.Unlock()
		e.stopShipper(id)
		e.mu.Lock()
		s = nil
	}
	if s == nil {
		var err error
		s, err = e.newShipper(env, db, id)
		if err != nil {
			e.mu.Unlock()
			return nil, "", err
		}
		if e.shippers == nil {
			e.shippers = map[string]*shipper{}
		}
		e.shippers[id] = s
	}
	e.mu.Unlock()
	s.mu.Lock()
	if name == sinkPrimary {
		s.db = db
	}
	s.lastSeen = time.Now()
	s.mu.Unlock()
	s.sinkFor(name, env, db)
	return s, name, nil
}

// newShipper creates and starts a copier (e.mu held).
func (e *Engine) newShipper(env agent.EngineEnv, db protocol.DatabaseSpec, id string) (*shipper, error) {
	root := e.stateRoot
	if root == "" {
		root = env.StateDir
		if filepath.Base(root) == "copy2" {
			root = filepath.Dir(root)
		}
	}
	dir := filepath.Join(root, db.Stanza)
	sp, err := openSpool(filepath.Join(dir, "spool"))
	if err != nil {
		return nil, err
	}
	base := context.Background()
	if e.ctx != nil {
		base = e.ctx
	}
	ctx, cancel := context.WithCancel(base)
	s := &shipper{e: e, id: id, dir: dir, path: db.SocketDir, sp: sp, busy: e.busyForLocked(id), db: db,
		sinks: map[string]*sink{}, log: env.Log.With("database_id", id), reqs: make(chan shipReq),
		ctx: ctx, stop: cancel, done: make(chan struct{}), lastSeen: time.Now(), lastWindow: time.Now()}
	if err := s.loadState(); err != nil {
		cancel()
		return nil, err
	}
	go s.run()
	return s, nil
}

func (e *Engine) busyForLocked(id string) *busyCount {
	b, _ := e.busy.LoadOrStore(id, &busyCount{})
	return b.(*busyCount)
}

func (e *Engine) stopShipper(id string) {
	e.mu.Lock()
	s := e.shippers[id]
	delete(e.shippers, id)
	e.mu.Unlock()
	if s != nil {
		s.stop()
		<-s.done
	}
}

// existingShipper is the database's copier if one runs.
func (e *Engine) existingShipper(id string) *shipper {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.shippers[baseID(id)]
}

// stopIdleShippers stops copiers of databases no longer watched.
func (e *Engine) stopIdleShippers() {
	e.mu.Lock()
	var idle []string
	for id, s := range e.shippers {
		s.mu.Lock()
		old := time.Since(s.lastSeen) > sinkIdle
		s.mu.Unlock()
		if old {
			idle = append(idle, id)
		}
	}
	e.mu.Unlock()
	for _, id := range idle {
		e.stopShipper(id)
	}
}

// Archiver reports the copying of db's changes to env's bucket (and keeps
// the copier running).
func (e *Engine) Archiver(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error) {
	s, name, err := e.shipperFor(env, db)
	if err != nil {
		return nil, err
	}
	return s.archiverStats(name), nil
}

// Run runs one task.
func (e *Engine) Run(ctx context.Context, env agent.EngineEnv, task *protocol.Task, tl agent.TaskLogger) (any, error) {
	db := *task.Database
	if !protocol.SQLitePath(db.SocketDir) {
		return nil, fmt.Errorf("this SQLite database has no valid file path (%q): edit it in the dashboard", db.SocketDir)
	}
	if err := allowed(env, db.SocketDir); err != nil {
		return nil, err
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
	case protocol.TaskFindMoment: // moment.go
		var p protocol.FindMomentParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.findMoment(ctx, env, db, p, task.ID, tl))
	case protocol.TaskIndexAdvisor: // indexadvice.go
		var p protocol.IndexAdvisorParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.indexAdvisor(ctx, env, db, task.ID, p, tl))
	case protocol.TaskPreviewMigration:
		var p protocol.PreviewParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.previewMigration(ctx, env, db, p, tl))
	case protocol.TaskCopySchema:
		return nilIfNil(e.copySchema(ctx, env, db))
	case protocol.TaskSafeCopy:
		var p protocol.SafeCopyParams
		if err := decode(task, &p); err != nil {
			return nil, err
		}
		return nilIfNil(e.safeCopy(ctx, env, db, p, tl))
	}
	return nil, fmt.Errorf("SQLite databases can't run %s tasks", task.Type)
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

// ---- integrity record (monitoring shows the last check)

type integrityRecord struct {
	At      time.Time `json:"at"`
	OK      bool      `json:"ok"`
	Problem string    `json:"problem,omitempty"`
}

func (e *Engine) integrityPath(env agent.EngineEnv, db protocol.DatabaseSpec) string {
	return filepath.Join(e.workDir(env, db), "integrity.json")
}

// noteIntegrity records a check of the file's pages ("ok" or a problem).
func (e *Engine) noteIntegrity(env agent.EngineEnv, db protocol.DatabaseSpec, at time.Time, result string) {
	rec := integrityRecord{At: at.UTC(), OK: result == "ok"}
	if !rec.OK {
		rec.Problem = result
	}
	_ = saveJSONFile(e.integrityPath(env, db), rec)
}

func (e *Engine) lastIntegrity(env agent.EngineEnv, db protocol.DatabaseSpec) (integrityRecord, bool) {
	var rec integrityRecord
	if err := loadJSONFile(e.integrityPath(env, db), &rec); err != nil {
		return rec, false
	}
	return rec, true
}

var errNotFound = errors.New("not found")

func (e *Engine) logFor(env agent.EngineEnv) *slog.Logger {
	if env.Log != nil {
		return env.Log
	}
	return slog.New(slog.DiscardHandler)
}

func notExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
