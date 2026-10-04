package sqlite

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Preview copies: the newest point restored into a private file, kept for
// ROWSAFE_PREVIEW_KEEP (default 1 hour) after a preview so the next one of
// the same database starts in seconds, like PostgreSQL's. A migration
// never runs on the kept file itself but on a fresh file copy of it
// (run.db), deleted afterwards, so the kept copy stays as restored. The
// copies are recorded in <engine state>/preview-copies.json and reported
// with the heartbeat (previewCopyStates, called by the engine's safe
// copies code: agent.EngineSafeCopies), deleted when they expire, when a
// person deletes one, or when the agent starts and finds one a preview
// was using.

const (
	previewCopyName = "copy.db"
	previewRunName  = "run.db"
)

// previewRoot holds one folder per preview copy. The name has a dot so
// the agent's own copies cleanup (internal/agent, copy IDs only) never
// takes it for one of PostgreSQL's copies.
func previewRoot(env agent.EngineEnv) string {
	return filepath.Join(cmp.Or(env.Config.Copies.Dir, env.Config.RewindDir), "sqlite.preview")
}

// previewCopy is one preview copy.
type previewCopy struct {
	ID          string     `json:"id"`
	DatabaseID  string     `json:"database_id"`
	Dir         string     `json:"dir"`
	Status      string     `json:"status"` // protocol.CopyRestoring | CopyReady
	CreatedAt   time.Time  `json:"created_at"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
	LastUsed    time.Time  `json:"last_used,omitzero"`
	Expires     time.Time  `json:"expires,omitzero"`
	// InUse: a preview runs on it (a copy found in use when the agent
	// starts was interrupted and is deleted).
	InUse bool `json:"in_use,omitempty"`
}

func (r previewCopy) file() string { return filepath.Join(r.Dir, previewCopyName) }

type previewCopies struct {
	mu      sync.Mutex
	path    string
	recs    map[string]previewCopy
	running map[string]context.CancelFunc // restoring, by id
	drop    map[string]bool               // deleted while a preview used it
}

var previewStores sync.Map // state file -> *previewCopies

func (e *Engine) previewCopies(env agent.EngineEnv) *previewCopies {
	path := filepath.Join(e.stateRootFor(env), "preview-copies.json")
	if v, ok := previewStores.Load(path); ok {
		return v.(*previewCopies)
	}
	pc := &previewCopies{path: path, recs: map[string]previewCopy{}, running: map[string]context.CancelFunc{}, drop: map[string]bool{}}
	var list []previewCopy
	if err := loadJSONFile(path, &list); err == nil {
		for _, r := range list {
			pc.recs[r.ID] = r
		}
	}
	v, _ := previewStores.LoadOrStore(path, pc)
	return v.(*previewCopies)
}

func (pc *previewCopies) saveLocked() error {
	list := make([]previewCopy, 0, len(pc.recs))
	for _, r := range pc.recs {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b previewCopy) int { return strings.Compare(a.ID, b.ID) })
	return saveJSONFile(pc.path, list)
}

func (pc *previewCopies) put(r previewCopy) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.recs[r.ID] = r
	return pc.saveLocked()
}

func (pc *previewCopies) all() []previewCopy {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	out := make([]previewCopy, 0, len(pc.recs))
	for _, r := range pc.recs {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b previewCopy) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// claim marks the database's ready preview copy in use and returns it.
func (pc *previewCopies) claim(dbID string) (previewCopy, bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	for id, r := range pc.recs {
		if r.DatabaseID == dbID && r.Status == protocol.CopyReady && !r.InUse {
			r.InUse = true
			pc.recs[id] = r
			_ = pc.saveLocked()
			return r, true
		}
	}
	return previewCopy{}, false
}

// release ends a preview's use of r: kept for keep (0: deleted).
func (pc *previewCopies) release(r previewCopy, keep time.Duration) {
	pc.mu.Lock()
	dropped := pc.drop[r.ID]
	delete(pc.drop, r.ID)
	if keep > 0 && !dropped {
		now := time.Now().UTC()
		r.InUse, r.LastUsed, r.Expires = false, now, now.Add(keep)
		pc.recs[r.ID] = r
		_ = pc.saveLocked()
		pc.mu.Unlock()
		return
	}
	pc.mu.Unlock()
	pc.remove(r)
}

// remove deletes a preview copy's folder and record.
func (pc *previewCopies) remove(r previewCopy) {
	if r.Dir != "" && filepath.Base(filepath.Dir(r.Dir)) == "sqlite.preview" {
		_ = os.RemoveAll(r.Dir)
	}
	pc.mu.Lock()
	delete(pc.recs, r.ID)
	_ = pc.saveLocked()
	pc.mu.Unlock()
}

// previewCopyStates are the preview copies, for the heartbeat (the safe
// copies code adds them to EngineSafeCopies.CopyStates).
func (e *Engine) previewCopyStates(env agent.EngineEnv) []protocol.CopyState {
	var out []protocol.CopyState
	for _, r := range e.previewCopies(env).all() {
		cs := protocol.CopyState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.CopyKindPreview, Status: r.Status,
			SizeBytes: r.SizeBytes, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo}
		if !r.Expires.IsZero() && !r.InUse {
			exp := r.Expires
			cs.Expires = &exp
		}
		out = append(out, cs)
	}
	return out
}

// dropPreviewCopy deletes preview copy id now (the dashboard's Delete, for
// EngineSafeCopies.DropCopy): a restore in progress stops, a copy a
// preview uses is deleted when the preview ends. False when id isn't a
// preview copy.
func (e *Engine) dropPreviewCopy(env agent.EngineEnv, id string) bool {
	pc := e.previewCopies(env)
	pc.mu.Lock()
	r, ok := pc.recs[id]
	if !ok {
		pc.mu.Unlock()
		return false
	}
	if cancel := pc.running[id]; cancel != nil {
		cancel()
		pc.mu.Unlock()
		return true
	}
	if r.InUse {
		pc.drop[id] = true
		pc.mu.Unlock()
		return true
	}
	pc.mu.Unlock()
	pc.remove(r)
	return true
}

// setPreviewCopyExpiries moves preview copies' expiry times (Extend, for
// EngineSafeCopies.SetCopyExpiries), at most a day from now.
func (e *Engine) setPreviewCopyExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	pc := e.previewCopies(env)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	changed := false
	for _, x := range exp {
		if r, ok := pc.recs[x.ID]; ok && r.Status == protocol.CopyReady && !x.Expires.Equal(r.Expires) {
			r.Expires = x.Expires.UTC()
			if limit := time.Now().Add(24 * time.Hour).UTC(); r.Expires.After(limit) {
				r.Expires = limit
			}
			pc.recs[x.ID] = r
			changed = true
		}
	}
	if changed {
		_ = pc.saveLocked()
	}
}

// expirePreviewCopies deletes kept preview copies past their time.
func (e *Engine) expirePreviewCopies(env agent.EngineEnv, now time.Time) {
	pc := e.previewCopies(env)
	for _, r := range pc.all() {
		if r.Status == protocol.CopyReady && !r.InUse && !r.Expires.IsZero() && now.After(r.Expires) {
			pc.remove(r)
		}
	}
}

// recoverPreviewCopies runs when the agent starts: copies a restore or a
// preview was interrupted on are deleted, and folders nobody knows.
func (e *Engine) recoverPreviewCopies(env agent.EngineEnv) {
	pc := e.previewCopies(env)
	known := map[string]bool{}
	for _, r := range pc.all() {
		if r.Status != protocol.CopyReady || r.InUse {
			pc.remove(r)
			env.Log.Warn("removed a SQLite preview copy whose restore or preview was interrupted", "copy_id", r.ID)
			continue
		}
		known[filepath.Base(r.Dir)] = true
		removeDB(filepath.Join(r.Dir, previewRunName))
	}
	if entries, err := os.ReadDir(previewRoot(env)); err == nil {
		for _, ent := range entries {
			if !known[ent.Name()] {
				_ = os.RemoveAll(filepath.Join(previewRoot(env), ent.Name()))
			}
		}
	}
}
