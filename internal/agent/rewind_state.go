package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind state. Copies and data directories kept aside by rewinds in place
// outlive tasks (and agent restarts), so the agent records them in
// <state dir>/rewinds.json: to report them in every heartbeat, to delete
// them when they expire even if the control plane is unreachable, and to
// clean up (or roll back) after a crash.

// rewindIDRE is the shape of copy and rewind IDs; they become directory
// names.
var rewindIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Copy and kept-data lifetimes.
const (
	defaultCopyLifetime = 24 * time.Hour
	maxCopyLifetime     = 7 * 24 * time.Hour
	defaultKeepDays     = 7
	maxKeepDays         = 30
)

// In-place phases, recorded before each step so a restarted agent knows
// what to undo.
const (
	phasePreflight = "preflight" // nothing changed yet
	phaseStopped   = "stopped"   // PostgreSQL stopped, data directory untouched
	phaseMoved     = "moved"     // data directory renamed to KeptDir
	phaseRestored  = "restored"  // a fresh data directory is in place (restoring or restored)
	// phaseRecovering: the restored data is replaying WAL privately. Once
	// it promotes, its new timeline's history may be in the repository, so
	// a rollback moves the original data to a new timeline too.
	phaseRecovering = "recovering"
	phaseStarted    = "started" // asked the helper to start the new data directory
	phaseDone       = "done"
)

// rewindRecord is one copy or kept data directory.
type rewindRecord struct {
	ID          string                `json:"id"`
	Kind        string                `json:"kind"` // protocol.RewindKind*
	DatabaseID  string                `json:"database_id"`
	Status      string                `json:"status"` // protocol.RewindCopy*, RewindKept*, RewindInProgress
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	Target      protocol.RewindTarget `json:"target"`
	SizeBytes   int64                 `json:"size_bytes"`
	// Database is the production database's spec (port, socket, stanza).
	Database protocol.DatabaseSpec `json:"database"`

	// Copies: the copy's directory (data/, socket/ inside) and how to start
	// it again after an agent restart.
	Dir   string `json:"dir,omitempty"`
	Major int    `json:"major,omitempty"`
	Port  int    `json:"port,omitempty"`
	// Preload is the copy's shared_preload_libraries ("" unless it needed
	// production's to start).
	Preload string `json:"preload,omitempty"`

	// Kept data: the live data directory and the one kept aside.
	DataDir string `json:"data_dir,omitempty"`
	KeptDir string `json:"kept_dir,omitempty"`
	// Phase is an in-place rewind's or undo's progress (phase*); Undo marks
	// an undo (the kept directory then holds the rewound data).
	Phase string `json:"phase,omitempty"`
	Undo  bool   `json:"undo,omitempty"`
	// FailedDir is a half-restored data directory moved aside by a rollback,
	// deleted once the original is back.
	FailedDir string `json:"failed_dir,omitempty"`
	// AsideDir is where an undo in progress sets the rewound data.
	AsideDir string `json:"aside_dir,omitempty"`
	KeepDays int    `json:"keep_days,omitempty"`
	// ConfigFile is PostgreSQL's config_file, for private recoveries.
	ConfigFile string `json:"config_file,omitempty"`
	// Contents: the data directory's entries are moved, not the directory
	// (Docker; rewind_contents.go).
	Contents bool `json:"contents,omitempty"`
}

func (r *rewindRecord) state() protocol.RewindState {
	s := protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: r.Kind, Status: r.Status, SizeBytes: r.SizeBytes,
		CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.Dir}
	if r.Kind == protocol.RewindKindKeptData {
		s.Path = r.KeptDir
	}
	if !r.Expires.IsZero() && r.Status != protocol.RewindInProgress && r.Status != protocol.RewindCopyRestoring {
		e := r.Expires
		s.Expires = &e
	}
	return s
}

// rewindStore holds the records, persisted after every change.
type rewindStore struct {
	mu   sync.Mutex
	path string
	recs map[string]*rewindRecord
	// running cancels a copy being restored (a drop cancels it); done is
	// closed when its task has cleaned up.
	running map[string]*runningRewind
}

type runningRewind struct {
	cancel context.CancelFunc
	done   chan struct{}
}

func loadRewindStore(path string) (*rewindStore, error) {
	s := &rewindStore{path: path, recs: map[string]*rewindRecord{}, running: map[string]*runningRewind{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var recs []*rewindRecord
	if err := json.Unmarshal(data, &recs); err != nil {
		return s, fmt.Errorf("reading %s: %w", path, err)
	}
	for _, r := range recs {
		if r != nil && rewindIDRE.MatchString(r.ID) {
			s.recs[r.ID] = r
		}
	}
	return s, nil
}

// saveLocked writes the records; the caller holds mu.
func (s *rewindStore) saveLocked() error {
	recs := make([]*rewindRecord, 0, len(s.recs))
	for _, r := range s.recs {
		recs = append(recs, r)
	}
	slices.SortFunc(recs, func(a, b *rewindRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

// get returns a copy of the record with id.
func (s *rewindStore) get(id string) (rewindRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return rewindRecord{}, false
	}
	return *r, true
}

// put stores (a copy of) r.
func (s *rewindStore) put(r rewindRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[r.ID] = &r
	return s.saveLocked()
}

// update changes the record with id, if it exists.
func (s *rewindStore) update(id string, fn func(*rewindRecord)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return fmt.Errorf("no rewind %s", id)
	}
	fn(r)
	return s.saveLocked()
}

func (s *rewindStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[id]; !ok {
		return nil
	}
	delete(s.recs, id)
	return s.saveLocked()
}

// all returns copies of every record, oldest first.
func (s *rewindStore) all() []rewindRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]rewindRecord, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b rewindRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// copyFor returns the database's copy, if any.
func (s *rewindStore) copyFor(databaseID string) (rewindRecord, bool) {
	for _, r := range s.all() {
		if r.Kind == protocol.RewindKindCopy && r.DatabaseID == databaseID {
			return r, true
		}
	}
	return rewindRecord{}, false
}

// states are the records as the heartbeat reports them.
func (s *rewindStore) states() []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range s.all() {
		out = append(out, r.state())
	}
	return out
}

// setExpiries applies expiry changes from the control plane (Extend),
// clamped: copies live at most 7 days from now, kept data 30.
func (s *rewindStore) setExpiries(exps []protocol.RewindExpiry, now time.Time) {
	if len(exps) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for _, e := range exps {
		r, ok := s.recs[e.ID]
		if !ok || e.Expires.Before(now) {
			continue // deleting is a task's job, never a stale expiry's
		}
		limit := now.Add(maxCopyLifetime)
		if r.Kind == protocol.RewindKindKeptData {
			limit = now.Add(maxKeepDays * 24 * time.Hour)
		}
		exp := e.Expires.UTC()
		if exp.After(limit) {
			exp = limit
		}
		if !exp.Equal(r.Expires) {
			r.Expires = exp
			changed = true
		}
	}
	if changed {
		_ = s.saveLocked()
	}
}

// startRunning registers a copy restore that a drop may cancel.
func (s *rewindStore) startRunning(id string, cancel context.CancelFunc) *runningRewind {
	s.mu.Lock()
	defer s.mu.Unlock()
	rr := &runningRewind{cancel: cancel, done: make(chan struct{})}
	s.running[id] = rr
	return rr
}

func (s *rewindStore) finishRunning(id string, rr *runningRewind) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running[id] == rr {
		delete(s.running, id)
	}
	close(rr.done)
}

// cancelRunning cancels a copy being restored and waits (up to wait) until
// its task has cleaned up. It reports whether one was running.
func (s *rewindStore) cancelRunning(id string, wait time.Duration) bool {
	s.mu.Lock()
	rr := s.running[id]
	s.mu.Unlock()
	if rr == nil {
		return false
	}
	rr.cancel()
	select {
	case <-rr.done:
	case <-time.After(wait):
	}
	return true
}

func (a *Agent) rewindStorePath() string { return filepath.Join(a.cfg.StateDir, "rewinds.json") }

// rewindState returns the agent's rewind store, loading it on first use.
func (a *Agent) rewindState() *rewindStore {
	a.rewindOnce.Do(func() {
		st, err := loadRewindStore(a.rewindStorePath())
		if err != nil && a.log != nil {
			a.log.Error("reading rewind state; starting empty (copies and kept data listed there are not managed until fixed)", "err", err)
		}
		a.rewinds = st
	})
	return a.rewinds
}

// rewindHousekeeping runs every minute beside the task loop: it deletes
// expired copies and kept data. It needs nothing from the control plane.
func (a *Agent) rewindHousekeeping(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		a.expireRewinds(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// expireRewinds deletes what expired before now.
func (a *Agent) expireRewinds(now time.Time) {
	for _, r := range a.rewindState().all() {
		if r.Expires.IsZero() || now.Before(r.Expires) {
			continue
		}
		switch {
		case r.Kind == protocol.RewindKindCopy && r.Status == protocol.RewindCopyReady:
			freed, err := a.removeCopy(r)
			if err != nil {
				a.log.Error("removing an expired copy failed", "copy_id", r.ID, "err", err)
				continue
			}
			a.log.Info("removed an expired copy", "copy_id", r.ID, "database_id", r.DatabaseID, "freed", humanBytes(freed))
		case r.Kind == protocol.RewindKindKeptData && (r.Status == protocol.RewindKeptBefore || r.Status == protocol.RewindKeptAfterUndo):
			if !a.inPlaceMu.TryLock() {
				continue // a rewind runs; next minute
			}
			freed, err := a.removeKept(r)
			a.inPlaceMu.Unlock()
			if err != nil {
				a.log.Error("deleting expired kept data failed", "rewind_id", r.ID, "err", err)
				continue
			}
			a.log.Info("deleted the data kept aside by a rewind, as planned", "rewind_id", r.ID, "database_id", r.DatabaseID,
				"path", r.KeptDir, "freed", humanBytes(freed))
		}
	}
}

// recoverRewinds runs once at agent start: copies whose restore was
// interrupted are removed, live copies are started again (the agent's
// restart stopped them), leftovers the state doesn't know are removed, and
// an in-place rewind or undo that was interrupted is rolled back.
func (a *Agent) recoverRewinds(ctx context.Context) {
	st := a.rewindState()
	known := map[string]bool{}
	for _, r := range st.all() {
		switch r.Kind {
		case protocol.RewindKindCopy:
			known[r.ID] = true
			switch {
			case r.Status != protocol.RewindCopyReady:
				if _, err := a.removeCopy(r); err != nil {
					a.log.Error("removing a copy whose restore was interrupted failed", "copy_id", r.ID, "err", err)
				} else {
					a.log.Warn("removed a copy whose restore was interrupted by an agent restart", "copy_id", r.ID)
				}
			case !r.Expires.IsZero() && time.Now().After(r.Expires):
				// expireRewinds removes it.
			default:
				go func() {
					if err := a.restartCopy(ctx, r); err != nil {
						a.log.Error("starting a copy again after an agent restart failed; it stays until it expires or is deleted",
							"copy_id", r.ID, "err", err)
					} else {
						a.log.Info("started a copy again after an agent restart", "copy_id", r.ID)
					}
				}()
			}
		case protocol.RewindKindKeptData:
			if r.Status == protocol.RewindInProgress {
				a.inPlaceMu.Lock()
				err := a.recoverInPlace(ctx, r)
				a.inPlaceMu.Unlock()
				if err != nil {
					a.log.Error("an interrupted rewind could not be rolled back by itself", "rewind_id", r.ID, "err", err)
				}
			}
		}
	}
	a.cleanupStaleCopies(known)
}
