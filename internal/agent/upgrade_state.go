package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Upgrade state. A major upgrade keeps the old version (Safe mode) or its
// configuration (Fast mode) for Undo, for days, across agent restarts: the
// agent records each upgrade in <state dir>/upgrades.json, reports it in
// the heartbeat, removes the kept version when it expires, and finishes
// (or reports) an upgrade its restart interrupted.

// Upgrade phases, recorded before each step.
const (
	upPhaseHelper    = "helper"     // the helper is upgrading (or rolling back)
	upPhaseStarted   = "started"    // the new version runs; backups may still need setting up
	upPhaseDone      = "done"       // upgraded, backups set up
	upPhaseUndo      = "undo"       // the helper is switching back
	upPhaseRestoring = "restoring"  // Fast mode's undo: restoring the old version from the backup
	upPhaseUndoStart = "undo_start" // starting the old version again
)

// upgradeRecord is one upgrade that can still be undone or cleaned up.
type upgradeRecord struct {
	ID         string                `json:"id"`
	DatabaseID string                `json:"database_id"`
	Database   protocol.DatabaseSpec `json:"database"`
	FromMajor  int                   `json:"from_major"`
	ToMajor    int                   `json:"to_major"`
	// FromVersion and ToVersion are the running versions before and after.
	FromVersion string    `json:"from_version,omitempty"`
	ToVersion   string    `json:"to_version,omitempty"`
	Cluster     string    `json:"cluster,omitempty"` // Debian cluster name
	Mode        string    `json:"mode"`
	Method      string    `json:"method"`
	Status      string    `json:"status"` // protocol.Upgrade*
	Phase       string    `json:"phase"`
	CreatedAt   time.Time `json:"created_at"`
	Expires     time.Time `json:"expires"`
	KeepDays    int       `json:"keep_days,omitempty"`
	// OldDataDir and NewDataDir are the two versions' data directories;
	// AsidePort is where the version not in use is kept, stopped.
	OldDataDir string `json:"old_data_dir,omitempty"`
	NewDataDir string `json:"new_data_dir,omitempty"`
	AsidePort  int    `json:"aside_port,omitempty"`
	// ConfigFile is the old version's postgresql.conf (Fast undo's
	// private recovery).
	ConfigFile    string `json:"config_file,omitempty"`
	BackupsReady  bool   `json:"backups_ready"`
	Mark          string `json:"mark,omitempty"`
	MarkBackupSet string `json:"mark_backup_set,omitempty"`
	KeptSizeBytes int64  `json:"kept_size_bytes,omitempty"`
	// HelperID is the helper request in flight (Phase helper or undo), so
	// a restarted agent can read its answer.
	HelperID string `json:"helper_id,omitempty"`
}

func (r *upgradeRecord) state() protocol.UpgradeState {
	s := protocol.UpgradeState{ID: r.ID, DatabaseID: r.DatabaseID, Port: r.Database.Port, FromMajor: r.FromMajor, ToMajor: r.ToMajor,
		Mode: r.Mode, Status: r.Status, CreatedAt: r.CreatedAt, BackupsReady: r.BackupsReady, Mark: r.Mark, KeptSizeBytes: r.KeptSizeBytes}
	if !r.Expires.IsZero() && r.Status != protocol.UpgradeInProgress {
		e := r.Expires
		s.Expires = &e
	}
	kept := r.FromMajor
	if r.Status == protocol.UpgradeUndone {
		kept = r.ToMajor
	}
	if r.Cluster != "" && r.Status != protocol.UpgradeInProgress {
		s.KeptCluster = fmt.Sprintf("%d/%s (port %d, stopped)", kept, r.Cluster, r.AsidePort)
	}
	return s
}

type upgradeStore struct {
	mu   sync.Mutex
	path string
	recs map[string]*upgradeRecord
}

func loadUpgradeStore(path string) (*upgradeStore, error) {
	s := &upgradeStore{path: path, recs: map[string]*upgradeRecord{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	var recs []*upgradeRecord
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

func (s *upgradeStore) saveLocked() error {
	recs := make([]*upgradeRecord, 0, len(s.recs))
	for _, r := range s.recs {
		recs = append(recs, r)
	}
	slices.SortFunc(recs, func(a, b *upgradeRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

func (s *upgradeStore) get(id string) (upgradeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return upgradeRecord{}, false
	}
	return *r, true
}

func (s *upgradeStore) put(r upgradeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[r.ID] = &r
	return s.saveLocked()
}

func (s *upgradeStore) update(id string, fn func(*upgradeRecord)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[id]
	if !ok {
		return fmt.Errorf("no upgrade %s", id)
	}
	fn(r)
	return s.saveLocked()
}

func (s *upgradeStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[id]; !ok {
		return nil
	}
	delete(s.recs, id)
	return s.saveLocked()
}

func (s *upgradeStore) all() []upgradeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]upgradeRecord, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(a, b upgradeRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// forDatabase returns the database's upgrade record, if any (there is at
// most one: a new upgrade needs the previous one cleaned up).
func (s *upgradeStore) forDatabase(dbID string) (upgradeRecord, bool) {
	for _, r := range s.all() {
		if r.DatabaseID == dbID {
			return r, true
		}
	}
	return upgradeRecord{}, false
}

func (s *upgradeStore) states() []protocol.UpgradeState {
	var out []protocol.UpgradeState
	for _, r := range s.all() {
		out = append(out, r.state())
	}
	return out
}

func (a *Agent) upgradeState() *upgradeStore {
	a.upgradeOnce.Do(func() {
		st, err := loadUpgradeStore(filepath.Join(a.cfg.StateDir, "upgrades.json"))
		if err != nil && a.log != nil {
			a.log.Error("reading upgrade state; starting empty (upgrades listed there can't be undone from Rowsafe until fixed)", "err", err)
		}
		a.upgrades = st
	})
	return a.upgrades
}

// upgradeHousekeeping runs every minute beside the task loop: it finishes
// setting up backups after an upgrade when that failed at first, and
// removes kept versions that expired. It needs nothing from the control
// plane.
func (a *Agent) upgradeHousekeeping(ctx context.Context) {
	a.recoverUpgrades(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.upgradeTick(ctx, time.Now())
	}
}

func (a *Agent) upgradeTick(ctx context.Context, now time.Time) {
	for _, r := range a.upgradeState().all() {
		switch {
		case r.Status == protocol.UpgradeInProgress:
		case !r.BackupsReady:
			if !a.inPlaceMu.TryLock() {
				continue
			}
			tl := &taskLog{}
			err := a.finishBackups(ctx, r, tl)
			a.inPlaceMu.Unlock()
			if err != nil {
				a.log.Warn("setting up backups for the upgraded PostgreSQL still fails; retrying in a minute", "upgrade_id", r.ID, "err", err)
			} else {
				a.log.Info("backups work again after the upgrade", "upgrade_id", r.ID)
			}
		case !r.Expires.IsZero() && now.After(r.Expires):
			if !a.inPlaceMu.TryLock() {
				continue
			}
			tl := &taskLog{}
			res, err := a.removeKeptVersion(ctx, r, tl)
			a.inPlaceMu.Unlock()
			if err != nil {
				a.log.Error("removing the version kept by an upgrade failed", "upgrade_id", r.ID, "err", err)
				continue
			}
			a.log.Info("removed the version kept by an upgrade, as planned", "upgrade_id", r.ID, "summary", res.Summary)
		}
	}
}

// recoverUpgrades runs once at agent start: an upgrade or undo whose agent
// was stopped while the helper worked is followed through from the
// helper's answer (the helper finishes, or rolls back, on its own).
func (a *Agent) recoverUpgrades(ctx context.Context) {
	for _, r := range a.upgradeState().all() {
		if r.Status != protocol.UpgradeInProgress {
			continue
		}
		a.inPlaceMu.Lock()
		err := a.resumeUpgrade(ctx, r)
		a.inPlaceMu.Unlock()
		if err != nil {
			a.log.Error("an upgrade interrupted by an agent restart needs attention", "upgrade_id", r.ID, "err", err)
		}
	}
}
