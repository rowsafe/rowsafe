package agent

import (
	"cmp"
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

// Rewinding a non-PostgreSQL database in place (engines).
//
// Engines do the work themselves (their own restores); the agent gives
// them two things through EngineEnv:
//
//   - Control: stopping and starting the database server through the same
//     root helper PostgreSQL uses (native hosts, only units root listed in
//     restart-allowed), for engines that swap data files (MySQL, MariaDB);
//   - KeptStore: where they record what a rewind kept aside for Undo, so
//     the heartbeat reports it (RewindKindKeptData), it outlives agent
//     restarts and it is deleted when it expires.

// ServerControl stops and starts a database server for a rewind in place.
type ServerControl interface {
	// Allowed reports whether db's server may be stopped and started here
	// (nil when it may), in plain words.
	Allowed(db protocol.DatabaseSpec) error
	// Stop stops db's server and returns once the helper says it stopped.
	Stop(ctx context.Context, db protocol.DatabaseSpec, id string) error
	// Start starts it again.
	Start(ctx context.Context, db protocol.DatabaseSpec, id string) error
}

// agentControl is the agent's ServerControl.
type agentControl struct{ a *Agent }

func (c agentControl) Allowed(db protocol.DatabaseSpec) error {
	if c.a.cfg.Container() {
		return fmt.Errorf("rewinding %s in Docker in place isn't available yet: restore a copy and bring back rows instead",
			protocol.EngineDisplayName(db.Engine))
	}
	_, err := c.a.inPlaceAllowed(db) // rewind_inplace.go
	return err
}

func (c agentControl) Stop(ctx context.Context, db protocol.DatabaseSpec, id string) error {
	return c.helper(ctx, helperStop, db, id)
}

func (c agentControl) Start(ctx context.Context, db protocol.DatabaseSpec, id string) error {
	return c.helper(ctx, helperStart, db, id)
}

func (c agentControl) helper(ctx context.Context, action string, db protocol.DatabaseSpec, id string) error {
	if err := c.Allowed(db); err != nil {
		return err
	}
	res, err := c.a.askHelper(ctx, action, db.Port, id)
	if err != nil {
		return err
	}
	if res["ok"] != "1" {
		return fmt.Errorf("the helper couldn't %s %s: %s", action, protocol.EngineDisplayName(db.Engine), cmp.Or(res["error"], "unknown error"))
	}
	return nil
}

// KeptRecord is data an engine's rewind in place kept aside (or a rewind
// in progress).
type KeptRecord struct {
	ID          string                `json:"id"` // the rewind ID
	DatabaseID  string                `json:"database_id"`
	Status      string                `json:"status"` // protocol.RewindKept*, RewindInProgress
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	Target      protocol.RewindTarget `json:"target"`
	SizeBytes   int64                 `json:"size_bytes"`
	Path        string                `json:"path,omitempty"` // where the kept data is
	KeepDays    int                   `json:"keep_days,omitempty"`
	// Phase is the engine's own progress marker, recorded before each step
	// so a restarted agent knows what to roll back.
	Phase string `json:"phase,omitempty"`
	// Undo: the kept data is the rewound data, set aside by an Undo.
	Undo bool `json:"undo,omitempty"`
	// Database is the production database's spec.
	Database protocol.DatabaseSpec `json:"database"`
	// Extra holds the engine's own fields (directories, names...).
	Extra map[string]string `json:"extra,omitempty"`
}

func (r KeptRecord) state() protocol.RewindState {
	s := protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindKeptData, Status: r.Status,
		SizeBytes: r.SizeBytes, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.Path}
	if !r.Expires.IsZero() && r.Status != protocol.RewindInProgress {
		e := r.Expires
		s.Expires = &e
	}
	return s
}

// KeptStore persists an engine's KeptRecords (<engine state dir>/kept.json).
type KeptStore struct {
	path string
	mu   sync.Mutex
	recs []KeptRecord
}

var (
	keptStoresMu sync.Mutex
	keptStores   = map[string]*KeptStore{}
)

// Kept returns the engine's kept-data store (one per state directory).
func (e EngineEnv) Kept() *KeptStore {
	path := filepath.Join(e.StateDir, "kept.json")
	keptStoresMu.Lock()
	defer keptStoresMu.Unlock()
	if s := keptStores[path]; s != nil {
		return s
	}
	s := &KeptStore{path: path}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &s.recs)
	}
	keptStores[path] = s
	return s
}

func (s *KeptStore) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.recs, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, data, 0o600)
}

// Put adds or replaces a record (by ID) and saves.
func (s *KeptStore) Put(r KeptRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.recs, func(x KeptRecord) bool { return x.ID == r.ID })
	if i >= 0 {
		s.recs[i] = r
	} else {
		s.recs = append(s.recs, r)
	}
	return s.saveLocked()
}

// Get returns the record with id.
func (s *KeptStore) Get(id string) (KeptRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.recs {
		if r.ID == id {
			return r, true
		}
	}
	return KeptRecord{}, false
}

// Remove deletes the record with id and saves.
func (s *KeptStore) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = slices.DeleteFunc(s.recs, func(x KeptRecord) bool { return x.ID == id })
	return s.saveLocked()
}

// All returns every record, oldest first.
func (s *KeptStore) All() []KeptRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.recs)
}

// ForDatabase returns the database's records.
func (s *KeptStore) ForDatabase(dbID string) []KeptRecord {
	var out []KeptRecord
	for _, r := range s.All() {
		if r.DatabaseID == dbID {
			out = append(out, r)
		}
	}
	return out
}

// States are the records as the heartbeat reports them.
func (s *KeptStore) States() []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range s.All() {
		out = append(out, r.state())
	}
	return out
}

// Expired returns the records kept past their expiry (never one in
// progress).
func (s *KeptStore) Expired(now time.Time) []KeptRecord {
	var out []KeptRecord
	for _, r := range s.All() {
		if r.Status != protocol.RewindInProgress && !r.Expires.IsZero() && now.After(r.Expires) {
			out = append(out, r)
		}
	}
	return out
}

// KeepUntil is when kept data expires: days (default 7, at most 30) from
// now.
func KeepUntil(days int, now time.Time) time.Time { return keepUntil(days, now) }

// ErrRewindBusy: another rewind of the database is in progress.
var ErrRewindBusy = errors.New("another rewind or undo of this database is in progress")
