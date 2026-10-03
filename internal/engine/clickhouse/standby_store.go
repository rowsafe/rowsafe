package clickhouse

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// chStandby is a standby this server runs (<state>/standbys.json); its
// applied state (the primary's parts it holds) is in
// <state>/standby/<id>.json.
type chStandby struct {
	ID         string    `json:"id"`
	DatabaseID string    `json:"database_id"`
	Stanza     string    `json:"stanza"` // the primary's bucket folder
	Port       int       `json:"port"`
	Phase      string    `json:"phase"` // protocol.StandbyPhase*
	CreatedAt  time.Time `json:"created_at"`
	// AppliedTo: the standby holds the primary as it was then.
	AppliedTo   time.Time  `json:"applied_to"`
	LastApplyAt *time.Time `json:"last_apply_at,omitempty"`
	Error       string     `json:"error,omitempty"`
	ErrorSince  *time.Time `json:"error_since,omitempty"`
	// DBs are the databases it restored (removing the standby drops them).
	DBs        []string   `json:"dbs,omitempty"`
	PromotedAt *time.Time `json:"promoted_at,omitempty"`
}

type standbyStore struct {
	mu   sync.Mutex
	path string
	dir  string
}

var (
	standbyStoresMu sync.Mutex
	standbyStores   = map[string]*standbyStore{}
)

func (e *Engine) standbyStore(env agent.EngineEnv) *standbyStore {
	standbyStoresMu.Lock()
	defer standbyStoresMu.Unlock()
	s := standbyStores[env.StateDir]
	if s == nil {
		s = &standbyStore{path: filepath.Join(env.StateDir, "standbys.json"), dir: filepath.Join(env.StateDir, "standby")}
		standbyStores[env.StateDir] = s
	}
	return s
}

func (s *standbyStore) load() ([]chStandby, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []chStandby
	return out, json.Unmarshal(data, &out)
}

func (s *standbyStore) all() []chStandby {
	s.mu.Lock()
	defer s.mu.Unlock()
	out, _ := s.load()
	return out
}

func (s *standbyStore) get(id string) (chStandby, bool) {
	for _, r := range s.all() {
		if r.ID == id {
			return r, true
		}
	}
	return chStandby{}, false
}

func (s *standbyStore) onPort(port int) (chStandby, bool) {
	for _, r := range s.all() {
		if r.Port == port && r.PromotedAt == nil {
			return r, true
		}
	}
	return chStandby{}, false
}

// update changes one record (or adds it) under the lock.
func (s *standbyStore) update(id string, fn func(r *chStandby)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(all, func(r chStandby) bool { return r.ID == id })
	if i < 0 {
		all = append(all, chStandby{ID: id})
		i = len(all) - 1
	}
	fn(&all[i])
	return saveJSONFile(s.path, all)
}

func (s *standbyStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return err
	}
	all = slices.DeleteFunc(all, func(r chStandby) bool { return r.ID == id })
	_ = os.Remove(s.statePath(id))
	return saveJSONFile(s.path, all)
}

func (s *standbyStore) statePath(id string) string { return filepath.Join(s.dir, id+".json") }

// loadState reads a standby's applied state.
func (s *standbyStore) loadState(id string) (*pitState, error) {
	data, err := os.ReadFile(s.statePath(id))
	if err != nil {
		return nil, err
	}
	var st pitState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *standbyStore) saveState(id string, st *pitState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	tmp := s.statePath(id) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.statePath(id))
}
