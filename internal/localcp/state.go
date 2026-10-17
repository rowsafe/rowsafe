// Package localcp is the control plane of a server without an account: it
// runs inside the agent (rowsafe-agent with ROWSAFE_URL=unix://PATH) and
// serves, on that Unix socket, the agent API the agent already speaks and the
// part of the user API the rowsafe CLI needs on the server. It keeps one
// server's databases, tasks, backups, Proofs and Marks in a JSON file, runs
// the schedules (full backups weekly, differential ones daily, Proof weekly)
// and moves a database through setup (plan, apply, restart, check, active)
// the way the hosted control plane does.
//
// The socket's file permissions are its access control, like Docker's: the
// agent's user (postgres) and root. Nothing leaves the server.
package localcp

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Kept history (open tasks are always kept).
const (
	keepFinishedTasks = 300
	keepBackups       = 500
	keepDrills        = 200
	keepMarks         = 500
)

// state is everything the control plane keeps.
type state struct {
	Host      hostRec                 `json:"host"`
	Databases []*dbRec                `json:"databases"`
	Tasks     []*taskRec              `json:"tasks"`
	Backups   []protocol.Backup       `json:"backups"`
	Drills    []protocol.Drill        `json:"drills"`
	Marks     []protocol.RestorePoint `json:"restore_points"`
	Copies    []*copyRec              `json:"copies,omitempty"` // Rewind (rewind.go)
	// Alerts (alerts.go): channels, alerts, conditions waiting out their
	// "for" duration, and the newest monitoring reading of each database.
	Channels     []*channelRec         `json:"channels,omitempty"`
	Alerts       []*alertRec           `json:"alerts,omitempty"`
	AlertPending map[string]time.Time  `json:"alert_pending,omitempty"`
	Metrics      map[string]*dbMetrics `json:"metrics,omitempty"`
}

// hostRec is this server, once its agent has enrolled.
type hostRec struct {
	ID           string     `json:"id,omitempty"`
	Token        string     `json:"token,omitempty"`
	Hostname     string     `json:"hostname,omitempty"`
	AgentVersion string     `json:"agent_version,omitempty"`
	Platform     string     `json:"platform,omitempty"`
	EnrolledAt   time.Time  `json:"enrolled_at,omitzero"`
	LastSeen     *time.Time `json:"last_seen,omitempty"`
	RestartPorts []int      `json:"restart_ports,omitempty"`
	// Software is the agent's newest software report (upgrade.go).
	Software   *protocol.SoftwareReport `json:"software,omitempty"`
	SoftwareAt *time.Time               `json:"software_at,omitempty"`
}

// dbRec is a database with what its health depends on.
type dbRec struct {
	protocol.Database
	StatusSince     time.Time            `json:"status_since"`
	ArchiverAt      *time.Time           `json:"archiver_at,omitempty"`
	ArchiverErrorAt *time.Time           `json:"archiver_error_at,omitempty"`
	ArchiverError   string               `json:"archiver_error,omitempty"`
	LastRun         map[string]time.Time `json:"last_run,omitempty"` // schedule kind -> when it last fired
}

// taskRec is a task with what claiming it needs.
type taskRec struct {
	protocol.TaskView
	AfterTaskID string     `json:"after_task_id,omitempty"`
	LeaseUntil  *time.Time `json:"lease_until,omitempty"`
}

func (t *taskRec) open() bool {
	return t.Status == protocol.StatusQueued || t.Status == protocol.StatusRunning
}

// store holds the state and writes it to path after every change.
type store struct {
	mu   sync.Mutex
	path string
	s    state
}

func openStore(path string) (*store, error) {
	st := &store{path: path}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(data, &st.s); err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
	}
	return st, nil
}

// read runs fn with the state locked, changing nothing.
func (st *store) read(fn func(s *state)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.s)
}

// update runs fn with the state locked and saves it if fn succeeds.
func (st *store) update(fn func(s *state) error) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := fn(&st.s); err != nil {
		return err
	}
	st.s.prune()
	return st.save()
}

// save writes the state atomically: a temporary file, fsync, rename.
func (st *store) save() error {
	data, err := json.MarshalIndent(&st.s, "", " ")
	if err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, st.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(st.path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// prune drops the oldest history beyond what is kept.
func (s *state) prune() {
	finished := 0
	for i := len(s.Tasks) - 1; i >= 0; i-- { // newest last
		if !s.Tasks[i].open() {
			finished++
			if finished > keepFinishedTasks {
				s.Tasks = slices.Delete(s.Tasks, i, i+1)
			}
		}
	}
	if n := len(s.Backups) - keepBackups; n > 0 {
		s.Backups = s.Backups[n:]
	}
	if n := len(s.Drills) - keepDrills; n > 0 {
		s.Drills = s.Drills[n:]
	}
	if n := len(s.Marks) - keepMarks; n > 0 {
		s.Marks = s.Marks[n:]
	}
	s.pruneAlerts()
	// Copies gone for a week are forgotten.
	s.Copies = slices.DeleteFunc(s.Copies, func(c *copyRec) bool {
		return c.RemovedAt != nil && time.Since(*c.RemovedAt) > 7*24*time.Hour
	})
}

// db finds a database by ID or name.
func (s *state) db(ref string) *dbRec {
	for _, d := range s.Databases {
		if d.ID == ref || d.Name == ref {
			return d
		}
	}
	return nil
}

func (s *state) task(id string) *taskRec {
	for _, t := range s.Tasks {
		if t.ID == id {
			return t
		}
	}
	return nil
}

// newID is a random ID with a prefix, like the hosted control plane's.
func newID(prefix string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return prefix + "_" + string(b)
}

// newToken is a secret for the agent.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "rsl_" + strings.TrimRight(fmt.Sprintf("%x", b), "=")
}
