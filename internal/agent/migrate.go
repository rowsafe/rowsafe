package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// Move in: copy a database from a managed provider into a cluster this
// agent looks after (protocol/migrate.go). Each migration keeps a directory
// under <state dir>/migrate/<id> (0700):
//
//	key         the private key the source connection string is sealed to
//	source      the source connection string (only after a check opened it)
//	pgpass      the source password, for pg_dump and the live sync
//	state.json  what the migration made (publication, subscription...)
//	dump/       a one-time copy's pg_dump output, while it runs
//
// Nothing here ever reaches the control plane: task results carry names,
// counts and sizes, and new passwords only sealed to the person's key.

var migrationIDRE = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)

// migState is a migration's state on this host.
type migState struct {
	ID       string                `json:"id"`
	Database protocol.DatabaseSpec `json:"database"` // the target cluster
	// SourceDB is the source database (datname); TargetDB the target's.
	SourceDB string `json:"source_db,omitempty"`
	TargetDB string `json:"target_db,omitempty"`
	Method   string `json:"method,omitempty"`
	Phase    string `json:"phase"`
	// CreatedDB: this migration created TargetDB (cancel may drop it).
	CreatedDB bool `json:"created_db,omitempty"`
	// Publication, Slot and Subscription are Rowsafe's objects for the live
	// sync ("rowsafe_<id>").
	Publication  string `json:"publication,omitempty"`
	Subscription string `json:"subscription,omitempty"`
	Tables       int    `json:"tables,omitempty"`
	SourceBytes  int64  `json:"source_bytes,omitempty"`
	// SourceReadOnly: Rowsafe made the source database read-only.
	SourceReadOnly bool      `json:"source_read_only,omitempty"`
	AppUser        string    `json:"app_user,omitempty"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// migrations tracks migrations in memory beside their directories: the
// progress of a running copy, for the reporter.
type migrations struct {
	mu       sync.Mutex
	progress map[string]*protocol.MigrationStatus
	// wake makes the reporter send now.
	wake chan struct{}
	// stopped are migrations the control plane no longer follows.
	stopped map[string]bool
	once    sync.Once
}

var agentMigrations sync.Map // *Agent -> *migrations

func (a *Agent) mig() *migrations {
	v, _ := agentMigrations.LoadOrStore(a, &migrations{})
	m := v.(*migrations)
	m.once.Do(func() {
		m.progress = map[string]*protocol.MigrationStatus{}
		m.stopped = map[string]bool{}
		m.wake = make(chan struct{}, 1)
	})
	return m
}

// setProgress records a running copy's progress and wakes the reporter.
func (m *migrations) setProgress(id string, st protocol.MigrationStatus) {
	m.mu.Lock()
	st.At = time.Now().UTC()
	m.progress[id] = &st
	delete(m.stopped, id)
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *migrations) update(id string, f func(*protocol.MigrationStatus)) {
	m.mu.Lock()
	if p := m.progress[id]; p != nil {
		f(p)
		p.At = time.Now().UTC()
	}
	m.mu.Unlock()
}

func (m *migrations) clearProgress(id string) {
	m.mu.Lock()
	delete(m.progress, id)
	m.mu.Unlock()
}

func (a *Agent) migrateRoot() string { return filepath.Join(a.cfg.StateDir, "migrate") }

func (a *Agent) migrateDir(id string) string { return filepath.Join(a.migrateRoot(), id) }

func (a *Agent) loadMigState(id string) (*migState, error) {
	data, err := os.ReadFile(filepath.Join(a.migrateDir(id), "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this server has no migration %s (it was cancelled or finished, or the agent's state was reset)", id)
	}
	if err != nil {
		return nil, err
	}
	var st migState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("reading migration %s: %w", id, err)
	}
	return &st, nil
}

func (a *Agent) saveMigState(st *migState) error {
	st.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(a.migrateDir(st.ID), "state.json"), data, 0o600)
}

// listMigStates returns every migration on this host.
func (a *Agent) listMigStates() []*migState {
	entries, err := os.ReadDir(a.migrateRoot())
	if err != nil {
		return nil
	}
	var out []*migState
	for _, e := range entries {
		if !e.IsDir() || !migrationIDRE.MatchString(e.Name()) {
			continue
		}
		if st, err := a.loadMigState(e.Name()); err == nil {
			out = append(out, st)
		}
	}
	return out
}

// sourceConninfo reads the source connection string a check stored.
func (a *Agent) sourceConninfo(id string) (conninfo, error) {
	data, err := os.ReadFile(filepath.Join(a.migrateDir(id), "source"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("this server doesn't have the source connection string (anymore): paste it again and check")
	}
	if err != nil {
		return nil, err
	}
	return parseConninfo(string(data))
}

func (a *Agent) passfile(id string) string { return filepath.Join(a.migrateDir(id), "pgpass") }

// runMigrate runs a migrate or migrate_copy task.
func (a *Agent) runMigrate(ctx context.Context, task *protocol.Task, db protocol.DatabaseSpec, tl *taskLog) (any, error) {
	var p protocol.MigrateParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
	}
	if !migrationIDRE.MatchString(p.MigrationID) {
		return nil, fmt.Errorf("invalid migration id %q", p.MigrationID)
	}
	if p.TargetDB != "" && !validTargetDB(p.TargetDB) {
		return nil, fmt.Errorf("the database name %q isn't allowed: use lowercase letters, digits and underscores (1-63), not starting with pg_", p.TargetDB)
	}
	if task.Type == protocol.TaskMigrateCopy {
		return nilIfNil(a.migrateCopy(ctx, db, p, tl))
	}
	switch p.Action {
	case protocol.MigrateKey:
		return nilIfNil(a.migrateKey(ctx, db, p, tl))
	case protocol.MigrateCheck:
		return nilIfNil(a.migrateCheck(ctx, db, p, tl))
	case protocol.MigrateFixIdentity:
		return nilIfNil(a.migrateFixIdentity(ctx, p, tl))
	case protocol.MigrateSwitchover:
		return nilIfNil(a.migrateSwitchover(ctx, p, tl))
	case protocol.MigrateCredentials:
		return nilIfNil(a.migrateCredentials(ctx, p, tl))
	case protocol.MigrateSourceWritable:
		return nilIfNil(a.migrateSourceWritable(ctx, p, tl))
	case protocol.MigrateCancel:
		return nilIfNil(a.migrateCancel(ctx, db, p, tl))
	case protocol.MigrateFinish:
		return nilIfNil(a.migrateFinish(ctx, p, tl))
	}
	return nil, fmt.Errorf("unknown migrate action %q (agent %s)", p.Action, Version)
}

// nilIfNil keeps a typed nil result out of the interface.
func nilIfNil[R any](res *R, err error) (any, error) {
	if res == nil {
		return nil, err
	}
	return res, err
}

var targetDBRE = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func validTargetDB(name string) bool {
	if !targetDBRE.MatchString(name) || strings.HasPrefix(name, "pg_") {
		return false
	}
	switch name {
	case "postgres", "template0", "template1":
		return false
	}
	return true
}

// migrateObjectName is Rowsafe's publication, slot and subscription name.
func migrateObjectName(id string) string { return "rowsafe_" + id }

// migrateKey makes (or, on a retry, returns) the migration's key pair.
func (a *Agent) migrateKey(ctx context.Context, db protocol.DatabaseSpec, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateKeyResult, error) {
	dir := a.migrateDir(p.MigrationID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "key")
	var pubKey string
	if data, err := os.ReadFile(keyPath); err == nil {
		k, err := e2e.ParsePrivateKey(string(data))
		if err != nil {
			return nil, fmt.Errorf("reading the migration key: %w", err)
		}
		pubKey = e2e.PublicKeyString(k.PublicKey())
	} else {
		k, err := e2e.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := writeFileAtomic(keyPath, []byte(e2e.MarshalPrivateKey(k)), 0o600); err != nil {
			return nil, err
		}
		pubKey = e2e.PublicKeyString(k.PublicKey())
	}
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		st = &migState{ID: p.MigrationID, Phase: protocol.MigratePhaseReady}
	}
	st.Database = db
	if err := a.saveMigState(st); err != nil {
		return nil, err
	}
	target, err := a.migrateTargetInfo(ctx, db, "")
	if err != nil {
		tl.Printf("reading the target: %v", err)
	}
	tl.Printf("made the key the source connection string is sealed to; the private key stays on this server")
	return &protocol.MigrateKeyResult{PublicKey: pubKey, Target: target}, nil
}

// openSource opens a sealed source connection string with the migration's
// key and keeps it (and its password file) on this server.
func (a *Agent) openSource(id string, box *e2e.Box) (conninfo, error) {
	if box == nil || !box.Valid() {
		return nil, errors.New("no source connection string was sent")
	}
	data, err := os.ReadFile(filepath.Join(a.migrateDir(id), "key"))
	if err != nil {
		return nil, errors.New("this server has no key for this migration: start the migration again")
	}
	k, err := e2e.ParsePrivateKey(string(data))
	if err != nil {
		return nil, err
	}
	plain, err := e2e.Open(k, protocol.MigrateInfo, protocol.MigrateSourceAAD(id), *box)
	if err != nil {
		return nil, fmt.Errorf("the connection string couldn't be opened on this server: %w", err)
	}
	ci, err := parseConninfo(string(plain))
	if err != nil {
		return nil, err
	}
	dir := a.migrateDir(id)
	if err := writeFileAtomic(filepath.Join(dir, "source"), plain, 0o600); err != nil {
		return nil, err
	}
	if err := writePassfile(a.passfile(id), ci); err != nil {
		return nil, err
	}
	return ci, nil
}

// migrateFinish forgets the source once the person is done with it.
func (a *Agent) migrateFinish(_ context.Context, p protocol.MigrateParams, tl *taskLog) (*protocol.MigrateActionResult, error) {
	st, err := a.loadMigState(p.MigrationID)
	if err != nil {
		return &protocol.MigrateActionResult{Summary: "Nothing left on this server for this migration."}, nil
	}
	if st.Phase != protocol.MigratePhaseSwitched {
		return nil, errors.New("this migration hasn't switched over: cancel it instead")
	}
	if err := removeAll(a.migrateDir(p.MigrationID)); err != nil {
		return nil, err
	}
	a.mig().clearProgress(p.MigrationID)
	tl.Printf("removed the source connection string, its password and the key from this server")
	sum := "Rowsafe forgot the old database's connection string. The old database itself is untouched"
	if st.SourceReadOnly {
		sum += " (still read-only)"
	}
	return &protocol.MigrateActionResult{Summary: sum + "."}, nil
}
