package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// EngineMigrate is optionally implemented by an engine that can move a
// database in from a managed provider (protocol.FeatureMoveIn). The agent
// keeps the migration's key pair, its folder and the progress reports; the
// engine does the rest. Every action of protocol.MigrateParams goes to
// Migrate (TaskMigrate and TaskMigrateCopy alike).
type EngineMigrate interface {
	Migrate(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, m MigrateEnv, taskType string, p protocol.MigrateParams, log TaskLogger) (any, error)
	// MigrateStatus reads a live sync's progress for the reporter (phase
	// syncing, copying or switching). false: nothing to report.
	MigrateStatus(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, m MigrateEnv) (protocol.MigrationStatus, bool)
}

// MigrateEnv is what an engine gets for one migration.
type MigrateEnv struct {
	ID string
	// Dir is the migration's private folder (0700): the key, the source
	// connection string once opened, the engine's own state.
	Dir string
	// Phase and SetPhase read and record the migration's phase
	// (protocol.MigratePhase*), which the progress reporter follows.
	Phase    string
	SetPhase func(phase string)
	// Progress reports a running copy's progress (dumping, restoring).
	Progress func(protocol.MigrationStatus)
}

// MigrateKeyFile is the migration's private key (in MigrateEnv.Dir).
const migrateKeyFile = "key"

// MigratePublicKey makes (or, on a retry, reads) the migration's P-256 key
// pair in dir and returns the public key the source is sealed to.
func MigratePublicKey(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	keyPath := filepath.Join(dir, migrateKeyFile)
	if data, err := os.ReadFile(keyPath); err == nil {
		k, err := e2e.ParsePrivateKey(string(data))
		if err != nil {
			return "", fmt.Errorf("reading the migration key: %w", err)
		}
		return e2e.PublicKeyString(k.PublicKey()), nil
	}
	k, err := e2e.GenerateKey()
	if err != nil {
		return "", err
	}
	if err := writeFileAtomic(keyPath, []byte(e2e.MarshalPrivateKey(k)), 0o600); err != nil {
		return "", err
	}
	return e2e.PublicKeyString(k.PublicKey()), nil
}

// OpenMigrateSource opens the sealed source connection string with the
// migration's key in dir. The plaintext never leaves the server.
func OpenMigrateSource(dir, id string, box *e2e.Box) ([]byte, error) {
	if box == nil || !box.Valid() {
		return nil, errors.New("no source connection string was sent")
	}
	data, err := os.ReadFile(filepath.Join(dir, migrateKeyFile))
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
	return plain, nil
}

// SealMigrateCredentials seals a new connection string to the person's
// browser key.
func SealMigrateCredentials(id, browserKey string, conn []byte) (*e2e.Box, error) {
	pub, err := e2e.ParsePublicKey(browserKey)
	if err != nil {
		return nil, fmt.Errorf("the browser key: %w", err)
	}
	box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateCredentialsAAD(id), conn)
	if err != nil {
		return nil, err
	}
	return &box, nil
}

func engineMigrate(engine string) EngineMigrate {
	e := engineFor(protocol.NormalizeEngine(engine))
	if e == nil {
		return nil
	}
	m, _ := e.(EngineMigrate)
	return m
}

// migrateEnv is the MigrateEnv of migration id on db.
func (a *Agent) migrateEnv(id string, db protocol.DatabaseSpec) MigrateEnv {
	m := MigrateEnv{ID: id, Dir: a.migrateDir(id)}
	if st, err := a.loadMigState(id); err == nil {
		m.Phase = st.Phase
	}
	m.SetPhase = func(phase string) {
		st, err := a.loadMigState(id)
		if err != nil {
			st = &migState{ID: id}
		}
		st.Database, st.Phase = db, phase
		if err := os.MkdirAll(a.migrateDir(id), 0o700); err == nil {
			_ = a.saveMigState(st)
		}
		a.mig().update(id, func(s *protocol.MigrationStatus) { s.Phase = phase })
	}
	m.Progress = func(st protocol.MigrationStatus) { a.mig().setProgress(id, st) }
	return m
}

// runEngineMigrate runs a migrate or migrate_copy task for a database of
// another engine.
func (a *Agent) runEngineMigrate(ctx context.Context, task *protocol.Task, db protocol.DatabaseSpec, tl *taskLog) (any, error) {
	em := engineMigrate(db.Engine)
	if em == nil {
		return nil, fmt.Errorf("moving in isn't available for %s databases with this agent (%s)", protocol.EngineDisplayName(db.Engine), Version)
	}
	var p protocol.MigrateParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
	}
	if !migrationIDRE.MatchString(p.MigrationID) {
		return nil, fmt.Errorf("invalid migration id %q", p.MigrationID)
	}
	if p.Action == protocol.MigrateFinish {
		if err := removeAll(a.migrateDir(p.MigrationID)); err != nil {
			return nil, err
		}
		a.mig().clearProgress(p.MigrationID)
		tl.Printf("removed the source connection string and the key from this server")
		return &protocol.MigrateActionResult{Summary: "Rowsafe forgot the old database's connection string. The old database itself is untouched."}, nil
	}
	m := a.migrateEnv(p.MigrationID, db)
	if m.Phase == "" {
		m.SetPhase(protocol.MigratePhaseNew)
	}
	return em.Migrate(ctx, a.engineEnvFor(db), db, m, task.Type, p, tl)
}

// engineMigrationStatus is the reporter's view of another engine's live
// sync.
func (a *Agent) engineMigrationStatus(ctx context.Context, st *migState) (protocol.MigrationStatus, bool) {
	em := engineMigrate(st.Database.Engine)
	if em == nil {
		return protocol.MigrationStatus{}, false
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return em.MigrateStatus(cctx, a.engineEnvFor(st.Database), st.Database, a.migrateEnv(st.ID, st.Database))
}
