package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The second copy for MySQL, MariaDB, MongoDB and ClickHouse: the engine
// runs a second, independent pipeline into the second storage, with the
// same code as the first: full backups (the control plane queues them
// weekly with Repo RepoSecond), restore tests from it (Proof alternates
// between the storages), and, for engines with continuous archiving
// (binary logs, oplog), a second shipper that copies the archive there
// too. Each keeps its state apart from the first (a "copy2" state
// directory, a database ID with copy2Suffix), and its data under the
// engine's own prefix in the second bucket, encrypted with the second
// storage's own passphrase.

// copy2Suffix marks the second copy's pipeline in an engine's per-database
// state (shippers, state files).
const copy2Suffix = "~copy2"

// engineEnv2 is an engine's environment for the second copy.
func (a *Agent) engineEnv2(name string) EngineEnv {
	env := a.engineEnv(name)
	env.Repo = a.cfg.Repo2
	env.StateDir = filepath.Join(env.StateDir, "copy2")
	return env
}

// copy2Spec is the database as the second copy's pipeline sees it.
func copy2Spec(db protocol.DatabaseSpec) protocol.DatabaseSpec {
	db.ID += copy2Suffix
	db.RetentionFull = db.SecondCopyRetentionFull
	if db.RetentionFull <= 0 {
		db.RetentionFull = protocol.DefaultSecondCopyRetentionFull
	}
	return db
}

// taskRepo is the storage a backup or drill task asks for.
func taskRepo(task *protocol.Task) int {
	if len(task.Params) == 0 {
		return 0
	}
	var p struct {
		Repo int `json:"repo"`
	}
	_ = json.Unmarshal(task.Params, &p)
	return p.Repo
}

// runEngineCopy2 runs a backup or drill task against the second copy.
func (a *Agent) runEngineCopy2(ctx context.Context, e Engine, task *protocol.Task, tl *taskLog) (any, error) {
	if !a.cfg.SecondCopy() {
		return nil, errors.New("this server has no second copy set up (the Rowsafe installer adds one with --add-storage)")
	}
	if msg := a.cfg.SecondCopyError(); msg != "" {
		return nil, fmt.Errorf("the second copy's settings on the server are incomplete: %s", msg)
	}
	t := *task
	db := copy2Spec(*task.Database)
	t.Database = &db
	tl.Printf("using the second copy (%s)", describeRepo(a.cfg.Repo2))
	res, err := e.Run(ctx, a.engineEnv2(e.Name()), &t, tl)
	switch r := res.(type) {
	case *protocol.BackupResult:
		r.Repo = protocol.RepoSecond
	case *protocol.DrillResult:
		r.Repo = protocol.RepoSecond
	}
	return res, err
}

// engineSecondCopyStatus reports a non-PostgreSQL database's second copy
// for the heartbeat, and keeps its archive shipper running.
func (a *Agent) engineSecondCopyStatus(db protocol.DatabaseSpec, st protocol.SecondCopyStatus) (protocol.SecondCopyStatus, bool) {
	name := protocol.NormalizeEngine(db.Engine)
	e := engineFor(name)
	if e == nil || !protocol.EngineHas(name, protocol.FeatureSecondCopy) {
		return st, false
	}
	st.Ready = true
	ar, ok := e.(EngineArchiver)
	if !ok || !protocol.EngineHas(name, protocol.FeaturePointInTime) {
		return st, true // backups only (ClickHouse)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stats, err := ar.Archiver(ctx, a.engineEnv2(name), copy2Spec(db))
	switch {
	case err != nil:
		st.LastError = err.Error()
	case stats != nil:
		st.SentCount, st.FailedCount = stats.ArchivedCount, stats.FailedCount
		st.LastSentAt = stats.LastArchivedTime
		if stats.Error != "" {
			st.LastError = stats.Error
			st.FailingSince = stats.LastFailedTime
		}
	}
	return st, true
}
