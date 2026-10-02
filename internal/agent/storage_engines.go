package agent

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Storage measurement for MySQL, MariaDB, MongoDB and ClickHouse: the
// engine lists its objects in a storage (EngineStorage) and the agent
// reports them in the heartbeat like pgBackRest's, for the first storage
// and the second copy.

// EngineStorage is optionally implemented by an engine that can list what
// a database keeps in a storage (env.Repo).
type EngineStorage interface {
	// StoredObjects lists every object under the database's path, keys
	// relative to it, with the prefixes of its backups ("backups/": one
	// folder per backup label) and of its continuous archive ("" when the
	// engine has none).
	StoredObjects(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (objs []StoredObject, backups, archive string, err error)
}

// StoredObject is one object in a storage.
type StoredObject struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// BackupLabelType is a backup's type from its label: Rowsafe's labels end
// with F (full), D (differential) or I (incremental).
func BackupLabelType(label string) string {
	switch {
	case strings.HasSuffix(label, "D"):
		return protocol.BackupDiff
	case strings.HasSuffix(label, "I"):
		return protocol.BackupIncr
	}
	return protocol.BackupFull
}

// SummarizeStorage adds up objects: the archive, the backups (one per
// folder under backups, stopped at its newest object) and everything.
func SummarizeStorage(objs []StoredObject, backups, archive string) protocol.RepoStorage {
	var r protocol.RepoStorage
	byLabel := map[string]*protocol.RepoBackup{}
	for _, o := range objs {
		r.TotalBytes += o.Size
		switch {
		case archive != "" && strings.HasPrefix(o.Key, archive):
			r.WALBytes += o.Size
			r.WALFiles++
		case strings.HasPrefix(o.Key, backups):
			r.BackupBytes += o.Size
			label, _, ok := strings.Cut(strings.TrimPrefix(o.Key, backups), "/")
			if !ok || label == "" {
				continue
			}
			b := byLabel[label]
			if b == nil {
				b = &protocol.RepoBackup{Label: label, Type: BackupLabelType(label)}
				byLabel[label] = b
			}
			b.StoredBytes += o.Size
			if o.LastModified.After(b.StoppedAt) {
				b.StoppedAt = o.LastModified.UTC()
			}
		}
	}
	for _, b := range byLabel {
		r.Backups = append(r.Backups, *b)
	}
	slices.SortFunc(r.Backups, func(a, b protocol.RepoBackup) int { return a.StoppedAt.Compare(b.StoppedAt) })
	return r
}

// measureEngine measures a non-PostgreSQL database in one storage.
func (a *Agent) measureEngine(ctx context.Context, db protocol.DatabaseSpec, repo int) (protocol.RepoStorage, bool) {
	name := protocol.NormalizeEngine(db.Engine)
	es, ok := engineFor(name).(EngineStorage)
	if !ok {
		return protocol.RepoStorage{}, false
	}
	env, spec, repoCfg := a.engineEnv(name), db, a.cfg.Repo
	if r, err := a.repo(); err == nil {
		repoCfg = r
		env.Repo = r
	}
	if repo == protocol.RepoSecond {
		env, spec, repoCfg = a.engineEnv2(name), copy2Spec(db), a.cfg.Repo2
	}
	mctx, cancel := context.WithTimeout(ctx, storageMeasureTimeout)
	defer cancel()
	objs, backups, archive, err := es.StoredObjects(mctx, env, spec)
	r := SummarizeStorage(objs, backups, archive)
	if err != nil {
		r = protocol.RepoStorage{Error: err.Error()}
	}
	r.DatabaseID, r.RepoInfo, r.MeasuredAt = db.ID, repoCfg.Info(repo), time.Now().UTC()
	return r, true
}
