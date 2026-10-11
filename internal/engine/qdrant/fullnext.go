package qdrant

import (
	"context"
	"path/filepath"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// fullNext: databases whose next backup takes a snapshot of every
// collection, whatever the change marks say (changes.go): after Rowsafe
// rewound the server or undid a rewind, and when the operation numbers of
// a collection went back (a snapshot was recovered outside Rowsafe). Kept
// in full-next.json in the state directory (database id -> why), so an
// agent restart doesn't forget it; cleared by the backup that takes them.

func fullNextPath(env agent.EngineEnv) string { return filepath.Join(env.StateDir, "full-next.json") }

func (e *Engine) fullNext(env agent.EngineEnv, dbID string) string {
	e.fullMu.Lock()
	defer e.fullMu.Unlock()
	m := map[string]string{}
	_ = loadJSONFile(fullNextPath(env), &m)
	return m[dbID]
}

func (e *Engine) setFullNext(env agent.EngineEnv, dbID, why string) {
	e.fullMu.Lock()
	defer e.fullMu.Unlock()
	m := map[string]string{}
	_ = loadJSONFile(fullNextPath(env), &m)
	if why == "" {
		if _, ok := m[dbID]; !ok {
			return
		}
		delete(m, dbID)
	} else {
		m[dbID] = why
	}
	if err := saveJSONFile(fullNextPath(env), m); err != nil && env.Log != nil {
		env.Log.Error("saving which Qdrant databases need every collection snapshotted", "err", err)
	}
}

// opsWatch compares the collections' operation numbers with the last ones
// seen (the monitor calls it every few minutes): a number that went back
// means a snapshot was recovered, so the next backup takes everything.
func (e *Engine) opsWatch(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, c *client) {
	now := c.opNums(ctx)
	if now == nil {
		return
	}
	e.mu.Lock()
	if e.ops == nil {
		e.ops = map[string]map[string][]int64{}
	}
	before := e.ops[db.ID]
	e.ops[db.ID] = now
	e.mu.Unlock()
	for name, ops := range now {
		if wentBack(before[name], ops) {
			e.setFullNext(env, db.ID, "the operation numbers of collection "+name+" went back (a snapshot was recovered)")
			return
		}
	}
}

// backupAfterRestore takes a backup of every collection right after a
// rewind or an undo changed them (the caller holds the database's lock):
// what the server holds now never passes for a snapshot taken before. If
// it fails, the next backup does it (fullNext stays set).
func (e *Engine) backupAfterRestore(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, c *client, r *repo, tl agent.TaskLogger) {
	why := e.fullNext(env, db.ID)
	in, err := inspect(ctx, c, false)
	if err == nil {
		var doc backupDoc
		docs, _, lerr := r.listBackups(ctx)
		if err = lerr; err == nil {
			var prev *backupDoc
			if len(docs) > 0 {
				prev = &docs[len(docs)-1]
			}
			tl.Printf("taking a backup of every collection as they are now")
			if doc, err = e.storeCollections(ctx, c, r, in, prev, true, sourceScheduled, "", tl); err == nil {
				if e.fullNext(env, db.ID) == why {
					e.setFullNext(env, db.ID, "")
				}
				tl.Printf("backup %s holds every collection as it is after the restore", doc.Label)
				return
			}
		}
	}
	tl.Printf("note: the backup after the restore failed (%v); the next backup takes every collection", err)
}
