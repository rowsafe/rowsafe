package clickhouse

import (
	"context"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineArchiver = (*Engine)(nil)

// Archiver reports the copier of ClickHouse's changes (starting it for a
// database it doesn't run for yet).
func (e *Engine) Archiver(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error) {
	s, err := e.shipperFor(env, db)
	if err != nil {
		return nil, err
	}
	st, serr := s.snapshot()
	return st.archiverStats(serr), nil
}

// flushTo has the copier record everything up to t (now at most), when it
// runs, so a restore to t is exact. Failures are notes in the task's log:
// the restore then says how far it could go.
func (e *Engine) flushTo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, t time.Time, tl agent.TaskLogger) {
	// Only a copier that runs here: a clone may restore another server's
	// database.
	e.mu.Lock()
	s := e.shippers[db.ID]
	e.mu.Unlock()
	if s == nil {
		return
	}
	if now := time.Now().UTC(); t.After(now) {
		t = now
	}
	st, _ := s.snapshot()
	if st.Record == "" || !st.To.Before(t) {
		return
	}
	if err := s.flush(ctx, t, 2*time.Minute); err != nil {
		tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", err)
	}
}

// pickTarget finds what a restore to target uses: for a moment, the backup
// assembled for it (pitr_restore.go); else as pickBackup. recovered is the
// moment the restore brings back.
func (e *Engine) pickTarget(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r *repo, target restoreTarget, tl agent.TaskLogger) (backupDoc, time.Time, error) {
	if target.Mark != "" {
		// The Mark's own backup (the control plane may name the backup a
		// moment would start from).
		target.BackupSet = ""
	}
	if target.Time.IsZero() || target.Mark != "" {
		b, err := pickBackup(ctx, r, target)
		return b, b.StoppedAt, err
	}
	e.flushTo(ctx, env, db, target.Time, tl)
	res, err := pitAt(ctx, r, target.Time, target.BackupSet)
	if err != nil {
		return backupDoc{}, time.Time{}, err
	}
	if !res.Exact {
		tl.Printf("note: %s", res.Note)
		return res.Doc, res.Doc.StoppedAt, nil
	}
	tl.Printf("assembled %s exactly as it was at %s: the newest backup before it, with every change ClickHouse made up to that moment",
		db.Name, target.Time.UTC().Format("2006-01-02 15:04:05.000000 UTC"))
	return res.Doc, target.Time, nil
}

// latestTarget is what Proof restores: the newest moment the record
// reaches (the newest backup carried forward with every change since), so
// the test covers the record too; the newest backup without one.
func (e *Engine) latestTarget(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r *repo, tl agent.TaskLogger) (backupDoc, time.Time, error) {
	e.flushTo(ctx, env, db, time.Now().UTC(), tl)
	e.mu.Lock()
	s := e.shippers[db.ID]
	e.mu.Unlock()
	if s != nil {
		if st, _ := s.snapshot(); st.Record != "" {
			if res, err := pitAt(ctx, r, st.To, ""); err == nil && res.Exact {
				tl.Printf("restoring %s as it was at %s: the newest backup with every change since", db.Name,
					st.To.UTC().Format("2006-01-02 15:04:05.000000 UTC"))
				return res.Doc, st.To, nil
			} else if err == nil {
				tl.Printf("note: %s", res.Note)
			}
		}
	}
	b, err := pickBackup(ctx, r, restoreTarget{Latest: true})
	return b, b.StoppedAt, err
}
