package clickhouse

import (
	"context"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Marks: a Mark is a differential
// backup taken on the spot (only what changed since the newest full
// backup), saved under the Mark's name in the bucket. Rewind to the Mark
// restores exactly that backup.

func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	tl.Printf("taking a backup for Mark %s", p.Name)
	doc, err := e.takeBackup(ctx, env, db, protocol.BackupDiff, p.Name, tl)
	if err != nil {
		return nil, fmt.Errorf("the Mark's backup failed: %w", err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	res := &protocol.RestorePointResult{Name: p.Name, LSN: doc.Label, CreatedAt: doc.StartedAt}
	if err := r.putJSON(ctx, markKey(p.Name), markDoc{Name: p.Name, Label: doc.Label, CreatedAt: doc.StartedAt}); err != nil {
		return res, fmt.Errorf("saving the Mark in your bucket: %w", err)
	}
	now := time.Now().UTC()
	res.Archived, res.ArchivedAt = true, &now
	tl.Printf("Mark %s is in your bucket (backup %s): Rewind can go back exactly to it", p.Name, doc.Label)
	return res, nil
}
