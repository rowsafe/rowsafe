package agent

import (
	"context"
	"log/slog"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// RunPreviewOn runs a migration's statements on the database dbname that
// t reaches (a connection string), as t's role, while a second session
// watches its locks, and fills res.Statements, res.Error and
// res.DurationMs: the agent's preview run, for rowsafe preview without an
// account, which runs it on a temporary database holding a copy of the
// schema. It returns the row-level security regressions it found and the
// run's log. The caller assesses res.
func RunPreviewOn(ctx context.Context, t pginspect.Target, dbname string, stmts []preview.Stmt, res *protocol.PreviewResult, runFor time.Duration) ([]protocol.PreviewFinding, string, error) {
	a := &Agent{log: slog.New(slog.DiscardHandler)}
	tl := &taskLog{}
	rls, err := a.runPreview(ctx, t, t, dbname, stmts, res, runFor, tl)
	return rls, tl.String(), err
}
