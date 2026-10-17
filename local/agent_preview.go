//go:build !windows

package local

import (
	"context"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// runPreviewOn runs a migration on the temporary database with the
// agent's own preview run (it builds on Linux and macOS only).
func runPreviewOn(ctx context.Context, t pginspect.Target, dbname string, stmts []preview.Stmt, res *protocol.PreviewResult, runFor time.Duration) error {
	_, err := agent.RunPreviewOn(ctx, t, dbname, stmts, res, runFor)
	return err
}
