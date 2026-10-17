package local

import (
	"context"
	"errors"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// runPreviewOn: the agent's preview run doesn't build on Windows, so
// previews there read the SQL instead.
func runPreviewOn(context.Context, pginspect.Target, string, []preview.Stmt, *protocol.PreviewResult, time.Duration) error {
	return errors.New("running it on a copy isn't available on Windows yet")
}
