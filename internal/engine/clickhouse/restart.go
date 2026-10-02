package clickhouse

import (
	"context"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineRestarter = (*Engine)(nil)

// Ready reports whether ClickHouse answers again after a restart.
// ClickHouse has no continuous archiving, so there is no mode to report.
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	if _, err := connectDB(ctx, env, db); err != nil {
		return "", err
	}
	return "", nil
}
