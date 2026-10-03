package clickhouse

import (
	"context"
	"strings"

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

var _ agent.EngineVersioner = (*Engine)(nil)

// Version is the running server's version ("25.8.15.35").
func (e *Engine) Version(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	v, err := c.scalar(ctx, "SELECT version()", nil)
	return strings.TrimSpace(v), err
}
