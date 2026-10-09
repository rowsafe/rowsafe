package opensearch

import (
	"context"
	"fmt"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Ready answers once OpenSearch is back after a restart Rowsafe made
// through root's helper (agent.EngineRestarter).
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	var h struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, "/_cluster/health", &h); err != nil {
		return "", err
	}
	if h.Status == "red" {
		return "", fmt.Errorf("OpenSearch answers but is still red (shards starting)")
	}
	return "health " + h.Status, nil
}
