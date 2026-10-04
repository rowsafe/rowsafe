package redis

import (
	"context"
	"errors"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Ready says whether the server answers again after a restart: PING, and
// done loading its data (INFO loading:0). The note says whether Rowsafe
// follows it again; "on" is ArchiveMode for the restart result.
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	defer c.Close()
	if _, err := c.do(ctx, "PING"); err != nil {
		return "", err
	}
	m, err := c.info(ctx, "persistence")
	if err != nil {
		return "", err
	}
	if m["loading"] == "1" {
		return "", errors.New(e.display() + " is still loading its data")
	}
	return e.archiveMode(db), nil
}
