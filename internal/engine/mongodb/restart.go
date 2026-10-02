package mongodb

import (
	"context"
	"errors"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineRestarter = (*Engine)(nil)

// Ready reports whether MongoDB answers again after a restart. A replica
// set member is ready once it is the writable primary again (what copying
// the oplog needs): "on"; a standalone server answers "off" (no oplog).
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c, err := connectDB(cctx, env, db)
	if err != nil {
		return "", err
	}
	defer disconnect(c)
	in, err := inspect(cctx, c)
	if err != nil {
		return "", err
	}
	switch {
	case in.SetName == "":
		return "off", nil
	case !in.Primary:
		return "", errors.New("MongoDB answers but isn't the primary of its replica set yet")
	}
	return "on", nil
}
