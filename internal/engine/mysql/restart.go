package mysql

import (
	"context"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineRestarter = (*Engine)(nil)

// Ready reports whether the server answers again after a restart: "on"
// when its binary log is on (what backups to any second need), "off"
// otherwise.
func (e *Engine) Ready(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := e.server(env, db).open(cctx)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	var logBin int
	if err := conn.QueryRowContext(cctx, `SELECT @@log_bin`).Scan(&logBin); err != nil {
		return "", err
	}
	if logBin == 1 {
		return "on", nil
	}
	return "off", nil
}
