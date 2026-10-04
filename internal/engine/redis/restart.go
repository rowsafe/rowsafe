package redis

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineRestartRefuser = (*Engine)(nil)

// RestartRefusal refuses to restart a server that keeps nothing on its own
// disk (snapshots and the append-only file both off): it would come back
// empty. Asked before Restart (root's helper or the container control
// service), updates and an upgrade's undo; upgrades check it too
// (UpgradeIssues). A server that doesn't answer isn't refused: restarting
// it is how it comes back.
func (e *Engine) RestartRefusal(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) string {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return ""
	}
	defer c.Close()
	if !keepsNothing(ctx, c) {
		return ""
	}
	return e.emptyRefusal()
}

// emptyRefusal is the plain refusal for a server that keeps nothing on
// its own disk.
func (e *Engine) emptyRefusal() string {
	name := e.display()
	return fmt.Sprintf("Rowsafe didn't restart %[1]s: it keeps nothing on its own disk (snapshots and the append-only file are off), "+
		"so it would come back empty. Turn on snapshots first (Pulse offers it, or Tuning), then try again.", name)
}

// keepsNothing: snapshots ("save") and the append-only file are both off.
// A server whose settings can't be read isn't taken for one.
func keepsNothing(ctx context.Context, c *conn) bool {
	save, err := c.configGet(ctx, "save")
	if err != nil {
		return false
	}
	aof, err := c.configGet(ctx, "appendonly")
	return err == nil && persistenceOff(save, aof)
}

// persistenceOff reads CONFIG GET save and appendonly.
func persistenceOff(save, appendonly string) bool {
	return strings.TrimSpace(save) == "" && strings.ToLower(strings.TrimSpace(appendonly)) != "yes"
}

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
