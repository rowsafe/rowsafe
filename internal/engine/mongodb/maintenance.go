package mongodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// maintenance runs a health fix. MongoDB has one: stopping a long-running
// client operation (killOp), after checking it is still the same one.
func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	if p.Action != protocol.MaintKillOp {
		return nil, fmt.Errorf("%s isn't a MongoDB fix", p.Action)
	}
	if p.PID <= 0 || p.BackendStart == nil {
		return nil, errors.New("kill_op needs the operation's id and start time")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	var res struct {
		Inprog []bson.M `bson:"inprog"`
	}
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "currentOp", Value: 1}, {Key: "opid", Value: p.PID}}).Decode(&res); err != nil {
		return nil, fmt.Errorf("looking the operation up: %w", err)
	}
	if len(res.Inprog) == 0 {
		return &protocol.MaintenanceResult{Action: p.Action, Summary: "The operation had already finished; nothing to stop.",
			DurationMs: time.Since(start).Milliseconds()}, nil
	}
	op := res.Inprog[0]
	if !clientOp(op) {
		return nil, errors.New("that operation is MongoDB's own work (replication, sessions, an oplog reader), not a client's: Rowsafe doesn't stop it")
	}
	secs := toFloat(op["microsecs_running"]) / 1e6
	began := time.Now().Add(-time.Duration(secs * float64(time.Second)))
	// The id may have been reused by a newer operation.
	if d := began.Sub(*p.BackendStart); d > 10*time.Second || d < -10*time.Second {
		return nil, errors.New("that operation has finished and its id now belongs to another one: nothing was stopped")
	}
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "killOp", Value: 1}, {Key: "op", Value: p.PID}}).Err(); err != nil {
		return nil, fmt.Errorf("killOp: %w", err)
	}
	ns, _ := op["ns"].(string)
	tl.Printf("stopped operation %d on %s, running for %.0f seconds", p.PID, ns, secs)
	return &protocol.MaintenanceResult{Action: p.Action,
		Summary:    fmt.Sprintf("Stopped the operation on %s that had been running for %s.", ns, roundDuration(time.Duration(secs)*time.Second)),
		DurationMs: time.Since(start).Milliseconds()}, nil
}
