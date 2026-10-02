package mongodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// profileOn turns the profiler on for slow operations (level 1) in the
// databases asked for (none: every user database where it is off). Level 1
// only writes operations slower than slowms into a small capped collection
// (system.profile, 1 MB by default): a negligible cost.
func (e *Engine) profileOn(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	dbs, err := userDatabases(ctx, c)
	if err != nil {
		return nil, err
	}
	targets := p.Tables
	if len(targets) == 0 {
		targets = profiler(ctx, c, dbs).Off
	}
	var done []string
	for _, name := range targets {
		if !slices.Contains(dbs, name) {
			continue // dropped since, or not a user database
		}
		if err := c.Database(name).RunCommand(ctx, bson.D{{Key: "profile", Value: 1}}).Err(); err != nil {
			if isUnauthorized(err) {
				return nil, errors.New("Rowsafe's MongoDB user may not change the profiler yet: run the install command on the server again (it refreshes Rowsafe's role), then try again")
			}
			return nil, fmt.Errorf("turning the profiler on in %s: %w", name, err)
		}
		tl.Printf("profiler on (slow operations) in %s", name)
		done = append(done, name)
	}
	res := &protocol.MaintenanceResult{Action: p.Action, DurationMs: time.Since(start).Milliseconds(), Details: done}
	if len(done) == 0 {
		res.Summary = "The profiler was already on; nothing to do."
	} else {
		res.Summary = fmt.Sprintf("Turned MongoDB's profiler on for slow operations in %s. Query statistics show up within 10 minutes.", strings.Join(done, ", "))
	}
	return res, nil
}
