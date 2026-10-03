package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// maintenance runs a health fix: stopping a long-running query (KILL QUERY)
// or cancelling a change that can't finish (KILL MUTATION), each after
// checking it is still the same one.
func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	var summary string
	var err error
	switch p.Action {
	case protocol.MaintKillQuery:
		summary, err = killQuery(ctx, env, db, p, tl)
	case protocol.MaintKillMutation:
		summary, err = killMutation(ctx, env, db, p, tl)
	case protocol.MaintCreateIndex: // indexes.go
		summary, err = e.createIndex(ctx, env, db, p, tl)
	case protocol.MaintDropIndex:
		summary, err = e.dropIndex(ctx, env, db, p, tl)
	default:
		return nil, fmt.Errorf("%s isn't a ClickHouse fix", p.Action)
	}
	if err != nil {
		return nil, err
	}
	return &protocol.MaintenanceResult{Action: p.Action, Summary: summary, DurationMs: time.Since(start).Milliseconds()}, nil
}

func killQuery(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	if p.QueryID == "" || p.BackendStart == nil {
		return "", errors.New("kill_query needs the query's id and start time")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	type proc struct {
		Elapsed float64 `json:"elapsed"`
		User    string  `json:"user"`
		Agent   string  `json:"http_user_agent"`
		Initial uint8   `json:"is_initial_query"`
		Kind    string  `json:"query_kind"`
	}
	params := map[string]string{"id": p.QueryID}
	ps, err := query[proc](ctx, c, `SELECT elapsed, user, http_user_agent, is_initial_query, query_kind
		FROM system.processes WHERE query_id = {id:String}`, params)
	if err != nil {
		return "", fmt.Errorf("looking the query up: %w", err)
	}
	if len(ps) == 0 {
		return "The query had already finished; nothing to stop.", nil
	}
	q := ps[0]
	if q.Agent == userAgent {
		return "", errors.New("that query is Rowsafe's own work (a backup or a check): Rowsafe doesn't stop it this way")
	}
	began := time.Now().Add(-time.Duration(q.Elapsed * float64(time.Second)))
	// A query id can be reused (clients may choose their own).
	if d := began.Sub(*p.BackendStart); d > 10*time.Second || d < -10*time.Second {
		return "", errors.New("that query has finished and its id now belongs to another one: nothing was stopped")
	}
	if err := c.exec(ctx, "KILL QUERY WHERE query_id = {id:String} ASYNC", params); err != nil {
		return "", fmt.Errorf("KILL QUERY: %w", err)
	}
	// Wait a little for it to go.
	for range 20 {
		if n, err := c.scalar(ctx, "SELECT count() FROM system.processes WHERE query_id = {id:String}", params); err == nil && n == "0" {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	tl.Printf("stopped query %s of user %s, running for %.0f seconds", p.QueryID, q.User, q.Elapsed)
	return fmt.Sprintf("Stopped the query of user %s that had been running for %s.", q.User,
		roundDuration(time.Duration(q.Elapsed)*time.Second)), nil
}

func killMutation(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (string, error) {
	if p.DB == "" || len(p.Tables) != 1 || p.MutationID == "" {
		return "", errors.New("kill_mutation needs the database, the table and the mutation's id")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	params := map[string]string{"db": p.DB, "table": p.Tables[0], "id": p.MutationID}
	type mut struct {
		Done    uint8  `json:"is_done"`
		Command string `json:"command"`
		ToDo    int64  `json:"parts_to_do"`
	}
	ms, err := query[mut](ctx, c, `SELECT is_done, command, parts_to_do FROM system.mutations
		WHERE database = {db:String} AND table = {table:String} AND mutation_id = {id:String}`, params)
	if err != nil {
		return "", fmt.Errorf("looking the change up: %w", err)
	}
	if len(ms) == 0 {
		return "That change is gone already (finished or cancelled); nothing to cancel.", nil
	}
	if ms[0].Done != 0 {
		return "That change has finished in the meantime; nothing to cancel.", nil
	}
	err = c.exec(ctx, `KILL MUTATION WHERE database = {db:String} AND table = {table:String} AND mutation_id = {id:String} AND NOT is_done`, params)
	if err != nil {
		if errCode(err) == codeAccessDenied {
			return "", errors.New("Rowsafe's ClickHouse login isn't allowed to cancel this kind of change: " + shortError(err))
		}
		return "", fmt.Errorf("KILL MUTATION: %w", err)
	}
	tl.Printf("cancelled change %s on %s.%s (%d parts were still to do): %s", p.MutationID, p.DB, p.Tables[0], ms[0].ToDo,
		truncate(ms[0].Command, 200))
	// The build of an index or projection Rowsafe added: remove it too.
	if s, ok := rowsafeBuild(p.DB, p.Tables[0], ms[0].Command); ok {
		drop(ctx, c, s, tl)
		return fmt.Sprintf("Stopped building %s on %s.%s and removed it.", s.Name, p.DB, p.Tables[0]), nil
	}
	return fmt.Sprintf("Cancelled the change on %s.%s that couldn't finish. Parts it had already changed stay changed.", p.DB, p.Tables[0]), nil
}
