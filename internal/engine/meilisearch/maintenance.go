package meilisearch

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Apply fix for Meilisearch (protocol.MaintMeili*). Each checks the
// situation is still the one Pulse saw, and changes nothing else.

// clearTasksAge: finished tasks older than this go (MaintMeiliClearTasks).
const clearTasksAge = 7 * 24 * time.Hour

func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.close()
	res := &protocol.MaintenanceResult{Action: p.Action}
	switch p.Action {
	case protocol.MaintMeiliCompactIndex:
		err = compactIndex(ctx, c, p, res, tl)
	case protocol.MaintMeiliClearTasks:
		err = clearTasks(ctx, c, res, tl)
	default:
		err = fmt.Errorf("%s has no %q fix", display, p.Action)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		return res, agent.Sentence(err)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// compactIndex compacts one index: Meilisearch rewrites its files without
// the free space inside them. Searches go on meanwhile.
func compactIndex(ctx context.Context, c *client, p protocol.MaintenanceParams, res *protocol.MaintenanceResult, tl agent.TaskLogger) error {
	if len(p.Tables) != 1 {
		return fmt.Errorf("name the one index to compact")
	}
	uid := p.Tables[0]
	if err := protocol.ValidMeilisearchIndex(uid, false); err != nil || isTemporary(uid) {
		return fmt.Errorf("invalid index %q", uid)
	}
	st, err := c.stats(ctx)
	if err != nil {
		return err
	}
	before, ok := st.Indexes[uid]
	if !ok {
		return fmt.Errorf("there is no index named %s", uid)
	}
	tl.Printf("compacting the index %s (%s on disk, %s used)", uid, humanBytes(before.IndexSize), humanBytes(before.UsedIndexSize))
	t, err := c.enqueue(ctx, http.MethodPost, "/indexes/"+url.PathEscape(uid)+"/compact", nil, nil)
	if err != nil {
		if isCode(err, "not_found") || isAuthError(err) {
			return fmt.Errorf("this Meilisearch can't compact indexes (it needs a newer version, or Rowsafe's key made before it could: run the Rowsafe installer again)")
		}
		return err
	}
	if _, err := c.waitTask(ctx, t, 6*time.Hour); err != nil {
		return err
	}
	after := before
	if st, err := c.stats(ctx); err == nil {
		after = st.Indexes[uid]
	}
	res.Summary = fmt.Sprintf("Compacted the index %s: %s on disk now (was %s).", uid, humanBytes(after.IndexSize), humanBytes(before.IndexSize))
	return nil
}

// clearTasks deletes finished tasks older than a week from the history.
func clearTasks(ctx context.Context, c *client, res *protocol.MaintenanceResult, tl agent.TaskLogger) error {
	before := time.Now().Add(-clearTasksAge).UTC().Format(time.RFC3339)
	q := url.Values{"statuses": {"succeeded,failed,canceled"}, "beforeFinishedAt": {before}}
	_, n, err := c.taskPage(ctx, url.Values{"statuses": {"succeeded,failed,canceled"}, "beforeFinishedAt": {before}, "limit": {"1"}})
	if err != nil {
		return err
	}
	if n == 0 {
		res.Summary = "No finished task older than a week: nothing to delete."
		return nil
	}
	tl.Printf("deleting %s finished more than a week ago from Meilisearch's task history", plural(n, "task", "tasks"))
	t, err := c.enqueue(ctx, http.MethodDelete, "/tasks", q, nil)
	if err != nil {
		return err
	}
	if _, err := c.waitTask(ctx, t, time.Hour); err != nil {
		return err
	}
	res.Summary = fmt.Sprintf("Deleted %s finished more than a week ago from the task history. Documents, indexes and waiting tasks are untouched.",
		plural(n, "task", "tasks"))
	return nil
}
