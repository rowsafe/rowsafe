package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment is read-only: the agent reads the change log (WAL) in the
// user's storage and lists when rows were deleted or changed, or tables
// emptied or dropped. It never changes the database, so assistants may use
// it; rewinding to the moment stays with people.

type findMomentInput struct {
	Database string   `json:"database" jsonschema:"the database's name or ID (list_databases)"`
	Tables   []string `json:"tables,omitempty" jsonschema:"only these tables: schema.table or just table (e.g. applications)"`
	DB       string   `json:"db,omitempty" jsonschema:"only this PostgreSQL database inside the server (datname), when it has several"`
	// SinceHours is how far back from To to search.
	SinceHours float64    `json:"since_hours,omitempty" jsonschema:"how many hours back to search (default 24, at most 168); ignored when from is set"`
	From       *time.Time `json:"from,omitempty" jsonschema:"search from this time (RFC 3339)"`
	To         *time.Time `json:"to,omitempty" jsonschema:"search up to this time (RFC 3339, default now)"`
	Kinds      []string   `json:"kinds,omitempty" jsonschema:"only these kinds of change: delete, update, truncate, drop (default all)"`
	MinRows    int64      `json:"min_rows,omitempty" jsonschema:"leave out transactions that deleted or changed fewer rows"`
	// TaskID fetches an earlier search instead of starting one.
	TaskID      string `json:"task_id,omitempty" jsonschema:"the task_id of an earlier find_moment still running: returns its result instead of starting a new search"`
	WaitSeconds *int   `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the result (default 55); searches of long ranges can take minutes, then call again with task_id"`
}

// MomentView is one transaction's change to one table.
type MomentView struct {
	Time    time.Time `json:"time" jsonschema:"when the transaction committed (UTC)"`
	XID     uint32    `json:"xid" jsonschema:"the transaction ID"`
	Kind    string    `json:"kind" jsonschema:"delete, update, truncate or drop"`
	DB      string    `json:"db"`
	Table   string    `json:"table,omitempty"`
	Rows    int64     `json:"rows" jsonschema:"rows deleted or changed; for truncate and drop, PostgreSQL's last estimate of the table's size"`
	Summary string    `json:"summary"`
	// RewindTo is the point just before the transaction.
	RewindTo time.Time `json:"rewind_to" jsonschema:"the point in time just before this transaction: restoring to it leaves the change out"`
}

type FindMomentView struct {
	Database     string       `json:"database"`
	TaskID       string       `json:"task_id"`
	Status       string       `json:"status" jsonschema:"queued or running (call again with task_id), succeeded or failed"`
	Error        string       `json:"error,omitempty"`
	From         *time.Time   `json:"from,omitempty"`
	To           *time.Time   `json:"to,omitempty"`
	Moments      []MomentView `json:"moments,omitempty" jsonschema:"the biggest changes, in time order"`
	Truncated    bool         `json:"truncated,omitempty" jsonschema:"more transactions matched than are listed"`
	Transactions int64        `json:"transactions,omitempty"`
	Notes        []string     `json:"notes,omitempty"`
	Summary      string       `json:"summary,omitempty"`
	Guidance     string       `json:"guidance"`
}

const momentGuidance = "Tell the user what happened and when. PostgreSQL's change log doesn't record who made a change. To undo it, the user can Rewind to just before it: in the Rowsafe dashboard (Rewind, Find the moment, \"Rewind to just before this\"), or `rowsafe rewind copy NAME --at REWIND_TO`, then compare and bring the rows back. You can't restore anything yourself."

func (t *tools) addMomentTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "find_moment",
		Description: "Find when rows were deleted or changed, or a table emptied (TRUNCATE) or dropped: the Rowsafe agent reads the database's change log (WAL) in the user's own storage, on their server, " +
			"and lists the biggest changes per transaction with the exact commit time, transaction ID, table and row count. Read-only: it never changes the database and never reads row contents. " +
			"Use it when the user says data went missing or was overwritten (\"when were rows deleted from applications?\") so they know exactly which point to rewind to. " +
			"Default range: the last 24 hours. It can take a minute or more; if the status is still queued or running, call again with task_id.",
		Annotations: readOnly("Find the moment"),
		InputSchema: inputSchema[findMomentInput](func(p map[string]*jsonschema.Schema) {
			p["since_hours"].Minimum, p["since_hours"].Maximum = ptr(0.0), ptr(protocol.MaxMomentRange.Hours())
			p["kinds"].Items.Enum = []any{protocol.MomentDelete, protocol.MomentUpdate, protocol.MomentTruncate, protocol.MomentDrop}
			p["wait_seconds"].Minimum, p["wait_seconds"].Maximum = ptr(0.0), ptr(maxWaitLimit.Seconds())
		}),
	}, t.findMoment)
}

func (t *tools) findMoment(ctx context.Context, _ *sdk.CallToolRequest, in findMomentInput) (*sdk.CallToolResult, FindMomentView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, FindMomentView{}, apiError(err)
	}
	var task protocol.TaskView
	if in.TaskID != "" {
		if task, err = t.c.Task(ctx, in.TaskID); err != nil {
			return nil, FindMomentView{}, apiError(err)
		}
		if task.Type != protocol.TaskFindMoment {
			return nil, FindMomentView{}, fmt.Errorf("task %s is a %s task, not find_moment", task.ID, task.Type)
		}
	} else {
		req := protocol.FindMomentRequest{DB: in.DB, Tables: in.Tables, From: in.From, To: in.To, Kinds: in.Kinds, MinRows: in.MinRows}
		if req.From == nil && in.SinceHours > 0 {
			end := time.Now().UTC()
			if in.To != nil {
				end = *in.To
			}
			from := end.Add(-time.Duration(in.SinceHours * float64(time.Hour)))
			req.From = &from
		}
		if task, err = t.c.FindMoment(ctx, d.ID, req); err != nil {
			return nil, FindMomentView{}, apiError(err)
		}
	}
	wait := 55
	if in.WaitSeconds != nil {
		wait = *in.WaitSeconds
	}
	deadline := time.Now().Add(min(time.Duration(wait)*time.Second, t.opts.MaxWait, maxWaitLimit))
	for !finished(task.Status) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, FindMomentView{}, fmt.Errorf("stopped waiting (the search continues; call find_moment with task_id %s): %w", task.ID, ctx.Err())
		case <-time.After(min(2*time.Second, time.Until(deadline))):
		}
		if task, err = t.c.Task(ctx, task.ID); err != nil {
			return nil, FindMomentView{}, apiError(err)
		}
	}
	out := FindMomentView{Database: d.Name, TaskID: task.ID, Status: task.Status, Error: task.Error, Guidance: momentGuidance}
	var b textBuilder
	switch task.Status {
	case protocol.StatusQueued, protocol.StatusRunning:
		b.line("The search of %s is %s (task %s). Call find_moment again with task_id %q for the result.", d.Name, task.Status, task.ID, task.ID)
		return text(b), out, nil
	case protocol.StatusSucceeded:
	default:
		b.line("The search of %s didn't work (%s): %s", d.Name, task.Status, task.Error)
		return text(b), out, nil
	}
	var r protocol.FindMomentResult
	if err := json.Unmarshal(task.Result, &r); err != nil {
		return nil, out, fmt.Errorf("reading the result of task %s: %w", task.ID, err)
	}
	out.From, out.To, out.Truncated, out.Transactions, out.Notes, out.Summary = &r.From, &r.To, r.Truncated, r.Transactions, r.Notes, r.Summary
	for _, m := range r.Moments {
		out.Moments = append(out.Moments, MomentView{Time: m.Time, XID: m.XID, Kind: m.Kind, DB: m.DB, Table: m.Table, Rows: m.Rows,
			Summary: m.Summary, RewindTo: m.Time.Add(-time.Microsecond)})
	}
	b.line("%s", r.Summary)
	for i, m := range out.Moments {
		if i == 30 {
			b.line("… and %d more in the structured result.", len(out.Moments)-30)
			break
		}
		b.line("- %s: %s (database %s, transaction %d; rewind to %s to leave it out)", m.Time.Format(time.RFC3339), m.Summary, m.DB, m.XID,
			m.RewindTo.Format("2006-01-02T15:04:05.000000Z07:00"))
	}
	for _, n := range r.Notes {
		b.line("Note: %s", n)
	}
	b.line("Next: %s", momentGuidance)
	return text(b), out, nil
}
