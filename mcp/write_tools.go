package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// ---- inputs ----

type planInput struct {
	Database      string `json:"database" jsonschema:"database name (or ID when it is already registered). New names: 2-40 lowercase letters, digits and dashes, starting with a letter; it becomes the pgBackRest stanza and bucket path"`
	Host          string `json:"host,omitempty" jsonschema:"only to register a new database: the host's hostname or ID from list_hosts"`
	Port          int    `json:"port,omitempty" jsonschema:"only to register: PostgreSQL port (default 5432)"`
	SocketDir     string `json:"socket_dir,omitempty" jsonschema:"only to register: PostgreSQL Unix socket directory (default /var/run/postgresql)"`
	RetentionFull int    `json:"retention_full,omitempty" jsonschema:"only to register: full backups to keep (default 2, about two weeks of point-in-time recovery with weekly fulls)"`
	WaitSeconds   int    `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the plan (usually ready in seconds when the agent is online); 0 returns at once"`
}

type applyInput struct {
	Database    string `json:"database" jsonschema:"database name or ID"`
	Confirm     string `json:"confirm" jsonschema:"the database's exact name, typed only after the user explicitly approved applying the plan"`
	Force       bool   `json:"force,omitempty" jsonschema:"replace an existing, foreign archive_command or archive_library (e.g. WAL-G). Only when the user explicitly asked for it"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the task to finish before returning (0 returns at once); if it is still running, poll get_task"`
}

type backupInput struct {
	Database    string `json:"database" jsonschema:"database name or ID"`
	Type        string `json:"type" jsonschema:"full, diff (changes since the last full; the usual choice for an ad-hoc backup) or incr (changes since the last backup of any type)"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the task to finish before returning (0 returns at once); if it is still running, poll get_task"`
}

type taskInput struct {
	Database    string `json:"database" jsonschema:"database name or ID"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the task to finish before returning (0 returns at once); if it is still running, poll get_task"`
}

type scheduleInput struct {
	Database      string  `json:"database" jsonschema:"database name or ID"`
	ScheduleFull  *string `json:"schedule_full,omitempty" jsonschema:"cron expression (5 fields, UTC) for full backups, e.g. '0 1 * * 0' (Sundays 01:00)"`
	ScheduleDiff  *string `json:"schedule_diff,omitempty" jsonschema:"cron expression (5 fields, UTC) for differential backups, e.g. '0 1 * * 1-6'; empty string disables them"`
	ScheduleDrill *string `json:"schedule_drill,omitempty" jsonschema:"cron expression (5 fields, UTC) for restore drills, e.g. '15 21 * * 0'"`
	RetentionFull *int    `json:"retention_full,omitempty" jsonschema:"full backups to keep (1-52). Lowering it expires older backups, and the WAL only they need, at the next backup"`
}

// WriteResult is what a task-queuing tool returns.
type WriteResult struct {
	TaskDetail
	Registered bool `json:"registered,omitempty" jsonschema:"plan_adoption registered a new database"`
}

type ScheduleResult struct {
	Database      string `json:"database"`
	RetentionFull int    `json:"retention_full"`
	ScheduleFull  string `json:"schedule_full"`
	ScheduleDiff  string `json:"schedule_diff"`
	ScheduleDrill string `json:"schedule_drill"`
}

func withWait[T any](fn func(props map[string]*jsonschema.Schema)) *jsonschema.Schema {
	return inputSchema[T](func(p map[string]*jsonschema.Schema) {
		if w := p["wait_seconds"]; w != nil {
			w.Minimum, w.Maximum = ptr(0.0), ptr(maxWaitLimit.Seconds())
		}
		if fn != nil {
			fn(p)
		}
	})
}

func (t *tools) addWriteTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "plan_adoption",
		Description: "Produce a read-only adopt plan for a PostgreSQL cluster: what Rowsafe would change to enable WAL archiving (pgBackRest config, stanza, archive_mode/archive_command/archive_timeout, wal_level if minimal) and whether a PostgreSQL restart will be needed. Nothing on the host changes. " +
			"If the database is not registered yet, pass host (from list_hosts) to register it first; registering counts against the plan's database limit (402 when full). For a registered database it re-plans (e.g. after the user changed settings). " +
			"Returns the plan task; show the plan to the user. Applying it is a separate step (apply_adoption) that needs their explicit approval.",
		Annotations: writes("Plan adoption (read-only on the host)", false, false),
		InputSchema: withWait[planInput](func(p map[string]*jsonschema.Schema) {
			p["port"].Minimum, p["port"].Maximum = ptr(1.0), ptr(65535.0)
			p["retention_full"].Minimum, p["retention_full"].Maximum = ptr(1.0), ptr(52.0)
		}),
	}, t.planAdoption)

	sdk.AddTool(s, &sdk.Tool{
		Name: "apply_adoption",
		Description: "Apply a database's adopt plan on its host: write the pgBackRest config, create the stanza, and set the archiving settings with ALTER SYSTEM + pg_reload_conf(). This changes production PostgreSQL settings. It never restarts PostgreSQL: when archive_mode or wal_level changes, PostgreSQL needs a restart later, which the user does (Restart PostgreSQL in the dashboard, `rowsafe restart`, or on the server); Rowsafe then verifies by itself. " +
			"REQUIRED before calling: show the user the latest plan (plan_adoption or get_task on the plan task), explain what changes and whether a restart will be needed, and get their explicit approval for this database. Then pass confirm set to the database's exact name. Never call it on your own initiative. " +
			"Leave force false unless the user explicitly asked to replace an existing archiver (e.g. WAL-G); force overwrites another tool's archive_command.",
		Annotations: writes("Apply adoption (changes PostgreSQL settings)", true, false),
		InputSchema: withWait[applyInput](nil),
	}, t.applyAdoption)

	sdk.AddTool(s, &sdk.Tool{
		Name: "run_backup",
		Description: "Queue a backup of an active (or verifying) database now, in addition to its schedule. It runs on the host with pgBackRest, uploads to the bucket, and can take hours for a large database. " +
			"Prefer type diff for an ad-hoc backup. A full backup reads the whole database, and afterwards retention expires the oldest full backup beyond retention_full (and the WAL only it needs), which shortens how far back point-in-time recovery reaches; use full only when needed (no recent full, or the user asks). " +
			"Fails with 409 if a backup is already queued or running.",
		Annotations: writes("Run a backup", false, false),
		InputSchema: withWait[backupInput](func(p map[string]*jsonschema.Schema) {
			p["type"].Enum = []any{protocol.BackupFull, protocol.BackupDiff, protocol.BackupIncr}
		}),
	}, t.runBackup)

	sdk.AddTool(s, &sdk.Tool{
		Name: "run_drill",
		Description: "Queue a restore test (Proof; task type drill) of an active database: the agent restores the latest backup plus archived WAL into a scratch cluster on the same host (private socket, no TCP, low CPU and IO priority), compares databases and table counts with production, and deletes it. " +
			"It needs free disk of about 1.3x the database size + 1 GiB on the host and can take hours. Fails with 409 if one is already queued or running.",
		Annotations: writes("Run a restore test (Proof)", false, false),
		InputSchema: withWait[taskInput](nil),
	}, t.runDrill)

	sdk.AddTool(s, &sdk.Tool{
		Name: "verify_database",
		Description: "Queue a WAL check (pgbackrest check): force a WAL switch and prove the segment reaches the bucket. Rowsafe runs it by itself once a database awaiting_restart has been restarted; use it to check right away, after fixing failing WAL archiving (it also rewrites the pgBackRest config archive_command reads), or to re-check a verifying database. " +
			"The first successful check makes the database active, starts its schedules and queues its first full backup.",
		Annotations: writes("Verify WAL archiving", false, false),
		InputSchema: withWait[taskInput](nil),
	}, t.verifyDatabase)

	sdk.AddTool(s, &sdk.Tool{
		Name: "update_schedule",
		Description: "Change a database's backup and restore test (drill) schedules (5-field cron expressions, evaluated in UTC) and/or how many full backups are kept. Omitted fields stay as they are; get_database shows the current values. " +
			"Lowering retention_full permanently deletes older backups at the next backup, shortening the point-in-time recovery window: confirm that with the user first. A changed schedule counts from now, so it never fires a missed run as a backlog.",
		Annotations: writes("Update schedules and retention", true, true),
		InputSchema: inputSchema[scheduleInput](func(p map[string]*jsonschema.Schema) {
			p["retention_full"].Minimum, p["retention_full"].Maximum = ptr(1.0), ptr(52.0)
		}),
	}, t.updateSchedule)
}

// ---- handlers ----

func (t *tools) planAdoption(ctx context.Context, _ *sdk.CallToolRequest, in planInput) (*sdk.CallToolResult, WriteResult, error) {
	d, err := t.c.Database(ctx, in.Database)
	switch {
	case err == nil:
		if in.Host != "" && in.Host != d.Hostname && in.Host != d.HostID {
			return nil, WriteResult{}, fmt.Errorf("%s is already registered on host %s, not %s; a database can't be moved between hosts", d.Name, d.Hostname, in.Host)
		}
		if (in.Port != 0 && in.Port != d.Port) || (in.SocketDir != "" && in.SocketDir != d.SocketDir) {
			return nil, WriteResult{}, fmt.Errorf("%s is already registered with socket %s port %d; port and socket_dir are fixed at registration", d.Name, d.SocketDir, d.Port)
		}
		if in.RetentionFull != 0 && in.RetentionFull != d.RetentionFull {
			return nil, WriteResult{}, fmt.Errorf("%s is already registered with retention_full %d; change it with update_schedule", d.Name, d.RetentionFull)
		}
		task, err := t.c.CreateTask(ctx, d.ID, protocol.TaskAdopt, protocol.AdoptParams{Apply: false})
		if err != nil {
			return nil, WriteResult{}, apiError(err)
		}
		return t.finish(ctx, task, d.Name, in.WaitSeconds, "Re-planning "+d.Name+" (read-only; nothing on the host changes).", false)
	case isStatus(err, http.StatusNotFound):
		if in.Host == "" {
			return nil, WriteResult{}, fmt.Errorf("no database %q is registered. To register it, pass host (hostname or ID from list_hosts), plus port and socket_dir if they are not 5432 and /var/run/postgresql", in.Database)
		}
		resp, err := t.c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{
			HostID: in.Host, Name: in.Database, Port: in.Port, SocketDir: in.SocketDir, RetentionFull: in.RetentionFull,
		})
		if err != nil {
			return nil, WriteResult{}, apiError(err)
		}
		lead := fmt.Sprintf("Registered %s (%s) on %s. Planning (read-only; nothing on the host changes).", resp.Database.Name, resp.Database.ID, resp.Database.Hostname)
		return t.finish(ctx, resp.Task, resp.Database.Name, in.WaitSeconds, lead, true)
	default:
		return nil, WriteResult{}, apiError(err)
	}
}

func (t *tools) applyAdoption(ctx context.Context, _ *sdk.CallToolRequest, in applyInput) (*sdk.CallToolResult, WriteResult, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, WriteResult{}, apiError(err)
	}
	if in.Confirm != d.Name {
		return nil, WriteResult{}, fmt.Errorf("not applied: confirm must be exactly %q. Show the user the adopt plan first and apply only after they explicitly approve it", d.Name)
	}
	// Refuse without a plan the user could have reviewed.
	plans, err := t.c.AllTasks(ctx, client.TaskQuery{Database: d.ID, Type: protocol.TaskAdopt, Limit: 20})
	if err != nil {
		return nil, WriteResult{}, apiError(err)
	}
	var plan *protocol.TaskView
	for i := range plans {
		p := plans[i]
		if p.Type != protocol.TaskAdopt {
			continue
		}
		if !finished(p.Status) {
			return nil, WriteResult{}, fmt.Errorf("not applied: adopt task %s for %s is still %s. Wait for it (get_task) and show the user the plan first", p.ID, d.Name, p.Status)
		}
		var params protocol.AdoptParams
		if p.Status == protocol.StatusSucceeded && json.Unmarshal(p.Params, &params) == nil && !params.Apply {
			plan = &p
			break
		}
	}
	if plan == nil {
		return nil, WriteResult{}, fmt.Errorf("not applied: %s has no successful adopt plan. Run plan_adoption, show the plan to the user and get their approval first", d.Name)
	}
	task, err := t.c.CreateTask(ctx, d.ID, protocol.TaskAdopt, protocol.AdoptParams{Apply: true, Force: in.Force})
	if err != nil {
		return nil, WriteResult{}, apiError(err)
	}
	lead := fmt.Sprintf("Applying the adopt plan to %s on %s (ALTER SYSTEM + reload; PostgreSQL is not restarted). Last reviewed plan: task %s.", d.Name, d.Hostname, plan.ID)
	if in.Force {
		lead += " force=true: an existing archive_command/archive_library will be replaced."
	}
	return t.finish(ctx, task, d.Name, in.WaitSeconds, lead, false)
}

func (t *tools) runBackup(ctx context.Context, _ *sdk.CallToolRequest, in backupInput) (*sdk.CallToolResult, WriteResult, error) {
	task, err := t.c.CreateTask(ctx, in.Database, protocol.TaskBackup, protocol.BackupParams{Type: in.Type})
	if err != nil {
		return nil, WriteResult{}, apiError(err)
	}
	return t.finish(ctx, task, in.Database, in.WaitSeconds, fmt.Sprintf("Queued a %s backup of %s.", in.Type, in.Database), false)
}

func (t *tools) runDrill(ctx context.Context, _ *sdk.CallToolRequest, in taskInput) (*sdk.CallToolResult, WriteResult, error) {
	task, err := t.c.CreateTask(ctx, in.Database, protocol.TaskDrill, nil)
	if err != nil {
		return nil, WriteResult{}, apiError(err)
	}
	return t.finish(ctx, task, in.Database, in.WaitSeconds, "Queued a restore test (Proof) of "+in.Database+".", false)
}

func (t *tools) verifyDatabase(ctx context.Context, _ *sdk.CallToolRequest, in taskInput) (*sdk.CallToolResult, WriteResult, error) {
	task, err := t.c.CreateTask(ctx, in.Database, protocol.TaskCheck, nil)
	if err != nil {
		return nil, WriteResult{}, apiError(err)
	}
	return t.finish(ctx, task, in.Database, in.WaitSeconds, "Queued a WAL check of "+in.Database+".", false)
}

func (t *tools) updateSchedule(ctx context.Context, _ *sdk.CallToolRequest, in scheduleInput) (*sdk.CallToolResult, ScheduleResult, error) {
	if in.ScheduleFull == nil && in.ScheduleDiff == nil && in.ScheduleDrill == nil && in.RetentionFull == nil {
		return nil, ScheduleResult{}, errors.New("nothing to change: pass at least one of schedule_full, schedule_diff, schedule_drill or retention_full")
	}
	before, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, ScheduleResult{}, apiError(err)
	}
	d, err := t.c.UpdateDatabase(ctx, before.ID, protocol.UpdateDatabaseRequest{
		RetentionFull: in.RetentionFull, ScheduleFull: in.ScheduleFull, ScheduleDiff: in.ScheduleDiff, ScheduleDrill: in.ScheduleDrill,
	})
	if err != nil {
		return nil, ScheduleResult{}, apiError(err)
	}
	out := ScheduleResult{Database: d.Name, RetentionFull: d.RetentionFull, ScheduleFull: d.ScheduleFull, ScheduleDiff: d.ScheduleDiff, ScheduleDrill: d.ScheduleDrill}
	var b textBuilder
	b.line("Updated %s. Schedules (UTC): full %q, diff %q, restore test (drill) %q. Retention: %d full backups.", d.Name, d.ScheduleFull, d.ScheduleDiff, d.ScheduleDrill, d.RetentionFull)
	if before.RetentionFull != d.RetentionFull {
		b.line("Retention changed from %d to %d full backups; it takes effect at the next backup.", before.RetentionFull, d.RetentionFull)
	}
	if d.Status != protocol.DBActive {
		b.line("%s is %s: schedules start once it is active.", d.Name, d.Status)
	}
	return text(b), out, nil
}

// finish optionally waits for a task and reports it with next steps.
func (t *tools) finish(ctx context.Context, task protocol.TaskView, dbName string, waitSeconds int, lead string, registered bool) (*sdk.CallToolResult, WriteResult, error) {
	if waitSeconds > 0 {
		deadline := time.Now().Add(min(time.Duration(waitSeconds)*time.Second, t.opts.MaxWait, maxWaitLimit))
		for !finished(task.Status) {
			left := time.Until(deadline)
			if left <= 0 {
				break
			}
			select {
			case <-ctx.Done():
				return nil, WriteResult{}, fmt.Errorf("stopped waiting (task %s continues; follow it with get_task): %w", task.ID, ctx.Err())
			case <-time.After(min(2*time.Second, left)):
			}
			tk, err := t.c.Task(ctx, task.ID)
			if err != nil {
				return nil, WriteResult{}, fmt.Errorf("task %s was queued, but reading it failed: %w", task.ID, apiError(err))
			}
			task = tk
		}
	}
	if task.DatabaseName == "" {
		task.DatabaseName = dbName
	}
	logTail := 0
	if task.Status == protocol.StatusFailed || task.Status == protocol.StatusLost {
		logTail = defaultLogTail
	}
	out := WriteResult{TaskDetail: taskDetail(task, logTail), Registered: registered}
	b := taskText(out.TaskDetail)
	var full textBuilder
	full.line("%s", lead)
	full.WriteString(b.String())
	return text(full), out, nil
}
