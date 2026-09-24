package mcp

import (
	"context"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Safety tools: what an agent about to run a migration or destructive SQL
// needs. safety_check and list_restore_points are read-only;
// create_restore_point is a write tool.

const restorePointNamePattern = `^[a-z0-9][a-z0-9_-]{0,62}$`

const (
	defaultRestorePointWait = 90 * time.Second
	maxRestorePointWait     = 120 * time.Second
)

type restorePointInput struct {
	Database    string `json:"database" jsonschema:"the Rowsafe database (PostgreSQL cluster) the operation will change, as named by list_databases"`
	Name        string `json:"name,omitempty" jsonschema:"restore point name: 1-63 lowercase letters, digits, - and _. Describe the operation, e.g. before-drop-orders or pre-migrate-20260924. Default: agent-<UTC timestamp>"`
	WaitSeconds *int   `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the restore point to be confirmed in the backup repository (default 90)"`
}

type ProtectionView struct {
	Database            string     `json:"database"`
	Protected           bool       `json:"protected" jsonschema:"true only if every condition holds: active, WAL archiving working and reported, a backup in the last 26h, and the latest restore drill passed within 8 days"`
	Reasons             []string   `json:"reasons" jsonschema:"each condition that does not hold"`
	Status              string     `json:"status"`
	CheckedAt           time.Time  `json:"checked_at"`
	LastBackupAt        *time.Time `json:"last_backup_at,omitempty"`
	LastFullAt          *time.Time `json:"last_full_at,omitempty"`
	WALLastArchivedAt   *time.Time `json:"wal_last_archived_at,omitempty"`
	ArchiverUp          bool       `json:"archiver_up"`
	ArchiveFailing      bool       `json:"archive_failing"`
	RecoveryWindowStart *time.Time `json:"recovery_window_start,omitempty" jsonschema:"the earliest point the database can be restored to"`
	LastDrillPassedAt   *time.Time `json:"last_drill_passed_at,omitempty"`
	LastDrillPassed     *bool      `json:"last_drill_passed,omitempty"`
	OpenFailedTasks     []TaskView `json:"open_failed_tasks"`
	Guidance            string     `json:"guidance"`
}

type RestorePointView struct {
	Database    string     `json:"database"`
	Name        string     `json:"name"`
	Status      string     `json:"status" jsonschema:"pending (being created), archived (confirmed in the backup repository: safe to rewind to) or unconfirmed (created, but archiving was not confirmed in time)"`
	TaskID      string     `json:"task_id"`
	LSN         string     `json:"lsn,omitempty"`
	WALFile     string     `json:"wal_file,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	RequestedAt time.Time  `json:"requested_at"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
	// RestoreFromBackup is what a restore to this point passes as --set.
	RestoreFromBackup string `json:"restore_from_backup,omitempty" jsonschema:"the backup a restore to this point must start from (pgbackrest --set)"`
}

type RestorePointResult struct {
	RestorePointView
	Confirmed bool   `json:"confirmed" jsonschema:"the restore point is in the backup repository"`
	TaskError string `json:"task_error,omitempty"`
	Guidance  string `json:"guidance"`
}

type RestorePointsOutput struct {
	Database      string             `json:"database"`
	RestorePoints []RestorePointView `json:"restore_points"`
}

func restorePointView(db string, p protocol.RestorePoint) RestorePointView {
	return RestorePointView{
		Database: db, Name: p.Name, Status: p.Status, TaskID: p.TaskID, LSN: p.LSN, WALFile: p.WALFile,
		CreatedBy: truncate(p.CreatedBy, 200), RequestedAt: p.RequestedAt, CreatedAt: p.CreatedAt, ArchivedAt: p.ArchivedAt,
		RestoreFromBackup: p.RestoreFromBackup,
	}
}

func (t *tools) addSafetyReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "safety_check",
		Description: "Check whether a database can be recovered right now, before you change it. " +
			"Call this BEFORE any destructive or risky database operation: running migrations (prisma migrate, rails db:migrate, alembic, django migrate, knex, goose, ...), DROP or TRUNCATE, DELETE or UPDATE without a narrow WHERE, bulk data changes, schema changes, or restoring a dump over a database. " +
			"protected=true means: active, WAL archiving works, a backup finished in the last 26h and the latest restore drill passed. " +
			"If it is not protected, tell the user the reasons and ask whether to proceed anyway before doing anything destructive. If it is protected, create a restore point next (create_restore_point).",
		Annotations: readOnly("Safety check before destructive changes"),
	}, t.safetyCheck)

	sdk.AddTool(s, &sdk.Tool{
		Name:        "list_restore_points",
		Description: "List a database's named restore points, newest first, with their status (archived = confirmed in the backup repository), LSN, and who created them. The database can be restored to any archived restore point.",
		Annotations: readOnly("List restore points"),
	}, t.listRestorePoints)
}

func (t *tools) addSafetyWriteTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "create_restore_point",
		Description: "Create a named restore point on a database and wait until it is confirmed in the backup repository. Call it right BEFORE a destructive or risky operation (after safety_check), so the database can be rewound to the moment just before it. " +
			"It is cheap and safe: it only writes a marker into the WAL (pg_create_restore_point) and forces a WAL switch; nothing else changes. Needs an active database. " +
			"Tell the user the restore point's name. If the operation then goes wrong, stop, don't try to repair data or restore it yourself, and tell the user they can restore the database to that restore point.",
		Annotations: writes("Create a restore point", false, false),
		InputSchema: inputSchema[restorePointInput](func(p map[string]*jsonschema.Schema) {
			p["name"].Pattern = restorePointNamePattern
			p["wait_seconds"].Minimum, p["wait_seconds"].Maximum = ptr(0.0), ptr(maxRestorePointWait.Seconds())
		}),
	}, t.createRestorePoint)
}

func (t *tools) safetyCheck(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, ProtectionView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, ProtectionView{}, apiError(err)
	}
	p, err := t.c.Protection(ctx, d.ID)
	if err != nil {
		return nil, ProtectionView{}, apiError(err)
	}
	out := ProtectionView{
		Database: d.Name, Protected: p.Protected, Reasons: p.Reasons, Status: p.Status, CheckedAt: p.CheckedAt,
		LastBackupAt: p.LastBackupAt, LastFullAt: p.LastFullAt, WALLastArchivedAt: p.WALLastArchivedAt, ArchiverUp: p.ArchiverUp,
		ArchiveFailing: p.ArchiveFailing, RecoveryWindowStart: p.RecoveryWindowStart, LastDrillPassedAt: p.LastDrillPassedAt,
		LastDrillPassed: p.LastDrillPassed, OpenFailedTasks: []TaskView{},
	}
	if out.Reasons == nil {
		out.Reasons = []string{}
	}
	for i, tk := range p.OpenFailedTasks {
		if i == 10 {
			break
		}
		out.OpenFailedTasks = append(out.OpenFailedTasks, taskView(tk))
	}
	now := time.Now()
	var b textBuilder
	if p.Protected {
		out.Guidance = fmt.Sprintf("Protected. Next: create_restore_point on %s right before the operation, tell the user its name, then proceed.", d.Name)
		window := ""
		if p.RecoveryWindowStart != nil {
			window = " from " + p.RecoveryWindowStart.UTC().Format(time.RFC3339)
		}
		b.line("PROTECTED: %s can be restored to any point%s up to about now (WAL last archived %s, last backup %s, last drill passed %s).",
			d.Name, window, ago(p.WALLastArchivedAt, now), ago(p.LastBackupAt, now), ago(p.LastDrillPassedAt, now))
	} else {
		out.Guidance = "NOT protected. Before any destructive operation, tell the user these reasons and ask whether to proceed anyway; don't proceed on your own. fleet_health gives the fix for each reason."
		b.line("NOT PROTECTED: %s (status %s). If a destructive operation goes wrong, it may not be recoverable:", d.Name, p.Status)
		for _, r := range p.Reasons {
			b.line("- %s", r)
		}
	}
	for _, tk := range out.OpenFailedTasks {
		b.line("Unresolved failed task: %s %s %s%s", tk.ID, tk.Type, tk.Status, errSuffix(tk.Error))
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}

func (t *tools) listRestorePoints(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, RestorePointsOutput, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, RestorePointsOutput{}, apiError(err)
	}
	points, err := t.c.RestorePoints(ctx, d.ID)
	if err != nil {
		return nil, RestorePointsOutput{}, apiError(err)
	}
	out := RestorePointsOutput{Database: d.Name, RestorePoints: []RestorePointView{}}
	now := time.Now()
	var b textBuilder
	if len(points) == 0 {
		b.line("No restore points for %s.", d.Name)
	}
	for i, p := range points {
		if i == 100 {
			b.line("… and %d older", len(points)-i)
			break
		}
		v := restorePointView(d.Name, p)
		out.RestorePoints = append(out.RestorePoints, v)
		line := fmt.Sprintf("%s: %s, requested %s by %s%s", v.Name, v.Status, ago(&v.RequestedAt, now), orDash(v.CreatedBy), lsnSuffix(v.LSN))
		if v.RestoreFromBackup != "" {
			line += ", restore from backup " + v.RestoreFromBackup
		}
		b.line("%s", line)
	}
	return text(b), out, nil
}

func lsnSuffix(lsn string) string {
	if lsn == "" {
		return ""
	}
	return ", LSN " + lsn
}

func (t *tools) createRestorePoint(ctx context.Context, _ *sdk.CallToolRequest, in restorePointInput) (*sdk.CallToolResult, RestorePointResult, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, RestorePointResult{}, apiError(err)
	}
	name := in.Name
	if name == "" {
		name = "agent-" + time.Now().UTC().Format("20060102-150405")
	}
	task, err := t.c.CreateRestorePoint(ctx, d.ID, name)
	if err != nil {
		return nil, RestorePointResult{}, apiError(err)
	}
	wait := defaultRestorePointWait
	if in.WaitSeconds != nil {
		wait = time.Duration(*in.WaitSeconds) * time.Second
	}
	wait = min(wait, t.opts.MaxWait)
	deadline := time.Now().Add(wait)
	for !finished(task.Status) && time.Until(deadline) > 0 {
		select {
		case <-ctx.Done():
			return nil, RestorePointResult{}, fmt.Errorf("stopped waiting for restore point %q (task %s continues; check list_restore_points): %w", name, task.ID, ctx.Err())
		case <-time.After(min(time.Second, time.Until(deadline))):
		}
		if task, err = t.c.Task(ctx, task.ID); err != nil {
			return nil, RestorePointResult{}, fmt.Errorf("restore point %q was requested, but reading its task failed: %w", name, apiError(err))
		}
	}

	out := RestorePointResult{RestorePointView: RestorePointView{Database: d.Name, Name: name, Status: protocol.RestorePointPending, TaskID: task.ID, RequestedAt: task.CreatedAt}}
	if points, err := t.c.RestorePoints(ctx, d.ID); err == nil {
		for _, p := range points {
			if p.Name == name {
				out.RestorePointView = restorePointView(d.Name, p)
				break
			}
		}
	}
	out.Confirmed = out.Status == protocol.RestorePointArchived
	var b textBuilder
	switch {
	case out.Confirmed:
		set := "the restore_from_backup label from `rowsafe restore-point list " + shellArg(d.Name) + "`"
		if out.RestoreFromBackup != "" {
			set = out.RestoreFromBackup
		}
		out.Guidance = fmt.Sprintf("Tell the user: restore point %q on %s is in the backup repository. If the operation goes wrong, stop and tell them they can restore %s to it (https://rowsafe.sh/docs/guides/restore, \"To a restore point\": pgbackrest restore --type=name --target=%s --set=%s). Never attempt the restore yourself.", name, d.Name, d.Name, name, set)
		b.line("Restore point %q on %s is ARCHIVED (confirmed in the backup repository)%s.", name, d.Name, lsnSuffix(out.LSN))
	case out.Status == protocol.RestorePointUnconfirmed:
		out.Guidance = "The restore point was written, but its WAL was not confirmed in the repository in time, so it may not be restorable yet. WAL archiving may be slow or failing: run safety_check, tell the user, and don't proceed with a destructive operation without their explicit OK."
		b.line("Restore point %q on %s is UNCONFIRMED: created%s, but not confirmed in the backup repository%s.", name, d.Name, lsnSuffix(out.LSN), errSuffix(task.Error))
	case task.Status == protocol.StatusFailed || task.Status == protocol.StatusLost || task.Status == protocol.StatusCancelled:
		out.TaskError = truncate(task.Error, maxErrorBytes)
		out.Guidance = "The restore point was NOT created. Tell the user and don't proceed with a destructive operation without their explicit OK. Check safety_check and fleet_health for the cause."
		b.line("Restore point %q on %s FAILED (task %s %s)%s", name, d.Name, task.ID, task.Status, errSuffix(task.Error))
	default:
		out.Guidance = fmt.Sprintf("Not confirmed yet. Check again with list_restore_points (or get_task %s) and wait for status archived before the destructive operation.", task.ID)
		b.line("Restore point %q on %s is still %s (task %s %s).", name, d.Name, out.Status, task.ID, task.Status)
	}
	b.line("Next: %s", out.Guidance)
	return text(b), out, nil
}
