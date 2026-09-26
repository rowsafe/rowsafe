package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Output views. They are the tools' structured results: small, stable, and
// free of anything secret. Text versions for the model come from the fmt*
// functions below.

// Output caps.
const (
	maxTextBytes    = 24 << 10 // text content of one tool result
	maxErrorBytes   = 2000     // one task error
	defaultLogTail  = 4000
	maxLogTail      = 16000
	maxInspectDBs   = 50 // databases listed from one PostgreSQL cluster
	onlineThreshold = 5 * time.Minute
)

type OrgView struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	Plan          string              `json:"plan"`
	Limits        protocol.PlanLimits `json:"limits"`
	Usage         protocol.OrgUsage   `json:"usage"`
	PlanPeriodEnd *time.Time          `json:"plan_period_end,omitempty"`
}

type HostView struct {
	ID            string                 `json:"id"`
	Hostname      string                 `json:"hostname"`
	Online        bool                   `json:"online" jsonschema:"a heartbeat arrived in the last 5 minutes"`
	LastSeenAt    *time.Time             `json:"last_seen_at,omitempty"`
	AgentVersion  string                 `json:"agent_version,omitempty"`
	Platform      string                 `json:"platform,omitempty"`
	UpdateChannel string                 `json:"update_channel"`
	PinnedVersion string                 `json:"pinned_version,omitempty"`
	LastUpdate    *protocol.UpdateReport `json:"last_update,omitempty" jsonschema:"outcome of the agent's last self-update attempt"`
}

func hostView(h protocol.Host, now time.Time) HostView {
	return HostView{
		ID: h.ID, Hostname: h.Hostname, Online: online(h, now), LastSeenAt: h.LastSeenAt,
		AgentVersion: h.AgentVersion, Platform: h.Platform, UpdateChannel: h.UpdateChannel,
		PinnedVersion: h.PinnedVersion, LastUpdate: h.LastUpdate,
	}
}

func online(h protocol.Host, now time.Time) bool {
	return h.LastSeenAt != nil && now.Sub(*h.LastSeenAt) <= onlineThreshold
}

type BackupView struct {
	Label         string    `json:"label"`
	Type          string    `json:"type" jsonschema:"full, diff or incr"`
	TaskID        string    `json:"task_id"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`
	AgeHours      float64   `json:"age_hours" jsonschema:"hours since the backup finished"`
	SizeBytes     int64     `json:"size_bytes" jsonschema:"database size"`
	RepoSizeBytes int64     `json:"repo_size_bytes" jsonschema:"bytes stored in the bucket (compressed, deduplicated)"`
}

func backupView(b protocol.Backup, now time.Time) BackupView {
	return BackupView{
		Label: b.Label, Type: b.Type, TaskID: b.TaskID, StartedAt: b.StartedAt, FinishedAt: b.StoppedAt,
		AgeHours: hours(now.Sub(b.StoppedAt)), SizeBytes: b.SizeBytes, RepoSizeBytes: b.RepoSizeBytes,
	}
}

type DrillView struct {
	Passed          bool       `json:"passed"`
	At              time.Time  `json:"at"`
	AgeHours        float64    `json:"age_hours"`
	TaskID          string     `json:"task_id"`
	BackupLabel     string     `json:"backup_label,omitempty"`
	RecoveredTo     *time.Time `json:"recovered_to,omitempty" jsonschema:"time of the last transaction replayed from WAL"`
	DurationSeconds float64    `json:"duration_seconds"`
	RestoredBytes   int64      `json:"restored_bytes"`
	Databases       int        `json:"databases" jsonschema:"databases compared with production"`
	Failures        []string   `json:"failures,omitempty"`
	Warnings        []string   `json:"warnings,omitempty"`
}

func drillView(d protocol.Drill, now time.Time) DrillView {
	return DrillView{
		Passed: d.Passed, At: d.CreatedAt, AgeHours: hours(now.Sub(d.CreatedAt)), TaskID: d.TaskID,
		BackupLabel: d.Result.BackupLabel, RecoveredTo: d.Result.RecoveredTo, DurationSeconds: d.Result.DurationSeconds,
		RestoredBytes: d.Result.RestoredBytes, Databases: len(d.Result.Databases),
		Failures: capList(d.Result.Failures, 10), Warnings: capList(d.Result.Warnings, 10),
	}
}

type WALView struct {
	LastArchivedAt *time.Time `json:"last_archived_at,omitempty"`
	LagSeconds     *int64     `json:"lag_seconds,omitempty" jsonschema:"seconds since the last segment was archived; an idle database legitimately archives nothing for hours"`
	ArchivedCount  int64      `json:"archived_count"`
	FailedCount    int64      `json:"failed_count"`
	LastFailedAt   *time.Time `json:"last_failed_at,omitempty"`
	Failing        bool       `json:"failing" jsonschema:"the most recent archive attempt failed"`
	ReportError    string     `json:"report_error,omitempty" jsonschema:"why the agent could not read pg_stat_archiver (PostgreSQL down or refusing the agent)"`
}

func walView(a *protocol.ArchiverStats, now time.Time) *WALView {
	if a == nil {
		return nil
	}
	w := &WALView{
		LastArchivedAt: a.LastArchivedTime, ArchivedCount: a.ArchivedCount, FailedCount: a.FailedCount,
		LastFailedAt: a.LastFailedTime, Failing: walFailing(a), ReportError: truncate(a.Error, 300),
	}
	if a.LastArchivedTime != nil {
		w.LagSeconds = ptr(int64(now.Sub(*a.LastArchivedTime).Seconds()))
	}
	return w
}

// walFailing mirrors RowsafeWALArchivingFailing: the latest attempt failed.
func walFailing(a *protocol.ArchiverStats) bool {
	if a == nil || a.LastFailedTime == nil {
		return false
	}
	return a.LastArchivedTime == nil || a.LastFailedTime.After(*a.LastArchivedTime)
}

type DatabaseSummary struct {
	Name            string      `json:"name"`
	ID              string      `json:"id"`
	Host            string      `json:"host"`
	Status          string      `json:"status" jsonschema:"pending_adopt, awaiting_restart, verifying or active"`
	PostgresVersion string      `json:"postgres_version,omitempty"`
	SizeBytes       int64       `json:"size_bytes,omitempty"`
	LastBackup      *BackupView `json:"last_backup,omitempty"`
	LastFullBackup  *BackupView `json:"last_full_backup,omitempty"`
	LastDrill       *DrillView  `json:"last_drill,omitempty"`
	WAL             *WALView    `json:"wal,omitempty"`
	Health          string      `json:"health" jsonschema:"ok, warning or critical"`
	Problems        []string    `json:"problems,omitempty" jsonschema:"one line per problem; fleet_health has the next action for each"`
}

// TaskView is one task. Log is only filled by get_task.
type TaskView struct {
	ID              string     `json:"id"`
	Type            string     `json:"type" jsonschema:"inspect, adopt, check, backup, drill (the restore test), restore_point, restart, maintenance or a rewind_* task"`
	Status          string     `json:"status" jsonschema:"queued, running, succeeded, failed, lost or cancelled"`
	Database        string     `json:"database,omitempty"`
	DatabaseID      string     `json:"database_id,omitempty"`
	Scheduled       bool       `json:"scheduled" jsonschema:"queued by the scheduler rather than a person"`
	Params          any        `json:"params,omitempty"`
	Error           string     `json:"error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	DurationSeconds float64    `json:"duration_seconds,omitempty"`
}

func taskView(t protocol.TaskView) TaskView {
	v := TaskView{
		ID: t.ID, Type: t.Type, Status: t.Status, Database: t.DatabaseName, DatabaseID: t.DatabaseID,
		Scheduled: t.Scheduled, Error: truncate(t.Error, maxErrorBytes), CreatedAt: t.CreatedAt,
		StartedAt: t.StartedAt, FinishedAt: t.FinishedAt,
	}
	if len(t.Params) > 0 {
		var p any
		if json.Unmarshal(t.Params, &p) == nil {
			v.Params = p
		}
	}
	if t.StartedAt != nil && t.FinishedAt != nil {
		v.DurationSeconds = t.FinishedAt.Sub(*t.StartedAt).Round(time.Second).Seconds()
	}
	return v
}

// TaskDetail is a task with its typed result and the end of its log.
type TaskDetail struct {
	TaskView
	Adopt        *AdoptView                   `json:"adopt,omitempty" jsonschema:"result of an adopt task: the plan, or what was applied"`
	Backup       *protocol.BackupResult       `json:"backup,omitempty"`
	Drill        *protocol.DrillResult        `json:"drill,omitempty"`
	CheckOK      *bool                        `json:"check_ok,omitempty" jsonschema:"result of a check task: WAL reached the repository"`
	RestorePoint *protocol.RestorePointResult `json:"restore_point,omitempty"`
	Restart      *protocol.RestartResult      `json:"restart,omitempty" jsonschema:"result of a restart a person asked for"`
	Maintenance  *protocol.MaintenanceResult  `json:"maintenance,omitempty" jsonschema:"result of a health fix a person applied (VACUUM, ending a session, removing an unused index...)"`
	LogTail      string                       `json:"log_tail,omitempty"`
	LogBytes     int                          `json:"log_bytes,omitempty" jsonschema:"full log size; log_tail holds only its end when smaller"`
	LogTruncated bool                         `json:"log_truncated,omitempty"`
	Done         bool                         `json:"done" jsonschema:"the task has finished (succeeded, failed, lost or cancelled)"`
	Next         string                       `json:"next,omitempty" jsonschema:"what to do next"`
}

// AdoptView is an adopt result without the long per-database list.
type AdoptView struct {
	PostgresVersion string            `json:"postgres_version,omitempty"`
	DataDirectory   string            `json:"data_directory,omitempty"`
	TotalSizeBytes  int64             `json:"total_size_bytes,omitempty"`
	Databases       []string          `json:"databases,omitempty"`
	WalLevel        string            `json:"wal_level,omitempty"`
	ArchiveMode     string            `json:"archive_mode,omitempty"`
	ArchiveCommand  string            `json:"archive_command,omitempty"`
	PendingRestart  []string          `json:"pending_restart,omitempty"`
	Plan            []protocol.Change `json:"plan"`
	Applied         bool              `json:"applied" jsonschema:"false: a read-only plan, nothing was changed"`
	RestartRequired bool              `json:"restart_required"`
	Warnings        []string          `json:"warnings,omitempty"`
}

func adoptView(r protocol.AdoptResult) *AdoptView {
	in := r.Inspect
	v := &AdoptView{
		PostgresVersion: in.ServerVersion, DataDirectory: in.DataDirectory, TotalSizeBytes: in.TotalSizeBytes,
		WalLevel: in.WalLevel, ArchiveMode: in.ArchiveMode, ArchiveCommand: truncate(in.ArchiveCommand, 500),
		PendingRestart: in.PendingRestart, Plan: r.Plan, Applied: r.Applied, RestartRequired: r.RestartRequired,
		Warnings: r.Warnings,
	}
	if v.Plan == nil {
		v.Plan = []protocol.Change{}
	}
	for i, d := range in.Databases {
		if i == maxInspectDBs {
			v.Databases = append(v.Databases, fmt.Sprintf("... and %d more", len(in.Databases)-i))
			break
		}
		v.Databases = append(v.Databases, d.Name)
	}
	return v
}

func finished(status string) bool {
	switch status {
	case protocol.StatusSucceeded, protocol.StatusFailed, protocol.StatusLost, protocol.StatusCancelled:
		return true
	}
	return false
}

func taskDetail(t protocol.TaskView, logTail int) TaskDetail {
	d := TaskDetail{TaskView: taskView(t), Done: finished(t.Status)}
	if len(t.Result) > 0 {
		switch t.Type {
		case protocol.TaskAdopt:
			var r protocol.AdoptResult
			if json.Unmarshal(t.Result, &r) == nil {
				d.Adopt = adoptView(r)
			}
		case protocol.TaskBackup:
			var r protocol.BackupResult
			if json.Unmarshal(t.Result, &r) == nil && r.Label != "" {
				d.Backup = &r
			}
		case protocol.TaskDrill:
			var r protocol.DrillResult
			if json.Unmarshal(t.Result, &r) == nil && r.BackupLabel != "" {
				if len(r.Databases) > maxInspectDBs {
					r.Databases = r.Databases[:maxInspectDBs]
				}
				r.Failures, r.Warnings = capList(r.Failures, 20), capList(r.Warnings, 20)
				d.Drill = &r
			}
		case protocol.TaskCheck:
			var r protocol.CheckResult
			if json.Unmarshal(t.Result, &r) == nil {
				d.CheckOK = ptr(r.OK)
			}
		case protocol.TaskRestorePoint:
			var r protocol.RestorePointResult
			if json.Unmarshal(t.Result, &r) == nil && r.Name != "" {
				d.RestorePoint = &r
			}
		case protocol.TaskRestart:
			var r protocol.RestartResult
			if json.Unmarshal(t.Result, &r) == nil {
				d.Restart = &r
			}
		case protocol.TaskMaintenance:
			var r protocol.MaintenanceResult
			if json.Unmarshal(t.Result, &r) == nil && r.Summary != "" {
				r.Details = capList(r.Details, 20)
				d.Maintenance = &r
			}
		}
	}
	if logTail > 0 && t.Log != "" {
		d.LogBytes = len(t.Log)
		d.LogTail = tail(t.Log, logTail)
		d.LogTruncated = len(d.LogTail) < len(t.Log)
	}
	d.Next = nextStep(t, d)
	return d
}

// nextStep says what to do after a task, in the CLI's words.
func nextStep(t protocol.TaskView, d TaskDetail) string {
	name := shellArg(cmpOr(t.DatabaseName, t.DatabaseID))
	switch t.Status {
	case protocol.StatusCancelled:
		return "The task was removed from the queue before it ran."
	case protocol.StatusQueued, protocol.StatusRunning:
		return fmt.Sprintf("The task is %s. Poll get_task with task_id %q until it finishes (backups and restore tests of large databases can take hours).", t.Status, t.ID)
	case protocol.StatusLost:
		return fmt.Sprintf("The agent stopped reporting on this task (it died, restarted or the host rebooted). Check the agent on the host (`systemctl status rowsafe-agent`, `journalctl -u rowsafe-agent`), then run the %s again.", t.Type)
	case protocol.StatusFailed:
		switch t.Type {
		case protocol.TaskCheck:
			return fmt.Sprintf("WAL verification failed. Read the error and log; usually archive_mode is still off (PostgreSQL not restarted) or the repository credentials are wrong. After fixing it: `rowsafe verify %s` (tool verify_database).", name)
		case protocol.TaskBackup:
			return fmt.Sprintf("Read the error and log (pgBackRest output). After fixing the cause: `rowsafe backup %s --type diff` (tool run_backup). See https://rowsafe.sh/docs/guides/monitoring.", name)
		case protocol.TaskDrill:
			return fmt.Sprintf("Read the error and log. After fixing the cause: `rowsafe proof %s` (tool run_drill). See https://rowsafe.sh/docs/guides/monitoring.", name)
		case protocol.TaskAdopt:
			return fmt.Sprintf("Read the error and log, fix the cause on the host, then re-plan: `rowsafe plan %s` (tool plan_adoption).", name)
		case protocol.TaskRestorePoint:
			return "The restore point was not created. Don't run a destructive operation relying on it; check safety_check for the cause."
		case protocol.TaskRestart:
			return "The PostgreSQL restart failed; the error says why (e.g. restarting from Rowsafe isn't allowed on this server). Tell the user; restarting is theirs to do, and no tool here can."
		case protocol.TaskMaintenance:
			return "The health fix didn't run; the error says why in plain words (Rowsafe checks each fix again right before it runs and leaves things alone when they changed). Tell the user; they can apply it again from the dashboard (Pulse, Health, Apply fix) if it still applies. No tool here applies fixes."
		case protocol.TaskSecurityFix:
			return "The security change didn't go through; the error says why (Rowsafe checks every change with PostgreSQL first and puts the previous settings back when something is off). Tell the user; they can try again from Pulse, Security in the dashboard. No tool here changes security settings."
		case protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
			protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup:
			return "This Rewind step failed; the error says why in plain words (a failed rewind in place puts the original data back by itself). Tell the user; they can try again from Rewind in the dashboard. No tool here rewinds."
		}
		return "Read the error and log."
	}
	switch t.Type {
	case protocol.TaskAdopt:
		if d.Adopt == nil {
			return ""
		}
		switch {
		case !d.Adopt.Applied:
			return fmt.Sprintf("This is a read-only plan; nothing changed. Show it to the user. If they approve, they apply it: the Turn on backups button in the dashboard, or `rowsafe apply %s` (AI assistants can't). Applying never restarts PostgreSQL.", name)
		case d.Adopt.RestartRequired:
			return fmt.Sprintf("Settings applied. PostgreSQL needs a restart for backups to start; the user restarts it when it suits them (Restart PostgreSQL in the dashboard, `rowsafe restart %s`, or on the server: sudo systemctl restart postgresql, or in Docker: docker compose restart postgres). Rowsafe never restarts it on its own, and AI assistants can't. Rowsafe notices the restart and verifies by itself; `rowsafe verify %s` (tool verify_database) checks right away.", name, name)
		default:
			return fmt.Sprintf("Settings applied; a WAL verification (check) was queued automatically. Follow it with list_tasks for %s.", name)
		}
	case protocol.TaskCheck:
		if d.CheckOK != nil && *d.CheckOK {
			return fmt.Sprintf("%s is protected. The first full backup is queued automatically when this was its first check; follow it with list_tasks.", name)
		}
	case protocol.TaskDrill:
		if d.Drill != nil && !d.Drill.Passed {
			return "The restore test (Proof) ran but its checks failed: the backups may not restore correctly. See https://rowsafe.sh/docs/guides/monitoring; take a new full backup and test again once the cause is understood."
		}
	}
	return ""
}

// ---- small helpers ----

func hours(d time.Duration) float64 { return float64(d.Round(6*time.Minute)) / float64(time.Hour) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n - len("…")
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// tail returns at most n bytes from the end of s, starting at a line.
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	t := s[len(s)-n:]
	if i := strings.IndexByte(t, '\n'); i >= 0 && i < len(t)-1 {
		t = t[i+1:]
	}
	for len(t) > 0 && !utf8Start(t[0]) {
		t = t[1:]
	}
	return t
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func capList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	out := append([]string(nil), s[:n]...)
	return append(out, fmt.Sprintf("... and %d more", len(s)-n))
}

func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(s, "\n")
	return truncate(s, n)
}

func ago(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := now.Sub(*t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%.1fh ago", d.Hours())
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// textBuilder accumulates a tool's text result up to maxTextBytes.
type textBuilder struct {
	strings.Builder
	full bool
}

func (b *textBuilder) line(format string, args ...any) {
	if b.full {
		return
	}
	s := fmt.Sprintf(format, args...) + "\n"
	if b.Len()+len(s) > maxTextBytes {
		b.WriteString("… (output truncated; the structured result has the rest, or narrow the request)\n")
		b.full = true
		return
	}
	b.WriteString(s)
}

// shellArg quotes a CLI argument only when needed.
func shellArg(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:/@", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
