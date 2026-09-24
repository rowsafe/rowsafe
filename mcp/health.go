package mcp

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Thresholds, mirroring deploy/prometheus/rowsafe.rules.yml.
const (
	backupStaleAfter = 26 * time.Hour
	fullStaleAfter   = 8 * 24 * time.Hour
	drillStaleAfter  = 8 * 24 * time.Hour
	taskFailureAge   = 24 * time.Hour // failed tasks older than this are history
	queuedTooLong    = time.Hour
)

const (
	sevCritical = "critical"
	sevWarning  = "warning"
	sevInfo     = "info"
)

// Problem is one thing in the fleet that needs attention.
type Problem struct {
	Severity   string `json:"severity" jsonschema:"critical (data at risk now), warning (degraded or not yet protected) or info"`
	Kind       string `json:"kind" jsonschema:"stable identifier, e.g. backup_stale or wal_archiving_failing"`
	Database   string `json:"database,omitempty"`
	Host       string `json:"host,omitempty"`
	Summary    string `json:"summary"`
	Detail     string `json:"detail,omitempty"`
	NextAction string `json:"next_action" jsonschema:"what to do, in order"`
	Command    string `json:"command,omitempty" jsonschema:"the rowsafe CLI command (or host command) for the next action"`
	Tool       string `json:"tool,omitempty" jsonschema:"the MCP tool that performs the next action, when there is one"`
	TaskID     string `json:"task_id,omitempty" jsonschema:"task to inspect with get_task"`
	Runbook    string `json:"runbook,omitempty"`
}

const runbookBase = "https://github.com/rowsafe/rowsafe/blob/main/docs/runbooks/alerts.md#"

// dbState is a database with the history its health depends on.
type dbState struct {
	db      protocol.Database
	backups []protocol.Backup   // newest first
	drills  []protocol.Drill    // newest first
	tasks   []protocol.TaskView // newest first, without logs
	err     error
}

// gather fetches backups, drills and recent tasks for each database, a few
// at a time.
func (t *tools) gather(ctx context.Context, dbs []protocol.Database) []dbState {
	out := make([]dbState, len(dbs))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i, d := range dbs {
		out[i].db = d
		wg.Add(1)
		go func(s *dbState) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ref := s.db.ID
			if s.backups, s.err = t.c.Backups(ctx, ref, 30); s.err != nil {
				return
			}
			if s.drills, s.err = t.c.Drills(ctx, ref, 5); s.err != nil {
				return
			}
			s.tasks, s.err = t.c.Tasks(ctx, ref, 20)
		}(&out[i])
	}
	wg.Wait()
	return out
}

func latestTask(tasks []protocol.TaskView, typ string) *protocol.TaskView {
	for i := range tasks {
		if tasks[i].Type == typ {
			return &tasks[i]
		}
	}
	return nil
}

func hasOpen(tasks []protocol.TaskView, typ string) bool {
	for _, t := range tasks {
		if t.Type == typ && !finished(t.Status) {
			return true
		}
	}
	return false
}

// assessDatabase lists a database's problems. host may be nil.
func assessDatabase(s dbState, host *protocol.Host, now time.Time) []Problem {
	d := s.db
	name, q := d.Name, shellArg(d.Name)
	var out []Problem
	add := func(p Problem) {
		p.Database = name
		p.Host = d.Hostname
		out = append(out, p)
	}
	if s.err != nil {
		add(Problem{Severity: sevWarning, Kind: "history_unavailable", Summary: "could not read backup, drill or task history",
			Detail: apiError(s.err).Error(), NextAction: "Retry; if it persists, check the control plane."})
	}
	if host != nil && !online(*host, now) {
		// The host problem says what to do; here only note the consequence.
		add(Problem{Severity: sevInfo, Kind: "host_offline", Summary: "its agent is offline: no backups, drills or WAL monitoring until it is back",
			NextAction: "Fix the agent on " + d.Hostname + " (see the host_offline problem for that host)."})
	}

	switch d.Status {
	case protocol.DBPendingAdopt:
		p := Problem{Severity: sevWarning, Kind: "not_adopted", Summary: "not protected yet: registered, but the adopt plan has not been applied",
			NextAction: "Show the user the adopt plan (get_task on the latest adopt task, or re-plan with plan_adoption). Apply it only after explicit approval; applying uses ALTER SYSTEM + reload and never restarts PostgreSQL.",
			Command:    fmt.Sprintf("rowsafe db plan %s && rowsafe db apply %s", q, q), Tool: "plan_adoption"}
		if lt := latestTask(s.tasks, protocol.TaskAdopt); lt != nil {
			p.TaskID = lt.ID
			if lt.Status == protocol.StatusFailed || lt.Status == protocol.StatusLost {
				p.Kind, p.Summary = "adopt_failed", "the latest adopt task "+lt.Status
				p.Detail = firstLine(lt.Error, 300)
				p.NextAction = "Read the task log with get_task, fix the cause on the host, then re-plan."
				p.Command, p.Tool = "rowsafe task show "+lt.ID, "get_task"
			}
		}
		add(p)
	case protocol.DBAwaitingRestart:
		detail := "archive_mode (or wal_level) is set but waits for a PostgreSQL restart, so WAL archiving has not started."
		if d.Inspect != nil && len(d.Inspect.PendingRestart) > 0 {
			detail = "Pending restart for: " + strings.Join(d.Inspect.PendingRestart, ", ") + ". " + detail
		}
		add(Problem{Severity: sevWarning, Kind: "awaiting_restart", Summary: "settings applied; waiting for a PostgreSQL restart, nothing is protected yet",
			Detail:     detail,
			NextAction: "The user restarts PostgreSQL in a maintenance window (Rowsafe never does), then verifies WAL archiving.",
			Command:    "sudo systemctl restart postgresql   # on " + d.Hostname + ", then: rowsafe db verify " + q,
			Tool:       "verify_database", Runbook: runbookBase + "rowsafeawaitingrestart"})
	case protocol.DBVerifying:
		lt := latestTask(s.tasks, protocol.TaskCheck)
		switch {
		case lt == nil:
			add(Problem{Severity: sevWarning, Kind: "verification_missing", Summary: "verifying, but no check task was found",
				NextAction: "Run the WAL verification again.", Command: "rowsafe db verify " + q, Tool: "verify_database"})
		case lt.Status == protocol.StatusFailed || lt.Status == protocol.StatusLost:
			add(Problem{Severity: sevCritical, Kind: "verification_failed", Summary: "WAL verification " + lt.Status + ": no backups are scheduled",
				Detail:     firstLine(lt.Error, 300),
				NextAction: "Read the check task's log (get_task). Usually archive_mode is still off (PostgreSQL not restarted) or the repository credentials are wrong. Fix it, then verify again.",
				Command:    "rowsafe task show " + lt.ID + " && rowsafe db verify " + q, Tool: "verify_database", TaskID: lt.ID,
				Runbook: runbookBase + "rowsafeverificationstuck"})
		default:
			add(Problem{Severity: sevInfo, Kind: "verifying", Summary: "WAL verification is " + lt.Status,
				NextAction: "Wait for the check task to finish.", Command: "rowsafe task show " + lt.ID, Tool: "get_task", TaskID: lt.ID})
		}
	case protocol.DBActive:
		out = append(out, assessBackups(s, now)...)
		out = append(out, assessDrills(s, now)...)
	}

	if a := d.Archiver; a != nil && d.Status != protocol.DBPendingAdopt {
		if walFailing(a) {
			add(Problem{Severity: sevCritical, Kind: "wal_archiving_failing",
				Summary: fmt.Sprintf("WAL archiving is failing (last failure %s, last success %s)", ago(a.LastFailedTime, now), ago(a.LastArchivedTime, now)),
				Detail:  "Point-in-time recovery stops at the last archived segment and pg_wal grows until the disk is full and PostgreSQL stops.",
				NextAction: "Act now. On the host: check disk headroom (df -h), read the error (pg_stat_archiver, the PostgreSQL log, /var/log/rowsafe/" + name + "-archive-push*.log) and reproduce it with pgbackrest check. " +
					"Typical causes: revoked or rotated bucket credentials, a missing pgBackRest config. After fixing, verify again (this rewrites the config archive_command reads).",
				Command: "rowsafe db verify " + q, Tool: "verify_database", Runbook: runbookBase + "rowsafewalarchivingfailing"})
		}
		if a.Error != "" && (host == nil || online(*host, now)) {
			add(Problem{Severity: sevCritical, Kind: "postgres_unreachable", Summary: "the agent cannot read pg_stat_archiver: PostgreSQL is probably down or refusing the agent",
				Detail:     firstLine(a.Error, 300),
				NextAction: "On " + d.Hostname + ": check PostgreSQL (pg_lsclusters, systemctl status postgresql@...), and that `sudo -u postgres psql -Xc 'select 1'` works over the registered socket and port.",
				Runbook:    runbookBase + "rowsafepostgresunreachable"})
		}
	}

	// Recently failed tasks with no later success of the same type.
	reported := map[string]bool{}
	for _, p := range out {
		if p.TaskID != "" {
			reported[p.TaskID] = true
		}
	}
	seen := map[string]bool{}
	for _, t := range s.tasks {
		if seen[t.Type] {
			continue
		}
		if finished(t.Status) {
			seen[t.Type] = true
		}
		if t.Status != protocol.StatusFailed && t.Status != protocol.StatusLost {
			continue
		}
		if reported[t.ID] || t.FinishedAt == nil || now.Sub(*t.FinishedAt) > taskFailureAge {
			continue
		}
		if d.Status == protocol.DBVerifying && t.Type == protocol.TaskCheck || d.Status == protocol.DBPendingAdopt && t.Type == protocol.TaskAdopt {
			continue // covered above
		}
		retry := map[string]string{
			protocol.TaskBackup: "rowsafe backup run " + q + " --type diff",
			protocol.TaskDrill:  "rowsafe drill run " + q,
			protocol.TaskCheck:  "rowsafe db verify " + q,
			protocol.TaskAdopt:  "rowsafe db plan " + q,
		}[t.Type]
		add(Problem{Severity: sevWarning, Kind: "task_" + t.Status, Summary: fmt.Sprintf("%s task %s %s", t.Type, t.Status, ago(t.FinishedAt, now)),
			Detail:     firstLine(t.Error, 300),
			NextAction: "Read the task's error and log with get_task. One transient failure needs no action if the next scheduled run succeeds; otherwise fix the cause and retry.",
			Command:    strings.TrimSuffix("rowsafe task show "+t.ID+" && "+retry, " && "), Tool: "get_task", TaskID: t.ID,
			Runbook: runbookBase + "rowsafetaskfailed"})
	}
	for _, t := range s.tasks {
		if t.Status == protocol.StatusQueued && now.Sub(t.CreatedAt) > queuedTooLong && (host == nil || online(*host, now)) {
			add(Problem{Severity: sevWarning, Kind: "task_not_claimed", Summary: fmt.Sprintf("%s task queued since %s and not picked up", t.Type, ago(&t.CreatedAt, now)),
				NextAction: "The agent runs one task at a time: it may be busy with a long backup or drill, or stuck. Check list_tasks for a running task, and the agent on the host (`journalctl -u rowsafe-agent`).",
				Command:    "rowsafe tasks " + q, Tool: "list_tasks", TaskID: t.ID})
			break
		}
	}
	return out
}

func assessBackups(s dbState, now time.Time) []Problem {
	d := s.db
	q := shellArg(d.Name)
	base := Problem{Database: d.Name, Host: d.Hostname}
	open := hasOpen(s.tasks, protocol.TaskBackup)
	if len(s.backups) == 0 {
		p := base
		if open {
			p.Severity, p.Kind, p.Summary = sevInfo, "first_backup_running", "the first full backup is queued or running"
			p.NextAction, p.Command, p.Tool = "Wait for it; follow it with list_tasks.", "rowsafe tasks "+q, "list_tasks"
		} else {
			p.Severity, p.Kind, p.Summary = sevCritical, "backup_missing", "active, but no backup has ever finished"
			p.NextAction, p.Command, p.Tool = "Take a full backup now, then check why the first one did not run (list_tasks).", "rowsafe backup run "+q+" --type full", "run_backup"
			p.Runbook = runbookBase + "rowsafebackupmissing"
		}
		return []Problem{p}
	}
	var out []Problem
	last := s.backups[0]
	if age := now.Sub(last.StoppedAt); age > backupStaleAfter {
		p := base
		p.Severity, p.Kind = sevCritical, "backup_stale"
		p.Summary = fmt.Sprintf("last backup finished %s (%s %s)", ago(&last.StoppedAt, now), last.Type, last.Label)
		p.NextAction = "Find out why scheduled backups stopped (list_tasks for failed, lost or never-claimed backup tasks), then take a backup."
		if open {
			p.Detail = "A backup task is queued or running now."
		}
		p.Command, p.Tool, p.Runbook = "rowsafe backup run "+q+" --type diff", "run_backup", runbookBase+"rowsafebackupmissing"
		out = append(out, p)
	}
	var lastFull *protocol.Backup
	for i := range s.backups {
		if s.backups[i].Type == protocol.BackupFull {
			lastFull = &s.backups[i]
			break
		}
	}
	if lastFull == nil || now.Sub(lastFull.StoppedAt) > fullStaleAfter {
		p := base
		p.Severity, p.Kind = sevWarning, "full_backup_stale"
		p.Summary = "no full backup in 8 days"
		if lastFull != nil {
			p.Summary = "last full backup finished " + ago(&lastFull.StoppedAt, now)
		}
		p.Detail = "Differentials still work against the old full, but retention cannot expire it and restores replay a longer chain."
		p.NextAction = "Check the Sunday full-backup tasks (list_tasks type=backup), then take a full backup."
		p.Command, p.Tool, p.Runbook = "rowsafe backup run "+q+" --type full", "run_backup", runbookBase+"rowsafefullbackupmissing"
		out = append(out, p)
	}
	return out
}

func assessDrills(s dbState, now time.Time) []Problem {
	d := s.db
	q := shellArg(d.Name)
	base := Problem{Database: d.Name, Host: d.Hostname}
	if len(s.drills) > 0 && !s.drills[0].Passed {
		dr := s.drills[0]
		p := base
		p.Severity, p.Kind = sevCritical, "drill_failed"
		p.Summary = "the latest restore drill FAILED " + ago(&dr.CreatedAt, now)
		p.Detail = strings.Join(capList(dr.Result.Failures, 3), "; ")
		p.NextAction = "Until a drill passes there is no proof the backups restore. Read the drill task's log (get_task). Disk-space failures: free space and re-run. Restore errors or missing databases are serious: take a new full backup and drill again."
		p.Command, p.Tool, p.TaskID = "rowsafe task show "+dr.TaskID+" && rowsafe drill run "+q, "run_drill", dr.TaskID
		p.Runbook = runbookBase + "rowsafedrillfailed"
		return []Problem{p}
	}
	var lastPass *protocol.Drill
	for i := range s.drills {
		if s.drills[i].Passed {
			lastPass = &s.drills[i]
			break
		}
	}
	switch {
	case lastPass != nil && now.Sub(lastPass.CreatedAt) > drillStaleAfter:
		p := base
		p.Severity, p.Kind, p.Summary = sevWarning, "drill_overdue", "last passing restore drill was "+ago(&lastPass.CreatedAt, now)
		p.NextAction = "Check the drill tasks (list_tasks type=drill) for failures, then run a drill."
		p.Command, p.Tool, p.Runbook = "rowsafe drill run "+q, "run_drill", runbookBase+"rowsafedrilloverdue"
		return []Problem{p}
	case lastPass == nil && now.Sub(d.CreatedAt) > drillStaleAfter:
		p := base
		p.Severity, p.Kind, p.Summary = sevWarning, "drill_missing", "no restore drill has ever passed"
		p.NextAction = "Run a restore drill to prove the backups restore."
		p.Command, p.Tool, p.Runbook = "rowsafe drill run "+q, "run_drill", runbookBase+"rowsafefirstdrillmissing"
		return []Problem{p}
	}
	return nil
}

func assessHost(h protocol.Host, dbNames []string, now time.Time) []Problem {
	var out []Problem
	base := Problem{Host: h.Hostname}
	if !online(h, now) {
		p := base
		p.Severity, p.Kind = sevCritical, "host_offline"
		if h.LastSeenAt == nil {
			p.Summary = "the agent has never sent a heartbeat"
		} else {
			p.Summary = "the agent's last heartbeat was " + ago(h.LastSeenAt, now)
		}
		if len(dbNames) > 0 {
			p.Detail = "Affected databases (no backups, drills or WAL monitoring; PostgreSQL still archives WAL): " + strings.Join(dbNames, ", ")
		} else {
			p.Severity = sevWarning
		}
		p.NextAction = "On " + h.Hostname + ": is the host up? `systemctl status rowsafe-agent` and `journalctl -u rowsafe-agent -n 100` show why the agent stopped; restart it once the cause is fixed."
		p.Command = "sudo systemctl restart rowsafe-agent   # on " + h.Hostname
		p.Runbook = runbookBase + "rowsafeagentdown"
		out = append(out, p)
	}
	if u := h.LastUpdate; u != nil && (u.State == protocol.UpdateRolledBack || u.State == protocol.UpdateFailed) {
		p := base
		p.Severity, p.Kind = sevWarning, "agent_update_"+u.State
		p.Summary = fmt.Sprintf("agent update to %s %s %s", u.ToVersion, strings.ReplaceAll(u.State, "_", " "), ago(&u.At, now))
		p.Detail = firstLine(u.Error, 300)
		p.NextAction = "The agent keeps running its previous version, and the release's rollout is halted for every host. The control-plane operator reviews it with `rowsafed release list` (docs/releases.md). Nothing to do on this host unless the error points at it (full disk, broken config)."
		if u.Retryable {
			p.Severity = sevInfo
			p.NextAction = "A transient failure (e.g. a download timeout); the agent retries within an hour."
		}
		p.Runbook = runbookBase + "rowsafeagentupdatefailed"
		out = append(out, p)
	}
	return out
}

func sortProblems(ps []Problem) {
	rank := map[string]int{sevCritical: 0, sevWarning: 1, sevInfo: 2}
	slices.SortStableFunc(ps, func(a, b Problem) int {
		return cmp.Or(cmp.Compare(rank[a.Severity], rank[b.Severity]), cmp.Compare(a.Database, b.Database), cmp.Compare(a.Host, b.Host))
	})
}

func worst(ps []Problem) string {
	h := "ok"
	for _, p := range ps {
		switch p.Severity {
		case sevCritical:
			return sevCritical
		case sevWarning:
			h = sevWarning
		}
	}
	return h
}
