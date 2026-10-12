package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

type table struct{ w *tabwriter.Writer }

func newTable(headers ...string) *table {
	t := &table{w: tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)}
	t.row(headers...)
	return t
}

func (t *table) row(cols ...string) { fmt.Fprintln(t.w, strings.Join(cols, "\t")) }
func (t *table) flush()             { t.w.Flush() }

func ago(t *time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := time.Since(*t)
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

func passFail(ok bool) string {
	if ok {
		return "PASSED"
	}
	return "FAILED"
}

func statusText(s string) string {
	switch s {
	case protocol.DBPendingAdopt:
		return "pending adopt (plan reviewed, not applied)"
	case protocol.DBAwaitingRestart:
		return "awaiting PostgreSQL restart"
	case protocol.DBVerifying:
		return "verifying WAL archiving"
	case protocol.DBActive:
		return "active (protected)"
	}
	return s
}

func firstLine(s string, n int) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

// printTask is rowsafe task ID: the task, what it did, and what went wrong.
func printTask(t protocol.TaskView) {
	fmt.Printf("Task %s: %s %s\n", t.ID, t.Type, strings.ToUpper(t.Status))
	printTaskResult(t)
	printTaskTrouble(t)
}

// printTaskResult prints what a task did, and reports whether it printed
// anything.
func printTaskResult(t protocol.TaskView) bool {
	switch t.Type {
	case protocol.TaskAdopt:
		var r protocol.AdoptResult
		if json.Unmarshal(t.Result, &r) == nil && (r.Inspect.ServerVersion != "" || len(r.Plan) > 0 || len(r.Warnings) > 0) {
			printAdopt(r)
			return true
		}
	case protocol.TaskRestorePoint:
		var r protocol.RestorePointResult
		if json.Unmarshal(t.Result, &r) == nil && r.LSN != "" {
			fmt.Println(markText(r))
			return true
		}
	case protocol.TaskBackup:
		var r protocol.BackupResult
		if json.Unmarshal(t.Result, &r) == nil && r.Label != "" {
			fmt.Printf("Backup %s (%s): %s database, %s stored, took %s\n", r.Label, r.Type,
				humanBytes(r.SizeBytes), humanBytes(r.RepoSizeBytes), r.StoppedAt.Sub(r.StartedAt).Round(time.Second))
			return true
		}
	case protocol.TaskDrill:
		var r protocol.DrillResult
		if json.Unmarshal(t.Result, &r) == nil && r.BackupLabel != "" {
			printDrill(r)
			return true
		}
	case protocol.TaskMaintenance:
		var r protocol.MaintenanceResult
		if json.Unmarshal(t.Result, &r) == nil && r.Summary != "" {
			fmt.Println(r.Summary)
			for _, d := range r.Details {
				fmt.Printf("  %s\n", d)
			}
			return true
		}
	case protocol.TaskSettings:
		var r protocol.SettingsResult
		if json.Unmarshal(t.Result, &r) == nil && r.Summary != "" {
			fmt.Println(r.Summary)
			return true
		}
	case protocol.TaskSecurityFix: // protocol/security.go
		var r protocol.SecurityFixResult
		if json.Unmarshal(t.Result, &r) == nil && r.Summary != "" {
			fmt.Println(r.Summary)
			return true
		}
	case protocol.TaskRestart:
		var r protocol.RestartResult
		if json.Unmarshal(t.Result, &r) == nil && r.Restarted {
			if r.ArchiveMode == "" { // an engine without WAL archiving (ClickHouse, Qdrant, ...)
				fmt.Printf("Restarted %s in %.1fs\n", cmp.Or(r.Unit, "the database"), float64(r.DurationMs)/1000)
			} else {
				fmt.Printf("Restarted %s in %.1fs; archive_mode is %s\n", cmp.Or(r.Unit, "PostgreSQL"),
					float64(r.DurationMs)/1000, r.ArchiveMode)
			}
			return true
		}
	case protocol.TaskPooling, protocol.TaskPoolerRetarget:
		return poolingResult(t)
	}
	return false
}

// markText says where a Mark is and whether the backups have it yet.
func markText(r protocol.RestorePointResult) string {
	where := fmt.Sprintf("LSN %s, WAL %s", r.LSN, r.WALFile)
	switch {
	case strings.Contains(r.LSN, ":"): // MySQL / MariaDB: a binary log position
		where = "binary log position " + r.LSN
	case r.WALFile == "": // a Mark taken as a backup of its own (Qdrant, ...)
		where = "backup " + r.LSN
	}
	if !r.Archived {
		return fmt.Sprintf("Mark %q made (%s), but NOT yet confirmed in the backups.", r.Name, where)
	}
	return fmt.Sprintf("Mark %q saved (%s).", r.Name, where)
}

// printTaskTrouble prints a task's error, and its log when it didn't succeed.
func printTaskTrouble(t protocol.TaskView) {
	if t.Error != "" {
		fmt.Printf("Error: %s\n", t.Error)
	}
	if t.Log != "" && t.Status != protocol.StatusSucceeded {
		fmt.Printf("\nLog:\n%s", t.Log)
	}
}

func printAdopt(r protocol.AdoptResult) {
	in := r.Inspect
	if in.ServerVersion != "" {
		engine := protocol.EngineDisplayName(in.Engine)
		if in.MySQL != nil {
			engine = protocol.EngineDisplayName(in.MySQL.Engine)
		}
		fmt.Printf("%s %s, %s across %d databases, data directory %s\n\n",
			engine, in.ServerVersion, humanBytes(in.TotalSizeBytes), len(in.Databases), in.DataDirectory)
	}
	if len(r.Plan) > 0 {
		if r.Applied {
			fmt.Println("Applied:")
		} else {
			fmt.Println("Plan (nothing has been changed yet):")
		}
		for _, c := range r.Plan {
			if c.Kind == "setting" {
				to := c.To
				if to == "" {
					to = "(reset)"
				}
				restart := ""
				if c.Restart {
					restart = "   [needs restart]"
				}
				fmt.Printf("  ~ %s: %s -> %s%s\n", c.Setting, orDash(c.From), to, restart)
			} else {
				fmt.Printf("  + %s\n", c.Description)
			}
		}
	}
	for _, w := range r.Warnings {
		fmt.Printf("\n  ! %s", w)
	}
	if len(r.Warnings) > 0 {
		fmt.Println()
	}
}

func printDrill(r protocol.DrillResult) {
	fmt.Printf("Proof %s: restored backup %s (%s) in %s\n", passFail(r.Passed), r.BackupLabel,
		humanBytes(r.RestoredBytes), (time.Duration(r.DurationSeconds) * time.Second).String())
	if r.RecoveredTo != nil {
		fmt.Printf("Recovered to the last transaction at %s\n", r.RecoveredTo.Local().Format(time.RFC1123))
	}
	for _, d := range r.Databases {
		mark := "ok"
		if !d.Present {
			mark = "MISSING"
		}
		fmt.Printf("  %-24s %-8s tables %d/%d\n", d.Name, mark, d.RestoredTables, d.SourceTables)
	}
	for _, w := range r.Warnings {
		fmt.Printf("  ! %s\n", w)
	}
	for _, f := range r.Failures {
		fmt.Printf("  x %s\n", f)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// updateText summarizes a host's last agent update attempt.
func updateText(r *protocol.UpdateReport) string {
	if r == nil {
		return "-"
	}
	when := ""
	if !r.At.IsZero() {
		at := r.At
		when = " " + ago(&at)
	}
	var s string
	switch r.State {
	case protocol.UpdateStaged, protocol.UpdateSwitched:
		s = "updating to " + r.ToVersion
	case protocol.UpdateConfirmed:
		s = "updated to " + r.ToVersion + when
	case protocol.UpdateRolledBack:
		s = "update to " + r.ToVersion + " rolled back" + when
	case protocol.UpdateFailed:
		s = "update to " + r.ToVersion + " failed" + when
	default:
		s = r.State + " " + r.ToVersion + when
	}
	if r.Error != "" {
		s += ": " + firstLine(r.Error, 50)
	}
	return s
}
