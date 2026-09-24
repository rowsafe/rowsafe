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

func printTask(t protocol.TaskView) {
	fmt.Printf("Task %s: %s %s\n", t.ID, t.Type, strings.ToUpper(t.Status))
	switch t.Type {
	case protocol.TaskAdopt:
		var r protocol.AdoptResult
		if json.Unmarshal(t.Result, &r) == nil {
			printAdopt(r)
		}
	case protocol.TaskRestorePoint:
		var r protocol.RestorePointResult
		if json.Unmarshal(t.Result, &r) == nil && r.LSN != "" {
			state := "archived"
			if !r.Archived {
				state = "NOT yet confirmed in the repository"
			}
			fmt.Printf("Restore point %q at LSN %s (WAL %s), %s\n", r.Name, r.LSN, r.WALFile, state)
		}
	case protocol.TaskBackup:
		var r protocol.BackupResult
		if json.Unmarshal(t.Result, &r) == nil && r.Label != "" {
			fmt.Printf("Backup %s (%s): %s database, %s stored, took %s\n", r.Label, r.Type,
				humanBytes(r.SizeBytes), humanBytes(r.RepoSizeBytes), r.StoppedAt.Sub(r.StartedAt).Round(time.Second))
		}
	case protocol.TaskDrill:
		var r protocol.DrillResult
		if json.Unmarshal(t.Result, &r) == nil && r.BackupLabel != "" {
			printDrill(r)
		}
	case protocol.TaskRestart:
		var r protocol.RestartResult
		if json.Unmarshal(t.Result, &r) == nil && r.Restarted {
			fmt.Printf("Restarted %s in %.1fs; archive_mode is %s\n", cmp.Or(r.Unit, "PostgreSQL"),
				float64(r.DurationMs)/1000, cmp.Or(r.ArchiveMode, "unknown"))
		}
	}
	if t.Error != "" {
		fmt.Printf("\nError: %s\n", t.Error)
	}
	if t.Log != "" && t.Status != protocol.StatusSucceeded {
		fmt.Printf("\nLog:\n%s", t.Log)
	}
}

func printAdopt(r protocol.AdoptResult) {
	in := r.Inspect
	if in.ServerVersion != "" {
		fmt.Printf("PostgreSQL %s, %s across %d databases, data directory %s\n\n",
			in.ServerVersion, humanBytes(in.TotalSizeBytes), len(in.Databases), in.DataDirectory)
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
	s := r.State + " " + r.ToVersion
	if !r.At.IsZero() {
		at := r.At
		s += " " + ago(&at)
	}
	if r.Error != "" {
		s += ": " + firstLine(r.Error, 50)
	}
	return s
}
