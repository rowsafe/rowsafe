package main

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe mark --json: machine-readable output for scripts and CI (the
// GitHub Action in integrations/github-action reads it).

// markJSON is what rowsafe mark --json prints: the Mark as the API lists it
// (status, lsn, restore_from_backup, ...), with the database name and, when
// the task failed, its error.
type markJSON struct {
	Database string `json:"database"`
	protocol.RestorePoint
	Error string `json:"error,omitempty"`
}

// createRestorePointJSON is rowsafe mark --json. Progress goes to stderr and
// only the JSON to stdout. It exits 1 (after printing the JSON) when the
// task failed, e.g. because the Mark wasn't confirmed in the repository.
func createRestorePointJSON(ctx context.Context, c *client.Client, db, label string, noWait bool) error {
	t, err := c.CreateRestorePoint(ctx, db, label)
	if err != nil {
		return err
	}
	out := markJSON{Database: db, RestorePoint: protocol.RestorePoint{
		Name: label, Status: protocol.RestorePointPending, TaskID: t.ID, RequestedAt: t.CreatedAt}}
	failed := false
	if !noWait {
		last := ""
		t, err = c.WaitTask(ctx, t.ID, func(t protocol.TaskView) {
			if t.Status != last {
				last = t.Status
				switch t.Status {
				case protocol.StatusQueued:
					fmt.Fprintf(os.Stderr, "Waiting for the agent to pick up the restore point (task %s)...\n", t.ID)
				case protocol.StatusRunning:
					fmt.Fprintf(os.Stderr, "Saving the Mark and waiting until it is in your storage...\n")
				}
			}
		})
		if err != nil {
			return err
		}
		if t.Status == protocol.StatusSucceeded {
			// The agent only succeeds once the WAL holding the Mark is archived.
			out.Status = protocol.RestorePointArchived
		} else {
			failed = true
			out.Status = t.Status
			out.Error = cmp.Or(firstLine(t.Error, 500), "the restore point task "+t.Status)
			if log := strings.TrimSpace(t.Log); log != "" {
				fmt.Fprintf(os.Stderr, "Task %s log:\n%s\n", t.ID, log)
			}
		}
	}
	// Read the Mark back for the fields only the control plane knows, such
	// as the backup a restore to it starts from.
	points, err := c.RestorePoints(ctx, db)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: couldn't read the Mark back: %v\n", err)
	}
	for _, p := range points {
		if p.Name == label {
			out.RestorePoint = p // after a failure: "unconfirmed" if it was written
			break
		}
	}
	if err := printJSON(out); err != nil {
		return err
	}
	if failed {
		return exitError(1)
	}
	return nil
}
