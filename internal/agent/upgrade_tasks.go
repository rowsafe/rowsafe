package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/rowsafe/rowsafe/protocol"
)

// runUpgradeTask runs the update and upgrade tasks (updates.go,
// upgrade.go).
func (a *Agent) runUpgradeTask(ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec) (any, error) {
	switch task.Type {
	case protocol.TaskPGUpdate:
		return runWithID(ctx, task, tl, db, a.pgUpdate)
	case protocol.TaskSecurityUpdates:
		return typed(a.securityUpdates(ctx, db, task.ID, tl))
	case protocol.TaskReboot:
		return typed(a.reboot(ctx, db, task.ID, tl))
	case protocol.TaskUpgradeCheck:
		return runRewind(ctx, task, tl, db, a.upgradeCheck)
	case protocol.TaskUpgradeRehearsal:
		return runWithID(ctx, task, tl, db, a.upgradeRehearsal)
	case protocol.TaskUpgrade:
		return runWithID(ctx, task, tl, db, a.upgrade)
	case protocol.TaskUpgradeUndo:
		return runWithID(ctx, task, tl, db, a.upgradeUndo)
	case protocol.TaskUpgradeCleanup:
		return runRewind(ctx, task, tl, db, a.upgradeCleanup)
	}
	return nil, fmt.Errorf("unsupported task type %q", task.Type)
}

// runWithID is runRewind for tasks that also need the task's ID (to name
// their requests to the root helper).
func runWithID[P any, R any](ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec,
	run func(context.Context, protocol.DatabaseSpec, P, string, *taskLog) (*R, error)) (any, error) {
	var p P
	if len(task.Params) > 0 {
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
		}
	}
	return typed(run(ctx, db, p, task.ID, tl))
}

// typed keeps a typed nil result out of the interface.
func typed[R any](res *R, err error) (any, error) {
	if res == nil {
		return nil, err
	}
	return res, err
}
