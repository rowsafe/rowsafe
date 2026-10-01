package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/protocol"
)

// One-click permission changes (protocol/permissions.go). The agent can't
// change what root allowed, and doesn't check the change either: it hands
// the signed request to root's helper (rowsafe-permissions.service, started
// by rowsafe-permissions.path), which verifies the passkey signature
// against the keys root paired and only then runs root's installer:
//
//	<state dir>/permissions/request     written by the agent: permissions.Request
//	/run/rowsafe-permissions/result     written by the helper: permissions.Answer

// Where the helper is looked for and how long it may take (variables for
// tests).
var (
	permissionsPathUnit  = permissions.PathUnit
	permissionsResultDir = permissions.DefaultAnswerDir
	permissionsWait      = 12 * time.Minute // the installer may take 10
	permissionsPoll      = 250 * time.Millisecond
	// permissionsAfter, when set, reads what root allows now, for the
	// result (the heartbeat's report).
	permissionsAfter func(Config) *protocol.PermissionsReport
)

func (a *Agent) permissionsRequestDir() string {
	if d := os.Getenv("ROWSAFE_PERMISSIONS_REQUEST_DIR"); d != "" {
		return d
	}
	return filepath.Join(a.cfg.StateDir, "permissions")
}

func (a *Agent) permissionsTask(ctx context.Context, task *protocol.Task, tl *taskLog) (*protocol.PermissionsResult, error) {
	host, _ := os.Hostname()
	if a.cfg.Sidecar() {
		tl.Printf("refused: one-click permission changes are not available in Docker")
		return &protocol.PermissionsResult{Refused: "one-click permission changes aren't available for servers where Rowsafe runs in Docker; " +
			"what the agent may do there is set where its containers are defined"}, nil
	}
	if len(task.Params) == 0 || len(task.Params) > permissions.MaxRequest/2 {
		return nil, errors.New("the task carries no signed change")
	}
	var signed protocol.SignedPermissionChange
	if err := json.Unmarshal(task.Params, &signed); err != nil {
		return nil, fmt.Errorf("the task's signed change is malformed: %w", err)
	}
	if _, err := os.Stat(permissionsPathUnit); err != nil {
		tl.Printf("refused: %s is missing", permissionsPathUnit)
		return &protocol.PermissionsResult{Refused: fmt.Sprintf("%s can't take one-click permission changes yet: its Rowsafe installation "+
			"is older than them. Run the Rowsafe installer on the server again (as root) to add them", host)}, nil
	}
	dir := a.permissionsRequestDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	data, err := json.Marshal(permissions.Request{ID: task.ID, Signed: signed})
	if err != nil {
		return nil, err
	}
	request := filepath.Join(dir, permissions.RequestName)
	if err := writeFileAtomic(request, data, 0o600); err != nil {
		return nil, err
	}
	tl.Printf("handed the signed change to root's permissions helper; waiting for it to check the passkey signature")
	ans, err := waitPermissionsAnswer(ctx, filepath.Join(permissionsResultDir, permissions.AnswerName), task.ID)
	if err != nil {
		_ = os.Remove(request)
		if errors.Is(err, errPermissionsNoAnswer) {
			return nil, fmt.Errorf("root's permissions helper on %s didn't answer within %s (check rowsafe-permissions.path on the server)",
				host, permissionsWait)
		}
		return nil, err
	}
	res := ans.PermissionsResult
	switch {
	case res.Applied:
		tl.Printf("the server verified the passkey signature and applied the change")
	default:
		tl.Printf("the server refused the change: %s", res.Refused)
	}
	if res.Output != "" {
		tl.Output("installer", []byte(res.Output))
	}
	if permissionsAfter != nil {
		res.Permissions = permissionsAfter(a.cfg)
	}
	return &res, nil
}

var errPermissionsNoAnswer = errors.New("no answer from the permissions helper")

func waitPermissionsAnswer(ctx context.Context, path, id string) (*permissions.Answer, error) {
	deadline := time.Now().Add(permissionsWait)
	for {
		if data, err := os.ReadFile(path); err == nil && len(data) <= 1<<20 {
			var ans permissions.Answer
			if json.Unmarshal(data, &ans) == nil && ans.ID == id {
				return &ans, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, errPermissionsNoAnswer
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(permissionsPoll):
		}
	}
}
