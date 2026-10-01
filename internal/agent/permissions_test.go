package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestPermissionsTask(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "rowsafe-permissions.path")
	results := filepath.Join(root, "run")
	_ = os.MkdirAll(results, 0o755)
	oldUnit, oldDir, oldWait := permissionsPathUnit, permissionsResultDir, permissionsWait
	permissionsPathUnit, permissionsResultDir, permissionsWait = unit, results, 2*time.Second
	t.Cleanup(func() { permissionsPathUnit, permissionsResultDir, permissionsWait = oldUnit, oldDir, oldWait })

	a := &Agent{cfg: Config{StateDir: root, Mode: ModeNative}, log: slog.New(slog.DiscardHandler)}
	signed := protocol.SignedPermissionChange{ChangeJSON: []byte(`{"kind":"rowsafe.permissions/v1"}`), CredentialID: []byte{1}, Signature: []byte{2}}
	params, _ := json.Marshal(signed)
	task := &protocol.Task{ID: "task-1", Type: protocol.TaskPermissions, Params: params}

	// No helper installed: a plain refusal.
	res, err := a.permissionsTask(context.Background(), task, &taskLog{})
	if err != nil || res.Applied || !strings.Contains(res.Refused, "can't take one-click permission changes yet") {
		t.Fatalf("no helper: %+v %v", res, err)
	}

	// The helper answers: the request it got is the signed change, as is.
	_ = os.WriteFile(unit, nil, 0o644)
	go func() {
		req := filepath.Join(root, "permissions", permissions.RequestName)
		for range 200 {
			if data, err := os.ReadFile(req); err == nil {
				var r permissions.Request
				_ = json.Unmarshal(data, &r)
				_ = os.Remove(req)
				ans := permissions.Answer{ID: r.ID, PermissionsResult: protocol.PermissionsResult{Applied: string(r.Signed.ChangeJSON) == string(signed.ChangeJSON), Output: "ok done"}}
				out, _ := json.Marshal(ans)
				_ = os.WriteFile(filepath.Join(results, permissions.AnswerName), out, 0o644)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	tl := &taskLog{}
	res, err = a.permissionsTask(context.Background(), task, tl)
	if err != nil || !res.Applied || res.Output != "ok done" {
		t.Fatalf("applied: %+v %v", res, err)
	}
	if !strings.Contains(tl.String(), "verified the passkey signature and applied") {
		t.Fatal(tl.String())
	}

	// No answer: the task fails and the request is taken back.
	task.ID = "task-2"
	if _, err := a.permissionsTask(context.Background(), task, &taskLog{}); err == nil || !strings.Contains(err.Error(), "didn't answer") {
		t.Fatalf("no answer: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "permissions", permissions.RequestName)); !os.IsNotExist(err) {
		t.Fatal("request left behind")
	}

	// Docker: refused.
	a.cfg.Mode = ModeDockerSidecar
	res, err = a.permissionsTask(context.Background(), task, &taskLog{})
	if err != nil || !strings.Contains(res.Refused, "Docker") {
		t.Fatalf("docker: %+v %v", res, err)
	}
}
