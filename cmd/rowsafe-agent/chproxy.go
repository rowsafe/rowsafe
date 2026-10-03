package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/chproxyroot"
	"github.com/rowsafe/rowsafe/internal/permissions"
)

// chproxyApply runs `rowsafe-permissions chproxy-apply`
// (rowsafe-chproxy-apply.service, root): installs and runs chproxy in front
// of ClickHouse's HTTP interface where root allowed pooling
// (internal/chproxyroot).
func chproxyApply(ctx context.Context) error {
	if err := trustedSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "rowsafe-chproxy: refused:", err)
		return err
	}
	getenv := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	read, err := permissions.ReadAsAgentFunc(getenv("ROWSAFE_AGENT_USER", "rowsafe"))
	if err != nil {
		return err
	}
	answerDir := getenv("RUNTIME_DIRECTORY", chproxyroot.DefaultAnswerDir)
	answer := func(res chproxyroot.Result) error {
		res.FinishedAt = time.Now().UTC()
		data, _ := json.Marshal(res)
		tmp := filepath.Join(answerDir, ".result.tmp")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, filepath.Join(answerDir, chproxyroot.ResultName))
	}
	data, err := read(filepath.Join(getenv("ROWSAFE_POOLER_REQUEST_DIR", chproxyroot.DefaultRequestDir), chproxyroot.RequestName), chproxyroot.MaxRequest, true)
	if errors.Is(err, permissions.ErrNoFile) {
		return nil
	}
	if err != nil {
		return err
	}
	var req chproxyroot.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return answer(chproxyroot.Result{Error: "invalid request"})
	}
	ports, public, err := chproxyroot.Allowed(getenv("ROWSAFE_POOLER_ALLOW", chproxyroot.DefaultAllowFile))
	if err != nil {
		return answer(chproxyroot.Result{ID: req.ID, Error: "connection pooling isn't allowed on this server (root allows it with: sudo rowsafe-allow pooler)"})
	}
	a := &chproxyroot.Applier{StateDir: getenv("STATE_DIRECTORY", chproxyroot.DefaultStateDir), Binary: chproxyroot.DefaultBinary,
		ConfigFile: chproxyroot.DefaultConfig, UnitFile: chproxyroot.DefaultUnit,
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
			return cmd.CombinedOutput()
		}}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res := a.Apply(ctx, req, ports, public)
	fmt.Fprintf(os.Stderr, "rowsafe-chproxy: %s %s ok=%v %s\n", req.ID, req.Action, res.OK, res.Error)
	return answer(res)
}
