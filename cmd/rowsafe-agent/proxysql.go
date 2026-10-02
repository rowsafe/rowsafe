package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/internal/proxysqlroot"
)

// proxysqlApply runs `rowsafe-permissions proxysql-apply`
// (rowsafe-proxysql.service, root): installs and configures ProxySQL in
// front of MySQL or MariaDB where root allowed pooling
// (internal/proxysqlroot).
func proxysqlApply(ctx context.Context) error {
	if err := trustedSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "rowsafe-proxysql: refused:", err)
		return err
	}
	getenv := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	agentUser := getenv("ROWSAFE_AGENT_USER", "mysql")
	read, err := permissions.ReadAsAgentFunc(agentUser)
	if err != nil {
		return err
	}
	answerDir := getenv("RUNTIME_DIRECTORY", proxysqlroot.DefaultAnswerDir)
	answer := func(res proxysqlroot.Result) error {
		res.FinishedAt = time.Now().UTC()
		data, _ := json.Marshal(res)
		tmp := filepath.Join(answerDir, ".result.tmp")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, filepath.Join(answerDir, proxysqlroot.ResultName))
	}
	data, err := read(filepath.Join(getenv("ROWSAFE_POOLER_REQUEST_DIR", proxysqlroot.DefaultRequestDir), proxysqlroot.RequestName), proxysqlroot.MaxRequest, true)
	if errors.Is(err, permissions.ErrNoFile) {
		return nil
	}
	if err != nil {
		return err
	}
	var req proxysqlroot.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return answer(proxysqlroot.Result{Error: "invalid request"})
	}
	allow, err := proxysqlroot.Allowed(getenv("ROWSAFE_POOLER_ALLOW", proxysqlroot.DefaultAllowFile))
	if err != nil {
		return answer(proxysqlroot.Result{ID: req.ID, Error: "connection pooling isn't allowed on this server (root allows it with: sudo rowsafe-allow pooler)"})
	}
	a := &proxysqlroot.Applier{StateDir: getenv("STATE_DIRECTORY", proxysqlroot.DefaultStateDir), StatsFile: proxysqlroot.DefaultStatsFile, AgentGID: -1,
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND=noninteractive"}
			return cmd.CombinedOutput()
		}}
	if u, err := user.Lookup(agentUser); err == nil {
		if gid, err := strconv.Atoi(u.Gid); err == nil {
			a.AgentGID = gid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	res := a.Apply(ctx, req, allow)
	fmt.Fprintf(os.Stderr, "rowsafe-proxysql: %s %s ok=%v %s\n", req.ID, req.Action, res.OK, res.Error)
	return answer(res)
}
