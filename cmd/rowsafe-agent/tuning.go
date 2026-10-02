package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/internal/tuneroot"
)

// tuningApply runs `rowsafe-permissions tuning-apply` (rowsafe-tuning.service,
// root): writes the settings the agent asked for into Rowsafe's own files,
// where root allowed it (internal/tuneroot).
func tuningApply() error {
	if err := trustedSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "rowsafe-tuning: refused:", err)
		return err
	}
	getenv := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	read, err := permissions.ReadAsAgentFunc(getenv("ROWSAFE_AGENT_USER", "postgres"))
	if err != nil {
		return err
	}
	answerDir := getenv("RUNTIME_DIRECTORY", tuneroot.DefaultAnswerDir)
	answer := func(res tuneroot.Result) error {
		res.FinishedAt = time.Now().UTC()
		data, _ := json.Marshal(res)
		tmp := filepath.Join(answerDir, ".result.tmp")
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		return os.Rename(tmp, filepath.Join(answerDir, tuneroot.ResultName))
	}
	data, err := read(filepath.Join(getenv("ROWSAFE_TUNING_REQUEST_DIR", tuneroot.DefaultRequestDir), tuneroot.RequestName), tuneroot.MaxRequest, true)
	if errors.Is(err, permissions.ErrNoFile) {
		return nil
	}
	if err != nil {
		return err
	}
	var req tuneroot.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return answer(tuneroot.Result{Error: "invalid request"})
	}
	allowed, err := tuneroot.Allowed(getenv("ROWSAFE_TUNING_ALLOW_FILE", tuneroot.DefaultAllowFile))
	if err != nil {
		return answer(tuneroot.Result{ID: req.ID, Error: "Tuning isn't allowed on this server: " + err.Error()})
	}
	where, ok := allowed[req.Engine]
	if !ok {
		return answer(tuneroot.Result{ID: req.ID, Error: fmt.Sprintf("changing %s's settings isn't allowed on this server (root allows it with: sudo rowsafe-allow tuning)", req.Engine)})
	}
	a := &tuneroot.Applier{StateDir: getenv("STATE_DIRECTORY", tuneroot.DefaultStateDir), Now: time.Now, AgentUID: -1}
	if u, err := user.Lookup(getenv("ROWSAFE_AGENT_USER", "postgres")); err == nil {
		if id, err := strconv.Atoi(u.Uid); err == nil {
			a.AgentUID = id
		}
	}
	res := a.Apply(req, where)
	fmt.Fprintf(os.Stderr, "rowsafe-tuning: %s %s ok=%v %s\n", req.ID, req.Engine, res.OK, res.Error)
	return answer(res)
}
