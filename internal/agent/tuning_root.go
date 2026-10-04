package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/tuneroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// Tuning for MongoDB, ClickHouse, Redis and Valkey goes through root's helper
// (internal/tuneroot): the agent writes the request, rowsafe-tuning.path
// starts root's copy of the agent, which writes the settings into
// Rowsafe's own files where root allowed it, and answers.

// Tuning helper paths (variables for tests; the environment can move them).
var (
	tuningAllowFile = envOr("ROWSAFE_TUNING_ALLOW_FILE", tuneroot.DefaultAllowFile)
	tuningResultDir = envOr("ROWSAFE_TUNING_RESULT_DIR", tuneroot.DefaultAnswerDir)
	tuningWait      = 90 * time.Second
)

// TuningAllowed says where root allows Rowsafe's settings file for engine
// (a directory for ClickHouse, the configuration file for MongoDB), or why
// changes aren't possible ("" path).
func TuningAllowed(cfg Config, engine string) (where, why string) {
	name := protocol.EngineDisplayName(engine)
	if cfg.Sidecar() {
		return "", fmt.Sprintf("%s runs in Docker, where Rowsafe can't change its configuration files: set these in the container's command or a mounted configuration file", name)
	}
	allowed, err := tuneroot.Allowed(tuningAllowFile)
	if err == nil {
		if w, ok := allowed[protocol.NormalizeEngine(engine)]; ok {
			return w, ""
		}
	}
	return "", fmt.Sprintf("Changing %s's settings from Rowsafe isn't allowed on this server. Root allows it with %s (Rowsafe then writes only its own settings file).",
		name, AllowHint(protocol.PermTuning))
}

// RequestTuning hands settings (name -> value, "" to remove one from
// Rowsafe's file) to root's helper and waits for its answer.
func RequestTuning(ctx context.Context, env EngineEnv, engine string, settings map[string]string, log TaskLogger) (tuneroot.Result, error) {
	var id [6]byte
	_, _ = rand.Read(id[:])
	req := tuneroot.Request{ID: hex.EncodeToString(id[:]), Engine: protocol.NormalizeEngine(engine), Settings: settings}
	if err := tuneroot.Check(req); err != nil {
		return tuneroot.Result{}, err
	}
	dir := envOr("ROWSAFE_TUNING_DIR", filepath.Join(env.Config.StateDir, "tuning"))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tuneroot.Result{}, err
	}
	data, _ := json.Marshal(req)
	log.Printf("asking root's helper to write %d %s setting(s) into the file root allowed", len(settings), protocol.EngineDisplayName(engine))
	if err := writeFileAtomic(filepath.Join(dir, tuneroot.RequestName), data, 0o600); err != nil {
		return tuneroot.Result{}, err
	}
	resPath := filepath.Join(tuningResultDir, tuneroot.ResultName)
	deadline := time.Now().Add(tuningWait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(resPath); err == nil {
			var res tuneroot.Result
			if json.Unmarshal(b, &res) == nil && res.ID == req.ID {
				if !res.OK {
					return res, errors.New(res.Error)
				}
				return res, nil
			}
		}
		select {
		case <-ctx.Done():
			return tuneroot.Result{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	_ = os.Remove(filepath.Join(dir, tuneroot.RequestName))
	return tuneroot.Result{}, errors.New("root's Tuning helper did not answer (check `systemctl status rowsafe-tuning.path`)")
}
