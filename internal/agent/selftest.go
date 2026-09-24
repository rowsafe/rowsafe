package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// CheckControlPlane verifies the control plane is reachable and healthy.
func CheckControlPlane(ctx context.Context, cfg Config) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.ControlURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
	}
	return nil
}

// The running agent saves the databases it watches so a staged binary's
// self-test can check it reaches the same Postgres clusters.
func watchedPath(cfg Config) string { return filepath.Join(cfg.StateDir, "watched.json") }

func saveWatched(cfg Config, dbs []protocol.DatabaseSpec) {
	if data, err := json.Marshal(dbs); err == nil {
		_ = writeFileAtomic(watchedPath(cfg), data, 0o600)
	}
}

func WatchedTargets(cfg Config) []pginspect.Target {
	data, err := os.ReadFile(watchedPath(cfg))
	if err != nil {
		return nil
	}
	var dbs []protocol.DatabaseSpec
	if json.Unmarshal(data, &dbs) != nil {
		return nil
	}
	var out []pginspect.Target
	for _, d := range dbs {
		out = append(out, pginspect.Target{SocketDir: d.SocketDir, Port: d.Port, User: cfg.PGUser})
	}
	return out
}
