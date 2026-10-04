package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/sqliteroot"
	"github.com/rowsafe/rowsafe/protocol"
)

// Closing SQLite files to other users (the security check's fix,
// protocol.SecSQLiteModes) for files the agent doesn't own goes through
// root's helper (internal/sqliteroot): the agent writes the request,
// rowsafe-sqlite-modes.path starts root's copy of the agent, which checks
// every path against root's own list of SQLite files and answers.

// sqliteModesWait is how long the agent waits for root's answer (a variable
// for tests).
var sqliteModesWait = 60 * time.Second

// The helper's files (the environment can move them, for tests).
func sqliteModesAllowFile() string {
	return envOr("ROWSAFE_SQLITE_MODES_ALLOW_FILE", sqliteroot.DefaultAllowFile)
}

func sqliteModesRequestDir(cfg Config) string {
	return envOr("ROWSAFE_SQLITE_MODES_DIR", filepath.Join(cfg.StateDir, "sqlite-modes"))
}

func sqliteModesResultDir() string {
	return envOr("ROWSAFE_SQLITE_MODES_RESULT_DIR", sqliteroot.DefaultAnswerDir)
}

// SQLiteModesAllowed says whether root's helper may close SQLite files to
// other users, or why not.
func SQLiteModesAllowed(cfg Config) (bool, string) {
	if cfg.Sidecar() {
		return false, "In Docker, the Rowsafe agent can change only the files its own user owns; there is no root helper in the container."
	}
	ok, err := sqliteroot.Allowed(sqliteModesAllowFile())
	if err == nil && ok {
		if _, err := os.Stat(sqliteModesRequestDir(cfg)); err == nil {
			return true, ""
		}
		return false, "Root's helper for SQLite files isn't set up on this server: root sets it up with " + AllowHint(protocol.PermSQLiteModes) + "."
	}
	return false, "Root didn't allow Rowsafe to close the SQLite files to other users on this server. Root allows it with " +
		AllowHint(protocol.PermSQLiteModes) + "."
}

// RequestSQLiteModes hands paths to root's helper and waits for its
// answer. The helper refuses any path that isn't a listed SQLite file, one
// of its side files, a copy next to it or its folder.
func RequestSQLiteModes(ctx context.Context, env EngineEnv, paths []string, log TaskLogger) (sqliteroot.Result, error) {
	var id [6]byte
	_, _ = rand.Read(id[:])
	req := sqliteroot.Request{ID: hex.EncodeToString(id[:]), Paths: paths}
	if err := sqliteroot.Check(req); err != nil {
		return sqliteroot.Result{}, err
	}
	dir := sqliteModesRequestDir(env.Config)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return sqliteroot.Result{}, err
	}
	data, _ := json.Marshal(req)
	log.Printf("asking root's helper to close %d path(s) to other users", len(paths))
	if err := writeFileAtomic(filepath.Join(dir, sqliteroot.RequestName), data, 0o600); err != nil {
		return sqliteroot.Result{}, err
	}
	resPath := filepath.Join(sqliteModesResultDir(), sqliteroot.ResultName)
	deadline := time.Now().Add(sqliteModesWait)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(resPath); err == nil {
			var res sqliteroot.Result
			if json.Unmarshal(b, &res) == nil && res.ID == req.ID {
				if !res.OK {
					return res, errors.New(res.Error)
				}
				return res, nil
			}
		}
		select {
		case <-ctx.Done():
			return sqliteroot.Result{}, ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
	_ = os.Remove(filepath.Join(dir, sqliteroot.RequestName))
	return sqliteroot.Result{}, errors.New("root's helper for SQLite files didn't answer within a minute: it may not be running on this server (rowsafe-sqlite-modes.path)")
}
