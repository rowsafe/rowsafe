package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rowsafe/rowsafe/internal/permissions"
	"github.com/rowsafe/rowsafe/internal/sqliteroot"
)

// sqliteModesApply runs `rowsafe-permissions sqlite-modes-apply`
// (rowsafe-sqlite-modes.service, root): closes the SQLite files the agent
// named to other users, only where root allowed it and only for the files
// root listed, their side files, copies next to them and their folders
// (internal/sqliteroot).
func sqliteModesApply() error {
	if err := trustedSelf(); err != nil {
		fmt.Fprintln(os.Stderr, "rowsafe-sqlite-modes: refused:", err)
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
	data, err := read(filepath.Join(getenv("ROWSAFE_SQLITE_MODES_REQUEST_DIR", sqliteroot.DefaultRequestDir), sqliteroot.RequestName), sqliteroot.MaxRequest, true)
	if errors.Is(err, permissions.ErrNoFile) {
		return nil
	}
	if err != nil {
		return err
	}
	res := sqliteroot.Apply(data, getenv("ROWSAFE_SQLITE_MODES_ALLOW_FILE", sqliteroot.DefaultAllowFile),
		getenv("ROWSAFE_SQLITE_PATHS_FILE", sqliteroot.DefaultListFile))
	fmt.Fprintf(os.Stderr, "rowsafe-sqlite-modes: %s ok=%v changed=%v refused=%v %s\n", res.ID, res.OK, res.Changed, res.Refused, res.Error)
	return sqliteroot.WriteAnswer(getenv("RUNTIME_DIRECTORY", sqliteroot.DefaultAnswerDir), res)
}
