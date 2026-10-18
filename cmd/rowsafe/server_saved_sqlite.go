package main

import (
	"fmt"

	"github.com/rowsafe/rowsafe/protocol"
)

// SQLite on a server on its own: a SQLite database is a file the app opens
// itself, and the agent needs access to it (and its -wal and -shm files),
// which root gives it with an ACL and a systemd drop-in. The installer
// does that and registers the file, so rowsafe add says to run it.
func sqliteAddHelp(path string) error {
	return fmt.Errorf("%s is a file: SQLite databases are added by the installer, which gives the agent access to the file (and its -wal and -shm files) and turns on its backups:\n"+
		"  curl -fsSL https://rowsafe.sh | sudo sh -s -- --no-account --sqlite %s\n"+
		"Then sudo rowsafe ls lists it", path, shellQuote(path))
}

// sqliteFile: s is a file's absolute path (where a connection string goes).
func sqliteFile(s string) bool { return protocol.SQLitePath(s) }
