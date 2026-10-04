package protocol

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ---- SQLite clones (FeatureFork for engine "sqlite")
//
// A SQLite clone is a NEW database file: the source as it was at a moment
// (any second in its window, or a Mark; "now" is a Mark the control plane
// saves first), restored by the target server's agent into a folder root
// allowed for clones at install (`--sqlite-clone-dir DIR`, the folders in
// /etc/rowsafe/sqlite-clone-dirs; in Docker the mounted folders named in
// ROWSAFE_SQLITE_CLONE_DIRS). It is registered as a new SQLite database
// (its own stanza and backups) whose DatabaseSpec.SocketDir is the new path.
//
//   - Same server: the agent reads the source's backups with its own
//     settings; nothing moves. Another server: fork_prepare seals the
//     source's bucket settings to the target agent's key (the fingerprint a
//     person confirmed), as for every engine.
//   - Agents report each allowed folder as a StandbyTarget with Engine
//     "sqlite", Port 0, Socket the folder, Usable (Reason says why not:
//     missing, not writable, on a network filesystem).
//   - The file must not exist, nor its -wal, -shm or -journal file: a clone
//     never overwrites anything. It is written next to its final name under
//     a hidden temporary name, then linked into place (an atomic create).
//   - The new file keeps the source's journal mode (WAL when the source
//     used it), mode 0660 with the folder's default ACL (0640 without one),
//     and the agent adds it to the files it may open.
//   - No masking for SQLite clones yet (the control plane refuses Mask).

// sqliteCloneNameRE is a clone's file name: letters, digits, dot, dash and
// underscore, not starting with a dot or a dash.
var sqliteCloneNameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,199}$`)

// SQLiteCloneName reports whether name can be a SQLite clone's file name
// in a folder (no folders, not a side file, not hidden).
func SQLiteCloneName(name string) bool {
	if !sqliteCloneNameRE.MatchString(name) || strings.HasSuffix(name, ".part") {
		return false
	}
	for _, s := range []string{"-wal", "-shm", "-journal"} {
		if strings.HasSuffix(name, s) {
			return false
		}
	}
	return true
}

// SQLiteCloneDir reports whether dir can be a folder for SQLite clones:
// absolute, clean, not the root folder.
func SQLiteCloneDir(dir string) bool {
	return dir != "/" && len(dir) <= 800 && SQLitePath(dir) && filepath.Clean(dir) == dir
}

// SQLiteClonePath reports whether path is a valid clone file directly in
// the folder dir.
func SQLiteClonePath(dir, path string) bool {
	return SQLiteCloneDir(dir) && SQLitePath(path) && filepath.Dir(path) == dir && SQLiteCloneName(filepath.Base(path))
}

// SQLiteNoCloneDir says how root allows clones on a server whose agent
// reports no folder for them.
const SQLiteNoCloneDir = "no folder there is allowed for SQLite clones: the server's owner can allow one by running the Rowsafe installer again with --sqlite-clone-dir /path/to/folder (in Docker, mount a folder and name it in ROWSAFE_SQLITE_CLONE_DIRS)"
