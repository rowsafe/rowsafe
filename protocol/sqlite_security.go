package protocol

import "time"

// ---- SQLite: the security check (EngineSecurity.SQLite)
//
// A SQLite database has no network port and no users: whoever can open the
// file can read and change everything in it. So its security check is
// about who on the server can reach the file (read-only, every 15 minutes
// and on demand):
//
//   - the database file and its -wal, -shm and -journal files readable or
//     writable by every user of the server ("others");
//   - the database inside a folder a web server serves (common web roots,
//     public/static/dist/build/www folders, and the root, alias,
//     file_server and DocumentRoot lines of the nginx, Caddy and Apache
//     configuration files the agent can read);
//   - its folder writable by everyone (anyone could delete or replace the
//     file);
//   - copies of it left next to it (.bak, .old, a date...) that every user
//     can read.
//
// The one fix (SecSQLiteModes) only removes every other user's access:
// owners, groups and ACL entries (the app's and Rowsafe's access) stay.

// SecSQLiteModes removes other users' access (o-rwx) from the files in
// SecurityFixParams.Paths (the database file, its side files and the
// copies of it the check found next to it) and their write access (o-w)
// from the database's folder. Nothing else changes: not the owner, the
// group, the ACL entries or the folder's other bits. The agent checks each
// path again (it must still be open to others and be one of those files),
// changes the files it owns itself, and hands the rest to root's helper
// where root allowed it (PermSQLiteModes).
const SecSQLiteModes = "sqlite_tighten_modes"

// SQLiteSecurity is what the security check reads for a SQLite database.
type SQLiteSecurity struct {
	// Path is the database file (DatabaseSpec.SocketDir).
	Path string `json:"path"`
	// Files are the database file and those of its -wal, -shm and -journal
	// files that exist (the real files when Path is a symbolic link).
	Files []SQLiteFileAccess `json:"files"`
	// Folder is the database's folder.
	Folder SQLiteFileAccess `json:"folder"`
	// OpenCopies are files next to the database named like a copy of it
	// (app.db.bak, app-backup.db, app.db.2024-05-01...) that are SQLite
	// databases readable or writable by everyone (at most 20).
	OpenCopies []SQLiteFileAccess `json:"open_copies,omitempty"`
	// WebRoot is set when the database is inside a folder a web server may
	// serve to anyone.
	WebRoot *SQLiteWebRoot `json:"web_root,omitempty"`
	// WebConfigs is how many web server configuration files the agent
	// read; WebConfigsUnreadable are the ones it found but couldn't read
	// (at most 10). Unreadable files never fail the check.
	WebConfigs           int      `json:"web_configs"`
	WebConfigsUnreadable []string `json:"web_configs_unreadable,omitempty"`
	// Helper: root allowed its helper to remove other users' access from
	// these files (PermSQLiteModes); HelperReason says why not.
	Helper       bool   `json:"helper,omitempty"`
	HelperReason string `json:"helper_reason,omitempty"`
}

// SQLiteFileAccess is one file's (or the folder's) permissions.
type SQLiteFileAccess struct {
	Path string `json:"path"`
	// Mode is the permission bits (with setuid, setgid and sticky:
	// 0o7777).
	Mode  uint32 `json:"mode"`
	Owner string `json:"owner"` // user name (the uid when it has none)
	Group string `json:"group"`
	// Mine: the agent can change the permissions itself (it owns the file,
	// or runs as root); otherwise only root's helper can.
	Mine bool `json:"mine,omitempty"`
	// Size and ModifiedAt: copies only.
	Size       int64      `json:"size,omitempty"`
	ModifiedAt *time.Time `json:"modified_at,omitempty"`
}

// OthersRead: every user of the server may read it.
func (f SQLiteFileAccess) OthersRead() bool { return f.Mode&0o004 != 0 }

// OthersWrite: every user of the server may change it.
func (f SQLiteFileAccess) OthersWrite() bool { return f.Mode&0o002 != 0 }

// OpenToOthers: a file every user may read or change.
func (f SQLiteFileAccess) OpenToOthers() bool { return f.Mode&0o006 != 0 }

// FolderOpen: a folder where every user may add, rename and delete files
// (writable by others without the sticky bit, which limits deleting to
// each file's owner).
func (f SQLiteFileAccess) FolderOpen() bool { return f.Mode&0o002 != 0 && f.Mode&0o1000 == 0 }

// SQLiteWebRoot is the web server folder the database is in.
type SQLiteWebRoot struct {
	// Root is the folder served (the file is inside it).
	Root string `json:"root"`
	// Server is "nginx", "caddy" or "apache" when a configuration file
	// serves Root; "" when only the folder's name or place says it is
	// usually served (Guess).
	Server string `json:"server,omitempty"`
	// Config is where the configuration serves it ("FILE:LINE").
	Config string `json:"config,omitempty"`
	// Guess: no configuration file the agent read serves it, but it is a
	// common web root (/var/www, /usr/share/nginx/html...) or a public,
	// static, dist, build or www folder.
	Guess bool `json:"guess,omitempty"`
}
