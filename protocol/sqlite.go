package protocol

import (
	"strings"
	"time"
)

// ---- SQLite (engine "sqlite")
//
// A SQLite database is one file that an application opens itself (Rails,
// Django, Laravel, PocketBase, Go and Node apps...): there is no server
// process. SQLite databases use the same tasks and results as PostgreSQL
// ones, with these meanings:
//
//   - A Rowsafe "database" is one database file. DatabaseSpec.SocketDir is
//     the file's absolute path as the agent opens it (in a Docker sidecar:
//     the path inside the agent's container, where the app's volume is
//     mounted); DatabaseSpec.Port is 0. Several databases per host are
//     normal; the control plane tells them apart by path (SQLitePath).
//   - The agent opens the file with SQLite's own locking (pure Go SQLite,
//     POSIX/OFD locks and the -shm file), so it is safe next to the app's
//     connections. It needs read and write access to the file, its -wal
//     and -shm files and their folder (root grants it at install, with a
//     POSIX ACL or a group, and says what changed).
//   - Backups (BackupFull; diff and incr are taken as full) are a
//     consistent copy through SQLite's online backup API, compressed and
//     encrypted on the server (objstore.Seal), under <repo path>/<stanza>/.
//     BackupResult.WALStart/WALStop are the copy's position in the change
//     stream ("<generation>/<wal index>/<frame>", empty without one).
//   - Continuous archiving (restores to any second) needs journal_mode=WAL:
//     the agent copies new WAL frames (whole committed transactions) into
//     encrypted, time-stamped segments every few seconds, keeps a read
//     transaction so the app's checkpoints can't overwrite frames it hasn't
//     copied, and checkpoints itself (PASSIVE) once they are copied. When
//     the chain breaks (the agent was stopped while the app reset the WAL,
//     the file was replaced...), it starts a new generation with a fresh
//     full copy. ArchiverStats report it (ArchiveMode "on" while it copies,
//     "off" in rollback-journal mode: restores then reach the newest backup
//     only, and Pulse offers to turn WAL on: MaintSQLiteWAL).
//   - RestorePointResult (a Mark): LSN is the stream position
//     ("<generation>/<wal index>/<frame>") right after the newest
//     committed transaction; WALFile the segment holding it. A Mark needs
//     WAL (continuous archiving).
//   - Rewind targets: Time restores the newest backup before it plus every
//     transaction committed by then (to the second); Mark exactly up to the
//     Mark. BackupSet is ignored: the agent picks the backup itself.
//     RecoveredTo is the newest transaction replayed (the backup's time
//     when none was).
//   - Rewind copies are restored files in the agent's rewind directory
//     (RewindCopyResult.SocketDir is the copy's path, Port 0, Databases one
//     entry "main"). RewindTable.DB is "main", Table the table name. Rows
//     are compared by primary key (rowid for tables without one, with a
//     note: VACUUM can renumber those); bringing rows back inserts the
//     missing ones in one transaction and never overwrites a row
//     (IncludeChanged is refused).
//   - Rewind in place writes the restored copy into the live file with the
//     online backup API: the app's open connections see the new content
//     (RewindInPlaceStopsServer is false). The file as it was is kept for
//     Undo (7 days by default) in the agent's rewind directory.
//   - Find the moment (FindMomentResult): the agent replays the range's
//     changes on a private scratch copy and compares each table's rows
//     (by rowid, or a WITHOUT ROWID table's primary key, as a hash of
//     their bytes: values are never decoded) before and after every
//     transaction. Moment.DB is "main", Table the table's name, Kind delete,
//     update or drop (a DELETE without WHERE is a delete of every row;
//     inserts aren't listed), LSN the transaction's stream position, XID
//     a sequence number with the high bit set (no transaction IDs in
//     SQLite), Time when the agent copied the change (within a second of
//     its commit, to the millisecond). "Just before" a change is a Time
//     target one millisecond earlier.
//   - Monitoring: database_size_bytes, disk_* and the sqlite_* metrics
//     (collect/catalog_sqlite.go), and DatabaseMonitoring.SQLite below.
//   - No server: restart, standby, pooling, updates, upgrades, Databases &
//     users and logs don't exist for SQLite (SQLiteNoServer says why).

// Maintenance actions (MaintenanceParams.Action) for SQLite, proposed by
// health (Apply fix) and recomputed by the control plane when applied. The
// agent checks each again before it runs.
const (
	// MaintSQLiteCheckpoint copies the changes waiting in the -wal file
	// into the database file, after the agent has copied them to the
	// bucket, and shrinks the -wal file (TRUNCATE) when nobody is reading
	// an older snapshot. Followed by a fresh full copy when the WAL was
	// truncated, so the change stream stays unbroken.
	MaintSQLiteCheckpoint = "sqlite_checkpoint"
	// MaintSQLiteVacuum rebuilds the file to give its free pages back to
	// the disk (VACUUM). Writes wait while it runs (SQLiteStatus
	// .VacuumEstimateSeconds); it needs about the file's size free on its
	// disk.
	MaintSQLiteVacuum = "sqlite_vacuum"
	// MaintSQLiteIncrementalVacuum gives free pages back without a rebuild
	// (PRAGMA incremental_vacuum), for files with auto_vacuum=incremental.
	MaintSQLiteIncrementalVacuum = "sqlite_incremental_vacuum"
	// MaintSQLiteOptimize refreshes the query planner's statistics
	// (PRAGMA optimize, ANALYZE of the tables it names).
	MaintSQLiteOptimize = "sqlite_optimize"
	// MaintSQLiteWAL switches the database to WAL (PRAGMA
	// journal_mode=WAL, persistent): "Turn on continuous backups". The app
	// keeps working; -wal and -shm files appear next to the database. The
	// agent refuses on network filesystems.
	MaintSQLiteWAL = "sqlite_wal"
)

// SQLiteNoServer is why a feature that needs a database server (restart,
// standby, pooling, updates, upgrades, Databases & users, logs) doesn't
// exist for SQLite, in one plain sentence per feature.
var SQLiteNoServer = map[string]string{
	FeatureRestart:  "SQLite runs inside your app, so there's no database server to restart.",
	FeatureStandby:  "SQLite runs inside your app, so there's no database server to replicate to a standby.",
	FeaturePooling:  "SQLite runs inside your app, so there are no network connections to pool.",
	FeatureUpdates:  "SQLite is built into your app, so it is updated with your app, not on the server.",
	FeatureUpgrades: "SQLite is built into your app, so it is upgraded with your app, not on the server.",
	FeatureDBAdmin:  "A SQLite database is one file with no users or accounts of its own to manage.",
	FeatureLogs:     "SQLite runs inside your app and keeps no log of its own; your app's logs have its errors.",
}

// SQLiteOff is why the other features SQLite doesn't have are off, in one
// plain sentence each (shown where people look for them).
var SQLiteOff = map[string]string{
	FeatureSettings: "Tuning doesn't apply to SQLite: there is no server to tune, and your app sets SQLite's options when it opens the file.",
	FeatureMoveIn:   "Moving in from Turso or Cloudflare D1 isn't available yet.",
}

// sqliteFeatures are what SQLite supports (EngineCapabilities). A SQLite
// database is a file that an application opens itself: there is no server
// to restart, replicate, pool, update or log, so those flags stay off
// (SQLiteNoServer).
var sqliteFeatures = EngineFeatures{
	Backups: true, // online backup API copies (internal/engine/sqlite/snapshot.go)
	// WAL frames copied every few seconds (internal/engine/sqlite/ship.go);
	// rollback-journal databases reach their newest backup only.
	PointInTime: true,
	Proof:       true,                                        // restore, integrity_check, foreign_key_check, row counts (drill.go)
	RewindCopy:  true, RewindRows: true, RewindInPlace: true, // rewind*.go, inplace.go
	Marks:      true,              // a stream position (marks.go)
	Monitoring: true, Fixes: true, // monitor.go, maintenance.go
	SecondCopy: true, // the same stream and backups into the second bucket (ship.go sinks)
	Files:      true, // the app's folders next to the database (agent-wide, restic)
	FindMoment: true, // the WAL pages replayed on a private copy, rows compared (internal/engine/sqlite/moment.go)
	Fork:       true, // clones into a new file in a folder root allowed (internal/engine/sqlite/fork.go)
	// Schema-based: SQLite keeps no query statistics (internal/engine/sqlite/advice.go, indexadvice.go).
	Recommendations: true, IndexAdvice: true,
}

// SQLiteStatus is SQLite's own health detail (DatabaseMonitoring.SQLite),
// read about every minute (StaleStatsTables about every 30 minutes).
type SQLiteStatus struct {
	CollectedAt time.Time `json:"collected_at"`
	// Path is the database file.
	Path      string `json:"path"`
	FileBytes int64  `json:"file_bytes"`
	// WALBytes is the -wal file's size (0 when there is none).
	WALBytes int64 `json:"wal_bytes"`
	// WALGrowing: the -wal file kept growing over the last readings
	// although the agent checkpoints (an app transaction or reader that
	// stays open stops checkpoints).
	WALGrowing bool  `json:"wal_growing,omitempty"`
	PageSize   int   `json:"page_size"`
	PageCount  int64 `json:"page_count"`
	// FreePages are pages the file keeps but doesn't use
	// (freelist_count): VACUUM gives them back to the disk.
	FreePages int64 `json:"free_pages"`
	// JournalMode is wal, delete, truncate, persist, memory or off.
	JournalMode string `json:"journal_mode"`
	// AutoVacuum is none, full or incremental.
	AutoVacuum string `json:"auto_vacuum"`
	// SQLiteVersion is the SQLite version that last wrote the file (its
	// header), e.g. "3.45.1".
	SQLiteVersion string `json:"sqlite_version,omitempty"`
	// NetworkFS names the network filesystem the file is on ("nfs",
	// "cifs"...), "" on a local disk. SQLite's locking isn't reliable
	// there: Rowsafe refuses WAL and changes on it.
	NetworkFS string `json:"network_fs,omitempty"`
	// Shipping: continuous backups (WAL frames copied to the bucket) run.
	Shipping bool `json:"shipping"`
	// ShippingLagSeconds is how old the oldest committed change not yet in
	// the bucket is (0 when caught up).
	ShippingLagSeconds float64    `json:"shipping_lag_seconds"`
	LastShippedAt      *time.Time `json:"last_shipped_at,omitempty"`
	// LastIntegrityCheck is when the agent last checked the file's pages
	// (quick_check on each backup's copy, integrity_check in Proof);
	// IntegrityOK its result and IntegrityProblem the first problem found.
	LastIntegrityCheck *time.Time `json:"last_integrity_check,omitempty"`
	IntegrityOK        *bool      `json:"integrity_ok,omitempty"`
	IntegrityProblem   string     `json:"integrity_problem,omitempty"`
	// BusyErrors counts the times the agent found the database busy or
	// locked since the previous reading (it retries; many mean long
	// transactions in the app).
	BusyErrors int64 `json:"busy_errors"`
	// StaleStatsTables are the tables whose query planner statistics are
	// missing or out of date (PRAGMA optimize would ANALYZE them; at most
	// 20).
	StaleStatsTables []string `json:"stale_stats_tables,omitempty"`
	Tables           int      `json:"tables"`
	Indexes          int      `json:"indexes"`
	// VacuumEstimateSeconds is how long a VACUUM would make writes wait,
	// estimated from the file's size.
	VacuumEstimateSeconds int `json:"vacuum_estimate_seconds,omitempty"`
	// DiskFreeBytes is the free space on the file's filesystem (a VACUUM
	// needs about FileBytes free).
	DiskFreeBytes int64 `json:"disk_free_bytes,omitempty"`
}

// SQLitePath reports whether p can be a SQLite database's path
// (DatabaseSpec.SocketDir): absolute, clean, not one of SQLite's side
// files (-wal, -shm, -journal).
func SQLitePath(p string) bool {
	if p == "" || p[0] != '/' || len(p) > 1024 || strings.ContainsAny(p, "\x00\n\r\t") {
		return false
	}
	for _, s := range []string{"-wal", "-shm", "-journal"} {
		if strings.HasSuffix(p, s) {
			return false
		}
	}
	if strings.HasSuffix(p, "/") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") ||
		strings.Contains(p, "/./") || strings.HasSuffix(p, "/.") || strings.Contains(p, "//") {
		return false
	}
	return true
}
