package protocol

import (
	"slices"
	"time"
)

// ---- Files: the folders that go with a database ----
//
// Uploads, CVs, media: a database is rarely the whole story. Rowsafe backs up
// the folders a person chose (native folders, or Docker volumes mounted into
// the agent container) with restic, into the same bucket as the database
// (<prefix>/<stanza>/files), encrypted on the server with a password derived
// from the backup passphrase. Only metadata reaches the control plane: paths,
// sizes, counts and times; file names only while the database allows it
// (FilesConfig.ListNames); never file contents.

// Files task types. They run in their own lane on the agent and the control
// plane, beside backups and Rewind.
const (
	// TaskFilesBackup snapshots folders now (FilesBackupParams ->
	// FilesBackupResult). The agent also snapshots on its own, every
	// FilesConfig.IntervalMinutes and right after every Mark.
	TaskFilesBackup = "files_backup"
	// TaskFilesRestore puts files back as they were at a point in time
	// (FilesRestoreParams -> FilesRestoreResult): missing files only, listed
	// paths, the paths stored in a table column, or the whole folder (the
	// current folder is kept aside for Undo).
	TaskFilesRestore = "files_restore"
	// TaskFilesUndo puts a folder replaced by a whole-folder restore back as
	// it was just before (FilesUndoParams -> FilesUndoResult).
	TaskFilesUndo = "files_undo"
	// TaskFilesCleanup deletes a folder kept aside by a whole-folder restore
	// (FilesCleanupParams -> FilesCleanupResult).
	TaskFilesCleanup = "files_cleanup"
	// TaskFilesBrowse lists or searches one folder's snapshot, names and
	// sizes only (FilesBrowseParams -> FilesBrowseResult). Refused when the
	// database keeps file names on the server (ListNames false).
	TaskFilesBrowse = "files_browse"
	// TaskFilesDiscover suggests folders to protect (no params ->
	// FilesDiscoverResult).
	TaskFilesDiscover = "files_discover"
	// TaskFilesAccess asks the host's root helper for read access to a
	// folder the agent can't read (FilesAccessParams -> FilesAccessResult).
	// Only on hosts where root allowed it at install (--allow-files).
	TaskFilesAccess = "files_access"
	// TaskFilesCheck is Proof for files (FilesCheckParams ->
	// FilesCheckResult): restic check reading part of the data, and a few
	// files restored and compared with the live ones. The agent also runs
	// it by itself once a week.
	TaskFilesCheck = "files_check"
)

// FilesTaskTypes are all files task types (the agent's files lane claims
// exactly these).
var FilesTaskTypes = []string{TaskFilesBackup, TaskFilesRestore, TaskFilesUndo, TaskFilesCleanup,
	TaskFilesBrowse, TaskFilesDiscover, TaskFilesAccess, TaskFilesCheck}

// IsFilesTask reports whether typ is a files task type.
func IsFilesTask(typ string) bool { return slices.Contains(FilesTaskTypes, typ) }

// FilesTaskTimeout is how long the agent lets a files task run.
func FilesTaskTimeout(typ string) time.Duration {
	switch typ {
	case TaskFilesBrowse, TaskFilesDiscover, TaskFilesAccess:
		return 15 * time.Minute
	case TaskFilesCleanup:
		return 30 * time.Minute
	}
	return 12 * time.Hour // a first snapshot or a whole-folder restore of a large folder
}

// Defaults and limits of the files settings.
const (
	FilesDefaultIntervalMinutes = 15
	FilesMinIntervalMinutes     = 5
	FilesMaxIntervalMinutes     = 24 * 60
	FilesDefaultKeepDays        = 7 // a whole-folder restore keeps the current folder aside this long
	FilesMaxKeepDays            = 30
	// FilesMinRetentionDays is the least time snapshots are kept, whatever
	// the database's recovery window.
	FilesMinRetentionDays = 7
)

// Folder statuses (FilesFolderState.Status).
const (
	FilesPending    = "pending"    // no snapshot yet (the first one is on its way)
	FilesOK         = "ok"         // the latest snapshot worked
	FilesUnreadable = "unreadable" // the agent's user can't read the folder
	FilesMissing    = "missing"    // the folder doesn't exist (not mounted?)
	FilesFailing    = "failing"    // snapshots fail (see LastError)
	FilesNoEngine   = "no_engine"  // restic isn't installed on the host
)

// Restore modes (FilesRestoreParams.Mode).
const (
	// FilesRestoreMissing puts back the files that are gone now; it never
	// overwrites a file unless Overwrite is set.
	FilesRestoreMissing = "missing"
	// FilesRestorePaths puts back the listed paths (files or folders).
	FilesRestorePaths = "paths"
	// FilesRestoreReferenced puts back the files whose paths a table column
	// stores (e.g. applications.cv_path), read from production or from a
	// Rewind copy.
	FilesRestoreReferenced = "referenced"
	// FilesRestoreFolder makes the whole folder exactly as it was (files
	// added since are removed); the current folder is kept aside for Undo.
	FilesRestoreFolder = "folder"
)

// ---- Agent <-> control plane ----
//
//	POST /v1/agent/files   FilesReport -> FilesSync
//
// The agent posts its files report about once a minute and gets the files
// settings of its databases back. It keeps working (snapshots on schedule,
// Marks, pruning) from the last settings it saved while the control plane is
// unreachable.

// FilesReport is the agent's files report.
type FilesReport struct {
	// Engine is the restic version on the host ("" when restic isn't
	// installed or doesn't run).
	Engine string `json:"engine,omitempty"`
	Mode   string `json:"mode,omitempty"` // native | docker-sidecar
	// HelperActions are the files actions the host's root helper can do:
	// "files-read" (grant read access) and "files-put" (put restored files
	// back as the folder's owner). Empty: root didn't allow it.
	HelperActions []string `json:"helper_actions,omitempty"`
	// AllowedRoots are the folders root allowed Rowsafe to read and restore
	// into, with everything under them (/etc/rowsafe/files-allowed).
	AllowedRoots []string             `json:"allowed_roots,omitempty"`
	Databases    []FilesDatabaseState `json:"databases,omitempty"`
}

// FilesDatabaseState is one database's files state on the host.
type FilesDatabaseState struct {
	DatabaseID string             `json:"database_id"`
	Folders    []FilesFolderState `json:"folders"`
	// RepoSizeBytes is what the files take in the bucket (after
	// deduplication and compression), measured after pruning.
	RepoSizeBytes  int64             `json:"repo_size_bytes,omitempty"`
	RepoSizeAt     *time.Time        `json:"repo_size_at,omitempty"`
	LastPruneAt    *time.Time        `json:"last_prune_at,omitempty"`
	LastPruneError string            `json:"last_prune_error,omitempty"`
	LastCheck      *FilesCheckResult `json:"last_check,omitempty"`
	// Kept are folders kept aside by whole-folder restores (Undo).
	Kept []FilesKept `json:"kept,omitempty"`
}

// FilesFolderState is one protected folder's state.
type FilesFolderState struct {
	ID     string `json:"id"`
	Path   string `json:"path"`
	Status string `json:"status"` // Files* statuses
	// Problem says, in plain words, what is wrong (unreadable, missing,
	// failing).
	Problem       string         `json:"problem,omitempty"`
	LastSnapshot  *FilesSnapshot `json:"last_snapshot,omitempty"`
	LastAttemptAt *time.Time     `json:"last_attempt_at,omitempty"`
	LastError     string         `json:"last_error,omitempty"`
	FailingSince  *time.Time     `json:"failing_since,omitempty"`
	// Snapshots is how many snapshots of the folder the bucket holds;
	// OldestSnapshotAt the oldest one's time (what restores can reach).
	Snapshots        int        `json:"snapshots"`
	OldestSnapshotAt *time.Time `json:"oldest_snapshot_at,omitempty"`
	// Recent are the newest snapshots (at most 50), so the control plane
	// can say which one is nearest to a point in time.
	Recent []FilesSnapshot `json:"recent,omitempty"`
}

// FilesSnapshot is one snapshot of one folder.
type FilesSnapshot struct {
	ID       string    `json:"id"` // restic's short snapshot ID
	FolderID string    `json:"folder_id"`
	Time     time.Time `json:"time"`
	Mark     string    `json:"mark,omitempty"` // taken for this Mark
	// Files and SizeBytes are what the folder held; AddedBytes is new data
	// this snapshot stored in the bucket.
	Files      int64 `json:"files,omitempty"`
	SizeBytes  int64 `json:"size_bytes,omitempty"`
	AddedBytes int64 `json:"added_bytes,omitempty"`
	DurationMs int64 `json:"duration_ms,omitempty"`
}

// FilesKept is a folder kept aside by a whole-folder restore.
type FilesKept struct {
	RestoreID  string     `json:"restore_id"`
	DatabaseID string     `json:"database_id,omitempty"`
	FolderID   string     `json:"folder_id"`
	Path       string     `json:"path"` // the protected folder
	Files      int64      `json:"files"`
	SizeBytes  int64      `json:"size_bytes"`
	CreatedAt  time.Time  `json:"created_at"`
	Expires    *time.Time `json:"expires,omitempty"`
}

// FilesSync answers a files report: the files settings of the host's
// databases.
type FilesSync struct {
	Databases []FilesConfig `json:"databases"`
	// IntervalSeconds is how often the control plane wants reports.
	IntervalSeconds int `json:"interval_seconds,omitempty"`
	// KeptExpires changes when kept folders are deleted (Keep longer).
	KeptExpires []FilesKeptExpiry `json:"kept_expires,omitempty"`
}

// FilesKeptExpiry moves a kept folder's deletion (clamped by the agent to
// FilesMaxKeepDays from now).
type FilesKeptExpiry struct {
	RestoreID string    `json:"restore_id"`
	Expires   time.Time `json:"expires"`
}

// FilesConfig is one database's files settings.
type FilesConfig struct {
	DatabaseID string        `json:"database_id"`
	Name       string        `json:"name"`
	Stanza     string        `json:"stanza"`
	Folders    []FilesFolder `json:"folders"`
	// IntervalMinutes is how often each folder is snapshotted.
	IntervalMinutes int `json:"interval_minutes"`
	// RetentionDays is how far back snapshots go: the database's recovery
	// window (at least FilesMinRetentionDays).
	RetentionDays int `json:"retention_days"`
	// ListNames allows file names to reach the control plane (browse,
	// search, examples in results). Off: only counts and sizes do.
	ListNames bool `json:"list_names"`
}

// FilesFolder is a protected folder.
type FilesFolder struct {
	ID   string `json:"id"`
	Path string `json:"path"` // absolute, as the agent sees it
	// Excludes are restic exclude patterns (e.g. "cache", "*.tmp").
	Excludes []string `json:"excludes,omitempty"`
}

// ---- Task params and results ----

// FilesBackupParams are the params of a files_backup task.
type FilesBackupParams struct {
	FolderIDs []string `json:"folder_ids,omitempty"` // empty: every folder of the database
	Mark      string   `json:"mark,omitempty"`       // tag the snapshots with this Mark
}

// FilesBackupResult is the agent's report for a files_backup task.
type FilesBackupResult struct {
	Snapshots []FilesSnapshot `json:"snapshots"`
	Failures  []string        `json:"failures,omitempty"`
	Summary   string          `json:"summary"`
}

// FilesTarget is the point to restore to: the newest snapshot at or before
// Time, the snapshot taken for Mark (else the newest before MarkTime), or
// SnapshotID.
type FilesTarget struct {
	Time       *time.Time `json:"time,omitempty"`
	Mark       string     `json:"mark,omitempty"`
	MarkTime   *time.Time `json:"mark_time,omitempty"`
	SnapshotID string     `json:"snapshot_id,omitempty"`
}

// FilesReference names the table column that stores file paths.
type FilesReference struct {
	DB     string `json:"db"`     // the PostgreSQL database (datname)
	Table  string `json:"table"`  // "schema.name"
	Column string `json:"column"` // a text column
	// CopyID reads the paths from this Rewind copy instead of production
	// (the rows as they were).
	CopyID string `json:"copy_id,omitempty"`
}

// FilesRestoreParams are the params of a files_restore task.
type FilesRestoreParams struct {
	RestoreID string      `json:"restore_id"` // [A-Za-z0-9_-]{1,64}
	FolderIDs []string    `json:"folder_ids,omitempty"`
	Target    FilesTarget `json:"target"`
	Mode      string      `json:"mode"` // FilesRestore*; default missing
	// Overwrite also puts back files that exist now but differ from the
	// snapshot (modes missing, paths, referenced).
	Overwrite bool            `json:"overwrite,omitempty"`
	Paths     []string        `json:"paths,omitempty"` // mode paths: relative to the folder
	Reference *FilesReference `json:"reference,omitempty"`
	// Preview only counts what would be restored; nothing changes.
	Preview bool `json:"preview,omitempty"`
	// KeepDays is how long a whole-folder restore keeps the current folder
	// aside (default FilesDefaultKeepDays).
	KeepDays int `json:"keep_days,omitempty"`
}

// FilesRestoreResult is the agent's report for a files_restore task.
type FilesRestoreResult struct {
	RestoreID string               `json:"restore_id"`
	Preview   bool                 `json:"preview,omitempty"`
	Folders   []FilesFolderRestore `json:"folders"`
	// Summary: "Brought back 1,204 files (310 MB) as of 14:00."
	Summary string `json:"summary"`
}

// FilesFolderRestore is what a restore did (or would do) in one folder.
type FilesFolderRestore struct {
	FolderID string        `json:"folder_id"`
	Path     string        `json:"path"`
	Snapshot FilesSnapshot `json:"snapshot"`
	// Restored files were missing and are back; Replaced existed but
	// differed and were overwritten; Removed (whole folder) were added after
	// the snapshot and are gone (kept aside).
	Restored      int64 `json:"restored"`
	RestoredBytes int64 `json:"restored_bytes"`
	Replaced      int64 `json:"replaced,omitempty"`
	Removed       int64 `json:"removed,omitempty"`
	// Unchanged are already there as in the snapshot; Differ exist but
	// differ and were left alone (no Overwrite); NotFound were asked for
	// (listed or referenced) but aren't in the snapshot.
	Unchanged int64 `json:"unchanged,omitempty"`
	Differ    int64 `json:"differ,omitempty"`
	NotFound  int64 `json:"not_found,omitempty"`
	// Referenced is how many distinct paths the column held (mode
	// referenced).
	Referenced int64 `json:"referenced,omitempty"`
	// KeptUntil: a whole-folder restore kept the folder as it was just
	// before; Undo puts it back until then.
	KeptUntil *time.Time `json:"kept_until,omitempty"`
	// HeldDir is set when Rowsafe could not write into the folder: the
	// files were restored there instead, and HeldReason says why.
	HeldDir    string `json:"held_dir,omitempty"`
	HeldReason string `json:"held_reason,omitempty"`
	// Examples are up to 10 restored paths, relative to the folder (only
	// when the database allows file names to leave the server).
	Examples []string `json:"examples,omitempty"`
}

// FilesUndoParams are the params of a files_undo task.
type FilesUndoParams struct {
	RestoreID string `json:"restore_id"`
}

// FilesUndoResult is the agent's report for a files_undo task.
type FilesUndoResult struct {
	RestoreID string `json:"restore_id"`
	FolderID  string `json:"folder_id"`
	Path      string `json:"path"`
	Files     int64  `json:"files"`
	Summary   string `json:"summary"`
}

// FilesCleanupParams are the params of a files_cleanup task.
type FilesCleanupParams struct {
	RestoreID string `json:"restore_id"`
}

// FilesCleanupResult is the agent's report for a files_cleanup task.
type FilesCleanupResult struct {
	RestoreID  string `json:"restore_id"`
	Removed    bool   `json:"removed"` // false: nothing was kept (already gone)
	FreedBytes int64  `json:"freed_bytes"`
	Summary    string `json:"summary"`
}

// FilesBrowseParams are the params of a files_browse task.
type FilesBrowseParams struct {
	FolderID string      `json:"folder_id"`
	Target   FilesTarget `json:"target"` // empty: the latest snapshot
	// Dir lists one directory (relative to the folder; "" is the folder
	// itself); Search instead finds paths containing it anywhere.
	Dir    string `json:"dir,omitempty"`
	Search string `json:"search,omitempty"`
	Limit  int    `json:"limit,omitempty"` // default 200, at most 1000
}

// FilesBrowseResult is the agent's report for a files_browse task.
type FilesBrowseResult struct {
	FolderID  string        `json:"folder_id"`
	Snapshot  FilesSnapshot `json:"snapshot"`
	Dir       string        `json:"dir,omitempty"`
	Search    string        `json:"search,omitempty"`
	Entries   []FilesEntry  `json:"entries"`
	Total     int           `json:"total"` // matches before Limit
	Truncated bool          `json:"truncated,omitempty"`
}

// FilesEntry is one file or directory in a snapshot.
type FilesEntry struct {
	Path  string    `json:"path"` // relative to the folder
	Type  string    `json:"type"` // file | dir | symlink
	Size  int64     `json:"size,omitempty"`
	MTime time.Time `json:"mtime"`
	// Missing: not in the folder now (deleted since); Changed: there, but
	// different.
	Missing bool `json:"missing,omitempty"`
	Changed bool `json:"changed,omitempty"`
}

// FilesDiscoverResult is the agent's report for a files_discover task.
type FilesDiscoverResult struct {
	Candidates []FilesCandidate `json:"candidates"`
}

// FilesCandidate is a folder the agent suggests protecting.
type FilesCandidate struct {
	Path string `json:"path"`
	// Why, in plain words: "Docker volume app_uploads", "Laravel storage".
	Why       string `json:"why"`
	SizeBytes int64  `json:"size_bytes"`
	Files     int64  `json:"files"`
	// Readable: the agent's user can read it all; otherwise protecting it
	// needs read access (FilesAccess).
	Readable bool `json:"readable"`
	// Partial: counting stopped early (a very large folder); the numbers
	// are at least this.
	Partial bool `json:"partial,omitempty"`
}

// FilesAccessParams are the params of a files_access task.
type FilesAccessParams struct {
	FolderID string `json:"folder_id,omitempty"`
	Path     string `json:"path"`
}

// FilesAccessResult is the agent's report for a files_access task.
type FilesAccessResult struct {
	Path    string `json:"path"`
	Granted bool   `json:"granted"`
	Summary string `json:"summary"`
}

// FilesCheckParams are the params of a files_check task.
type FilesCheckParams struct {
	// ReadData is the part of the stored data to read back, restic's
	// --read-data-subset (e.g. "5%" or "3/52"); "" reads a different
	// fifty-second each week, so all of it once a year.
	ReadData string `json:"read_data,omitempty"`
}

// FilesCheckResult is Proof for files.
type FilesCheckResult struct {
	At       time.Time `json:"at"`
	Passed   bool      `json:"passed"`
	ReadData string    `json:"read_data"`
	// Sampled files were restored and compared with the live files that
	// haven't changed since; Matched is how many were identical.
	Sampled    int      `json:"sampled"`
	Matched    int      `json:"matched"`
	Problems   []string `json:"problems,omitempty"`
	DurationMs int64    `json:"duration_ms"`
	Summary    string   `json:"summary"`
}

// ---- Files user API ----
//
//	GET    /v1/databases/{ref}/files                               FilesInfo
//	PATCH  /v1/databases/{ref}/files                               UpdateFilesSettingsRequest -> FilesInfo
//	POST   /v1/databases/{ref}/files/folders                       AddFilesFolderRequest -> FilesFolderView (201)
//	PATCH  /v1/databases/{ref}/files/folders/{id}                  UpdateFilesFolderRequest -> FilesFolderView
//	DELETE /v1/databases/{ref}/files/folders/{id}                  -> 204 (snapshots stay until they age out)
//	POST   /v1/databases/{ref}/files/folders/{id}/access           -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/backup                        FilesBackupParams -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/restore                       FilesRestoreRequest -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/restores/{id}/undo            FilesConfirmRequest -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/restores/{id}/cleanup         -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/browse                        FilesBrowseParams -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/discover                      -> FilesTasksResponse
//	POST   /v1/databases/{ref}/files/check                         -> FilesTasksResponse
//	GET    /v1/databases/{ref}/files/nearest?time=RFC3339          FilesNearest
//
// Everything that changes files is for people only (never AI assistants on
// /mcp); the MCP server only reads FilesInfo.

// FilesInfo answers GET /v1/databases/{ref}/files.
type FilesInfo struct {
	DatabaseID string            `json:"database_id"`
	Database   string            `json:"database"`
	Settings   FilesSettings     `json:"settings"`
	Folders    []FilesFolderView `json:"folders"`
	Host       FilesHost         `json:"host"`
	// Candidates are the folders the latest discovery suggested (not yet
	// protected).
	Candidates    []FilesCandidate  `json:"candidates,omitempty"`
	CandidatesAt  *time.Time        `json:"candidates_at,omitempty"`
	RepoSizeBytes int64             `json:"repo_size_bytes,omitempty"`
	LastCheck     *FilesCheckResult `json:"last_check,omitempty"`
	LastPruneAt   *time.Time        `json:"last_prune_at,omitempty"`
	Kept          []FilesKept       `json:"kept,omitempty"`
	ReportedAt    *time.Time        `json:"reported_at,omitempty"`
	Tasks         []TaskView        `json:"tasks,omitempty"` // recent files tasks, newest first
}

// FilesSettings are a database's files settings as the API shows them.
type FilesSettings struct {
	IntervalMinutes int  `json:"interval_minutes"`
	ListNames       bool `json:"list_names"`
	RetentionDays   int  `json:"retention_days"`
}

// FilesHost is what the database's host can do for files.
type FilesHost struct {
	Hostname string `json:"hostname"`
	Mode     string `json:"mode,omitempty"`
	Engine   string `json:"engine,omitempty"` // restic version; "" not installed
	Online   bool   `json:"online"`
	// CanGrantAccess: root allowed Rowsafe to give itself read access to
	// folders under AllowedRoots; CanPutBack: to put restored files back as
	// the folder's owner. Reason says why not, in plain words.
	CanGrantAccess bool     `json:"can_grant_access"`
	CanPutBack     bool     `json:"can_put_back"`
	AllowedRoots   []string `json:"allowed_roots,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

// FilesFolderView is a protected folder as the API shows it.
type FilesFolderView struct {
	FilesFolder
	// State is what the agent last reported (Status pending until then).
	State     FilesFolderState `json:"state"`
	CreatedAt time.Time        `json:"created_at"`
}

// UpdateFilesSettingsRequest changes a database's files settings; omitted
// fields are unchanged.
type UpdateFilesSettingsRequest struct {
	IntervalMinutes *int  `json:"interval_minutes,omitempty"`
	ListNames       *bool `json:"list_names,omitempty"`
}

// AddFilesFolderRequest protects a folder.
type AddFilesFolderRequest struct {
	Path     string   `json:"path"`
	Excludes []string `json:"excludes,omitempty"`
}

// UpdateFilesFolderRequest changes a folder's excludes.
type UpdateFilesFolderRequest struct {
	Excludes []string `json:"excludes"`
}

// FilesRestoreRequest restores files. Time or Mark (or SnapshotID); Confirm
// (the database's name) is needed unless Preview. AfterTaskID makes the
// restore wait for another task (e.g. Rewind's rows) to succeed first.
type FilesRestoreRequest struct {
	Time        *time.Time      `json:"time,omitempty"`
	Mark        string          `json:"mark,omitempty"`
	SnapshotID  string          `json:"snapshot_id,omitempty"`
	FolderIDs   []string        `json:"folder_ids,omitempty"`
	Mode        string          `json:"mode,omitempty"`
	Overwrite   bool            `json:"overwrite,omitempty"`
	Paths       []string        `json:"paths,omitempty"`
	Reference   *FilesReference `json:"reference,omitempty"`
	Preview     bool            `json:"preview,omitempty"`
	Confirm     string          `json:"confirm,omitempty"`
	AfterTaskID string          `json:"after_task_id,omitempty"`
}

// FilesConfirmRequest confirms a files action with the database's name.
type FilesConfirmRequest struct {
	Confirm string `json:"confirm"`
}

// FilesTasksResponse lists the tasks a files request queued.
type FilesTasksResponse struct {
	Tasks []TaskView `json:"tasks"`
}

// FilesNearest answers GET /v1/databases/{ref}/files/nearest: per folder,
// the snapshot a restore to Time would use, and how far before Time it is.
type FilesNearest struct {
	Time    time.Time            `json:"time"`
	Folders []FilesNearestFolder `json:"folders"`
}

type FilesNearestFolder struct {
	FolderID string         `json:"folder_id"`
	Path     string         `json:"path"`
	Snapshot *FilesSnapshot `json:"snapshot,omitempty"` // nil: no snapshot that old
	// GapSeconds is how long before Time the snapshot was taken.
	GapSeconds int64 `json:"gap_seconds,omitempty"`
}
