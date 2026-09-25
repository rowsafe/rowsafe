package protocol

import "time"

// ---- Rewind: restore a copy, compare, bring back rows, rewind in place ----
//
// Everything happens on the customer's server: the agent restores copies next
// to production, compares them and copies rows over locally. Only names,
// counts and sizes reach the control plane.

// Rewind task types.
const (
	// TaskRewindCopy restores the database as it was at a point in time (or a
	// Mark) into an isolated copy next to production (RewindCopyParams ->
	// RewindCopyResult). The copy listens on a private Unix socket only,
	// never archives WAL, and is removed at Expires even if the control plane
	// is unreachable. At most one copy per database.
	TaskRewindCopy = "rewind_copy"
	// TaskRewindDrop stops and deletes a copy (RewindDropParams ->
	// RewindDropResult). Dropping a copy that is still being restored
	// cancels the restore.
	TaskRewindDrop = "rewind_drop"
	// TaskRewindCompare counts, per table and by primary key, the rows that
	// differ between a copy and production (RewindCompareParams ->
	// RewindCompareResult). Read-only on production except for temporary
	// tables.
	TaskRewindCompare = "rewind_compare"
	// TaskRewindRows brings rows that are missing in production (and, with
	// IncludeChanged, rows that changed) back from a copy (RewindRowsParams ->
	// RewindRowsResult). One transaction per database; the control plane
	// saves a Mark first.
	TaskRewindRows = "rewind_rows"
	// TaskRewindInPlace rewinds the whole cluster to a point in time: stop
	// PostgreSQL through the root helper, keep the data directory aside,
	// restore into a fresh one and start again (RewindInPlaceParams ->
	// RewindInPlaceResult). Any failure after the stop puts the original data
	// back and starts it.
	TaskRewindInPlace = "rewind_in_place"
	// TaskRewindUndo swaps the data directory kept aside by a rewind back in
	// (RewindUndoParams -> RewindUndoResult). The rewound data is kept aside
	// in turn.
	TaskRewindUndo = "rewind_undo"
	// TaskRewindCleanup deletes the data directory a rewind (or its undo)
	// kept aside (RewindCleanupParams -> RewindCleanupResult).
	TaskRewindCleanup = "rewind_cleanup"
)

// RewindTarget is the point to go back to: Time or Mark (exactly one).
type RewindTarget struct {
	// Time is any second in the recovery window (UTC). Recovery stops after
	// the last transaction that committed at or before it.
	Time *time.Time `json:"time,omitempty"`
	// Mark is a restore point name.
	Mark string `json:"mark,omitempty"`
	// BackupSet is pgbackrest restore --set: the newest backup that finished
	// at or before the target. The control plane fills it; it is required
	// for a Mark (pgBackRest can't pick the backup for --type=name) and
	// optional for a Time.
	BackupSet string `json:"backup_set,omitempty"`
	// XID (Find the moment) stops recovery just before this transaction
	// commits: everything up to it, not including it (pgbackrest
	// --type=xid --target=XID --target-exclusive). Time is then the
	// transaction's commit time, used to pick BackupSet and to show the
	// point; Time and XID come together, without Mark.
	XID uint32 `json:"xid,omitempty"`
	// Timeline is pgbackrest --target-timeline: "" (PostgreSQL's default,
	// latest), "current" (the backup's timeline) or a timeline number. Only
	// needed to reach a point before an earlier in-place rewind happened.
	Timeline string `json:"timeline,omitempty"`
}

// RewindCopyParams are the params of a rewind_copy task.
type RewindCopyParams struct {
	CopyID string       `json:"copy_id"` // [A-Za-z0-9_-]{1,64}
	Target RewindTarget `json:"target"`
	// Expires is when the agent removes the copy by itself (default 24h
	// from now, at most 7 days; the agent clamps it).
	Expires time.Time `json:"expires"`
}

// RewindCopyResult is the agent's report for a rewind_copy task.
type RewindCopyResult struct {
	CopyID string `json:"copy_id"`
	// RecoveredTo is the commit time of the last transaction replayed (nil
	// when none was replayed after the backup).
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
	Databases   []DBInfo   `json:"databases"`
	// SocketDir and Port locate the copy's private Unix socket (0700, only
	// the agent's OS user can connect). It never listens on TCP.
	SocketDir string    `json:"socket_dir"`
	Port      int       `json:"port"`
	Expires   time.Time `json:"expires"` // as the agent applied it
	Summary   string    `json:"summary"`
}

// RewindDropParams are the params of a rewind_drop task.
type RewindDropParams struct {
	CopyID string `json:"copy_id"`
}

// RewindDropResult is the agent's report for a rewind_drop task.
type RewindDropResult struct {
	CopyID     string `json:"copy_id"`
	Removed    bool   `json:"removed"` // false: there was no such copy (already gone)
	FreedBytes int64  `json:"freed_bytes"`
	Summary    string `json:"summary"`
}

// RewindTable names one table: DB is the PostgreSQL database (datname),
// Table is "schema.name" (the agent looks both up in the catalogs).
type RewindTable struct {
	DB    string `json:"db"`
	Table string `json:"table"`
}

// RewindCompareParams are the params of a rewind_compare task. No tables:
// every table with a primary key in every database of the copy (capped).
type RewindCompareParams struct {
	CopyID string        `json:"copy_id"`
	Tables []RewindTable `json:"tables,omitempty"`
}

// RewindTableDiff is one table's comparison, by primary key.
type RewindTableDiff struct {
	RewindTable
	// MissingInProduction: rows in the copy whose key is gone from
	// production (deleted since).
	MissingInProduction int64 `json:"missing_in_production"`
	// Changed: rows with the same key whose values differ.
	Changed int64 `json:"changed"`
	// OnlyInProduction: rows added to production since.
	OnlyInProduction int64 `json:"only_in_production"`
	// Related are tables linked by foreign keys (parents and children), so
	// they can be brought back together.
	Related []RewindTable `json:"related,omitempty"`
	// Skipped is set, in plain words, when the table wasn't compared (no
	// primary key, too big, dropped since...); the counts are then zero.
	Skipped string `json:"skipped,omitempty"`
	// Note is a plain remark about a compared table, e.g. columns added or
	// removed since.
	Note string `json:"note,omitempty"`
	// SizeBytes is the table's size in the copy.
	SizeBytes int64 `json:"size_bytes,omitempty"`
}

// RewindCompareResult is the agent's report for a rewind_compare task.
type RewindCompareResult struct {
	CopyID  string            `json:"copy_id"`
	Tables  []RewindTableDiff `json:"tables"`
	Summary string            `json:"summary"`
}

// RewindRowsParams are the params of a rewind_rows task.
type RewindRowsParams struct {
	CopyID string        `json:"copy_id"`
	Tables []RewindTable `json:"tables"`
	// IncludeChanged also sets rows that exist in both but differ back to
	// the copy's values.
	IncludeChanged bool `json:"include_changed,omitempty"`
	// MaxRows caps the rows written in one run (the plan's limit); 0 means
	// the agent's own limit (10 million). Over it, nothing is changed.
	MaxRows int64 `json:"max_rows,omitempty"`
}

// RewindTableRows is what a rewind_rows task did to one table.
type RewindTableRows struct {
	RewindTable
	Inserted int64 `json:"inserted"`
	Updated  int64 `json:"updated"`
	// Conflicts are rows not brought back because another row now holds one
	// of their unique values (e.g. the same email).
	Conflicts int64 `json:"conflicts,omitempty"`
	// SequencesAdvanced lists sequences moved forward past the restored keys.
	SequencesAdvanced []string `json:"sequences_advanced,omitempty"`
}

// RewindRowsResult is the agent's report for a rewind_rows task.
type RewindRowsResult struct {
	Tables []RewindTableRows `json:"tables"`
	// Summary: "Brought back 1,204 rows in applications and 3,310 in
	// application_notes."
	Summary string `json:"summary"`
}

// RewindInPlaceParams are the params of a rewind_in_place task.
type RewindInPlaceParams struct {
	RewindID string       `json:"rewind_id"` // [A-Za-z0-9_-]{1,64}
	Target   RewindTarget `json:"target"`
	// KeepDays is how long the old data directory is kept for Undo before
	// the agent deletes it (default 7, 1 to 30).
	KeepDays int `json:"keep_days"`
}

// RewindInPlaceResult is the agent's report for a rewind_in_place task.
type RewindInPlaceResult struct {
	RewindID    string     `json:"rewind_id"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	// OldDataDir is where the data as it was before the rewind is kept.
	OldDataDir string     `json:"old_data_dir"`
	KeptUntil  *time.Time `json:"kept_until,omitempty"`
	// RolledBack: the rewind failed after PostgreSQL was stopped and the
	// original data was put back and started again (the task fails).
	RolledBack bool     `json:"rolled_back,omitempty"`
	DurationMs int64    `json:"duration_ms"`
	Warnings   []string `json:"warnings,omitempty"`
	Summary    string   `json:"summary"`
}

// RewindUndoParams are the params of a rewind_undo task.
type RewindUndoParams struct {
	RewindID string `json:"rewind_id"`
}

// RewindUndoResult is the agent's report for a rewind_undo task.
type RewindUndoResult struct {
	RewindID string `json:"rewind_id"`
	// RewoundDataDir is where the rewound data (with anything written to it
	// since the rewind) is now kept aside.
	RewoundDataDir string     `json:"rewound_data_dir"`
	KeptUntil      *time.Time `json:"kept_until,omitempty"`
	RolledBack     bool       `json:"rolled_back,omitempty"`
	DurationMs     int64      `json:"duration_ms"`
	Summary        string     `json:"summary"`
}

// RewindCleanupParams are the params of a rewind_cleanup task.
type RewindCleanupParams struct {
	RewindID string `json:"rewind_id"`
}

// RewindCleanupResult is the agent's report for a rewind_cleanup task.
type RewindCleanupResult struct {
	RewindID   string `json:"rewind_id"`
	Removed    bool   `json:"removed"` // false: nothing was kept (already gone)
	FreedBytes int64  `json:"freed_bytes"`
	Summary    string `json:"summary"`
}

// Rewind state kinds (RewindState.Kind).
const (
	RewindKindCopy     = "copy"      // a restored copy (ID is the copy ID)
	RewindKindKeptData = "kept_data" // a data directory kept aside (ID is the rewind ID)
)

// Rewind state statuses (RewindState.Status).
const (
	RewindCopyRestoring = "restoring"     // rewind_copy is running
	RewindCopyReady     = "ready"         // up and usable for compare and rows
	RewindKeptBefore    = "before_rewind" // the data from before an in-place rewind: Undo is possible
	RewindKeptAfterUndo = "after_undo"    // the rewound data, kept aside by an Undo
	RewindInProgress    = "in_progress"   // rewind_in_place or rewind_undo is running
)

// RewindState is a live copy or a kept data directory on the host, reported
// in every heartbeat (HeartbeatRequest.Rewinds). What the agent no longer
// reports is gone (expired, dropped or cleaned up).
type RewindState struct {
	ID          string     `json:"id"`
	DatabaseID  string     `json:"database_id"`
	Kind        string     `json:"kind"`   // RewindKind*
	Status      string     `json:"status"` // RewindCopy*, RewindKept*, RewindInProgress
	SizeBytes   int64      `json:"size_bytes"`
	Expires     *time.Time `json:"expires,omitempty"` // when the agent deletes it by itself
	CreatedAt   time.Time  `json:"created_at"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	Path        string     `json:"path,omitempty"` // the copy's or kept data directory
}

// RewindExpiry changes when the agent deletes a copy or kept data
// (HeartbeatResponse.RewindExpires), e.g. after Extend in the dashboard.
// The agent clamps it (copies: at most 7 days from now; kept data: 30).
type RewindExpiry struct {
	ID      string    `json:"id"`
	Expires time.Time `json:"expires"`
}

// ---- Rewind user API ----
//
//	GET    /v1/databases/{ref}/rewind                              RewindInfo
//	POST   /v1/databases/{ref}/rewind/copies                       CreateRewindCopyRequest -> RewindTasksResponse
//	DELETE /v1/databases/{ref}/rewind/copies/{id}                  -> RewindTasksResponse
//	POST   /v1/databases/{ref}/rewind/copies/{id}/extend           ExtendRewindCopyRequest -> RewindCopy
//	POST   /v1/databases/{ref}/rewind/copies/{id}/compare          RewindCompareRequest -> RewindTasksResponse
//	POST   /v1/databases/{ref}/rewind/copies/{id}/restore-rows     RewindRowsRequest -> RewindTasksResponse (Mark, then rows)
//	POST   /v1/databases/{ref}/rewind/in-place                     RewindInPlaceRequest -> RewindTasksResponse (Mark, then rewind)
//	POST   /v1/databases/{ref}/rewind/{rewind_id}/undo             RewindConfirmRequest -> RewindTasksResponse
//	POST   /v1/databases/{ref}/rewind/{rewind_id}/cleanup          -> RewindTasksResponse

// RewindInfo answers GET /v1/databases/{ref}/rewind.
type RewindInfo struct {
	DatabaseID string `json:"database_id"`
	Database   string `json:"database"`
	// Earliest and Latest bound the recovery window: any second between them
	// can be restored.
	Earliest *time.Time     `json:"earliest,omitempty"`
	Latest   *time.Time     `json:"latest,omitempty"`
	Marks    []RestorePoint `json:"marks"`
	// Copy is the database's copy, if one exists or is being restored.
	Copy *RewindCopy `json:"copy,omitempty"`
	// Kept lists data directories kept aside by rewinds in place.
	Kept []RewindKept `json:"kept,omitempty"`
	// CanRewindInPlace says whether a rewind in place can run on this host;
	// InPlaceReason says why not, in plain words.
	CanRewindInPlace bool       `json:"can_rewind_in_place"`
	InPlaceReason    string     `json:"in_place_reason,omitempty"`
	Tasks            []TaskView `json:"tasks,omitempty"` // recent rewind tasks, newest first
}

// RewindCopy is a copy as the API shows it.
type RewindCopy struct {
	ID          string       `json:"id"`
	Status      string       `json:"status"` // restoring | ready | failed | removed
	Target      RewindTarget `json:"target"`
	RecoveredTo *time.Time   `json:"recovered_to,omitempty"`
	SizeBytes   int64        `json:"size_bytes"`
	Databases   []DBInfo     `json:"databases,omitempty"`
	Expires     time.Time    `json:"expires"`
	CreatedAt   time.Time    `json:"created_at"`
	TaskID      string       `json:"task_id,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// RewindKept is a kept data directory as the API shows it.
type RewindKept struct {
	RewindID    string       `json:"rewind_id"`
	Status      string       `json:"status"` // RewindKeptBefore (Undo available) | RewindKeptAfterUndo
	Target      RewindTarget `json:"target"`
	RecoveredTo *time.Time   `json:"recovered_to,omitempty"`
	SizeBytes   int64        `json:"size_bytes"`
	Expires     *time.Time   `json:"expires,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
}

// CreateRewindCopyRequest restores a copy: Time or Mark. With XID (Find
// the moment), the copy stops just before that transaction and Time is its
// commit time.
type CreateRewindCopyRequest struct {
	Time  *time.Time `json:"time,omitempty"`
	Mark  string     `json:"mark,omitempty"`
	XID   uint32     `json:"xid,omitempty"`
	Hours int        `json:"hours,omitempty"` // how long to keep it (default 24, at most 168)
}

// ExtendRewindCopyRequest keeps a copy Hours longer (from now).
type ExtendRewindCopyRequest struct {
	Hours int `json:"hours"`
}

type RewindCompareRequest struct {
	Tables []RewindTable `json:"tables,omitempty"`
}

type RewindRowsRequest struct {
	Tables         []RewindTable `json:"tables"`
	IncludeChanged bool          `json:"include_changed,omitempty"`
	Confirm        string        `json:"confirm"` // the database's name
}

type RewindInPlaceRequest struct {
	Time    *time.Time `json:"time,omitempty"`
	Mark    string     `json:"mark,omitempty"`
	XID     uint32     `json:"xid,omitempty"` // as in CreateRewindCopyRequest
	Confirm string     `json:"confirm"` // the database's name
}

type RewindConfirmRequest struct {
	Confirm string `json:"confirm"` // the database's name
}

// RewindTasksResponse lists the tasks a rewind request queued, in order
// (e.g. the Mark, then the rewind).
type RewindTasksResponse struct {
	Tasks []TaskView  `json:"tasks"`
	Copy  *RewindCopy `json:"copy,omitempty"`
}
