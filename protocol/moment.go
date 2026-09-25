package protocol

import "time"

// ---- Find the moment: when were rows deleted, changed or tables emptied ----
//
// The agent reads PostgreSQL's change log (the WAL in the customer's own
// repository) on the customer's server and reports only what happened, per
// transaction: when it committed, its transaction ID, which table, what
// kind of change and how many rows. Row contents never leave the server
// (the agent never decodes them).

// TaskFindMoment searches a time range for big deletes, updates, TRUNCATEs
// and DROPs (FindMomentParams -> FindMomentResult). Read-only: it only
// reads the repository and the catalogs, never changes the database.
const TaskFindMoment = "find_moment"

// Kinds of change (Moment.Kind, FindMomentParams.Kinds).
const (
	MomentDelete   = "delete"   // rows deleted
	MomentUpdate   = "update"   // rows changed
	MomentTruncate = "truncate" // a table emptied with TRUNCATE
	MomentDrop     = "drop"     // a table (or database) removed with DROP
)

// MomentKinds are all kinds, in display order.
var MomentKinds = []string{MomentDelete, MomentUpdate, MomentTruncate, MomentDrop}

// Limits of a search (the agent clamps to them).
const (
	// MaxMomentRange is the longest time range one search covers.
	MaxMomentRange = 7 * 24 * time.Hour
	// DefaultMomentRange is searched when no range is given.
	DefaultMomentRange = 24 * time.Hour
	// MaxMoments is the most transactions a result lists.
	MaxMoments = 500
	// DefaultMoments is how many it lists by default.
	DefaultMoments = 100
)

// FindMomentParams are the params of a find_moment task.
type FindMomentParams struct {
	// DB limits the search to one PostgreSQL database (datname); "" means
	// every database of the cluster.
	DB string `json:"db,omitempty"`
	// Tables limits it to these tables: "schema.name" or just "name" (any
	// schema). Empty means every table.
	Tables []string `json:"tables,omitempty"`
	// From and To bound the search (commit times, UTC). Defaults: the last
	// 24 hours. At most MaxMomentRange apart.
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
	// Kinds limits the kinds of change (MomentDelete...); empty means all.
	Kinds []string `json:"kinds,omitempty"`
	// MinRows leaves out transactions that deleted or changed fewer rows
	// (default 1). TRUNCATE and DROP are always listed.
	MinRows int64 `json:"min_rows,omitempty"`
	// Limit is how many transactions to list, biggest first (default
	// DefaultMoments, at most MaxMoments).
	Limit int `json:"limit,omitempty"`
}

// Moment is what one transaction did to one table.
type Moment struct {
	// Time is when the transaction committed (UTC): the change became
	// visible then.
	Time time.Time `json:"time"`
	// XID is the transaction ID. Rewinding "to just before" it restores
	// everything up to, but not including, this transaction
	// (RewindTarget.XID).
	XID  uint32 `json:"xid"`
	Kind string `json:"kind"` // MomentDelete...
	// DB is the PostgreSQL database (datname).
	DB string `json:"db"`
	// Table is "schema.name"; "" when Rowsafe couldn't name it (the table
	// was removed or rebuilt before Rowsafe saw its name). For a dropped
	// database both Table and Note say so.
	Table string `json:"table,omitempty"`
	// Parent is the partitioned table Table is a partition of.
	Parent string `json:"parent,omitempty"`
	// Rows deleted or changed. For TRUNCATE and DROP it is the table's
	// size as PostgreSQL last estimated it (Estimated); 0 when unknown.
	Rows      int64 `json:"rows"`
	Estimated bool  `json:"estimated,omitempty"`
	// TxTables is how many tables the whole transaction touched (this is
	// one of them).
	TxTables int `json:"tx_tables,omitempty"`
	// LSN is where the transaction's commit is in the WAL.
	LSN string `json:"lsn,omitempty"`
	// Summary in plain words: "1,204 rows deleted from applications in one
	// transaction".
	Summary string `json:"summary"`
	// Note is a plain remark, e.g. why the table has no name.
	Note string `json:"note,omitempty"`
}

// MomentBucket counts the changes in one slice of the searched range, for
// the timeline chart (every matching transaction, not only the listed
// ones).
type MomentBucket struct {
	Start     time.Time `json:"start"`
	Deleted   int64     `json:"deleted"`
	Updated   int64     `json:"updated"`
	Truncates int       `json:"truncates"`
	Drops     int       `json:"drops"`
}

// MomentTable totals the changes to one table over the searched range.
type MomentTable struct {
	DB           string `json:"db"`
	Table        string `json:"table"`
	Deleted      int64  `json:"deleted"`
	Updated      int64  `json:"updated"`
	Truncates    int    `json:"truncates,omitempty"`
	Drops        int    `json:"drops,omitempty"`
	Transactions int64  `json:"transactions"`
}

// FindMomentResult is the agent's report for a find_moment task.
type FindMomentResult struct {
	// From and To are the range actually searched (UTC). It can be shorter
	// than asked: WAL before the oldest backup is gone, the newest changes
	// may not have reached the repository yet, or the search hit its size
	// limit (Notes say which).
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Moments are the biggest transactions in the range (at most Limit),
	// in time order.
	Moments []Moment `json:"moments"`
	// Truncated: more transactions matched than are listed.
	Truncated bool `json:"truncated,omitempty"`
	// Buckets is the timeline (BucketSeconds each, from From).
	Buckets       []MomentBucket `json:"buckets"`
	BucketSeconds int            `json:"bucket_seconds"`
	// Tables are per-table totals, most rows first (at most 50).
	Tables []MomentTable `json:"tables,omitempty"`
	// Transactions is how many transactions matched; Deleted, Updated,
	// Truncates and Drops add up every one of them.
	Transactions int64 `json:"transactions"`
	Deleted      int64 `json:"deleted"`
	Updated      int64 `json:"updated"`
	Truncates    int   `json:"truncates"`
	Drops        int   `json:"drops"`
	// Segments and WALBytes are how much of the change log was read.
	Segments   int   `json:"segments"`
	WALBytes   int64 `json:"wal_bytes"`
	DurationMs int64 `json:"duration_ms"`
	// Notes are plain remarks about the search's limits.
	Notes []string `json:"notes,omitempty"`
	// Summary in plain words: "Found 3 big changes between 14:00 and
	// 15:00: the biggest deleted 1,204 rows from applications at 14:05:37."
	Summary string `json:"summary"`
}

// ---- Find the moment user API ----
//
//	POST /v1/databases/{ref}/moments        FindMomentRequest -> TaskView (queues find_moment)
//	GET  /v1/databases/{ref}/moments        MomentsInfo (recent searches, the searchable window)
//
// Results arrive in the task (GET /v1/tasks/{id}: Result is a
// FindMomentResult). Read-only, so AI assistants may use it too (the MCP
// tool find_moment).

// FindMomentRequest starts a search. The same fields as FindMomentParams;
// the control plane checks them and fills the defaults.
type FindMomentRequest = FindMomentParams

// MomentsInfo answers GET /v1/databases/{ref}/moments.
type MomentsInfo struct {
	DatabaseID string `json:"database_id"`
	Database   string `json:"database"`
	// Earliest is the oldest point the change log still covers (the oldest
	// backup's start); nil before the first backup.
	Earliest *time.Time `json:"earliest,omitempty"`
	// Searches are the recent find_moment tasks, newest first (with their
	// results).
	Searches []TaskView `json:"searches"`
	// Tables are table names known from monitoring, for the table picker
	// ("schema.name" with their database), biggest first.
	Tables []MomentTableName `json:"tables,omitempty"`
}

// MomentTableName is a table the picker offers.
type MomentTableName struct {
	DB    string `json:"db"`
	Table string `json:"table"`
	Rows  int64  `json:"rows,omitempty"`
}
