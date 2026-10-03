package protocol

import "time"

// ---- ClickHouse (engine "clickhouse")
//
// ClickHouse databases use the same tasks and results as PostgreSQL ones,
// with these meanings:
//
//   - A Rowsafe "database" is one ClickHouse server (clickhouse-server);
//     the databases inside it are InspectResult.Databases.
//   - DatabaseSpec.Port is the server's HTTP port (8123 by default). The
//     agent connects to 127.0.0.1, or to ROWSAFE_CLICKHOUSE_URL in a Docker
//     sidecar; SocketDir is unused.
//   - Backups are ClickHouse's own BACKUP of every user database, written
//     through a gateway the agent runs for the length of the task: the
//     gateway speaks S3 to ClickHouse, encrypts every object on the server
//     (objstore.Seal, ROWSAFE_REPO_CIPHER_PASS) and stores it in the bucket
//     under <repo path>/<stanza>/. ClickHouse never sees the bucket's keys
//     or the passphrase. BackupFull is a full BACKUP; BackupDiff a BACKUP
//     with base_backup = the newest full one (only the parts that changed
//     since are copied); BackupIncr is treated as BackupDiff.
//   - Continuous archiving (restores to any second): ClickHouse never
//     changes data in place; every INSERT, merge and mutation writes a new
//     part, and system.part_log records when, to the microsecond. The agent
//     copies each new part from the data folder (read only: the clickhouse
//     group, or the data volume mounted read only in Docker) to the bucket
//     as it appears, sealed, with a log of what changed (parts, table and
//     database definitions) under <repo path>/<stanza>/pitr/. A restore to
//     a moment takes the newest backup that finished before it and carries
//     it forward with that log: the parts active at that moment are served
//     to ClickHouse as one backup. ArchiverStats report the copier
//     (ArchiveMode "on" once it runs; ArchivedCount counts parts copied).
//     Tables without parts (Log, Memory...) or on object storage come back
//     as of that backup. Differential backups are cheap (parts never change
//     once written), so they run every hour by default.
//   - BackupResult: WALStart/WALStop are unused; Label is the backup's
//     folder name.
//   - RestorePointResult (a Mark): a differential backup taken on the spot
//     and named after the Mark. LSN is that backup's label; WALFile is
//     unused.
//   - Rewind targets: Mark restores the Mark's backup; Time restores the
//     server as it was at that moment (from BackupSet when the control
//     plane filled it, or the newest backup that finished before it).
//     RecoveredTo is that moment; when the record can't reach it (the
//     agent wasn't copying), the backup alone is restored and RecoveredTo
//     is when it finished.
//   - Rewind copies run as a separate, temporary clickhouse-server on the
//     same host, listening on 127.0.0.1 only, with its own data folder
//     under the agent's rewind directory (RewindCopyResult.Port is its HTTP
//     port, SocketDir is empty).
//   - RewindTable: DB is the ClickHouse database, Table the table name.
//     Rows are compared on all their columns (ClickHouse tables have no
//     unique key): a row is missing when production has fewer copies of it
//     than the copy.
//   - Monitoring: the shared metrics the engine can fill (connections_*,
//     database_size_bytes, longest_query_seconds, replication_lag_seconds,
//     disk_*), the clickhouse_* metrics in collect/catalog_clickhouse.go,
//     Activity (running queries; ActivityQuery.QueryID identifies each) and
//     DatabaseMonitoring.ClickHouse below.

// MaintKillQuery stops a running ClickHouse query (KILL QUERY).
// MaintenanceParams.QueryID is its query_id and BackendStart when it
// started: the agent checks the query is still the same one, running
// since then, before stopping it.
const MaintKillQuery = "kill_query"

// MaintKillMutation cancels a ClickHouse mutation (ALTER ... UPDATE/DELETE)
// that can't finish (KILL MUTATION). MaintenanceParams.DB and Tables[0] are
// its table ("table", no database prefix) and MutationID its mutation_id;
// the agent checks it is still not done before cancelling it. Parts it
// already changed stay changed.
const MaintKillMutation = "kill_mutation"

// clickhouseFeatures are what ClickHouse supports (EngineCapabilities).
var clickhouseFeatures = EngineFeatures{
	Backups: true, Proof: true,
	PointInTime: true, // new parts copied as they appear (internal/engine/clickhouse/pitr_*.go)
	RewindCopy:  true, RewindRows: true, RewindInPlace: true, Marks: true,
	Monitoring: true, Fixes: true, Restart: true,
	Recommendations: true, // query log, table layout (internal/engine/clickhouse/insights.go)
	Logs:            true, // the error log (internal/engine/clickhouse/logs.go)
	DBAdmin:         true, Security: true, Files: true, SecondCopy: true,
	MigrationPreview: true, SafeCopies: true,
	Fork:     true, // clones restored from a backup into an empty server (fork.go in internal/engine/clickhouse)
	MoveIn:   true, // one-time copy from ClickHouse Cloud or any ClickHouse (migrate.go in internal/engine/clickhouse)
	Settings: true, // config.d and users.d through root's tuning helper (opt-in)
}

// ClickHouseStatus is ClickHouse's own health detail
// (DatabaseMonitoring.ClickHouse), read about every 5 minutes.
type ClickHouseStatus struct {
	CollectedAt time.Time `json:"collected_at"`
	// Parts are the partitions with the most active parts (at most 10, the
	// most first), from system.parts. Too many parts in one partition slow
	// queries down, then delay and finally refuse inserts
	// (parts_to_delay_insert, parts_to_throw_insert).
	Parts []ClickHouseParts `json:"parts,omitempty"`
	// PartsToDelayInsert and PartsToThrowInsert are the server's
	// merge_tree_settings (0 when unknown).
	PartsToDelayInsert int `json:"parts_to_delay_insert,omitempty"`
	PartsToThrowInsert int `json:"parts_to_throw_insert,omitempty"`
	// Mutations are the mutations not done yet (system.mutations,
	// is_done = 0), the oldest first, at most 20.
	Mutations []ClickHouseMutation `json:"mutations,omitempty"`
	// Replicas are the replicated tables with a problem (read-only, or
	// more than a minute behind), at most 20.
	Replicas []ClickHouseReplica `json:"replicas,omitempty"`
	// DetachedParts counts parts ClickHouse set aside (system.detached_parts)
	// by reason: "broken", "unexpected", "ignored"... A broken part is data
	// ClickHouse could not read at startup.
	DetachedParts map[string]int `json:"detached_parts,omitempty"`
	// MemoryLimitBytes is the server's memory limit (max_server_memory_usage,
	// or the ratio of RAM it resolves to; 0 when unknown).
	MemoryLimitBytes int64 `json:"memory_limit_bytes,omitempty"`
}

// ClickHouseParts is one partition's active parts.
type ClickHouseParts struct {
	DB        string `json:"db"`
	Table     string `json:"table"`
	Partition string `json:"partition"`
	Parts     int    `json:"parts"`
}

// ClickHouseMutation is one mutation not done yet.
type ClickHouseMutation struct {
	DB         string    `json:"db"`
	Table      string    `json:"table"`
	MutationID string    `json:"mutation_id"`
	Command    string    `json:"command"` // up to 500 characters
	CreatedAt  time.Time `json:"created_at"`
	// PartsToDo is how many parts are still to be changed.
	PartsToDo int `json:"parts_to_do"`
	// FailReason is the latest error (empty when it hasn't failed);
	// FailedAt when it happened.
	FailReason string     `json:"fail_reason,omitempty"`
	FailedAt   *time.Time `json:"failed_at,omitempty"`
}

// ClickHouseReplica is a replicated table with a problem.
type ClickHouseReplica struct {
	DB       string `json:"db"`
	Table    string `json:"table"`
	ReadOnly bool   `json:"read_only"`
	// DelaySeconds is absolute_delay: how far behind the other replicas.
	DelaySeconds int64 `json:"delay_seconds"`
	QueueSize    int   `json:"queue_size"`
	// LastError is the newest replication queue error (empty when none).
	LastError string `json:"last_error,omitempty"`
}

// MarkIsBackup reports whether engine's Marks are backups of their own (a
// differential backup taken on the spot; RestorePointResult.LSN is its
// label), restored as they are rather than replayed to: ClickHouse.
func MarkIsBackup(engine string) bool { return NormalizeEngine(engine) == EngineClickHouse }
