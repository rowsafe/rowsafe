// Package protocol defines the JSON contract between the Rowsafe control
// plane (rowsafed), the agent (rowsafe-agent) and the CLI (rowsafe).
package protocol

import (
	"encoding/json"
	"time"
)

// Task types. The agent only ever executes these fixed operations; it never
// runs arbitrary commands sent by the control plane.
const (
	TaskInspect = "inspect" // read-only: report version, settings, sizes
	TaskAdopt   = "adopt"   // plan (default) or apply WAL archiving to the repo
	TaskCheck   = "check"   // pgbackrest check: proves WAL reaches the repo
	TaskBackup  = "backup"  // pgbackrest backup (full, diff or incr)
	TaskDrill   = "drill"   // restore latest backup to a scratch dir and verify
	// TaskRestorePoint creates a named restore point and waits until the WAL
	// holding it is archived. It may run alongside another task on the same
	// database (it is only a few SQL statements).
	TaskRestorePoint = "restore_point"
	// TaskRestart restarts the database's PostgreSQL. Only a person asks for
	// it (Restart in the dashboard, `rowsafe restart`), and the agent runs it
	// only for clusters root allowed at install time (HeartbeatRequest.
	// RestartPorts), through a root helper; it never restarts on its own.
	TaskRestart = "restart"
	// TaskMaintenance runs one fixed maintenance action (MaintenanceParams)
	// that the control plane proposed as a health fix: VACUUM, ANALYZE,
	// REINDEX/DROP INDEX CONCURRENTLY, cancelling a query, ending a session or
	// dropping an inactive replication slot. The agent validates everything
	// again before running it.
	TaskMaintenance = "maintenance"
)

// Maintenance actions (MaintenanceParams.Action).
const (
	// MaintVacuum: VACUUM (ANALYZE[, FREEZE]) each of Tables in DB.
	MaintVacuum = "vacuum"
	// MaintAnalyze: ANALYZE each of Tables in DB.
	MaintAnalyze = "analyze"
	// MaintReindexIndex: REINDEX INDEX CONCURRENTLY Index in DB (PostgreSQL 12+).
	MaintReindexIndex = "reindex_index"
	// MaintDropIndex: DROP INDEX CONCURRENTLY Index in DB; refused when it
	// backs a constraint, is a primary key/unique/exclusion index, or has
	// been used since the finding.
	MaintDropIndex = "drop_index"
	// MaintCancelQuery: pg_cancel_backend(PID) if BackendStart still matches.
	MaintCancelQuery = "cancel_query"
	// MaintTerminateSession: pg_terminate_backend(PID) if BackendStart still
	// matches and it isn't a Rowsafe, replication or autovacuum backend.
	MaintTerminateSession = "terminate_session"
	// MaintDropReplicationSlot: pg_drop_replication_slot(Slot) if inactive.
	MaintDropReplicationSlot = "drop_replication_slot"
)

// MaintenanceParams are the params of a maintenance task.
type MaintenanceParams struct {
	Action string `json:"action"` // Maint* above
	// DB is the PostgreSQL database (datname) inside the cluster, for
	// object actions (tables and indexes).
	DB string `json:"db,omitempty"`
	// Tables are "schema.table" names; the agent splits and quotes them.
	Tables []string `json:"tables,omitempty"`
	Index  string   `json:"index,omitempty"` // "schema.index"
	Slot   string   `json:"slot,omitempty"`
	PID    int      `json:"pid,omitempty"`
	// BackendStart must still match the session's backend_start (PIDs are
	// reused).
	BackendStart *time.Time `json:"backend_start,omitempty"`
	Freeze       bool       `json:"freeze,omitempty"`
	// Unused marks a drop_index for an unused index: the agent refuses when
	// the index has been scanned since (idx_scan > 0).
	Unused bool `json:"unused,omitempty"`
	// CreateIndex is the index of a create_index (protocol/indexadvisor.go).
	CreateIndex *CreateIndexParams `json:"create_index,omitempty"`
	// ---- advisor (protocol/advisor.go) ----
	// Columns of a create_index on Tables[0] (column names, unquoted).
	Columns []string `json:"columns,omitempty"`
	// Sequence is "schema.sequence" for sync_sequence.
	Sequence string `json:"sequence,omitempty"`
	// Settings are the storage parameters of set_table_storage_params.
	Settings map[string]string `json:"settings,omitempty"`
	// ---- end advisor ----
}

// MaintenanceResult is the agent's report for a maintenance task.
type MaintenanceResult struct {
	Action string `json:"action"`
	// Summary is plain words: "Cleaned up 3 tables; about 1.2 million dead
	// rows removed."
	Summary    string   `json:"summary"`
	Details    []string `json:"details,omitempty"`
	DurationMs int64    `json:"duration_ms"`
}

// Task statuses.
const (
	StatusQueued    = "queued"
	StatusRunning   = "running"
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusLost      = "lost" // lease expired while running (agent died or hung)
	// StatusCancelled: removed from the queue before it ran (its database or
	// host was removed from Rowsafe).
	StatusCancelled = "cancelled"
)

// Database statuses.
const (
	DBPendingAdopt    = "pending_adopt"    // registered, adopt plan not applied yet
	DBAwaitingRestart = "awaiting_restart" // settings applied, Postgres restart needed
	DBVerifying       = "verifying"        // check task queued/running
	DBActive          = "active"           // WAL archiving proven, schedules running
)

// Backup types accepted by pgBackRest.
const (
	BackupFull = "full"
	BackupDiff = "diff"
	BackupIncr = "incr"
)

// DatabaseSpec is everything the agent needs to act on one database server
// (a PostgreSQL cluster, unless Engine says otherwise). It carries no
// secrets: repository credentials live only on the host.
type DatabaseSpec struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Stanza        string `json:"stanza"`
	Port          int    `json:"port"`
	SocketDir     string `json:"socket_dir"`
	RetentionFull int    `json:"retention_full"`
	// SecondCopyRetentionFull is how many full backups the second copy keeps
	// (0: DefaultSecondCopyRetentionFull). See secondcopy.go.
	SecondCopyRetentionFull int `json:"second_copy_retention_full,omitempty"`
	// Engine is the database engine (Engine* in engine.go); "" from older
	// control planes means PostgreSQL (NormalizeEngine).
	Engine string `json:"engine,omitempty"`
}

// Task is a unit of work handed to an agent.
type Task struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Database  *DatabaseSpec   `json:"database,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

type AdoptParams struct {
	Apply bool `json:"apply"`
	// Force replaces an existing, foreign archive_command (e.g. WAL-G).
	Force bool `json:"force,omitempty"`
}

type BackupParams struct {
	Type string `json:"type"`
	Repo int    `json:"repo,omitempty"` // RepoSecond: back up to the second copy (secondcopy.go)
}

// ---- Agent <-> control plane ----

type EnrollRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

type EnrollResponse struct {
	HostID     string `json:"host_id"`
	AgentToken string `json:"agent_token"`
}

type HeartbeatRequest struct {
	Hostname     string          `json:"hostname"`
	AgentVersion string          `json:"agent_version"`
	Archivers    []ArchiverStats `json:"archivers,omitempty"`
	Update       *UpdateReport   `json:"update,omitempty"`
	// Platform is the agent's release artifact key, e.g. "linux/amd64"
	// (release.Platform()). Older agents omit it.
	Platform string `json:"platform,omitempty"`
	// Mode is the agent's mode: "native" or "docker-sidecar". Older agents
	// omit it (native).
	Mode string `json:"mode,omitempty"`
	// RestartPorts are the ports of the local clusters root allowed Rowsafe
	// to restart when someone asks (/etc/rowsafe/restart-allowed, written by
	// the installer). Empty: restarting from Rowsafe is off on this host.
	RestartPorts []int `json:"restart_ports,omitempty"`
	// RestartActions are what the installed root helper can do for the
	// clusters in RestartPorts: "restart", and "stop" and "start" (needed to
	// rewind in place) from the helper installed with agent 0.4.0 on. Empty
	// with RestartPorts set: an older helper that can only restart.
	RestartActions []string `json:"restart_actions,omitempty"`
	// Rewinds are the live copies and kept data directories on this host.
	Rewinds []RewindState `json:"rewinds,omitempty"`
	// ManagedStorage: Rowsafe Storage or the customer's own bucket
	// (storage.go). Not Storage, which is storage use per repository.
	ManagedStorage *StorageStatus `json:"managed_storage,omitempty"`
	// Storage and SecondCopies: backup storage use and the second copy
	// (secondcopy.go).
	Storage      []RepoStorage      `json:"storage,omitempty"`
	SecondCopies []SecondCopyStatus `json:"second_copies,omitempty"`
	// Software is PostgreSQL's versions, pending updates and upgrades on
	// this host (upgrade.go); sent about every hour.
	Software *SoftwareReport `json:"software,omitempty"`
	// DockerControl: docker-sidecar agents only (see protocol/docker.go).
	DockerControl *DockerControlReport `json:"docker_control,omitempty"`
	// Copies are Guard's preview and safe copies (protocol/copies.go).
	Copies *CopiesReport `json:"copies,omitempty"`
	// StandbyHeartbeat: the agent's key, addresses, standbys and fences
	// (protocol/standby.go).
	StandbyHeartbeat
}

// HeartbeatResponse tells the agent which databases to watch.
type HeartbeatResponse struct {
	// Databases are the databases past the initial plan: the agent reports
	// their WAL archiving and runs their tasks.
	Databases []DatabaseSpec `json:"databases"`
	Update    *UpdateOffer   `json:"update,omitempty"`
	// Monitored are the databases built-in monitoring covers: every
	// database of the host, including ones not adopted yet (monitoring is
	// read-only). A superset of Databases.
	Monitored []DatabaseSpec `json:"monitored,omitempty"`
	// RewindExpires changes when copies and kept data are deleted (Extend).
	RewindExpires []RewindExpiry `json:"rewind_expires,omitempty"`
	// Copies extends or deletes Guard copies (protocol/copies.go).
	Copies *CopiesUpdate `json:"copies,omitempty"`
	// StandbyInstructions: fences to hold (protocol/standby.go).
	StandbyInstructions
}

// ArchiverStats mirrors pg_stat_archiver for one adopted database.
type ArchiverStats struct {
	DatabaseID       string     `json:"database_id"`
	ArchivedCount    int64      `json:"archived_count"`
	FailedCount      int64      `json:"failed_count"`
	LastArchivedTime *time.Time `json:"last_archived_time,omitempty"`
	LastFailedTime   *time.Time `json:"last_failed_time,omitempty"`
	Error            string     `json:"error,omitempty"`
	// ArchiveMode is PostgreSQL's current archive_mode ("off", "on",
	// "always") as the agent sees it now; empty when unknown. The control
	// plane uses it to notice the restart of a database waiting for one, and
	// verifies it itself.
	ArchiveMode string `json:"archive_mode,omitempty"`

	// Docker sidecar agents (Mode "docker-sidecar") archive through a spool:
	// PostgreSQL's archive_command copies WAL into it and the agent pushes it
	// to the repository. For them the fields above describe the repository
	// (last successful push; failures include push failures and a stalled
	// spool) and PostgreSQL's own pg_stat_archiver view is in Spooled*.
	Mode            string     `json:"mode,omitempty"`
	SpooledCount    int64      `json:"spooled_count,omitempty"`
	LastSpooledTime *time.Time `json:"last_spooled_time,omitempty"`
	SpoolFiles      int        `json:"spool_files,omitempty"`       // WAL files waiting to be pushed
	SpoolBytes      int64      `json:"spool_bytes,omitempty"`       // their total size
	SpoolOldestTime *time.Time `json:"spool_oldest_time,omitempty"` // when the oldest waiting file was spooled
	SpoolStalled    bool       `json:"spool_stalled,omitempty"`     // the oldest file has waited too long
	LastPushedWAL   string     `json:"last_pushed_wal,omitempty"`
	PushFailedCount int64      `json:"push_failed_count,omitempty"` // since the agent started
	LastPushError   string     `json:"last_push_error,omitempty"`
}

type ClaimResponse struct {
	Task *Task `json:"task"`
}

type CompleteRequest struct {
	Status string          `json:"status"` // succeeded | failed
	Error  string          `json:"error,omitempty"`
	Log    string          `json:"log,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// ---- Task results ----

type InspectResult struct {
	ServerVersion          string   `json:"server_version"`
	VersionNum             int      `json:"version_num"`
	DataDirectory          string   `json:"data_directory"`
	ConfigFile             string   `json:"config_file"`
	Port                   int      `json:"port"`
	IsSuperuser            bool     `json:"is_superuser"`
	InRecovery             bool     `json:"in_recovery"`
	WalLevel               string   `json:"wal_level"`
	ArchiveMode            string   `json:"archive_mode"`
	ArchiveCommand         string   `json:"archive_command"`
	ArchiveLibrary         string   `json:"archive_library,omitempty"`
	ArchiveTimeoutSeconds  int      `json:"archive_timeout_seconds"`
	SharedPreloadLibraries string   `json:"shared_preload_libraries"`
	PendingRestart         []string `json:"pending_restart,omitempty"`
	Databases              []DBInfo `json:"databases"`
	TotalSizeBytes         int64    `json:"total_size_bytes"`
	// MySQL is set for MySQL and MariaDB servers (mysql.go).
	MySQL *MySQLInspect `json:"mysql,omitempty"`
}

// Major returns the Postgres major version (e.g. 18 for 180004).
func (r InspectResult) Major() int { return r.VersionNum / 10000 }

type DBInfo struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	Tables    int    `json:"tables"`
}

// Change is one step of an adopt plan.
type Change struct {
	Kind        string `json:"kind"` // file | command | setting
	Description string `json:"description"`
	Setting     string `json:"setting,omitempty"`
	From        string `json:"from,omitempty"`
	To          string `json:"to,omitempty"`
	Restart     bool   `json:"restart,omitempty"`
}

type AdoptResult struct {
	Inspect         InspectResult `json:"inspect"`
	Plan            []Change      `json:"plan"`
	Applied         bool          `json:"applied"`
	RestartRequired bool          `json:"restart_required"`
	Warnings        []string      `json:"warnings,omitempty"`
}

// RestartResult is the agent's report for a restart task.
type RestartResult struct {
	Restarted  bool   `json:"restarted"`
	Unit       string `json:"unit"`        // the systemd unit restarted, e.g. postgresql@18-main.service
	DurationMs int64  `json:"duration_ms"` // from the request until PostgreSQL answered again
	// ArchiveMode is archive_mode once PostgreSQL is back ("on" once the
	// adopt settings are in effect).
	ArchiveMode string `json:"archive_mode"`
}

type CheckResult struct {
	OK      bool          `json:"ok"`
	Inspect InspectResult `json:"inspect"`
}

type BackupResult struct {
	Label         string    `json:"label"`
	Type          string    `json:"type"`
	StartedAt     time.Time `json:"started_at"`
	StoppedAt     time.Time `json:"stopped_at"`
	SizeBytes     int64     `json:"size_bytes"`
	RepoSizeBytes int64     `json:"repo_size_bytes"`
	WALStart      string    `json:"wal_start,omitempty"`
	WALStop       string    `json:"wal_stop,omitempty"`
	Repo          int       `json:"repo,omitempty"` // RepoSecond for a backup to the second copy
}

type DrillResult struct {
	Passed          bool            `json:"passed"`
	BackupLabel     string          `json:"backup_label"`
	RecoveredTo     *time.Time      `json:"recovered_to,omitempty"`
	DurationSeconds float64         `json:"duration_seconds"`
	RestoredBytes   int64           `json:"restored_bytes"`
	Databases       []DrillDatabase `json:"databases"`
	Failures        []string        `json:"failures,omitempty"`
	Warnings        []string        `json:"warnings,omitempty"`
	Repo            int             `json:"repo,omitempty"` // RepoSecond: restored from the second copy
}

type DrillDatabase struct {
	Name           string `json:"name"`
	Present        bool   `json:"present"`
	SourceTables   int    `json:"source_tables"`
	RestoredTables int    `json:"restored_tables"`
}

// ---- Agent-initiated setup ----
//
// The installer, run by root on the database host, registers the host's
// PostgreSQL and turns on backups with the agent's credentials
// (rowsafe-agent setup ...). Endpoints, scoped to the calling host:
//
//	POST /v1/agent/setup/databases             SetupRegisterRequest -> 201 (new) or 200 (existing) SetupDatabase
//	GET  /v1/agent/setup/databases             {"databases": [SetupDatabase...]}
//	GET  /v1/agent/setup/databases/{id}        SetupDatabase
//	POST /v1/agent/setup/databases/{id}/apply  SetupApplyRequest -> 202 SetupDatabase

type SetupRegisterRequest struct {
	Name      string `json:"name"` // database name in Rowsafe: lowercase letters, digits, dashes
	Port      int    `json:"port"`
	SocketDir string `json:"socket_dir,omitempty"`
	// Engine is the database engine; "" is PostgreSQL.
	Engine string `json:"engine,omitempty"`
}

type SetupDatabase struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Port      int          `json:"port"`
	SocketDir string       `json:"socket_dir,omitempty"`
	Status    string       `json:"status"`         // pending_adopt, awaiting_restart, verifying, active, ...
	Plan      *AdoptResult `json:"plan,omitempty"` // the latest adopt result (plan, or applied result)
	// PlanTaskID is the latest adopt task; PlanTaskStatus its status
	// (queued, running, succeeded, failed) and PlanError its error when it
	// failed.
	PlanTaskID     string     `json:"plan_task_id,omitempty"`
	PlanTaskStatus string     `json:"plan_task_status,omitempty"`
	PlanError      string     `json:"plan_error,omitempty"`
	LastBackupAt   *time.Time `json:"last_backup_at,omitempty"`
	BackupRunning  bool       `json:"backup_running,omitempty"`
	DashboardURL   string     `json:"dashboard_url,omitempty"`
	// Engine is the database engine; "" (older control planes) is
	// PostgreSQL.
	Engine string `json:"engine,omitempty"`
}

type SetupDatabaseList struct {
	Databases []SetupDatabase `json:"databases"`
}

type SetupApplyRequest struct {
	Force bool `json:"force,omitempty"` // replace a foreign archive_command
}

// ---- User API ----

type CreateEnrollmentTokenRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

type EnrollmentToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Host struct {
	ID            string        `json:"id"`
	Hostname      string        `json:"hostname"`
	AgentVersion  string        `json:"agent_version"`
	Platform      string        `json:"platform,omitempty"` // "" until the agent reports it
	UpdateChannel string        `json:"update_channel"`
	PinnedVersion string        `json:"pinned_version,omitempty"`
	LastUpdate    *UpdateReport `json:"last_update,omitempty"`
	LastSeenAt    *time.Time    `json:"last_seen_at,omitempty"`
	CreatedAt     time.Time     `json:"created_at"`
}

// UpdateHostRequest changes a host's update policy. Pin "" clears the pin.
type UpdateHostRequest struct {
	UpdateChannel *string `json:"update_channel,omitempty"`
	PinnedVersion *string `json:"pinned_version,omitempty"`
}

type CreateDatabaseRequest struct {
	HostID        string `json:"host_id"` // host ID or hostname
	Name          string `json:"name"`
	Port          int    `json:"port,omitempty"`
	SocketDir     string `json:"socket_dir,omitempty"`
	RetentionFull int    `json:"retention_full,omitempty"`
	// Engine is the database engine; "" is PostgreSQL. The control plane
	// refuses engines whose EngineCapabilities have no Backups yet.
	Engine string `json:"engine,omitempty"`
}

type Database struct {
	ID            string         `json:"id"`
	HostID        string         `json:"host_id"`
	Hostname      string         `json:"hostname"`
	Name          string         `json:"name"`
	Stanza        string         `json:"stanza"`
	Port          int            `json:"port"`
	SocketDir     string         `json:"socket_dir"`
	Status        string         `json:"status"`
	RetentionFull int            `json:"retention_full"`
	ScheduleFull  string         `json:"schedule_full"`
	ScheduleDiff  string         `json:"schedule_diff"`
	ScheduleDrill string         `json:"schedule_drill"`
	Inspect       *InspectResult `json:"inspect,omitempty"`
	Archiver      *ArchiverStats `json:"archiver,omitempty"`
	// CanRestart: root allowed Rowsafe to restart this database's
	// PostgreSQL (its port is in the host's restart allow list).
	CanRestart bool      `json:"can_restart"`
	CreatedAt  time.Time `json:"created_at"`
	// Engine is the database engine (Engine* in engine.go). Current control
	// planes always set it; "" from older ones means PostgreSQL.
	Engine string `json:"engine,omitempty"`
	// EngineVersion is the database server's version as the agent reported
	// it ("18.1", "8.4.3", "7.0.12"); for PostgreSQL it mirrors
	// Inspect.ServerVersion. "" until known.
	EngineVersion string `json:"engine_version,omitempty"`
}

type CreateTaskRequest struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

type TaskView struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	DatabaseID string `json:"database_id,omitempty"`
	// DatabaseName is the database's name (also for removed databases).
	DatabaseName string          `json:"database_name,omitempty"`
	HostID       string          `json:"host_id"`
	Status       string          `json:"status"`
	Scheduled    bool            `json:"scheduled"`
	Params       json.RawMessage `json:"params,omitempty"`
	Error        string          `json:"error,omitempty"`
	Log          string          `json:"log,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
	StartedAt    *time.Time      `json:"started_at,omitempty"`
	FinishedAt   *time.Time      `json:"finished_at,omitempty"`
}

type Backup struct {
	ID            string    `json:"id"`
	DatabaseID    string    `json:"database_id"`
	TaskID        string    `json:"task_id"`
	Label         string    `json:"label"`
	Type          string    `json:"type"`
	StartedAt     time.Time `json:"started_at"`
	StoppedAt     time.Time `json:"stopped_at"`
	SizeBytes     int64     `json:"size_bytes"`
	RepoSizeBytes int64     `json:"repo_size_bytes"`
}

type Drill struct {
	ID         string      `json:"id"`
	DatabaseID string      `json:"database_id"`
	TaskID     string      `json:"task_id"`
	Passed     bool        `json:"passed"`
	Result     DrillResult `json:"result"`
	CreatedAt  time.Time   `json:"created_at"`
}

type Error struct {
	Error string `json:"error"`
}

type CreateDatabaseResponse struct {
	Database Database `json:"database"`
	Task     TaskView `json:"task"` // the initial adopt plan (read-only)
}

// TaskTimeout is how long the agent lets a task run before killing it.
// The control plane's lease is slightly longer.
func TaskTimeout(taskType string) time.Duration {
	switch taskType {
	case TaskInspect:
		return 2 * time.Minute
	case TaskAdopt, TaskCheck:
		return 10 * time.Minute
	case TaskRestorePoint, TaskRestart, TaskSettings:
		return 5 * time.Minute
	case TaskCopySchema: // catalog queries only
		return 5 * time.Minute
	case TaskSecurityScan, TaskSecurityFix: // security.go; a firewall change waits for its confirmation
		return 10 * time.Minute
	case TaskMaintenance: // a VACUUM or REINDEX of a large table takes a while
		return 2 * time.Hour
	case TaskRewindDrop, TaskRewindCleanup: // stopping a copy, deleting a large directory
		return 30 * time.Minute
	case TaskRewindCompare, TaskRewindRows:
		return 2 * time.Hour
	case TaskRewindUndo: // stop, two renames, start
		return time.Hour
	case TaskUpgradeCheck, TaskUpgradeCleanup, TaskPGUpdate, TaskReboot:
		return 30 * time.Minute
	case TaskSecurityUpdates:
		return 2 * time.Hour
	case TaskStandbyPrepare, TaskStandbyRelease, TaskStandbyFence, TaskStandbyPromote, TaskStandbyRemove, TaskStandbyUnfence:
		return 15 * time.Minute
	case TaskFindMoment: // reads the WAL of the range from the repository
		return time.Hour
	case TaskMigrate: // a switchover waits for the sync to catch up (migrate.go)
		return time.Hour
	case TaskDBAdmin: // Databases & users (dbadmin.go); removing a large database deletes its files
		return 30 * time.Minute
	default: // backup, drill, rewind copy and in place: a large restore takes hours
		return 12 * time.Hour
	}
}

// ---- Agent self-update ----

// Update states reported by the agent.
const (
	UpdateStaged     = "staged"      // new version downloaded, verified and self-tested
	UpdateSwitched   = "switched"    // symlink swapped, restarting into new version
	UpdateConfirmed  = "confirmed"   // new version passed probation
	UpdateRolledBack = "rolled_back" // new version failed probation; previous restored
	UpdateFailed     = "failed"      // rejected before switching (bad signature, self-test...)
)

// UpdateOffer is sent in the heartbeat response when the control plane wants
// this host on a different version. Manifest and Signature are passed through
// verbatim: the agent verifies the signature with a key built into it, so the
// control plane cannot forge releases.
type UpdateOffer struct {
	Version   string `json:"version"`
	Manifest  string `json:"manifest"`  // exact signed JSON bytes
	Signature string `json:"signature"` // base64 Ed25519 signature over Manifest
}

// UpdateReport tells the control plane how the last update attempt went.
type UpdateReport struct {
	State       string `json:"state"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version"`
	Error       string `json:"error,omitempty"`
	// Retryable marks transient failures (e.g. a download timeout) that say
	// nothing about the release itself and must not halt its rollout.
	Retryable bool      `json:"retryable,omitempty"`
	At        time.Time `json:"at"`
}

// ReleaseManifest is the signed description of one agent release.
type ReleaseManifest struct {
	Version    string              `json:"version"`
	ReleasedAt time.Time           `json:"released_at"`
	Artifacts  map[string]Artifact `json:"artifacts"` // key: "linux/amd64"
}

type Artifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ---- Organizations, plans and API keys ----

// Plans. Their limits live in the control plane (store.PlanLimits).
const (
	PlanFree     = "free"
	PlanPro      = "pro"
	PlanBusiness = "business"
)

// OrgHeader selects the organization a service-token request acts for.
const OrgHeader = "X-Rowsafe-Org"

type PlanLimits struct {
	MaxHosts     int `json:"max_hosts"`
	MaxDatabases int `json:"max_databases"`
	// MaxRewindRows is the most rows one Rewind "bring back rows" run may
	// write (RewindRowsParams.MaxRows).
	MaxRewindRows int64 `json:"max_rewind_rows"`
}

type OrgUsage struct {
	Hosts     int `json:"hosts"`
	Databases int `json:"databases"`
}

type Org struct {
	ID                  string     `json:"id"`
	Name                string     `json:"name"`
	ExternalID          string     `json:"external_id"` // Better Auth organization ID; "" for orgs made with rowsafed bootstrap
	Plan                string     `json:"plan"`
	Limits              PlanLimits `json:"limits"`
	Usage               OrgUsage   `json:"usage"`
	PolarCustomerID     string     `json:"polar_customer_id,omitempty"`
	PolarSubscriptionID string     `json:"polar_subscription_id,omitempty"`
	PlanPeriodEnd       *time.Time `json:"plan_period_end,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

type CreateOrgRequest struct {
	Name       string `json:"name"`
	ExternalID string `json:"external_id"`
}

// UpdatePlanRequest sets an org's plan. Omitted optional fields keep their
// current value and "" clears an ID. Moving to the free plan clears the
// subscription ID and period end unless they are given.
type UpdatePlanRequest struct {
	Plan                string     `json:"plan"`
	PolarCustomerID     *string    `json:"polar_customer_id,omitempty"`
	PolarSubscriptionID *string    `json:"polar_subscription_id,omitempty"`
	PlanPeriodEnd       *time.Time `json:"plan_period_end,omitempty"`
}

type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	// ReadOnly keys may only make GET requests.
	ReadOnly bool `json:"read_only"`
}

type CreateAPIKeyRequest struct {
	Name     string `json:"name"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// CreatedAPIKey carries the plaintext key, which is shown only once.
type CreatedAPIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	CreatedAt time.Time `json:"created_at"`
	ReadOnly  bool      `json:"read_only"`
}

// UpdateDatabaseRequest changes a database's retention and schedules.
// Omitted fields are unchanged. Schedules are 5-field cron expressions in
// UTC; schedule_diff "" disables differential backups.
type UpdateDatabaseRequest struct {
	RetentionFull *int    `json:"retention_full,omitempty"`
	ScheduleFull  *string `json:"schedule_full,omitempty"`
	ScheduleDiff  *string `json:"schedule_diff,omitempty"`
	ScheduleDrill *string `json:"schedule_drill,omitempty"`
}

// AuditEvent records a change made through the API.
type AuditEvent struct {
	ID     string          `json:"id"`
	At     time.Time       `json:"at"`
	Actor  string          `json:"actor"`  // "key:<id> (<name>)", "dashboard[:<user>]" or "rowsafed"
	Action string          `json:"action"` // e.g. "database.update"
	Target string          `json:"target,omitempty"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

// ActorHeader names the person acting through the service token (e.g. the
// dashboard user's email) for the audit log. It is ignored with API keys.
const ActorHeader = "X-Rowsafe-Actor"

// ---- Restore points and protection ----

// ClaimRequest optionally limits a claim to some task types (the agent's
// fast lane claims only restore points so they never wait behind a backup).
type ClaimRequest struct {
	Types []string `json:"types,omitempty"`
}

type RestorePointParams struct {
	Name string `json:"name"`
}

type CreateRestorePointRequest struct {
	Name string `json:"name"`
}

// RestorePointResult is the agent's report for a restore_point task.
type RestorePointResult struct {
	Name       string     `json:"name"`
	LSN        string     `json:"lsn"`
	WALFile    string     `json:"wal_file"`
	Archived   bool       `json:"archived"`
	CreatedAt  time.Time  `json:"created_at"`
	ArchivedAt *time.Time `json:"archived_at,omitempty"`
}

// Restore point states.
const (
	RestorePointPending     = "pending"     // task queued or running
	RestorePointArchived    = "archived"    // WAL with the restore point is in the repository
	RestorePointUnconfirmed = "unconfirmed" // created, but archiving wasn't confirmed in time
)

type RestorePoint struct {
	ID          string     `json:"id"`
	DatabaseID  string     `json:"database_id"`
	Name        string     `json:"name"`
	Status      string     `json:"status"`
	TaskID      string     `json:"task_id"`
	LSN         string     `json:"lsn,omitempty"`
	WALFile     string     `json:"wal_file,omitempty"`
	CreatedBy   string     `json:"created_by"`
	RequestedAt time.Time  `json:"requested_at"`
	CreatedAt   *time.Time `json:"created_at,omitempty"`  // when PostgreSQL wrote it
	ArchivedAt  *time.Time `json:"archived_at,omitempty"` // when its WAL was confirmed archived
	// RestoreFromBackup is the newest backup that finished before the
	// restore point: pass it to pgbackrest restore as --set, because with
	// --type=name pgBackRest can't pick the backup itself.
	RestoreFromBackup string `json:"restore_from_backup,omitempty"`
}

// Protection is a conservative "is this database recoverable right now"
// check. Protected is true only if every condition holds; Reasons lists
// each one that doesn't.
type Protection struct {
	Protected           bool       `json:"protected"`
	Reasons             []string   `json:"reasons"`
	Status              string     `json:"status"`
	CheckedAt           time.Time  `json:"checked_at"`
	LastBackupAt        *time.Time `json:"last_backup_at,omitempty"`
	LastFullAt          *time.Time `json:"last_full_at,omitempty"`
	WALLastArchivedAt   *time.Time `json:"wal_last_archived_at,omitempty"`
	ArchiverUp          bool       `json:"archiver_up"`
	ArchiveFailing      bool       `json:"archive_failing"`
	RecoveryWindowStart *time.Time `json:"recovery_window_start,omitempty"`
	LastDrillPassedAt   *time.Time `json:"last_drill_passed_at,omitempty"`
	LastDrillPassed     *bool      `json:"last_drill_passed,omitempty"`
	OpenFailedTasks     []TaskView `json:"open_failed_tasks"`
}

// ---- Monitoring (agent -> control plane) ----

// MonitoringReport is what the agent posts to POST /v1/agent/monitoring
// about once a minute. Metric names are listed at https://rowsafe.sh/docs/guides/monitoring; the
// control plane drops names it doesn't know.
type MonitoringReport struct {
	CollectedAt time.Time `json:"collected_at"`
	// Host metrics (CPU, load, memory, swap, disk). Empty on platforms
	// where the agent can't read them.
	Host      map[string]float64   `json:"host,omitempty"`
	Databases []DatabaseMonitoring `json:"databases,omitempty"`
}

// DatabaseMonitoring is one database cluster's part of a report.
type DatabaseMonitoring struct {
	DatabaseID string `json:"database_id"`
	// Error is set when the agent could not query PostgreSQL.
	Error            string             `json:"error,omitempty"`
	Metrics          map[string]float64 `json:"metrics,omitempty"`
	Sizes            []DatabaseSize     `json:"sizes,omitempty"` // about every 5 minutes
	ReplicationSlots []ReplicationSlot  `json:"replication_slots,omitempty"`
	Activity         *Activity          `json:"activity,omitempty"`
	Statements       *Statements        `json:"statements,omitempty"` // about every 5 minutes
	// QueryStats is pg_stat_statements activity since the previous reading
	// (about every 5 minutes; newer agents only).
	QueryStats *QueryStats `json:"query_stats,omitempty"`
	// Insights are table and index statistics (about every 30 minutes;
	// newer agents only).
	Insights *Insights `json:"insights,omitempty"`
	// Replication is streaming replication status (newer agents only).
	Replication *ReplicationStatus `json:"replication,omitempty"`
	// Settings are the PostgreSQL settings that matter (settings.go; about
	// every 5 minutes, newer agents only).
	Settings *SettingsSnapshot `json:"settings,omitempty"`
}

// MonitoringAck answers a monitoring report.
type MonitoringAck struct {
	// IntervalSeconds is how often the control plane wants reports.
	IntervalSeconds int `json:"interval_seconds"`
}

type DatabaseSize struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
}

type ReplicationSlot struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // physical | logical
	Active bool   `json:"active"`
	// RetainedBytes is how much WAL the slot holds back (nil on a standby
	// or for a slot that never reserved WAL).
	RetainedBytes *int64 `json:"retained_bytes,omitempty"`
	WALStatus     string `json:"wal_status,omitempty"` // reserved | extended | unreserved | lost
	// LagBytes is how far a logical slot's consumer is behind (WAL written
	// but not yet confirmed by the consumer). Newer agents only.
	LagBytes *int64 `json:"lag_bytes,omitempty"`
	Database string `json:"database,omitempty"` // logical slots: the database it decodes
}

// Activity lists sessions running a query, or idle in a transaction, for
// over a minute.
type Activity struct {
	CollectedAt time.Time `json:"collected_at,omitzero"` // absent until the agent reports
	// QueryTextCollected is false when the agent runs with
	// ROWSAFE_COLLECT_QUERY_TEXT=false; Query is then empty.
	QueryTextCollected bool            `json:"query_text_collected"`
	Queries            []ActivityQuery `json:"queries"`
	// Blocking lists sessions waiting for a lock held by another session,
	// and the sessions holding those locks (newer agents; absent when no
	// session is blocked).
	Blocking []LockSession `json:"blocking,omitempty"`
}

type ActivityQuery struct {
	PID             int     `json:"pid"`
	DurationSeconds float64 `json:"duration_seconds"` // since the query (or, idle in transaction, the last one) started
	XactSeconds     float64 `json:"xact_seconds"`     // since the transaction started (0 outside one)
	State           string  `json:"state"`
	WaitEventType   string  `json:"wait_event_type,omitempty"`
	WaitEvent       string  `json:"wait_event,omitempty"`
	ApplicationName string  `json:"application_name,omitempty"`
	Database        string  `json:"database,omitempty"`
	User            string  `json:"user,omitempty"`
	Query           string  `json:"query,omitempty"` // up to 500 characters
	// BackendStart is when the session started; with PID it identifies the
	// session for a cancel_query or terminate_session fix (PIDs are
	// reused). Newer agents only.
	BackendStart *time.Time `json:"backend_start,omitempty"`
}

// Statements is the top of pg_stat_statements by total execution time,
// cumulative since its last reset. Query text is normalized by PostgreSQL
// (constants become $1, $2...).
type Statements struct {
	CollectedAt time.Time       `json:"collected_at,omitzero"` // absent until the agent reports
	Available   bool            `json:"available"`
	Reason      string          `json:"reason,omitempty"` // why not available
	Statements  []StatementStat `json:"statements"`
}

type StatementStat struct {
	QueryID     string  `json:"query_id"` // a 64-bit integer, as a string
	Query       string  `json:"query"`    // up to 2000 characters
	Database    string  `json:"database,omitempty"`
	User        string  `json:"user,omitempty"`
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	MeanTimeMs  float64 `json:"mean_time_ms"`
	Rows        int64   `json:"rows"`
}

// ---- Monitoring and alerting (user API) ----

// MetricsResponse answers GET /v1/databases/{ref}/metrics and
// GET /v1/hosts/{ref}/metrics.
type MetricsResponse struct {
	From       time.Time      `json:"from"`
	To         time.Time      `json:"to"`
	Step       int            `json:"step"`       // seconds between points
	Resolution string         `json:"resolution"` // stored resolution used: 1m, 5m or 1h
	Series     []MetricSeries `json:"series"`
}

type MetricSeries struct {
	Metric string `json:"metric"`
	Unit   string `json:"unit"`
	// Points are [unix_seconds, value] pairs, oldest first. A bucket
	// without samples has no point.
	Points [][2]float64 `json:"points"`
}

// MonitoringSnapshot answers GET /v1/databases/{ref}/monitoring: the
// newest details the agent reported besides the metric series.
type MonitoringSnapshot struct {
	ReportedAt *time.Time `json:"reported_at,omitempty"` // nil until the agent reports
	// Error is set when the agent could not query PostgreSQL in its newest
	// report.
	Error            string            `json:"error,omitempty"`
	ReplicationSlots []ReplicationSlot `json:"replication_slots"`
	Sizes            []DatabaseSize    `json:"sizes"`
	SizesAt          *time.Time        `json:"sizes_at,omitempty"`
	// Replication is the newest streaming replication status (absent until
	// an agent that reports it does).
	Replication *ReplicationStatus `json:"replication,omitempty"`
}

// MetricInfo describes one collected metric (GET /v1/monitoring/metrics).
type MetricInfo struct {
	Name        string `json:"name"`
	Scope       string `json:"scope"` // database | host
	Unit        string `json:"unit"`
	Description string `json:"description"`
}

// Alert severities, from most to least urgent.
const (
	SeverityCritical = "critical"
	SeverityWarning  = "warning"
	SeverityInfo     = "info"
)

// Alert states shown by the API. (An alert whose condition has not yet
// held for the rule's for_seconds is pending and not listed.)
const (
	AlertFiring   = "firing"
	AlertResolved = "resolved"
)

type Alert struct {
	ID          string         `json:"id"`
	Rule        string         `json:"rule"`
	Severity    string         `json:"severity"`
	State       string         `json:"state"`
	Database    *AlertDatabase `json:"database,omitempty"`
	Host        *AlertHost     `json:"host,omitempty"`
	Summary     string         `json:"summary"`
	Description string         `json:"description"`
	NextStep    string         `json:"next_step,omitempty"` // what to do, usually a CLI command
	Value       *float64       `json:"value,omitempty"`
	Threshold   *float64       `json:"threshold,omitempty"`
	Unit        string         `json:"unit,omitempty"` // unit of value and threshold
	URL         string         `json:"url,omitempty"`  // dashboard page, when ROWSAFE_APP_URL is set
	StartedAt   time.Time      `json:"started_at"`
	ResolvedAt  *time.Time     `json:"resolved_at,omitempty"`
	// AcknowledgedAt stops repeat notifications of a firing alert.
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
}

type AlertDatabase struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type AlertHost struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// AlertRule is a built-in rule with the org's overrides applied.
type AlertRule struct {
	Rule        string   `json:"rule"`
	Title       string   `json:"title"`
	Scope       string   `json:"scope"` // database | host
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Threshold   *float64 `json:"threshold,omitempty"` // absent for rules without one
	Unit        string   `json:"unit,omitempty"`      // unit of threshold
	ForSeconds  int      `json:"for_seconds"`
	Severity    string   `json:"severity"`
	// Customized is true when the org overrides any default.
	Customized bool             `json:"customized"`
	Defaults   AlertRuleDefault `json:"defaults"`
}

type AlertRuleDefault struct {
	Threshold  *float64 `json:"threshold,omitempty"`
	ForSeconds int      `json:"for_seconds"`
	Severity   string   `json:"severity"`
}

// UpdateAlertRuleRequest replaces an org's override of a rule: an omitted
// field goes back to the default (enabled: true).
type UpdateAlertRuleRequest struct {
	Enabled    *bool    `json:"enabled,omitempty"`
	Threshold  *float64 `json:"threshold,omitempty"`
	ForSeconds *int     `json:"for_seconds,omitempty"`
	Severity   *string  `json:"severity,omitempty"`
}

// Notification channel types.
const (
	ChannelEmail   = "email"
	ChannelSlack   = "slack"
	ChannelDiscord = "discord"
	ChannelWebhook = "webhook"
)

type NotificationChannel struct {
	ID          string        `json:"id"`
	Type        string        `json:"type"`
	Name        string        `json:"name"`
	Config      ChannelConfig `json:"config"` // url is masked in responses
	MinSeverity string        `json:"min_severity"`
	CreatedAt   time.Time     `json:"created_at"`
	LastSentAt  *time.Time    `json:"last_sent_at,omitempty"`
	LastError   string        `json:"last_error,omitempty"`
	LastErrorAt *time.Time    `json:"last_error_at,omitempty"`
	// SigningSecret is returned once, when a webhook channel is created.
	SigningSecret string `json:"signing_secret,omitempty"`
}

type ChannelConfig struct {
	Addresses []string `json:"addresses,omitempty"` // email
	URL       string   `json:"url,omitempty"`       // slack, discord, webhook (https only)
}

type CreateNotificationChannelRequest struct {
	Type        string        `json:"type"`
	Name        string        `json:"name"`
	Config      ChannelConfig `json:"config"`
	MinSeverity string        `json:"min_severity,omitempty"` // default warning
}

type ChannelTestResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ---- CLI login (OAuth 2.0 device authorization, RFC 8628 style) ----

// DefaultAPIURL is the hosted control plane. The CLI and the agent use it
// unless ROWSAFE_URL (or a saved login) says otherwise.
const DefaultAPIURL = "https://api.rowsafe.sh"

// Device-flow errors returned by POST /v1/auth/device/token (HTTP 400).
const (
	DeviceAuthorizationPending = "authorization_pending" // keep polling
	DeviceSlowDown             = "slow_down"             // polled too fast: add 5s to the interval
	DeviceExpiredToken         = "expired_token"         // expired, unknown or already used: start over
	DeviceAccessDenied         = "access_denied"         // the user declined
)

type DeviceAuthRequest struct {
	ClientName string `json:"client_name"` // e.g. "rowsafe CLI on laptop"
}

type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"` // "XXXX-XXXX"
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"` // seconds
	Interval                int    `json:"interval"`   // seconds between polls
}

type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

// DeviceTokenResponse carries a new API key, shown only this once.
type DeviceTokenResponse struct {
	APIKey string   `json:"api_key"`
	KeyID  string   `json:"key_id"`
	Org    OrgBrief `json:"org"`
}

type OrgBrief struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Device authorization states, as the approval page sees them.
const (
	DeviceStatusPending  = "pending"
	DeviceStatusApproved = "approved"
	DeviceStatusDenied   = "denied"
	DeviceStatusExpired  = "expired"
	DeviceStatusConsumed = "consumed" // approved and the CLI has its key
)

// DeviceAuthorization is what the approval page shows before the user
// approves (service token only).
type DeviceAuthorization struct {
	UserCode   string    `json:"user_code"`
	ClientName string    `json:"client_name"`
	ClientIP   string    `json:"client_ip,omitempty"` // where the CLI asked from
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type ApproveDeviceRequest struct {
	OrgID string `json:"org_id"`
}

// DenyDeviceRequest's OrgID is optional; with it the denial is audit-logged
// in that org.
type DenyDeviceRequest struct {
	OrgID string `json:"org_id,omitempty"`
}

// WhoAmI describes the credentials making the request.
type WhoAmI struct {
	Org    Org     `json:"org"`
	APIKey *APIKey `json:"api_key,omitempty"` // nil for the service token
	Actor  string  `json:"actor"`
	// OAuth is set for an AI app's OAuth access token (only on /mcp).
	OAuth *OAuthConnection `json:"oauth,omitempty"`
}
