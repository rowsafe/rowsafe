package protocol

import (
	"strings"
	"time"
)

// ---- Fork: a new, independent database cloned from another at any point
// in its recovery window ----
//
// A fork is the source database as it was at a moment (now, any second in
// the recovery window, or a Mark), restored on a server of the organization
// (another one, or the same one on a new port) and registered as a new
// Rowsafe database with its own name, backups (its own stanza: it never
// writes into the source's) and restore tests. Personal data can be masked
// before anyone can connect, for staging.
//
// Secrets never pass through Rowsafe in the clear: for another server the
// source's agent seals the bucket settings it needs to read the source's
// backups to the target agent's key (the sealed handoff of Standby, purpose
// "fork"), after a person confirmed that key's fingerprint. On the same
// server nothing moves at all. The fork's own backups go to the target
// server's own bucket and passphrase.

// Fork task types. Every one starts with "fork_" (IsForkTask). They carry
// the databases they act on in their params (the fork's database only
// exists once it is restored), so they run beside the source's backups.
const (
	// TaskForkPrepare runs on the source's server when the fork goes to
	// another server: it seals the source's repository settings for the
	// target agent (ForkPrepareParams -> ForkPrepareResult).
	TaskForkPrepare = "fork_prepare"
	// TaskForkRestore runs on the target server: it creates (or takes) the
	// cluster, restores the source to the chosen point privately (no network
	// connections), masks personal data if asked, and starts it
	// (ForkRestoreParams -> ForkRestoreResult).
	TaskForkRestore = "fork_restore"
)

// IsForkTask reports whether a task type belongs to Fork.
func IsForkTask(taskType string) bool { return strings.HasPrefix(taskType, "fork_") }

// HandoffPurposeFork is SealedBox.Purpose for a fork.
const HandoffPurposeFork = "fork"

// ForkHandoffContext is the SealedBox.Context of a fork's handoff.
func ForkHandoffContext(sourceDatabaseID, forkID string) string {
	return "fork:" + sourceDatabaseID + ":" + forkID
}

// ForkSecrets is the plaintext inside a fork's SealedBox: what the target
// needs to read the source's backups (and nothing to write them: the fork
// backs up to its own server's bucket).
type ForkSecrets struct {
	Repo StandbyRepo `json:"repo"`
}

// Where a fork runs on its server (ForkRestoreParams.Placement).
const (
	// ForkNewCluster: the root helper creates a new PostgreSQL cluster
	// (pg_createcluster, its own systemd unit) on a free port, when root
	// allowed it at install (--allow-create-cluster).
	ForkNewCluster = "new_cluster"
	// ForkEmptyCluster: an existing cluster with no data yet, that the root
	// helper may stop and start. Its own (empty) data is kept aside.
	ForkEmptyCluster = "empty_cluster"
	// ForkDocker: a Docker agent sidecar set up as a fork target
	// (ROWSAFE_FORK_TARGET_DIR): its PostgreSQL container waits until the
	// fork is restored into its volume, then starts on it.
	ForkDocker = "docker"
	// ForkEmptyServer: an existing, empty server of another engine than
	// PostgreSQL (MySQL, MariaDB) whose Rowsafe account may load data into
	// it (StandbyTarget): the fork is restored privately next to it and
	// loaded into it.
	ForkEmptyServer = "empty_server"
	// ForkSQLiteFile: a new SQLite file in a folder root allowed for clones
	// at install (StandbyTarget.Socket of a "sqlite" target;
	// protocol/sqlite_fork.go). ForkRestoreParams.SocketDir is the new
	// file's path; the agent never overwrites anything there.
	ForkSQLiteFile = "sqlite_file"
)

// ForkPrepareParams are the params of a fork_prepare task (on the source's
// server).
type ForkPrepareParams struct {
	ForkID string `json:"fork_id"` // [A-Za-z0-9_-]{1,64}
	// Source is the database being forked (on this server).
	Source DatabaseSpec `json:"source"`
	// RecipientKey is the target agent's X25519 public key;
	// RecipientFingerprint is the fingerprint the person confirmed. The
	// agent refuses when they don't match.
	RecipientKey         string `json:"recipient_key"`
	RecipientFingerprint string `json:"recipient_fingerprint"`
	// Verify: the fork is a restore test (Proof on another server): the
	// source also reports what the test checks the restore against
	// (ForkPrepareResult.Verify).
	Verify bool `json:"verify,omitempty"`
}

// ForkPrepareResult is the agent's report for a fork_prepare task.
type ForkPrepareResult struct {
	ForkID string    `json:"fork_id"`
	Box    SealedBox `json:"box"`
	// What the target checks before it restores: the same major version,
	// enough disk, and the settings recovery needs at least as high.
	Major     int            `json:"major"`
	SystemID  string         `json:"system_id"`
	SizeBytes int64          `json:"size_bytes"`
	Settings  map[string]int `json:"settings,omitempty"`
	// Verify is what a restore test elsewhere checks against (only with
	// ForkPrepareParams.Verify).
	Verify  *ForkVerifyFacts `json:"verify,omitempty"`
	Summary string           `json:"summary"`
}

// ForkMaskRule masks one column of the fork with a strategy (the same
// strategies as Guard's safe copies).
type ForkMaskRule struct {
	DB       string `json:"db"`
	Table    string `json:"table"` // schema.name
	Column   string `json:"column"`
	Strategy string `json:"strategy"`
}

// ForkMasking is how a fork is masked, before anyone can connect to it.
type ForkMasking struct {
	// Rules are the source's saved masking rules.
	Rules []ForkMaskRule `json:"rules,omitempty"`
	// Suggest also masks every column no rule covers whose name and type
	// look personal (emails, names, phone numbers, addresses, IPs, password
	// hashes, ...).
	Suggest bool `json:"suggest"`
}

// ForkMaskReport says what masking did.
type ForkMaskReport struct {
	Tables  int   `json:"tables"`
	Columns int   `json:"columns"`
	Rows    int64 `json:"rows"`
	// Strategies counts masked columns per strategy.
	Strategies map[string]int `json:"strategies,omitempty"`
	// Masked lists the masked columns ("db: schema.table.column (strategy)").
	Masked []string `json:"masked,omitempty"`
	// Skipped lists rules not applied, with a plain reason.
	Skipped []string `json:"skipped,omitempty"`
}

// ForkRestoreParams are the params of a fork_restore task (on the target
// server).
type ForkRestoreParams struct {
	ForkID string `json:"fork_id"`
	// Name is the fork's Rowsafe name; a new cluster is named after it.
	Name string `json:"name"`
	// Source is the database being forked. On another server it only
	// locates the backups (its stanza) and binds the handoff (its ID).
	Source DatabaseSpec `json:"source"`
	// Target is the point to restore: a Time or a Mark (the control plane
	// turns "now" into a Mark it saves first), with the backup to start
	// from. Neither: the latest point the backups hold (a source that is
	// lost, where no Mark can be saved; SQLite without continuous backups).
	Target    RewindTarget `json:"target"`
	Placement string       `json:"placement"` // Fork*
	// Port: for a new cluster the port to create it on (0: the agent picks a
	// free one in the allowed range); for an empty cluster its port.
	Port int `json:"port,omitempty"`
	// SocketDir: for ForkSQLiteFile, the new file's absolute path (in an
	// allowed folder; it and its -wal/-shm/-journal files must not exist).
	SocketDir string `json:"socket_dir,omitempty"`
	// Box and SenderKey: the source agent's sealed repository settings (nil
	// when the source is on this server: nothing moves).
	Box *SealedBox `json:"box,omitempty"`
	// OwnRepo: the source's server is lost (Restore to another server), so
	// nothing was sealed: this server reads the source's backups with its
	// own storage settings (installed with the same storage and passphrase
	// as the lost one). Major, SizeBytes and the rest come from what the
	// control plane last knew; PostgreSQL's settings are read from the
	// restored backup itself.
	OwnRepo bool `json:"own_repo,omitempty"`
	// SourceFolder is the source's backup folder when it isn't its stanza
	// (the setup started fresh in a new folder: AdoptResult.RepoFolder);
	// only with OwnRepo (a handoff carries it).
	SourceFolder string         `json:"source_folder,omitempty"`
	SenderKey    string         `json:"sender_key,omitempty"`
	Major        int            `json:"major,omitempty"`
	SizeBytes    int64          `json:"size_bytes,omitempty"`
	Settings     map[string]int `json:"settings,omitempty"`
	// Masking, when set, masks the fork before it starts for real.
	Masking *ForkMasking `json:"masking,omitempty"`
	// Verify: a restore test (Proof on another server), not a fork. The
	// agent restores the newest point in the source's backups into its
	// drill directory, runs the drill's checks against VerifyFacts,
	// reports ForkRestoreResult.Drill and deletes the restored copy.
	// Placement, Port and Masking are ignored; nothing is registered and
	// no backups start.
	Verify      bool             `json:"verify,omitempty"`
	VerifyFacts *ForkVerifyFacts `json:"verify_facts,omitempty"`
}

// ---- Proof on another server (ForkRestoreParams.Verify) ----
//
// When a database's own server lacks the disk for Proof (the weekly restore
// test), the test can run on another server of the organization, or on a
// temporary Rowsafe Cloud server deleted right after. It is a fork that is
// only checked: fork_prepare on the source's server seals the bucket
// settings to the other server's key (as for any fork) and, with Verify,
// reports what the test checks against; fork_restore with Verify on the
// other server restores into its drill directory, checks like the drill
// does, reports a DrillResult and deletes the copy. The control plane
// records it as the source's Proof (DrillResult.RanOn).

// FeatureForkVerify is in HeartbeatRequest.Features of agents that run
// restore tests of another server's databases (ForkRestoreParams.Verify)
// and report ForkHeartbeat.DrillFreeBytes.
const FeatureForkVerify = "fork_verify"

// ForkVerifyFacts is what a restore test elsewhere checks the restored copy
// against, read on the source's server when the test starts.
type ForkVerifyFacts struct {
	// Databases are the source's databases (tables per database), as the
	// drill compares them.
	Databases []DBInfo `json:"databases"`
	// SizeBytes is the source's size (the disk the test needs).
	SizeBytes int64 `json:"size_bytes"`
	// Version is the engine's version ("8.4.6", "7.0.15"; PostgreSQL:
	// server_version_num), for the other server's programs.
	Version string `json:"version,omitempty"`
	// Preload is PostgreSQL's shared_preload_libraries (loaded only when
	// the restore can't start without them, as in the drill).
	Preload string `json:"preload,omitempty"`
}

// ProofSpaceNeeded is the free disk a restore test of a database of
// sizeBytes needs where it runs (the agent's drill check: the restored data
// plus replayed changes and headroom).
func ProofSpaceNeeded(sizeBytes int64) int64 {
	return int64(float64(sizeBytes)*1.3) + 1<<30
}

// ForkRestoreResult is the agent's report for a fork_restore task.
type ForkRestoreResult struct {
	ForkID    string `json:"fork_id"`
	Placement string `json:"placement"`
	Port      int    `json:"port"`
	SocketDir string `json:"socket_dir"`
	DataDir   string `json:"data_dir"`
	Major     int    `json:"major"`
	// Unit is the systemd unit running the fork ("" in Docker); Created:
	// Rowsafe created the cluster for it.
	Unit    string `json:"unit,omitempty"`
	Created bool   `json:"created,omitempty"`
	// RecoveredTo is the commit time of the last transaction replayed (nil
	// when none was replayed after the backup).
	RecoveredTo *time.Time      `json:"recovered_to,omitempty"`
	SizeBytes   int64           `json:"size_bytes"`
	Databases   []DBInfo        `json:"databases,omitempty"`
	Masking     *ForkMaskReport `json:"masking,omitempty"`
	// KeptDataDir is an empty cluster's own data, set aside (deleted by the
	// agent after 7 days).
	KeptDataDir string   `json:"kept_data_dir,omitempty"`
	DurationMs  int64    `json:"duration_ms"`
	Warnings    []string `json:"warnings,omitempty"`
	Summary     string   `json:"summary"`
	// Drill is a restore test's result (ForkRestoreParams.Verify): the
	// fork's restored copy is gone, nothing else above is set but
	// ForkID, DurationMs and Summary.
	Drill *DrillResult `json:"drill,omitempty"`
}

// ---- Heartbeat additions (embedded in HeartbeatRequest) ----

// ForkHeartbeat is what an agent reports about Fork in every heartbeat.
type ForkHeartbeat struct {
	// ForkBoxKey is a Docker sidecar's X25519 public key for sealed
	// handoffs (native agents report theirs as box_key, with Standby).
	ForkBoxKey string `json:"fork_box_key,omitempty"`
	// ForkClusters: root allowed Rowsafe to create PostgreSQL clusters on
	// this server for forks (nil: not allowed, or not possible here).
	ForkClusters *ForkClusters `json:"fork_clusters,omitempty"`
	// ForkTarget: this Docker sidecar waits to receive a fork.
	ForkTarget *ForkDockerTarget `json:"fork_target,omitempty"`
	// Forks is the progress of the fork restores running on this server.
	Forks []ForkState `json:"forks,omitempty"`
	// DrillFreeBytes is the free disk in this server's drill directory
	// (where restore tests run, its own and other servers'); 0: unknown.
	DrillFreeBytes int64 `json:"drill_free_bytes,omitempty"`
}

// ForkClusters is what the root helper may create on a server.
type ForkClusters struct {
	// Majors are the PostgreSQL major versions installed (a fork needs the
	// source's).
	Majors []int `json:"majors"`
	// PortMin and PortMax bound the ports new clusters get.
	PortMin int `json:"port_min"`
	PortMax int `json:"port_max"`
	// FreePorts are a few ports in that range nothing uses right now.
	FreePorts []int `json:"free_ports,omitempty"`
}

// ForkDockerTarget is a Docker sidecar waiting to receive a fork.
type ForkDockerTarget struct {
	Major int `json:"major"`
	// Empty: nothing was restored into its volume yet (only an empty
	// target can receive a fork).
	Empty bool `json:"empty"`
}

// Fork restore steps (ForkState.Step), in order.
const (
	ForkStepCluster  = "cluster"  // creating or taking the cluster
	ForkStepRestore  = "restore"  // downloading the backup
	ForkStepRecover  = "recover"  // replaying changes up to the point
	ForkStepMask     = "mask"     // masking personal data
	ForkStepStart    = "start"    // starting it for real
	ForkStepFinished = "finished" // the task is reporting
)

// ForkState is a running fork restore's progress.
type ForkState struct {
	ForkID string    `json:"fork_id"`
	Step   string    `json:"step"`             // ForkStep*
	Detail string    `json:"detail,omitempty"` // plain words
	At     time.Time `json:"at"`
}

// ---- Fork user API ----
//
//	GET  /v1/databases/{ref}/forks   ForkInfo
//	POST /v1/databases/{ref}/forks   CreateForkRequest -> 202 ForkView
//	GET  /v1/forks/{id}              ForkView
//
//	POST /v1/databases/{ref}/restore-elsewhere   RestoreElsewhereRequest -> 202 ForkView
//	POST /v1/databases/{ref}/retire              RetireDatabaseRequest -> 204
//
// Writes are for owners and admins (the dashboard, read-write API keys).
// AI agents can't fork (a person compares the target's key), but they can
// restore a database whose server is lost to another server, and retire it
// (protocol.ApprovalActions): nothing secret moves then.

// ---- Restore to another server (the source's server is lost) ----
//
// When a database's server is gone (dead disk, deleted VPS), nothing can
// seal its bucket settings any more. Another server of the organization
// that was installed with the same storage (the same bucket, or Rowsafe
// Storage) and the same passphrase can read its backups with its own
// settings: the control plane queues fork_restore there with OwnRepo, the
// point (the latest in the backups, a second, or a Mark) and what it last
// knew about the source. The control plane never sees the passphrase: a
// wrong one fails on that server with the usual plain error (the backups
// were encrypted with another passphrase). Afterwards the old database can
// be retired: Rowsafe forgets it and keeps its backups until an owner
// deletes them.

// FeatureForkOwnRepo is in HeartbeatRequest.Features of agents that restore
// a lost source's backups with their own storage (ForkRestoreParams.OwnRepo,
// and a fork to the latest point in the backups).
const FeatureForkOwnRepo = "fork_own_repo"

// SourceLostAfter is how long a database's server must have been silent
// before it can be restored to another server as lost (a reboot or a
// network blip is not a lost server).
const SourceLostAfter = 10 * time.Minute

// How a target's storage compares with the lost source's
// (ForkTarget.Storage, on ForkSourceLost.Targets).
const (
	// ForkStorageSame: the same storage (Rowsafe Storage of the same
	// organization, or the same bucket). The passphrase is checked when it
	// restores.
	ForkStorageSame = "same"
	// ForkStorageUnknown: its agent hasn't said where its backups go yet;
	// the restore checks.
	ForkStorageUnknown = "unknown"
	// ForkStorageOther: another bucket or kind of storage: it can't read
	// the lost server's backups.
	ForkStorageOther = "other"
)

// ForkSourceLost is ForkInfo's part for a database whose server is offline.
type ForkSourceLost struct {
	// LastSeen is when the source's server last reported.
	LastSeen *time.Time `json:"last_seen,omitempty"`
	// Allowed: it has been silent for SourceLostAfter and the database can
	// be restored to another server now; else Hint says why not.
	Allowed bool   `json:"allowed"`
	Hint    string `json:"hint,omitempty"`
	// Storage is where its backups are (StorageRowsafe, StorageOwn, "" when
	// unknown); Bucket and Endpoint name its own bucket (no secrets), for
	// installing a new server with the same storage.
	Storage  string `json:"storage,omitempty"`
	Bucket   string `json:"bucket,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
	// Targets are the organization's other servers, with Storage set;
	// usable ones first.
	Targets []ForkTarget `json:"targets"`
}

// RestoreElsewhereRequest restores a database whose server is lost to
// another server. Neither At nor Mark: the latest point in its backups.
type RestoreElsewhereRequest struct {
	// Name is the restored database's name (the old one keeps its name
	// until it is retired).
	Name      string     `json:"name"`
	HostID    string     `json:"host_id"` // host ID or hostname
	Placement string     `json:"placement,omitempty"`
	Port      int        `json:"port,omitempty"`
	At        *time.Time `json:"at,omitempty"`
	Mark      string     `json:"mark,omitempty"`
	// Path is a SQLite database's new file (ForkSQLiteFile).
	Path string `json:"path,omitempty"`
}

// RetireDatabaseRequest retires a database whose server is lost: Rowsafe
// forgets it and keeps its backups until an owner deletes them. Confirm is
// the database's name.
type RetireDatabaseRequest struct {
	Confirm string `json:"confirm"`
}

// Fork statuses (ForkView.Status).
const (
	ForkMarking    = "marking"    // saving the Mark "now" stands for
	ForkPreparing  = "preparing"  // the source's server seals the bucket settings
	ForkRestoring  = "restoring"  // the target server restores
	ForkProtecting = "protecting" // registered: backups being turned on, first backup
	ForkReady      = "ready"      // the new database is protected
	ForkFailed     = "failed"
)

// Fork progress step states (ForkProgressStep.State).
const (
	ForkStepPending = "pending"
	ForkStepRunning = "running"
	ForkStepDone    = "done"
	ForkStepFailed  = "failed"
)

// ForkInfo answers GET /v1/databases/{ref}/forks.
type ForkInfo struct {
	Database   string `json:"database"`
	DatabaseID string `json:"database_id"`
	// CanFork: the database can be forked now; else Hint says why.
	CanFork bool   `json:"can_fork"`
	Hint    string `json:"hint,omitempty"`
	// Window is the recovery window: any second in it can be forked.
	Window  ForkWindow   `json:"window"`
	Marks   []ForkMark   `json:"marks"`
	Targets []ForkTarget `json:"targets"`
	// Forks were made from this database, newest first.
	Forks []ForkView `json:"forks"`
	// ForkedFrom is set when this database is itself a fork.
	ForkedFrom *ForkView `json:"forked_from,omitempty"`
	// SourceLost is set when the database's server is offline: it can be
	// restored to another server (Restore to another server).
	SourceLost *ForkSourceLost `json:"source_lost,omitempty"`
}

// ForkWindow is the span a fork can be taken from.
type ForkWindow struct {
	Earliest *time.Time `json:"earliest,omitempty"`
	Latest   *time.Time `json:"latest,omitempty"`
}

// ForkMark is a Mark a fork can start from.
type ForkMark struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// ForkTarget is a server a fork can go to.
type ForkTarget struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	// SameServer: the source's own server (nothing leaves it; no
	// fingerprint to confirm).
	SameServer bool `json:"same_server"`
	Online     bool `json:"online"`
	// Fingerprint is the target agent's key fingerprint, which the person
	// confirms (another server only).
	Fingerprint string      `json:"fingerprint,omitempty"`
	Places      []ForkPlace `json:"places"`
	Usable      bool        `json:"usable"`
	Reason      string      `json:"reason,omitempty"` // why not usable, in plain words
	// Docker: the server is a Docker sidecar waiting for a fork.
	Docker bool `json:"docker,omitempty"`
	// Storage compares its storage with a lost source's (ForkStorage*;
	// only on ForkSourceLost.Targets).
	Storage string `json:"storage,omitempty"`
}

// ForkPlace is one place on a server a fork can go.
type ForkPlace struct {
	Placement string `json:"placement"` // Fork*
	Port      int    `json:"port"`      // 0: Rowsafe picks a free port
	Label     string `json:"label"`     // "A new PostgreSQL 18 on port 5440"
	// Dir is the folder a ForkSQLiteFile clone is written to (the person
	// adds a file name).
	Dir string `json:"dir,omitempty"`
}

// CreateForkRequest creates a fork. Neither At nor Mark: now (Rowsafe saves
// a Mark on the source first and forks from it).
type CreateForkRequest struct {
	Name      string     `json:"name"`
	HostID    string     `json:"host_id"` // host ID or hostname
	Placement string     `json:"placement,omitempty"`
	Port      int        `json:"port,omitempty"`
	At        *time.Time `json:"at,omitempty"`
	Mark      string     `json:"mark,omitempty"`
	Mask      bool       `json:"mask,omitempty"`
	// Fingerprint is the target agent's key fingerprint as the person
	// confirmed it (another server only).
	Fingerprint string `json:"fingerprint,omitempty"`
	// Path is a SQLite clone's new file (ForkSQLiteFile): a file name in
	// one of the place's folders (SQLiteClonePath).
	Path string `json:"path,omitempty"`
}

// ForkView is one fork and its progress.
type ForkView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	SourceID   string     `json:"source_id"`
	SourceName string     `json:"source_name"`
	HostID     string     `json:"host_id"`
	Hostname   string     `json:"hostname"`
	SameServer bool       `json:"same_server"`
	Placement  string     `json:"placement"`
	Port       int        `json:"port,omitempty"`
	Path       string     `json:"path,omitempty"` // a SQLite clone's file
	At         *time.Time `json:"at,omitempty"`   // the chosen time
	Mark       string     `json:"mark,omitempty"` // the chosen (or saved) Mark
	Now        bool       `json:"now,omitempty"`
	// SourceLost: a restore to another server of a database whose server
	// is lost (read with the target's own storage settings).
	SourceLost  bool               `json:"source_lost,omitempty"`
	Masked      bool               `json:"masked"`
	Status      string             `json:"status"` // Fork*
	Steps       []ForkProgressStep `json:"steps"`
	RecoveredTo *time.Time         `json:"recovered_to,omitempty"`
	SizeBytes   int64              `json:"size_bytes,omitempty"`
	Databases   []string           `json:"databases,omitempty"`
	DatabaseID  string             `json:"database_id,omitempty"` // the fork's database, once registered
	Masking     *ForkMaskReport    `json:"masking,omitempty"`
	Summary     string             `json:"summary,omitempty"`
	Error       string             `json:"error,omitempty"`
	Warnings    []string           `json:"warnings,omitempty"`
	CreatedBy   string             `json:"created_by,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
	FinishedAt  *time.Time         `json:"finished_at,omitempty"`
}

// ForkProgressStep is one step of a fork, for live progress.
type ForkProgressStep struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	State  string `json:"state"` // ForkStep{Pending,Running,Done,Failed}
	Detail string `json:"detail,omitempty"`
}
