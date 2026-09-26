package protocol

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// ---- Standby: a second server that stays in sync, is readable, and takes
// over if the primary dies ----
//
// A standby is another server of the organization with the agent installed.
// It restores the latest backup from the bucket and then follows the
// primary: through the bucket (restore_command; works without any network
// path between the servers, about archive_timeout behind) and, when it can
// reach the primary's PostgreSQL, by streaming replication too. It is a hot
// standby: readable, for reports and read-only queries.
//
// Secrets never pass through Rowsafe in the clear. Each agent has an X25519
// key pair (HeartbeatRequest.BoxKey); the primary's agent seals what the
// standby needs (bucket settings and passphrase, replication credentials)
// to the standby agent's key, and the control plane only relays the
// SealedBox. The person confirms the standby's key fingerprint before the
// primary seals anything.

// Standby task types. Every one starts with "standby_" (IsStandbyTask).
const (
	// TaskStandbyPrepare runs on the primary: a replication role with a
	// random password and pg_hba lines for the standby's addresses only
	// (when streaming is possible), and the sealed handoff
	// (StandbyPrepareParams -> StandbyPrepareResult).
	TaskStandbyPrepare = "standby_prepare"
	// TaskStandbyCreate runs on the standby's server: restore the latest
	// backup into the chosen (empty) cluster's data directory, keeping its
	// data aside, and start it as a hot standby through the root helper
	// (StandbyCreateParams -> StandbyCreateResult). Also rebuilds a fenced
	// old primary as the standby of the new one.
	TaskStandbyCreate = "standby_create"
	// TaskStandbyPromote turns the standby into the primary: wait until it
	// has replayed what the old primary wrote (when known), then promote
	// (StandbyPromoteParams -> StandbyPromoteResult).
	TaskStandbyPromote = "standby_promote"
	// TaskStandbyFence stops the old primary for good before a promotion:
	// standby.signal in its data directory (if it is ever started again it
	// comes up read-only), its last WAL pushed to the bucket, PostgreSQL
	// stopped through the root helper, and the agent keeps it stopped
	// (StandbyFenceParams -> StandbyFenceResult).
	TaskStandbyFence = "standby_fence"
	// TaskStandbyRemove stops following on the standby's server: PostgreSQL
	// is stopped and the data the cluster had before is put back
	// (StandbyRemoveParams -> StandbyRemoveResult).
	TaskStandbyRemove = "standby_remove"
	// TaskStandbyRelease runs on the primary when a standby is removed:
	// drop its replication role and pg_hba lines (StandbyReleaseParams ->
	// StandbyReleaseResult).
	TaskStandbyRelease = "standby_release"
	// TaskStandbyUnfence starts a fenced primary again when the promotion
	// that fenced it did not happen (the standby is still a standby):
	// standby.signal is removed and PostgreSQL started through the root
	// helper (StandbyUnfenceParams -> StandbyUnfenceResult).
	TaskStandbyUnfence = "standby_unfence"
)

// StandbyRoleName is the primary's replication role (and the standby's
// application_name) for a standby: "rowsafe_standby_" and the standby ID's
// letters, digits and underscores, lowercased (at most 40 of them).
func StandbyRoleName(standbyID string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(standbyID) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteRune(c)
		}
	}
	id := b.String()
	if len(id) > 40 {
		id = id[len(id)-40:]
	}
	return "rowsafe_standby_" + id
}

// FixStandbyRebuild is a health fix (FindingFix.Kind): rebuild the
// database's standby from the latest backup (it fell behind or broke).
const FixStandbyRebuild = "standby_rebuild"

// IsStandbyTask reports whether a task type belongs to Standby.
func IsStandbyTask(taskType string) bool { return strings.HasPrefix(taskType, "standby_") }

// ---- Sealed handoff (reusable: Proof on another server uses it too) ----

// SealedBox is a secret sealed by one agent for another: X25519 (an
// ephemeral key and the sender's static key, both with the recipient's
// key), HKDF-SHA256 and AES-256-GCM, bound to Purpose and Context (see
// internal/handoff). Keys are base64 (standard encoding) X25519 public
// keys.
type SealedBox struct {
	Version      int    `json:"v"`
	Purpose      string `json:"purpose"` // e.g. "standby"
	Context      string `json:"context"` // e.g. "standby:<database id>:<standby id>"
	SenderKey    string `json:"sender_key"`
	RecipientKey string `json:"recipient_key"`
	EphemeralKey string `json:"ephemeral_key"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// KeyFingerprint is an agent key's fingerprint: the first 64 bits of
// SHA-256 of the X25519 public key, as four groups of four hex digits
// ("7F3A-91C2-0B4E-D8A1"). It is what `rowsafe-agent key` prints on the
// server and what a person confirms before anything is sealed to it.
func KeyFingerprint(publicKey string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid agent key")
	}
	sum := sha256.Sum256(raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:8]))
	return h[0:4] + "-" + h[4:8] + "-" + h[8:12] + "-" + h[12:16], nil
}

// SameFingerprint compares fingerprints, ignoring case, spaces, colons and
// dashes.
func SameFingerprint(a, b string) bool {
	norm := func(s string) string {
		return strings.ToUpper(strings.NewReplacer("-", "", " ", "", ":", "").Replace(s))
	}
	na, nb := norm(a), norm(b)
	return len(na) == 16 && na == nb
}

// HandoffPurposeStandby is SealedBox.Purpose for a standby.
const HandoffPurposeStandby = "standby"

// StandbyHandoffContext is the SealedBox.Context of a standby's handoff.
func StandbyHandoffContext(databaseID, standbyID string) string {
	return "standby:" + databaseID + ":" + standbyID
}

// StandbySecrets is the plaintext inside a standby's SealedBox. It never
// leaves the two agents unencrypted.
type StandbySecrets struct {
	Repo StandbyRepo `json:"repo"`
	// Streaming: a replication role exists for this standby and pg_hba lets
	// it in from the standby's addresses. Empty user: archive only.
	ReplicationUser     string `json:"replication_user,omitempty"`
	ReplicationPassword string `json:"replication_password,omitempty"`
	// PrimaryAddresses are the primary's own IP addresses, in the order the
	// standby tries them; PrimaryPort its PostgreSQL port.
	PrimaryAddresses []string `json:"primary_addresses,omitempty"`
	PrimaryPort      int      `json:"primary_port,omitempty"`
	// PrimaryTLS: the primary has ssl=on (the standby then requires TLS).
	PrimaryTLS bool `json:"primary_tls,omitempty"`
}

// StandbyRepo is the primary's pgBackRest repository, as the standby
// needs it to restore and to fetch WAL (and, once promoted, to archive and
// back up to the same place).
type StandbyRepo struct {
	Endpoint   string `json:"endpoint"`
	Bucket     string `json:"bucket"`
	Region     string `json:"region,omitempty"`
	Key        string `json:"key"`
	KeySecret  string `json:"key_secret"`
	CipherPass string `json:"cipher_pass"`
	PathPrefix string `json:"path_prefix,omitempty"`
	URIStyle   string `json:"uri_style,omitempty"`
	Port       int    `json:"port,omitempty"`
	// SkipTLSVerify mirrors the primary's setting (test repositories only).
	SkipTLSVerify bool `json:"skip_tls_verify,omitempty"`
	// CAPEM is the CA bundle the primary trusts instead of the system store
	// (its ROWSAFE_REPO_S3_CA_FILE), if any.
	CAPEM string `json:"ca_pem,omitempty"`
}

// ---- Heartbeat additions (embedded in HeartbeatRequest/Response) ----

// StandbyHeartbeat is what an agent reports about Standby in every
// heartbeat (inlined into HeartbeatRequest).
type StandbyHeartbeat struct {
	// BoxKey is the agent's X25519 public key (base64). Agents without it
	// can't take part in a standby.
	BoxKey string `json:"box_key,omitempty"`
	// Addresses are the server's own IP addresses (no loopback or
	// link-local), for pg_hba on a primary and for its standby to connect.
	Addresses []string `json:"addresses,omitempty"`
	// Standbys are the standbys this server runs.
	Standbys []StandbyState `json:"standbys,omitempty"`
	// Primaries is the WAL position of each database this server is the
	// primary of, and its streams to Rowsafe standbys.
	Primaries []PrimaryState `json:"primaries,omitempty"`
	// Fences are the fenced clusters on this server and whether they are
	// stopped.
	Fences []FenceState `json:"fences,omitempty"`
	// PoolerDatabases are the databases a Rowsafe-managed connection pooler
	// on this server sends connections to (filled by the pooler feature).
	// When a database's primary changes, the control plane queues a
	// "pooler_retarget" task on every server listing it.
	PoolerDatabases []string `json:"pooler_databases,omitempty"`
}

// StandbyInstructions are what the control plane tells an agent about
// Standby in every heartbeat response (inlined into HeartbeatResponse).
type StandbyInstructions struct {
	// Fences are clusters on this server that must stay stopped: the
	// database's primary moved to another server. The agent stops them
	// (through the root helper, else pg_ctl) whenever they run, and never
	// starts them.
	Fences []Fence `json:"fences,omitempty"`
}

// Standby phases (StandbyState.Phase).
const (
	StandbyPhaseCreating  = "creating"  // standby_create is running
	StandbyPhaseFollowing = "following" // running as a hot standby
	StandbyPhasePromoting = "promoting" // standby_promote is running
	StandbyPhaseStopped   = "stopped"   // PostgreSQL is not running
)

// Standby modes: how WAL reaches the standby right now.
const (
	StandbyModeStreaming = "streaming" // connected to the primary (and the bucket as a fallback)
	StandbyModeArchive   = "archive"   // from the bucket only (about a minute behind)
)

// StandbyState is one standby as its server's agent sees it.
type StandbyState struct {
	StandbyID  string `json:"standby_id"`
	DatabaseID string `json:"database_id"`
	Port       int    `json:"port"`
	Phase      string `json:"phase"` // StandbyPhase*
	// Running: PostgreSQL answers; InRecovery: it is (still) a standby.
	Running    bool   `json:"running"`
	InRecovery bool   `json:"in_recovery"`
	Mode       string `json:"mode,omitempty"` // StandbyMode*
	// ReceiverStatus is pg_stat_wal_receiver.status ("" when not connected).
	ReceiverStatus string `json:"receiver_status,omitempty"`
	// StreamingSeenAt is the last time the agent saw the WAL receiver
	// streaming from the primary.
	StreamingSeenAt *time.Time `json:"streaming_seen_at,omitempty"`
	// ReceiveLSN and ReplayLSN are pg_last_wal_receive_lsn() and
	// pg_last_wal_replay_lsn() ("" when unknown).
	ReceiveLSN string `json:"receive_lsn,omitempty"`
	ReplayLSN  string `json:"replay_lsn,omitempty"`
	// LastReplayAt is the commit time of the last transaction replayed.
	LastReplayAt *time.Time `json:"last_replay_at,omitempty"`
	// ReplayPaused: recovery is paused (pg_is_wal_replay_paused()).
	ReplayPaused bool `json:"replay_paused,omitempty"`
	// PrimaryAddress is the address streaming uses ("" in archive mode).
	PrimaryAddress string `json:"primary_address,omitempty"`
	// PrimaryReachable: the primary's PostgreSQL answered a connection
	// attempt from this server just now (no address: false).
	PrimaryReachable bool `json:"primary_reachable"`
	// PrimaryUnreachableSince is when the primary stopped answering (nil
	// while it answers, or when there is no network path at all).
	PrimaryUnreachableSince *time.Time `json:"primary_unreachable_since,omitempty"`
	Error                   string     `json:"error,omitempty"`
	CheckedAt               time.Time  `json:"checked_at"`
}

// PrimaryState is a primary's WAL position and its streams to standbys.
type PrimaryState struct {
	DatabaseID string          `json:"database_id"`
	WALLSN     string          `json:"wal_lsn"` // pg_current_wal_lsn()
	Streams    []StandbyStream `json:"streams,omitempty"`
	At         time.Time       `json:"at"`
}

// StandbyStream is one Rowsafe standby streaming from a primary
// (pg_stat_replication, application_name StandbyRoleName(id)).
type StandbyStream struct {
	Role             string   `json:"role"` // StandbyRoleName of the standby
	State            string   `json:"state"`
	ReplayLagBytes   *int64   `json:"replay_lag_bytes,omitempty"`
	ReplayLagSeconds *float64 `json:"replay_lag_seconds,omitempty"`
	FlushLagSeconds  *float64 `json:"flush_lag_seconds,omitempty"`
}

// Fence is a cluster that must stay stopped.
type Fence struct {
	ID         string `json:"id"`
	DatabaseID string `json:"database_id"`
	Port       int    `json:"port"`
	SocketDir  string `json:"socket_dir"`
	// SystemID is the database's system identifier: a cluster on the port
	// with another one is something else and is left alone.
	SystemID string    `json:"system_id,omitempty"`
	Since    time.Time `json:"since"`
}

// FenceState is how a fence holds on its server.
type FenceState struct {
	ID         string `json:"id"`
	DatabaseID string `json:"database_id"`
	Port       int    `json:"port"`
	// Running: a PostgreSQL of this database answers on the port (the
	// agent is stopping it).
	Running   bool       `json:"running"`
	StoppedAt *time.Time `json:"stopped_at,omitempty"` // when the agent last stopped it
	// Other: a cluster with another system identifier now runs on the port
	// (left alone).
	Other bool      `json:"other,omitempty"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

// ---- Task params and results ----

// StandbyPrepareParams are the params of a standby_prepare task (on the
// primary's server).
type StandbyPrepareParams struct {
	StandbyID string `json:"standby_id"` // [A-Za-z0-9_-]{1,64}
	// RecipientKey is the standby agent's X25519 public key;
	// RecipientFingerprint is the fingerprint the person confirmed. The
	// agent refuses when they don't match.
	RecipientKey         string `json:"recipient_key"`
	RecipientFingerprint string `json:"recipient_fingerprint"`
	// StandbyAddresses are the standby server's IPs: pg_hba lets the
	// replication role in from these only.
	StandbyAddresses []string `json:"standby_addresses,omitempty"`
	// Stream sets up streaming (role and pg_hba); false: archive only.
	Stream bool `json:"stream"`
}

// StandbyPrepareResult is the agent's report for a standby_prepare task.
type StandbyPrepareResult struct {
	StandbyID string    `json:"standby_id"`
	Box       SealedBox `json:"box"`
	// What the standby checks before it restores: the same major version,
	// the same system, enough disk.
	Major     int    `json:"major"`
	SystemID  string `json:"system_id"`
	SizeBytes int64  `json:"size_bytes"`
	// Settings are the primary's values that a hot standby needs at least as
	// high (max_connections, max_worker_processes, ...).
	Settings map[string]int `json:"settings,omitempty"`
	// Streaming: the role and pg_hba lines are in place.
	Streaming       bool     `json:"streaming"`
	ReplicationRole string   `json:"replication_role,omitempty"`
	TLS             bool     `json:"tls"`
	ListenLocalOnly bool     `json:"listen_local_only,omitempty"` // listen_addresses is localhost: no streaming
	Warnings        []string `json:"warnings,omitempty"`
	Summary         string   `json:"summary"`
}

// StandbyCreateParams are the params of a standby_create task (on the
// standby's server).
type StandbyCreateParams struct {
	StandbyID string `json:"standby_id"`
	// Port and SocketDir locate the cluster on this server that becomes the
	// standby. It must be empty (no user databases); its data is kept aside
	// and put back when the standby is removed.
	Port      int       `json:"port"`
	SocketDir string    `json:"socket_dir"`
	Box       SealedBox `json:"box"`
	// SenderKey is the primary agent's public key as the control plane
	// knows it; the box must have been sealed by it.
	SenderKey string         `json:"sender_key"`
	Major     int            `json:"major"`
	SystemID  string         `json:"system_id"`
	SizeBytes int64          `json:"size_bytes"`
	Settings  map[string]int `json:"settings,omitempty"`
	// Rebuild turns a fenced old primary into the standby: the fence FenceID
	// is lifted by this task. With Reattach the agent first tries to follow
	// the new primary on the data it has (possible when the old primary
	// stopped cleanly and the standby replayed all of it before promoting);
	// otherwise, or if PostgreSQL refuses, it restores from the bucket and
	// keeps the old data aside (writes the old primary accepted after the
	// promotion are never thrown away).
	Rebuild  bool   `json:"rebuild,omitempty"`
	FenceID  string `json:"fence_id,omitempty"`
	Reattach bool   `json:"reattach,omitempty"`
	// SwitchLSN is where the new primary's timeline starts (its promotion's
	// ReplayLSN): a reattached old primary must replay past it.
	SwitchLSN string `json:"switch_lsn,omitempty"`
	// KeepDays is how long the data kept aside stays before the agent
	// deletes it (default 7, 1 to 30).
	KeepDays int `json:"keep_days,omitempty"`
}

// StandbyCreateResult is the agent's report for a standby_create task.
type StandbyCreateResult struct {
	StandbyID      string     `json:"standby_id"`
	Mode           string     `json:"mode"` // StandbyMode*
	PrimaryAddress string     `json:"primary_address,omitempty"`
	DataDir        string     `json:"data_dir"`
	KeptDataDir    string     `json:"kept_data_dir,omitempty"`
	KeptUntil      *time.Time `json:"kept_until,omitempty"`
	Reattached     bool       `json:"reattached,omitempty"`
	ReplayLSN      string     `json:"replay_lsn,omitempty"`
	RolledBack     bool       `json:"rolled_back,omitempty"`
	DurationMs     int64      `json:"duration_ms"`
	Warnings       []string   `json:"warnings,omitempty"`
	Summary        string     `json:"summary"`
}

// StandbyPromoteParams are the params of a standby_promote task.
type StandbyPromoteParams struct {
	StandbyID string `json:"standby_id"`
	// WaitForLSN is the old primary's shutdown checkpoint (its fence
	// result): the standby promotes only once it has replayed past it,
	// unless Force. "" when the old primary could not be fenced cleanly.
	WaitForLSN string `json:"wait_for_lsn,omitempty"`
	// Force promotes even when WaitForLSN isn't reached within the wait.
	Force bool `json:"force,omitempty"`
	// Automatic marks a promotion by automatic failover (for messages).
	Automatic bool `json:"automatic,omitempty"`
}

// StandbyPromoteResult is the agent's report for a standby_promote task.
type StandbyPromoteResult struct {
	StandbyID    string     `json:"standby_id"`
	Promoted     bool       `json:"promoted"`
	PromotedAt   *time.Time `json:"promoted_at,omitempty"`
	Timeline     int        `json:"timeline,omitempty"`
	ReplayLSN    string     `json:"replay_lsn,omitempty"` // where the new timeline starts
	LastReplayAt *time.Time `json:"last_replay_at,omitempty"`
	// CaughtUp: WaitForLSN was reached (or there was none and everything
	// received was replayed). MissingBytes is how much of the old primary's
	// WAL the standby didn't have when it promoted anyway (Force).
	CaughtUp     bool   `json:"caught_up"`
	MissingBytes int64  `json:"missing_bytes,omitempty"`
	Summary      string `json:"summary"`
}

// StandbyFenceParams are the params of a standby_fence task (on the old
// primary's server).
type StandbyFenceParams struct {
	FenceID   string `json:"fence_id"`
	StandbyID string `json:"standby_id"`
	SystemID  string `json:"system_id,omitempty"`
}

// StandbyFenceResult is the agent's report for a standby_fence task.
type StandbyFenceResult struct {
	FenceID string `json:"fence_id"`
	Stopped bool   `json:"stopped"`
	// Method is how PostgreSQL was stopped: "helper", "pg_ctl" or
	// "already_stopped".
	Method string `json:"method"`
	// CheckpointLSN is the shutdown checkpoint of the stopped cluster (from
	// pg_controldata): the standby must replay past it to lose nothing.
	CheckpointLSN string `json:"checkpoint_lsn,omitempty"`
	Timeline      int    `json:"timeline,omitempty"`
	// FinalWALPushed: the last (partial) WAL segment was pushed to the
	// bucket, so a standby following through the bucket gets everything.
	FinalWALPushed bool     `json:"final_wal_pushed,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Summary        string   `json:"summary"`
}

// StandbyRemoveParams are the params of a standby_remove task.
type StandbyRemoveParams struct {
	StandbyID string `json:"standby_id"`
}

// StandbyRemoveResult is the agent's report for a standby_remove task.
type StandbyRemoveResult struct {
	StandbyID string `json:"standby_id"`
	// Restored: the cluster's own data (kept aside when the standby was
	// created) is back and running.
	Restored bool   `json:"restored"`
	Summary  string `json:"summary"`
}

// StandbyUnfenceParams are the params of a standby_unfence task.
type StandbyUnfenceParams struct {
	FenceID string `json:"fence_id"`
}

// StandbyUnfenceResult is the agent's report for a standby_unfence task.
type StandbyUnfenceResult struct {
	FenceID string `json:"fence_id"`
	Started bool   `json:"started"`
	Summary string `json:"summary"`
}

// StandbyReleaseParams are the params of a standby_release task.
type StandbyReleaseParams struct {
	StandbyID string `json:"standby_id"`
}

// StandbyReleaseResult is the agent's report for a standby_release task.
type StandbyReleaseResult struct {
	StandbyID string `json:"standby_id"`
	Summary   string `json:"summary"`
}

// ---- Standby user API ----
//
//	GET  /v1/databases/{ref}/standby              StandbyInfo
//	GET  /v1/databases/{ref}/standby/candidates   []StandbyCandidate
//	POST /v1/databases/{ref}/standby              CreateStandbyRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/promote      PromoteStandbyRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/rebuild      RebuildStandbyRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/remove       StandbyConfirmRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/forget-fence ForgetFenceRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/unfence      UnfenceRequest -> StandbyInfo
//	PUT  /v1/databases/{ref}/standby/failover     FailoverSettings -> StandbyInfo
//
// Moving a database to another server is a standby followed by a planned
// switchover (never a failover): the old server is stopped briefly and
// cleanly, the new one replays everything and is promoted, poolers follow,
// and the old server stays fenced as a way back for KeepDays.
//
//	POST /v1/databases/{ref}/move                 MoveRequest -> StandbyInfo
//	POST /v1/databases/{ref}/move/schedule        MoveScheduleRequest -> StandbyInfo
//	POST /v1/databases/{ref}/move/switch          StandbyConfirmRequest -> StandbyInfo (switch now)
//	POST /v1/databases/{ref}/move/cancel          StandbyConfirmRequest -> StandbyInfo (before switching)
//	POST /v1/databases/{ref}/move/switch-back     MoveBackRequest -> StandbyInfo
//	POST /v1/databases/{ref}/move/finish          ForgetFenceRequest-like: MoveFinishRequest -> StandbyInfo
//
// Every write is for people only (owners and admins, read-write API keys);
// AI assistants on /mcp can read StandbyInfo but can't change anything.

// Standby statuses as the API shows them (StandbyView.Status).
const (
	StandbyPreparing = "preparing" // the primary is preparing the handoff
	StandbyCreating  = "creating"  // restoring on the standby's server
	StandbyReady     = "ready"     // following the primary
	StandbyLagging   = "lagging"   // following, but further behind than it should be
	StandbyDown      = "down"      // its agent or PostgreSQL isn't reporting
	StandbyFailed    = "failed"    // creating failed; see Error
	StandbyPromoting = "promoting" // being promoted
	StandbyPromoted  = "promoted"  // became the primary (history)
	StandbyRemoving  = "removing"
	StandbyRemoved   = "removed"
)

// StandbyInfo answers GET /v1/databases/{ref}/standby.
type StandbyInfo struct {
	DatabaseID string          `json:"database_id"`
	Database   string          `json:"database"`
	Primary    StandbyServer   `json:"primary"`
	Standby    *StandbyView    `json:"standby,omitempty"`
	Fences     []FenceView     `json:"fences,omitempty"`
	Failover   FailoverView    `json:"failover"`
	CanCreate  bool            `json:"can_create"`
	CreateHint string          `json:"create_hint,omitempty"` // why not, in plain words
	Events     []StandbyEvent  `json:"events"`
	Tasks      []TaskView      `json:"tasks,omitempty"` // recent standby tasks, newest first
	Connect    []ConnectString `json:"connect,omitempty"`
	// Move is the database's move to another server, if one is open or
	// finished recently (MoveView).
	Move *MoveView `json:"move,omitempty"`
}

// StandbyServer is a server in a standby pair.
type StandbyServer struct {
	HostID   string     `json:"host_id"`
	Hostname string     `json:"hostname"`
	Port     int        `json:"port"`
	LastSeen *time.Time `json:"last_seen,omitempty"`
	Online   bool       `json:"online"`
	// CanStop: the root helper there may stop and start this cluster.
	CanStop bool `json:"can_stop"`
	// Fingerprint is the server's agent key fingerprint (what
	// `rowsafe-agent key` prints there).
	Fingerprint string   `json:"fingerprint,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
}

// StandbyView is a standby as the API shows it.
type StandbyView struct {
	ID       string        `json:"id"`
	Server   StandbyServer `json:"server"`
	Status   string        `json:"status"`         // Standby* statuses
	Mode     string        `json:"mode,omitempty"` // StandbyMode*
	Rebuild  bool          `json:"rebuild,omitempty"`
	LagBytes *int64        `json:"lag_bytes,omitempty"`
	// LagSeconds estimates how far behind the standby is in time.
	LagSeconds     *float64   `json:"lag_seconds,omitempty"`
	LastReplayAt   *time.Time `json:"last_replay_at,omitempty"`
	ReportedAt     *time.Time `json:"reported_at,omitempty"`
	PrimaryAddress string     `json:"primary_address,omitempty"`
	// Note explains the mode in plain words (e.g. why it doesn't stream).
	Note      string     `json:"note,omitempty"`
	Error     string     `json:"error,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ReadyAt   *time.Time `json:"ready_at,omitempty"`
	// CanPromote and PromoteHint: whether Promote may be offered now.
	CanPromote  bool   `json:"can_promote"`
	PromoteHint string `json:"promote_hint,omitempty"`
	// PrimaryReachable: the primary's agent is online (the promotion stops
	// it first); otherwise a promotion needs the typed confirmation that
	// the primary is down or will stay stopped.
	PrimaryReachable bool `json:"primary_reachable"`
}

// FenceView is a fenced old primary.
type FenceView struct {
	ID      string        `json:"id"`
	Server  StandbyServer `json:"server"`
	Since   time.Time     `json:"since"`
	Reason  string        `json:"reason"`
	Stopped bool          `json:"stopped"` // its agent reported PostgreSQL stopped
	// CanUnfence: the standby didn't become the primary, so the old primary
	// may be started again (Unfence).
	CanUnfence bool        `json:"can_unfence,omitempty"`
	Clean      bool        `json:"clean"` // stopped before the promotion; the new standby can reuse its data
	State      *FenceState `json:"state,omitempty"`
	Released   bool        `json:"released,omitempty"`
}

// FailoverSettings configure automatic failover (off by default).
type FailoverSettings struct {
	Automatic bool `json:"automatic"`
	// AfterSeconds is how long every condition must hold (default 180).
	AfterSeconds int `json:"after_seconds"`
	// MaxDataLossSeconds bounds the changes a failover may lose (default
	// 60).
	MaxDataLossSeconds int `json:"max_data_loss_seconds"`
	// Confirm must be the database's name when turning automatic failover
	// on.
	Confirm string `json:"confirm,omitempty"`
}

// FailoverView is the settings plus what automatic failover sees now.
type FailoverView struct {
	FailoverSettings
	// Available: automatic failover can work for this pair (a standby that
	// streams: a second witness besides Rowsafe); Hint says why not.
	Available bool   `json:"available"`
	Hint      string `json:"hint,omitempty"`
	// Conditions are the checks automatic failover makes, as they stand.
	Conditions []FailoverCondition `json:"conditions,omitempty"`
}

// FailoverCondition is one of automatic failover's checks.
type FailoverCondition struct {
	Name  string     `json:"name"`
	Met   bool       `json:"met"`
	Since *time.Time `json:"since,omitempty"`
	Note  string     `json:"note,omitempty"`
}

// StandbyEvent is one entry of a database's standby timeline.
type StandbyEvent struct {
	ID      string    `json:"id"`
	At      time.Time `json:"at"`
	Kind    string    `json:"kind"` // created, ready, promoted, fenced, failover, rebuilt, removed, ...
	Message string    `json:"message"`
	Actor   string    `json:"actor,omitempty"`
}

// ConnectString is a copy-paste connection string that follows the
// primary.
type ConnectString struct {
	Driver string `json:"driver"` // psql, psycopg, pgx, jdbc, node-postgres
	Value  string `json:"value"`
	Note   string `json:"note,omitempty"`
}

// StandbyCandidate is a server that could hold the standby.
type StandbyCandidate struct {
	HostID      string   `json:"host_id"`
	Hostname    string   `json:"hostname"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Online      bool     `json:"online"`
	Addresses   []string `json:"addresses,omitempty"`
	// Ports are the clusters there the helper may stop and start and that
	// no Rowsafe database uses.
	Ports []int `json:"ports,omitempty"`
	// Usable and Reason: whether it can be picked, and why not.
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
}

// CreateStandbyRequest creates a standby on HostID's cluster on Port.
type CreateStandbyRequest struct {
	HostID string `json:"host_id"` // host ID or hostname
	Port   int    `json:"port,omitempty"`
	// Fingerprint must be the standby server's key fingerprint, as the
	// person compared it with what `rowsafe-agent key` prints there.
	Fingerprint string `json:"fingerprint"`
	// Stream: set up streaming when the standby can reach the primary
	// (default true). false: follow through the bucket only.
	Stream *bool `json:"stream,omitempty"`
}

// PromoteStandbyRequest promotes the standby.
type PromoteStandbyRequest struct {
	Confirm string `json:"confirm"` // the database's name
	// PrimaryDown must be "<primary hostname> is down" when the primary's
	// agent isn't reporting (Rowsafe can't stop it first).
	PrimaryDown string `json:"primary_down,omitempty"`
	// Force promotes even if the standby hasn't replayed everything the
	// stopped primary wrote (after a promote that stopped short).
	Force bool `json:"force,omitempty"`
}

// RebuildStandbyRequest turns the fenced old primary (FenceID) into the
// new standby.
type RebuildStandbyRequest struct {
	FenceID     string `json:"fence_id"`
	Fingerprint string `json:"fingerprint"`
	Confirm     string `json:"confirm"` // the database's name
}

// StandbyConfirmRequest confirms a removal with the database's name.
type StandbyConfirmRequest struct {
	Confirm string `json:"confirm"`
}

// UnfenceRequest starts the fenced primary FenceID again, when the
// promotion that fenced it didn't happen. Confirm is the database's name.
type UnfenceRequest struct {
	FenceID string `json:"fence_id"`
	Confirm string `json:"confirm"`
}

// Move statuses (MoveView.Status).
const (
	MoveSyncing   = "syncing"   // the new server is being set up or catching up
	MoveSwitching = "switching" // planned switchover in progress
	MoveMoved     = "moved"     // done: the old server is fenced, kept as a way back
	MoveFinished  = "finished"  // the old server was let go (or its time to switch back ran out)
	MoveCancelled = "cancelled" // stopped before switching; the database never moved
	MoveFailed    = "failed"    // setting up the new server failed; the database never moved
)

// MoveView is a move of the database to another server.
type MoveView struct {
	ID     string        `json:"id"`
	Status string        `json:"status"` // Move*
	From   StandbyServer `json:"from"`
	To     StandbyServer `json:"to"`
	// SwitchAt is when the switchover starts by itself (nil: when a person
	// says so). The new server must be in sync by then; otherwise it waits.
	SwitchAt   *time.Time `json:"switch_at,omitempty"`
	SwitchedAt *time.Time `json:"switched_at,omitempty"`
	// KeepUntil is how long the old server is kept (stopped, fenced) as a
	// way back: Switch back is offered until then.
	KeepDays  int        `json:"keep_days"`
	KeepUntil *time.Time `json:"keep_until,omitempty"`
	// Back: this move goes back to the server a previous move left.
	Back      bool   `json:"back,omitempty"`
	CanSwitch bool   `json:"can_switch"`
	Hint      string `json:"hint,omitempty"` // why not, or what it waits for
	// CanSwitchBack and CanFinish are offered once moved.
	CanSwitchBack bool      `json:"can_switch_back"`
	CanFinish     bool      `json:"can_finish"`
	Error         string    `json:"error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by,omitempty"`
	// Connect is how apps reach the database once moved (the new server
	// alone; and poolers were pointed at it).
	Connect []ConnectString `json:"connect,omitempty"`
}

// MoveRequest moves the database to HostID's empty cluster on Port.
type MoveRequest struct {
	HostID      string `json:"host_id"`
	Port        int    `json:"port,omitempty"`
	Fingerprint string `json:"fingerprint"` // the new server's key fingerprint, as compared
	// SwitchAt starts the switchover by itself at that time (nil: wait for
	// Switch now).
	SwitchAt *time.Time `json:"switch_at,omitempty"`
	// KeepDays keeps the old server as a way back (default 7, 1 to 30).
	KeepDays int   `json:"keep_days,omitempty"`
	Stream   *bool `json:"stream,omitempty"`
}

// MoveScheduleRequest sets (or, nil, clears) when the switchover starts.
type MoveScheduleRequest struct {
	SwitchAt *time.Time `json:"switch_at,omitempty"`
}

// MoveBackRequest moves the database back to the server the last move
// left: that server is turned into the standby (reusing its data), and the
// switchover happens as soon as it is in sync.
type MoveBackRequest struct {
	Confirm     string `json:"confirm"`     // the database's name
	Fingerprint string `json:"fingerprint"` // the old server's key fingerprint
}

// MoveFinishRequest lets the old server go (Remove old server): Rowsafe
// stops keeping it stopped. Confirm is its hostname.
type MoveFinishRequest struct {
	Confirm string `json:"confirm"`
}

// ForgetFenceRequest stops keeping a fenced old primary stopped (it stays
// stopped; Rowsafe just stops watching). Confirm is its hostname.
type ForgetFenceRequest struct {
	FenceID string `json:"fence_id"`
	Confirm string `json:"confirm"`
}
