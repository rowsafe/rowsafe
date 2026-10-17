package protocol

import "time"

// ---- A standby on servers without an account ----
//
// Without an account each server runs its own control plane
// (internal/localcp) and the two never talk through Rowsafe. What they
// share is the bucket, and both hold its passphrase: the standby's server
// is set up with the primary's bucket and passphrase, restores from it
// (StandbyCreateParams.FromBucket), and both derive the replication
// password from the passphrase (StandbyPrepareParams.Local). Nothing secret
// is typed, shown or sent between the servers.
//
// The pair's record (PrimaryRecord) is one small object in the database's
// folder of the bucket saying which server is the primary, or that the
// primary stopped for a switchover and where its last change is. The
// primary's fence writes "stopped", a promotion writes "primary", and every
// primary's agent reads it: one that finds another server promoted after
// it reports itself superseded, and its control plane fences it.
//
//	GET  /v1/databases/{ref}/standby              StandbyInfo (with Local)
//	POST /v1/databases/{ref}/standby              LocalStandbyRequest -> StandbyInfo (create, or rebuild a fenced old primary)
//	POST /v1/databases/{ref}/standby/link         LocalLinkRequest -> StandbyInfo (on the primary: let the standby stream)
//	POST /v1/databases/{ref}/standby/unlink       StandbyConfirmRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/fence        StandbyConfirmRequest -> StandbyInfo (on the primary: stop for a switchover)
//	POST /v1/databases/{ref}/standby/promote      PromoteStandbyRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/unfence      UnfenceRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/remove       StandbyConfirmRequest -> StandbyInfo
//	POST /v1/databases/{ref}/standby/forget-fence ForgetFenceRequest -> StandbyInfo
//
// Each answer's Tasks[0] is the task the request queued.

// PrimaryRecordPath is the record's place in the database's folder of the
// bucket (next to pgBackRest's archive/ and backup/).
const PrimaryRecordPath = "rowsafe/primary.json"

// Pair record states (PrimaryRecord.State).
const (
	PrimaryRecordPrimary = "primary" // Primary runs the database as its primary
	PrimaryRecordStopped = "stopped" // Primary stopped for good for a switchover, at CheckpointLSN
)

// PrimaryRecord is the pair's record in the bucket. MAC is HMAC-SHA256 over
// the other fields with a key derived from the bucket's passphrase, so only
// a server holding it can write one that counts.
type PrimaryRecord struct {
	Version  int    `json:"v"`
	Database string `json:"database"` // the stanza
	SystemID string `json:"system_id"`
	// Primary is the server's name; Fingerprint its agent key's
	// (KeyFingerprint), which identifies it.
	Primary     string `json:"primary"`
	Fingerprint string `json:"fingerprint"`
	State       string `json:"state"` // PrimaryRecord*
	// Timeline is the primary's timeline (a promotion's new one).
	Timeline int `json:"timeline,omitempty"`
	// CheckpointLSN is a stopped primary's last change (its shutdown
	// checkpoint): the standby promotes once it replayed past it.
	CheckpointLSN string `json:"checkpoint_lsn,omitempty"`
	// SwitchLSN is where a promotion's timeline starts: a cleanly stopped
	// old primary can follow the new one on its own data from there.
	SwitchLSN string    `json:"switch_lsn,omitempty"`
	At        time.Time `json:"at"`
	MAC       string    `json:"mac,omitempty"`
}

// PrimaryRecordState is what an agent read of a database's record
// (StandbyHeartbeat.Records).
type PrimaryRecordState struct {
	DatabaseID string `json:"database_id"`
	// Record is nil when the bucket has none (no promotion or fence yet).
	Record *PrimaryRecord `json:"record,omitempty"`
	// Mine: the record names this server.
	Mine bool `json:"mine,omitempty"`
	// Superseded: this server runs the database as its primary, and the
	// record says another server was promoted after it (the same system, a
	// later timeline). Its control plane fences it.
	Superseded bool `json:"superseded,omitempty"`
	// Error is why the record couldn't be read (the bucket, a record not
	// made with this passphrase, ...).
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

// LocalStandbyRequest turns this server's empty cluster on Port (or a
// fenced old primary of the database) into the database's standby.
type LocalStandbyRequest struct {
	// Port is the empty cluster (default: the only one Rowsafe may stop and
	// start that holds no database Rowsafe protects).
	Port int `json:"port,omitempty"`
	// PrimaryAddress (and PrimaryPort, default 5432) is where the standby
	// streams from; "" follows through the bucket only.
	PrimaryAddress string `json:"primary_address,omitempty"`
	PrimaryPort    int    `json:"primary_port,omitempty"`
	// Folder is the backups' folder in the bucket (default: the name).
	Folder  string `json:"folder,omitempty"`
	Confirm string `json:"confirm"` // the database's name
}

// LocalLinkRequest lets a standby at Addresses stream from this server's
// database.
type LocalLinkRequest struct {
	Addresses []string `json:"addresses"`
}

// Server roles in a pair without an account (LocalStandby.Role).
const (
	LocalRolePrimary = "primary"
	LocalRoleStandby = "standby"
	LocalRoleFenced  = "fenced"
)

// LocalStandby is StandbyInfo's part on a server without an account.
type LocalStandby struct {
	Role string `json:"role"` // LocalRole*
	// Link is the standby the primary lets stream (link).
	Link *LocalLink `json:"link,omitempty"`
	// PrimaryAddress is where the standby streams from ("" through the
	// bucket only); Folder the backups' folder.
	PrimaryAddress string `json:"primary_address,omitempty"`
	Folder         string `json:"folder,omitempty"`
	// Record is the pair's record as this server's agent last read it.
	Record      *PrimaryRecord `json:"record,omitempty"`
	RecordError string         `json:"record_error,omitempty"`
	RecordAt    *time.Time     `json:"record_at,omitempty"`
	// PromoteNeedsDown: the record doesn't say the primary stopped, so a
	// promotion needs the typed PromoteStandbyRequest.PrimaryDown, which
	// must be DownConfirm.
	PromoteNeedsDown bool   `json:"promote_needs_down,omitempty"`
	DownConfirm      string `json:"down_confirm,omitempty"`
}

// LocalLink is a standby a primary lets stream.
type LocalLink struct {
	StandbyID string    `json:"standby_id"`
	Addresses []string  `json:"addresses"`
	Role      string    `json:"replication_role,omitempty"`
	Streaming bool      `json:"streaming"` // the role and pg_hba lines are in place
	CreatedAt time.Time `json:"created_at"`
	Warnings  []string  `json:"warnings,omitempty"`
}
