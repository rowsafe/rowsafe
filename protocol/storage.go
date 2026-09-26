package protocol

import "time"

// ---- Rowsafe Storage ----
//
// Rowsafe Storage is a bucket Rowsafe operates, so a new server needs no
// bucket of its own. Backups are still encrypted on the server with the
// passphrase generated there (ROWSAFE_REPO_CIPHER_PASS), which Rowsafe never
// has: the bucket only ever holds ciphertext. Agents get short-lived
// credentials scoped to their organization's prefix and renew them well
// before they expire.

// Storage modes (ROWSAFE_STORAGE on the host, StorageStatus.Mode).
const (
	StorageOwn     = "own"     // the customer's own bucket (ROWSAFE_REPO_S3_*)
	StorageRowsafe = "rowsafe" // Rowsafe Storage
)

// StorageCredentials answers POST /v1/agent/storage/credentials: where the
// repository is and temporary credentials for it. The agent keeps them in
// its state directory (0600) and in the pgBackRest configs it renders.
type StorageCredentials struct {
	Endpoint   string `json:"endpoint"` // host name, no scheme
	Port       int    `json:"port,omitempty"`
	Region     string `json:"region"`
	URIStyle   string `json:"uri_style"`
	Bucket     string `json:"bucket"`
	PathPrefix string `json:"path_prefix"` // e.g. /orgs/org_123; stanzas live below it

	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`

	ExpiresAt time.Time `json:"expires_at"`
	// RefreshAt is when the agent should ask for new credentials; well
	// before ExpiresAt, so a control plane outage of days doesn't stop WAL
	// archiving.
	RefreshAt time.Time `json:"refresh_at"`
}

// StorageStatus is the agent's storage state, sent with every heartbeat.
type StorageStatus struct {
	Mode string `json:"mode"` // StorageOwn or StorageRowsafe
	// Repo identifies the repository without revealing anything secret
	// (a hash of endpoint, bucket and path prefix). It changes when the
	// host moves to another bucket; the control plane then takes a new
	// full backup there.
	Repo string `json:"repo,omitempty"`
	// Rowsafe Storage only: when the credentials the agent holds expire,
	// and why the last renewal failed ("" when it worked).
	CredentialsExpireAt *time.Time `json:"credentials_expire_at,omitempty"`
	RefreshError        string     `json:"refresh_error,omitempty"`
}

// StorageOffer answers GET /v1/storage/offer (no authentication): whether
// this control plane offers Rowsafe Storage. The installer asks it before
// showing the choice.
type StorageOffer struct {
	Available bool `json:"available"`
	// FreeBytes is what the free plan includes.
	FreeBytes int64 `json:"free_bytes,omitempty"`
}

// Storage quota states (OrgStorage.State).
const (
	StorageQuotaOK      = "ok"
	StorageQuotaWarning = "warning" // at or above 80% of the quota
	StorageQuotaOver    = "over"    // full backups paused; WAL keeps flowing
)

// OrgStorage answers GET /v1/org/storage.
type OrgStorage struct {
	// Available: this control plane offers Rowsafe Storage.
	Available  bool       `json:"available"`
	Plan       string     `json:"plan"`
	QuotaBytes int64      `json:"quota_bytes"`
	UsedBytes  int64      `json:"used_bytes"`
	MeasuredAt *time.Time `json:"measured_at,omitempty"`
	// State is StorageQuotaOK, StorageQuotaWarning or StorageQuotaOver.
	State string `json:"state"`
	// Hosts are the servers of the org and where each keeps its backups.
	Hosts []StorageHost `json:"hosts"`
	// Databases are the database prefixes in Rowsafe Storage and their size.
	Databases []StorageDatabase `json:"databases"`
	// Deletions are backups in Rowsafe Storage scheduled for deletion
	// (removed databases, servers moved to their own bucket).
	Deletions []StorageDeletion `json:"deletions"`
}

type StorageHost struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Mode     string `json:"mode"` // "" when the agent hasn't said yet
	// CredentialsExpireAt: Rowsafe Storage credentials held by the agent.
	CredentialsExpireAt *time.Time `json:"credentials_expire_at,omitempty"`
	RefreshError        string     `json:"refresh_error,omitempty"`
}

type StorageDatabase struct {
	Name       string `json:"name"`
	DatabaseID string `json:"database_id,omitempty"` // "" for a removed database
	Bytes      int64  `json:"bytes"`
}

type StorageDeletion struct {
	Prefix   string     `json:"prefix"`
	Name     string     `json:"name"`   // the database name (the stanza)
	Reason   string     `json:"reason"` // "database_removed", "moved", "org_deleted"
	DeleteAt time.Time  `json:"delete_at"`
	Bytes    int64      `json:"bytes"`
	WarnedAt *time.Time `json:"warned_at,omitempty"`
}

// Reasons for a StorageDeletion.
const (
	StorageDeletionRemoved    = "database_removed"
	StorageDeletionMoved      = "moved"
	StorageDeletionOrgDeleted = "org_deleted"
)
