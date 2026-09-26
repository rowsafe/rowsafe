package protocol

import "time"

// ---- Second backup copy and storage costs ----
//
// A second copy keeps the database's backups and change log (WAL) in a
// second bucket, usually at another provider, so losing one bucket, one
// account or one provider never loses the backups (the 3-2-1 rule: the
// database, two copies, one of them elsewhere). The second copy is set up on
// the server (`install.sh --add-storage`): its keys and its own encryption
// passphrase stay there, like the first storage's. The control plane only
// sees where it is (provider, endpoint, bucket), sizes, and how the copy is
// doing.
//
// PostgreSQL archives WAL to the first storage exactly as before, and only
// then hands a copy to a local queue that the agent sends on to the second
// storage. So a second storage that is down or slow never holds PostgreSQL
// up: its queue is capped (SecondCopyQueueMaxFiles), and WAL that doesn't
// fit is left out of the second copy (a gap, reported) rather than kept on
// the server's disk. The next full backup to the second copy closes the gap.

// Repositories (the Repo fields of BackupParams, DrillParams,
// RewindTarget...). 0 means the first storage.
const (
	RepoPrimary = 1 // the first storage (ROWSAFE_REPO_*)
	RepoSecond  = 2 // the second copy (ROWSAFE_REPO2_*)
)

// SecondCopyQueueMaxFiles bounds the local queue of WAL files waiting to go
// to the second storage (16 MiB each by default: 4 GiB). Beyond it,
// archive_command leaves files out of the second copy instead of filling
// the disk.
const SecondCopyQueueMaxFiles = 256

// DefaultSecondCopyRetentionFull is how many full backups the second copy
// keeps unless the control plane says otherwise (DatabaseSpec).
const DefaultSecondCopyRetentionFull = 2

// Storage providers (RepoInfo.Provider), recognized from the endpoint.
const (
	ProviderR2     = "r2"
	ProviderS3     = "s3"
	ProviderB2     = "b2"
	ProviderWasabi = "wasabi"
	ProviderSpaces = "spaces"
	ProviderPosix  = "posix" // a local or mounted directory (tests)
	ProviderOther  = "other"
)

// RepoInfo says where a repository is. It carries no secrets.
type RepoInfo struct {
	Repo     int    `json:"repo"`               // RepoPrimary or RepoSecond
	Provider string `json:"provider"`           // Provider*
	Endpoint string `json:"endpoint,omitempty"` // host[:port]
	Bucket   string `json:"bucket,omitempty"`
	Region   string `json:"region,omitempty"`
}

// DrillParams are the (optional) params of a drill task (Proof).
type DrillParams struct {
	// Repo is the storage to restore from: 0 or RepoPrimary for the first,
	// RepoSecond for the second copy.
	Repo int `json:"repo,omitempty"`
}

// RepoBackup is one backup in a repository, with the space it takes there.
type RepoBackup struct {
	Label     string    `json:"label"`
	Type      string    `json:"type"` // full | diff | incr
	StoppedAt time.Time `json:"stopped_at"`
	// StoredBytes is what the backup's own files take in the repository
	// (compressed and encrypted); a differential shares the rest with its
	// full backup.
	StoredBytes int64 `json:"stored_bytes"`
}

// RepoStorage is one database's use of one repository, measured by the
// agent (HeartbeatRequest.Storage): about every 6 hours and after each
// backup. The agent keeps sending its last measurement.
type RepoStorage struct {
	DatabaseID string `json:"database_id"`
	RepoInfo
	MeasuredAt  time.Time    `json:"measured_at"`
	TotalBytes  int64        `json:"total_bytes"`  // everything under the database's path
	WALBytes    int64        `json:"wal_bytes"`    // the archived change log
	BackupBytes int64        `json:"backup_bytes"` // the backups
	WALFiles    int          `json:"wal_files"`
	Backups     []RepoBackup `json:"backups,omitempty"` // oldest first
	// Error says, in pgBackRest's words, why measuring failed (the
	// repository was unreachable, ...). The sizes are then zero.
	Error string `json:"error,omitempty"`
}

// SecondCopyStatus is how WAL is getting to the second copy
// (HeartbeatRequest.SecondCopies), reported in every heartbeat while a
// second copy is configured on the host.
type SecondCopyStatus struct {
	DatabaseID string `json:"database_id"`
	RepoInfo
	// Ready: the second storage is initialized for this database (its
	// stanza exists). Until then nothing can be sent to it.
	Ready bool `json:"ready"`
	// Queued WAL files waiting on the server to be sent, and their size.
	QueuedFiles  int        `json:"queued_files"`
	QueuedBytes  int64      `json:"queued_bytes"`
	OldestQueued *time.Time `json:"oldest_queued,omitempty"`
	// SentCount counts WAL files sent since the agent started.
	SentCount  int64      `json:"sent_count"`
	LastSent   string     `json:"last_sent,omitempty"`
	LastSentAt *time.Time `json:"last_sent_at,omitempty"`
	// FailingSince is when sending started failing (nil while it works).
	FailingSince *time.Time `json:"failing_since,omitempty"`
	FailedCount  int64      `json:"failed_count"`
	LastError    string     `json:"last_error,omitempty"`
	// GapSince: WAL was left out of the second copy since this time (its
	// queue was full, or the agent couldn't queue a file), so the second
	// copy can't restore past that point until a new full backup reaches
	// it. Cleared by the next full backup to the second copy.
	GapSince *time.Time `json:"gap_since,omitempty"`
	// SkippedFiles counts the WAL files left out since GapSince.
	SkippedFiles int `json:"skipped_files,omitempty"`
}

// ---- Storage user API ----
//
//	GET /v1/databases/{ref}/storage   StorageOverview

// StorageOverview answers GET /v1/databases/{ref}/storage: how much space
// the backups take, what it costs, how it grows, and the second copy.
type StorageOverview struct {
	DatabaseID string `json:"database_id"`
	Database   string `json:"database"`
	Host       string `json:"host"`
	// Repos lists the storages, first storage first. Empty until the agent
	// has measured (a few minutes after a backup).
	Repos []RepoCost `json:"repos"`
	// TotalBytes and MonthlyCost add up the repositories; MonthlyCost is
	// nil when a price is unknown.
	TotalBytes  int64    `json:"total_bytes"`
	MonthlyCost *float64 `json:"monthly_cost,omitempty"`
	// Trend is the daily total over the last 90 days, oldest first.
	Trend []StoragePoint `json:"trend"`
	// Growth30d is the change in TotalBytes over the last 30 days (nil
	// with less than a week of history).
	Growth30d *int64 `json:"growth_30d,omitempty"`
	// SecondCopy is the second copy's state; nil when there is none.
	SecondCopy *SecondCopyView `json:"second_copy,omitempty"`
	// AddSecondCopy is how to add (or change) the second copy: it is set up
	// on the server, because its keys never leave it.
	AddSecondCopy SecondCopySetup `json:"add_second_copy"`
	// Tips are ways to spend less, each backed by a health fix.
	Tips []StorageTip `json:"tips,omitempty"`
	// Prices says where the prices come from.
	Prices PriceSource `json:"prices"`
}

// RepoCost is one storage's size and estimated monthly cost.
type RepoCost struct {
	RepoInfo
	ProviderName string       `json:"provider_name"` // "Cloudflare R2"
	MeasuredAt   *time.Time   `json:"measured_at,omitempty"`
	TotalBytes   int64        `json:"total_bytes"`
	WALBytes     int64        `json:"wal_bytes"`
	BackupBytes  int64        `json:"backup_bytes"`
	Backups      []RepoBackup `json:"backups,omitempty"`
	FullBackups  int          `json:"full_backups"`
	// RetentionFull is how many full backups this storage keeps.
	RetentionFull int `json:"retention_full"`
	// MonthlyCost is the estimate for this database's part (nil: price
	// unknown for this provider). The provider's minimums count as if this
	// database were the only thing in the account.
	MonthlyCost *float64 `json:"monthly_cost,omitempty"`
	// PriceNote says how the estimate was made, e.g. "$0.015 per GB-month;
	// the first 10 GB of the account are free".
	PriceNote string `json:"price_note"`
	// Error is why the last measurement failed.
	Error string `json:"error,omitempty"`
}

// StoragePoint is one day's total size.
type StoragePoint struct {
	Day   string `json:"day"` // 2006-01-02 (UTC)
	Bytes int64  `json:"bytes"`
	// ByRepo splits Bytes by repository ("1", "2").
	ByRepo map[string]int64 `json:"by_repo,omitempty"`
}

// Second copy states (SecondCopyView.State).
const (
	SecondCopySettingUp  = "setting_up"  // configured, nothing sent yet
	SecondCopyOK         = "ok"          // WAL arrives; a full backup is there
	SecondCopyCatchingUp = "catching_up" // sending a backlog
	SecondCopyNoBackup   = "no_backup"   // WAL arrives, no full backup yet
	SecondCopyFailing    = "failing"     // sending fails
	SecondCopyGap        = "gap"         // WAL was left out: needs a full backup
	SecondCopyStale      = "stale"       // the agent stopped reporting it
)

// SecondCopyView is the second copy as the API shows it.
type SecondCopyView struct {
	RepoInfo
	ProviderName string `json:"provider_name"`
	State        string `json:"state"`   // SecondCopy*
	Summary      string `json:"summary"` // plain words
	// Behind is how far the copy is behind the first storage (queued WAL).
	QueuedFiles  int        `json:"queued_files"`
	QueuedBytes  int64      `json:"queued_bytes"`
	LastSentAt   *time.Time `json:"last_sent_at,omitempty"`
	FailingSince *time.Time `json:"failing_since,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
	GapSince     *time.Time `json:"gap_since,omitempty"`
	LastBackupAt *time.Time `json:"last_backup_at,omitempty"`
	LastFullAt   *time.Time `json:"last_full_at,omitempty"`
	ReportedAt   *time.Time `json:"reported_at,omitempty"`
	// ScheduleFull is when full backups go to the second copy (cron, UTC).
	ScheduleFull  string `json:"schedule_full"`
	RetentionFull int    `json:"retention_full"`
	// LastProofAt and LastProofPassed describe the newest Proof restored
	// from the second copy.
	LastProofAt     *time.Time `json:"last_proof_at,omitempty"`
	LastProofPassed *bool      `json:"last_proof_passed,omitempty"`
}

// SecondCopySetup is what the dashboard shows to add a second copy.
type SecondCopySetup struct {
	// Command is the one command to run on the server, e.g.
	// curl -fsSL https://rowsafe.sh | sudo sh -s -- --add-storage
	Command string `json:"command"`
	Host    string `json:"host"`
	// Why explains, in plain words, why it runs on the server.
	Why string `json:"why"`
}

// StorageTip is a way to spend less on storage; FindingID and FixID name
// the health fix that does it (Apply fix).
type StorageTip struct {
	Title         string  `json:"title"`
	Detail        string  `json:"detail"`
	MonthlySaving float64 `json:"monthly_saving"`
	FindingID     string  `json:"finding_id"`
	FixID         string  `json:"fix_id"`
}

// PriceSource is where the price table comes from.
type PriceSource struct {
	AsOf string `json:"as_of"` // 2026-09
	Note string `json:"note"`
}

// FixRetention changes how many full backups a storage keeps (params
// RetentionFixParams). It queues no task: the new setting takes effect when
// the next backup to that storage expires old ones.
const FixRetention = "retention"

// RetentionFixParams are the params of a retention fix.
type RetentionFixParams struct {
	Repo          int `json:"repo"`
	RetentionFull int `json:"retention_full"`
}
