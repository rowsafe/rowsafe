package protocol

import (
	"regexp"
	"time"
)

// ---- Guard: migration previews and safe copies ----
//
// Both run on a copy the agent restores next to production (the Rewind copy
// machinery): production itself is never touched. A preview runs a
// migration on the copy and reports what it did (locks, rewrites, rows,
// time) with a verdict. A safe copy is a masked copy that listens on a TCP
// port of the database server for developers and AI agents. Masking happens
// on the server before the copy opens; the data never leaves it. Only names,
// counts, sizes and timings reach the control plane.

// Task types.
const (
	// TaskPreviewMigration runs SQL on a fresh copy of the database
	// (PreviewParams -> PreviewResult). A preview copy restored recently is
	// reused (the migration runs on a clone of the database inside it).
	TaskPreviewMigration = "preview_migration"
	// TaskSafeCopy restores a copy, masks it, and opens it on a TCP port for
	// the allowed addresses (SafeCopyParams -> SafeCopyResult).
	TaskSafeCopy = "safe_copy"
	// TaskCopySchema lists production's tables and columns, for reviewing
	// masking rules (CopySchemaParams -> CopySchemaResult). Read-only, catalog
	// only: no row is read.
	TaskCopySchema = "copy_schema"
)

// Copy kinds (CopyState.Kind).
const (
	CopyKindPreview = "preview" // kept for a while so the next preview starts fast
	CopyKindSafe    = "safe"    // a masked copy reachable over TCP
)

// Copy statuses (CopyState.Status, SafeCopy.Status).
const (
	CopyRestoring = "restoring"
	CopyMasking   = "masking"
	CopyReady     = "ready"
	CopyFailed    = "failed"   // control plane only: the task failed
	CopyDeleting  = "deleting" // control plane only: asked the agent to delete it
	CopyRemoved   = "removed"  // control plane only: gone (deleted or expired)
)

// Preview verdicts.
const (
	PreviewSafe      = "safe"
	PreviewCareful   = "careful"
	PreviewDangerous = "dangerous"
	PreviewFailed    = "failed" // the migration failed on the copy
)

// PreviewParams are the params of a preview_migration task.
type PreviewParams struct {
	PreviewID string `json:"preview_id"` // [A-Za-z0-9_-]{1,32}
	SQL       string `json:"sql"`
	// DB is the PostgreSQL database (datname) the migration runs in. Empty:
	// the one named like the Rowsafe database, or the only one.
	DB string `json:"db,omitempty"`
	// FreshMinutes: reuse a preview copy whose data is at most this old
	// (default 60). -1 always restores a new copy.
	FreshMinutes int `json:"fresh_minutes,omitempty"`
	// TimeoutSeconds caps the migration's run on the copy (default 1800, at
	// most 14400).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// Preview run modes (PreviewResult.Mode).
const (
	// PreviewInTransaction: the whole migration ran in one transaction,
	// committed at the end (what most migration tools do).
	PreviewInTransaction = "transaction"
	// PreviewAsWritten: the SQL manages its own transactions or has
	// statements that can't run in one (CREATE INDEX CONCURRENTLY, VACUUM),
	// so each statement ran as written, like psql would.
	PreviewAsWritten = "as_written"
)

// PreviewResult is the agent's report for a preview_migration task. It
// comes back with a failed task too when the migration itself failed
// (Verdict PreviewFailed, Error set).
type PreviewResult struct {
	PreviewID string `json:"preview_id"`
	Verdict   string `json:"verdict"`
	// Summary is one or two plain sentences, e.g. "Dangerous: ALTER TABLE
	// orders rewrites 3.1 GB and blocks writes for about 2 min."
	Summary string `json:"summary"`
	DB      string `json:"db"`
	Mode    string `json:"mode"`
	// DataAsOf is when the copy's data is from (its last replayed change).
	DataAsOf   *time.Time `json:"data_as_of,omitempty"`
	CopyReused bool       `json:"copy_reused"`
	// RestoreMs is how long restoring the copy took (0 when reused).
	RestoreMs  int64              `json:"restore_ms"`
	DurationMs int64              `json:"duration_ms"` // the migration itself
	Statements []PreviewStatement `json:"statements"`
	Findings   []PreviewFinding   `json:"findings,omitempty"`
	Error      *PreviewError      `json:"error,omitempty"`
}

// PreviewStatement is what one statement did on the copy.
type PreviewStatement struct {
	N       int    `json:"n"`    // 1-based position in the SQL
	Line    int    `json:"line"` // line where it starts
	SQL     string `json:"sql"`  // the statement (shortened)
	Command string `json:"command"`
	// Ran is false for statements after a failure (not run).
	Ran        bool   `json:"ran"`
	DurationMs int64  `json:"duration_ms"`
	Rows       *int64 `json:"rows,omitempty"` // rows inserted, updated, deleted or copied
	// Locks on tables and indexes that existed before the migration, i.e.
	// what production's queries would wait for.
	Locks       []PreviewLock     `json:"locks,omitempty"`
	Rewrites    []PreviewRelation `json:"rewrites,omitempty"`     // tables rewritten (new file)
	IndexBuilds []PreviewRelation `json:"index_builds,omitempty"` // indexes built or rebuilt
	Dropped     []PreviewRelation `json:"dropped,omitempty"`      // tables that existed and are gone
	Risk        string            `json:"risk"`                   // PreviewSafe | PreviewCareful | PreviewDangerous
	// Impact is the estimated effect on production, in plain words.
	Impact string `json:"impact,omitempty"`
	Error  string `json:"error,omitempty"`
	// Superuser: Rowsafe ran it as a superuser before the migration
	// (CREATE EXTENSION); everything else runs as a regular role.
	Superuser bool `json:"superuser,omitempty"`
}

// PreviewLock is a lock the migration took on an existing relation.
type PreviewLock struct {
	Relation string `json:"relation"` // schema.name
	Mode     string `json:"mode"`     // e.g. AccessExclusiveLock
	// Blocks is what the lock stops on production: "reads and writes",
	// "writes", "schema changes" or "" (nothing ordinary).
	Blocks string `json:"blocks,omitempty"`
	// HeldMs is how long it was held: until the end of the statement, or of
	// the whole migration when it ran in one transaction.
	HeldMs int64 `json:"held_ms"`
	// SizeBytes is the relation's size before the migration.
	SizeBytes int64 `json:"size_bytes,omitempty"`
}

// PreviewRelation is a table or index a statement rewrote or built.
type PreviewRelation struct {
	Name      string `json:"name"`            // schema.name
	Table     string `json:"table,omitempty"` // for an index: its table
	SizeBytes int64  `json:"size_bytes"`      // before the migration (0: new)
	Rows      int64  `json:"rows,omitempty"`  // estimated
}

// PreviewFinding is one heuristic finding with a suggestion.
type PreviewFinding struct {
	Rule       string `json:"rule"`
	Severity   string `json:"severity"`            // PreviewCareful | PreviewDangerous
	Statement  int    `json:"statement,omitempty"` // PreviewStatement.N; 0 = the whole migration
	Title      string `json:"title"`
	Detail     string `json:"detail,omitempty"`
	Suggestion string `json:"suggestion,omitempty"`
}

// PreviewError is where and why the migration failed. Values from the data
// (a row that broke a constraint...) are left out: they stay in the agent's
// log on the server.
type PreviewError struct {
	Statement int    `json:"statement"`
	Line      int    `json:"line"`
	Code      string `json:"code,omitempty"` // SQLSTATE
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
}

// ---- Masking ----

// Masking modes (SafeCopyParams.Masking.Mode).
const (
	MaskingRules = "rules" // saved rules, and suggestions for every column they don't cover
	MaskingNone  = "none"  // no masking: an admin chose it explicitly
)

// MaskingRule masks one column with a strategy (see package masking).
type MaskingRule struct {
	DB       string `json:"db"`
	Table    string `json:"table"` // schema.name
	Column   string `json:"column"`
	Strategy string `json:"strategy"`
}

// MaskingPlan is how a safe copy is masked.
type MaskingPlan struct {
	Mode  string        `json:"mode"`
	Rules []MaskingRule `json:"rules,omitempty"`
}

// MaskingReport says what masking did.
type MaskingReport struct {
	Mode    string `json:"mode"`
	Tables  int    `json:"tables"`
	Columns int    `json:"columns"`
	Rows    int64  `json:"rows"`
	// Strategies counts masked columns per strategy.
	Strategies map[string]int `json:"strategies,omitempty"`
	// Skipped lists rules not applied, with a plain reason.
	Skipped    []string `json:"skipped,omitempty"`
	DurationMs int64    `json:"duration_ms"`
}

// ---- Safe copies ----

// CopyAccess is who can reach a safe copy and how.
type CopyAccess struct {
	// Listen is the server address the copy listens on (besides
	// localhost): one of CopiesReport.Addresses, or "*" for all of them.
	Listen string `json:"listen"`
	// AllowFrom are the client addresses (IP or CIDR) pg_hba lets in; at
	// least one.
	AllowFrom []string `json:"allow_from"`
	// Role is the login role created on the copy; PasswordVerifier its
	// SCRAM-SHA-256 verifier (the password itself never reaches Rowsafe's
	// agent or, when the requester made it, Rowsafe at all).
	Role             string `json:"role"`
	PasswordVerifier string `json:"password_verifier"`
}

// SafeCopyParams are the params of a safe_copy task.
type SafeCopyParams struct {
	CopyID  string      `json:"copy_id"` // [A-Za-z0-9_-]{1,32}
	Expires time.Time   `json:"expires"` // default 24h, at most 7 days
	Masking MaskingPlan `json:"masking"`
	Access  CopyAccess  `json:"access"`
}

// SafeCopyResult is the agent's report for a safe_copy task.
type SafeCopyResult struct {
	CopyID      string     `json:"copy_id"`
	Listen      string     `json:"listen"`
	Port        int        `json:"port"`
	Role        string     `json:"role"`
	Databases   []string   `json:"databases"`
	SizeBytes   int64      `json:"size_bytes"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	Expires     time.Time  `json:"expires"`
	// TLSCert is the copy's certificate (PEM; public). Self-signed unless
	// the host has one configured (TLSOwnCert).
	TLSCert    string        `json:"tls_cert"`
	TLSOwnCert bool          `json:"tls_own_cert,omitempty"`
	Masking    MaskingReport `json:"masking"`
	Summary    string        `json:"summary"`
}

// CopySchemaParams are the params of a copy_schema task.
type CopySchemaParams struct{}

// CopySchemaResult lists production's tables and columns (no rows).
type CopySchemaResult struct {
	Databases []SchemaDatabase `json:"databases"`
	// Truncated: the schema was too large and was cut (the first tables by
	// name are listed).
	Truncated bool `json:"truncated,omitempty"`
}

type SchemaDatabase struct {
	Name   string        `json:"name"`
	Tables []SchemaTable `json:"tables"`
}

type SchemaTable struct {
	Name      string         `json:"name"` // schema.name
	Rows      int64          `json:"rows"` // estimate
	SizeBytes int64          `json:"size_bytes"`
	Columns   []SchemaColumn `json:"columns"`
}

type SchemaColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"` // format_type, e.g. "character varying(255)"
	Nullable bool   `json:"nullable,omitempty"`
	// Unique: the column alone has a unique index.
	Unique bool `json:"unique,omitempty"`
	// Generated columns can't be masked (they follow their inputs).
	Generated bool `json:"generated,omitempty"`
}

// ---- Heartbeat ----

// CopiesReport is sent in every heartbeat (HeartbeatRequest.Copies) by
// agents that support Guard copies.
type CopiesReport struct {
	Copies []CopyState `json:"copies,omitempty"`
	// Addresses are the server's own IP addresses a safe copy can listen
	// on. Empty on Docker sidecars (a copy there can't be reached).
	Addresses []HostAddress `json:"addresses,omitempty"`
	// OwnTLSCert: the host has a certificate configured for copies
	// (otherwise each copy makes a self-signed one).
	OwnTLSCert bool `json:"own_tls_cert,omitempty"`
}

// CopyState is a preview or safe copy on the host.
type CopyState struct {
	ID          string     `json:"id"`
	DatabaseID  string     `json:"database_id"`
	Kind        string     `json:"kind"`   // CopyKind*
	Status      string     `json:"status"` // CopyRestoring | CopyMasking | CopyReady
	SizeBytes   int64      `json:"size_bytes"`
	CreatedAt   time.Time  `json:"created_at"`
	Expires     *time.Time `json:"expires,omitempty"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	Listen      string     `json:"listen,omitempty"`
	Port        int        `json:"port,omitempty"`
}

// HostAddress is one IP address of the server.
type HostAddress struct {
	IP        string `json:"ip"`
	Interface string `json:"interface"`
	// Private: RFC 1918, CGNAT (100.64/10, e.g. Tailscale), IPv6 ULA or
	// link-local; reachable only from a private network or VPN.
	Private bool `json:"private"`
}

// CopiesUpdate is the heartbeat response's instructions for copies
// (HeartbeatResponse.Copies).
type CopiesUpdate struct {
	// Expires moves expiry times (Extend). Clamped to 7 days from now.
	Expires []RewindExpiry `json:"expires,omitempty"`
	// Drop lists copies to delete now (Delete in the dashboard). Unknown
	// IDs are ignored.
	Drop []string `json:"drop,omitempty"`
}

// ---- User API ----
//
//	POST   /v1/databases/{ref}/previews                    CreatePreviewRequest -> Preview
//	GET    /v1/databases/{ref}/previews                    -> []Preview (newest first, without statements)
//	GET    /v1/previews/{id}                               -> Preview
//	GET    /v1/databases/{ref}/safe-copies                 -> SafeCopiesInfo
//	POST   /v1/databases/{ref}/safe-copies                 CreateSafeCopyRequest -> CreateSafeCopyResponse
//	DELETE /v1/databases/{ref}/safe-copies/{id}            -> SafeCopy
//	POST   /v1/databases/{ref}/safe-copies/{id}/extend     ExtendSafeCopyRequest -> SafeCopy
//	GET    /v1/databases/{ref}/masking                     -> MaskingInfo
//	PUT    /v1/databases/{ref}/masking                     PutMaskingRequest -> MaskingInfo
//	POST   /v1/databases/{ref}/masking/refresh             -> MaskingInfo (queues copy_schema)

// Preview is a migration preview as the API shows it.
type Preview struct {
	ID         string `json:"id"`
	DatabaseID string `json:"database_id"`
	Database   string `json:"database"`
	// Status is the task's: queued, running, succeeded, failed, lost or
	// cancelled. A migration that failed on the copy is "succeeded" with
	// Verdict failed: the preview itself worked.
	Status  string `json:"status"`
	Verdict string `json:"verdict,omitempty"`
	Summary string `json:"summary,omitempty"`
	// Label names the SQL (e.g. a migration file name).
	Label      string         `json:"label,omitempty"`
	Source     string         `json:"source,omitempty"` // dashboard, cli, action, mcp, api
	SQLBytes   int            `json:"sql_bytes"`
	DB         string         `json:"db,omitempty"`
	CreatedBy  string         `json:"created_by,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	StartedAt  *time.Time     `json:"started_at,omitempty"`
	FinishedAt *time.Time     `json:"finished_at,omitempty"`
	TaskID     string         `json:"task_id"`
	Error      string         `json:"error,omitempty"` // why the preview couldn't run
	Result     *PreviewResult `json:"result,omitempty"`
}

// CreatePreviewRequest previews SQL on a copy.
type CreatePreviewRequest struct {
	SQL    string `json:"sql"`
	DB     string `json:"db,omitempty"`
	Label  string `json:"label,omitempty"`
	Source string `json:"source,omitempty"`
	// FreshMinutes: see PreviewParams (0 = default).
	FreshMinutes int `json:"fresh_minutes,omitempty"`
}

// SafeCopy is a safe copy as the API shows it.
type SafeCopy struct {
	ID         string    `json:"id"`
	DatabaseID string    `json:"database_id"`
	Status     string    `json:"status"`
	Masked     bool      `json:"masked"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	Expires    time.Time `json:"expires"`
	// Host and Port are where clients connect; DB the database in the
	// connection string; Role the login role.
	Host      string   `json:"host"`
	Port      int      `json:"port,omitempty"`
	DB        string   `json:"db,omitempty"`
	Role      string   `json:"role"`
	AllowFrom []string `json:"allow_from"`
	// ConnectionString has no password: it was shown once, when the copy
	// was created.
	ConnectionString string         `json:"connection_string,omitempty"`
	SizeBytes        int64          `json:"size_bytes,omitempty"`
	RecoveredTo      *time.Time     `json:"recovered_to,omitempty"`
	TLSCert          string         `json:"tls_cert,omitempty"`
	Masking          *MaskingReport `json:"masking,omitempty"`
	TaskID           string         `json:"task_id"`
	// Task is the safe_copy task while it runs or when it failed.
	Task  *TaskView `json:"task,omitempty"`
	Error string    `json:"error,omitempty"`
}

// SafeCopiesInfo answers GET /v1/databases/{ref}/safe-copies.
type SafeCopiesInfo struct {
	Copies []SafeCopy `json:"copies"`
	// Limit and Used count live safe copies across the organization.
	Limit int `json:"limit"`
	Used  int `json:"used"`
	// Available says whether a safe copy can be created now; Reason says
	// why not, in plain words.
	Available bool          `json:"available"`
	Reason    string        `json:"reason,omitempty"`
	Addresses []HostAddress `json:"addresses,omitempty"`
	// ClientIP is the caller's address as Rowsafe sees it (a sensible
	// AllowFrom default).
	ClientIP string `json:"client_ip,omitempty"`
	// Preview is the kept preview copy, if one exists.
	Preview *CopyState `json:"preview,omitempty"`
}

// CreateSafeCopyRequest creates a safe copy.
type CreateSafeCopyRequest struct {
	Hours     int      `json:"hours,omitempty"` // default 24, at most 168
	AllowFrom []string `json:"allow_from,omitempty"`
	// Listen: an address from SafeCopiesInfo.Addresses, "private" (the
	// first private one, default), "public" (the first public one) or "*".
	Listen string `json:"listen,omitempty"`
	// ConnectHost is the host name clients use when it isn't the listen
	// address (e.g. a public IP in front of a private one, or a DNS name).
	ConnectHost string `json:"connect_host,omitempty"`
	DB          string `json:"db,omitempty"` // database in the connection string
	// Masking is "rules" (default) or "none"; "none" needs NoMaskingConfirm
	// set to the database's name, and is refused for AI assistants.
	Masking          string `json:"masking,omitempty"`
	NoMaskingConfirm string `json:"no_masking_confirm,omitempty"`
	// PasswordVerifier is a SCRAM-SHA-256 verifier of a password the
	// requester made, so the password never reaches Rowsafe. Without it
	// Rowsafe makes a password and returns it once.
	PasswordVerifier string `json:"password_verifier,omitempty"`
	// Role is the login role's name (default rowsafe_copy_<id>).
	Role string `json:"role,omitempty"`
}

// CreateSafeCopyResponse is the new copy. Password and ConnectionString
// (with the password) are only set when Rowsafe made the password, and are
// never shown again.
type CreateSafeCopyResponse struct {
	Copy             SafeCopy `json:"copy"`
	Task             TaskView `json:"task"`
	Password         string   `json:"password,omitempty"`
	ConnectionString string   `json:"connection_string,omitempty"`
}

// ExtendSafeCopyRequest keeps a safe copy Hours longer (from now).
type ExtendSafeCopyRequest struct {
	Hours int `json:"hours"`
}

// MaskingColumn is one column with its masking.
type MaskingColumn struct {
	DB     string `json:"db"`
	Table  string `json:"table"`
	Column string `json:"column"`
	Type   string `json:"type"`
	// Strategy is what a safe copy uses: the saved rule, else Suggested.
	Strategy  string `json:"strategy"`
	Suggested string `json:"suggested"`
	Saved     bool   `json:"saved,omitempty"`
	// Allowed lists the strategies that fit the column's type.
	Allowed []string `json:"allowed"`
	Unique  bool     `json:"unique,omitempty"`
	Rows    int64    `json:"rows,omitempty"` // the table's estimate
}

// MaskingStrategyInfo describes a strategy for the review screen.
type MaskingStrategyInfo struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Example     string `json:"example,omitempty"`
}

// MaskingInfo answers GET /v1/databases/{ref}/masking.
type MaskingInfo struct {
	// Columns is production's schema (from the last copy_schema task) with
	// each column's masking. Empty until the schema was read once.
	Columns    []MaskingColumn       `json:"columns"`
	Truncated  bool                  `json:"truncated,omitempty"`
	SchemaAt   *time.Time            `json:"schema_at,omitempty"`
	SchemaTask *TaskView             `json:"schema_task,omitempty"` // the latest copy_schema task
	Rules      []MaskingRule         `json:"rules"`                 // saved rules
	UpdatedAt  *time.Time            `json:"updated_at,omitempty"`
	UpdatedBy  string                `json:"updated_by,omitempty"`
	Strategies []MaskingStrategyInfo `json:"strategies"`
	// Masked counts columns a safe copy masks today.
	Masked int `json:"masked"`
}

// PutMaskingRequest saves the database's masking rules (replacing them).
type PutMaskingRequest struct {
	Rules []MaskingRule `json:"rules"`
}

// passwordVerifierRE is a SCRAM-SHA-256 verifier as PostgreSQL stores it:
// SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey> (base64).
var passwordVerifierRE = regexp.MustCompile(`^SCRAM-SHA-256\$[0-9]{4,7}:[A-Za-z0-9+/]{16,64}={0,2}\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=$`)

// ValidPasswordVerifier reports whether s is a SCRAM-SHA-256 verifier (and
// nothing else: it is placed in SQL).
func ValidPasswordVerifier(s string) bool { return passwordVerifierRE.MatchString(s) }
