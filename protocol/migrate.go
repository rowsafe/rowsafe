package protocol

import (
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// ---- Move in: bring a database from a managed provider onto a server ----
//
// A migration copies one PostgreSQL database (a datname) from anywhere the
// target server can reach (DigitalOcean, RDS, Supabase, Neon...) into a
// database inside a PostgreSQL cluster Rowsafe protects. Everything runs on
// the target server's agent: it connects to the source with the person's
// credentials, which reach it sealed end to end (package e2e) and never
// leave the server. The control plane only sees names, counts and sizes.
//
// Live sync (MigrateMethodLive) copies the schema with pg_dump, then uses
// PostgreSQL's logical replication (a publication on the source, a
// subscription on the target) until the person switches over. The one-time
// copy (MigrateMethodDump) is pg_dump/pg_restore while writes are stopped.

// Migration task types.
const (
	// TaskMigrate runs one quick MigrateParams.Action (key, check,
	// fix_identity, switchover, credentials, source_writable, cancel,
	// finish). It runs beside backups (the agent's side lane).
	TaskMigrate = "migrate"
	// TaskMigrateCopy copies the schema and starts the live sync, or makes
	// the one-time copy (MigrateParams with Method). It can take hours.
	TaskMigrateCopy = "migrate_copy"
)

// Migrate actions (MigrateParams.Action) of a TaskMigrate.
const (
	// MigrateKey makes the key pair the source connection string is sealed
	// to (-> MigrateKeyResult). The private key stays on the server.
	MigrateKey = "key"
	// MigrateCheck opens the sealed source, keeps it on the server and
	// checks both sides (-> MigrateCheckResult). Read-only on both.
	MigrateCheck = "check"
	// MigrateFixIdentity sets REPLICA IDENTITY FULL on the source tables
	// that have no primary key (Tables), so live sync can copy their
	// updates and deletes (-> MigrateActionResult).
	MigrateFixIdentity = "fix_identity"
	// MigrateSwitchover stops writes on the source (ReadOnly) or trusts
	// that they were stopped, waits until the target has everything, copies
	// sequence values, ends the sync, compares row counts and creates the
	// login apps use from now on (-> MigrateSwitchoverResult).
	MigrateSwitchover = "switchover"
	// MigrateCredentials gives the app login a new password and seals the
	// new connection string to BrowserKey (-> MigrateSwitchoverResult with
	// only Credentials).
	MigrateCredentials = "credentials"
	// MigrateSourceWritable undoes ReadOnly on the source (rolling back).
	MigrateSourceWritable = "source_writable"
	// MigrateCancel stops a migration: ends the sync, removes Rowsafe's
	// publication and replication slot from the source and forgets the
	// source. With DropTarget it also deletes the target database, if the
	// migration created it.
	MigrateCancel = "cancel"
	// MigrateFinish forgets the source (its connection string and key) once
	// the person is done with it. The source itself is left as it is.
	MigrateFinish = "finish"
)

// Migration methods.
const (
	MigrateMethodLive = "live" // schema + logical replication, switch over when ready
	MigrateMethodDump = "dump" // one-time pg_dump/pg_restore while writes are stopped
)

// Migration phases (MigrationStatus.Phase, and the control plane's
// migrations.status).
const (
	MigratePhaseNew       = "new"       // waiting for the key
	MigratePhaseReady     = "ready"     // key made: waiting for the source connection string
	MigratePhaseChecking  = "checking"  // check queued or running
	MigratePhaseChecked   = "checked"   // check done: pick a method and start
	MigratePhaseSchema    = "schema"    // copying the schema
	MigratePhaseCopying   = "copying"   // live sync: first copy of the tables
	MigratePhaseSyncing   = "syncing"   // live sync: every table copied, following changes
	MigratePhaseDumping   = "dumping"   // one-time copy: pg_dump from the source
	MigratePhaseRestoring = "restoring" // one-time copy: pg_restore into the target
	MigratePhaseSwitching = "switching" // switchover running
	MigratePhaseSwitched  = "switched"  // done: apps can use the new server
	MigratePhaseFailed    = "failed"    // stopped by an error (see Error)
	MigratePhaseCancelled = "cancelled"
	MigratePhaseFinished  = "finished" // switched and the source forgotten
)

// MigrateInfo is the HKDF info of every box a migration seals.
const MigrateInfo = "rowsafe-migrate-v1"

// MigrateSourceAAD and MigrateCredentialsAAD bind a box to its migration
// and purpose.
func MigrateSourceAAD(migrationID string) []byte { return []byte("source:" + migrationID) }
func MigrateCredentialsAAD(migrationID string) []byte {
	return []byte("credentials:" + migrationID)
}

// MigrateParams are the params of TaskMigrate and TaskMigrateCopy.
type MigrateParams struct {
	MigrationID string `json:"migration_id"` // [a-z0-9_]{1,40}
	Action      string `json:"action,omitempty"`
	// Source is the source connection string (URL or key=value) sealed to
	// the key MigrateKey made, with MigrateSourceAAD. Check only (none:
	// check again with the source the server has); the control plane
	// removes it from the task once the task finished.
	Source *e2e.Box `json:"source,omitempty"`
	// TargetDB is the database to create (or fill, if empty) in the target
	// cluster; "" means the source database's name.
	TargetDB string `json:"target_db,omitempty"`
	// Method: MigrateMethodLive or MigrateMethodDump (migrate_copy).
	Method string `json:"method,omitempty"`
	// Tables are "schema.table" names (fix_identity).
	Tables []string `json:"tables,omitempty"`
	// ReadOnly makes the source database read-only and disconnects its
	// sessions before the final copy (switchover; a one-time copy).
	ReadOnly bool `json:"read_only,omitempty"`
	// BrowserKey is the P-256 public key (raw, base64) the new connection
	// string is sealed to (switchover, credentials, a one-time copy).
	BrowserKey string `json:"browser_key,omitempty"`
	// AppUser is the login apps use on the new server ("" : the source's
	// user name when usable, else "app").
	AppUser string `json:"app_user,omitempty"`
	// Host is the address written in the new connection string ("" : the
	// agent picks one of MigrateTarget.Addresses).
	Host string `json:"host,omitempty"`
	// DropTarget (cancel) deletes the target database if the migration
	// created it.
	DropTarget bool `json:"drop_target,omitempty"`
}

// MigrateKeyResult answers MigrateKey.
type MigrateKeyResult struct {
	// PublicKey is the agent's P-256 public key for this migration (raw
	// uncompressed point, base64).
	PublicKey string `json:"public_key"`
	// Target is what the agent knows about the target cluster already, so
	// the wizard can show it while the person pastes the source.
	Target MigrateTarget `json:"target"`
}

// MigrateSource describes the source, without secrets.
type MigrateSource struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Database string `json:"database"`
	User     string `json:"user"`
	// Provider is a MigrateProvider id ("rds", "supabase"...; "other").
	Provider      string   `json:"provider"`
	ServerVersion string   `json:"server_version,omitempty"`
	VersionNum    int      `json:"version_num,omitempty"`
	SizeBytes     int64    `json:"size_bytes,omitempty"`
	Tables        int      `json:"tables,omitempty"`
	Sequences     int      `json:"sequences,omitempty"`
	LargeObjects  int64    `json:"large_objects,omitempty"`
	Encoding      string   `json:"encoding,omitempty"`
	Collation     string   `json:"collation,omitempty"`
	WalLevel      string   `json:"wal_level,omitempty"`
	SSL           bool     `json:"ssl"`
	Extensions    []string `json:"extensions,omitempty"`
}

// MigrateTarget describes the target cluster.
type MigrateTarget struct {
	ServerVersion string `json:"server_version,omitempty"`
	VersionNum    int    `json:"version_num,omitempty"`
	// Database is the database the data goes into; Exists says whether it
	// exists already (then it must hold no tables).
	Database string `json:"database,omitempty"`
	Exists   bool   `json:"exists,omitempty"`
	// FreeBytes is the free space where PostgreSQL keeps its data.
	FreeBytes int64 `json:"free_bytes,omitempty"`
	// Addresses are this server's addresses apps could connect to (public
	// IPs first, then private ones, then the host name).
	Addresses []string `json:"addresses,omitempty"`
	// ListensRemotely: PostgreSQL accepts TCP connections from other
	// machines (listen_addresses isn't only localhost).
	ListensRemotely bool `json:"listens_remotely"`
	Port            int  `json:"port,omitempty"`
	SSL             bool `json:"ssl"`
}

// Check outcomes.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// MigrateCheckItem is one line of the check list.
type MigrateCheckItem struct {
	ID     string `json:"id"`     // stable: "connect", "version", "logical", "identity"...
	Status string `json:"status"` // CheckOK, CheckWarn, CheckFail
	Title  string `json:"title"`  // plain: "Your tables all have a primary key"
	Detail string `json:"detail,omitempty"`
	// Fix is the next step in plain words (provider-specific when known).
	Fix string `json:"fix,omitempty"`
	// Action is a MigrateParams.Action Rowsafe can run to fix it
	// ("fix_identity").
	Action string `json:"action,omitempty"`
	// Items are the affected objects ("public.events"), capped.
	Items []string `json:"items,omitempty"`
	// Blocks names the method this failure rules out: MigrateMethodLive or
	// "" (both).
	Blocks string `json:"blocks,omitempty"`
}

// MigrateCheckResult answers MigrateCheck.
type MigrateCheckResult struct {
	Source MigrateSource      `json:"source"`
	Target MigrateTarget      `json:"target"`
	Checks []MigrateCheckItem `json:"checks"`
	// LiveSync: live sync can start now. DumpOK: a one-time copy can.
	LiveSync bool `json:"live_sync"`
	DumpOK   bool `json:"dump_ok"`
	// Method is the recommended method.
	Method string `json:"method"`
	// EstimatedCopySeconds is a rough first-copy time; for a one-time copy
	// it is also the downtime.
	EstimatedCopySeconds int64 `json:"estimated_copy_seconds"`
	// AppUser is the default login name for apps on the new server.
	AppUser string `json:"app_user"`
	Summary string `json:"summary"`
}

// MigrateActionResult answers fix_identity, source_writable, cancel and
// finish.
type MigrateActionResult struct {
	Summary string   `json:"summary"`
	Details []string `json:"details,omitempty"`
}

// MigrateCopyResult answers TaskMigrateCopy. A one-time copy also switches
// over, so Switchover is set.
type MigrateCopyResult struct {
	Method string `json:"method"`
	// TablesTotal are the tables the sync covers (live) or were copied.
	TablesTotal int `json:"tables_total"`
	// CreatedDatabase: the migration created the target database.
	CreatedDatabase bool `json:"created_database"`
	// Warnings are schema statements that couldn't be applied on the target
	// (an extension it doesn't have, a role that only exists at the
	// provider...), in plain words where possible.
	Warnings   []string                 `json:"warnings,omitempty"`
	Switchover *MigrateSwitchoverResult `json:"switchover,omitempty"`
	DurationMs int64                    `json:"duration_ms"`
	Summary    string                   `json:"summary"`
}

// MigrateTableCount compares one table after the switchover.
type MigrateTableCount struct {
	Table  string `json:"table"` // schema.table
	Source int64  `json:"source"`
	Target int64  `json:"target"`
	// Estimated: a table too big to count in time; the numbers are
	// PostgreSQL's estimates.
	Estimated bool `json:"estimated,omitempty"`
}

// MigrateSwitchoverResult answers MigrateSwitchover and MigrateCredentials.
type MigrateSwitchoverResult struct {
	SourceReadOnly bool `json:"source_read_only"`
	// SequencesSynced counts sequences set to the source's values.
	SequencesSynced int `json:"sequences_synced"`
	// Tables compares row counts; Mismatches counts differing tables.
	Tables     []MigrateTableCount `json:"tables,omitempty"`
	Mismatches int                 `json:"mismatches"`
	RowsTotal  int64               `json:"rows_total"`
	// Credentials is the new connection string (with its new password),
	// sealed to BrowserKey with MigrateCredentialsAAD. Only the person's
	// browser (or CLI) can open it.
	Credentials *e2e.Box `json:"credentials,omitempty"`
	// ConnectionHint is the same connection string without the password,
	// safe to show and store.
	ConnectionHint string   `json:"connection_hint,omitempty"`
	AppUser        string   `json:"app_user,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	DurationMs     int64    `json:"duration_ms"`
	Summary        string   `json:"summary"`
}

// MigrationStatus is the agent's live progress report, posted about every
// 10 seconds while a copy or sync runs (POST /v1/agent/migrations/{id}/status).
type MigrationStatus struct {
	Phase string `json:"phase"` // MigratePhase*
	// Tables: copied (or restored) so far out of total.
	TablesTotal  int `json:"tables_total"`
	TablesCopied int `json:"tables_copied"`
	// Bytes: the target database's size so far against the source's.
	BytesTotal  int64 `json:"bytes_total"`
	BytesCopied int64 `json:"bytes_copied"`
	// LagBytes is how far the target is behind the source (live sync; nil
	// when unknown).
	LagBytes *int64 `json:"lag_bytes,omitempty"`
	// Error is the sync's latest error in plain words ("" when fine).
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

// MigrationStatusAck answers a status report; Stop tells the agent the
// control plane no longer follows this migration.
type MigrationStatusAck struct {
	Stop bool `json:"stop,omitempty"`
}

// MigrateCaughtUpBytes: at most this far behind counts as caught up.
const MigrateCaughtUpBytes = 64 << 10

// ---- User API ----

// Migration is a move-in as the API shows it.
type Migration struct {
	ID string `json:"id"`
	// DatabaseID/DatabaseName: the Rowsafe database (target cluster).
	DatabaseID   string `json:"database_id"`
	DatabaseName string `json:"database_name"`
	Hostname     string `json:"hostname"`
	Status       string `json:"status"` // MigratePhase*
	Method       string `json:"method,omitempty"`
	TargetDB     string `json:"target_db,omitempty"`
	// PublicKey: seal the source connection string to it (status ready and
	// later, until finished).
	PublicKey string              `json:"public_key,omitempty"`
	Source    *MigrateSource      `json:"source,omitempty"`
	Check     *MigrateCheckResult `json:"check,omitempty"`
	Progress  *MigrationStatus    `json:"progress,omitempty"`
	Copy      *MigrateCopyResult  `json:"copy,omitempty"`
	// Switchover is the switchover's result without the sealed credentials.
	Switchover *MigrateSwitchoverResult `json:"switchover,omitempty"`
	// CredentialsReady: a sealed connection string waits to be picked up
	// (GET .../credentials, once).
	CredentialsReady bool   `json:"credentials_ready"`
	SourceReadOnly   bool   `json:"source_read_only"`
	Error            string `json:"error,omitempty"`
	// TaskID/TaskStatus: the latest task and its status.
	TaskID     string     `json:"task_id,omitempty"`
	TaskType   string     `json:"task_type,omitempty"`
	TaskAction string     `json:"task_action,omitempty"`
	TaskStatus string     `json:"task_status,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	SwitchedAt *time.Time `json:"switched_at,omitempty"`
}

// CreateMigrationRequest starts a move-in into a Rowsafe database.
type CreateMigrationRequest struct {
	// Database is the Rowsafe database (name or ID) to move into.
	Database string `json:"database"`
}

// CheckMigrationRequest hands over the sealed source. Without one, a
// checked migration is checked again with the source the server has.
type CheckMigrationRequest struct {
	Source   e2e.Box `json:"source,omitzero"`
	TargetDB string  `json:"target_db,omitempty"`
}

// StartMigrationRequest starts the copy. For a one-time copy the switchover
// fields apply too (it stops writes and ends with the new login).
type StartMigrationRequest struct {
	Method     string `json:"method"`
	TargetDB   string `json:"target_db,omitempty"`
	ReadOnly   bool   `json:"read_only,omitempty"`
	BrowserKey string `json:"browser_key,omitempty"`
	AppUser    string `json:"app_user,omitempty"`
	Host       string `json:"host,omitempty"`
}

// SwitchoverRequest switches a live sync over. Confirm must be the target
// database's name.
type SwitchoverRequest struct {
	ReadOnly   bool   `json:"read_only"`
	BrowserKey string `json:"browser_key"`
	AppUser    string `json:"app_user,omitempty"`
	Host       string `json:"host,omitempty"`
	Confirm    string `json:"confirm"`
}

// FixIdentityRequest asks Rowsafe to set REPLICA IDENTITY FULL on source
// tables without a primary key (all of the check's list when empty).
type FixIdentityRequest struct {
	Tables []string `json:"tables,omitempty"`
}

// NewCredentialsRequest asks for a new password for the app login.
type NewCredentialsRequest struct {
	BrowserKey string `json:"browser_key"`
}

// CancelMigrationRequest stops a migration.
type CancelMigrationRequest struct {
	DropTarget bool `json:"drop_target,omitempty"`
}

// MigrationCredentials is the sealed connection string, handed out once.
type MigrationCredentials struct {
	Credentials e2e.Box `json:"credentials"`
	AppUser     string  `json:"app_user"`
	Hint        string  `json:"connection_hint"`
}

// ---- Providers ----

// MigrateProvider is what Rowsafe knows about a managed provider as a
// source, in plain words (docs: guides/move-in).
type MigrateProvider struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Hosts are host name suffixes that identify it.
	Hosts []string `json:"-"`
	// Setting is a pg_settings name only this provider has.
	Setting string `json:"-"`
	// Logical is how to turn on logical replication ("" : not offered, use
	// the one-time copy).
	Logical string `json:"logical,omitempty"`
	// Grant is how to give the user the right to replicate.
	Grant string `json:"grant,omitempty"`
	// Network is how to let this server connect.
	Network string `json:"network,omitempty"`
	// Docs is the provider's own page about it.
	Docs string `json:"docs,omitempty"`
}

// MigrateProviders lists the providers Rowsafe recognizes, from their
// official documentation (sources in docs/guides/move-in).
var MigrateProviders = []MigrateProvider{
	{
		ID: "digitalocean", Name: "DigitalOcean", Hosts: []string{".db.ondigitalocean.com"},
		Logical: "DigitalOcean's own guide for moving to a self-managed server uses logical replication with the doadmin user. If Rowsafe finds it off on your cluster, ask DigitalOcean support, or use the one-time copy.",
		Grant:   "Use the doadmin user (DigitalOcean doesn't give full superuser access, so a few objects may need attention).",
		Network: "Add this server's IP address under the cluster's Network Access > Trusted sources (IPv4 only).",
		Docs:    "https://docs.digitalocean.com/products/databases/postgresql/how-to/migrate-to-self-managed/",
	},
	{
		ID: "aurora", Name: "Amazon Aurora", Hosts: []string{".cluster-", ".rds.amazonaws.com"},
		Logical: "In the RDS console, set rds.logical_replication to 1 in the cluster's custom DB cluster parameter group, then reboot the writer instance.",
		Grant:   "Use a user with the rds_superuser role (the master user has it).",
		Network: "Allow this server's IP address on port 5432 in the cluster's security group.",
		Docs:    "https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraPostgreSQL.Replication.Logical.Configure.html",
	},
	{
		ID: "rds", Name: "Amazon RDS", Hosts: []string{".rds.amazonaws.com"}, Setting: "rds.logical_replication",
		Logical: "In the RDS console, set rds.logical_replication to 1 in the instance's custom DB parameter group, then reboot the instance.",
		Grant:   "Use the master user, or run: GRANT rds_replication TO your_user;",
		Network: "Allow this server's IP address on port 5432 in the instance's security group.",
		Docs:    "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.FeatureSupport.LogicalReplication.html",
	},
	{
		ID: "supabase", Name: "Supabase", Hosts: []string{".supabase.co", ".supabase.com"},
		Logical: "Supabase has logical replication on. Use the direct connection string (db.<project>.supabase.co), not the pooler.",
		Grant:   "Use the postgres user.",
		Network: "The direct connection is IPv6 unless you turn on Supabase's IPv4 add-on; this server needs IPv6, or the add-on.",
		Docs:    "https://supabase.com/docs/guides/database/postgres/setup-replication-external",
	},
	{
		ID: "neon", Name: "Neon", Hosts: []string{".neon.tech"},
		Logical: "In the Neon Console open Settings > Logical replication and click Enable (it restarts your computes and can't be turned off). Use the connection string without -pooler.",
		Grant:   "Use a role created in the Neon Console, CLI or API (they have REPLICATION through neon_superuser); roles created with SQL can't replicate.",
		Network: "If you use IP Allow, add this server's IP address.",
		Docs:    "https://neon.com/docs/guides/logical-replication-neon",
	},
	{
		ID: "heroku", Name: "Heroku Postgres", Hosts: []string{".compute-1.amazonaws.com", ".compute.amazonaws.com"},
		Grant: "Heroku's documentation offers pg_dump for moving data out; Rowsafe uses the one-time copy.",
		Docs:  "https://devcenter.heroku.com/articles/heroku-postgres-import-export",
	},
	{
		ID: "render", Name: "Render", Hosts: []string{".render.com"},
		Logical: "Render turns logical replication on through a support request (Pro workspace or higher). Ask Render support to enable it for this database.",
		Grant:   "Publishing all tables needs a superuser: ask Render support to create the publication, or use the one-time copy.",
		Docs:    "https://render.com/docs/postgresql-logical-replication",
	},
	{
		ID: "railway", Name: "Railway", Hosts: []string{".rlwy.net", ".railway.app", ".railway.internal"},
		Logical: "Run ALTER SYSTEM SET wal_level = 'logical'; then restart the Postgres service from its menu in Railway.",
		Grant:   "Use the postgres user.",
		Docs:    "https://docs.railway.com/guides/migrate-database-minimal-downtime",
	},
	{
		ID: "crunchy", Name: "Crunchy Bridge", Hosts: []string{".postgresbridge.com"},
		Logical: "Crunchy Bridge has wal_level = logical by default.",
		Grant:   "Use the postgres superuser.",
		Network: "Allow this server's IP address in the cluster's firewall rules.",
		Docs:    "https://docs.crunchybridge.com/how-to/logical-replication",
	},
	{
		ID: "cloudsql", Name: "Google Cloud SQL", Setting: "cloudsql.logical_decoding",
		Logical: "Set the cloudsql.logical_decoding flag to on for the instance (it restarts the instance).",
		Grant:   "Use a user in cloudsqlsuperuser with REPLICATION: ALTER USER your_user WITH REPLICATION;",
		Network: "Add this server's IP address to the instance's authorized networks.",
		Docs:    "https://docs.cloud.google.com/sql/docs/postgres/replication/configure-logical-replication",
	},
	{
		ID: "azure", Name: "Azure Database for PostgreSQL", Hosts: []string{".postgres.database.azure.com"},
		Logical: "In the Azure portal set the server parameter wal_level to logical, save, and restart the server.",
		Grant:   "Run: ALTER ROLE your_admin WITH REPLICATION;",
		Network: "Allow this server's IP address in the server's networking (firewall) settings.",
		Docs:    "https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-logical",
	},
}

// otherProvider is any PostgreSQL Rowsafe doesn't recognize.
var otherProvider = MigrateProvider{
	ID: "other", Name: "PostgreSQL",
	Logical: "Set wal_level = logical in postgresql.conf (or ALTER SYSTEM SET wal_level = 'logical') and restart PostgreSQL.",
	Grant:   "Use a superuser, or a user with REPLICATION that owns the tables.",
	Network: "Allow this server's IP address in pg_hba.conf and any firewall.",
	Docs:    "https://www.postgresql.org/docs/current/logical-replication-config.html",
}

// MigrateProviderByID returns a provider by id ("other" when unknown).
func MigrateProviderByID(id string) MigrateProvider {
	for _, p := range MigrateProviders {
		if p.ID == id {
			return p
		}
	}
	return otherProvider
}

// DetectMigrateProvider guesses the provider from the host name, then from
// provider-only settings the source has (settings may be nil).
func DetectMigrateProvider(host string, settings map[string]bool) MigrateProvider {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, p := range MigrateProviders {
		if p.ID == "aurora" {
			// Aurora endpoints are rds.amazonaws.com names with "cluster-".
			if strings.HasSuffix(h, ".rds.amazonaws.com") && strings.Contains(h, ".cluster-") {
				return p
			}
			continue
		}
		for _, suffix := range p.Hosts {
			if strings.HasSuffix(h, suffix) {
				return p
			}
		}
	}
	for _, p := range MigrateProviders {
		if p.Setting != "" && settings[p.Setting] {
			return p
		}
	}
	return otherProvider
}
