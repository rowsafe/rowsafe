package protocol

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// ---- Meilisearch (engine "meilisearch")
//
// Meilisearch is a search engine (Community Edition, MIT): Rowsafe never
// installs or turns on its Enterprise Edition features (sharding, the
// network of instances, snapshots to S3). Meilisearch databases use the
// same tasks and results as PostgreSQL ones, with these meanings
// (internal/engine/meilisearch):
//
//   - A Rowsafe "database" is one Meilisearch instance; its indexes are
//     InspectResult.Databases (DBInfo.Tables holds the number of
//     documents). Meilisearch 1.12 or newer.
//   - DatabaseSpec.Port is the port apps use (7700 by default). On servers
//     Rowsafe creates, that port is Rowsafe's TLS front (the installer's
//     --listen-public) and Meilisearch itself listens on 127.0.0.1 only
//     (MeilisearchLocalPort); the agent talks to Meilisearch there. The
//     agent signs in with its own API key, made on the server by the
//     installer with the master key (which stays on the server, root's,
//     and is never kept by the agent); SocketDir is unused.
//   - Backups are Meilisearch's own snapshots (POST /snapshots): the agent
//     asks for one, reads the file Meilisearch writes into its snapshot
//     folder, encrypts it on the server (objstore.Seal) and stores it
//     under <repo path>/<stanza>/backup/<label>/. Every backup is whole;
//     BackupDiff and BackupIncr are taken as full. They run every hour by
//     default. There is no restore to any second (PointInTime is false):
//     restores go back to a snapshot. DatabaseSpec.RetentionFull counts
//     days: every snapshot of the last 48 hours is kept, then the newest of
//     each day (and those Marks point at) within that many days.
//   - RestorePointResult (a Mark): a snapshot taken on the spot, named
//     after the Mark. LSN is that snapshot's label.
//   - Rewind targets: Mark restores the Mark's snapshot; Time the newest
//     snapshot taken at or before that moment. RecoveredTo is when that
//     snapshot was taken.
//   - Rewind copies run as a separate, temporary Meilisearch on the same
//     host, started from the snapshot with the host's own Meilisearch
//     program, listening on 127.0.0.1 only (RewindCopyResult.Port), with a
//     master key of its own that never leaves the agent: production's keys
//     don't open it.
//   - RewindTable: DB is "" and Table an index's uid. Documents are
//     compared by their primary key; bringing documents back adds those
//     missing from production and replaces changed ones only with
//     IncludeChanged.
//   - Rewind in place goes through Meilisearch itself, without a restart:
//     the snapshot's indexes are copied from a temporary Meilisearch into
//     production under temporary names (MeilisearchRestorePrefix), then one
//     swap of indexes puts them in place at once. The indexes as they were
//     stay in production under those temporary names for Undo (KeepDays),
//     then are deleted. API keys are left as they are.
//   - Monitoring: database_size_bytes, disk_* and the meilisearch_* metrics
//     (collect/catalog_meilisearch.go), and DatabaseMonitoring.Meilisearch
//     below.
//   - Databases & users: "databases" are indexes (created and removed),
//     "users" are API keys on chosen indexes (DBAccess* presets:
//     read_only searches, read_write also adds and deletes documents,
//     owner manages the index's settings too). A new key is made on the
//     server and leaves it only sealed to the person who asked
//     (SealedSecret); DBSecret.Password is the key, DBSecret.URL the
//     instance's address. Rowsafe's own key and keys with every right are
//     listed, never changed.

// Meilisearch's defaults.
const (
	// MeilisearchPort is Meilisearch's default port and the port apps use
	// on servers Rowsafe creates (TLS).
	MeilisearchPort = 7700
	// MeilisearchLocalPort is where Meilisearch itself listens, on
	// 127.0.0.1 only, behind Rowsafe's TLS front on servers Rowsafe creates.
	MeilisearchLocalPort = 7701
	// MeilisearchRestorePrefix starts the temporary names of indexes a
	// rewind in place copies in (and keeps for Undo):
	// rowsafe-restore-<8 hex>-<uid>. Pulse leaves them out.
	MeilisearchRestorePrefix = "rowsafe-restore-"
)

// MeilisearchVersion is the Meilisearch release Rowsafe installs and
// updates to (the installer's MEILI_VERSION and the root helper's
// meili_pin_version, with the SHA-256 of its files). Updates go to a newer
// pinned release of the same major version, through Meilisearch's dumpless
// upgrade, after a Mark.
const MeilisearchVersion = "1.54.3"

// MeilisearchInPlaceMinVersion is the oldest Meilisearch a rewind in place
// works on: it copies indexes with POST /export (Meilisearch 1.16) and
// swaps them in with renames (POST /swap-indexes with "rename",
// Meilisearch 1.18).
const MeilisearchInPlaceMinVersion = "1.18"

// MeilisearchInPlaceProblem says why a rewind in place can't run on
// version ("" when it can, or when the version is unknown).
func MeilisearchInPlaceProblem(version string) string {
	var maj, minor int
	if _, err := fmt.Sscanf(strings.TrimPrefix(version, "v"), "%d.%d", &maj, &minor); err != nil {
		return ""
	}
	if maj < 1 || maj == 1 && minor < 18 {
		return fmt.Sprintf("Rewind in place needs Meilisearch %s or newer, and this server runs %s: restore a copy and bring documents back "+
			"instead, or update Meilisearch first", MeilisearchInPlaceMinVersion, version)
	}
	return ""
}

// Meilisearch fixes (MaintenanceParams.Action).
const (
	// MaintMeiliCompactIndex compacts one index (Tables[0], its uid) when
	// it takes much more disk than its data needs (POST
	// /indexes/{uid}/compact, in recent Meilisearch releases): searches go
	// on meanwhile.
	MaintMeiliCompactIndex = "meilisearch_compact_index"
	// MaintMeiliClearTasks deletes the history of finished tasks
	// (succeeded, failed or canceled) older than 7 days, when the task
	// queue grows large. Documents, indexes and pending tasks are left as
	// they are.
	MaintMeiliClearTasks = "meilisearch_clear_tasks"
)

// meilisearchFeatures are what Meilisearch supports (EngineCapabilities).
var meilisearchFeatures = EngineFeatures{
	Backups: true, Proof: true, Marks: true,
	RewindCopy: true, RewindRows: true, RewindInPlace: true,
	Monitoring: true, Fixes: true,
	Restart:  true, // through root's helper (meilisearch.service), only when root allowed it
	Updates:  true, // the newest pinned release (MeilisearchVersion), by the root helper, on servers Rowsafe's installer set up
	DBAdmin:  true, // indexes and API keys
	Security: true,
}

// MeilisearchStatus is Meilisearch's own health detail
// (DatabaseMonitoring.Meilisearch), read about every 5 minutes. Index
// names, sizes and counts only: never documents or keys.
type MeilisearchStatus struct {
	CollectedAt time.Time `json:"collected_at"`
	Version     string    `json:"version"`
	// Edition is "community" (Rowsafe never installs the Enterprise
	// Edition; an adopted instance reports what it runs, "" when unknown).
	Edition string `json:"edition,omitempty"`
	// DatabaseSizeBytes is the size on disk, UsedDatabaseSizeBytes what the
	// data uses of it (the rest is free space Meilisearch reuses or a
	// compaction gives back).
	DatabaseSizeBytes     int64              `json:"database_size_bytes"`
	UsedDatabaseSizeBytes int64              `json:"used_database_size_bytes"`
	LastUpdate            *time.Time         `json:"last_update,omitempty"`
	Indexes               []MeilisearchIndex `json:"indexes"`
	// Tasks: waiting (enqueued), running (processing), failed in the last
	// 24 hours, and every task in the queue's history; the oldest waiting
	// task's age.
	TasksEnqueued         int64      `json:"tasks_enqueued"`
	TasksProcessing       int64      `json:"tasks_processing"`
	TasksFailed24h        int64      `json:"tasks_failed_24h"`
	TasksTotal            int64      `json:"tasks_total"`
	OldestEnqueuedSeconds float64    `json:"oldest_enqueued_seconds,omitempty"`
	LastFailedTask        *MeiliTask `json:"last_failed_task,omitempty"`
	// MaxIndexingMemoryBytes is the indexing memory limit when the agent
	// knows it (the installer's settings), 0 otherwise.
	MaxIndexingMemoryBytes int64 `json:"max_indexing_memory_bytes,omitempty"`
	// Analytics: Meilisearch sends usage data to its makers (no
	// --no-analytics), when the agent knows it.
	Analytics *bool `json:"analytics,omitempty"`
}

// MeilisearchIndex is one index (Rowsafe's temporary ones left out).
type MeilisearchIndex struct {
	UID            string `json:"uid"`
	PrimaryKey     string `json:"primary_key,omitempty"`
	Documents      int64  `json:"documents"`
	IndexSizeBytes int64  `json:"index_size_bytes"`
	UsedSizeBytes  int64  `json:"used_size_bytes"`
	Embeddings     int64  `json:"embeddings,omitempty"`
	IsIndexing     bool   `json:"is_indexing,omitempty"`
}

// MeiliTask is one task of Meilisearch's queue (no payload).
type MeiliTask struct {
	UID       int64  `json:"uid"`
	Type      string `json:"type"`
	IndexUID  string `json:"index_uid,omitempty"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	// Error is the code in plain words. Meilisearch's own message never
	// leaves the server: it can quote documents.
	Error      string     `json:"error,omitempty"`
	EnqueuedAt *time.Time `json:"enqueued_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ---- Databases & users for Meilisearch

// meiliIndexRE: an index uid Meilisearch accepts (letters, digits, - and
// _, at most 400 bytes).
var meiliIndexRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,400}$`)

// ValidMeilisearchIndex checks an index uid; "*" (every index) only when
// wildcard.
func ValidMeilisearchIndex(uid string, wildcard bool) error {
	if wildcard && uid == "*" {
		return nil
	}
	if !meiliIndexRE.MatchString(uid) {
		return fmt.Errorf("%q isn't an index name: use letters, digits, - and _", uid)
	}
	return nil
}

// MeilisearchKeyActions are the actions of a new key per preset
// (DBAccess*).
var MeilisearchKeyActions = map[string][]string{
	DBAccessReadOnly:  {"search"},
	DBAccessReadWrite: {"search", "documents.*", "tasks.get"},
	DBAccessOwner:     {"search", "documents.*", "indexes.get", "indexes.update", "settings.*", "stats.get", "tasks.get"},
}

// MeilisearchKeyAccess recognizes a preset from a key's actions ("" when
// they are someone else's).
func MeilisearchKeyAccess(actions []string) string {
	got := slices.Sorted(slices.Values(actions))
	for access, want := range MeilisearchKeyActions {
		if slices.Equal(got, slices.Sorted(slices.Values(want))) {
			return access
		}
	}
	return ""
}

// validateMeilisearchDBAdmin checks what is Meilisearch's own: indexes
// are the databases, API keys the users, and keys have no owner or
// password to reset in place (reset_password makes a new key with the same
// rights and removes the old one).
func validateMeilisearchDBAdmin(p DBAdminParams) error {
	switch p.Action {
	case DBAdminCreateDatabase:
		if err := ValidMeilisearchIndex(p.Database, false); err != nil {
			return err
		}
		if p.Owner != "" && !p.CreateOwner {
			return fmt.Errorf("Meilisearch indexes have no owner: give a key access to the index instead")
		}
	case DBAdminDropDatabase:
		if err := ValidMeilisearchIndex(p.Database, false); err != nil {
			return err
		}
	case DBAdminCreateUser:
		for _, d := range p.Databases {
			if err := ValidMeilisearchIndex(d, true); err != nil {
				return err
			}
		}
	case DBAdminDropUser:
		if p.ReassignTo != "" {
			return fmt.Errorf("Meilisearch keys own nothing, so there is nothing to hand over")
		}
	}
	return nil
}
