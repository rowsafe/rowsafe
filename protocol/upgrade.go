package protocol

import "time"

// ---- PostgreSQL updates and upgrades, server security updates ----
//
// Rowsafe keeps PostgreSQL current on the customer's own server, only when a
// person clicks (or, per database, opted in to automatic minor updates):
//
//   - minor updates (16.9 -> 16.10): the same major's packages, never a
//     major change, then a restart of that cluster and a check that WAL
//     archiving still works;
//   - server security updates (security origin only, PostgreSQL's own
//     server packages left to the update above) and a reboot;
//   - major upgrades (16 -> 18): a preflight, a required rehearsal on a
//     restored copy (production untouched), then the upgrade in Safe mode
//     (the old version is kept, stopped, for an instant Undo) or Fast mode
//     (hard links; Undo restores the old version from the backup taken just
//     before, losing what was written since).
//
// The agent runs unprivileged; everything that needs root (installing
// packages, pg_upgradecluster, a reboot) goes through the root helper's
// update service, which root allows at install time, per capability, in
// /etc/rowsafe/updates-allowed. The control plane saves a Mark first.

// Task types.
const (
	// TaskPGUpdate installs the newest minor release of the cluster's major
	// (PGUpdateParams -> PGUpdateResult) and restarts it.
	TaskPGUpdate = "pg_update"
	// TaskSecurityUpdates installs the server's pending security updates
	// (SecurityUpdatesResult). PostgreSQL's server packages are left out.
	TaskSecurityUpdates = "security_updates"
	// TaskReboot reboots the server (RebootResult). The agent finishes the
	// task after the boot, once PostgreSQL answers again.
	TaskReboot = "reboot"
	// TaskUpgradeCheck is the read-only preflight of a major upgrade
	// (UpgradeCheckParams -> UpgradeCheckResult).
	TaskUpgradeCheck = "upgrade_check"
	// TaskUpgradeRehearsal restores the latest backup into a scratch copy,
	// installs the target major if needed, runs pg_upgrade on the copy and
	// checks it (UpgradeRehearsalParams -> UpgradeRehearsalResult).
	// Production is not touched; the copy is deleted afterwards.
	TaskUpgradeRehearsal = "upgrade_rehearsal"
	// TaskUpgrade upgrades the cluster to a new major (UpgradeParams ->
	// UpgradeResult). Any failure before the new version accepts
	// connections puts the old one back.
	TaskUpgrade = "upgrade"
	// TaskUpgradeUndo goes back to the old major (UpgradeUndoParams ->
	// UpgradeUndoResult).
	TaskUpgradeUndo = "upgrade_undo"
	// TaskUpgradeCleanup removes the version kept aside by an upgrade or its
	// undo (UpgradeCleanupParams -> UpgradeCleanupResult).
	TaskUpgradeCleanup = "upgrade_cleanup"
)

// What root may allow in /etc/rowsafe/updates-allowed (SoftwareReport.Allowed).
const (
	// UpdateAllowPostgres: install PostgreSQL minor updates and upgrade
	// majors, for the clusters in /etc/rowsafe/restart-allowed.
	UpdateAllowPostgres = "postgresql"
	UpdateAllowSecurity = "security" // install security updates
	UpdateAllowReboot   = "reboot"   // reboot the server
)

// Upgrade modes.
const (
	// UpgradeSafe copies the data (pg_upgrade --copy, or --clone where the
	// filesystem supports it). Needs free disk about the database's size;
	// the old version stays, stopped, and Undo just starts it again.
	UpgradeSafe = "safe"
	// UpgradeFast hard-links the data (pg_upgrade --link): minutes of
	// downtime whatever the size, little extra disk. The old version can't
	// be started again; Undo restores it from the backup taken just before
	// the upgrade, losing what was written since.
	UpgradeFast = "fast"
)

// Upgrade statuses (UpgradeState.Status).
const (
	UpgradeInProgress = "in_progress" // upgrade or undo running
	UpgradeDone       = "upgraded"    // running the new major; the old one is kept for Undo
	UpgradeUndone     = "undone"      // back on the old major; the new one is kept aside until cleanup
)

// Upgrade check statuses (UpgradeCheck.Status): CheckOK (migrate.go), or:
const (
	CheckWarning = "warning" // the upgrade can go ahead; read this first
	CheckBlocker = "blocker" // the upgrade (or rehearsal) can't go ahead until this is fixed
)

// Fix kinds for the health findings about updates (see FindingFix).
const (
	FixPGUpdate        = "pg_update"        // pg_update task (confirm; Mark first)
	FixSecurityUpdates = "security_updates" // security_updates task (confirm; Mark first)
	FixReboot          = "reboot"           // reboot task (strong confirm; Mark first)
	FixUpgradeCleanup  = "upgrade_cleanup"  // upgrade_cleanup task (confirm)
)

// ---- task params and results ----

// PGUpdateParams are the params of a pg_update task.
type PGUpdateParams struct {
	// ToVersion is the minor version the person agreed to (e.g. "16.10");
	// informational: the newest minor of the same major is installed.
	ToVersion string `json:"to_version,omitempty"`
}

// PGUpdateResult is the agent's report for a pg_update task.
type PGUpdateResult struct {
	FromVersion string `json:"from_version"` // "16.9"
	ToVersion   string `json:"to_version"`   // "16.10"
	// PackageVersion is the installed postgresql-MAJOR package version.
	PackageVersion string   `json:"package_version,omitempty"`
	Packages       []string `json:"packages,omitempty"` // packages upgraded
	Restarted      bool     `json:"restarted"`
	// DowntimeMs is from the start of the installation until PostgreSQL
	// answered again (the packages stop it while they are replaced).
	DowntimeMs int64 `json:"downtime_ms"`
	DurationMs int64 `json:"duration_ms"`
	// ArchivingOK: pgbackrest check passed afterwards.
	ArchivingOK bool     `json:"archiving_ok"`
	Warnings    []string `json:"warnings,omitempty"`
	Summary     string   `json:"summary"` // "Updated to 16.10 in 12 s."
}

// SecurityUpdatesResult is the agent's report for a security_updates task.
type SecurityUpdatesResult struct {
	Installed int      `json:"installed"`
	Packages  []string `json:"packages,omitempty"`
	// HeldBack are PostgreSQL server packages with a security update, left
	// for Update PostgreSQL (which saves a Mark and checks archiving).
	HeldBack       []string `json:"held_back,omitempty"`
	RebootRequired bool     `json:"reboot_required"`
	DurationMs     int64    `json:"duration_ms"`
	Summary        string   `json:"summary"`
}

// RebootResult is the agent's report for a reboot task, sent after the
// server is back.
type RebootResult struct {
	RequestedAt time.Time  `json:"requested_at"`
	BootedAt    *time.Time `json:"booted_at,omitempty"`
	// DowntimeMs is from the request until PostgreSQL answered again.
	DowntimeMs   int64  `json:"downtime_ms"`
	PostgresBack bool   `json:"postgres_back"`
	Summary      string `json:"summary"`
}

// UpgradeCheckParams are the params of an upgrade_check task.
type UpgradeCheckParams struct {
	ToMajor int `json:"to_major"` // 0: the newest available
}

// UpgradeCheck is one preflight check, in plain words.
type UpgradeCheck struct {
	ID     string `json:"id"`     // stable: packages, extensions, disk, replica, standbys, pgbackrest, helper, layout, ...
	Status string `json:"status"` // Check*
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
}

// UpgradeMode says whether a mode can be used and what it needs.
type UpgradeMode struct {
	Mode      string `json:"mode"`   // UpgradeSafe | UpgradeFast
	Method    string `json:"method"` // pg_upgrade transfer: copy | clone | link
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// NeedBytes is the free disk the mode needs next to the data directory.
	NeedBytes int64 `json:"need_bytes"`
}

// UpgradeCheckResult is the agent's report for an upgrade_check task.
type UpgradeCheckResult struct {
	FromMajor   int    `json:"from_major"`
	ToMajor     int    `json:"to_major"`
	FromVersion string `json:"from_version"`         // running, e.g. "16.9"
	ToVersion   string `json:"to_version,omitempty"` // the target's newest minor, e.g. "18.1"
	// Majors are the newer majors the configured repositories offer.
	Majors []int          `json:"majors,omitempty"`
	Checks []UpgradeCheck `json:"checks"`
	// CanRehearse: nothing blocks a rehearsal. CanUpgrade: nothing blocks
	// the upgrade itself on this server (a passed rehearsal is still
	// required).
	CanRehearse bool          `json:"can_rehearse"`
	CanUpgrade  bool          `json:"can_upgrade"`
	Modes       []UpgradeMode `json:"modes,omitempty"`
	SizeBytes   int64         `json:"size_bytes"`
	FreeBytes   int64         `json:"free_bytes"`
	// Sidecar: PostgreSQL runs in Docker; Rowsafe can't change its image.
	// DockerSteps then describes the change, in plain words.
	Sidecar     bool     `json:"sidecar,omitempty"`
	DockerSteps []string `json:"docker_steps,omitempty"`
	Summary     string   `json:"summary"`
}

// UpgradeRehearsalParams are the params of an upgrade_rehearsal task.
type UpgradeRehearsalParams struct {
	ToMajor int `json:"to_major"`
}

// UpgradeRehearsalResult is the agent's report for an upgrade_rehearsal
// task.
type UpgradeRehearsalResult struct {
	FromMajor   int    `json:"from_major"`
	ToMajor     int    `json:"to_major"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Passed      bool   `json:"passed"`
	// Issues block the upgrade (what pg_upgrade --check or the checks of
	// the upgraded copy found), in plain words; Warnings don't.
	Issues      []string        `json:"issues,omitempty"`
	Warnings    []string        `json:"warnings,omitempty"`
	Databases   []DrillDatabase `json:"databases,omitempty"`
	BackupLabel string          `json:"backup_label,omitempty"`
	RecoveredTo *time.Time      `json:"recovered_to,omitempty"`
	// Timings, in seconds.
	RestoreSeconds float64 `json:"restore_seconds"`
	UpgradeSeconds float64 `json:"upgrade_seconds"` // pg_upgrade itself
	AnalyzeSeconds float64 `json:"analyze_seconds"` // refreshing planner statistics
	TotalSeconds   float64 `json:"total_seconds"`
	// Method is the pg_upgrade transfer mode the rehearsal used.
	Method string `json:"method"`
	// Expected downtime of the real upgrade in each mode (seconds);
	// DowntimeEstimated when a mode's figure is derived rather than
	// measured.
	SafeDowntimeSeconds float64 `json:"safe_downtime_seconds"`
	FastDowntimeSeconds float64 `json:"fast_downtime_seconds"`
	DowntimeEstimated   bool    `json:"downtime_estimated,omitempty"`
	// PgBackRestOK: pgBackRest accepted the upgraded copy (it supports the
	// target major).
	PgBackRestOK bool `json:"pgbackrest_ok"`
	// PackagesInstalled lists packages the rehearsal installed for the
	// target major (they stay installed for the upgrade).
	PackagesInstalled []string `json:"packages_installed,omitempty"`
	Summary           string   `json:"summary"`
}

// UpgradeParams are the params of an upgrade task.
type UpgradeParams struct {
	UpgradeID string `json:"upgrade_id"` // [A-Za-z0-9_-]{1,64}
	ToMajor   int    `json:"to_major"`
	Mode      string `json:"mode"` // UpgradeSafe | UpgradeFast
	// KeepDays is how long the old version is kept for Undo (default 7,
	// 1 to 30).
	KeepDays int `json:"keep_days,omitempty"`
	// Mark is the restore point saved just before (Fast mode's Undo, and
	// its automatic rollback, restore to it), MarkBackupSet the newest
	// backup finished before it (pgbackrest restore --set).
	Mark          string `json:"mark,omitempty"`
	MarkBackupSet string `json:"mark_backup_set,omitempty"`
}

// UpgradeResult is the agent's report for an upgrade task.
type UpgradeResult struct {
	UpgradeID   string `json:"upgrade_id"`
	FromMajor   int    `json:"from_major"`
	ToMajor     int    `json:"to_major"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	Mode        string `json:"mode"`
	Method      string `json:"method"` // copy | clone | link
	// DowntimeMs is from stopping the old version until the new one
	// accepted connections.
	DowntimeMs int64 `json:"downtime_ms"`
	DurationMs int64 `json:"duration_ms"`
	// OldCluster describes where the old version is kept, stopped.
	OldCluster string     `json:"old_cluster,omitempty"`
	KeptUntil  *time.Time `json:"kept_until,omitempty"`
	// BackupsReady: pgBackRest took the new version on (stanza-upgrade and
	// check passed). If not, the agent keeps trying.
	BackupsReady bool `json:"backups_ready"`
	// RolledBack: the upgrade failed and the old version was put back and
	// started (the task fails).
	RolledBack bool     `json:"rolled_back,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
	Summary    string   `json:"summary"`
}

// UpgradeUndoParams are the params of an upgrade_undo task.
type UpgradeUndoParams struct {
	UpgradeID string `json:"upgrade_id"`
	// Target is where Fast mode's Undo restores the old version to: the
	// Mark saved before the upgrade, with its backup set. Unused in Safe
	// mode.
	Target *RewindTarget `json:"target,omitempty"`
}

// UpgradeUndoResult is the agent's report for an upgrade_undo task.
type UpgradeUndoResult struct {
	UpgradeID string `json:"upgrade_id"`
	Version   string `json:"version"` // running again, e.g. "16.10"
	// RestoredTo is set when the old version was restored from the backup
	// (Fast mode).
	RestoredTo   *time.Time `json:"restored_to,omitempty"`
	DowntimeMs   int64      `json:"downtime_ms"`
	DurationMs   int64      `json:"duration_ms"`
	BackupsReady bool       `json:"backups_ready"`
	RolledBack   bool       `json:"rolled_back,omitempty"`
	KeptUntil    *time.Time `json:"kept_until,omitempty"`
	Summary      string     `json:"summary"`
}

// UpgradeCleanupParams are the params of an upgrade_cleanup task.
type UpgradeCleanupParams struct {
	UpgradeID string `json:"upgrade_id"`
}

// UpgradeCleanupResult is the agent's report for an upgrade_cleanup task.
type UpgradeCleanupResult struct {
	UpgradeID       string   `json:"upgrade_id"`
	Removed         bool     `json:"removed"`
	FreedBytes      int64    `json:"freed_bytes"`
	PackagesRemoved []string `json:"packages_removed,omitempty"`
	Summary         string   `json:"summary"`
}

// ---- heartbeat ----

// SoftwareReport is what the agent knows about the server's PostgreSQL
// versions, pending updates and upgrades (HeartbeatRequest.Software). It is
// refreshed about every hour, and right after an update or upgrade.
type SoftwareReport struct {
	CheckedAt time.Time `json:"checked_at"`
	// PackageManager is "apt", or "" where Rowsafe can't read or install
	// packages (Docker sidecar, other systems).
	PackageManager string `json:"package_manager,omitempty"`
	Error          string `json:"error,omitempty"`
	// ListsUpdatedAt is when the package lists were last refreshed.
	ListsUpdatedAt *time.Time `json:"lists_updated_at,omitempty"`
	// Allowed is what root allowed Rowsafe to install or do
	// (UpdateAllow*), from /etc/rowsafe/updates-allowed.
	Allowed []string `json:"allowed,omitempty"`
	// HelperActions are the update actions the installed root helper
	// understands (empty: no update helper installed).
	HelperActions []string          `json:"helper_actions,omitempty"`
	Clusters      []ClusterSoftware `json:"clusters,omitempty"`
	// SecurityUpdates counts packages with a pending security update;
	// SecurityPackages names the first ones.
	SecurityUpdates  int        `json:"security_updates"`
	SecurityPackages []string   `json:"security_packages,omitempty"`
	RebootRequired   bool       `json:"reboot_required"`
	RebootPackages   []string   `json:"reboot_packages,omitempty"`
	BootedAt         *time.Time `json:"booted_at,omitempty"`
	// Upgrades are the major upgrades on this server that can still be
	// undone or cleaned up.
	Upgrades []UpgradeState `json:"upgrades,omitempty"`
}

// ClusterSoftware is one local PostgreSQL cluster's versions.
type ClusterSoftware struct {
	Port    int    `json:"port"`
	Major   int    `json:"major"`
	Cluster string `json:"cluster,omitempty"` // Debian cluster name, e.g. "main"
	Unit    string `json:"unit,omitempty"`
	// Running is the running server's version ("16.9"; "" when down).
	Running string `json:"running,omitempty"`
	// Installed is the installed package's minor version ("16.10") and
	// InstalledPackage its full package version.
	Installed        string `json:"installed,omitempty"`
	InstalledPackage string `json:"installed_package,omitempty"`
	// Candidate is the newest minor of the same major the repositories
	// offer; equal to Installed when up to date.
	Candidate        string `json:"candidate,omitempty"`
	CandidatePackage string `json:"candidate_package,omitempty"`
	// Origin is where the packages come from: "apt.postgresql.org",
	// "Debian", "Ubuntu" or "".
	Origin string `json:"origin,omitempty"`
	// Majors are newer majors the repositories offer, oldest first.
	Majors            []int    `json:"majors,omitempty"`
	ExtensionPackages []string `json:"extension_packages,omitempty"`
}

// UpgradeState is a major upgrade that can still be undone or cleaned up.
type UpgradeState struct {
	ID         string     `json:"id"`
	DatabaseID string     `json:"database_id"`
	Port       int        `json:"port"`
	FromMajor  int        `json:"from_major"`
	ToMajor    int        `json:"to_major"`
	Mode       string     `json:"mode"`
	Status     string     `json:"status"` // Upgrade*
	CreatedAt  time.Time  `json:"created_at"`
	Expires    *time.Time `json:"expires,omitempty"` // when the kept version is removed by itself
	// KeptCluster is the version kept aside, e.g. "16/main (port 5433, stopped)".
	KeptCluster   string `json:"kept_cluster,omitempty"`
	KeptSizeBytes int64  `json:"kept_size_bytes,omitempty"`
	// BackupsReady: pgBackRest took on the running version.
	BackupsReady bool `json:"backups_ready"`
	// Mark is the Mark saved before the upgrade (Fast mode's Undo restores to it).
	Mark string `json:"mark,omitempty"`
}

// ---- user API ----
//
//	GET  /v1/databases/{ref}/upgrades                       UpgradeInfo
//	POST /v1/databases/{ref}/update                         ConfirmRequest -> UpgradeTasksResponse (Mark, then pg_update)
//	PUT  /v1/databases/{ref}/auto-update                    AutoUpdateRequest -> UpgradeInfo
//	POST /v1/databases/{ref}/upgrades/check                 UpgradeTargetRequest -> UpgradeTasksResponse
//	POST /v1/databases/{ref}/upgrades/rehearsal             UpgradeTargetRequest -> UpgradeTasksResponse
//	POST /v1/databases/{ref}/upgrades                       UpgradeRequest -> UpgradeTasksResponse (Mark, then upgrade)
//	POST /v1/databases/{ref}/upgrades/{id}/undo             ConfirmRequest -> UpgradeTasksResponse
//	POST /v1/databases/{ref}/upgrades/{id}/cleanup          -> UpgradeTasksResponse
//	POST /v1/databases/{ref}/security-updates               ConfirmRequest -> UpgradeTasksResponse (Mark, then security_updates)
//	POST /v1/databases/{ref}/reboot                         ConfirmRequest -> UpgradeTasksResponse (Mark, then reboot)
//
// Owners and admins with read-write keys only; never through /mcp; audited.

// UpgradeInfo answers GET /v1/databases/{ref}/upgrades.
type UpgradeInfo struct {
	DatabaseID string `json:"database_id"`
	Database   string `json:"database"`
	Host       string `json:"host"`
	// Version is the running version ("16.9"), Major its major.
	Version string `json:"version,omitempty"`
	Major   int    `json:"major,omitempty"`
	// Installed and Candidate are package minor versions (Candidate is
	// newer when UpdateAvailable).
	Installed       string `json:"installed,omitempty"`
	Candidate       string `json:"candidate,omitempty"`
	UpdateAvailable bool   `json:"update_available"`
	// RestartPending: newer binaries are installed than the running server
	// uses (a restart finishes the update).
	RestartPending bool `json:"restart_pending,omitempty"`
	// Majors are newer majors the server's repositories offer.
	Majors []int `json:"majors,omitempty"`
	// Sidecar: PostgreSQL runs in Docker (Rowsafe can check and rehearse,
	// but the upgrade itself is a change to the compose file).
	Sidecar bool `json:"sidecar,omitempty"`
	// What root allowed on this server (UpdateAllow*), and why an action
	// can't run now (empty when it can).
	Allowed         []string `json:"allowed"`
	UpdateReason    string   `json:"update_reason,omitempty"`
	UpgradeReason   string   `json:"upgrade_reason,omitempty"`
	SecurityReason  string   `json:"security_reason,omitempty"`
	RebootReason    string   `json:"reboot_reason,omitempty"`
	SecurityUpdates int      `json:"security_updates"`
	RebootRequired  bool     `json:"reboot_required"`
	// Automatic minor updates: Sundays at 03:00 in Timezone.
	AutoMinorUpdates bool       `json:"auto_minor_updates"`
	AutoTimezone     string     `json:"auto_timezone,omitempty"`
	NextAutoUpdate   *time.Time `json:"next_auto_update,omitempty"`
	// Check is the newest preflight; Rehearsal the newest rehearsal (with
	// the task that ran it), RehearsalValid whether it still allows an
	// upgrade to its target (passed, recent, same major since).
	Check            *UpgradeCheckResult     `json:"check,omitempty"`
	CheckAt          *time.Time              `json:"check_at,omitempty"`
	Rehearsal        *UpgradeRehearsalResult `json:"rehearsal,omitempty"`
	RehearsalAt      *time.Time              `json:"rehearsal_at,omitempty"`
	RehearsalValid   bool                    `json:"rehearsal_valid"`
	RehearsalTaskID  string                  `json:"rehearsal_task_id,omitempty"`
	RehearsalExpires *time.Time              `json:"rehearsal_expires,omitempty"`
	// Upgrade is the upgrade that can still be undone or cleaned up.
	Upgrade *UpgradeState `json:"upgrade,omitempty"`
	// CheckedAt is when the agent last looked at the server's packages.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Tasks are recent update and upgrade tasks, newest first.
	Tasks []TaskView `json:"tasks,omitempty"`
}

// ConfirmRequest carries the confirmation of a change: the database's name
// (the host name for a reboot).
type ConfirmRequest struct {
	Confirm string `json:"confirm"`
}

// UpgradeTargetRequest names the major to check or rehearse (0: newest).
type UpgradeTargetRequest struct {
	To int `json:"to,omitempty"`
}

// UpgradeRequest starts a major upgrade.
type UpgradeRequest struct {
	To      int    `json:"to"`
	Mode    string `json:"mode"`    // UpgradeSafe | UpgradeFast
	Confirm string `json:"confirm"` // the database's name
}

// AutoUpdateRequest turns automatic minor updates on or off.
type AutoUpdateRequest struct {
	Enabled bool `json:"enabled"`
	// Timezone is an IANA zone (e.g. "Europe/Berlin"); updates run on
	// Sundays at 03:00 there. Default UTC.
	Timezone string `json:"timezone,omitempty"`
}

// UpgradeTasksResponse lists the tasks a request queued, in order (e.g.
// the Mark, then the update).
type UpgradeTasksResponse struct {
	Tasks []TaskView `json:"tasks"`
}
