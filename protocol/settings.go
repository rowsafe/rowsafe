package protocol

import "time"

// ---- Settings and tuning ----
//
// The agent reports the PostgreSQL settings that matter (and every setting
// changed from its default) with the host's memory, CPUs and disk type, in
// its monitoring report about every 5 minutes. The control plane explains
// them, recommends values for the server (package tune), and changes them
// only through a settings task: ALTER SYSTEM for each setting, then a
// reload. Settings that need a restart wait for one; Rowsafe never restarts
// PostgreSQL on its own. Rowsafe's archiving settings are never changed
// this way.

// TaskSettings changes PostgreSQL settings with ALTER SYSTEM and reloads
// (SettingsParams -> SettingsResult). The agent validates every change
// again (locked settings, limits against the host's memory, libraries that
// must exist), keeps the previous postgresql.auto.conf values in the result
// so the change can be undone, and puts them back if PostgreSQL reports an
// error in its configuration afterwards. It runs beside backups (like a
// health fix), never beside a restart.
const TaskSettings = "settings"

// FixTune is a health fix that changes settings: a settings task with
// SettingsParams (e.g. the memory recommendations, or loading
// pg_stat_statements).
const FixTune = "tune"

// Kinds of settings changes (SettingsParams.Kind, SettingsChange.Kind).
const (
	SettingsKindTune   = "tune"   // recommendations for the server
	SettingsKindSet    = "set"    // one or more settings a person chose
	SettingsKindFix    = "fix"    // a Pulse fix
	SettingsKindRevert = "revert" // undoing an earlier change
)

// Workload hints for recommendations.
const (
	WorkloadWeb       = "web"       // many short queries: a web or mobile app's database
	WorkloadAnalytics = "analytics" // few, large queries: reporting, a data warehouse
	WorkloadMixed     = "mixed"     // some of both (the default)
)

// Disk kinds (SettingsHost.Disk).
const (
	DiskSSD = "ssd"
	DiskHDD = "hdd"
)

// SettingChange is one change: Value, or back to the default (Reset:
// ALTER SYSTEM RESET).
type SettingChange struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Reset bool   `json:"reset,omitempty"`
}

// SettingsParams are the params of a settings task.
type SettingsParams struct {
	Kind    string          `json:"kind"` // SettingsKind*
	Changes []SettingChange `json:"changes"`
}

// SettingsResult is the agent's report for a settings task.
type SettingsResult struct {
	Applied []AppliedSetting `json:"applied"`
	// PendingRestart lists every setting that waits for a restart now
	// (these changes and earlier ones).
	PendingRestart []string `json:"pending_restart,omitempty"`
	// Summary is plain words: "Changed 5 settings; 2 take effect after a
	// restart."
	Summary string `json:"summary"`
	// Snapshot is the settings as they are after the change.
	Snapshot *SettingsSnapshot `json:"snapshot,omitempty"`
	// Extension is set when the agent also created an extension (e.g.
	// pg_stat_statements in the postgres database).
	Extension string `json:"extension,omitempty"`
}

// AppliedSetting is one setting a settings task changed.
type AppliedSetting struct {
	Name string `json:"name"`
	From string `json:"from"`         // the value in effect before
	To   string `json:"to,omitempty"` // "" when reset to the default
	// Previous is the setting's line in postgresql.auto.conf before the
	// change (nil: none, so undoing it is ALTER SYSTEM RESET).
	Previous *string `json:"previous,omitempty"`
	// Restart: the new value takes effect after PostgreSQL restarts.
	Restart bool `json:"restart,omitempty"`
}

// SettingsHost is what recommendations need to know about the server.
type SettingsHost struct {
	MemoryBytes int64 `json:"memory_bytes,omitempty"`
	CPUs        int   `json:"cpus,omitempty"`
	// Disk is DiskSSD or DiskHDD as the kernel reports the data
	// directory's disk (/sys/block/*/queue/rotational); "" when unknown.
	// Virtual disks often report "hdd" on SSD-backed clouds: people can
	// correct it.
	Disk string `json:"disk,omitempty"`
	// DataDiskBytes is the size of the filesystem holding the data
	// directory.
	DataDiskBytes int64 `json:"data_disk_bytes,omitempty"`
}

// PGSetting is one row of pg_settings (with the pending value from
// pg_file_settings).
type PGSetting struct {
	Name     string   `json:"name"`
	Setting  string   `json:"setting"`        // in Unit, as pg_settings has it
	Unit     string   `json:"unit,omitempty"` // "8kB", "kB", "MB", "ms", "s", "min"
	VarType  string   `json:"vartype"`        // bool, integer, real, string, enum
	Context  string   `json:"context"`        // postmaster (restart), sighup (reload), user, superuser, ...
	Source   string   `json:"source"`         // default, configuration file, command line, override, ...
	BootVal  string   `json:"boot_val,omitempty"`
	MinVal   string   `json:"min_val,omitempty"`
	MaxVal   string   `json:"max_val,omitempty"`
	EnumVals []string `json:"enum_vals,omitempty"`
	// SourceFile is the base name of the file the value comes from
	// (postgresql.conf, postgresql.auto.conf, an include file).
	SourceFile     string `json:"source_file,omitempty"`
	PendingRestart bool   `json:"pending_restart,omitempty"`
	// PendingValue is the value in the configuration files that waits for
	// a restart (when PendingRestart).
	PendingValue string `json:"pending_value,omitempty"`
	// AutoConf is the value in postgresql.auto.conf (ALTER SYSTEM), if any.
	AutoConf *string `json:"auto_conf,omitempty"`
}

// SettingsSnapshot is the settings the agent reports (DatabaseMonitoring.
// Settings, about every 5 minutes) and returns after a settings task.
type SettingsSnapshot struct {
	CollectedAt time.Time    `json:"collected_at,omitzero"`
	VersionNum  int          `json:"version_num,omitempty"`
	Host        SettingsHost `json:"host"`
	// Settings are the settings in tune's catalog and every other setting
	// set in a configuration file or on the command line.
	Settings []PGSetting `json:"settings"`
	// ConfigErrors are problems PostgreSQL found in its configuration
	// files (pg_file_settings.error): they would stop it at the next
	// restart. Rowsafe changes nothing while there are any.
	ConfigErrors []string `json:"config_errors,omitempty"`
	// PgStatStatements: "loaded" (in shared_preload_libraries and running),
	// "available" (installed, not loaded) or "" (not installed).
	PgStatStatements string `json:"pg_stat_statements,omitempty"`
	// InRecovery: a standby, where settings follow the primary's rules.
	InRecovery bool `json:"in_recovery,omitempty"`
	// DatabaseBytes is the size of all its databases.
	DatabaseBytes int64 `json:"database_bytes,omitempty"`
}

// ---- User API ----
//
//	GET  /v1/databases/{ref}/settings[?workload=web|analytics|mixed&disk=ssd|hdd]  SettingsOverview
//	POST /v1/databases/{ref}/settings                          ApplySettingsRequest -> 202 ApplySettingsResponse
//	POST /v1/databases/{ref}/settings/changes/{id}/revert      -> 202 ApplySettingsResponse

// SettingsOverview answers GET /v1/databases/{ref}/settings.
type SettingsOverview struct {
	// Available is false until the agent has reported settings; Reason
	// says why.
	Available   bool         `json:"available"`
	Reason      string       `json:"reason,omitempty"`
	CollectedAt *time.Time   `json:"collected_at,omitempty"`
	VersionNum  int          `json:"version_num,omitempty"`
	Host        SettingsHost `json:"host"`
	// DiskDetected is what the agent detected; Host.Disk is what
	// recommendations use (the person's choice when they corrected it).
	DiskDetected string `json:"disk_detected,omitempty"`
	Workload     string `json:"workload"`
	// Settings are the settings that matter, by category, then Other: the
	// rest set in a configuration file.
	Settings []SettingView `json:"settings"`
	Other    []SettingView `json:"other"`
	// Recommendations are what "Tune for this server" would change.
	Recommendations []Recommendation `json:"recommendations"`
	PendingRestart  []string         `json:"pending_restart"`
	ConfigErrors    []string         `json:"config_errors,omitempty"`
	// Changes are the latest changes made through Rowsafe, newest first.
	Changes []SettingsChange `json:"changes"`
	// CanRestart: Restart PostgreSQL may be offered (restarts allowed, agent
	// online, not a Docker sidecar).
	CanRestart bool `json:"can_restart"`
	// CanChange is false when Rowsafe can't change settings now (agent
	// offline, a standby, errors in the configuration); ChangeReason says
	// why.
	CanChange    bool   `json:"can_change"`
	ChangeReason string `json:"change_reason,omitempty"`
	// Busy: a settings change is queued or running.
	Busy bool `json:"busy,omitempty"`
}

// Setting categories, in display order.
const (
	SettingsCatMemory      = "memory"
	SettingsCatConnections = "connections"
	SettingsCatWAL         = "wal"
	SettingsCatAutovacuum  = "autovacuum"
	SettingsCatPlanner     = "planner"
	SettingsCatParallel    = "parallel"
	SettingsCatTimeouts    = "timeouts"
	SettingsCatLogging     = "logging"
	SettingsCatStatistics  = "statistics"
	SettingsCatOther       = "other"
)

// SettingView is one setting as the dashboard shows it.
type SettingView struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Title       string   `json:"title,omitempty"`       // "Shared memory cache"
	Explanation string   `json:"explanation,omitempty"` // plain words
	Value       string   `json:"value"`                 // for people: "128 MB", "on", "5 min"
	Setting     string   `json:"setting"`               // raw, in Unit
	Unit        string   `json:"unit,omitempty"`
	VarType     string   `json:"vartype"`
	EnumVals    []string `json:"enum_vals,omitempty"`
	Default     string   `json:"default"` // for people
	IsDefault   bool     `json:"is_default"`
	// Source: "default", "postgresql.conf", "postgresql.auto.conf" (set
	// with ALTER SYSTEM, e.g. by Rowsafe), "command line", or another file.
	Source string `json:"source"`
	// Apply: "reload" (takes effect at once) or "restart".
	Apply          string `json:"apply"`
	PendingRestart bool   `json:"pending_restart,omitempty"`
	PendingValue   string `json:"pending_value,omitempty"` // for people
	Locked         bool   `json:"locked,omitempty"`
	LockedReason   string `json:"locked_reason,omitempty"`
}

// Recommendation is one change "Tune for this server" proposes.
type Recommendation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Current string `json:"current"` // for people
	Value   string `json:"value"`   // what to set, in PostgreSQL's syntax: "4GB", "1.1"
	Display string `json:"display"` // for people: "4 GB"
	Why     string `json:"why"`
	Restart bool   `json:"restart,omitempty"`
	// Optional recommendations change behavior apps may notice (e.g.
	// ending forgotten transactions): offered, not selected by default.
	Optional bool `json:"optional,omitempty"`
}

// ApplySettingsRequest is the body of POST /v1/databases/{ref}/settings.
type ApplySettingsRequest struct {
	// Kind is SettingsKindTune (Changes must be among the recommendations)
	// or SettingsKindSet.
	Kind    string          `json:"kind"`
	Changes []SettingChange `json:"changes"`
	// Workload and Disk are remembered for later recommendations (tune).
	Workload string `json:"workload,omitempty"`
	Disk     string `json:"disk,omitempty"`
}

// ApplySettingsResponse answers an apply or revert (202): the queued tasks,
// a restore_point task first when Rowsafe saves a Mark before.
type ApplySettingsResponse struct {
	ChangeID string     `json:"change_id"`
	Tasks    []TaskView `json:"tasks"`
}

// SettingsChange is one change made through Rowsafe.
type SettingsChange struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	TaskID    string          `json:"task_id"`
	Status    string          `json:"status"` // the task's
	Error     string          `json:"error,omitempty"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
	Requested []SettingChange `json:"requested"`
	// Applied is filled once the task succeeded.
	Applied []AppliedSetting `json:"applied,omitempty"`
	Summary string           `json:"summary,omitempty"`
	// RevertOf is the change this one undid; RevertedBy the change that
	// undid this one.
	RevertOf   string `json:"revert_of,omitempty"`
	RevertedBy string `json:"reverted_by,omitempty"`
	// CanRevert: succeeded, not undone yet, and the newest change of the
	// settings it touched.
	CanRevert bool `json:"can_revert,omitempty"`
}
