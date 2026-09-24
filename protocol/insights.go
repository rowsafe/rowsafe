package protocol

import (
	"encoding/json"
	"time"
)

// Deeper monitoring: query trends, table and index insights, locks,
// replication, availability, health scores and disk forecasts. Everything
// here is additive: older agents and control planes ignore it.

// ---- Agent -> control plane ----

// QueryStats is what pg_stat_statements recorded between two readings,
// about 5 minutes apart: the agent subtracts the previous cumulative
// counters, so a statistics reset, an evicted entry or an agent restart
// yields no numbers for that interval rather than a bogus spike.
// Statements are aggregated by query ID (over users and databases).
type QueryStats struct {
	CollectedAt     time.Time `json:"collected_at,omitzero"`
	IntervalSeconds float64   `json:"interval_seconds"` // time since the previous reading
	// Statements are the busiest statements of the interval (by total
	// execution time, plus the most frequently called), at most 50.
	Statements []QueryDelta `json:"statements"`
	// Totals over every statement in the interval, listed or not.
	TotalCalls  int64   `json:"total_calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	// Truncated is how many active statements were left out.
	Truncated int `json:"truncated,omitempty"`
}

// QueryDelta is one statement's activity during an interval.
type QueryDelta struct {
	QueryID     string  `json:"query_id"` // pg_stat_statements queryid, a 64-bit integer as a string
	Query       string  `json:"query"`    // normalized text, up to 2000 characters
	Database    string  `json:"database,omitempty"`
	User        string  `json:"user,omitempty"`
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	Rows        int64   `json:"rows"`
}

// LockSession is one session in a blocking chain: waiting for a lock, or
// holding one that others wait for (or both).
type LockSession struct {
	PID int `json:"pid"`
	// BlockedBy lists the sessions it waits for (empty for a session that
	// only blocks others: the root of a chain).
	BlockedBy []int `json:"blocked_by"`
	// Blocking is how many sessions wait directly for this one.
	Blocking int `json:"blocking"`
	// WaitSeconds is how long it has waited for the lock (0 when not
	// waiting).
	WaitSeconds     float64 `json:"wait_seconds"`
	LockType        string  `json:"lock_type,omitempty"` // relation, transactionid, tuple, ...
	LockMode        string  `json:"lock_mode,omitempty"` // mode it waits for, e.g. AccessExclusiveLock
	Relation        string  `json:"relation,omitempty"`  // table it waits on, when known
	State           string  `json:"state"`
	DurationSeconds float64 `json:"duration_seconds"` // since its current (or last) query started
	XactSeconds     float64 `json:"xact_seconds"`     // since its transaction started
	WaitEventType   string  `json:"wait_event_type,omitempty"`
	WaitEvent       string  `json:"wait_event,omitempty"`
	ApplicationName string  `json:"application_name,omitempty"`
	Database        string  `json:"database,omitempty"`
	User            string  `json:"user,omitempty"`
	Query           string  `json:"query,omitempty"` // up to 500 characters; empty with ROWSAFE_COLLECT_QUERY_TEXT=false
	// BackendStart is when the session started (see ActivityQuery).
	BackendStart *time.Time `json:"backend_start,omitempty"`
}

// ReplicationStatus describes streaming replication from this server's
// point of view.
type ReplicationStatus struct {
	Role string `json:"role"` // primary | replica
	// Replicas are standbys connected to this server (pg_stat_replication).
	Replicas []Replica `json:"replicas"`
	// Receiver is set on a replica: its connection to the primary.
	Receiver *WALReceiver `json:"receiver,omitempty"`
	// On a replica: how far replay is behind. ReplayLagSeconds is 0 when
	// everything received has been replayed.
	ReplayLagSeconds *float64 `json:"replay_lag_seconds,omitempty"`
	ReplayLagBytes   *int64   `json:"replay_lag_bytes,omitempty"`
}

// Replica is one standby streaming from this server.
type Replica struct {
	ApplicationName  string     `json:"application_name,omitempty"`
	ClientAddr       string     `json:"client_addr,omitempty"`
	State            string     `json:"state"`      // streaming, catchup, backup, ...
	SyncState        string     `json:"sync_state"` // async, sync, potential, quorum
	SentLagBytes     *int64     `json:"sent_lag_bytes,omitempty"`
	FlushLagBytes    *int64     `json:"flush_lag_bytes,omitempty"`
	ReplayLagBytes   *int64     `json:"replay_lag_bytes,omitempty"`
	WriteLagSeconds  *float64   `json:"write_lag_seconds,omitempty"`
	FlushLagSeconds  *float64   `json:"flush_lag_seconds,omitempty"`
	ReplayLagSeconds *float64   `json:"replay_lag_seconds,omitempty"`
	ReplyAt          *time.Time `json:"reply_at,omitempty"`
}

// WALReceiver is a replica's connection to its primary (pg_stat_wal_receiver).
// The connection string is never collected: it may hold a password.
type WALReceiver struct {
	Status        string     `json:"status"` // streaming, starting, ...; "" when not connected
	SenderHost    string     `json:"sender_host,omitempty"`
	SenderPort    int        `json:"sender_port,omitempty"`
	SlotName      string     `json:"slot_name,omitempty"`
	LastMessageAt *time.Time `json:"last_message_at,omitempty"`
}

// Insights are table and index statistics of every database of a cluster,
// collected every 30 minutes or so. Each list holds at most 20 entries,
// worst first. Bloat figures are estimates from the planner statistics
// (the widely used queries from the PostgreSQL community), not
// measurements.
type Insights struct {
	CollectedAt time.Time          `json:"collected_at,omitzero"`
	DurationMs  int64              `json:"duration_ms"`
	Databases   []InsightsDatabase `json:"databases"`
	// Truncated is true when some databases or checks were skipped
	// (too many databases or tables, or a query timed out); Notes say which.
	Truncated bool     `json:"truncated"`
	Notes     []string `json:"notes,omitempty"`

	LargestTables    []TableSize      `json:"largest_tables"`
	LargestIndexes   []IndexSize      `json:"largest_indexes"`
	TableBloat       []TableBloat     `json:"table_bloat"`
	IndexBloat       []IndexBloat     `json:"index_bloat"`
	UnusedIndexes    []UnusedIndex    `json:"unused_indexes"`
	DuplicateIndexes []DuplicateIndex `json:"duplicate_indexes"`
	SeqScanTables    []SeqScanTable   `json:"seq_scan_tables"`
	VacuumStats      []TableVacuum    `json:"vacuum_stats"`
	FreezeAge        []TableFreeze    `json:"freeze_age"`
}

// InsightsDatabase is one database looked at.
type InsightsDatabase struct {
	Name string `json:"name"`
	// StatsReset is when this database's statistics were last reset;
	// usage counts (index scans, sequential scans) are counted since then.
	// Nil when they were never reset.
	StatsReset *time.Time `json:"stats_reset,omitempty"`
	Tables     int        `json:"tables"`
	Skipped    string     `json:"skipped,omitempty"` // why it was not examined
}

type TableSize struct {
	Database     string `json:"database"`
	Schema       string `json:"schema"`
	Table        string `json:"table"`
	TotalBytes   int64  `json:"total_bytes"` // table + indexes + TOAST
	TableBytes   int64  `json:"table_bytes"`
	IndexBytes   int64  `json:"index_bytes"`
	RowsEstimate int64  `json:"rows_estimate"`
}

type IndexSize struct {
	Database string `json:"database"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Index    string `json:"index"`
	Bytes    int64  `json:"bytes"`
	Scans    int64  `json:"scans"`
}

// TableBloat is estimated wasted space in a table.
type TableBloat struct {
	Database   string  `json:"database"`
	Schema     string  `json:"schema"`
	Table      string  `json:"table"`
	TableBytes int64   `json:"table_bytes"`
	BloatBytes int64   `json:"bloat_bytes"` // estimate
	BloatPct   float64 `json:"bloat_pct"`   // estimate
}

// IndexBloat is estimated wasted space in a B-tree index.
type IndexBloat struct {
	Database   string  `json:"database"`
	Schema     string  `json:"schema"`
	Table      string  `json:"table"`
	Index      string  `json:"index"`
	IndexBytes int64   `json:"index_bytes"`
	BloatBytes int64   `json:"bloat_bytes"` // estimate
	BloatPct   float64 `json:"bloat_pct"`   // estimate
}

// UnusedIndex has not been scanned since statistics were last reset. It
// excludes indexes that enforce a primary key, unique or exclusion
// constraint.
type UnusedIndex struct {
	Database   string     `json:"database"`
	Schema     string     `json:"schema"`
	Table      string     `json:"table"`
	Index      string     `json:"index"`
	Bytes      int64      `json:"bytes"`
	Definition string     `json:"definition"`
	StatsSince *time.Time `json:"stats_since,omitempty"` // nil: since statistics began
}

// DuplicateIndex is an index that another index makes unnecessary.
type DuplicateIndex struct {
	Database string `json:"database"`
	Schema   string `json:"schema"`
	Table    string `json:"table"`
	Index    string `json:"index"` // the one that can go
	// Kind: "duplicate" (same columns and options) or "redundant" (its
	// columns are the leading columns of CoveredBy).
	Kind              string `json:"kind"`
	CoveredBy         string `json:"covered_by"`
	Bytes             int64  `json:"bytes"`
	Definition        string `json:"definition"`
	CoveredDefinition string `json:"covered_by_definition"`
}

// SeqScanTable is a large table read mostly by sequential scans.
type SeqScanTable struct {
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	SeqScans   int64  `json:"seq_scans"`
	SeqRows    int64  `json:"seq_rows_read"`
	IndexScans int64  `json:"index_scans"`
	LiveRows   int64  `json:"live_rows"`
	TableBytes int64  `json:"table_bytes"`
}

// TableVacuum is a table's dead rows and last maintenance.
type TableVacuum struct {
	Database         string     `json:"database"`
	Schema           string     `json:"schema"`
	Table            string     `json:"table"`
	LiveRows         int64      `json:"live_rows"`
	DeadRows         int64      `json:"dead_rows"`
	DeadPct          float64    `json:"dead_pct"`
	ModsSinceAnalyze int64      `json:"mods_since_analyze"`
	LastVacuum       *time.Time `json:"last_vacuum,omitempty"`
	LastAutovacuum   *time.Time `json:"last_autovacuum,omitempty"`
	LastAnalyze      *time.Time `json:"last_analyze,omitempty"`
	LastAutoanalyze  *time.Time `json:"last_autoanalyze,omitempty"`
	TableBytes       int64      `json:"table_bytes"`
}

// TableFreeze is a table's transaction ID age: at 2^31 PostgreSQL stops
// accepting writes; autovacuum freezes tables long before that.
type TableFreeze struct {
	Database      string  `json:"database"`
	Schema        string  `json:"schema"`
	Table         string  `json:"table"`
	XIDAge        int64   `json:"xid_age"`
	FreezeMaxAge  int64   `json:"freeze_max_age"` // autovacuum_freeze_max_age
	WraparoundPct float64 `json:"wraparound_pct"` // XIDAge as a share of the 2^31 limit
	TableBytes    int64   `json:"table_bytes"`
}

// ---- User API ----

// Health grades, from best to worst.
const (
	GradeHealthy        = "healthy"         // score 90-100
	GradeNeedsAttention = "needs_attention" // 70-89
	GradeAtRisk         = "at_risk"         // 50-69
	GradeCritical       = "critical"        // below 50
)

// DatabaseHealth answers GET /v1/databases/{ref}/health.
type DatabaseHealth struct {
	DatabaseID string    `json:"database_id"`
	Database   string    `json:"database"`
	Host       string    `json:"host"`
	Status     string    `json:"status"` // lifecycle status (active, pending_adopt, ...)
	Score      int       `json:"score"`  // 0-100
	Grade      string    `json:"grade"`  // healthy | needs_attention | at_risk | critical
	Summary    string    `json:"summary"`
	CheckedAt  time.Time `json:"checked_at"`
	// Findings are problems, worst first; empty when all is well.
	Findings []Finding `json:"findings"`
	// Checks are one line per area (backups, disk, ...), good or bad.
	Checks       []HealthCheck `json:"checks"`
	DiskForecast *DiskForecast `json:"disk_forecast,omitempty"`
}

// Finding is one problem, in plain language.
type Finding struct {
	ID          string `json:"id"`       // stable code, e.g. "disk_full_soon"
	Category    string `json:"category"` // protection | availability | disk | connections | maintenance | performance | replication
	Severity    string `json:"severity"` // critical | warning | info
	Title       string `json:"title"`
	Explanation string `json:"explanation"`
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"` // CLI command or SQL to start with
	Penalty     int    `json:"penalty"`           // points taken off the score
	// Fixes are what Rowsafe can do about it, best first. Clients apply one
	// by ids only (POST /v1/databases/{ref}/fixes); the server recomputes
	// health and runs the fix with its own params.
	Fixes []FindingFix `json:"fixes,omitempty"`
}

// FindingFix is one thing Rowsafe can do about a finding ("Apply fix").
type FindingFix struct {
	// ID is stable within the finding, e.g. "vacuum", "end:4312",
	// "drop:public.orders_created_idx".
	ID   string `json:"id"`
	Kind string `json:"kind"` // Fix* below
	// Label is the button text, e.g. "Back up now", "Clean up 3 tables".
	Label string `json:"label"`
	// Description says what happens, the impact and how long it takes, in
	// plain words (1-2 sentences).
	Description string `json:"description"`
	// Params are built by the server; clients display nothing from them.
	Params json.RawMessage `json:"params,omitempty"`
	// Confirm, when set, is a warning to show before running it; the API
	// then needs confirm = the database name.
	Confirm     string `json:"confirm,omitempty"`
	Destructive bool   `json:"destructive,omitempty"`
	// MarkFirst: Rowsafe saves a Mark (restore point) before running it.
	MarkFirst bool `json:"mark_first,omitempty"`
	// Available is false when it can't run now; Reason says why (agent
	// offline, restarts not allowed, needs PostgreSQL 12+, ...).
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Fix kinds. All but FixMaintenance map to existing task types.
const (
	FixBackup      = "backup"      // backup task, params BackupParams
	FixProof       = "proof"       // drill task
	FixCheck       = "check"       // check (verify) task
	FixApply       = "apply"       // adopt task with apply (confirm)
	FixPlan        = "plan"        // adopt task, plan only
	FixRestart     = "restart"     // restart task (confirm; only when restarts are allowed)
	FixMaintenance = "maintenance" // maintenance task, params MaintenanceParams
)

// ApplyFixRequest is the body of POST /v1/databases/{ref}/fixes.
type ApplyFixRequest struct {
	FindingID string `json:"finding_id"`
	FixID     string `json:"fix_id"`
	// Confirm is the database name, required when the fix has Confirm.
	Confirm string `json:"confirm,omitempty"`
}

// ApplyFixResponse answers POST /v1/databases/{ref}/fixes (202): the queued
// tasks, a restore_point task first when the fix has MarkFirst.
type ApplyFixResponse struct {
	Tasks []TaskView `json:"tasks"`
}

// HealthCheck is the state of one area.
type HealthCheck struct {
	Category string `json:"category"`
	Label    string `json:"label"`
	Status   string `json:"status"` // ok | warning | critical | unknown
	Detail   string `json:"detail"`
}

// HealthOverview answers GET /v1/health: every database, worst first.
type HealthOverview struct {
	CheckedAt time.Time               `json:"checked_at"`
	Databases []DatabaseHealthSummary `json:"databases"`
}

type DatabaseHealthSummary struct {
	DatabaseID string   `json:"database_id"`
	Database   string   `json:"database"`
	Host       string   `json:"host"`
	Status     string   `json:"status"`
	Score      int      `json:"score"`
	Grade      string   `json:"grade"`
	Summary    string   `json:"summary"`
	Critical   int      `json:"critical"`
	Warnings   int      `json:"warnings"`
	Info       int      `json:"info"`
	TopFinding *Finding `json:"top_finding,omitempty"`
}

// Disk forecast states.
const (
	ForecastFilling       = "filling"         // growing: DaysUntilFull is set
	ForecastNotGrowing    = "not_growing"     // flat or shrinking
	ForecastNotEnoughData = "not_enough_data" // under 2 days of history
	ForecastNoData        = "no_data"         // no disk metrics (agent can't read the data directory)
)

// DiskForecast estimates when the filesystem holding PostgreSQL's data
// directory fills up, from a robust trend (Theil-Sen) of hourly disk usage
// over the last 14 days.
type DiskForecast struct {
	State      string    `json:"state"`
	Summary    string    `json:"summary"` // plain language
	ComputedAt time.Time `json:"computed_at"`
	FreeBytes  *int64    `json:"free_bytes,omitempty"`
	TotalBytes *int64    `json:"total_bytes,omitempty"`
	UsedPct    *float64  `json:"used_pct,omitempty"`
	// DaysUntilFull and FullAt are set when the disk is filling.
	DaysUntilFull *float64   `json:"days_until_full,omitempty"`
	FullAt        *time.Time `json:"full_at,omitempty"`
	// Growth of used disk space (negative: shrinking).
	GrowthBytesPerDay  *float64 `json:"growth_bytes_per_day,omitempty"`
	GrowthBytesPerWeek *float64 `json:"growth_bytes_per_week,omitempty"`
	// Growth of all databases' size together.
	DatabaseSizeBytes          *int64   `json:"database_size_bytes,omitempty"`
	DatabaseGrowthBytesPerDay  *float64 `json:"database_growth_bytes_per_day,omitempty"`
	DatabaseGrowthBytesPerWeek *float64 `json:"database_growth_bytes_per_week,omitempty"`
	// History used: hourly points between HistoryFrom and HistoryTo.
	HistoryFrom   *time.Time `json:"history_from,omitempty"`
	HistoryTo     *time.Time `json:"history_to,omitempty"`
	HistoryPoints int        `json:"history_points"`
}

// InsightsResponse answers GET /v1/databases/{ref}/insights.
type InsightsResponse struct {
	// Available is false until an agent that collects insights reports.
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Insights
}

// QueriesResponse answers GET /v1/databases/{ref}/queries: the old
// cumulative snapshot (the embedded Statements fields) plus the top
// statements of a time range.
type QueriesResponse struct {
	Statements
	From *time.Time `json:"from,omitempty"`
	To   *time.Time `json:"to,omitempty"`
	Sort string     `json:"sort,omitempty"` // total_time | calls | mean_time | rows
	// TrendAvailable is false until an agent that reports query_stats does.
	TrendAvailable bool         `json:"trend_available"`
	Top            []QueryTrend `json:"top"`
	Totals         QueryTotals  `json:"totals"`
}

// QueryTrend is one statement's activity in a time range.
type QueryTrend struct {
	QueryID     string  `json:"query_id"`
	Query       string  `json:"query"`
	Database    string  `json:"database,omitempty"`
	User        string  `json:"user,omitempty"`
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	MeanTimeMs  float64 `json:"mean_time_ms"`
	Rows        int64   `json:"rows"`
	// TimeSharePct is its share of all statement time in the range.
	TimeSharePct float64 `json:"time_share_pct"`
	// The same statement in the previous window of equal length.
	PreviousCalls      *int64   `json:"previous_calls,omitempty"`
	PreviousMeanTimeMs *float64 `json:"previous_mean_time_ms,omitempty"`
	MeanChange         *float64 `json:"mean_change,omitempty"` // mean_time_ms / previous_mean_time_ms
	// Regression: mean time more than doubled against the previous window
	// (with enough calls in both to mean something).
	Regression bool `json:"regression"`
}

type QueryTotals struct {
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	Statements  int     `json:"statements"` // distinct statements with activity
}

// QueryDetail answers GET /v1/databases/{ref}/queries/{query_id}.
type QueryDetail struct {
	QueryID    string       `json:"query_id"`
	Query      string       `json:"query"`
	Database   string       `json:"database,omitempty"`
	User       string       `json:"user,omitempty"`
	From       time.Time    `json:"from"`
	To         time.Time    `json:"to"`
	Step       int          `json:"step"` // seconds per point
	Current    QueryPeriod  `json:"current"`
	Previous   *QueryPeriod `json:"previous,omitempty"`
	Regression bool         `json:"regression"`
	Points     []QueryPoint `json:"points"`
}

type QueryPeriod struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Calls       int64     `json:"calls"`
	TotalTimeMs float64   `json:"total_time_ms"`
	MeanTimeMs  float64   `json:"mean_time_ms"`
	Rows        int64     `json:"rows"`
}

// QueryPoint is one bucket of a statement's time series.
type QueryPoint struct {
	T           int64   `json:"t"` // unix seconds, start of the bucket
	Calls       int64   `json:"calls"`
	TotalTimeMs float64 `json:"total_time_ms"`
	MeanTimeMs  float64 `json:"mean_time_ms"`
	Rows        int64   `json:"rows"`
}

// Availability answers GET /v1/databases/{ref}/availability: whether the
// agent could query PostgreSQL, minute by minute.
type Availability struct {
	DatabaseID string         `json:"database_id"`
	Windows    []UptimeWindow `json:"windows"` // 24h, 7d, 30d
	Incidents  []Incident     `json:"incidents"`
}

type UptimeWindow struct {
	Window string `json:"window"` // "24h", "7d", "30d"
	// UptimePct is the share of observed minutes in which PostgreSQL
	// answered; nil without observations.
	UptimePct *float64 `json:"uptime_pct,omitempty"`
	// ObservedPct is the share of the window the agent reported at all
	// (minutes without a report count neither as up nor as down).
	ObservedPct float64 `json:"observed_pct"`
	DownMinutes float64 `json:"down_minutes"`
}

// Incident is a stretch of time the agent could not query PostgreSQL.
type Incident struct {
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	DurationSeconds float64    `json:"duration_seconds"`
	Ongoing         bool       `json:"ongoing"`
	Error           string     `json:"error,omitempty"`
}

// OrgSettings answers GET and PUT /v1/org/settings.
type OrgSettings struct {
	// WeeklyReport sends "Your databases this week" every Monday.
	WeeklyReport bool `json:"weekly_report"`
	// WeeklyReportRecipients; empty sends it to the addresses of the org's
	// email alert channels.
	WeeklyReportRecipients []string `json:"weekly_report_recipients"`
	// WeeklyReportSendsTo is who the next report goes to.
	WeeklyReportSendsTo    []string   `json:"weekly_report_sends_to"`
	WeeklyReportLastSentAt *time.Time `json:"weekly_report_last_sent_at,omitempty"`
}

// UpdateOrgSettingsRequest changes org settings; omitted fields are kept.
type UpdateOrgSettingsRequest struct {
	WeeklyReport           *bool     `json:"weekly_report,omitempty"`
	WeeklyReportRecipients *[]string `json:"weekly_report_recipients,omitempty"`
}

// WeeklyReportPreview answers GET /v1/org/weekly-report: the report as it
// would be sent now.
type WeeklyReportPreview struct {
	Enabled    bool      `json:"enabled"`
	Recipients []string  `json:"recipients"`
	Subject    string    `json:"subject"`
	Text       string    `json:"text"`
	HTML       string    `json:"html"`
	From       time.Time `json:"from"`
	To         time.Time `json:"to"`
}
