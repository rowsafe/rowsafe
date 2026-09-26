package protocol

import "time"

// Logs (Pulse · Logs): the agent tails PostgreSQL's own log (a log file,
// csvlog, jsonlog or journald), removes literal values from statements and
// error messages on the server, and sends the result to the control plane,
// which keeps it for the plan's retention, groups repeated errors, turns
// patterns into health findings and forwards it to the org's log
// destinations. Everything here is additive: older agents and control
// planes ignore it.
//
// What leaves the server, per entry: time, severity, kind, SQLSTATE, the
// message, DETAIL, HINT and CONTEXT with literal values removed, the
// statement normalized like pg_stat_statements ($1, $2 for constants), the
// PostgreSQL user, database, application name, client address, process ID
// and a duration. Statements that may carry a password (ALTER ROLE ...
// PASSWORD, connection strings) are always replaced by a placeholder, and
// bind parameters (DETAIL: parameters: $1 = '...') are always dropped
// unless the database's "Send full query text" setting is on.
//
//	POST /v1/agent/logs   LogBatch -> LogAck

// MaintLogSettings is the maintenance action (MaintenanceParams.Action)
// that turns on useful logging with ALTER SYSTEM and a reload: slow
// statements over a second, lock waits, temporary files, long autovacuum
// runs, checkpoints and a log_line_prefix with time, process, user,
// database, application, client and SQLSTATE. It only ever makes logging
// more useful: a setting that is already at least as detailed is kept, and
// log_connections, log_statement and anything needing a restart are never
// touched.
const MaintLogSettings = "log_settings"

// FixLogSettings is the ID of the fix that runs MaintLogSettings.
const FixLogSettings = "log_settings"

// Log entry kinds (LogEntry.Kind), from the message; a message in another
// language than English is "error" or "other" by its severity.
const (
	LogKindError              = "error"                // ERROR, FATAL or PANIC not covered below
	LogKindSlowQuery          = "slow_query"           // log_min_duration_statement
	LogKindLockWait           = "lock_wait"            // log_lock_waits: still waiting / acquired
	LogKindDeadlock           = "deadlock"             // deadlock detected (40P01)
	LogKindAuthFailure        = "auth_failure"         // failed login (28P01, 28000)
	LogKindTooManyConnections = "too_many_connections" // sorry, too many clients already (53300)
	LogKindCheckpoint         = "checkpoint"           // checkpoints and restartpoints
	LogKindAutovacuum         = "autovacuum"           // automatic vacuum or analyze
	LogKindTempFile           = "temp_file"            // log_temp_files
	LogKindConnection         = "connection"           // log_connections, log_disconnections
	LogKindStatement          = "statement"            // log_statement
	LogKindServer             = "server"               // startup, shutdown, crash recovery, reloads
	LogKindOther              = "other"
)

// LogKinds lists every kind.
var LogKinds = []string{LogKindError, LogKindSlowQuery, LogKindLockWait, LogKindDeadlock, LogKindAuthFailure,
	LogKindTooManyConnections, LogKindCheckpoint, LogKindAutovacuum, LogKindTempFile, LogKindConnection,
	LogKindStatement, LogKindServer, LogKindOther}

// Log source formats (LogSource.Format).
const (
	LogFormatStderr   = "stderr"   // plain text with log_line_prefix
	LogFormatCSV      = "csvlog"   // logging_collector with csvlog
	LogFormatJSON     = "jsonlog"  // logging_collector with jsonlog (PostgreSQL 15+)
	LogFormatJournald = "journald" // stderr captured by systemd-journald
)

// Log source problems (LogSource.Problem): why the agent can't read the
// log, for the dashboard to explain.
const (
	LogProblemNoAccess      = "no_access"      // PostgreSQL's log settings can't be read (not a superuser)
	LogProblemNotFound      = "not_found"      // the agent can't tell where the log goes
	LogProblemPermission    = "permission"     // the log file isn't readable by the agent's user
	LogProblemDockerStdout  = "docker_stdout"  // Docker: the log goes to the container's output
	LogProblemJournal       = "journal"        // journald, and the agent's user may not read it
	LogProblemSyslog        = "syslog"         // log_destination is syslog (or eventlog) only
	LogProblemUnsupported   = "unsupported"    // anything else, see Detail
	LogProblemNotConnecting = "not_connecting" // PostgreSQL doesn't answer
)

// LogBatch is what the agent posts to POST /v1/agent/logs every few
// seconds while there is something new, and at least every minute with the
// sources' status.
type LogBatch struct {
	Databases []DatabaseLogs `json:"databases"`
}

// DatabaseLogs is one database cluster's part of a batch.
type DatabaseLogs struct {
	DatabaseID string     `json:"database_id"`
	Source     *LogSource `json:"source,omitempty"` // nil: unchanged since the last batch
	Entries    []LogEntry `json:"entries,omitempty"`
	// Skipped counts lines left out since the previous batch because the
	// log was busier than the agent sends (or the control plane was
	// unreachable for long).
	Skipped int64 `json:"skipped,omitempty"`
}

// LogSource is where the agent reads a database's log and how that goes.
type LogSource struct {
	CheckedAt time.Time `json:"checked_at"`
	Format    string    `json:"format,omitempty"` // LogFormat*; "" when unreadable
	// Path is the file (or, for journald, the systemd unit) being read.
	Path string `json:"path,omitempty"`
	// Readable: the agent reads the log. Otherwise Problem (LogProblem*)
	// and Detail say why.
	Readable bool   `json:"readable"`
	Problem  string `json:"problem,omitempty"`
	Detail   string `json:"detail,omitempty"`
	// Settings are PostgreSQL's logging settings as the agent reads them
	// (log_min_duration_statement, log_lock_waits, log_line_prefix,
	// logging_collector, log_destination, lc_messages, ...).
	Settings map[string]string `json:"settings,omitempty"`
	// Sending is false while the database's "Send logs" setting is off.
	Sending  bool `json:"sending"`
	FullText bool `json:"full_text"`
	// AgentMode is "docker-sidecar" for Docker sidecar agents.
	AgentMode string `json:"agent_mode,omitempty"`
}

// LogEntry is one log message, with literal values removed unless the
// database sends full query text.
type LogEntry struct {
	Time     time.Time `json:"time"`
	Severity string    `json:"severity"` // LOG, WARNING, ERROR, FATAL, PANIC, ...
	Kind     string    `json:"kind"`     // LogKind*
	SQLState string    `json:"sqlstate,omitempty"`
	Message  string    `json:"message"`
	Detail   string    `json:"detail,omitempty"`
	Hint     string    `json:"hint,omitempty"`
	Context  string    `json:"context,omitempty"`
	// Statement is the statement that caused it (or the slow statement),
	// normalized.
	Statement   string `json:"statement,omitempty"`
	User        string `json:"user,omitempty"`
	Database    string `json:"database,omitempty"`
	Application string `json:"application,omitempty"`
	Client      string `json:"client,omitempty"` // client address, "[local]" for Unix sockets
	PID         int    `json:"pid,omitempty"`
	// DurationMs: slow statements, lock waits.
	DurationMs *float64 `json:"duration_ms,omitempty"`
	// Redacted: literal values were removed from this entry.
	Redacted bool `json:"redacted,omitempty"`
}

// LogAck answers a LogBatch with each database's settings.
type LogAck struct {
	// IntervalSeconds is the longest the agent should wait between batches
	// (the status heartbeat); it sends sooner when there are entries.
	IntervalSeconds int           `json:"interval_seconds"`
	Databases       []LogSettings `json:"databases"`
}

// LogSettings are one database's log settings.
type LogSettings struct {
	DatabaseID string `json:"database_id,omitempty"`
	// Enabled sends logs to Rowsafe at all (default on).
	Enabled bool `json:"enabled"`
	// FullText sends statements and messages with their literal values
	// (default off). Passwords are removed either way.
	FullText  bool       `json:"full_text"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	UpdatedBy string     `json:"updated_by,omitempty"`
}

// ---- User API ----
//
//	GET   /v1/databases/{ref}/logs            LogsResponse (?kind=&severity=&q=&from=&to=&before=&after=&limit=)
//	GET   /v1/databases/{ref}/logs/groups     LogGroupsResponse (?kind=&from=&to=&q=)
//	GET   /v1/databases/{ref}/logs/overview   LogsOverview
//	PATCH /v1/databases/{ref}/logs/settings   UpdateLogSettingsRequest -> LogSettings
//	GET, POST        /v1/log-destinations            [LogDestination], CreateLogDestinationRequest -> LogDestination
//	PATCH, DELETE    /v1/log-destinations/{id}       UpdateLogDestinationRequest -> LogDestination
//	POST             /v1/log-destinations/{id}/test  ChannelTestResult

// Log filters accepted by ?kind= besides the kinds themselves.
const (
	LogFilterErrors      = "errors"      // severity ERROR, FATAL or PANIC
	LogFilterLocks       = "locks"       // lock waits and deadlocks
	LogFilterMaintenance = "maintenance" // checkpoints, autovacuum, temp files
)

// LogEntryView is a stored entry.
type LogEntryView struct {
	ID string `json:"id"` // increasing; pass as before= or after=
	LogEntry
	ReceivedAt time.Time `json:"received_at"`
	// Group is the entry's fingerprint: repeated errors share it.
	Group string `json:"group"`
}

type LogsResponse struct {
	Entries []LogEntryView `json:"entries"`
	// More: older entries match (pass the last entry's ID as before=).
	More bool `json:"more"`
	// Latest is the newest entry ID of the database, for a live tail
	// (after=); "" when there are none.
	Latest string `json:"latest"`
}

// LogGroup is one kind of message and how often it happened.
type LogGroup struct {
	Group    string    `json:"group"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	SQLState string    `json:"sqlstate,omitempty"`
	Message  string    `json:"message"` // the newest occurrence's message
	Count    int64     `json:"count"`
	FirstAt  time.Time `json:"first_at"`
	LastAt   time.Time `json:"last_at"`
	// Sample is the newest occurrence.
	Sample LogEntryView `json:"sample"`
}

type LogGroupsResponse struct {
	From   time.Time  `json:"from"`
	To     time.Time  `json:"to"`
	Groups []LogGroup `json:"groups"`
}

// LogsOverview is what the Logs page shows above the list.
type LogsOverview struct {
	Settings LogSettings `json:"settings"`
	// Source is the agent's newest report (nil until an agent that reads
	// logs reports).
	Source *LogSource `json:"source,omitempty"`
	// Counts are entries per kind in the last 24 hours.
	Counts map[string]int64 `json:"counts"`
	// Errors24h: entries with severity ERROR, FATAL or PANIC in 24 hours.
	Errors24h int64 `json:"errors_24h"`
	// RetentionDays is how long the plan keeps logs; DailyLimit how many
	// entries a day the organization's plan keeps, UsedToday and
	// SkippedToday this UTC day's counts (all databases).
	RetentionDays int   `json:"retention_days"`
	DailyLimit    int64 `json:"daily_limit"`
	UsedToday     int64 `json:"used_today"`
	SkippedToday  int64 `json:"skipped_today"`
	// OldestAt is the oldest entry kept for this database.
	OldestAt *time.Time `json:"oldest_at,omitempty"`
}

type UpdateLogSettingsRequest struct {
	Enabled  *bool `json:"enabled,omitempty"`
	FullText *bool `json:"full_text,omitempty"`
}

// Log destination types.
const (
	LogDestDatadog     = "datadog"
	LogDestBetterStack = "betterstack"
	LogDestPapertrail  = "papertrail"
	LogDestLoki        = "loki"
	LogDestElastic     = "elasticsearch" // Elasticsearch and OpenSearch (_bulk API)
	LogDestWebhook     = "webhook"
	LogDestSyslog      = "syslog" // RFC 5424 over TLS (RFC 5425 framing)
)

// LogDestTypes lists every destination type.
var LogDestTypes = []string{LogDestDatadog, LogDestBetterStack, LogDestPapertrail, LogDestLoki, LogDestElastic,
	LogDestWebhook, LogDestSyslog}

// LogDestination forwards the org's (already redacted) log stream.
type LogDestination struct {
	ID     string               `json:"id"`
	Type   string               `json:"type"`
	Name   string               `json:"name"`
	Config LogDestinationConfig `json:"config"`
	Filter LogDestinationFilter `json:"filter"`
	// HasSecret: an API key, token or password is stored (encrypted);
	// SecretHint shows its last characters.
	HasSecret  bool      `json:"has_secret"`
	SecretHint string    `json:"secret_hint,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	// Delivery state.
	LastSentAt  *time.Time `json:"last_sent_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
	Delivered   int64      `json:"delivered"` // entries delivered since it was created
	// SigningSecret is returned once, when a webhook destination is
	// created (X-Rowsafe-Signature, as for notification webhooks).
	SigningSecret string `json:"signing_secret,omitempty"`
}

// LogDestinationConfig holds a destination's non-secret settings; which
// fields apply depends on the type (see the docs).
type LogDestinationConfig struct {
	// Site is Datadog's site, e.g. "datadoghq.com", "datadoghq.eu".
	Site string `json:"site,omitempty"`
	// URL: Loki (base URL), Elasticsearch/OpenSearch (base URL), Better
	// Stack (ingesting host URL), webhook.
	URL string `json:"url,omitempty"`
	// Host and Port: syslog and Papertrail.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	// Username: Loki (Grafana Cloud user ID) and Elasticsearch basic auth.
	Username string `json:"username,omitempty"`
	// Index: Elasticsearch/OpenSearch index or data stream (default
	// "rowsafe-logs").
	Index string `json:"index,omitempty"`
}

// LogDestinationFilter narrows what a destination receives; empty fields
// mean everything.
type LogDestinationFilter struct {
	Kinds       []string `json:"kinds,omitempty"`        // kinds or LogFilter* groups
	DatabaseIDs []string `json:"database_ids,omitempty"` // only these databases
}

type CreateLogDestinationRequest struct {
	Type   string               `json:"type"`
	Name   string               `json:"name"`
	Config LogDestinationConfig `json:"config"`
	Filter LogDestinationFilter `json:"filter"`
	// Secret is the API key, token or password (write-only).
	Secret string `json:"secret,omitempty"`
}

// UpdateLogDestinationRequest changes a destination; omitted fields are
// kept. Secret "" keeps the stored one.
type UpdateLogDestinationRequest struct {
	Name    *string               `json:"name,omitempty"`
	Enabled *bool                 `json:"enabled,omitempty"`
	Config  *LogDestinationConfig `json:"config,omitempty"`
	Filter  *LogDestinationFilter `json:"filter,omitempty"`
	Secret  *string               `json:"secret,omitempty"`
}

// ForwardedLog is one entry as log destinations receive it (the generic
// webhook's entries, the Elasticsearch document, the Datadog and Better
// Stack attributes).
type ForwardedLog struct {
	ID           string `json:"id"`
	Host         string `json:"host"`
	DatabaseID   string `json:"database_id"`
	DatabaseName string `json:"database_name"` // the database's name in Rowsafe
	LogEntry
}
