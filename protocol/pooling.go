package protocol

import "time"

// Connection pooling: a Rowsafe-managed PgBouncer in front of a database.
//
// PgBouncer runs on the database's server, installed and configured by the
// root helper only where root allowed it at install time (--allow-pooler,
// /etc/rowsafe/pooler-allowed). A server has at most one Rowsafe-managed
// pooler, in front of one of its PostgreSQL clusters. Clients log in with
// their own PostgreSQL user and password (scram-sha-256): PgBouncer looks
// the password up through a dedicated role, rowsafe_pgbouncer, whose own
// random password is kept only in PgBouncer's root-owned userlist.

// Task types.
const (
	// TaskPooling turns pooling on (installing PgBouncer when needed),
	// changes its settings, or turns it off (PoolingParams). Only a person
	// asks for it, and only where root allowed it (HeartbeatRequest.Pooler).
	TaskPooling = "pooling"
	// TaskPoolerRetarget points the pooler of a database at another
	// PostgreSQL server (PoolerRetargetParams), typically the new primary
	// after a failover or switchover. The agent pauses PgBouncer, reloads it
	// with the new target and resumes it, so clients wait instead of
	// failing.
	TaskPoolerRetarget = "pooler_retarget"
)

// Pooling actions (PoolingParams.Action).
const (
	PoolingOn  = "on"  // install if needed, configure and start (also: change settings)
	PoolingOff = "off" // stop, restore PgBouncer's own config, remove what Rowsafe installed
)

// Pool modes. Transaction pooling lends a server connection for one
// transaction at a time: many more clients per PostgreSQL connection, but
// session state (SET, LISTEN, advisory locks, SQL PREPARE, temporary
// tables) doesn't carry over between transactions. Session pooling keeps
// one server connection per client connection: everything works as with a
// direct connection, but it saves only the cost of connecting.
const (
	PoolModeTransaction = "transaction"
	PoolModeSession     = "session"
)

// Where PgBouncer listens (PoolingSettings.Listen).
const (
	// PoolerListenLocal: this server only (127.0.0.1 and ::1).
	PoolerListenLocal = "local"
	// PoolerListenPrivate: this server and its private network addresses
	// (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7): the default.
	PoolerListenPrivate = "private"
	// PoolerListenPublic: every address, including public ones. Only when a
	// person chooses it explicitly.
	PoolerListenPublic = "public"
)

// DefaultPoolerPort is where PgBouncer listens unless told otherwise.
const DefaultPoolerPort = 6432

// PoolingSettings are the choices a person makes. Zero values mean
// "Rowsafe picks" (the agent computes them from max_connections and the
// server's CPUs; PoolingResult.Settings has the values used).
type PoolingSettings struct {
	Mode          string `json:"mode,omitempty"`            // PoolMode*; default transaction
	PoolSize      int    `json:"pool_size,omitempty"`       // default_pool_size: server connections per database and user
	MaxClientConn int    `json:"max_client_conn,omitempty"` // client connections PgBouncer accepts
	Listen        string `json:"listen,omitempty"`          // PoolerListen*; default private
	Port          int    `json:"port,omitempty"`            // default 6432
}

// PoolingParams are the params of a pooling task.
type PoolingParams struct {
	Action   string          `json:"action"` // PoolingOn | PoolingOff
	Settings PoolingSettings `json:"settings,omitzero"`
}

// PoolingResult is the agent's report for a pooling task.
type PoolingResult struct {
	Action string `json:"action"`
	// On is true when PgBouncer runs with Rowsafe's configuration after the
	// task.
	On bool `json:"on"`
	// Summary is plain words: "Pooling is on: PgBouncer 1.24.1 listens on
	// 127.0.0.1 and 10.0.0.5, port 6432, transaction mode, 20 connections
	// per pool."
	Summary string `json:"summary"`
	// Version is PgBouncer's version ("1.24.1").
	Version string `json:"version,omitempty"`
	// Installed: this task installed the pgbouncer package.
	Installed bool `json:"installed,omitempty"`
	// Removed: this task removed the pgbouncer package Rowsafe had installed.
	Removed bool `json:"removed,omitempty"`
	// Settings are the values in effect (automatic ones filled in).
	Settings PoolingSettings `json:"settings,omitzero"`
	// Addresses are the addresses PgBouncer listens on ("*" for all).
	Addresses []string `json:"addresses,omitempty"`
	// Target is where PgBouncer sends connections ("127.0.0.1:5432").
	Target string `json:"target,omitempty"`
	// Warnings are things the person should know: roles whose md5
	// passwords can't log in through PgBouncer, a pg_hba.conf that refuses
	// password logins from PgBouncer...
	Warnings   []string `json:"warnings,omitempty"`
	DurationMs int64    `json:"duration_ms"`
}

// PoolerRetargetParams are the params of a pooler_retarget task: the
// PostgreSQL server PgBouncer should send connections to from now on.
// The standby feature queues it when a primary changes.
type PoolerRetargetParams struct {
	Host string `json:"host"` // IP address or DNS name
	Port int    `json:"port"`
}

// PoolerRetargetResult is the agent's report for a pooler_retarget task.
type PoolerRetargetResult struct {
	From string `json:"from"` // previous target, "10.0.0.5:5432"
	To   string `json:"to"`
	// Paused: clients were held (PAUSE ... RESUME) while PgBouncer switched,
	// so none got an error. False when PgBouncer couldn't pause in time
	// (the old server not answering): open server connections were then
	// closed, and clients in a transaction got an error.
	Paused bool `json:"paused"`
	// PausedMs is how long clients waited.
	PausedMs   int64  `json:"paused_ms"`
	Summary    string `json:"summary"`
	DurationMs int64  `json:"duration_ms"`
}

// PoolerStatus is what the agent reports about PgBouncer in its heartbeat
// (HeartbeatRequest.Pooler). Absent from older agents.
type PoolerStatus struct {
	// Allowed: root allowed Rowsafe to install and manage PgBouncer on this
	// server (the installer's --allow-pooler). AllowedPorts are the
	// PostgreSQL clusters it may pool.
	Allowed      bool  `json:"allowed"`
	AllowedPorts []int `json:"allowed_ports,omitempty"`
	// Managed: a Rowsafe-managed PgBouncer is set up on this server (pooling
	// was turned on and not off). The standby feature queues a
	// pooler_retarget for such a host when the primary changes.
	Managed bool `json:"managed"`
	// DatabaseID is the Rowsafe database it pools (Managed only).
	DatabaseID string `json:"database_id,omitempty"`
	// Running: PgBouncer answered the agent just now.
	Running  bool            `json:"running"`
	Version  string          `json:"version,omitempty"`
	Settings PoolingSettings `json:"settings,omitzero"`
	// Addresses PgBouncer listens on; Target is where it sends connections.
	Addresses []string `json:"addresses,omitempty"`
	Target    string   `json:"target,omitempty"`
	// External: the agent watches a PgBouncer that Rowsafe doesn't manage
	// (a Docker service, ROWSAFE_POOLER_STATS_URL): monitoring only.
	External bool   `json:"external,omitempty"`
	Error    string `json:"error,omitempty"` // why PgBouncer couldn't be read
}

// PoolerStats is the newest reading of PgBouncer's admin console for one
// database (DatabaseMonitoring.Pooler), about every minute.
type PoolerStats struct {
	CollectedAt time.Time  `json:"collected_at,omitzero"`
	Version     string     `json:"version,omitempty"`
	Pools       []PoolStat `json:"pools"`
}

// PoolStat is one line of SHOW POOLS, with SHOW STATS for its database.
type PoolStat struct {
	Database       string  `json:"database"`
	User           string  `json:"user"`
	Mode           string  `json:"mode,omitempty"`
	ClientsActive  int     `json:"clients_active"`
	ClientsWaiting int     `json:"clients_waiting"`
	ServersActive  int     `json:"servers_active"`
	ServersIdle    int     `json:"servers_idle"`
	PoolSize       int     `json:"pool_size,omitempty"`
	MaxWaitSeconds float64 `json:"max_wait_seconds"`
	AvgWaitMs      float64 `json:"avg_wait_ms"`   // database-wide, last minute
	XactPerSecond  float64 `json:"xact_per_sec"`  // database-wide, last minute
	QueryPerSecond float64 `json:"query_per_sec"` // database-wide, last minute
}

// PoolingView answers GET /v1/databases/{ref}/pooling.
type PoolingView struct {
	// State: off, turning_on, on, turning_off, failed.
	State string `json:"state"`
	// Allowed: root allowed Rowsafe to manage PgBouncer on the server and
	// this database's cluster is on its list. Reason says why not.
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
	// Available: pooling can be turned on or changed now (allowed, agent
	// connected, nothing running). Otherwise Reason says why.
	Available bool `json:"available"`
	// External: a PgBouncer Rowsafe doesn't manage (Docker) is monitored.
	External bool            `json:"external,omitempty"`
	Settings PoolingSettings `json:"settings,omitzero"`
	// Running: PgBouncer answered the agent recently.
	Running   bool     `json:"running"`
	Version   string   `json:"version,omitempty"`
	Addresses []string `json:"addresses,omitempty"`
	Target    string   `json:"target,omitempty"`
	// OtherDatabase: the server's pooler already serves another database.
	OtherDatabase string    `json:"other_database,omitempty"`
	LastTask      *TaskView `json:"last_task,omitempty"`
	Warnings      []string  `json:"warnings,omitempty"`
	// Connection strings (without passwords): Direct to PostgreSQL, Pooled
	// through PgBouncer (when on).
	Direct string       `json:"direct"`
	Pooled string       `json:"pooled,omitempty"`
	Stats  *PoolerStats `json:"stats,omitempty"`
	// Defaults are the settings Rowsafe would pick now.
	Defaults PoolingSettings `json:"defaults"`
}

// PoolingRequest is the body of PUT /v1/databases/{ref}/pooling (turn on or
// change settings) and DELETE (turn off; Settings ignored). Confirm is the
// database's name.
type PoolingRequest struct {
	Settings PoolingSettings `json:"settings,omitzero"`
	Confirm  string          `json:"confirm"`
}

// FixPooling is the fix kind that queues a pooling task (turn on, raise
// the pool size, switch mode), params PoolingParams.
const FixPooling = "pooling"
