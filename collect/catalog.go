// Package collect gathers PostgreSQL and host metrics on the database host
// for Rowsafe's built-in monitoring. It only runs cheap, read-only queries
// with a short statement_timeout, and never blocks backups or drills.
package collect

// Scopes of a metric.
const (
	ScopeDatabase = "database" // one PostgreSQL cluster (a Rowsafe database)
	ScopeHost     = "host"
)

// Metric describes one collected series. Everything is sent as a gauge:
// counters are turned into rates on the agent.
type Metric struct {
	Name        string
	Scope       string
	Unit        string
	Description string
}

// Database metric names.
const (
	MConnActive          = "connections_active"
	MConnIdle            = "connections_idle"
	MConnIdleInXact      = "connections_idle_in_transaction"
	MConnTotal           = "connections_total"
	MConnMax             = "connections_max"
	MConnUsedPct         = "connections_used_pct"
	MXactCommitRate      = "xact_commit_rate"
	MXactRollbackRate    = "xact_rollback_rate"
	MTupReturnedRate     = "tup_returned_rate"
	MTupFetchedRate      = "tup_fetched_rate"
	MTupInsertedRate     = "tup_inserted_rate"
	MTupUpdatedRate      = "tup_updated_rate"
	MTupDeletedRate      = "tup_deleted_rate"
	MCacheHitPct         = "cache_hit_pct"
	MDeadlocksPerMin     = "deadlocks_per_min"
	MTempFilesPerMin     = "temp_files_per_min"
	MTempBytesRate       = "temp_bytes_rate"
	MDatabaseSizeBytes   = "database_size_bytes"
	MWALBytesRate        = "wal_bytes_rate"
	MCheckpointsTimed    = "checkpoints_timed_per_min"
	MCheckpointsReq      = "checkpoints_requested_per_min"
	MLongestXactSeconds  = "longest_transaction_seconds"
	MLongestQuerySeconds = "longest_query_seconds"
	MIdleInXactOldest    = "idle_in_transaction_oldest_seconds"
	MLocksWaiting        = "locks_waiting"
	MSlotsInactive       = "replication_slots_inactive"
	MSlotInactiveRetain  = "replication_slot_inactive_retained_bytes"
	MSlotRetainedMax     = "replication_slot_retained_bytes"
	MXIDAge              = "xid_age"
	MXIDHeadroomPct      = "xid_headroom_pct"
	MDiskFreePct         = "disk_free_pct"
	MDiskFreeBytes       = "disk_free_bytes"
	MDiskTotalBytes      = "disk_total_bytes"
)

// Host metric names (disk_* are shared with the database scope).
const (
	HCPUPct       = "cpu_pct"
	HCPUCount     = "cpu_count"
	HLoad1        = "load1"
	HLoad5        = "load5"
	HLoad15       = "load15"
	HMemTotal     = "mem_total_bytes"
	HMemAvailable = "mem_available_bytes"
	HMemUsedPct   = "mem_used_pct"
	HSwapTotal    = "swap_total_bytes"
	HSwapUsed     = "swap_used_bytes"
	HDiskUsedPct  = "disk_used_pct"
)

// Catalog lists every metric the control plane accepts, in display order.
var Catalog = []Metric{
	{MConnActive, ScopeDatabase, "count", "Client sessions running a query"},
	{MConnIdle, ScopeDatabase, "count", "Idle client sessions"},
	{MConnIdleInXact, ScopeDatabase, "count", "Client sessions idle inside an open transaction"},
	{MConnTotal, ScopeDatabase, "count", "All client sessions"},
	{MConnMax, ScopeDatabase, "count", "max_connections"},
	{MConnUsedPct, ScopeDatabase, "%", "Client sessions as a percentage of max_connections"},
	{MXactCommitRate, ScopeDatabase, "/s", "Committed transactions per second"},
	{MXactRollbackRate, ScopeDatabase, "/s", "Rolled back transactions per second"},
	{MTupReturnedRate, ScopeDatabase, "/s", "Rows returned by sequential and index scans per second"},
	{MTupFetchedRate, ScopeDatabase, "/s", "Rows fetched by index scans per second"},
	{MTupInsertedRate, ScopeDatabase, "/s", "Rows inserted per second"},
	{MTupUpdatedRate, ScopeDatabase, "/s", "Rows updated per second"},
	{MTupDeletedRate, ScopeDatabase, "/s", "Rows deleted per second"},
	{MCacheHitPct, ScopeDatabase, "%", "Share of block reads served from shared buffers (only when there was real read traffic)"},
	{MDeadlocksPerMin, ScopeDatabase, "/min", "Deadlocks detected per minute"},
	{MTempFilesPerMin, ScopeDatabase, "/min", "Temporary files created per minute (queries spilling to disk)"},
	{MTempBytesRate, ScopeDatabase, "B/s", "Bytes written to temporary files per second"},
	{MDatabaseSizeBytes, ScopeDatabase, "B", "Total size of all databases in the cluster"},
	{MWALBytesRate, ScopeDatabase, "B/s", "WAL generated per second"},
	{MCheckpointsTimed, ScopeDatabase, "/min", "Scheduled checkpoints per minute"},
	{MCheckpointsReq, ScopeDatabase, "/min", "Requested (forced) checkpoints per minute; frequent ones mean max_wal_size is too small"},
	{MLongestXactSeconds, ScopeDatabase, "s", "Age of the oldest open transaction"},
	{MLongestQuerySeconds, ScopeDatabase, "s", "Run time of the longest running query"},
	{MIdleInXactOldest, ScopeDatabase, "s", "How long the oldest idle-in-transaction session has been idle"},
	{MLocksWaiting, ScopeDatabase, "count", "Lock requests waiting to be granted"},
	{MSlotsInactive, ScopeDatabase, "count", "Replication slots with no consumer connected"},
	{MSlotInactiveRetain, ScopeDatabase, "B", "WAL held back by the worst inactive replication slot"},
	{MSlotRetainedMax, ScopeDatabase, "B", "WAL held back by the worst replication slot"},
	{MXIDAge, ScopeDatabase, "count", "Transaction ID age of the oldest database (age(datfrozenxid))"},
	{MXIDHeadroomPct, ScopeDatabase, "%", "Transaction IDs left before wraparound protection stops writes"},
	{MDiskFreePct, ScopeDatabase, "%", "Free space on the data directory's filesystem"},
	{MDiskFreeBytes, ScopeDatabase, "B", "Free bytes on the data directory's filesystem"},
	{MDiskTotalBytes, ScopeDatabase, "B", "Size of the data directory's filesystem"},

	{HCPUPct, ScopeHost, "%", "CPU busy (all cores)"},
	{HCPUCount, ScopeHost, "count", "Logical CPUs"},
	{HLoad1, ScopeHost, "", "Load average over 1 minute"},
	{HLoad5, ScopeHost, "", "Load average over 5 minutes"},
	{HLoad15, ScopeHost, "", "Load average over 15 minutes"},
	{HMemTotal, ScopeHost, "B", "Physical memory"},
	{HMemAvailable, ScopeHost, "B", "Memory available for new work without swapping (MemAvailable)"},
	{HMemUsedPct, ScopeHost, "%", "Memory in use (1 - MemAvailable/MemTotal)"},
	{HSwapTotal, ScopeHost, "B", "Swap space"},
	{HSwapUsed, ScopeHost, "B", "Swap in use"},
	{HDiskUsedPct, ScopeHost, "%", "Used space on the filesystem holding PostgreSQL's data directory"},
	{MDiskFreeBytes, ScopeHost, "B", "Free bytes on that filesystem"},
	{MDiskTotalBytes, ScopeHost, "B", "Size of that filesystem"},
}

// Lookup returns a metric by scope and name.
func Lookup(scope, name string) (Metric, bool) {
	for _, m := range Catalog {
		if m.Scope == scope && m.Name == name {
			return m, true
		}
	}
	return Metric{}, false
}

// Names returns the metric names of a scope in catalog order.
func Names(scope string) []string {
	var out []string
	for _, m := range Catalog {
		if m.Scope == scope {
			out = append(out, m.Name)
		}
	}
	return out
}
