package collect

// MySQL and MariaDB metrics. Where a PostgreSQL metric means the same thing
// (connections, rows written per second, cache hit ratio, disk, longest
// transaction, replication lag...) MySQL and MariaDB report it under the
// same name; these are their own.
const (
	MThreadsRunning      = "threads_running"
	MQueriesPerSec       = "queries_per_sec"
	MSlowQueriesPerMin   = "slow_queries_per_min"
	MRowLockWaitsPerMin  = "row_lock_waits_per_min"
	MBinlogBytesRate     = "binlog_bytes_rate"
	MAbortedConnectsMin  = "aborted_connects_per_min"
	MBufferPoolUsedPct   = "buffer_pool_used_pct"
	MHistoryListLength   = "innodb_history_list_length"
	MTmpDiskTablesPerMin = "tmp_disk_tables_per_min"
)

func init() {
	Catalog = append(Catalog,
		Metric{MThreadsRunning, ScopeDatabase, "count", "MySQL/MariaDB: threads running a statement right now (Threads_running)"},
		Metric{MQueriesPerSec, ScopeDatabase, "/s", "MySQL/MariaDB: statements received per second (Questions)"},
		Metric{MSlowQueriesPerMin, ScopeDatabase, "/min", "MySQL/MariaDB: statements slower than long_query_time per minute (Slow_queries)"},
		Metric{MRowLockWaitsPerMin, ScopeDatabase, "/min", "MySQL/MariaDB: times a statement had to wait for a row lock, per minute"},
		Metric{MBinlogBytesRate, ScopeDatabase, "B/s", "MySQL/MariaDB: binary log written per second"},
		Metric{MAbortedConnectsMin, ScopeDatabase, "/min", "MySQL/MariaDB: failed connection attempts per minute (wrong password, no access...)"},
		Metric{MBufferPoolUsedPct, ScopeDatabase, "%", "MySQL/MariaDB: InnoDB buffer pool pages holding data"},
		Metric{MHistoryListLength, ScopeDatabase, "count", "MySQL/MariaDB: old row versions InnoDB still keeps for open transactions (history list length)"},
		Metric{MTmpDiskTablesPerMin, ScopeDatabase, "/min", "MySQL/MariaDB: internal temporary tables written to disk per minute"},
	)
}
