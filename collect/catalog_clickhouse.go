package collect

// ClickHouse metrics (the ClickHouse engine reports them next to the shared
// ones it can fill: connections_total, connections_max, connections_used_pct,
// database_size_bytes, longest_query_seconds, replication_lag_seconds and
// disk_*). Rates are per second since the previous reading.
const (
	MCHQueriesRate       = "clickhouse_queries_rate"
	MCHSelectRate        = "clickhouse_select_rate"
	MCHInsertRate        = "clickhouse_insert_rate"
	MCHInsertedRowsRate  = "clickhouse_inserted_rows_rate"
	MCHFailedQueriesRate = "clickhouse_failed_queries_rate"
	MCHReadBytesRate     = "clickhouse_read_bytes_rate"
	MCHRunningQueries    = "clickhouse_running_queries"
	MCHRunningMerges     = "clickhouse_running_merges"
	MCHPartsActive       = "clickhouse_parts_active"
	MCHPartsMaxPerPart   = "clickhouse_parts_max_in_partition"
	MCHDelayedInserts    = "clickhouse_delayed_inserts"
	MCHRejectedInserts   = "clickhouse_rejected_inserts_rate"
	MCHMutationsPending  = "clickhouse_mutations_pending"
	MCHMutationsFailed   = "clickhouse_mutations_failed"
	MCHReadonlyReplicas  = "clickhouse_readonly_replicas"
	MCHMemoryBytes       = "clickhouse_memory_bytes"
	MCHMemoryUsedPct     = "clickhouse_memory_used_pct"
	MCHBrokenParts       = "clickhouse_broken_parts"
)

func init() {
	Catalog = append(Catalog,
		Metric{MCHQueriesRate, ScopeDatabase, "/s", "ClickHouse: queries per second"},
		Metric{MCHSelectRate, ScopeDatabase, "/s", "ClickHouse: SELECT queries per second"},
		Metric{MCHInsertRate, ScopeDatabase, "/s", "ClickHouse: INSERT queries per second"},
		Metric{MCHInsertedRowsRate, ScopeDatabase, "/s", "ClickHouse: rows inserted per second"},
		Metric{MCHFailedQueriesRate, ScopeDatabase, "/s", "ClickHouse: queries that failed, per second"},
		Metric{MCHReadBytesRate, ScopeDatabase, "B/s", "ClickHouse: bytes read by queries per second"},
		Metric{MCHRunningQueries, ScopeDatabase, "count", "ClickHouse: queries running now"},
		Metric{MCHRunningMerges, ScopeDatabase, "count", "ClickHouse: background merges running now"},
		Metric{MCHPartsActive, ScopeDatabase, "count", "ClickHouse: active data parts in all tables"},
		Metric{MCHPartsMaxPerPart, ScopeDatabase, "count", "ClickHouse: the most active parts in one partition (too many delay, then refuse, inserts)"},
		Metric{MCHDelayedInserts, ScopeDatabase, "count", "ClickHouse: inserts being slowed down now because a partition has too many parts"},
		Metric{MCHRejectedInserts, ScopeDatabase, "/s", "ClickHouse: inserts refused because a partition had too many parts, per second"},
		Metric{MCHMutationsPending, ScopeDatabase, "count", "ClickHouse: mutations (ALTER UPDATE/DELETE) not done yet"},
		Metric{MCHMutationsFailed, ScopeDatabase, "count", "ClickHouse: mutations not done that keep failing"},
		Metric{MCHReadonlyReplicas, ScopeDatabase, "count", "ClickHouse: replicated tables that went read-only (lost ClickHouse Keeper)"},
		Metric{MCHMemoryBytes, ScopeDatabase, "B", "ClickHouse: memory the server uses"},
		Metric{MCHMemoryUsedPct, ScopeDatabase, "%", "ClickHouse: memory used, as a percentage of the server's limit"},
		Metric{MCHBrokenParts, ScopeDatabase, "count", "ClickHouse: data parts set aside as broken (detached)"},
	)
}
