package collect

// Redis and Valkey metrics (the Redis engine reports them next to the shared
// ones it can fill: connections_total, connections_max, connections_used_pct,
// database_size_bytes, replication_lag_seconds and disk_*). Rates are per
// second since the previous reading.
const (
	MRedisUsedMemoryBytes     = "redis_used_memory_bytes"
	MRedisMemoryUsedPct       = "redis_memory_used_pct" // of maxmemory (absent without a limit)
	MRedisFragmentationRatio  = "redis_fragmentation_ratio"
	MRedisOpsRate             = "redis_ops_rate"
	MRedisHitRatePct          = "redis_hit_rate_pct"
	MRedisEvictedKeysRate     = "redis_evicted_keys_rate"
	MRedisExpiredKeysRate     = "redis_expired_keys_rate"
	MRedisKeys                = "redis_keys"
	MRedisBlockedClients      = "redis_blocked_clients"
	MRedisRejectedConnsRate   = "redis_rejected_connections_rate"
	MRedisNetInputRate        = "redis_net_input_rate"
	MRedisNetOutputRate       = "redis_net_output_rate"
	MRedisChangesSinceSave    = "redis_changes_since_save"
	MRedisLastSaveAgeSeconds  = "redis_last_save_age_seconds"
	MRedisBgsaveFailed        = "redis_bgsave_failed"    // 1 when the last snapshot to disk failed
	MRedisAOFWriteFailed      = "redis_aof_write_failed" // 1 when the last append-only file write failed
	MRedisSlowlogRate         = "redis_slowlog_rate"
	MRedisLatencyMaxSeconds   = "redis_latency_max_seconds"
	MRedisConnectedReplicas   = "redis_connected_replicas" // Rowsafe's link left out
	MRedisReplicationLagBytes = "redis_replication_lag_bytes"
)

func init() {
	Catalog = append(Catalog,
		Metric{MRedisUsedMemoryBytes, ScopeDatabase, "B", "Redis: memory used by the data and the server"},
		Metric{MRedisMemoryUsedPct, ScopeDatabase, "%", "Redis: memory used, as a percentage of maxmemory"},
		Metric{MRedisFragmentationRatio, ScopeDatabase, "", "Redis: memory the system gave the server, divided by the memory it uses (above 1.5: fragmented)"},
		Metric{MRedisOpsRate, ScopeDatabase, "/s", "Redis: commands per second"},
		Metric{MRedisHitRatePct, ScopeDatabase, "%", "Redis: reads that found their key, as a percentage of all key reads"},
		Metric{MRedisEvictedKeysRate, ScopeDatabase, "/s", "Redis: keys evicted per second to stay under maxmemory"},
		Metric{MRedisExpiredKeysRate, ScopeDatabase, "/s", "Redis: keys expired per second"},
		Metric{MRedisKeys, ScopeDatabase, "count", "Redis: keys in all logical databases"},
		Metric{MRedisBlockedClients, ScopeDatabase, "count", "Redis: clients waiting in a blocking command (BLPOP, XREAD...)"},
		Metric{MRedisRejectedConnsRate, ScopeDatabase, "/s", "Redis: connections refused because maxclients was reached, per second"},
		Metric{MRedisNetInputRate, ScopeDatabase, "B/s", "Redis: bytes received per second"},
		Metric{MRedisNetOutputRate, ScopeDatabase, "B/s", "Redis: bytes sent per second"},
		Metric{MRedisChangesSinceSave, ScopeDatabase, "count", "Redis: changes since the last snapshot to its own disk"},
		Metric{MRedisLastSaveAgeSeconds, ScopeDatabase, "s", "Redis: time since the last snapshot to its own disk"},
		Metric{MRedisBgsaveFailed, ScopeDatabase, "", "Redis: 1 when the last snapshot to its own disk failed"},
		Metric{MRedisAOFWriteFailed, ScopeDatabase, "", "Redis: 1 when the last write to its append-only file failed"},
		Metric{MRedisSlowlogRate, ScopeDatabase, "/s", "Redis: commands per second slower than slowlog-log-slower-than"},
		Metric{MRedisLatencyMaxSeconds, ScopeDatabase, "s", "Redis: the latest latency spike the latency monitor recorded"},
		Metric{MRedisConnectedReplicas, ScopeDatabase, "count", "Redis: replicas connected to this server"},
		Metric{MRedisReplicationLagBytes, ScopeDatabase, "B", "Redis: changes the slowest replica hasn't received yet (on a primary) or this replica is behind (on a replica)"},
	)
}
