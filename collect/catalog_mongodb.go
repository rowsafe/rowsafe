package collect

// MongoDB metrics (the MongoDB engine reports them next to the shared
// ones it can fill: connections_total, connections_max, connections_used_pct,
// connections_active, database_size_bytes, longest_query_seconds,
// replication_lag_seconds, replicas_connected and disk_*).
const (
	MMongoOpsInsertRate  = "mongodb_ops_insert_rate"
	MMongoOpsQueryRate   = "mongodb_ops_query_rate"
	MMongoOpsUpdateRate  = "mongodb_ops_update_rate"
	MMongoOpsDeleteRate  = "mongodb_ops_delete_rate"
	MMongoOpsGetmoreRate = "mongodb_ops_getmore_rate"
	MMongoOpsCommandRate = "mongodb_ops_command_rate"
	MMongoQueuedOps      = "mongodb_queued_ops"
	MMongoCacheUsedPct   = "mongodb_cache_used_pct"
	MMongoCacheDirtyPct  = "mongodb_cache_dirty_pct"
	MMongoOplogWindow    = "mongodb_oplog_window_hours"
	MMongoResidentBytes  = "mongodb_resident_bytes"
	MMongoNetInRate      = "mongodb_network_in_rate"
	MMongoNetOutRate     = "mongodb_network_out_rate"
)

func init() {
	Catalog = append(Catalog,
		Metric{MMongoOpsInsertRate, ScopeDatabase, "/s", "MongoDB: documents inserted per second (opcounters)"},
		Metric{MMongoOpsQueryRate, ScopeDatabase, "/s", "MongoDB: queries per second"},
		Metric{MMongoOpsUpdateRate, ScopeDatabase, "/s", "MongoDB: updates per second"},
		Metric{MMongoOpsDeleteRate, ScopeDatabase, "/s", "MongoDB: deletes per second"},
		Metric{MMongoOpsGetmoreRate, ScopeDatabase, "/s", "MongoDB: getMore operations (cursor batches) per second"},
		Metric{MMongoOpsCommandRate, ScopeDatabase, "/s", "MongoDB: other commands per second"},
		Metric{MMongoQueuedOps, ScopeDatabase, "count", "MongoDB: operations waiting for a lock or a storage ticket"},
		Metric{MMongoCacheUsedPct, ScopeDatabase, "%", "MongoDB: WiredTiger cache in use, as a percentage of its maximum"},
		Metric{MMongoCacheDirtyPct, ScopeDatabase, "%", "MongoDB: modified data in the WiredTiger cache not yet written to disk"},
		Metric{MMongoOplogWindow, ScopeDatabase, "h", "MongoDB: how far back the oplog reaches (how long the agent may be stopped without losing changes)"},
		Metric{MMongoResidentBytes, ScopeDatabase, "B", "MongoDB: memory the server process uses"},
		Metric{MMongoNetInRate, ScopeDatabase, "B/s", "MongoDB: bytes received from clients per second"},
		Metric{MMongoNetOutRate, ScopeDatabase, "B/s", "MongoDB: bytes sent to clients per second"},
	)
}
