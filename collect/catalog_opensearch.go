package collect

// OpenSearch metrics (the OpenSearch engine reports them next to the shared
// ones it can fill: database_size_bytes, connections_total and disk_*).
// Rates are per second since the previous reading.
const (
	MOpenSearchHeapUsedPct      = "opensearch_heap_used_pct"
	MOpenSearchDocuments        = "opensearch_documents"
	MOpenSearchSearchRate       = "opensearch_search_rate"
	MOpenSearchIndexRate        = "opensearch_index_rate"
	MOpenSearchSearchLatencyMs  = "opensearch_search_latency_ms"
	MOpenSearchIndexLatencyMs   = "opensearch_index_latency_ms"
	MOpenSearchRejectedRate     = "opensearch_rejected_rate"
	MOpenSearchOldGCMsRate      = "opensearch_old_gc_ms_rate"
	MOpenSearchUnassignedShards = "opensearch_unassigned_shards"
	MOpenSearchStatus           = "opensearch_status" // 0 green, 1 yellow, 2 red
)

func init() {
	Catalog = append(Catalog,
		Metric{MOpenSearchHeapUsedPct, ScopeDatabase, "%", "OpenSearch: Java heap in use, as a percentage of its maximum"},
		Metric{MOpenSearchDocuments, ScopeDatabase, "count", "OpenSearch: documents in all indices (system ones left out)"},
		Metric{MOpenSearchSearchRate, ScopeDatabase, "/s", "OpenSearch: searches per second (per shard)"},
		Metric{MOpenSearchIndexRate, ScopeDatabase, "/s", "OpenSearch: documents indexed per second"},
		Metric{MOpenSearchSearchLatencyMs, ScopeDatabase, "ms", "OpenSearch: average time of a search (per shard) since the previous reading"},
		Metric{MOpenSearchIndexLatencyMs, ScopeDatabase, "ms", "OpenSearch: average time to index a document since the previous reading"},
		Metric{MOpenSearchRejectedRate, ScopeDatabase, "/s", "OpenSearch: searches and writes turned away per second (queues full)"},
		Metric{MOpenSearchOldGCMsRate, ScopeDatabase, "ms/s", "OpenSearch: time spent in old-generation garbage collection per second"},
		Metric{MOpenSearchUnassignedShards, ScopeDatabase, "count", "OpenSearch: shards not placed on any node"},
		Metric{MOpenSearchStatus, ScopeDatabase, "", "OpenSearch: cluster health, 0 green, 1 yellow, 2 red"},
	)
}
