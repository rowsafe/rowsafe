package collect

// Qdrant metrics (the Qdrant engine reports them next to the shared ones it
// can fill: database_size_bytes and disk_*). Rates are per second since the
// previous reading.
const (
	MQdrantCollections       = "qdrant_collections"
	MQdrantPoints            = "qdrant_points"
	MQdrantResidentBytes     = "qdrant_resident_bytes"
	MQdrantMemoryUsedPct     = "qdrant_memory_used_pct" // of the server's (or container's) memory
	MQdrantCollectionsRed    = "qdrant_collections_red"
	MQdrantCollectionsYellow = "qdrant_collections_yellow"
	MQdrantOptimizerErrors   = "qdrant_optimizer_errors"
	MQdrantRequestsRate      = "qdrant_requests_rate"
	MQdrantFailedRate        = "qdrant_failed_requests_rate"
	MQdrantIssues            = "qdrant_issues"
)

func init() {
	Catalog = append(Catalog,
		Metric{MQdrantCollections, ScopeDatabase, "count", "Qdrant: collections"},
		Metric{MQdrantPoints, ScopeDatabase, "count", "Qdrant: points in every collection"},
		Metric{MQdrantResidentBytes, ScopeDatabase, "B", "Qdrant: memory the server process uses"},
		Metric{MQdrantMemoryUsedPct, ScopeDatabase, "%", "Qdrant: memory the server process uses, as a percentage of the server's memory"},
		Metric{MQdrantCollectionsRed, ScopeDatabase, "count", "Qdrant: collections that failed (red)"},
		Metric{MQdrantCollectionsYellow, ScopeDatabase, "count", "Qdrant: collections optimizing in the background (yellow)"},
		Metric{MQdrantOptimizerErrors, ScopeDatabase, "count", "Qdrant: collections whose optimizer reports an error"},
		Metric{MQdrantRequestsRate, ScopeDatabase, "/s", "Qdrant: REST and gRPC requests per second"},
		Metric{MQdrantFailedRate, ScopeDatabase, "/s", "Qdrant: requests per second that failed on the server (5xx)"},
		Metric{MQdrantIssues, ScopeDatabase, "count", "Qdrant: issues Qdrant itself reports (such as unindexed fields searches filter on)"},
	)
}
