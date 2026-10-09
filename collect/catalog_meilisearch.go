package collect

// Meilisearch metrics (the Meilisearch engine reports them next to the
// shared ones it can fill: database_size_bytes and disk_*). Rates are per
// second since the previous reading.
const (
	MMeiliDocuments         = "meilisearch_documents"
	MMeiliIndexes           = "meilisearch_indexes"
	MMeiliUsedSizeBytes     = "meilisearch_used_size_bytes"
	MMeiliFreeSpacePct      = "meilisearch_reclaimable_pct" // of the database's size on disk
	MMeiliTasksEnqueued     = "meilisearch_tasks_enqueued"
	MMeiliTasksProcessing   = "meilisearch_tasks_processing"
	MMeiliTasksFailedRate   = "meilisearch_tasks_failed_rate"
	MMeiliOldestTaskSeconds = "meilisearch_oldest_enqueued_task_seconds"
	MMeiliTasksTotal        = "meilisearch_tasks_total"
	MMeiliIndexing          = "meilisearch_indexing" // 1 while an index is being indexed
	MMeiliUp                = "meilisearch_up"
)

func init() {
	Catalog = append(Catalog,
		Metric{MMeiliDocuments, ScopeDatabase, "count", "Meilisearch: documents in every index"},
		Metric{MMeiliIndexes, ScopeDatabase, "count", "Meilisearch: indexes"},
		Metric{MMeiliUsedSizeBytes, ScopeDatabase, "B", "Meilisearch: disk its data uses (the rest of its size on disk is free space it reuses)"},
		Metric{MMeiliFreeSpacePct, ScopeDatabase, "%", "Meilisearch: free space inside its files, as a percentage of their size (compacting an index gives it back)"},
		Metric{MMeiliTasksEnqueued, ScopeDatabase, "count", "Meilisearch: tasks waiting (document additions, settings changes...)"},
		Metric{MMeiliTasksProcessing, ScopeDatabase, "count", "Meilisearch: tasks running"},
		Metric{MMeiliTasksFailedRate, ScopeDatabase, "/s", "Meilisearch: tasks failed per second"},
		Metric{MMeiliOldestTaskSeconds, ScopeDatabase, "s", "Meilisearch: how long the oldest waiting task has waited"},
		Metric{MMeiliTasksTotal, ScopeDatabase, "count", "Meilisearch: tasks in its history (it deletes the oldest at a million)"},
		Metric{MMeiliIndexing, ScopeDatabase, "", "Meilisearch: 1 while it is indexing"},
		Metric{MMeiliUp, ScopeDatabase, "", "Meilisearch: 1 when it answers"},
	)
}
