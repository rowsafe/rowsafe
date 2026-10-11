package protocol

import "time"

// ---- Snapshots every few minutes (OpenSearch, Qdrant, Meilisearch)
//
// These engines keep no log of their changes Rowsafe could copy, so a
// restore goes back to a snapshot, and what a restore can lose is the time
// between two snapshots. Agents that report FeatureQuickSnapshots make
// frequent snapshots cheap:
//
//   - OpenSearch: snapshots copy only new files; retention keeps every
//     snapshot of the last day, then one an hour for a week, then the daily
//     full ones (internal/engine/opensearch/backup.go).
//   - Qdrant: a backup takes a snapshot only of the collections that changed
//     since the newest backup (each collection's operation number, segments,
//     settings and points), one collection at a time, and names the earlier
//     snapshot of the others; nothing changed costs nothing.
//   - Meilisearch: a backup that finds nothing changed since the newest
//     snapshot (no task since its own, the same API keys) records that
//     snapshot again instead of having Meilisearch copy everything.
//
// Such a backup reports RepoSizeBytes 0 when it stored nothing new.
const FeatureQuickSnapshots = "quick_snapshots"

// The default schedules with quick snapshots (cron, UTC). OpenSearch's is
// OpenSearchScheduleDiff (every 5 minutes) with a daily full snapshot.
const (
	QdrantSchedule      = "*/15 * * * *"
	MeilisearchSchedule = "*/15 * * * *"
)

// The default schedules before quick snapshots: the control plane moves a
// database still on one of them to the new default once its agent reports
// FeatureQuickSnapshots (once: a schedule a person chose stays).
const (
	OpenSearchScheduleDiffBefore = "*/30 * * * *"
	QdrantScheduleBefore         = "0 * * * *"
	MeilisearchScheduleBefore    = "0 * * * *"
)

// SnapshotEngine reports whether an engine's backups are snapshots on a
// schedule with nothing in between (OpenSearch, Qdrant, Meilisearch): how
// far back a restore reaches is set by how often they run.
func SnapshotEngine(engine string) bool {
	switch NormalizeEngine(engine) {
	case EngineOpenSearch, EngineQdrant, EngineMeilisearch:
		return true
	}
	return false
}

// Snapshots that can't keep up: when a scheduled snapshot of a
// SnapshotEngine takes longer than SnapshotBusyShare of the time between
// two runs, the control plane skips scheduled runs until SnapshotRestFactor
// times that snapshot's duration has passed since it finished, so
// snapshots never take more than about a quarter of the server's time, and
// says so (the next one that is quick enough runs on schedule again).
const (
	SnapshotBusyShare  = 0.25
	SnapshotRestFactor = 3
)

// SnapshotDue says whether a scheduled snapshot may run now: last is how
// long the newest backup took and when it finished, interval the time
// between two runs of its schedule.
func SnapshotDue(lastDuration time.Duration, lastStopped, now time.Time, interval time.Duration) bool {
	if lastDuration <= 0 || interval <= 0 || lastDuration <= time.Duration(float64(interval)*SnapshotBusyShare) {
		return true
	}
	return now.Sub(lastStopped) >= SnapshotRestFactor*lastDuration
}
