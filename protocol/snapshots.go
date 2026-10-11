package protocol

import (
	"strings"
	"time"
)

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

// QdrantQuickMinVersion is the oldest Qdrant whose telemetry tells which
// collections changed (each shard's operation number and segments): older
// ones have every collection snapshotted each time, so they keep the hourly
// schedule.
const QdrantQuickMinVersion = "1.17"

// QuickSnapshotsFor says whether a database of engine at version (as the
// agent reported it; "" unknown) may take snapshots every few minutes,
// given an agent that reports FeatureQuickSnapshots.
func QuickSnapshotsFor(engine, version string) bool {
	switch NormalizeEngine(engine) {
	case EngineOpenSearch, EngineMeilisearch:
		return true
	case EngineQdrant:
		return version != "" && versionAtLeast(version, QdrantQuickMinVersion)
	}
	return false
}

// versionAtLeast compares dotted versions numerically ("1.19.2" >= "1.17").
func versionAtLeast(v, min string) bool {
	num := func(s string) []int {
		var out []int
		for _, p := range strings.Split(strings.TrimPrefix(strings.TrimSpace(s), "v"), ".") {
			n := 0
			for _, r := range p {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			out = append(out, n)
		}
		return out
	}
	a, b := num(v), num(min)
	for i := range max(len(a), len(b)) {
		x, y := 0, 0
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x > y
		}
	}
	return true
}

// SnapshotScheduleKind is the schedule of an engine's frequent snapshots:
// "diff" for OpenSearch (between its daily full ones, which start retention
// periods and stay at most hourly), "full" for Qdrant and Meilisearch.
func SnapshotScheduleKind(engine string) string {
	if NormalizeEngine(engine) == EngineOpenSearch {
		return BackupDiff
	}
	return BackupFull
}

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
// The rest is capped at SnapshotMaxRest, so a very slow snapshot never
// stops the next ones for long. Times are the control plane's own (when
// the backup task started and finished), never the server's clock.
const (
	SnapshotBusyShare  = 0.25
	SnapshotRestFactor = 3
	SnapshotMaxRest    = 3 * time.Hour
)

// SnapshotRest is how long the server rests after a snapshot that took
// took, between runs every interval (0: none).
func SnapshotRest(took, interval time.Duration) time.Duration {
	if took <= 0 || interval <= 0 || took <= time.Duration(float64(interval)*SnapshotBusyShare) {
		return 0
	}
	return min(SnapshotRestFactor*took, SnapshotMaxRest)
}

// SnapshotDue says whether a scheduled snapshot may run now: last is how
// long the newest backup took and when it finished, interval the time
// between two runs of its schedule.
func SnapshotDue(lastDuration time.Duration, lastStopped, now time.Time, interval time.Duration) bool {
	rest := SnapshotRest(lastDuration, interval)
	if rest == 0 || lastStopped.After(now) {
		return true
	}
	return now.Sub(lastStopped) >= rest
}
