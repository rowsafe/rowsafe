package protocol

import "time"

// ---- OpenSearch (engine "opensearch")
//
// OpenSearch servers use the same tasks and results as PostgreSQL ones,
// with these meanings (internal/engine/opensearch):
//
//   - A Rowsafe "database" is one single-node OpenSearch server (2.x or
//     3.x, the security plugin on or off); its indices and data streams are
//     InspectResult.Databases (DBInfo.Tables holds the number of documents).
//     Clusters of several nodes are refused at adopt with a plain sentence.
//   - DatabaseSpec.Port is the REST port (9200). The agent connects to
//     127.0.0.1 over HTTPS (plain HTTP when the server has TLS off), as its
//     own user ("rowsafe", made by the installer; its password stays on the
//     server). The certificate isn't checked on loopback: the connection
//     never leaves the server.
//   - Backups are OpenSearch's own snapshots into a shared-file-system
//     repository on the server's own disk (path.repo, the installer sets it
//     up: /var/lib/rowsafe-opensearch/snapshots), never into a bucket: the
//     agent then copies every new file of the repository to the bucket,
//     encrypted on the server (objstore.Seal, ROWSAFE_REPO_CIPHER_PASS), under
//     <repo path>/<stanza>/repo/, and removes from the bucket what OpenSearch
//     removed. OpenSearch never sees the bucket or its keys. Snapshots are
//     incremental by nature (a file already in the repository is never
//     copied twice): BackupFull and BackupDiff are both a snapshot of every
//     index and data stream (not the security plugin's own index or other
//     system indices); a full one starts a retention period, like
//     pgBackRest's full backups. Retention keeps the newest RetentionFull
//     full snapshots and every snapshot and Mark newer than the oldest of
//     them, through OpenSearch (which deletes only files no kept snapshot
//     needs), then the bucket follows. BackupResult.Label is the backup's
//     label (20261009-013000F, 20261009-013000D); the snapshot's name is
//     "rowsafe-" + its label in lowercase.
//   - There is no log of changes: restores go back to a snapshot (a backup
//     or a Mark), never to any second (PointInTime is off). A new database
//     gets a snapshot every 30 minutes (OpenSearchScheduleDiff) and a full
//     one every day.
//   - RestorePointResult (a Mark, MarkIsBackup): a snapshot taken on the
//     spot and named after the Mark. LSN is its label; WALFile is unused.
//   - Proof restores the newest snapshot from the bucket (not from the
//     server's disk) into a temporary OpenSearch on the same server: the
//     same program as production, as the agent's user, on 127.0.0.1 only,
//     with a small heap and its own random login, then checks every index
//     came back green with its documents.
//   - Rewind copies are such a temporary OpenSearch, kept until they expire
//     (RewindCopyResult.Port is its HTTPS port on 127.0.0.1; SocketDir is
//     empty). RewindTable: DB is the index (or data stream) name, Table is
//     "*" (every document). A compare counts, by document _id, the documents
//     only in the copy (MissingInProduction), those whose content differs
//     (Changed) and those added since (OnlyInProduction); large indices are
//     sampled (Note). Bringing documents back writes them with their _id
//     and never overwrites one unless IncludeChanged.
//   - Rewind in place: a snapshot of everything as it is now first (kept
//     for Undo, KeepDays), then the indices and data streams are replaced
//     by the snapshot's through OpenSearch itself (deleted, then restored
//     from the server's own repository); searches of them fail for the
//     moments that takes, nothing restarts. If the restore fails, the
//     snapshot taken first is restored instead.
//   - Monitoring: the shared metrics the engine can fill (database_size_bytes,
//     connections_*, disk_*), and DatabaseMonitoring.OpenSearch below.

// EngineOpenSearch is OpenSearch (Apache-2.0).
const EngineOpenSearch = "opensearch"

// OpenSearch registers itself in the engine lists (engine.go,
// cloud_engines.go, dbadmin.go), so the shared lists stay as they are.
func init() {
	Engines = append(Engines, EngineOpenSearch)
	EngineCapabilities[EngineOpenSearch] = opensearchFeatures
	CloudEngines = append(CloudEngines, opensearchCloud)
	systemUsers[EngineOpenSearch] = OpenSearchSystemUsers
}

// opensearchFeatures are what OpenSearch supports (EngineCapabilities).
var opensearchFeatures = EngineFeatures{
	Backups: true, Proof: true,
	RewindCopy: true, RewindRows: true, RewindInPlace: true, Marks: true,
	Monitoring: true, Fixes: true,
	Restart:  true, // through root's helper, the units root allowed (opensearch.service)
	DBAdmin:  true, // the security plugin's users and roles, on index patterns (opensearch_dbadmin.go)
	Security: true,
}

// OpenSearchSystemUsers are users OpenSearch's security plugin (or its
// installers) keep for themselves: listed, never changed from Rowsafe.
var OpenSearchSystemUsers = []string{"admin", "kibanaserver", "kibanaro", "logstash", "readall", "snapshotrestore", "anomalyadmin"}

// OpenSearch on servers Rowsafe creates: the 3.x series from OpenSearch's
// own apt repository (artifacts.opensearch.org, pinned to 3.*), single
// node, with its bundled Java. TLS on the REST port only (9200) with the
// security plugin on and no demo users; the node-to-node port (9300)
// listens on the server itself only. 4 GB of memory at least (half of it
// for OpenSearch's heap).
var opensearchCloud = CloudEngine{Engine: EngineOpenSearch, Name: "OpenSearch", Versions: []string{"3"}, DefaultVersion: "3",
	Port: 9200, Scheme: "https", MinMemoryMB: 4096,
	Note: "OpenSearch 3 from OpenSearch's own packages, one node. Apps connect over HTTPS on port 9200 with a user and password. " +
		"Backups are its own snapshots, every 30 minutes and on every Mark: restores go back to a snapshot, not to any second. Sizes with 4 GB of memory or more."}

// OpenSearchScheduleFull and OpenSearchScheduleDiff are a new OpenSearch
// database's backup schedules: a full snapshot every day (01:00 UTC) and
// one every 30 minutes in between. Every snapshot copies only new files.
const (
	OpenSearchScheduleFull = "0 1 * * *"
	OpenSearchScheduleDiff = "*/30 * * * *"
	OpenSearchPort         = 9200
)

// FeatureServerCertificateOpenSearch is in HeartbeatRequest.Features of
// agents that install certificates for Rowsafe Cloud names on OpenSearch
// servers: the installer's --install-opensearch --listen-public serves
// /etc/ssl/rowsafe-opensearch/rowsafe-server.crt and .key on 9200, and
// OpenSearch loads new files by itself (certificates hot reload, without
// requiring the same issuer), without a restart.
const FeatureServerCertificateOpenSearch = "server_certificate_opensearch"

// OpenSearch fixes (MaintenanceParams.Action). The agent checks the
// situation is still the same before changing anything.
const (
	// MaintOpenSearchReplicas sets number_of_replicas to 0 on the indices
	// whose replicas can't be placed: a single-node server can never hold a
	// replica, so its health stays yellow. MaintenanceParams.Tables are the
	// indices (empty: every index with unassigned replicas). Instant, no
	// data moves.
	MaintOpenSearchReplicas = "opensearch_replicas"
	// MaintOpenSearchReadOnly removes the read-only block OpenSearch puts on
	// indices when the disk passed its flood-stage watermark
	// (index.blocks.read_only_allow_delete), once the disk has room again
	// (below the high watermark): writes work again.
	MaintOpenSearchReadOnly = "opensearch_read_only"
)

// OpenSearchStatus is OpenSearch's own health detail
// (DatabaseMonitoring.OpenSearch), read about every minute. Index names
// appear (they are names, like table names); documents never do.
type OpenSearchStatus struct {
	CollectedAt time.Time `json:"collected_at"`
	Version     string    `json:"version"`
	// Distribution is "opensearch" (a server that answers like
	// Elasticsearch is refused at adopt).
	ClusterName string `json:"cluster_name,omitempty"`
	// Status is the cluster's health: green, yellow or red.
	Status string `json:"status"`
	Nodes  int    `json:"nodes"`
	// Shards: active, relocating, initializing and unassigned shards
	// (primaries and replicas), and unassigned primaries (data that can't
	// be read: red).
	ActiveShards        int `json:"active_shards"`
	RelocatingShards    int `json:"relocating_shards,omitempty"`
	InitializingShards  int `json:"initializing_shards,omitempty"`
	UnassignedShards    int `json:"unassigned_shards,omitempty"`
	UnassignedPrimaries int `json:"unassigned_primaries,omitempty"`
	// UnassignedReplicaIndices are the indices with replicas that can't be
	// placed (at most 50), for MaintOpenSearchReplicas.
	UnassignedReplicaIndices []string `json:"unassigned_replica_indices,omitempty"`
	// RedIndices are indices with a primary shard unassigned (at most 50).
	RedIndices []string `json:"red_indices,omitempty"`
	// Indices and Documents count the server's indices (system ones left
	// out) and their documents; StoreBytes is what they take on disk.
	Indices    int   `json:"indices"`
	Documents  int64 `json:"documents"`
	StoreBytes int64 `json:"store_bytes"`
	// Disk is the data folder's disk as OpenSearch sees it, with the
	// watermarks it acts on (percent used): above Low no new replicas are
	// placed, above High shards move away, above FloodStage every index gets
	// a read-only block.
	DiskTotalBytes     int64   `json:"disk_total_bytes,omitempty"`
	DiskAvailableBytes int64   `json:"disk_available_bytes,omitempty"`
	WatermarkLow       float64 `json:"watermark_low,omitempty"`
	WatermarkHigh      float64 `json:"watermark_high,omitempty"`
	WatermarkFlood     float64 `json:"watermark_flood,omitempty"`
	// ReadOnlyIndices have the read-only block of a full disk
	// (index.blocks.read_only_allow_delete), at most 50.
	ReadOnlyIndices []string `json:"read_only_indices,omitempty"`
	// Heap: the JVM's heap in use and its maximum; HeapPercent is what
	// OpenSearch reports (heap_used_percent).
	HeapUsedBytes int64 `json:"heap_used_bytes"`
	HeapMaxBytes  int64 `json:"heap_max_bytes"`
	HeapPercent   int   `json:"heap_percent"`
	// MemoryTotalBytes is the server's memory as OpenSearch sees it.
	MemoryTotalBytes int64 `json:"memory_total_bytes,omitempty"`
	// GC: the old generation's collections since the JVM started (count and
	// time), and how many happened since the previous sample with the time
	// they took (long pauses stop searches).
	OldGCCount         int64 `json:"old_gc_count"`
	OldGCMillis        int64 `json:"old_gc_millis"`
	OldGCRecent        int64 `json:"old_gc_recent,omitempty"`
	OldGCRecentMillis  int64 `json:"old_gc_recent_millis,omitempty"`
	YoungGCRecentCount int64 `json:"young_gc_recent,omitempty"`
	// CircuitBreakerTrips counts requests OpenSearch refused to protect its
	// memory, since it started.
	CircuitBreakerTrips int64 `json:"circuit_breaker_trips,omitempty"`
	// Rejected counts requests the search and write thread pools turned away
	// since the previous sample (queues full).
	SearchRejected int64 `json:"search_rejected,omitempty"`
	WriteRejected  int64 `json:"write_rejected,omitempty"`
	// OpenHTTP is the HTTP connections open now.
	OpenHTTP int64 `json:"open_http,omitempty"`
	// Security: the security plugin is on (users and passwords) and the REST
	// port speaks TLS.
	SecurityPlugin bool `json:"security_plugin"`
	TLS            bool `json:"tls"`
	// Snapshots: the newest snapshot of Rowsafe's repository and how many
	// it holds; RepoBytes is the repository's size on this server's disk.
	LastSnapshotAt *time.Time `json:"last_snapshot_at,omitempty"`
	Snapshots      int        `json:"snapshots,omitempty"`
	RepoBytes      int64      `json:"repo_bytes,omitempty"`
}
