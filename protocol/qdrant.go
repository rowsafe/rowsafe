package protocol

import (
	"fmt"
	"time"
)

// ---- Qdrant (engine "qdrant")
//
// Qdrant is a vector database (Apache-2.0) apps reach over HTTP (REST, 6333
// by default) and gRPC (6334). Qdrant databases use the same tasks and
// results as PostgreSQL ones, with these meanings (internal/engine/qdrant):
//
//   - A Rowsafe "database" is one single-node Qdrant server; its
//     collections are InspectResult.Databases (DBInfo.Tables holds the
//     number of points, clamped). Distributed (cluster) mode is refused at
//     adopt with a plain sentence. Qdrant 1.13 or newer.
//   - DatabaseSpec.Port is the server's REST port. The agent connects to
//     127.0.0.1 (https when the server has TLS on: the connection never
//     leaves the machine, so the certificate, made for the server's public
//     names, isn't checked against a name; else http), or to
//     ROWSAFE_QDRANT_URL in a Docker sidecar (checked against
//     ROWSAFE_QDRANT_CA_FILE when set). SocketDir is unused.
//   - Rowsafe's access: Qdrant has no role that can take a full snapshot
//     without every right, so Rowsafe gets a key of its own, separate from
//     the server's own keys: the alternative key (service.alt_api_key),
//     which root sets and hands to the agent at install. The server's own
//     keys (api_key, read_only_api_key) stay root's and never reach
//     Rowsafe. With JWT access control on (service.jwt_rbac), the agent
//     never sends its key at all: it signs a token valid for a few minutes
//     for each request. Root can rotate Rowsafe's key alone.
//   - Backups are Qdrant's own full storage snapshot (every collection and
//     alias; POST /snapshots), downloaded from the server over its API as
//     Qdrant writes it, encrypted on the server (objstore.Seal) and stored
//     under <repo path>/<stanza>/; the snapshot is then deleted from the
//     server's disk. Every backup is full (BackupDiff and BackupIncr are
//     taken as full); WALStart/WALStop are unused.
//   - No continuous archiving: restores go back to a backup, not to any
//     second (PointInTime is false). A Mark is a backup taken on the spot
//     and named after the Mark (RestorePointResult.LSN is its label).
//   - Rewind targets: Mark restores the Mark's backup; Time the newest
//     backup taken at or before it (BackupSet when the control plane
//     filled it). RecoveredTo is when that backup was taken.
//   - Rewind copies, Proof and restores run a separate, temporary Qdrant
//     (the host's own program; in Docker, the one in the agent image) on
//     127.0.0.1 only, on a free port, with a key only the agent knows,
//     started from the snapshot (--storage-snapshot) in the agent's rewind
//     or drill directory. RewindCopyResult.Port is its REST port.
//   - Rewind in place restores each collection through Qdrant's own API
//     (a collection snapshot uploaded with priority "snapshot"; no
//     restart): collections that didn't exist then are removed and the
//     aliases are put back as they were. A snapshot of the data from before
//     is kept in the bucket for Undo (KeepDays). Rowsafe's own collection
//     (QdrantKeysCollection) is never rewound.
//   - Proof restores the newest backup into a temporary Qdrant and checks
//     every collection is there, green, with the points the backup
//     recorded, and that a search answers in each (DrillDatabase: Name the
//     collection, SourceTables/RestoredTables its points).
//   - Monitoring: the shared metrics the engine can fill
//     (database_size_bytes, disk_* in a native install), the qdrant_*
//     metrics, and DatabaseMonitoring.Qdrant below.
//   - Databases & users: "users" are API keys, JSON Web Tokens the agent
//     signs on the server with Rowsafe's key (JWT access control must be
//     on), shown once to the person who asked (sealed like a password).
//     Each is tied to a point in QdrantKeysCollection, so removing a key
//     (or making it a new token) revokes the old token at once. Access:
//     read_only (every collection, or the ones chosen), read_write (the
//     collections chosen: Qdrant has no read-write right on every
//     collection short of admin) or owner (admin: everything, including
//     creating and deleting collections and snapshots). "Databases" are
//     collections: created by apps (with their vector size and distance),
//     removed from the dashboard (Mark first, like other engines).

// QdrantKeysCollection is the collection where Rowsafe records the API
// keys made in Databases & users (one point per key, no vectors); a key's
// token is valid only while its point is there.
const QdrantKeysCollection = "rowsafe_keys"

// Qdrant fixes (MaintenanceParams.Action), proposed by health and checked
// again by the agent before anything changes. Both act through Qdrant's
// API, live, without a restart.
const (
	// MaintQdrantIndexField creates the payload index Qdrant itself
	// suggests for a field searches filter on (GET /issues,
	// UNINDEXED_FIELD): MaintenanceParams.DB is the collection,
	// Settings["field"] the field and Settings["schema"] the index type
	// Qdrant named (keyword, integer, float, bool, geo, datetime, uuid,
	// text). The agent applies it only while Qdrant still reports that
	// issue. Searches use the index once it is built (in the background).
	MaintQdrantIndexField = "qdrant_index_field"
	// MaintQdrantVectorsOnDisk moves the vectors of a collection
	// (MaintenanceParams.DB) to disk (memory-mapped) when the server is
	// short of memory: Qdrant rebuilds the collection's storage in the
	// background; searches keep working and read from disk (slower on a
	// cold cache). Every named vector of the collection moves.
	MaintQdrantVectorsOnDisk = "qdrant_vectors_on_disk"
)

// QdrantMinMemoryMB is the least memory a server Rowsafe creates gets for
// Qdrant (CloudEngine.MinMemoryMB); the installer checks it on the server.
const QdrantMinMemoryMB = 2048

// qdrantFeatures are what Qdrant supports (EngineCapabilities).
var qdrantFeatures = EngineFeatures{
	Backups: true, Proof: true,
	RewindCopy: true, RewindInPlace: true, Marks: true,
	Monitoring: true, Fixes: true, Restart: true,
	DBAdmin:  true, // API keys (JWTs signed on the server), collections listed and removed
	Security: true, // TLS, keys, JWT, CORS, snapshot recovery from URLs, the look from the internet
}

// QdrantStatus is Qdrant's own health detail (DatabaseMonitoring.Qdrant),
// read about every 5 minutes. Collection and field names only, never
// points, vectors or payloads.
type QdrantStatus struct {
	CollectedAt time.Time `json:"collected_at"`
	Version     string    `json:"version"`
	// Cluster: distributed mode is on (Rowsafe protects single servers).
	Cluster bool `json:"cluster,omitempty"`
	// RecoveryMode: Qdrant started in recovery mode (it refuses writes).
	RecoveryMode bool `json:"recovery_mode,omitempty"`
	// Memory: the process's resident memory, the server's memory as Qdrant
	// sees it (cgroup limit or RAM), and how much the vectors of every
	// collection take in memory (vectors not kept on disk).
	ResidentBytes        int64 `json:"resident_bytes"`
	TotalMemoryBytes     int64 `json:"total_memory_bytes,omitempty"`
	VectorsInMemoryBytes int64 `json:"vectors_in_memory_bytes,omitempty"`
	// Collections are the collections (at most 200, the largest first).
	Collections []QdrantCollection `json:"collections,omitempty"`
	// Issues are what Qdrant itself reports (GET /issues), at most 20.
	Issues []QdrantIssue `json:"issues,omitempty"`
	// GRPCOldCert: gRPC serves another certificate than REST (Qdrant loads
	// a renewed certificate for gRPC only when it restarts).
	GRPCOldCert bool `json:"grpc_old_cert,omitempty"`
	// LocalSnapshots counts snapshot files on the server's disk and their
	// size (full and per collection): Rowsafe deletes its own after the
	// upload; others are someone else's.
	LocalSnapshots      int   `json:"local_snapshots,omitempty"`
	LocalSnapshotsBytes int64 `json:"local_snapshots_bytes,omitempty"`
}

// Qdrant collection statuses (QdrantCollection.Status).
const (
	QdrantGreen  = "green"  // ready
	QdrantYellow = "yellow" // optimizing in the background
	QdrantGrey   = "grey"   // optimizations pending until the next update
	QdrantRed    = "red"    // an operation failed: the collection may not answer
)

// QdrantCollection is one collection's state.
type QdrantCollection struct {
	Name   string `json:"name"`
	Status string `json:"status"` // Qdrant* above
	// OptimizerError is the optimizer's error ("" when it is fine).
	OptimizerError string `json:"optimizer_error,omitempty"`
	Points         int64  `json:"points"`
	IndexedVectors int64  `json:"indexed_vectors"`
	Segments       int    `json:"segments"`
	// VectorsBytes and PayloadBytes are the sizes Qdrant reports.
	VectorsBytes int64 `json:"vectors_bytes,omitempty"`
	PayloadBytes int64 `json:"payload_bytes,omitempty"`
	// OnDisk: every vector of the collection is kept on disk (memory
	// mapped) rather than in memory.
	OnDisk bool `json:"on_disk,omitempty"`
	// Vectors names the collection's vectors ("" is the unnamed one).
	Vectors []string `json:"vectors,omitempty"`
	// Shards, Replicas: a single server has 1 replica per shard.
	Shards   int `json:"shards,omitempty"`
	Replicas int `json:"replicas,omitempty"`
}

// QdrantIssue is one issue Qdrant reports. For an unindexed field,
// Collection, Field and Schemas say what MaintQdrantIndexField would
// create.
type QdrantIssue struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Collection  string   `json:"collection,omitempty"`
	Field       string   `json:"field,omitempty"`
	Schemas     []string `json:"schemas,omitempty"`
}

// QdrantSecurity is what the security check reads from Qdrant
// (EngineSecurity.Qdrant), from its settings as the API and the
// configuration file show them. Keys are never read or reported, only
// whether they are set.
type QdrantSecurity struct {
	// APIKey: requests need a key (api_key, or alt_api_key alone).
	APIKey bool `json:"api_key"`
	// ReadOnlyKey: a read-only key is set.
	ReadOnlyKey bool `json:"read_only_key,omitempty"`
	// JWT: JSON Web Tokens are accepted (service.jwt_rbac): Databases &
	// users can make keys.
	JWT bool `json:"jwt"`
	// TLS: REST and gRPC use TLS (service.enable_tls).
	TLS bool `json:"tls"`
	// GRPCPort is the gRPC port (0: gRPC is off).
	GRPCPort int `json:"grpc_port,omitempty"`
	// CORS: browsers on any site may call the REST API (enable_cors, on by
	// default): only harmful together with a key in a web page.
	CORS bool `json:"cors,omitempty"`
	// URLRecovery: snapshots may be recovered from any URL
	// (enable_snapshot_url_recovery, on by default), which lets anyone
	// with an admin key make the server fetch addresses inside your
	// network.
	URLRecovery bool `json:"url_recovery,omitempty"`
	// Telemetry: Qdrant sends anonymous usage statistics to its developers.
	Telemetry bool `json:"telemetry,omitempty"`
	// P2P: the port for other cluster members (6335) listens beyond this
	// server.
	P2P bool `json:"p2p,omitempty"`
	// ConfigFile is the configuration file, when known (for "Do it
	// yourself"); ConfigKnown false when the agent couldn't read it (the
	// fields above that need it are then Qdrant's defaults).
	ConfigFile  string `json:"config_file,omitempty"`
	ConfigKnown bool   `json:"config_known,omitempty"`
}

// validateQdrantDBAdmin checks what is Qdrant's own: keys rather than
// users with passwords, collections created by apps.
func validateQdrantDBAdmin(p DBAdminParams) error {
	switch p.Action {
	case DBAdminCreateDatabase:
		return fmt.Errorf("Qdrant collections are created by your app, with its vector size and distance; " +
			"once it has made one, give it a key to that collection here")
	case DBAdminCreateUser:
		if p.Access == DBAccessReadWrite && len(p.Databases) == 0 {
			return fmt.Errorf("Qdrant gives read-write access per collection: choose the collections, " +
				"or make an admin key (owner) for every collection")
		}
		if p.Access == DBAccessOwner && len(p.Databases) > 0 {
			return fmt.Errorf("an admin key reaches every collection; choose read-write for some collections")
		}
	case DBAdminDropUser:
		if p.ReassignTo != "" {
			return fmt.Errorf("Qdrant keys own nothing, so there is nothing to hand over")
		}
	}
	return nil
}
