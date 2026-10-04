package protocol

import "time"

// ---- Redis and Valkey (engines "redis" and "valkey")
//
// Redis and Valkey databases use the same tasks and results as PostgreSQL
// ones, with these meanings (internal/engine/redis serves both):
//
//   - A Rowsafe "database" is one standalone redis-server or valkey-server
//     (with or without replicas of its own); its logical databases (0-15 by
//     default) are InspectResult.Databases, named "db0", "db1"... with
//     DBInfo.Tables holding the number of keys. Redis Cluster and servers
//     managed by Sentinel are refused at adopt with a plain sentence.
//     Redis 7.0 or newer and Valkey 7.2 or newer.
//   - DatabaseSpec.Port is the server's TCP port (6379 by default). The
//     agent connects to 127.0.0.1, or to ROWSAFE_REDIS_HOST in a Docker
//     sidecar, as its own ACL user ("rowsafe", created by the installer;
//     its password stays on the server). SocketDir is unused.
//   - Backups: a full snapshot (RDB) the server sends the agent over the
//     replication handshake (what `redis-cli --rdb` does: no file access,
//     works across containers), encrypted on the server (objstore.Seal)
//     and stored under <repo path>/<stanza>/. BackupResult.WALStart and
//     WALStop are "<replication id>:<offset>" of the snapshot. Every backup
//     is full; BackupDiff and BackupIncr are taken as full.
//   - Continuous archiving (restores to any second): the agent stays
//     attached to the server as a replica that never serves anything
//     (INFO replication shows it as ip=rowsafe-agent; Pulse leaves it
//     out), cuts the replication stream into segments about every minute,
//     each command stamped with the moment it arrived, and uploads them
//     sealed. When the server can't continue the stream (its backlog was
//     overwritten while the agent was away), the snapshot it sends instead
//     becomes a new backup by itself. ArchiverStats.ArchiveMode is "on"
//     while the agent follows the server, RedisArchiveSnapshots when it
//     can't (Error says why in plain words: replication refused, or
//     min-replicas-to-write in use). Backups are then snapshots on the
//     schedule only, through BGSAVE and the server's own file, and restores
//     go back to those snapshots, not to any second.
//   - Restores to a moment load the newest snapshot taken before it into a
//     temporary server of the same engine and version (the host's own
//     binary; in Docker, the one shipped in the agent image) and replay the
//     stream up to that second. Precision is the agent's arrival time
//     (about a second). Keys whose expiry time has passed by the time of
//     the restore are gone, as Redis itself drops them.
//   - RestorePointResult (a Mark): LSN is "<replication id>:<offset>" of
//     the server when the Mark was taken; a restore to it replays exactly
//     up to that offset. WALFile is the segment holding it.
//   - Rewind copies run as a separate, temporary server on the same host,
//     listening only on a Unix socket in a private directory
//     (RewindCopyResult.SocketDir/redis.sock; Port is 0).
//   - RewindTable: DB is the logical database ("0".."15"), Table a key
//     pattern (Redis glob: "user:*"; "*" for every key). A compare without
//     tables reports one entry per logical database (Table "*"): keys only
//     in the copy (MissingInProduction), keys whose value differs
//     (Changed), keys added since (OnlyInProduction). Large databases are
//     sampled: Note then says how many keys were compared. Bringing keys
//     back writes them with their remaining time to live and never
//     overwrites a key unless IncludeChanged.
//   - Rewind in place replaces the data through the server itself, one
//     logical database at a time: the restored keys are loaded into an
//     empty logical database, then SWAPDB swaps it with the live one in an
//     instant (no restart, never a moment without data). The data from
//     before is a snapshot kept in the bucket for Undo (KeepDays).
//   - Monitoring: the shared metrics the engine can fill (connections_*,
//     database_size_bytes, replication_lag_seconds, disk_* in a native
//     install), the redis_* metrics in collect/catalog_redis.go, and
//     DatabaseMonitoring.Redis below.

// RedisArchiveSnapshots is ArchiverStats.ArchiveMode for a Redis or Valkey
// server Rowsafe can't follow: backups are scheduled snapshots only.
const RedisArchiveSnapshots = "snapshots"

// Redis and Valkey fixes (MaintenanceParams.Action). The agent checks the
// situation is still the same before changing anything, applies the change
// live (CONFIG SET) and keeps it in the server's configuration file when
// the server can write it (CONFIG REWRITE); the summary says when it lasts
// only until the next restart.
const (
	// MaintRedisEvictionPolicy sets maxmemory-policy
	// (Settings["maxmemory-policy"]: allkeys-lru, allkeys-lfu, volatile-lru,
	// volatile-lfu...), for a server near maxmemory with noeviction (which
	// refuses writes once full).
	MaintRedisEvictionPolicy = "redis_eviction_policy"
	// MaintRedisMemoryPurge asks the allocator to give unused memory back
	// (MEMORY PURGE; jemalloc only). Harmless, instant.
	MaintRedisMemoryPurge = "redis_memory_purge"
	// MaintRedisActiveDefrag turns on active defragmentation
	// (activedefrag yes; jemalloc only), which compacts memory in the
	// background at a small CPU cost.
	MaintRedisActiveDefrag = "redis_active_defrag"
	// MaintRedisKillClient disconnects one client (CLIENT KILL ID).
	// MaintenanceParams.PID is its client id and BackendStart when it
	// connected: the agent checks it is still the same connection, and
	// refuses replicas, the agent's own link and its own connections.
	MaintRedisKillClient = "redis_kill_client"
	// MaintRedisBacklog raises repl-backlog-size
	// (Settings["repl-backlog-size"], bytes), so a replica (and Rowsafe's
	// link) that drops for a moment continues where it stopped instead of
	// asking the server for a whole new snapshot.
	MaintRedisBacklog = "redis_repl_backlog"
)

// redisFeatures are what Redis supports (EngineCapabilities). Redis and
// Valkey share the agent package internal/engine/redis.
var redisFeatures = EngineFeatures{
	Backups: true, PointInTime: true, Proof: true,
	RewindCopy: true, RewindRows: true, RewindInPlace: true, Marks: true,
	Monitoring: true, Fixes: true, Restart: true,
	Files: true, SecondCopy: true,
	DBAdmin: true,
	Settings: true, // Tuning: CONFIG SET, kept in redis.conf (settings.go)
}

// valkeyFeatures are Redis's: Valkey is a fork of Redis 7.2 that speaks the
// same protocol and keeps the same files.
var valkeyFeatures = redisFeatures

// RedisStatus is Redis's (or Valkey's) own health detail
// (DatabaseMonitoring.Redis), read about every 5 minutes. Key names and
// values never appear in it.
type RedisStatus struct {
	CollectedAt time.Time `json:"collected_at"`
	Version     string    `json:"version"`
	// Role is "master" or "replica" (INFO replication).
	Role string `json:"role"`
	// Memory: used_memory, maxmemory (0: no limit), maxmemory-policy, the
	// allocator (activedefrag and MEMORY PURGE need jemalloc), the
	// fragmentation ratio and its bytes (used_memory_rss - used_memory).
	UsedMemoryBytes    int64   `json:"used_memory_bytes"`
	MaxMemoryBytes     int64   `json:"max_memory_bytes"`
	MaxMemoryPolicy    string  `json:"max_memory_policy"`
	Allocator          string  `json:"allocator,omitempty"`
	ActiveDefrag       bool    `json:"active_defrag"`
	FragmentationRatio float64 `json:"fragmentation_ratio,omitempty"`
	FragmentationBytes int64   `json:"fragmentation_bytes,omitempty"`
	// TotalSystemMemoryBytes is the host's memory as Redis sees it (0 when
	// unknown).
	TotalSystemMemoryBytes int64 `json:"total_system_memory_bytes,omitempty"`
	// EvictedKeys counts keys evicted since the server started.
	EvictedKeys int64            `json:"evicted_keys"`
	Persistence RedisPersistence `json:"persistence"`
	// Replicas are the server's own replicas (Rowsafe's link left out).
	Replicas []RedisReplica `json:"replicas,omitempty"`
	// Primary is set on a replica: its link to its primary.
	Primary *RedisPrimaryLink `json:"primary,omitempty"`
	// SlowLog are the newest slow log entries (at most 20). Command is the
	// command's name only, never its arguments (keys are customer data).
	SlowLog []RedisSlowEntry `json:"slowlog,omitempty"`
	// Latency are the latency monitor's events (LATENCY LATEST), when it
	// is on (latency-monitor-threshold > 0).
	Latency []RedisLatencyEvent `json:"latency,omitempty"`
	// Clients are connections that look stuck (blocked for over 5 minutes,
	// or holding a large output buffer), at most 20, the worst first.
	Clients []RedisClient `json:"clients,omitempty"`
	// MaxClients is the maxclients setting.
	MaxClients int64 `json:"max_clients,omitempty"`
	// ReplBacklogBytes is repl-backlog-size; FullSyncs counts the whole
	// snapshots the server sent replicas since it started (sync_full),
	// AgentFullSyncs24h the ones Rowsafe's link needed in the last day
	// (each costs the server a fork and a snapshot).
	ReplBacklogBytes  int64 `json:"repl_backlog_bytes,omitempty"`
	FullSyncs         int64 `json:"full_syncs,omitempty"`
	AgentFullSyncs24h int   `json:"agent_full_syncs_24h,omitempty"`
	// MinReplicasToWrite is min-replicas-to-write (Rowsafe doesn't follow a
	// server that uses it: its link would count as a replica).
	MinReplicasToWrite int `json:"min_replicas_to_write,omitempty"`
	// NoPassword: the default user signs in without a password (anyone who
	// can reach the port can read and change everything).
	NoPassword bool `json:"no_password,omitempty"`
	// Link is how Rowsafe follows the server: "replica" (every change,
	// restores to any second), "snapshots" (scheduled snapshots only;
	// LinkProblem says why in plain words) or "" (not yet).
	Link        string `json:"link,omitempty"`
	LinkProblem string `json:"link_problem,omitempty"`
}

// RedisPersistence is how the server keeps its data on its own disk.
type RedisPersistence struct {
	// SaveRules is the "save" setting ("" when snapshots are off).
	SaveRules        string     `json:"save_rules"`
	LastSaveAt       *time.Time `json:"last_save_at,omitempty"`
	LastBgsaveOK     bool       `json:"last_bgsave_ok"`
	ChangesSinceSave int64      `json:"changes_since_save"`
	AOFEnabled       bool       `json:"aof_enabled"`
	AOFLastWriteOK   bool       `json:"aof_last_write_ok"`
	AOFLastRewriteOK bool       `json:"aof_last_rewrite_ok"`
	Loading          bool       `json:"loading,omitempty"`
	ForkMicroseconds int64      `json:"fork_microseconds,omitempty"` // latest_fork_usec
}

// RedisReplica is one of the server's replicas.
type RedisReplica struct {
	Addr        string `json:"addr"` // ip:port as the replica announced it
	State       string `json:"state"`
	LagSeconds  int64  `json:"lag_seconds"`
	BehindBytes int64  `json:"behind_bytes"`
}

// RedisPrimaryLink is a replica's link to its primary.
type RedisPrimaryLink struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	LinkUp         bool   `json:"link_up"`
	DownSeconds    int64  `json:"down_seconds,omitempty"`
	LastIOSeconds  int64  `json:"last_io_seconds"`
	SyncInProgress bool   `json:"sync_in_progress,omitempty"`
}

// RedisSlowEntry is one slow log entry.
type RedisSlowEntry struct {
	ID             int64     `json:"id"`
	At             time.Time `json:"at"`
	DurationMicros int64     `json:"duration_micros"`
	Command        string    `json:"command"`
	Client         string    `json:"client,omitempty"` // the client's name, when it set one
}

// RedisLatencyEvent is one LATENCY LATEST row.
type RedisLatencyEvent struct {
	Event    string    `json:"event"`
	At       time.Time `json:"at"`
	LatestMs int64     `json:"latest_ms"`
	MaxMs    int64     `json:"max_ms"`
}

// RedisClient is a connection that looks stuck. ID and ConnectedAt
// identify it for a redis_kill_client fix (ids are never reused while the
// server runs; ConnectedAt guards against a restart).
type RedisClient struct {
	ID                int64     `json:"id"`
	Addr              string    `json:"addr"`
	Name              string    `json:"name,omitempty"`
	User              string    `json:"user,omitempty"`
	ConnectedAt       time.Time `json:"connected_at"`
	IdleSeconds       int64     `json:"idle_seconds"`
	Command           string    `json:"command"` // the last command's name
	Blocked           bool      `json:"blocked,omitempty"`
	OutputBufferBytes int64     `json:"output_buffer_bytes,omitempty"`
	// Reason says, in plain words, why it is listed.
	Reason string `json:"reason"`
}
