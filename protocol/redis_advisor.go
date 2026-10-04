package protocol

// ---- Redis and Valkey: recommendations (AdvisorFacts.Redis)
//
// About every 30 minutes the agent looks at a Redis or Valkey server for
// the recommendations: a sample of its keys (SCAN, then TYPE, PTTL and
// MEMORY USAGE of each, slowly and in small batches, at most
// RedisSampleKeysPerDB keys per logical database), the command statistics
// (INFO commandstats) and slow log (command names only), and a few
// settings. None of these change a key or its place in the eviction order.
//
// Key names and values are customer data and never leave the server: only
// key-name patterns do, where every part that looks like an id (anything
// with a digit, long hex strings, emails, long random-looking words) is
// replaced by "*" ("session:*", "user:*:cart"), parts with many distinct
// values become "*" too, and a pattern is only reported when it covers at
// least RedisPatternMinKeys sampled keys (and 0.5% of the sample).
// Everything else counts as "other keys", by number and size only.

// RedisAdvisorFacts are a Redis or Valkey server's facts for the
// recommendations.
type RedisAdvisorFacts struct {
	Version string `json:"version"`
	// Role is "master" or "replica".
	Role          string `json:"role"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	// Memory: used_memory, used_memory_dataset, maxmemory (0: no limit),
	// maxmemory-policy and the host's memory as the server sees it (0 when
	// unknown).
	UsedMemoryBytes        int64  `json:"used_memory_bytes"`
	DatasetBytes           int64  `json:"dataset_bytes"`
	MaxMemoryBytes         int64  `json:"max_memory_bytes"`
	MaxMemoryPolicy        string `json:"max_memory_policy"`
	TotalSystemMemoryBytes int64  `json:"total_system_memory_bytes,omitempty"`
	// Persistence settings: save ("" when snapshots are off), appendonly
	// and appendfsync.
	Save        string `json:"save"`
	AppendOnly  bool   `json:"append_only"`
	AppendFsync string `json:"append_fsync,omitempty"`
	// Databases is the databases setting (16 by default).
	Databases int `json:"databases"`

	// DBs are the logical databases that hold keys, and what was sampled
	// in each.
	DBs []RedisDBFacts `json:"dbs"`
	// Patterns are the key-name patterns of the sample, at most 40, the
	// biggest first.
	Patterns []RedisKeyPattern `json:"patterns"`
	// Commands are the command statistics since the server started (or its
	// statistics were reset): the 30 that took the most time, plus the
	// commands that go through many keys or elements at once
	// (RedisHeavyCommands) when they were used. Names only.
	Commands []RedisCommandStat `json:"commands"`
	// SlowCommands count the slow log's entries (at most the newest 128)
	// by command name.
	SlowCommands []RedisSlowCommand `json:"slow_commands,omitempty"`
	// SampleMs is how long the key sample took; Partial: it stopped before
	// RedisSampleKeysPerDB keys in some database (time limit, the server
	// got busy), so the numbers come from fewer keys.
	SampleMs int64 `json:"sample_ms"`
	Partial  bool  `json:"partial,omitempty"`
}

// RedisDBFacts is one logical database.
type RedisDBFacts struct {
	DB int `json:"db"`
	// Keys and Expires (keys with a time to live) come from INFO keyspace.
	Keys    int64 `json:"keys"`
	Expires int64 `json:"expires"`
	// SampledKeys and SampledBytes (MEMORY USAGE) are the sample;
	// OtherKeys and OtherBytes the sampled keys no reported pattern covers.
	SampledKeys  int64 `json:"sampled_keys"`
	SampledBytes int64 `json:"sampled_bytes"`
	OtherKeys    int64 `json:"other_keys"`
	OtherBytes   int64 `json:"other_bytes"`
	// BigKeys are sampled keys of RedisBigKeyBytes or more; BiggestKeyBytes
	// is the biggest sampled key.
	BigKeys         int64 `json:"big_keys"`
	BiggestKeyBytes int64 `json:"biggest_key_bytes"`
}

// RedisKeyPattern is a group of keys whose names share a shape. Estimated
// figures scale the sample up to the whole logical database.
type RedisKeyPattern struct {
	DB      int    `json:"db"`
	Pattern string `json:"pattern"` // a Redis glob: "session:*"
	// Type is the most common type: string, hash, list, set, zset,
	// stream, or another type's name (modules).
	Type           string `json:"type"`
	SampledKeys    int64  `json:"sampled_keys"`
	SampledBytes   int64  `json:"sampled_bytes"`
	EstimatedKeys  int64  `json:"estimated_keys"`
	EstimatedBytes int64  `json:"estimated_bytes"`
	MaxKeyBytes    int64  `json:"max_key_bytes"`
	BigKeys        int64  `json:"big_keys,omitempty"` // sampled keys of RedisBigKeyBytes or more
	// NoTTL counts sampled keys without a time to live.
	NoTTL int64 `json:"no_ttl"`
}

// RedisCommandStat is one command's statistics (INFO commandstats).
type RedisCommandStat struct {
	Name        string  `json:"name"` // lower case; subcommands as "config|get"
	Calls       int64   `json:"calls"`
	Usec        int64   `json:"usec"`
	UsecPerCall float64 `json:"usec_per_call"`
}

// RedisSlowCommand counts one command's slow log entries.
type RedisSlowCommand struct {
	Name      string `json:"name"` // lower case
	Count     int    `json:"count"`
	MaxMicros int64  `json:"max_micros"`
}

// Sampling limits.
const (
	RedisSampleKeysPerDB = 10000
	RedisPatternMinKeys  = 10
	RedisMaxPatterns     = 40
	// RedisBigKeyBytes: a key this big (MEMORY USAGE) blocks the server
	// noticeably when read whole, deleted or expired.
	RedisBigKeyBytes = 10 << 20
)

// RedisHeavyCommands go through every key, or every element of a key, at
// once: on a big database or key they block every other client meanwhile.
var RedisHeavyCommands = []string{"keys", "flushall", "flushdb", "hgetall", "hkeys", "hvals", "smembers",
	"sunion", "sunionstore", "sinter", "sinterstore", "sdiff", "sdiffstore", "lrange", "zrange",
	"zrangebyscore", "zrevrange", "zrevrangebyscore", "sort", "sort_ro", "xrange", "xrevrange"}
