package protocol

// ---- Redis and Valkey settings (Tuning)
//
// The agent reports the settings in tune's Redis catalog as PGSettings
// (CONFIG GET; Unit "B" for sizes, "s", "ms" or "us" for times, VarType
// "bool" for yes/no switches; every one changes on the running server, so
// Context is "sighup"). A setting whose value in the server's
// configuration file differs from the running one has PendingValue (the
// value Redis comes back with after a restart).
//
// A settings task applies each change live (CONFIG SET), then keeps it:
// through root's Tuning helper, which edits the server's configuration
// file where root allowed it at install (`--allow-tuning`, a copy kept
// first); else through the server itself (CONFIG REWRITE) when it can
// write its own file; else the change lasts until the server restarts,
// which SettingsSnapshot.Redis.LiveOnly says before and the result's
// summary says after. AppliedSetting.Previous is the running value
// before the change (an undo puts it back).
//
// "Tune for this server" reads the workload hint with Redis meanings:
// RedisWorkloadCache, RedisWorkloadStore, and WorkloadMixed for "not
// sure", where the share of keys with an expiry decides.

// Workload hints for Redis and Valkey (the same stored values as
// PostgreSQL's).
const (
	RedisWorkloadCache = WorkloadWeb       // a cache: keys can be recomputed, most expire
	RedisWorkloadStore = WorkloadAnalytics // a store or a queue: no key may be lost
)

// RedisSettingsFacts is what recommendations and validation need to know
// about a Redis or Valkey server beyond its settings
// (SettingsSnapshot.Redis).
type RedisSettingsFacts struct {
	// Keys and ExpiringKeys count every logical database's keys, and the
	// ones with a time to live (INFO keyspace).
	Keys         int64 `json:"keys"`
	ExpiringKeys int64 `json:"expiring_keys"`
	// UsedMemoryBytes is used_memory: a memory limit below it would evict
	// (or refuse writes) at once.
	UsedMemoryBytes int64 `json:"used_memory_bytes"`
	// ConfigFile is the server's configuration file ("" when it was
	// started without one).
	ConfigFile string `json:"config_file,omitempty"`
	// Kept says how changes are kept after a restart: "file" (root's
	// Tuning helper edits the configuration file), "rewrite" (the server
	// rewrites its own file, when it may), or "" (they aren't).
	Kept string `json:"kept,omitempty"`
	// LiveOnly says, in plain words, when changes may last only until the
	// server restarts ("" when they are kept).
	LiveOnly string `json:"live_only,omitempty"`
}

// How Redis settings changes are kept (RedisSettingsFacts.Kept).
const (
	RedisKeptFile    = "file"
	RedisKeptRewrite = "rewrite"
)
