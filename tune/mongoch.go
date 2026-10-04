package tune

import (
	"fmt"
	"strconv"

	"github.com/rowsafe/rowsafe/protocol"
)

// MongoDB and ClickHouse settings. Rowsafe changes them only in files of
// its own, through a root helper root allowed at install (`rowsafe-allow
// tuning`): ClickHouse's config.d/rowsafe-tuning.xml (server settings) and
// users.d/rowsafe-tuning.xml (the default profile's), and a block of
// MongoDB's configuration file. The agent reports them as PGSettings like
// MySQL's (Unit "B" for sizes; Context "sighup" when a change takes effect
// at once, "postmaster" when it waits for a restart).

// ClickHouseProfileSettings are the ClickHouse settings that belong to the
// default profile (users.d); the others are server settings (config.d).
var ClickHouseProfileSettings = map[string]bool{
	"max_memory_usage": true, "max_threads": true, "max_execution_time": true,
	"max_bytes_before_external_group_by": true, "max_bytes_before_external_sort": true, "log_queries": true,
}

var clickhouseCatalog = []Entry{
	{Name: "max_server_memory_usage_to_ram_ratio", Category: protocol.SettingsCatMemory, Title: "Memory ClickHouse may use (share of the server's)",
		Explanation: "The most memory the whole server may use, as a share of the server's memory. Past it, queries fail instead of the operating system running out. 0.9 is ClickHouse's default."},
	{Name: "max_memory_usage", Category: protocol.SettingsCatMemory, Title: "Memory per query", Off: "0",
		Explanation: "The most memory one query may use. A limit keeps one runaway report from failing every other query."},
	{Name: "max_bytes_before_external_group_by", Category: protocol.SettingsCatMemory, Title: "GROUP BY spills to disk past", Off: "0",
		Explanation: "Past this much memory, GROUP BY continues on disk instead of failing. Off by default; about half the memory per query is usual."},
	{Name: "max_bytes_before_external_sort", Category: protocol.SettingsCatMemory, Title: "ORDER BY spills to disk past", Off: "0",
		Explanation: "Past this much memory, sorting continues on disk instead of failing."},
	{Name: "mark_cache_size", Category: protocol.SettingsCatMemory, Title: "Cache for where data is (marks)",
		Explanation: "Memory for the marks that say where each granule of data is in a file. ClickHouse's default suits most servers."},
	{Name: "uncompressed_cache_size", Category: protocol.SettingsCatMemory, Title: "Cache for uncompressed data",
		Explanation: "Memory for recently read, uncompressed data. Only queries that ask for it use it."},

	{Name: "max_concurrent_queries", Category: protocol.SettingsCatConnections, Title: "Queries at once", Off: "0",
		Explanation: "How many queries may run at the same time; more wait their turn or fail. 0 means no limit."},
	{Name: "max_connections", Category: protocol.SettingsCatConnections, Title: "Maximum connections",
		Explanation: "How many client connections the server accepts at once."},

	{Name: "max_threads", Category: protocol.SettingsCatParallel, Title: "Threads per query", Off: "0",
		Explanation: "How many threads one query may use. 0 means as many as the server has CPUs, which suits most servers."},
	{Name: "background_pool_size", Category: protocol.SettingsCatParallel, Title: "Merges at once",
		Explanation: "Threads that merge data parts in the background. More keeps up with heavy inserts; each uses CPU and disk."},

	{Name: "max_execution_time", Category: protocol.SettingsCatTimeouts, Title: "Longest query", Off: "0",
		Explanation: "Stops queries that run longer than this (in seconds). Off by default."},

	{Name: "log_queries", Category: protocol.SettingsCatLogging, Title: "Log queries",
		Explanation: "Records every query in system.query_log, which Pulse reads for slow queries. On by default."},
}

var mongoCatalog = []Entry{
	{Name: "wiredtiger_cache_size", Category: protocol.SettingsCatMemory, Title: "Memory for caching data",
		Explanation: "Memory WiredTiger keeps your collections and indexes in (storage.wiredTiger.engineConfig.cacheSizeGB). MongoDB's default is half of the server's memory minus 1 GB, which suits a server that mostly runs MongoDB."},
	{Name: "max_incoming_connections", Category: protocol.SettingsCatConnections, Title: "Maximum connections",
		Explanation: "How many connections MongoDB accepts at once (net.maxIncomingConnections)."},
	{Name: "transaction_lifetime_limit_seconds", Category: protocol.SettingsCatTimeouts, Title: "Longest transaction",
		Explanation: "Transactions open longer than this are aborted (in seconds), so a forgotten one can't hold the cache. 60 is MongoDB's default."},
	{Name: "slow_op_threshold_ms", Category: protocol.SettingsCatLogging, Title: "Slow operation threshold",
		Explanation: "Operations slower than this (in milliseconds) are logged as slow (operationProfiling.slowOpThresholdMs)."},
	{Name: "profiling_mode", Category: protocol.SettingsCatLogging, Title: "Profiler",
		Explanation: "off, or slowOp: also record slow operations in each database's system.profile collection (operationProfiling.mode). Rowsafe never turns on \"all\", which records every operation."},
}

var engineCategories = []struct{ ID, Title string }{
	{protocol.SettingsCatMemory, "Memory"},
	{protocol.SettingsCatConnections, "Connections"},
	{protocol.SettingsCatParallel, "Threads"},
	{protocol.SettingsCatTimeouts, "Timeouts"},
	{protocol.SettingsCatLogging, "Logging"},
	{protocol.SettingsCatOther, "Other settings"},
}

var (
	clickhouseTuner = newTuner(protocol.EngineClickHouse, clickhouseCatalog, engineCategories, recommendClickHouse, validateClickHouse)
	mongoTuner      = newTuner(protocol.EngineMongoDB, mongoCatalog, engineCategories, recommendMongo, validateMongo)
)

func entriesOf(c []Entry) map[string]Entry {
	m := map[string]Entry{}
	for _, e := range c {
		m[e.Name] = e
	}
	return m
}

var (
	clickhouseEntries = entriesOf(clickhouseCatalog)
	mongoEntries      = entriesOf(mongoCatalog)
)

// EngineValue turns a change's value into what engine's file takes: sizes
// in bytes, numbers as given, switches as 1/0 (ClickHouse) or true/false.
func EngineValue(engine string, s protocol.PGSetting, value string) (string, bool) {
	if e := protocol.NormalizeEngine(engine); e == protocol.EngineRedis || e == protocol.EngineValkey {
		return RedisValue(s, value)
	}
	v, ok := MySQLValue(s, value)
	if !ok || s.VarType != "bool" {
		return v, ok
	}
	if engine == protocol.EngineClickHouse {
		return map[string]string{"ON": "1", "OFF": "0"}[v], true
	}
	return map[string]string{"ON": "true", "OFF": "false"}[v], true
}

// validateCatalog checks changes against a catalog: known names, valid
// values within the server's limits, then check for each value.
func validateCatalog(engine string, entries map[string]Entry, changes []protocol.SettingChange, f Facts,
	check func(name, value string, s protocol.PGSetting) *Refusal) error {
	if len(changes) == 0 {
		return refuse("settings", "choose at least one setting to change")
	}
	if len(changes) > MaxChanges {
		return refuse("settings", "at most %d settings at a time", MaxChanges)
	}
	seen := map[string]bool{}
	for _, c := range changes {
		e, ok := entries[c.Name]
		if !ok {
			return refuse(c.Name, "Rowsafe only changes the settings it explains on this page")
		}
		if seen[c.Name] {
			return refuse(c.Name, "listed twice")
		}
		seen[c.Name] = true
		if e.LockedReason != "" {
			return refuse(c.Name, "%s", e.LockedReason)
		}
		s, ok := f.Settings[c.Name]
		if !ok {
			return refuse(c.Name, "this server doesn't report this setting")
		}
		if c.Reset {
			continue
		}
		v, ok := EngineValue(engine, s, c.Value)
		if !ok {
			return refuse(c.Name, "%q isn't a valid value here", c.Value)
		}
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			if lo, err := strconv.ParseFloat(s.MinVal, 64); err == nil && s.MinVal != "" && n < lo {
				return refuse(c.Name, "at least %s", displayEntry(e, s.MinVal, s.Unit, s.VarType))
			}
			if hi, err := strconv.ParseFloat(s.MaxVal, 64); err == nil && s.MaxVal != "" && n > hi {
				return refuse(c.Name, "at most %s", displayEntry(e, s.MaxVal, s.Unit, s.VarType))
			}
		}
		if r := check(c.Name, v, s); r != nil {
			return r
		}
	}
	return nil
}

func validateClickHouse(changes []protocol.SettingChange, f Facts) error {
	mem := f.Host.MemoryBytes
	return validateCatalog(protocol.EngineClickHouse, clickhouseEntries, changes, f, func(name, v string, s protocol.PGSetting) *Refusal {
		n, _ := strconv.ParseFloat(v, 64)
		switch name {
		case "max_server_memory_usage_to_ram_ratio":
			if n < 0.1 || n > 0.95 {
				return refuse(name, "between 0.1 and 0.95: above that the operating system may run out of memory")
			}
		case "max_memory_usage", "max_bytes_before_external_group_by", "max_bytes_before_external_sort", "mark_cache_size", "uncompressed_cache_size":
			if mem > 0 && n > float64(mem)*0.9 {
				return refuse(name, "%s is more than this server's memory can spare", HumanBytes(int64(n)))
			}
		case "max_concurrent_queries", "max_connections":
			if n < 0 || n > 100000 || (name == "max_connections" && n < 10) {
				return refuse(name, "between %d and 100000", map[bool]int{true: 10, false: 0}[name == "max_connections"])
			}
		case "max_threads", "background_pool_size":
			if n < 0 || n > 1024 || (name == "background_pool_size" && n < 1) {
				return refuse(name, "between 1 and 1024")
			}
		case "max_execution_time":
			if n < 0 || n > 7*86400 {
				return refuse(name, "at most a week (604800 seconds)")
			}
		}
		return nil
	})
}

func validateMongo(changes []protocol.SettingChange, f Facts) error {
	mem := f.Host.MemoryBytes
	return validateCatalog(protocol.EngineMongoDB, mongoEntries, changes, f, func(name, v string, s protocol.PGSetting) *Refusal {
		n, _ := strconv.ParseFloat(v, 64)
		switch name {
		case "wiredtiger_cache_size":
			if n < 256*float64(mib) {
				return refuse(name, "at least 256 MB")
			}
			if mem > 0 && n > float64(mem)*0.8 {
				return refuse(name, "%s is more than 80%% of this server's %s: MongoDB also needs memory outside its cache", HumanBytes(int64(n)), HumanBytes(mem))
			}
		case "max_incoming_connections":
			if n < 10 || n > 1000000 {
				return refuse(name, "between 10 and 1000000")
			}
		case "transaction_lifetime_limit_seconds":
			if n < 1 || n > 86400 {
				return refuse(name, "between 1 second and a day")
			}
		case "slow_op_threshold_ms":
			if n < 1 || n > 3600000 {
				return refuse(name, "between 1 ms and an hour")
			}
		case "profiling_mode":
			if v != "off" && v != "slowOp" {
				return refuse(name, "off or slowOp: recording every operation slows the server down")
			}
		}
		return nil
	})
}

type engineRec struct {
	entries map[string]Entry
	in      Input
	out     []protocol.SettingRecommendation
}

func (r *engineRec) get(name string) (protocol.PGSetting, bool) {
	s, ok := r.in.Settings[name]
	return s, ok
}

func (r *engineRec) add(s protocol.PGSetting, value, display, why string, optional bool) {
	e := r.entries[s.Name]
	r.out = append(r.out, protocol.SettingRecommendation{Name: s.Name, Title: e.Title, Current: displayEntry(e, s.Setting, s.Unit, s.VarType),
		Value: value, Display: display, Why: why, Restart: s.Context == "postmaster", Optional: optional})
}

// recommendClickHouse: a memory limit per query (half of the server's), so
// one runaway query can't fail every other; for analytics, GROUP BY and
// ORDER BY spill to disk past half of that instead of failing.
func recommendClickHouse(in Input) []protocol.SettingRecommendation {
	r := &engineRec{entries: clickhouseEntries, in: in}
	mem := in.Host.MemoryBytes
	if mem <= 0 {
		return nil
	}
	perQuery := mem / 2 / gib * gib
	if perQuery < gib {
		perQuery = mem / 2 / (256 * mib) * (256 * mib)
	}
	if s, ok := r.get("max_memory_usage"); ok && (s.Setting == "0" || s.Setting == "") {
		r.add(s, strconv.FormatInt(perQuery, 10), HumanBytes(perQuery),
			fmt.Sprintf("Half of the server's %s: one runaway query fails on its own instead of taking the memory every other query needs.", HumanBytes(mem)), false)
	}
	if in.Workload == protocol.WorkloadAnalytics {
		for _, name := range []string{"max_bytes_before_external_group_by", "max_bytes_before_external_sort"} {
			if s, ok := r.get(name); ok && (s.Setting == "0" || s.Setting == "") {
				r.add(s, strconv.FormatInt(perQuery/2, 10), HumanBytes(perQuery/2),
					"Big reports group and sort a lot: past this they continue on disk instead of failing.", false)
			}
		}
	}
	if in.Workload == protocol.WorkloadWeb {
		if s, ok := r.get("max_execution_time"); ok && (s.Setting == "0" || s.Setting == "") {
			r.add(s, "60", "1 min", "A web app's queries take seconds at most: a limit stops forgotten ones.", true)
		}
	}
	return r.out
}

// recommendMongo: WiredTiger's default cache (half of memory minus 1 GB)
// suits a server that mostly runs MongoDB; Rowsafe only proposes it back
// when a configured size is far from it.
func recommendMongo(in Input) []protocol.SettingRecommendation {
	r := &engineRec{entries: mongoEntries, in: in}
	mem := in.Host.MemoryBytes
	s, ok := r.get("wiredtiger_cache_size")
	if mem <= 0 || !ok {
		return nil
	}
	target := max(256*mib, (mem-gib)/2/(256*mib)*(256*mib))
	if cur, ok := Bytes(s.Setting, s.Unit); ok && (float64(cur) < 0.6*float64(target) || float64(cur) > 1.4*float64(target)) {
		why := fmt.Sprintf("Half of the server's %s minus 1 GB, MongoDB's own rule for a server that mostly runs it.", HumanBytes(mem))
		if cur > target {
			why = fmt.Sprintf("%s leaves too little of the server's %s for connections, queries and the operating system's file cache.", HumanBytes(cur), HumanBytes(mem))
		}
		r.add(s, strconv.FormatInt(target, 10), HumanBytes(target), why, false)
	}
	return r.out
}
