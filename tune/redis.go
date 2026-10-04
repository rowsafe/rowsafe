package tune

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// Redis and Valkey settings (one catalog for both). Every setting here
// changes on the running server (CONFIG SET); the agent then keeps it in
// the server's configuration file where it can (protocol/redis_settings.go).
// Settings Rowsafe's link depends on are listed locked; passwords, the
// port, the address and the data folder are not listed at all (the
// security page covers passwords; requirepass is never read).

// RedisSaveOff is how the "save" setting reads when snapshots on the
// server's disk are off (it is `save ""` in the configuration file).
const RedisSaveOff = `""`

// RedisSaveDefault are Redis's own snapshot rules.
const RedisSaveDefault = "3600 1 300 100 60 10000"

// RedisSetting describes how a catalog setting reads: its unit, type,
// words and Redis's default.
type RedisSetting struct {
	Unit, VarType string
	Enums         []string
	Default       string
}

// RedisSettings are the catalog's settings as the agent reports them.
var RedisSettings = map[string]RedisSetting{
	"maxmemory":                 {Unit: "B", VarType: "integer", Default: "0"},
	"maxmemory-policy":          {VarType: "enum", Enums: redisPolicies, Default: "noeviction"},
	"activedefrag":              {VarType: "bool", Default: "no"},
	"save":                      {VarType: "string", Default: RedisSaveDefault},
	"appendonly":                {VarType: "bool", Default: "no"},
	"appendfsync":               {VarType: "enum", Enums: []string{"always", "everysec", "no"}, Default: "everysec"},
	"maxclients":                {VarType: "integer", Default: "10000"},
	"timeout":                   {Unit: "s", VarType: "integer", Default: "0"},
	"tcp-keepalive":             {Unit: "s", VarType: "integer", Default: "300"},
	"slowlog-log-slower-than":   {Unit: "us", VarType: "integer", Default: "10000"},
	"slowlog-max-len":           {VarType: "integer", Default: "128"},
	"latency-monitor-threshold": {Unit: "ms", VarType: "integer", Default: "0"},
	"latency-tracking":          {VarType: "bool", Default: "yes"},
	"repl-backlog-size":         {Unit: "B", VarType: "integer", Default: "1048576"},
	"min-replicas-to-write":     {VarType: "integer", Default: "0"},
}

var redisPolicies = []string{"noeviction", "allkeys-lru", "allkeys-lfu", "allkeys-random", "volatile-lru", "volatile-lfu", "volatile-random", "volatile-ttl"}

var redisCatalog = []Entry{
	{Name: "maxmemory", Category: protocol.SettingsCatMemory, Title: "Memory limit", Off: "0",
		Explanation: "The most memory the server may use for data. When it is reached, the server makes room as the policy below says, or refuses writes. Off (0) means no limit: the server grows until the operating system runs out of memory and stops it."},
	{Name: "maxmemory-policy", Category: protocol.SettingsCatMemory, Title: "When the memory limit is reached",
		Explanation: "noeviction refuses writes, so no key is ever lost: right for a store or a queue. allkeys-lru or allkeys-lfu remove the keys used least: right for a cache. The volatile-* policies remove only keys with an expiry."},
	{Name: "activedefrag", Category: protocol.SettingsCatMemory, Title: "Defragment memory",
		Explanation: "Compacts memory in the background, at a small CPU cost, when fragmentation wastes a lot of it. Needs the jemalloc allocator, the usual one."},

	{Name: "save", Category: protocol.SettingsCatWAL, Title: "Snapshots on the server's disk", Off: RedisSaveOff,
		Explanation: "When the server writes a snapshot of its data to its own disk, as pairs of seconds and changes (\"300 100\": after 5 minutes if 100 keys changed). It is how the server gets its data back after a restart. Rowsafe's backups don't depend on it."},
	{Name: "appendonly", Category: protocol.SettingsCatWAL, Title: "Append-only file",
		Explanation: "Also writes every change to a log on the server's disk, so a restart loses at most a second of changes. It costs disk writes. Rowsafe's backups already keep every change, so restores to any second don't need it."},
	{Name: "appendfsync", Category: protocol.SettingsCatWAL, Title: "Append-only file flushed",
		Explanation: "everysec (the usual) flushes the append-only file to disk every second; always after every write (much slower); no leaves it to the operating system."},
	{Name: "repl-backlog-size", Category: protocol.SettingsCatWAL, Title: "Replication backlog",
		LockedReason: "Rowsafe's link to the server depends on it. When the link has to start over too often, Pulse proposes a larger one (Apply fix)."},
	{Name: "min-replicas-to-write", Category: protocol.SettingsCatWAL, Title: "Replicas needed for writes",
		LockedReason: "Rowsafe's link counts as a replica, so this decides whether Rowsafe can follow every change. Change it on the server if you must."},

	{Name: "maxclients", Category: protocol.SettingsCatConnections, Title: "Maximum connections",
		Explanation: "How many client connections the server accepts at once. The operating system's limit on open files may lower it."},
	{Name: "timeout", Category: protocol.SettingsCatConnections, Title: "Close idle connections after", Off: "0",
		Explanation: "Closes client connections idle this long. Off (0) is the usual: connection pools keep idle connections open on purpose."},
	{Name: "tcp-keepalive", Category: protocol.SettingsCatConnections, Title: "Check idle connections every", Off: "0",
		Explanation: "Checks idle connections are still there, so connections to clients that vanished (a crashed app server, a dropped network) are closed. 300 seconds is the default."},

	{Name: "slowlog-log-slower-than", Category: protocol.SettingsCatLogging, Title: "Slow command threshold", Off: "-1",
		Explanation: "Commands slower than this are recorded in the slow log, which Pulse reads. 10 ms is the default; 0 would record every command."},
	{Name: "slowlog-max-len", Category: protocol.SettingsCatLogging, Title: "Slow log length",
		Explanation: "How many slow commands the slow log keeps. Older ones are dropped."},
	{Name: "latency-monitor-threshold", Category: protocol.SettingsCatLogging, Title: "Latency monitor threshold", Off: "0",
		Explanation: "Records events (snapshots starting, slow commands, waits for the disk) that take longer than this, which Pulse shows. Off by default; 100 ms is a good start."},
	{Name: "latency-tracking", Category: protocol.SettingsCatStatistics, Title: "Latency per command",
		Explanation: "Keeps latency statistics per command (INFO latencystats). On by default; the cost is small."},
}

var redisCategories = []struct{ ID, Title string }{
	{protocol.SettingsCatMemory, "Memory"},
	{protocol.SettingsCatWAL, "Persistence on the server's disk"},
	{protocol.SettingsCatConnections, "Connections"},
	{protocol.SettingsCatLogging, "Slow log and latency"},
	{protocol.SettingsCatStatistics, "Statistics"},
	{protocol.SettingsCatOther, "Other settings"},
}

var (
	redisTuner   = newTuner(protocol.EngineRedis, redisCatalog, redisCategories, recommendRedis, validateRedis)
	redisEntries = entriesOf(redisCatalog)
)

var (
	redisSizeRE = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)\s*([kmgt]?)(b?)$`)
	redisSaveRE = regexp.MustCompile(`^[0-9]{1,9} [0-9]{1,9}( [0-9]{1,9} [0-9]{1,9}){0,7}$`)
)

// RedisBytes parses a size as Redis reads it: a number of bytes, or with a
// unit where k, m, g are powers of 1000 and kb, mb, gb powers of 1024
// (case-insensitive).
func RedisBytes(v string) (int64, bool) {
	m := redisSizeRE.FindStringSubmatch(strings.ToLower(strings.TrimSpace(v)))
	if m == nil {
		return 0, false
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	if m[2] == "" && m[3] != "" { // "100b"
		m[3] = ""
	}
	base := 1000.0
	if m[3] == "b" {
		base = 1024
	}
	mult := math.Pow(base, float64(strings.Index(" kmgt", cmpOrString(m[2], " "))))
	n := f * mult
	if n != math.Trunc(n) || n > math.MaxInt64/2 {
		return 0, false
	}
	return int64(n), true
}

func cmpOrString(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// RedisValue turns a value as a person wrote it into what CONFIG SET and
// the configuration file take: sizes in bytes, times as whole numbers in
// the setting's unit, switches as yes/no, the save rules normalized
// (RedisSaveOff when off). "off" is the setting's off value.
func RedisValue(s protocol.PGSetting, value string) (string, bool) {
	v := strings.TrimSpace(value)
	if s.Name == "save" {
		switch strings.ToLower(v) {
		case "", `""`, "''", "off", "none":
			return RedisSaveOff, true
		}
		v = strings.Join(strings.Fields(v), " ")
		if !redisSaveRE.MatchString(v) {
			return "", false
		}
		return v, true
	}
	v = strings.Trim(v, `'"`)
	if e, ok := redisEntries[s.Name]; ok && e.Off != "" && strings.EqualFold(v, "off") && s.VarType != "bool" {
		return e.Off, true
	}
	switch {
	case s.VarType == "bool":
		switch strings.ToLower(v) {
		case "on", "true", "1", "yes":
			return "yes", true
		case "off", "false", "0", "no":
			return "no", true
		}
		return "", false
	case IsMemoryUnit(s.Unit):
		b, ok := RedisBytes(v)
		if !ok {
			// "4GB", "512 MB" as PostgreSQL writes them.
			if q, ok2 := Bytes(strings.Replace(v, "KB", "kB", 1), s.Unit); ok2 && q >= 0 {
				return strconv.FormatInt(q, 10), true
			}
			return "", false
		}
		return strconv.FormatInt(b, 10), true
	case IsTimeUnit(s.Unit):
		ms, ok := Quantity(v, s.Unit)
		if !ok {
			return "", false
		}
		unit, _ := Quantity("1", s.Unit)
		n := ms / unit
		if math.Abs(n-math.Round(n)) > 1e-6 {
			return "", false
		}
		return strconv.FormatInt(int64(math.Round(n)), 10), true
	case s.VarType == "integer" || s.VarType == "enum":
		return MySQLValue(s, v)
	}
	return "", false
}

func validateRedis(changes []protocol.SettingChange, f Facts) error {
	mem := f.Host.MemoryBytes
	return validateCatalog(protocol.EngineRedis, redisEntries, changes, f, func(name, v string, s protocol.PGSetting) *Refusal {
		n, _ := strconv.ParseInt(v, 10, 64)
		switch name {
		case "maxmemory":
			if n == 0 {
				return nil
			}
			if n < 64*mib {
				return refuse(name, "at least 64 MB, or off for no limit")
			}
			if mem > 0 && float64(n) > 0.9*float64(mem) {
				return refuse(name, "%s is more than 90%% of this server's %s: snapshots copy memory while they run, and the operating system needs some too", HumanBytes(n), HumanBytes(mem))
			}
			if f.Redis != nil && f.Redis.UsedMemoryBytes > 0 && n <= f.Redis.UsedMemoryBytes {
				return refuse(name, "the server already uses %s: a lower limit would at once remove keys or refuse writes", HumanBytes(f.Redis.UsedMemoryBytes))
			}
		case "maxclients":
			if n < 32 || n > 1000000 {
				return refuse(name, "between 32 and 1000000")
			}
		case "timeout":
			if n != 0 && (n < 10 || n > 7*86400) {
				return refuse(name, "off, or between 10 seconds and a week: shorter cuts connections apps keep open on purpose")
			}
		case "tcp-keepalive":
			if n < 0 || n > 86400 {
				return refuse(name, "off, or at most a day")
			}
		case "slowlog-log-slower-than":
			if n == 0 {
				return refuse(name, "0 would record every command and slow the server down: 10 ms (10000 µs) is the default")
			}
			if n < -1 || n > 60_000_000 {
				return refuse(name, "off, or at most a minute")
			}
		case "slowlog-max-len":
			if n < 0 || n > 100000 {
				return refuse(name, "at most 100000")
			}
		case "latency-monitor-threshold":
			if n != 0 && (n < 10 || n > 60000) {
				return refuse(name, "off, or between 10 ms and a minute: lower records events all the time")
			}
		}
		return nil
	})
}

// redisUse says what the server is for: "cache", "store", or "" when it
// isn't clear. The person's choice wins; "not sure" (mixed) looks at how
// many keys expire, and inferred is true then.
func redisUse(in Input) (use string, inferred bool) {
	switch in.Workload {
	case protocol.RedisWorkloadCache:
		return "cache", false
	case protocol.RedisWorkloadStore:
		return "store", false
	}
	if in.Redis == nil || in.Redis.Keys < 100 {
		return "", true
	}
	share := float64(in.Redis.ExpiringKeys) / float64(in.Redis.Keys)
	switch {
	case share >= 0.9:
		return "cache", true
	case share <= 0.1:
		return "store", true
	}
	return "", true
}

// recommendRedis: a memory limit when there is none (about 75% of the
// server's memory, shared with the other databases on it), the eviction
// policy that suits the use (a cache makes room; a store refuses writes
// rather than lose keys), snapshots on the server's own disk for a store
// that has none (a restart would empty it), and the monitoring Pulse reads
// (latency monitor, slow log, keepalives). Persistence is never turned
// off, and the append-only file is never proposed: Rowsafe's link already
// keeps every change.
func recommendRedis(in Input) []protocol.SettingRecommendation {
	r := &engineRec{entries: redisEntries, in: in}
	name := "the server"
	mem := in.Host.MemoryBytes
	var used int64
	if in.Redis != nil {
		used = in.Redis.UsedMemoryBytes
	}
	use, inferred := redisUse(in)

	if s, ok := r.get("maxmemory"); ok && mem > 0 {
		cur, _ := strconv.ParseInt(s.Setting, 10, 64)
		share := 0.75 / float64(1+max(0, in.OtherDatabases))
		target := int64(float64(mem)*share) / (64 * mib) * (64 * mib)
		roomy := target >= 64*mib && target > used+used/4
		why := fmt.Sprintf("about %d%% of the server's %s", int(math.Round(share*100)), HumanBytes(mem))
		if in.OtherDatabases > 0 {
			why += fmt.Sprintf(", as %d other database%s on this server need%s memory too", in.OtherDatabases, plural(in.OtherDatabases), map[bool]string{true: "s", false: ""}[in.OtherDatabases == 1])
		}
		switch {
		case cur == 0 && roomy:
			r.add(s, strconv.FormatInt(target, 10), HumanBytes(target),
				fmt.Sprintf("Without a limit, %s grows until the operating system runs out of memory and stops it. A limit of %s leaves room for the snapshots it takes (they copy memory that changes meanwhile) and for the operating system.", name, why), false)
		case cur > 0 && float64(cur) > 0.9*float64(mem) && roomy:
			r.add(s, strconv.FormatInt(target, 10), HumanBytes(target),
				fmt.Sprintf("%s leaves almost nothing of the server's %s for snapshots (they copy memory that changes meanwhile) and the operating system: %s is safer.", HumanBytes(cur), HumanBytes(mem), why), false)
		}
	}

	if s, ok := r.get("maxmemory-policy"); ok {
		switch {
		case use == "cache" && s.Setting == "noeviction":
			why := "A cache's keys can be computed again: when the memory limit is reached, removing the least recently used ones keeps writes working instead of refusing them."
			if inferred {
				why = fmt.Sprintf("Almost every key has an expiry, as in a cache. %s", why)
			}
			r.add(s, "allkeys-lru", "allkeys-lru", why, inferred)
		case use == "store" && !inferred && strings.HasPrefix(s.Setting, "allkeys-"):
			r.add(s, "noeviction", "noeviction",
				"In a store or a queue no key may disappear: when the memory limit is reached, refusing writes is safer than removing keys silently. Pulse warns well before it is reached.", false)
		}
	}

	if s, ok := r.get("save"); ok && use == "store" && s.Setting == RedisSaveOff {
		if aof, ok := r.get("appendonly"); ok && aof.Setting != "yes" {
			r.add(s, RedisSaveDefault, "after 1 hour (1 change), 5 min (100), 1 min (10000)",
				"Nothing is written to the server's own disk, so a restart empties it, and getting the data back would take a restore. Snapshots on its disk bring it back by itself.", inferred)
		}
	}

	if s, ok := r.get("tcp-keepalive"); ok && s.Setting == "0" {
		r.add(s, "300", "5 min", "Connections to clients that vanished (a crashed app server, a dropped network) stay open forever without it.", false)
	}
	if s, ok := r.get("latency-monitor-threshold"); ok && s.Setting == "0" {
		r.add(s, "100", "100 ms", "Records what makes the server slow (snapshots starting, slow commands, disk waits) so Pulse can show it. The cost is negligible.", false)
	}
	if s, ok := r.get("slowlog-log-slower-than"); ok && strings.HasPrefix(s.Setting, "-") {
		r.add(s, "10000", "10 ms", "The slow log is off, so Pulse can't show slow commands.", false)
	}
	return r.out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// RedisPGSetting is a catalog setting as the agent reports it, from its
// running value (CONFIG GET). Source is "default" when it has Redis's
// default value, else "set at runtime" (the agent corrects it when the
// configuration file says the same).
func RedisPGSetting(name, running string) protocol.PGSetting {
	d := RedisSettings[name]
	if name == "save" && strings.TrimSpace(running) == "" {
		running = RedisSaveOff
	}
	s := protocol.PGSetting{Name: name, Setting: running, Unit: d.Unit, VarType: d.VarType, BootVal: d.Default,
		Context: "sighup", Source: "set at runtime"}
	if len(d.Enums) > 0 {
		s.EnumVals = append([]string(nil), d.Enums...)
		if running != "" && !slices.Contains(s.EnumVals, running) {
			s.EnumVals = append(s.EnumVals, running)
		}
	}
	if RedisSame(s, d.Default) {
		s.Source = "default"
	}
	return s
}

// RedisSame reports whether a setting's running value equals value as a
// person or a configuration file writes it ("1gb" is 1073741824).
func RedisSame(s protocol.PGSetting, value string) bool {
	v, ok := RedisValue(s, value)
	if !ok {
		return false
	}
	if s.VarType == "bool" {
		return boolValue(s.Setting) == boolValue(v)
	}
	return strings.EqualFold(strings.Join(strings.Fields(s.Setting), " "), v)
}
