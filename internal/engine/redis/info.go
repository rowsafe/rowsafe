package redis

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// serverInfo is what Rowsafe reads about a server (INFO and a few settings).
type serverInfo struct {
	Engine     string // protocol.EngineRedis or EngineValkey, as the server says
	Version    string
	VersionNum int // major*10000 + minor*100 + patch
	Role       string
	Cluster    bool
	Port       int
	ConfigFile string
	Executable string
	RunID      string
	// Keyspace: keys and keys with an expiry per logical database.
	Keyspace  map[int]dbKeys
	Databases int // the databases setting (16 by default)
	// Memory.
	UsedMemory        int64
	UsedMemoryDataset int64
	MaxMemory         int64
	MaxMemoryPolicy   string
	TotalSystemMemory int64
	// Replication.
	ReplID             string
	ReplOffset         int64
	MinReplicasToWrite int
	BacklogSize        int64
	// Persistence and files.
	Dir        string
	DBFilename string
	ACLFile    string
	Loading    bool
	// Modules are the modules it loaded (path and arguments).
	Modules [][]string
}

type dbKeys struct {
	Keys    int64 `json:"keys"`
	Expires int64 `json:"expires"`
}

// minVersion is the oldest Redis Rowsafe supports (Valkey: 7.2, its first).
const (
	minRedis  = 70000
	minValkey = 70200
)

// versionNum parses "7.2.4" (and "8.1", "255.255.255" for unstable builds).
func versionNum(v string) int {
	parts := strings.SplitN(v, ".", 4)
	n := 0
	for i, mul := range []int{10000, 100, 1} {
		if i >= len(parts) {
			break
		}
		x, err := strconv.Atoi(strings.TrimFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' }))
		if err != nil {
			break
		}
		n += min(x, 99) * mul
	}
	return n
}

// majorMinor is "7.2" for 70204.
func majorMinor(n int) string { return fmt.Sprintf("%d.%d", n/10000, n/100%100) }

// engineOf says which engine an INFO server section describes.
func engineOf(m infoMap) (engine, version string) {
	if strings.EqualFold(m["server_name"], "valkey") || m["valkey_version"] != "" {
		return protocol.EngineValkey, cmpOr(m["valkey_version"], m["redis_version"])
	}
	return protocol.EngineRedis, m["redis_version"]
}

// inspect reads the server.
func inspect(ctx context.Context, c *conn) (serverInfo, error) {
	m, err := c.info(ctx, "server", "memory", "replication", "persistence", "keyspace", "cluster")
	if err != nil {
		return serverInfo{}, err
	}
	in := infoFrom(m)
	// Settings (Rowsafe's user may read them; older logins may not).
	for name, set := range map[string]func(string){
		"databases":             func(v string) { in.Databases, _ = strconv.Atoi(v) },
		"maxmemory-policy":      func(v string) { in.MaxMemoryPolicy = v },
		"min-replicas-to-write": func(v string) { in.MinReplicasToWrite, _ = strconv.Atoi(v) },
		"repl-backlog-size":     func(v string) { in.BacklogSize, _ = strconv.ParseInt(v, 10, 64) },
		"dir":                   func(v string) { in.Dir = v },
		"dbfilename":            func(v string) { in.DBFilename = v },
		"aclfile":               func(v string) { in.ACLFile = v },
	} {
		if v, err := c.configGet(ctx, name); err == nil && v != "" {
			set(v)
		}
	}
	if in.Databases == 0 {
		in.Databases = 16
	}
	in.Modules = productionModules(ctx, c)
	return in, nil
}

// infoFrom fills what INFO alone says.
func infoFrom(m infoMap) serverInfo {
	in := serverInfo{Keyspace: map[int]dbKeys{}}
	in.Engine, in.Version = engineOf(m)
	in.VersionNum = versionNum(in.Version)
	in.Role = m["role"]
	in.Cluster = m["cluster_enabled"] == "1"
	in.Port = int(m.int("tcp_port"))
	in.ConfigFile = m["config_file"]
	in.Executable = m["executable"]
	in.RunID = m["run_id"]
	in.UsedMemory = m.int("used_memory")
	in.UsedMemoryDataset = m.int("used_memory_dataset")
	in.MaxMemory = m.int("maxmemory")
	in.TotalSystemMemory = m.int("total_system_memory")
	in.ReplID = m["master_replid"]
	in.ReplOffset = m.int("master_repl_offset")
	in.Loading = m["loading"] == "1"
	if in.MaxMemoryPolicy == "" {
		in.MaxMemoryPolicy = m["maxmemory_policy"]
	}
	for k, v := range m {
		if n, ok := strings.CutPrefix(k, "db"); ok {
			idx, err := strconv.Atoi(n)
			if err != nil {
				continue
			}
			f := fields(v)
			keys, _ := strconv.ParseInt(f["keys"], 10, 64)
			exp, _ := strconv.ParseInt(f["expires"], 10, 64)
			in.Keyspace[idx] = dbKeys{Keys: keys, Expires: exp}
		}
	}
	return in
}

// totalKeys is the number of keys in every logical database.
func (in serverInfo) totalKeys() int64 {
	var n int64
	for _, k := range in.Keyspace {
		n += k.Keys
	}
	return n
}

// dbInfos lists the logical databases that hold keys ("db0", ...), with
// their keys in Tables; sizes are shared out by keys (Redis has no size per
// logical database).
func (in serverInfo) dbInfos() []protocol.DBInfo {
	idx := make([]int, 0, len(in.Keyspace))
	for i := range in.Keyspace {
		idx = append(idx, i)
	}
	slices.Sort(idx)
	total := in.totalKeys()
	out := []protocol.DBInfo{}
	for _, i := range idx {
		k := in.Keyspace[i]
		d := protocol.DBInfo{Name: "db" + strconv.Itoa(i), Tables: int(min(k.Keys, 1<<31-1))}
		if total > 0 {
			d.SizeBytes = int64(float64(in.UsedMemoryDataset) * float64(k.Keys) / float64(total))
		}
		out = append(out, d)
	}
	return out
}

// isReplica: the server follows another one.
func (in serverInfo) isReplica() bool { return in.Role == "slave" || in.Role == "replica" }

// inspectResult is the PostgreSQL-shaped report the control plane stores.
func (in serverInfo) inspectResult(engine string, port int, archiveMode string) protocol.InspectResult {
	return protocol.InspectResult{
		Engine: engine, ServerVersion: in.Version, VersionNum: in.VersionNum,
		DataDirectory: in.Dir, ConfigFile: in.ConfigFile, Port: port, InRecovery: in.isReplica(),
		ArchiveMode: archiveMode, Databases: in.dbInfos(), TotalSizeBytes: in.UsedMemoryDataset,
	}
}

// supported says why a server can't be protected ("" when it can).
func (in serverInfo) supported(engine string) string {
	name := protocol.EngineDisplayName(engine)
	switch {
	case in.Engine != engine:
		return fmt.Sprintf("this server is %s, not %s: add it to Rowsafe as a %s database", protocol.EngineDisplayName(in.Engine), name, protocol.EngineDisplayName(in.Engine))
	case in.Cluster:
		return name + " runs in cluster mode (Redis Cluster), which Rowsafe doesn't protect yet: only standalone servers, with or without replicas"
	case engine == protocol.EngineValkey && in.VersionNum < minValkey:
		return fmt.Sprintf("Valkey %s is too old: Rowsafe needs Valkey 7.2 or newer", in.Version)
	case engine == protocol.EngineRedis && in.VersionNum < minRedis:
		return fmt.Sprintf("Redis %s is too old: Rowsafe needs Redis 7.0 or newer (Redis's own packages at packages.redis.io have it for this system)", in.Version)
	}
	return ""
}
