package redis

import (
	"cmp"
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The recommendations' facts (protocol.RedisAdvisorFacts), about every 30
// minutes: a slow-paced sample of the keys on a connection of its own, in
// the background so monitoring goes on meanwhile. Key names stay here:
// only patterns (keypattern.go) and counts are reported.

const (
	insightsEvery   = 30 * time.Minute
	sampleBatch     = 100 // SCAN COUNT, and keys looked at per round trip
	samplePause     = 20 * time.Millisecond
	sampleDBTime    = 90 * time.Second // per logical database
	sampleTotalTime = 5 * time.Minute
	sampleMaxDBs    = 64 // logical databases sampled (the busiest first)
)

// advisorState runs the sample in the background; the next monitoring
// report carries its result.
type advisorState struct {
	mu      sync.Mutex
	at      time.Time
	running bool
	result  *protocol.Insights
}

// advisorInsights returns a finished sample (once), and starts the next
// one when due.
func (e *Engine) advisorInsights(env agent.EngineEnv, db protocol.DatabaseSpec, a *advisorState) *protocol.Insights {
	a.mu.Lock()
	defer a.mu.Unlock()
	if r := a.result; r != nil {
		a.result = nil
		return r
	}
	if a.running || time.Since(a.at) < insightsEvery {
		return nil
	}
	a.running, a.at = true, time.Now()
	go func() {
		ctx, cancel := context.WithTimeout(e.baseCtx(), sampleTotalTime+time.Minute)
		defer cancel()
		ins := e.collectInsights(ctx, env, db)
		a.mu.Lock()
		a.result, a.running = ins, false
		a.mu.Unlock()
	}()
	return nil
}

// collectInsights connects and looks; nil when it can't (tried again in 30
// minutes).
func (e *Engine) collectInsights(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) *protocol.Insights {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil
	}
	defer c.Close()
	ins, err := insightsOf(ctx, c)
	if err != nil {
		env.Log.Debug("redis insights", "database", db.ID, "err", firstLine(err.Error()))
		return nil
	}
	return ins
}

// insightsOf collects the facts over c (which it may SELECT other logical
// databases on).
func insightsOf(ctx context.Context, c *conn) (*protocol.Insights, error) {
	start := time.Now()
	info, err := c.info(ctx, "all")
	if err != nil {
		return nil, err
	}
	in := infoFrom(info)
	if in.Loading {
		return nil, errLoading
	}
	f := &protocol.RedisAdvisorFacts{Version: in.Version, Role: info["role"], UptimeSeconds: info.int("uptime_in_seconds"),
		UsedMemoryBytes: in.UsedMemory, DatasetBytes: in.UsedMemoryDataset, MaxMemoryBytes: in.MaxMemory,
		MaxMemoryPolicy: info["maxmemory_policy"], TotalSystemMemoryBytes: in.TotalSystemMemory,
		AppendOnly: info["aof_enabled"] == "1", Databases: 16,
		DBs: []protocol.RedisDBFacts{}, Patterns: []protocol.RedisKeyPattern{}, Commands: commandStats(info)}
	if f.Role == "slave" {
		f.Role = "replica"
	}
	if v, err := c.configGet(ctx, "save"); err == nil {
		f.Save = strings.TrimSpace(v)
	}
	if v, err := c.configGet(ctx, "appendfsync"); err == nil {
		f.AppendFsync = v
	}
	if v, err := c.configGet(ctx, "maxmemory-policy"); err == nil && v != "" {
		f.MaxMemoryPolicy = v
	}
	if v, err := c.configGet(ctx, "databases"); err == nil {
		if n, _ := strconv.Atoi(v); n > 0 {
			f.Databases = n
		}
	}
	f.SlowCommands = slowCommands(ctx, c)

	ins := &protocol.Insights{CollectedAt: start.UTC(), Databases: []protocol.InsightsDatabase{}, LargestTables: []protocol.TableSize{},
		LargestIndexes: []protocol.IndexSize{}, TableBloat: []protocol.TableBloat{}, IndexBloat: []protocol.IndexBloat{},
		UnusedIndexes: []protocol.UnusedIndex{}, DuplicateIndexes: []protocol.DuplicateIndex{}, SeqScanTables: []protocol.SeqScanTable{},
		VacuumStats: []protocol.TableVacuum{}, FreezeAge: []protocol.TableFreeze{},
		Advisor: &protocol.AdvisorFacts{ForeignKeys: []protocol.ForeignKeyWithoutIndex{}, NoPrimaryKey: []protocol.TableWithoutPK{},
			IntegerKeys: []protocol.IntegerKey{}, SequencesBehind: []protocol.SequenceBehind{}, InvalidIndexes: []protocol.InvalidIndex{},
			DuplicateConstraints: []protocol.DuplicateConstraint{}, TimestampColumns: []protocol.TimestampTable{},
			LargeTables: []protocol.LargeTable{}, Redis: f}}

	// The logical databases with keys, the biggest first.
	idx := make([]int, 0, len(in.Keyspace))
	for i, k := range in.Keyspace {
		if k.Keys > 0 {
			idx = append(idx, i)
		}
	}
	slices.SortFunc(idx, func(a, b int) int { return cmp.Or(cmpInt(in.Keyspace[b].Keys, in.Keyspace[a].Keys), a-b) })
	deadline := start.Add(sampleTotalTime)
	for n, i := range idx {
		k := in.Keyspace[i]
		d := protocol.RedisDBFacts{DB: i, Keys: k.Keys, Expires: k.Expires}
		ins.Databases = append(ins.Databases, protocol.InsightsDatabase{Name: "db" + strconv.Itoa(i), Tables: int(min(k.Keys, 1<<31-1))})
		if n >= sampleMaxDBs || time.Now().After(deadline) {
			f.Partial = true
			ins.Databases[len(ins.Databases)-1].Skipped = "not sampled this time (time limit)"
			f.DBs = append(f.DBs, d)
			continue
		}
		until := time.Now().Add(sampleDBTime)
		if until.After(deadline) {
			until = deadline
		}
		tree, complete, err := sampleDB(ctx, c, i, until)
		if err != nil {
			return nil, err
		}
		if !complete && tree.sampled < min(k.Keys, protocol.RedisSampleKeysPerDB) {
			f.Partial = true
		}
		pats, other := tree.patterns()
		scale := 1.0
		if tree.sampled > 0 && k.Keys > tree.sampled {
			scale = float64(k.Keys) / float64(tree.sampled)
		}
		d.SampledKeys, d.OtherKeys, d.OtherBytes = tree.sampled, other.keys, other.bytes
		d.BigKeys, d.BiggestKeyBytes = other.big, other.max
		for _, p := range pats {
			d.SampledBytes += p.bytes
			d.BigKeys += p.big
			d.BiggestKeyBytes = max(d.BiggestKeyBytes, p.max)
			f.Patterns = append(f.Patterns, protocol.RedisKeyPattern{DB: i, Pattern: p.pattern, Type: p.mainType(),
				SampledKeys: p.keys, SampledBytes: p.bytes, EstimatedKeys: int64(float64(p.keys) * scale),
				EstimatedBytes: int64(float64(p.bytes) * scale), MaxKeyBytes: p.max, BigKeys: p.big, NoTTL: p.noTTL})
		}
		d.SampledBytes += other.bytes
		f.DBs = append(f.DBs, d)
	}
	if len(idx) > 0 {
		_, _ = c.do(ctx, "SELECT", 0)
	}
	slices.SortStableFunc(f.Patterns, func(a, b protocol.RedisKeyPattern) int { return cmpInt(b.EstimatedBytes, a.EstimatedBytes) })
	f.Patterns = f.Patterns[:min(len(f.Patterns), protocol.RedisMaxPatterns)]
	slices.SortFunc(f.DBs, func(a, b protocol.RedisDBFacts) int { return a.DB - b.DB })
	f.SampleMs = time.Since(start).Milliseconds()
	ins.Truncated = f.Partial
	if f.Partial {
		ins.Notes = append(ins.Notes, "Some logical databases were sampled only in part this time (time limit); the figures come from fewer keys.")
	}
	ins.DurationMs = f.SampleMs
	return ins, nil
}

var errLoading = respError("LOADING the server is loading its data")

// sampleDB looks at up to RedisSampleKeysPerDB keys of logical database
// db, in batches, pausing between them for at least four times as long as
// a batch took (so Rowsafe takes a small share of the server's time, and
// less when it is busy). complete: SCAN went through every key.
func sampleDB(ctx context.Context, c *conn, db int, until time.Time) (*keyTree, bool, error) {
	tree := newKeyTree()
	if _, err := c.do(ctx, "SELECT", db); err != nil {
		return tree, false, err
	}
	seen := map[string]bool{} // SCAN may return a key twice
	cursor := "0"
	for {
		if tree.sampled >= protocol.RedisSampleKeysPerDB || time.Now().After(until) {
			return tree, false, nil
		}
		t0 := time.Now()
		v, err := c.do(ctx, "SCAN", cursor, "COUNT", sampleBatch)
		if err != nil {
			return tree, false, err
		}
		r := asArray(v)
		if len(r) != 2 {
			return tree, false, respError("ERR unexpected SCAN reply")
		}
		cursor = asString(r[0])
		var keys []string
		for _, k := range asArray(r[1]) {
			name := asString(k)
			if !seen[name] && int64(len(keys))+tree.sampled < protocol.RedisSampleKeysPerDB {
				seen[name] = true
				keys = append(keys, name)
			}
		}
		if len(keys) > 0 {
			// TYPE, PTTL and MEMORY USAGE don't touch a key's last use (the
			// eviction order stays as it was).
			cmds := make([][]any, 0, 3*len(keys))
			for _, k := range keys {
				cmds = append(cmds, []any{"TYPE", k}, []any{"PTTL", k}, []any{"MEMORY", "USAGE", k, "SAMPLES", 5})
			}
			replies, errs, err := c.pipeline(ctx, cmds)
			if err != nil {
				return tree, false, err
			}
			for j, k := range keys {
				if errs[3*j] != nil || errs[3*j+2] != nil {
					continue
				}
				typ := asString(replies[3*j])
				if typ == "none" || typ == "" {
					continue // deleted or expired meanwhile
				}
				tree.add(k, asInt(replies[3*j+2]), typ, errs[3*j+1] == nil && asInt(replies[3*j+1]) == -1)
			}
		}
		if cursor == "0" {
			return tree, true, nil
		}
		pause := max(samplePause, 4*time.Since(t0))
		select {
		case <-ctx.Done():
			return tree, false, ctx.Err()
		case <-time.After(pause):
		}
	}
}

// commandStats reads INFO commandstats: the 30 commands that took the most
// time, plus the heavy ones used (names only).
func commandStats(info infoMap) []protocol.RedisCommandStat {
	out := []protocol.RedisCommandStat{}
	for k, v := range info {
		name, ok := strings.CutPrefix(k, "cmdstat_")
		if !ok {
			continue
		}
		f := fields(v)
		calls, _ := strconv.ParseInt(f["calls"], 10, 64)
		usec, _ := strconv.ParseInt(f["usec"], 10, 64)
		per, _ := strconv.ParseFloat(f["usec_per_call"], 64)
		if calls <= 0 {
			continue
		}
		out = append(out, protocol.RedisCommandStat{Name: strings.ToLower(name), Calls: calls, Usec: usec, UsecPerCall: per})
	}
	slices.SortFunc(out, func(a, b protocol.RedisCommandStat) int {
		return cmp.Or(cmpInt(b.Usec, a.Usec), strings.Compare(a.Name, b.Name))
	})
	var keep []protocol.RedisCommandStat
	for i, s := range out {
		if i < 30 || slices.Contains(protocol.RedisHeavyCommands, s.Name) {
			keep = append(keep, s)
		}
	}
	if keep == nil {
		keep = []protocol.RedisCommandStat{}
	}
	return keep
}

// slowCommands counts the slow log's entries by command name (never the
// arguments: they hold keys and values).
func slowCommands(ctx context.Context, c *conn) []protocol.RedisSlowCommand {
	v, err := c.do(ctx, "SLOWLOG", "GET", 128)
	if err != nil {
		return nil
	}
	by := map[string]*protocol.RedisSlowCommand{}
	for _, ent := range asArray(v) {
		f := asArray(ent)
		if len(f) < 4 {
			continue
		}
		args := asArray(f[3])
		if len(args) == 0 {
			continue
		}
		name := strings.ToLower(asString(args[0]))
		if len(name) > 64 {
			continue
		}
		s := by[name]
		if s == nil {
			s = &protocol.RedisSlowCommand{Name: name}
			by[name] = s
		}
		s.Count++
		s.MaxMicros = max(s.MaxMicros, asInt(f[2]))
	}
	out := make([]protocol.RedisSlowCommand, 0, len(by))
	for _, s := range by {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b protocol.RedisSlowCommand) int {
		return cmp.Or(b.Count-a.Count, strings.Compare(a.Name, b.Name))
	})
	return out[:min(len(out), 20)]
}
