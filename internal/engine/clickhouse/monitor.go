package clickhouse

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for ClickHouse: system.metrics and system.events (queries, inserts,
// connections, merges, memory), data parts (too many parts in a partition
// slows, then refuses inserts), mutations that can't finish, replicas that
// went read-only or fell behind, broken parts, disk space, and the queries
// running for over a minute. Read-only and cheap; database sizes and the
// detailed status every 5 minutes.

const (
	sizesEvery       = 5 * time.Minute
	longQueryMinimum = 60 * time.Second
)

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	mu         sync.Mutex
	client     *client
	login      Login
	prev       map[string]float64
	prevAt     time.Time
	lastSizes  time.Time
	queryStart map[string]time.Time // query_id -> start, as first seen
}

func (e *Engine) monitorFor(id string) *dbMonitor {
	e.mon.mu.Lock()
	defer e.mon.mu.Unlock()
	if e.mon.dbs == nil {
		e.mon.dbs = map[string]*dbMonitor{}
	}
	m := e.mon.dbs[id]
	if m == nil {
		m = &dbMonitor{queryStart: map[string]time.Time{}}
		e.mon.dbs[id] = m
	}
	return m
}

// Monitor collects one sample of db.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: db.ID}
	m := e.monitorFor(db.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	l, ok, err := loadLogin(env, db.Port)
	switch {
	case err != nil:
		dm.Error = err.Error()
		return dm, nil
	case !ok:
		dm.Error = ErrNoLogin.Error()
		return dm, nil
	}
	if m.client == nil || m.login != l {
		m.client, m.login = newClient(serverURL(db.Port), l), l
	}
	if err := m.sample(ctx, dm); err != nil {
		dm.Error = "can't read ClickHouse's status: " + shortError(plainLoginError(err))
	}
	return dm, nil
}

type nameValue struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

func (m *dbMonitor) sample(ctx context.Context, dm *protocol.DatabaseMonitoring) error {
	c := m.client
	now := time.Now()
	metrics := map[string]float64{}
	cur, err := query[nameValue](ctx, c, `SELECT metric AS name, toFloat64(value) AS value FROM system.metrics
		WHERE metric IN ('Query', 'Merge', 'TCPConnection', 'HTTPConnection', 'MySQLConnection', 'PostgreSQLConnection',
			'InterserverConnection', 'DelayedInserts', 'ReadonlyReplica', 'MemoryTracking')`, nil)
	if err != nil {
		return err
	}
	cm := map[string]float64{}
	for _, v := range cur {
		cm[v.Name] = v.Value
	}
	conns := cm["TCPConnection"] + cm["HTTPConnection"] + cm["MySQLConnection"] + cm["PostgreSQLConnection"] + cm["InterserverConnection"]
	metrics[collect.MConnTotal] = conns
	metrics[collect.MCHRunningMerges] = cm["Merge"]
	metrics[collect.MCHDelayedInserts] = cm["DelayedInserts"]
	metrics[collect.MCHReadonlyReplicas] = cm["ReadonlyReplica"]
	metrics[collect.MCHMemoryBytes] = cm["MemoryTracking"]

	settings, _ := query[nameValue](ctx, c, `SELECT name, toFloat64OrZero(value) AS value FROM system.server_settings
		WHERE name IN ('max_connections', 'max_server_memory_usage')`, nil)
	var memLimit float64
	for _, s := range settings {
		switch s.Name {
		case "max_connections":
			if s.Value > 0 {
				metrics[collect.MConnMax] = s.Value
				metrics[collect.MConnUsedPct] = 100 * conns / s.Value
			}
		case "max_server_memory_usage":
			memLimit = s.Value
		}
	}
	if memLimit > 0 {
		metrics[collect.MCHMemoryUsedPct] = 100 * cm["MemoryTracking"] / memLimit
	}

	events, err := query[nameValue](ctx, c, `SELECT event AS name, toFloat64(value) AS value FROM system.events
		WHERE event IN ('Query', 'SelectQuery', 'InsertQuery', 'InsertedRows', 'FailedQuery', 'SelectedBytes', 'RejectedInserts')`, nil)
	if err != nil {
		return err
	}
	ev := map[string]float64{}
	for _, v := range events {
		ev[v.Name] = v.Value
	}
	counters := map[string]float64{
		collect.MCHQueriesRate:       ev["Query"],
		collect.MCHSelectRate:        ev["SelectQuery"],
		collect.MCHInsertRate:        ev["InsertQuery"],
		collect.MCHInsertedRowsRate:  ev["InsertedRows"],
		collect.MCHFailedQueriesRate: ev["FailedQuery"],
		collect.MCHReadBytesRate:     ev["SelectedBytes"],
		collect.MCHRejectedInserts:   ev["RejectedInserts"],
	}
	if m.prev != nil {
		secs := now.Sub(m.prevAt).Seconds()
		for k, v := range counters {
			if p, ok := m.prev[k]; ok && secs > 0 && v >= p {
				metrics[k] = (v - p) / secs
			}
		}
	}
	m.prev, m.prevAt = counters, now

	type partsRow struct {
		Active   float64 `json:"active"`
		MaxParts float64 `json:"max_parts"`
		Bytes    float64 `json:"bytes"`
	}
	if ps, err := query[partsRow](ctx, c, `SELECT toFloat64(sum(n)) AS active, toFloat64(max(n)) AS max_parts, toFloat64(sum(b)) AS bytes
		FROM (SELECT count() AS n, sum(bytes_on_disk) AS b FROM system.parts WHERE active GROUP BY database, table, partition_id)`, nil); err == nil && len(ps) == 1 {
		metrics[collect.MCHPartsActive] = ps[0].Active
		metrics[collect.MCHPartsMaxPerPart] = ps[0].MaxParts
		metrics[collect.MDatabaseSizeBytes] = ps[0].Bytes
	}
	type mutRow struct {
		Pending float64 `json:"pending"`
		Failed  float64 `json:"failed"`
	}
	if ms, err := query[mutRow](ctx, c, `SELECT toFloat64(count()) AS pending, toFloat64(countIf(latest_fail_reason != '')) AS failed
		FROM system.mutations WHERE NOT is_done`, nil); err == nil && len(ms) == 1 {
		metrics[collect.MCHMutationsPending] = ms[0].Pending
		metrics[collect.MCHMutationsFailed] = ms[0].Failed
	}
	if n, err := c.scalar(ctx, "SELECT count() FROM system.detached_parts WHERE startsWith(reason, 'broken')", nil); err == nil {
		metrics[collect.MCHBrokenParts] = parseFloat(n)
	}
	type replRow struct {
		Lag      float64 `json:"lag"`
		Replicas float64 `json:"replicas"`
	}
	if rs, err := query[replRow](ctx, c, `SELECT toFloat64(max(absolute_delay)) AS lag, toFloat64(count()) AS replicas FROM system.replicas`, nil); err == nil &&
		len(rs) == 1 && rs[0].Replicas > 0 {
		metrics[collect.MReplicationLagSeconds] = rs[0].Lag
	}
	type diskRow struct {
		Free  float64 `json:"free_space"`
		Total float64 `json:"total_space"`
	}
	if ds, err := query[diskRow](ctx, c, "SELECT toFloat64(free_space) AS free_space, toFloat64(total_space) AS total_space FROM system.disks WHERE name = 'default'", nil); err == nil &&
		len(ds) == 1 && ds[0].Total > 0 {
		metrics[collect.MDiskTotalBytes] = ds[0].Total
		metrics[collect.MDiskFreeBytes] = ds[0].Free
		metrics[collect.MDiskFreePct] = 100 * ds[0].Free / ds[0].Total
	}

	act, longest, running := runningQueries(ctx, c, m.login.User, queryTextOn(), m.queryStart)
	metrics[collect.MLongestQuerySeconds] = longest
	metrics[collect.MCHRunningQueries] = running
	dm.Activity = act

	if now.Sub(m.lastSizes) >= sizesEvery {
		type sizeRow struct {
			DB    string `json:"database"`
			Bytes int64  `json:"bytes"`
		}
		if ss, err := query[sizeRow](ctx, c, `SELECT database, toInt64(sum(bytes_on_disk)) AS bytes FROM system.parts
			WHERE active AND database NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA') GROUP BY database ORDER BY database`, nil); err == nil {
			for _, s := range ss {
				dm.Sizes = append(dm.Sizes, protocol.DatabaseSize{Name: s.DB, SizeBytes: s.Bytes})
			}
		}
		dm.ClickHouse = status(ctx, c, int64(memLimit), queryTextOn())
		m.lastSizes = now
	}
	dm.Metrics = metrics
	return nil
}

func parseFloat(s string) float64 {
	f, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return f
}

func queryTextOn() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ROWSAFE_COLLECT_QUERY_TEXT")))
	return v != "false" && v != "0" && v != "no" && v != "off"
}

var errorName = regexp.MustCompile(`\(([A-Z][A-Z0-9_]{2,})\)`)

// reasonWithoutText is a mutation's error when query text isn't collected:
// only ClickHouse's error name, never the message (it can quote values).
func reasonWithoutText(reason string) string {
	if strings.TrimSpace(reason) == "" {
		return ""
	}
	const hidden = "the details stay on the server: query text collection is off"
	// The name ends the message (values quoted in it come before).
	line, _, _ := strings.Cut(strings.TrimSpace(reason), "\n")
	if ms := errorName.FindAllStringSubmatch(line, -1); len(ms) > 0 {
		return ms[len(ms)-1][1] + " (" + hidden + ")"
	}
	return "It fails (" + hidden + ")"
}

// runningQueries lists the queries running for over a minute (Activity),
// the longest one's seconds and how many run. The agent's own (its user,
// its User-Agent: backups, checks, monitoring) are left out.
func runningQueries(ctx context.Context, c *client, agentUser string, withText bool, starts map[string]time.Time) (*protocol.Activity, float64, float64) {
	act := &protocol.Activity{CollectedAt: time.Now().UTC(), QueryTextCollected: withText, Queries: []protocol.ActivityQuery{}}
	type proc struct {
		QueryID string  `json:"query_id"`
		Elapsed float64 `json:"elapsed"`
		User    string  `json:"user"`
		DB      string  `json:"current_database"`
		Query   string  `json:"query"`
		Client  string  `json:"client_name"`
		Agent   string  `json:"http_user_agent"`
		Kind    string  `json:"query_kind"`
	}
	ps, err := query[proc](ctx, c, `SELECT query_id, elapsed, user, current_database, substring(query, 1, 500) AS query, client_name,
		http_user_agent, query_kind FROM system.processes
		WHERE is_initial_query AND http_user_agent != {agent:String} AND user != {user:String}`,
		map[string]string{"agent": userAgent, "user": agentUser})
	if err != nil {
		return act, 0, 0
	}
	seen := map[string]bool{}
	longest := 0.0
	for _, p := range ps {
		longest = max(longest, p.Elapsed)
		if p.Elapsed < longQueryMinimum.Seconds() {
			continue
		}
		q := protocol.ActivityQuery{QueryID: p.QueryID, DurationSeconds: p.Elapsed, State: "active", Database: p.DB, User: p.User,
			ApplicationName: p.Client}
		if q.ApplicationName == "" {
			q.ApplicationName = p.Agent
		}
		if withText {
			q.Query = truncate(p.Query, 500)
		}
		// The start is kept from the first sighting, so it (and the fix id
		// built from it) stays the same while the query runs.
		start := time.Now().Add(-time.Duration(p.Elapsed * float64(time.Second))).UTC().Truncate(time.Second)
		if first, ok := starts[p.QueryID]; ok && start.Sub(first).Abs() < 10*time.Second {
			start = first
		} else if starts != nil {
			starts[p.QueryID] = start
		}
		seen[p.QueryID] = true
		q.BackendStart = &start
		act.Queries = append(act.Queries, q)
	}
	for id := range starts {
		if !seen[id] {
			delete(starts, id)
		}
	}
	return act, longest, float64(len(ps))
}

// status reads ClickHouse's own health detail (DatabaseMonitoring.ClickHouse).
func status(ctx context.Context, c *client, memLimit int64, withText bool) *protocol.ClickHouseStatus {
	st := &protocol.ClickHouseStatus{CollectedAt: time.Now().UTC(), MemoryLimitBytes: memLimit}
	type partRow struct {
		DB        string `json:"database"`
		Table     string `json:"table"`
		Partition string `json:"partition"`
		Parts     int    `json:"parts"`
	}
	if ps, err := query[partRow](ctx, c, `SELECT database, table, partition, toInt32(count()) AS parts FROM system.parts WHERE active
		GROUP BY database, table, partition ORDER BY parts DESC LIMIT 10`, nil); err == nil {
		for _, p := range ps {
			st.Parts = append(st.Parts, protocol.ClickHouseParts{DB: p.DB, Table: p.Table, Partition: p.Partition, Parts: p.Parts})
		}
	}
	if ss, err := query[nameValue](ctx, c, `SELECT name, toFloat64OrZero(value) AS value FROM system.merge_tree_settings
		WHERE name IN ('parts_to_delay_insert', 'parts_to_throw_insert')`, nil); err == nil {
		for _, s := range ss {
			if s.Name == "parts_to_delay_insert" {
				st.PartsToDelayInsert = int(s.Value)
			} else {
				st.PartsToThrowInsert = int(s.Value)
			}
		}
	}
	type mutRow struct {
		DB       string `json:"database"`
		Table    string `json:"table"`
		ID       string `json:"mutation_id"`
		Command  string `json:"command"`
		Created  int64  `json:"created"`
		ToDo     int    `json:"parts_to_do"`
		Reason   string `json:"latest_fail_reason"`
		FailedAt int64  `json:"failed_at"`
	}
	if ms, err := query[mutRow](ctx, c, `SELECT database, table, mutation_id, substring(command, 1, 500) AS command,
		toInt64(toUnixTimestamp(create_time)) AS created, toInt32(parts_to_do) AS parts_to_do, latest_fail_reason,
		toInt64(toUnixTimestamp(latest_fail_time)) AS failed_at
		FROM system.mutations WHERE NOT is_done ORDER BY create_time LIMIT 20`, nil); err == nil {
		for _, m := range ms {
			mu := protocol.ClickHouseMutation{DB: m.DB, Table: m.Table, MutationID: m.ID,
				CreatedAt: time.Unix(m.Created, 0).UTC(), PartsToDo: m.ToDo}
			// The command and its error can hold values from the data.
			if withText {
				mu.Command = m.Command
				mu.FailReason = firstLine(m.Reason)
			} else {
				mu.FailReason = reasonWithoutText(m.Reason)
			}
			if m.Reason != "" && m.FailedAt > 0 {
				t := time.Unix(m.FailedAt, 0).UTC()
				mu.FailedAt = &t
			}
			st.Mutations = append(st.Mutations, mu)
		}
	}
	type replRow struct {
		DB       string `json:"database"`
		Table    string `json:"table"`
		ReadOnly uint8  `json:"is_readonly"`
		Delay    int64  `json:"delay"`
		Queue    int    `json:"queue_size"`
		LastErr  string `json:"last_error"`
	}
	if rs, err := query[replRow](ctx, c, `SELECT database, table, is_readonly, toInt64(absolute_delay) AS delay, toInt32(queue_size) AS queue_size,
		last_queue_update_exception AS last_error FROM system.replicas WHERE is_readonly OR absolute_delay > 60
		ORDER BY is_readonly DESC, absolute_delay DESC LIMIT 20`, nil); err == nil {
		for _, r := range rs {
			st.Replicas = append(st.Replicas, protocol.ClickHouseReplica{DB: r.DB, Table: r.Table, ReadOnly: r.ReadOnly != 0,
				DelaySeconds: r.Delay, QueueSize: r.Queue, LastError: firstLine(r.LastErr)})
		}
	}
	type detRow struct {
		Reason string `json:"reason"`
		N      int    `json:"n"`
	}
	if ds, err := query[detRow](ctx, c, "SELECT reason, toInt32(count()) AS n FROM system.detached_parts GROUP BY reason", nil); err == nil && len(ds) > 0 {
		st.DetachedParts = map[string]int{}
		for _, d := range ds {
			r := d.Reason
			if r == "" {
				r = "detached"
			}
			st.DetachedParts[r] += d.N
		}
	}
	return st
}
