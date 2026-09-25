package mongodb

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for MongoDB: serverStatus (connections, operations, queues, the
// WiredTiger cache, memory, network), the oplog window, replication lag,
// disk space where the data lives, database sizes every 5 minutes and the
// operations running for over a minute. Read-only and cheap.

const (
	sizesEvery      = 5 * time.Minute
	longOpThreshold = 60 * time.Second
)

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	client    *mongo.Client
	uri       string
	prev      map[string]float64
	prevAt    time.Time
	lastSizes time.Time
	dbPath    string
}

func (e *Engine) monitorFor(id string) *dbMonitor {
	e.mon.mu.Lock()
	defer e.mon.mu.Unlock()
	if e.mon.dbs == nil {
		e.mon.dbs = map[string]*dbMonitor{}
	}
	m := e.mon.dbs[id]
	if m == nil {
		m = &dbMonitor{}
		e.mon.dbs[id] = m
	}
	return m
}

// Monitor collects one sample of db.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: db.ID}
	m := e.monitorFor(db.ID)
	l, err := loadLogin(env, db.Port)
	if err != nil {
		dm.Error = err.Error()
		return dm, nil
	}
	uri := l.uri(db.Port)
	if m.client == nil || m.uri != uri {
		if m.client != nil {
			disconnect(m.client)
		}
		c, err := connect(ctx, uri)
		if err != nil {
			m.client = nil
			dm.Error = "can't connect to MongoDB: " + err.Error()
			return dm, nil
		}
		m.client, m.uri = c, uri
	}
	if err := e.sample(ctx, m, dm); err != nil {
		if isNetworkError(err) {
			disconnect(m.client)
			m.client = nil
		}
		dm.Error = firstLine(err.Error())
	}
	return dm, nil
}

func (e *Engine) sample(ctx context.Context, m *dbMonitor, dm *protocol.DatabaseMonitoring) error {
	c := m.client
	now := time.Now()
	var ss bson.M
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "serverStatus", Value: 1}}).Decode(&ss); err != nil {
		return err
	}
	metrics := map[string]float64{}
	cur, avail := toFloat(lookup(ss, "connections", "current")), toFloat(lookup(ss, "connections", "available"))
	metrics[collect.MConnTotal] = cur
	metrics[collect.MConnMax] = cur + avail
	if cur+avail > 0 {
		metrics[collect.MConnUsedPct] = 100 * cur / (cur + avail)
	}
	if v := lookup(ss, "connections", "active"); v != nil {
		metrics[collect.MConnActive] = toFloat(v)
	}
	metrics[collect.MMongoQueuedOps] = toFloat(lookup(ss, "globalLock", "currentQueue", "total"))
	if v := lookup(ss, "mem", "resident"); v != nil {
		metrics[collect.MMongoResidentBytes] = toFloat(v) * (1 << 20)
	}
	if wt, ok := lookup(ss, "wiredTiger", "cache").(bson.M); ok {
		maxB := toFloat(wt["maximum bytes configured"])
		if maxB > 0 {
			metrics[collect.MMongoCacheUsedPct] = 100 * toFloat(wt["bytes currently in the cache"]) / maxB
			metrics[collect.MMongoCacheDirtyPct] = 100 * toFloat(wt["tracked dirty bytes in the cache"]) / maxB
		}
	}
	counters := map[string]float64{
		collect.MMongoOpsInsertRate:  toFloat(lookup(ss, "opcounters", "insert")),
		collect.MMongoOpsQueryRate:   toFloat(lookup(ss, "opcounters", "query")),
		collect.MMongoOpsUpdateRate:  toFloat(lookup(ss, "opcounters", "update")),
		collect.MMongoOpsDeleteRate:  toFloat(lookup(ss, "opcounters", "delete")),
		collect.MMongoOpsGetmoreRate: toFloat(lookup(ss, "opcounters", "getmore")),
		collect.MMongoOpsCommandRate: toFloat(lookup(ss, "opcounters", "command")),
		collect.MMongoNetInRate:      toFloat(lookup(ss, "network", "bytesIn")),
		collect.MMongoNetOutRate:     toFloat(lookup(ss, "network", "bytesOut")),
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

	if _, isRS := lookup(ss, "repl", "setName").(string); isRS {
		first, last, _ := oplogBounds(ctx, c)
		if !first.IsZero() {
			metrics[collect.MMongoOplogWindow] = last.Sub(first).Hours()
		}
		lag, secondaries := replicationLag(ctx, c)
		metrics[collect.MReplicasConnected] = float64(secondaries)
		if secondaries > 0 {
			metrics[collect.MReplicationLagSeconds] = lag
		}
	}

	if m.dbPath == "" {
		var opts struct {
			Parsed bson.M `bson:"parsed"`
		}
		if c.Database("admin").RunCommand(ctx, bson.D{{Key: "getCmdLineOpts", Value: 1}}).Decode(&opts) == nil {
			m.dbPath = cmpOr(lookupString(opts.Parsed, "storage", "dbPath"), "/data/db")
		}
	}
	if m.dbPath != "" {
		if total, free, err := diskUsage(m.dbPath); err == nil && total > 0 {
			metrics[collect.MDiskTotalBytes] = float64(total)
			metrics[collect.MDiskFreeBytes] = float64(free)
			metrics[collect.MDiskFreePct] = 100 * float64(free) / float64(total)
		}
	}

	act, longest := longOps(ctx, c, queryTextOn())
	metrics[collect.MLongestQuerySeconds] = longest
	dm.Activity = act

	if now.Sub(m.lastSizes) >= sizesEvery {
		if dbs, err := c.ListDatabases(ctx, bson.D{}); err == nil {
			var total int64
			for _, d := range dbs.Databases {
				total += d.SizeOnDisk
				if !isSystemDB(d.Name) {
					dm.Sizes = append(dm.Sizes, protocol.DatabaseSize{Name: d.Name, SizeBytes: d.SizeOnDisk})
				}
			}
			metrics[collect.MDatabaseSizeBytes] = float64(total)
			m.lastSizes = now
		}
	}
	dm.Metrics = metrics
	return nil
}

func queryTextOn() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("ROWSAFE_COLLECT_QUERY_TEXT")))
	return v != "false" && v != "0" && v != "no" && v != "off"
}

// replicationLag is the slowest secondary's lag behind the primary, in
// seconds, and how many secondaries there are.
func replicationLag(ctx context.Context, c *mongo.Client) (float64, int) {
	var st struct {
		Members []struct {
			StateStr   string    `bson:"stateStr"`
			OptimeDate time.Time `bson:"optimeDate"`
			Health     float64   `bson:"health"`
		} `bson:"members"`
	}
	if c.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetGetStatus", Value: 1}}).Decode(&st) != nil {
		return 0, 0
	}
	var primary time.Time
	for _, m := range st.Members {
		if m.StateStr == "PRIMARY" {
			primary = m.OptimeDate
		}
	}
	lag, n := 0.0, 0
	for _, m := range st.Members {
		if m.StateStr != "SECONDARY" {
			continue
		}
		n++
		if !primary.IsZero() {
			lag = max(lag, primary.Sub(m.OptimeDate).Seconds())
		}
	}
	return lag, n
}

// longOps lists client operations running for over a minute (Activity) and
// the longest running one's seconds.
func longOps(ctx context.Context, c *mongo.Client, withText bool) (*protocol.Activity, float64) {
	act := &protocol.Activity{CollectedAt: time.Now().UTC(), QueryTextCollected: withText, Queries: []protocol.ActivityQuery{}}
	var res struct {
		Inprog []bson.M `bson:"inprog"`
	}
	err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "currentOp", Value: 1}, {Key: "active", Value: true}}).Decode(&res)
	if err != nil {
		return act, 0
	}
	longest := 0.0
	for _, op := range res.Inprog {
		if !clientOp(op) {
			continue
		}
		secs := toFloat(op["microsecs_running"]) / 1e6
		if secs == 0 {
			secs = toFloat(op["secs_running"])
		}
		longest = max(longest, secs)
		if secs < longOpThreshold.Seconds() {
			continue
		}
		q := protocol.ActivityQuery{PID: toInt(op["opid"]), DurationSeconds: secs, XactSeconds: 0, State: "active"}
		q.State, _ = op["op"].(string)
		if ns, _ := op["ns"].(string); ns != "" {
			q.Database, _, _ = strings.Cut(ns, ".")
		}
		q.ApplicationName, _ = op["appName"].(string)
		if users, ok := op["effectiveUsers"].(bson.A); ok && len(users) > 0 {
			if u, ok := users[0].(bson.M); ok {
				q.User, _ = u["user"].(string)
			}
		}
		if withText {
			if cmd, ok := op["command"]; ok {
				if b, err := json.Marshal(cmd); err == nil {
					q.Query = truncate(string(b), 500)
				}
			}
		}
		start := time.Now().Add(-time.Duration(secs * float64(time.Second))).UTC().Truncate(time.Second)
		q.BackendStart = &start
		act.Queries = append(act.Queries, q)
	}
	return act, longest
}

// clientOp is an operation a client started: not MongoDB's own work
// (replication, TTL, sessions), not an oplog or change stream cursor
// waiting for data, not the agent itself.
func clientOp(op bson.M) bool {
	if _, ok := op["client"]; !ok {
		if _, ok2 := op["client_s"]; !ok2 {
			return false
		}
	}
	if app, _ := op["appName"].(string); app == "rowsafe-agent" {
		return false
	}
	if ns, _ := op["ns"].(string); strings.HasPrefix(ns, "local.") || strings.HasPrefix(ns, "config.") || strings.HasPrefix(ns, "admin.$cmd") {
		return false
	}
	switch op["op"] {
	case "query", "insert", "update", "remove", "command", "getmore":
	default:
		return false
	}
	if cmd, ok := op["command"].(bson.M); ok {
		for _, k := range []string{"hello", "isMaster", "ismaster", "getMore"} {
			if _, ok := cmd[k]; ok && k != "getMore" {
				return false
			}
		}
		if _, ok := cmd["getMore"]; ok {
			if cur, ok := op["cursor"].(bson.M); ok {
				if t, _ := cur["tailable"].(bool); t {
					return false
				}
			}
		}
		if p, ok := cmd["pipeline"].(bson.A); ok && len(p) > 0 {
			if st, ok := p[0].(bson.M); ok {
				if _, cs := st["$changeStream"]; cs {
					return false
				}
			}
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
