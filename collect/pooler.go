package collect

import (
	"context"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbouncer"
	"github.com/rowsafe/rowsafe/protocol"
)

// PgBouncer metrics (database scope): the pooler in front of a database,
// read from its admin console every minute.
const (
	PPoolerUp       = "pooler_up"
	PClientsActive  = "pooler_clients_active"
	PClientsWaiting = "pooler_clients_waiting"
	PServersActive  = "pooler_servers_active"
	PServersIdle    = "pooler_servers_idle"
	PPoolUsedPct    = "pooler_pool_used_pct"
	PWaitMaxSeconds = "pooler_wait_max_seconds"
	PWaitAvgMs      = "pooler_wait_avg_ms"
	PXactRate       = "pooler_xact_rate"
	PQueryRate      = "pooler_query_rate"
)

func init() {
	Catalog = append(Catalog,
		Metric{PPoolerUp, ScopeDatabase, "", "1 when PgBouncer answered that minute, 0 when it did not (only where pooling is on)"},
		Metric{PClientsActive, ScopeDatabase, "count", "Client connections to PgBouncer using a server connection or idle"},
		Metric{PClientsWaiting, ScopeDatabase, "count", "Client connections waiting for PgBouncer to give them a server connection"},
		Metric{PServersActive, ScopeDatabase, "count", "PgBouncer's server connections in use by a client"},
		Metric{PServersIdle, ScopeDatabase, "count", "PgBouncer's server connections open and free"},
		Metric{PPoolUsedPct, ScopeDatabase, "%", "Server connections in use in the busiest pool, as a percentage of its pool size"},
		Metric{PWaitMaxSeconds, ScopeDatabase, "s", "How long the longest-waiting client has waited for a server connection"},
		Metric{PWaitAvgMs, ScopeDatabase, "ms", "Average time clients waited for a server connection over the last minute"},
		Metric{PXactRate, ScopeDatabase, "/s", "Transactions per second through PgBouncer"},
		Metric{PQueryRate, ScopeDatabase, "/s", "Queries per second through PgBouncer"},
	)
}

// PoolerSource is a PgBouncer admin console to read for one database.
type PoolerSource struct {
	DatabaseID string
	Target     pgbouncer.Target
	// Databases limits the reading to these PgBouncer databases (nil: all
	// but the admin console itself).
	Databases []string
}

// readPooler reads SHOW POOLS, STATS and DATABASES.
func readPooler(ctx context.Context, src PoolerSource) (pools, stats, dbs []pgbouncer.Row, version string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := src.Target.Connect(ctx)
	if err != nil {
		return nil, nil, nil, "", err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	version, _ = pgbouncer.Version(ctx, conn)
	if pools, err = pgbouncer.Show(ctx, conn, "POOLS"); err != nil {
		return nil, nil, nil, "", err
	}
	stats, _ = pgbouncer.Show(ctx, conn, "STATS")
	dbs, _ = pgbouncer.Show(ctx, conn, "DATABASES")
	return pools, stats, dbs, version, nil
}

// maxPools bounds the pools sent per database.
const maxPools = 50

// poolerTotals are SHOW STATS counters of one reading, per PgBouncer
// database, to turn into rates at the next one.
type poolerTotals struct {
	at   time.Time
	byDB map[string]dbTotals
}

type dbTotals struct{ xact, query, wait, assigned int64 }

// dbRates are one database's rates since the previous reading.
type dbRates struct{ xactPerSec, queryPerSec, waitMs float64 }

func rates(cur, prev dbTotals, secs float64) (dbRates, bool) {
	if secs <= 0 || cur.xact < prev.xact || cur.query < prev.query || cur.wait < prev.wait {
		return dbRates{}, false // PgBouncer restarted: counters began again
	}
	r := dbRates{xactPerSec: float64(cur.xact-prev.xact) / secs, queryPerSec: float64(cur.query-prev.query) / secs}
	// Waits happen when a client is given a server connection: per
	// assignment where PgBouncer counts them (1.23+), else per transaction.
	n := cur.assigned - prev.assigned
	if cur.assigned == 0 || n < 0 {
		n = cur.xact - prev.xact
	}
	if n > 0 {
		r.waitMs = float64(cur.wait-prev.wait) / float64(n) / 1000
	}
	return r, true
}

// poolerMetrics sums SHOW POOLS (one line per database and user) and SHOW
// STATS (per database) over the databases that count; rates need a
// previous reading.
func poolerMetrics(pools, stats, dbs []pgbouncer.Row, only []string, prev *poolerTotals, now time.Time) (map[string]float64, *protocol.PoolerStats, *poolerTotals) {
	counts := func(db string) bool {
		if db == "pgbouncer" || db == "" {
			return false
		}
		return only == nil || slices.Contains(only, db)
	}
	poolSize := map[string]int64{}
	for _, d := range dbs {
		poolSize[d["name"]] = d.Int("pool_size")
	}
	cur := &poolerTotals{at: now, byDB: map[string]dbTotals{}}
	perDB := map[string]dbRates{}
	m := map[string]float64{PPoolerUp: 1}
	var xact, query, waitWeighted, waitWeight float64
	haveRates := false
	for _, s := range stats {
		db := s["database"]
		if !counts(db) {
			continue
		}
		t := dbTotals{xact: s.Int("total_xact_count"), query: s.Int("total_query_count"), wait: s.Int("total_wait_time"),
			assigned: s.Int("total_server_assignment_count")}
		cur.byDB[db] = t
		if prev == nil {
			continue
		}
		p, ok := prev.byDB[db]
		if !ok {
			p = dbTotals{} // a pool that appeared since: counted from zero
		}
		r, ok := rates(t, p, now.Sub(prev.at).Seconds())
		if !ok {
			continue
		}
		haveRates = true
		perDB[db] = r
		xact += r.xactPerSec
		query += r.queryPerSec
		weight := max(r.xactPerSec, 1e-9)
		waitWeighted += r.waitMs * weight
		waitWeight += weight
	}
	if haveRates {
		m[PXactRate], m[PQueryRate] = xact, query
		m[PWaitAvgMs] = 0
		if waitWeight > 0 {
			m[PWaitAvgMs] = waitWeighted / waitWeight
		}
	}
	snap := &protocol.PoolerStats{Pools: []protocol.PoolStat{}}
	var clActive, clWaiting, svActive, svIdle, usedPct, maxWait float64
	for _, p := range pools {
		db := p["database"]
		if !counts(db) {
			continue
		}
		wait := float64(p.Int("maxwait")) + float64(p.Int("maxwait_us"))/1e6
		ps := protocol.PoolStat{
			Database: db, User: p["user"], Mode: p["pool_mode"],
			ClientsActive: int(p.Int("cl_active")), ClientsWaiting: int(p.Int("cl_waiting")),
			ServersActive: int(p.Int("sv_active")), ServersIdle: int(p.Int("sv_idle") + p.Int("sv_used")),
			PoolSize: int(poolSize[db]), MaxWaitSeconds: wait,
			AvgWaitMs: perDB[db].waitMs, XactPerSecond: perDB[db].xactPerSec, QueryPerSecond: perDB[db].queryPerSec,
		}
		clActive += float64(ps.ClientsActive)
		clWaiting += float64(ps.ClientsWaiting)
		svActive += float64(ps.ServersActive)
		svIdle += float64(ps.ServersIdle)
		maxWait = max(maxWait, wait)
		if ps.PoolSize > 0 {
			usedPct = max(usedPct, math.Min(100, 100*float64(ps.ServersActive)/float64(ps.PoolSize)))
		}
		snap.Pools = append(snap.Pools, ps)
	}
	// The busiest pools first.
	slices.SortStableFunc(snap.Pools, func(a, b protocol.PoolStat) int {
		return (b.ClientsWaiting*1000 + b.ServersActive) - (a.ClientsWaiting*1000 + a.ServersActive)
	})
	if len(snap.Pools) > maxPools {
		snap.Pools = snap.Pools[:maxPools]
	}
	m[PClientsActive], m[PClientsWaiting], m[PServersActive], m[PServersIdle] = clActive, clWaiting, svActive, svIdle
	m[PPoolUsedPct], m[PWaitMaxSeconds] = usedPct, maxWait
	return m, snap, cur
}

// pooler reads the PgBouncer in front of a database, if there is one. A
// PgBouncer that can't be read gives pooler_up 0.
func (c *Collector) pooler(ctx context.Context, srcs []PoolerSource, dbID string) (map[string]float64, *protocol.PoolerStats) {
	src, ok := poolerFor(srcs, dbID)
	if !ok {
		delete(c.poolerPrev, dbID)
		return nil, nil
	}
	pools, stats, dbs, version, err := readPooler(ctx, src)
	if err != nil {
		c.o.Log.Debug("reading PgBouncer failed", "database_id", dbID, "err", err)
		delete(c.poolerPrev, dbID)
		return map[string]float64{PPoolerUp: 0}, nil
	}
	now := c.o.Now()
	m, snap, cur := poolerMetrics(pools, stats, dbs, src.Databases, c.poolerPrev[dbID], now)
	c.poolerPrev[dbID] = cur
	snap.CollectedAt, snap.Version = now.UTC(), version
	return m, snap
}

// poolerFor returns the pooler source of a database, if any.
func poolerFor(srcs []PoolerSource, dbID string) (PoolerSource, bool) {
	for _, s := range srcs {
		if strings.EqualFold(s.DatabaseID, dbID) {
			return s, true
		}
	}
	return PoolerSource{}, false
}
