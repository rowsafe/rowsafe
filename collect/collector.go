package collect

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Defaults for the collection loop.
const (
	DefaultInterval   = time.Minute
	SlowEvery         = 5 * time.Minute // database sizes and pg_stat_statements
	perClusterTimeout = 20 * time.Second
	sendTimeout       = 20 * time.Second
	maxBackoff        = 30 * time.Minute
)

// Options configures a Collector.
type Options struct {
	Log *slog.Logger
	// PGUser is the role the agent connects as (peer authentication).
	PGUser string
	// Databases returns the clusters to watch (the agent's current list).
	Databases func() []protocol.DatabaseSpec
	// Engine collects a sample of a database whose engine isn't PostgreSQL
	// (the agent's registered engines). Without it, or when it returns nil,
	// such a database is left out of the report.
	Engine func(context.Context, protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error)
	// Send delivers a report to the control plane.
	Send func(context.Context, protocol.MonitoringReport) (protocol.MonitoringAck, error)
	// QueryText includes query text in activity snapshots
	// (ROWSAFE_COLLECT_QUERY_TEXT, default true).
	QueryText bool
	// ProcRoot is where /proc is mounted (tests point it elsewhere).
	ProcRoot string
	Now      func() time.Time
	// InsightsInterval is how often table and index insights are collected
	// (default 30 minutes; slow runs back off up to 4 hours).
	InsightsInterval time.Duration
	// InsightsSync collects insights inline instead of in the background
	// (tests).
	InsightsSync bool
}

// Collector gathers one report per round. It is not safe for concurrent use.
type Collector struct {
	o        Options
	deltas   *deltaTracker
	clusters map[string]*clusterState
	host     *hostCollector
	lastSlow time.Time
}

func New(o Options) *Collector {
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.InsightsInterval <= 0 {
		o.InsightsInterval = DefaultInsightsInterval
	}
	return &Collector{o: o, deltas: newDeltaTracker(), clusters: map[string]*clusterState{},
		host: &hostCollector{procRoot: o.ProcRoot}}
}

// Settings read from the agent's environment.
type Settings struct {
	Enabled   bool // ROWSAFE_MONITORING (default true)
	QueryText bool // ROWSAFE_COLLECT_QUERY_TEXT (default true)
}

func SettingsFromEnv() Settings {
	return Settings{
		Enabled:   envBool("ROWSAFE_MONITORING", true),
		QueryText: envBool("ROWSAFE_COLLECT_QUERY_TEXT", true),
	}
}

func envBool(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	}
	return def
}

// Run collects and sends a report every interval until ctx ends. It reads
// ROWSAFE_MONITORING and ROWSAFE_COLLECT_QUERY_TEXT from the environment.
// It runs beside the agent's task loop and never holds anything a task
// needs: a slow or failing PostgreSQL only delays the next report.
func Run(ctx context.Context, o Options) {
	s := SettingsFromEnv()
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if !s.Enabled {
		o.Log.Info("built-in monitoring is off (ROWSAFE_MONITORING=false)")
		return
	}
	o.QueryText = s.QueryText
	c := New(o)
	interval := DefaultInterval
	// Reports go out at the same second of every interval, chosen at random
	// per agent: the control plane files samples under the minute they
	// arrive in, so a drifting loop would put two reports in one minute and
	// none in the next, and a shared second would make every agent report
	// at once.
	offset := 5*time.Second + rand.N(45*time.Second)
	failures := 0
	next := nextSlot(time.Now().Add(15*time.Second), interval, offset) // after the first heartbeat
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
		report := c.Collect(ctx)
		sctx, cancel := context.WithTimeout(ctx, sendTimeout)
		ack, err := o.Send(sctx, report)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			failures++
			// Back off, so an old control plane without the endpoint or a
			// revoked agent doesn't get a report every minute.
			wait := min(interval*time.Duration(1<<min(failures, 6)), maxBackoff)
			if failures == 1 || wait == maxBackoff {
				o.Log.Warn("sending monitoring report failed", "err", err, "retry_in", wait.String())
			}
			next = nextSlot(time.Now().Add(wait-interval), interval, offset)
			continue
		}
		failures = 0
		if ack.IntervalSeconds >= 15 && ack.IntervalSeconds <= 3600 {
			interval = time.Duration(ack.IntervalSeconds) * time.Second
		}
		next = nextSlot(time.Now(), interval, offset)
	}
}

// nextSlot is the first time after now that is offset past a multiple of
// interval.
func nextSlot(now time.Time, interval, offset time.Duration) time.Time {
	t := now.Truncate(interval).Add(offset % interval)
	for !t.After(now) {
		t = t.Add(interval)
	}
	return t
}

// Collect gathers one report: host metrics and, per watched database, its
// metrics, replication slots and long-running sessions (and, every few
// minutes, database sizes and top statements).
func (c *Collector) Collect(ctx context.Context) protocol.MonitoringReport {
	now := c.o.Now()
	var dbs []protocol.DatabaseSpec
	if c.o.Databases != nil {
		dbs = c.o.Databases()
	}
	slow := now.Sub(c.lastSlow) >= SlowEvery-5*time.Second
	if slow {
		c.lastSlow = now
	}
	report := protocol.MonitoringReport{CollectedAt: now.UTC()}
	keep := map[string]bool{}
	var dataDirs []string
	for _, db := range dbs {
		if protocol.NormalizeEngine(db.Engine) != protocol.EnginePostgreSQL {
			if dm := c.otherEngine(ctx, db); dm != nil {
				report.Databases = append(report.Databases, *dm)
			}
			continue
		}
		keep[db.ID] = true
		st := c.clusters[db.ID]
		if st == nil {
			st = &clusterState{}
			c.clusters[db.ID] = st
		}
		dm := protocol.DatabaseMonitoring{DatabaseID: db.ID}
		target := Target{SocketDir: db.SocketDir, Port: db.Port, User: c.o.PGUser}
		cctx, cancel := context.WithTimeout(ctx, perClusterTimeout)
		r, err := readCluster(cctx, target, st, slow, c.o.QueryText)
		cancel()
		if err != nil {
			dm.Error = err.Error()
			report.Databases = append(report.Databases, dm)
			continue
		}
		at := c.o.Now()
		dm.Metrics = derive(r, db.ID, at, c.deltas)
		if r.dataDir != "" {
			dataDirs = append(dataDirs, r.dataDir)
			if d, err := diskUsage(r.dataDir); err == nil {
				dm.Metrics[MDiskFreePct] = d.freePct
				dm.Metrics[MDiskFreeBytes] = d.free
				dm.Metrics[MDiskTotalBytes] = d.total
			}
		}
		dm.ReplicationSlots = r.slots
		dm.Activity = &protocol.Activity{CollectedAt: at.UTC(), QueryTextCollected: c.o.QueryText, Queries: r.activity,
			Blocking: r.blocking}
		if dm.Activity.Queries == nil {
			dm.Activity.Queries = []protocol.ActivityQuery{}
		}
		dm.Replication = r.replication
		if slow {
			dm.Sizes = r.sizes
			if r.statements != nil {
				r.statements.CollectedAt = at.UTC()
				dm.Statements = r.statements
			}
			if r.queryStats != nil {
				r.queryStats.CollectedAt = at.UTC()
				dm.QueryStats = r.queryStats
			}
			dm.Settings = c.settings(ctx, target, at) // settings.go
		}
		c.startInsights(ctx, st, target, at)
		dm.Insights = st.insights.take()
		report.Databases = append(report.Databases, dm)
	}
	c.deltas.forget(keep)
	for id := range c.clusters {
		if !keep[id] {
			delete(c.clusters, id)
		}
	}
	report.Host = c.host.collect(dataDirs)
	return report
}

// otherEngine collects a non-PostgreSQL database's sample through
// Options.Engine (nil: left out of the report).
func (c *Collector) otherEngine(ctx context.Context, db protocol.DatabaseSpec) *protocol.DatabaseMonitoring {
	if c.o.Engine == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, perClusterTimeout)
	defer cancel()
	dm, err := c.o.Engine(cctx, db)
	if err != nil {
		if dm == nil {
			dm = &protocol.DatabaseMonitoring{}
		}
		dm.Error = err.Error()
	}
	if dm != nil {
		dm.DatabaseID = db.ID
	}
	return dm
}

// startInsights begins a cluster's insights run when one is due. It runs
// in the background (the report carries it once it is done) unless
// InsightsSync is set.
func (c *Collector) startInsights(ctx context.Context, st *clusterState, t Target, now time.Time) {
	every := c.o.InsightsInterval
	if !st.insights.start(now, every) {
		return
	}
	run := func() {
		began := time.Now()
		res, err := CollectInsights(ctx, t)
		if err != nil {
			c.o.Log.Debug("collecting table insights failed", "err", err)
		} else {
			res.CollectedAt = c.o.Now().UTC()
		}
		st.insights.finish(res, time.Since(began), every)
	}
	if c.o.InsightsSync {
		run()
		return
	}
	go run()
}
