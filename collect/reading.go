package collect

import (
	"context"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Reading is one reading of a cluster made on demand, outside the agent's
// collection loop: what `rowsafe pulse postgres://...` looks at without an
// agent or an account.
type Reading struct {
	protocol.DatabaseMonitoring
	CollectedAt time.Time
	// VersionNum is server_version_num.
	VersionNum int
	// Local: the cluster runs on this machine (Target.Local), so disk
	// readings are its own.
	Local bool
}

// ReadOptions says what a Reading includes besides the metrics, sessions,
// replication slots, replication and database sizes.
type ReadOptions struct {
	// Statements: the top of pg_stat_statements (totals since its last
	// reset; a single reading has no interval to compare with).
	Statements bool
	// Insights: tables and indexes (bloat, unused and duplicate indexes,
	// vacuum, transaction ID age). The slowest part: up to a minute on a
	// large cluster.
	Insights bool
	// Settings: the settings that matter, with this host's memory, CPUs and
	// disk when the cluster runs here.
	Settings bool
	// QueryText includes query text in the activity snapshot.
	QueryText bool
	// ProcRoot is where /proc is mounted ("" is /proc).
	ProcRoot string
}

// Read takes one reading of the cluster at t. Counters that the loop turns
// into rates between two readings (commits, deadlocks, WAL) are left out;
// the cache hit ratio is the one since statistics were last reset.
func Read(ctx context.Context, t Target, o ReadOptions) (*Reading, error) {
	st := &clusterState{}
	r, err := readCluster(ctx, t, st, true, o.QueryText)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	out := &Reading{CollectedAt: at, VersionNum: r.versionNum, Local: t.Local()}
	dm := &out.DatabaseMonitoring
	dm.Metrics = make(map[string]float64, len(r.gauges)+4)
	for k, v := range r.gauges {
		dm.Metrics[k] = v
	}
	if hit, read := r.dbCounters["blks_hit"], r.dbCounters["blks_read"]; hit+read >= minBlocksForHitRatio {
		dm.Metrics[MCacheHitPct] = clampPct(100 * hit / (hit + read))
	}
	if out.Local && r.dataDir != "" {
		if d, err := diskUsage(r.dataDir); err == nil {
			dm.Metrics[MDiskFreePct] = d.freePct
			dm.Metrics[MDiskFreeBytes] = d.free
			dm.Metrics[MDiskTotalBytes] = d.total
		}
	}
	dm.ReplicationSlots = r.slots
	dm.Activity = &protocol.Activity{CollectedAt: at, QueryTextCollected: o.QueryText, Queries: r.activity, Blocking: r.blocking}
	if dm.Activity.Queries == nil {
		dm.Activity.Queries = []protocol.ActivityQuery{}
	}
	dm.Replication = r.replication
	dm.Sizes = r.sizes
	if o.Statements && r.statements != nil {
		r.statements.CollectedAt = at
		dm.Statements = r.statements
	}
	if o.Settings {
		s, err := ReadSettings(ctx, t, o.ProcRoot)
		if err != nil {
			return nil, fmt.Errorf("reading settings: %w", err)
		}
		s.CollectedAt = at
		dm.Settings = s
	}
	if o.Insights {
		ins, err := CollectInsights(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("reading tables and indexes: %w", err)
		}
		ins.CollectedAt = time.Now().UTC()
		dm.Insights = ins
	}
	return out, nil
}
