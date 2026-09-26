package collect

import (
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbouncer"
)

func TestPoolerMetrics(t *testing.T) {
	pools := []pgbouncer.Row{
		{"database": "pgbouncer", "user": "pgbouncer", "cl_active": "1"},
		{"database": "shop", "user": "app", "cl_active": "30", "cl_waiting": "4", "sv_active": "20", "sv_idle": "0", "sv_used": "0",
			"maxwait": "1", "maxwait_us": "500000", "pool_mode": "transaction"},
		{"database": "shop", "user": "report", "cl_active": "2", "cl_waiting": "0", "sv_active": "1", "sv_idle": "3", "sv_used": "1", "pool_mode": "transaction"},
	}
	dbs := []pgbouncer.Row{{"name": "shop", "pool_size": "20"}, {"name": "pgbouncer", "pool_size": "2"}}
	t0 := time.Unix(1_700_000_000, 0)
	stats := func(xact, query, wait string) []pgbouncer.Row {
		return []pgbouncer.Row{{"database": "shop", "total_xact_count": xact, "total_query_count": query, "total_wait_time": wait}}
	}
	m, snap, prev := poolerMetrics(pools, stats("1000", "3000", "0"), dbs, nil, nil, t0)
	if m[PPoolerUp] != 1 || m[PClientsActive] != 32 || m[PClientsWaiting] != 4 || m[PServersActive] != 21 || m[PServersIdle] != 4 {
		t.Fatalf("counts %v", m)
	}
	if m[PPoolUsedPct] != 100 || m[PWaitMaxSeconds] != 1.5 {
		t.Fatalf("usage and wait %v", m)
	}
	if _, ok := m[PXactRate]; ok {
		t.Fatal("rates without a previous reading")
	}
	if len(snap.Pools) != 2 || snap.Pools[0].User != "app" || snap.Pools[0].PoolSize != 20 {
		t.Fatalf("snapshot %+v", snap.Pools)
	}
	// A minute later: 6000 transactions, 12 s of waiting in all.
	m, snap, _ = poolerMetrics(pools, stats("7000", "15000", "12000000"), dbs, nil, prev, t0.Add(time.Minute))
	if m[PXactRate] != 100 || m[PQueryRate] != 200 || m[PWaitAvgMs] != 2 {
		t.Fatalf("rates %v", m)
	}
	if snap.Pools[0].XactPerSecond != 100 {
		t.Fatalf("per pool %+v", snap.Pools[0])
	}
	// PgBouncer restarted: counters went back, no rates.
	m, _, _ = poolerMetrics(pools, stats("5", "5", "0"), dbs, nil, prev, t0.Add(2*time.Minute))
	if _, ok := m[PXactRate]; ok {
		t.Fatal("rates across a restart")
	}
	// Only some databases count.
	m, _, _ = poolerMetrics(pools, nil, dbs, []string{"other"}, nil, t0)
	if m[PClientsActive] != 0 {
		t.Fatalf("filtered %v", m)
	}
	for _, name := range []string{PPoolerUp, PClientsWaiting, PWaitAvgMs, PPoolUsedPct} {
		if _, ok := Lookup(ScopeDatabase, name); !ok {
			t.Errorf("%s not in the catalog", name)
		}
	}
}
