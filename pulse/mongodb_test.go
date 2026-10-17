package pulse

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

func mongoInput() Input {
	return Input{Database: "shop", Host: "db.example.com", Engine: protocol.EngineMongoDB,
		Command: func(sub string) string { return "rowsafe " + sub + " mongodb://app@db/shop" },
		Metrics: map[string]float64{collect.MConnUsedPct: 5, collect.MConnTotal: 10, collect.MConnMax: 200, collect.MMongoOplogWindow: 48}}
}

func TestMongoDBHealthy(t *testing.T) {
	h := Evaluate(mongoInput(), now)
	if h.Score != 100 || len(h.Findings) != 0 {
		t.Fatalf("%d %v", h.Score, ids(h))
	}
	if c := check(t, h, CatReplication); c.Status != "ok" || c.Detail != "Reaches back 2 days." {
		t.Errorf("oplog %+v", c)
	}
	for _, c := range h.Checks {
		if strings.Contains(c.Detail, "PostgreSQL") || c.Category == CatMaintenance {
			t.Errorf("PostgreSQL's rules ran: %+v", c)
		}
	}
}

func TestMongoDBFindings(t *testing.T) {
	start := now.Add(-20 * time.Minute)
	since := now.Add(-10 * 24 * time.Hour)
	in := mongoInput()
	in.Local = true
	in.Metrics[collect.MDiskFreePct], in.Metrics[collect.MDiskFreeBytes] = 3, 2<<30
	in.Metrics[collect.MConnUsedPct], in.Metrics[collect.MConnTotal] = 96, 192
	in.Metrics[collect.MMongoCacheDirtyPct] = 25
	in.Metrics[collect.MMongoQueuedOps] = 40
	in.Metrics[collect.MMongoOplogWindow] = 3
	in.Metrics[collect.MReplicasConnected], in.Metrics[collect.MReplicationLagSeconds] = 1, 600
	in.Activity = &protocol.Activity{CollectedAt: now, Queries: []protocol.ActivityQuery{
		{PID: 77, DurationSeconds: 1200, ApplicationName: "billing", Database: "shop", BackendStart: &start},
		{PID: 78, DurationSeconds: 1300, ApplicationName: "rowsafe", BackendStart: &start}, // never offered
		{PID: 79, DurationSeconds: 90, BackendStart: &start}}}
	in.Insights = &protocol.Insights{CollectedAt: now,
		UnusedIndexes:    []protocol.UnusedIndex{{Database: "shop", Schema: "shop", Table: "orders", Index: "status_1", Bytes: 40 << 20, StatsSince: &since}},
		DuplicateIndexes: []protocol.DuplicateIndex{{Database: "shop", Schema: "shop", Table: "orders", Index: "a_1", CoveredBy: "a_1_b_1", Kind: "redundant", Bytes: 1 << 20}},
		Advisor:          &protocol.AdvisorFacts{Profiler: &protocol.MongoProfiler{Off: []string{"shop"}, SlowMs: 100}}}
	h := Evaluate(in, now)
	got := ids(h)
	for _, want := range []string{"disk_almost_full", "mongodb_connections_high", "mongodb_long_operation", "mongodb_cache_pressure",
		"mongodb_queued_ops", "mongodb_oplog_window", "mongodb_replication_lag", "mongodb_profiler_off", "unused_indexes", "duplicate_indexes"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if f := finding(t, h, "disk_almost_full"); !strings.Contains(f.Explanation, "MongoDB") || f.Command != "df -h; du -sh /var/lib/mongodb" || len(f.Fixes) != 0 {
		t.Errorf("disk %+v", f)
	}
	if f := finding(t, h, "mongodb_connections_high"); f.Severity != protocol.SeverityCritical {
		t.Errorf("connections %+v", f)
	}
	long := finding(t, h, "mongodb_long_operation")
	if len(long.Fixes) != 1 || long.Fixes[0].ID != "kill:77:"+itoa(start.Unix()) || long.Fixes[0].Confirm == "" || !long.Fixes[0].Destructive {
		t.Fatalf("kill fixes %+v", long.Fixes)
	}
	var p protocol.MaintenanceParams
	_ = json.Unmarshal(long.Fixes[0].Params, &p)
	if p.Action != protocol.MaintKillOp || p.PID != 77 || !p.BackendStart.Equal(start) {
		t.Errorf("kill params %+v", p)
	}
	if f := finding(t, h, "mongodb_queued_ops"); !strings.Contains(f.Action, "rowsafe activity mongodb://app@db/shop") {
		t.Errorf("queued action %q", f.Action)
	}
	prof := finding(t, h, "mongodb_profiler_off")
	if len(prof.Fixes) != 1 || !strings.Contains(prof.Explanation, "rowsafe top") {
		t.Errorf("profiler %+v", prof)
	}
	_ = json.Unmarshal(prof.Fixes[0].Params, &p)
	if p.Action != protocol.MaintMongoProfile || !slices.Equal(p.Tables, []string{"shop"}) {
		t.Errorf("profile params %+v", p)
	}
	drop := finding(t, h, "unused_indexes").Fixes
	if len(drop) != 1 || drop[0].ID != "drop:shop.orders.status_1" {
		t.Fatalf("drop %+v", drop)
	}
	_ = json.Unmarshal(drop[0].Params, &p)
	if p.Action != protocol.MaintDropIndex || p.DB != "shop" || p.Index != "shop.status_1" || !p.Unused || !slices.Equal(p.Tables, []string{"orders"}) {
		t.Errorf("drop params %+v", p)
	}
	if h.Score > capCritical {
		t.Errorf("score %d", h.Score)
	}
	// The dashboard has its own index recommendations.
	in.Dashboard = true
	if got := ids(Evaluate(in, now)); slices.Contains(got, "unused_indexes") {
		t.Errorf("dashboard: %v", got)
	}
}

func TestMongoDBNoReadings(t *testing.T) {
	in := mongoInput()
	in.Metrics = nil
	h := Evaluate(in, now)
	if c := check(t, h, CatConnections); c.Status != "unknown" {
		t.Errorf("%+v", c)
	}
}
