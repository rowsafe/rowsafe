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

func params(t *testing.T, fx protocol.FindingFix) protocol.MaintenanceParams {
	t.Helper()
	var p protocol.MaintenanceParams
	if err := json.Unmarshal(fx.Params, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func fixIDs(f protocol.Finding) []string {
	var out []string
	for _, x := range f.Fixes {
		out = append(out, x.ID)
	}
	return out
}

func TestCleanupBlockedBySession(t *testing.T) {
	start := now.Add(-5 * time.Hour)
	in := healthy()
	in.Metrics[collect.MLongestXactSeconds] = 4 * 3600
	in.Insights = &protocol.Insights{CollectedAt: now.Add(-time.Hour), VacuumStats: []protocol.TableVacuum{
		{Database: "app", Schema: "public", Table: "orders", DeadRows: 2_000_000},
		{Database: "app", Schema: "public", Table: "items", DeadRows: 500_000},
	}}
	in.Activity = &protocol.Activity{CollectedAt: now, Queries: []protocol.ActivityQuery{}, Horizon: &protocol.CleanupHorizon{
		Sessions: []protocol.ActivityQuery{
			{PID: 42, BackendStart: &start, State: "idle in transaction", ApplicationName: "report", User: "bi", Database: "app",
				XactSeconds: 4 * 3600, DurationSeconds: 3600, XminAge: 3_000_000},
			{PID: 43, BackendStart: &start, State: "active", ApplicationName: "rowsafe-agent", XactSeconds: 5 * 3600, XminAge: 4_000_000},
			{PID: 44, BackendStart: &start, State: "active", ApplicationName: "web", XactSeconds: 60, XminAge: 10},
		},
	}}
	h := Evaluate(in, now)
	f := finding(t, h, "cleanup_blocked")
	if f.Title != "Cleanup is blocked by a transaction open for 4 hours" || f.Severity != protocol.SeverityWarning || f.Penalty != 5 {
		t.Errorf("finding: %+v", f)
	}
	if !strings.Contains(f.Explanation, "report (session 42, user bi, database app)") || !strings.Contains(f.Explanation, "2.5 million dead rows") {
		t.Errorf("explanation: %s", f.Explanation)
	}
	// Rowsafe's own session and a short one are not blockers.
	if got := fixIDs(f); !slices.Equal(got, []string{"end:42:" + itoa(start.Unix())}) || f.Command != "" {
		t.Fatalf("fixes %v command %q", got, f.Command)
	}
	if p := params(t, f.Fixes[0]); p.Action != protocol.MaintTerminateSession || p.PID != 42 || !f.Fixes[0].Destructive {
		t.Errorf("params %+v", p)
	}
	// It stands for the long transaction finding.
	if slices.Contains(ids(h), "long_transaction") {
		t.Errorf("both findings: %v", ids(h))
	}
	// Without the horizon (an older agent) the old finding remains.
	in.Activity.Horizon = nil
	if got := ids(Evaluate(in, now)); !slices.Contains(got, "long_transaction") || slices.Contains(got, "cleanup_blocked") {
		t.Errorf("older agent: %v", got)
	}
}

func TestCleanupBlockedByPreparedAndSlots(t *testing.T) {
	prepared := now.Add(-50 * time.Hour)
	in := healthy()
	in.VersionNum = 160000
	in.Activity = &protocol.Activity{CollectedAt: now, Horizon: &protocol.CleanupHorizon{
		Prepared: []protocol.PreparedXact{
			{GID: "tx-1", Database: "app", PreparedAt: prepared, Seconds: 50 * 3600, XminAge: 150_000_000},
			{GID: "tx-new", Database: "app", PreparedAt: now, Seconds: 5, XminAge: 3},
		},
	}}
	in.Slots = []protocol.ReplicationSlot{
		{Name: "cdc", Type: "logical", Database: "app", CatalogXminAge: ptr[int64](2_000_000)},
		{Name: "standby1", Type: "physical", Active: true, XminAge: ptr[int64](500_000)},
	}
	in.Replication = &protocol.ReplicationStatus{Role: "primary", Replicas: []protocol.Replica{
		{ApplicationName: "reports", XminAge: ptr[int64](20_000_000)},
	}}
	h := Evaluate(in, now)
	f := finding(t, h, "cleanup_blocked")
	if f.Title != "Cleanup is blocked by a prepared transaction left for 2 days" || f.Penalty != 10 {
		t.Errorf("finding: %+v", f)
	}
	if !strings.Contains(f.Explanation, "2 more things hold cleanup back too") {
		t.Errorf("explanation: %s", f.Explanation)
	}
	want := []string{"rollback_prepared:app:tx-1", "drop_slot:cdc", "advance_slot:cdc"}
	if got := fixIDs(f); !slices.Equal(got, want) {
		t.Fatalf("fixes %v, want %v", got, want)
	}
	rb := f.Fixes[0]
	if p := params(t, rb); p.Action != protocol.MaintRollbackPrepared || p.DB != "app" || p.GID != "tx-1" || !p.PreparedAt.Equal(prepared) || !rb.Destructive || rb.Confirm == "" {
		t.Errorf("rollback %+v %+v", rb, p)
	}
	if p := params(t, f.Fixes[2]); p.Action != protocol.MaintAdvanceReplicationSlot || p.Slot != "cdc" || !f.Fixes[2].Destructive {
		t.Errorf("advance %+v", p)
	}
	// PostgreSQL 10 can't move a slot forward: only dropping it.
	in.VersionNum = 100000
	if got := fixIDs(finding(t, Evaluate(in, now), "cleanup_blocked")); slices.Contains(got, "advance_slot:cdc") {
		t.Errorf("PostgreSQL 10: %v", got)
	}
	// A standby's queries alone: no fix, the action says what to do there.
	in.Activity, in.Slots = nil, nil
	f = finding(t, Evaluate(in, now), "cleanup_blocked")
	if f.Title != "Cleanup is blocked by queries on the replica reports" || len(f.Fixes) != 0 || !strings.Contains(f.Command, "on the replica") ||
		!strings.Contains(f.Action, "hot_standby_feedback") {
		t.Errorf("standby: %+v", f)
	}
	// Stale metrics: slots and standbys aren't acted on.
	in.Metrics = nil
	if slices.Contains(ids(Evaluate(in, now)), "cleanup_blocked") {
		t.Error("stale readings")
	}
}

func TestCleanupCatalogSlot(t *testing.T) {
	in := healthy()
	in.Slots = []protocol.ReplicationSlot{{Name: "sub", Type: "logical", Active: true, CatalogXminAge: ptr[int64](30_000_000)}}
	f := finding(t, Evaluate(in, now), "cleanup_blocked")
	if !strings.Contains(f.Explanation, "catalog") || len(f.Fixes) != 0 || f.Title != "Cleanup is blocked by the replication slot sub" {
		t.Errorf("%+v", f)
	}
}
