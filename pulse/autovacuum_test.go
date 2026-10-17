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

func TestMultixactWraparound(t *testing.T) {
	in := healthy()
	in.Metrics[collect.MMultixactHeadroomPct] = 15
	in.Insights = &protocol.Insights{CollectedAt: now.Add(-time.Hour), MultixactAge: []protocol.TableFreeze{
		{Database: "app", Schema: "public", Table: "orders", MXIDAge: 1_900_000_000},
		{Database: "app", Schema: "public", Table: "items", MXIDAge: 1_800_000_000},
	}}
	f := finding(t, Evaluate(in, now), "multixact_wraparound")
	if f.Severity != protocol.SeverityCritical || f.Penalty != 30 || !strings.Contains(f.Explanation, "15%") || f.Command != "" {
		t.Errorf("critical: %+v", f)
	}
	if len(f.Fixes) != 1 || f.Fixes[0].ID != "freeze:app" {
		t.Fatalf("fixes %+v", f.Fixes)
	}
	if p := params(t, f.Fixes[0]); p.Action != protocol.MaintVacuum || !p.Freeze || !slices.Equal(p.Tables, []string{"public.orders", "public.items"}) {
		t.Errorf("params %+v", p)
	}
	in.Metrics[collect.MMultixactHeadroomPct] = 40
	if f := finding(t, Evaluate(in, now), "multixact_wraparound"); f.Severity != protocol.SeverityWarning || f.Penalty != 15 {
		t.Errorf("warning: %+v", f)
	}
	// Without the tables (older insights): advice and a command.
	in.Insights = nil
	if f := finding(t, Evaluate(in, now), "multixact_wraparound"); len(f.Fixes) != 0 {
		t.Errorf("no tables: %+v", f)
	}
	in.Metrics[collect.MMultixactHeadroomPct] = 60
	if slices.Contains(ids(Evaluate(in, now)), "multixact_wraparound") {
		t.Error("60% headroom flagged")
	}
	in.Metrics[collect.MMultixactHeadroomPct] = 15
	in.Insights = &protocol.Insights{CollectedAt: now}
	if f := finding(t, Evaluate(in, now), "multixact_wraparound"); f.Command == "" {
		t.Errorf("no fix and no command: %+v", f)
	}
}

func autovacuumInput(busyMin float64, waiting int) Input {
	in := healthy()
	in.Metrics[collect.MAutovacuumWorkers], in.Metrics[collect.MAutovacuumMaxWorkers] = 3, 3
	in.Metrics[collect.MAutovacuumBusyMin] = busyMin
	in.Insights = &protocol.Insights{CollectedAt: now.Add(-time.Hour), Autovacuum: &protocol.AutovacuumBacklog{Waiting: waiting, DeadRows: 4_000_000,
		Tables: []protocol.TableVacuum{{Database: "app", Schema: "public", Table: "events", DeadRows: 3_000_000}}}}
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now, VersionNum: 170000, Settings: []protocol.PGSetting{
		setting("autovacuum_max_workers", "3", ""),
		setting("autovacuum_vacuum_cost_limit", "-1", ""),
	}}
	return in
}

func TestAutovacuumSaturated(t *testing.T) {
	in := autovacuumInput(45, 12)
	f := finding(t, Evaluate(in, now), "autovacuum_saturated")
	if f.Severity != protocol.SeverityWarning || f.Title != "Cleanup can't keep up: all 3 autovacuum workers busy for 45 minutes" ||
		!strings.Contains(f.Explanation, "12 tables wait their turn with 4.0 million dead rows (the most: events, 3.0 million)") {
		t.Errorf("finding: %+v", f)
	}
	if len(f.Fixes) != 1 || f.Fixes[0].ID != "autovacuum_capacity" || f.Fixes[0].Kind != protocol.FixTune || f.Fixes[0].Confirm == "" || f.Command != "" {
		t.Fatalf("fixes %+v", f.Fixes)
	}
	var p protocol.SettingsParams
	if err := json.Unmarshal(f.Fixes[0].Params, &p); err != nil {
		t.Fatal(err)
	}
	want := []protocol.SettingChange{{Name: "autovacuum_max_workers", Value: "5"}, {Name: "autovacuum_vacuum_cost_limit", Value: "1000"}}
	if p.Kind != protocol.SettingsKindFix || !slices.Equal(p.Changes, want) {
		t.Errorf("changes %+v", p.Changes)
	}
	// Before PostgreSQL 18 more workers need a restart, and the fix says so.
	if fx := f.Fixes[0]; !strings.Contains(fx.Description, "need a restart") || !strings.Contains(fx.Confirm, "after a restart") {
		t.Errorf("restart not said: %+v", fx)
	}
	// PostgreSQL 18: workers change on reload, up to autovacuum_worker_slots.
	in = autovacuumInput(45, 12)
	in.Settings.VersionNum = 180000
	in.Settings.Settings[0].Context = "sighup"
	in.Settings.Settings = append(in.Settings.Settings, setting("autovacuum_worker_slots", "16", ""))
	fx := finding(t, Evaluate(in, now), "autovacuum_saturated").Fixes[0]
	if err := json.Unmarshal(fx.Params, &p); err != nil || !slices.Equal(p.Changes, want) || strings.Contains(fx.Description, "restart") ||
		strings.Contains(fx.Confirm, "after a restart") {
		t.Errorf("PostgreSQL 18 reload: %+v %+v", fx, p.Changes)
	}
	// ... and past the slots, the slots too, with a restart.
	in.Settings.Settings[2].Setting = "3"
	fx = finding(t, Evaluate(in, now), "autovacuum_saturated").Fixes[0]
	p = protocol.SettingsParams{}
	_ = json.Unmarshal(fx.Params, &p)
	if !slices.Contains(p.Changes, protocol.SettingChange{Name: "autovacuum_worker_slots", Value: "5"}) || !strings.Contains(fx.Description, "need a restart") {
		t.Errorf("PostgreSQL 18 slots: %+v %+v", fx, p.Changes)
	}
	// Busy now with tables waiting, not for long: a suggestion.
	if f := finding(t, Evaluate(autovacuumInput(5, 4), now), "autovacuum_saturated"); f.Severity != protocol.SeverityInfo || !strings.Contains(f.Title, "4 tables are waiting") {
		t.Errorf("info: %+v", f)
	}
	// A free worker, or busy briefly with little waiting: nothing.
	in = autovacuumInput(45, 12)
	in.Metrics[collect.MAutovacuumWorkers] = 2
	if slices.Contains(ids(Evaluate(in, now)), "autovacuum_saturated") {
		t.Error("a free worker")
	}
	if slices.Contains(ids(Evaluate(autovacuumInput(5, 1), now)), "autovacuum_saturated") {
		t.Error("briefly busy")
	}
	// More workers already set: the restart is the fix.
	in = autovacuumInput(45, 12)
	in.Settings.Settings[0].PendingRestart, in.Settings.Settings[0].PendingValue = true, "5"
	restart := protocol.FindingFix{ID: "restart", Kind: protocol.FixRestart, Available: true}
	in.RestartFixes = []protocol.FindingFix{restart}
	if f := finding(t, Evaluate(in, now), "autovacuum_saturated"); len(f.Fixes) != 1 || f.Fixes[0].ID != "restart" || !strings.Contains(f.Action, "restarts") {
		t.Errorf("pending: %+v", f)
	}
	// At the most workers and a high cost limit: nothing left to raise.
	in = autovacuumInput(45, 12)
	in.Settings.Settings = []protocol.PGSetting{setting("autovacuum_max_workers", "10", ""), setting("autovacuum_vacuum_cost_limit", "2000", "")}
	if f := finding(t, Evaluate(in, now), "autovacuum_saturated"); len(f.Fixes) != 0 || f.Command == "" {
		t.Errorf("nothing to raise: %+v", f)
	}
}
