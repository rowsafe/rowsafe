package pulse

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

func repackInput() Input {
	in := healthy()
	in.Metrics[collect.MDiskFreeBytes] = 50 << 30
	in.Insights = &protocol.Insights{CollectedAt: now.Add(-time.Hour),
		TableBloat: []protocol.TableBloat{
			{Database: "app", Schema: "public", Table: "orders", TableBytes: 4 << 30, BloatBytes: 2 << 30, BloatPct: 50},
			{Database: "app", Schema: "public", Table: "events", TableBytes: 1 << 30, BloatBytes: 400 << 20, BloatPct: 40},
		},
		LargestTables: []protocol.TableSize{{Database: "app", Schema: "public", Table: "orders", TotalBytes: 6 << 30, TableBytes: 4 << 30}},
	}
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now, Tools: []protocol.ToolExtension{
		{Name: protocol.ToolPgRepack, Version: "1.5.2", Program: true, Databases: []string{"app"}},
	}}
	return in
}

func TestRepackFixes(t *testing.T) {
	in := repackInput()
	b := finding(t, Evaluate(in, now), "bloat")
	if got := fixIDs(b); !slices.Equal(got[:2], []string{"repack:app.public.orders", "repack:app.public.events"}) {
		t.Fatalf("fixes %v", got)
	}
	fx := b.Fixes[0]
	if p := params(t, fx); p.Action != protocol.MaintRepackTable || p.DB != "app" || !slices.Equal(p.Tables, []string{"public.orders"}) {
		t.Errorf("params %+v", p)
	}
	if !fx.Available || fx.Confirm == "" || fx.Destructive || !strings.Contains(fx.Description, "8.0 GB") || b.Command != "" ||
		!strings.Contains(b.Action, "pg_repack") || strings.Contains(fx.Description, "turns on") {
		t.Errorf("fix %+v, finding %+v", fx, b)
	}
	// Not enough disk for the copy: shown, not available.
	in.Metrics[collect.MDiskFreeBytes] = 3 << 30
	if fx := finding(t, Evaluate(in, now), "bloat").Fixes[0]; fx.Available || !strings.Contains(fx.Reason, "free disk") {
		t.Errorf("low disk: %+v", fx)
	}
	// The extension not on yet: the fix turns it on first.
	in = repackInput()
	in.Settings.Tools[0].Databases = nil
	if fx := finding(t, Evaluate(in, now), "bloat").Fixes[0]; !strings.Contains(fx.Description, "turns on the pg_repack extension in app") {
		t.Errorf("extension off: %+v", fx)
	}
	// No program, or no package: the old advice.
	in.Settings.Tools[0].Program = false
	b = finding(t, Evaluate(in, now), "bloat")
	if slices.ContainsFunc(b.Fixes, func(f protocol.FindingFix) bool { return strings.HasPrefix(f.ID, "repack:") }) || !strings.Contains(b.Command, "pg_repack") {
		t.Errorf("no program: %+v", b)
	}
	in.Settings.Tools = nil
	if b := finding(t, Evaluate(in, now), "bloat"); strings.HasPrefix(b.Fixes[0].ID, "repack:") {
		t.Errorf("no package: %+v", b.Fixes)
	}
}
