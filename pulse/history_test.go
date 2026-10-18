package pulse

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// hourlyDisk is 14 days of hourly free space on a 100 GB disk, starting
// at free bytes and changing by perDay.
func hourlyDisk(free, perDay float64) ForecastInput {
	var in ForecastInput
	start := now.Add(-14 * 24 * time.Hour)
	for i := range 14 * 24 {
		t := start.Add(time.Duration(i) * time.Hour)
		v := free + perDay*t.Sub(start).Hours()/24
		if i == 100 {
			v -= 20e9 // one odd reading: Theil-Sen shrugs it off
		}
		in.Free = append(in.Free, Point{t, v})
		in.Total = append(in.Total, Point{t, 100e9})
		in.DBSize = append(in.DBSize, Point{t, 100e9 - v})
	}
	return in
}

func TestTheilSen(t *testing.T) {
	var pts []Point
	for i := range 7 {
		pts = append(pts, Point{now.Add(time.Duration(i) * time.Hour), float64(i) * 3600})
	}
	pts[3].V = 1e9
	s, ok := TheilSen(pts)
	if !ok || math.Abs(s-1) > 0.01 {
		t.Fatalf("slope %v %v, want 1/s despite the outlier", s, ok)
	}
	if _, ok := TheilSen([]Point{{now, 1}, {now.Add(time.Minute), 2}}); ok {
		t.Fatal("points less than an hour apart give a slope")
	}
}

func TestForecast(t *testing.T) {
	// Filling: 40 GB free at the start, 2 GB less a day: 12 GB left now,
	// about 6 days.
	fc := Forecast(hourlyDisk(40e9, -2e9), now)
	if fc.State != protocol.ForecastFilling || fc.DaysUntilFull == nil || math.Abs(*fc.DaysUntilFull-6) > 0.3 {
		t.Fatalf("filling: %+v", fc)
	}
	if fc.GrowthBytesPerDay == nil || math.Abs(*fc.GrowthBytesPerDay-2e9) > 1e7 || !strings.Contains(fc.Summary, "2.0 GB a day") {
		t.Fatalf("growth: %v %q", fc.GrowthBytesPerDay, fc.Summary)
	}
	if fc.DatabaseGrowthBytesPerDay == nil || math.Abs(*fc.DatabaseGrowthBytesPerDay-2e9) > 1e7 {
		t.Fatalf("database growth: %v", fc.DatabaseGrowthBytesPerDay)
	}
	// Not growing.
	if fc := Forecast(hourlyDisk(40e9, 0), now); fc.State != protocol.ForecastNotGrowing {
		t.Fatalf("flat: %+v", fc)
	}
	// Shrinking.
	if fc := Forecast(hourlyDisk(10e9, 1e9), now); fc.State != protocol.ForecastNotGrowing || !strings.Contains(fc.Summary, "shrinking") {
		t.Fatalf("shrinking: %+v", fc)
	}
	// A day of history: not enough yet.
	in := hourlyDisk(40e9, -2e9)
	in.Free, in.Total = in.Free[len(in.Free)-24:], in.Total[len(in.Total)-24:]
	if fc := Forecast(in, now); fc.State != protocol.ForecastNotEnoughData || fc.FreeBytes == nil || !strings.Contains(fc.Summary, "2 days of history") {
		t.Fatalf("one day: %+v", fc)
	}
	// Nothing at all.
	if fc := Forecast(ForecastInput{}, now); fc.State != protocol.ForecastNoData {
		t.Fatalf("none: %+v", fc)
	}
	// The newest reading wins over the hourly average.
	cur := 5e9
	in = hourlyDisk(40e9, -2e9)
	in.CurFree = &cur
	if fc := Forecast(in, now); *fc.FreeBytes != 5e9 || *fc.DaysUntilFull > 3 {
		t.Fatalf("current: %+v", fc)
	}
}

func TestForecastFindings(t *testing.T) {
	in := healthy()
	in.Local = true
	in.Metrics[collect.MDiskFreePct], in.Metrics[collect.MDiskFreeBytes] = 30, 30e9
	fc := Forecast(hourlyDisk(40e9, -2e9), now) // ~6 days
	in.Forecast = &fc
	h := Evaluate(in, now)
	f := finding(t, h, "disk_full_soon")
	if f.Severity != protocol.SeverityWarning || !strings.Contains(f.Title, "6 days") || !strings.Contains(f.Explanation, "2.0 GB a day") {
		t.Fatalf("warning: %+v", f)
	}
	if c := check(t, h, CatDisk); c.Status != "warning" || !strings.Contains(c.Detail, "lasts 6 days") {
		t.Fatalf("disk check: %+v", c)
	}
	// Within 3 days: critical.
	fc = Forecast(hourlyDisk(30e9, -2e9), now) // 2 GB left
	in.Forecast = &fc
	if f := finding(t, Evaluate(in, now), "disk_full_soon"); f.Severity != protocol.SeverityCritical {
		t.Fatalf("critical: %+v", f)
	}
	// Not growing: no finding, the summary in the check.
	fc = Forecast(hourlyDisk(40e9, 0), now)
	in.Forecast = &fc
	h = Evaluate(in, now)
	if len(h.Findings) != 0 || !strings.Contains(check(t, h, CatDisk).Detail, "not growing") {
		t.Fatalf("flat: %v %+v", ids(h), check(t, h, CatDisk))
	}
	// A connection that can't see the disk (not a superuser): the agent's
	// readings stand in.
	in = healthy()
	fc = Forecast(hourlyDisk(40e9, -2e9), now)
	in.Forecast = &fc
	h = Evaluate(in, now)
	finding(t, h, "disk_full_soon")
	if c := check(t, h, CatDisk); !strings.HasPrefix(c.Detail, "12% free") {
		t.Fatalf("disk from the forecast: %+v", c)
	}
}

func TestIsRegression(t *testing.T) {
	q := "SELECT * FROM orders WHERE customer_id = $1"
	for _, c := range []struct {
		name                string
		query               string
		curCalls, prevCalls int64
		curTotal, prevTotal float64
		want                bool
	}{
		{"10x slower", q, 100, 100, 100 * 50, 100 * 5, true},
		{"not twice", q, 100, 100, 100 * 9, 100 * 5, false},
		{"too few calls", q, 10, 100, 10 * 50, 100 * 5, false},
		{"fast either way", q, 1000, 1000, 1000 * 0.5, 1000 * 0.1, false},
		{"small but many", q, 100000, 100000, 100000 * 3, 100000 * 1, true}, // 2 ms more x 100k calls
		{"monitoring", "SELECT queryid, calls FROM pg_stat_statements", 100, 100, 100 * 50, 100 * 5, false},
		{"never ran before", q, 100, 0, 100 * 50, 0, false},
	} {
		if got := IsRegression(c.query, c.curCalls, c.curTotal, c.prevCalls, c.prevTotal); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestStatementShape(t *testing.T) {
	for q, want := range map[string]string{
		`SELECT o.id FROM orders o JOIN "Customers" c ON c.id = o.customer_id WHERE o.id = $1`: "select orders Customers",
		`UPDATE public.listings SET price = $1 WHERE id = $2`:                                  "update public.listings",
		`INSERT INTO events (a, b) VALUES ($1, $2)`:                                            "insert events",
		`DELETE FROM sessions WHERE expires_at < $1`:                                           "delete sessions",
		`WITH x AS (SELECT 1) SELECT * FROM x`:                                                 "other x",
	} {
		kind, tables := statementShape(q)
		got := kind
		for _, t := range tables {
			got += " " + strings.TrimPrefix(t.schema+"."+t.name, ".")
		}
		if got != want {
			t.Errorf("%s: %q, want %q", q, got, want)
		}
	}
	if !MonitoringQuery("SELECT * FROM pg_stat_activity a JOIN pg_catalog.pg_database d ON true") || MonitoringQuery("SELECT * FROM orders") {
		t.Fatal("monitoring query")
	}
}

func TestRegressionFinding(t *testing.T) {
	in := healthy()
	in.Regressions = []Regression{
		{QueryID: "1", Query: "SELECT * FROM orders WHERE customer_id = $1", Database: "shop", CurMeanMs: 198, PrevMs: 12, Calls: 500},
		{QueryID: "2", Query: "INSERT INTO events VALUES ($1)", Database: "shop", CurMeanMs: 40, PrevMs: 10, Calls: 500},
	}
	old := now.Add(-48 * time.Hour)
	in.Insights = &protocol.Insights{CollectedAt: now, VacuumStats: []protocol.TableVacuum{
		{Database: "shop", Schema: "public", Table: "orders", LiveRows: 1000, ModsSinceAnalyze: 500, LastAutoanalyze: &old},
	}}
	in.Command = func(sub string) string { return "rowsafe " + sub + " shop" }
	h := Evaluate(in, now)
	f := finding(t, h, "query_regression")
	if f.Title != "2 queries got slower today" || f.Explanation != "The slowest: reading orders now takes 198 ms instead of 12 ms." {
		t.Fatalf("finding: %q %q", f.Title, f.Explanation)
	}
	if len(f.Fixes) != 1 || f.Fixes[0].ID != "analyze:shop" || !strings.Contains(f.Action, "Refresh the statistics") {
		t.Fatalf("fixes: %+v %q", f.Fixes, f.Action)
	}
	var p protocol.MaintenanceParams
	_ = json.Unmarshal(f.Fixes[0].Params, &p)
	if p.Action != protocol.MaintAnalyze || len(p.Tables) != 1 || p.Tables[0] != "public.orders" {
		t.Fatalf("params: %+v", p)
	}
	// Statistics just refreshed: no button, the likely causes instead.
	in.Insights.VacuumStats[0].ModsSinceAnalyze = 0
	f = finding(t, Evaluate(in, now), "query_regression")
	if len(f.Fixes) != 0 || !strings.Contains(f.Action, "rowsafe explain shop") {
		t.Fatalf("no stale statistics: %+v", f)
	}
	// One insert: its title says how much slower.
	in.Regressions = in.Regressions[1:]
	f = finding(t, Evaluate(in, now), "query_regression")
	if f.Title != "A query got 4 times slower today" || !strings.Contains(f.Action, "Inserts usually") {
		t.Fatalf("insert: %+v", f)
	}
	// The dashboard has its own.
	in.Dashboard = true
	for _, x := range Evaluate(in, now).Findings {
		if x.ID == "query_regression" {
			t.Fatal("query_regression in dashboard mode")
		}
	}
}

func TestSetProtection(t *testing.T) {
	h := Evaluate(healthy(), now)
	last := now.Add(-3 * time.Hour)
	SetProtection(&h, protocol.Protection{Protected: true, LastBackupAt: &last, LastDrillPassedAt: &last})
	if c := check(t, h, CatProtection); c.Status != "ok" || c.Detail != "Protected: continuous backups to your storage, the last backup 3 hours ago, the last restore test (Proof) passed 3 hours ago." {
		t.Fatalf("protected: %+v", c)
	}
	SetProtection(&h, protocol.Protection{Reasons: []string{"no successful backup yet"}})
	if c := check(t, h, CatProtection); c.Status != "warning" || c.Detail != "Not protected: no successful backup yet." || h.Score != 100 {
		t.Fatalf("not protected: %+v %d", c, h.Score)
	}
}
