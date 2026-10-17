package localcp

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// diskReport is a monitoring report with the disk's readings.
func diskReport(dbID string, at time.Time, free float64) protocol.MonitoringReport {
	return protocol.MonitoringReport{CollectedAt: at, Databases: []protocol.DatabaseMonitoring{{DatabaseID: dbID, Metrics: map[string]float64{
		collect.MDiskFreeBytes: free, collect.MDiskTotalBytes: 100e9, collect.MDiskFreePct: free / 1e9, collect.MDatabaseSizeBytes: 90e9 - free,
	}}}}
}

func TestHistoryDiskForecastAndAlert(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)

	if fc, err := c.DiskForecast(ctx, "shop"); err != nil || fc.State != protocol.ForecastNoData {
		t.Fatalf("before any reading: %+v %v", fc, err)
	}
	// 40 GB free, 2 GB less every day, a reading every 3 hours.
	start := *now
	free := func() float64 { return 40e9 - 2e9*now.Sub(start).Hours()/24 }
	var firing []protocol.Alert
	for *now = start; now.Sub(start) < 15*24*time.Hour; *now = now.Add(3 * time.Hour) {
		a.call("POST", "/v1/agent/monitoring", diskReport(db.ID, *now, free()), nil)
		if now.Sub(start) == 24*time.Hour {
			if fc, _ := c.DiskForecast(ctx, "shop"); fc.State != protocol.ForecastNotEnoughData || fc.FreeBytes == nil {
				t.Fatalf("after a day: %+v", fc)
			}
		}
		s.Tick()
		firing, _ = c.Alerts(ctx, "firing", 50)
	}
	fc, err := c.DiskForecast(ctx, "shop")
	if err != nil || fc.State != protocol.ForecastFilling || fc.DaysUntilFull == nil || math.Abs(*fc.DaysUntilFull-5) > 0.3 ||
		math.Abs(*fc.GrowthBytesPerDay-2e9) > 2e7 || fc.HistoryPoints < 100 {
		t.Fatalf("after 15 days: %+v %v", fc, err)
	}
	alert := func() *protocol.Alert {
		for i := range firing {
			if firing[i].Rule == "disk_full_forecast" {
				return &firing[i]
			}
		}
		return nil
	}
	if x := alert(); x == nil || x.Severity != protocol.SeverityWarning || !strings.Contains(x.Summary, "shop: the disk on db1 will be full in about 5 days") ||
		!strings.Contains(x.NextStep, "sudo rowsafe pulse shop") || x.Value == nil || *x.Value > 6 {
		t.Fatalf("disk_full_forecast: %+v", x)
	}
	// Three more days: within 3 days, critical.
	for end := now.Add(3 * 24 * time.Hour); now.Before(end); *now = now.Add(3 * time.Hour) {
		a.call("POST", "/v1/agent/monitoring", diskReport(db.ID, *now, free()), nil)
		s.Tick()
	}
	firing, _ = c.Alerts(ctx, "firing", 50)
	if x := alert(); x == nil || x.Severity != protocol.SeverityCritical {
		t.Fatalf("within 3 days: %+v", x)
	}
	// The rule is listed with the hosted one's threshold.
	rules, _ := c.AlertRules(ctx)
	if r := rules[len(rules)-1]; r.Rule != "disk_full_forecast" || *r.Threshold != 14 || r.Unit != "days" {
		t.Fatalf("rules: %+v", r)
	}
	// The space was given back: not growing any more, resolved.
	start, free = *now, func() float64 { return 60e9 }
	for end := now.Add(14 * 24 * time.Hour); now.Before(end); *now = now.Add(3 * time.Hour) {
		a.call("POST", "/v1/agent/monitoring", diskReport(db.ID, *now, free()), nil)
		s.Tick()
	}
	firing, _ = c.Alerts(ctx, "firing", 50)
	if x := alert(); x != nil {
		t.Fatalf("still firing: %+v", x)
	}
}

// queryReport is an hour's statement activity: orders' lookup takes ms
// each, the event insert a steady millisecond.
func queryReport(dbID string, at time.Time, ms float64) protocol.MonitoringReport {
	return protocol.MonitoringReport{CollectedAt: at, Databases: []protocol.DatabaseMonitoring{{DatabaseID: dbID,
		Metrics: map[string]float64{collect.MConnUsedPct: 10, collect.MConnTotal: 10, collect.MConnMax: 100, collect.MCacheHitPct: 99.9},
		Activity: &protocol.Activity{CollectedAt: at, QueryTextCollected: true, Queries: []protocol.ActivityQuery{
			{PID: 7, DurationSeconds: 90, State: "active", Query: "SELECT * FROM orders WHERE email = 'ana@example.com'"}}},
		QueryStats: &protocol.QueryStats{CollectedAt: at, IntervalSeconds: 3600, TotalCalls: 1200, TotalTimeMs: 100*ms + 1000, Statements: []protocol.QueryDelta{
			{QueryID: "101", Query: "SELECT * FROM orders WHERE customer_id = $1", Database: "shop", User: "app", Calls: 100, TotalTimeMs: 100 * ms, Rows: 100},
			{QueryID: "202", Query: "INSERT INTO events (kind) VALUES ($1)", Database: "shop", User: "app", Calls: 1000, TotalTimeMs: 1000, Rows: 1000},
		}},
	}}}
}

func TestHistoryQueries(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)
	if q, err := c.QueryTrends(ctx, "shop", client.QueryTrendsQuery{}); err != nil || q.TrendAvailable || len(q.Top) != 0 {
		t.Fatalf("before any reading: %+v %v", q, err)
	}
	if ins, err := c.Insights(ctx, "shop"); err != nil || ins.Available || ins.Reason == "" {
		t.Fatalf("insights before any reading: %+v %v", ins, err)
	}

	// Two days at 5 ms, then a day at 50 ms.
	start := *now
	for *now = start; now.Sub(start) < 72*time.Hour; *now = now.Add(time.Hour) {
		ms := 5.0
		if now.Sub(start) >= 48*time.Hour {
			ms = 50
		}
		a.call("POST", "/v1/agent/monitoring", queryReport(db.ID, *now, ms), nil)
	}
	*now = now.Add(-30 * time.Minute) // within the last hour reported
	old := now.Add(-72 * time.Hour)
	a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{Databases: []protocol.DatabaseMonitoring{{DatabaseID: db.ID,
		Metrics: map[string]float64{collect.MConnUsedPct: 10, collect.MConnTotal: 10, collect.MConnMax: 100},
		Statements: &protocol.Statements{CollectedAt: *now, Available: true, Statements: []protocol.StatementStat{{QueryID: "101", Query: "SELECT * FROM orders WHERE customer_id = $1", Calls: 7200}},
			Plans: []protocol.QueryPlan{{QueryID: "101", Summary: "Reads the whole table orders: about 2.1 million rows"}}},
		Insights: &protocol.Insights{CollectedAt: *now, VacuumStats: []protocol.TableVacuum{
			{Database: "shop", Schema: "public", Table: "orders", LiveRows: 1000, ModsSinceAnalyze: 900, LastAutoanalyze: &old}}},
	}, {DatabaseID: "db_gone", Metrics: map[string]float64{collect.MConnUsedPct: 1}}}}, nil)

	q, err := c.QueryTrends(ctx, "shop", client.QueryTrendsQuery{Since: 24 * time.Hour})
	if err != nil || !q.TrendAvailable || len(q.Top) != 2 || len(q.Statements.Statements) != 1 {
		t.Fatalf("top: %+v %v", q, err)
	}
	top := q.Top[0]
	if top.QueryID != "101" || !top.Regression || top.MeanChange == nil || *top.MeanChange != 10 || top.Calls != 2400 ||
		top.PlanSummary == "" || top.Database != "shop" || q.Top[1].Regression {
		t.Fatalf("slower query: %+v", top)
	}
	if q.Totals.Calls != 24*1200 || q.Totals.Statements != 2 || q.From == nil || now.Sub(*q.From) > 24*time.Hour {
		t.Fatalf("totals: %+v from %v", q.Totals, q.From)
	}
	if q, _ := c.QueryTrends(ctx, "shop", client.QueryTrendsQuery{Since: 24 * time.Hour, Sort: "calls"}); q.Top[0].QueryID != "202" {
		t.Fatalf("by calls: %+v", q.Top)
	}
	if _, err := c.QueryTrends(ctx, "shop", client.QueryTrendsQuery{Sort: "nope"}); apiStatus(err) != 400 {
		t.Fatalf("bad sort: %v", err)
	}
	d, err := c.QueryDetail(ctx, "shop", "101", client.QueryTrendsQuery{Since: 48 * time.Hour})
	if err != nil || len(d.Points) != 48 || d.Previous == nil || d.Previous.MeanTimeMs != 5 || d.Current.MeanTimeMs != 27.5 || d.Plan == nil {
		t.Fatalf("detail: %+v %v", d, err)
	}
	if _, err := c.QueryDetail(ctx, "shop", "999", client.QueryTrendsQuery{}); apiStatus(err) != 404 {
		t.Fatalf("unknown statement: %v", err)
	}

	// What pulse NAME adds to its own reading.
	h, err := c.LocalHistory(ctx, "shop")
	if err != nil || len(h.Regressions) != 1 || h.Regressions[0].QueryID != "101" || *h.Regressions[0].PreviousMeanTimeMs != 5 ||
		h.Since == nil || h.Protection == nil || h.Forecast.State == "" {
		t.Fatalf("history: %+v %v", h, err)
	}

	// Pulse from the agent's readings (a database without a saved
	// connection string): the slow-down, its fix offered on a connection.
	health, err := c.Health(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	var reg *protocol.Finding
	for i := range health.Findings {
		if health.Findings[i].ID == "query_regression" {
			reg = &health.Findings[i]
		}
	}
	if reg == nil || reg.Title != "A query got 10 times slower today" || len(reg.Fixes) != 1 || reg.Fixes[0].Available ||
		!strings.Contains(reg.Fixes[0].Reason, "sudo rowsafe add shop") {
		t.Fatalf("health: %+v", health)
	}
	if health.Checks[0].Category != "protection" || !strings.Contains(health.Checks[0].Detail, "rotected") || health.DiskForecast == nil {
		t.Fatalf("checks: %+v", health.Checks)
	}
	if fleet, err := c.FleetHealth(ctx); err != nil || len(fleet.Databases) != 1 || fleet.Databases[0].TopFinding == nil {
		t.Fatalf("fleet: %+v %v", fleet, err)
	}
	if ins, err := c.Insights(ctx, "shop"); err != nil || !ins.Available || len(ins.VacuumStats) != 1 {
		t.Fatalf("insights: %+v %v", ins, err)
	}

	// Kept across a restart; what's running now (its text can carry
	// values) and a database that is gone are not.
	s.hist.flush(*now)
	path := filepath.Join(filepath.Dir(s.st.path), HistoryFile)
	data, err := os.ReadFile(path)
	if err != nil || strings.Contains(string(data), "ana@example.com") || strings.Contains(string(data), "db_gone") {
		t.Fatalf("history file: %v %s", err, data)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("history file mode %v", fi.Mode())
	}
	s2, err := Open(filepath.Dir(s.st.path), nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.now = func() time.Time { return *now }
	var regs int
	s2.hist.view(db.ID, func(x *dbHistory) { regs = len(x.regressions(*now)) })
	if regs != 1 {
		t.Fatal("history lost after a restart")
	}
}

// The history stays bounded however long the server runs and however
// many different statements it sees.
func TestHistoryBounded(t *testing.T) {
	db := &dbHistory{}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	long := strings.Repeat("x", 3000)
	for i := range 40 * 24 * 4 { // 40 days, every 15 minutes
		at := start.Add(time.Duration(i) * 15 * time.Minute)
		hour := at.Truncate(time.Hour)
		qs := &protocol.QueryStats{TotalCalls: 1, TotalTimeMs: 1}
		for j := range 60 { // new statements all the time
			qs.Statements = append(qs.Statements, protocol.QueryDelta{QueryID: fmt.Sprint(i*100 + j), Query: long, Calls: 1, TotalTimeMs: float64(j)})
		}
		db.closeHours(hour)
		db.add(protocol.DatabaseMonitoring{Metrics: map[string]float64{collect.MDiskFreeBytes: 1, "other": 2}, QueryStats: qs}, hour, at)
	}
	if len(db.Hours) > keepHours || len(db.Queries) > keepQueryHours || len(db.Texts) > maxQueryTexts {
		t.Fatalf("hours %d, query hours %d, texts %d", len(db.Hours), len(db.Queries), len(db.Texts))
	}
	for _, q := range db.Queries {
		if len(q.Stats) > queriesPerHour {
			t.Fatalf("%d statements in an hour", len(q.Stats))
		}
	}
	for _, x := range db.Texts {
		if len(x.Query) > maxQueryText {
			t.Fatalf("text of %d characters", len(x.Query))
		}
	}
	if _, ok := db.Hours[0].V["other"]; ok {
		t.Fatal("a metric that isn't kept")
	}
	h := &history{path: filepath.Join(t.TempDir(), HistoryFile), h: historyData{Databases: map[string]*dbHistory{"db_1": db}}, dirty: true}
	h.flush(start)
	if fi, err := os.Stat(h.path); err != nil || fi.Size() > 4<<20 {
		t.Fatalf("history file: %v %v", fi.Size(), err)
	}
}

// A history file that can't be read doesn't stop the agent.
func TestHistoryUnreadable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, HistoryFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, nil)
	if err != nil || len(s.hist.h.Databases) != 0 {
		t.Fatalf("open: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, HistoryFile+".unreadable")); err != nil {
		t.Fatal("the unreadable file isn't kept aside")
	}
}
