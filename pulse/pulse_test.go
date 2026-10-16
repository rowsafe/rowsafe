package pulse

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

var now = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

func ids(h protocol.DatabaseHealth) []string {
	var out []string
	for _, f := range h.Findings {
		out = append(out, f.ID)
	}
	return out
}

func finding(t *testing.T, h protocol.DatabaseHealth, id string) protocol.Finding {
	t.Helper()
	for _, f := range h.Findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("no finding %s in %v", id, ids(h))
	return protocol.Finding{}
}

func check(t *testing.T, h protocol.DatabaseHealth, cat string) protocol.HealthCheck {
	t.Helper()
	for _, c := range h.Checks {
		if c.Category == cat {
			return c
		}
	}
	t.Fatalf("no check %s", cat)
	return protocol.HealthCheck{}
}

func healthy() Input {
	return Input{Database: "app", Host: "db.example.com", Metrics: map[string]float64{
		collect.MConnUsedPct: 10, collect.MConnTotal: 10, collect.MConnMax: 100, collect.MXIDHeadroomPct: 95,
		collect.MCacheHitPct: 99.5,
	}}
}

func TestHealthy(t *testing.T) {
	h := Evaluate(healthy(), now)
	if h.Score != 100 || h.Grade != protocol.GradeHealthy || len(h.Findings) != 0 || h.Summary != "Everything looks good." {
		t.Fatalf("got %d %s %v %q", h.Score, h.Grade, ids(h), h.Summary)
	}
	if c := check(t, h, CatProtection); c.Status != "unknown" || !strings.Contains(c.Detail, "agent") {
		t.Errorf("backups check: %+v", c)
	}
	// The disk is checked only when the database runs here.
	if slices.ContainsFunc(h.Checks, func(c protocol.HealthCheck) bool { return c.Category == CatDisk }) {
		t.Error("disk checked for a database on another machine")
	}
	in := healthy()
	in.Local = true
	if c := check(t, Evaluate(in, now), CatDisk); c.Status != "unknown" {
		t.Errorf("local disk without readings: %+v", c)
	}
}

func TestNoReadings(t *testing.T) {
	h := Evaluate(Input{Database: "app"}, now)
	if h.Score != 100 || len(h.Findings) != 0 {
		t.Fatalf("got %d %v", h.Score, ids(h))
	}
	for _, cat := range []string{CatConnections, CatMaintenance, CatPerformance, CatReplication} {
		if c := check(t, h, cat); c.Status != "unknown" {
			t.Errorf("%s: %+v", cat, c)
		}
	}
}

func TestScoreCaps(t *testing.T) {
	// A critical finding caps the score at 59, a warning at 89; a
	// category never takes off more than its cap.
	crit := []protocol.Finding{{Category: CatConnections, Severity: protocol.SeverityCritical, Penalty: 15}}
	if s := Score(crit); s != 59 {
		t.Errorf("critical: %d", s)
	}
	warn := []protocol.Finding{{Category: CatPerformance, Severity: protocol.SeverityWarning, Penalty: 5}}
	if s := Score(warn); s != 89 {
		t.Errorf("warning: %d", s)
	}
	many := []protocol.Finding{
		{Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 10},
		{Category: CatPerformance, Severity: protocol.SeverityInfo, Penalty: 10},
	}
	if s := Score(many); s != 85 {
		t.Errorf("performance cap: %d", s)
	}
	for score, grade := range map[int]string{100: protocol.GradeHealthy, 90: protocol.GradeHealthy, 89: protocol.GradeNeedsAttention,
		70: protocol.GradeNeedsAttention, 69: protocol.GradeAtRisk, 50: protocol.GradeAtRisk, 49: protocol.GradeCritical} {
		if g := Grade(score); g != grade {
			t.Errorf("Grade(%d) = %s", score, g)
		}
	}
}

func TestConnectionsAndSessions(t *testing.T) {
	start := now.Add(-time.Hour)
	in := healthy()
	in.Metrics[collect.MConnUsedPct], in.Metrics[collect.MConnTotal] = 97, 97
	in.Metrics[collect.MIdleInXactOldest] = 20 * 60
	in.Activity = &protocol.Activity{CollectedAt: now, Queries: []protocol.ActivityQuery{
		{PID: 11, BackendStart: &start, State: "idle in transaction", ApplicationName: "web", DurationSeconds: 1200, XactSeconds: 1300},
		{PID: 12, BackendStart: &start, State: "idle in transaction", ApplicationName: "rowsafe-agent", DurationSeconds: 1200},
		{PID: 13, BackendStart: nil, State: "idle in transaction", DurationSeconds: 1200},
	}}
	h := Evaluate(in, now)
	f := finding(t, h, "connections_exhausted")
	if f.Severity != protocol.SeverityCritical || h.Score > 59 {
		t.Errorf("%+v score %d", f, h.Score)
	}
	// Only the app's own session with a known start is offered.
	if len(f.Fixes) != 1 || f.Fixes[0].ID != "end:11:"+itoa(start.Unix()) || f.Fixes[0].Confirm == "" || !f.Fixes[0].Destructive {
		t.Fatalf("fixes: %+v", f.Fixes)
	}
	var p protocol.MaintenanceParams
	if err := json.Unmarshal(f.Fixes[0].Params, &p); err != nil || p.Action != protocol.MaintTerminateSession || p.PID != 11 || !p.BackendStart.Equal(start) {
		t.Errorf("params %+v %v", p, err)
	}
	if f := finding(t, h, "idle_in_transaction"); len(f.Fixes) != 1 {
		t.Errorf("idle fixes: %+v", f.Fixes)
	}
	// A stale activity snapshot offers nothing to end.
	in.Activity.CollectedAt = now.Add(-10 * time.Minute)
	if f := finding(t, Evaluate(in, now), "connections_exhausted"); len(f.Fixes) != 0 || f.Command == "" {
		t.Errorf("stale snapshot: %+v", f)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestMaintenance(t *testing.T) {
	in := healthy()
	in.Metrics[collect.MXIDHeadroomPct] = 15
	in.Insights = &protocol.Insights{CollectedAt: now.Add(-time.Hour),
		FreezeAge: []protocol.TableFreeze{{Database: "app", Schema: "public", Table: "events"}},
		VacuumStats: []protocol.TableVacuum{
			{Database: "app", Schema: "public", Table: "orders", DeadRows: 200_000, DeadPct: 60},
			{Database: "app", Schema: "public", Table: "fresh", DeadRows: 200_000, DeadPct: 60, LastAutovacuum: ptr(now.Add(-time.Hour))},
			{Database: "app", Schema: "public", Table: "small", DeadRows: 50, DeadPct: 90},
		},
		TableBloat: []protocol.TableBloat{{Database: "app", Schema: "public", Table: "orders", TableBytes: 4 << 30, BloatBytes: 2 << 30, BloatPct: 50}},
		IndexBloat: []protocol.IndexBloat{{Database: "app", Schema: "public", Table: "orders", Index: "orders_idx", IndexBytes: 1 << 30, BloatBytes: 600 << 20, BloatPct: 60}},
	}
	in.VersionNum = 170000
	h := Evaluate(in, now)
	x := finding(t, h, "xid_wraparound")
	if x.Severity != protocol.SeverityCritical || len(x.Fixes) != 1 || x.Fixes[0].ID != "freeze:app" {
		t.Errorf("xid: %+v", x)
	}
	v := finding(t, h, "vacuum_behind")
	if !strings.Contains(v.Title, "1 table") || len(v.Fixes) != 1 || v.Fixes[0].ID != "vacuum:app" {
		t.Errorf("vacuum_behind: %+v", v)
	}
	var p protocol.MaintenanceParams
	_ = json.Unmarshal(v.Fixes[0].Params, &p)
	if p.Action != protocol.MaintVacuum || p.DB != "app" || !slices.Equal(p.Tables, []string{"public.orders"}) {
		t.Errorf("vacuum params %+v", p)
	}
	b := finding(t, h, "bloat")
	if b.Severity != protocol.SeverityWarning || len(b.Fixes) != 2 || b.Fixes[0].ID != "reindex:app.public.orders_idx" {
		t.Errorf("bloat: %+v", b)
	}
	if c := check(t, h, CatMaintenance); c.Status != "critical" {
		t.Errorf("check %+v", c)
	}
	// REINDEX CONCURRENTLY needs PostgreSQL 12.
	in.VersionNum = 110000
	if b := finding(t, Evaluate(in, now), "bloat"); b.Fixes[0].Available || b.Fixes[0].Reason == "" {
		t.Errorf("PostgreSQL 11 reindex: %+v", b.Fixes[0])
	}
	// Old insights aren't acted on.
	in.Insights.CollectedAt = now.Add(-7 * time.Hour)
	if got := ids(Evaluate(in, now)); slices.Contains(got, "vacuum_behind") || slices.Contains(got, "bloat") {
		t.Errorf("stale insights: %v", got)
	}
}

func TestIndexes(t *testing.T) {
	in := healthy()
	in.Insights = &protocol.Insights{CollectedAt: now,
		UnusedIndexes: []protocol.UnusedIndex{
			{Database: "app", Schema: "public", Table: "orders", Index: "orders_status", Bytes: 50 << 20},
			{Database: "app", Schema: "public", Table: "orders", Index: "tiny", Bytes: 1 << 20},
		},
		DuplicateIndexes: []protocol.DuplicateIndex{
			{Database: "app", Schema: "public", Table: "orders", Index: "orders_id_dup", CoveredBy: "orders_pkey", Bytes: 1 << 20},
			{Database: "app_copy", Schema: "public", Table: "orders", Index: "orders_id_dup", CoveredBy: "orders_pkey", Bytes: 1 << 20},
		},
		SeqScanTables: []protocol.SeqScanTable{{Database: "app", Schema: "public", Table: "events", SeqScans: 500, SeqRows: 5_000_000, LiveRows: 100_000}},
	}
	in.Command = func(sub string) string { return "rowsafe " + sub + " 'postgres://app@db/app?sslmode=require'" }
	h := Evaluate(in, now)
	u := finding(t, h, "unused_indexes")
	if !strings.HasPrefix(u.Title, "1 index is never used") || len(u.Fixes) != 1 || u.Fixes[0].ID != "drop:app.public.orders_status" {
		t.Errorf("unused: %+v", u)
	}
	var p protocol.MaintenanceParams
	_ = json.Unmarshal(u.Fixes[0].Params, &p)
	if p.Action != protocol.MaintDropIndex || !p.Unused || p.Index != "public.orders_status" {
		t.Errorf("unused params %+v", p)
	}
	d := finding(t, h, "duplicate_indexes")
	// Same index name in two databases: the labels say which.
	if len(d.Fixes) != 2 || d.Fixes[0].Label != "Drop orders_id_dup in app" || d.Fixes[1].Label != "Drop orders_id_dup in app_copy" {
		t.Errorf("duplicate fixes: %+v", d.Fixes)
	}
	m := finding(t, h, "missing_index")
	if !strings.Contains(m.Action, "rowsafe top 'postgres://app@db/app?sslmode=require'") {
		t.Errorf("missing_index action: %s", m.Action)
	}
}

func TestReplication(t *testing.T) {
	in := healthy()
	in.Metrics[collect.MSlotInactiveRetain] = 3 << 30
	in.Metrics[collect.MReplicationLagSeconds] = 2000
	in.Slots = []protocol.ReplicationSlot{
		{Name: "old_replica", Type: "physical", RetainedBytes: ptr(int64(3 << 30))},
		{Name: "live", Type: "physical", Active: true, RetainedBytes: ptr(int64(5 << 30))},
	}
	in.Replication = &protocol.ReplicationStatus{Role: "primary", Replicas: []protocol.Replica{{ReplayLagSeconds: ptr(2000.0)}}}
	h := Evaluate(in, now)
	s := finding(t, h, "inactive_slot")
	if len(s.Fixes) != 1 || s.Fixes[0].ID != "drop_slot:old_replica" || !s.Fixes[0].Destructive {
		t.Errorf("slot: %+v", s)
	}
	if l := finding(t, h, "replication_lag"); l.Severity != protocol.SeverityCritical {
		t.Errorf("lag: %+v", l)
	}
	if c := check(t, h, CatReplication); c.Status != "critical" {
		t.Errorf("check %+v", c)
	}
}

func TestDisk(t *testing.T) {
	in := healthy()
	in.Local = true
	in.Metrics[collect.MDiskFreePct], in.Metrics[collect.MDiskFreeBytes] = 3, 2e9
	h := Evaluate(in, now)
	if f := finding(t, h, "disk_almost_full"); f.Severity != protocol.SeverityCritical {
		t.Errorf("%+v", f)
	}
	// A database on another machine: this machine's disk says nothing.
	in.Local = false
	if slices.Contains(ids(Evaluate(in, now)), "disk_almost_full") {
		t.Error("remote database judged by this machine's disk")
	}
}

func setting(name, value, unit string) protocol.PGSetting {
	return protocol.PGSetting{Name: name, Setting: value, Unit: unit, Source: "configuration file", Context: "postmaster", VarType: "integer"}
}

func TestSettings(t *testing.T) {
	in := healthy()
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now, VersionNum: 170000, PgStatStatements: "available",
		Host: protocol.SettingsHost{MemoryBytes: 16 << 30, CPUs: 4},
		Settings: []protocol.PGSetting{
			setting("shared_buffers", "16384", "8kB"), // 128 MB
			setting("max_connections", "100", ""),
			{Name: "shared_preload_libraries", Setting: "", Source: "default", Context: "postmaster", VarType: "string"},
		}}
	h := Evaluate(in, now)
	m := finding(t, h, "default_memory_settings")
	if len(m.Fixes) != 1 || m.Fixes[0].Kind != protocol.FixTune || m.Fixes[0].Confirm == "" {
		t.Fatalf("memory: %+v", m)
	}
	var p protocol.SettingsParams
	_ = json.Unmarshal(m.Fixes[0].Params, &p)
	if p.Kind != protocol.SettingsKindFix || !slices.ContainsFunc(p.Changes, func(c protocol.SettingChange) bool { return c.Name == "shared_buffers" }) {
		t.Errorf("tune params %+v", p)
	}
	s := finding(t, h, "pg_stat_statements_off")
	_ = json.Unmarshal(s.Fixes[0].Params, &p)
	if len(p.Changes) != 1 || p.Changes[0].Value != "pg_stat_statements" {
		t.Errorf("pg_stat_statements params %+v", p)
	}
	// Memory unknown (a server Rowsafe can't see): no memory finding.
	in.Settings.Host.MemoryBytes = 0
	if slices.Contains(ids(Evaluate(in, now)), "default_memory_settings") {
		t.Error("memory finding without the server's memory")
	}
	// A standby: settings change on the primary.
	in.Settings.InRecovery = true
	if s := finding(t, Evaluate(in, now), "pg_stat_statements_off"); s.Fixes[0].Available {
		t.Errorf("standby fix available: %+v", s.Fixes[0])
	}
}

func TestPendingRestart(t *testing.T) {
	in := healthy()
	sb := setting("shared_buffers", "16384", "8kB")
	sb.PendingRestart, sb.PendingValue = true, "524288" // 4 GB
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now, Settings: []protocol.PGSetting{sb}}
	in.Local = true
	f := finding(t, Evaluate(in, now), "settings_pending_restart")
	if !strings.Contains(f.Title, "More memory for PostgreSQL") || f.Command == "" {
		t.Errorf("%+v", f)
	}
	// Elsewhere (a managed database), no command to run here.
	in.Local = false
	if f := finding(t, Evaluate(in, now), "settings_pending_restart"); f.Command != "" {
		t.Errorf("remote restart command: %q", f.Command)
	}
}

func TestDeterministicOrder(t *testing.T) {
	in := healthy()
	in.Metrics[collect.MConnUsedPct] = 85
	in.Metrics[collect.MXIDHeadroomPct] = 10
	in.Insights = &protocol.Insights{CollectedAt: now,
		DuplicateIndexes: []protocol.DuplicateIndex{{Database: "app", Schema: "public", Table: "t", Index: "i", CoveredBy: "j"}}}
	h := Evaluate(in, now)
	got := ids(h)
	if got[0] != "xid_wraparound" || got[1] != "connections_high" || got[len(got)-1] != "duplicate_indexes" {
		t.Errorf("order %v", got)
	}
	if !strings.HasPrefix(h.Summary, "Needs attention now: Close to a forced write stop") {
		t.Errorf("summary %q", h.Summary)
	}
}

func TestLowerFirst(t *testing.T) {
	for in, want := range map[string]string{"20 indexes repeat": "20 indexes repeat", "Only 80% of reads": "only 80% of reads",
		"PostgreSQL is using": "PostgreSQL is using", "WAL piles up": "WAL piles up", "": ""} {
		if got := lowerFirst(in); got != want {
			t.Errorf("lowerFirst(%q) = %q", in, got)
		}
	}
}

func TestSettingsLocked(t *testing.T) {
	in := healthy()
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now, PgStatStatements: "available",
		Settings: []protocol.PGSetting{{Name: "shared_preload_libraries", Source: "default", Context: "postmaster", VarType: "string"}}}
	in.SettingsLocked = "Changing settings needs a superuser."
	f := finding(t, Evaluate(in, now), "pg_stat_statements_off")
	if f.Fixes[0].Available || f.Fixes[0].Reason != in.SettingsLocked {
		t.Errorf("%+v", f.Fixes[0])
	}
}

func TestDashboardMode(t *testing.T) {
	start := now.Add(-time.Hour)
	in := healthy()
	in.Dashboard, in.MarkFirst, in.Host = true, true, "db1"
	in.Metrics[collect.MConnUsedPct], in.Metrics[collect.MConnTotal] = 97, 97
	in.Metrics[collect.MLongestBlockedSeconds], in.Metrics[collect.MBlockedSessions] = 400, 2
	in.Activity = &protocol.Activity{CollectedAt: now, Queries: []protocol.ActivityQuery{
		{PID: 11, BackendStart: &start, State: "idle in transaction", DurationSeconds: 1200}},
		Blocking: []protocol.LockSession{{PID: 12, BackendStart: &start, State: "active", Blocking: 2}}}
	in.Insights = &protocol.Insights{CollectedAt: now,
		UnusedIndexes: []protocol.UnusedIndex{{Database: "app", Schema: "public", Table: "orders", Index: "orders_status", Bytes: 50 << 20}}}
	sb := setting("shared_buffers", "16384", "8kB")
	sb.PendingRestart, sb.PendingValue = true, "524288"
	in.Settings = &protocol.SettingsSnapshot{CollectedAt: now, Host: protocol.SettingsHost{MemoryBytes: 16 << 30, CPUs: 4},
		Settings: []protocol.PGSetting{sb, setting("max_connections", "100", "")}}
	pooling := protocol.FindingFix{ID: "pooling", Kind: protocol.FixPooling, Label: "Turn on pooling", Available: true}
	restart := protocol.FindingFix{ID: "restart", Kind: protocol.FixRestart, Label: "Restart PostgreSQL", Available: false, Reason: "not allowed"}
	in.ConnectionFixes, in.RestartFixes = []protocol.FindingFix{pooling}, []protocol.FindingFix{restart}
	var seen []string
	in.Fix = func(fx protocol.FindingFix) protocol.FindingFix {
		seen = append(seen, fx.ID)
		if fx.Kind == protocol.FixMaintenance && strings.HasPrefix(fx.ID, "cancel:") {
			fx.Available, fx.Reason = false, "busy"
		}
		return fx
	}
	var points []string
	in.Extra = func(point string, sofar []protocol.Finding) []protocol.Finding {
		points = append(points, point)
		if point == PointAfterCache && !slices.ContainsFunc(sofar, func(f protocol.Finding) bool { return f.ID == "blocked_queries" }) {
			t.Error("Extra doesn't see the findings so far")
		}
		if point == PointEnd {
			return []protocol.Finding{{ID: "deadlocks", Category: CatPerformance, Severity: protocol.SeverityWarning, Title: "Transactions are deadlocking", Penalty: 2}}
		}
		return nil
	}
	h := Evaluate(in, now)
	if !slices.Equal(points, []string{PointAfterCache, PointAfterIndexes, PointAfterStatements, PointEnd}) {
		t.Errorf("points %v", points)
	}
	if c := check(t, h, CatPerformance); c.Status != "warning" {
		t.Errorf("performance check doesn't count Extra's findings: %+v", c)
	}
	c := finding(t, h, "connections_exhausted")
	if c.Fixes[len(c.Fixes)-1].ID != "pooling" {
		t.Errorf("connection fixes %+v", c.Fixes)
	}
	b := finding(t, h, "blocked_queries")
	if len(seen) == 0 || b.Fixes[0].Available || b.Fixes[0].Reason != "busy" {
		t.Errorf("Fix hook not applied: %+v (seen %v)", b.Fixes, seen)
	}
	u := finding(t, h, "unused_indexes")
	if !u.Fixes[0].MarkFirst || !strings.Contains(u.Fixes[0].Description, "Rowsafe saves a Mark first") {
		t.Errorf("drop fix: %+v", u.Fixes[0])
	}
	p := finding(t, h, "settings_pending_restart")
	if len(p.Fixes) != 1 || p.Fixes[0].ID != "restart" || p.Command != "sudo systemctl restart postgresql" {
		t.Errorf("pending restart: %+v", p)
	}
	for _, f := range h.Findings {
		if strings.Contains(f.Action, "rowsafe ") {
			t.Errorf("%s tells people to run a command in the dashboard: %s", f.ID, f.Action)
		}
	}
	in.SkipPendingRestart = true
	if slices.Contains(ids(Evaluate(in, now)), "settings_pending_restart") {
		t.Error("SkipPendingRestart")
	}
}

func TestRulesSections(t *testing.T) {
	in := healthy()
	in.Metrics[collect.MConnUsedPct] = 85
	r := NewRules(in, now)
	f, c := r.Connections(true)
	if len(f) != 1 || f[0].ID != "connections_high" || c.Category != CatConnections || c.Status != "warning" {
		t.Errorf("connections %+v %+v", f, c)
	}
	f, c = r.Maintenance(false)
	if len(f) != 0 || c.Status != "unknown" {
		t.Errorf("maintenance without readings %+v %+v", f, c)
	}
	if f, c := r.Replication(true); len(f) != 0 || c.Detail != "No replicas." {
		t.Errorf("replication %+v %+v", f, c)
	}
}
