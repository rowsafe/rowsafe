package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// The dashboard's reads (alerts, activity, metrics, security, updates, ...)
// and the actions that never change production.

const secretMark = "SECRETXYZ"

type apiCall struct {
	Method, Path, Query string
	Body                []byte
}

// dashAPI answers the endpoints the new tools use and records every call.
type dashAPI struct {
	t     *testing.T
	mu    sync.Mutex
	calls []apiCall
}

func (f *dashAPI) take() []apiCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.calls
	f.calls = nil
	return c
}

func (f *dashAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.calls = append(f.calls, apiCall{r.Method, r.URL.Path, r.URL.RawQuery, body})
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	at := time.Now().Add(-2 * time.Hour).UTC()
	v, status := f.answer(r, at)
	if v == nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
		return
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *dashAPI) answer(r *http.Request, at time.Time) (any, int) {
	p := r.URL.Path
	val := 92.5
	thr := 90.0
	ok := http.StatusOK
	task := func(id, typ string) protocol.TaskView {
		return protocol.TaskView{ID: id, Type: typ, Status: protocol.StatusQueued, DatabaseID: "db_app", CreatedAt: at}
	}
	if r.Method == http.MethodGet {
		switch p {
		case "/v1/databases/app", "/v1/databases/db_app":
			return protocol.Database{ID: "db_app", Name: "app", HostID: "h_1", Hostname: "db1", Status: protocol.DBActive}, ok
		case "/v1/databases/mongo":
			return protocol.Database{ID: "db_mongo", Name: "mongo", HostID: "h_1", Hostname: "db1", Engine: protocol.EngineMongoDB}, ok
		case "/v1/databases/legacy":
			return protocol.Database{ID: "db_legacy", Name: "legacy", HostID: "h_1", Hostname: "db1", Engine: "cassandra"}, ok
		case "/v1/databases/shop":
			return protocol.Database{ID: "db_shop", Name: "shop", HostID: "h_1", Hostname: "db1", Engine: protocol.EngineMySQL}, ok
		case "/v1/alerts":
			return []protocol.Alert{{ID: "al_1", Rule: "disk_used", Severity: protocol.SeverityWarning, State: protocol.AlertFiring,
				Database: &protocol.AlertDatabase{ID: "db_app", Name: "app"}, Host: &protocol.AlertHost{ID: "h_1", Hostname: "db1"},
				Summary: "Disk 92% full", Description: "The data directory's disk is almost full.", NextStep: "Free space or grow the disk.",
				Value: &val, Threshold: &thr, Unit: "%", StartedAt: at}}, ok
		case "/v1/alerts/al_1":
			return protocol.Alert{ID: "al_1", Rule: "disk_used", Severity: protocol.SeverityWarning, State: protocol.AlertFiring, Summary: "Disk 92% full", StartedAt: at}, ok
		case "/v1/alert-rules":
			return []protocol.AlertRule{{Rule: "disk_used", Title: "Disk almost full", Scope: "database", Enabled: true, Threshold: &thr, Unit: "%", ForSeconds: 300, Severity: protocol.SeverityWarning}}, ok
		case "/v1/notification-channels":
			return []protocol.NotificationChannel{
				{ID: "nc_1", Type: protocol.ChannelSlack, Name: "Ops", Config: protocol.ChannelConfig{URL: "https://hooks.slack.com/services/T0/B0/" + secretMark},
					MinSeverity: protocol.SeverityWarning, LastError: `Post "https://hooks.slack.com/services/T0/B0/` + secretMark + `": timeout`, SigningSecret: "whsec_" + secretMark},
				{ID: "nc_2", Type: protocol.ChannelEmail, Name: "Team", Config: protocol.ChannelConfig{Addresses: []string{secretMark + "@example.com"}}},
			}, ok
		case "/v1/databases/db_app/activity":
			return protocol.Activity{CollectedAt: time.Now().Add(-30 * time.Second), QueryTextCollected: true,
				Queries: []protocol.ActivityQuery{
					{PID: 11, DurationSeconds: 4, State: "active", User: "app", Query: "SELECT 1"},
					{PID: 12, DurationSeconds: 95, State: "active", User: "app", WaitEventType: "Lock", WaitEvent: "relation", Query: "ALTER TABLE orders ADD COLUMN x int"},
					{PID: 13, DurationSeconds: 300, XactSeconds: 600, State: "idle in transaction", User: "worker", Query: "UPDATE orders SET paid = true"},
				},
				Blocking: []protocol.LockSession{
					{PID: 13, Blocking: 1, State: "idle in transaction", DurationSeconds: 300, XactSeconds: 600, User: "worker"},
					{PID: 12, BlockedBy: []int{13}, WaitSeconds: 95, LockMode: "AccessExclusiveLock", Relation: "public.orders", State: "active", User: "app"},
				}}, ok
		case "/v1/databases/db_app/disk-forecast":
			days, free, total, g := 12.0, int64(8<<30), int64(100<<30), float64(700<<20)
			full := time.Now().Add(12 * 24 * time.Hour)
			return protocol.DiskForecast{State: protocol.ForecastFilling, Summary: "The disk is full in about 12 days.", FreeBytes: &free, TotalBytes: &total,
				DaysUntilFull: &days, FullAt: &full, GrowthBytesPerDay: &g, HistoryPoints: 300}, ok
		case "/v1/databases/db_app/availability":
			up := 99.5
			end := at.Add(7 * time.Minute)
			return protocol.Availability{DatabaseID: "db_app", Windows: []protocol.UptimeWindow{{Window: "24h", UptimePct: &up, ObservedPct: 100, DownMinutes: 7}},
				Incidents: []protocol.Incident{{StartedAt: at, EndedAt: &end, DurationSeconds: 420, Error: "connection refused"}}}, ok
		case "/v1/monitoring/metrics":
			return []protocol.MetricInfo{{Name: "connections_total", Scope: "database", Unit: "count"}, {Name: "cpu_pct", Scope: "host", Unit: "%"},
				{Name: "disk_free_bytes", Scope: "database", Unit: "B"}, {Name: "disk_free_bytes", Scope: "host", Unit: "B"}}, ok
		case "/v1/databases/db_app/metrics", "/v1/hosts/h_1/metrics", "/v1/hosts/db1/metrics":
			var series []protocol.MetricSeries
			for _, m := range strings.Split(r.URL.Query().Get("metrics"), ",") {
				if m == "" {
					continue
				}
				t0 := float64(at.Unix())
				series = append(series, protocol.MetricSeries{Metric: m, Unit: "%", Points: [][2]float64{{t0, 10}, {t0 + 60, 30}, {t0 + 120, 20}}})
			}
			return protocol.MetricsResponse{Series: series}, ok
		case "/v1/databases/db_app/security":
			return protocol.SecurityView{DatabaseID: "db_app", Database: "app", Available: true, Grade: "D", Score: 55, Summary: "Anyone on the internet can try passwords.",
				Findings: []protocol.Finding{
					{ID: "scram", Severity: protocol.SeverityInfo, Title: "Old password storage", Penalty: 2},
					{ID: "open_to_internet", Severity: protocol.SeverityCritical, Title: "Open to the internet", Action: "Allow only your app servers.", Penalty: 30,
						Fixes: []protocol.FindingFix{{ID: "restrict", Kind: protocol.FixSecurity, Label: "Allow only these addresses", Available: true, Params: json.RawMessage(`{"verifier":"` + secretMark + `"}`)}}},
				},
				Checks: []protocol.SecurityCheck{{ID: "tls", Label: "Encryption", Status: "warning", Detail: "TLS is off."}}}, ok
		case "/v1/databases/db_app/upgrades":
			return protocol.UpgradeInfo{Database: "app", Version: "16.9", Major: 16, Installed: "16.9", Candidate: "16.10", UpdateAvailable: true, Majors: []int{17, 18},
				SecurityUpdates: 3, RebootRequired: true, Allowed: []string{"postgresql"},
				Rehearsal: &protocol.UpgradeRehearsalResult{ToMajor: 17, Passed: true, Summary: "The upgrade to 17 worked on a copy.", SafeDowntimeSeconds: 40}, RehearsalValid: true,
				Tasks: []protocol.TaskView{{ID: "t_up", Type: protocol.TaskUpgradeRehearsal, Status: protocol.StatusSucceeded, Result: json.RawMessage(`{"passed":true}`)}}}, ok
		case "/v1/audit-events":
			return []protocol.AuditEvent{
				{ID: "a1", At: at, Actor: "dashboard:ana@example.com", Action: "notification_channel.create", Target: "Ops",
					Detail: json.RawMessage(`{"type":"slack","url":"https://hooks.slack.com/x/` + secretMark + `","note":"see https://x.test/` + secretMark + `"}`)},
				{ID: "a2", At: at, Actor: "key:k1 (ci)", Action: "database.update", Target: "app", Detail: json.RawMessage(`{"verifier":"` + secretMark + `","retention_full":3}`)},
				{ID: "a3", At: at.Add(-72 * time.Hour), Actor: "rowsafed", Action: "database.update", Target: "other"},
			}, ok
		case "/v1/databases/db_app/pooling":
			return protocol.PoolingView{State: "on", Allowed: true, Available: true, Running: true, Settings: protocol.PoolingSettings{Mode: "transaction", PoolSize: 20, MaxClientConn: 500, Port: 6432},
				Direct: "postgresql://app@db1:5432/app", Pooled: "postgresql://app@db1:6432/app",
				LastTask: &protocol.TaskView{ID: "t_p", Type: "pooling", Status: protocol.StatusSucceeded, Result: json.RawMessage(`{"on":true}`)}}, ok
		case "/v1/org/weekly-report":
			return protocol.WeeklyReportPreview{Enabled: true, Recipients: []string{secretMark + "@example.com"}, Subject: "Your weekly Pulse", Text: "All 3 databases are protected.", From: at, To: at}, ok
		case "/v1/databases/db_app/forks":
			return protocol.ForkInfo{Database: "app", CanFork: true, Forks: []protocol.ForkView{{ID: "fk_1", Name: "app-staging", SourceName: "app", Hostname: "db2", Status: protocol.ForkReady, CreatedAt: at}}}, ok
		case "/v1/migrations":
			return []protocol.Migration{{ID: "mi_1", DatabaseID: "db_app", Status: protocol.MigratePhaseSyncing, Method: "live", PublicKey: secretMark,
				Source: &protocol.MigrateSource{Host: "rds.example.com", Port: 5432, Provider: "rds"}, Progress: &protocol.MigrationStatus{TablesTotal: 4, TablesCopied: 4}}}, ok
		case "/v1/databases/db_app/previews":
			return []protocol.Preview{{ID: "pv_1", Database: "app", Status: protocol.StatusSucceeded, Verdict: protocol.PreviewCareful, Label: "0042_orders.sql", Summary: "Rewrites orders.", CreatedAt: at}}, ok
		case "/v1/databases/db_app/safe-copies":
			return protocol.SafeCopiesInfo{Available: true, Limit: 2}, ok
		case "/v1/databases/db_app/masking":
			return protocol.MaskingInfo{Masked: 1, Columns: []protocol.MaskingColumn{{DB: "app", Table: "public.users", Column: "email", Strategy: "email"}, {DB: "app", Table: "public.users", Column: "id", Strategy: "keep"}}}, ok
		case "/v1/databases/db_app/moments":
			res, _ := json.Marshal(protocol.FindMomentResult{Summary: "1,204 rows deleted from applications."})
			return protocol.MomentsInfo{Database: "app", Earliest: &at, Searches: []protocol.TaskView{{ID: "t_m", Type: protocol.TaskFindMoment, Status: protocol.StatusSucceeded, Result: res, CreatedAt: at}}}, ok
		case "/v1/databases/db_app/standby":
			return protocol.StandbyInfo{Database: "app", Primary: protocol.StandbyServer{Hostname: "db1", Port: 5432}}, ok
		case "/v1/databases/db_app/standby/candidates":
			return []protocol.StandbyCandidate{{HostID: "h_2", Hostname: "db2", Online: true, Usable: true}}, ok
		case "/v1/databases/db_app/files":
			return protocol.FilesInfo{Database: "app", Folders: []protocol.FilesFolderView{{FilesFolder: protocol.FilesFolder{ID: "f1", Path: "/srv/app/storage"}}}}, ok
		case "/v1/databases/db_app/files/nearest":
			return protocol.FilesNearest{Folders: []protocol.FilesNearestFolder{{FolderID: "f1", Path: "/srv/app/storage", Snapshot: &protocol.FilesSnapshot{Time: at, Files: 1204}, GapSeconds: 300}}}, ok
		case "/v1/databases/db_app/recommendations", "/v1/databases/app/recommendations":
			return protocol.RecommendationsResponse{Database: "app", Available: true, Recommendations: []protocol.Recommendation{{Finding: protocol.Finding{ID: "rec_1", Severity: protocol.SeverityWarning, Title: "Foreign key without an index"}, Group: protocol.RecGroupSchema}}}, ok
		case "/v1/tasks/t_check":
			res, _ := json.Marshal(protocol.UpgradeCheckResult{ToMajor: 17, Summary: "PostgreSQL 16.9 can be upgraded to 17.",
				Checks: []protocol.UpgradeCheck{{ID: "disk", Status: protocol.CheckWarning, Title: "Disk is tight"}}})
			return protocol.TaskView{ID: "t_check", Type: protocol.TaskUpgradeCheck, Status: protocol.StatusSucceeded, Result: res, CreatedAt: at}, ok
		case "/v1/tasks/t_scan":
			return protocol.TaskView{ID: "t_scan", Type: protocol.TaskSecurityScan, Status: protocol.StatusSucceeded, CreatedAt: at}, ok
		}
		return nil, 0
	}
	switch r.Method + " " + p {
	case "POST /v1/alerts/al_1/ack":
		now := time.Now()
		return protocol.Alert{ID: "al_1", State: protocol.AlertFiring, Summary: "Disk 92% full", AcknowledgedAt: &now, AcknowledgedBy: "key:k1"}, ok
	case "POST /v1/databases/db_app/recommendations/rec_1/dismiss":
		return protocol.RecommendationDismissal{Reason: protocol.DismissLater, By: "key:k1", At: at}, ok
	case "DELETE /v1/databases/db_app/recommendations/rec_1/dismiss":
		return struct{}{}, ok
	case "POST /v1/databases/db_app/index-recommendations/run":
		return task("t_idx", protocol.TaskIndexAdvisor), http.StatusAccepted
	case "POST /v1/databases/db_app/upgrades/check", "POST /v1/databases/db_shop/upgrades/check":
		return protocol.UpgradeTasksResponse{Tasks: []protocol.TaskView{task("t_check", protocol.TaskUpgradeCheck)}}, http.StatusAccepted
	case "POST /v1/databases/db_app/upgrades/rehearsal":
		return protocol.UpgradeTasksResponse{Tasks: []protocol.TaskView{task("t_reh", protocol.TaskUpgradeRehearsal)}}, http.StatusAccepted
	case "POST /v1/databases/db_app/security/check":
		t := task("t_scan", protocol.TaskSecurityScan)
		return protocol.SecurityCheckResponse{Task: &t, OutsideStarted: true}, http.StatusAccepted
	case "POST /v1/databases/db_app/files/backup":
		return protocol.FilesTasksResponse{Tasks: []protocol.TaskView{task("t_fb", protocol.TaskFilesBackup)}}, http.StatusAccepted
	case "POST /v1/databases/db_app/files/check":
		return protocol.FilesTasksResponse{Tasks: []protocol.TaskView{task("t_fc", protocol.TaskFilesCheck)}}, http.StatusAccepted
	case "POST /v1/databases/db_app/safe-copies/sc_1/extend":
		return protocol.SafeCopy{ID: "sc_1", Status: protocol.CopyReady, Masked: true, Expires: time.Now().Add(48 * time.Hour)}, ok
	}
	return nil, 0
}

func connectClient(t *testing.T, c *client.Client, opts Options) *sdk.ClientSession {
	t.Helper()
	ctx := t.Context()
	st, ct := sdk.NewInMemoryTransports()
	ss, err := NewServer(c, opts).Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call runs a tool and returns its text and structured result as JSON.
func call(t *testing.T, cs *sdk.ClientSession, name string, args map[string]any) (string, string) {
	t.Helper()
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var txt strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			txt.WriteString(tc.Text)
		}
	}
	if res.IsError {
		t.Fatalf("%s(%v) failed: %s", name, args, txt.String())
	}
	sc, _ := json.Marshal(res.StructuredContent)
	return txt.String(), string(sc)
}

func TestNewReadToolsOnlyRead(t *testing.T) {
	f := &dashAPI{t: t}
	api := httptest.NewServer(f)
	defer api.Close()
	cs := connectClient(t, client.New(api.URL, "rsk_test"), Options{AllowWrites: true, MaxWait: 5 * time.Second})

	cases := []struct {
		tool string
		args map[string]any
		want []string // in the text or the structured result
	}{
		{"list_alerts", map[string]any{"include_rules": true}, []string{"[WARNING] app on db1: Disk 92% full", "Now 92.5% (threshold 90.0%)", "Next step: Free space", "ack_alert", "disk_used (Disk almost full, database): on, above 90.0% for 5m0s, warning", "Ops (slack", `Post "[link hidden]": timeout`, "request_change (action alert_rule)"}},
		{"list_alerts", map[string]any{"alert_id": "al_1"}, []string{"Disk 92% full"}},
		{"list_alerts", map[string]any{"database": "other"}, []string{"No alerts firing right now for other."}},
		{"live_activity", map[string]any{"database": "app"}, []string{"session 13 (user worker) holds the lock", "waiting 1m35s: session 12 (user app) wants AccessExclusiveLock on public.orders", "transaction open for 10m0s"}},
		{"disk_forecast", map[string]any{"database": "app"}, []string{"full in about 12 days", "8.0 GiB free of 100.0 GiB", "700.0 MiB a day"}},
		{"uptime", map[string]any{"database": "app"}, []string{"last 24h: 99.50% up, down 7m0s", "connection refused"}},
		{"database_metrics", map[string]any{"database": "app"}, []string{"connections_used_pct (database): 10.0% / 20.0% / 30.0%, latest 20.0%", "cpu_pct (host)"}},
		{"database_metrics", map[string]any{"database": "app", "metrics": []any{"cpu", "connections_total"}, "points": true}, []string{"cpu_pct (host)", "connections_total (database)", `"points":[`}},
		{"database_metrics", map[string]any{"host": "db1", "since_hours": 24}, []string{"Metrics of db1", "mem_used_pct (host)"}},
		{"security_status", map[string]any{"database": "app"}, []string{"grade D, 55/100", "Can be fixed: Allow only these addresses", "request_change (action security_action)", "Encryption: warning"}},
		{"updates_status", map[string]any{"database": "app"}, []string{"Minor update available: 16.9 -> 16.10", "Newer major versions: 17, 18", "3 operating system security updates", "needs a reboot", "It still allows the upgrade", "action upgrade_database", "check_upgrade", "action reboot_server"}},
		{"audit_log", map[string]any{"target": "app", "since_hours": 24}, []string{"key:k1 (ci): database.update app", `"verifier":"[hidden]"`}},
		{"audit_log", nil, []string{"notification_channel.create Ops", `"url":"[hidden]"`, "[link hidden]", "rowsafed"}},
		{"pooling_status", map[string]any{"database": "app"}, []string{"Connection pooling for app: on, answering", "postgresql://app@db1:6432/app"}},
		{"pooling_status", map[string]any{"database": "mongo"}, []string{"Rowsafe doesn't offer connection pooling"}},
		{"weekly_pulse", nil, []string{"Your weekly Pulse", "All 3 databases are protected."}},
		{"list_forks", map[string]any{"database": "app"}, []string{"app-staging (fk_1): ready on db2", "action fork_database", "mi_1: syncing from rds rds.example.com:5432 (live), 4 of 4 tables"}},
		{"get_preview", map[string]any{"database": "app"}, []string{"pv_1 (0042_orders.sql): careful. Rewrites orders."}},
		{"list_safe_copies", map[string]any{"database": "app", "masking": true}, []string{"mask 1 columns", "public.users.email: email", "action masking_rules"}},
		{"find_moment", map[string]any{"database": "app", "list_searches": true}, []string{"t_m (succeeded): 1,204 rows deleted"}},
		{"standby_status", map[string]any{"database": "app", "candidates": true}, []string{`"hostname":"db2"`, `"usable":true`}},
		{"files_status", map[string]any{"database": "app", "at": "2026-09-24T14:00:00Z"}, []string{"/srv/app/storage: the snapshot of", "1204 files"}},
		{"recommendations", map[string]any{"database": "app"}, []string{"Foreign key without an index (id rec_1)"}},
	}
	for _, tc := range cases {
		txt, sc := call(t, cs, tc.tool, tc.args)
		all := txt + "\n" + sc
		for _, w := range tc.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s(%v) lacks %q:\n%s\n%s", tc.tool, tc.args, w, txt, sc)
			}
		}
		if strings.Contains(all, secretMark) {
			t.Errorf("%s(%v) leaks a secret:\n%s\n%s", tc.tool, tc.args, txt, sc)
		}
		for _, c := range f.take() {
			if c.Method != http.MethodGet {
				t.Errorf("%s(%v) sent %s %s", tc.tool, tc.args, c.Method, c.Path)
			}
		}
	}

	tools, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range tools.Tools {
		switch tl.Name {
		case "list_alerts", "live_activity", "disk_forecast", "uptime", "database_metrics", "security_status", "updates_status", "audit_log",
			"pooling_status", "weekly_pulse", "list_forks":
			if tl.Annotations == nil || !tl.Annotations.ReadOnlyHint {
				t.Errorf("%s isn't marked read-only", tl.Name)
			}
		}
	}
}

func TestActionToolsHitOnlyTheirEndpoint(t *testing.T) {
	f := &dashAPI{t: t}
	api := httptest.NewServer(f)
	defer api.Close()
	cs := connectClient(t, client.New(api.URL, "rsk_test"), Options{AllowWrites: true, MaxWait: 10 * time.Second})

	cases := []struct {
		tool     string
		args     map[string]any
		endpoint string // the one non-GET request
		body     string // in its body
		want     []string
	}{
		{"ack_alert", map[string]any{"alert_id": "al_1"}, "POST /v1/alerts/al_1/ack", "", []string{"no more repeat notifications"}},
		{"dismiss_recommendation", map[string]any{"database": "app", "id": "rec_1", "reason": "later", "note": "next sprint"}, "POST /v1/databases/db_app/recommendations/rec_1/dismiss", `"reason":"later"`, []string{"We'll handle it later"}},
		{"dismiss_recommendation", map[string]any{"database": "app", "id": "rec_1", "undo": true}, "DELETE /v1/databases/db_app/recommendations/rec_1/dismiss", "", []string{"open again"}},
		{"run_index_check", map[string]any{"database": "app"}, "POST /v1/databases/db_app/index-recommendations/run", "", []string{"on a copy", "t_idx"}},
		{"check_upgrade", map[string]any{"database": "app", "to": "17", "wait_seconds": 5}, "POST /v1/databases/db_app/upgrades/check", `"to":17`, []string{"can be upgraded to 17", "[warning] Disk is tight", "action upgrade_database"}},
		{"check_upgrade", map[string]any{"database": "shop", "to": "8.4", "wait_seconds": 5}, "POST /v1/databases/db_shop/upgrades/check", `"to":804`, nil},
		{"rehearse_upgrade", map[string]any{"database": "app"}, "POST /v1/databases/db_app/upgrades/rehearsal", "", []string{"throwaway copy", "t_reh"}},
		{"run_security_check", map[string]any{"database": "app", "wait_seconds": 5}, "POST /v1/databases/db_app/security/check", "", []string{"Now grade D, 55/100", "check from the internet"}},
		{"backup_files", map[string]any{"database": "app", "folders": []any{"/srv/app/storage/"}, "mark": "before-cleanup"}, "POST /v1/databases/db_app/files/backup", `"folder_ids":["f1"]`, []string{"tagged before-cleanup", "t_fb"}},
		{"backup_files", map[string]any{"database": "app", "check": true}, "POST /v1/databases/db_app/files/check", "", []string{"files Proof", "t_fc"}},
		{"extend_safe_copy", map[string]any{"database": "app", "id": "sc_1", "hours": 48}, "POST /v1/databases/db_app/safe-copies/sc_1/extend", `"hours":48`, []string{"is now deleted at"}},
	}
	for _, tc := range cases {
		txt, sc := call(t, cs, tc.tool, tc.args)
		for _, w := range tc.want {
			if !strings.Contains(txt+sc, w) {
				t.Errorf("%s(%v) lacks %q:\n%s", tc.tool, tc.args, w, txt)
			}
		}
		var writes []string
		for _, c := range f.take() {
			if c.Method == http.MethodGet {
				continue
			}
			writes = append(writes, c.Method+" "+c.Path)
			if tc.body != "" && !strings.Contains(string(c.Body), tc.body) {
				t.Errorf("%s(%v): body %s lacks %s", tc.tool, tc.args, c.Body, tc.body)
			}
			if strings.HasSuffix(c.Path, "/tasks") || strings.HasSuffix(c.Path, "/fixes") || strings.Contains(c.Path, "/restore") {
				t.Errorf("%s(%v) sent %s %s", tc.tool, tc.args, c.Method, c.Path)
			}
		}
		if !slices.Equal(writes, []string{tc.endpoint}) {
			t.Errorf("%s(%v) sent %v, want only %s", tc.tool, tc.args, writes, tc.endpoint)
		}
	}

	// Engines without the feature get a plain answer, and nothing is queued.
	for _, name := range []string{"run_index_check", "check_upgrade", "run_security_check", "backup_files"} {
		res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: name, Arguments: map[string]any{"database": "legacy"}})
		if err != nil {
			t.Fatal(err)
		}
		if txt := res.Content[0].(*sdk.TextContent).Text; !res.IsError || !strings.Contains(txt, "Rowsafe doesn't offer") {
			t.Errorf("%s on an engine without the feature: %s", name, txt)
		}
		for _, c := range f.take() {
			if c.Method != http.MethodGet {
				t.Errorf("%s on an engine without the feature sent %s %s", name, c.Method, c.Path)
			}
		}
	}
}

// Without --allow-writes (and on an OAuth connection) only the reads exist.
func TestActionToolsNeedWrites(t *testing.T) {
	f := &dashAPI{t: t}
	api := httptest.NewServer(f)
	defer api.Close()
	for _, opts := range []Options{{}, {Remote: true, AllowRestorePoints: true}} {
		cs := connectClient(t, client.New(api.URL, "rsk_test"), opts)
		tools, err := cs.ListTools(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tl := range tools.Tools {
			names = append(names, tl.Name)
		}
		for _, n := range []string{"ack_alert", "dismiss_recommendation", "run_index_check", "check_upgrade", "rehearse_upgrade", "run_security_check", "backup_files"} {
			if slices.Contains(names, n) {
				t.Errorf("%+v offers %s", opts, n)
			}
		}
		if opts.Remote && slices.Contains(names, "extend_safe_copy") {
			t.Error("an OAuth connection offers extend_safe_copy")
		}
		for _, n := range []string{"list_alerts", "live_activity", "database_metrics", "security_status", "updates_status", "audit_log", "weekly_pulse"} {
			if !slices.Contains(names, n) {
				t.Errorf("%+v lacks %s", opts, n)
			}
		}
	}
}
