package localcp

import (
	"bufio"
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/*.golden")

func TestMetricsConfig(t *testing.T) {
	token := "0123456789abcdef0123"
	for _, c := range []struct {
		listen, token string
		ok            bool
		err           string
	}{
		{"", "", true, ""},
		{"", token, false, "ROWSAFE_METRICS_LISTEN"},
		{"127.0.0.1:9188", "", true, ""},
		{"localhost:9188", "", true, ""},
		{"[::1]:9188", "", true, ""},
		{"127.0.0.2:9188", "", true, ""},
		{"0.0.0.0:9188", "", false, "anyone who can reach"},
		{":9188", "", false, "anyone who can reach"},
		{"[::]:9188", "", false, "anyone who can reach"},
		{"10.0.0.5:9188", "", false, "anyone who can reach"},
		{"db1.example.com:9188", "", false, "anyone who can reach"},
		{"0.0.0.0:9188", token, true, ""},
		{"10.0.0.5:9188", token, true, ""},
		{"127.0.0.1:9188", token, true, ""},
		{"0.0.0.0:9188", "short", false, "at least 16"},
		{"0.0.0.0:9188", "with a space in it, long enough", false, "without spaces"},
		{"127.0.0.1", "", false, "address and port"},
		{"127.0.0.1:0", "", false, "1 to 65535"},
		{"127.0.0.1:metrics", "", false, "1 to 65535"},
	} {
		env := map[string]string{MetricsListenEnv: c.listen, MetricsTokenEnv: c.token}
		cfg, err := MetricsConfigFrom(func(k string) string { return env[k] })
		if c.ok != (err == nil) || err != nil && !strings.Contains(err.Error(), c.err) {
			t.Errorf("%q token %q: %v", c.listen, c.token, err)
			continue
		}
		if err == nil && (cfg.Listen != c.listen || cfg.Token != c.token) {
			t.Errorf("%q: %+v", c.listen, cfg)
		}
	}
}

func TestMetricsToken(t *testing.T) {
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	get := func(h http.Handler, method, path, auth string) int {
		req := httptest.NewRequest(method, path, nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code == http.StatusOK && !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain; version=0.0.4") {
			t.Errorf("content type %q", w.Header().Get("Content-Type"))
		}
		return w.Code
	}
	const token = "0123456789abcdef0123"
	h := s.MetricsHandler(token)
	for auth, want := range map[string]int{
		"":                       http.StatusUnauthorized,
		"Bearer nope":            http.StatusUnauthorized,
		"Bearer " + token + "x":  http.StatusUnauthorized,
		"Basic " + token:         http.StatusUnauthorized,
		token:                    http.StatusUnauthorized,
		"Bearer " + token:        http.StatusOK,
		"Bearer " + token + " ":  http.StatusUnauthorized,
		"bearer " + token + "\n": http.StatusUnauthorized,
	} {
		if got := get(h, "GET", "/metrics", auth); got != want {
			t.Errorf("auth %q: %d, want %d", auth, got, want)
		}
	}
	open := s.MetricsHandler("")
	if got := get(open, "GET", "/metrics", ""); got != http.StatusOK {
		t.Errorf("without a token: %d", got)
	}
	if got := get(open, "POST", "/metrics", ""); got != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", got)
	}
	if got := get(open, "GET", "/v1/databases", ""); got != http.StatusNotFound {
		t.Errorf("another path: %d", got)
	}
}

// serveMetrics listens only when agent.env says so, and only where allowed.
func TestServeMetrics(t *testing.T) {
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	port := addr[strings.LastIndex(addr, ":")+1:]

	// Every interface without a token: refused, nothing listens.
	t.Setenv(MetricsListenEnv, "0.0.0.0:"+port)
	t.Setenv(MetricsTokenEnv, "")
	s.serveMetrics(ctx)
	if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c.Close()
		t.Fatal("listening without a token on every interface")
	}

	t.Setenv(MetricsListenEnv, addr)
	s.serveMetrics(ctx)
	var resp *http.Response
	for range 50 {
		if resp, err = http.Get("http://" + addr + "/metrics"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "# TYPE rowsafe_database_info gauge") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

// metricsServer is a server with two databases: one protected with
// backups, Proofs, continuous backup and monitoring readings; one waiting
// for its restart, with an alert firing.
func metricsServer(t *testing.T) *Server {
	t.Helper()
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	ptr := func(t time.Time) *time.Time { return &t }
	s.updates.offer = &protocol.UpdateOffer{Version: "0.10.22"}

	if err := s.st.update(func(st *state) error {
		st.Host = hostRec{ID: "hst_1", Hostname: "db1", AgentVersion: "0.10.18", Platform: "linux/amd64",
			EnrolledAt: ago(30 * 24 * time.Hour), LastSeen: ptr(ago(20 * time.Second))}
		st.Databases = []*dbRec{
			{Database: protocol.Database{ID: "db_app", Name: "app", Status: protocol.DBActive, RetentionFull: 2,
				Archiver: &protocol.ArchiverStats{DatabaseID: "db_app", ArchivedCount: 900, FailedCount: 3,
					LastArchivedTime: ptr(ago(2 * time.Minute)), LastFailedTime: ptr(ago(3 * 24 * time.Hour))}},
				StatusSince: ago(20 * 24 * time.Hour), ArchiverAt: ptr(ago(30 * time.Second))},
			{Database: protocol.Database{ID: "db_shop", Name: "shop", Engine: protocol.EnginePostgreSQL, Status: protocol.DBAwaitingRestart},
				StatusSince: ago(26 * time.Hour)},
		}
		st.Backups = []protocol.Backup{
			{ID: "b1", DatabaseID: "db_app", Type: protocol.BackupFull, StartedAt: ago(10*24*time.Hour + 10*time.Minute), StoppedAt: ago(10 * 24 * time.Hour), SizeBytes: 5 << 30, RepoSizeBytes: 1 << 30},
			{ID: "b2", DatabaseID: "db_app", Type: protocol.BackupFull, StartedAt: ago(3*24*time.Hour + 12*time.Minute), StoppedAt: ago(3 * 24 * time.Hour), SizeBytes: 6 << 30, RepoSizeBytes: 1200 << 20},
			{ID: "b3", DatabaseID: "db_app", Type: protocol.BackupDiff, StartedAt: ago(11*time.Hour + 90*time.Second), StoppedAt: ago(11 * time.Hour), SizeBytes: 6 << 30, RepoSizeBytes: 40 << 20},
		}
		st.Drills = []protocol.Drill{
			{ID: "d1", DatabaseID: "db_app", Passed: true, CreatedAt: ago(9 * 24 * time.Hour)},
			{ID: "d2", DatabaseID: "db_app", Passed: false, CreatedAt: ago(2 * 24 * time.Hour)},
		}
		st.Tasks = []*taskRec{
			{TaskView: protocol.TaskView{ID: "t1", DatabaseID: "db_app", Type: protocol.TaskDrill, Status: protocol.StatusFailed,
				CreatedAt: ago(2*24*time.Hour + time.Hour), FinishedAt: ptr(ago(2 * 24 * time.Hour))}},
		}
		st.Alerts = []*alertRec{
			{Key: "drill_failed:db_app", Alert: protocol.Alert{ID: "alr_1", Rule: "drill_failed", State: "firing"}},
			{Key: "backup_stale:db_app", Alert: protocol.Alert{ID: "alr_0", Rule: "backup_stale", State: "resolved"}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	s.prom.record(protocol.MonitoringReport{
		Host: map[string]float64{collect.HCPUPct: 12.5, collect.HMemUsedPct: 41, collect.MDiskFreeBytes: 20 << 30},
		Databases: []protocol.DatabaseMonitoring{
			{DatabaseID: "db_app", Metrics: map[string]float64{collect.MConnActive: 3, collect.MConnUsedPct: 4.5,
				collect.MCacheHitPct: 99.25, collect.MReplicationLagSeconds: 0.5, collect.MDiskFreePct: 61, "not_in_the_catalog": 1}},
			{DatabaseID: "db_shop", Error: "connection refused"},
		},
	}, now.Add(-40*time.Second))
	return s
}

func TestMetricsGolden(t *testing.T) {
	s := metricsServer(t)
	var b strings.Builder
	s.writeMetrics(&b)
	got := b.String()
	checkExposition(t, got)

	path := filepath.Join("testdata", "metrics.golden")
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (go test ./internal/localcp -run TestMetricsGolden -update writes it)", err)
	}
	if got != string(want) {
		t.Errorf("metrics differ from %s (rerun with -update and review the diff):\n%s", path, got)
	}

	// Readings older than 10 minutes are dropped, not repeated forever.
	now := s.now().Add(15 * time.Minute)
	s.now = func() time.Time { return now }
	b.Reset()
	s.writeMetrics(&b)
	stale := b.String()
	for _, gone := range []string{"rowsafe_connections_active", "rowsafe_host_cpu_pct"} {
		if strings.Contains(stale, gone) {
			t.Errorf("stale reading %s still exported", gone)
		}
	}
	if !strings.Contains(stale, `rowsafe_database_up{database="app",host="db1"} 0`) {
		t.Error("a stale reading should make rowsafe_database_up 0")
	}
}

// An empty server (just installed) still serves valid metrics.
func TestMetricsEmpty(t *testing.T) {
	s, err := Open(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	s.writeMetrics(&b)
	checkExposition(t, b.String())
}

// checkExposition checks the text format: one HELP and TYPE per family
// before its samples, valid names, label values quoted, no repeated series.
func checkExposition(t *testing.T, text string) {
	t.Helper()
	typed := map[string]bool{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "# HELP "):
			name := strings.Fields(line)[2]
			if typed[name] {
				t.Errorf("family %s written twice", name)
			}
		case strings.HasPrefix(line, "# TYPE "):
			f := strings.Fields(line)
			if len(f) != 4 || (f[3] != "gauge" && f[3] != "counter") {
				t.Errorf("bad TYPE line %q", line)
			}
			typed[f[2]] = true
		case line == "":
			t.Error("empty line")
		default:
			series, value, ok := strings.Cut(line, " ")
			if i := strings.LastIndex(line, "} "); i >= 0 {
				series, value, ok = line[:i+1], line[i+2:], true
			}
			name, _, _ := strings.Cut(series, "{")
			if !ok || !validMetricName(name) || !typed[name] || value == "" {
				t.Errorf("bad sample %q", line)
			}
			if seen[series] {
				t.Errorf("series written twice: %s", series)
			}
			seen[series] = true
		}
	}
}

// What the agent collects can't take the name of a family this file
// writes, and every collected metric gets a valid name.
func TestMetricNamesDontClash(t *testing.T) {
	ours := map[string]bool{}
	for _, f := range metricFamilies {
		ours[f] = true
	}
	seen := map[string]bool{}
	for _, c := range collect.Catalog {
		n := collectedName(c.Scope, c.Name)
		if ours[n] {
			t.Errorf("collected metric %s/%s clashes with %s", c.Scope, c.Name, n)
		}
		if !validMetricName(n) {
			t.Errorf("collected metric %s/%s: %s is not a valid name", c.Scope, c.Name, n)
		}
		if seen[n] {
			t.Errorf("two collected metrics are named %s", n)
		}
		seen[n] = true
	}
	// Every family written is listed.
	s := metricsServer(t)
	var b strings.Builder
	s.writeMetrics(&b)
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "# TYPE ") {
			n := strings.Fields(line)[2]
			if !ours[n] && !seen[n] {
				t.Errorf("%s is missing from metricFamilies", n)
			}
		}
	}
}
