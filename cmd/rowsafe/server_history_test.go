package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/local"
	"github.com/rowsafe/rowsafe/protocol"
)

// report posts a monitoring report to the server's control plane as its
// agent.
func report(t *testing.T, sock string, rep protocol.MonitoringReport) {
	t.Helper()
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	body, _ := json.Marshal(rep)
	req, _ := http.NewRequest(http.MethodPost, "http://local/v1/agent/monitoring", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer rsl_local")
	resp, err := hc.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("monitoring: %v %v", resp, err)
	}
	resp.Body.Close()
}

// On the server, top and pulse answer from the agent's readings.
func TestTopAndPulseOnServer(t *testing.T) {
	localServer(t)
	ctx := t.Context()
	sock := strings.TrimPrefix(os.Getenv("ROWSAFE_URL"), "unix://")
	if _, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"add", "app", "postgres://app@localhost:5432/shop", "--no-check", "--yes"})
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	report(t, sock, protocol.MonitoringReport{CollectedAt: now, Databases: []protocol.DatabaseMonitoring{{DatabaseID: "db_l1",
		Metrics: map[string]float64{collect.MDiskFreeBytes: 40e9, collect.MDiskTotalBytes: 100e9, collect.MDiskFreePct: 40},
		QueryStats: &protocol.QueryStats{CollectedAt: now, TotalCalls: 30, TotalTimeMs: 90, Statements: []protocol.QueryDelta{
			{QueryID: "101", Query: "SELECT * FROM orders WHERE customer_id = $1", Database: "shop", Calls: 30, TotalTimeMs: 90}}},
	}}})

	// rowsafe top app: the saved name, answered by the agent's history.
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"top", "app"}) })
	if err != nil || !strings.Contains(out, "Top statements of shop in the last 24h") || !strings.Contains(out, "FROM orders") {
		t.Fatalf("top: %v\n%s", err, out)
	}
	// rowsafe pulse: every database on the server, from the agent's readings.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"pulse"}) })
	if !strings.Contains(out, "shop") {
		t.Fatalf("pulse: %v\n%s", err, out)
	}
	// The history the direct reading gets.
	l, err := local.Open("postgres://app@localhost:5432/shop")
	if err != nil {
		t.Fatal(err)
	}
	h, name := serverHistory(ctx, &localDB{DB: l})
	if h == nil || name != "shop" || h.Protection == nil || h.Forecast.FreeBytes == nil || *h.Forecast.FreeBytes != 40e9 {
		t.Fatalf("history: %+v %q", h, name)
	}
	prev := 5.0
	opts := withHistory(local.Options{}, &protocol.LocalHistory{Forecast: h.Forecast, Regressions: []protocol.QueryTrend{
		{QueryID: "101", Query: "SELECT 1 FROM orders", MeanTimeMs: 50, PreviousMeanTimeMs: &prev, Calls: 100}}})
	if opts.Forecast == nil || len(opts.Regressions) != 1 || opts.Regressions[0].PrevMs != 5 {
		t.Fatalf("options: %+v", opts)
	}
	// Elsewhere: nothing.
	onServer = false
	t.Cleanup(func() { onServer = false })
	if h, _ := serverHistory(ctx, &localDB{DB: l}); h != nil {
		t.Fatal("history off the server")
	}
}
