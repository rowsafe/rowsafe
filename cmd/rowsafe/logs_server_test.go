package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestLogsOnServer: sudo rowsafe logs on a server on its own reads what
// the agent keeps there, and forwards it where root says.
func TestLogsOnServer(t *testing.T) {
	localServer(t)
	ctx := context.Background()
	sock := strings.TrimPrefix(os.Getenv("ROWSAFE_URL"), "unix://")
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	now := time.Now().UTC()
	slow := 1800.0
	body, _ := json.Marshal(protocol.LogBatch{Databases: []protocol.DatabaseLogs{{DatabaseID: "db_l1", Entries: []protocol.LogEntry{
		{Time: now.Add(-3 * time.Hour), Severity: "ERROR", Kind: protocol.LogKindError, SQLState: "42P01", Message: `relation "old" does not exist`},
		{Time: now.Add(-20 * time.Minute), Severity: "LOG", Kind: protocol.LogKindSlowQuery, Message: "duration: 1800 ms", Statement: "SELECT * FROM orders", DurationMs: &slow},
		{Time: now.Add(-10 * time.Minute), Severity: "ERROR", Kind: protocol.LogKindError, SQLState: "23505", Message: "duplicate key value violates unique constraint", User: "app", Database: "shop"},
	}}}})
	req, _ := http.NewRequest(http.MethodPost, "http://local/v1/agent/logs", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer rsl_local")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("agent logs: %d", resp.StatusCode)
	}

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "shop", "--errors", "--since", "1h"}) })
	if err != nil || !strings.Contains(out, "duplicate key") || strings.Contains(out, `"old"`) || strings.Contains(out, "orders") {
		t.Fatalf("--errors --since 1h: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "shop", "--grep", "ORDERS"}) })
	if err != nil || !strings.Contains(out, "slow_query") || strings.Contains(out, "duplicate") {
		t.Fatalf("--grep: %v\n%s", err, out)
	}
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "shop", "--errors", "--kind", "locks"}) }); err == nil {
		t.Fatal("--errors with --kind locks")
	}

	got := make(chan string, 5)
	recv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- r.Header.Get("X-Rowsafe-Signature") + " " + string(b)
	}))
	defer recv.Close()
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"logs", "forward", "--url", recv.URL + "/in", "--kinds", "errors"})
	})
	if err != nil || !strings.Contains(out, "Added webhook") || !strings.Contains(out, "whsec_") || !strings.Contains(out, "sudo rowsafe logs forward test") {
		t.Fatalf("logs forward --url: %v\n%s", err, out)
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "forward"}) })
	if err != nil || !strings.Contains(out, "webhook") || strings.Contains(out, "/in") {
		t.Fatalf("logs forward: %v\n%s", err, out)
	}
	if out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "forward", "test", "webhook"}) }); err != nil || !strings.Contains(out, "Test entry sent") {
		t.Fatalf("logs forward test: %v\n%s", err, out)
	}
	select {
	case b := <-got:
		if !strings.HasPrefix(b, "t=") || !strings.Contains(b, `"event":"logs"`) || !strings.Contains(b, "Test from Rowsafe") {
			t.Fatalf("test delivery: %s", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no test delivery")
	}
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "forward", "--name", "x"}) }); err == nil {
		t.Fatal("logs forward without a URL or type")
	}
	if out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"logs", "forward", "remove", "webhook", "--yes"}) }); err != nil || !strings.Contains(out, "Removed") {
		t.Fatalf("remove: %v\n%s", err, out)
	}
}
