package agent

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestClipLog(t *testing.T) {
	if got := clipLog("short\n", 100); got != "short\n" {
		t.Errorf("short log changed: %q", got)
	}
	var b strings.Builder
	for i := range 10000 {
		b.WriteString(strings.Repeat("x", 40))
		b.WriteString(string(rune('a' + i%26)))
		b.WriteByte('\n')
	}
	long := b.String()
	got := clipLog(long, 4096)
	if len(got) > 4096+100 || !strings.HasPrefix(got, long[:42]) || !strings.HasSuffix(got, long[len(long)-42:]) ||
		!strings.Contains(got, "bytes of the log left out") {
		t.Fatalf("clipped (%d bytes): %q...%q", len(got), got[:80], got[len(got)-80:])
	}
	for _, line := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
		if len(line) != 41 && !strings.Contains(line, "left out") {
			t.Fatalf("a line was cut: %q", line)
		}
	}
}

// reportServer answers task reports with the given statuses in turn (then
// 204) and records what each one carried.
func reportServer(t *testing.T, statuses ...int) (*Agent, func() []protocol.CompleteRequest) {
	var mu sync.Mutex
	var got []protocol.CompleteRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CompleteRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		got = append(got, req)
		n := len(got)
		mu.Unlock()
		if n <= len(statuses) {
			http.Error(w, "refused", statuses[n-1])
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, client: newControlClient(srv.URL, "rsa_x")}
	return a, func() []protocol.CompleteRequest {
		mu.Lock()
		defer mu.Unlock()
		return append([]protocol.CompleteRequest(nil), got...)
	}
}

func TestReportRetriesShorterWhenRefused(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	big := strings.Repeat("a line of a verbose backup log\n", 8000)

	// Too large: sent again with a short log, still a success.
	a, got := reportServer(t, http.StatusRequestEntityTooLarge)
	if !a.report(context.Background(), log, "t1", protocol.CompleteRequest{Status: protocol.StatusSucceeded, Log: big}) {
		t.Fatal("not delivered")
	}
	if g := got(); len(g) != 2 || len(g[1].Log) > minReportLog+100 || g[1].Status != protocol.StatusSucceeded {
		t.Fatalf("reports: %d, last log %d bytes, status %s", len(g), len(g[len(g)-1].Log), g[len(g)-1].Status)
	}

	// A result this control plane can't read: a failure that says so,
	// instead of a task that silently disappears.
	a, got = reportServer(t, http.StatusBadRequest)
	if !a.report(context.Background(), log, "t2", protocol.CompleteRequest{Status: protocol.StatusSucceeded, Log: "ok", Result: json.RawMessage(`{"new_field":1}`)}) {
		t.Fatal("not delivered")
	}
	if g := got(); len(g) != 2 || g[1].Result != nil || g[1].Status != protocol.StatusFailed || !strings.Contains(g[1].Error, "refused its result (HTTP 400)") {
		t.Fatalf("reports: %+v", g)
	}

	// No longer ours: given up at once.
	a, got = reportServer(t, http.StatusNotFound)
	if !a.report(context.Background(), log, "t3", protocol.CompleteRequest{Status: protocol.StatusSucceeded}) || len(got()) != 1 {
		t.Fatalf("404: %d reports", len(got()))
	}
}

func TestReportRetriesRateLimited(t *testing.T) {
	if testing.Short() {
		t.Skip("-short: waits 5s between attempts")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, got := reportServer(t, http.StatusTooManyRequests)
	if !a.report(context.Background(), log, "t1", protocol.CompleteRequest{Status: protocol.StatusSucceeded, Log: "ok"}) {
		t.Fatal("not delivered")
	}
	if g := got(); len(g) != 2 || g[1].Status != protocol.StatusSucceeded {
		t.Fatalf("reports: %+v", g)
	}
}

// A stopping agent waits for the tasks its lanes run to send their outcome,
// up to a grace period.
func TestWaitTasksWaitsForReports(t *testing.T) {
	reached, release := make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reached)
		<-release
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, client: newControlClient(srv.URL, "rsa_x"),
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the agent is stopping: the task fails at once and reports it
	done := make(chan struct{})
	go func() {
		a.execute(ctx, &protocol.Task{ID: "t1", Type: "no_such_type"}, false)
		close(done)
	}()
	<-reached
	if a.waitTasks(100 * time.Millisecond) {
		t.Fatal("waitTasks returned while a report was on its way")
	}
	close(release)
	if !a.waitTasks(5 * time.Second) {
		t.Fatal("waitTasks didn't see the task finish")
	}
	<-done
}
