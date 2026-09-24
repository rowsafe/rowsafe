package agent

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A removed host's agent says so and backs off instead of hammering the
// control plane every heartbeat period.
func TestRevokedAgentBacksOff(t *testing.T) {
	var heartbeats atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		heartbeats.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid credentials"}`))
	}))
	defer ts.Close()

	old := RevokedBackoff
	RevokedBackoff = 300 * time.Millisecond
	defer func() { RevokedBackoff = old }()

	var logs syncBuffer
	a := &Agent{
		cfg:    Config{HeartbeatPeriod: 5 * time.Millisecond, StateDir: t.TempDir()},
		log:    slog.New(slog.NewTextHandler(&logs, nil)),
		client: newControlClient(ts.URL, "rsa_revoked"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	a.heartbeatLoop(ctx)

	if n := heartbeats.Load(); n < 2 || n > 4 {
		t.Fatalf("%d heartbeats in 700ms with a 300ms backoff; want 2-4 (a 5ms period would give ~140)", n)
	}
	if !strings.Contains(logs.String(), "the host was removed from Rowsafe") {
		t.Fatalf("no clear log message:\n%s", logs.String())
	}
}
