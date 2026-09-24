package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Monitoring covers every database of the host the control plane lists as
// monitored, including ones not adopted yet.
func TestMonitoredDatabases(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"new control plane", `{"databases":[{"id":"db_active"}],"monitored":[{"id":"db_active"},{"id":"db_pending"}]}`,
			[]string{"db_active", "db_pending"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(tc.body))
			}))
			defer ts.Close()
			a := &Agent{
				cfg:    Config{HeartbeatPeriod: time.Hour, StateDir: t.TempDir()},
				log:    slog.New(slog.DiscardHandler),
				client: newControlClient(ts.URL, "rsa_x"),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			a.heartbeatLoop(ctx)
			got := a.monitoredDatabases()
			if len(got) != len(tc.want) {
				t.Fatalf("monitored = %+v, want %v", got, tc.want)
			}
			for i, id := range tc.want {
				if got[i].ID != id {
					t.Errorf("monitored[%d] = %s, want %s", i, got[i].ID, id)
				}
			}
			if len(a.watched) != 1 || a.watched[0].ID != "db_active" {
				t.Errorf("watched = %+v", a.watched)
			}
		})
	}
}
