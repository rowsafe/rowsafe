package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// poolingAPI serves the pooling endpoints for one database, "app".
type poolingAPI struct {
	mu     sync.Mutex
	view   protocol.PoolingView
	puts   []protocol.PoolingRequest
	offs   []protocol.PoolingRequest
	reject int
}

func (p *poolingAPI) serve(t *testing.T) {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	task := protocol.TaskView{ID: "task_1", Type: protocol.TaskPooling, DatabaseName: "app", Status: protocol.StatusQueued}
	mux.HandleFunc("GET /v1/databases/app/pooling", func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		defer p.mu.Unlock()
		j(w, 200, p.view)
	})
	for _, route := range []string{"PUT /v1/databases/app/pooling", "POST /v1/databases/app/pooling/off"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.reject != 0 {
				j(w, p.reject, protocol.Error{Error: "PgBouncer isn't allowed on db1"})
				return
			}
			var req protocol.PoolingRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			if r.Method == "PUT" {
				p.puts = append(p.puts, req)
			} else {
				p.offs = append(p.offs, req)
			}
			j(w, 202, task)
		})
	}
	mux.HandleFunc("GET /v1/tasks/task_1", func(w http.ResponseWriter, r *http.Request) {
		done := task
		done.Status = protocol.StatusSucceeded
		done.Result, _ = json.Marshal(protocol.PoolingResult{Action: "on", On: true, Summary: "Pooling is on: PgBouncer 1.24.1 listens on 127.0.0.1."})
		j(w, 200, done)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("ROWSAFE_API_KEY", "rsk_test")
	t.Setenv("ROWSAFE_DATABASE", "")
	t.Chdir(t.TempDir())
}

func TestPoolingCommands(t *testing.T) {
	p := &poolingAPI{view: protocol.PoolingView{State: "off", Reason: "db1 doesn't allow Rowsafe to manage PgBouncer: run the installer there with --allow-pooler.",
		Direct:   "postgres://USER:PASSWORD@db1:5432/DATABASE",
		Defaults: protocol.PoolingSettings{Mode: "transaction", PoolSize: 20, Listen: "private", Port: 6432}}}
	p.serve(t)
	ctx := t.Context()
	t.Cleanup(func() { stdin = os.Stdin })

	stdin = strings.NewReader("y\n")
	if err := dispatch(ctx, []string{"pooling", "on", "app"}); err == nil || !strings.Contains(err.Error(), "--allow-pooler") {
		t.Fatalf("not allowed: %v", err)
	}
	p.view.Allowed = true
	stdin = strings.NewReader("n\n")
	if err := dispatch(ctx, []string{"pooling", "on", "app"}); err == nil || !strings.Contains(err.Error(), "cancelled") || len(p.puts) != 0 {
		t.Fatalf("answering n: %v %v", err, p.puts)
	}
	stdin = strings.NewReader("")
	if err := dispatch(ctx, []string{"pooling", "on", "app", "--mode", "session", "--pool-size", "30", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if len(p.puts) != 1 || p.puts[0].Confirm != "app" || p.puts[0].Settings.Mode != "session" || p.puts[0].Settings.PoolSize != 30 || p.puts[0].Settings.Listen != "" {
		t.Fatalf("request %+v", p.puts)
	}
	p.reject = http.StatusForbidden
	if err := dispatch(ctx, []string{"pooling", "off", "app", "--yes"}); err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("refused off: %v", err)
	}
	p.reject = 0
	if err := dispatch(ctx, []string{"pooling", "off", "app", "--yes"}); err != nil || len(p.offs) != 1 || p.offs[0].Confirm != "app" {
		t.Fatalf("off: %v %+v", err, p.offs)
	}
	p.view.State, p.view.Running, p.view.Pooled = "on", true, "postgres://USER:PASSWORD@db1:6432/DATABASE"
	p.view.Stats = &protocol.PoolerStats{Pools: []protocol.PoolStat{{Database: "shop", User: "app", ClientsActive: 12, ClientsWaiting: 3}}}
	if err := dispatch(ctx, []string{"pooling", "status", "app"}); err != nil {
		t.Fatal(err)
	}
	if h := helpFor([]string{"pooling"}); !strings.Contains(h, "rowsafe pooling on [NAME]") || !strings.Contains(h, "rowsafe pooling off") {
		t.Errorf("help pooling:\n%s", h)
	}
}
