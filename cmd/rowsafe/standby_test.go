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
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// standbyAPI is the control plane's Standby endpoints, for the CLI.
type standbyAPI struct {
	mu   sync.Mutex
	info protocol.StandbyInfo
	reqs []string
	// promoted: the next GET shows db-2 as the primary.
	promoted bool
}

func (f *standbyAPI) handler() http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop")) })
	mux.HandleFunc("GET /v1/databases/{ref}/standby", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		info := f.info
		if f.promoted {
			info.Primary = info.Standby.Server
			info.Standby = nil
		}
		j(w, 200, info)
	})
	mux.HandleFunc("GET /v1/databases/{ref}/standby/candidates", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, []protocol.StandbyCandidate{
			{HostID: "host_2", Hostname: "db-2", Fingerprint: "7F3A-91C2-0B4E-D8A1", Online: true, Ports: []int{5432}, Usable: true},
			{HostID: "host_3", Hostname: "db-3", Online: false, Reason: "its Rowsafe agent isn't reporting"},
		})
	})
	record := func(r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		f.reqs = append(f.reqs, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/v1/databases/shop/standby")+" "+string(b))
	}
	for _, pattern := range []string{"POST /v1/databases/{ref}/standby", "POST /v1/databases/{ref}/standby/promote",
		"POST /v1/databases/{ref}/standby/rebuild", "POST /v1/databases/{ref}/standby/remove", "PUT /v1/databases/{ref}/standby/failover",
		"POST /v1/databases/{ref}/standby/unfence"} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			record(r)
			if strings.HasSuffix(r.URL.Path, "/promote") {
				f.promoted = true
			}
			if strings.HasSuffix(r.URL.Path, "/failover") {
				f.info.Failover.Automatic = strings.Contains(f.reqs[len(f.reqs)-1], `"automatic":true`)
			}
			j(w, 202, f.info)
		})
	}
	return mux
}

func TestStandbyCommands(t *testing.T) {
	seen := time.Now().Add(-10 * time.Second)
	lag := 0.4
	f := &standbyAPI{info: protocol.StandbyInfo{Database: "shop",
		Primary: protocol.StandbyServer{HostID: "host_1", Hostname: "db-1", Port: 5432, Online: true, LastSeen: &seen},
		Standby: &protocol.StandbyView{ID: "sby_1", Server: protocol.StandbyServer{HostID: "host_2", Hostname: "db-2", Port: 5432, Online: true, LastSeen: &seen},
			Status: protocol.StandbyReady, Mode: protocol.StandbyModeStreaming, LagSeconds: &lag, CanPromote: true, PrimaryReachable: true},
		Failover: protocol.FailoverView{FailoverSettings: protocol.FailoverSettings{AfterSeconds: 180, MaxDataLossSeconds: 60}, Available: true},
		Connect:  []protocol.ConnectString{{Driver: "psql", Value: "postgresql://USER@10.0.0.1:5432,10.0.0.2:5432/DBNAME?target_session_attrs=read-write"}}}}
	ts := httptest.NewServer(f.handler())
	t.Cleanup(ts.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("ROWSAFE_API_KEY", "rsk_test")
	t.Setenv("ROWSAFE_DATABASE", "")
	t.Chdir(t.TempDir())
	t.Cleanup(func() { stdin = os.Stdin })
	old := standbyPoll
	standbyPoll = time.Millisecond
	t.Cleanup(func() { standbyPoll = old })
	ctx := t.Context()
	last := func() string { return f.reqs[len(f.reqs)-1] }

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "shop"}) })
	if err != nil || !strings.Contains(out, "in sync (streaming)") || !strings.Contains(out, "rowsafe standby promote shop") ||
		!strings.Contains(out, "target_session_attrs=read-write") {
		t.Fatalf("standby: %v\n%s", err, out)
	}

	// add: an unusable server is refused; the fingerprint is typed.
	if err := dispatch(ctx, []string{"standby", "add", "shop", "--host", "db-3"}); err == nil || !strings.Contains(err.Error(), "isn't reporting") {
		t.Fatalf("add on an offline server: %v", err)
	}
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = func() bool { return false } })
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "add", "shop", "--host", "db-2"}) }); err == nil ||
		!strings.Contains(err.Error(), "--fingerprint") {
		t.Fatalf("add without a fingerprint and no terminal: %v", err)
	}
	if _, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"standby", "add", "shop", "--host", "db-2", "--fingerprint", "7f3a91c20b4ed8a1", "--no-stream", "--no-wait"})
	}); err != nil || last() != `POST  {"fingerprint":"7f3a91c20b4ed8a1","host_id":"host_2","port":5432,"stream":false}` {
		t.Fatalf("add: %v %s", err, last())
	}

	// failover: on needs the name.
	stdin = strings.NewReader("nope\n")
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "failover", "shop", "--on"}) }); err == nil {
		t.Fatal("failover on without the name")
	}
	if _, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"standby", "failover", "shop", "--on", "--after", "5m", "--yes"})
	}); err != nil || last() != `PUT /failover {"after_seconds":300,"automatic":true,"confirm":"shop","max_data_loss_seconds":60}` {
		t.Fatalf("failover on: %v %s", err, last())
	}

	// promote with the primary down needs --primary-down (with --yes).
	f.mu.Lock()
	f.info.Standby.PrimaryReachable = false
	f.mu.Unlock()
	if err := dispatch(ctx, []string{"standby", "promote", "shop", "--yes"}); err == nil || !strings.Contains(err.Error(), "--primary-down") {
		t.Fatalf("promote without --primary-down: %v", err)
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"standby", "promote", "shop", "--yes", "--primary-down"}) })
	if err != nil || !strings.Contains(out, "db-2 is the primary now") ||
		last() != `POST /promote {"confirm":"shop","primary_down":"db-1 is down"}` {
		t.Fatalf("promote: %v %s\n%s", err, last(), out)
	}
}
