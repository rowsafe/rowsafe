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

// forkAPI is the control plane's Fork endpoints, for the CLI.
type forkAPI struct {
	mu    sync.Mutex
	reqs  []protocol.CreateForkRequest
	polls int
}

func (f *forkAPI) handler() http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop")) })
	mux.HandleFunc("GET /v1/databases/{ref}/forks", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.ForkInfo{Database: "shop", CanFork: true, Targets: []protocol.ForkTarget{
			{HostID: "host_1", Hostname: "db-1", SameServer: true, Online: true, Usable: true,
				Places: []protocol.ForkPlace{{Placement: protocol.ForkNewCluster, Label: "a new PostgreSQL 18 cluster on a free port"}}},
			{HostID: "host_2", Hostname: "db-2", Online: true, Usable: true, Fingerprint: "7F3A-91C2-0B4E-D8A1",
				Places: []protocol.ForkPlace{{Placement: protocol.ForkEmptyCluster, Port: 5433, Label: "the empty PostgreSQL 18 cluster on port 5433"}}},
			{HostID: "host_3", Hostname: "db-3", Reason: "PostgreSQL 18 isn't installed there"},
		}, Forks: []protocol.ForkView{{ID: "fork_0", Name: "shop-old", Status: protocol.ForkFailed, Hostname: "db-2", Error: "the bucket is unreachable"}}})
	})
	mux.HandleFunc("POST /v1/databases/{ref}/forks", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var req protocol.CreateForkRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.reqs = append(f.reqs, req)
		j(w, 202, protocol.ForkView{ID: "fork_1", Name: req.Name, SourceName: "shop", Hostname: "db-2", Status: protocol.ForkPreparing,
			Steps: []protocol.ForkProgressStep{{Key: "prepare", Label: "Hand over bucket access", State: protocol.ForkStepRunning}}})
	})
	mux.HandleFunc("GET /v1/forks/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.polls++
		at := time.Date(2026, 9, 24, 14, 4, 0, 0, time.UTC)
		j(w, 200, protocol.ForkView{ID: "fork_1", Name: "shop-staging", SourceName: "shop", Hostname: "db-2", Port: 5433,
			Status: protocol.ForkReady, RecoveredTo: &at, Masking: &protocol.ForkMaskReport{Tables: 2, Columns: 3, Rows: 1204},
			Steps: []protocol.ForkProgressStep{{Key: "prepare", Label: "Hand over bucket access", State: protocol.ForkStepDone},
				{Key: "restore", Label: "Restore", State: protocol.ForkStepDone, Detail: "1.2 GiB"}}})
	})
	return mux
}

func TestForkCommands(t *testing.T) {
	f := &forkAPI{}
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
	old := forkPoll
	forkPoll = time.Millisecond
	t.Cleanup(func() { forkPoll = old })
	ctx := t.Context()

	// Where to? The servers are listed, with why one can't.
	_, err := captureStdout(t, func() error { return dispatch(ctx, []string{"fork", "shop"}) })
	if err == nil || !strings.Contains(err.Error(), "db-3 (PostgreSQL 18 isn't installed there)") {
		t.Fatalf("%v", err)
	}
	// Same server: a new cluster, now, no fingerprint.
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"fork", "shop", "--to", "db-1", "--port", "5441"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	r := f.reqs[len(f.reqs)-1]
	if r.Name != "shop-fork" || r.HostID != "host_1" || r.Placement != protocol.ForkNewCluster || r.Port != 5441 || r.At != nil || r.Mark != "" || r.Fingerprint != "" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(out, "now (Rowsafe saves a Mark first)") || !strings.Contains(out, "✓ Restore: 1.2 GiB") ||
		!strings.Contains(out, "shop-staging is ready on db-2:5433") || !strings.Contains(out, "Masked 3 columns in 2 tables (1204 rows)") {
		t.Fatal(out)
	}
	// Another server needs the fingerprint (typed, or --fingerprint off a terminal).
	old2 := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() { stdinIsTerminal = old2 })
	_, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"fork", "shop", "--to", "db-2", "--mark", "before-migration", "--mask"})
	})
	if err == nil || !strings.Contains(err.Error(), "--fingerprint") {
		t.Fatalf("%v", err)
	}
	_, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"fork", "shop", "--to", "db-2", "--mark", "before-migration", "--mask", "--name", "shop-staging",
			"--fingerprint", "7F3A-91C2-0B4E-D8A1", "--no-wait"})
	})
	if err != nil {
		t.Fatal(err)
	}
	r = f.reqs[len(f.reqs)-1]
	if r.Name != "shop-staging" || r.Placement != protocol.ForkEmptyCluster || r.Port != 5433 || r.Mark != "before-migration" || !r.Mask ||
		r.Fingerprint != "7F3A-91C2-0B4E-D8A1" {
		t.Fatalf("%+v", r)
	}
	// --into-port must be one of the empty clusters.
	if _, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"fork", "shop", "--to", "db-2", "--into-port", "5499", "--fingerprint", "x"})
	}); err == nil || !strings.Contains(err.Error(), "5433") {
		t.Fatalf("%v", err)
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"forks", "shop"}) })
	if err != nil || !strings.Contains(out, "shop-old") || !strings.Contains(out, "the bucket is unreachable") {
		t.Fatalf("%v\n%s", err, out)
	}
}
