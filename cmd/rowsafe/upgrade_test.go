package main

import (
	"encoding/json"
	"errors"
	"fmt"
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

// upgradeAPI is the control plane's update and upgrade endpoints, for the CLI.
type upgradeAPI struct {
	mu    sync.Mutex
	info  protocol.UpgradeInfo
	reqs  []string
	tasks map[string]protocol.TaskView
	fail  string
}

func (f *upgradeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop")) })
	mux.HandleFunc("GET /v1/databases/{ref}/upgrades", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		j(w, 200, f.info)
	})
	record := func(r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		f.reqs = append(f.reqs, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/v1/databases/shop")+" "+string(b))
	}
	for pattern, types := range map[string][]string{
		"POST /v1/databases/{ref}/update":                {protocol.TaskRestorePoint, protocol.TaskPGUpdate},
		"POST /v1/databases/{ref}/upgrades/check":        {protocol.TaskUpgradeCheck},
		"POST /v1/databases/{ref}/upgrades/rehearsal":    {protocol.TaskUpgradeRehearsal},
		"POST /v1/databases/{ref}/upgrades":              {protocol.TaskRestorePoint, protocol.TaskUpgrade},
		"POST /v1/databases/{ref}/upgrades/{id}/undo":    {protocol.TaskRestorePoint, protocol.TaskUpgradeUndo},
		"POST /v1/databases/{ref}/upgrades/{id}/cleanup": {protocol.TaskUpgradeCleanup},
	} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			record(r)
			var out protocol.UpgradeTasksResponse
			for _, typ := range types {
				tk := protocol.TaskView{ID: fmt.Sprintf("task_%d", len(f.tasks)+1), Type: typ, Status: protocol.StatusQueued}
				f.tasks[tk.ID] = tk
				out.Tasks = append(out.Tasks, tk)
			}
			j(w, 202, out)
		})
	}
	mux.HandleFunc("PUT /v1/databases/{ref}/auto-update", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var req protocol.AutoUpdateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.reqs = append(f.reqs, fmt.Sprintf("PUT /auto-update %v %s", req.Enabled, req.Timezone))
		info := f.info
		info.AutoMinorUpdates, info.AutoTimezone = req.Enabled, req.Timezone
		next := time.Date(2026, 9, 27, 1, 0, 0, 0, time.UTC)
		info.NextAutoUpdate = &next
		j(w, 200, info)
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		tk := f.tasks[r.PathValue("id")]
		tk.Status = protocol.StatusSucceeded
		var res any
		switch tk.Type {
		case protocol.TaskRestorePoint:
			res = protocol.RestorePointResult{Name: "before-upgrade-18-20260925-120000", Archived: true}
		case protocol.TaskPGUpdate:
			res = protocol.PGUpdateResult{Summary: "Updated PostgreSQL from 17.2 to 17.6 in 9 s."}
		case protocol.TaskUpgradeCheck:
			res = protocol.UpgradeCheckResult{FromMajor: 17, ToMajor: 18, CanRehearse: true, CanUpgrade: true, Summary: "Ready to rehearse.",
				Checks: []protocol.UpgradeCheck{{ID: "target", Status: protocol.CheckOK, Title: "PostgreSQL 18.1 is available"},
					{ID: "standbys", Status: protocol.CheckWarning, Title: "1 replica streams from this server", Detail: "Set it up again afterwards."}}}
		case protocol.TaskUpgradeRehearsal:
			res = protocol.UpgradeRehearsalResult{FromMajor: 17, ToMajor: 18, FromVersion: "17.6", ToVersion: "18.1", Passed: true,
				UpgradeSeconds: 20, SafeDowntimeSeconds: 95, FastDowntimeSeconds: 30}
		case protocol.TaskUpgrade:
			res = protocol.UpgradeResult{Summary: "Upgraded PostgreSQL 17.6 to 18.1 in 2 min 10 s."}
		case protocol.TaskUpgradeUndo:
			res = protocol.UpgradeUndoResult{Summary: "Back on PostgreSQL 17.6."}
		case protocol.TaskUpgradeCleanup:
			res = protocol.UpgradeCleanupResult{Summary: "Removed PostgreSQL 17/main (2.0 GiB freed)."}
		}
		if tk.Type == f.fail {
			tk.Status, tk.Error = protocol.StatusFailed, "The rehearsal found problems: pg_upgrade --check found problems."
		}
		tk.Result, _ = json.Marshal(res)
		j(w, 200, tk)
	})
	return mux
}

func TestUpdateAndUpgradeCommands(t *testing.T) {
	f := &upgradeAPI{tasks: map[string]protocol.TaskView{}, info: protocol.UpgradeInfo{Database: "shop", Host: "db1", Version: "17.2", Major: 17,
		Installed: "17.2", Candidate: "17.6", UpdateAvailable: true, Majors: []int{18}, Allowed: []string{"postgresql"}}}
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
	ctx := t.Context()
	last := func() string { return f.reqs[len(f.reqs)-1] }

	// update: the name must be typed.
	stdin = strings.NewReader("y\n")
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"update", "shop"}) }); err == nil || len(f.reqs) != 0 {
		t.Fatalf("update with y: %v %v", err, f.reqs)
	}
	stdin = strings.NewReader("shop\n")
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"update", "shop"}) })
	if err != nil || !strings.Contains(out, "Update available:   17.6") || !strings.Contains(out, "Mark saved first") ||
		!strings.Contains(out, "Updated PostgreSQL from 17.2 to 17.6") || last() != `POST /update {"confirm":"shop"}` {
		t.Fatalf("update: %v %v\n%s", err, f.reqs, out)
	}
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"update", "shop", "--auto", "on", "--timezone", "Europe/Berlin"})
	})
	if err != nil || last() != "PUT /auto-update true Europe/Berlin" || !strings.Contains(out, "Sundays at 03:00 (Europe/Berlin)") {
		t.Fatalf("auto: %v %s\n%s", err, last(), out)
	}
	// Up to date: says so, asks nothing.
	f.info.UpdateAvailable, f.info.UpdateReason = false, "PostgreSQL 17.6 is the newest 17 release this server's package sources offer."
	n := len(f.reqs)
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"update", "shop"}) }); err != nil || len(f.reqs) != n ||
		!strings.Contains(out, "is the newest 17 release") {
		t.Fatalf("up to date: %v\n%s", err, out)
	}

	// upgrade without flags shows the state.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "shop"}) })
	if err != nil || !strings.Contains(out, "Newer majors:       18") || !strings.Contains(out, "rowsafe upgrade shop --rehearse-only") {
		t.Fatalf("upgrade state: %v\n%s", err, out)
	}
	// --rehearse-only: check and rehearsal, nothing else.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "shop", "--rehearse-only"}) })
	if err != nil || !strings.Contains(out, "note 1 replica streams") || !strings.Contains(out, "Rehearsal of 17.6 -> 18.1: passed") ||
		!strings.Contains(out, "Safe mode about 1m35s") || strings.Contains(strings.Join(f.reqs, "\n"), "POST /upgrades {") {
		t.Fatalf("rehearse only: %v %v\n%s", err, f.reqs, out)
	}
	if f.reqs[len(f.reqs)-2] != `POST /upgrades/check {"to":18}` || last() != `POST /upgrades/rehearsal {"to":18}` {
		t.Fatalf("rehearsal requests %v", f.reqs)
	}
	// A failed rehearsal stops there.
	f.fail = protocol.TaskUpgradeRehearsal
	n = len(f.reqs)
	var exit exitError
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "shop", "--to", "18", "--yes"}) }); !errors.As(err, &exit) ||
		!strings.Contains(out, "found problems") || len(f.reqs) != n+2 {
		t.Fatalf("failed rehearsal: %v %v\n%s", err, f.reqs, out)
	}
	f.fail = ""
	// With a valid rehearsal: straight to the upgrade, name typed.
	at := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	exp := at.Add(14 * 24 * time.Hour)
	f.info.Rehearsal = &protocol.UpgradeRehearsalResult{FromMajor: 17, ToMajor: 18, Passed: true, SafeDowntimeSeconds: 95, FastDowntimeSeconds: 30}
	f.info.RehearsalValid, f.info.RehearsalAt, f.info.RehearsalExpires = true, &at, &exp
	stdin = strings.NewReader("shop\n")
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "shop", "--to", "18", "--mode", "fast"}) })
	if err != nil || !strings.Contains(out, "about 30s without connections") || !strings.Contains(out, "anything written after the upgrade is lost") ||
		!strings.Contains(out, "Upgraded PostgreSQL 17.6 to 18.1") || last() != `POST /upgrades {"confirm":"shop","mode":"fast","to":18}` {
		t.Fatalf("upgrade: %v %s\n%s", err, last(), out)
	}
	if err := dispatch(ctx, []string{"upgrade", "shop", "--mode", "yolo"}); err == nil {
		t.Error("bad mode accepted")
	}
	// Undo and cleanup.
	exp7 := at.Add(7 * 24 * time.Hour)
	f.info.Upgrade = &protocol.UpgradeState{ID: "upg_1", FromMajor: 17, ToMajor: 18, Mode: protocol.UpgradeSafe, Status: protocol.UpgradeDone,
		Expires: &exp7, BackupsReady: true}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "shop"}) })
	if err != nil || !strings.Contains(out, "rowsafe upgrade undo shop") || !strings.Contains(out, "rowsafe upgrade cleanup shop") {
		t.Fatalf("state after the upgrade: %v\n%s", err, out)
	}
	stdin = strings.NewReader("shop\n")
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "undo", "shop"}) }); err != nil ||
		last() != `POST /upgrades/upg_1/undo {"confirm":"shop"}` || !strings.Contains(out, "Back on PostgreSQL 17.6.") {
		t.Fatalf("undo: %v %s\n%s", err, last(), out)
	}
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"upgrade", "cleanup", "shop", "--yes"}) }); err != nil ||
		last() != `POST /upgrades/upg_1/cleanup {"confirm":"shop"}` || !strings.Contains(out, "Removed PostgreSQL 17/main") {
		t.Fatalf("cleanup: %v %s\n%s", err, last(), out)
	}
	if h := helpFor([]string{"upgrade"}); !strings.Contains(h, "--rehearse-only") || !strings.Contains(h, "rowsafe upgrade undo") {
		t.Errorf("help upgrade:\n%s", h)
	}
}
