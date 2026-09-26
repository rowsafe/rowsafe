package main

import (
	"encoding/json"
	"errors"
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

// fakeSettingsAPI is the control plane's settings endpoints for one
// database, "shop".
type fakeSettingsAPI struct {
	mu       sync.Mutex
	ov       protocol.SettingsOverview
	applied  []protocol.ApplySettingsRequest
	reverted []string
	query    string // the last GET's query string
	result   protocol.SettingsResult
	reject   string
}

func (f *fakeSettingsAPI) handler() http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop")) })
	mux.HandleFunc("GET /v1/databases/shop/settings", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.query = r.URL.RawQuery
		j(w, 200, f.ov)
	})
	mux.HandleFunc("POST /v1/databases/shop/settings", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.ApplySettingsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.reject != "" {
			j(w, http.StatusBadRequest, protocol.Error{Error: f.reject})
			return
		}
		f.applied = append(f.applied, req)
		j(w, http.StatusAccepted, protocol.ApplySettingsResponse{ChangeID: "stc_1", Tasks: []protocol.TaskView{
			{ID: "task_mark", Type: protocol.TaskRestorePoint, Status: protocol.StatusQueued},
			{ID: "task_set", Type: protocol.TaskSettings, Status: protocol.StatusQueued}}})
	})
	mux.HandleFunc("POST /v1/databases/shop/settings/changes/{id}/revert", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reverted = append(f.reverted, r.PathValue("id"))
		j(w, http.StatusAccepted, protocol.ApplySettingsResponse{ChangeID: "stc_2", Tasks: []protocol.TaskView{
			{ID: "task_set", Type: protocol.TaskSettings, Status: protocol.StatusQueued}}})
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		t := protocol.TaskView{ID: r.PathValue("id"), Status: protocol.StatusSucceeded}
		if t.ID == "task_mark" {
			t.Type = protocol.TaskRestorePoint
			t.Result, _ = json.Marshal(protocol.RestorePointResult{Name: "before-tune-20260925-120000", Archived: true})
		} else {
			t.Type = protocol.TaskSettings
			t.Result, _ = json.Marshal(f.result)
		}
		j(w, 200, t)
	})
	return mux
}

func settingsCLI(t *testing.T, f *fakeSettingsAPI) {
	t.Helper()
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
}

func settingsOverview() protocol.SettingsOverview {
	prev := "64MB"
	return protocol.SettingsOverview{
		Available: true, Workload: protocol.WorkloadMixed, CanChange: true,
		Host: protocol.SettingsHost{MemoryBytes: 16 << 30, CPUs: 4, Disk: protocol.DiskSSD},
		Settings: []protocol.SettingView{
			{Name: "shared_buffers", Category: protocol.SettingsCatMemory, Title: "Memory for caching data", Explanation: "Memory PostgreSQL sets aside.",
				Value: "128 MB", Default: "128 MB", Source: "postgresql.conf", Apply: "restart"},
			{Name: "work_mem", Category: protocol.SettingsCatMemory, Value: "4 MB", Default: "4 MB", Source: "default", Apply: "reload"},
			{Name: "archive_command", Category: protocol.SettingsCatWAL, Value: "pgbackrest ...", Default: "(none)", Source: "postgresql.auto.conf",
				Apply: "reload", Locked: true, LockedReason: "Rowsafe sets this."},
		},
		Other: []protocol.SettingView{{Name: "log_line_prefix", Category: protocol.SettingsCatOther, Value: "%m", Source: "postgresql.conf", Apply: "reload"}},
		Recommendations: []protocol.Recommendation{
			{Name: "shared_buffers", Current: "128 MB", Value: "4GB", Display: "4 GB", Why: "A quarter of memory.", Restart: true},
			{Name: "work_mem", Current: "4 MB", Value: "18MB", Display: "18 MB", Why: "Fewer spills."},
			{Name: "idle_in_transaction_session_timeout", Current: "off", Value: "10min", Display: "10 min", Why: "Ends forgotten transactions.", Optional: true},
		},
		PendingRestart: []string{},
		Changes: []protocol.SettingsChange{{ID: "stc_9", Kind: protocol.SettingsKindSet, Status: protocol.StatusSucceeded, CreatedBy: "key:k (ci)",
			CreatedAt: time.Now().Add(-time.Hour), Summary: "Set work_mem to 64 MB.", CanRevert: true,
			Applied: []protocol.AppliedSetting{{Name: "work_mem", From: "4 MB", To: "64MB", Previous: &prev}}}},
	}
}

func TestSettingsList(t *testing.T) {
	f := &fakeSettingsAPI{ov: settingsOverview()}
	settingsCLI(t, f)
	ctx := t.Context()
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"settings", "shop"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PostgreSQL settings of shop (16 GB memory, 4 CPUs, SSD)", "Memory", "shared_buffers", "needs a restart",
		"managed by Rowsafe", "1 other setting set in a configuration file: --all lists them.",
		"Rowsafe recommends 2 changes for this server: `rowsafe tune shop`", "stc_9", "Undo the latest: rowsafe settings undo shop stc_9"} {
		if !strings.Contains(out, want) {
			t.Errorf("settings lacks %q:\n%s", want, out)
		}
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"settings", "shop", "shared_buffers"}) })
	if err != nil || !strings.Contains(out, "shared_buffers: Memory for caching data") || !strings.Contains(out, "Recommended: 4 GB. A quarter of memory.") ||
		!strings.Contains(out, "takes effect after a restart") {
		t.Errorf("one setting: %v\n%s", err, out)
	}
	// With the project's database, the one argument is a setting.
	t.Setenv("ROWSAFE_DATABASE", "shop")
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"settings", "archive_command"}) })
	if err != nil || !strings.Contains(out, "never through Rowsafe. Rowsafe sets this.") {
		t.Errorf("locked setting: %v\n%s", err, out)
	}
	if err := dispatch(ctx, []string{"settings", "shop", "no_such"}); err == nil {
		t.Error("an unknown setting printed nothing")
	}
}

func TestSettingsSet(t *testing.T) {
	f := &fakeSettingsAPI{ov: settingsOverview(), result: protocol.SettingsResult{Summary: "Changed 2 settings. 1 take effect at once; 1 when PostgreSQL restarts.",
		Applied: []protocol.AppliedSetting{{Name: "work_mem"}, {Name: "shared_buffers", Restart: true}}}}
	settingsCLI(t, f)
	ctx := t.Context()
	stdin = strings.NewReader("y\n")
	out, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"settings", "set", "shop", "work_mem=64MB", "Shared_Buffers=2GB", "log_line_prefix=default"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"work_mem: 4 MB -> 64MB", "shared_buffers: 128 MB -> 2GB (after a restart)", "log_line_prefix: %m -> its default",
		"Some take effect only after PostgreSQL restarts", "Mark saved: before-tune-", "Changed 2 settings.",
		"Restart PostgreSQL when it suits you: rowsafe restart shop", "Undo: rowsafe settings undo shop stc_1"} {
		if !strings.Contains(out, want) {
			t.Errorf("set lacks %q:\n%s", want, out)
		}
	}
	last := f.applied[len(f.applied)-1]
	if last.Kind != protocol.SettingsKindSet || len(last.Changes) != 3 || last.Changes[2] != (protocol.SettingChange{Name: "log_line_prefix", Reset: true}) {
		t.Errorf("request %+v", last)
	}
	n := len(f.applied)
	stdin = strings.NewReader("n\n")
	if err := dispatch(ctx, []string{"settings", "set", "shop", "work_mem=64MB"}); err == nil || !strings.Contains(err.Error(), "cancelled") || len(f.applied) != n {
		t.Errorf("declined: %v", err)
	}
	if err := dispatch(ctx, []string{"settings", "set", "shop", "work_mem"}); err == nil || !strings.Contains(err.Error(), "SETTING=VALUE") {
		t.Errorf("no value: %v", err)
	}
	f.reject = "archive_command: Rowsafe never changes this setting."
	if err := dispatch(ctx, []string{"settings", "set", "shop", "archive_command=x", "--yes"}); err == nil || !strings.Contains(err.Error(), "not changed: archive_command") {
		t.Errorf("refused: %v", err)
	}
	f.reject = ""
	f.ov.CanChange, f.ov.ChangeReason = false, "The agent on db1 isn't connected."
	if err := dispatch(ctx, []string{"settings", "set", "shop", "work_mem=8MB", "--yes"}); err == nil || !strings.Contains(err.Error(), "isn't connected") {
		t.Errorf("offline: %v", err)
	}
}

func TestTune(t *testing.T) {
	f := &fakeSettingsAPI{ov: settingsOverview(), result: protocol.SettingsResult{Summary: "Changed 2 settings."}}
	settingsCLI(t, f)
	ctx := t.Context()
	stdin = strings.NewReader("y\n")
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"tune", "shop", "--workload", "web", "--disk", "ssd"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"Tune shop for this server (16 GB memory, 4 CPUs, SSD; workload: mixed)", "* shared_buffers: 128 MB -> 4 GB (after a restart)",
		"A quarter of memory.", "  idle_in_transaction_session_timeout: off -> 10 min (optional: --all adds it)", "Apply 2 changes?"} {
		if !strings.Contains(out, want) {
			t.Errorf("tune lacks %q:\n%s", want, out)
		}
	}
	if f.query != "disk=ssd&workload=web" {
		t.Errorf("query %q", f.query)
	}
	req := f.applied[0]
	if req.Kind != protocol.SettingsKindTune || req.Workload != "web" || req.Disk != "ssd" || len(req.Changes) != 2 || req.Changes[0] != (protocol.SettingChange{Name: "shared_buffers", Value: "4GB"}) {
		t.Errorf("request %+v", req)
	}
	// --all adds the optional one.
	stdin = strings.NewReader("")
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"tune", "shop", "--all", "--yes"}) }); err != nil || len(f.applied[1].Changes) != 3 {
		t.Errorf("--all: %v %+v", err, f.applied)
	}
	if err := dispatch(ctx, []string{"tune", "shop", "--workload", "games"}); err == nil {
		t.Error("bad workload accepted")
	}
	f.ov.Recommendations = nil
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"tune", "shop"}) })
	if err != nil || !strings.Contains(out, "Nothing to change") {
		t.Errorf("nothing to tune: %v\n%s", err, out)
	}
}

func TestSettingsUndo(t *testing.T) {
	f := &fakeSettingsAPI{ov: settingsOverview(), result: protocol.SettingsResult{Summary: "Set work_mem to 64 MB."}}
	settingsCLI(t, f)
	ctx := t.Context()
	stdin = strings.NewReader("y\n")
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"settings", "undo", "shop"}) })
	if err != nil || !strings.Contains(out, "work_mem back to 64MB") || len(f.reverted) != 1 || f.reverted[0] != "stc_9" {
		t.Fatalf("undo: %v %v\n%s", err, f.reverted, out)
	}
	f.ov.Changes[0].CanRevert = false
	var exit exitError
	if err := dispatch(ctx, []string{"settings", "undo", "shop", "stc_9", "--yes"}); err == nil || errors.As(err, &exit) || !strings.Contains(err.Error(), "can't be undone") {
		t.Errorf("not revertable: %v", err)
	}
	if err := dispatch(ctx, []string{"settings", "undo", "shop"}); err == nil || !strings.Contains(err.Error(), "nothing to undo") {
		t.Errorf("nothing: %v", err)
	}
}
