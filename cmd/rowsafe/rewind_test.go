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

func TestParseRewindTime(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip(err)
	}
	oldLocal, oldNow := time.Local, now
	t.Cleanup(func() { time.Local, now = oldLocal, oldNow })
	time.Local = berlin
	fixed := time.Date(2026, 9, 24, 16, 30, 0, 0, time.UTC)
	now = func() time.Time { return fixed }
	for in, want := range map[string]time.Time{
		"2026-09-24T12:04:00Z":      time.Date(2026, 9, 24, 12, 4, 0, 0, time.UTC),
		"2026-09-24T14:04:00+02:00": time.Date(2026, 9, 24, 12, 4, 0, 0, time.UTC),
		"2026-09-24 14:04":          time.Date(2026, 9, 24, 12, 4, 0, 0, time.UTC), // CEST
		"2026-09-24 14:04:30":       time.Date(2026, 9, 24, 12, 4, 30, 0, time.UTC),
		"14:04":                     time.Date(2026, 9, 24, 12, 4, 0, 0, time.UTC),
		"10m ago":                   fixed.Add(-10 * time.Minute),
		"2h ago":                    fixed.Add(-2 * time.Hour),
		"1d ago":                    fixed.Add(-24 * time.Hour),
		"1h30m ago":                 fixed.Add(-90 * time.Minute),
		"90 min ago":                fixed.Add(-90 * time.Minute),
	} {
		got, err := parseRewindTime(in)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "yesterday", "14h", "2026-09-24 25:00", "-10m ago", "ago"} {
		if _, err := parseRewindTime(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := describeTime(time.Date(2026, 9, 24, 12, 4, 0, 0, time.UTC)); got != "2026-09-24 14:04:00 CEST (12:04:00 UTC)" {
		t.Errorf("describeTime = %q", got)
	}
	if _, _, _, err := rewindTarget("19:00", ""); err == nil || !strings.Contains(err.Error(), "future") {
		t.Errorf("a time in the future: %v", err)
	}
	if _, _, _, err := rewindTarget("14:00", "m"); err == nil {
		t.Error("both --at and --mark accepted")
	}
}

func TestTableArgs(t *testing.T) {
	cp := protocol.RewindCopy{Databases: []protocol.DBInfo{{Name: "postgres"}, {Name: "shop"}}}
	got, err := tableArgs([]string{"public.orders", "billing:invoices"}, "", cp)
	if err != nil || len(got) != 2 || got[0] != (protocol.RewindTable{DB: "shop", Table: "public.orders"}) ||
		got[1] != (protocol.RewindTable{DB: "billing", Table: "invoices"}) {
		t.Fatalf("%+v %v", got, err)
	}
	cp.Databases = append(cp.Databases, protocol.DBInfo{Name: "billing"})
	if _, err := tableArgs([]string{"orders"}, "", cp); err == nil || !strings.Contains(err.Error(), "--db") {
		t.Fatalf("ambiguous: %v", err)
	}
	if got, _ := tableArgs([]string{"orders"}, "billing", cp); got[0].DB != "billing" {
		t.Fatalf("--db: %+v", got)
	}
}

// rewindAPI is the control plane's Rewind endpoints, for the CLI.
type rewindAPI struct {
	mu    sync.Mutex
	info  protocol.RewindInfo
	reqs  []string // "METHOD path body"
	tasks map[string]protocol.TaskView
	fail  string // task type that fails
}

func (f *rewindAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("shop", "other")) })
	mux.HandleFunc("GET /v1/databases/{ref}/rewind", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		j(w, 200, f.info)
	})
	queue := func(types ...string) protocol.RewindTasksResponse {
		var out protocol.RewindTasksResponse
		for _, typ := range types {
			tk := protocol.TaskView{ID: fmt.Sprintf("task_%d", len(f.tasks)+1), Type: typ, Status: protocol.StatusQueued}
			f.tasks[tk.ID] = tk
			out.Tasks = append(out.Tasks, tk)
		}
		return out
	}
	record := func(r *http.Request) string {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		f.reqs = append(f.reqs, r.Method+" "+strings.TrimPrefix(r.URL.Path, "/v1/databases/shop/rewind")+" "+string(b))
		return string(b)
	}
	for pattern, types := range map[string][]string{
		"POST /v1/databases/{ref}/rewind/copies":                   {protocol.TaskRewindCopy},
		"DELETE /v1/databases/{ref}/rewind/copies/{id}":            {protocol.TaskRewindDrop},
		"POST /v1/databases/{ref}/rewind/copies/{id}/compare":      {protocol.TaskRewindCompare},
		"POST /v1/databases/{ref}/rewind/copies/{id}/restore-rows": {protocol.TaskRestorePoint, protocol.TaskRewindRows},
		"POST /v1/databases/{ref}/rewind/in-place":                 {protocol.TaskRestorePoint, protocol.TaskRewindInPlace},
		"POST /v1/databases/{ref}/rewind/{rid}/undo":               {protocol.TaskRewindUndo},
		"POST /v1/databases/{ref}/rewind/{rid}/cleanup":            {protocol.TaskRewindCleanup},
	} {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			f.mu.Lock()
			defer f.mu.Unlock()
			record(r)
			j(w, 202, queue(types...))
		})
	}
	mux.HandleFunc("POST /v1/databases/{ref}/rewind/copies/{id}/extend", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		record(r)
		j(w, 200, protocol.RewindCopy{ID: r.PathValue("id"), Expires: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)})
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		tk, ok := f.tasks[r.PathValue("id")]
		if !ok {
			j(w, 404, protocol.Error{Error: "not found"})
			return
		}
		tk.Status = protocol.StatusSucceeded
		var res any
		switch tk.Type {
		case protocol.TaskRestorePoint:
			res = protocol.RestorePointResult{Name: "before-rewind-20260924-143000", Archived: true}
		case protocol.TaskRewindCopy:
			res = protocol.RewindCopyResult{CopyID: "cp_1", Summary: "The copy is ready: 1.0 GiB, restored to the last change before 12:04:00 UTC."}
		case protocol.TaskRewindCompare:
			res = protocol.RewindCompareResult{CopyID: "cp_1", Summary: "Compared 2 tables: 1,204 rows are missing in production (in public.orders).",
				Tables: []protocol.RewindTableDiff{
					{RewindTable: protocol.RewindTable{DB: "shop", Table: "public.orders"}, MissingInProduction: 1204, Changed: 3,
						Related: []protocol.RewindTable{{DB: "shop", Table: "public.customers"}}},
					{RewindTable: protocol.RewindTable{DB: "shop", Table: "public.events"}, Skipped: "it has no primary key"},
				}}
		case protocol.TaskRewindRows:
			res = protocol.RewindRowsResult{Summary: "Brought back 1,204 rows in public.orders."}
		case protocol.TaskRewindInPlace:
			res = protocol.RewindInPlaceResult{Summary: "Rewound the database to 12:04:00 UTC on 2026-09-24."}
		case protocol.TaskRewindUndo:
			res = protocol.RewindUndoResult{Summary: "Undid the rewind."}
		case protocol.TaskRewindCleanup:
			res = protocol.RewindCleanupResult{Summary: "Deleted the data from before the rewind (1.0 GiB)."}
		case protocol.TaskRewindDrop:
			res = protocol.RewindDropResult{Summary: "Deleted the copy."}
		}
		if tk.Type == f.fail {
			tk.Status, tk.Error = protocol.StatusFailed, "Rewinding failed while restoring the backup: boom. Rowsafe put the original data back."
		}
		tk.Result, _ = json.Marshal(res)
		j(w, 200, tk)
	})
	return mux
}

func TestRewindCommands(t *testing.T) {
	expires := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	at := time.Date(2026, 9, 24, 12, 4, 0, 0, time.UTC)
	f := &rewindAPI{tasks: map[string]protocol.TaskView{}, info: protocol.RewindInfo{Database: "shop",
		Earliest: &at, Latest: &expires, CanRewindInPlace: true,
		Copy: &protocol.RewindCopy{ID: "cp_1", Status: "ready", Target: protocol.RewindTarget{Time: &at}, SizeBytes: 1 << 30,
			Databases: []protocol.DBInfo{{Name: "postgres"}, {Name: "shop"}}, Expires: expires},
		Kept: []protocol.RewindKept{{RewindID: "rw_1", Status: protocol.RewindKeptBefore, SizeBytes: 1 << 30, CreatedAt: at}}}}
	ts := httptest.NewServer(f.handler(t))
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

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "shop"}) })
	if err != nil || !strings.Contains(out, "Recovery window: any second from") || !strings.Contains(out, "Copy cp_1: ready") ||
		!strings.Contains(out, "rowsafe rewind undo shop") || !strings.Contains(out, "rowsafe rewind database shop") {
		t.Fatalf("rewind: %v\n%s", err, out)
	}

	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"rewind", "copy", "shop", "--at", "2026-09-24T12:04:00Z", "--hours", "48"})
	})
	if err != nil || !strings.Contains(out, "The copy is ready") || !strings.Contains(out, "rowsafe rewind compare shop") {
		t.Fatalf("copy: %v\n%s", err, out)
	}
	if last() != `POST /copies {"hours":48,"time":"2026-09-24T12:04:00Z"}` {
		t.Fatalf("copy request %s", last())
	}
	if err := dispatch(ctx, []string{"rewind", "copy", "shop"}); err == nil || !strings.Contains(err.Error(), "--at TIME") {
		t.Fatalf("copy without a point: %v", err)
	}
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "copy", "shop", "--mark", "before-migration"}) }); err != nil ||
		last() != `POST /copies {"hours":24,"mark":"before-migration"}` {
		t.Fatalf("copy at a mark: %v %s", err, last())
	}

	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "compare", "shop", "public.orders"}) })
	if err != nil || !strings.Contains(out, "public.orders") || !strings.Contains(out, "1204") || !strings.Contains(out, "public.customers") ||
		!strings.Contains(out, "public.events: it has no primary key") || !strings.Contains(out, "rowsafe rewind rows shop public.orders") {
		t.Fatalf("compare: %v\n%s", err, out)
	}
	if last() != `POST /copies/cp_1/compare {"tables":[{"db":"shop","table":"public.orders"}]}` {
		t.Fatalf("compare request %s", last())
	}

	// Bring back rows: the name must be typed.
	n := len(f.reqs)
	stdin = strings.NewReader("y\n")
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "rows", "shop", "public.orders"}) }); err == nil ||
		!strings.Contains(err.Error(), "cancelled") || len(f.reqs) != n {
		t.Fatalf("rows with y: %v", err)
	}
	stdin = strings.NewReader("shop\n")
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"rewind", "rows", "shop", "public.orders", "--include-changed"})
	})
	if err != nil || !strings.Contains(out, "Mark saved first: before-rewind-") || !strings.Contains(out, "Brought back 1,204 rows in public.orders.") {
		t.Fatalf("rows: %v\n%s", err, out)
	}
	if last() != `POST /copies/cp_1/restore-rows {"confirm":"shop","include_changed":true,"tables":[{"db":"shop","table":"public.orders"}]}` {
		t.Fatalf("rows request %s", last())
	}

	// The whole database: very explicit, name typed.
	stdin = strings.NewReader("yes\n")
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"rewind", "database", "shop", "--at", "2026-09-24T12:04:00Z"})
	})
	if err == nil || !strings.Contains(out, "will be removed from the live database") || !strings.Contains(out, "kept aside for 7 days") {
		t.Fatalf("database without the name: %v\n%s", err, out)
	}
	stdin = strings.NewReader("shop\n")
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"rewind", "database", "shop", "--at", "2026-09-24T12:04:00Z"})
	})
	if err != nil || !strings.Contains(out, "Rewound the database") || !strings.Contains(out, "rowsafe rewind undo shop") {
		t.Fatalf("database: %v\n%s", err, out)
	}
	if last() != `POST /in-place {"confirm":"shop","time":"2026-09-24T12:04:00Z"}` {
		t.Fatalf("in-place request %s", last())
	}
	// A failed rewind says so and exits 1.
	f.fail = protocol.TaskRewindInPlace
	stdin = strings.NewReader("shop\n")
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "database", "shop", "--mark", "m"}) })
	var exit exitError
	if !errors.As(err, &exit) || !strings.Contains(out, "put the original data back") {
		t.Fatalf("failed rewind: %v\n%s", err, out)
	}
	f.fail = ""

	stdin = strings.NewReader("shop\n")
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "undo", "shop"}) }); err != nil ||
		last() != `POST /rw_1/undo {"confirm":"shop"}` || !strings.Contains(out, "Undid the rewind.") {
		t.Fatalf("undo: %v %s\n%s", err, last(), out)
	}
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "cleanup", "shop", "--yes"}) }); err != nil ||
		last() != `POST /rw_1/cleanup null` || !strings.Contains(out, "Deleted the data") {
		t.Fatalf("cleanup: %v %s\n%s", err, last(), out)
	}
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "extend", "shop", "--hours", "48"}) }); err != nil ||
		last() != `POST /copies/cp_1/extend {"hours":48}` || !strings.Contains(out, "now kept until") {
		t.Fatalf("extend: %v %s\n%s", err, last(), out)
	}
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"rewind", "drop", "shop", "--yes"}) }); err != nil ||
		last() != `DELETE /copies/cp_1 null` || !strings.Contains(out, "Deleted the copy.") {
		t.Fatalf("drop: %v %s\n%s", err, last(), out)
	}

	// No copy yet: compare and rows say what to do first.
	f.info.Copy = nil
	if err := dispatch(ctx, []string{"rewind", "compare", "shop"}); err == nil || !strings.Contains(err.Error(), "rowsafe rewind copy shop") {
		t.Fatalf("compare without a copy: %v", err)
	}
	if h := helpFor([]string{"rewind"}); !strings.Contains(h, "rowsafe rewind rows [NAME] TABLE...") || !strings.Contains(h, "never touches production") {
		t.Errorf("help rewind:\n%s", h)
	}
}
