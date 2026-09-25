package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// markAPI serves what rowsafe mark --json uses. A
// label starting with "fail-" makes the task fail after writing the Mark
// (not confirmed in the repository).
func markAPI(t *testing.T) {
	t.Helper()
	var mu sync.Mutex
	points := map[string]protocol.RestorePoint{} // task ID -> point
	tasks := map[string]protocol.TaskView{}
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, []protocol.Database{{ID: "db_app", Name: "app", Status: protocol.DBActive, Hostname: "db1"}})
	})
	mux.HandleFunc("POST /v1/databases/{ref}/restore-points", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CreateRestorePointRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		defer mu.Unlock()
		for _, p := range points {
			if p.Name == req.Name {
				j(w, 409, protocol.Error{Error: `restore point "` + req.Name + `" already exists for app`})
				return
			}
		}
		id := "task_" + req.Name
		tasks[id] = protocol.TaskView{ID: id, Type: protocol.TaskRestorePoint, Status: protocol.StatusQueued}
		points[id] = protocol.RestorePoint{ID: "rp_" + req.Name, Name: req.Name, Status: protocol.RestorePointPending, TaskID: id}
		j(w, 201, tasks[id])
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tk := tasks[r.PathValue("id")]
		p := points[tk.ID]
		now := time.Now().UTC()
		p.LSN, p.WALFile, p.CreatedAt, p.RestoreFromBackup = "0/3000090", "000000010000000000000003", &now, "20260924-020000F"
		if len(p.Name) > 5 && p.Name[:5] == "fail-" {
			tk.Status, tk.Error, tk.Log = protocol.StatusFailed, "restore point was created but is not yet confirmed in the repository", "timed out"
			p.Status = protocol.RestorePointUnconfirmed
		} else {
			tk.Status = protocol.StatusSucceeded
			p.Status, p.ArchivedAt = protocol.RestorePointArchived, &now
		}
		tasks[tk.ID], points[tk.ID] = tk, p
		j(w, 200, tk)
	})
	mux.HandleFunc("GET /v1/databases/{ref}/restore-points", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		out := []protocol.RestorePoint{}
		for _, p := range points {
			out = append(out, p)
		}
		j(w, 200, out)
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

func TestMarkJSON(t *testing.T) {
	markAPI(t)
	ctx := t.Context()

	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"mark", "app", "before-deploy-abc1234", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var m markJSON
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if m.Database != "app" || m.Name != "before-deploy-abc1234" || m.Status != protocol.RestorePointArchived ||
		m.RestoreFromBackup != "20260924-020000F" || m.LSN == "" || m.ArchivedAt == nil || m.Error != "" {
		t.Fatalf("mark --json = %+v", m)
	}

	// --no-wait: the Mark is pending; the database is inferred.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"mark", "queued-only", "--no-wait", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	m = markJSON{}
	if err := json.Unmarshal([]byte(out), &m); err != nil || m.Database != "app" || m.Status != protocol.RestorePointPending || m.TaskID == "" {
		t.Fatalf("mark --no-wait --json = %+v (%v)\n%s", m, err, out)
	}

	// A task that fails still prints the Mark, with the error, and exits 1.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"mark", "app", "fail-archiving", "--json"}) })
	var exit exitError
	if !errors.As(err, &exit) || exit != 1 {
		t.Fatalf("failed task: err %v", err)
	}
	m = markJSON{}
	if err := json.Unmarshal([]byte(out), &m); err != nil || m.Status != protocol.RestorePointUnconfirmed || m.Error == "" {
		t.Fatalf("failed mark --json = %+v (%v)\n%s", m, err, out)
	}

	// A duplicate label is an API error, on stderr, with nothing on stdout.
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"mark", "app", "before-deploy-abc1234", "--json"}) })
	if err == nil || out != "" {
		t.Fatalf("duplicate: err %v, stdout %q", err, out)
	}
}
