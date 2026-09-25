// Command mockapi is a stand-in for the Rowsafe API, just enough for the
// GitHub Action's tests (rowsafe show, status, mark, marks). It uses the
// protocol types, so a change there that breaks the action shows up here.
//
//	go run ./integrations/github-action/test/mockapi -addr 127.0.0.1:8787 -databases app,unprotected
//
// A database whose name contains "unprotected" is not protected; one whose
// name contains "broken" fails every Mark (not confirmed in the repository);
// on one whose name contains "stuck", the agent never picks up the task.
// GET /_mock/marks lists the Marks created so far, one "db/name" per line.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

type api struct {
	mu     sync.Mutex
	dbs    []string
	points []protocol.RestorePoint // newest last
	tasks  map[string]*protocol.TaskView
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address")
	names := flag.String("databases", "app", "comma-separated database names")
	flag.Parse()
	a := &api{dbs: strings.Split(*names, ","), tasks: map[string]*protocol.TaskView{}}
	log.Printf("mock Rowsafe API on http://%s with databases %s", *addr, *names)
	log.Fatal(http.ListenAndServe(*addr, a.handler()))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *api) database(name string) (protocol.Database, bool) {
	if !slices.Contains(a.dbs, name) {
		return protocol.Database{}, false
	}
	return protocol.Database{ID: "db_" + name, Name: name, Status: protocol.DBActive, Hostname: "db1",
		Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}, true
}

func (a *api) handler() http.Handler {
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer rsk_") {
				writeJSON(w, http.StatusUnauthorized, protocol.Error{Error: "missing or invalid API key"})
				return
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			h(w, r)
		}
	}
	db := func(h func(http.ResponseWriter, *http.Request, protocol.Database)) http.HandlerFunc {
		return auth(func(w http.ResponseWriter, r *http.Request) {
			d, ok := a.database(r.PathValue("ref"))
			if !ok {
				writeJSON(w, http.StatusNotFound, protocol.Error{Error: fmt.Sprintf("database %q not found", r.PathValue("ref"))})
				return
			}
			h(w, r, d)
		})
	}

	mux.HandleFunc("GET /v1/databases", auth(func(w http.ResponseWriter, r *http.Request) {
		out := []protocol.Database{}
		for _, n := range a.dbs {
			d, _ := a.database(n)
			out = append(out, d)
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /v1/databases/{ref}", db(func(w http.ResponseWriter, r *http.Request, d protocol.Database) {
		writeJSON(w, http.StatusOK, d)
	}))
	mux.HandleFunc("GET /v1/databases/{ref}/protection", db(func(w http.ResponseWriter, r *http.Request, d protocol.Database) {
		now := time.Now().UTC()
		backup, passed := now.Add(-3*time.Hour), now.Add(-50*time.Hour)
		p := protocol.Protection{Protected: true, Reasons: []string{}, Status: d.Status, CheckedAt: now,
			LastBackupAt: &backup, WALLastArchivedAt: &now, ArchiverUp: true, LastDrillPassedAt: &passed,
			OpenFailedTasks: []protocol.TaskView{}}
		if strings.Contains(d.Name, "unprotected") {
			p.Protected = false
			p.Reasons = []string{"WAL archiving is failing: the last attempt failed 12 minutes ago",
				"no restore test (Proof) has passed in the last 8 days"}
		}
		writeJSON(w, http.StatusOK, p)
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/restore-points", db(func(w http.ResponseWriter, r *http.Request, d protocol.Database) {
		var req protocol.CreateRestorePointRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
			writeJSON(w, http.StatusBadRequest, protocol.Error{Error: "name is required"})
			return
		}
		for _, p := range a.points {
			if p.DatabaseID == d.ID && p.Name == req.Name {
				writeJSON(w, http.StatusConflict, protocol.Error{Error: fmt.Sprintf("restore point %q already exists for %s", req.Name, d.Name)})
				return
			}
		}
		id := fmt.Sprintf("task_%d", len(a.tasks)+1)
		t := &protocol.TaskView{ID: id, Type: protocol.TaskRestorePoint, Status: protocol.StatusQueued,
			DatabaseName: d.Name, CreatedAt: time.Now().UTC()}
		a.tasks[id] = t
		a.points = append(a.points, protocol.RestorePoint{ID: "rp_" + id, DatabaseID: d.ID, Name: req.Name,
			Status: protocol.RestorePointPending, TaskID: id, CreatedBy: "api key ci", RequestedAt: t.CreatedAt})
		log.Printf("Mark %s/%s requested (%s)", d.Name, req.Name, id)
		writeJSON(w, http.StatusCreated, t)
	}))
	mux.HandleFunc("GET /v1/tasks/{id}", auth(func(w http.ResponseWriter, r *http.Request) {
		t, ok := a.tasks[r.PathValue("id")]
		if !ok {
			writeJSON(w, http.StatusNotFound, protocol.Error{Error: "task not found"})
			return
		}
		// Queued on the first poll, finished on the next one.
		if strings.Contains(t.DatabaseName, "stuck") {
			writeJSON(w, http.StatusOK, t)
			return
		}
		if t.Status == protocol.StatusQueued {
			t.Status = protocol.StatusRunning
			writeJSON(w, http.StatusOK, t)
			return
		}
		if t.Status == protocol.StatusRunning {
			i := slices.IndexFunc(a.points, func(p protocol.RestorePoint) bool { return p.TaskID == t.ID })
			p := &a.points[i]
			now := time.Now().UTC()
			p.LSN, p.WALFile, p.CreatedAt, p.RestoreFromBackup = "0/3000090", "000000010000000000000003", &now, "20260924-020000F"
			if strings.Contains(t.DatabaseName, "broken") {
				t.Status = protocol.StatusFailed
				t.Error = fmt.Sprintf("restore point %q was created at 0/3000090 but is not yet confirmed in the repository "+
					"(WAL segment 000000010000000000000003): timed out after 1m30s. WAL archiving may be failing; check `rowsafe show`", p.Name)
				p.Status = protocol.RestorePointUnconfirmed
			} else {
				t.Status = protocol.StatusSucceeded
				p.ArchivedAt, p.Status = &now, protocol.RestorePointArchived
				t.Result, _ = json.Marshal(protocol.RestorePointResult{Name: p.Name, LSN: p.LSN, WALFile: p.WALFile,
					Archived: true, CreatedAt: now, ArchivedAt: &now})
			}
			log.Printf("Mark %s/%s %s", t.DatabaseName, p.Name, t.Status)
		}
		writeJSON(w, http.StatusOK, t)
	}))
	mux.HandleFunc("GET /v1/databases/{ref}/restore-points", db(func(w http.ResponseWriter, r *http.Request, d protocol.Database) {
		out := []protocol.RestorePoint{}
		for i := len(a.points) - 1; i >= 0; i-- {
			if a.points[i].DatabaseID == d.ID {
				out = append(out, a.points[i])
			}
		}
		writeJSON(w, http.StatusOK, out)
	}))
	mux.HandleFunc("GET /_mock/marks", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		for _, p := range a.points {
			fmt.Fprintf(w, "%s/%s %s\n", strings.TrimPrefix(p.DatabaseID, "db_"), p.Name, p.Status)
		}
	})
	return mux
}
