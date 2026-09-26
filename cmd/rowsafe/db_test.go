package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeDBAdmin is the control plane and the agent for rowsafe db: it seals
// the new password to the key the CLI sent, like the agent does, and hands
// the sealed secret out once.
type fakeDBAdmin struct {
	mu      sync.Mutex
	params  []protocol.DBAdminParams
	secrets map[string]*protocol.SealedSecret
	fetched int
}

func (f *fakeDBAdmin) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, 200, dbs("app")) })
	tasks := map[string]protocol.TaskView{}
	mux.HandleFunc("POST /v1/databases/app/dbadmin", func(w http.ResponseWriter, r *http.Request) {
		var p protocol.DBAdminParams
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.params = append(f.params, p)
		id := "task_" + string(rune('a'+len(f.params)))
		res := protocol.DBAdminResult{Action: p.Action, Summary: "Created the user " + p.User + "."}
		if protocol.DBAdminMakesPassword(p) {
			conn := protocol.DBConnection{User: p.User, Database: "shop", Host: "10.0.0.5", Port: 5432, SSLMode: "require"}
			plain, _ := json.Marshal(protocol.DBSecret{DBConnection: conn, Password: "Pw123", URL: protocol.ConnectionURL(conn, "Pw123")})
			sealed, err := protocol.Seal(p.PublicKey, []byte(id), plain)
			if err != nil {
				t.Fatal(err)
			}
			f.secrets[id] = sealed
			res.Connection = &conn
		}
		raw, _ := json.Marshal(res)
		tasks[id] = protocol.TaskView{ID: id, Type: protocol.TaskDBAdmin, Status: protocol.StatusSucceeded, Result: raw}
		j(w, 202, protocol.DBAdminResponse{Tasks: []protocol.TaskView{{ID: id, Type: protocol.TaskDBAdmin, Status: protocol.StatusQueued}}})
	})
	mux.HandleFunc("GET /v1/tasks/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		j(w, 200, tasks[r.PathValue("id")])
	})
	mux.HandleFunc("POST /v1/databases/app/dbadmin/secret", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.DBAdminSecretRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		s := f.secrets[req.TaskID]
		if s == nil {
			j(w, 404, protocol.Error{Error: "gone"})
			return
		}
		delete(f.secrets, req.TaskID)
		f.fetched++
		j(w, 200, s)
	})
	return mux
}

func TestDBUserAdd(t *testing.T) {
	f := &fakeDBAdmin{secrets: map[string]*protocol.SealedSecret{}}
	ts := httptest.NewServer(f.handler(t))
	defer ts.Close()
	cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_URL", ts.URL)

	out, err := captureStdout(t, func() error {
		return dispatch(t.Context(), []string{"db", "user", "add", "reporting", "--db", "shop", "--access", "read-only"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	p := f.params[0]
	if p.Action != protocol.DBAdminCreateUser || p.Access != protocol.DBAccessReadOnly || len(p.Databases) != 1 || p.PublicKey == "" {
		t.Errorf("params %+v", p)
	}
	for _, want := range []string{"Created the user reporting.", "postgresql://reporting:Pw123@10.0.0.5:5432/shop?sslmode=require",
		"password  Pw123", "Rowsafe doesn't keep the password"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if f.fetched != 1 || len(f.secrets) != 0 {
		t.Errorf("secret fetched %d times", f.fetched)
	}

	// Checked before anything is sent.
	if err := dispatch(t.Context(), []string{"db", "create", "Bad-Name"}); err == nil || !strings.Contains(err.Error(), "can't be used") {
		t.Errorf("bad name: %v", err)
	}
	if err := dispatch(t.Context(), []string{"db", "user", "add", "x"}); err == nil || !strings.Contains(err.Error(), "at least one database") {
		t.Errorf("no --db: %v", err)
	}
	if err := dispatch(t.Context(), []string{"db", "drop", "shop"}); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("drop without a terminal: %v", err)
	}
	if len(f.params) != 1 {
		t.Errorf("sent %d requests", len(f.params))
	}
}
