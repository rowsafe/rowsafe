package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestAdoptEngineDefaults: rowsafe adopt sends PostgreSQL's defaults only
// for PostgreSQL. Every other engine gets its own (or 0, which the control
// plane fills in with the engine's own port and backup schedule), so a new
// engine in protocol.Engines can't be registered on 5432 with
// PostgreSQL's socket directory and retention.
func TestAdoptEngineDefaults(t *testing.T) {
	var got protocol.CreateDatabaseRequest
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/databases", func(w http.ResponseWriter, r *http.Request) {
		got = protocol.CreateDatabaseRequest{}
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(protocol.CreateDatabaseResponse{Database: protocol.Database{ID: "d1", Name: "app"}, Task: protocol.TaskView{ID: "t1"}})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	c := client.New(ts.URL, "rsk_test")
	adopt := func(args ...string) protocol.CreateDatabaseRequest {
		t.Helper()
		if err := adoptCmd(context.Background(), c, append([]string{"--host", "h1", "--no-wait"}, args...)); err != nil {
			t.Fatalf("adopt %v: %v", args, err)
		}
		return got
	}
	type want struct {
		port      int
		socketDir string
		retention int
	}
	for _, e := range protocol.Engines {
		args := []string{"--engine", e, "app"}
		w := want{} // the control plane's defaults for the engine
		switch e {
		case protocol.EnginePostgreSQL:
			w = want{5432, "/var/run/postgresql", 2}
		case protocol.EngineMySQL:
			w = want{3306, "/var/run/mysqld/mysqld.sock", 2}
		case protocol.EngineMariaDB:
			w = want{3306, "/run/mysqld/mysqld.sock", 2}
		case protocol.EngineSQLite:
			args = []string{"--engine", e, "--path", "/srv/app/db.sqlite3", "app"}
			w = want{0, "/srv/app/db.sqlite3", 0}
		}
		r := adopt(args...)
		if r.Port != w.port || r.SocketDir != w.socketDir || r.RetentionFull != w.retention || r.Engine != e {
			t.Errorf("%s: sent port %d, socket %q, retention %d (engine %q); want %+v", e, r.Port, r.SocketDir, r.RetentionFull, r.Engine, w)
		}
	}
	// Flags given on the command line are kept.
	if r := adopt("--engine", protocol.EngineOpenSearch, "--port", "9201", "--retention-full", "3", "app"); r.Port != 9201 || r.RetentionFull != 3 || r.SocketDir != "" {
		t.Errorf("opensearch with flags: %+v", r)
	}
}

// TestAdoptEngineHelp: every engine is in --engine's help, from
// protocol.Engines.
func TestAdoptEngineHelp(t *testing.T) {
	h := helpFor([]string{"adopt"})
	for _, e := range protocol.Engines {
		if !strings.Contains(adoptEngineList(), e) || !strings.Contains(h, e) {
			t.Errorf("%s is missing from adopt's help:\n%s", e, h)
		}
	}
	if !strings.Contains(adoptEngineList(), "postgresql (default)") {
		t.Errorf("list = %q", adoptEngineList())
	}
}
