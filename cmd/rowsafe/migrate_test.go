package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// fakeMigrations plays the control plane and the server's agent for
// rowsafe migrate: it opens the sealed source like the agent would and
// seals the new connection string to the CLI's key.
type fakeMigrations struct {
	mu        sync.Mutex
	m         protocol.Migration
	gotSource string
	bodies    []string
	creds     *protocol.MigrationCredentials
	readOnly  bool
}

func TestMigrateStartAndSwitch(t *testing.T) {
	agentKey, _ := e2e.GenerateKey()
	f := &fakeMigrations{}
	const source = "postgres://doadmin:s3cret@db-1.db.ondigitalocean.com:25060/defaultdb?sslmode=require"
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	record := func(r *http.Request) []byte {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.bodies = append(f.bodies, string(b))
		f.mu.Unlock()
		return b
	}
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, dbs("shop")) })
	mux.HandleFunc("POST /v1/migrations", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		f.m = protocol.Migration{ID: "mig_1", DatabaseName: "shop", Status: protocol.MigratePhaseReady,
			PublicKey: e2e.PublicKeyString(agentKey.PublicKey()), TaskStatus: protocol.StatusSucceeded}
		j(w, f.m)
	})
	mux.HandleFunc("GET /v1/migrations/mig_1", func(w http.ResponseWriter, r *http.Request) { j(w, f.m) })
	mux.HandleFunc("POST /v1/migrations/mig_1/check", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CheckMigrationRequest
		_ = json.Unmarshal(record(r), &req)
		plain, err := e2e.Open(agentKey, protocol.MigrateInfo, protocol.MigrateSourceAAD("mig_1"), req.Source)
		if err != nil {
			t.Errorf("the agent can't open the source: %v", err)
		}
		f.gotSource = string(plain)
		f.m.Status, f.m.TaskStatus = protocol.MigratePhaseChecked, protocol.StatusSucceeded
		f.m.Check = &protocol.MigrateCheckResult{LiveSync: true, DumpOK: true, Method: protocol.MigrateMethodLive,
			Source:  protocol.MigrateSource{Host: "db-1.db.ondigitalocean.com", Provider: "digitalocean", SizeBytes: 5 << 30},
			Target:  protocol.MigrateTarget{Database: "defaultdb"},
			Checks:  []protocol.MigrateCheckItem{{ID: "logical", Status: protocol.CheckOK, Title: "Logical replication is on at the source"}},
			Summary: "Ready for live sync"}
		j(w, f.m)
	})
	mux.HandleFunc("POST /v1/migrations/mig_1/start", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		lag := int64(0)
		f.m.Status, f.m.Method = protocol.MigratePhaseSyncing, protocol.MigrateMethodLive
		f.m.Progress = &protocol.MigrationStatus{Phase: protocol.MigratePhaseSyncing, TablesTotal: 3, TablesCopied: 3, LagBytes: &lag}
		j(w, f.m)
	})
	mux.HandleFunc("POST /v1/migrations/mig_1/switchover", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.SwitchoverRequest
		_ = json.Unmarshal(record(r), &req)
		f.readOnly = req.ReadOnly
		if req.Confirm != "shop" {
			t.Errorf("confirm = %q", req.Confirm)
		}
		pub, err := e2e.ParsePublicKey(req.BrowserKey)
		if err != nil {
			t.Fatal(err)
		}
		box, _ := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateCredentialsAAD("mig_1"), []byte("postgresql://app:n3w@203.0.113.5:5432/defaultdb?sslmode=require"))
		f.creds = &protocol.MigrationCredentials{Credentials: box, AppUser: "app"}
		f.m.Status, f.m.TaskStatus, f.m.CredentialsReady = protocol.MigratePhaseSwitched, protocol.StatusSucceeded, true
		f.m.Switchover = &protocol.MigrateSwitchoverResult{Summary: "Switched over: 3 tables, 1,000 rows, all match."}
		j(w, f.m)
	})
	mux.HandleFunc("POST /v1/migrations/mig_1/credentials/claim", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		j(w, f.creds)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	_, _ = cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("MY_SOURCE", source)
	t.Cleanup(func() { stdin, stdinIsTerminal = os.Stdin, func() bool { return false } })
	stdinIsTerminal = func() bool { return false }

	out, err := captureStdout(t, func() error {
		return dispatch(t.Context(), []string{"migrate", "start", "shop", "--source-env", "MY_SOURCE", "--yes"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if f.gotSource != source {
		t.Errorf("the agent got %q", f.gotSource)
	}
	for _, b := range f.bodies {
		if strings.Contains(b, "s3cret") || strings.Contains(b, "doadmin") {
			t.Fatalf("the source reached the control plane in the clear: %s", b)
		}
	}
	if !strings.Contains(out, "DigitalOcean") || !strings.Contains(out, "rowsafe migrate switch mig_1") {
		t.Errorf("start output:\n%s", out)
	}

	out, err = captureStdout(t, func() error {
		return dispatch(t.Context(), []string{"migrate", "switch", "mig_1", "--yes"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !f.readOnly || !strings.Contains(out, "postgresql://app:n3w@203.0.113.5:5432/defaultdb") || !strings.Contains(out, "all match") {
		t.Errorf("switch output:\n%s", out)
	}
}

// A Turso database into a SQLite file: the source is built from the URL
// and the token, sealed here; the copy ends with the file's path, no
// password.
func TestMigrateStartSQLite(t *testing.T) {
	agentKey, _ := e2e.GenerateKey()
	const token = "eyJhbGciOiJFZERTQSJ9.eyJpZCI6InNlY3JldCJ9.c2lnbmF0dXJlLXNlY3JldA"
	var mu sync.Mutex
	var bodies []string
	var gotSource string
	var started protocol.StartMigrationRequest
	m := protocol.Migration{ID: "mig_2", DatabaseName: "app", Engine: protocol.EngineSQLite, Status: protocol.MigratePhaseReady,
		PublicKey: e2e.PublicKeyString(agentKey.PublicKey()), TaskStatus: protocol.StatusSucceeded}
	j := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	record := func(r *http.Request) []byte {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		return b
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { j(w, dbs("app")) })
	mux.HandleFunc("POST /v1/migrations", func(w http.ResponseWriter, r *http.Request) { record(r); j(w, m) })
	mux.HandleFunc("GET /v1/migrations/mig_2", func(w http.ResponseWriter, r *http.Request) { j(w, m) })
	mux.HandleFunc("POST /v1/migrations/mig_2/check", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CheckMigrationRequest
		_ = json.Unmarshal(record(r), &req)
		plain, _ := e2e.Open(agentKey, protocol.MigrateInfo, protocol.MigrateSourceAAD("mig_2"), req.Source)
		gotSource = string(plain)
		m.Status = protocol.MigratePhaseChecked
		m.Check = &protocol.MigrateCheckResult{DumpOK: true, Method: protocol.MigrateMethodDump, EstimatedCopySeconds: 5,
			Source: protocol.MigrateSource{Host: "app-acme.turso.io", Database: "app-acme", Provider: "turso", SizeBytes: 1 << 20},
			Target: protocol.MigrateTarget{Database: "/srv/app/data.db", Exists: true}, Summary: "Ready for a one-time copy"}
		j(w, m)
	})
	mux.HandleFunc("POST /v1/migrations/mig_2/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.Unmarshal(record(r), &started)
		m.Status, m.Method, m.TargetDB = protocol.MigratePhaseSwitched, protocol.MigrateMethodDump, "/srv/app/data.db"
		m.Switchover = &protocol.MigrateSwitchoverResult{Summary: "/srv/app/data.db now holds app-acme from Turso.", ConnectionHint: "/srv/app/data.db"}
		j(w, m)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	_, _ = cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("TURSO_TOKEN", token)
	t.Cleanup(func() { stdin, stdinIsTerminal = os.Stdin, func() bool { return false } })
	stdinIsTerminal = func() bool { return false }
	out, err := captureStdout(t, func() error {
		return dispatch(t.Context(), []string{"migrate", "start", "app", "--turso", "app-acme.turso.io", "--source-env", "TURSO_TOKEN", "--yes"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if gotSource != "libsql://app-acme.turso.io?authToken="+token {
		t.Errorf("the agent got %q", gotSource)
	}
	for _, b := range bodies {
		if strings.Contains(b, token) {
			t.Fatalf("the token reached the control plane in the clear: %s", b)
		}
	}
	if started.Method != protocol.MigrateMethodDump || started.ReadOnly {
		t.Errorf("start = %+v", started)
	}
	if !strings.Contains(out, "From Turso") || !strings.Contains(out, "point your app at the file /srv/app/data.db") || strings.Contains(out, token) {
		t.Errorf("output:\n%s", out)
	}
	if _, err := sqliteSource("", "nope", "TURSO_TOKEN"); err == nil {
		t.Error("--d1 without a slash accepted")
	}
	if _, err := sqliteSource("", "0123456789abcdef0123456789abcdef/not-a-uuid", "TURSO_TOKEN"); err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("bad D1 id: %v", err)
	}
}
