package main

import (
	"context"
	"encoding/json"
	"net"
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

// fakeAccount is the account a server without one connects to.
type fakeAccount struct {
	mu           sync.Mutex
	existing     []string // database names the account already has
	alreadySetUp bool     // what the plan finds
	registered   map[string]protocol.SetupDatabase
	applied      map[string]bool
	imported     []protocol.ImportDatabase
	deleted      []string
	revoked      bool
}

const agentTok = "rsa_agent-token"

func (f *fakeAccount) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	user := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer rsk_person" {
				writeTestJSON(w, 401, protocol.Error{Error: "unknown key"})
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			h(w, r)
		}
	}
	agent := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+agentTok {
				writeTestJSON(w, 401, protocol.Error{Error: "unknown agent token"})
				return
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/whoami", user(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, 200, protocol.WhoAmI{Org: protocol.Org{ID: "org_1", Name: "Acme"}})
	}))
	mux.HandleFunc("GET /v1/databases", user(func(w http.ResponseWriter, r *http.Request) {
		out := []protocol.Database{}
		for _, n := range f.existing {
			out = append(out, protocol.Database{ID: "db_x", Name: n})
		}
		writeTestJSON(w, 200, out)
	}))
	mux.HandleFunc("POST /v1/hosts/enrollment-tokens", user(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, 201, protocol.EnrollmentToken{Token: "rse_once", ExpiresAt: time.Now().Add(time.Hour)})
	}))
	mux.HandleFunc("DELETE /v1/databases/{ref}", user(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("keep_archiving") != "true" {
			t.Error("a half-connected database is removed with keep_archiving")
		}
		f.deleted = append(f.deleted, r.PathValue("ref"))
		w.WriteHeader(204)
	}))
	mux.HandleFunc("DELETE /v1/hosts/{ref}", user(func(w http.ResponseWriter, r *http.Request) {
		f.deleted = append(f.deleted, r.PathValue("ref"))
		w.WriteHeader(204)
	}))
	mux.HandleFunc("POST /v1/auth/logout", user(func(w http.ResponseWriter, r *http.Request) {
		f.revoked = true
		w.WriteHeader(204)
	}))
	mux.HandleFunc("POST /v1/agent/setup/databases", agent(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.SetupRegisterRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		sd := protocol.SetupDatabase{ID: "db_acc_" + req.Name, Name: req.Name, Port: req.Port, SocketDir: req.SocketDir,
			Status: protocol.DBPendingAdopt, PlanTaskStatus: protocol.StatusQueued}
		f.registered[sd.ID] = sd
		writeTestJSON(w, 201, sd)
	}))
	mux.HandleFunc("GET /v1/agent/setup/databases/{id}", agent(func(w http.ResponseWriter, r *http.Request) {
		sd := f.registered[r.PathValue("id")]
		sd.PlanTaskStatus, sd.Plan = protocol.StatusSucceeded, &protocol.AdoptResult{AlreadySetUp: f.alreadySetUp}
		if f.applied[sd.ID] {
			sd.Status = protocol.DBActive
		}
		writeTestJSON(w, 200, sd)
	}))
	mux.HandleFunc("POST /v1/agent/setup/databases/{id}/apply", agent(func(w http.ResponseWriter, r *http.Request) {
		f.applied[r.PathValue("id")] = true
		writeTestJSON(w, 202, f.registered[r.PathValue("id")])
	}))
	mux.HandleFunc("POST /v1/agent/import", agent(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.ImportRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.imported = append(f.imported, req.Databases...)
		out := protocol.ImportResponse{}
		for _, d := range req.Databases {
			out.Databases = append(out.Databases, protocol.ImportCounts{Name: d.Name, Backups: len(d.Backups), Drills: len(d.Drills), RestorePoints: len(d.RestorePoints)})
		}
		writeTestJSON(w, 200, out)
	}))
	return mux
}

func writeTestJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// noAccountServer lays out a server without an account in a temporary
// directory: agent.env, the agent's identity, the control plane's state
// with one protected database and its history, and an agent that
// restarts onto whatever agent.env says.
type noAccountServer struct {
	dir, env, state, sock string
	envBefore             []byte
	restarts              int
	ln                    net.Listener
}

func newNoAccountServer(t *testing.T, open ...protocol.TaskView) *noAccountServer {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rs-na") // short: a socket path has a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s := &noAccountServer{dir: dir, env: filepath.Join(dir, "agent.env"), state: filepath.Join(dir, "state")}
	s.sock = filepath.Join(s.state, "control.sock")
	if err := os.Mkdir(s.state, 0o700); err != nil {
		t.Fatal(err)
	}
	s.envBefore = []byte("# Rowsafe agent\nROWSAFE_URL='unix://" + s.sock + "'\nROWSAFE_STATE_DIR=" + s.state +
		"\n#ROWSAFE_ENROLL_TOKEN=\nROWSAFE_REPO_S3_BUCKET='shop-backups'\nROWSAFE_REPO_S3_KEY_SECRET='s3cret'\n")
	if err := os.WriteFile(s.env, s.envBefore, 0o640); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(s.state, "agent.json"), []byte(`{"host_id":"host_l","agent_token":"rsl_local"}`), 0o600)
	at := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
	created := at.Add(2 * time.Hour)
	tasks := []map[string]any{}
	for _, o := range open {
		tasks = append(tasks, map[string]any{"id": o.ID, "type": o.Type, "status": o.Status, "database_id": "db_l1", "database_name": "shop"})
	}
	st := map[string]any{
		"host": map[string]any{"id": "host_l", "token": "rsl_local", "hostname": "db1"},
		"databases": []protocol.Database{{ID: "db_l1", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql",
			Status: protocol.DBActive, Engine: protocol.EnginePostgreSQL}},
		"tasks":   tasks,
		"backups": []protocol.Backup{{ID: "bk_1", DatabaseID: "db_l1", TaskID: "task_1", Label: "20261014-010000F", Type: protocol.BackupFull, StartedAt: at, StoppedAt: at.Add(time.Minute)}},
		"drills":  []protocol.Drill{{ID: "drill_1", DatabaseID: "db_l1", TaskID: "task_2", Passed: true, CreatedAt: at.Add(time.Hour)}},
		"restore_points": []protocol.RestorePoint{
			{ID: "rp_1", DatabaseID: "db_l1", Name: "before-drop", TaskID: "task_3", LSN: "0/3000000", CreatedAt: &created, RequestedAt: created},
			{ID: "rp_2", DatabaseID: "db_l1", Name: "never-written", TaskID: "task_4", RequestedAt: created},
		},
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(s.state, "local-control.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	s.listen(t)

	oldEnv, oldRestart, oldSleep, oldTerm := agentEnvPath, restartAgent, sleepCtx, stdinIsTerminal
	agentEnvPath = s.env
	restartAgent = func(ctx context.Context) error { s.restart(t); return nil }
	sleepCtx = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	stdinIsTerminal = func() bool { return false }
	t.Cleanup(func() {
		agentEnvPath, restartAgent, sleepCtx, stdinIsTerminal = oldEnv, oldRestart, oldSleep, oldTerm
		if s.ln != nil {
			s.ln.Close()
		}
	})
	return s
}

func (s *noAccountServer) listen(t *testing.T) {
	ln, err := net.Listen("unix", s.sock)
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
}

// restart is the agent starting again with agent.env as it is now.
func (s *noAccountServer) restart(t *testing.T) {
	s.restarts++
	if s.ln != nil {
		s.ln.Close() // removes the socket
		s.ln = nil
	}
	data, _ := os.ReadFile(s.env)
	if _, local := protocol.LocalSocket(envValue(data, "ROWSAFE_URL")); local {
		s.listen(t)
		return
	}
	if envValue(data, "ROWSAFE_ENROLL_TOKEN") == "rse_once" {
		_ = os.WriteFile(filepath.Join(s.state, "agent.json"), []byte(`{"host_id":"host_acc","agent_token":"`+agentTok+`"}`), 0o600)
	}
}

func accountEnv(t *testing.T, f *fakeAccount) *httptest.Server {
	t.Helper()
	f.registered, f.applied = map[string]protocol.SetupDatabase{}, map[string]bool{}
	ts := httptest.NewServer(f.handler(t))
	t.Cleanup(ts.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ROWSAFE_URL", "")
	t.Setenv("ROWSAFE_API_KEY", "")
	return ts
}

func TestLoginConnectsServerWithoutAccount(t *testing.T) {
	f := &fakeAccount{alreadySetUp: true}
	ts := accountEnv(t, f)
	s := newNoAccountServer(t)
	ctx := t.Context()

	// No terminal and no --yes: refused before logging in.
	err := dispatch(ctx, []string{"login", "--url", ts.URL, "--key", "rsk_person"})
	if err == nil || !strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), "1 database: shop") {
		t.Fatalf("without --yes: %v", err)
	}
	if err := dispatch(ctx, []string{"login", "--url", ts.URL, "--key", "rsk_person", "--yes"}); err != nil {
		t.Fatal(err)
	}
	env, _ := os.ReadFile(s.env)
	if envValue(env, "ROWSAFE_URL") != ts.URL || envValue(env, "ROWSAFE_ENROLL_TOKEN") != "" ||
		envValue(env, "ROWSAFE_REPO_S3_KEY_SECRET") != "s3cret" || envValue(env, "ROWSAFE_STATE_DIR") != s.state {
		t.Fatalf("agent.env after connecting:\n%s", env)
	}
	if !strings.HasPrefix(string(env), "# Rowsafe agent\n") || strings.Count(string(env), "ROWSAFE_URL=") != 1 {
		t.Fatalf("agent.env lost its shape:\n%s", env)
	}
	if fi, _ := os.Stat(s.env); fi.Mode().Perm() != 0o640 {
		t.Errorf("agent.env mode %v", fi.Mode().Perm())
	}
	if s.restarts != 1 || !f.applied["db_acc_shop"] {
		t.Fatalf("restarts %d, applied %v", s.restarts, f.applied)
	}
	if len(f.imported) != 1 || len(f.imported[0].Backups) != 1 || len(f.imported[0].Drills) != 1 ||
		len(f.imported[0].RestorePoints) != 1 || f.imported[0].RestorePoints[0].Name != "before-drop" {
		t.Fatalf("imported %+v", f.imported)
	}
	for _, p := range []string{s.env + asideSuffix, filepath.Join(s.state, "agent.json") + asideSuffix, filepath.Join(s.state, "local-control.json"), s.sock} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s is still there", p)
		}
	}
	if _, err := os.Stat(filepath.Join(s.state, "local-control.json") + connectedSuffix); err != nil {
		t.Error("the control plane's state isn't kept aside")
	}
	// Logged in now, to the account.
	saved, _, _ := readSavedConfig()
	if saved.APIKey != "rsk_person" || saved.URL != ts.URL {
		t.Fatalf("saved login %+v", saved)
	}
}

func TestLoginPutsServerBack(t *testing.T) {
	f := &fakeAccount{alreadySetUp: false} // an agent too old to say so
	ts := accountEnv(t, f)
	s := newNoAccountServer(t)
	err := dispatch(t.Context(), []string{"login", "--url", ts.URL, "--key", "rsk_person", "--yes"})
	if err == nil {
		t.Fatal("connected although the plan didn't find Rowsafe's backups")
	}
	for _, want := range []string{"Put back as it was", "Backups never stopped", "Removed what this attempt had added", "Not logged in"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q:\n%v", want, err)
		}
	}
	if env, _ := os.ReadFile(s.env); string(env) != string(s.envBefore) {
		t.Fatalf("agent.env not put back:\n%s", env)
	}
	if id, _ := os.ReadFile(filepath.Join(s.state, "agent.json")); !strings.Contains(string(id), "rsl_local") {
		t.Fatalf("the agent's identity not put back: %s", id)
	}
	if fi, err := os.Stat(s.sock); err != nil || fi.Mode()&os.ModeSocket == 0 || s.restarts != 2 {
		t.Fatalf("the agent isn't back on its own control plane (restarts %d, %v)", s.restarts, err)
	}
	if _, err := os.Stat(filepath.Join(s.state, "local-control.json")); err != nil {
		t.Fatal("the control plane's state moved")
	}
	if strings.Join(f.deleted, ",") != "shop,host_acc" || len(f.imported) != 0 || len(f.applied) != 0 {
		t.Fatalf("account cleanup: deleted %v, imported %v, applied %v", f.deleted, f.imported, f.applied)
	}
	if saved, _, _ := readSavedConfig(); saved.APIKey != "" {
		t.Fatal("the login was saved although the server wasn't connected")
	}
}

func TestLoginRefusesBeforeChanging(t *testing.T) {
	f := &fakeAccount{alreadySetUp: true, existing: []string{"shop"}}
	ts := accountEnv(t, f)
	s := newNoAccountServer(t)
	err := dispatch(t.Context(), []string{"login", "--url", ts.URL, "--key", "rsk_person", "--yes"})
	if err == nil || !strings.Contains(err.Error(), "already has a database named shop") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("name taken: %v", err)
	}
	if env, _ := os.ReadFile(s.env); string(env) != string(s.envBefore) || s.restarts != 0 {
		t.Fatal("changed the server")
	}

	// A backup running: wait for it.
	f2 := &fakeAccount{alreadySetUp: true}
	ts2 := accountEnv(t, f2)
	s2 := newNoAccountServer(t, protocol.TaskView{ID: "task_9", Type: protocol.TaskBackup, Status: protocol.StatusRunning})
	err = dispatch(t.Context(), []string{"login", "--url", ts2.URL, "--key", "rsk_person", "--yes"})
	if err == nil || !strings.Contains(err.Error(), "backup is running") || s2.restarts != 0 {
		t.Fatalf("running backup: %v", err)
	}
}

func TestAnswerYes(t *testing.T) {
	t.Cleanup(func() { stdin = os.Stdin })
	for in, want := range map[string]bool{"\n": true, "y\n": true, "Yes\n": true, "n\n": false, "": false, "y": true, "nope\n": false} {
		stdin = strings.NewReader(in)
		if got := answerYes(); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}

// On a terminal: the question, and no answer (the input ends) is no.
func TestLoginAsksBeforeConnecting(t *testing.T) {
	f := &fakeAccount{alreadySetUp: true}
	ts := accountEnv(t, f)
	s := newNoAccountServer(t)
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdin = os.Stdin })
	stdin = strings.NewReader("")
	err := dispatch(t.Context(), []string{"login", "--url", ts.URL, "--key", "rsk_person"})
	if err == nil || !strings.Contains(err.Error(), "stays without an account") || s.restarts != 0 {
		t.Fatalf("no answer: %v (restarts %d)", err, s.restarts)
	}
	if saved, _, _ := readSavedConfig(); saved.APIKey != "" {
		t.Fatal("logged in although the server stays without an account")
	}
	stdin = strings.NewReader("\n")
	if err := dispatch(t.Context(), []string{"login", "--url", ts.URL, "--key", "rsk_person"}); err != nil || s.restarts != 1 {
		t.Fatalf("Enter: %v (restarts %d)", err, s.restarts)
	}
}

func TestSetEnv(t *testing.T) {
	in := []byte("A=1\n#ROWSAFE_URL=https://x\nB='2'\nROWSAFE_ENROLL_TOKEN='rse_a'\nROWSAFE_ENROLL_TOKEN=rse_b\n")
	out := string(setEnv(setEnv(in, "ROWSAFE_URL", "https://api.example"), "ROWSAFE_ENROLL_TOKEN", ""))
	if out != "A=1\nROWSAFE_URL='https://api.example'\nB='2'\n" {
		t.Fatalf("setEnv:\n%s", out)
	}
	if envValue(in, "ROWSAFE_ENROLL_TOKEN") != "rse_b" || envValue(in, "B") != "2" || envValue(in, "C") != "" {
		t.Error("envValue")
	}
}
