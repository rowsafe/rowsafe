package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeAPI is just enough of the control plane for the CLI's own logic.
type fakeAPI struct {
	mu         sync.Mutex
	dbs        []protocol.Database
	hosts      []protocol.Host
	protected  map[string]bool
	polls      []string // device-token responses to hand out, in order
	marks      []string // "db/label" of created restore points
	logouts    []string // API keys that logged out
	deviceName string
	health     map[string]int      // database -> health score
	tasks      []protocol.TaskView // tasks created through POST /v1/databases/{ref}/tasks
	reject     map[string]int      // task type -> status POST /v1/databases/{ref}/tasks answers
	retryAfter string              // Retry-After header on rejections
	findings   []protocol.Finding  // findings of every database (with health set)
	fixes      []protocol.ApplyFixRequest
	fixReject  *protocol.Error // POST /fixes answers 409 with this
}

func (f *fakeAPI) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer rsk_") {
				j(w, 401, protocol.Error{Error: "invalid credentials"})
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /v1/databases", authed(func(w http.ResponseWriter, r *http.Request) { j(w, 200, f.dbs) }))
	mux.HandleFunc("GET /v1/hosts", authed(func(w http.ResponseWriter, r *http.Request) { j(w, 200, f.hosts) }))
	mux.HandleFunc("GET /v1/databases/{ref}", authed(func(w http.ResponseWriter, r *http.Request) {
		for _, d := range f.dbs {
			if d.Name == r.PathValue("ref") {
				j(w, 200, d)
				return
			}
		}
		j(w, 404, protocol.Error{Error: "not found"})
	}))
	for _, p := range []string{"backups", "drills", "tasks"} {
		mux.HandleFunc("GET /v1/databases/{ref}/"+p, authed(func(w http.ResponseWriter, r *http.Request) { j(w, 200, []any{}) }))
	}
	mux.HandleFunc("GET /v1/tasks", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := []protocol.TaskView{}
		for _, tk := range f.tasks {
			if typ := r.URL.Query().Get("type"); typ == "" || typ == tk.Type {
				out = append(out, tk)
			}
		}
		j(w, 200, out)
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/tasks", authed(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CreateTaskRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if !slices.ContainsFunc(f.dbs, func(d protocol.Database) bool { return d.Name == r.PathValue("ref") }) {
			j(w, 404, protocol.Error{Error: "not found"})
			return
		}
		if status := f.reject[req.Type]; status != 0 {
			if f.retryAfter != "" {
				w.Header().Set("Retry-After", f.retryAfter)
			}
			j(w, status, protocol.Error{Error: "rejected"})
			return
		}
		tk := protocol.TaskView{ID: fmt.Sprintf("task_%d", len(f.tasks)+1), Type: req.Type, Status: protocol.StatusQueued,
			DatabaseName: r.PathValue("ref"), Params: req.Params}
		f.tasks = append(f.tasks, tk)
		j(w, 201, tk)
	}))
	mux.HandleFunc("GET /v1/tasks/{id}", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		for _, tk := range f.tasks {
			if tk.ID == r.PathValue("id") {
				// The agent finishes every task at once.
				tk.Status = protocol.StatusSucceeded
				switch tk.Type {
				case protocol.TaskRestorePoint:
					tk.Result, _ = json.Marshal(protocol.RestorePointResult{Name: "before-fix-drop-20260924-120000", Archived: true})
				case protocol.TaskMaintenance:
					var p protocol.MaintenanceParams
					_ = json.Unmarshal(tk.Params, &p)
					if p.Action == protocol.MaintDropIndex {
						tk.Status, tk.Error = protocol.StatusFailed, "The index public.orders_created_idx is now used by queries, so Rowsafe didn't remove it."
					} else {
						tk.Result, _ = json.Marshal(protocol.MaintenanceResult{Action: p.Action,
							Summary: "Cleaned up 3 tables; about 1.2 million dead rows removed.", Details: []string{"Tables: a, b, c."}})
					}
				}
				if tk.Type == protocol.TaskRestart {
					tk.Result, _ = json.Marshal(protocol.RestartResult{Restarted: true, Unit: "postgresql@18-main.service",
						DurationMs: 4200, ArchiveMode: "on"})
				}
				j(w, 200, tk)
				return
			}
		}
		j(w, 404, protocol.Error{Error: "not found"})
	}))
	mux.HandleFunc("GET /v1/org", authed(func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.Org{ID: "org_1", Name: "Acme", Plan: "pro", Limits: protocol.PlanLimits{MaxHosts: 5, MaxDatabases: 25}})
	}))
	mux.HandleFunc("GET /v1/databases/{ref}/protection", authed(func(w http.ResponseWriter, r *http.Request) {
		ok := f.protected[r.PathValue("ref")]
		p := protocol.Protection{Protected: ok, Reasons: []string{}, OpenFailedTasks: []protocol.TaskView{}}
		if !ok {
			p.Reasons = []string{"no restore drill has run yet"}
		}
		j(w, 200, p)
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/restore-points", authed(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CreateRestorePointRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.marks = append(f.marks, r.PathValue("ref")+"/"+req.Name)
		f.mu.Unlock()
		j(w, 201, protocol.TaskView{ID: "task_1", Type: protocol.TaskRestorePoint, Status: protocol.StatusQueued})
	}))
	mux.HandleFunc("GET /v1/databases/{ref}/health", authed(func(w http.ResponseWriter, r *http.Request) {
		score, ok := f.health[r.PathValue("ref")]
		if !ok {
			j(w, 404, protocol.Error{Error: "not found"})
			return
		}
		h := protocol.DatabaseHealth{Database: r.PathValue("ref"), Score: score, Grade: protocol.GradeHealthy, Findings: []protocol.Finding{}}
		if f.findings != nil {
			h.Findings = f.findings
		} else if score < 70 {
			h.Grade = protocol.GradeAtRisk
			h.Findings = []protocol.Finding{{ID: "backup_stale", Severity: "critical", Title: "No backup in 2 days",
				Explanation: "x", Action: "y", Penalty: 25}}
		}
		j(w, 200, h)
	}))
	mux.HandleFunc("POST /v1/databases/{ref}/fixes", authed(func(w http.ResponseWriter, r *http.Request) {
		var req protocol.ApplyFixRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fixReject != nil {
			j(w, http.StatusConflict, f.fixReject)
			return
		}
		f.fixes = append(f.fixes, req)
		var out protocol.ApplyFixResponse
		for _, fd := range f.findings {
			for _, fx := range fd.Fixes {
				if fd.ID != req.FindingID || fx.ID != req.FixID {
					continue
				}
				if fx.MarkFirst {
					tk := protocol.TaskView{ID: fmt.Sprintf("task_%d", len(f.tasks)+1), Type: protocol.TaskRestorePoint, Status: protocol.StatusQueued}
					f.tasks = append(f.tasks, tk)
					out.Tasks = append(out.Tasks, tk)
				}
				tk := protocol.TaskView{ID: fmt.Sprintf("task_%d", len(f.tasks)+1), Type: protocol.TaskMaintenance, Status: protocol.StatusQueued,
					DatabaseName: r.PathValue("ref"), Params: fx.Params}
				f.tasks = append(f.tasks, tk)
				out.Tasks = append(out.Tasks, tk)
			}
		}
		if len(out.Tasks) == 0 {
			j(w, http.StatusNotFound, protocol.Error{Error: "This fix no longer applies."})
			return
		}
		j(w, http.StatusAccepted, out)
	}))
	mux.HandleFunc("GET /v1/health", authed(func(w http.ResponseWriter, r *http.Request) {
		o := protocol.HealthOverview{Databases: []protocol.DatabaseHealthSummary{}}
		for name, score := range f.health {
			o.Databases = append(o.Databases, protocol.DatabaseHealthSummary{Database: name, Score: score})
		}
		j(w, 200, o)
	}))
	mux.HandleFunc("POST /v1/auth/device", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the device flow start must not send credentials")
		}
		var req protocol.DeviceAuthRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.deviceName = req.ClientName
		j(w, 200, protocol.DeviceAuthResponse{DeviceCode: "rsd_x", UserCode: "BCDF-GHJK", VerificationURI: "https://app.test/cli",
			VerificationURIComplete: "https://app.test/cli?code=BCDF-GHJK", ExpiresIn: 600, Interval: 3})
	})
	mux.HandleFunc("POST /v1/auth/device/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		next := f.polls[0]
		f.polls = f.polls[1:]
		f.mu.Unlock()
		if next == "ok" {
			j(w, 200, protocol.DeviceTokenResponse{APIKey: "rsk_new", KeyID: "key_new", Org: protocol.OrgBrief{ID: "org_1", Name: "Acme"}})
			return
		}
		j(w, 400, protocol.Error{Error: next})
	})
	mux.HandleFunc("GET /v1/whoami", authed(func(w http.ResponseWriter, r *http.Request) {
		j(w, 200, protocol.WhoAmI{Org: protocol.Org{ID: "org_1", Name: "Acme", Plan: "pro"},
			APIKey: &protocol.APIKey{ID: "key_x", Name: "ci"}})
	}))
	mux.HandleFunc("POST /v1/auth/logout", authed(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.logouts = append(f.logouts, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		f.mu.Unlock()
		w.WriteHeader(204)
	}))
	return mux
}

// cliEnv isolates config, project files and environment for one test.
func cliEnv(t *testing.T, f *fakeAPI) (*httptest.Server, *client.Client) {
	t.Helper()
	ts := httptest.NewServer(f.handler(t))
	t.Cleanup(ts.Close)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("ROWSAFE_URL", ts.URL)
	t.Setenv("ROWSAFE_API_KEY", "rsk_test")
	t.Setenv("ROWSAFE_DATABASE", "")
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		t.Setenv(v, "")
	}
	t.Chdir(t.TempDir())
	return ts, client.New(ts.URL, "rsk_test")
}

func dbs(names ...string) []protocol.Database {
	var out []protocol.Database
	for _, n := range names {
		out = append(out, protocol.Database{ID: "db_" + n, Name: n, Status: protocol.DBActive})
	}
	return out
}

func TestResolveDatabase(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app", "billing")}
	_, c := cliEnv(t, f)
	ctx := t.Context()

	if got, err := resolveDatabase(ctx, c, "explicit"); err != nil || got != "explicit" {
		t.Fatalf("explicit: %q, %v", got, err)
	}
	_, err := resolveDatabase(ctx, c, "")
	if err == nil || !strings.Contains(err.Error(), "2 databases: app, billing") || !strings.Contains(err.Error(), "rowsafe init") {
		t.Fatalf("ambiguous: %v", err)
	}

	// .rowsafe.json in a parent directory.
	root, _ := os.Getwd()
	if _, err := writeProjectConfig(root, "billing"); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "src", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	if got, err := resolveDatabase(ctx, c, ""); err != nil || got != "billing" {
		t.Fatalf(".rowsafe.json: %q, %v", got, err)
	}
	// ROWSAFE_DATABASE wins over the file.
	t.Setenv("ROWSAFE_DATABASE", "app")
	if got, err := resolveDatabase(ctx, c, ""); err != nil || got != "app" {
		t.Fatalf("ROWSAFE_DATABASE: %q, %v", got, err)
	}
	t.Setenv("ROWSAFE_DATABASE", "")
	t.Chdir(t.TempDir())

	f.dbs = dbs("only")
	if got, err := resolveDatabase(ctx, c, ""); err != nil || got != "only" {
		t.Fatalf("single database: %q, %v", got, err)
	}
	f.dbs = nil
	if _, err := resolveDatabase(ctx, c, ""); err == nil || !strings.Contains(err.Error(), "rowsafe adopt") {
		t.Fatalf("no databases: %v", err)
	}
}

func TestMarkArgs(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app", "billing")}
	_, c := cliEnv(t, f)
	ctx := t.Context()
	root, _ := os.Getwd()
	if _, err := writeProjectConfig(root, "app"); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args          []string
		db, label     string
		wantErrSubstr string
	}{
		{nil, "app", "", ""}, // project database, default label
		{[]string{"before-drop"}, "app", "before-drop", ""}, // not a database: a label
		{[]string{"billing"}, "billing", "", ""},            // a database: default label
		{[]string{"billing", "pre-migration"}, "billing", "pre-migration", ""},
		{[]string{"a", "b", "c"}, "", "", "expected"},
	}
	for _, tc := range cases {
		db, label, err := markArgs(ctx, c, tc.args)
		if tc.wantErrSubstr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Errorf("markArgs(%q): err %v", tc.args, err)
			}
			continue
		}
		if err != nil || db != tc.db || label != tc.label {
			t.Errorf("markArgs(%q) = %q, %q, %v; want %q, %q", tc.args, db, label, err, tc.db, tc.label)
		}
	}

	// Through the command: the default label is manual-<UTC time>.
	if err := dispatch(ctx, []string{"mark", "--no-wait"}); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, []string{"mark", "before-drop", "--no-wait"}); err != nil {
		t.Fatal(err)
	}
	if len(f.marks) != 2 || !strings.HasPrefix(f.marks[0], "app/manual-"+time.Now().UTC().Format("20060102")) || f.marks[1] != "app/before-drop" {
		t.Fatalf("marks = %q", f.marks)
	}
}

func TestResolveHost(t *testing.T) {
	f := &fakeAPI{}
	_, c := cliEnv(t, f)
	ctx := t.Context()
	if _, err := resolveHost(ctx, c, ""); err == nil || !strings.Contains(err.Error(), "enroll-token") {
		t.Fatalf("no hosts: %v", err)
	}
	f.hosts = []protocol.Host{{ID: "host_1", Hostname: "db1"}}
	if h, err := resolveHost(ctx, c, ""); err != nil || h != "db1" {
		t.Fatalf("one host: %q, %v", h, err)
	}
	f.hosts = append(f.hosts, protocol.Host{ID: "host_2", Hostname: "db2"})
	_, err := resolveHost(ctx, c, "")
	if err == nil || !strings.Contains(err.Error(), "--host db1") || !strings.Contains(err.Error(), "--host db2") {
		t.Fatalf("two hosts: %v", err)
	}
	if h, _ := resolveHost(ctx, c, "db2"); h != "db2" {
		t.Fatalf("explicit host: %q", h)
	}
}

// TestEveryCommand checks that each command in the reference has help and
// is dispatched, and that the short help names only real commands.
func TestEveryCommand(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app"), hosts: []protocol.Host{}}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	sub := regexp.MustCompile(`^[a-z][a-z-]*$`)
	seen := map[string]bool{}
	for _, line := range strings.Split(usage, "\n") {
		if !strings.HasPrefix(line, "  rowsafe ") {
			continue
		}
		fields := strings.Fields(line)
		cmd := fields[1:2]
		if len(fields) > 2 && sub.MatchString(fields[2]) {
			cmd = fields[1:3]
		}
		key := strings.Join(cmd, " ")
		if seen[key] {
			continue
		}
		seen[key] = true
		if h := helpFor(cmd[:1]); strings.Contains(h, "No help") {
			t.Errorf("rowsafe help %s: %s", cmd[0], h)
		}
		// An unknown flag stops every command before it does anything.
		if err := dispatch(ctx, append(cmd, "--no-such-flag")); err != nil && strings.Contains(err.Error(), "unknown command") {
			t.Errorf("rowsafe %s is in the reference but not dispatched: %v", key, err)
		}
	}
	if len(seen) < 45 {
		t.Fatalf("parsed only %d commands from the reference: %v", len(seen), seen)
	}
	for _, m := range regexp.MustCompile(`rowsafe ([a-z][a-z-]*)`).FindAllStringSubmatch(shortHelp, -1) {
		if m[1] != "help" && strings.Contains(helpFor(m[1:2]), "No help") {
			t.Errorf("the short help mentions rowsafe %s, which has no reference entry", m[1])
		}
	}
	for _, old := range []string{"drill", "drills", "health", "db list", "backup run", "restore-point create", "task show"} {
		// "run", "show" and "create" are taken for names now: there are no such databases or tasks.
		if err := dispatch(ctx, strings.Fields(old)); err == nil {
			t.Errorf("rowsafe %s still works", old)
		}
	}
	if err := dispatch(ctx, []string{"hosts"}); err == nil || !strings.Contains(err.Error(), "rowsafe hosts enroll-token") {
		t.Errorf("rowsafe hosts without a command: %v", err)
	}
}

func TestRestart(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app")}
	f.dbs[0].Status = protocol.DBAwaitingRestart
	f.dbs[0].Hostname = "db1"
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	t.Cleanup(func() { stdin = os.Stdin })

	// Not allowed on this server: refused before asking, with the manual command.
	stdin = strings.NewReader("y\n")
	if err := dispatch(ctx, []string{"restart", "app"}); err == nil || !strings.Contains(err.Error(), "sudo systemctl restart postgresql") ||
		!strings.Contains(err.Error(), "--allow-restart") {
		t.Fatalf("CanRestart=false: %v", err)
	}
	f.dbs[0].CanRestart = true

	stdin = strings.NewReader("n\n")
	if err := dispatch(ctx, []string{"restart", "app"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("answering n: %v", err)
	}
	stdin = strings.NewReader("")
	if err := dispatch(ctx, []string{"restart"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("no answer: %v", err)
	}
	if len(f.tasks) != 0 {
		t.Fatalf("a cancelled restart created tasks: %+v", f.tasks)
	}

	stdin = strings.NewReader("") // --yes must not read an answer
	if err := dispatch(ctx, []string{"restart", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if len(f.tasks) != 1 || f.tasks[0].Type != protocol.TaskRestart || f.tasks[0].DatabaseName != "app" ||
		string(f.tasks[0].Params) != `{"confirm":"app"}` {
		t.Fatalf("tasks = %+v, want one restart task for app confirming its name", f.tasks)
	}

	f.reject = map[string]int{protocol.TaskRestart: http.StatusForbidden}
	if err := dispatch(ctx, []string{"restart", "--yes"}); err == nil || !strings.Contains(err.Error(), "doesn't allow restarts") {
		t.Fatalf("403: %v", err)
	}
	f.reject[protocol.TaskRestart], f.retryAfter = http.StatusTooManyRequests, "73"
	if err := dispatch(ctx, []string{"restart", "--yes"}); err == nil || !strings.Contains(err.Error(), "try again in 73 seconds") {
		t.Fatalf("429: %v", err)
	}
	f.reject[protocol.TaskRestart] = http.StatusConflict
	if err := dispatch(ctx, []string{"restart", "--yes"}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("409: %v", err)
	}
	if h := helpFor([]string{"restart"}); !strings.Contains(h, "rowsafe restart [NAME] [--yes]") || !strings.Contains(h, "never restarts PostgreSQL on its own") {
		t.Errorf("help restart:\n%s", h)
	}
}

// Right after a restart Rowsafe checks by itself: verify waits for that check.
func TestVerifyWaitsForOpenCheck(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app"), reject: map[string]int{protocol.TaskCheck: http.StatusConflict},
		tasks: []protocol.TaskView{{ID: "task_open", Type: protocol.TaskCheck, Status: protocol.StatusRunning, DatabaseName: "app"}}}
	_, _ = cliEnv(t, f)
	if err := dispatch(t.Context(), []string{"verify", "app"}); err != nil {
		t.Fatal(err)
	}
	if len(f.tasks) != 1 {
		t.Fatalf("tasks = %+v", f.tasks)
	}
	f.tasks[0].Status = protocol.StatusSucceeded // nothing open: the 409 stands
	if err := dispatch(t.Context(), []string{"verify", "app"}); err == nil {
		t.Fatal("verify succeeded without a check")
	}
}

func TestProof(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app")}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	if err := dispatch(ctx, []string{"proof", "--no-wait"}); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, []string{"proofs", "app"}); err != nil {
		t.Fatal(err)
	}
	if len(f.tasks) != 1 || f.tasks[0].Type != protocol.TaskDrill {
		t.Fatalf("tasks = %+v, want one drill task", f.tasks)
	}
}

func TestStatusExitCodes(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app"), hosts: []protocol.Host{}, protected: map[string]bool{"app": true}}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	var exit exitError
	if err := dispatch(ctx, []string{"status", "app"}); err != nil {
		t.Fatalf("protected: %v", err)
	}
	if err := dispatch(ctx, []string{"status", "app", "--json"}); err != nil {
		t.Fatalf("protected, JSON: %v", err)
	}
	f.protected["app"] = false
	if err := dispatch(ctx, []string{"status", "app"}); !errors.As(err, &exit) || exit != 3 {
		t.Fatalf("unprotected: %v, want exit 3", err)
	}
	// Fleet health: an active database with no backups or drills is a problem.
	if err := dispatch(ctx, []string{"status"}); !errors.As(err, &exit) || exit != 3 {
		t.Fatalf("fleet with problems: %v, want exit 3", err)
	}
	f.dbs = nil
	if err := dispatch(ctx, []string{"status", "--json"}); err != nil {
		t.Fatalf("empty fleet: %v", err)
	}
	if err := dispatch(ctx, []string{"status", "a", "b"}); err == nil || errors.As(err, &exit) {
		t.Fatalf("two names: %v", err)
	}
}

func TestInitWritesProjectConfig(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app", "billing")}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	if err := os.WriteFile(".rowsafe.json", []byte(`{"require_protection": true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, []string{"init"}); err == nil || !strings.Contains(err.Error(), "rowsafe init NAME") {
		t.Fatalf("init with two databases and no NAME: %v", err)
	}
	if err := dispatch(ctx, []string{"init", "nope"}); err == nil {
		t.Fatal("init with an unknown database succeeded")
	}
	if err := dispatch(ctx, []string{"init", "billing"}); err != nil {
		t.Fatal(err)
	}
	var pc map[string]any
	data, _ := os.ReadFile(".rowsafe.json")
	if err := json.Unmarshal(data, &pc); err != nil || pc["database"] != "billing" || pc["require_protection"] != true {
		t.Fatalf(".rowsafe.json = %s (%v)", data, err)
	}
	if pc2, _ := findProjectConfig(""); pc2.Database != "billing" || !pc2.RequireProtection {
		t.Fatalf("the guard hook's loader reads %+v", pc2)
	}
}

func TestBrowserLogin(t *testing.T) {
	f := &fakeAPI{polls: []string{protocol.DeviceAuthorizationPending, protocol.DeviceSlowDown, protocol.DeviceAuthorizationPending, "ok"}}
	ts, _ := cliEnv(t, f)
	t.Setenv("ROWSAFE_API_KEY", "")
	t.Setenv("ROWSAFE_URL", "")
	var slept []time.Duration
	var opened []string
	oldSleep, oldOpen := sleepCtx, openBrowser
	sleepCtx = func(ctx context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	openBrowser = func(u string) error { opened = append(opened, u); return nil }
	t.Cleanup(func() { sleepCtx, openBrowser = oldSleep, oldOpen })
	ctx := t.Context()

	if err := dispatch(ctx, []string{"whoami"}); err == nil || !strings.Contains(err.Error(), "rowsafe login") {
		t.Fatalf("whoami before login: %v", err)
	}
	if err := dispatch(ctx, []string{"login", "--url", ts.URL, "--name", "laptop"}); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{3 * time.Second, 3 * time.Second, 8 * time.Second, 8 * time.Second}
	if len(slept) != len(want) || slept[0] != want[0] || slept[2] != want[2] || slept[3] != want[3] {
		t.Fatalf("poll intervals = %v, want %v (slow_down adds 5s)", slept, want)
	}
	if f.deviceName != "laptop" {
		t.Fatalf("client name = %q", f.deviceName)
	}
	if canOpenBrowser() && (len(opened) != 1 || opened[0] != "https://app.test/cli?code=BCDF-GHJK") {
		t.Fatalf("opened %v", opened)
	}
	saved, p, err := readSavedConfig()
	if err != nil || saved.URL != ts.URL || saved.APIKey != "rsk_new" || saved.KeyID != "key_new" || saved.Org == nil || saved.Org.Name != "Acme" {
		t.Fatalf("saved config %+v, %v", saved, err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v", st.Mode().Perm())
	}
	// The saved URL is used from now on, without --url or ROWSAFE_URL.
	if err := dispatch(ctx, []string{"whoami"}); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, []string{"logout"}); err != nil {
		t.Fatal(err)
	}
	if len(f.logouts) != 1 || f.logouts[0] != "rsk_new" {
		t.Fatalf("logout revoked %q", f.logouts)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("logout left the config behind")
	}

	// Over SSH the browser is never opened.
	t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
	opened = nil
	f.polls = []string{protocol.DeviceAccessDenied}
	if err := dispatch(ctx, []string{"login", "--url", ts.URL}); err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("denied login: %v", err)
	}
	if len(opened) != 0 {
		t.Fatal("opened a browser over SSH")
	}
	f.polls = []string{protocol.DeviceExpiredToken}
	if err := dispatch(ctx, []string{"login", "--url", ts.URL}); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired login: %v", err)
	}
}

func TestKeyLogin(t *testing.T) {
	f := &fakeAPI{}
	ts, _ := cliEnv(t, f)
	t.Setenv("ROWSAFE_API_KEY", "")
	ctx := t.Context()
	if err := dispatch(ctx, []string{"login", "--key", "nope"}); err == nil {
		t.Fatal("a malformed key was accepted")
	}
	if err := dispatch(ctx, []string{"login", "--key", "rsk_pasted"}); err != nil {
		t.Fatal(err)
	}
	saved, _, _ := readSavedConfig()
	if saved.URL != ts.URL || saved.APIKey != "rsk_pasted" || saved.KeyID != "" || saved.Org.ID != "org_1" {
		t.Fatalf("saved %+v", saved)
	}
	// A pasted key is never revoked by logout.
	if err := dispatch(ctx, []string{"logout"}); err != nil {
		t.Fatal(err)
	}
	if len(f.logouts) != 0 {
		t.Fatalf("logout revoked a pasted key: %q", f.logouts)
	}
}

func TestLoginURLDefault(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "")
	if got := loginURL("", config{}); got != "https://api.rowsafe.sh" {
		t.Fatalf("default = %q", got)
	}
	if got := loginURL("", config{URL: "https://saved.example/"}); got != "https://saved.example" {
		t.Fatalf("saved = %q", got)
	}
	t.Setenv("ROWSAFE_URL", "https://env.example")
	if got := loginURL("", config{URL: "https://saved.example"}); got != "https://env.example" {
		t.Fatalf("env = %q", got)
	}
	if got := loginURL("https://flag.example", config{}); got != "https://flag.example" {
		t.Fatalf("flag = %q", got)
	}
}

func TestHelp(t *testing.T) {
	if h := helpFor(nil); !strings.Contains(h, "Getting started") || !strings.Contains(h, "Rewind") || !strings.Contains(h, "Proof") ||
		!strings.Contains(h, "Pulse") || !strings.Contains(h, "Guard") || !strings.Contains(h, "Admin") {
		t.Fatalf("short help:\n%s", h)
	}
	if h := helpFor([]string{"mark"}); !strings.Contains(h, "rowsafe mark [NAME] [LABEL]") || !strings.Contains(h, "before-drop") {
		t.Fatalf("help mark:\n%s", h)
	}
	if h := helpFor([]string{"backups"}); !strings.Contains(h, "rowsafe backups [NAME]") || strings.Contains(h, "rowsafe backup [NAME]") {
		t.Fatalf("help backups:\n%s", h)
	}
	if h := helpFor([]string{"proof"}); !strings.Contains(h, "rowsafe proof [NAME] [--no-wait]") || !strings.Contains(h, "--proof-schedule") {
		t.Fatalf("help proof:\n%s", h)
	}
	if h := helpFor([]string{"adopt"}); !strings.Contains(h, "--host may be omitted") {
		t.Fatalf("help adopt:\n%s", h)
	}
	if h := helpFor([]string{"all"}); !strings.Contains(h, "rowsafe hosts enroll-token") || !strings.Contains(h, "ROWSAFE_DATABASE") {
		t.Fatalf("help all is incomplete")
	}
	if h := helpFor([]string{"frobnicate"}); !strings.Contains(h, "No help") {
		t.Fatalf("unknown topic:\n%s", h)
	}
}

func TestPulseExitCodes(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app", "old"), health: map[string]int{"app": 95, "old": 40}}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	var exit exitError
	if err := dispatch(ctx, []string{"pulse", "app"}); err != nil {
		t.Fatalf("healthy database: %v", err)
	}
	if err := dispatch(ctx, []string{"pulse", "old", "--json"}); !errors.As(err, &exit) || exit != 3 {
		t.Fatalf("database at risk: %v, want exit 3", err)
	}
	if err := dispatch(ctx, []string{"pulse"}); !errors.As(err, &exit) || exit != 3 {
		t.Fatalf("fleet with a database at risk: %v, want exit 3", err)
	}
	f.health = map[string]int{"app": 95}
	if err := dispatch(ctx, []string{"pulse"}); err != nil {
		t.Fatalf("healthy fleet: %v", err)
	}
	if h := helpFor([]string{"pulse"}); !strings.Contains(h, "rowsafe pulse [NAME]") || !strings.Contains(h, "caps the score at 59") {
		t.Errorf("help pulse:\n%s", h)
	}
}

func fixFindings() []protocol.Finding {
	vac, _ := json.Marshal(protocol.MaintenanceParams{Action: protocol.MaintVacuum, DB: "shop", Tables: []string{"public.a"}})
	drop, _ := json.Marshal(protocol.MaintenanceParams{Action: protocol.MaintDropIndex, DB: "shop", Index: "public.orders_created_idx", Unused: true})
	return []protocol.Finding{
		{ID: "vacuum_behind", Severity: protocol.SeverityWarning, Title: "Dead rows are piling up in 3 tables", Action: "Clean them up.",
			Fixes: []protocol.FindingFix{{ID: "vacuum", Kind: protocol.FixMaintenance, Label: "Clean up 3 tables",
				Description: "Runs VACUUM gently; nothing is locked.", Params: vac, Available: true}}},
		{ID: "unused_indexes", Severity: protocol.SeverityInfo, Title: "1 index is never used", Action: "Remove it.",
			Fixes: []protocol.FindingFix{
				{ID: "drop:public.orders_created_idx", Kind: protocol.FixMaintenance, Label: "Remove public.orders_created_idx",
					Description: "Frees 1.4 GB.", Params: drop, Confirm: "Queries that need it get slower.", Destructive: true, MarkFirst: true, Available: true},
				{ID: "drop:public.other_idx", Kind: protocol.FixMaintenance, Label: "Remove public.other_idx", Available: false,
					Reason: "The agent is offline."},
			}},
		{ID: "cache_hit_low", Severity: protocol.SeverityInfo, Title: "Cache hit rate is low", Action: "Consider more memory.",
			Command: "SHOW shared_buffers"},
	}
}

// captureStdout returns what fn printed.
func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, r)
		done <- b.String()
	}()
	ferr := fn()
	w.Close()
	os.Stdout = old
	return <-done, ferr
}

func TestFix(t *testing.T) {
	f := &fakeAPI{dbs: dbs("shop", "other"), health: map[string]int{"shop": 80}, findings: fixFindings()}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	t.Cleanup(func() { stdin, stdinIsTerminal = os.Stdin, func() bool { return false } })
	stdinIsTerminal = func() bool { return false }

	// The list: numbered available fixes, unavailable ones with their reason.
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"fix", "shop"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shop: Rowsafe can fix 2 of 3 findings", "(vacuum_behind)", " 1) Clean up 3 tables",
		" 2) Remove public.orders_created_idx  [asks you to confirm, saves a Mark first]", " -) Remove public.other_idx",
		"Not available now: The agent is offline.", "Apply one: rowsafe fix shop NUMBER"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "cache_hit_low") || len(f.fixes) != 0 {
		t.Errorf("listed a finding without fixes, or applied something:\n%s", out)
	}

	// By number, answering y.
	stdin = strings.NewReader("y\n")
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"fix", "shop", "1"}) })
	if err != nil || !strings.Contains(out, "Cleaned up 3 tables; about 1.2 million dead rows removed.") || !strings.Contains(out, "  Tables: a, b, c.") {
		t.Fatalf("fix 1: %v\n%s", err, out)
	}
	if len(f.fixes) != 1 || f.fixes[0] != (protocol.ApplyFixRequest{FindingID: "vacuum_behind", FixID: "vacuum"}) {
		t.Fatalf("fixes sent %+v", f.fixes)
	}

	// No answer: nothing applied.
	stdin = strings.NewReader("")
	if err := dispatch(ctx, []string{"fix", "shop", "vacuum_behind"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("no answer: %v", err)
	}
	// A fix with Confirm needs the database name typed exactly.
	stdin = strings.NewReader("y\n")
	if err := dispatch(ctx, []string{"fix", "shop", "unused_indexes", "drop:public.orders_created_idx"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
		t.Fatalf("answering y to a destructive fix: %v", err)
	}
	if len(f.fixes) != 1 {
		t.Fatalf("a cancelled fix was sent: %+v", f.fixes)
	}
	// Typed; the Mark is saved first; the agent refuses: exit 1 with its reason.
	stdin = strings.NewReader("shop\n")
	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"fix", "shop", "unused_indexes", "drop:public.orders_created_idx"})
	})
	var exit exitError
	if !errors.As(err, &exit) || exit != 1 || !strings.Contains(out, "Warning: Queries that need it get slower.") ||
		!strings.Contains(out, "Mark saved: before-fix-drop-") || !strings.Contains(out, "The fix didn't work: The index public.orders_created_idx is now used") {
		t.Fatalf("destructive fix: %v\n%s", err, out)
	}
	if last := f.fixes[len(f.fixes)-1]; last.Confirm != "shop" {
		t.Fatalf("confirm not sent: %+v", last)
	}
	// The only available fix of a finding is picked without naming it;
	// an unavailable one explains why.
	if err := dispatch(ctx, []string{"fix", "shop", "unused_indexes", "drop:public.other_idx", "--yes"}); err == nil ||
		!strings.Contains(err.Error(), "The agent is offline") {
		t.Fatalf("unavailable fix: %v", err)
	}
	if err := dispatch(ctx, []string{"fix", "shop", "cache_hit_low"}); err == nil || !strings.Contains(err.Error(), "can't fix") {
		t.Fatalf("finding without fixes: %v", err)
	}
	if err := dispatch(ctx, []string{"fix", "shop", "gone"}); err == nil || !strings.Contains(err.Error(), "no finding") {
		t.Fatalf("unknown finding: %v", err)
	}
	if err := dispatch(ctx, []string{"fix", "shop", "7"}); err == nil || !strings.Contains(err.Error(), "no fix number 7") {
		t.Fatalf("unknown number: %v", err)
	}
	// With the database from .rowsafe.json, FINDING comes first.
	t.Setenv("ROWSAFE_DATABASE", "shop")
	stdin = strings.NewReader("")
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"fix", "vacuum_behind", "--yes"}) }); err != nil {
		t.Fatal(err)
	}
	if last := f.fixes[len(f.fixes)-1]; last.FindingID != "vacuum_behind" || last.Confirm != "" {
		t.Fatalf("inferred database: %+v", last)
	}
	// The server says it no longer applies.
	f.fixReject = &protocol.Error{Error: "This fix no longer applies; the page refreshed."}
	if err := dispatch(ctx, []string{"fix", "1", "--yes"}); err == nil || !strings.Contains(err.Error(), "no longer applies") {
		t.Fatalf("409: %v", err)
	}
	f.fixReject = nil

	// Interactive: pick from the list.
	stdinIsTerminal = func() bool { return true }
	n := len(f.fixes)
	stdin = strings.NewReader("1\ny\n")
	if out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"fix"}) }); err != nil || len(f.fixes) != n+1 {
		t.Fatalf("interactive pick: %v\n%s", err, out)
	}
	stdin = strings.NewReader("\n")
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"fix"}) }); err != nil || len(f.fixes) != n+1 {
		t.Fatalf("Enter must leave it: %v", err)
	}

	// pulse points to the fix instead of a command.
	out, _ = captureStdout(t, func() error { return dispatch(ctx, []string{"pulse", "shop"}) })
	if !strings.Contains(out, "Fix: rowsafe fix shop vacuum_behind  (Clean up 3 tables)") || !strings.Contains(out, "Try: SHOW shared_buffers") {
		t.Errorf("pulse:\n%s", out)
	}
	if h := helpFor([]string{"fix"}); !strings.Contains(h, "rowsafe fix [NAME]") || !strings.Contains(h, "Apply fix") {
		t.Errorf("help fix:\n%s", h)
	}
}
