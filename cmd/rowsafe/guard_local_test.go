package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// hookOutput runs rowsafe guard on a Bash event and decodes its reply.
func hookOutput(t *testing.T, command, cwd string) (systemMessage, context string) {
	t.Helper()
	ev, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}, "cwd": cwd})
	stdin = strings.NewReader(string(ev))
	t.Cleanup(func() { stdin = os.Stdin })
	out, err := captureStdout(t, func() error { return dispatch(t.Context(), []string{"guard"}) })
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	if strings.TrimSpace(out) == "" {
		return "", ""
	}
	var reply struct {
		SystemMessage string `json:"systemMessage"`
		Hook          struct {
			Context string `json:"additionalContext"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &reply); err != nil {
		t.Fatalf("reply: %v\n%s", err, out)
	}
	return reply.SystemMessage, reply.Hook.Context
}

func TestGuardWithoutAccount(t *testing.T) {
	url := localTestURL(t)
	_, _ = cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_API_KEY", "")
	t.Setenv("ROWSAFE_URL", "")
	t.Setenv("ROWSAFE_REQUIRE_PROTECTION", "")
	dir, _ := os.Getwd()

	// Nothing destructive: no reply.
	if msg, _ := hookOutput(t, `psql -c "SELECT 1"`, dir); msg != "" {
		t.Errorf("a SELECT: %q", msg)
	}

	// DATABASE_URL in the project's .env: no restore point, and the SQL is checked.
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("DATABASE_URL="+url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	msg, ctx := hookOutput(t, `psql "$DATABASE_URL" -c "TRUNCATE orders"`, dir)
	if !strings.Contains(msg, "no restore point") || !strings.Contains(msg, "Dangerous") {
		t.Errorf("system message %q", msg)
	}
	for _, want := range []string{"nothing to go back to", "pg_dump", "https://rowsafe.sh", "DATABASE_URL in .env", "TRUNCATE deletes every row"} {
		if !strings.Contains(ctx, want) {
			t.Errorf("context lacks %q:\n%s", want, ctx)
		}
	}

	// A migration tool: no SQL to check, a pointer to rowsafe preview.
	_, ctx = hookOutput(t, `bin/rails db:migrate`, dir)
	if !strings.Contains(ctx, "rowsafe preview FILE.sql") || !strings.Contains(ctx, "no") {
		t.Errorf("rails: %s", ctx)
	}

	// Logged in, with a database the account protects: the account's flow, not this one.
	t.Setenv("ROWSAFE_API_KEY", "rsk_test")
	t.Setenv("ROWSAFE_DATABASE", "app")
	if _, d := guardLocalDB(true, false, "app"); d != "" {
		t.Errorf("logged in with an account database: %q", d)
	}
	// Logged in, no Rowsafe database for this project, DATABASE_URL here: checked without a restore point.
	if d, src := guardLocalDB(true, false, ""); d == nil || src != "DATABASE_URL in .env" {
		t.Errorf("logged in without a project database: %v %q", d, src)
	}
}

func TestPreviewWithoutAccount(t *testing.T) {
	url := localTestURL(t)
	_, _ = cliEnv(t, &fakeAPI{})
	file := filepath.Join(t.TempDir(), "001_add.sql")
	if err := os.WriteFile(file, []byte("ALTER TABLE orders ADD COLUMN note2 text;\nTRUNCATE orders;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error { return dispatch(t.Context(), []string{"preview", url, file, "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var got previewJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got.Verdict != protocol.PreviewDangerous || got.Error != "" || got.Result == nil || got.Result.Checked != protocol.PreviewCheckedSchema || got.Label != "001_add.sql" {
		t.Fatalf("preview --json: %+v", got)
	}

	out, err = captureStdout(t, func() error {
		return dispatch(t.Context(), []string{"preview", url, file, "--static", "--fail-on", "dangerous"})
	})
	var exit exitError
	if !errors.As(err, &exit) || exit != previewExitVerdict {
		t.Errorf("--fail-on dangerous: %v", err)
	}
	if !strings.Contains(out, "nothing ran") || !strings.Contains(out, "No restore point") {
		t.Errorf("text:\n%s", out)
	}
	if err := dispatch(t.Context(), []string{"preview", url}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("no file: %v", err)
	}
}

// On a server whose agent runs without an account, guard saves the
// restore point through the agent's local control plane, as with an
// account, and finds the only database by itself.
func TestGuardLocalControlPlane(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a server without an account is a Linux server")
	}
	_, _ = cliEnv(t, &fakeAPI{})
	dir, err := os.MkdirTemp("/tmp", "rsg") // a socket path under 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	var mu sync.Mutex
	var marks []string
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }
	mux.HandleFunc("GET /v1/databases", func(w http.ResponseWriter, r *http.Request) { reply(w, dbs("app")) })
	mux.HandleFunc("POST /v1/databases/app/restore-points", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CreateRestorePointRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		marks = append(marks, req.Name)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		reply(w, protocol.TaskView{ID: "task_1", Type: protocol.TaskRestorePoint, Status: protocol.StatusQueued})
	})
	mux.HandleFunc("GET /v1/tasks/task_1", func(w http.ResponseWriter, r *http.Request) {
		reply(w, protocol.TaskView{ID: "task_1", Type: protocol.TaskRestorePoint, Status: protocol.StatusSucceeded})
	})
	mux.HandleFunc("GET /v1/databases/app/restore-points", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var out []protocol.RestorePoint
		for _, m := range marks {
			out = append(out, protocol.RestorePoint{Name: m, Status: protocol.RestorePointArchived, LSN: "0/3000060"})
		}
		reply(w, out)
	})
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	t.Setenv("ROWSAFE_API_KEY", "")
	t.Setenv("ROWSAFE_URL", "unix://"+sock)
	t.Setenv("DATABASE_URL", "")
	cwd, _ := os.Getwd()
	msg, ctx := hookOutput(t, `psql -c "DROP TABLE orders"`, cwd)
	if len(marks) != 1 || !strings.Contains(msg, "restore point "+marks[0]+" created on app") {
		t.Fatalf("marks %v, message %q", marks, msg)
	}
	if !strings.Contains(ctx, "this server's Rowsafe agent") || !strings.Contains(ctx, "sudo rowsafe restore app --to "+marks[0]) {
		t.Errorf("context: %s", ctx)
	}
}
