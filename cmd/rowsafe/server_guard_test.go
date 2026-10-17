package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeGuardResult is what the fake agent reports for Guard's tasks: a
// migration that fails on the data, and a ready safe copy.
func fakeGuardResult(task *protocol.Task) any {
	switch task.Type {
	case protocol.TaskPreviewMigration:
		var p protocol.PreviewParams
		_ = json.Unmarshal(task.Params, &p)
		if strings.Contains(p.SQL, "nickname") {
			return protocol.PreviewResult{PreviewID: p.PreviewID, Verdict: protocol.PreviewSafe, DB: "shop", Mode: protocol.PreviewInTransaction,
				Summary: "Safe: ALTER TABLE users takes a brief lock (2 ms)."}
		}
		return protocol.PreviewResult{PreviewID: p.PreviewID, Verdict: protocol.PreviewFailed, DB: "shop", Mode: protocol.PreviewInTransaction,
			Summary:    "Fails on the copy: statement 1 failed (could not create unique index \"users_email_key\").",
			Statements: []protocol.PreviewStatement{{N: 1, Line: 1, SQL: p.SQL, Command: "ALTER TABLE", Ran: true, Error: "could not create unique index", Risk: protocol.PreviewDangerous}},
			Error:      &protocol.PreviewError{Statement: 1, Line: 1, Code: "23505", Message: "could not create unique index \"users_email_key\""}}
	case protocol.TaskRestorePoint:
		var p protocol.RestorePointParams
		_ = json.Unmarshal(task.Params, &p)
		return protocol.RestorePointResult{Name: p.Name, LSN: "0/3000060", Archived: true, CreatedAt: time.Now().UTC()}
	case protocol.TaskSafeCopy:
		var p protocol.SafeCopyParams
		_ = json.Unmarshal(task.Params, &p)
		return protocol.SafeCopyResult{CopyID: p.CopyID, Listen: p.Access.Listen, Port: p.Access.Port, Role: p.Access.Role, Databases: []string{"postgres", "shop"},
			Expires: p.Expires, Masking: protocol.MaskingReport{Mode: p.Masking.Mode, Tables: 1, Columns: 1}}
	}
	return struct{}{}
}

// On a server Rowsafe protects on its own, rowsafe preview runs on a full
// copy of the data (the agent's preview), and rowsafe copies create makes a
// masked copy on localhost on the chosen port.
func TestGuardOnServer(t *testing.T) {
	c := localServer(t)
	ctx := t.Context()
	onServer = true
	t.Cleanup(func() { onServer = false })

	for _, args := range [][]string{
		{"postgres://app@localhost/shop", "m.sql"}, // a connection string: the schema-only check
		{"shop", "m.sql", "--static"},
		{"shop", "m.sql", "--timeout", "1m"},
		{"nope", "m.sql"}, // not a database of this server
	} {
		if fullCopyPreview(ctx, c, args) {
			t.Errorf("%q previews on a full copy", args)
		}
	}
	if !fullCopyPreview(ctx, c, []string{"shop", "m.sql"}) || !fullCopyPreview(ctx, c, []string{"--fail-on", "dangerous", "m.sql"}) {
		t.Fatal("shop doesn't preview on a full copy")
	}

	file := filepath.Join(t.TempDir(), "0042_unique_email.sql")
	if err := os.WriteFile(file, []byte("ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStdout(t, func() error {
		return dispatch(ctx, []string{"preview", "shop", file, "--json", "--fail-on", "dangerous"})
	})
	if err == nil || err.Error() != exitError(previewExitFails).Error() {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	var res previewJSON
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Verdict != protocol.PreviewFailed || res.Result == nil ||
		res.Result.Checked != "" || res.Label != "0042_unique_email.sql" || res.Result.Error.Code != "23505" {
		t.Fatalf("preview result: %+v %v\n%s", res, err, out)
	}
	if list, err := c.Previews(ctx, "shop"); err != nil || len(list) != 1 || list[0].Source != "cli" {
		t.Fatalf("previews: %+v %v", list, err)
	}

	out, err = captureStdout(t, func() error {
		return dispatch(ctx, []string{"copies", "create", "shop", "--masked", "--port", "6543", "--hours", "3", "--json"})
	})
	var cp struct {
		Copy             protocol.SafeCopy `json:"copy"`
		Password         string            `json:"password"`
		ConnectionString string            `json:"connection_string"`
	}
	if err != nil || json.Unmarshal([]byte(out), &cp) != nil || cp.Copy.Status != protocol.CopyReady || !cp.Copy.Masked || cp.Password == "" ||
		!strings.Contains(cp.ConnectionString, ":"+cp.Password+"@127.0.0.1:6543/shop?sslmode=require") {
		t.Fatalf("copies create: %v\n%s", err, out)
	}
	if _, err := captureStdout(t, func() error { return dispatch(ctx, []string{"copies", "create", "shop", "--masked", "--no-masking"}) }); err == nil {
		t.Fatal("--masked with --no-masking")
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"copies", "shop"}) })
	if err != nil || !strings.Contains(out, "1 of 20 on this server") || !strings.Contains(out, "127.0.0.1:6543") {
		t.Fatalf("copies: %v\n%s", err, out)
	}
}

// rowsafe guard on such a server: the restore point, and the command's SQL
// run on a full copy beside it. A migration that fails on the data is
// stopped before it reaches production.
func TestGuardFullCopyOnServer(t *testing.T) {
	c := localServer(t)
	cwd := t.TempDir()
	msg, note := hookOutput(t, `psql -c "ALTER TABLE users ALTER COLUMN nickname TYPE varchar(80)"`, cwd)
	if !strings.Contains(msg, "restore point agent-") || !strings.Contains(msg, "Preview on a full copy of the data: Safe") ||
		!strings.Contains(note, "full copy of shop restored from its backups") {
		t.Fatalf("message %q\nnote %s", msg, note)
	}
	if list, _ := c.Previews(t.Context(), "shop"); len(list) != 1 || list[0].Source != "mcp" {
		t.Fatalf("previews: %+v", list)
	}

	ev, _ := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
		"tool_input": map[string]string{"command": `psql -c "ALTER TABLE users ALTER COLUMN zip TYPE integer USING zip::integer"`}})
	stdin = strings.NewReader(string(ev))
	t.Cleanup(func() { stdin = os.Stdin })
	var err error
	var out string
	stderr := captureStderr(t, func() {
		out, err = captureStdout(t, func() error { return dispatch(t.Context(), []string{"guard"}) })
	})
	if err == nil || err.Error() != exitError(2).Error() || !strings.Contains(stderr, "fails on a full copy of shop's data") ||
		!strings.Contains(stderr, "users_email_key") || !strings.Contains(stderr, "Restore point agent-") {
		t.Fatalf("a failing migration: %v\n%s\n%s", err, stderr, out)
	}
}

// captureStderr runs fn with stderr going to a pipe and returns it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	w.Close()
	os.Stderr = old
	return <-done
}
