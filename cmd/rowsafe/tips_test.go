// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTips(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("ROWSAFE_URL", "")
	t.Setenv("ROWSAFE_API_KEY", "")
	old := tipsAllowed
	t.Cleanup(func() { tipsAllowed = old })
	allowed := true
	tipsAllowed = func() bool { return allowed }

	// Not logged in, after pulse: the MCP tip, with the database's name
	// (never a connection string).
	out := captureStderr(t, func() { showTip(context.Background(), []string{"pulse", "shop"}) })
	if !strings.Contains(out, "Tip: your AI agent can run these checks too") || !strings.Contains(out, "rowsafe mcp shop") {
		t.Fatalf("tip: %q", out)
	}
	// At most one an hour.
	if out := captureStderr(t, func() { showTip(context.Background(), []string{"pulse", "shop"}) }); out != "" {
		t.Fatalf("a second tip within the hour: %q", out)
	}
	// An hour later: the next one, not the same again.
	f := readTips()
	f.Last = time.Now().Add(-2 * time.Hour)
	_ = writeTips(f)
	out = captureStderr(t, func() { showTip(context.Background(), []string{"pulse", "postgres://u:secret@h/db"}) })
	if !strings.Contains(out, "curl -fsSL https://rowsafe.sh | sudo sh") || strings.Contains(out, "secret") {
		t.Fatalf("second tip: %q", out)
	}
	// Off: nothing.
	f = readTips()
	f.Last = time.Time{}
	f.Shown = nil
	_ = writeTips(f)
	if err := tipsCmd([]string{"off"}); err != nil {
		t.Fatal(err)
	}
	if out := captureStderr(t, func() { showTip(context.Background(), []string{"pulse", "shop"}) }); out != "" {
		t.Fatalf("tips off: %q", out)
	}
	// Not at a terminal (or --json, or an AI agent): nothing.
	_ = tipsCmd([]string{"on"})
	allowed = false
	if out := captureStderr(t, func() { showTip(context.Background(), []string{"pulse", "shop"}) }); out != "" {
		t.Fatalf("not at a terminal: %q", out)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = old
	w.Close()
	b := make([]byte, 1<<16)
	n, _ := r.Read(b)
	return string(b[:n])
}
