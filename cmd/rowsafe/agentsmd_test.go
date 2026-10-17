package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInitAgentSection(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app", "billing")}
	_, _ = cliEnv(t, f)
	ctx := t.Context()
	t.Cleanup(func() { stdin, stdinIsTerminal = os.Stdin, func() bool { return false } })
	stdinIsTerminal = func() bool { return false }

	// No terminal, no --yes: nothing is created.
	if err := dispatch(ctx, []string{"init", "billing"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("AGENTS.md"); !os.IsNotExist(err) {
		t.Fatalf("AGENTS.md written without --yes or a terminal: %v", err)
	}

	// --yes and no instruction files: a new AGENTS.md; again: unchanged.
	out, err := captureStdout(t, func() error { return dispatch(ctx, []string{"init", "billing", "--yes", "--json"}) })
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		Database   string      `json:"database"`
		Config     string      `json:"config"`
		AgentFiles []agentFile `json:"agent_files"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("--json: %v in %q", err, out)
	}
	if res.Database != "billing" || len(res.AgentFiles) != 1 || res.AgentFiles[0] != (agentFile{"AGENTS.md", "created"}) {
		t.Fatalf("--json: %+v", res)
	}
	first := readFile(t, "AGENTS.md")
	for _, want := range []string{agentSectionStart, "`rowsafe status billing`", "`rowsafe mark billing before-<what>`", "`rowsafe pulse billing`", agentSectionEnd} {
		if !strings.Contains(first, want) {
			t.Errorf("AGENTS.md lacks %q:\n%s", want, first)
		}
	}
	out, err = captureStdout(t, func() error { return dispatch(ctx, []string{"init", "billing", "--yes", "--json"}) })
	if err != nil || !strings.Contains(out, `"already_there"`) {
		t.Fatalf("second run: %v, %s", err, out)
	}
	if readFile(t, "AGENTS.md") != first {
		t.Fatal("a second init changed AGENTS.md")
	}

	// Existing files keep every byte; a CLAUDE.md that imports AGENTS.md is
	// left alone.
	if err := os.WriteFile("AGENTS.md", []byte("# Agents\n\nUse pnpm."), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("CLAUDE.md", []byte("@AGENTS.md\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, []string{"init", "app", "--yes"}); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, "AGENTS.md")
	if !strings.HasPrefix(got, "# Agents\n\nUse pnpm.\n\n"+agentSectionStart) || !strings.Contains(got, "`rowsafe status app`") {
		t.Fatalf("AGENTS.md:\n%s", got)
	}
	if readFile(t, "CLAUDE.md") != "@AGENTS.md\n" {
		t.Fatal("CLAUDE.md that imports AGENTS.md was changed")
	}

	// A CLAUDE.md of its own gets the section too; --no-agents leaves both.
	if err := os.WriteFile("CLAUDE.md", []byte("# Claude\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := dispatch(ctx, []string{"init", "app", "--no-agents", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, "CLAUDE.md") != "# Claude\n" {
		t.Fatal("--no-agents changed CLAUDE.md")
	}

	// On a terminal it asks: no keeps the file, yes appends.
	stdinIsTerminal = func() bool { return true }
	stdin = strings.NewReader("n\n")
	if err := dispatch(ctx, []string{"init", "app"}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, "CLAUDE.md") != "# Claude\n" {
		t.Fatal("answering no changed CLAUDE.md")
	}
	stdin = strings.NewReader("y\n")
	if err := dispatch(ctx, []string{"init", "app"}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, "CLAUDE.md"); !strings.HasPrefix(got, "# Claude\n\n"+agentSectionStart) {
		t.Fatalf("CLAUDE.md:\n%s", got)
	}
	if strings.Count(readFile(t, "AGENTS.md"), agentSectionStart) != 1 {
		t.Fatal("AGENTS.md got the section twice")
	}
}
