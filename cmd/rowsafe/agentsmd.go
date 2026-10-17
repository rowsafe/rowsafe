package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// rowsafe init's offer to tell the project's AI agents (Claude Code, Codex,
// Cursor, ...) about Rowsafe: a short section added to AGENTS.md and
// CLAUDE.md. It only ever appends, between markers, and never touches a
// file that already has the section.

const (
	agentSectionStart = "<!-- rowsafe:start -->"
	agentSectionEnd   = "<!-- rowsafe:end -->"
)

// agentSection is the text added for database name.
func agentSection(name string) string {
	return strings.NewReplacer("NAME", name).Replace(agentSectionStart + `
## Database safety (Rowsafe)

This project's database (` + "`NAME`" + `) is protected by Rowsafe. Use the ` + "`rowsafe`" + ` CLI (or ` + "`npx rowsafe`" + `):

- Before a migration or destructive SQL (DROP, TRUNCATE, DELETE or UPDATE without a narrow WHERE, resets, re-seeding): run ` + "`rowsafe status NAME`" + `. If it isn't protected, tell the user why and wait for their OK. Then set a restore point with ` + "`rowsafe mark NAME before-<what>`" + ` and tell the user its name.
- ` + "`rowsafe pulse NAME`" + ` shows the database's health and what to fix. Run ` + "`rowsafe fix`" + ` only when the user agrees.
- If something goes wrong: stop, don't try to repair the data, and tell the user the Mark's name. They decide whether to restore it (` + "`rowsafe rewind NAME`" + ` or the Rowsafe dashboard).
` + agentSectionEnd + "\n")
}

// agentFile is one instructions file and what init did with it.
type agentFile struct {
	Path   string `json:"path"`
	Result string `json:"result"` // added, created, already_there, skipped
}

// agentFiles are the instruction files in dir that should get the section:
// AGENTS.md and CLAUDE.md where they exist (not a CLAUDE.md that only
// imports AGENTS.md, or is the same file), else a new AGENTS.md, which
// Codex, Cursor and most other agents read.
func agentFiles(dir string) ([]string, error) {
	agents, claude := filepath.Join(dir, "AGENTS.md"), filepath.Join(dir, "CLAUDE.md")
	ai, aerr := os.Stat(agents)
	ci, cerr := os.Stat(claude)
	for _, err := range []error{aerr, cerr} {
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	var out []string
	if aerr == nil {
		out = append(out, agents)
	}
	if cerr == nil {
		data, err := os.ReadFile(claude)
		if err != nil {
			return nil, err
		}
		sameFile := aerr == nil && os.SameFile(ai, ci)
		if !sameFile && !(aerr == nil && bytes.Contains(data, []byte("@AGENTS.md"))) {
			out = append(out, claude)
		}
	}
	if len(out) == 0 {
		out = append(out, agents)
	}
	return out, nil
}

// pendingAgentFiles reports which of files still need the section, and marks
// the others already_there.
func pendingAgentFiles(files []string) (pending []string, done []agentFile, err error) {
	for _, p := range files {
		data, err := os.ReadFile(p)
		if errors.Is(err, fs.ErrNotExist) {
			pending = append(pending, p)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if bytes.Contains(data, []byte(agentSectionStart)) {
			done = append(done, agentFile{Path: p, Result: "already_there"})
			continue
		}
		pending = append(pending, p)
	}
	return pending, done, nil
}

// addAgentSection appends the section to p (creating it if needed), after a
// blank line, keeping everything already in it.
func addAgentSection(p, name string) (string, error) {
	data, err := os.ReadFile(p)
	result := "added"
	if errors.Is(err, fs.ErrNotExist) {
		result = "created"
	} else if err != nil {
		return "", err
	}
	if bytes.Contains(data, []byte(agentSectionStart)) {
		return "already_there", nil
	}
	var b strings.Builder
	if len(data) > 0 {
		if !bytes.HasSuffix(data, []byte("\n")) {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString(agentSection(name))
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(b.String()); err != nil {
		f.Close()
		return "", err
	}
	return result, f.Close()
}

// offerAgentSection adds the section to the project's instruction files:
// right away with --yes, after asking on a terminal, and not at all without
// a terminal (it says how instead).
func offerAgentSection(dir, name string, yes, quiet bool) ([]agentFile, error) {
	files, err := agentFiles(dir)
	if err != nil {
		return nil, err
	}
	pending, out, err := pendingAgentFiles(files)
	if err != nil || len(pending) == 0 {
		return out, err
	}
	names := make([]string, len(pending))
	for i, p := range pending {
		names[i] = filepath.Base(p)
	}
	which := strings.Join(names, " and ")
	if !yes {
		if !stdinIsTerminal() {
			if !quiet {
				fmt.Fprintf(os.Stderr, "Tip: `rowsafe init %s --yes` adds a short section to %s so AI agents check backups and set a Mark before migrations.\n", name, which)
			}
			for _, p := range pending {
				out = append(out, agentFile{Path: p, Result: "skipped"})
			}
			return out, nil
		}
		verb := "Add a short Rowsafe section to"
		if _, err := os.Stat(pending[0]); errors.Is(err, fs.ErrNotExist) && len(pending) == 1 {
			verb = "Create"
		}
		fmt.Fprintf(os.Stderr, "%s %s, so AI agents (Claude Code, Codex, Cursor) check backups and set a Mark before migrations? [y/N] ", verb, which)
		if a := readLine(); !strings.EqualFold(a, "y") && !strings.EqualFold(a, "yes") {
			for _, p := range pending {
				out = append(out, agentFile{Path: p, Result: "skipped"})
			}
			return out, nil
		}
	}
	for _, p := range pending {
		r, err := addAgentSection(p, name)
		if err != nil {
			return out, err
		}
		out = append(out, agentFile{Path: p, Result: r})
	}
	return out, nil
}
