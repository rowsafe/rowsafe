package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Tests run the way AI agents and CI run the CLI: no terminal to ask on
// (TestMain, in telemetry_test.go). A test that answers questions (through
// stdin) says so with onTerminal.

// onTerminal makes the CLI ask its questions, as on a terminal.
func onTerminal(t *testing.T) {
	t.Helper()
	old := stdinIsTerminal
	t.Cleanup(func() { stdinIsTerminal = old })
	stdinIsTerminal = func() bool { return true }
}

// runCaptured runs the CLI as main does and returns its exit code, stdout
// and stderr.
func runCaptured(t *testing.T, ctx context.Context, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	capture := func(f **os.File) func() string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := *f
		*f = w
		var b strings.Builder
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = io.Copy(&b, r) }()
		return func() string { w.Close(); *f = old; wg.Wait(); r.Close(); return b.String() }
	}
	outDone := capture(&os.Stdout)
	errDone := capture(&os.Stderr)
	code = cliMain(ctx, args)
	stderr = errDone()
	stdout = outDone()
	return code, stdout, stderr
}

// readWatch records whether the CLI read stdin.
type readWatch struct{ read bool }

func (r *readWatch) Read([]byte) (int, error) { r.read = true; return 0, io.EOF }

// placeholders are values for the reference's arguments.
var placeholders = map[string]string{
	"NAME": "app", "DB": "app", "DATABASE": "app", "SOURCE": "app", "SERVER": "db1", "HOST": "db1", "ID": "x1",
	"VERSION": "1.2.3", "USER": "bob", "SIZE": "small", "FILE": "migration.sql", "RULE": "replication_lag",
	"TABLE...": "public.orders", "TABLE": "public.orders", "PATH": "/srv/uploads", "EXTENSION": "vector",
	"SETTING=VALUE...": "work_mem=64MB", "TABLE.COLUMN": "public.orders.note", "STRATEGY": "keep", "DB[,DB]": "app",
	"TIME": "10m ago", "LABEL": "before-deploy", "A": "ops@example.com", "URL": "https://example.com/hook",
}

var placeholderRe = regexp.MustCompile(`^[A-Z][A-Z_.]*$`)

// referenceInvocation turns a reference entry (without "rowsafe ") into
// arguments: the command words, the required arguments and flags with
// example values. What is optional ([...]) is left out; of alternatives
// (a|b, (x | y)) the first is taken.
func referenceInvocation(entry string) []string {
	var args []string
	depth, group, skipGroup, words, afterFlag := 0, false, false, true, false
	entry = strings.ReplaceAll(entry, "[DB:]TABLE.COLUMN", "TABLE.COLUMN")
	for _, tok := range strings.Fields(entry) {
		if depth > 0 || strings.HasPrefix(tok, "[") {
			depth += strings.Count(tok, "[") - strings.Count(tok, "]")
			words = false
			continue
		}
		if strings.HasPrefix(tok, "(") {
			group, skipGroup = true, false
			tok = strings.TrimPrefix(tok, "(")
		}
		if group {
			if strings.HasSuffix(tok, ")") {
				group = false
				tok = strings.TrimSuffix(tok, ")")
			}
			if tok == "|" {
				skipGroup = true
			}
			if skipGroup || tok == "|" {
				continue
			}
		}
		lower := strings.ToLower(tok) == tok && !strings.HasPrefix(tok, "-")
		if tok == "|" || tok == "--" || lower && !words && !afterFlag && !strings.Contains(tok, "|") ||
			!lower && !strings.HasPrefix(tok, "-") && !placeholderRe.MatchString(tok) && placeholders[tok] == "" {
			break // the local line's "pulse CONN | fix CONN", installer options, the description
		}
		afterFlag = strings.HasPrefix(tok, "-")
		if !lower {
			words = false
		}
		tok, _, _ = strings.Cut(tok, "|")
		if v, ok := placeholders[tok]; ok {
			args = append(args, v)
		} else if placeholderRe.MatchString(tok) {
			args = append(args, "x")
		} else {
			args = append(args, tok)
		}
	}
	return args
}

// TestAgentRules runs every command in the reference the way an AI agent
// does: --help works, logged in or not; without a terminal and without
// --yes nothing waits on a question, the exit code is one of the
// documented ones, errors say what to do next, and with --json stdout is
// only JSON.
func TestAgentRules(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app"), hosts: []protocol.Host{{ID: "host_1", Hostname: "db1"}},
		protected: map[string]bool{}, health: map[string]int{"app": 90}, anything: true}
	f.dbs[0].Hostname, f.dbs[0].CanRestart = "db1", true
	_, _ = cliEnv(t, f)
	t.Cleanup(func() { stdin = os.Stdin })
	// These run another program, or read a secret from stdin on purpose.
	skip := map[string]bool{"connect": true, "hosts add": true, "mcp": true, "guard": true, "login": true}
	readsSecret := map[string]bool{"add": true, "migrate start": true, "log-destinations add": true, "security fix": true}
	// An error that starts like Go's own (or a bare HTTP status) explains nothing.
	bare := regexp.MustCompile(`(?m)^error: (HTTP \d|json: |invalid character|(Get|Post|Put|Patch|Delete) "|dial tcp|context deadline|exit status|[A-Z][a-z]+( [A-Z][a-z]+)*$)`)

	var entries []string
	lines := strings.Split(usage, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  rowsafe ") {
			continue
		}
		entry, _, _ := strings.Cut(strings.TrimPrefix(line, "  rowsafe "), "   ") // then the description
		for j := i + 1; j < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[j]), "[") && strings.HasPrefix(lines[j], "        "); j++ {
			entry += " " + strings.TrimSpace(lines[j]) // flags continued on the next line
		}
		entries = append(entries, entry)
	}
	if len(entries) < 100 {
		t.Fatalf("parsed only %d reference entries", len(entries))
	}
	helped := map[string]bool{}
	for _, entry := range entries {
		args := referenceInvocation(entry)
		words := helpTopic(args)
		key := strings.Join(words, " ")
		if skip[key] || skip[words[0]] {
			continue
		}
		if !helped[key] {
			helped[key] = true
			code, out, errOut := runCaptured(t, t.Context(), append(cloneArgs(words), "--help")...)
			if code != 0 || !strings.Contains(out, "rowsafe "+key) {
				t.Errorf("rowsafe %s --help: exit %d, stdout %q, stderr %q", key, code, firstLine(out, 80), firstLine(errOut, 80))
			}
		}
		for _, asJSON := range []bool{false, true} {
			run := args
			if asJSON {
				run = append(cloneArgs(args), "--json")
			}
			w := &readWatch{}
			stdin = w
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			start := time.Now()
			code, out, errOut := runCaptured(t, ctx, run...)
			cancel()
			name := "rowsafe " + strings.Join(run, " ")
			if took := time.Since(start); took > 4*time.Second {
				t.Errorf("%s: took %s (waiting on something?)", name, took.Round(time.Second))
			}
			if w.read && !readsSecret[key] {
				t.Errorf("%s: read stdin without a terminal (a question?)\n%s", name, errOut)
			}
			if strings.Contains(errOut, "cancelled") {
				t.Errorf("%s: answered a question without a terminal: %s", name, errOut)
			}
			if code < 0 || code > 3 {
				t.Errorf("%s: exit %d", name, code)
			}
			if code == 2 && !strings.Contains(errOut, "rowsafe help") {
				t.Errorf("%s: a usage error that doesn't say where the help is: %s", name, errOut)
			}
			if m := bare.FindString(errOut); m != "" {
				t.Errorf("%s: a bare error (%q) instead of the next step: %s", name, m, errOut)
			}
			if asJSON && (code == 0 || code == 3 || code == 1 && strings.TrimSpace(out) != "") {
				var v any
				if err := json.Unmarshal([]byte(out), &v); err != nil {
					t.Errorf("%s: exit %d, stdout isn't one JSON value (%v): %q", name, code, err, firstLine(out, 120))
				}
			}
			if code == 2 && out != "" {
				t.Errorf("%s: a usage error printed to stdout: %q", name, firstLine(out, 120))
			}
		}
	}
	if len(helped) < 100 {
		t.Fatalf("checked only %d commands", len(helped))
	}
}

// TestChangesNeedYes: a change without --yes and without a terminal is
// refused at once, naming --yes, and nothing is sent.
func TestChangesNeedYes(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app")}
	f.dbs[0].Hostname, f.dbs[0].CanRestart = "db1", true
	_, _ = cliEnv(t, f)
	t.Cleanup(func() { stdin = os.Stdin })
	for _, args := range [][]string{{"restart", "app"}, {"apply", "app"}, {"remove", "app"}, {"hosts", "remove", "db1"}} {
		w := &readWatch{}
		stdin = w
		code, _, errOut := runCaptured(t, t.Context(), args...)
		if code != 1 || !strings.Contains(errOut, "--yes") || w.read {
			t.Errorf("rowsafe %s without --yes: exit %d, read stdin %v, %s", strings.Join(args, " "), code, w.read, errOut)
		}
	}
	if len(f.tasks) != 0 {
		t.Fatalf("refused changes created tasks: %+v", f.tasks)
	}
	// With --yes it goes ahead, and --json prints the task as it ended.
	code, out, errOut := runCaptured(t, t.Context(), "restart", "app", "--yes", "--json")
	var task protocol.TaskView
	if code != 0 || json.Unmarshal([]byte(out), &task) != nil || task.Type != protocol.TaskRestart || task.Status != protocol.StatusSucceeded {
		t.Fatalf("restart --yes --json: exit %d, stdout %q, stderr %q", code, out, errOut)
	}
}

// TestExitCodes: 2 for a command used the wrong way, 1 for an error, each
// with the next step.
func TestExitCodes(t *testing.T) {
	f := &fakeAPI{dbs: dbs("app")}
	_, _ = cliEnv(t, f)
	for _, tc := range []struct {
		args []string
		code int
		says string
	}{
		{[]string{"ls", "--no-such-flag"}, 2, "rowsafe help ls"},
		{[]string{"no-such-command"}, 2, "rowsafe help"},
		{[]string{"hosts", "pin"}, 2, "expected HOST VERSION"},
		{[]string{"tune", "--workload", "games"}, 2, "--workload must be"},
		{[]string{"show", "nope"}, 1, "rowsafe ls"},
		{[]string{"ls", "--json"}, 0, ""},
	} {
		code, _, errOut := runCaptured(t, t.Context(), tc.args...)
		if code != tc.code || !strings.Contains(errOut, tc.says) {
			t.Errorf("rowsafe %s: exit %d (want %d), stderr %q (want %q)", strings.Join(tc.args, " "), code, tc.code, errOut, tc.says)
		}
	}
	t.Setenv("ROWSAFE_API_KEY", "")
	if code, _, errOut := runCaptured(t, t.Context(), "no-such-command"); code != 2 || !strings.Contains(errOut, "unknown command") {
		t.Errorf("an unknown command, not logged in: exit %d, %s", code, errOut)
	}
	t.Setenv("ROWSAFE_API_KEY", "bad") // the fake control plane refuses it: 401
	if code, _, errOut := runCaptured(t, t.Context(), "ls"); code != 1 || !strings.Contains(errOut, "rowsafe login") {
		t.Errorf("a refused key: exit %d, %s", code, errOut)
	}
	t.Setenv("ROWSAFE_URL", "http://127.0.0.1:1")
	if code, _, errOut := runCaptured(t, t.Context(), "ls"); code != 1 || !strings.Contains(errOut, "can't reach Rowsafe at http://127.0.0.1:1") ||
		!strings.Contains(errOut, "ROWSAFE_URL") {
		t.Errorf("no control plane: exit %d, %s", code, errOut)
	}
}

func cloneArgs(s []string) []string { return append([]string(nil), s...) }
