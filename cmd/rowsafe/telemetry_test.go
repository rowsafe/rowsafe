package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestMain lets the test binary act as the sender process, as the CLI does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == telemetrySendArg {
		telemetrySend(os.Stdin)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// telemetryHome gives the test its own config directory, with no login and
// no telemetry variables.
func telemetryHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", home+"/.config")
	for _, v := range []string{"ROWSAFE_TELEMETRY", "DO_NOT_TRACK", "ROWSAFE_URL", "ROWSAFE_API_KEY", "CLAUDECODE",
		"CODEX_SANDBOX", "CODEX_SANDBOX_NETWORK_DISABLED", "CODEX_THREAD_ID", "CURSOR_AGENT", "GEMINI_CLI"} {
		t.Setenv(v, "")
	}
}

// captureLaunch records what would be sent instead of starting a process.
func captureLaunch(t *testing.T) *[]protocol.TelemetryEvent {
	t.Helper()
	var sent []protocol.TelemetryEvent
	old := telemetryLaunch
	telemetryLaunch = func(_ string, ev protocol.TelemetryEvent) { sent = append(sent, ev) }
	t.Cleanup(func() { telemetryLaunch = old })
	return &sent
}

func quiet(t *testing.T) {
	t.Helper()
	old := os.Stdout
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = devnull
	t.Cleanup(func() { os.Stdout = old; devnull.Close() })
}

func TestTelemetryNothingSentUnlessOn(t *testing.T) {
	telemetryHome(t)
	quiet(t)
	sent := captureLaunch(t)
	run := func() { (&telemetryRun{args: []string{"ls"}, start: time.Now()}).done(nil) }

	run()
	if len(*sent) != 0 {
		t.Fatalf("sent %d events with usage counts never turned on", len(*sent))
	}
	if err := telemetryCmd([]string{"on"}); err != nil {
		t.Fatal(err)
	}
	for _, env := range [][2]string{{"ROWSAFE_TELEMETRY", "0"}, {"ROWSAFE_TELEMETRY", "off"}, {"DO_NOT_TRACK", "1"}, {"DO_NOT_TRACK", "true"}} {
		t.Setenv(env[0], env[1])
		run()
		t.Setenv(env[0], "")
		if len(*sent) != 0 {
			t.Fatalf("sent with %s=%s", env[0], env[1])
		}
	}
	t.Setenv("DO_NOT_TRACK", "0")
	run()
	if len(*sent) != 1 {
		t.Fatalf("sent %d events once on, want 1", len(*sent))
	}
	if err := telemetryCmd([]string{"off"}); err != nil {
		t.Fatal(err)
	}
	run()
	if len(*sent) != 1 {
		t.Fatal("sent after rowsafe telemetry off")
	}
	if telemetryInstallID() != "" {
		t.Fatal("the install ID survived rowsafe telemetry off")
	}
}

func TestTelemetryOnKeepsOneID(t *testing.T) {
	telemetryHome(t)
	quiet(t)
	if err := telemetryCmd([]string{"on"}); err != nil {
		t.Fatal(err)
	}
	id := telemetryInstallID()
	if !installIDRe.MatchString(id) {
		t.Fatalf("install ID %q", id)
	}
	p, _ := telemetryPath()
	if fi, err := os.Stat(p); err != nil || !hasPerm(fi, 0o600) {
		t.Fatalf("telemetry.json: %v %v", fi, err)
	}
	if err := telemetryCmd([]string{"on"}); err != nil {
		t.Fatal(err)
	}
	if telemetryInstallID() != id {
		t.Fatal("turning on twice made a new ID")
	}
}

// The event carries exactly the documented fields, and none of the words a
// person typed beyond the command's own names.
func TestTelemetryEventOnlyAllowedFields(t *testing.T) {
	telemetryHome(t)
	secrets := []string{"shop-prod", "postgres://alice:hunter2@db.example.com/shop", "fsn1", "db.example.com", "alice"}
	args := []string{"cloud", "create", "shop-prod", "--region", "fsn1", "--allow", "db.example.com"}
	ev := telemetryEvent(strings.Repeat("ab", 16), args, errors.New("could not reach db.example.com as alice"), 3*time.Second, false)
	if ev.Command != "cloud create" {
		t.Fatalf("command %q", ev.Command)
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(ev)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	want := []string{"agent", "arch", "command", "duration", "exit_code", "install_id", "logged_in", "os", "terminal", "version"}
	if !slices.Equal(keys, want) {
		t.Fatalf("fields %v, want exactly %v (a new field needs the docs and the control plane updated)", keys, want)
	}
	for _, s := range secrets {
		if strings.Contains(string(data), s) {
			t.Fatalf("event contains %q: %s", s, data)
		}
	}
	ev = telemetryEvent(strings.Repeat("ab", 16), []string{"pulse", "postgres://alice:hunter2@db.example.com/shop"}, exitError(3), 0, true)
	if data, _ := json.Marshal(ev); strings.Contains(string(data), "hunter2") || ev.Command != "pulse" || ev.ExitCode != 3 {
		t.Fatalf("pulse event: %s", data)
	}
}

func TestTelemetryCommand(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"ls"}, "ls"},
		{[]string{"show", "shop"}, "show"},
		{[]string{"cloud", "create", "shop", "--size", "small"}, "cloud create"},
		{[]string{"cloud", "maintenance", "set", "shop", "--day", "sun"}, "cloud maintenance set"},
		{[]string{"cloud", "show", "create"}, "cloud show"}, // a server named "create"
		{[]string{"rewind", "copy", "--at", "10m ago"}, "rewind copy"},
		{[]string{"fix", "postgres://u@h/db"}, "fix"},
		{[]string{"mcp", "postgres://u@h/db"}, "mcp"},
		{[]string{"db", "user", "add", "alice"}, "db user add"},
		{[]string{"mark", "shop", "before-migration"}, "mark"},
		{[]string{"telemetry", "status", "--json"}, "telemetry status"},
		{[]string{"hosts", "list", "hosts"}, "hosts list"},
		{[]string{"shop-prod"}, protocol.TelemetryOther},
		{[]string{"--json"}, protocol.TelemetryOther},
	} {
		if got := telemetryCommand(c.args); got != c.want {
			t.Errorf("telemetryCommand(%q) = %q, want %q", c.args, got, c.want)
		}
	}
}

func TestTelemetryAgent(t *testing.T) {
	for env, want := range map[string]string{
		"":                                 "",
		"CLAUDECODE=1":                     "claude-code",
		"CLAUDECODE=0":                     "",
		"CODEX_SANDBOX=seatbelt":           "codex",
		"CODEX_SANDBOX_NETWORK_DISABLED=1": "codex",
		"CURSOR_AGENT=1":                   "cursor",
		"CURSOR_TRACE_ID=abc":              "", // any terminal in Cursor
		"GEMINI_CLI=1":                     "gemini",
		"TERM_PROGRAM=vscode":              "",
	} {
		k, v, _ := strings.Cut(env, "=")
		got := telemetryAgent(func(name string) string {
			if name == k {
				return v
			}
			return ""
		})
		if got != want {
			t.Errorf("%s: agent %q, want %q", env, got, want)
		}
	}
}

func TestExitCode(t *testing.T) {
	for err, want := range map[error]int{nil: 0, exitError(3): 3, errors.New("x"): 1} {
		if got := exitCode(err); got != want {
			t.Errorf("exitCode(%v) = %d, want %d", err, got, want)
		}
	}
}

// The command hands the event to a separate process and returns at once,
// even when the control plane never answers; the process sends it.
func TestTelemetryNeverWaits(t *testing.T) {
	telemetryHome(t)
	quiet(t)
	got := make(chan []byte, 1)
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == protocol.TelemetryPath && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			got <- body
		}
		select { // never answer while the test runs
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer ts.Close()
	defer close(release)
	t.Setenv("ROWSAFE_URL", ts.URL)
	if err := telemetryCmd([]string{"on"}); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	(&telemetryRun{args: []string{"status", "shop"}, start: start}).done(exitError(3))
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("the command waited %s for usage counts", took)
	}
	select {
	case body := <-got:
		var ev protocol.TelemetryEvent
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ev); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if ev.Command != "status" || ev.ExitCode != 3 || ev.LoggedIn || ev.InstallID != telemetryInstallID() {
			t.Fatalf("sent %+v", ev)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sender process sent nothing")
	}
}
