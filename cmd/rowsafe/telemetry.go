package main

// Usage counts (rowsafe telemetry): off unless the person runs `rowsafe
// telemetry on`, and never prompted. Then, after each command, one
// protocol.TelemetryEvent (the command's names from the reference, the
// version, OS, exit code, a duration bucket, terminal or not, which AI agent
// if any, logged in or not, a random install ID) goes to the control plane
// from a separate process, so the command never waits on the network and
// never fails because of it. ROWSAFE_TELEMETRY=0 and DO_NOT_TRACK=1 always
// win over the saved choice.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// telemetrySendArg runs the CLI as the sender: it reads one envelope on
// stdin, posts it once and exits.
const telemetrySendArg = "__telemetry-send"

// telemetrySendTimeout bounds the sender process, not the command.
const telemetrySendTimeout = 3 * time.Second

type telemetryRun struct {
	args  []string
	start time.Time
}

// telemetryStart is called by main before the command runs. As the sender
// process it posts and exits instead.
func telemetryStart(args []string) *telemetryRun {
	if len(args) > 0 && args[0] == telemetrySendArg {
		telemetrySend(os.Stdin)
		os.Exit(0)
	}
	return &telemetryRun{args: args, start: time.Now()}
}

// done hands the run to the sender process when usage counts are on, and
// returns at once.
func (t *telemetryRun) done(err error) {
	if telemetryOffBy(os.Getenv) != "" {
		return
	}
	id := telemetryInstallID()
	if id == "" {
		return
	}
	cfg, loginErr := loadConfig()
	ev := telemetryEvent(id, t.args, err, time.Since(t.start), loginErr == nil)
	telemetryLaunch(strings.TrimRight(cfg.URL, "/"), ev)
}

func telemetryEvent(id string, args []string, err error, took time.Duration, loggedIn bool) protocol.TelemetryEvent {
	return protocol.TelemetryEvent{
		InstallID: id,
		Command:   telemetryCommand(args),
		Version:   telemetryVersion(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		ExitCode:  exitCode(err),
		Duration:  protocol.TelemetryDuration(took.Seconds()),
		Terminal:  telemetryTerminal(),
		Agent:     telemetryAgent(os.Getenv),
		LoggedIn:  loggedIn,
	}
}

// exitCode is the code main exits with for err.
func exitCode(err error) int {
	var exit exitError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.As(err, &exit):
		return min(max(int(exit), 0), 255)
	}
	return 1
}

var telemetryVersionRe = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,40}$`)

func telemetryVersion() string {
	if telemetryVersionRe.MatchString(version) {
		return version
	}
	return "dev"
}

// telemetryTerminal: stdin is a terminal (a character device other than
// /dev/null, which agents and scripts often give).
func telemetryTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(fi, null)
}

// telemetryOffBy names the environment variable that turns usage counts
// off, whatever was saved: ROWSAFE_TELEMETRY=0 (or false, off, no) and
// DO_NOT_TRACK set to anything but 0 or false.
func telemetryOffBy(getenv func(string) string) string {
	switch strings.ToLower(strings.TrimSpace(getenv("ROWSAFE_TELEMETRY"))) {
	case "0", "false", "off", "no":
		return "ROWSAFE_TELEMETRY"
	}
	switch strings.ToLower(strings.TrimSpace(getenv("DO_NOT_TRACK"))) {
	case "", "0", "false":
		return ""
	}
	return "DO_NOT_TRACK"
}

// telemetryAgent names the AI agent running the CLI, from variables only
// that agent sets (a plain terminal in the same editor doesn't count), or "".
func telemetryAgent(getenv func(string) string) string {
	switch {
	case getenv("CLAUDECODE") == "1":
		return "claude-code"
	case getenv("CODEX_SANDBOX") != "" || getenv("CODEX_SANDBOX_NETWORK_DISABLED") != "" || getenv("CODEX_THREAD_ID") != "":
		return "codex"
	case getenv("CURSOR_AGENT") == "1":
		return "cursor"
	case getenv("GEMINI_CLI") == "1":
		return "gemini"
	}
	return ""
}

// telemetryCommands are the command paths in the reference ("pulse", "cloud
// create", "cloud maintenance set"): the only words ever sent, so a
// database's or server's name never is.
var telemetryCommands = sync.OnceValue(func() map[string]bool {
	word := regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	paths := map[string]bool{}
	for _, line := range strings.Split(usage, "\n") {
		if !strings.HasPrefix(line, "  rowsafe ") {
			continue
		}
		// The description starts after two spaces. rowsafe pulse CONN | fix
		// CONN | ...: each part is a command.
		syntax, _, _ := strings.Cut(strings.TrimPrefix(line, "  rowsafe "), "  ")
		for _, part := range strings.Split(syntax, " | ") {
			var words []string
			for _, w := range strings.Fields(part) {
				if !word.MatchString(w) || len(words) == 3 {
					break
				}
				words = append(words, w)
				paths[strings.Join(words, " ")] = true
			}
		}
	}
	return paths
})

// telemetryCommand is the longest run of leading words that is a command in
// the reference, or protocol.TelemetryOther.
func telemetryCommand(args []string) string {
	var words []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") || len(words) == 3 {
			break
		}
		words = append(words, a)
	}
	for n := len(words); n > 0; n-- {
		if p := strings.Join(words[:n], " "); telemetryCommands()[p] {
			return p
		}
	}
	return protocol.TelemetryOther
}

// ---- the saved choice: telemetry.json next to config.json ----

func telemetryPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rowsafe", "telemetry.json"), nil
}

type telemetryFile struct {
	InstallID string `json:"install_id"`
}

var installIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// telemetryInstallID is the saved random ID, "" when usage counts are off.
func telemetryInstallID() string {
	p, err := telemetryPath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var f telemetryFile
	if json.Unmarshal(data, &f) != nil || !installIDRe.MatchString(f.InstallID) {
		return ""
	}
	return f.InstallID
}

// ---- sending ----

type telemetryEnvelope struct {
	URL   string                  `json:"url"`
	Event protocol.TelemetryEvent `json:"event"`
}

// telemetryLaunch starts the sender process and returns without waiting
// for it (tests replace it).
var telemetryLaunch = func(url string, ev protocol.TelemetryEvent) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	body, err := json.Marshal(telemetryEnvelope{URL: url, Event: ev})
	if err != nil {
		return
	}
	r, w, err := os.Pipe()
	if err != nil {
		return
	}
	defer r.Close()
	// A few hundred bytes fit in the pipe's buffer: this never blocks.
	_, werr := w.Write(body)
	w.Close()
	if werr != nil {
		return
	}
	cmd := exec.Command(exe, telemetrySendArg)
	cmd.Stdin = r // stdout and stderr: /dev/null, so nobody reading ours waits for it
	detach(cmd)   // its own process group: Ctrl-C in the terminal doesn't reach it
	if cmd.Start() == nil {
		_ = cmd.Process.Release()
	}
}

// telemetrySend posts one envelope once, quietly: no retries, no output.
func telemetrySend(in io.Reader) {
	var env telemetryEnvelope
	data, err := io.ReadAll(io.LimitReader(in, 4096))
	if err != nil || json.Unmarshal(data, &env) != nil || env.Event.Validate() != nil {
		return
	}
	if !strings.HasPrefix(env.URL, "https://") && !strings.HasPrefix(env.URL, "http://") {
		return
	}
	body, _ := json.Marshal(env.Event)
	ctx, cancel := context.WithTimeout(context.Background(), telemetrySendTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, env.URL+protocol.TelemetryPath, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "rowsafe-cli")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

// ---- rowsafe telemetry on|off|status ----

func telemetryCmd(args []string) error {
	sub := "status"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "on":
		return telemetryOn(args)
	case "off":
		return telemetryOff(args)
	case "status":
		return telemetryStatus(args)
	}
	return fmt.Errorf("unknown command %q. The telemetry commands:\n%s", "telemetry "+sub, strings.TrimSpace(helpFor([]string{"telemetry"})))
}

func telemetryOn(args []string) error {
	if _, err := parseTelemetryFlags("telemetry on", args, nil); err != nil {
		return err
	}
	p, err := telemetryPath()
	if err != nil {
		return err
	}
	if telemetryInstallID() == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		data, _ := json.Marshal(telemetryFile{InstallID: hex.EncodeToString(b)})
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, append(data, '\n'), 0o600); err != nil {
			return err
		}
	}
	fmt.Println("Usage counts are on: after each command, the command's name and the few details")
	fmt.Println("`rowsafe telemetry status` shows go to Rowsafe. Thank you. Turn off: rowsafe telemetry off")
	if by := telemetryOffBy(os.Getenv); by != "" {
		fmt.Printf("%s is set here, so nothing is sent until it isn't.\n", by)
	}
	return nil
}

func telemetryOff(args []string) error {
	if _, err := parseTelemetryFlags("telemetry off", args, nil); err != nil {
		return err
	}
	p, err := telemetryPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Println("Usage counts are off, and this computer's random ID is forgotten. Nothing is sent.")
	return nil
}

// telemetryStatusOut is `rowsafe telemetry status --json`.
type telemetryStatusOut struct {
	On bool `json:"on"`
	// OffBy is the environment variable keeping them off, if any.
	OffBy string `json:"off_by,omitempty"`
	URL   string `json:"url"`
	// Example is what this very command sends when on.
	Example protocol.TelemetryEvent `json:"example"`
}

func telemetryStatus(args []string) error {
	var asJSON bool
	if _, err := parseTelemetryFlags("telemetry status", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&asJSON, "json", false, "print JSON")
	}); err != nil {
		return err
	}
	id := telemetryInstallID()
	by := telemetryOffBy(os.Getenv)
	cfg, loginErr := loadConfig()
	out := telemetryStatusOut{
		On: id != "" && by == "", OffBy: by, URL: strings.TrimRight(cfg.URL, "/") + protocol.TelemetryPath,
		Example: telemetryEvent(id, []string{"telemetry", "status"}, nil, 0, loginErr == nil),
	}
	if id == "" {
		out.Example.InstallID = "(a random ID made by rowsafe telemetry on)"
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	example, _ := json.MarshalIndent(out.Example, "  ", "  ")
	switch {
	case out.On:
		fmt.Printf("Usage counts: on. After each command, one line like this goes to %s:\n\n  %s\n\n", out.URL, example)
	case by != "":
		fmt.Printf("Usage counts: off (%s is set). Nothing is sent.\n\nIf they were on, after each command one line like this would go to %s:\n\n  %s\n\n", by, out.URL, example)
	default:
		fmt.Printf("Usage counts: off (the default). Nothing is sent.\n\nIf you turn them on, after each command one line like this goes to %s:\n\n  %s\n\n", out.URL, example)
	}
	fmt.Println("Never sent: arguments, flag values, names of databases or servers, connection strings, hostnames,")
	fmt.Println("error messages, or anything tied to your account. It's sent in the background, never retried, and")
	fmt.Println("the command never waits for it.")
	if out.On {
		fmt.Println("\nTurn off: rowsafe telemetry off (or set ROWSAFE_TELEMETRY=0 or DO_NOT_TRACK=1)")
	} else if by == "" {
		fmt.Println("\nTurn on: rowsafe telemetry on")
	}
	return nil
}

func parseTelemetryFlags(name string, args []string, define func(*flag.FlagSet)) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	if define != nil {
		define(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("rowsafe %s takes no arguments", name)
	}
	return fs, nil
}
