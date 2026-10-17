// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/rowsafe/rowsafe/client"
)

// Tips: after a command that worked, one short line about something useful
// next. Only for a person at a terminal: never with --json, in a pipe, for
// an AI agent or in CI. At most one an hour, each tip at most every two
// weeks. rowsafe tips off (or ROWSAFE_NO_TIPS=1) stops them.

const (
	tipEvery     = time.Hour
	tipRepeatGap = 14 * 24 * time.Hour
)

// tipState is what the CLI knows when picking a tip.
type tipState struct {
	cmd      string
	name     string // the database named on the command line, else "NAME"
	onServer bool   // this server's agent runs on its own
	loggedIn bool   // logged in to an account
	channels func() int
}

type tipDef struct {
	id   string
	when func(t tipState) bool
	text func(t tipState) string
}

func oneOf(cmd string, cmds ...string) bool { return slices.Contains(cmds, cmd) }

var tips = []tipDef{
	{"alerts", func(t tipState) bool {
		return t.onServer && oneOf(t.cmd, "status", "backups", "proofs", "marks", "mark", "add") && t.channels() == 0
	}, func(t tipState) string {
		return "get an alert when backups or Proof need you, on your phone: sudo rowsafe channels add --type ntfy --name phone --url https://ntfy.sh/YOUR-TOPIC (or slack, discord, webhook)"
	}},
	{"mark", func(t tipState) bool { return t.onServer && oneOf(t.cmd, "status", "backups") }, func(t tipState) string {
		return "before a risky change, save a restore point to come back to: sudo rowsafe mark " + t.name + " before-change"
	}},
	{"dashboard", func(t tipState) bool {
		return t.onServer && oneOf(t.cmd, "status", "backups", "proofs", "alerts", "restores")
	}, func(t tipState) string {
		return "sudo rowsafe login adds the dashboard: every server in one place, and alerts even when this server is down. Backups and Marks come along."
	}},
	{"mcp", func(t tipState) bool { return !t.loggedIn && oneOf(t.cmd, "pulse", "schema", "explain", "insights") }, func(t tipState) string {
		return "your AI agent can run these checks too: claude mcp add rowsafe -- rowsafe mcp " + t.name + "   (Codex: codex mcp add rowsafe -- rowsafe mcp " + t.name + ")"
	}},
	{"protect", func(t tipState) bool { return !t.loggedIn && !t.onServer && oneOf(t.cmd, "pulse", "fix") }, func(t tipState) string {
		return "backups you can restore to any second, tested every week: on the database's server, curl -fsSL https://rowsafe.sh | sudo sh"
	}},
	{"preview", func(t tipState) bool { return oneOf(t.cmd, "schema", "explain") }, func(t tipState) string {
		return "check a migration before it runs (locks, rewrites, a verdict): rowsafe preview " + t.name + " migration.sql"
	}},
}

type tipsFile struct {
	Off   bool                 `json:"off,omitempty"`
	Last  time.Time            `json:"last,omitzero"`
	Shown map[string]time.Time `json:"shown,omitempty"`
}

func tipsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rowsafe", "tips.json"), nil
}

func readTips() tipsFile {
	var f tipsFile
	if p, err := tipsPath(); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(data, &f)
		}
	}
	return f
}

func writeTips(f tipsFile) error {
	p, err := tipsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(f)
	return os.WriteFile(p, data, 0o600)
}

// tipsAllowed: a person at a terminal who hasn't turned tips off.
var tipsAllowed = func() bool {
	if jsonMode || os.Getenv("ROWSAFE_NO_TIPS") != "" || os.Getenv("CI") != "" || agentRunning() {
		return false
	}
	return term.IsTerminal(int(os.Stdout.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
}

// agentRunning: an AI coding agent runs this command (its usual variables).
func agentRunning() bool {
	for _, k := range []string{"CLAUDECODE", "CODEX_SANDBOX", "CURSOR_AGENT", "GEMINI_CLI"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}

// showTip prints at most one tip after a command that worked.
func showTip(ctx context.Context, args []string) {
	if len(args) == 0 || !tipsAllowed() {
		return
	}
	f := readTips()
	now := time.Now()
	if f.Off || now.Sub(f.Last) < tipEvery {
		return
	}
	t := tipState{cmd: args[0], name: "NAME", channels: func() int { return -1 }}
	for _, a := range args[1:] {
		if !strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "://") && !strings.Contains(a, "=") && len(a) <= 63 {
				t.name = a
			}
			break
		}
	}
	if cfg, err := loadConfig(); err == nil {
		t.onServer = cfg.APIKey == "local"
		t.loggedIn = cfg.APIKey != "" && !t.onServer
		if t.onServer {
			t.channels = func() int {
				ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
				chans, err := client.New(cfg.URL, cfg.APIKey).NotificationChannels(ctx)
				if err != nil {
					return -1
				}
				return len(chans)
			}
		}
	}
	for _, tip := range tips {
		if now.Sub(f.Shown[tip.id]) < tipRepeatGap || !tip.when(t) {
			continue
		}
		fmt.Fprintln(os.Stderr, "\n"+dim("Tip: "+tip.text(t)))
		if f.Shown == nil {
			f.Shown = map[string]time.Time{}
		}
		f.Last, f.Shown[tip.id] = now, now
		_ = writeTips(f)
		return
	}
}

// tipsCmd is rowsafe tips on|off|status.
func tipsCmd(args []string) error {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	f := readTips()
	switch sub {
	case "on", "off":
		f.Off = sub == "off"
		if err := writeTips(f); err != nil {
			return err
		}
		fmt.Printf("Tips are %s.\n", sub)
	case "status":
		state := "on"
		if f.Off || os.Getenv("ROWSAFE_NO_TIPS") != "" {
			state = "off"
		}
		if jsonMode {
			return printJSON(map[string]string{"tips": state})
		}
		fmt.Printf("Tips are %s: at most one short line an hour after a command, only at a terminal (never with --json or for AI agents).\n", state)
	default:
		return errors.New("rowsafe tips on | off | status")
	}
	return nil
}
