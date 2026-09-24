package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/mcp"
	"github.com/rowsafe/rowsafe/protocol"
)

// mcpServe runs an MCP server on stdin/stdout for AI assistants such as
// Claude Code. It acts with the saved login (or ROWSAFE_URL and
// ROWSAFE_API_KEY); stdout carries only the protocol.
func mcpServe(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	allowWrites := fs.Bool("allow-writes", false, "also offer tools that queue tasks (plan, apply, backup, restore test, verify, restore points) and change schedules")
	allowRP := fs.Bool("allow-restore-points", false, "also offer create_restore_point, but no other write tool")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	mode := "read-only"
	switch {
	case *allowWrites:
		mode = "read and write"
	case *allowRP:
		mode = "read-only + restore point"
	}
	fmt.Fprintf(os.Stderr, "rowsafe mcp: serving %s tools for %s on stdio\n", mode, c.BaseURL)
	s := mcp.NewServer(c, mcp.Options{AllowWrites: *allowWrites, AllowRestorePoints: *allowRP, Version: version})
	if err := s.Run(ctx, &sdk.StdioTransport{}); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// ---- rowsafe guard: a Claude Code PreToolUse hook ----

// hookEvent is the part of a Claude Code PreToolUse event guard reads.
type hookEvent struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
	Cwd string `json:"cwd"`
}

// projectConfig is .rowsafe.json in a project (or a parent directory).
type projectConfig struct {
	Database          string `json:"database"`
	RequireProtection bool   `json:"require_protection"`
}

// guard reads a PreToolUse event on stdin. When the Bash command looks like
// a destructive database operation, it creates a restore point on the
// project's database first and tells Claude its name. It blocks the command
// only when protection is required (ROWSAFE_REQUIRE_PROTECTION=1 or
// "require_protection": true) and the database isn't protected or the
// restore point can't be confirmed. Otherwise failures only warn.
func guard(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	check := fs.String("check", "", "only report whether this command looks destructive (exit 0 yes, 1 no)")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	if *check != "" {
		reason, ok := mcp.DestructiveDBCommand(*check, os.ReadFile)
		if !ok {
			fmt.Println("not destructive")
			return exitError(1)
		}
		fmt.Println("destructive:", reason)
		return nil
	}

	var ev hookEvent
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 4<<20)).Decode(&ev); err != nil {
		return fmt.Errorf("reading the hook event from stdin: %w", err)
	}
	if ev.ToolName != "Bash" || ev.ToolInput.Command == "" {
		return nil
	}
	reason, ok := mcp.DestructiveDBCommand(ev.ToolInput.Command, func(p string) ([]byte, error) { return readSmallFile(ev.Cwd, p) })
	if !ok {
		return nil
	}

	proj, projPath := findProjectConfig(ev.Cwd)
	db := cmp.Or(strings.TrimSpace(os.Getenv("ROWSAFE_DATABASE")), proj.Database)
	required := proj.RequireProtection
	if v, err := strconv.ParseBool(os.Getenv("ROWSAFE_REQUIRE_PROTECTION")); err == nil {
		required = v
	}
	fail := func(msg string) error {
		if required {
			fmt.Fprintf(os.Stderr, "Rowsafe blocked this command (%s): %s\nProtection is required here (ROWSAFE_REQUIRE_PROTECTION or require_protection in .rowsafe.json). Tell the user; don't work around this block.\n", reason, msg)
			os.Exit(2)
		}
		return hookReply("Rowsafe: "+msg+" The command runs without a fresh restore point.",
			fmt.Sprintf("Rowsafe could not create a restore point before this command (%s): %s Tell the user before relying on being able to undo it.", reason, msg))
	}
	if db == "" {
		return fail("no Rowsafe database is configured for this project: set ROWSAFE_DATABASE or add .rowsafe.json with {\"database\": \"NAME\"}.")
	}
	cfg, err := loadConfig()
	if err != nil {
		return fail(err.Error() + ".")
	}
	c := client.New(cfg.URL, cfg.APIKey)
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()

	if required {
		p, err := c.Protection(ctx, db)
		if err != nil {
			return fail(fmt.Sprintf("checking protection of %s failed: %v.", db, err))
		}
		if !p.Protected {
			return fail(fmt.Sprintf("%s is not protected: %s.", db, strings.Join(p.Reasons, "; ")))
		}
	}
	name := "agent-" + time.Now().UTC().Format("20060102-150405")
	task, err := c.CreateRestorePoint(ctx, db, name)
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict { // two commands in the same second
		name += fmt.Sprintf("-%03d", time.Now().Nanosecond()/1e6)
		task, err = c.CreateRestorePoint(ctx, db, name)
	}
	if err != nil {
		return fail(fmt.Sprintf("creating a restore point on %s failed: %v.", db, err))
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 90*time.Second)
	task, err = c.WaitTask(waitCtx, task.ID, nil)
	waitCancel()
	status := "pending"
	lsn := ""
	if points, perr := c.RestorePoints(ctx, db); perr == nil {
		for _, p := range points {
			if p.Name == name {
				status, lsn = p.Status, p.LSN
			}
		}
	}
	if status != protocol.RestorePointArchived {
		detail := fmt.Sprintf("restore point %s on %s is %s, not confirmed in the backup repository", name, db, status)
		if err == nil && task.Error != "" {
			detail += ": " + firstLine(task.Error, 200)
		}
		return fail(detail + ".")
	}
	src := "ROWSAFE_DATABASE"
	if os.Getenv("ROWSAFE_DATABASE") == "" {
		src = projPath
	}
	return hookReply(fmt.Sprintf("Rowsafe: restore point %s created on %s (LSN %s) before: %s", name, db, lsn, reason),
		fmt.Sprintf("Rowsafe created restore point %q on database %s (from %s), confirmed in the backup repository, right before this command (%s). "+
			"If the command goes wrong, stop and tell the user they can restore %s to restore point %q; don't try to repair the data or restore it yourself.",
			name, db, src, reason, db, name))
}

// hookReply lets the command run and passes a note to the user and to Claude.
func hookReply(userMsg, context string) error {
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"systemMessage": userMsg,
		"hookSpecificOutput": map[string]any{
			"hookEventName":     "PreToolUse",
			"additionalContext": context,
		},
	})
}

// findProjectConfig looks for .rowsafe.json in dir and its parents.
func findProjectConfig(dir string) (projectConfig, string) {
	var pc projectConfig
	if dir == "" {
		dir, _ = os.Getwd()
	}
	for dir != "" {
		p := filepath.Join(dir, ".rowsafe.json")
		if data, err := os.ReadFile(p); err == nil {
			if json.Unmarshal(data, &pc) == nil {
				return pc, p
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return pc, ""
}

// readSmallFile reads a SQL file named in the command, relative to the
// command's directory, if it is a regular file under 1 MiB.
func readSmallFile(cwd, p string) ([]byte, error) {
	if !filepath.IsAbs(p) && cwd != "" {
		p = filepath.Join(cwd, p)
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, errors.New("not a small regular file")
	}
	return os.ReadFile(p)
}
