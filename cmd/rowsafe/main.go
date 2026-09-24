// Command rowsafe is the Rowsafe CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

var version = "dev"

// usage is the full command reference (rowsafe help all). rowsafe help
// COMMAND prints the lines of it that start with that command.
const usage = `rowsafe - databases that let you sleep at night

All commands (NAME is optional where shown in brackets; see "rowsafe help names"):

  rowsafe login [--no-browser] [--url URL]   log in with your browser (default URL https://api.rowsafe.sh)
  rowsafe login --key rsk_... [--url URL]    log in with an existing API key (CI, scripts)
  rowsafe logout [--keep-key]                forget the login and revoke the key "rowsafe login" created
  rowsafe whoami                             control plane, organization, plan and API key in use
  rowsafe init [NAME]                        write .rowsafe.json here, so commands in this project use NAME

  rowsafe ls                                 databases (alias: db list)
  rowsafe show [NAME]                        one database in detail (alias: db show)
  rowsafe status [NAME] [--json]             with NAME: is it recoverable right now? without: fleet health.
                                             Exit 0 if protected / all healthy, 3 if not (for scripts and hooks)
  rowsafe adopt NAME [--host HOST] [--port 5432] [--socket-dir DIR] [--retention-full 2]
                                             register an existing Postgres; prints a read-only plan.
                                             --host may be omitted when the organization has one host
  rowsafe plan [NAME]                        re-run the read-only adopt plan
  rowsafe apply [NAME] [--force] [--yes]     apply the plan (never restarts Postgres)
  rowsafe verify [NAME]                      prove WAL reaches the repository; activates schedules

  rowsafe backup [NAME] [--type full|diff|incr] [--no-wait]
                                             take a backup now (alias: backup run)
  rowsafe backups [NAME]                     backups (alias: backup list)
  rowsafe drill [NAME] [--no-wait]           restore the latest backup to a scratch dir and check it (alias: drill run)
  rowsafe drills [NAME]                      restore drills (alias: drill list)
  rowsafe mark [NAME] [LABEL] [--no-wait]    named restore point, e.g. before a migration (alias: restore-point create).
                                             LABEL defaults to manual-<UTC time>
  rowsafe marks [NAME]                       restore points (alias: restore-point list)
  rowsafe tasks [NAME] [--status S] [--type T] [--limit N]
                                             recent tasks for a database, or for all of them
  rowsafe task show ID                       one task with its full log

  rowsafe db set [NAME] [--retention-full N] [--full-schedule CRON] [--diff-schedule CRON] [--drill-schedule CRON]
                                             change retention and schedules (5-field cron, UTC; --diff-schedule "" disables diffs)
  rowsafe db remove NAME [--keep-archiving] [--yes]
                                             stop managing a database; never changes the host
  rowsafe db protection [NAME] [--json]      same as rowsafe status NAME

  rowsafe org                                plan, limits and usage
  rowsafe api-keys list
  rowsafe api-keys create NAME [--read-only] the key is shown once; read-only keys can only read
  rowsafe api-keys revoke ID
  rowsafe audit [--limit N]                  who changed what, newest first

  rowsafe hosts list                         hosts with agent version and update state
  rowsafe hosts enroll-token [--ttl 1h]      token + install command for a new host
  rowsafe hosts pin HOST VERSION             keep a host's agent on VERSION (ignores rollout and halts)
  rowsafe hosts unpin HOST                   follow the host's update channel again
  rowsafe hosts channel HOST NAME            switch the host's update channel (e.g. stable, beta)
  rowsafe hosts remove HOST [--yes]          remove a host without databases and revoke its agent

  rowsafe alerts [--all | --resolved]        firing alerts (with --all, resolved ones too)
  rowsafe alerts ack ID                      acknowledge a firing alert: no more reminders
  rowsafe alerts rules                       built-in alert rules with this org's settings
  rowsafe db top NAME [--limit 20]           top statements by total time (pg_stat_statements)
  rowsafe db activity NAME                   queries running, or idle in a transaction, for over a minute
  rowsafe channels list
  rowsafe channels add --type email --name NAME --address A [--address B] [--min-severity warning]
  rowsafe channels add --type slack|discord|webhook --name NAME --url URL [--min-severity warning]
                                             where alerts are sent (webhooks print a signing secret once)
  rowsafe channels remove ID
  rowsafe channels test ID                   send a test notification now

  rowsafe mcp [--allow-restore-points | --allow-writes]
                                             MCP server on stdio for AI assistants (docs/mcp.md); read-only
                                             unless restore points or all write tools are allowed
  rowsafe guard                              Claude Code PreToolUse hook: before a destructive database
                                             command, create a restore point (docs/agents.md)
  rowsafe guard --check COMMAND              tell whether COMMAND looks destructive (exit 0 yes, 1 no)

Run commands wait for the task to finish; pass --no-wait to return at once.

Environment: ROWSAFE_URL and ROWSAFE_API_KEY override the saved login; ROWSAFE_DATABASE names the database.
`

type config struct {
	URL    string `json:"url"`
	APIKey string `json:"api_key"`
	// KeyID is set when `rowsafe login` created the key in the browser
	// flow; `rowsafe logout` revokes only such keys.
	KeyID string             `json:"key_id,omitempty"`
	Org   *protocol.OrgBrief `json:"org,omitempty"`
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rowsafe", "config.json"), nil
}

func loadConfig() (config, error) {
	var c config
	if p, err := configPath(); err == nil {
		if data, err := os.ReadFile(p); err == nil {
			if err := json.Unmarshal(data, &c); err != nil {
				return c, fmt.Errorf("reading %s: %w", p, err)
			}
		}
	}
	if v := os.Getenv("ROWSAFE_URL"); v != "" {
		c.URL = v
	}
	if v := os.Getenv("ROWSAFE_API_KEY"); v != "" {
		c.APIKey = v
	}
	if c.URL == "" {
		c.URL = protocol.DefaultAPIURL
	}
	if c.APIKey == "" {
		return c, errors.New("not logged in: run `rowsafe login`")
	}
	c.URL = strings.TrimRight(c.URL, "/")
	return c, nil
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if len(args) == 0 {
			fmt.Print(shortHelp)
			os.Exit(2)
		}
		fmt.Print(helpFor(args[1:]))
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := dispatch(ctx, args); err != nil {
		var exit exitError
		if errors.As(err, &exit) {
			os.Exit(int(exit)) // the command already said what happened
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// exitError carries a non-zero exit code for failed tasks.
type exitError int

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func dispatch(ctx context.Context, args []string) error {
	cmd := args[0]
	if cmd == "version" {
		fmt.Println(version)
		return nil
	}
	switch cmd {
	case "login":
		return login(ctx, args[1:])
	case "logout":
		return logout(ctx, args[1:])
	case "whoami":
		return whoami(ctx)
	}
	if cmd == "guard" {
		return guard(ctx, args[1:])
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg.URL, cfg.APIKey)
	args = expandAlias(args)
	cmd = args[0]
	if handled, err := shortCommand(ctx, c, args); handled {
		return err
	}
	if cmd == "mcp" {
		return mcpServe(ctx, c, args[1:])
	}
	if handled, err := monitorCommand(ctx, c, args); handled {
		return err
	}

	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	rest := []string{}
	if len(args) > 2 {
		rest = args[2:]
	}
	switch cmd + " " + sub {
	case "hosts list":
		return hostsList(ctx, c)
	case "hosts enroll-token":
		return hostsEnrollToken(ctx, c, cfg, rest)
	case "hosts pin":
		return hostsPin(ctx, c, rest)
	case "hosts unpin":
		return hostsUnpin(ctx, c, rest)
	case "hosts channel":
		return hostsChannel(ctx, c, rest)
	case "api-keys list":
		return apiKeysList(ctx, c)
	case "api-keys create":
		return apiKeysCreate(ctx, c, rest)
	case "api-keys revoke":
		return apiKeysRevoke(ctx, c, rest)
	case "hosts remove":
		return hostsRemove(ctx, c, rest)
	case "db set":
		return dbSet(ctx, c, rest)
	case "db remove":
		return dbRemove(ctx, c, rest)
	case "db protection":
		return dbProtection(ctx, c, rest)
	case "restore-point create":
		return restorePointCreate(ctx, c, rest)
	case "restore-point list":
		return restorePointList(ctx, c, rest)
	case "db list":
		return dbList(ctx, c)
	case "db show":
		return dbShow(ctx, c, rest)
	case "db adopt":
		return dbAdopt(ctx, c, rest)
	case "db plan":
		return dbPlan(ctx, c, rest)
	case "db apply":
		return dbApply(ctx, c, rest)
	case "db verify":
		return dbVerify(ctx, c, rest)
	case "backup run":
		return backupRun(ctx, c, rest)
	case "backup list":
		return backupList(ctx, c, rest)
	case "drill run":
		return drillRun(ctx, c, rest)
	case "drill list":
		return drillList(ctx, c, rest)
	case "task show":
		return taskShow(ctx, c, rest)
	}
	if cmd == "org" && sub == "" {
		return orgShow(ctx, c)
	}
	if cmd == "tasks" {
		return tasksList(ctx, c, args[1:])
	}
	if cmd == "audit" {
		return auditList(ctx, c, args[1:])
	}
	return fmt.Errorf("unknown command %q; run `rowsafe help`", strings.Join(args, " "))
}
