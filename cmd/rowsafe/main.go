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

Getting started
  rowsafe login [--no-browser] [--url URL]   log in with your browser (default URL https://api.rowsafe.sh)
  rowsafe login --key rsk_... [--url URL]    log in with an existing API key (CI, scripts)
  rowsafe logout [--keep-key]                forget the login and revoke the key "rowsafe login" created
  rowsafe whoami                             control plane, organization, plan and API key in use
  rowsafe hosts enroll-token [--ttl 1h]      the install command for a database server. The installer sets up
                                             everything there and asks before turning on backups
  rowsafe init [NAME]                        write .rowsafe.json here, so commands in this project use NAME
  rowsafe restart [NAME] [--yes]             restart PostgreSQL, e.g. when setup needs it; asks first. Only on
                                             servers where the installer allowed it
  rowsafe version                            the CLI's version

Manual setup, from your workstation (the installer does this for you)
  rowsafe adopt NAME [--host HOST] [--port 5432] [--socket-dir DIR] [--retention-full 2]
                                             register an existing PostgreSQL; prints a read-only plan.
                                             --host may be omitted when the organization has one host
  rowsafe plan [NAME]                        re-run the read-only plan
  rowsafe apply [NAME] [--force] [--yes]     apply the plan (never restarts PostgreSQL)
  rowsafe verify [NAME]                      check now that WAL reaches your storage; backups start once it passes

Rewind: continuous backups, restore to any second
  rowsafe ls                                 databases
  rowsafe show [NAME]                        one database in detail
  rowsafe status [NAME] [--json]             with NAME: is it recoverable right now? without: every problem, with
                                             what to do. Exit 0 if protected / all healthy, 3 if not
  rowsafe backup [NAME] [--type full|diff|incr] [--no-wait]
                                             take a backup now
  rowsafe backups [NAME]                     backups
  rowsafe mark [NAME] [LABEL] [--no-wait] [--json]
                                             a named restore point (a Mark), e.g. before a migration.
                                             LABEL defaults to manual-<UTC time>. --json prints the Mark
                                             (status, restore_from_backup) for scripts and CI
  rowsafe marks [NAME]                       restore points
  rowsafe set [NAME] [--retention-full N] [--full-schedule CRON] [--diff-schedule CRON] [--proof-schedule CRON]
                                             change retention and schedules (5-field cron, UTC; --diff-schedule "" disables diffs)
  rowsafe remove NAME [--keep-archiving] [--yes]
                                             stop managing a database; never changes the server
  rowsafe rewind [NAME] [--json]             the recovery window, the copy and data kept aside by a rewind
  rowsafe rewind find [NAME] [--table T] [--since 24h | --from TIME [--to TIME]] [--kind delete,update,truncate,drop]
                                             when were rows deleted or changed, or a table emptied or dropped?
                                             Lists the biggest changes with exact times, to rewind to just before
  rowsafe rewind copy [NAME] (--at TIME | --mark LABEL) [--hours 24] [--no-wait]
                                             restore a copy as it was then, next to production (never
                                             touches it). TIME: "2026-09-24 14:04" or "14:04" (your time
                                             zone), "10m ago", or RFC 3339
  rowsafe rewind compare [NAME] [TABLE...] [--db DB] [--json]
                                             rows missing in production, changed, or added since, by
                                             primary key (no TABLE: every table)
  rowsafe rewind rows [NAME] TABLE... [--include-changed] [--db DB] [--yes]
                                             bring the missing rows back from the copy (a Mark first; asks
                                             you to type the name). TABLE is schema.table or DB:schema.table
  rowsafe rewind extend [NAME] [--hours 24]  keep the copy longer
  rowsafe rewind drop [NAME] [--yes]         delete the copy
  rowsafe rewind database [NAME] (--at TIME | --mark LABEL) [--yes]
                                             rewind the whole live database (stops PostgreSQL; the current
                                             data is kept aside for undo; asks you to type the name). Only on
                                             servers where the installer allowed restarting PostgreSQL
  rowsafe rewind undo [NAME] [--yes]         undo the rewind: put the data from before it back
  rowsafe rewind cleanup [NAME] [--yes]      delete the data kept aside by a rewind (frees disk)

Move in: bring a database from DigitalOcean, RDS, Supabase, Neon... onto your server
  rowsafe migrate [NAME] [--json]            migrations (into NAME, or all)
  rowsafe migrate start [NAME] [--into DB] [--method live|dump] [--source-env VAR] [--id ID] [--host ADDR] [--user NAME] [--yes]
                                             check the source and start copying into the server of NAME. The
                                             connection string is typed (not shown), piped, or read from $VAR,
                                             and sealed here to the server's key: Rowsafe never sees it
  rowsafe migrate status ID [--json]         progress: tables copied, how far behind, the check's findings
  rowsafe migrate fix ID [--yes]             mark source tables without a primary key REPLICA IDENTITY FULL
  rowsafe migrate switch ID [--writes-stopped] [--user NAME] [--host ADDR] [--yes]
                                             switch over: the old database goes read-only (unless you stopped
                                             writes yourself), the last changes arrive, then the new
                                             connection string is shown once
  rowsafe migrate password ID                a new password for the apps' login, shown once
  rowsafe migrate writable ID                make the old database writable again (rollback)
  rowsafe migrate cancel ID [--drop-copy] [--yes]
                                             stop and remove the sync from the old database
  rowsafe migrate finish ID [--yes]          forget the old database's connection string
  Advanced (restore by hand or to another server): https://rowsafe.sh/docs/guides/restore

Updates and upgrades: PostgreSQL kept current, with a Mark first
  rowsafe update [NAME] [--yes] [--no-wait]  install the newest minor release (e.g. 16.9 -> 16.10) and restart
                                             PostgreSQL; asks you to type the name. Only on servers where the
                                             installer allowed updates (--allow-updates)
  rowsafe update [NAME] --auto on|off [--timezone ZONE]
                                             install minor releases by itself, Sundays at 03:00 (your time zone)
  rowsafe upgrade [NAME] [--json]            versions, newer majors, the latest rehearsal, an upgrade to undo
  rowsafe upgrade [NAME] [--to 18] [--rehearse-only] [--mode safe|fast] [--yes]
                                             check, rehearse on a restored copy (production isn't touched),
                                             then upgrade. Safe keeps the old version for an instant undo;
                                             fast hard-links the data (undo restores from the backup)
  rowsafe upgrade undo [NAME] [--yes]        go back to the version the upgrade kept (7 days)
  rowsafe upgrade cleanup [NAME] [--yes]     remove the kept version (frees disk; no undo afterwards)
  (Security updates and reboots: rowsafe fix, on servers where the installer allowed them)

Proof: the weekly restore test
  rowsafe proof [NAME] [--no-wait]           restore the latest backup to a scratch copy and check it, now
  rowsafe proofs [NAME]                      restore test results

Pulse: health, monitoring and alerts
  rowsafe pulse [NAME] [--json]              health score (0-100) and findings in plain language; without NAME,
                                             every database. Exit 3 if one scores below 70
  rowsafe fix [NAME] [FINDING [FIX] | NUMBER] [--yes]
                                             what Rowsafe can fix from pulse (clean up tables, end a stuck
                                             session, remove an unused index...) and do it; asks first
  rowsafe insights [NAME] [--limit 10] [--json]
                                             largest tables, unused and duplicate indexes, estimated bloat,
                                             dead rows and vacuum, transaction ID age
  rowsafe top [NAME] [--since 24h] [--sort total_time|calls|mean_time|rows] [--query ID] [--json]
                                             statements that took the most time in a range, and which got slower
  rowsafe recommendations [NAME] [--group schema|queries|capacity|indexes] [--dismissed] [--json]
                                             what would make it better (missing indexes, ids running out,
                                             N+1 queries, memory...), why and what it costs; without NAME,
                                             each database's top one. Apply the ones Rowsafe can do with rowsafe fix
  rowsafe recommendations [NAME] --dismiss ID [--reason not_relevant|intended|later|wrong] [--note TEXT]
  rowsafe recommendations [NAME] --restore ID
                                             set a recommendation aside, or bring it back
  rowsafe activity [NAME]                    queries running, or idle in a transaction, for over a minute
  rowsafe alerts [--all | --resolved]        firing alerts (with --all, resolved ones too)
  rowsafe alerts ack ID                      acknowledge a firing alert: no more reminders
  rowsafe alerts rules                       built-in alert rules with this org's settings
  rowsafe channels list
  rowsafe channels add --type email --name NAME --address A [--address B] [--min-severity warning]
  rowsafe channels add --type slack|discord|webhook --name NAME --url URL [--min-severity warning]
                                             where alerts are sent (webhooks print a signing secret once)
  rowsafe channels remove ID
  rowsafe channels test ID                   send a test notification now
  rowsafe report [--preview [--html]] [--on | --off] [--to A,B] [--send-test]
                                             "Your weekly Pulse", the weekly email: settings, preview, test

Guard: the safety net for AI agents
  rowsafe mcp [--allow-restore-points | --allow-writes]
                                             MCP server on stdio for AI assistants (https://rowsafe.sh/docs/reference/mcp); read-only
                                             unless restore points or all write tools are allowed
  rowsafe guard                              Claude Code PreToolUse hook: before a destructive database
                                             command, create a restore point (https://rowsafe.sh/docs/guides/ai-agents)
  rowsafe guard --check COMMAND              tell whether COMMAND looks destructive (exit 0 yes, 1 no)
  (rowsafe status NAME, above, exits 3 when a database is not protected: use it to gate risky changes)

Admin
  rowsafe tasks [NAME] [--status S] [--type T] [--limit N]
                                             recent tasks for a database, or for all of them
  rowsafe task ID                            one task with its full log
  rowsafe hosts list                         hosts with agent version and update state
  rowsafe hosts pin HOST VERSION             keep a host's agent on VERSION (ignores rollout and halts)
  rowsafe hosts unpin HOST                   follow the host's update channel again
  rowsafe hosts channel HOST NAME            switch the host's update channel (e.g. stable, beta)
  rowsafe hosts remove HOST [--yes]          remove a host without databases and revoke its agent
  rowsafe org                                plan, limits and usage
  rowsafe api-keys list
  rowsafe api-keys create NAME [--read-only] the key is shown once; read-only keys can only read
  rowsafe api-keys revoke ID
  rowsafe audit [--limit N]                  who changed what, newest first

Backups, proof and mark wait for the task to finish; pass --no-wait to return at once.

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
	cmd, rest := args[0], args[1:]
	// Commands that work without a saved login.
	switch cmd {
	case "version":
		fmt.Println(version)
		return nil
	case "login":
		return login(ctx, rest)
	case "logout":
		return logout(ctx, rest)
	case "whoami":
		return whoami(ctx)
	case "guard":
		return guard(ctx, rest)
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	c := client.New(cfg.URL, cfg.APIKey)
	switch cmd {
	// Getting started and manual setup
	case "init":
		return initCmd(ctx, c, rest)
	case "restart":
		return restartCmd(ctx, c, rest)
	case "adopt":
		return adoptCmd(ctx, c, rest)
	case "plan":
		return planCmd(ctx, c, rest)
	case "apply":
		return applyCmd(ctx, c, rest)
	case "verify":
		return verifyCmd(ctx, c, rest)
	// Rewind
	case "ls":
		return listCmd(ctx, c, rest)
	case "show":
		return showCmd(ctx, c, rest)
	case "status":
		return statusCmd(ctx, c, rest)
	case "backup":
		return backupCmd(ctx, c, rest)
	case "backups":
		return backupsCmd(ctx, c, rest)
	case "mark":
		return markCmd(ctx, c, rest)
	case "marks":
		return marksCmd(ctx, c, rest)
	case "set":
		return setCmd(ctx, c, rest)
	case "remove":
		return removeCmd(ctx, c, rest)
	case "rewind":
		return rewindCmd(ctx, c, rest)
	case "migrate": // move in from a managed database (migrate.go)
		return migrateCmd(ctx, c, rest)
	// Updates and upgrades (upgrade.go)
	case "update":
		return updateCmd(ctx, c, rest)
	case "upgrade":
		return upgradeCmd(ctx, c, rest)
	// Proof
	case "proof":
		return proofCmd(ctx, c, rest)
	case "proofs":
		return proofsCmd(ctx, c, rest)
	// Pulse
	case "pulse":
		return pulseCmd(ctx, c, rest)
	case "fix":
		return fixCmd(ctx, c, rest)
	case "insights":
		return insightsCmd(ctx, c, rest)
	case "top":
		return topCmd(ctx, c, rest)
	case "recommendations": // advisor (recommendations.go)
		return recommendationsCmd(ctx, c, rest)
	case "activity":
		return activityCmd(ctx, c, rest)
	case "report":
		return reportCmd(ctx, c, rest)
	case "alerts":
		return alertsCmd(ctx, c, rest)
	case "channels":
		return group(ctx, c, "channels", rest, map[string]subcommand{
			"list": channelsList, "add": channelsAdd, "remove": channelsRemove, "test": channelsTest,
		})
	// Guard
	case "mcp":
		return mcpServe(ctx, c, rest)
	// Admin
	case "tasks":
		return tasksList(ctx, c, rest)
	case "task":
		return taskShow(ctx, c, rest)
	case "hosts":
		return group(ctx, c, "hosts", rest, map[string]subcommand{
			"list": hostsList, "pin": hostsPin, "unpin": hostsUnpin, "channel": hostsChannel, "remove": hostsRemove,
			"enroll-token": func(ctx context.Context, c *client.Client, args []string) error {
				return hostsEnrollToken(ctx, c, cfg, args)
			},
		})
	case "api-keys":
		return group(ctx, c, "api-keys", rest, map[string]subcommand{
			"list": apiKeysList, "create": apiKeysCreate, "revoke": apiKeysRevoke,
		})
	case "org":
		return orgShow(ctx, c, rest)
	case "audit":
		return auditList(ctx, c, rest)
	}
	return fmt.Errorf("unknown command %q; run `rowsafe help`", cmd)
}

// subcommand runs one command of a group such as rowsafe hosts.
type subcommand func(ctx context.Context, c *client.Client, args []string) error

// group runs "rowsafe NAME SUB ...", or lists the group's commands.
func group(ctx context.Context, c *client.Client, name string, args []string, subs map[string]subcommand) error {
	if len(args) > 0 {
		if run, ok := subs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
		return fmt.Errorf("unknown command %q. The %s commands:\n%s", name+" "+args[0], name, strings.TrimSpace(helpFor([]string{name})))
	}
	return fmt.Errorf("which one? The %s commands:\n%s", name, strings.TrimSpace(helpFor([]string{name})))
}
