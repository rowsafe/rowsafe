package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/mcp"
	"github.com/rowsafe/rowsafe/protocol"
)

const shortHelp = `rowsafe - backups, point-in-time recovery and restore drills for your Postgres

Getting started
  rowsafe login                      log in with your browser
  rowsafe hosts enroll-token         install command for a database host
  rowsafe adopt NAME                 register a Postgres on that host (read-only plan)
  rowsafe apply NAME                 apply the plan (never restarts Postgres)
  rowsafe verify NAME                prove WAL reaches the repository; backups start
  rowsafe init NAME                  make NAME this project's database (.rowsafe.json)

Protect
  rowsafe status [NAME]              is it recoverable right now? (exit 0 yes, 3 no)
  rowsafe ls                         databases
  rowsafe show [NAME]                one database in detail
  rowsafe backup [NAME]              back up now          rowsafe backups [NAME]   list them
  rowsafe drill [NAME]               restore drill now    rowsafe drills [NAME]    list them
  rowsafe mark [NAME] [LABEL]        restore point, e.g. before a migration
  rowsafe tasks [NAME]               recent tasks

Monitor
  rowsafe health [NAME]              health score (0-100) and what to fix
  rowsafe insights [NAME]            largest tables, unused indexes, bloat, vacuum
  rowsafe top [NAME]                 queries that take the most time, and which got slower
  rowsafe report                     the weekly "Your databases this week" email

Recover
  rowsafe marks [NAME]               restore points to recover to
  rowsafe backups [NAME]             backups and the recovery window
  https://rowsafe.sh/docs/guides/restore
                                     the restore procedure (pgBackRest)

Admin
  rowsafe whoami | logout | org | audit
  rowsafe hosts list|enroll-token|pin|unpin|channel|remove
  rowsafe api-keys list|create|revoke
  rowsafe db set|remove NAME         retention, schedules; stop managing a database
  rowsafe alerts | channels | mcp | guard

NAME can be left out in a project with .rowsafe.json, with ROWSAFE_DATABASE
set, or when the organization has one database ("rowsafe help names").

"rowsafe help COMMAND" shows a command's details; "rowsafe help all" lists everything.
`

// helpDetails adds explanations that don't fit the one-line reference.
var helpDetails = map[string]string{
	"names": nameRules,
	"health": `The score starts at 100 and loses points for each problem found: backups,
restore tests and WAL archiving; whether PostgreSQL answers; disk space and
when it will run out; connections; vacuum, transaction ID wraparound and
wasted space; locks, slow-downs and index suggestions; replication. One
critical problem caps the score at 59, a warning at 89. 90-100 is healthy,
70-89 needs attention, 50-69 at risk, below 50 critical.`,
	"mark": `LABEL defaults to manual-<UTC time>. With a single argument, it is the
database if it names one of your databases, and otherwise the label for the
inferred database: in a project whose .rowsafe.json names "app",
"rowsafe mark before-drop" marks app as "before-drop", while
"rowsafe mark app" marks app with the default label.`,
	"status": `With NAME: a conservative check that the database is recoverable right now
(active, WAL archiving reporting and not failing, a backup in the last 26
hours, the latest drill passed within 8 days). Without NAME: every problem
across hosts and databases, each with the command to run next.
Exit status: 0 protected (or all healthy), 3 not, 1 on errors.`,
	"login": `Opens a browser page where you confirm the code shown in the terminal; the
new API key is saved to your config directory (mode 0600). Over SSH, or with
--no-browser, open the printed link on any device. --key logs in with an
existing key instead. The control plane is --url, else ROWSAFE_URL, else the
saved login, else https://api.rowsafe.sh.`,
	"init": `Writes {"database": NAME} to .rowsafe.json in the current directory (keeping
other settings in an existing file). Commands run in this directory or below
then use NAME when it is left out; so does the Claude Code guard hook.`,
}

// aliases maps short commands to their long forms.
var aliases = map[string][]string{
	"ls":      {"db", "list"},
	"show":    {"db", "show"},
	"adopt":   {"db", "adopt"},
	"plan":    {"db", "plan"},
	"apply":   {"db", "apply"},
	"verify":  {"db", "verify"},
	"backups": {"backup", "list"},
	"drills":  {"drill", "list"},
	"marks":   {"restore-point", "list"},
}

// expandAlias rewrites short forms to the long commands. "backup" and
// "drill" alone mean "run" unless followed by run or list.
func expandAlias(args []string) []string {
	if long, ok := aliases[args[0]]; ok {
		return append(append([]string{}, long...), args[1:]...)
	}
	if (args[0] == "backup" || args[0] == "drill") && (len(args) == 1 || (args[1] != "run" && args[1] != "list")) {
		return append([]string{args[0], "run"}, args[1:]...)
	}
	return args
}

// shortCommand runs the commands that exist only in short form.
func shortCommand(ctx context.Context, c *client.Client, args []string) (bool, error) {
	switch args[0] {
	case "mark":
		return true, markCmd(ctx, c, args[1:])
	case "status":
		return true, statusCmd(ctx, c, args[1:])
	case "init":
		return true, initCmd(ctx, c, args[1:])
	case "health":
		return true, healthCmd(ctx, c, args[1:])
	case "insights":
		return true, insightsCmd(ctx, c, args[1:])
	case "top":
		return true, topCmd(ctx, c, args[1:])
	case "report":
		return true, reportCmd(ctx, c, args[1:])
	}
	return false, nil
}

func markCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("mark", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "return once queued")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	db, label, err := markArgs(ctx, c, pos)
	if err != nil {
		return err
	}
	if label == "" {
		label = "manual-" + time.Now().UTC().Format("20060102-150405")
	}
	return createRestorePoint(ctx, c, db, label, *noWait)
}

func statusCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	switch len(pos) {
	case 0:
		return fleetStatus(ctx, c, *asJSON)
	case 1:
		return protectionStatus(ctx, c, pos[0], *asJSON)
	}
	return errors.New("expected at most one database name")
}

func fleetStatus(ctx context.Context, c *client.Client, asJSON bool) error {
	h, err := mcp.CheckFleet(ctx, c)
	if err != nil {
		return err
	}
	if asJSON {
		out, _ := json.MarshalIndent(h, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Println(h.Summary)
		for _, p := range h.Problems {
			where := p.Database
			if where == "" {
				where = p.Host
			}
			if where != "" {
				where += ": "
			}
			fmt.Printf("  [%s] %s%s\n", p.Severity, where, p.Summary)
			if p.Command != "" {
				fmt.Printf("      next: %s\n", p.Command)
			} else if p.NextAction != "" {
				fmt.Printf("      next: %s\n", firstLine(p.NextAction, 160))
			}
		}
	}
	if !h.Healthy {
		return exitError(3)
	}
	return nil
}

func initCmd(ctx context.Context, c *client.Client, args []string) error {
	pos, err := positionals(flag.NewFlagSet("init", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("expected at most one database name")
	}
	name := ""
	if len(pos) == 1 {
		name = pos[0]
	} else {
		// Don't let an existing .rowsafe.json or ROWSAFE_DATABASE answer the
		// question init is asking.
		dbs, err := c.Databases(ctx)
		if err != nil {
			return err
		}
		if len(dbs) != 1 {
			if len(dbs) == 0 {
				return errors.New("no databases yet: register one with `rowsafe adopt NAME`")
			}
			return fmt.Errorf("which database? This organization has %s; run `rowsafe init NAME`", listNames(dbs))
		}
		name = dbs[0].Name
	}
	d, err := c.Database(ctx, name)
	if err != nil {
		return fmt.Errorf("database %q: %w", name, err)
	}
	p, err := writeProjectConfig(".", d.Name)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s: rowsafe commands in this directory now default to %s.\n", p, d.Name)
	return nil
}

// writeProjectConfig sets "database" in dir/.rowsafe.json, keeping any
// other settings (e.g. require_protection) already there.
func writeProjectConfig(dir, name string) (string, error) {
	p, err := filepath.Abs(filepath.Join(dir, ".rowsafe.json"))
	if err != nil {
		return "", err
	}
	fields := map[string]any{}
	if data, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(data, &fields); err != nil {
			return "", fmt.Errorf("%s is not valid JSON: %w", p, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	fields["database"] = name
	data, _ := json.MarshalIndent(fields, "", "  ")
	return p, os.WriteFile(p, append(data, '\n'), 0o644)
}

// helpFor prints help for "rowsafe help [TOPIC...]".
func helpFor(args []string) string {
	if len(args) == 0 {
		return shortHelp
	}
	topic := strings.Join(args, " ")
	if topic == "all" {
		return usage + "\n" + nameRules + "\n"
	}
	var lines []string
	if long, ok := aliases[args[0]]; ok {
		lines = append(lines, fmt.Sprintf("rowsafe %s is short for rowsafe %s.", args[0], strings.Join(long, " ")))
	}
	lines = append(lines, referenceLines(topic)...)
	if long, ok := aliases[args[0]]; ok && len(args) == 1 {
		lines = append(lines, referenceLines(strings.Join(long, " "))...)
	}
	if d, ok := helpDetails[topic]; ok {
		lines = append(lines, "", d)
	}
	if len(lines) == 0 {
		return fmt.Sprintf("No help for %q. Run `rowsafe help all` for every command.\n", topic)
	}
	return strings.Join(lines, "\n") + "\n"
}

// referenceLines returns the reference entries for a command, with their
// continuation lines.
func referenceLines(topic string) []string {
	var out []string
	in := false
	for _, line := range strings.Split(usage, "\n") {
		switch {
		case strings.HasPrefix(line, "  rowsafe "+topic+" ") || line == "  rowsafe "+topic:
			in = true
			out = append(out, strings.TrimPrefix(line, "  "))
		case in && strings.HasPrefix(line, "        "):
			out = append(out, strings.TrimPrefix(line, "  "))
		default:
			in = false
		}
	}
	return out
}

// createRestorePoint is rowsafe mark and restore-point create.
func createRestorePoint(ctx context.Context, c *client.Client, db, label string, noWait bool) error {
	t, err := c.CreateRestorePoint(ctx, db, label)
	if err != nil {
		return err
	}
	if noWait {
		fmt.Printf("Queued restore point %q on %s (task %s).\n", label, db, t.ID)
		return nil
	}
	return waitAndReport(ctx, c, t.ID, db)
}

// protectionStatus is rowsafe status NAME and db protection.
func protectionStatus(ctx context.Context, c *client.Client, name string, asJSON bool) error {
	p, err := c.Protection(ctx, name)
	if err != nil {
		return err
	}
	if asJSON {
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))
	} else {
		printProtection(name, p)
	}
	if !p.Protected {
		return exitError(3)
	}
	return nil
}

func printProtection(name string, p protocol.Protection) {
	if p.Protected {
		fmt.Printf("%s is PROTECTED.\n", name)
	} else {
		fmt.Printf("%s is NOT PROTECTED:\n", name)
		for _, r := range p.Reasons {
			fmt.Printf("  - %s\n", r)
		}
	}
	fmt.Printf("\nLast backup:        %s\n", ago(p.LastBackupAt))
	fmt.Printf("Last WAL archived:  %s\n", ago(p.WALLastArchivedAt))
	if p.RecoveryWindowStart != nil {
		fmt.Printf("Recoverable from:   %s\n", p.RecoveryWindowStart.Local().Format(time.RFC1123))
	}
	fmt.Printf("Last passing drill: %s\n", ago(p.LastDrillPassedAt))
	for _, t := range p.OpenFailedTasks {
		fmt.Printf("Failing:            %s %s (%s): %s\n", t.Type, t.Status, t.ID, firstLine(t.Error, 80))
	}
}
