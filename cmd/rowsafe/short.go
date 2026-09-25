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

const shortHelp = `rowsafe - backups you can restore to any second, tested every week

Getting started
  rowsafe login                      log in with your browser
  rowsafe hosts enroll-token         the install command for a database server; the installer
                                     sets up backups there and asks before changing anything
  rowsafe restart [NAME]             restart PostgreSQL when setup needs it (asks first)
  rowsafe init NAME                  make NAME this project's database (.rowsafe.json)
  rowsafe adopt | plan | apply | verify NAME
                                     set up by hand from your workstation instead

Rewind: continuous backups, restore to any second
  rowsafe ls                         databases
  rowsafe show [NAME]                one database in detail
  rowsafe backup [NAME]              back up now          rowsafe backups [NAME]   list them
  rowsafe mark [NAME] [LABEL]        a named restore point, e.g. before a migration
  rowsafe marks [NAME]               restore points
  rowsafe rewind [NAME]              restore a copy at any second, compare it, bring rows back,
                                     or rewind the whole database (rowsafe help rewind)

Proof: the weekly restore test
  rowsafe proof [NAME]               run the restore test now
  rowsafe proofs [NAME]              results

Pulse: health and monitoring
  rowsafe pulse [NAME]               health score (0-100) and what to fix
  rowsafe fix [NAME]                 let Rowsafe fix what pulse found (asks first)
  rowsafe insights [NAME]            largest tables, unused indexes, bloat, vacuum
  rowsafe top [NAME]                 queries that take the most time, and which got slower
  rowsafe alerts                     firing alerts (rowsafe channels: where they go)
  rowsafe report                     "Your weekly Pulse", the weekly email

Guard: the safety net for AI agents
  rowsafe status [NAME]              is it recoverable right now? (exit 0 yes, 3 no)
  rowsafe mcp                        MCP server for AI assistants
  rowsafe guard                      Claude Code hook: a restore point before destructive commands

Admin
  rowsafe tasks [NAME] | task ID     recent tasks; one task with its log
  rowsafe set | remove | activity NAME
                                     retention and schedules; stop managing; long-running queries
  rowsafe hosts | api-keys | org | audit | whoami | logout

NAME can be left out in a project with .rowsafe.json, with ROWSAFE_DATABASE
set, or when the organization has one database ("rowsafe help names").

"rowsafe help COMMAND" shows a command's details; "rowsafe help all" lists everything.
`

// helpDetails adds explanations that don't fit the one-line reference.
var helpDetails = map[string]string{
	"names": nameRules,
	"rewind": `Deleted rows by mistake? Restore a copy as it was just before (it runs next to
production on your server, on a private socket, and never touches production),
compare it with production, and bring the missing rows back:
  rowsafe rewind copy --at "14:04"
  rowsafe rewind compare
  rowsafe rewind rows public.orders public.order_items
Rows come back by primary key, parents before children, in one transaction;
triggers don't fire for them, and nothing else in production changes. The
copy is deleted by itself after 24 hours (rowsafe rewind extend keeps it).
When the whole database has to go back, rowsafe rewind database stops
PostgreSQL, restores it to that point and starts it again; the current data
is kept aside so rowsafe rewind undo can put it back. Your data never leaves
your server: Rowsafe only sees table names and counts.`,
	"pulse": `The score starts at 100 and loses points for each problem found: backups,
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
hours, the latest restore test (Proof) passed within 8 days). Without NAME:
every problem across hosts and databases, each with the command to run next.
Exit status: 0 protected (or all healthy), 3 not, 1 on errors.`,
	"login": `Opens a browser page where you confirm the code shown in the terminal; the
new API key is saved to your config directory (mode 0600). Over SSH, or with
--no-browser, open the printed link on any device. --key logs in with an
existing key instead. The control plane is --url, else ROWSAFE_URL, else the
saved login, else https://api.rowsafe.sh.`,
	"init": `Writes {"database": NAME} to .rowsafe.json in the current directory (keeping
other settings in an existing file). Commands run in this directory or below
then use NAME when it is left out; so does the Claude Code guard hook.`,
	"restart": `Rowsafe never restarts PostgreSQL on its own. It restarts it only when you ask
(this command, Restart PostgreSQL in the dashboard, or the installer), and
only on servers where the installer was allowed to (root decides at install
time). If this server doesn't allow it, the task fails and says how to
restart by hand. A database waiting for a restart to start its backups
finishes setting up by itself once PostgreSQL is back.`,
	"fix": `Without FINDING, lists the findings of "rowsafe pulse" that Rowsafe can fix
by itself, numbered, and (in a terminal) asks which one to apply. Fixes are
proposed by Rowsafe and checked again right before they run: cleaning up
tables (VACUUM), refreshing statistics (ANALYZE), rebuilding a bloated index
or removing an unused one without blocking writes, cancelling a query or
ending a session that blocks others, removing an inactive replication slot,
backups, restore tests and checks. Fixes that end a session or remove
something ask you to type the database name (--yes skips the questions);
removing an index saves a Mark first so it can be undone. The same fixes
are the "Apply fix" buttons in the dashboard (Pulse, Health).`,
	"proof": `Proof restores the latest backup plus WAL into a scratch copy on the same
server (its own socket, no network, low priority), checks that every
database and table is there, and deletes the copy. It runs every week on
its own (rowsafe set --proof-schedule changes when); this runs it now.`,
}

func markCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("mark", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "return once queued")
	asJSON := fs.Bool("json", false, "print the Mark as JSON (progress goes to stderr)")
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
	if *asJSON {
		return createRestorePointJSON(ctx, c, db, label, *noWait)
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
	lines := referenceLines(topic)
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

// createRestorePoint is rowsafe mark.
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

// protectionStatus is rowsafe status NAME.
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
	fmt.Printf("\nLast backup:          %s\n", ago(p.LastBackupAt))
	fmt.Printf("Last WAL archived:    %s\n", ago(p.WALLastArchivedAt))
	if p.RecoveryWindowStart != nil {
		fmt.Printf("Recoverable from:     %s\n", p.RecoveryWindowStart.Local().Format(time.RFC1123))
	}
	fmt.Printf("Restore test passed:  %s\n", ago(p.LastDrillPassedAt))
	for _, t := range p.OpenFailedTasks {
		fmt.Printf("Failing:              %s %s (%s): %s\n", t.Type, t.Status, t.ID, firstLine(t.Error, 80))
	}
}
