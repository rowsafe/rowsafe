package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// parse handles "NAME --flags" and "--flags NAME" orders.
func parse(fs *flag.FlagSet, args []string, wantName bool) (string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return "", err
		}
		args = fs.Args()
		if len(args) > 0 {
			positional = append(positional, args[0])
			args = args[1:]
		}
	}
	if !wantName {
		if len(positional) > 0 {
			return "", fmt.Errorf("unexpected argument %q", positional[0])
		}
		return "", nil
	}
	if len(positional) != 1 {
		return "", errors.New("expected exactly one database name")
	}
	return positional[0], nil
}

func hostsList(ctx context.Context, c *client.Client, args []string) error {
	if _, err := parse(flag.NewFlagSet("hosts list", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	hosts, err := c.Hosts(ctx)
	if err != nil {
		return err
	}
	t := newTable("HOST", "ID", "AGENT", "PLATFORM", "CHANNEL", "PIN", "LAST UPDATE", "LAST SEEN")
	for _, h := range hosts {
		t.row(h.Hostname, h.ID, orDash(h.AgentVersion), orDash(h.Platform), h.UpdateChannel, orDash(h.PinnedVersion),
			updateText(h.LastUpdate), ago(h.LastSeenAt))
	}
	t.flush()
	return nil
}

// parseN is parse for commands with a fixed number of positional arguments.
func parseN(fs *flag.FlagSet, args []string, names ...string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) > 0 {
			positional = append(positional, args[0])
			args = args[1:]
		}
	}
	if len(positional) != len(names) {
		return nil, fmt.Errorf("expected %s", strings.Join(names, " "))
	}
	return positional, nil
}

func printHostPolicy(h protocol.Host) {
	pin := "none (follows its channel)"
	if h.PinnedVersion != "" {
		pin = h.PinnedVersion
	}
	fmt.Printf("%s: agent %s, channel %s, pinned to %s\n", h.Hostname, orDash(h.AgentVersion), h.UpdateChannel, pin)
}

func hostsPin(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("hosts pin", flag.ContinueOnError), args, "HOST", "VERSION")
	if err != nil {
		return err
	}
	h, err := c.UpdateHost(ctx, pos[0], protocol.UpdateHostRequest{PinnedVersion: &pos[1]})
	if err != nil {
		return err
	}
	printHostPolicy(h)
	return nil
}

func hostsUnpin(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("hosts unpin", flag.ContinueOnError), args, "HOST")
	if err != nil {
		return err
	}
	none := ""
	h, err := c.UpdateHost(ctx, pos[0], protocol.UpdateHostRequest{PinnedVersion: &none})
	if err != nil {
		return err
	}
	printHostPolicy(h)
	return nil
}

func hostsChannel(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("hosts channel", flag.ContinueOnError), args, "HOST", "NAME")
	if err != nil {
		return err
	}
	h, err := c.UpdateHost(ctx, pos[0], protocol.UpdateHostRequest{UpdateChannel: &pos[1]})
	if err != nil {
		return err
	}
	printHostPolicy(h)
	return nil
}

func orgShow(ctx context.Context, c *client.Client, args []string) error {
	if _, err := parse(flag.NewFlagSet("org", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	o, err := c.Org(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Organization: %s (%s)\n", o.Name, o.ID)
	fmt.Printf("Plan:         %s", o.Plan)
	if o.PlanPeriodEnd != nil {
		fmt.Printf(" (current period ends %s)", o.PlanPeriodEnd.Local().Format("2006-01-02"))
	}
	fmt.Println()
	fmt.Printf("Hosts:        %d of %d\n", o.Usage.Hosts, o.Limits.MaxHosts)
	fmt.Printf("Databases:    %d of %d\n", o.Usage.Databases, o.Limits.MaxDatabases)
	return nil
}

func apiKeysList(ctx context.Context, c *client.Client, args []string) error {
	if _, err := parse(flag.NewFlagSet("api-keys list", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	keys, err := c.APIKeys(ctx)
	if err != nil {
		return err
	}
	t := newTable("ID", "NAME", "ACCESS", "CREATED", "LAST USED")
	for _, k := range keys {
		access := "read-write"
		if k.ReadOnly {
			access = "read-only"
		}
		t.row(k.ID, k.Name, access, k.CreatedAt.Local().Format("2006-01-02 15:04"), ago(k.LastUsedAt))
	}
	t.flush()
	return nil
}

func apiKeysCreate(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("api-keys create", flag.ContinueOnError)
	readOnly := fs.Bool("read-only", false, "the key can only read (GET requests)")
	pos, err := parseN(fs, args, "NAME")
	if err != nil {
		return err
	}
	k, err := c.CreateAPIKey(ctx, pos[0], *readOnly)
	if err != nil {
		return err
	}
	fmt.Printf("API key %q (%s):\n  %s\n\nThe key is shown once; store it now.\n", k.Name, k.ID, k.Key)
	return nil
}

func apiKeysRevoke(ctx context.Context, c *client.Client, args []string) error {
	pos, err := parseN(flag.NewFlagSet("api-keys revoke", flag.ContinueOnError), args, "ID")
	if err != nil {
		return err
	}
	if err := c.RevokeAPIKey(ctx, pos[0]); err != nil {
		return err
	}
	fmt.Println("Revoked", pos[0])
	return nil
}

func hostsEnrollToken(ctx context.Context, c *client.Client, cfg config, args []string) error {
	fs := flag.NewFlagSet("enroll-token", flag.ContinueOnError)
	ttl := fs.Duration("ttl", time.Hour, "how long the token stays valid")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	tok, err := c.CreateEnrollmentToken(ctx, *ttl)
	if err != nil {
		return err
	}
	fmt.Printf("Enrollment token (single use, expires %s):\n  %s\n\n", tok.ExpiresAt.Local().Format(time.RFC1123), tok.Token)
	fmt.Printf("On the database server:\n  %s\n\n", installCommand(cfg.URL, tok.Token))
	fmt.Println("It installs the agent, sets up storage, finds PostgreSQL and shows the plan, then asks before turning")
	fmt.Println("on backups (and before restarting PostgreSQL, if that is needed). Nothing else to run here.")
	return nil
}

// installCommand is the one-liner that installs and enrolls an agent. It
// runs from a normal sudo-capable login (e.g. debian), not a root shell.
// ROWSAFE_URL is only needed for a control plane other than the default.
func installCommand(url, token string) string {
	env := ""
	if u := strings.TrimRight(url, "/"); u != "" && u != protocol.DefaultAPIURL {
		env = "ROWSAFE_URL=" + u + " "
	}
	return "curl -fsSL https://rowsafe.sh | sudo " + env + "sh -s " + token
}

func listCmd(ctx context.Context, c *client.Client, args []string) error {
	if _, err := parse(flag.NewFlagSet("ls", flag.ContinueOnError), args, false); err != nil {
		return err
	}
	dbs, err := c.Databases(ctx)
	if err != nil {
		return err
	}
	t := newTable("NAME", "HOST", "STATUS", "POSTGRES", "SIZE", "LAST WAL ARCHIVED")
	for _, d := range dbs {
		version, size := "-", "-"
		if d.Inspect != nil {
			version, size = d.Inspect.ServerVersion, humanBytes(d.Inspect.TotalSizeBytes)
		}
		wal := "-"
		if d.Archiver != nil {
			wal = ago(d.Archiver.LastArchivedTime)
		}
		t.row(d.Name, d.Hostname, d.Status, version, size, wal)
	}
	t.flush()
	return nil
}

func showCmd(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("show", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	d, err := c.Database(ctx, name)
	if err != nil {
		return err
	}
	fmt.Printf("Name:       %s (%s)\n", d.Name, d.ID)
	fmt.Printf("Host:       %s\n", d.Hostname)
	fmt.Printf("Status:     %s\n", statusText(d.Status))
	fmt.Printf("Socket:     %s port %d\n", d.SocketDir, d.Port)
	fmt.Printf("Retention:  %d full backups\n", d.RetentionFull)
	fmt.Printf("Schedules:  full %q, diff %q, restore test %q (UTC)\n", d.ScheduleFull, d.ScheduleDiff, d.ScheduleDrill)
	if in := d.Inspect; in != nil {
		fmt.Printf("Postgres:   %s, %s, data directory %s\n", in.ServerVersion, humanBytes(in.TotalSizeBytes), in.DataDirectory)
		fmt.Printf("Archiving:  archive_mode=%s archive_timeout=%ds\n", in.ArchiveMode, in.ArchiveTimeoutSeconds)
		if len(in.PendingRestart) > 0 {
			fmt.Printf("Pending:    restart needed for %s\n", strings.Join(in.PendingRestart, ", "))
		}
	}
	if a := d.Archiver; a != nil {
		fmt.Printf("WAL:        last archived %s, %d archived, %d failed", ago(a.LastArchivedTime), a.ArchivedCount, a.FailedCount)
		if a.LastFailedTime != nil {
			fmt.Printf(" (last failure %s)", ago(a.LastFailedTime))
		}
		fmt.Println()
		if a.Error != "" {
			fmt.Printf("            the agent can't read archiver stats right now: %s\n", firstLine(a.Error, 100))
		}
	}
	if d.CanRestart {
		fmt.Println("Restart:    allowed from Rowsafe (rowsafe restart)")
	} else {
		if d.Archiver != nil && d.Archiver.Mode == "docker-sidecar" {
			fmt.Println("Restart:    not allowed from Rowsafe (Docker: add the container control service)")
		} else {
			fmt.Println("Restart:    not allowed from Rowsafe on this server (allowed at install time)")
		}
	}
	backups, err := c.Backups(ctx, name, 1)
	if err == nil && len(backups) > 0 {
		b := backups[0]
		fmt.Printf("Backup:     %s %s, %s ago\n", b.Type, b.Label, time.Since(b.StoppedAt).Round(time.Minute))
	}
	drills, err := c.Drills(ctx, name, 1)
	if err == nil && len(drills) > 0 {
		dr := drills[0]
		fmt.Printf("Proof:      restore test %s, %s ago\n", passFail(dr.Passed), time.Since(dr.CreatedAt).Round(time.Minute))
	}
	return nil
}

func adoptCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	host := fs.String("host", "", "host ID or hostname (see `rowsafe hosts list`); optional with a single host")
	port := fs.Int("port", 5432, "Postgres port")
	socketDir := fs.String("socket-dir", "/var/run/postgresql", "Unix socket directory")
	retention := fs.Int("retention-full", 2, "full backups to keep (weekly fulls: 2 = about 2 weeks of PITR)")
	noWait := fs.Bool("no-wait", false, "don't wait for the plan")
	engine := fs.String("engine", "", "database engine: postgresql (default), or another engine Rowsafe supports")
	name, err := parse(fs, args, true)
	if err != nil {
		return err
	}
	if *host, err = resolveHost(ctx, c, *host); err != nil {
		return err
	}
	resp, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{
		HostID: *host, Name: name, Port: *port, SocketDir: *socketDir, RetentionFull: *retention, Engine: *engine,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Registered %s (%s). Planning...\n\n", resp.Database.Name, resp.Database.ID)
	if *noWait {
		fmt.Printf("Task %s queued. Check it with `rowsafe task %s`.\n", resp.Task.ID, resp.Task.ID)
		return nil
	}
	return waitAndReport(ctx, c, resp.Task.ID, name)
}

func planCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, err := c.CreateTask(ctx, name, protocol.TaskAdopt, protocol.AdoptParams{Apply: false})
	if err != nil {
		return err
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func applyCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	force := fs.Bool("force", false, "replace an existing archive_command or archive_library")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	d, err := c.Database(ctx, name)
	if err != nil {
		return err
	}
	if !*yes {
		fmt.Printf("This changes PostgreSQL settings on %s (%s) with ALTER SYSTEM and reloads it.\n", d.Hostname, d.Name)
		fmt.Println("It never restarts PostgreSQL. Review the plan first with `rowsafe plan`.")
		if !confirm("Apply?") {
			return errors.New("cancelled")
		}
	}
	t, err := c.CreateTask(ctx, name, protocol.TaskAdopt, protocol.AdoptParams{Apply: true, Force: *force})
	if err != nil {
		return err
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func verifyCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, err := c.CreateTask(ctx, name, protocol.TaskCheck, nil)
	var ae *client.APIError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict {
		// Usually Rowsafe's own check after a restart: wait for that one.
		open, lerr := c.AllTasks(ctx, client.TaskQuery{Database: name, Type: protocol.TaskCheck, Limit: 10})
		if lerr == nil {
			for _, o := range open {
				if o.Status == protocol.StatusQueued || o.Status == protocol.StatusRunning {
					fmt.Fprintf(os.Stderr, "Rowsafe is already checking %s (task %s); waiting for it.\n", name, o.ID)
					return waitAndReport(ctx, c, o.ID, name)
				}
			}
		}
	}
	if err != nil {
		return err
	}
	return waitAndReport(ctx, c, t.ID, name)
}

// restartCmd is rowsafe restart: restart a database's PostgreSQL when a
// person asks. The agent does it only on servers where root allowed it at
// install time; Rowsafe never restarts PostgreSQL on its own.
func restartCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("restart", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	d, err := c.Database(ctx, name)
	if err != nil {
		return err
	}
	if !d.CanRestart {
		return errors.New(restartNotAllowed(d))
	}
	fmt.Printf("Database %s on %s (%s)\n", d.Name, d.Hostname, statusText(d.Status))
	fmt.Println("PostgreSQL restarts: it takes a few seconds; open connections are dropped and apps reconnect.")
	if !*yes && !confirm("Restart PostgreSQL on "+d.Hostname+" now?") {
		return errors.New("cancelled; nothing was restarted")
	}
	t, err := c.CreateTask(ctx, d.Name, protocol.TaskRestart, map[string]string{"confirm": d.Name})
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusForbidden:
			return errors.New(restartNotAllowed(d))
		case http.StatusConflict:
			return fmt.Errorf("not restarted: the agent on %s is offline, or a restart is already running (%s)", d.Hostname, ae.Msg)
		case http.StatusTooManyRequests:
			wait := "a moment"
			if ae.RetryAfter > 0 {
				wait = fmt.Sprintf("%d seconds", int(ae.RetryAfter.Seconds()))
			}
			return fmt.Errorf("not restarted: PostgreSQL on %s was restarted in the last 2 minutes; try again in %s", d.Hostname, wait)
		}
	}
	if err != nil {
		return err
	}
	if err := waitAndReport(ctx, c, t.ID, d.Name); err != nil {
		return err
	}
	if d.Status == protocol.DBAwaitingRestart {
		fmt.Printf("\nRowsafe now checks the backups by itself and starts them; follow it with `rowsafe status %s`.\n", d.Name)
	}
	return nil
}

// restartNotAllowed explains why Rowsafe can't restart d's PostgreSQL.
func restartNotAllowed(d protocol.Database) string {
	if d.Archiver != nil && d.Archiver.Mode == "docker-sidecar" {
		return fmt.Sprintf("not restarted: Rowsafe can't restart PostgreSQL's container on %s yet.\n"+
			"Either restart it yourself: docker compose restart postgres (your PostgreSQL service's name)\n"+
			"or allow it: add the container control service to your compose file; the database's Settings in the dashboard show the lines "+
			"(https://rowsafe.sh/docs/guides/docker#let-rowsafe-restart-the-container).", d.Hostname)
	}
	return fmt.Sprintf("not restarted: %s doesn't allow restarts from Rowsafe (only root can allow it, at install time).\n"+
		"Either restart PostgreSQL yourself, on %s:\n  sudo systemctl restart postgresql\n"+
		"or allow it: re-run the install command on %s and say yes to restarts (--allow-restart).", d.Hostname, d.Hostname, d.Hostname)
}

func backupCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	typ := fs.String("type", "full", "full, diff or incr")
	noWait := fs.Bool("no-wait", false, "return once queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, err := c.CreateTask(ctx, name, protocol.TaskBackup, protocol.BackupParams{Type: *typ})
	if err != nil {
		return err
	}
	if *noWait {
		fmt.Println("Queued", t.ID)
		return nil
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func backupsCmd(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("backups", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	backups, err := c.Backups(ctx, name, 50)
	if err != nil {
		return err
	}
	t := newTable("LABEL", "TYPE", "FINISHED", "DURATION", "DB SIZE", "STORED")
	for _, b := range backups {
		t.row(b.Label, b.Type, b.StoppedAt.Local().Format("2006-01-02 15:04"),
			b.StoppedAt.Sub(b.StartedAt).Round(time.Second).String(), humanBytes(b.SizeBytes), humanBytes(b.RepoSizeBytes))
	}
	t.flush()
	return nil
}

func proofCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("proof", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "return once queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, err := c.CreateTask(ctx, name, protocol.TaskDrill, nil)
	if err != nil {
		return err
	}
	if *noWait {
		fmt.Printf("Queued the restore test of %s (task %s). See the result with `rowsafe proofs %s`.\n", name, t.ID, name)
		return nil
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func proofsCmd(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("proofs", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	drills, err := c.Drills(ctx, name, 20)
	if err != nil {
		return err
	}
	if len(drills) == 0 {
		fmt.Printf("No restore tests of %s yet. Run one now: rowsafe proof %s\n", name, name)
		return nil
	}
	t := newTable("WHEN", "RESULT", "BACKUP", "RECOVERED TO", "DURATION", "DATABASES")
	for _, d := range drills {
		recovered := "-"
		if d.Result.RecoveredTo != nil {
			recovered = d.Result.RecoveredTo.Local().Format("2006-01-02 15:04:05")
		}
		t.row(d.CreatedAt.Local().Format("2006-01-02 15:04"), passFail(d.Passed), d.Result.BackupLabel, recovered,
			(time.Duration(d.Result.DurationSeconds) * time.Second).String(), fmt.Sprint(len(d.Result.Databases)))
	}
	t.flush()
	return nil
}

func tasksList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("tasks", flag.ContinueOnError)
	status := fs.String("status", "", "only tasks in this status (queued, running, succeeded, failed, lost, cancelled)")
	typ := fs.String("type", "", "only tasks of this type (inspect, adopt, check, backup, drill (the restore test), restore_point, restart)")
	limit := fs.Int("limit", 30, "how many tasks to show")
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if args = fs.Args(); len(args) > 0 {
			positional, args = append(positional, args[0]), args[1:]
		}
	}
	if len(positional) > 1 {
		return errors.New("expected at most one database name")
	}
	q := client.TaskQuery{Status: *status, Type: *typ, Limit: *limit}
	if len(positional) == 1 {
		q.Database = positional[0]
	}
	tasks, err := c.AllTasks(ctx, q)
	if err != nil {
		return err
	}
	t := newTable("ID", "DATABASE", "TYPE", "STATUS", "CREATED", "DURATION", "ERROR")
	for _, task := range tasks {
		dur := "-"
		if task.StartedAt != nil && task.FinishedAt != nil {
			dur = task.FinishedAt.Sub(*task.StartedAt).Round(time.Second).String()
		}
		kind := task.Type
		if task.Scheduled {
			kind += " (scheduled)"
		}
		t.row(task.ID, orDash(task.DatabaseName), kind, task.Status, task.CreatedAt.Local().Format("2006-01-02 15:04"), dur,
			firstLine(task.Error, 60))
	}
	t.flush()
	return nil
}

func auditList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	limit := fs.Int("limit", 50, "how many events to show")
	if _, err := parse(fs, args, false); err != nil {
		return err
	}
	events, err := c.AuditEvents(ctx, *limit)
	if err != nil {
		return err
	}
	t := newTable("WHEN", "ACTOR", "ACTION", "TARGET", "DETAIL")
	for _, e := range events {
		t.row(e.At.Local().Format("2006-01-02 15:04:05"), e.Actor, e.Action, orDash(e.Target), firstLine(string(e.Detail), 80))
	}
	t.flush()
	return nil
}

func setCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	retention := fs.Int("retention-full", 0, "full backups to keep (1-52)")
	full := fs.String("full-schedule", "", "cron for full backups, UTC (e.g. \"0 1 * * 0\")")
	diff := fs.String("diff-schedule", "", "cron for differential backups, UTC; \"\" disables them")
	proof := fs.String("proof-schedule", "", "cron for the restore test, UTC")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	var req protocol.UpdateDatabaseRequest
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "retention-full":
			req.RetentionFull = retention
		case "full-schedule":
			req.ScheduleFull = full
		case "diff-schedule":
			req.ScheduleDiff = diff
		case "proof-schedule":
			req.ScheduleDrill = proof
		}
	})
	if req == (protocol.UpdateDatabaseRequest{}) {
		return errors.New("nothing to change: pass --retention-full, --full-schedule, --diff-schedule or --proof-schedule")
	}
	d, err := c.UpdateDatabase(ctx, name, req)
	if err != nil {
		return err
	}
	diffText := d.ScheduleDiff
	if diffText == "" {
		diffText = "off"
	}
	fmt.Printf("%s: keep %d full backups; full %q, diff %q, restore test %q (UTC)\n",
		d.Name, d.RetentionFull, d.ScheduleFull, diffText, d.ScheduleDrill)
	return nil
}

func removeCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	keep := fs.Bool("keep-archiving", false, "remove an adopted database; its host keeps archiving WAL to the repository")
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	name, err := parse(fs, args, true)
	if err != nil {
		return err
	}
	d, err := c.Database(ctx, name)
	if err != nil {
		return err
	}
	if !*yes {
		fmt.Printf("Rowsafe will stop backing up, testing restores and monitoring %s on %s. Nothing on the server is changed.\n", d.Name, d.Hostname)
		if *keep {
			fmt.Println("PostgreSQL keeps archiving WAL to the repository. To turn that off, follow the Rollback")
			fmt.Println("section of https://rowsafe.sh/docs/guides/adopt#rollback")
		}
		if !confirm("Remove " + d.Name + "?") {
			return errors.New("cancelled")
		}
	}
	if err := c.DeleteDatabase(ctx, name, *keep); err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusConflict && strings.Contains(ae.Msg, "keep_archiving") {
			return fmt.Errorf("%w\n\nRe-run with --keep-archiving to remove it and leave archiving on", err)
		}
		return err
	}
	fmt.Printf("Removed %s. Its backup history stays in the repository.\n", d.Name)
	return nil
}

func hostsRemove(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("hosts remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	pos, err := parseN(fs, args, "HOST")
	if err != nil {
		return err
	}
	if !*yes {
		fmt.Printf("This revokes the agent on %s; it stops working until the host is enrolled again.\n", pos[0])
		fmt.Println("WAL archiving on the host is not affected. Uninstall the agent afterwards (https://rowsafe.sh/docs/guides/agent-updates#uninstall).")
		if !confirm("Remove host " + pos[0] + "?") {
			return errors.New("cancelled")
		}
	}
	if err := c.DeleteHost(ctx, pos[0]); err != nil {
		return err
	}
	fmt.Println("Removed", pos[0])
	return nil
}

func taskShow(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("task", flag.ContinueOnError)
	pos, err := parseN(fs, args, "ID")
	if err != nil {
		return err
	}
	t, err := c.Task(ctx, pos[0])
	if err != nil {
		return err
	}
	printTask(t)
	return nil
}

func waitAndReport(ctx context.Context, c *client.Client, taskID, dbName string) error {
	last := ""
	t, err := c.WaitTask(ctx, taskID, func(t protocol.TaskView) {
		if t.Status != last {
			last = t.Status
			if t.Status == protocol.StatusQueued {
				fmt.Fprintf(os.Stderr, "Waiting for the agent to pick up the %s (task %s)...\n", taskName(t.Type), t.ID)
			} else if t.Status == protocol.StatusRunning {
				fmt.Fprintf(os.Stderr, "Running...\n")
			}
		}
	})
	if err != nil {
		return err
	}
	printTask(t)
	if t.Status != protocol.StatusSucceeded {
		return exitError(1)
	}
	switch t.Type {
	case protocol.TaskAdopt:
		var res protocol.AdoptResult
		if json.Unmarshal(t.Result, &res) == nil {
			switch {
			case !res.Applied:
				fmt.Printf("\nNext: rowsafe apply %s\n", dbName)
			case res.RestartRequired:
				fmt.Printf("\nNext: PostgreSQL needs a quick restart for backups to start. Restart it when it suits you:\n"+
					"  `rowsafe restart %s`, Restart PostgreSQL in the dashboard, or on the server: sudo systemctl restart postgresql\n"+
					"Rowsafe notices the restart by itself and finishes; `rowsafe verify %s` checks right away.\n", dbName, dbName)
			default:
				fmt.Printf("\nVerification queued automatically. Follow it with `rowsafe tasks %s`.\n", dbName)
			}
		}
	case protocol.TaskCheck:
		fmt.Printf("\n%s is protected. The first full backup is queued; follow it with `rowsafe tasks %s`.\n", dbName, dbName)
	case protocol.TaskRestorePoint:
		fmt.Printf("\nTo go back to it: rowsafe rewind copy %s --mark LABEL (a copy next to production), or Rewind in the dashboard\n", dbName)
	}
	return nil
}

// stdin is where confirm reads the answer; tests replace it.
var stdin io.Reader = os.Stdin

// taskName is a task type in words.
func taskName(typ string) string {
	switch typ {
	case protocol.TaskDrill:
		return "restore test"
	case protocol.TaskRestorePoint:
		return "restore point"
	case protocol.TaskCheck:
		return "WAL check"
	case protocol.TaskRestart:
		return "PostgreSQL restart"
	case protocol.TaskMaintenance:
		return "fix"
	case protocol.TaskIndexAdvisor:
		return "index check"
	case protocol.TaskRewindCopy, protocol.TaskRewindDrop, protocol.TaskRewindCompare, protocol.TaskRewindRows,
		protocol.TaskRewindInPlace, protocol.TaskRewindUndo, protocol.TaskRewindCleanup:
		return rewindTaskName(typ)
	}
	return typ
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
}

func marksCmd(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("marks", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	points, err := c.RestorePoints(ctx, name)
	if err != nil {
		return err
	}
	t := newTable("NAME", "STATUS", "CREATED", "RESTORE FROM BACKUP", "LSN", "BY")
	for _, p := range points {
		created := "-"
		if p.CreatedAt != nil {
			created = p.CreatedAt.Local().Format("2006-01-02 15:04:05")
		}
		t.row(p.Name, p.Status, created, orDash(p.RestoreFromBackup), orDash(p.LSN), p.CreatedBy)
	}
	t.flush()
	return nil
}
