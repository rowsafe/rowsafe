package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
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

func hostsList(ctx context.Context, c *client.Client) error {
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

func orgShow(ctx context.Context, c *client.Client) error {
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

func apiKeysList(ctx context.Context, c *client.Client) error {
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
	fmt.Printf("On the database host:\n  %s\n", installCommand(cfg.URL, tok.Token))
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

func dbList(ctx context.Context, c *client.Client) error {
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

func dbShow(ctx context.Context, c *client.Client, args []string) error {
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
	fmt.Printf("Schedules:  full %q, diff %q, drill %q (UTC)\n", d.ScheduleFull, d.ScheduleDiff, d.ScheduleDrill)
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
	backups, err := c.Backups(ctx, name, 1)
	if err == nil && len(backups) > 0 {
		b := backups[0]
		fmt.Printf("Backup:     %s %s, %s ago\n", b.Type, b.Label, time.Since(b.StoppedAt).Round(time.Minute))
	}
	drills, err := c.Drills(ctx, name, 1)
	if err == nil && len(drills) > 0 {
		dr := drills[0]
		fmt.Printf("Drill:      %s, %s ago\n", passFail(dr.Passed), time.Since(dr.CreatedAt).Round(time.Minute))
	}
	return nil
}

func dbAdopt(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("adopt", flag.ContinueOnError)
	host := fs.String("host", "", "host ID or hostname (see `rowsafe hosts list`); optional with a single host")
	port := fs.Int("port", 5432, "Postgres port")
	socketDir := fs.String("socket-dir", "/var/run/postgresql", "Unix socket directory")
	retention := fs.Int("retention-full", 2, "full backups to keep (weekly fulls: 2 = about 2 weeks of PITR)")
	noWait := fs.Bool("no-wait", false, "don't wait for the plan")
	name, err := parse(fs, args, true)
	if err != nil {
		return err
	}
	if *host, err = resolveHost(ctx, c, *host); err != nil {
		return err
	}
	resp, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{
		HostID: *host, Name: name, Port: *port, SocketDir: *socketDir, RetentionFull: *retention,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Registered %s (%s). Planning...\n\n", resp.Database.Name, resp.Database.ID)
	if *noWait {
		fmt.Printf("Task %s queued. Check it with `rowsafe task show %s`.\n", resp.Task.ID, resp.Task.ID)
		return nil
	}
	return waitAndReport(ctx, c, resp.Task.ID, name)
}

func dbPlan(ctx context.Context, c *client.Client, args []string) error {
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

func dbApply(ctx context.Context, c *client.Client, args []string) error {
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

func dbVerify(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, err := c.CreateTask(ctx, name, protocol.TaskCheck, nil)
	if err != nil {
		return err
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func backupRun(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("backup run", flag.ContinueOnError)
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

func backupList(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("backup list", flag.ContinueOnError), args)
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

func drillRun(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("drill run", flag.ContinueOnError)
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
		fmt.Println("Queued", t.ID)
		return nil
	}
	return waitAndReport(ctx, c, t.ID, name)
}

func drillList(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("drill list", flag.ContinueOnError), args)
	if err != nil {
		return err
	}
	drills, err := c.Drills(ctx, name, 20)
	if err != nil {
		return err
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
	typ := fs.String("type", "", "only tasks of this type (inspect, adopt, check, backup, drill)")
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

func dbSet(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db set", flag.ContinueOnError)
	retention := fs.Int("retention-full", 0, "full backups to keep (1-52)")
	full := fs.String("full-schedule", "", "cron for full backups, UTC (e.g. \"0 1 * * 0\")")
	diff := fs.String("diff-schedule", "", "cron for differential backups, UTC; \"\" disables them")
	drill := fs.String("drill-schedule", "", "cron for restore drills, UTC")
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
		case "drill-schedule":
			req.ScheduleDrill = drill
		}
	})
	if req == (protocol.UpdateDatabaseRequest{}) {
		return errors.New("nothing to change: pass --retention-full, --full-schedule, --diff-schedule or --drill-schedule")
	}
	d, err := c.UpdateDatabase(ctx, name, req)
	if err != nil {
		return err
	}
	diffText := d.ScheduleDiff
	if diffText == "" {
		diffText = "off"
	}
	fmt.Printf("%s: keep %d full backups; full %q, diff %q, drill %q (UTC)\n",
		d.Name, d.RetentionFull, d.ScheduleFull, diffText, d.ScheduleDrill)
	return nil
}

func dbRemove(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db remove", flag.ContinueOnError)
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
		fmt.Printf("Rowsafe will stop backing up, drilling and monitoring %s on %s. Nothing on the host is changed.\n", d.Name, d.Hostname)
		if *keep {
			fmt.Println("PostgreSQL keeps archiving WAL to the repository. To turn that off, follow the Rollback")
			fmt.Println("section of docs/runbooks/adopt.md.")
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
		fmt.Println("WAL archiving on the host is not affected. Uninstall the agent afterwards (see docs/runbooks/adopt.md).")
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
	fs := flag.NewFlagSet("task show", flag.ContinueOnError)
	id, err := parse(fs, args, true)
	if err != nil {
		return err
	}
	t, err := c.Task(ctx, id)
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
				fmt.Fprintf(os.Stderr, "Waiting for the agent to pick up %s task %s...\n", t.Type, t.ID)
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
				fmt.Printf("\nNext: restart PostgreSQL in a maintenance window (e.g. `sudo systemctl restart postgresql`), then run `rowsafe verify %s`.\n", dbName)
			default:
				fmt.Printf("\nVerification queued automatically. Follow it with `rowsafe tasks %s`.\n", dbName)
			}
		}
	case protocol.TaskCheck:
		fmt.Printf("\n%s is protected. The first full backup is queued; follow it with `rowsafe tasks %s`.\n", dbName, dbName)
	case protocol.TaskRestorePoint:
		fmt.Println("\nTo recover to it, see \"Restore to a named restore point\" in docs/runbooks/restore.md.")
	}
	return nil
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N] ", prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y") || strings.EqualFold(strings.TrimSpace(line), "yes")
}

func restorePointCreate(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("restore-point create", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "return once queued")
	pos, err := parseN(fs, args, "DATABASE", "POINT")
	if err != nil {
		return err
	}
	return createRestorePoint(ctx, c, pos[0], pos[1], *noWait)
}

func restorePointList(ctx context.Context, c *client.Client, args []string) error {
	name, err := dbArg(ctx, c, flag.NewFlagSet("restore-point list", flag.ContinueOnError), args)
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

// dbProtection exits 0 if the database is protected and 3 if not, so
// scripts and AI-agent hooks can gate risky changes on it.
// dbProtection exits 0 if the database is protected and 3 if not, so
// scripts and AI-agent hooks can gate risky changes on it.
func dbProtection(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("db protection", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full check as JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	return protectionStatus(ctx, c, name, *asJSON)
}
