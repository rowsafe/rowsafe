package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// rowsafe migrate: move a database in from a managed provider (DigitalOcean,
// RDS, Supabase, Neon...) onto a server Rowsafe protects. The source
// connection string is sealed on this machine to the server's key: it
// never reaches Rowsafe in the clear. The new login's connection string
// comes back sealed to a key this command holds in memory.

var migrateSubs = map[string]subcommand{
	"start":    migrateStartCmd,
	"status":   migrateStatusCmd,
	"fix":      migrateFixCmd,
	"switch":   migrateSwitchCmd,
	"password": migratePasswordCmd,
	"writable": migrateWritableCmd,
	"cancel":   migrateCancelCmd,
	"finish":   migrateFinishCmd,
}

func migrateCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := migrateSubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return migrateList(ctx, c, args)
}

func migrateList(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	db := ""
	if len(pos) > 0 {
		db = pos[0]
	}
	ms, err := c.Migrations(ctx, db)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(ms)
	}
	if len(ms) == 0 {
		fmt.Println("No migrations yet. Move a database in from DigitalOcean, RDS, Supabase, Neon or any PostgreSQL:\n  rowsafe migrate start [NAME]")
		return nil
	}
	t := newTable("ID", "INTO", "FROM", "METHOD", "STATUS", "PROGRESS")
	for _, m := range ms {
		from := "-"
		if m.Source != nil {
			from = m.Source.Host + "/" + m.Source.Database
		}
		into := m.DatabaseName
		if m.TargetDB != "" {
			into += "/" + m.TargetDB
		}
		t.row(m.ID, into, from, orDash(m.Method), m.Status, progressText(m))
	}
	t.flush()
	return nil
}

// progressText is the migration's progress in a few words.
func progressText(m protocol.Migration) string {
	p := m.Progress
	switch m.Status {
	case protocol.MigratePhaseSyncing:
		if p != nil && p.LagBytes != nil {
			if *p.LagBytes <= protocol.MigrateCaughtUpBytes {
				return "caught up: ready to switch over"
			}
			return humanBytes(*p.LagBytes) + " behind"
		}
		return "following changes"
	case protocol.MigratePhaseCopying, protocol.MigratePhaseDumping, protocol.MigratePhaseRestoring:
		if p != nil && p.TablesTotal > 0 {
			return fmt.Sprintf("%d of %d tables, %s of %s", p.TablesCopied, p.TablesTotal, humanBytes(p.BytesCopied), humanBytes(p.BytesTotal))
		}
	case protocol.MigratePhaseFailed:
		return firstLine(m.Error, 60)
	case protocol.MigratePhaseSwitched:
		if m.Switchover != nil {
			return firstLine(m.Switchover.Summary, 60)
		}
	}
	return "-"
}

// readSource reads the source connection string: from --source-env, from
// stdin when it isn't a terminal, or typed without echo.
func readSource(envVar string) (string, error) {
	if envVar != "" {
		v := strings.TrimSpace(os.Getenv(envVar))
		if v == "" {
			return "", fmt.Errorf("$%s is empty", envVar)
		}
		return v, nil
	}
	if !stdinIsTerminal() {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	fmt.Print("Paste the connection string of the database to move in (it isn't shown; it is encrypted\n" +
		"here to your server's key, so Rowsafe never sees it):\n> ")
	off := exec.Command("stty", "-echo")
	off.Stdin = os.Stdin
	echoOff := off.Run() == nil
	line := readLine()
	if echoOff {
		on := exec.Command("stty", "echo")
		on.Stdin = os.Stdin
		_ = on.Run()
	}
	fmt.Println()
	return strings.TrimSpace(line), nil
}

func migrateStartCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate start", flag.ContinueOnError)
	into := fs.String("into", "", "the new database's name on the server (default: the source's)")
	method := fs.String("method", "", "live (keep syncing until you switch over) or dump (a one-time copy while writes are stopped); default: what the check recommends")
	sourceEnv := fs.String("source-env", "", "read the source connection string from this environment variable")
	yes := fs.Bool("yes", false, "start without asking")
	again := fs.String("id", "", "check an existing migration again (after fixing what its check found)")
	host := fs.String("host", "", "one-time copy: the server address to put in the new connection string")
	user := fs.String("user", "", "one-time copy: the login name apps use on the new server")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *method != "" && *method != protocol.MigrateMethodLive && *method != protocol.MigrateMethodDump {
		return errors.New("--method is live or dump")
	}
	src, err := readSource(*sourceEnv)
	if err != nil {
		return err
	}
	if src == "" {
		return errors.New("no connection string given")
	}
	var m protocol.Migration
	if *again != "" {
		m, err = c.Migration(ctx, *again)
	} else {
		m, err = c.CreateMigration(ctx, name)
	}
	if err != nil {
		return err
	}
	fmt.Printf("Migration %s into %s: waiting for the server's key...\n", m.ID, name)
	m, err = c.WaitMigration(ctx, m.ID, func(m protocol.Migration) bool { return m.PublicKey != "" || m.Status == protocol.MigratePhaseFailed }, nil)
	if err != nil {
		return err
	}
	if m.PublicKey == "" {
		return fmt.Errorf("the server couldn't make its key: %s", m.Error)
	}
	pub, err := e2e.ParsePublicKey(m.PublicKey)
	if err != nil {
		return err
	}
	box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(m.ID), []byte(src))
	if err != nil {
		return err
	}
	fmt.Println("Sealed the connection string for the server. Checking both databases...")
	if m, err = c.CheckMigration(ctx, m.ID, protocol.CheckMigrationRequest{Source: box, TargetDB: *into}); err != nil {
		return err
	}
	m, err = c.WaitMigration(ctx, m.ID, client.MigrationTaskDone, nil)
	if err != nil {
		return err
	}
	if m.Check == nil {
		return fmt.Errorf("the check failed: %s", orText(m.Error, "see rowsafe task "+m.TaskID))
	}
	printCheck(*m.Check)
	chosen := *method
	if chosen == "" {
		chosen = m.Check.Method
	}
	if chosen == protocol.MigrateMethodLive && !m.Check.LiveSync || chosen == protocol.MigrateMethodDump && !m.Check.DumpOK {
		fmt.Printf("\nFix what's marked above, then check again: rowsafe migrate start %s --id %s\n(rowsafe migrate cancel %s removes the migration.)\n", name, m.ID, m.ID)
		return exitError(1)
	}
	var req protocol.StartMigrationRequest
	req.Method = chosen
	var key *ecdh.PrivateKey
	if chosen == protocol.MigrateMethodDump {
		fmt.Printf("\nA one-time copy stops writes to %s (Rowsafe makes it read-only and disconnects your apps), copies\n"+
			"everything, then gives you the new connection string. Expect about %s of downtime.\n",
			m.Check.Source.Host, humanDuration(m.Check.EstimatedCopySeconds))
		if key, err = e2e.GenerateKey(); err != nil {
			return err
		}
		req.ReadOnly, req.BrowserKey, req.Host, req.AppUser = true, e2e.PublicKeyString(key.PublicKey()), *host, *user
	} else {
		fmt.Println("\nLive sync copies everything while your apps keep running, then follows every change until you switch over.")
	}
	if !*yes && !confirm("Start now?") {
		fmt.Printf("Not started. Start later with: rowsafe migrate start again, or cancel: rowsafe migrate cancel %s\n", m.ID)
		return nil
	}
	if m, err = c.StartMigration(ctx, m.ID, req); err != nil {
		return err
	}
	return followMigration(ctx, c, m.ID, key)
}

// followMigration prints progress until the copy is caught up (live) or
// switched (one-time copy).
func followMigration(ctx context.Context, c *client.Client, id string, key *ecdh.PrivateKey) error {
	m, err := c.WaitMigration(ctx, id, func(m protocol.Migration) bool {
		switch m.Status {
		case protocol.MigratePhaseFailed, protocol.MigratePhaseSwitched, protocol.MigratePhaseCancelled:
			return true
		case protocol.MigratePhaseSyncing:
			return m.Progress != nil && m.Progress.LagBytes != nil && *m.Progress.LagBytes <= protocol.MigrateCaughtUpBytes
		}
		return false
	}, func(m protocol.Migration) { fmt.Printf("  %s: %s\n", m.Status, progressText(m)) })
	if err != nil {
		return err
	}
	switch m.Status {
	case protocol.MigratePhaseFailed:
		return fmt.Errorf("the migration stopped: %s", m.Error)
	case protocol.MigratePhaseSyncing:
		fmt.Printf("\nCaught up. Your apps still use the old database. When you're ready:\n  rowsafe migrate switch %s\n", id)
		return nil
	}
	return printSwitched(ctx, c, m, key)
}

func printSwitched(ctx context.Context, c *client.Client, m protocol.Migration, key *ecdh.PrivateKey) error {
	if m.Switchover != nil {
		fmt.Println(m.Switchover.Summary)
		for _, w := range m.Switchover.Warnings {
			fmt.Println("  note:", w)
		}
	}
	if key == nil || !m.CredentialsReady {
		return nil
	}
	cred, err := c.ClaimMigrationCredentials(ctx, m.ID)
	if err != nil {
		return err
	}
	plain, err := e2e.Open(key, protocol.MigrateInfo, protocol.MigrateCredentialsAAD(m.ID), cred.Credentials)
	if err != nil {
		return err
	}
	fmt.Printf("\nYour apps' new connection string (save it now: Rowsafe doesn't keep it):\n\n  %s\n\n", plain)
	fmt.Printf("Put it in your apps (DATABASE_URL). The old database is kept as it was for rollback;\n"+
		"when you no longer need it: rowsafe migrate finish %s\n", m.ID)
	return nil
}

func printCheck(r protocol.MigrateCheckResult) {
	prov := protocol.MigrateProviderByID(r.Source.Provider)
	fmt.Printf("\nFrom %s (%s, PostgreSQL %s, %s) into %s on this server (PostgreSQL %s)\n",
		prov.Name, r.Source.Host, orDash(r.Source.ServerVersion), humanBytes(r.Source.SizeBytes), orDash(r.Target.Database), orDash(r.Target.ServerVersion))
	for _, ch := range r.Checks {
		mark := map[string]string{protocol.CheckOK: "ok  ", protocol.CheckWarn: "note", protocol.CheckFail: "FIX "}[ch.Status]
		fmt.Printf("  %s %s\n", mark, ch.Title)
		if ch.Detail != "" && ch.Status != protocol.CheckOK {
			fmt.Printf("       %s\n", ch.Detail)
		}
		for i, it := range ch.Items {
			if i == 8 {
				fmt.Printf("       and %d more\n", len(ch.Items)-8)
				break
			}
			fmt.Printf("       - %s\n", it)
		}
		if ch.Fix != "" && ch.Status != protocol.CheckOK {
			fmt.Printf("       What to do: %s\n", ch.Fix)
		}
		if ch.Action == protocol.MigrateFixIdentity && ch.Status == protocol.CheckFail {
			fmt.Printf("       Or let Rowsafe do it: rowsafe migrate fix ID\n")
		}
	}
	fmt.Printf("\n%s\n", r.Summary)
}

func humanDuration(s int64) string {
	switch {
	case s < 90:
		return "a minute"
	case s < 3600:
		return fmt.Sprintf("%d minutes", (s+59)/60)
	}
	return fmt.Sprintf("%.1f hours", float64(s)/3600)
}

// migrationArg reads the ID argument.
func migrationArg(fs *flag.FlagSet, args []string) (string, error) {
	pos, err := positionals(fs, args)
	if err != nil {
		return "", err
	}
	if len(pos) != 1 {
		return "", errors.New("which migration? Pass its ID (rowsafe migrate lists them)")
	}
	return pos[0], nil
}

func migrateStatusCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	m, err := c.Migration(ctx, id)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(m)
	}
	fmt.Printf("Migration %s into %s", m.ID, m.DatabaseName)
	if m.TargetDB != "" {
		fmt.Printf(" (database %s)", m.TargetDB)
	}
	fmt.Println()
	if m.Source != nil {
		fmt.Printf("From:     %s (%s/%s as %s)\n", protocol.MigrateProviderByID(m.Source.Provider).Name, m.Source.Host, m.Source.Database, m.Source.User)
	}
	fmt.Printf("Status:   %s (%s)\n", m.Status, progressText(m))
	if m.Method != "" {
		fmt.Printf("Method:   %s\n", m.Method)
	}
	if m.SourceReadOnly {
		fmt.Printf("The old database is read-only (rowsafe migrate writable %s undoes it).\n", m.ID)
	}
	if m.Error != "" {
		fmt.Printf("Error:    %s\n", m.Error)
	}
	if m.Status == protocol.MigratePhaseChecked && m.Check != nil {
		printCheck(*m.Check)
	}
	if m.Copy != nil {
		for _, w := range m.Copy.Warnings {
			fmt.Println("  note:", w)
		}
	}
	if m.Switchover != nil {
		fmt.Println(m.Switchover.Summary)
		if m.Switchover.ConnectionHint != "" {
			fmt.Printf("Apps connect with: %s (password shown once at the switchover; rowsafe migrate password %s sets a new one)\n",
				m.Switchover.ConnectionHint, m.ID)
		}
	}
	return nil
}

// waitAction waits for the task an action queued and fails with its error.
func waitAction(ctx context.Context, c *client.Client, m protocol.Migration) (protocol.Migration, error) {
	m, err := c.WaitMigration(ctx, m.ID, client.MigrationTaskDone, nil)
	if err != nil {
		return m, err
	}
	if m.TaskStatus != protocol.StatusSucceeded {
		return m, fmt.Errorf("%s", orText(m.Error, "the task "+m.TaskID+" failed"))
	}
	return m, nil
}

func migrateFixCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate fix", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	fmt.Println("Rowsafe marks the source's tables without a primary key REPLICA IDENTITY FULL, so live sync can copy their\n" +
		"updates and deletes. Your data doesn't change; updates to those tables write a little more to the source's log.")
	if !*yes && !confirm("Change the source?") {
		return nil
	}
	m, err := c.FixMigrationIdentity(ctx, id, nil)
	if err != nil {
		return err
	}
	if _, err = waitAction(ctx, c, m); err != nil {
		return err
	}
	fmt.Printf("Done. Check again: rowsafe migrate start %s --id %s\n", m.DatabaseName, id)
	return nil
}

func migrateSwitchCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate switch", flag.ContinueOnError)
	stopped := fs.Bool("writes-stopped", false, "you stopped your apps' writes yourself; Rowsafe doesn't touch the old database")
	user := fs.String("user", "", "the login name apps use on the new server (default: the source's user name, or app)")
	host := fs.String("host", "", "the server address to put in the new connection string")
	yes := fs.Bool("yes", false, "don't ask")
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	m, err := c.Migration(ctx, id)
	if err != nil {
		return err
	}
	if *stopped {
		fmt.Println("Rowsafe waits until the new server has every change, sets the sequences, ends the sync and compares row counts.")
	} else {
		fmt.Println("Rowsafe makes the old database read-only and disconnects your apps from it, waits until the new server has\n" +
			"every change, sets the sequences, ends the sync and compares row counts. Your apps can't write until they\n" +
			"use the new connection string. The old database stays as it is, for rollback.")
	}
	if !*yes && !confirm(fmt.Sprintf("Switch %s over now?", m.DatabaseName)) {
		return nil
	}
	key, err := e2e.GenerateKey()
	if err != nil {
		return err
	}
	if m, err = c.SwitchoverMigration(ctx, id, protocol.SwitchoverRequest{ReadOnly: !*stopped, BrowserKey: e2e.PublicKeyString(key.PublicKey()),
		AppUser: *user, Host: *host, Confirm: m.DatabaseName}); err != nil {
		return err
	}
	m, err = waitAction(ctx, c, m)
	if err != nil {
		return err
	}
	return printSwitched(ctx, c, m, key)
}

func migratePasswordCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate password", flag.ContinueOnError)
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	key, err := e2e.GenerateKey()
	if err != nil {
		return err
	}
	m, err := c.NewMigrationCredentials(ctx, id, e2e.PublicKeyString(key.PublicKey()))
	if err != nil {
		return err
	}
	if m, err = waitAction(ctx, c, m); err != nil {
		return err
	}
	return printSwitched(ctx, c, m, key)
}

func migrateWritableCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate writable", flag.ContinueOnError)
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	m, err := c.MigrationSourceWritable(ctx, id)
	if err != nil {
		return err
	}
	if _, err = waitAction(ctx, c, m); err != nil {
		return err
	}
	fmt.Println("The old database accepts writes again.")
	return nil
}

func migrateCancelCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate cancel", flag.ContinueOnError)
	drop := fs.Bool("drop-copy", false, "also delete the partial copy on the server (only if the migration created it)")
	yes := fs.Bool("yes", false, "don't ask")
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	if !*yes && !confirm("Cancel this migration? Rowsafe removes its sync from the old database, which keeps running as before.") {
		return nil
	}
	m, err := c.CancelMigration(ctx, id, *drop)
	if err != nil {
		return err
	}
	if _, err = waitAction(ctx, c, m); err != nil {
		return err
	}
	fmt.Println("Cancelled.")
	return nil
}

func migrateFinishCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("migrate finish", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	id, err := migrationArg(fs, args)
	if err != nil {
		return err
	}
	if !*yes && !confirm("Forget the old database's connection string? (Rowsafe can't make it writable again afterwards; the old database itself isn't changed.)") {
		return nil
	}
	m, err := c.FinishMigration(ctx, id)
	if err != nil {
		return err
	}
	if _, err = waitAction(ctx, c, m); err != nil {
		return err
	}
	fmt.Println("Done. You can delete the old database at your provider whenever you like.")
	return nil
}
