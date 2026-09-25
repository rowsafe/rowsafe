package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe update and rowsafe upgrade: PostgreSQL minor updates and major
// upgrades, done by the agent on the database server (through its root
// helper, only where the installer allowed it), with a Mark first.

// ---- rowsafe update [NAME] ----

func updateCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	noWait := fs.Bool("no-wait", false, "return once the update is queued")
	auto := fs.String("auto", "", `automatic minor updates on Sundays at 03:00: "on" or "off"`)
	tz := fs.String("timezone", "", "with --auto on: the time zone for 03:00 (IANA name, e.g. Europe/Berlin; default: this computer's)")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *auto != "" {
		return autoUpdateCmd(ctx, c, name, *auto, *tz)
	}
	info, err := c.Upgrades(ctx, name)
	if err != nil {
		return err
	}
	printVersions(info)
	if !info.UpdateAvailable {
		fmt.Println(orText(info.UpdateReason, "Nothing to update."))
		return nil
	}
	if info.UpdateReason != "" {
		fmt.Printf("Rowsafe can't update it now: %s\n", info.UpdateReason)
		return exitError(1)
	}
	fmt.Printf("\nUpdate %s from PostgreSQL %s to %s: Rowsafe saves a Mark, installs PostgreSQL %d's newest packages,\n", name, info.Version, info.Candidate, info.Major)
	fmt.Println("restarts PostgreSQL (apps are disconnected for a few seconds) and checks that backups still work.")
	if !*yes {
		fmt.Printf("Type the database name (%s) to update: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.UpdatePostgres(ctx, name, name)
	if err != nil {
		return apiErr(err)
	}
	return finishUpgradeTasks(ctx, c, resp.Tasks, *noWait)
}

func autoUpdateCmd(ctx context.Context, c *client.Client, name, onOff, tz string) error {
	var enabled bool
	switch onOff {
	case "on":
		enabled = true
		if tz == "" {
			tz = localZone()
		}
	case "off":
	default:
		return errors.New(`--auto takes "on" or "off"`)
	}
	info, err := c.SetAutoUpdate(ctx, name, enabled, tz)
	if err != nil {
		return apiErr(err)
	}
	if !info.AutoMinorUpdates {
		fmt.Printf("Automatic minor updates are off for %s.\n", name)
		return nil
	}
	fmt.Printf("Automatic minor updates are on for %s: Sundays at 03:00 (%s), with a Mark first.\n", name, info.AutoTimezone)
	if info.NextAutoUpdate != nil {
		fmt.Printf("Next window: %s\n", describeTime(*info.NextAutoUpdate))
	}
	return nil
}

// localZone is this computer's IANA time zone name, or UTC.
func localZone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		if _, err := time.LoadLocation(tz); err == nil {
			return tz
		}
	}
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(link, "zoneinfo/"); i >= 0 {
			return link[i+len("zoneinfo/"):]
		}
	}
	return "UTC"
}

func printVersions(info protocol.UpgradeInfo) {
	fmt.Printf("%s on %s: PostgreSQL %s\n", info.Database, info.Host, orText(info.Version, "(unknown version)"))
	if info.RestartPending {
		fmt.Printf("  PostgreSQL %s is installed; a restart makes it run (rowsafe restart %s)\n", info.Installed, info.Database)
	}
	if info.UpdateAvailable {
		fmt.Printf("  Update available:   %s (bug and security fixes)\n", info.Candidate)
	}
	if len(info.Majors) > 0 {
		var ms []string
		for _, m := range info.Majors {
			ms = append(ms, strconv.Itoa(m))
		}
		fmt.Printf("  Newer majors:       %s (rowsafe upgrade %s --to %d)\n", strings.Join(ms, ", "), info.Database, info.Majors[len(info.Majors)-1])
	}
	if info.AutoMinorUpdates {
		fmt.Printf("  Automatic updates:  Sundays 03:00 (%s)\n", info.AutoTimezone)
	}
	if info.SecurityUpdates > 0 || info.RebootRequired {
		fmt.Printf("  Server:             %d security updates waiting", info.SecurityUpdates)
		if info.RebootRequired {
			fmt.Print("; a reboot is needed")
		}
		fmt.Printf(" (rowsafe fix %s)\n", info.Database)
	}
}

// ---- rowsafe upgrade [NAME] ----

var upgradeSubs = map[string]subcommand{
	"undo":    upgradeUndoCmd,
	"cleanup": upgradeCleanupCmd,
}

func upgradeCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := upgradeSubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	fs := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	to := fs.Int("to", 0, "the major version to upgrade to (default: the newest the server offers)")
	rehearseOnly := fs.Bool("rehearse-only", false, "only rehearse on a restored copy; production isn't touched")
	mode := fs.String("mode", protocol.UpgradeSafe, "safe (keeps the old version for an instant undo; needs free disk) or fast (hard links; undo restores from the backup)")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	asJSON := fs.Bool("json", false, "without other flags: print the upgrade state as JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	acting := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "to" || f.Name == "rehearse-only" || f.Name == "mode" {
			acting = true
		}
	})
	info, err := c.Upgrades(ctx, name)
	if err != nil {
		return err
	}
	if !acting {
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(info)
		}
		printUpgradeState(info)
		return nil
	}
	if *mode != protocol.UpgradeSafe && *mode != protocol.UpgradeFast {
		return errors.New(`--mode takes "safe" or "fast"`)
	}
	target := *to
	if target == 0 && len(info.Majors) > 0 {
		target = info.Majors[len(info.Majors)-1]
	}
	if target == 0 {
		return fmt.Errorf("%s's server offers no PostgreSQL newer than %d", name, info.Major)
	}
	if info.Upgrade != nil {
		return fmt.Errorf("the previous upgrade still keeps a version: remove it first (rowsafe upgrade cleanup %s), or undo it (rowsafe upgrade undo %s)", name, name)
	}

	// 1. The preflight and the rehearsal, unless a recent one passed.
	reh := info.Rehearsal
	if !info.RehearsalValid || reh == nil || reh.ToMajor != target || *rehearseOnly {
		fmt.Printf("Checking whether %s can be upgraded from PostgreSQL %s to %d...\n", name, info.Version, target)
		resp, err := c.CheckUpgrade(ctx, name, target)
		if err != nil {
			return apiErr(err)
		}
		done, err := waitUpgradeTasks(ctx, c, resp.Tasks)
		if err != nil {
			return err
		}
		var chk protocol.UpgradeCheckResult
		_ = json.Unmarshal(done.Result, &chk)
		printChecks(chk)
		if !chk.CanRehearse {
			return exitError(1)
		}
		fmt.Printf("\nRehearsing: the latest backup is restored into a scratch copy on the server and upgraded to PostgreSQL %d.\n", target)
		fmt.Println("Production isn't touched (PostgreSQL's new version may be installed on the server for it).")
		resp, err = c.RehearseUpgrade(ctx, name, target)
		if err != nil {
			return apiErr(err)
		}
		done, err = waitUpgradeTasks(ctx, c, resp.Tasks)
		var r protocol.UpgradeRehearsalResult
		if len(done.Result) > 0 {
			_ = json.Unmarshal(done.Result, &r)
			printRehearsal(r)
		}
		if err != nil {
			return err
		}
		reh = &r
		if *rehearseOnly || !chk.CanUpgrade {
			if !chk.CanUpgrade {
				fmt.Println("\nThe upgrade itself can't run on this server yet (see the checks above).")
			} else {
				fmt.Printf("\nUpgrade when you're ready: rowsafe upgrade %s --to %d [--mode safe|fast]\n", name, target)
			}
			return nil
		}
	} else {
		fmt.Printf("The rehearsal of the upgrade to PostgreSQL %d passed on %s.\n", target, describeTime(*info.RehearsalAt))
	}

	// 2. The upgrade.
	secs := reh.SafeDowntimeSeconds
	if *mode == protocol.UpgradeFast {
		secs = reh.FastDowntimeSeconds
	}
	fmt.Printf("\nUpgrade %s from PostgreSQL %s to %d in %s mode:\n", name, info.Version, target, *mode)
	fmt.Printf("  - Rowsafe saves a Mark, stops PostgreSQL, upgrades it and starts PostgreSQL %d: about %s without connections.\n",
		target, humanDurationSeconds(secs))
	if *mode == protocol.UpgradeSafe {
		fmt.Printf("  - PostgreSQL %d is kept (stopped) for 7 days: rowsafe upgrade undo %s switches back in seconds.\n", info.Major, name)
	} else {
		fmt.Printf("  - Undo (7 days) restores PostgreSQL %d from the backup taken just before: anything written after the upgrade is lost from the live database.\n", info.Major)
	}
	fmt.Println("  - Then a full backup and a Proof run on the new version.")
	if !*yes {
		fmt.Printf("Type the database name (%s) to upgrade: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.Upgrade(ctx, name, protocol.UpgradeRequest{To: target, Mode: *mode, Confirm: name})
	if err != nil {
		return apiErr(err)
	}
	return finishUpgradeTasks(ctx, c, resp.Tasks, false)
}

func humanDurationSeconds(s float64) string {
	d := time.Duration(s * float64(time.Second)).Round(time.Second)
	if d < time.Second {
		return "a few seconds"
	}
	return d.String()
}

func printUpgradeState(info protocol.UpgradeInfo) {
	printVersions(info)
	name := info.Database
	fmt.Println()
	if up := info.Upgrade; up != nil {
		kept := up.FromMajor
		if up.Status == protocol.UpgradeUndone {
			kept = up.ToMajor
		}
		until := ""
		if up.Expires != nil {
			until = " until " + describeTime(*up.Expires)
		}
		switch up.Status {
		case protocol.UpgradeDone:
			fmt.Printf("Upgraded from %d to %d (%s mode). PostgreSQL %d is kept%s.\n", up.FromMajor, up.ToMajor, up.Mode, kept, until)
			fmt.Printf("  Undo:                 rowsafe upgrade undo %s\n", name)
		case protocol.UpgradeUndone:
			fmt.Printf("The upgrade to %d was undone. PostgreSQL %d is kept aside%s.\n", up.ToMajor, kept, until)
		default:
			fmt.Printf("An upgrade to %d is running.\n", up.ToMajor)
		}
		if up.Status != protocol.UpgradeInProgress {
			fmt.Printf("  Remove PostgreSQL %d:  rowsafe upgrade cleanup %s\n", kept, name)
		}
		if !up.BackupsReady {
			fmt.Println("  Backups aren't set up for the running version yet; Rowsafe keeps trying.")
		}
		return
	}
	if info.Rehearsal != nil {
		printRehearsal(*info.Rehearsal)
		if info.RehearsalValid {
			fmt.Printf("  It allows the upgrade until %s: rowsafe upgrade %s --to %d [--mode safe|fast]\n",
				describeTime(*info.RehearsalExpires), name, info.Rehearsal.ToMajor)
		}
	} else if len(info.Majors) > 0 {
		fmt.Printf("Check and rehearse (production isn't touched): rowsafe upgrade %s --rehearse-only\n", name)
	}
	if info.UpgradeReason != "" {
		fmt.Printf("Note: %s\n", info.UpgradeReason)
	}
}

func printChecks(chk protocol.UpgradeCheckResult) {
	for _, ck := range chk.Checks {
		mark := "ok  "
		switch ck.Status {
		case protocol.CheckWarning:
			mark = "note"
		case protocol.CheckBlocker:
			mark = "NO  "
		}
		fmt.Printf("  %s %s\n", mark, ck.Title)
		if ck.Detail != "" && ck.Status != protocol.CheckOK {
			fmt.Printf("       %s\n", ck.Detail)
		}
	}
	for i, s := range chk.DockerSteps {
		fmt.Printf("  %d. %s\n", i+1, s)
	}
	fmt.Println(chk.Summary)
}

func printRehearsal(r protocol.UpgradeRehearsalResult) {
	verdict := "passed"
	if !r.Passed {
		verdict = "found problems"
	}
	fmt.Printf("Rehearsal of %s -> %s: %s\n", orText(r.FromVersion, strconv.Itoa(r.FromMajor)), orText(r.ToVersion, strconv.Itoa(r.ToMajor)), verdict)
	for _, is := range r.Issues {
		fmt.Printf("  problem: %s\n", is)
	}
	for _, w := range r.Warnings {
		fmt.Printf("  note:    %s\n", w)
	}
	if r.Passed {
		fmt.Printf("  pg_upgrade took %s on the copy; expected downtime: Safe mode about %s, Fast mode about %s\n",
			humanDurationSeconds(r.UpgradeSeconds), humanDurationSeconds(r.SafeDowntimeSeconds), humanDurationSeconds(r.FastDowntimeSeconds))
	}
}

func upgradeUndoCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("upgrade undo", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Upgrades(ctx, name)
	if err != nil {
		return err
	}
	up := info.Upgrade
	if up == nil || up.Status != protocol.UpgradeDone {
		return fmt.Errorf("there is no upgrade of %s to undo", name)
	}
	fmt.Printf("Undo the upgrade of %s: go back from PostgreSQL %d to %d.\n", name, up.ToMajor, up.FromMajor)
	if up.Mode == protocol.UpgradeFast {
		fmt.Printf("  PostgreSQL %d is restored from the backup at the Mark saved before the upgrade: anything written since is lost\n", up.FromMajor)
		fmt.Println("  from the live database (a Mark keeps it recoverable), and the database is unavailable while it restores.")
	} else {
		fmt.Printf("  Anything written since the upgrade stays in PostgreSQL %d, kept aside (not in the live database). A short stop.\n", up.ToMajor)
	}
	if !*yes {
		fmt.Printf("Type the database name (%s) to undo the upgrade: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.UndoUpgrade(ctx, name, up.ID, name)
	if err != nil {
		return apiErr(err)
	}
	return finishUpgradeTasks(ctx, c, resp.Tasks, false)
}

func upgradeCleanupCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("upgrade cleanup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.Upgrades(ctx, name)
	if err != nil {
		return err
	}
	up := info.Upgrade
	if up == nil || up.Status == protocol.UpgradeInProgress {
		return fmt.Errorf("%s has no version kept by an upgrade", name)
	}
	kept := up.FromMajor
	if up.Status == protocol.UpgradeUndone {
		kept = up.ToMajor
	}
	fmt.Printf("Remove PostgreSQL %d from %s's server (kept by the upgrade); the upgrade can't be undone afterwards.\n", kept, name)
	if !*yes {
		fmt.Printf("Type the database name (%s) to remove it: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.CleanupUpgrade(ctx, name, up.ID, name)
	if err != nil {
		return apiErr(err)
	}
	return finishUpgradeTasks(ctx, c, resp.Tasks, false)
}

// finishUpgradeTasks waits for the tasks and prints the last one's summary.
func finishUpgradeTasks(ctx context.Context, c *client.Client, tasks []protocol.TaskView, noWait bool) error {
	if noWait {
		for _, t := range tasks {
			fmt.Printf("Task %s: %s (queued)\n", t.ID, upgradeTaskName(t.Type))
		}
		return nil
	}
	done, err := waitUpgradeTasks(ctx, c, tasks)
	if err != nil {
		return err
	}
	var r struct {
		Summary string `json:"summary"`
	}
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Done."))
	return nil
}

// waitUpgradeTasks waits for each task in order, saying what happens, and
// returns the last one.
func waitUpgradeTasks(ctx context.Context, c *client.Client, tasks []protocol.TaskView) (protocol.TaskView, error) {
	var last protocol.TaskView
	for _, t := range tasks {
		status := ""
		done, err := c.WaitTask(ctx, t.ID, func(v protocol.TaskView) {
			if v.Status == status {
				return
			}
			status = v.Status
			switch v.Status {
			case protocol.StatusQueued:
				fmt.Fprintf(os.Stderr, "Waiting for the agent to start %s (task %s)...\n", upgradeTaskName(v.Type), v.ID)
			case protocol.StatusRunning:
				fmt.Fprintf(os.Stderr, "%s...\n", upgradeTaskDoing(v.Type))
			}
		})
		if err != nil {
			return done, err
		}
		last = done
		if done.Status != protocol.StatusSucceeded {
			msg := orText(done.Error, "the task ended as "+done.Status)
			if done.Status == protocol.StatusLost {
				msg = "the agent stopped reporting while it ran (it may have restarted); see `rowsafe task " + done.ID + "`"
			}
			fmt.Printf("%s didn't work: %s\n", capitalize(upgradeTaskName(done.Type)), msg)
			return done, exitError(1)
		}
		if done.Type == protocol.TaskRestorePoint {
			var r protocol.RestorePointResult
			_ = json.Unmarshal(done.Result, &r)
			fmt.Printf("Mark saved first: %s\n", orText(r.Name, "done"))
		}
	}
	return last, nil
}

func upgradeTaskName(typ string) string {
	switch typ {
	case protocol.TaskRestorePoint:
		return "a Mark first"
	case protocol.TaskPGUpdate:
		return "the update"
	case protocol.TaskUpgradeCheck:
		return "the upgrade check"
	case protocol.TaskUpgradeRehearsal:
		return "the rehearsal"
	case protocol.TaskUpgrade:
		return "the upgrade"
	case protocol.TaskUpgradeUndo:
		return "the undo"
	case protocol.TaskUpgradeCleanup:
		return "removing the kept version"
	case protocol.TaskSecurityUpdates:
		return "the security updates"
	case protocol.TaskReboot:
		return "the reboot"
	}
	return typ
}

func upgradeTaskDoing(typ string) string {
	switch typ {
	case protocol.TaskRestorePoint:
		return "Saving a Mark"
	case protocol.TaskPGUpdate:
		return "Updating: PostgreSQL restarts for a few seconds"
	case protocol.TaskUpgradeCheck:
		return "Checking"
	case protocol.TaskUpgradeRehearsal:
		return "Rehearsing on a restored copy (about as long as a restore test, plus pg_upgrade)"
	case protocol.TaskUpgrade:
		return "Upgrading: PostgreSQL is stopped until it's done"
	case protocol.TaskUpgradeUndo:
		return "Undoing the upgrade"
	case protocol.TaskUpgradeCleanup:
		return "Removing the kept version"
	}
	return capitalize(upgradeTaskName(typ))
}
