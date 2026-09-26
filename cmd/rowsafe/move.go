package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe move: move a database to another server. A standby on the new
// server, then a planned switchover at the time you pick (nothing lost),
// with the old server kept stopped as a way back.

var moveSubs = map[string]subcommand{
	"switch":   moveSwitchCmd,
	"schedule": moveScheduleCmd,
	"cancel":   moveCancelCmd,
	"back":     moveBackCmd,
	"finish":   moveFinishCmd,
}

func moveCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := moveSubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return moveStartCmd(ctx, c, args)
}

func printMove(name string, m *protocol.MoveView) {
	if m == nil {
		fmt.Printf("%s isn't being moved. Move it: rowsafe move %s --to SERVER\n", name, name)
		return
	}
	fmt.Printf("%s: move from %s to %s (%s)\n", name, m.From.Hostname, m.To.Hostname, m.Status)
	if m.Hint != "" {
		fmt.Printf("  %s\n", m.Hint)
	}
	if m.Error != "" {
		fmt.Printf("  Error: %s\n", m.Error)
	}
	switch {
	case m.CanSwitch:
		fmt.Printf("  Switch over now: rowsafe move switch %s\n", name)
	case m.Status == protocol.MoveMoved:
		if m.KeepUntil != nil {
			fmt.Printf("  %s stays stopped until %s as a way back.\n", m.From.Hostname, m.KeepUntil.Local().Format("2006-01-02 15:04"))
		}
		if m.CanSwitchBack {
			fmt.Printf("  Switch back: rowsafe move back %s\n", name)
		}
		if m.CanFinish {
			fmt.Printf("  Remove the old server: rowsafe move finish %s\n", name)
		}
		for _, cs := range m.Connect {
			fmt.Printf("  New address: %s\n", cs.Value)
		}
	}
}

func moveStartCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("move", flag.ContinueOnError)
	to := fs.String("to", "", "the new server (its hostname); without it, show the move in progress")
	port := fs.Int("port", 0, "the empty PostgreSQL cluster there (default: the only one Rowsafe may stop and start)")
	at := fs.String("at", "", "switch over by itself at this time (\"2026-09-24 23:00\", \"23:00\" or RFC 3339); default: when you run rowsafe move switch")
	keep := fs.Int("keep-days", 7, "keep the old server (stopped) this many days as a way back, 1 to 30")
	fingerprint := fs.String("fingerprint", "", "the new server's key fingerprint (sudo -u postgres rowsafe-agent key, there)")
	noWait := fs.Bool("no-wait", false, "return once queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *to == "" {
		info, err := c.StandbyInfo(ctx, name)
		if err != nil {
			return apiErr(err)
		}
		printMove(name, info.Move)
		return nil
	}
	req := protocol.MoveRequest{KeepDays: *keep}
	if *at != "" {
		t, err := parseRewindTime(*at)
		if err != nil {
			return err
		}
		if t.Before(now()) {
			return fmt.Errorf("%s is in the past", describeTime(t))
		}
		utc := t.UTC()
		req.SwitchAt = &utc
	}
	cands, err := c.StandbyCandidates(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	var cand *protocol.StandbyCandidate
	for i := range cands {
		if cands[i].Hostname == *to || cands[i].HostID == *to {
			cand = &cands[i]
		}
	}
	if cand == nil {
		return fmt.Errorf("no server %q with the Rowsafe agent in this organization", *to)
	}
	if !cand.Usable {
		return fmt.Errorf("%s can't take %s: %s", cand.Hostname, name, cand.Reason)
	}
	if *port == 0 {
		if len(cand.Ports) != 1 {
			return fmt.Errorf("which cluster on %s? Pass --port (%v)", cand.Hostname, cand.Ports)
		}
		*port = cand.Ports[0]
	}
	req.HostID, req.Port = cand.HostID, *port
	fmt.Printf("Move %s to %s (port %d).\n\n", name, cand.Hostname, *port)
	fmt.Printf("  1. Rowsafe sets %s up as a standby from the latest backup and keeps it in sync.\n", cand.Hostname)
	when := "when you run rowsafe move switch " + name
	if req.SwitchAt != nil {
		when = "at " + describeTime(*req.SwitchAt)
	}
	fmt.Printf("  2. It switches over %s: the current server stops briefly and cleanly, %s replays everything\n", when, cand.Hostname)
	fmt.Println("     and takes over. Nothing is lost; apps are disconnected for about a minute.")
	fmt.Printf("  3. The old server stays stopped for %d days so you can switch back.\n", *keep)
	fmt.Printf("\n  %s's agent key fingerprint: %s. Check it with `sudo -u postgres rowsafe-agent key` there.\n", cand.Hostname, cand.Fingerprint)
	if *fingerprint == "" {
		if !stdinIsTerminal() {
			return errors.New("pass --fingerprint with the fingerprint `rowsafe-agent key` prints on the new server")
		}
		fmt.Printf("\nType the fingerprint %s prints to go ahead: ", cand.Hostname)
		*fingerprint = strings.TrimSpace(readLine())
	}
	req.Fingerprint = *fingerprint
	if _, err := c.Move(ctx, name, req); err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("Queued. Follow it with: rowsafe move %s\n", name)
		return nil
	}
	fmt.Println("\nSetting up the new server:")
	info, err := waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		m := i.Move
		switch {
		case m == nil:
			return false, nil
		case m.Status == protocol.MoveFailed:
			return true, fmt.Errorf("the move failed: %s", orText(m.Error, "see rowsafe standby "+name))
		case m.CanSwitch, m.Status == protocol.MoveSwitching, m.Status == protocol.MoveMoved:
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Println()
	printMove(name, info.Move)
	return nil
}

// moveFor reads the database's move.
func moveFor(ctx context.Context, c *client.Client, fs *flag.FlagSet, args []string) (string, *protocol.MoveView, error) {
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return "", nil, err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return name, nil, apiErr(err)
	}
	if info.Move == nil {
		return name, nil, fmt.Errorf("%s isn't being moved", name)
	}
	return name, info.Move, nil
}

func moveSwitchCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("move switch", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, m, err := moveFor(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if !m.CanSwitch {
		return fmt.Errorf("can't switch over now: %s", orText(m.Hint, m.Status))
	}
	fmt.Printf("Switch %s over to %s now: %s stops briefly and cleanly, %s replays everything and takes over.\n",
		name, m.To.Hostname, m.From.Hostname, m.To.Hostname)
	if !*yes {
		fmt.Printf("Type the database name (%s) to switch over: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.MoveSwitch(ctx, name, name); err != nil {
		return apiErr(err)
	}
	fmt.Println("Switching over:")
	info, err := waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		switch {
		case i.Move == nil:
			return false, nil
		case i.Move.Status == protocol.MoveMoved:
			return true, nil
		case i.Move.Status == protocol.MoveSyncing && i.Move.Error != "":
			return true, errors.New(i.Move.Error)
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Println()
	printMove(name, info.Move)
	return nil
}

func moveScheduleCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("move schedule", flag.ContinueOnError)
	at := fs.String("at", "", "switch over by itself at this time")
	clearIt := fs.Bool("clear", false, "wait for rowsafe move switch instead")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	var req protocol.MoveScheduleRequest
	switch {
	case *clearIt:
	case *at != "":
		t, err := parseRewindTime(*at)
		if err != nil {
			return err
		}
		utc := t.UTC()
		req.SwitchAt = &utc
	default:
		return errors.New("pass --at TIME, or --clear")
	}
	info, err := c.MoveSchedule(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	printMove(name, info.Move)
	return nil
}

func moveCancelCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("move cancel", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, m, err := moveFor(ctx, c, fs, args)
	if err != nil {
		return err
	}
	fmt.Printf("Cancel moving %s to %s: it stays where it is; %s gets its own data back.\n", name, m.To.Hostname, m.To.Hostname)
	if !*yes {
		fmt.Printf("Type the database name (%s) to cancel the move: ", name)
		if readLine() != name {
			return errors.New("not cancelled")
		}
	}
	if _, err := c.MoveCancel(ctx, name, name); err != nil {
		return apiErr(err)
	}
	fmt.Println("Cancelled.")
	return nil
}

func moveBackCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("move back", flag.ContinueOnError)
	fingerprint := fs.String("fingerprint", "", "the old server's key fingerprint (sudo -u postgres rowsafe-agent key, there)")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, m, err := moveFor(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if !m.CanSwitchBack {
		return fmt.Errorf("can't switch back: %s", orText(m.Hint, m.Status))
	}
	fmt.Printf("Switch %s back to %s: it follows %s again (on its own data), then switches over by itself.\n",
		name, m.From.Hostname, m.To.Hostname)
	fmt.Printf("%s's agent key fingerprint: %s.\n", m.From.Hostname, m.From.Fingerprint)
	if *fingerprint == "" {
		*fingerprint = m.From.Fingerprint
	}
	if !*yes {
		fmt.Printf("Type the database name (%s) to switch back: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.MoveBack(ctx, name, protocol.MoveBackRequest{Confirm: name, Fingerprint: *fingerprint}); err != nil {
		return apiErr(err)
	}
	fmt.Println("Switching back:")
	info, err := waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		switch {
		case i.Move == nil || !i.Move.Back:
			return false, nil
		case i.Move.Status == protocol.MoveMoved:
			return true, nil
		case i.Move.Status == protocol.MoveFailed:
			return true, errors.New(orText(i.Move.Error, "switching back failed"))
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Println()
	printMove(name, info.Move)
	return nil
}

func moveFinishCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("move finish", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the old server's name")
	name, m, err := moveFor(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if !m.CanFinish {
		return fmt.Errorf("there is no old server to remove: %s", orText(m.Hint, m.Status))
	}
	fmt.Printf("Remove the old server %s from %s: Rowsafe stops keeping it stopped. PostgreSQL stays stopped there\n", m.From.Hostname, name)
	fmt.Println("(read-only if started); switching back is no longer possible.")
	if !*yes {
		fmt.Printf("Type the old server's name (%s) to remove it: ", m.From.Hostname)
		if readLine() != m.From.Hostname {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.MoveFinish(ctx, name, m.From.Hostname); err != nil {
		return apiErr(err)
	}
	fmt.Printf("Done: %s is on %s for good.\n", name, m.To.Hostname)
	return nil
}
