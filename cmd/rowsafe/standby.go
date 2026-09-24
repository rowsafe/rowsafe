package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe standby: a second server that stays in sync with the primary, is
// readable, and takes over if the primary dies. The control plane queues
// the agents' tasks; the CLI waits for them.

var standbySubs = map[string]subcommand{
	"status":   standbyStatusCmd,
	"add":      standbyAddCmd,
	"promote":  standbyPromoteCmd,
	"rebuild":  standbyRebuildCmd,
	"remove":   standbyRemoveCmd,
	"failover": standbyFailoverCmd,
	"unfence":  standbyUnfenceCmd,
}

func standbyCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := standbySubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return standbyStatusCmd(ctx, c, args)
}

// standbyPoll is how often the CLI checks progress (tests shorten it).
var standbyPoll = 3 * time.Second

func standbyStatusCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	printStandby(info)
	return nil
}

func serverLine(s protocol.StandbyServer) string {
	state := "online"
	if !s.Online {
		state = "not reporting (last seen " + ago(s.LastSeen) + ")"
	}
	return fmt.Sprintf("%s:%d, %s", s.Hostname, s.Port, state)
}

func standbyStatusText(v *protocol.StandbyView) string {
	switch v.Status {
	case protocol.StandbyReady:
		if v.Mode == protocol.StandbyModeStreaming {
			return "in sync (streaming)"
		}
		return "in sync through the bucket (about a minute behind)"
	case protocol.StandbyLagging:
		return "behind"
	case protocol.StandbyCreating, protocol.StandbyPreparing:
		return "being created"
	}
	return v.Status
}

func printStandby(info protocol.StandbyInfo) {
	fmt.Printf("%s: Standby\n\n", info.Database)
	fmt.Printf("Primary:  %s\n", serverLine(info.Primary))
	if v := info.Standby; v != nil {
		fmt.Printf("Standby:  %s\n", serverLine(v.Server))
		fmt.Printf("  Status: %s\n", standbyStatusText(v))
		if v.LagSeconds != nil || v.LagBytes != nil {
			lag := "-"
			if v.LagSeconds != nil {
				lag = (time.Duration(*v.LagSeconds * float64(time.Second))).Round(time.Second).String()
			}
			if v.LagBytes != nil {
				lag += " (" + humanBytes(*v.LagBytes) + ")"
			}
			fmt.Printf("  Behind: %s\n", lag)
		}
		if v.Note != "" {
			fmt.Printf("  Note:   %s\n", v.Note)
		}
		if v.Error != "" {
			fmt.Printf("  Error:  %s\n", v.Error)
		}
		if v.CanPromote {
			fmt.Printf("  Promote it: rowsafe standby promote %s\n", info.Database)
		} else if v.PromoteHint != "" && v.Status != protocol.StandbyPromoted {
			fmt.Printf("  Promote: %s\n", v.PromoteHint)
		}
	} else if info.CanCreate {
		fmt.Printf("Standby:  none. Add one: rowsafe standby add %s --host SERVER\n", info.Database)
	} else {
		fmt.Printf("Standby:  none (%s)\n", info.CreateHint)
	}
	for _, f := range info.Fences {
		if f.Released {
			continue
		}
		state := "PostgreSQL is stopped and kept stopped"
		if !f.Stopped {
			state = "waiting for its agent to confirm PostgreSQL is stopped"
		}
		fmt.Printf("Fenced:   %s (old primary since %s): %s\n", serverLine(f.Server), f.Since.Local().Format("2006-01-02 15:04"), state)
		fmt.Printf("  Turn it into the new standby: rowsafe standby rebuild %s --host %s\n", info.Database, f.Server.Hostname)
		if f.CanUnfence {
			fmt.Printf("  Or start it again as the primary (the standby wasn't promoted): rowsafe standby unfence %s\n", info.Database)
		}
	}
	fo := info.Failover
	if fo.Automatic {
		fmt.Printf("\nAutomatic failover: on (after %s, at most %s of changes lost)\n",
			time.Duration(fo.AfterSeconds)*time.Second, time.Duration(fo.MaxDataLossSeconds)*time.Second)
	} else {
		fmt.Printf("\nAutomatic failover: off")
		if !fo.Available && fo.Hint != "" {
			fmt.Printf(" (%s)", fo.Hint)
		}
		fmt.Println()
	}
	if len(info.Connect) > 0 {
		fmt.Println("\nConnection strings that follow the primary:")
		for _, cs := range info.Connect {
			fmt.Printf("  %-14s %s\n", cs.Driver, cs.Value)
			if cs.Note != "" {
				fmt.Printf("  %-14s %s\n", "", cs.Note)
			}
		}
	}
	if len(info.Events) > 0 {
		fmt.Println("\nTimeline:")
		for i, e := range info.Events {
			if i == 8 {
				break
			}
			fmt.Printf("  %s  %s\n", e.At.Local().Format("2006-01-02 15:04"), e.Message)
		}
	}
}

// waitStandby polls until done says the standby reached a state, printing
// its status as it changes.
func waitStandby(ctx context.Context, c *client.Client, name string, done func(protocol.StandbyInfo) (bool, error)) (protocol.StandbyInfo, error) {
	last := ""
	for {
		info, err := c.StandbyInfo(ctx, name)
		if err != nil {
			return info, apiErr(err)
		}
		if ok, err := done(info); ok || err != nil {
			return info, err
		}
		if v := info.Standby; v != nil && v.Status != last {
			last = v.Status
			fmt.Printf("  %s\n", standbyStatusText(v))
		}
		select {
		case <-ctx.Done():
			return info, ctx.Err()
		case <-time.After(standbyPoll):
		}
	}
}

// failedStandbyTask is the newest failed standby task's error, if the
// newest task failed.
func failedStandbyTask(info protocol.StandbyInfo) error {
	if len(info.Tasks) == 0 {
		return nil
	}
	t := info.Tasks[0]
	if t.Status == protocol.StatusFailed || t.Status == protocol.StatusLost || t.Status == protocol.StatusCancelled {
		return fmt.Errorf("%s: %s", t.Type, orText(t.Error, t.Status))
	}
	return nil
}

func standbyAddCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby add", flag.ContinueOnError)
	host := fs.String("host", "", "the server that becomes the standby (its hostname)")
	port := fs.Int("port", 0, "the empty PostgreSQL cluster there (default: the only one Rowsafe may stop and start)")
	fingerprint := fs.String("fingerprint", "", "the standby server's key fingerprint (sudo -u postgres rowsafe-agent key, there)")
	noStream := fs.Bool("no-stream", false, "follow through the bucket only (no connection between the servers)")
	noWait := fs.Bool("no-wait", false, "return once queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	cands, err := c.StandbyCandidates(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	var cand *protocol.StandbyCandidate
	for i := range cands {
		if cands[i].Hostname == *host || cands[i].HostID == *host {
			cand = &cands[i]
		}
	}
	if *host == "" || cand == nil {
		var names []string
		for _, x := range cands {
			s := x.Hostname
			if !x.Usable {
				s += " (" + x.Reason + ")"
			}
			names = append(names, s)
		}
		if len(names) == 0 {
			return errors.New("no other server with the Rowsafe agent in this organization: install it on the standby server first (rowsafe hosts enroll-token)")
		}
		return fmt.Errorf("which server? Pass --host with one of: %s", strings.Join(names, ", "))
	}
	if !cand.Usable {
		return fmt.Errorf("%s can't hold the standby: %s", cand.Hostname, cand.Reason)
	}
	if *port == 0 {
		if len(cand.Ports) != 1 {
			return fmt.Errorf("which cluster on %s? Pass --port (%v)", cand.Hostname, cand.Ports)
		}
		*port = cand.Ports[0]
	}
	fmt.Printf("Set up a standby of %s on %s (port %d).\n\n", name, cand.Hostname, *port)
	fmt.Printf("  The cluster on port %d is stopped and its (empty) data set aside; the latest backup is restored there.\n", *port)
	fmt.Printf("  %s's agent key fingerprint, as Rowsafe knows it: %s\n", cand.Hostname, cand.Fingerprint)
	fmt.Printf("  Check it matches what `sudo -u postgres rowsafe-agent key` prints on %s: the bucket settings are sealed to that key.\n", cand.Hostname)
	if *fingerprint == "" {
		if !stdinIsTerminal() {
			return errors.New("pass --fingerprint with the fingerprint `rowsafe-agent key` prints on the standby server")
		}
		fmt.Printf("\nType the fingerprint %s prints to go ahead: ", cand.Hostname)
		*fingerprint = strings.TrimSpace(readLine())
	}
	stream := !*noStream
	info, err := c.CreateStandby(ctx, name, protocol.CreateStandbyRequest{HostID: cand.HostID, Port: *port, Fingerprint: *fingerprint, Stream: &stream})
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("Queued. Follow it with: rowsafe standby %s\n", name)
		return nil
	}
	fmt.Println("\nCreating the standby (restoring the latest backup; this takes as long as a restore):")
	info, err = waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		if i.Standby == nil {
			return true, errors.New("the standby is gone")
		}
		switch i.Standby.Status {
		case protocol.StandbyReady, protocol.StandbyLagging:
			return true, nil
		case protocol.StandbyFailed:
			return true, fmt.Errorf("creating the standby failed: %s", orText(i.Standby.Error, "see rowsafe standby "+name))
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Println()
	printStandby(info)
	return nil
}

func standbyPromoteCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby promote", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	down := fs.Bool("primary-down", false, "the primary's server is down or will stay stopped (needed when its agent isn't reporting)")
	force := fs.Bool("force", false, "promote even if the standby misses some of the stopped primary's last changes")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	v := info.Standby
	if v == nil {
		return fmt.Errorf("%s has no standby", name)
	}
	if !v.CanPromote {
		return fmt.Errorf("the standby can't be promoted now: %s", orText(v.PromoteHint, v.Status))
	}
	req := protocol.PromoteStandbyRequest{Confirm: name, Force: *force}
	fmt.Printf("Promote the standby of %s: %s becomes the primary.\n\n", name, v.Server.Hostname)
	if v.PrimaryReachable {
		fmt.Printf("  Rowsafe first stops PostgreSQL on %s for good (fenced: it stays stopped, and would come back read-only),\n", info.Primary.Hostname)
		fmt.Printf("  then waits until %s has replayed everything %s wrote. Apps are disconnected meanwhile.\n", v.Server.Hostname, info.Primary.Hostname)
	} else {
		fmt.Printf("  %s isn't reporting, so Rowsafe can't stop it first. If it is still running and apps write to it,\n", info.Primary.Hostname)
		fmt.Println("  both servers accept writes (split brain). Promote only if it is down or will stay stopped:")
		fmt.Printf("  when its agent comes back, Rowsafe stops PostgreSQL there at once.\n")
		req.PrimaryDown = info.Primary.Hostname + " is down"
		if !*down && (*yes || !stdinIsTerminal()) {
			return fmt.Errorf("the primary isn't reporting: pass --primary-down to confirm %s is down or will stay stopped", info.Primary.Hostname)
		}
		if !*down {
			fmt.Printf("\nType %q to confirm: ", req.PrimaryDown)
			if readLine() != req.PrimaryDown {
				return errors.New("cancelled; nothing was changed")
			}
		}
	}
	fmt.Println("  Apps using a connection string with both servers (rowsafe standby shows them) follow by themselves.")
	if !*yes {
		fmt.Printf("\nType the database name (%s) to promote the standby: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.PromoteStandby(ctx, name, req); err != nil {
		return apiErr(err)
	}
	fmt.Println("\nPromoting:")
	info, err = waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		if i.Primary.HostID == v.Server.HostID {
			return true, nil
		}
		if i.Standby != nil && i.Standby.Status != protocol.StandbyPromoting {
			if err := failedStandbyTask(i); err != nil {
				return true, err
			}
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Printf("\n%s is the primary now.\n\n", info.Primary.Hostname)
	printStandby(info)
	return nil
}

// fenceFor picks the fenced old primary on host ("" if there's one).
func fenceFor(info protocol.StandbyInfo, host string) (*protocol.FenceView, error) {
	var live []protocol.FenceView
	for _, f := range info.Fences {
		if !f.Released && (host == "" || f.Server.Hostname == host || f.Server.HostID == host) {
			live = append(live, f)
		}
	}
	switch len(live) {
	case 0:
		return nil, fmt.Errorf("%s has no fenced old primary%s", info.Database, map[bool]string{true: "", false: " on " + host}[host == ""])
	case 1:
		return &live[0], nil
	}
	return nil, errors.New("several fenced servers: pass --host")
}

func standbyRebuildCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby rebuild", flag.ContinueOnError)
	host := fs.String("host", "", "the fenced old primary")
	fingerprint := fs.String("fingerprint", "", "its agent key fingerprint (sudo -u postgres rowsafe-agent key, there)")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	f, err := fenceFor(info, *host)
	if err != nil {
		return err
	}
	fmt.Printf("Turn %s (the old primary) into the new standby of %s.\n\n", f.Server.Hostname, name)
	if f.Clean {
		fmt.Println("  It stopped cleanly before the promotion, so Rowsafe first tries to reuse its data (fast).")
	}
	fmt.Println("  Otherwise the latest backup is restored there; its current data is kept aside for 7 days")
	fmt.Println("  (with anything it accepted after the promotion), never deleted right away.")
	fmt.Printf("  Its agent key fingerprint: %s (check it with `sudo -u postgres rowsafe-agent key` there).\n", f.Server.Fingerprint)
	if *fingerprint == "" {
		*fingerprint = f.Server.Fingerprint
		if !*yes {
			fmt.Printf("\nType the fingerprint %s prints to go ahead: ", f.Server.Hostname)
			*fingerprint = strings.TrimSpace(readLine())
		}
	}
	if !*yes {
		fmt.Printf("Type the database name (%s) to rebuild it: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.RebuildStandby(ctx, name, protocol.RebuildStandbyRequest{FenceID: f.ID, Fingerprint: *fingerprint, Confirm: name}); err != nil {
		return apiErr(err)
	}
	fmt.Println("\nRebuilding:")
	info, err = waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		if i.Standby == nil {
			return false, nil
		}
		switch i.Standby.Status {
		case protocol.StandbyReady, protocol.StandbyLagging:
			return true, nil
		case protocol.StandbyFailed:
			return true, fmt.Errorf("rebuilding failed: %s", orText(i.Standby.Error, "see rowsafe standby "+name))
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	fmt.Println()
	printStandby(info)
	return nil
}

func standbyRemoveCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby remove", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if info.Standby == nil {
		return fmt.Errorf("%s has no standby", name)
	}
	fmt.Printf("Remove the standby of %s on %s: its PostgreSQL is stopped, the cluster gets its own data back,\n", name, info.Standby.Server.Hostname)
	fmt.Println("and the primary drops the standby's access. Automatic failover turns off.")
	if !*yes {
		fmt.Printf("Type the database name (%s) to remove the standby: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.RemoveStandby(ctx, name, name); err != nil {
		return apiErr(err)
	}
	fmt.Println("Removing the standby; follow it with: rowsafe standby " + name)
	return nil
}

func standbyFailoverCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby failover", flag.ContinueOnError)
	on := fs.Bool("on", false, "turn automatic failover on")
	off := fs.Bool("off", false, "turn it off")
	after := fs.Duration("after", 0, "how long every condition must hold first (default 3m)")
	loss := fs.Duration("max-data-loss", 0, "the most recent changes a failover may lose (default 1m)")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *on == *off {
		return errors.New("pass --on or --off")
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	req := info.Failover.FailoverSettings
	req.Automatic = *on
	if *after > 0 {
		req.AfterSeconds = int(after.Seconds())
	}
	if *loss > 0 {
		req.MaxDataLossSeconds = int(loss.Seconds())
	}
	if *on {
		fmt.Printf("Automatic failover for %s: when %s and its agent stop answering for %s, the standby can't reach it either,\n",
			name, info.Primary.Hostname, time.Duration(req.AfterSeconds)*time.Second)
		fmt.Printf("and the standby lost at most %s of changes, Rowsafe promotes the standby by itself and alerts you.\n",
			time.Duration(req.MaxDataLossSeconds)*time.Second)
		fmt.Println("If the old primary was only cut off and apps can still reach it, both may accept writes until its agent")
		fmt.Println("comes back and Rowsafe stops it: https://rowsafe.sh/docs/guides/standby#split-brain")
		if !*yes {
			fmt.Printf("Type the database name (%s) to turn it on: ", name)
			if readLine() != name {
				return errors.New("cancelled; nothing was changed")
			}
		}
		req.Confirm = name
	}
	info, err = c.SetFailover(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("Automatic failover is %s.\n", map[bool]string{true: "on", false: "off"}[info.Failover.Automatic])
	return nil
}

func standbyUnfenceCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby unfence", flag.ContinueOnError)
	host := fs.String("host", "", "the fenced server")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	f, err := fenceFor(info, *host)
	if err != nil {
		return err
	}
	if !f.CanUnfence {
		return fmt.Errorf("%s can't be started again as the primary: the standby became the primary. Rebuild it as the new standby instead", f.Server.Hostname)
	}
	fmt.Printf("Start PostgreSQL on %s again as the primary of %s (the standby wasn't promoted).\n", f.Server.Hostname, name)
	if !*yes {
		fmt.Printf("Type the database name (%s) to go ahead: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	if _, err := c.Unfence(ctx, name, protocol.UnfenceRequest{FenceID: f.ID, Confirm: name}); err != nil {
		return apiErr(err)
	}
	fmt.Println("Starting it again; follow it with: rowsafe standby " + name)
	return nil
}
