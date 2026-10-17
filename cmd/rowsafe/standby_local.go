package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe standby on a server on its own (no account): each server runs its
// own control plane, so a person runs one command on each server
// (protocol/standby_local.go). The two share only the bucket and its
// passphrase.

var localStandbySubs = map[string]subcommand{
	"status":   localStandbyStatus,
	"create":   localStandbyCreate,
	"link":     localStandbyLink,
	"unlink":   localStandbyUnlink,
	"fence":    localStandbyFence,
	"promote":  localStandbyPromote,
	"unfence":  localStandbyUnfence,
	"remove":   localStandbyRemove,
	"forget":   localStandbyForget,
	"failover": localStandbyFailover,
}

func localStandbyCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := localStandbySubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
		switch args[0] {
		case "add":
			return newUsageError("on servers on their own, run on the standby's server: sudo rowsafe standby create NAME --primary PRIMARY-ADDRESS")
		case "rebuild":
			return newUsageError("on the old primary: sudo rowsafe standby create NAME --primary NEW-PRIMARY-ADDRESS")
		}
	}
	return localStandbyStatus(ctx, c, args)
}

func localStandbyStatus(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby", flag.ContinueOnError)
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	if jsonMode {
		return printJSON(info)
	}
	printLocalStandby(info)
	return nil
}

// printLocalStandby shows this server's half of the pair.
func printLocalStandby(info protocol.StandbyInfo) {
	l := info.Local
	if l == nil {
		printStandby(info)
		return
	}
	fmt.Printf("%s: Standby (this server is the %s)\n\n", info.Database, map[string]string{protocol.LocalRolePrimary: "primary",
		protocol.LocalRoleStandby: "standby", protocol.LocalRoleFenced: "old primary, stopped"}[l.Role])
	v := info.Standby
	switch l.Role {
	case protocol.LocalRolePrimary:
		fmt.Printf("Primary:  %s (this server), port %d\n", info.Primary.Hostname, info.Primary.Port)
		if v == nil {
			fmt.Println("Standby:  none here. On the other server, set up with this server's bucket and passphrase:")
			fmt.Printf("            sudo rowsafe standby create %s --primary THIS-SERVER'S-ADDRESS\n", info.Database)
			fmt.Printf("          and here, so it can stream: sudo rowsafe standby link %s --address ITS-ADDRESS\n", info.Database)
			break
		}
		fmt.Printf("Standby:  %s\n", v.Server.Hostname)
		if v.Status != "" {
			fmt.Printf("  Status: %s\n", standbyStatusText(v))
		}
		printLag(v)
		if v.Note != "" {
			fmt.Printf("  Note:   %s\n", v.Note)
		}
		if l.Link != nil {
			for _, w := range l.Link.Warnings {
				fmt.Printf("  Note:   %s\n", w)
			}
		}
		fmt.Printf("  Switch over: here, sudo rowsafe standby fence %s; then on the standby, sudo rowsafe standby promote %s\n", info.Database, info.Database)
	case protocol.LocalRoleStandby:
		fmt.Printf("Primary:  %s", info.Primary.Hostname)
		if l.PrimaryAddress != "" {
			state := "answers"
			if !info.Primary.Online {
				state = "doesn't answer from here"
			}
			fmt.Printf(" (%s:%d, %s)", l.PrimaryAddress, info.Primary.Port, state)
		}
		fmt.Println()
		if v != nil {
			fmt.Printf("Standby:  %s (this server), port %d\n", v.Server.Hostname, v.Server.Port)
			fmt.Printf("  Status: %s\n", standbyStatusText(v))
			printLag(v)
			if v.LastReplayAt != nil {
				fmt.Printf("  Last change replayed: %s (%s)\n", v.LastReplayAt.Local().Format("2006-01-02 15:04:05"), ago(v.LastReplayAt))
			}
			if v.Note != "" {
				fmt.Printf("  Note:   %s\n", v.Note)
			}
			if v.Error != "" {
				fmt.Printf("  Error:  %s\n", v.Error)
			}
			switch {
			case !v.CanPromote:
				fmt.Printf("  Promote: not now (%s)\n", v.PromoteHint)
			case !l.PromoteNeedsDown:
				fmt.Printf("  The primary stopped for a switchover: promote this server with sudo rowsafe standby promote %s\n", info.Database)
			default:
				fmt.Printf("  Switch over: on the primary, sudo rowsafe standby fence %s; then here, sudo rowsafe standby promote %s\n", info.Database, info.Database)
				fmt.Printf("  If the primary is down: sudo rowsafe standby promote %s --primary-down\n", info.Database)
			}
		}
	case protocol.LocalRoleFenced:
		fmt.Printf("Primary:  %s\n", info.Primary.Hostname)
		fmt.Printf("This server: PostgreSQL is stopped and kept stopped (read-only if started).\n")
	}
	if r := l.Record; r != nil {
		what := "is the primary"
		if r.State == protocol.PrimaryRecordStopped {
			what = "stopped for good"
			if r.CheckpointLSN != "" {
				what += " (last change at " + r.CheckpointLSN + ")"
			}
		}
		fmt.Printf("\nIn the bucket: %s %s since %s\n", r.Primary, what, r.At.Local().Format("2006-01-02 15:04"))
	} else if l.RecordError != "" {
		fmt.Printf("\nIn the bucket: can't read the pair's record (%s)\n", l.RecordError)
	}
	for _, f := range info.Fences {
		state := "stopped and kept stopped"
		if !f.Stopped {
			state = "being stopped"
		}
		fmt.Printf("\nFenced since %s: %s.\n", f.Since.Local().Format("2006-01-02 15:04"), state)
		fmt.Printf("  Turn it into the new standby: sudo rowsafe standby create %s --primary NEW-PRIMARY-ADDRESS\n", info.Database)
		if f.CanUnfence {
			fmt.Printf("  Or, if the standby was not promoted, start it again as the primary: sudo rowsafe standby unfence %s\n", info.Database)
		}
	}
	fmt.Println("\nAutomatic failover: off (servers on their own need a person to promote; see sudo rowsafe standby failover)")
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

func printLag(v *protocol.StandbyView) {
	if v.LagSeconds == nil && v.LagBytes == nil {
		return
	}
	lag := "-"
	if v.LagSeconds != nil {
		lag = (time.Duration(*v.LagSeconds * float64(time.Second))).Round(time.Second).String()
	}
	if v.LagBytes != nil {
		lag += " (" + humanBytes(*v.LagBytes) + ")"
	}
	fmt.Printf("  Behind: %s\n", lag)
}

// localStandbyTask waits for the task a change queued (the answer's newest
// standby task) and fails with its error.
func localStandbyTask(ctx context.Context, c *client.Client, info protocol.StandbyInfo, what string) (protocol.TaskView, error) {
	if len(info.Tasks) == 0 {
		return protocol.TaskView{}, nil
	}
	t, err := waitTask(ctx, c, info.Tasks[0].ID, nil)
	if err != nil {
		return t, err
	}
	if t.Status != protocol.StatusSucceeded {
		return t, fmt.Errorf("%s: %s", what, orText(t.Error, t.Status))
	}
	return t, nil
}

func localStandbyCreate(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby create", flag.ContinueOnError)
	primary := fs.String("primary", "", "the primary's IP address (and :port), to stream from it; without it the standby follows through the bucket")
	port := fs.Int("port", 0, "the empty PostgreSQL cluster here that becomes the standby (default: the only one Rowsafe may stop and start)")
	folder := fs.String("folder", "", "the backups' folder in the bucket, when the primary says it isn't the database's name")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	noWait := fs.Bool("no-wait", false, "return once queued")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return newUsageError("usage: sudo rowsafe standby create NAME [--primary ADDRESS[:PORT]] [--port N]: NAME is the primary's database name")
	}
	name := pos[0]
	req := protocol.LocalStandbyRequest{Port: *port, Folder: *folder, Confirm: name}
	if *primary != "" {
		host, p, err := net.SplitHostPort(*primary)
		if err != nil {
			host = strings.Trim(*primary, "[]")
		} else if req.PrimaryPort, err = strconv.Atoi(p); err != nil {
			return newUsageError("--primary: invalid port in " + *primary)
		}
		req.PrimaryAddress = host
	}
	fmt.Printf("Turn PostgreSQL here into a standby of %s, from the backups in this server's bucket.\n\n", name)
	fmt.Println("  This server must be set up with the primary's bucket and passphrase (they read its backups).")
	fmt.Println("  The empty cluster that becomes the standby is stopped and its data kept aside (put back if you remove the standby);")
	fmt.Println("  on a stopped old primary, its data is reused when it can be, else kept aside for 7 days.")
	if req.PrimaryAddress != "" {
		fmt.Printf("  It streams from %s when it can (let it in there first: sudo rowsafe standby link %s --address THIS-SERVER'S-ADDRESS),\n", req.PrimaryAddress, name)
		fmt.Println("  and always follows through the bucket.")
	} else {
		fmt.Println("  It follows through the bucket, about a minute behind (pass --primary ADDRESS to stream).")
	}
	if err := confirmTypedAs(*yes, name, fmt.Sprintf("\nType the database name (%s) to go ahead: ", name)); err != nil {
		return err
	}
	info, err := c.LocalStandbyCreate(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("Queued. Follow it with: sudo rowsafe standby %s\n", name)
		return nil
	}
	fmt.Println("\nCreating the standby (restoring the latest backup; this takes as long as a restore)...")
	t, err := localStandbyTask(ctx, c, info, "creating the standby failed")
	if err != nil {
		return err
	}
	if t.Result != nil {
		var res protocol.StandbyCreateResult
		if json.Unmarshal(t.Result, &res) == nil {
			fmt.Println(res.Summary)
			for _, w := range res.Warnings {
				fmt.Println("Note: " + w)
			}
		}
	}
	// The agent reports the running standby with its next heartbeat.
	info, err = waitStandby(ctx, c, name, func(i protocol.StandbyInfo) (bool, error) {
		return i.Standby != nil && i.Standby.Status != protocol.StandbyCreating && i.Standby.ReportedAt != nil, nil
	})
	if err != nil {
		return err
	}
	if jsonMode {
		return printJSON(info)
	}
	fmt.Println()
	printLocalStandby(info)
	return nil
}

func localStandbyLink(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby link", flag.ContinueOnError)
	var addrs stringList
	fs.Var(&addrs, "address", "the standby server's IP address (repeat for more)")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	var list []string
	for _, a := range addrs {
		for _, x := range strings.Split(a, ",") {
			if x = strings.TrimSpace(x); x != "" {
				list = append(list, x)
			}
		}
	}
	if len(list) == 0 {
		return newUsageError("pass --address with the standby server's IP address")
	}
	info, err := c.LocalStandbyLink(ctx, name, protocol.LocalLinkRequest{Addresses: list})
	if err != nil {
		return apiErr(err)
	}
	t, err := localStandbyTask(ctx, c, info, "letting the standby stream failed")
	if err != nil {
		return err
	}
	var res protocol.StandbyPrepareResult
	_ = json.Unmarshal(t.Result, &res)
	if jsonMode {
		return printJSON(res)
	}
	fmt.Println(res.Summary)
	for _, w := range res.Warnings {
		fmt.Println("Note: " + w)
	}
	cmd := "sudo rowsafe standby create " + name
	if a := firstAddress(res.PrimaryAddresses); a != "" {
		cmd += " --primary " + net.JoinHostPort(a, strconv.Itoa(res.Port))
	}
	if res.Folder != "" {
		cmd += " --folder " + res.Folder
	}
	fmt.Printf("\nNow on the standby's server (set up with this server's bucket and passphrase):\n  %s\n", cmd)
	return nil
}

// firstAddress prefers a private address (the servers' own network).
func firstAddress(addrs []string) string {
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.IsPrivate() {
			return a
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return ""
}

func localStandbyUnlink(ctx context.Context, c *client.Client, args []string) error {
	return localStandbyConfirmed(ctx, c, args, "standby unlink", "unlink",
		"Stop letting the standby of %s stream from this server (its replication role and pg_hba.conf line are removed). It still follows through the bucket.\n",
		"Type the database name (%s) to go ahead: ", "removing the standby's access failed", nil)
}

func localStandbyFence(ctx context.Context, c *client.Client, args []string) error {
	return localStandbyConfirmed(ctx, c, args, "standby fence", "fence",
		"Stop PostgreSQL here for good so the standby of %s can take over without losing anything (a switchover):\n"+
			"  apps are disconnected, the last changes are pushed to the bucket, standby.signal keeps it read-only if started,\n"+
			"  and Rowsafe keeps it stopped. Then promote the standby on its server.\n",
		"Type the database name (%s) to stop it: ", "stopping PostgreSQL failed",
		func(name string, t protocol.TaskView) {
			var res protocol.StandbyFenceResult
			_ = json.Unmarshal(t.Result, &res)
			fmt.Println(res.Summary)
			for _, w := range res.Warnings {
				fmt.Println("Note: " + w)
			}
			if res.Recorded {
				fmt.Printf("\nNow on the standby's server: sudo rowsafe standby promote %s\n", name)
			} else {
				fmt.Printf("\nThe bucket doesn't say it stopped, so on the standby's server promote with: sudo rowsafe standby promote %s --primary-down\n", name)
			}
			fmt.Printf("If you change your mind before that, start it again here: sudo rowsafe standby unfence %s\n", name)
		})
}

func localStandbyUnfence(ctx context.Context, c *client.Client, args []string) error {
	return localStandbyConfirmed(ctx, c, args, "standby unfence", "unfence",
		"Start PostgreSQL here again as the primary of %s. Rowsafe first checks in the bucket that the standby wasn't promoted.\n",
		"Type the database name (%s) to start it: ", "starting it again failed", nil)
}

func localStandbyRemove(ctx context.Context, c *client.Client, args []string) error {
	return localStandbyConfirmed(ctx, c, args, "standby remove", "remove",
		"Remove the standby of %s on this server: its PostgreSQL is stopped and the cluster gets its own data back.\n",
		"Type the database name (%s) to remove the standby: ", "removing the standby failed", nil)
}

// localStandbyConfirmed runs a change confirmed with the database's name,
// waits for its task and prints its summary (or what done prints).
func localStandbyConfirmed(ctx context.Context, c *client.Client, args []string, cmd, path, intro, prompt, failed string,
	done func(name string, t protocol.TaskView)) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	fmt.Printf(intro, name)
	if err := confirmTypedAs(*yes, name, fmt.Sprintf("\n"+prompt, name)); err != nil {
		return err
	}
	info, err := c.LocalStandbyChange(ctx, name, path, name)
	if err != nil {
		return apiErr(err)
	}
	t, err := localStandbyTask(ctx, c, info, failed)
	if err != nil {
		return err
	}
	if done != nil {
		done(name, t)
	} else if t.Result != nil {
		var res struct {
			Summary string `json:"summary"`
		}
		if json.Unmarshal(t.Result, &res) == nil && res.Summary != "" {
			fmt.Println(res.Summary)
		}
	}
	return nil
}

func localStandbyPromote(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby promote", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	down := fs.Bool("primary-down", false, "the primary is down or will stay stopped (needed when it didn't stop for a switchover)")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.StandbyInfo(ctx, name)
	if err != nil {
		return apiErr(err)
	}
	v, l := info.Standby, info.Local
	if l == nil || l.Role != protocol.LocalRoleStandby || v == nil {
		return fmt.Errorf("this server doesn't run a standby of %s: promote it on the standby's server", name)
	}
	if !v.CanPromote {
		return fmt.Errorf("the standby can't be promoted now: %s", orText(v.PromoteHint, v.Status))
	}
	req := protocol.PromoteStandbyRequest{Confirm: name}
	fmt.Printf("Promote this server: it becomes the primary of %s.\n\n", name)
	if !l.PromoteNeedsDown {
		fmt.Printf("  %s stopped for good for a switchover: this server first replays its last change, so nothing is lost.\n", info.Primary.Hostname)
	} else {
		fmt.Printf("  %s didn't stop for a switchover (the bucket doesn't say so). If it still runs and apps write to it,\n", info.Primary.Hostname)
		fmt.Println("  both servers take writes until it reads the bucket and stops (about a minute after it can reach it; never if it can't).")
		fmt.Printf("  To switch over without that risk, run there first: sudo rowsafe standby fence %s\n", name)
		fmt.Println("  Promote now only if it is down or will stay stopped. Changes it made that didn't reach this server are not here.")
		req.PrimaryDown = l.DownConfirm
		if !*down && (*yes || !stdinIsTerminal()) {
			return fmt.Errorf("not promoted: the primary didn't stop for a switchover. Pass --primary-down to confirm %s", l.DownConfirm)
		}
		if !*down {
			if err := confirmTypedAs(false, l.DownConfirm, fmt.Sprintf("\nType %q to confirm: ", l.DownConfirm)); err != nil {
				return err
			}
		}
	}
	fmt.Println("  Then backups run from this server (to the same bucket) and apps must point at it.")
	if err := confirmTypedAs(*yes, name, fmt.Sprintf("\nType the database name (%s) to promote this server: ", name)); err != nil {
		return err
	}
	out, err := c.PromoteStandby(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	fmt.Println("\nPromoting...")
	t, err := localStandbyTask(ctx, c, out, "promoting failed")
	if err != nil {
		return err
	}
	var res protocol.StandbyPromoteResult
	_ = json.Unmarshal(t.Result, &res)
	if jsonMode {
		return printJSON(res)
	}
	fmt.Println(res.Summary)
	for _, w := range res.Warnings {
		fmt.Println("Note: " + w)
	}
	fmt.Printf("\nBackups start here now (a full backup first). Point your apps at this server.\n")
	fmt.Printf("Later, turn the old primary into the new standby (on it): sudo rowsafe standby create %s --primary THIS-SERVER'S-ADDRESS\n", name)
	return nil
}

func localStandbyForget(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby forget", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	fmt.Printf("Stop keeping the stopped old copy of %s here and forget it. PostgreSQL stays stopped (read-only if started),\n", name)
	fmt.Println("but Rowsafe no longer keeps it so: if someone starts it as a primary, two servers may take writes.")
	if err := confirmTypedAs(*yes, name, fmt.Sprintf("\nType the database name (%s) to go ahead: ", name)); err != nil {
		return err
	}
	if _, err := c.ForgetFence(ctx, name, protocol.ForgetFenceRequest{Confirm: name}); err != nil {
		return fmt.Errorf("not changed: %w", apiErr(err))
	}
	fmt.Printf("Rowsafe no longer keeps %s here.\n", name)
	return nil
}

func localStandbyFailover(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("standby failover", flag.ContinueOnError)
	fs.Bool("on", false, "turn automatic failover on")
	fs.Bool("off", false, "turn it off")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	_, err = c.SetFailover(ctx, name, protocol.FailoverSettings{})
	if err == nil {
		return errors.New("unexpected answer")
	}
	return apiErr(err)
}
