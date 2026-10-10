package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe cloud maintenance: a Rowsafe Cloud server's weekly maintenance
// window, where updates that need a restart go in (a Mark first). The
// window is on by default; it can be moved, turned off, postponed once, or
// applied now. Critical fixes still go in once due.

func cloudMaintenanceCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "set":
			return cloudMaintenanceSet(ctx, c, args[1:])
		case "postpone":
			return cloudMaintenancePostpone(ctx, c, args[1:])
		case "apply-now":
			return cloudMaintenanceApplyNow(ctx, c, args[1:])
		}
	}
	fs := flag.NewFlagSet("cloud maintenance", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	s, err := maintenanceServerArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	m, err := c.CloudMaintenance(ctx, s.ID)
	if err != nil {
		return cloudErr(err)
	}
	return showMaintenance(m, *asJSON)
}

func maintenanceServerArg(ctx context.Context, c *client.Client, fs *flag.FlagSet, args []string) (client.CloudServer, error) {
	ref, err := optionalName(fs, args)
	if err != nil {
		return client.CloudServer{}, err
	}
	return findServer(ctx, c, ref)
}

func showMaintenance(m protocol.MaintenanceInfo, asJSON bool) error {
	if asJSON {
		return printJSON(m)
	}
	fmt.Printf("%s\n", orText(m.ServerName, m.ServerID))
	printMaintenance(&m)
	if m.Rolling != "" {
		fmt.Printf("  With the standby:   %s\n", m.Rolling)
	}
	if m.PostponedWindow != nil {
		fmt.Printf("  Postponed:          the window of %s\n", m.PostponedWindow.Local().Format("Mon 2 Jan 15:04"))
	}
	if r := m.LastRun; r != nil {
		fmt.Printf("  Last run:           %s, %s", r.WindowStart.Local().Format("Mon 2 Jan 15:04"), r.Status)
		if len(r.Applied) > 0 {
			fmt.Printf(" (%s)", strings.Join(r.Applied, ", "))
		}
		fmt.Println()
	}
	return nil
}

var weekdays = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

// parseWeekday reads sun..sat, sunday..saturday or 0..6.
func parseWeekday(s string) (int, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if n, err := strconv.Atoi(s); err == nil && n >= 0 && n <= 6 {
		return n, nil
	}
	if len(s) >= 3 {
		if d, ok := weekdays[s[:3]]; ok && strings.HasPrefix(strings.ToLower(time.Weekday(d).String()), s) {
			return d, nil
		}
	}
	return 0, fmt.Errorf("--day takes a day of the week (sun, mon, ... or 0-6), not %q", s)
}

// cloudMaintenanceSet: rowsafe cloud maintenance set [NAME] [--day sun]
// [--hour 3] [--timezone ZONE] | --off [--json]
func cloudMaintenanceSet(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud maintenance set", flag.ContinueOnError)
	day := fs.String("day", "", "the day of the week: sun, mon, ... sat")
	hour := fs.Int("hour", -1, "the hour it starts, 0-23")
	tz := fs.String("timezone", "", "the time zone (IANA, e.g. Europe/Berlin; default: the region's)")
	off := fs.Bool("off", false, "turn the window off (critical fixes still go in once due)")
	on := fs.Bool("on", false, "turn the window on again, as it was")
	asJSON := fs.Bool("json", false, "print JSON")
	s, err := maintenanceServerArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	m, err := c.CloudMaintenance(ctx, s.ID)
	if err != nil {
		return cloudErr(err)
	}
	req := protocol.MaintenanceWindowRequest{Enabled: m.Enabled, Day: m.Day, Hour: m.Hour, Timezone: m.Timezone}
	changed := false
	var ferr error
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "json" || f.Name == "off" {
			return
		}
		changed = true
		switch f.Name {
		case "day":
			req.Day, ferr = parseWeekday(*day)
			req.Enabled = true
		case "hour":
			if *hour < 0 || *hour > 23 {
				ferr = errors.New("--hour takes 0 to 23")
			}
			req.Hour, req.Enabled = *hour, true
		case "timezone":
			if _, err := time.LoadLocation(*tz); *tz != "" && err != nil {
				ferr = fmt.Errorf("unknown time zone %q (use an IANA name like Europe/Berlin)", *tz)
			}
			req.Timezone = *tz
		case "on":
			req.Enabled = true
		}
	})
	if ferr != nil {
		return ferr
	}
	if *off && *on {
		return errors.New("--on or --off, not both")
	}
	if *off {
		req.Enabled, changed = false, true
	}
	if !changed {
		return errors.New("nothing to change: pass --day, --hour, --timezone, --on or --off")
	}
	m, err = c.SetCloudMaintenance(ctx, s.ID, req)
	if err != nil {
		return apiErr(err)
	}
	return showMaintenance(m, *asJSON)
}

// cloudMaintenancePostpone: rowsafe cloud maintenance postpone [NAME] [--json]
func cloudMaintenancePostpone(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud maintenance postpone", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	s, err := maintenanceServerArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	m, err := c.PostponeCloudMaintenance(ctx, s.ID)
	if err != nil {
		return apiErr(err)
	}
	return showMaintenance(m, *asJSON)
}

// cloudMaintenanceApplyNow: rowsafe cloud maintenance apply-now [NAME] [--yes] [--json]
func cloudMaintenanceApplyNow(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud maintenance apply-now", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the server's name")
	asJSON := fs.Bool("json", false, "print JSON")
	s, err := maintenanceServerArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	m, err := c.CloudMaintenance(ctx, s.ID)
	if err != nil {
		return cloudErr(err)
	}
	if len(m.Pending) == 0 {
		return fmt.Errorf("nothing is waiting for a restart on %s: there's nothing to apply", s.Name)
	}
	out := msgOut(*asJSON)
	fmt.Fprintf(out, "Apply now on %s, a Mark first:\n", s.Name)
	for _, p := range m.Pending {
		fmt.Fprintf(out, "  %s (downtime: %s)\n", p.Summary, orText(p.Downtime, "none"))
	}
	if err := confirmTyped(*yes, s.Name); err != nil {
		return err
	}
	if m, err = c.ApplyCloudMaintenanceNow(ctx, s.ID, s.Name); err != nil {
		return fmt.Errorf("not applied: %w", apiErr(err))
	}
	if *asJSON {
		return printJSON(m)
	}
	fmt.Printf("Applying it now; follow it with rowsafe cloud maintenance %s\n", s.Name)
	return nil
}

// cloudDeleteAfter: rowsafe cloud delete-after [NAME] 24h|never [--json]:
// when Rowsafe deletes a clone.
func cloudDeleteAfter(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("cloud delete-after", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var ref, when string
	switch len(pos) {
	case 1:
		when = pos[0]
	case 2:
		ref, when = pos[0], pos[1]
	default:
		return errors.New("usage: rowsafe cloud delete-after [NAME] 24h|never")
	}
	hours := 0
	if v := strings.TrimSpace(when); v != "0" && v != "never" {
		d, err := parseSince(v)
		if err != nil {
			return fmt.Errorf("can't read %q: use e.g. 4h, 2d (at most 30d), or never", v)
		}
		if hours = int(math.Ceil(d.Hours())); hours < 1 || hours > 720 {
			return errors.New("delete-after must be between 1 hour and 30 days, or never")
		}
	}
	s, err := findServer(ctx, c, ref)
	if err != nil {
		return err
	}
	s, err = c.SetCloudDeleteAfter(ctx, s.ID, hours)
	if err != nil {
		return apiErr(err)
	}
	if *asJSON {
		return printJSON(s)
	}
	if s.DeleteAt != nil {
		fmt.Printf("Rowsafe deletes %s at %s.\n", s.Name, s.DeleteAt.Local().Format("Mon 2 Jan 15:04"))
	} else if hours > 0 {
		fmt.Printf("Rowsafe deletes %s %d hours after it's ready.\n", s.Name, hours)
	} else {
		fmt.Printf("%s is kept until you delete it.\n", s.Name)
	}
	return nil
}
