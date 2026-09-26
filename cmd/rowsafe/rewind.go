package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe rewind: restore a copy of a database as it was at any second (or
// a Mark), compare it with production, bring rows back, or rewind the whole
// database in place. Everything runs on the database server; the CLI asks
// the control plane, which queues the agent's tasks, and waits for them.

var rewindSubs = map[string]subcommand{
	"copy":     rewindCopyCmd,
	"compare":  rewindCompareCmd,
	"rows":     rewindRowsCmd,
	"drop":     rewindDropCmd,
	"extend":   rewindExtendCmd,
	"database": rewindDatabaseCmd,
	"undo":     rewindUndoCmd,
	"cleanup":  rewindCleanupCmd,
	"find":     rewindFindCmd, // Find the moment (moment.go)
}

func rewindCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		if run, ok := rewindSubs[args[0]]; ok {
			return run(ctx, c, args[1:])
		}
	}
	return rewindShow(ctx, c, args)
}

// now is the clock for TIME arguments (tests replace it).
var now = time.Now

var agoRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(s|m|min|h|d)\s*ago$`)

// parseRewindTime reads TIME: RFC 3339 ("2026-09-24T14:04:00Z"),
// "2026-09-24 14:04[:05]" or "14:04[:05]" (today) in the local time zone,
// or "10m ago" / "2h ago" / "1d ago" / "1h30m ago".
func parseRewindTime(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			n := now().In(time.Local)
			return time.Date(n.Year(), n.Month(), n.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local), nil
		}
	}
	lower := strings.ToLower(s)
	if m := agoRE.FindStringSubmatch(lower); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		unit := map[string]time.Duration{"s": time.Second, "m": time.Minute, "min": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
		return now().Add(-time.Duration(n * float64(unit))), nil
	}
	if d, ok := strings.CutSuffix(lower, " ago"); ok {
		if dur, err := time.ParseDuration(strings.ReplaceAll(strings.TrimSpace(d), " ", "")); err == nil && dur > 0 {
			return now().Add(-dur), nil
		}
	}
	return time.Time{}, fmt.Errorf("can't read the time %q: use e.g. \"2026-09-24 14:04\" (your time zone), \"14:04\" (today), "+
		"\"10m ago\" or 2026-09-24T12:04:00Z", s)
}

// describeTime: "2026-09-24 14:04:00 CEST (12:04:00 UTC)".
func describeTime(t time.Time) string {
	local := t.In(time.Local)
	s := local.Format("2006-01-02 15:04:05 MST")
	if _, off := local.Zone(); off != 0 {
		s += " (" + t.UTC().Format("15:04:05 UTC") + ")"
	}
	return s
}

// rewindTargetFlags adds --at and --mark.
func rewindTargetFlags(fs *flag.FlagSet) (at, mark *string) {
	return fs.String("at", "", "the point in time: \"2026-09-24 14:04\" (your time zone), \"14:04\", \"10m ago\" or RFC 3339"),
		fs.String("mark", "", "a Mark (restore point) instead of a time")
}

func rewindTarget(at, mark string) (*time.Time, string, string, error) {
	switch {
	case at != "" && mark != "":
		return nil, "", "", errors.New("give --at or --mark, not both")
	case mark != "":
		return nil, mark, "the Mark " + mark, nil
	case at != "":
		t, err := parseRewindTime(at)
		if err != nil {
			return nil, "", "", err
		}
		if t.After(now().Add(time.Minute)) {
			return nil, "", "", fmt.Errorf("%s is in the future", describeTime(t))
		}
		utc := t.UTC()
		return &utc, "", describeTime(t), nil
	}
	return nil, "", "", errors.New("which point? Pass --at TIME (e.g. --at \"14:04\" or --at \"10m ago\") or --mark LABEL")
}

// ---- rowsafe rewind [NAME] ----

func rewindShow(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.RewindInfo(ctx, name)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info)
	}
	fmt.Printf("%s: Rewind\n\n", name)
	if info.Earliest != nil && info.Latest != nil {
		fmt.Printf("Recovery window: any second from %s to %s\n", describeTime(*info.Earliest), describeTime(*info.Latest))
	} else {
		fmt.Println("Recovery window: none yet (it starts with the first backup)")
	}
	if len(info.Marks) > 0 {
		marks := info.Marks
		if len(marks) > 5 {
			marks = marks[:5]
		}
		fmt.Printf("Marks:           %d", len(info.Marks))
		var names []string
		for _, m := range marks {
			names = append(names, m.Name)
		}
		fmt.Printf(" (latest: %s; all: rowsafe marks %s)\n", strings.Join(names, ", "), name)
	}
	fmt.Println()
	if cp := info.Copy; cp != nil {
		printRewindCopy(*cp)
		switch cp.Status {
		case "ready":
			fmt.Printf("  Compare it with production:  rowsafe rewind compare %s [TABLE...]\n", name)
			fmt.Printf("  Bring rows back:             rowsafe rewind rows %s TABLE...\n", name)
			fmt.Printf("  Keep it longer / delete it:  rowsafe rewind extend %s --hours 24 / rowsafe rewind drop %s\n", name, name)
		case "restoring":
			fmt.Printf("  Being restored; follow it with rowsafe rewind %s\n", name)
		}
	} else {
		fmt.Printf("Copy: none. Restore one: rowsafe rewind copy %s --at \"TIME\" (or --mark LABEL)\n", name)
	}
	for _, k := range info.Kept {
		fmt.Println()
		printKept(name, k)
	}
	fmt.Println()
	if info.CanRewindInPlace {
		fmt.Printf("Rewind the whole database in place: rowsafe rewind database %s --at \"TIME\" (asks first)\n", name)
	} else if info.InPlaceReason != "" {
		fmt.Printf("Rewinding the whole database in place isn't available: %s\n", info.InPlaceReason)
	}
	if len(info.Tasks) > 0 {
		fmt.Println("\nRecent rewind tasks:")
		t := newTable("  TASK", "TYPE", "STATUS", "CREATED", "ERROR")
		for _, tk := range info.Tasks {
			t.row("  "+tk.ID, tk.Type, tk.Status, tk.CreatedAt.Local().Format("2006-01-02 15:04"), firstLine(tk.Error, 60))
		}
		t.flush()
	}
	return nil
}

func printRewindCopy(cp protocol.RewindCopy) {
	target := "?"
	if cp.Target.Mark != "" {
		target = "the Mark " + cp.Target.Mark
	} else if cp.Target.Time != nil {
		target = describeTime(*cp.Target.Time)
	}
	fmt.Printf("Copy %s: %s, restored to %s\n", cp.ID, cp.Status, target)
	if cp.RecoveredTo != nil {
		fmt.Printf("  Last change in it:  %s\n", describeTime(*cp.RecoveredTo))
	}
	if cp.SizeBytes > 0 {
		fmt.Printf("  Size:               %s\n", humanBytes(cp.SizeBytes))
	}
	if len(cp.Databases) > 0 {
		var names []string
		for _, d := range cp.Databases {
			names = append(names, d.Name)
		}
		fmt.Printf("  Databases:          %s\n", strings.Join(names, ", "))
	}
	if !cp.Expires.IsZero() {
		fmt.Printf("  Deleted by itself:  %s\n", describeTime(cp.Expires))
	}
	if cp.Error != "" {
		fmt.Printf("  Error:              %s\n", cp.Error)
	}
}

func printKept(name string, k protocol.RewindKept) {
	until := "until you delete it"
	if k.Expires != nil {
		until = "until " + describeTime(*k.Expires)
	}
	switch k.Status {
	case protocol.RewindKeptBefore:
		fmt.Printf("Rewound in place (%s): the data from before the rewind (%s) is kept %s.\n", k.RewindID, humanBytes(k.SizeBytes), until)
		fmt.Printf("  Undo the rewind:          rowsafe rewind undo %s\n", name)
	case protocol.RewindKeptAfterUndo:
		fmt.Printf("Rewind %s was undone: the rewound data (%s) is kept %s.\n", k.RewindID, humanBytes(k.SizeBytes), until)
	default:
		fmt.Printf("Rewind %s: %s\n", k.RewindID, k.Status)
		return
	}
	fmt.Printf("  Delete it now (frees disk): rowsafe rewind cleanup %s\n", name)
}

// readyCopy returns the database's copy, which must be ready.
func readyCopy(ctx context.Context, c *client.Client, name string) (protocol.RewindInfo, *protocol.RewindCopy, error) {
	info, err := c.RewindInfo(ctx, name)
	if err != nil {
		return info, nil, err
	}
	switch {
	case info.Copy == nil:
		return info, nil, fmt.Errorf("%s has no copy. Restore one first: rowsafe rewind copy %s --at \"TIME\"", name, name)
	case info.Copy.Status == "restoring":
		return info, nil, fmt.Errorf("the copy of %s is still being restored; try again when `rowsafe rewind %s` says it is ready", name, name)
	case info.Copy.Status != "ready":
		return info, nil, fmt.Errorf("the copy of %s is %s. Restore a new one: rowsafe rewind copy %s --at \"TIME\"", name, info.Copy.Status, name)
	}
	return info, info.Copy, nil
}

// waitRewindTasks waits for each task in order, saying what happens, and
// returns the last one.
func waitRewindTasks(ctx context.Context, c *client.Client, tasks []protocol.TaskView) (protocol.TaskView, error) {
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
				fmt.Fprintf(os.Stderr, "Waiting for the agent to start %s (task %s)...\n", rewindTaskName(v.Type), v.ID)
			case protocol.StatusRunning:
				fmt.Fprintf(os.Stderr, "%s...\n", rewindTaskDoing(v.Type))
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
			fmt.Printf("%s didn't work: %s\n", capitalize(rewindTaskName(done.Type)), msg)
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

func rewindTaskName(typ string) string {
	switch typ {
	case protocol.TaskRestorePoint:
		return "a Mark first"
	case protocol.TaskRewindCopy:
		return "the copy"
	case protocol.TaskRewindDrop:
		return "deleting the copy"
	case protocol.TaskRewindCompare:
		return "the comparison"
	case protocol.TaskRewindRows:
		return "bringing back rows"
	case protocol.TaskRewindInPlace:
		return "the rewind"
	case protocol.TaskRewindUndo:
		return "the undo"
	case protocol.TaskRewindCleanup:
		return "deleting the kept data"
	}
	return typ
}

func rewindTaskDoing(typ string) string {
	switch typ {
	case protocol.TaskRestorePoint:
		return "Saving a Mark"
	case protocol.TaskRewindCopy:
		return "Restoring the copy (this takes about as long as a restore test)"
	case protocol.TaskRewindCompare:
		return "Comparing"
	case protocol.TaskRewindRows:
		return "Bringing rows back"
	case protocol.TaskRewindInPlace:
		return "Rewinding: PostgreSQL is stopped until it's done"
	case protocol.TaskRewindUndo:
		return "Undoing the rewind: PostgreSQL is stopped for a moment"
	}
	return "Running"
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---- rowsafe rewind copy ----

func rewindCopyCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind copy", flag.ContinueOnError)
	at, mark := rewindTargetFlags(fs)
	hours := fs.Int("hours", 24, "how long to keep the copy (at most 168)")
	noWait := fs.Bool("no-wait", false, "return once the copy is queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, markName, what, err := rewindTarget(*at, *mark)
	if err != nil {
		return err
	}
	if *hours < 1 || *hours > 168 {
		return errors.New("--hours must be between 1 and 168 (7 days)")
	}
	resp, err := c.CreateRewindCopy(ctx, name, protocol.CreateRewindCopyRequest{Time: t, Mark: markName, Hours: *hours})
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("Restoring a copy of %s as it was at %s, next to production (it never touches production).\n", name, what)
	if *noWait {
		fmt.Printf("Queued. Follow it with: rowsafe rewind %s\n", name)
		return nil
	}
	done, err := waitRewindTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.RewindCopyResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "The copy is ready."))
	fmt.Printf("\nNext: rowsafe rewind compare %s    (which rows differ from production)\n", name)
	return nil
}

// ---- rowsafe rewind compare ----

// tableArgs reads TABLE arguments: "schema.table" or "table" in the only
// database of the copy (or --db), or "db:schema.table".
func tableArgs(pos []string, db string, cp protocol.RewindCopy) ([]protocol.RewindTable, error) {
	var out []protocol.RewindTable
	for _, p := range pos {
		d, table, ok := strings.Cut(p, ":")
		if !ok {
			d, table = db, p
		}
		if d == "" {
			var user []string
			for _, x := range cp.Databases {
				if x.Name != "postgres" && !strings.HasPrefix(x.Name, "template") {
					user = append(user, x.Name)
				}
			}
			if len(user) != 1 {
				return nil, fmt.Errorf("which PostgreSQL database is %s in? The copy has %s; write DB:%s or pass --db DB",
					p, strings.Join(user, ", "), p)
			}
			d = user[0]
		}
		if table == "" {
			return nil, fmt.Errorf("no table in %q", p)
		}
		out = append(out, protocol.RewindTable{DB: d, Table: table})
	}
	return out, nil
}

// splitNameAndTables takes an optional NAME before TABLE...: the first
// argument is the database when it names one.
func splitNameAndTables(ctx context.Context, c *client.Client, pos []string) (string, []string, error) {
	if len(pos) > 0 {
		dbs, err := c.Databases(ctx)
		if err != nil {
			return "", nil, err
		}
		if slices.ContainsFunc(dbs, func(d protocol.Database) bool { return d.Name == pos[0] || d.ID == pos[0] }) {
			return pos[0], pos[1:], nil
		}
	}
	name, err := resolveDatabase(ctx, c, "")
	return name, pos, err
}

func rewindCompareCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind compare", flag.ContinueOnError)
	db := fs.String("db", "", "the PostgreSQL database the tables are in (when the copy has several)")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	name, tablesArg, err := splitNameAndTables(ctx, c, pos)
	if err != nil {
		return err
	}
	_, cp, err := readyCopy(ctx, c, name)
	if err != nil {
		return err
	}
	tables, err := tableArgs(tablesArg, *db, *cp)
	if err != nil {
		return err
	}
	resp, err := c.CompareRewindCopy(ctx, name, cp.ID, tables)
	if err != nil {
		return apiErr(err)
	}
	done, err := waitRewindTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.RewindCompareResult
	_ = json.Unmarshal(done.Result, &r)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	printCompare(name, r)
	return nil
}

func printCompare(name string, r protocol.RewindCompareResult) {
	t := newTable("TABLE", "MISSING IN PRODUCTION", "CHANGED", "ONLY IN PRODUCTION", "RELATED")
	var skipped []protocol.RewindTableDiff
	var bring []string
	multiDB := false
	for _, d := range r.Tables {
		if d.DB != r.Tables[0].DB {
			multiDB = true
		}
	}
	label := func(x protocol.RewindTable) string {
		if multiDB {
			return x.DB + ":" + x.Table
		}
		return x.Table
	}
	for _, d := range r.Tables {
		if d.Skipped != "" {
			skipped = append(skipped, d)
			continue
		}
		var rel []string
		for _, x := range d.Related {
			rel = append(rel, label(x))
		}
		t.row(label(d.RewindTable), fmt.Sprint(d.MissingInProduction), fmt.Sprint(d.Changed), fmt.Sprint(d.OnlyInProduction), orDash(strings.Join(rel, ", ")))
		if d.MissingInProduction > 0 || d.Changed > 0 {
			bring = append(bring, label(d.RewindTable))
		}
	}
	t.flush()
	for _, d := range r.Tables {
		if d.Skipped == "" && d.Note != "" {
			fmt.Printf("  %s: %s\n", label(d.RewindTable), d.Note)
		}
	}
	if len(skipped) > 0 {
		fmt.Println("\nNot compared:")
		for _, d := range skipped {
			fmt.Printf("  %s: %s\n", label(d.RewindTable), d.Skipped)
		}
	}
	fmt.Printf("\n%s\n", orText(r.Summary, "Done."))
	if len(bring) > 0 {
		fmt.Printf("\nBring the missing rows back: rowsafe rewind rows %s %s\n", name, strings.Join(bring, " "))
		fmt.Println("(add --include-changed to also set changed rows back; tables listed as related are linked by foreign keys)")
	}
}

// ---- rowsafe rewind rows ----

func rewindRowsCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind rows", flag.ContinueOnError)
	db := fs.String("db", "", "the PostgreSQL database the tables are in (when the copy has several)")
	changed := fs.Bool("include-changed", false, "also set rows that changed since back to the copy's values")
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	name, tablesArg, err := splitNameAndTables(ctx, c, pos)
	if err != nil {
		return err
	}
	if len(tablesArg) == 0 {
		return fmt.Errorf("which tables? rowsafe rewind rows %s TABLE... (see rowsafe rewind compare %s)", name, name)
	}
	_, cp, err := readyCopy(ctx, c, name)
	if err != nil {
		return err
	}
	tables, err := tableArgs(tablesArg, *db, *cp)
	if err != nil {
		return err
	}
	var names []string
	for _, t := range tables {
		names = append(names, t.Table)
	}
	fmt.Printf("%s: bring back the rows that are missing in production in %s, from the copy", name, strings.Join(names, ", "))
	if cp.Target.Time != nil {
		fmt.Printf(" (%s)", describeTime(*cp.Target.Time))
	} else if cp.Target.Mark != "" {
		fmt.Printf(" (the Mark %s)", cp.Target.Mark)
	}
	fmt.Println(".")
	if *changed {
		fmt.Println("Rows that changed since are also set back to the copy's values.")
	} else {
		fmt.Println("Rows that exist in production are left as they are (--include-changed sets changed ones back).")
	}
	fmt.Println("Rowsafe saves a Mark first. Triggers don't fire for the rows brought back; rows added since stay.")
	if !*yes {
		fmt.Printf("Type the database name (%s) to go ahead: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.RestoreRows(ctx, name, cp.ID, protocol.RewindRowsRequest{Tables: tables, IncludeChanged: *changed, Confirm: name})
	if err != nil {
		return apiErr(err)
	}
	done, err := waitRewindTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.RewindRowsResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Done."))
	return nil
}

// ---- rowsafe rewind drop / extend ----

func rewindDropCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind drop", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.RewindInfo(ctx, name)
	if err != nil {
		return err
	}
	if info.Copy == nil {
		fmt.Printf("%s has no copy.\n", name)
		return nil
	}
	if !*yes {
		fmt.Printf("Delete the copy of %s (%s)? Production isn't touched. [y/N] ", name, humanBytes(info.Copy.SizeBytes))
		if a := readLine(); !strings.EqualFold(a, "y") && !strings.EqualFold(a, "yes") {
			return errors.New("cancelled")
		}
	}
	resp, err := c.DeleteRewindCopy(ctx, name, info.Copy.ID)
	if err != nil {
		return apiErr(err)
	}
	done, err := waitRewindTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.RewindDropResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Deleted the copy."))
	return nil
}

func rewindExtendCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind extend", flag.ContinueOnError)
	hours := fs.Int("hours", 24, "keep the copy this many hours from now (at most 168)")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	if *hours < 1 || *hours > 168 {
		return errors.New("--hours must be between 1 and 168 (7 days)")
	}
	_, cp, err := readyCopy(ctx, c, name)
	if err != nil {
		return err
	}
	out, err := c.ExtendRewindCopy(ctx, name, cp.ID, *hours)
	if err != nil {
		return apiErr(err)
	}
	fmt.Printf("The copy of %s is now kept until %s.\n", name, describeTime(out.Expires))
	return nil
}

// ---- rowsafe rewind database / undo / cleanup ----

func rewindDatabaseCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind database", flag.ContinueOnError)
	at, mark := rewindTargetFlags(fs)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, markName, what, err := rewindTarget(*at, *mark)
	if err != nil {
		return err
	}
	info, err := c.RewindInfo(ctx, name)
	if err != nil {
		return err
	}
	if !info.CanRewindInPlace && info.InPlaceReason != "" {
		return fmt.Errorf("rewinding %s in place isn't available: %s", name, info.InPlaceReason)
	}
	fmt.Printf("Rewind the whole database %s to %s.\n\n", name, what)
	fmt.Printf("  Everything written after %s will be removed from the live database.\n", what)
	fmt.Println("  PostgreSQL is stopped while Rowsafe restores it: apps can't connect until it's done.")
	fmt.Println("  The current data is kept aside for 7 days so you can undo (rowsafe rewind undo).")
	fmt.Println("  Rowsafe saves a Mark first. To look at old data without touching production, use rowsafe rewind copy instead.")
	if !*yes {
		fmt.Printf("\nType the database name (%s) to rewind it: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.RewindInPlace(ctx, name, protocol.RewindInPlaceRequest{Time: t, Mark: markName, Confirm: name})
	if err != nil {
		return apiErr(err)
	}
	done, err := waitRewindTasks(ctx, c, resp.Tasks)
	var r protocol.RewindInPlaceResult
	_ = json.Unmarshal(done.Result, &r)
	if err != nil {
		if r.Summary != "" && !strings.Contains(done.Error, r.Summary) {
			fmt.Println(r.Summary)
		}
		return err
	}
	fmt.Println(orText(r.Summary, "Rewound."))
	for _, w := range r.Warnings {
		fmt.Printf("  Note: %s\n", w)
	}
	fmt.Printf("\nUndo it: rowsafe rewind undo %s    Delete the kept data: rowsafe rewind cleanup %s\n", name, name)
	return nil
}

// latestKept is the kept data an undo applies to.
func latestKept(info protocol.RewindInfo) *protocol.RewindKept {
	var out *protocol.RewindKept
	for i := range info.Kept {
		k := &info.Kept[i]
		if out == nil || k.CreatedAt.After(out.CreatedAt) {
			out = k
		}
	}
	return out
}

func rewindUndoCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind undo", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask; confirms with the database's name")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.RewindInfo(ctx, name)
	if err != nil {
		return err
	}
	k := latestKept(info)
	if k == nil || k.Status != protocol.RewindKeptBefore {
		return fmt.Errorf("there is no rewind of %s to undo", name)
	}
	fmt.Printf("Undo the rewind of %s: put the data from before the rewind back.\n", name)
	fmt.Println("  Anything written since the rewind is kept aside (not deleted), and PostgreSQL is stopped for a moment.")
	if !*yes {
		fmt.Printf("Type the database name (%s) to undo the rewind: ", name)
		if readLine() != name {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.UndoRewind(ctx, name, k.RewindID, name)
	if err != nil {
		return apiErr(err)
	}
	done, err := waitRewindTasks(ctx, c, resp.Tasks)
	if err != nil {
		return err
	}
	var r protocol.RewindUndoResult
	_ = json.Unmarshal(done.Result, &r)
	fmt.Println(orText(r.Summary, "Undone."))
	return nil
}

func rewindCleanupCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind cleanup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	info, err := c.RewindInfo(ctx, name)
	if err != nil {
		return err
	}
	if len(info.Kept) == 0 {
		fmt.Printf("%s has no data kept aside by a rewind.\n", name)
		return nil
	}
	var total int64
	for _, k := range info.Kept {
		total += k.SizeBytes
	}
	if !*yes {
		fmt.Printf("Delete the data %s kept aside by rewinds (%s)? The rewind can't be undone after this. [y/N] ", name, humanBytes(total))
		if a := readLine(); !strings.EqualFold(a, "y") && !strings.EqualFold(a, "yes") {
			return errors.New("cancelled")
		}
	}
	for _, k := range info.Kept {
		resp, err := c.CleanupRewind(ctx, name, k.RewindID)
		if err != nil {
			return apiErr(err)
		}
		done, err := waitRewindTasks(ctx, c, resp.Tasks)
		if err != nil {
			return err
		}
		var r protocol.RewindCleanupResult
		_ = json.Unmarshal(done.Result, &r)
		fmt.Println(orText(r.Summary, "Deleted."))
	}
	return nil
}

// apiErr shows the control plane's reason as is.
func apiErr(err error) error {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return errors.New(ae.Msg)
	}
	return err
}
