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

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe fix: apply what Rowsafe can do about a database's health findings
// (FindingFix). Only fixes the control plane proposes run, by their ids;
// the control plane checks them again and queues the work with its own
// parameters, and the agent checks once more before running it.

// stdinIsTerminal reports whether the user can answer questions (tests
// replace it).
var stdinIsTerminal = func() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// readLine reads one line from stdin without buffering past it, so several
// questions can read from the same input.
func readLine() string {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				break
			}
			b.WriteByte(buf[0])
		}
		if err != nil {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// fixChoice is one fix of one finding.
type fixChoice struct {
	finding protocol.Finding
	fix     protocol.FindingFix
	n       int // number in the list; 0 when not available
}

// fixChoices lists the fixes of h's findings in order, numbering the
// available ones from 1.
func fixChoices(h protocol.DatabaseHealth) []fixChoice {
	var out []fixChoice
	n := 0
	for _, f := range h.Findings {
		for _, fx := range f.Fixes {
			c := fixChoice{finding: f, fix: fx}
			if fx.Available {
				n++
				c.n = n
			}
			out = append(out, c)
		}
	}
	return out
}

func fixCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "don't ask for confirmation")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	db, ids, err := fixArgs(ctx, c, pos)
	if err != nil {
		return err
	}
	h, err := c.Health(ctx, db)
	if err != nil {
		return err
	}
	withRecommendations(ctx, c, &h) // advisor (recommendations.go)
	choices := fixChoices(h)

	var pick *fixChoice
	switch {
	case len(ids) == 0:
		printFixes(h, choices)
		if !hasAvailable(choices) || *yes || !stdinIsTerminal() {
			return nil
		}
		fmt.Print("\nWhich one? (number, or Enter to leave it) ")
		answer := readLine()
		if answer == "" {
			return nil
		}
		if pick, err = pickByNumber(choices, answer); err != nil {
			return err
		}
	default:
		if pick, err = pickByID(h, choices, ids); err != nil {
			return err
		}
	}
	if !pick.fix.Available {
		return fmt.Errorf("%q can't run now: %s", pick.fix.Label, orText(pick.fix.Reason, "Rowsafe didn't say why"))
	}
	return applyFix(ctx, c, h, *pick, *yes)
}

// fixArgs splits [NAME] [FINDING_ID|NUMBER] [FIX_ID]. With one or two
// arguments, the first is the database if it names one.
func fixArgs(ctx context.Context, c *client.Client, pos []string) (db string, ids []string, err error) {
	switch len(pos) {
	case 0:
	case 1, 2:
		dbs, err := c.Databases(ctx)
		if err != nil {
			return "", nil, err
		}
		for _, d := range dbs {
			if d.Name == pos[0] || d.ID == pos[0] {
				db = pos[0]
			}
		}
		ids = pos
		if db != "" {
			ids = pos[1:]
		}
	case 3:
		db, ids = pos[0], pos[1:]
	default:
		return "", nil, errors.New("expected [NAME] [FINDING] [FIX]")
	}
	db, err = resolveDatabase(ctx, c, db)
	return db, ids, err
}

func hasAvailable(choices []fixChoice) bool {
	for _, c := range choices {
		if c.n > 0 {
			return true
		}
	}
	return false
}

func pickByNumber(choices []fixChoice, s string) (*fixChoice, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return nil, fmt.Errorf("%q is not one of the numbers listed", s)
	}
	for i := range choices {
		if choices[i].n == n {
			return &choices[i], nil
		}
	}
	return nil, fmt.Errorf("there is no fix number %d (the list may have changed; run rowsafe fix again)", n)
}

// pickByID finds FINDING [FIX], or a list number.
func pickByID(h protocol.DatabaseHealth, choices []fixChoice, ids []string) (*fixChoice, error) {
	if len(ids) == 1 {
		if _, err := strconv.Atoi(ids[0]); err == nil {
			return pickByNumber(choices, ids[0])
		}
	}
	var finding *protocol.Finding
	for i := range h.Findings {
		if h.Findings[i].ID == ids[0] {
			finding = &h.Findings[i]
		}
	}
	if finding == nil {
		return nil, fmt.Errorf("%s has no finding %q now (it may have been resolved); run `rowsafe fix %s` to see what can be fixed",
			h.Database, ids[0], h.Database)
	}
	var mine []fixChoice
	for _, c := range choices {
		if c.finding.ID == finding.ID {
			mine = append(mine, c)
		}
	}
	if len(mine) == 0 {
		return nil, fmt.Errorf("Rowsafe can't fix %q by itself: %s", finding.Title, finding.Action)
	}
	if len(ids) == 2 {
		for i := range mine {
			if mine[i].fix.ID == ids[1] {
				return &mine[i], nil
			}
		}
		return nil, fmt.Errorf("%q has no fix %q now; its fixes: %s", finding.Title, ids[1], fixIDs(mine))
	}
	var avail []int
	for i, c := range mine {
		if c.fix.Available {
			avail = append(avail, i)
		}
	}
	switch len(avail) {
	case 0:
		return &mine[0], nil // explains why it can't run
	case 1:
		return &mine[avail[0]], nil
	}
	if stdinIsTerminal() {
		printFixes(protocol.DatabaseHealth{Database: h.Database, Findings: []protocol.Finding{*finding}}, mine)
		fmt.Print("\nWhich one? (number, or Enter to leave it) ")
		answer := readLine()
		if answer == "" {
			return nil, errors.New("nothing was changed")
		}
		return pickByNumber(mine, answer)
	}
	return nil, fmt.Errorf("%q has several fixes; name one: %s", finding.Title, fixIDs(mine))
}

func fixIDs(cs []fixChoice) string {
	var ids []string
	for _, c := range cs {
		ids = append(ids, fmt.Sprintf("%s (%s)", c.fix.ID, c.fix.Label))
	}
	return strings.Join(ids, ", ")
}

func printFixes(h protocol.DatabaseHealth, choices []fixChoice) {
	if len(choices) == 0 {
		if len(h.Findings) == 0 {
			fmt.Printf("%s: nothing to fix, no problems found.\n", h.Database)
		} else {
			fmt.Printf("%s: nothing Rowsafe can fix by itself right now. What to do about each finding: rowsafe pulse %s\n", h.Database, h.Database)
		}
		return
	}
	withFixes := 0
	for _, f := range h.Findings {
		if len(f.Fixes) > 0 {
			withFixes++
		}
	}
	fmt.Printf("%s: Rowsafe can fix %d of %d %s\n", h.Database, withFixes, len(h.Findings), plural(len(h.Findings), "finding", "findings"))
	last := ""
	for _, c := range choices {
		if c.finding.ID != last {
			last = c.finding.ID
			mark := map[string]string{protocol.SeverityCritical: "!!", protocol.SeverityWarning: "! ", protocol.SeverityInfo: "- "}[c.finding.Severity]
			fmt.Printf("\n%s %s  (%s)\n", orText(mark, "- "), c.finding.Title, c.finding.ID)
		}
		num := " -"
		if c.n > 0 {
			num = fmt.Sprintf("%2d", c.n)
		}
		var notes []string
		if c.fix.Confirm != "" {
			notes = append(notes, "asks you to confirm")
		}
		if c.fix.MarkFirst {
			notes = append(notes, "saves a Mark first")
		}
		line := fmt.Sprintf("  %s) %s", num, c.fix.Label)
		if len(notes) > 0 {
			line += "  [" + strings.Join(notes, ", ") + "]"
		}
		fmt.Println(line)
		if c.fix.Description != "" {
			fmt.Printf("      %s\n", c.fix.Description)
		}
		if !c.fix.Available {
			fmt.Printf("      Not available now: %s\n", orText(c.fix.Reason, "Rowsafe didn't say why."))
		}
	}
	if hasAvailable(choices) {
		fmt.Printf("\nApply one: rowsafe fix %s NUMBER   (or: rowsafe fix %s FINDING FIX)\n", h.Database, h.Database)
	}
}

func applyFix(ctx context.Context, c *client.Client, h protocol.DatabaseHealth, pick fixChoice, yes bool) error {
	fx := pick.fix
	fmt.Printf("%s: %s\n", h.Database, fx.Label)
	if fx.Description != "" {
		fmt.Println(fx.Description)
	}
	if fx.MarkFirst {
		fmt.Println("Rowsafe saves a Mark (restore point) first, so you can go back to just before it.")
	}
	confirmName := ""
	if fx.Confirm != "" {
		confirmName = h.Database
		fmt.Printf("\nWarning: %s\n", fx.Confirm)
		if !yes {
			fmt.Printf("Type the database name (%s) to go ahead: ", h.Database)
			if readLine() != h.Database {
				return errors.New("cancelled; nothing was changed")
			}
		}
	} else if !yes {
		fmt.Print("Apply this fix now? [y/N] ")
		if a := readLine(); !strings.EqualFold(a, "y") && !strings.EqualFold(a, "yes") {
			return errors.New("cancelled; nothing was changed")
		}
	}
	resp, err := c.ApplyFix(ctx, h.Database, pick.finding.ID, fx.ID, confirmName)
	var ae *client.APIError
	if errors.As(err, &ae) {
		return fmt.Errorf("not applied: %s", ae.Msg)
	}
	if err != nil {
		return err
	}
	if len(resp.Tasks) == 0 {
		fmt.Println("Done.")
		return nil
	}
	for _, t := range resp.Tasks {
		if err := waitFixTask(ctx, c, t, h.Database); err != nil {
			return err
		}
	}
	return nil
}

// waitFixTask waits for one task of a fix and says how it went.
func waitFixTask(ctx context.Context, c *client.Client, t protocol.TaskView, db string) error {
	switch t.Type {
	case protocol.TaskMaintenance, protocol.TaskRestorePoint, protocol.TaskSecurityFix:
	default:
		// Backups, restore tests, checks, setup and restarts report as
		// their own commands do.
		fmt.Println()
		return waitAndReport(ctx, c, t.ID, db)
	}
	what := "the fix"
	if t.Type == protocol.TaskRestorePoint {
		what = "a Mark first"
	}
	last := ""
	done, err := c.WaitTask(ctx, t.ID, func(v protocol.TaskView) {
		if v.Status == last {
			return
		}
		last = v.Status
		switch v.Status {
		case protocol.StatusQueued:
			fmt.Fprintf(os.Stderr, "Waiting for the agent to start %s (task %s)...\n", what, v.ID)
		case protocol.StatusRunning:
			if t.Type == protocol.TaskRestorePoint {
				fmt.Fprintln(os.Stderr, "Saving a Mark...")
			} else {
				fmt.Fprintln(os.Stderr, "Running...")
			}
		}
	})
	if err != nil {
		return err
	}
	if t.Type == protocol.TaskRestorePoint {
		var r protocol.RestorePointResult
		_ = json.Unmarshal(done.Result, &r)
		if done.Status != protocol.StatusSucceeded {
			fmt.Printf("The Mark could not be saved: %s\n", orText(done.Error, done.Status))
			return exitError(1)
		}
		fmt.Printf("Mark saved: %s\n", orText(r.Name, "done"))
		return nil
	}
	var r protocol.MaintenanceResult
	_ = json.Unmarshal(done.Result, &r)
	if done.Status != protocol.StatusSucceeded {
		msg := orText(done.Error, "the task ended as "+done.Status)
		if done.Status == protocol.StatusLost {
			msg = "the agent stopped reporting while it ran (it may have restarted); check with `rowsafe pulse " + db + "`"
		}
		fmt.Printf("The fix didn't work: %s\n", msg)
		printDetails(r.Details)
		return exitError(1)
	}
	fmt.Println(orText(r.Summary, "Done."))
	printDetails(r.Details)
	return nil
}

func printDetails(details []string) {
	for _, d := range details {
		fmt.Printf("  %s\n", d)
	}
}

func orText(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// firstAvailableFix is a finding's best fix that can run now.
func firstAvailableFix(f protocol.Finding) *protocol.FindingFix {
	for i := range f.Fixes {
		if f.Fixes[i].Available {
			return &f.Fixes[i]
		}
	}
	return nil
}
