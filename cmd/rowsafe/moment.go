package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe rewind find: when were rows deleted (changed, a table emptied or
// dropped)? The agent reads the change log in your storage on the server
// and lists the biggest changes with their exact times, so you don't have
// to guess the point to rewind to.

// csvList is a repeatable, comma-separated flag.
type csvList []string

func (s *csvList) String() string { return strings.Join(*s, ",") }
func (s *csvList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

var sinceRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(m|min|h|d|w)$`)

// parseSince reads "30m", "24h", "2d", "1w" or a Go duration ("1h30m").
func parseSince(s string) (time.Duration, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if m := sinceRE.FindStringSubmatch(s); m != nil {
		n, _ := strconv.ParseFloat(m[1], 64)
		unit := map[string]time.Duration{"m": time.Minute, "min": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
		return time.Duration(n * float64(unit)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("can't read --since %q: use e.g. 30m, 6h, 2d", s)
	}
	return d, nil
}

func rewindFindCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("rewind find", flag.ContinueOnError)
	var tables, kinds csvList
	fs.Var(&tables, "table", "only this table (schema.table or table; repeat or comma-separate for several)")
	fs.Var(&kinds, "kind", "only these kinds: delete, update, truncate, drop (comma-separated)")
	db := fs.String("db", "", "only this PostgreSQL database (when the server has several)")
	since := fs.String("since", "", "how far back to search, e.g. 30m, 6h, 2d (default 24h, at most 7d)")
	from := fs.String("from", "", "search from this time: \"2026-09-24 14:00\" (your time zone), \"14:00\", \"2h ago\" or RFC 3339")
	to := fs.String("to", "", "search up to this time (default now)")
	minRows := fs.Int64("min-rows", 0, "leave out transactions that changed fewer rows")
	limit := fs.Int("limit", 0, "how many transactions to list, biggest first (default 100)")
	asJSON := fs.Bool("json", false, "print JSON")
	noWait := fs.Bool("no-wait", false, "queue the search and print its task ID")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	req := protocol.FindMomentRequest{DB: *db, Tables: tables, Kinds: kinds, MinRows: *minRows, Limit: *limit}
	if *to != "" {
		t, err := parseRewindTime(*to)
		if err != nil {
			return err
		}
		t = t.UTC()
		req.To = &t
	}
	switch {
	case *from != "" && *since != "":
		return errors.New("give --from or --since, not both")
	case *from != "":
		t, err := parseRewindTime(*from)
		if err != nil {
			return err
		}
		t = t.UTC()
		req.From = &t
	case *since != "":
		d, err := parseSince(*since)
		if err != nil {
			return err
		}
		end := now()
		if req.To != nil {
			end = *req.To
		}
		t := end.Add(-d).UTC()
		req.From = &t
	}
	task, err := c.FindMoment(ctx, name, req)
	if err != nil {
		return apiErr(err)
	}
	if *noWait {
		fmt.Printf("Searching (task %s). Follow it with: rowsafe task %s\n", task.ID, task.ID)
		return nil
	}
	if !*asJSON {
		what := "big deletes, updates, TRUNCATEs and DROPs"
		if len(tables) > 0 {
			what += " in " + strings.Join(tables, ", ")
		}
		fmt.Fprintf(os.Stderr, "Looking for %s in %s's change log...\n", what, name)
	}
	done, err := c.WaitTask(ctx, task.ID, func(v protocol.TaskView) {})
	if err != nil {
		return err
	}
	if done.Status != protocol.StatusSucceeded {
		msg := orText(done.Error, "the search ended as "+done.Status)
		fmt.Printf("The search didn't work: %s\n", msg)
		return exitError(1)
	}
	var r protocol.FindMomentResult
	if err := json.Unmarshal(done.Result, &r); err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	printMoments(name, r)
	return nil
}

// justBefore is the time to rewind to so a transaction is left out: one
// microsecond before it committed (PostgreSQL's commit times have
// microseconds; recovery stops after the last commit at or before it).
func justBefore(m protocol.Moment) time.Time { return m.Time.Add(-time.Microsecond) }

func printMoments(name string, r protocol.FindMomentResult) {
	fmt.Printf("Searched %s to %s.\n", describeTime(r.From), describeTime(r.To))
	for _, n := range r.Notes {
		fmt.Println("Note: " + n)
	}
	if len(r.Moments) == 0 {
		fmt.Println(r.Summary)
		return
	}
	fmt.Println()
	multiDB := false
	for _, m := range r.Moments {
		if m.DB != r.Moments[0].DB {
			multiDB = true
		}
	}
	t := newTable("WHEN (YOUR TIME ZONE)", "WHAT", "TRANSACTION")
	for _, m := range r.Moments {
		what := m.Summary
		if multiDB {
			what += " (database " + m.DB + ")"
		}
		t.row(m.Time.In(time.Local).Format("2006-01-02 15:04:05 MST"), what, strconv.FormatUint(uint64(m.XID), 10))
	}
	t.flush()
	fmt.Println()
	fmt.Println(r.Summary)
	if r.Truncated {
		fmt.Printf("Only the %d biggest are listed; narrow it down with --table, --kind or --since.\n", len(r.Moments))
	}
	big := r.Moments[0]
	for _, m := range r.Moments {
		if momentBigger(m, big) {
			big = m
		}
	}
	fmt.Println()
	fmt.Println("Rewind to just before the biggest one (a copy next to production; it never touches it):")
	fmt.Printf("  rowsafe rewind copy %s --at %s\n", name, justBefore(big).UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
	fmt.Println("PostgreSQL's change log doesn't record who made a change, so Rowsafe can't say which user or app it was.")
}

func momentBigger(a, b protocol.Moment) bool {
	ddl := func(m protocol.Moment) bool {
		return m.Kind == protocol.MomentTruncate || m.Kind == protocol.MomentDrop
	}
	if ddl(a) != ddl(b) {
		return ddl(a)
	}
	return a.Rows > b.Rows
}
