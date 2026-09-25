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

// rowsafe recommendations: indexes the index advisor proved on a copy of the
// database. Creating one is a fix: `rowsafe fix NAME index_recommendation`.

func recommendationsCmd(ctx context.Context, c *client.Client, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "find":
			return recommendationsFind(ctx, c, args[1:])
		case "schedule":
			return recommendationsSchedule(ctx, c, args[1:])
		}
	}
	fs := flag.NewFlagSet("recommendations", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	all := fs.Bool("all", false, "also list created, dismissed and no longer needed ones")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	v, err := c.IndexRecommendations(ctx, name)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(v)
	}
	printIndexAdvisor(name, v, *all)
	return nil
}

func printIndexAdvisor(name string, v protocol.IndexAdvisorView, all bool) {
	if !v.Available {
		fmt.Printf("No index recommendations for %s: %s\n", name, v.Reason)
		return
	}
	var open, other []protocol.IndexRecommendationView
	for _, r := range v.Recommendations {
		if r.Status == protocol.IndexRecOpen {
			open = append(open, r)
		} else {
			other = append(other, r)
		}
	}
	switch {
	case len(open) == 0 && v.LastRun == nil:
		fmt.Printf("Rowsafe hasn't looked for index recommendations for %s yet.\n", name)
	case len(open) == 0:
		fmt.Printf("No index recommendations for %s: no new index would make its busiest queries much faster.\n", name)
	default:
		fmt.Printf("Index recommendations for %s, each tested on a copy of the database:\n", name)
	}
	for i, r := range open {
		fmt.Printf("\n%d. %s\n", i+1, r.Title)
		fmt.Printf("   %s\n", r.Explanation)
		fmt.Printf("   Index: %s\n", r.Definition)
		for _, s := range r.Statements[:min(len(r.Statements), 3)] {
			fmt.Printf("   - %s faster: %s\n", protocol.TimesFaster(s.Speedup), firstLine(s.Query, 100))
		}
		if r.Creating != nil {
			fmt.Printf("   Being created now (task %s).\n", r.Creating.ID)
		} else if r.FixID != "" {
			fmt.Printf("   Create it: rowsafe fix %s %s %s\n", name, r.FindingID, r.FixID)
		}
	}
	if all {
		for _, r := range other {
			fmt.Printf("\n- [%s] %s\n", r.Status, r.Title)
			if r.Outcome != nil {
				fmt.Printf("  %s\n", r.Outcome.Summary)
			} else if r.Usage != nil {
				fmt.Printf("  Used %d times so far (%s).\n", r.Usage.Scans, humanBytes(r.Usage.SizeBytes))
			}
		}
	} else if len(other) > 0 {
		fmt.Printf("\n%d more (created, dismissed or no longer needed): rowsafe recommendations %s --all\n", len(other), name)
	}
	fmt.Println()
	if v.LastRun != nil {
		when := ago(v.LastRun.FinishedAt)
		if v.LastRun.Summary != "" {
			fmt.Printf("Last check %s: %s\n", when, v.LastRun.Summary)
		} else if v.LastRun.Error != "" {
			fmt.Printf("Last check %s failed: %s\n", when, v.LastRun.Error)
		}
	}
	if v.Running != nil {
		fmt.Printf("A check is %s now (task %s).\n", v.Running.Status, v.Running.ID)
	} else if v.NextRunAt != nil {
		fmt.Printf("Next check: %s UTC (schedule %s). Check now: rowsafe recommendations find %s\n",
			v.NextRunAt.UTC().Format("2006-01-02 15:04"), v.Schedule, name)
	}
}

func recommendationsFind(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("recommendations find", flag.ContinueOnError)
	noWait := fs.Bool("no-wait", false, "return once queued")
	name, err := dbArg(ctx, c, fs, args)
	if err != nil {
		return err
	}
	t, err := c.RunIndexAdvisor(ctx, name)
	if err != nil {
		return err
	}
	if *noWait {
		fmt.Printf("Looking for index recommendations for %s (task %s). See them with `rowsafe recommendations %s`.\n", name, t.ID, name)
		return nil
	}
	if err := waitAndReport(ctx, c, t.ID, name); err != nil {
		return err
	}
	v, err := c.IndexRecommendations(ctx, name)
	if err != nil {
		return err
	}
	fmt.Println()
	printIndexAdvisor(name, v, false)
	return nil
}

func recommendationsSchedule(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("recommendations schedule", flag.ContinueOnError)
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	var name, sched string
	switch len(pos) {
	case 1:
		sched = pos[0]
		if name, err = dbArg(ctx, c, fs, nil); err != nil {
			return err
		}
	case 2:
		name, sched = pos[0], pos[1]
	default:
		return errors.New(`usage: rowsafe recommendations schedule [NAME] auto|off|"CRON"`)
	}
	v, err := c.SetIndexAdvisorSchedule(ctx, name, strings.TrimSpace(sched))
	if err != nil {
		return err
	}
	fmt.Printf("Index recommendations for %s: schedule %s.\n", name, v.Schedule)
	return nil
}
