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

// The index advisor's part of rowsafe recommendations: the proven indexes
// themselves are in the Indexes group; these are the check behind them.
//
//	rowsafe recommendations find [NAME] [--no-wait]
//	rowsafe recommendations schedule [NAME] auto|off|CRON

// indexAdvisorSubcommand runs find or schedule (ok is false for anything
// else).
func indexAdvisorSubcommand(ctx context.Context, c *client.Client, args []string) (ok bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "find":
		return true, recommendationsFind(ctx, c, args[1:])
	case "schedule":
		return true, recommendationsSchedule(ctx, c, args[1:])
	}
	return false, nil
}

// printIndexCheck is the line under the recommendations about the last and
// next index check (nothing when the control plane doesn't have one).
func printIndexCheck(ctx context.Context, c *client.Client, name string) {
	v, err := c.IndexRecommendations(ctx, name)
	if err != nil || !v.Available {
		return
	}
	fmt.Println()
	switch {
	case v.Running != nil:
		fmt.Printf("Index check: %s now (task %s).\n", v.Running.Status, v.Running.ID)
	case v.LastRun != nil && v.LastRun.Status != protocol.StatusSucceeded:
		fmt.Printf("Index check %s didn't finish: %s\n", ago(v.LastRun.FinishedAt), orText(v.LastRun.Error, "see the task"))
	case v.LastRun != nil:
		fmt.Printf("Index check %s: %s\n", ago(v.LastRun.FinishedAt), orText(v.LastRun.Summary, v.LastRun.Skipped))
	default:
		fmt.Println("Index check: not run yet.")
	}
	for _, r := range v.Recommendations {
		if r.Status == protocol.IndexRecCreated {
			line := "Created by Rowsafe: " + r.Spec.Name
			if r.Outcome != nil {
				line += ". " + r.Outcome.Summary
			} else if r.Usage != nil {
				line += fmt.Sprintf(" (used %d times so far)", r.Usage.Scans)
			}
			fmt.Println(line)
		}
	}
	if v.Running == nil {
		next := "off"
		if v.NextRunAt != nil {
			next = v.NextRunAt.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		fmt.Printf("Next index check: %s. Now: rowsafe recommendations find %s\n", next, name)
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
		fmt.Printf("Testing index ideas for %s on a copy (task %s). See the result with `rowsafe recommendations %s --group indexes`.\n", name, t.ID, name)
		return nil
	}
	if err := waitAndReport(ctx, c, t.ID, name); err != nil {
		return err
	}
	fmt.Printf("\nSee them with: rowsafe recommendations %s --group indexes\n", name)
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
	fmt.Printf("Index checks for %s: %s.\n", name, v.Schedule)
	return nil
}
