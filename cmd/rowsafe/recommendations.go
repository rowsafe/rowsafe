package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// rowsafe recommendations [NAME]: what would make a database better
// (schema, queries, capacity, indexes), with why and what it costs; the
// ones Rowsafe can do are applied with rowsafe fix.

func recommendationsCmd(ctx context.Context, c *client.Client, args []string) error {
	fs := flag.NewFlagSet("recommendations", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the full result as JSON")
	group := fs.String("group", "", "only this group: schema, queries, capacity or indexes")
	dismiss := fs.String("dismiss", "", "set the recommendation with this ID aside")
	reason := fs.String("reason", protocol.DismissNotRelevant, "why, with --dismiss: not_relevant, intended, later or wrong")
	note := fs.String("note", "", "a note, with --dismiss")
	restore := fs.String("restore", "", "bring back the dismissed recommendation with this ID")
	showDismissed := fs.Bool("dismissed", false, "also list the dismissed recommendations")
	pos, err := positionals(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("expected at most one database name")
	}
	if *group != "" && !isRecGroup(*group) {
		return fmt.Errorf("--group must be schema, queries, capacity or indexes")
	}
	if len(pos) == 0 && *dismiss == "" && *restore == "" {
		return fleetRecommendations(ctx, c, *asJSON)
	}
	name := ""
	if len(pos) == 1 {
		name = pos[0]
	}
	if name, err = resolveDatabase(ctx, c, name); err != nil {
		return err
	}
	switch {
	case *dismiss != "":
		d, err := c.DismissRecommendation(ctx, name, *dismiss, protocol.DismissRecommendationRequest{Reason: *reason, Note: *note})
		if err != nil {
			return err
		}
		fmt.Printf("Dismissed %s (%s). Bring it back with: rowsafe recommendations %s --restore %s\n",
			*dismiss, orText(protocol.DismissReasons[d.Reason], d.Reason), name, *dismiss)
		return nil
	case *restore != "":
		if err := c.RestoreRecommendation(ctx, name, *restore); err != nil {
			return err
		}
		fmt.Printf("Brought back %s.\n", *restore)
		return nil
	}
	r, err := c.DatabaseRecommendations(ctx, name)
	if err != nil {
		return err
	}
	if *group != "" {
		r.Recommendations = filterGroup(r.Recommendations, *group)
		r.Dismissed = filterGroup(r.Dismissed, *group)
	}
	if *asJSON {
		return printJSON(r)
	}
	printRecommendations(r, *showDismissed)
	return nil
}

func isRecGroup(g string) bool {
	for _, x := range protocol.RecommendationGroups {
		if x == g {
			return true
		}
	}
	return false
}

func filterGroup(rs []protocol.Recommendation, g string) []protocol.Recommendation {
	out := []protocol.Recommendation{}
	for _, r := range rs {
		if r.Group == g {
			out = append(out, r)
		}
	}
	return out
}

func fleetRecommendations(ctx context.Context, c *client.Client, asJSON bool) error {
	o, err := c.Recommendations(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(o)
	}
	if len(o.Databases) == 0 {
		fmt.Println("No databases yet. Register one with: rowsafe adopt NAME")
		return nil
	}
	t := newTable("DATABASE", "HOST", "OPEN", "TOP RECOMMENDATION")
	for _, d := range o.Databases {
		top := "-"
		if d.Top != nil {
			top = firstLine(d.Top.Title, 80)
		}
		t.row(d.Database, d.Host, strconv.Itoa(d.Count), top)
	}
	t.flush()
	fmt.Println("\nDetails, why and what it costs: rowsafe recommendations NAME")
	return nil
}

var groupTitle = map[string]string{
	protocol.RecGroupSchema:   "Schema",
	protocol.RecGroupQueries:  "Queries",
	protocol.RecGroupCapacity: "Capacity",
	protocol.RecGroupIndexes:  "Indexes",
}

func printRecommendations(r protocol.RecommendationsResponse, showDismissed bool) {
	switch {
	case !r.Available:
		fmt.Printf("No recommendations for %s yet: %s\n", r.Database, r.Reason)
	case len(r.Recommendations) == 0:
		fmt.Printf("Nothing to recommend for %s right now.\n", r.Database)
	default:
		fmt.Printf("%s: %d recommendations, most important first.\n", r.Database, len(r.Recommendations))
	}
	for _, g := range protocol.RecommendationGroups {
		var in []protocol.Recommendation
		for _, x := range r.Recommendations {
			if x.Group == g {
				in = append(in, x)
			}
		}
		if len(in) == 0 {
			continue
		}
		fmt.Printf("\n%s\n", strings.ToUpper(groupTitle[g]))
		for _, x := range in {
			printRecommendation(r.Database, x)
		}
	}
	for _, n := range r.Notes {
		fmt.Printf("\nNote: %s\n", n)
	}
	if len(r.Dismissed) > 0 {
		if !showDismissed {
			fmt.Printf("\n%d dismissed (show them with --dismissed).\n", len(r.Dismissed))
			return
		}
		fmt.Printf("\nDISMISSED\n")
		for _, x := range r.Dismissed {
			why := x.Dismissed.Reason
			if l, ok := protocol.DismissReasons[why]; ok {
				why = l
			}
			fmt.Printf("\n- %s\n   %s, by %s. Bring back: rowsafe recommendations %s --restore %s\n", x.Title, why, x.Dismissed.By, r.Database, x.ID)
		}
	}
}

func printRecommendation(db string, x protocol.Recommendation) {
	mark := map[string]string{protocol.SeverityCritical: "!!", protocol.SeverityWarning: "! ", protocol.SeverityInfo: "- "}[x.Severity]
	fmt.Printf("\n%s %s\n", mark, x.Title)
	fmt.Printf("   Why: %s\n", x.Explanation)
	fmt.Printf("   What to do: %s\n", x.Action)
	if x.Cost != "" {
		fmt.Printf("   What it costs: %s\n", x.Cost)
	}
	for _, f := range x.Facts {
		fmt.Printf("   · %s\n", f)
	}
	for i, s := range x.Steps {
		fmt.Printf("   %d. %s\n", i+1, s)
	}
	if fx := firstAvailableFix(x.Finding); fx != nil {
		fmt.Printf("   Fix: rowsafe fix %s %s  (%s)\n", db, x.ID, fx.Label)
	} else if x.Command != "" && len(x.Steps) == 0 {
		fmt.Printf("   Do it yourself: %s\n", x.Command)
	}
	fmt.Printf("   Not relevant? rowsafe recommendations %s --dismiss %s\n", db, x.ID)
}

// withRecommendations adds the recommendations Rowsafe can fix to h's
// findings, so rowsafe fix offers them too (older control planes have
// none: nothing is added).
func withRecommendations(ctx context.Context, c *client.Client, h *protocol.DatabaseHealth) {
	r, err := c.DatabaseRecommendations(ctx, h.Database)
	if err != nil {
		return
	}
	for _, x := range r.Recommendations {
		if x.Source == "advisor" && len(x.Fixes) > 0 {
			h.Findings = append(h.Findings, x.Finding)
		}
	}
}
