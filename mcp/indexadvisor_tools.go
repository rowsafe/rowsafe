package mcp

import (
	"context"
	"fmt"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// index_recommendations: indexes Rowsafe proved on a copy of the database.
// Read-only: AI agents can suggest an index, never create one (creating is
// Apply fix in the dashboard or `rowsafe fix`, by a person).

// IndexRecommendationsOutput is index_recommendations' result.
type IndexRecommendationsOutput struct {
	Database string                    `json:"database"`
	Advisor  protocol.IndexAdvisorView `json:"advisor"`
}

func (t *tools) addIndexAdvisorTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "index_recommendations",
		Description: "Indexes that would make a database's slowest queries faster. Rowsafe finds them from the busiest statements (pg_stat_statements), " +
			"then tests each one on a copy of the database restored next to production (the query plan before and after building the index), and only " +
			"recommends indexes PostgreSQL actually uses that make a query at least twice as fast. Each recommendation has the index definition, the " +
			"queries it helps with their speedup, its size and build time, and its effect on writes. Also lists indexes Rowsafe created earlier and how much " +
			"they are used. Read-only: you can't create indexes. Tell the user to click Create index on the recommendation in the Rowsafe dashboard " +
			"(Pulse, Recommendations) or run `rowsafe fix`; Rowsafe then builds it without blocking the app.",
		Annotations: readOnly("Index recommendations"),
	}, t.indexRecommendations)
}

func (t *tools) indexRecommendations(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, IndexRecommendationsOutput, error) {
	v, err := t.c.IndexRecommendations(ctx, in.Database)
	if err != nil {
		return nil, IndexRecommendationsOutput{}, apiError(err)
	}
	if v.Recommendations == nil {
		v.Recommendations = []protocol.IndexRecommendationView{}
	}
	out := IndexRecommendationsOutput{Database: in.Database, Advisor: v}
	var b textBuilder
	if !v.Available {
		b.line("No index recommendations for %s: %s", in.Database, v.Reason)
		return text(b), out, nil
	}
	open := 0
	for _, r := range v.Recommendations {
		if r.Status != protocol.IndexRecOpen {
			continue
		}
		open++
		b.line("%d. %s", open, r.Title)
		b.line("   %s", r.Explanation)
		b.line("   Index: %s", r.Definition)
		for _, s := range r.Statements[:min(len(r.Statements), 5)] {
			b.line("   - about %s faster (%d calls): %s", protocol.TimesFaster(s.Speedup), s.Calls, s.Query)
		}
	}
	if open == 0 {
		b.line("No open index recommendations for %s.", in.Database)
	} else {
		b.line("")
		b.line("To create one, the user clicks Create index in the Rowsafe dashboard (Pulse, Recommendations) or runs `rowsafe fix %s`. Don't run CREATE INDEX yourself.", in.Database)
	}
	for _, r := range v.Recommendations {
		if r.Status == protocol.IndexRecCreated {
			line := "Created by Rowsafe: " + r.Spec.Name
			if r.Outcome != nil {
				line += ". " + r.Outcome.Summary
			} else if r.Usage != nil {
				line += fmt.Sprintf(", used %d times so far", r.Usage.Scans)
			}
			b.line("%s", line)
		}
	}
	if v.LastRun != nil && v.LastRun.Summary != "" {
		b.line("Last check: %s", v.LastRun.Summary)
	}
	return text(b), out, nil
}
