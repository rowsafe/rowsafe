package mcp

import (
	"context"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
)

// Advisor: the recommendations tool (schema, queries, capacity, indexes).
// Read-only: fixes are applied by people in the dashboard.

type recommendationsInput struct {
	Database string `json:"database,omitempty" jsonschema:"database name or ID; omit for every database's top recommendation"`
	Group    string `json:"group,omitempty" jsonschema:"only this group: schema, queries, capacity or indexes"`
	Limit    int    `json:"limit,omitempty" jsonschema:"number of recommendations in the text summary"`
}

// RecommendationsOutput is recommendations' result: one database or all.
type RecommendationsOutput struct {
	Database *protocol.RecommendationsResponse `json:"database,omitempty" jsonschema:"one database's open and dismissed recommendations"`
	Fleet    *protocol.RecommendationsOverview `json:"fleet,omitempty" jsonschema:"every database's count and top recommendation"`
}

func (t *tools) addAdvisorTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "recommendations",
		Description: "Recommendations to make a database better, highest impact first, each with what to change, why, and what it costs: " +
			"schema (foreign keys without an index, integer ids running out of numbers with the date they would, sequences behind their column that make inserts fail, invalid indexes from failed builds, tables without a primary key, duplicate constraints, timestamp without time zone, large time-series tables to partition), " +
			"queries (N+1 patterns, queries reading far more than they return, results without LIMIT, sorts spilling to disk), capacity (data no longer fitting in memory, CPU saturation, connections near the limit, disk filling up, autovacuum settings for large busy tables) and index suggestions. " +
			"Some list fixes Rowsafe can apply (create the index, move the sequence forward, remove the invalid index, tune autovacuum): the user applies them with Apply fix in the dashboard (Pulse, Recommendations); no MCP tool applies them. " +
			"For schema changes Rowsafe can't do safely by itself (widening an id column, adding a primary key), the result has a step-by-step plan: propose it to the user, don't run it. Without a database it lists each database's top recommendation.",
		Annotations: readOnly("Recommendations"),
		InputSchema: inputSchema[recommendationsInput](func(p map[string]*jsonschema.Schema) {
			p["group"].Enum = []any{protocol.RecGroupSchema, protocol.RecGroupQueries, protocol.RecGroupCapacity, protocol.RecGroupIndexes}
			p["limit"].Minimum, p["limit"].Maximum, p["limit"].Default = ptr(1.0), ptr(50.0), []byte("15")
		}),
	}, t.recommendations)
}

func stripRecParams(rs []protocol.Recommendation) {
	for i := range rs {
		stripFixParams(&rs[i].Finding)
	}
}

func (t *tools) recommendations(ctx context.Context, _ *sdk.CallToolRequest, in recommendationsInput) (*sdk.CallToolResult, RecommendationsOutput, error) {
	var b textBuilder
	if in.Database == "" {
		o, err := t.c.Recommendations(ctx)
		if err != nil {
			return nil, RecommendationsOutput{}, apiError(err)
		}
		if o.Databases == nil {
			o.Databases = []protocol.DatabaseRecommendations{}
		}
		if len(o.Databases) == 0 {
			b.line("No databases registered.")
		}
		for i := range o.Databases {
			d := &o.Databases[i]
			if d.Top == nil {
				b.line("%s on %s: nothing to recommend.", d.Database, d.Host)
				continue
			}
			stripFixParams(&d.Top.Finding)
			b.line("%s on %s: %d recommendations (%d critical, %d warnings). Top: %s", d.Database, d.Host, d.Count, d.Critical, d.Warnings, d.Top.Title)
		}
		if len(o.Databases) > 0 {
			b.line("")
			b.line("Call recommendations with a database for the details, costs and plans.")
		}
		return text(b), RecommendationsOutput{Fleet: &o}, nil
	}
	r, err := t.c.DatabaseRecommendations(ctx, in.Database)
	if err != nil {
		return nil, RecommendationsOutput{}, apiError(err)
	}
	if r.Recommendations == nil {
		r.Recommendations = []protocol.Recommendation{}
	}
	if r.Dismissed == nil {
		r.Dismissed = []protocol.Recommendation{}
	}
	stripRecParams(r.Recommendations)
	stripRecParams(r.Dismissed)
	if in.Group != "" {
		var keep []protocol.Recommendation
		for _, x := range r.Recommendations {
			if x.Group == in.Group {
				keep = append(keep, x)
			}
		}
		r.Recommendations = append([]protocol.Recommendation{}, keep...)
	}
	switch {
	case !r.Available:
		b.line("No recommendations for %s yet: %s", r.Database, r.Reason)
	case len(r.Recommendations) == 0:
		b.line("Nothing to recommend for %s right now.", r.Database)
	default:
		b.line("%d recommendations for %s, highest impact first.", len(r.Recommendations), r.Database)
	}
	for i, x := range r.Recommendations {
		if i >= clamp(in.Limit, 15, 50) {
			b.line("")
			b.line("... and %d more (see the structured result).", len(r.Recommendations)-i)
			break
		}
		b.line("")
		b.line("[%s, %s] %s", strings.ToUpper(x.Severity), x.Group, x.Title)
		b.line("  Why: %s", x.Explanation)
		b.line("  What to do: %s", x.Action)
		if x.Cost != "" {
			b.line("  What it costs: %s", x.Cost)
		}
		var fixes []string
		for _, fx := range x.Fixes {
			if fx.Available {
				fixes = append(fixes, fx.Label)
			}
		}
		if len(fixes) > 0 {
			b.line("  Rowsafe can do this: %s. The user clicks Apply fix in the dashboard (Pulse, Recommendations); you can't apply it.", strings.Join(fixes, "; "))
		}
		for j, s := range x.Steps {
			b.line("  Step %d: %s", j+1, s)
		}
	}
	for _, n := range r.Notes {
		b.line("")
		b.line("Note: %s", n)
	}
	if len(r.Dismissed) > 0 {
		b.line("")
		b.line("%d dismissed by the user (not relevant for them).", len(r.Dismissed))
	}
	return text(b), RecommendationsOutput{Database: &r}, nil
}
