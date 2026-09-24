package mcp

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const triagePrompt = `Triage my Rowsafe fleet.

1. Call fleet_health. If it reports no critical or warning problems, say so in one or two sentences and stop.
2. For each critical problem, then each warning: read the evidence before concluding. Use get_task on the task_id it names (the log tail shows pgBackRest's or PostgreSQL's own error), and get_database for context.
3. Report, worst first: what is wrong, what it puts at risk (e.g. point-in-time recovery stopped, no proven restore), the likely cause from the evidence, and the exact next step (the command or tool fleet_health gave, adjusted to what you found).
4. Don't run write tools (backups, drills, verification, apply) during triage. Offer them, and run one only after I say yes. Rowsafe never restarts PostgreSQL; restarts and host-side fixes are for me to do.`

func addPrompts(s *sdk.Server) {
	s.AddPrompt(&sdk.Prompt{
		Name:        "incident_triage",
		Title:       "Triage Rowsafe problems",
		Description: "Check the whole fleet, read the evidence for each problem, and propose next steps without changing anything.",
	}, func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		return &sdk.GetPromptResult{
			Description: "Rowsafe incident triage",
			Messages:    []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: triagePrompt}}},
		}, nil
	})
}
