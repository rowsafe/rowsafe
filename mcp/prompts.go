package mcp

import (
	"context"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const triagePrompt = `Triage my Rowsafe fleet.

1. Call fleet_health. If it reports no critical or warning problems, say so in one or two sentences and stop.
2. For each critical problem, then each warning: read the evidence before concluding. Use get_task on the task_id it names (the log tail shows the backup tool's or the database's own error), and get_database for context (list_alerts, live_activity and disk_forecast when they help).
3. Report, worst first: what is wrong, what it puts at risk (e.g. point-in-time recovery stopped, no proven restore), the likely cause from the evidence, and the exact next step (the command or tool fleet_health gave, adjusted to what you found). When database_health lists a fix Rowsafe can apply, the next step is that fix (Apply fix in the dashboard, Pulse, Health); don't give me SQL to run instead.
4. Don't change anything during triage: no write tools (backups, restore tests, verification) and no request_change. Offer them, and run one only after I say yes. Rowsafe never restarts a database or applies a fix on its own, and neither do you: restarts, health fixes and recovery happen when I click them in the dashboard or approve a request_change you file once I agree. After a restart, Rowsafe verifies by itself. If data was lost or damaged, the next step is Rewind (restore a copy, bring the missing rows back, or rewind the whole database); rewind_window shows how far back it goes. Never restore anything yourself.`

const pulseFixPrompt = `Fix what Pulse found on DATABASE.

1. Call database_health for DATABASE (and recommendations for what it suggests beyond health). List the findings that have a fix Rowsafe can apply, worst first: for each, what is wrong, what the fix does, whether it is disruptive, and its finding_id and fix_id. Leave out fixes that aren't available right now (say why).
2. Ask me which ones to apply. Don't ask for any I didn't pick.
3. For each one I pick, call request_change with action apply_fix, database DATABASE, params {"finding_id": ..., "fix_id": ...} (plus "confirm": the database's name when the fix asks for one) and a one-sentence reason in my words. Then show me the approval links: nothing changes until I approve them in the dashboard.
4. Follow them with get_approval (wait_seconds 60). Once approved, follow the tasks with get_task and tell me how each went; if one was denied or failed, say so and stop there. Finally call database_health again and tell me the new score.`

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
	s.AddPrompt(&sdk.Prompt{
		Name:        "fix_what_pulse_found",
		Title:       "Fix what Pulse found",
		Description: "List a database's findings Rowsafe can fix, let the user pick, and ask them to approve each fix (needs request_change).",
		Arguments:   []*sdk.PromptArgument{{Name: "database", Description: "the database's name", Required: true}},
	}, func(_ context.Context, req *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		db := ""
		if req != nil && req.Params != nil {
			db = strings.TrimSpace(req.Params.Arguments["database"])
		}
		if db == "" {
			db = "the database I name (ask me which one; list_databases shows them)"
		}
		return &sdk.GetPromptResult{
			Description: "Apply Pulse fixes with approval",
			Messages:    []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: strings.ReplaceAll(pulseFixPrompt, "DATABASE", db)}}},
		}, nil
	})
}
