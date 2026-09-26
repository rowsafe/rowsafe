package mcp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// Logs: PostgreSQL's log, already redacted on the database server.
// Read-only.

type logsInput struct {
	Database string `json:"database" jsonschema:"database name (as shown by list_databases) or ID"`
	Kind     string `json:"kind,omitempty" jsonschema:"errors, locks, maintenance, or one kind: error, slow_query, lock_wait, deadlock, auth_failure, too_many_connections, checkpoint, autovacuum, temp_file, connection, statement, server, other"`
	Search   string `json:"search,omitempty" jsonschema:"case-insensitive text in the message, detail, statement, user or client address"`
	Grouped  bool   `json:"grouped,omitempty" jsonschema:"repeated messages of the last 24 hours with their counts, instead of lines"`
	Limit    int    `json:"limit,omitempty" jsonschema:"number of lines or groups"`
}

// LogsOutput is get_logs' result.
type LogsOutput struct {
	Database string                  `json:"database"`
	Source   *protocol.LogSource     `json:"source,omitempty" jsonschema:"where the agent reads the log, or why it can't"`
	Sending  bool                    `json:"sending" jsonschema:"false when sending logs is off for this database"`
	Entries  []protocol.LogEntryView `json:"entries,omitempty"`
	Groups   []protocol.LogGroup     `json:"groups,omitempty"`
	More     bool                    `json:"more,omitempty"`
}

func (t *tools) addLogTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "get_logs",
		Description: "Read a database's PostgreSQL log: errors, slow queries (over log_min_duration_statement), lock waits, deadlocks, failed logins, checkpoints and autovacuum, newest first, or grouped by message with counts. " +
			"Statements are normalized ($1, $2 for values) and quoted values in messages hidden on the database server, unless the database sends full query text. Use it to explain an error spike, find the statement behind an error, or see who is failing to log in.",
		Annotations: readOnly("Read logs"),
		InputSchema: inputSchema[logsInput](func(p map[string]*jsonschema.Schema) {
			p["limit"].Minimum, p["limit"].Maximum = ptr(1.0), ptr(200.0)
		}),
	}, t.getLogs)
}

func (t *tools) getLogs(ctx context.Context, _ *sdk.CallToolRequest, in logsInput) (*sdk.CallToolResult, LogsOutput, error) {
	out := LogsOutput{Database: in.Database}
	ov, err := t.c.LogsOverview(ctx, in.Database)
	if err != nil {
		return nil, out, apiError(err)
	}
	out.Source, out.Sending = ov.Source, ov.Settings.Enabled
	var b textBuilder
	switch {
	case !ov.Settings.Enabled:
		b.line("Sending logs is off for %s (Log settings in the dashboard); older lines may still be listed.", in.Database)
	case ov.Source == nil:
		b.line("The agent hasn't reported on %s's log yet.", in.Database)
	case !ov.Source.Readable:
		b.line("The agent can't read %s's log: %s", in.Database, ov.Source.Detail)
	}
	q := client.LogsQuery{Kind: in.Kind, Search: in.Search, Limit: clamp(in.Limit, 50, 200)}
	now := time.Now()
	if in.Grouped {
		g, err := t.c.LogGroups(ctx, in.Database, q)
		if err != nil {
			return nil, out, apiError(err)
		}
		if len(g.Groups) > q.Limit {
			g.Groups = g.Groups[:q.Limit]
		}
		out.Groups = g.Groups
		if len(g.Groups) == 0 {
			b.line("No matching log lines in the last 24 hours.")
		}
		for _, gr := range g.Groups {
			b.line("%6d× %-12s %s (first %s, last %s)", gr.Count, gr.Kind, oneLine(gr.Message, 300), ago(&gr.FirstAt, now), ago(&gr.LastAt, now))
		}
		return text(b), out, nil
	}
	res, err := t.c.Logs(ctx, in.Database, q)
	if err != nil {
		return nil, out, apiError(err)
	}
	out.Entries, out.More = res.Entries, res.More
	if len(res.Entries) == 0 {
		b.line("No matching log lines.")
	}
	for _, e := range res.Entries {
		who := strings.Trim(fmt.Sprintf("%s@%s %s", e.User, e.Database, e.Client), "@ ")
		b.line("%s %-7s %-12s %s%s", e.Time.UTC().Format("2006-01-02 15:04:05Z"), e.Severity, e.Kind, oneLine(e.Message, 300), suffix(who))
		if e.Detail != "" {
			b.line("    DETAIL: %s", oneLine(e.Detail, 300))
		}
		if e.Statement != "" {
			b.line("    STATEMENT: %s", oneLine(e.Statement, 300))
		}
	}
	if res.More {
		b.line("(more lines match; narrow with kind or search)")
	}
	return text(b), out, nil
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

func suffix(who string) string {
	if who == "" {
		return ""
	}
	return " [" + who + "]"
}
