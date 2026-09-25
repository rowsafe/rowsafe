package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// Settings: a read-only view of PostgreSQL's settings and what Rowsafe
// recommends. No MCP tool changes settings: a person does, in the
// dashboard (Tuning) or with rowsafe tune / rowsafe settings set.

type settingsInput struct {
	Database string `json:"database" jsonschema:"database name (as shown by list_databases) or ID"`
	Workload string `json:"workload,omitempty" jsonschema:"what the database serves, for the recommendations: web, analytics or mixed (default: the one saved for the database)"`
}

// SettingsOutput is database_settings' result.
type SettingsOutput struct {
	Database string                    `json:"database"`
	Settings protocol.SettingsOverview `json:"settings"`
}

func (t *tools) addSettingsTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "database_settings",
		Description: "PostgreSQL's settings that matter for a database (memory, connections, change log and checkpoints, autovacuum, planner, parallel queries, timeouts, logging, query statistics), each with a plain explanation, its value and default, where it is set (default, postgresql.conf, postgresql.auto.conf) and whether changing it needs a restart; " +
			"the server's memory, CPUs and disk type; settings waiting for a restart; Rowsafe's recommendations for the server (PGTune-style: shared_buffers about 25% of memory, work_mem from memory and connections, SSD costs, ...) with the reason for each; and the latest changes made through Rowsafe. " +
			"Read-only. Rowsafe's archiving settings (archive_mode, archive_command, archive_timeout) are managed by Rowsafe and must not be changed. To change settings, point the user to Tuning in the Rowsafe dashboard or `rowsafe tune NAME`: a person applies them there (Rowsafe saves a Mark first and can undo a change). Never tell the user to edit postgresql.conf or run ALTER SYSTEM for a change Rowsafe recommends.",
		Annotations: readOnly("PostgreSQL settings"),
		InputSchema: inputSchema[settingsInput](func(p map[string]*jsonschema.Schema) {
			p["workload"].Enum = []any{protocol.WorkloadWeb, protocol.WorkloadAnalytics, protocol.WorkloadMixed}
		}),
	}, t.databaseSettings)
}

func (t *tools) databaseSettings(ctx context.Context, _ *sdk.CallToolRequest, in settingsInput) (*sdk.CallToolResult, SettingsOutput, error) {
	ov, err := t.c.Settings(ctx, in.Database, in.Workload, "")
	if err != nil {
		return nil, SettingsOutput{}, apiError(err)
	}
	if ov.Settings == nil {
		ov.Settings = []protocol.SettingView{}
	}
	if ov.Other == nil {
		ov.Other = []protocol.SettingView{}
	}
	if ov.Recommendations == nil {
		ov.Recommendations = []protocol.Recommendation{}
	}
	if ov.PendingRestart == nil {
		ov.PendingRestart = []string{}
	}
	if ov.Changes == nil {
		ov.Changes = []protocol.SettingsChange{}
	}
	var b textBuilder
	if !ov.Available {
		b.line("%s", ov.Reason)
		return text(b), SettingsOutput{Database: in.Database, Settings: ov}, nil
	}
	var host []string
	if ov.Host.MemoryBytes > 0 {
		host = append(host, tune.HumanBytes(ov.Host.MemoryBytes)+" memory")
	}
	if ov.Host.CPUs > 0 {
		host = append(host, fmt.Sprintf("%d CPUs", ov.Host.CPUs))
	}
	if ov.Host.Disk != "" {
		host = append(host, strings.ToUpper(ov.Host.Disk))
	}
	b.line("Settings of %s (%s; workload: %s).", in.Database, strings.Join(host, ", "), ov.Workload)
	for _, cat := range tune.Categories {
		first := true
		for _, s := range ov.Settings {
			if s.Category != cat.ID {
				continue
			}
			if first {
				b.line("")
				b.line("%s:", cat.Title)
				first = false
			}
			note := ""
			switch {
			case s.Locked:
				note = " [managed by Rowsafe]"
			case s.Apply == "restart":
				note = " [restart]"
			}
			if s.PendingRestart {
				note += " [" + s.PendingValue + " after a restart]"
			}
			b.line("- %s = %s (default %s, set in %s)%s", s.Name, s.Value, s.Default, s.Source, note)
		}
	}
	if len(ov.PendingRestart) > 0 {
		b.line("")
		b.line("Waiting for a PostgreSQL restart: %s. The user restarts it from the dashboard or with `rowsafe restart`.", strings.Join(ov.PendingRestart, ", "))
	}
	if len(ov.Recommendations) > 0 {
		b.line("")
		b.line("Recommended for this server (the user applies them with Tuning in the dashboard or `rowsafe tune %s`):", in.Database)
		for _, r := range ov.Recommendations {
			opt := ""
			if r.Optional {
				opt = " (optional)"
			}
			if r.Restart {
				opt += " (needs a restart)"
			}
			b.line("- %s: %s -> %s%s. %s", r.Name, r.Current, r.Display, opt, r.Why)
		}
	} else {
		b.line("")
		b.line("No recommendations: the settings suit this server.")
	}
	return text(b), SettingsOutput{Database: in.Database, Settings: ov}, nil
}
