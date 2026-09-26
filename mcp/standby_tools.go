package mcp

import (
	"context"
	"fmt"
	"strconv"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Standby is read-only here. Guard's rule: AI agents never change
// production's topology. No tool creates, promotes, rebuilds or removes a
// standby or changes automatic failover; people do that in the dashboard
// (Standby) or with `rowsafe standby`, after confirming.

const standbyGuidance = "Standby changes (create, promote / fail over, rebuild, remove, automatic failover) are for people only: " +
	"in the Rowsafe dashboard (Standby) or with `rowsafe standby`. You can't do any of them. If the primary looks down, tell the user; " +
	"never tell them to promote without first checking the old primary is really down or that Rowsafe can stop it."

type StandbyStatusView struct {
	Database string `json:"database"`
	Primary  string `json:"primary" jsonschema:"the primary's server and port"`
	// Standby is empty when there is none.
	Standby           string     `json:"standby,omitempty" jsonschema:"the standby's server and port"`
	Status            string     `json:"status,omitempty" jsonschema:"preparing, creating, ready, lagging, down, failed, promoting, removing"`
	Mode              string     `json:"mode,omitempty" jsonschema:"streaming (connected to the primary) or archive (through the bucket, about a minute behind)"`
	LagSeconds        *float64   `json:"lag_seconds,omitempty"`
	LagBytes          *int64     `json:"lag_bytes,omitempty"`
	LastReplayAt      *time.Time `json:"last_replay_at,omitempty"`
	Note              string     `json:"note,omitempty"`
	Fenced            []string   `json:"fenced,omitempty" jsonschema:"old primaries kept stopped after a promotion"`
	AutoFailover      bool       `json:"automatic_failover"`
	Move              string     `json:"move,omitempty" jsonschema:"a move to another server in progress or just done, in plain words"`
	ConnectionStrings []string   `json:"connection_strings,omitempty" jsonschema:"connection strings that follow the primary"`
	Guidance          string     `json:"guidance"`
}

func (t *tools) addStandbyReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "standby_status",
		Description: "Show a database's standby server (a second server that stays in sync, is readable for reports, and can take over): " +
			"whether it is in sync, streaming or following through the bucket, how far behind, fenced old primaries, whether automatic failover is on, " +
			"and connection strings that follow the primary. Read-only: no tool creates, promotes or removes a standby.",
		Annotations: readOnly("Standby status"),
	}, t.standbyStatus)
}

func (t *tools) standbyStatus(ctx context.Context, _ *sdk.CallToolRequest, in databaseInput) (*sdk.CallToolResult, StandbyStatusView, error) {
	d, err := t.c.Database(ctx, in.Database)
	if err != nil {
		return nil, StandbyStatusView{}, apiError(err)
	}
	info, err := t.c.StandbyInfo(ctx, d.ID)
	if err != nil {
		return nil, StandbyStatusView{}, apiError(err)
	}
	out := StandbyStatusView{Database: d.Name, Primary: serverName(info.Primary.Hostname, info.Primary.Port),
		AutoFailover: info.Failover.Automatic, Guidance: standbyGuidance}
	if v := info.Standby; v != nil {
		out.Standby = serverName(v.Server.Hostname, v.Server.Port)
		out.Status, out.Mode, out.LagSeconds, out.LagBytes, out.LastReplayAt, out.Note = v.Status, v.Mode, v.LagSeconds, v.LagBytes, v.LastReplayAt, v.Note
	}
	for _, f := range info.Fences {
		if !f.Released {
			out.Fenced = append(out.Fenced, serverName(f.Server.Hostname, f.Server.Port))
		}
	}
	if m := info.Move; m != nil {
		out.Move = fmt.Sprintf("move from %s to %s: %s", m.From.Hostname, m.To.Hostname, m.Status)
		if m.Hint != "" {
			out.Move += " (" + m.Hint + ")"
		}
	}
	for _, c := range info.Connect {
		out.ConnectionStrings = append(out.ConnectionStrings, c.Driver+": "+c.Value)
	}
	return nil, out, nil
}

func serverName(host string, port int) string {
	if host == "" {
		return ""
	}
	return host + ":" + strconv.Itoa(port)
}
