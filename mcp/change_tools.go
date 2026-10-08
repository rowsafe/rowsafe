package mcp

import (
	"context"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Direct tools for the most common changes to production, so an agent
// doesn't need request_change's catalog for them. Each files exactly the
// request request_change would (fileChange, POST /v1/approvals), so the
// same rules apply: by default it runs right away as the person who
// connected the agent, or it waits for a person and says why.

type createCloudServerInput struct {
	Name          string   `json:"name" jsonschema:"the server's name, also its database's: 2 to 40 lowercase letters, digits and hyphens, starting with a letter (like shop-db)"`
	Region        string   `json:"region" jsonschema:"a region ID from cloud_catalog (it decides the cloud): pick one near the app"`
	Size          string   `json:"size" jsonschema:"a size ID from cloud_catalog offered in that region and not sold out (a small app fits the smallest)"`
	Engine        string   `json:"engine,omitempty" jsonschema:"the database: postgresql (default), mysql, mariadb, valkey or clickhouse, as cloud_catalog offers them (MySQL not on Arm sizes; ClickHouse on sizes with 4 GB of memory or more)"`
	EngineVersion string   `json:"engine_version,omitempty" jsonschema:"the engine's version from cloud_catalog (PostgreSQL 15, 16, 17 or 18, default 17)"`
	AllowedIPs    []string `json:"allowed_ips,omitempty" jsonschema:"who can connect to the database: the app's IP addresses or networks (203.0.113.4 or 203.0.113.0/24); empty: nobody until cloud_firewall opens it"`
	Standby       bool     `json:"standby,omitempty" jsonschema:"also a standby server of the same size, ready to take over (clouds billed by the hour only); it doubles the price"`
	Extensions    []string `json:"extensions,omitempty" jsonschema:"PostgreSQL 15 to 18 only: extensions installed and turned on from the start, in the postgres database and every database created later: vector (pgvector), postgis (PostGIS), timescaledb (TimescaleDB, Apache-2.0 edition; loaded at start)"`
	Reason        string   `json:"reason" jsonschema:"what it's for and what it costs, in one or two plain sentences (recorded with the change)"`
	WaitSeconds   int      `json:"wait_seconds,omitempty" jsonschema:"when it waits for a person: seconds to wait for their decision (0 returns at once)"`
}

type cloudFirewallInput struct {
	Server      string   `json:"server" jsonschema:"the Rowsafe Cloud server's name or ID (cs_...; list_cloud_servers shows them)"`
	AllowedIPs  []string `json:"allowed_ips" jsonschema:"the whole list of who can connect afterwards (it replaces the current one): IP addresses or networks; empty closes it to everyone"`
	Reason      string   `json:"reason" jsonschema:"why, in one or two plain sentences (recorded with the change)"`
	WaitSeconds int      `json:"wait_seconds,omitempty" jsonschema:"when it waits for a person: seconds to wait for their decision (0 returns at once)"`
}

type applyFixInput struct {
	Database    string `json:"database" jsonschema:"database name or ID"`
	FindingID   string `json:"finding_id" jsonschema:"the finding's ID (database_health, database_insights or recommendations show it)"`
	FixID       string `json:"fix_id" jsonschema:"the fix's ID from that finding"`
	Confirm     string `json:"confirm,omitempty" jsonschema:"the database's name, when the fix says it needs a confirmation (a restart)"`
	Reason      string `json:"reason" jsonschema:"why, in one or two plain sentences (recorded with the change)"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"when it waits for a person: seconds to wait for their decision (0 returns at once)"`
}

const actsAs = " It runs right away as the person who connected you, with their rights in the dashboard (it waits for an owner or admin instead when your team asks first, when that person is a member, or when a safety net needs a person: then give the user the approval link). The same as request_change "

func (t *tools) addChangeTools(s *sdk.Server) {
	reason := func(p map[string]*jsonschema.Schema) {
		p["reason"].MinLength, p["reason"].MaxLength = ptr(1), ptr(1000)
	}
	sdk.AddTool(s, &sdk.Tool{
		Name: "create_cloud_server",
		Description: "Creates a Rowsafe Cloud server: a database (PostgreSQL by default; MySQL, MariaDB, Valkey or ClickHouse where cloud_catalog offers them) that Rowsafe runs and protects from the start (backups, Proof, Pulse), billed to the organization. Pick the region and size with cloud_catalog, " +
			"tell the user the size and the price (per hour, and the most a month; a standby doubles it) and get their OK first." + actsAs + "create_cloud_server. " +
			"A first payment (pay as you go not active yet, or a cloud billed by the month) is made by an owner at a checkout: an owner's request comes back with the checkout link to give them; the server is created once paid. " +
			"Then follow it with get_cloud_server (wait_seconds) until it's ready, about 5 to 10 minutes.",
		Annotations: writes("Create a Rowsafe Cloud server (costs money)", false, false),
		InputSchema: withWait[createCloudServerInput](func(p map[string]*jsonschema.Schema) {
			reason(p)
			p["name"].Pattern = "^[a-z][a-z0-9-]{1,39}$"
		}),
	}, t.createCloudServer)

	sdk.AddTool(s, &sdk.Tool{
		Name: "cloud_firewall",
		Description: "Sets who can connect to a Rowsafe Cloud server's database: allowed_ips replaces the whole list, so apps connecting from an address no longer listed are cut off. " +
			"Confirm with the user first when it removes addresses." + actsAs + "cloud_firewall.",
		Annotations: writes("Change who can connect to a Rowsafe Cloud server", true, true),
		InputSchema: withWait[cloudFirewallInput](reason),
	}, t.cloudFirewall)

	sdk.AddTool(s, &sdk.Tool{
		Name: "apply_fix",
		Description: "Applies a fix Rowsafe proposed for a finding (database_health, database_insights and recommendations list them with their IDs), exactly like the dashboard's Apply fix button: " +
			"Rowsafe recomputes the fix, saves a Mark first when the fix says so, and refuses a fix it didn't propose. Tell the user what it does (and if it restarts the database) and get their OK first." + actsAs + "apply_fix.",
		Annotations: writes("Apply a Pulse fix", true, false),
		InputSchema: withWait[applyFixInput](reason),
	}, t.applyFix)
}

func (t *tools) createCloudServer(ctx context.Context, req *sdk.CallToolRequest, in createCloudServerInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	p := map[string]any{"name": strings.TrimSpace(in.Name), "region": strings.TrimSpace(in.Region), "size": strings.TrimSpace(in.Size)}
	if v := strings.ToLower(strings.TrimSpace(in.Engine)); v != "" {
		p["engine"] = v
	}
	if v := strings.TrimSpace(in.EngineVersion); v != "" {
		p["engine_version"] = v
	}
	if in.AllowedIPs != nil {
		p["allowed_ips"] = in.AllowedIPs
	}
	if in.Standby {
		p["standby"] = true
	}
	if len(in.Extensions) > 0 {
		p["extensions"] = in.Extensions
	}
	return t.fileChange(ctx, req, "create_cloud_server", "", p, in.Reason, in.WaitSeconds)
}

func (t *tools) cloudFirewall(ctx context.Context, req *sdk.CallToolRequest, in cloudFirewallInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	ips := in.AllowedIPs
	if ips == nil {
		ips = []string{}
	}
	return t.fileChange(ctx, req, "cloud_firewall", "", map[string]any{"server": strings.TrimSpace(in.Server), "allowed_ips": ips}, in.Reason, in.WaitSeconds)
}

func (t *tools) applyFix(ctx context.Context, req *sdk.CallToolRequest, in applyFixInput) (*sdk.CallToolResult, ApprovalOutput, error) {
	p := map[string]any{"finding_id": strings.TrimSpace(in.FindingID), "fix_id": strings.TrimSpace(in.FixID)}
	if c := strings.TrimSpace(in.Confirm); c != "" {
		p["confirm"] = c
	}
	return t.fileChange(ctx, req, "apply_fix", in.Database, p, in.Reason, in.WaitSeconds)
}
