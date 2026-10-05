package mcp

import (
	"context"
	"fmt"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
)

// Private connections (AWS PrivateLink) to Rowsafe Cloud servers: read-only.
// Turning one on or off, changing who can connect and creating endpoints
// are for people in the dashboard (they cost money and change networking).

type privateConnectionInput struct {
	Server string `json:"server" jsonschema:"the server's name (as list_hosts shows it) or its Rowsafe Cloud server ID (cs_...)"`
}

// PrivateConnectionOutput is get_private_connection's result.
type PrivateConnectionOutput struct {
	Server string                       `json:"server"`
	View   client.PrivateConnectionView `json:"private_connection"`
}

func (t *tools) addCloudReadTools(s *sdk.Server) {
	sdk.AddTool(s, &sdk.Tool{
		Name: "get_private_connection",
		Description: "Shows a Rowsafe Cloud server's private connection from the customer's AWS network (AWS PrivateLink): whether it's offered and its price, " +
			"whether it's on, the endpoint service name to paste in the AWS console, the region and zone IDs, the AWS accounts allowed to connect, " +
			"the endpoints connected and their state, and how apps connect (host, port, sslmode=require). Read-only: turning it on or off, " +
			"changing the accounts and creating endpoints are done by an owner or admin in the dashboard.",
		Annotations: readOnly("Private connection"),
	}, t.getPrivateConnection)
}

func (t *tools) getPrivateConnection(ctx context.Context, _ *sdk.CallToolRequest, in privateConnectionInput) (*sdk.CallToolResult, PrivateConnectionOutput, error) {
	servers, err := t.c.CloudServers(ctx)
	if err != nil {
		return nil, PrivateConnectionOutput{}, apiError(err)
	}
	var srv *client.CloudServerRef
	for i := range servers {
		if servers[i].ID == in.Server || servers[i].Name == in.Server {
			srv = &servers[i]
			break
		}
	}
	if srv == nil {
		return nil, PrivateConnectionOutput{}, fmt.Errorf("no server named %q was created by Rowsafe in this organization", in.Server)
	}
	v, err := t.c.PrivateConnection(ctx, srv.ID)
	if err != nil {
		return nil, PrivateConnectionOutput{}, apiError(err)
	}
	out := PrivateConnectionOutput{Server: srv.Name, View: v}
	var b textBuilder
	switch {
	case !v.Offered:
		b.line("%s: private connections aren't offered for this server (they are for Rowsafe Cloud servers on AWS, when the control plane offers them).", srv.Name)
	case v.Link == nil:
		b.line("%s: no private connection. It can be turned on in the dashboard (the server's page): %s a month at most, billed by the hour, AWS only, same region (%s).",
			srv.Name, money(v.PriceCents, v.Currency), v.RegionName)
		if v.Unavailable != "" {
			b.line("Right now: %s", v.Unavailable)
		}
	default:
		l := v.Link
		b.line("%s: private connection %s (%s).", srv.Name, l.Status, l.Step)
		if l.Problem != nil {
			b.line("Problem: %s", *l.Problem)
		}
		if l.ServiceName != nil {
			b.line("Endpoint service name: %s (region %s, zone IDs %s).", *l.ServiceName, v.Region, strings.Join(l.Zones, ", "))
		}
		b.line("AWS accounts allowed to connect: %s.", strings.Join(l.Accounts, ", "))
		for _, c := range l.Connections {
			b.line("- endpoint %s from account %s: %s", c.ID, c.Account, c.State)
		}
		for _, e := range v.Endpoints {
			b.line("- endpoint Rowsafe created in %s (%s, %s): %s %s", e.AccountName, e.NetworkID, e.EndpointID, e.State, e.DNSName)
		}
		if v.Connection != nil {
			b.line("Apps connect to %s port %d with sslmode=%s. %s", v.Connection.Host, v.Connection.Port, v.Connection.SSLMode, v.Connection.TLS)
		}
		if v.OnlyPrivate {
			b.line("The database's port is closed to the internet: only private connections.")
		}
	}
	return text(b), out, nil
}

func money(cents int64, currency string) string {
	if currency == "" || currency == "USD" {
		return fmt.Sprintf("$%d", cents/100)
	}
	return fmt.Sprintf("%d.%02d %s", cents/100, cents%100, currency)
}
