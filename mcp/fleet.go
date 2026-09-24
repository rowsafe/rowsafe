package mcp

import (
	"context"

	"github.com/rowsafe/rowsafe/client"
)

// CheckFleet runs the fleet_health assessment outside MCP (rowsafe status).
func CheckFleet(ctx context.Context, c *client.Client) (FleetHealth, error) {
	t := &tools{c: c}
	_, out, err := t.fleetHealth(ctx, nil, noInput{})
	return out, err
}
