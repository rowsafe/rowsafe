package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Rowsafe Cloud's maintenance window (protocol/maintenance.go): the weekly
// hour updates that need a restart go in, a Mark first. Owners, admins and
// read-write API keys; not AI assistants through MCP.

func maintenancePath(id string) string { return "/v1/cloud/servers/" + esc(id) + "/maintenance" }

// CloudMaintenance is a Rowsafe Cloud server's window, what the next one
// applies and the critical fixes it is missing.
func (c *Client) CloudMaintenance(ctx context.Context, id string) (out protocol.MaintenanceInfo, err error) {
	return out, c.do(ctx, http.MethodGet, maintenancePath(id), nil, &out)
}

// SetCloudMaintenance changes the window (or turns it off).
func (c *Client) SetCloudMaintenance(ctx context.Context, id string, req protocol.MaintenanceWindowRequest) (out protocol.MaintenanceInfo, err error) {
	return out, c.do(ctx, http.MethodPut, maintenancePath(id), req, &out)
}

// PostponeCloudMaintenance skips the next window once (a week later).
func (c *Client) PostponeCloudMaintenance(ctx context.Context, id string) (out protocol.MaintenanceInfo, err error) {
	return out, c.do(ctx, http.MethodPost, maintenancePath(id)+"/postpone", nil, &out)
}

// ApplyCloudMaintenanceNow applies what the next window would, now.
// confirm is the server's name.
func (c *Client) ApplyCloudMaintenanceNow(ctx context.Context, id, confirm string) (out protocol.MaintenanceInfo, err error) {
	return out, c.do(ctx, http.MethodPost, maintenancePath(id)+"/apply-now", protocol.ConfirmRequest{Confirm: confirm}, &out)
}

// SetCloudDeleteAfter changes when Rowsafe deletes a clone: hours from now
// (from when it's ready, for one being set up); 0 keeps it.
func (c *Client) SetCloudDeleteAfter(ctx context.Context, id string, hours int) (out CloudServer, err error) {
	body := struct {
		Hours int `json:"hours"`
	}{hours}
	return out, c.do(ctx, http.MethodPut, "/v1/cloud/servers/"+esc(id)+"/delete-after", body, &out)
}
