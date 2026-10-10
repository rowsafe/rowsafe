package client

import (
	"context"
	"net/http"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// HostPermissions is what root on a server allowed Rowsafe to do there
// (GET /v1/hosts/{ref}/permissions; protocol/permissions.go). Turning one
// on takes root's yes (sudo rowsafe-allow NAME, or a passkey root paired,
// in the dashboard); turning one off is a click in the dashboard.
type HostPermissions struct {
	HostID     string     `json:"host_id"`
	Hostname   string     `json:"hostname"`
	Online     bool       `json:"online"`
	Reported   bool       `json:"reported"`
	ReportedAt *time.Time `json:"reported_at,omitempty"`
	// AllowCommand: `sudo rowsafe-allow` works on this server.
	AllowCommand bool `json:"allow_command"`
	// Sidecar: a Docker sidecar agent, set up in its compose file.
	Sidecar     bool                       `json:"sidecar"`
	Permissions []HostPermission           `json:"permissions"`
	Owners      []protocol.PermissionOwner `json:"owners"`
	// AddOwnerCommand pairs a passkey for one-click changes (on the server).
	AddOwnerCommand string `json:"add_owner_command"`
}

// HostPermission is one permission's state on a server.
type HostPermission struct {
	Name string `json:"name"` // protocol.Perm*
	// State: allowed, not_allowed, unavailable (Reason says why) or unknown.
	State  string `json:"state"`
	Asked  bool   `json:"asked"`
	Reason string `json:"reason,omitempty"`
	// Needs is the permission this one only works with.
	Needs string `json:"needs,omitempty"`
	// AllowCommand and RemoveCommand turn it on and off on the server.
	AllowCommand  string `json:"allow_command"`
	RemoveCommand string `json:"remove_command"`
	Removable     bool   `json:"removable"`
}

// HostPermissions reads what Rowsafe may do on a host (its ID or name).
func (c *Client) HostPermissions(ctx context.Context, ref string) (out HostPermissions, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/hosts/"+esc(ref)+"/permissions", nil, &out)
}

// AgentUpdate is a host's agent version and update state, after "Update
// now" (POST /v1/hosts/{ref}/agent-update).
type AgentUpdate struct {
	HostID   string `json:"host_id"`
	Hostname string `json:"hostname"`
	// Mode: native or docker-sidecar; Container: the agent runs from
	// Rowsafe's image, and its container is replaced instead.
	Mode      string `json:"mode"`
	Container bool   `json:"container"`
	Running   string `json:"running"`
	Channel   string `json:"channel"`
	Newest    string `json:"newest,omitempty"`
	Behind    bool   `json:"behind"`
	Status    string `json:"status"`
	Pinned    string `json:"pinned,omitempty"`
	// Requested is the version asked for, until it arrives.
	Requested   string     `json:"requested,omitempty"`
	RequestedAt *time.Time `json:"requested_at,omitempty"`
}

// UpdateAgentNow offers a host's agent the newest release (or version) on
// its next heartbeat, ahead of the staged rollout. Pins and halts still
// apply.
func (c *Client) UpdateAgentNow(ctx context.Context, ref, version string) (out AgentUpdate, err error) {
	body := struct {
		Version string `json:"version"`
	}{version}
	return out, c.do(ctx, http.MethodPost, "/v1/hosts/"+esc(ref)+"/agent-update", body, &out)
}
