package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// PostgreSQL updates and upgrades (see protocol/upgrade.go for the
// endpoints).

func dbPath(ref string) string { return "/v1/databases/" + esc(ref) }

// Upgrades is the database's versions, what can be updated or upgraded,
// the newest check and rehearsal, and an upgrade that can be undone.
func (c *Client) Upgrades(ctx context.Context, ref string) (out protocol.UpgradeInfo, err error) {
	return out, c.do(ctx, http.MethodGet, dbPath(ref)+"/upgrades", nil, &out)
}

// UpdatePostgres installs the newest minor release (a Mark first).
func (c *Client) UpdatePostgres(ctx context.Context, ref, confirm string) (out protocol.UpgradeTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/update", protocol.ConfirmRequest{Confirm: confirm}, &out)
}

// SetAutoUpdate turns automatic minor updates (Sundays 03:00 in tz) on or off.
func (c *Client) SetAutoUpdate(ctx context.Context, ref string, enabled bool, tz string) (out protocol.UpgradeInfo, err error) {
	return out, c.do(ctx, http.MethodPut, dbPath(ref)+"/auto-update", protocol.AutoUpdateRequest{Enabled: enabled, Timezone: tz}, &out)
}

// CheckUpgrade runs the upgrade preflight (to 0: the newest major).
func (c *Client) CheckUpgrade(ctx context.Context, ref string, to int) (out protocol.UpgradeTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/upgrades/check", protocol.UpgradeTargetRequest{To: to}, &out)
}

// RehearseUpgrade upgrades a restored copy, never production.
func (c *Client) RehearseUpgrade(ctx context.Context, ref string, to int) (out protocol.UpgradeTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/upgrades/rehearsal", protocol.UpgradeTargetRequest{To: to}, &out)
}

// Upgrade upgrades the database to a new major (a Mark first).
func (c *Client) Upgrade(ctx context.Context, ref string, req protocol.UpgradeRequest) (out protocol.UpgradeTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/upgrades", req, &out)
}

// UndoUpgrade goes back to the version the upgrade kept.
func (c *Client) UndoUpgrade(ctx context.Context, ref, upgradeID, confirm string) (out protocol.UpgradeTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/upgrades/"+esc(upgradeID)+"/undo", protocol.ConfirmRequest{Confirm: confirm}, &out)
}

// CleanupUpgrade removes the version an upgrade (or its undo) kept aside.
func (c *Client) CleanupUpgrade(ctx context.Context, ref, upgradeID, confirm string) (out protocol.UpgradeTasksResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/upgrades/"+esc(upgradeID)+"/cleanup", protocol.ConfirmRequest{Confirm: confirm}, &out)
}
