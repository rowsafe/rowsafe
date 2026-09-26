package client

import (
	"context"
	"net/http"
	"net/url"

	"github.com/rowsafe/rowsafe/protocol"
)

// Settings returns a database's PostgreSQL settings, with recommendations
// for workload ("" is the one saved for the database) and disk ("" is the
// saved or detected disk type).
func (c *Client) Settings(ctx context.Context, ref, workload, disk string) (out protocol.SettingsOverview, err error) {
	q := url.Values{}
	if workload != "" {
		q.Set("workload", workload)
	}
	if disk != "" {
		q.Set("disk", disk)
	}
	path := "/v1/databases/" + esc(ref) + "/settings"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// ApplySettings changes settings (ALTER SYSTEM + reload on the server,
// after a Mark when the database is backed up).
func (c *Client) ApplySettings(ctx context.Context, ref string, req protocol.ApplySettingsRequest) (out protocol.ApplySettingsResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/settings", req, &out)
}

// RevertSettings undoes a change made through Rowsafe.
func (c *Client) RevertSettings(ctx context.Context, ref, changeID string) (out protocol.ApplySettingsResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/settings/changes/"+esc(changeID)+"/revert", struct{}{}, &out)
}
