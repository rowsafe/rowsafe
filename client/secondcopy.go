package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Storage returns what a database's backups take in each storage, what that
// costs, and the second copy (GET /v1/databases/{ref}/storage).
func (c *Client) Storage(ctx context.Context, ref string) (out protocol.StorageOverview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/storage", nil, &out)
}

// SecondCopyBackups lists the backups in the second copy, newest first (on
// a server without an account: GET /v1/databases/{ref}/backups?repo=2).
func (c *Client) SecondCopyBackups(ctx context.Context, ref string, limit int) (out []protocol.Backup, err error) {
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/databases/%s/backups?repo=%d&limit=%d", esc(ref), protocol.RepoSecond, limit), nil, &out)
}
