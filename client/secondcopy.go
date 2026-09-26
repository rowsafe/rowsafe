package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Storage returns what a database's backups take in each storage, what that
// costs, and the second copy (GET /v1/databases/{ref}/storage).
func (c *Client) Storage(ctx context.Context, ref string) (out protocol.StorageOverview, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/storage", nil, &out)
}
