package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// RestoreFromBucket restores a database from the bucket onto this server
// (a server on its own: protocol/restore_bucket.go).
func (c *Client) RestoreFromBucket(ctx context.Context, req protocol.BucketRestoreRequest) (out protocol.BucketRestoreResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/restores/from-bucket", req, &out)
}
