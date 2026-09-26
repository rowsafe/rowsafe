package client

import (
	"context"

	"github.com/rowsafe/rowsafe/protocol"
)

// Pooling is a database's connection pooling (PgBouncer).
func (c *Client) Pooling(ctx context.Context, ref string) (out protocol.PoolingView, err error) {
	return out, c.do(ctx, "GET", "/v1/databases/"+esc(ref)+"/pooling", nil, &out)
}

// SetPooling turns pooling on or changes its settings; req.Confirm must be
// the database's name.
func (c *Client) SetPooling(ctx context.Context, ref string, req protocol.PoolingRequest) (out protocol.TaskView, err error) {
	return out, c.do(ctx, "PUT", "/v1/databases/"+esc(ref)+"/pooling", req, &out)
}

// PoolingOff turns pooling off; confirm must be the database's name.
func (c *Client) PoolingOff(ctx context.Context, ref, confirm string) (out protocol.TaskView, err error) {
	return out, c.do(ctx, "POST", "/v1/databases/"+esc(ref)+"/pooling/off", protocol.PoolingRequest{Confirm: confirm}, &out)
}
