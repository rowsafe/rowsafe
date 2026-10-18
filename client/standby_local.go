package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// A standby on servers without an account (protocol/standby_local.go): the
// changes each server's own control plane makes.

// LocalStandbyCreate turns this server's empty cluster (or a fenced old
// primary) into the database's standby.
func (c *Client) LocalStandbyCreate(ctx context.Context, ref string, req protocol.LocalStandbyRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref), req, &out)
}

// LocalStandbyLink lets a standby stream from this server's database.
func (c *Client) LocalStandbyLink(ctx context.Context, ref string, req protocol.LocalLinkRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/link", req, &out)
}

// LocalStandbyChange is a change confirmed with the database's name:
// unlink, fence, unfence or remove.
func (c *Client) LocalStandbyChange(ctx context.Context, ref, action, confirm string) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/"+action, protocol.StandbyConfirmRequest{Confirm: confirm}, &out)
}
