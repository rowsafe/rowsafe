package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Standby: a second server that follows the primary and can take over (see
// protocol/standby.go for the endpoints).

func standbyPath(ref string) string { return "/v1/databases/" + esc(ref) + "/standby" }

// StandbyInfo is the database's standby, fenced old primaries, failover
// settings and timeline.
func (c *Client) StandbyInfo(ctx context.Context, ref string) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodGet, standbyPath(ref), nil, &out)
}

// StandbyCandidates lists the servers that could hold the standby.
func (c *Client) StandbyCandidates(ctx context.Context, ref string) (out []protocol.StandbyCandidate, err error) {
	return out, c.do(ctx, http.MethodGet, standbyPath(ref)+"/candidates", nil, &out)
}

// CreateStandby sets up a standby on another server.
func (c *Client) CreateStandby(ctx context.Context, ref string, req protocol.CreateStandbyRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref), req, &out)
}

// PromoteStandby makes the standby the primary (stopping the old one first
// when its agent is online).
func (c *Client) PromoteStandby(ctx context.Context, ref string, req protocol.PromoteStandbyRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/promote", req, &out)
}

// RebuildStandby turns a fenced old primary into the new standby.
func (c *Client) RebuildStandby(ctx context.Context, ref string, req protocol.RebuildStandbyRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/rebuild", req, &out)
}

// RemoveStandby stops the standby and puts its cluster back as it was.
func (c *Client) RemoveStandby(ctx context.Context, ref, confirm string) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/remove", protocol.StandbyConfirmRequest{Confirm: confirm}, &out)
}

// Unfence starts a fenced primary again when its standby wasn't promoted.
func (c *Client) Unfence(ctx context.Context, ref string, req protocol.UnfenceRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/unfence", req, &out)
}

// ForgetFence stops keeping a fenced old primary stopped.
func (c *Client) ForgetFence(ctx context.Context, ref string, req protocol.ForgetFenceRequest) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPost, standbyPath(ref)+"/forget-fence", req, &out)
}

// SetFailover changes the automatic failover settings.
func (c *Client) SetFailover(ctx context.Context, ref string, req protocol.FailoverSettings) (out protocol.StandbyInfo, err error) {
	return out, c.do(ctx, http.MethodPut, standbyPath(ref)+"/failover", req, &out)
}
