package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rowsafe/rowsafe/protocol"
)

// RequestApproval asks a person to approve a change (protocol.ApprovalActions).
// Nothing runs until an owner or admin approves it in the dashboard.
func (c *Client) RequestApproval(ctx context.Context, req protocol.CreateApprovalRequest) (out protocol.Approval, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/approvals", req, &out)
}

// Approvals lists approval requests, newest first; status filters
// (protocol.Approval*, "" for all).
func (c *Client) Approvals(ctx context.Context, status string, limit int) (out []protocol.Approval, err error) {
	q := url.Values{}
	if status != "" {
		q.Set("status", status)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/approvals"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// Approval returns one approval request with its outcome.
func (c *Client) Approval(ctx context.Context, id string) (out protocol.Approval, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/approvals/"+esc(id), nil, &out)
}

// CancelApproval withdraws a pending request.
func (c *Client) CancelApproval(ctx context.Context, id string) (out protocol.Approval, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/approvals/"+esc(id)+"/cancel", nil, &out)
}
