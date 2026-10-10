package client

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/rowsafe/rowsafe/protocol"
)

// RequestApproval makes a change (protocol.ApprovalActions) as the person
// behind this key or connection, right away: the record comes back approved
// (done) or failed. When Rowsafe refuses (a member, a server key to compare,
// no backup yet, ...), it returns an *APIError with status 403 and the
// reason; nothing waits for a person.
func (c *Client) RequestApproval(ctx context.Context, req protocol.CreateApprovalRequest) (out protocol.Approval, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/approvals", req, &out)
}

// Approvals lists the changes AI agents made, newest first; status filters
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

// Approval returns one change an AI agent made, with its outcome.
func (c *Client) Approval(ctx context.Context, id string) (out protocol.Approval, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/approvals/"+esc(id), nil, &out)
}

// CancelApproval withdrew a request that waited for a person. Nothing waits
// any more; it is kept for compatibility.
func (c *Client) CancelApproval(ctx context.Context, id string) (out protocol.Approval, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/approvals/"+esc(id)+"/cancel", nil, &out)
}
