package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment (see protocol/moment.go for the endpoints).

func momentsPath(ref string) string { return "/v1/databases/" + esc(ref) + "/moments" }

// FindMoment queues a find_moment search; its result (a
// protocol.FindMomentResult) arrives in the task.
func (c *Client) FindMoment(ctx context.Context, ref string, req protocol.FindMomentRequest) (out protocol.TaskView, err error) {
	return out, c.do(ctx, http.MethodPost, momentsPath(ref), req, &out)
}

// Moments lists recent searches, the searchable window and known tables.
func (c *Client) Moments(ctx context.Context, ref string) (out protocol.MomentsInfo, err error) {
	return out, c.do(ctx, http.MethodGet, momentsPath(ref), nil, &out)
}
