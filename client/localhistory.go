package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// LocalHistory is what the agent's readings over time add to a reading of
// the database (a server without an account only).
func (c *Client) LocalHistory(ctx context.Context, ref string) (out protocol.LocalHistory, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/history", nil, &out)
}
