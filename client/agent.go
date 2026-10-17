package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// The agent's setup API, with the agent's own token as the key (the
// installer's `rowsafe-agent setup`, and `sudo rowsafe login` connecting a
// server without an account): it only reaches the calling host's databases.

// SetupRegister registers a database of the agent's host and queues its
// plan (a database already registered there is returned as it is).
func (c *Client) SetupRegister(ctx context.Context, req protocol.SetupRegisterRequest) (out protocol.SetupDatabase, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/agent/setup/databases", req, &out)
}

// SetupDatabase is a registered database's setup: its plan and status.
func (c *Client) SetupDatabase(ctx context.Context, id string) (out protocol.SetupDatabase, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/agent/setup/databases/"+esc(id), nil, &out)
}

// SetupApply applies the plan the setup showed.
func (c *Client) SetupApply(ctx context.Context, id string, req protocol.SetupApplyRequest) (out protocol.SetupDatabase, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/agent/setup/databases/"+esc(id)+"/apply", req, &out)
}

// Import brings the history of a server that ran without an account into
// the account it is now connected to.
func (c *Client) Import(ctx context.Context, req protocol.ImportRequest) (out protocol.ImportResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/agent/import", req, &out)
}
