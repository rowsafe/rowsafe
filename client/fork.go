package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Fork: a new, independent database cloned from another at any point in its
// recovery window (see protocol/fork.go for the endpoints).

// Forks is what a database can be forked from and to, and its forks.
func (c *Client) Forks(ctx context.Context, ref string) (out protocol.ForkInfo, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/forks", nil, &out)
}

// CreateFork forks a database.
func (c *Client) CreateFork(ctx context.Context, ref string, req protocol.CreateForkRequest) (out protocol.ForkView, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/forks", req, &out)
}

// Fork is one fork and its progress.
func (c *Client) Fork(ctx context.Context, id string) (out protocol.ForkView, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/forks/"+esc(id), nil, &out)
}
