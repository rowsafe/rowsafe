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

// RestoreElsewhere restores a database whose server is lost to another
// server (its progress is a fork's).
func (c *Client) RestoreElsewhere(ctx context.Context, ref string, req protocol.RestoreElsewhereRequest) (out protocol.ForkView, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/restore-elsewhere", req, &out)
}

// RetireDatabase removes a database whose server is lost from Rowsafe,
// keeping its backups; confirm is the database's name.
func (c *Client) RetireDatabase(ctx context.Context, ref, confirm string) error {
	return c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/retire", protocol.RetireDatabaseRequest{Confirm: confirm}, nil)
}

// Fork is one fork and its progress.
func (c *Client) Fork(ctx context.Context, id string) (out protocol.ForkView, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/forks/"+esc(id), nil, &out)
}
