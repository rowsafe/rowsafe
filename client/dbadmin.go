package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Databases & users: the databases, users and extensions inside a database
// server (see protocol/dbadmin.go for the endpoints).

func dbadminPath(ref string) string { return "/v1/databases/" + esc(ref) + "/dbadmin" }

// DBAdminState is the latest list and the dbadmin task running now.
func (c *Client) DBAdminState(ctx context.Context, ref string) (out protocol.DBAdminState, err error) {
	return out, c.do(ctx, http.MethodGet, dbadminPath(ref), nil, &out)
}

// DBAdmin queues one action (a list, create a database, a user...). The
// last task is the action itself; a restore point may come before it.
func (c *Client) DBAdmin(ctx context.Context, ref string, p protocol.DBAdminParams) (out protocol.DBAdminResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbadminPath(ref), p, &out)
}

// DBAdminSecret fetches the sealed password of a finished task, once.
func (c *Client) DBAdminSecret(ctx context.Context, ref, taskID string) (out protocol.SealedSecret, err error) {
	return out, c.do(ctx, http.MethodPost, dbadminPath(ref)+"/secret", protocol.DBAdminSecretRequest{TaskID: taskID}, &out)
}
