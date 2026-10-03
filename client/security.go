package client

import (
	"context"
	"net/http"

	"github.com/rowsafe/rowsafe/protocol"
)

// Security check (Pulse, Security; see protocol/security.go).

// Security is a database's security grade, findings and checklist.
func (c *Client) Security(ctx context.Context, ref string) (out protocol.SecurityView, err error) {
	return out, c.do(ctx, http.MethodGet, dbPath(ref)+"/security", nil, &out)
}

// CheckSecurity re-reads the database's security settings now (a read-only
// security_scan task) and starts a check from the internet when it is on.
func (c *Client) CheckSecurity(ctx context.Context, ref string) (out protocol.SecurityCheckResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/security/check", nil, &out)
}
