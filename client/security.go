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

// UpdateSecuritySettings changes a database's security settings (today:
// whether Rowsafe checks its port from the internet) and returns the view.
func (c *Client) UpdateSecuritySettings(ctx context.Context, ref string, req protocol.UpdateSecuritySettingsRequest) (out protocol.SecurityView, err error) {
	return out, c.do(ctx, http.MethodPatch, dbPath(ref)+"/security", req, &out)
}

// SecurityAction runs one security action (protocol.Sec*). req.Confirm is
// the database's name. A new password travels only as its SCRAM verifier
// (set_password), or is made on the server and sealed to req.PublicKey
// (redis_require_password: DBAdminSecret fetches it).
func (c *Client) SecurityAction(ctx context.Context, ref string, req protocol.SecurityActionRequest) (out protocol.SecurityActionResponse, err error) {
	return out, c.do(ctx, http.MethodPost, dbPath(ref)+"/security/actions", req, &out)
}
