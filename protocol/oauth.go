package protocol

import "time"

// "Sign in with Rowsafe": OAuth 2.1 for the remote MCP endpoint (/mcp).
// AI apps (ChatGPT, Claude, Cursor, VS Code, ...) connect without an API
// key: the control plane is the authorization server, a person approves the
// connection in the dashboard, and the app gets short-lived access tokens
// bound to the MCP endpoint. They never get more than the scopes below.

// OAuth scopes. AI apps can read (always) and, when the person allows it,
// save Marks. Nothing else, ever: no restores, restarts, fixes or settings.
const (
	// ScopeRead reads databases' health, backups, Proof runs, Marks and
	// recommendations: the read-only MCP tools.
	ScopeRead = "rowsafe:read"
	// ScopeMarks also allows create_restore_point (save a Mark).
	ScopeMarks = "rowsafe:marks"
	// ScopeOfflineAccess is accepted (and ignored: refresh tokens are always
	// issued) because some clients ask for it.
	ScopeOfflineAccess = "offline_access"
)

// OAuthScopes are the scopes an AI app can be granted, in display order.
var OAuthScopes = []string{ScopeRead, ScopeMarks}

// Token prefixes. Access tokens only work on /mcp.
const (
	OAuthAccessTokenPrefix  = "rso_"
	OAuthRefreshTokenPrefix = "rsr_"
)

// OAuthConnection is an AI app connected to an organization with "Sign in
// with Rowsafe" (Settings, Connected apps).
type OAuthConnection struct {
	ID         string `json:"id"`
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	// VerifiedDomain is the domain that published the app's identity (a
	// client ID metadata document, e.g. chatgpt.com). Empty when the app
	// registered itself and its name is unverified.
	VerifiedDomain string `json:"verified_domain,omitempty"`
	// RedirectHost is where approvals were sent: a website host, or
	// "localhost" for an app on the person's own computer.
	RedirectHost string     `json:"redirect_host"`
	Scopes       []string   `json:"scopes"`
	ApprovedBy   string     `json:"approved_by"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// OAuth authorization request statuses (the consent page).
const (
	OAuthRequestPending   = "pending"
	OAuthRequestApproved  = "approved"
	OAuthRequestDenied    = "denied"
	OAuthRequestCompleted = "completed" // the app received its code
	OAuthRequestExpired   = "expired"
)

// OAuthAuthorizationRequest is an AI app asking to connect, as the
// dashboard's consent page shows it (GET /v1/internal/oauth/requests/{id}).
type OAuthAuthorizationRequest struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	ClientID       string `json:"client_id"`
	ClientName     string `json:"client_name"`
	ClientURI      string `json:"client_uri,omitempty"`
	VerifiedDomain string `json:"verified_domain,omitempty"`
	// RedirectURI is where the app receives the approval; RedirectHost its
	// host, shown on the consent page. Loopback is true for an app running on
	// the person's own computer (http://localhost or 127.0.0.1).
	RedirectURI  string   `json:"redirect_uri"`
	RedirectHost string   `json:"redirect_host"`
	Loopback     bool     `json:"loopback"`
	Scopes       []string `json:"scopes"` // what the app asked for
	// OrgID and GrantedScopes are set once the request was decided.
	OrgID         string    `json:"org_id,omitempty"`
	GrantedScopes []string  `json:"granted_scopes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// ApproveOAuthRequest approves a request for one organization. Scopes must
// include ScopeRead and may add ScopeMarks.
type ApproveOAuthRequest struct {
	OrgID  string   `json:"org_id"`
	Scopes []string `json:"scopes"`
}

// DenyOAuthRequest's OrgID is optional; with it the denial is audit-logged
// in that org.
type DenyOAuthRequest struct {
	OrgID string `json:"org_id,omitempty"`
}

// OAuthDecision tells the dashboard where to send the browser next: back to
// the control plane, which hands the app its answer.
type OAuthDecision struct {
	ContinueURL string `json:"continue_url"`
}
