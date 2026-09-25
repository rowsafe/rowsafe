package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// HTTPOptions configures the remote (Streamable HTTP) endpoint.
type HTTPOptions struct {
	Version string
	// APIURL, when set, sends the tools' API calls over HTTP to this base URL.
	// By default they go straight to the api handler in-process, through the
	// same routing, authentication and middleware as any other request.
	APIURL string
	// MaxWait caps wait_seconds. Keep it below the HTTP server's write timeout.
	MaxWait time.Duration
	Logger  *slog.Logger
	// ResourceMetadataURL turns on "Sign in with Rowsafe": OAuth access
	// tokens (rso_...) are accepted besides API keys, and a request without
	// valid credentials gets a 401 whose WWW-Authenticate challenge points
	// clients at this OAuth protected resource metadata document (RFC 9728),
	// from which they discover the authorization server.
	ResourceMetadataURL string
}

type clientKey struct{}

// NewHTTPHandler serves MCP over Streamable HTTP. Every request must carry an
// org API key (Authorization: Bearer rsk_...) or, with ResourceMetadataURL
// set, an OAuth access token (rso_...); the tools act as that credential
// through the user API served by api. For an API key the write tools are
// always listed: the API refuses them with 403 for a read-only key. For an
// OAuth token the tools follow its scopes: read-only tools, plus
// create_restore_point with rowsafe:marks. The API enforces the same scopes.
func NewHTTPHandler(api http.Handler, opts HTTPOptions) http.Handler {
	if opts.MaxWait <= 0 {
		opts.MaxWait = 45 * time.Second
	}
	cache := sdk.NewSchemaCache()
	inProcess := &http.Client{Transport: handlerTransport{api}, Timeout: 30 * time.Second}
	mcpHandler := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		a, _ := r.Context().Value(clientKey{}).(*access)
		if a == nil {
			return nil
		}
		return NewServer(a.c, Options{AllowWrites: a.writes, AllowRestorePoints: a.marks, Remote: true, Version: opts.Version,
			MaxWait: opts.MaxWait, SchemaCache: cache})
	}, &sdk.StreamableHTTPOptions{
		// Each request stands alone and is authenticated on its own; no
		// session outlives it. Plain JSON responses pass any proxy.
		Stateless:    true,
		JSONResponse: true,
		// rowsafed listens on loopback behind a TLS proxy, which forwards a
		// public Host header. Every request is authenticated by its API key,
		// which is what DNS-rebinding protection would otherwise stand in for.
		DisableLocalhostProtection: true,
		MaxRequestBodyBytes:        1 << 20,
		Logger:                     opts.Logger,
	})

	oauth := opts.ResourceMetadataURL != ""
	challenge := func(w http.ResponseWriter, invalidToken bool, msg string) {
		unauthorized(w, opts.ResourceMetadataURL, invalidToken, msg)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		key = strings.TrimSpace(key)
		isKey := strings.HasPrefix(key, "rsk_")
		isToken := oauth && strings.HasPrefix(key, protocol.OAuthAccessTokenPrefix)
		if !isKey && !isToken {
			if oauth {
				challenge(w, key != "", "sign in with Rowsafe, or send Authorization: Bearer rsk_...")
			} else {
				challenge(w, false, "missing or invalid API key: send Authorization: Bearer rsk_...")
			}
			return
		}
		var c *client.Client
		switch {
		case opts.APIURL != "":
			c = client.New(strings.TrimRight(opts.APIURL, "/"), key)
		default:
			c = client.New("http://rowsafed.internal", key)
			c.HTTP = inProcess
		}
		// Authenticate up front so bad credentials fail the MCP handshake
		// with 401 instead of every tool call.
		a := &access{c: c}
		var err error
		if isKey {
			a.writes = true
			_, err = c.Org(r.Context())
		} else {
			var who protocol.WhoAmI
			if who, err = c.WhoAmI(r.Context()); err == nil {
				if who.OAuth == nil {
					err = &client.APIError{Status: http.StatusUnauthorized, Msg: "not an OAuth access token"}
				} else {
					a.marks = slices.Contains(who.OAuth.Scopes, protocol.ScopeMarks)
				}
			}
		}
		if err != nil {
			if isStatus(err, http.StatusUnauthorized) {
				if isKey {
					challenge(w, true, "invalid API key")
				} else {
					challenge(w, true, "the access token is invalid, expired or revoked: sign in with Rowsafe again")
				}
				return
			}
			if opts.Logger != nil {
				opts.Logger.Error("mcp: authenticating request", "err", err)
			}
			writeJSONError(w, http.StatusBadGateway, "could not authenticate the request")
			return
		}
		mcpHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, a)))
	})
}

// access is what one request's credentials may use.
type access struct {
	c      *client.Client
	writes bool // API key: every write tool (the API checks read-only keys)
	marks  bool // OAuth token with rowsafe:marks
}

// unauthorized answers 401 with a Bearer challenge. With OAuth on it names
// the protected resource metadata and the scopes to ask for (MCP
// authorization, RFC 9728 section 5.1, RFC 6750 section 3).
func unauthorized(w http.ResponseWriter, resourceMetadata string, invalidToken bool, msg string) {
	params := []string{`realm="rowsafe"`}
	if resourceMetadata != "" {
		params = append([]string{fmt.Sprintf("resource_metadata=%q", resourceMetadata),
			fmt.Sprintf("scope=%q", strings.Join(protocol.OAuthScopes, " "))}, params...)
	}
	if invalidToken {
		params = append(params, `error="invalid_token"`)
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	writeJSONError(w, http.StatusUnauthorized, msg)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(protocol.Error{Error: msg})
}

// handlerTransport serves client requests with an http.Handler in-process.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	if r.Body == nil {
		r.Body = http.NoBody
	}
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "127.0.0.1:0" // in-process MCP tool call
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	resp := rec.Result()
	resp.Request = req
	return resp, nil
}
