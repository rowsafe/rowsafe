package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
}

type clientKey struct{}

// NewHTTPHandler serves MCP over Streamable HTTP. Every request must carry an
// org API key (Authorization: Bearer rsk_...); the tools act as that key
// through the user API served by api. Write tools are always listed: the API
// refuses them with 403 for a read-only key.
func NewHTTPHandler(api http.Handler, opts HTTPOptions) http.Handler {
	if opts.MaxWait <= 0 {
		opts.MaxWait = 45 * time.Second
	}
	cache := sdk.NewSchemaCache()
	inProcess := &http.Client{Transport: handlerTransport{api}, Timeout: 30 * time.Second}
	mcpHandler := sdk.NewStreamableHTTPHandler(func(r *http.Request) *sdk.Server {
		c, _ := r.Context().Value(clientKey{}).(*client.Client)
		if c == nil {
			return nil
		}
		return NewServer(c, Options{AllowWrites: true, Remote: true, Version: opts.Version, MaxWait: opts.MaxWait, SchemaCache: cache})
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		key = strings.TrimSpace(key)
		if !strings.HasPrefix(key, "rsk_") {
			unauthorized(w, "missing or invalid API key: send Authorization: Bearer rsk_...")
			return
		}
		var c *client.Client
		if opts.APIURL != "" {
			c = client.New(strings.TrimRight(opts.APIURL, "/"), key)
		} else {
			c = client.New("http://rowsafed.internal", key)
			c.HTTP = inProcess
		}
		// Authenticate up front so a bad key fails the MCP handshake with 401
		// instead of every tool call.
		if _, err := c.Org(r.Context()); err != nil {
			if isStatus(err, http.StatusUnauthorized) {
				unauthorized(w, "invalid API key")
				return
			}
			if opts.Logger != nil {
				opts.Logger.Error("mcp: authenticating request", "err", err)
			}
			writeJSONError(w, http.StatusBadGateway, "could not authenticate the request")
			return
		}
		mcpHandler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientKey{}, c)))
	})
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="rowsafe"`)
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
