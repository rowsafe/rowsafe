package qdrant

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Login is how the agent reaches one Qdrant server: Rowsafe's own key
// (the server's alternative key, service.alt_api_key, set by root at
// install), or a key the person gave (save-login). It is saved in the
// engine's state directory, readable only by the agent, and never leaves
// the server: with JWT access control on, the agent doesn't even send it
// to Qdrant, only tokens it signs with it, valid for a few minutes.
type Login struct {
	Key string `json:"key,omitempty"`
	// JWT: the server accepts tokens signed with Key (service.jwt_rbac),
	// so the agent sends those rather than the key itself.
	JWT bool `json:"jwt,omitempty"`
	// URL is where the server's REST API is (scheme, host and port), ""
	// for this server on the port (https when it has TLS on, else http).
	URL string `json:"url,omitempty"`
	// Source: "alt" (Rowsafe's own key, from root), "key" (one the person
	// gave), "" (no key: the server needs none).
	Source string `json:"source,omitempty"`
}

// urlEnv points a Docker sidecar at the database's container
// ("https://qdrant:6333").
const urlEnv = "ROWSAFE_QDRANT_URL"

// caEnv is an optional CA file to verify ROWSAFE_QDRANT_URL's certificate.
const caEnv = "ROWSAFE_QDRANT_CA_FILE"

// ErrNoLogin explains a server without Rowsafe's key.
var ErrNoLogin = errors.New("Rowsafe has no key for this Qdrant server yet: run the Rowsafe installer on the server again to give it one")

func loginsDir(env agent.EngineEnv) string { return filepath.Join(env.SharedStateDir(), "logins") }

func loginPath(env agent.EngineEnv, port int) string {
	return filepath.Join(loginsDir(env), strconv.Itoa(port)+".json")
}

// loadLogin reads the saved login for the server on port (ok false: none).
func loadLogin(env agent.EngineEnv, port int) (Login, bool, error) {
	data, err := os.ReadFile(loginPath(env, port))
	if errors.Is(err, os.ErrNotExist) {
		return Login{}, false, nil
	}
	if err != nil {
		return Login{}, false, err
	}
	var l Login
	if err := json.Unmarshal(data, &l); err != nil {
		return Login{}, false, fmt.Errorf("reading %s: %w", loginPath(env, port), err)
	}
	return l, true, nil
}

// saveLogin writes the login (0600) for the server on port.
func saveLogin(env agent.EngineEnv, port int, l Login) error {
	if err := os.MkdirAll(loginsDir(env), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(l, "", "  ")
	f, err := os.CreateTemp(loginsDir(env), ".login-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, loginPath(env, port))
}

// inDocker: the agent is a sidecar reaching the server in another container.
func inDocker() bool { return strings.TrimSpace(os.Getenv(urlEnv)) != "" }

// client talks to one Qdrant server's REST API.
type client struct {
	base    *url.URL
	http    *http.Client
	key     string
	jwt     bool
	tokenMu sync.Mutex
	token   string
	tokenAt time.Time
}

// signToken makes a JWT (HS256) with claims, signed with key, the way
// Qdrant checks them (the secret is the key's bytes).
func signToken(key string, claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	head := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	msg := head + "." + enc.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(msg))
	return msg + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

// agentTokenTTL is how long the agent's own tokens are valid.
const agentTokenTTL = 5 * time.Minute

// authHeader sets the request's credentials.
func (c *client) authHeader(h http.Header) error {
	if c.key == "" {
		return nil
	}
	if !c.jwt {
		h.Set("api-key", c.key)
		return nil
	}
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token == "" || time.Since(c.tokenAt) > agentTokenTTL/2 {
		now := time.Now()
		t, err := signToken(c.key, map[string]any{"access": "m", "exp": now.Add(agentTokenTTL).Unix(), "subject": "rowsafe-agent"})
		if err != nil {
			return err
		}
		c.token, c.tokenAt = t, now
	}
	h.Set("authorization", "Bearer "+c.token)
	return nil
}

// apiError is an error answer from Qdrant.
type apiError struct {
	Status  int
	Message string
}

func (e *apiError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "Qdrant refused Rowsafe's key (" + e.Message + "): run the Rowsafe installer on the server again to give it a new one"
	}
	if e.Message == "" {
		return fmt.Sprintf("Qdrant answered %d", e.Status)
	}
	return "Qdrant: " + e.Message
}

func isStatus(err error, status int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == status
}

// envelope is Qdrant's answer: {"result": ..., "status": "ok"|{"error": ...}}.
type envelope struct {
	Result json.RawMessage `json:"result"`
	Status json.RawMessage `json:"status"`
}

func statusError(raw json.RawMessage) string {
	var s struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &s) == nil && s.Error != "" {
		return s.Error
	}
	var str string
	if json.Unmarshal(raw, &str) == nil && str != "ok" {
		return str
	}
	return ""
}

// request sends one request; body is JSON-encoded unless it is an
// io.Reader (sent as is, with contentType).
func (c *client) request(ctx context.Context, method, path string, q url.Values, body any, contentType string) (*http.Response, error) {
	u := *c.base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	if q != nil {
		u.RawQuery = q.Encode()
	}
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case io.Reader:
		rd = b
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		rd, contentType = bytes.NewReader(data), "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if err := c.authHeader(req.Header); err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, plainConnError(err)
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		msg := strings.TrimSpace(string(data))
		var env envelope
		if json.Unmarshal(data, &env) == nil && len(env.Status) > 0 {
			if m := statusError(env.Status); m != "" {
				msg = m
			}
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, &apiError{Status: resp.StatusCode, Message: msg}
	}
	return resp, nil
}

// call sends a JSON request and decodes the answer's result into out
// (nil: ignored).
func (c *client) call(ctx context.Context, method, path string, q url.Values, body, out any) error {
	resp, err := c.request(ctx, method, path, q, body, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var env envelope
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<20)).Decode(&env); err != nil {
		return fmt.Errorf("reading Qdrant's answer to %s %s: %w", method, path, err)
	}
	if m := statusError(env.Status); m != "" {
		return &apiError{Status: resp.StatusCode, Message: m}
	}
	if out == nil || len(env.Result) == 0 {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// get is a GET returning the raw body (non-JSON endpoints: /metrics).
func (c *client) getRaw(ctx context.Context, path string, limit int64) ([]byte, error) {
	resp, err := c.request(ctx, http.MethodGet, path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// plainConnError makes a dial error read as a sentence.
func plainConnError(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return fmt.Errorf("Qdrant isn't answering (%v): is it running?", oe.Err)
	}
	return err
}

// tlsFor is how the agent checks the server's certificate: on this
// machine (loopback) the certificate is for the server's public names or
// self-signed, and the connection never leaves the machine, so it is read
// but not checked against a name; a sidecar's URL is checked against
// ROWSAFE_QDRANT_CA_FILE when set.
func tlsFor(base *url.URL) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca := strings.TrimSpace(os.Getenv(caEnv)); ca != "" && !isLoopback(base.Hostname()) {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", ca)
		}
		cfg.RootCAs = pool
		return cfg, nil
	}
	cfg.InsecureSkipVerify = true //nolint:gosec // loopback, or a sidecar's private network without a CA file
	return cfg, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func newHTTPClient(base *url.URL) (*http.Client, error) {
	cfg, err := tlsFor(base)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: cfg, Proxy: nil, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second}
	return &http.Client{Transport: tr}, nil
}

// schemeCache remembers whether a local port speaks TLS.
var schemeCache sync.Map // "127.0.0.1:6333" -> "https" | "http"

// localScheme finds whether the server on addr speaks TLS (https) or not.
func localScheme(ctx context.Context, addr string) string {
	if v, ok := schemeCache.Load(addr); ok {
		return v.(string)
	}
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second},
		Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // loopback: only asks whether TLS is on
	hctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	nc, err := d.DialContext(hctx, "tcp", addr)
	if err == nil {
		nc.Close()
		schemeCache.Store(addr, "https")
		return "https"
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return "https" // nothing answers: the error says so later
	}
	var re tls.RecordHeaderError
	if errors.As(err, &re) || strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
		schemeCache.Store(addr, "http")
		return "http"
	}
	return "https"
}

// baseURL is where the server's REST API is.
func baseURL(ctx context.Context, l Login, port int) (*url.URL, error) {
	raw := l.URL
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv(urlEnv))
	}
	if raw == "" {
		addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		raw = localScheme(ctx, addr) + "://" + addr
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s isn't a Qdrant URL (https://host:6333)", raw)
	}
	// Plain HTTP only on this machine, or to the database's container on
	// a Docker sidecar's compose network (private to the host).
	if u.Scheme == "http" && !isLoopback(u.Hostname()) && os.Getenv("ROWSAFE_MODE") != "docker-sidecar" {
		return nil, fmt.Errorf("Rowsafe reaches Qdrant only over TLS, on this machine, or as a Docker sidecar on its compose network; %s is plain HTTP to another host", raw)
	}
	return u, nil
}

// newClient connects to a server with a login.
func newClient(ctx context.Context, l Login, port int) (*client, error) {
	base, err := baseURL(ctx, l, port)
	if err != nil {
		return nil, err
	}
	h, err := newHTTPClient(base)
	if err != nil {
		return nil, err
	}
	return &client{base: base, http: h, key: l.Key, jwt: l.JWT}, nil
}

// connectDB connects to a database's server with the saved login. A
// server without a login is reached without a key (one that needs none).
func connectDB(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*client, error) {
	return connectPort(ctx, env, db.Port)
}

func connectPort(ctx context.Context, env agent.EngineEnv, port int) (*client, error) {
	l, _, err := loadLogin(env, port)
	if err != nil {
		return nil, err
	}
	return newClient(ctx, l, port)
}

// close releases idle connections.
func (c *client) Close() {
	if t, ok := c.http.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}
