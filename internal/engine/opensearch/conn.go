package opensearch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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

// Login is how the agent signs in to one OpenSearch server (its REST
// port). The installer creates a dedicated user "rowsafe" with a random
// password and saves it in the engine's state directory, readable only by
// the agent; it never leaves the server. NoAuth: the server runs without
// the security plugin, so there is nothing to sign in with.
type Login struct {
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	NoAuth   bool   `json:"no_auth,omitempty"`
	// TLS: the login was made over HTTPS, so it is never sent over plain
	// HTTP. PublicKey pins the server's key then (base64 SHA-256 of its
	// SubjectPublicKeyInfo): on loopback, where the certificate isn't
	// checked, only that key or the key of the certificate Rowsafe manages
	// (serverTLSDir, renewed by the agent) is trusted.
	TLS       bool   `json:"tls,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

// spki is a certificate's pinned form.
func spki(c *x509.Certificate) string {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// managedKey is the pinned form of the certificate Rowsafe manages ("" when
// there is none).
func managedKey() string {
	data, err := os.ReadFile(filepath.Join(tlsDir, serverCertFile))
	if err != nil {
		return ""
	}
	b, _ := pem.Decode(data)
	if b == nil {
		return ""
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return ""
	}
	return spki(c)
}

// errKeyChanged: the server on the port presents a key Rowsafe wasn't told
// about.
var errKeyChanged = errors.New("OpenSearch's TLS key on this server changed since Rowsafe's user was made, so Rowsafe doesn't send its password: " +
	"if you changed OpenSearch's certificate, run the Rowsafe installer on this server again to trust the new one")

// LoginUser is Rowsafe's OpenSearch user, and LoginRole its role.
const (
	LoginUser = "rowsafe"
	LoginRole = "rowsafe_agent"
)

// Environment (tests, and a server reached elsewhere than 127.0.0.1).
const (
	// urlEnv is the server's REST URL, e.g. https://127.0.0.1:9200
	// (user:password@ in it is used when no login is saved).
	urlEnv = "ROWSAFE_OPENSEARCH_URL"
	// caEnv is a CA file to check the server's certificate with when the
	// server isn't on this machine's loopback.
	caEnv = "ROWSAFE_OPENSEARCH_CA_FILE"
)

func loginsDir(env agent.EngineEnv) string { return filepath.Join(env.SharedStateDir(), "logins") }

func loginPath(env agent.EngineEnv, port int) string {
	return filepath.Join(loginsDir(env), strconv.Itoa(port)+".json")
}

// loadLogin finds the login for the server on port: the saved one, else
// the user in ROWSAFE_OPENSEARCH_URL, else none (ok is false).
func loadLogin(env agent.EngineEnv, port int) (l Login, ok bool, err error) {
	data, err := os.ReadFile(loginPath(env, port))
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &l); err != nil {
			return l, false, fmt.Errorf("reading %s: %w", loginPath(env, port), err)
		}
		return l, l.User != "" || l.NoAuth, nil
	case !errors.Is(err, os.ErrNotExist):
		return l, false, err
	}
	if u, err := url.Parse(strings.TrimSpace(os.Getenv(urlEnv))); err == nil && u.User != nil && u.User.Username() != "" {
		pw, _ := u.User.Password()
		return Login{User: u.User.Username(), Password: pw}, true, nil
	}
	return Login{}, false, nil
}

// saveLogin writes the login (0600) for the server on port.
func saveLogin(env agent.EngineEnv, port int, l Login) error {
	if err := os.MkdirAll(loginsDir(env), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(l, "", "  ")
	tmp := loginPath(env, port) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, loginPath(env, port))
}

// client talks to one OpenSearch server's REST API.
type client struct {
	base   *url.URL
	login  Login
	http   *http.Client
	scheme string // the scheme that answered (https or http)
}

// schemes remembers, per address, whether the server speaks HTTPS.
var schemes sync.Map // host:port -> "https" | "http"

// baseURL is the REST URL of the server on port: ROWSAFE_OPENSEARCH_URL
// when set, else 127.0.0.1.
func baseURL(port int) *url.URL {
	if s := strings.TrimSpace(os.Getenv(urlEnv)); s != "" {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			u.User, u.Path, u.RawQuery = nil, "", ""
			return u
		}
	}
	return &url.URL{Scheme: "https", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}
}

// loopback reports whether host is this machine's loopback.
func loopback(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// tlsConfig checks the server's certificate unless the connection stays on
// this machine (loopback: the certificate is the server's own, often
// self-signed, and nothing crosses a network).
func tlsConfig(host string) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if loopback(host) {
		c.InsecureSkipVerify = true //nolint:gosec // loopback only: the connection never leaves the server
		return c
	}
	if f := strings.TrimSpace(os.Getenv(caEnv)); f != "" {
		if pem, err := os.ReadFile(f); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(pem) {
				c.RootCAs = pool
			}
		}
	}
	return c
}

func newClient(base *url.URL, l Login) *client {
	u := *base
	tc := tlsConfig(u.Host)
	if l.PublicKey != "" && tc.InsecureSkipVerify {
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errKeyChanged
			}
			c, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if k := spki(c); k == l.PublicKey || k == managedKey() {
				return nil
			}
			return errKeyChanged
		}
	}
	tr := &http.Transport{TLSClientConfig: tc, Proxy: nil, MaxIdleConnsPerHost: 4,
		DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, TLSHandshakeTimeout: 10 * time.Second}
	return &client{base: &u, login: l, http: &http.Client{Transport: tr}, scheme: u.Scheme}
}

// apiError is an error OpenSearch answered with.
type apiError struct {
	Status int
	Type   string
	Reason string
}

func (e *apiError) Error() string {
	switch {
	case e.Status == http.StatusUnauthorized:
		return "OpenSearch refused Rowsafe's login (HTTP 401)"
	case e.Status == http.StatusForbidden && e.Reason == "":
		return "OpenSearch didn't allow Rowsafe's user to do that (HTTP 403)"
	case e.Reason != "":
		if e.Type != "" {
			return fmt.Sprintf("OpenSearch: %s (%s, HTTP %d)", e.Reason, e.Type, e.Status)
		}
		return fmt.Sprintf("OpenSearch: %s (HTTP %d)", e.Reason, e.Status)
	}
	return fmt.Sprintf("OpenSearch answered HTTP %d", e.Status)
}

// statusOf is the HTTP status of an OpenSearch error (0 for another error).
func statusOf(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

func errType(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Type
	}
	return ""
}

// parseAPIError reads OpenSearch's error body ({"error":{"type","reason"}}
// or the security plugin's {"status","message"}).
func parseAPIError(status int, body []byte) *apiError {
	e := &apiError{Status: status}
	var v struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
		Reason  string          `json:"reason"`
	}
	if json.Unmarshal(body, &v) == nil {
		var inner struct {
			Type      string `json:"type"`
			Reason    string `json:"reason"`
			RootCause []struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"root_cause"`
		}
		var s string
		switch {
		case len(v.Error) > 0 && json.Unmarshal(v.Error, &inner) == nil:
			e.Type, e.Reason = inner.Type, inner.Reason
			if e.Reason == "" && len(inner.RootCause) > 0 {
				e.Type, e.Reason = inner.RootCause[0].Type, inner.RootCause[0].Reason
			}
		case len(v.Error) > 0 && json.Unmarshal(v.Error, &s) == nil:
			e.Reason = s
		case v.Message != "":
			e.Reason = v.Message
		case v.Reason != "":
			e.Reason = v.Reason
		}
	}
	if e.Reason == "" && status != http.StatusUnauthorized && status != http.StatusForbidden {
		e.Reason = strings.TrimSpace(firstLine(string(body)))
		if len(e.Reason) > 300 {
			e.Reason = e.Reason[:300]
		}
	}
	return e
}

// raw sends one request and returns the status and body. A status of 300
// or more is an *apiError (the body is still returned).
func (c *client) raw(ctx context.Context, method, path string, body io.Reader, contentType string) (int, []byte, error) {
	u := c.base.String() + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return 0, nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "rowsafe-agent")
	if !c.login.NoAuth && c.login.User != "" {
		req.SetBasicAuth(c.login.User, c.login.Password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, plainConnError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode >= 300 {
		return resp.StatusCode, data, parseAPIError(resp.StatusCode, data)
	}
	return resp.StatusCode, data, nil
}

// do sends in (JSON, nil for none) and decodes the answer into out (nil:
// ignore it).
func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ct := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body, ct = bytes.NewReader(b), "application/json"
	}
	_, data, err := c.raw(ctx, method, path, body, ct)
	if err != nil {
		return err
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("reading OpenSearch's answer to %s %s: %w", method, strings.SplitN(path, "?", 2)[0], err)
		}
	}
	return nil
}

func (c *client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

// plainConnError turns network errors into a plain sentence.
func plainConnError(err error) error {
	var ne net.Error
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case strings.Contains(err.Error(), "connection refused"):
		return errors.New("nothing answers on OpenSearch's port (connection refused): is OpenSearch running?")
	case errors.As(err, &ne) && ne.Timeout():
		return errors.New("OpenSearch didn't answer in time")
	}
	return err
}

// notTLS reports whether err says the server answered in plain HTTP.
func notTLS(err error) bool {
	var rh tls.RecordHeaderError
	return errors.As(err, &rh) || strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") ||
		strings.Contains(err.Error(), "first record does not look like a TLS handshake")
}

// dial makes a client for the server on port with login l, finding out
// whether it speaks HTTPS (remembered per address).
func dial(ctx context.Context, port int, l Login) (*client, error) {
	base := baseURL(port)
	if s, ok := schemes.Load(base.Host); ok {
		base.Scheme = s.(string)
	}
	c := newClient(base, l)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, _, err := c.raw(cctx, http.MethodGet, "/", nil, "")
	if err != nil && base.Scheme == "https" && notTLS(err) {
		// Plain HTTP only for a server on this machine that never had TLS
		// with this login: a login made over TLS never goes in the clear.
		if l.TLS || !loopback(base.Host) {
			return c, errors.New("OpenSearch answers without TLS on this port now, and Rowsafe doesn't send its login in the clear: is it still the same server?")
		}
		base.Scheme = "http"
		c = newClient(base, l)
		_, _, err = c.raw(cctx, http.MethodGet, "/", nil, "")
	}
	if err != nil && errors.Is(err, errKeyChanged) || err != nil && strings.Contains(err.Error(), errKeyChanged.Error()) {
		return c, errKeyChanged
	}
	if err == nil || statusOf(err) != 0 {
		schemes.Store(base.Host, base.Scheme)
	}
	return c, err
}

// connectDB signs in to db's server with the saved login.
func connectDB(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*client, error) {
	return connectPort(ctx, env, db.Port)
}

func connectPort(ctx context.Context, env agent.EngineEnv, port int) (*client, error) {
	l, ok, err := loadLogin(env, port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("Rowsafe has no login for OpenSearch on port %d yet: run the Rowsafe installer on this server again to create Rowsafe's own OpenSearch user", port)
	}
	c, err := dial(ctx, port, l)
	if err != nil {
		if statusOf(err) == http.StatusUnauthorized {
			return nil, fmt.Errorf("OpenSearch on port %d refused Rowsafe's own user: run the Rowsafe installer on this server again to make it a new password", port)
		}
		return nil, err
	}
	return c, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
