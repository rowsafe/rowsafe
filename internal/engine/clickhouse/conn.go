package clickhouse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Login is how the agent signs in to one ClickHouse server (its HTTP
// interface). The installer creates a dedicated user "rowsafe" with a random
// password and saves it in the engine's state directory, readable only by
// the agent; it never leaves the server.
type Login struct {
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
}

// Environment of a Docker sidecar (and of a single server elsewhere).
const (
	// urlEnv is the server's HTTP interface, e.g. http://clickhouse:8123
	// (user:password@ in it is used when no login is saved).
	urlEnv = "ROWSAFE_CLICKHOUSE_URL"
	// gatewayListenEnv is where the backup gateway listens, e.g.
	// 0.0.0.0:9010 (default 127.0.0.1, a random port).
	gatewayListenEnv = "ROWSAFE_CLICKHOUSE_GATEWAY_LISTEN"
	// gatewayURLEnv is how ClickHouse reaches the gateway, e.g.
	// http://agent:9010 (default: the address it listens on).
	gatewayURLEnv = "ROWSAFE_CLICKHOUSE_GATEWAY_URL"
)

// userAgent marks the agent's own queries (system.processes.http_user_agent).
const userAgent = "rowsafe-agent"

func loginsDir(env agent.EngineEnv) string { return filepath.Join(env.SharedStateDir(), "logins") }

func loginPath(env agent.EngineEnv, port int) string {
	return filepath.Join(loginsDir(env), strconv.Itoa(port)+".json")
}

// loadLogin finds the login for the server on port: the saved one, else
// the user in ROWSAFE_CLICKHOUSE_URL, else none (ok is false).
func loadLogin(env agent.EngineEnv, port int) (l Login, ok bool, err error) {
	data, err := os.ReadFile(loginPath(env, port))
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &l); err != nil {
			return l, false, fmt.Errorf("reading %s: %w", loginPath(env, port), err)
		}
		return l, l.User != "", nil
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

// serverURL is the HTTP interface of the server on port: ROWSAFE_CLICKHOUSE_URL
// (a Docker sidecar), else 127.0.0.1.
func serverURL(port int) *url.URL {
	if s := strings.TrimSpace(os.Getenv(urlEnv)); s != "" {
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			u.User, u.Path, u.RawQuery = nil, "/", ""
			return u
		}
	}
	return &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), Path: "/"}
}

// inDocker reports whether the agent reaches ClickHouse in another
// container (ROWSAFE_CLICKHOUSE_URL is set).
func inDocker() bool { return strings.TrimSpace(os.Getenv(urlEnv)) != "" }

// client talks to one ClickHouse server over HTTP.
type client struct {
	base *url.URL
	user string
	pass string
	http *http.Client
	ua   string // User-Agent ("rowsafe-agent")
	// condCache: the server has the query condition cache (25.3+), which
	// the index advisor turns off for its measurements.
	condCache bool
}

var sharedTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConnsPerHost = 4
	t.ResponseHeaderTimeout = 0 // long queries stream their answer late
	return t
}()

func newClient(base *url.URL, l Login) *client {
	return &client{base: base, user: l.User, pass: l.Password, http: &http.Client{Transport: sharedTransport}, ua: userAgent}
}

// connectDB is a client for a production database's server, checked with
// a first query.
func connectDB(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*client, error) {
	l, ok, err := loadLogin(env, db.Port)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNoLogin
	}
	c := newClient(serverURL(db.Port), l)
	if err := c.ping(ctx); err != nil {
		return nil, fmt.Errorf("can't connect to ClickHouse on port %d: %w", db.Port, err)
	}
	return c, nil
}

// ErrNoLogin: the agent has no ClickHouse login for the server yet.
var ErrNoLogin = errors.New("Rowsafe has no ClickHouse login on this server yet: run the Rowsafe installer on the server again to create it")

// ping runs SELECT 1 (it proves the login too).
func (c *client) ping(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := c.scalar(pctx, "SELECT 1", nil)
	return err
}

// Error is an error ClickHouse returned.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string { return e.Message }

var codeRE = regexp.MustCompile(`Code: (\d+)\. `)

// ClickHouse error codes the engine reacts to.
const (
	codeRequiredPassword     = 194
	codeAccessDenied         = 497
	codeAuthenticationFailed = 516
	codeUnknownUser          = 192
)

// errCode is err's ClickHouse error code (0 when it isn't one).
func errCode(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func parseError(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	e := &Error{Message: msg}
	if m := codeRE.FindStringSubmatch(msg); m != nil {
		e.Code, _ = strconv.Atoi(m[1])
	}
	if e.Code == 0 && msg == "" {
		e.Message = fmt.Sprintf("ClickHouse answered HTTP %d", status)
	}
	return e
}

// request sends query (in the body, or in the URL with data as the body for
// an INSERT) with query parameters ({name:Type}) and settings.
func (c *client) request(ctx context.Context, query string, params map[string]string, settings map[string]string, data io.Reader) (*http.Response, error) {
	u := *c.base
	q := url.Values{}
	for k, v := range settings {
		q.Set(k, v)
	}
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	var body io.Reader = strings.NewReader(query)
	if data != nil {
		q.Set("query", query)
		body = data
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), body)
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.pass)
	}
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, plainConnError(err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		return nil, parseError(resp.StatusCode, b)
	}
	return resp, nil
}

func newGet(ctx context.Context, u string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err == nil {
		req.Header.Set("User-Agent", userAgent)
	}
	return req, err
}

// exec runs a statement and drops its answer.
func (c *client) exec(ctx context.Context, query string, params map[string]string, settings ...string) error {
	resp, err := c.request(ctx, query, params, withWait(settings), nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return midStreamError(b)
}

// withWait turns "k", "v" pairs into settings and asks ClickHouse to answer
// only once the query finished (so an error comes with an error status).
func withWait(kv []string) map[string]string {
	s := map[string]string{"wait_end_of_query": "1"}
	for i := 0; i+1 < len(kv); i += 2 {
		s[kv[i]] = kv[i+1]
	}
	return s
}

// midStreamError finds an error ClickHouse wrote after it started answering.
func midStreamError(b []byte) error {
	i := bytes.LastIndex(b, []byte("Code: "))
	if i < 0 || !bytes.Contains(b[i:], []byte("DB::Exception")) {
		return nil
	}
	return parseError(200, b[i:])
}

// query runs a SELECT and decodes each row (JSONEachRow) into a T.
func query[T any](ctx context.Context, c *client, q string, params map[string]string, settings ...string) ([]T, error) {
	s := withWait(settings)
	s["output_format_json_quote_64bit_integers"] = "0"
	s["output_format_json_quote_denormals"] = "0"
	s["default_format"] = "JSONEachRow"
	resp, err := c.request(ctx, q, params, s, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out []T
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64<<10), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			if e := midStreamError(line); e != nil {
				return out, e
			}
			return out, fmt.Errorf("reading ClickHouse's answer: %w", err)
		}
		out = append(out, v)
	}
	return out, sc.Err()
}

// scalar runs a query that returns one value, as text.
func (c *client) scalar(ctx context.Context, q string, params map[string]string, settings ...string) (string, error) {
	s := withWait(settings)
	s["default_format"] = "TabSeparatedRaw"
	resp, err := c.request(ctx, q, params, s, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if e := midStreamError(b); e != nil {
		return "", e
	}
	return strings.TrimRight(string(b), "\n"), nil
}

// plainConnError turns network errors into something people read.
func plainConnError(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "connection refused"):
		return errors.New("nothing answers on that port (is ClickHouse running?)")
	case strings.Contains(s, "no such host"):
		return fmt.Errorf("the ClickHouse host isn't known here (%s)", firstLine(s))
	case strings.Contains(s, "context deadline exceeded"), strings.Contains(s, "i/o timeout"):
		return fmt.Errorf("ClickHouse didn't answer in time (%s)", firstLine(s))
	}
	return err
}

// plainLoginError explains a refused login.
func plainLoginError(err error) error {
	switch errCode(err) {
	case codeAuthenticationFailed, codeRequiredPassword, codeUnknownUser:
		return errors.New("ClickHouse refused Rowsafe's login (wrong or missing user): run the Rowsafe installer on the server again to create it")
	}
	return err
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// shortError is a ClickHouse error message without its stack and version
// noise, for logs and results people read.
func shortError(err error) string {
	if err == nil {
		return ""
	}
	s := firstLine(err.Error())
	if i := strings.Index(s, "DB::Exception: "); i >= 0 {
		s = s[i+len("DB::Exception: "):]
	}
	for _, cut := range []string{" (version ", ", Stack trace", ". Stack trace", " Stack trace ("} {
		if i := strings.Index(s, cut); i > 0 {
			s = s[:i]
		}
	}
	return strings.TrimSpace(s)
}

// ---- quoting (names always come from ClickHouse's own catalogs)

// quoteIdent quotes a database, table or column name.
func quoteIdent(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "`", "\\`")
	return "`" + r.Replace(s) + "`"
}

// quoteString quotes a string literal.
func quoteString(s string) string {
	r := strings.NewReplacer("\\", "\\\\", "'", "\\'")
	return "'" + r.Replace(s) + "'"
}

// tableName is `db`.`table`.
func tableName(db, table string) string { return quoteIdent(db) + "." + quoteIdent(table) }
