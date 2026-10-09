package meilisearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// client speaks Meilisearch's HTTP API to one instance on this server
// (127.0.0.1), with one API key. Before each new connection the port's
// listener is checked (listener.go): any user can listen on a free port, so
// nothing secret goes to a port Meilisearch's user doesn't hold. Over TLS
// (an instance serving its own certificate on loopback) the certificate
// isn't checked: the connection never leaves the server, the certificate
// is made for the server's public names, and the listener check stands in.
type client struct {
	base string // http://127.0.0.1:7700
	key  string
	http *http.Client
}

// apiError is an error Meilisearch answered with. Its message can quote
// documents (a field that didn't parse), so it never leaves the agent:
// Error says the code in plain words.
type apiError struct {
	Status  int
	Code    string `json:"code"`
	Message string `json:"message"`
	Type    string `json:"type"`
}

func (e *apiError) Error() string {
	return "Meilisearch: " + codeWords(e.Code, e.Type, e.Status)
}

// codeWords says an error code in plain words, without Meilisearch's
// message.
func codeWords(code, typ string, status int) string {
	switch code {
	case "":
		if status != 0 {
			return fmt.Sprintf("it answered HTTP %d", status)
		}
		return "it refused the request"
	case "index_not_found":
		return "the index doesn't exist (index_not_found)"
	case "index_already_exists":
		return "an index with that name already exists (index_already_exists)"
	case "missing_authorization_header", "invalid_api_key":
		return "the API key was refused (" + code + ")"
	case "api_key_not_found":
		return "that API key doesn't exist (api_key_not_found)"
	case "invalid_api_key_actions":
		return "it doesn't know some of the key's actions (invalid_api_key_actions)"
	case "no_space_left_on_device":
		return "the disk is full (no_space_left_on_device)"
	case "database_size_limit_reached":
		return "the database reached its size limit (database_size_limit_reached)"
	case "task_not_found":
		return "the task doesn't exist (task_not_found)"
	case "document_not_found":
		return "the document doesn't exist (document_not_found)"
	case "index_primary_key_no_candidate_found", "index_primary_key_multiple_candidates_found", "missing_document_id", "invalid_document_id":
		return "documents without a usable primary key (" + code + ")"
	case "invalid_document_fields", "malformed_payload", "bad_request":
		return "it refused the data it was sent (" + code + ")"
	case "internal":
		return "an internal error (internal)"
	}
	if typ != "" {
		return fmt.Sprintf("it refused the request (%s, %s)", code, typ)
	}
	return "it refused the request (" + code + ")"
}

// isCode reports whether err is Meilisearch's error code.
func isCode(err error, code string) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Code == code
}

// isAuthError: the key is missing, invalid or lacks the right.
func isAuthError(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}

// newClient is a client for 127.0.0.1:port; check vets the port's
// listener before every new connection (prodCheck or scratchCheck).
func newClient(scheme string, port int, key string, check listenerCheck) *client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // never through a proxy: this server only
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if check == nil {
				return nil, errors.New("Rowsafe sends nothing to Meilisearch before checking who listens on its port")
			}
			if err := check(port); err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // loopback only, see client
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	return &client{
		base: scheme + "://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
		key:  key,
		http: &http.Client{Transport: tr},
	}
}

// withKey is c with another key (the same connections).
func (c *client) withKey(key string) *client {
	d := *c
	d.key = key
	return &d
}

func (c *client) close() {
	if t, ok := c.http.Transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}
}

// do sends a request; out (when not nil) receives the JSON answer.
func (c *client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	var rd io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(data)
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.key != "" && path != "/health" { // the health check needs no key: none is sent
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return plainConnError(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		ae := &apiError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, ae)
		return ae
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("reading Meilisearch's answer to %s %s: %w", method, path, err)
	}
	return nil
}

// plainConnError says what a connection failure means.
func plainConnError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" {
		return fmt.Errorf("Meilisearch doesn't answer on this server (%v)", oe.Err)
	}
	if strings.Contains(err.Error(), "server gave HTTP response to HTTPS client") {
		return errors.New("Meilisearch answers with plain HTTP, not HTTPS")
	}
	if strings.Contains(err.Error(), "malformed HTTP response") {
		return errors.New("Meilisearch answers with HTTPS (TLS), not plain HTTP")
	}
	return err
}

// ---- the API

func (c *client) health(ctx context.Context) error {
	var h struct {
		Status string `json:"status"`
	}
	if err := c.do(ctx, http.MethodGet, "/health", nil, nil, &h); err != nil {
		return err
	}
	if h.Status != "available" {
		return fmt.Errorf("Meilisearch says it is %q", h.Status)
	}
	return nil
}

type versionInfo struct {
	PkgVersion string `json:"pkgVersion"`
	CommitSha  string `json:"commitSha"`
	CommitDate string `json:"commitDate"`
}

func (c *client) version(ctx context.Context) (versionInfo, error) {
	var v versionInfo
	err := c.do(ctx, http.MethodGet, "/version", nil, nil, &v)
	return v, err
}

type indexStats struct {
	NumberOfDocuments         int64            `json:"numberOfDocuments"`
	IndexSize                 int64            `json:"indexSize"`
	UsedIndexSize             int64            `json:"usedIndexSize"`
	RawDocumentDbSize         int64            `json:"rawDocumentDbSize"`
	IsIndexing                bool             `json:"isIndexing"`
	NumberOfEmbeddings        int64            `json:"numberOfEmbeddings"`
	NumberOfEmbeddedDocuments int64            `json:"numberOfEmbeddedDocuments"`
	FieldDistribution         map[string]int64 `json:"fieldDistribution"`
}

type globalStats struct {
	DatabaseSize     int64                 `json:"databaseSize"`
	UsedDatabaseSize int64                 `json:"usedDatabaseSize"`
	LastUpdate       *time.Time            `json:"lastUpdate"`
	Indexes          map[string]indexStats `json:"indexes"`
}

func (c *client) stats(ctx context.Context) (globalStats, error) {
	var s globalStats
	err := c.do(ctx, http.MethodGet, "/stats", nil, nil, &s)
	return s, err
}

type indexInfo struct {
	UID        string    `json:"uid"`
	PrimaryKey *string   `json:"primaryKey"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

func (i indexInfo) primaryKey() string {
	if i.PrimaryKey == nil {
		return ""
	}
	return *i.PrimaryKey
}

// indexes lists every index.
func (c *client) indexes(ctx context.Context) ([]indexInfo, error) {
	var out []indexInfo
	for offset := 0; ; {
		var page struct {
			Results []indexInfo `json:"results"`
			Total   int         `json:"total"`
		}
		q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {"1000"}}
		if err := c.do(ctx, http.MethodGet, "/indexes", q, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Results...)
		offset += len(page.Results)
		if len(page.Results) == 0 || offset >= page.Total {
			return out, nil
		}
	}
}

func (c *client) index(ctx context.Context, uid string) (indexInfo, error) {
	var i indexInfo
	err := c.do(ctx, http.MethodGet, "/indexes/"+url.PathEscape(uid), nil, nil, &i)
	return i, err
}

// settings are an index's settings, as Meilisearch gives them.
func (c *client) settings(ctx context.Context, uid string) (map[string]json.RawMessage, error) {
	var s map[string]json.RawMessage
	err := c.do(ctx, http.MethodGet, "/indexes/"+url.PathEscape(uid)+"/settings", nil, nil, &s)
	return s, err
}

// ---- tasks

type task struct {
	UID        int64           `json:"uid"`
	TaskUID    int64           `json:"taskUid"` // in the answer to an enqueued request
	IndexUID   *string         `json:"indexUid"`
	Status     string          `json:"status"`
	Type       string          `json:"type"`
	Error      *apiError       `json:"error"`
	Details    json.RawMessage `json:"details"`
	EnqueuedAt *time.Time      `json:"enqueuedAt"`
	StartedAt  *time.Time      `json:"startedAt"`
	FinishedAt *time.Time      `json:"finishedAt"`
}

func (t task) id() int64 {
	if t.UID != 0 {
		return t.UID
	}
	return t.TaskUID
}

func (t task) index() string {
	if t.IndexUID == nil {
		return ""
	}
	return *t.IndexUID
}

func (t task) done() bool {
	return t.Status == "succeeded" || t.Status == "failed" || t.Status == "canceled"
}

func (c *client) task(ctx context.Context, uid int64) (task, error) {
	var t task
	err := c.do(ctx, http.MethodGet, "/tasks/"+strconv.FormatInt(uid, 10), nil, nil, &t)
	return t, err
}

// waitTask waits for an enqueued task to finish and fails unless it
// succeeded.
func (c *client) waitTask(ctx context.Context, enq task, timeout time.Duration) (task, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id := enq.id()
	wait := 50 * time.Millisecond
	for {
		t, err := c.task(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return t, fmt.Errorf("Meilisearch's task %d (%s) didn't finish within %s", id, enq.Type, timeout)
			}
			return t, err
		}
		if t.done() {
			if t.Status != "succeeded" {
				msg := t.Status
				if t.Error != nil {
					msg += ": " + codeWords(t.Error.Code, t.Error.Type, 0)
				}
				return t, fmt.Errorf("Meilisearch's task %d (%s) %s", id, t.Type, msg)
			}
			return t, nil
		}
		select {
		case <-ctx.Done():
			return t, fmt.Errorf("Meilisearch's task %d (%s) didn't finish within %s", id, enq.Type, timeout)
		case <-time.After(wait):
		}
		wait = min(wait*2, 2*time.Second)
	}
}

// taskPage reads tasks matching q (statuses, types, indexUids, limit...).
func (c *client) taskPage(ctx context.Context, q url.Values) ([]task, int64, error) {
	var page struct {
		Results []task `json:"results"`
		Total   int64  `json:"total"`
	}
	err := c.do(ctx, http.MethodGet, "/tasks", q, nil, &page)
	return page.Results, page.Total, err
}

// waitIdle waits until no task of these indexes is enqueued or processing.
func (c *client) waitIdle(ctx context.Context, indexes []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q := url.Values{"statuses": {"enqueued,processing"}, "limit": {"1"}}
	if len(indexes) > 0 {
		q.Set("indexUids", strings.Join(indexes, ","))
	}
	for {
		_, n, err := c.taskPage(ctx, q)
		if err == nil && n == 0 {
			return nil
		}
		if ctx.Err() != nil {
			if err == nil {
				err = fmt.Errorf("%d tasks were still waiting after %s", n, timeout)
			}
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (c *client) enqueue(ctx context.Context, method, path string, q url.Values, body any) (task, error) {
	var t task
	err := c.do(ctx, method, path, q, body, &t)
	return t, err
}

// ---- keys

type apiKey struct {
	UID         string     `json:"uid,omitempty"`
	Key         string     `json:"key,omitempty"`
	Name        *string    `json:"name"`
	Description *string    `json:"description"`
	Actions     []string   `json:"actions"`
	Indexes     []string   `json:"indexes"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	CreatedAt   *time.Time `json:"createdAt,omitempty"`
	UpdatedAt   *time.Time `json:"updatedAt,omitempty"`
}

func (k apiKey) name() string {
	if k.Name == nil {
		return ""
	}
	return *k.Name
}

func (c *client) keys(ctx context.Context) ([]apiKey, error) {
	var out []apiKey
	for offset := 0; ; {
		var page struct {
			Results []apiKey `json:"results"`
			Total   int      `json:"total"`
		}
		q := url.Values{"offset": {strconv.Itoa(offset)}, "limit": {"1000"}}
		if err := c.do(ctx, http.MethodGet, "/keys", q, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Results...)
		offset += len(page.Results)
		if len(page.Results) == 0 || offset >= page.Total {
			return out, nil
		}
	}
}

// createKey makes a key; the answer holds its value (Key).
func (c *client) createKey(ctx context.Context, k apiKey) (apiKey, error) {
	var out apiKey
	err := c.do(ctx, http.MethodPost, "/keys", nil, k, &out)
	return out, err
}

func (c *client) deleteKey(ctx context.Context, uid string) error {
	return c.do(ctx, http.MethodDelete, "/keys/"+url.PathEscape(uid), nil, nil, nil)
}

// ---- documents

// documentIDs calls fn with the primary key values of an index's
// documents, a page at a time (as JSON: numbers and strings stay apart).
func (c *client) documentIDs(ctx context.Context, uid, pk string, fn func(ids []json.RawMessage) error) error {
	const page = 1000
	for offset := 0; ; offset += page {
		var res struct {
			Results []map[string]json.RawMessage `json:"results"`
			Total   int                          `json:"total"`
		}
		q := url.Values{"fields": {pk}, "limit": {strconv.Itoa(page)}, "offset": {strconv.Itoa(offset)}}
		if err := c.do(ctx, http.MethodGet, "/indexes/"+url.PathEscape(uid)+"/documents", q, nil, &res); err != nil {
			return err
		}
		ids := make([]json.RawMessage, 0, len(res.Results))
		for _, d := range res.Results {
			if v, ok := d[pk]; ok {
				ids = append(ids, v)
			}
		}
		if err := fn(ids); err != nil {
			return err
		}
		if len(res.Results) < page || offset+page >= res.Total {
			return nil
		}
	}
}

// fetchDocuments reads whole documents by primary key.
func (c *client) fetchDocuments(ctx context.Context, uid string, ids []json.RawMessage) ([]json.RawMessage, error) {
	var res struct {
		Results []json.RawMessage `json:"results"`
	}
	body := map[string]any{"ids": ids, "limit": len(ids), "retrieveVectors": true}
	err := c.do(ctx, http.MethodPost, "/indexes/"+url.PathEscape(uid)+"/documents/fetch", nil, body, &res)
	return res.Results, err
}
