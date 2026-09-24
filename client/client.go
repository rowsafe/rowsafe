// Package client is a Go client for the Rowsafe user API.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

type Client struct {
	BaseURL string
	// APIKey is an org API key (rsk_...) or the control plane's service token.
	APIKey string
	// OrgID selects the org when APIKey is the service token.
	OrgID string
	HTTP  *http.Client
}

func New(baseURL, apiKey string) *Client {
	return &Client{BaseURL: baseURL, APIKey: apiKey, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// NewService returns a client that authenticates with the service token and
// acts for orgID. Pass orgID "" for the /v1/internal/ endpoints.
func NewService(baseURL, serviceToken, orgID string) *Client {
	c := New(baseURL, serviceToken)
	c.OrgID = orgID
	return c
}

type APIError struct {
	Status int
	Msg    string
	// RetryAfter is the response's Retry-After, when it gave one in seconds
	// (e.g. 429 for a restart too soon after the last one).
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return e.Msg }

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	if c.OrgID != "" {
		req.Header.Set(protocol.OrgHeader, c.OrgID)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e protocol.Error
		if json.Unmarshal(data, &e) != nil || e.Error == "" {
			e.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(data))
		}
		ae := &APIError{Status: resp.StatusCode, Msg: e.Error}
		if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && secs > 0 {
			ae.RetryAfter = time.Duration(secs) * time.Second
		}
		return ae
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func esc(s string) string { return url.PathEscape(s) }

func (c *Client) Hosts(ctx context.Context) (out []protocol.Host, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/hosts", nil, &out)
}

func (c *Client) CreateEnrollmentToken(ctx context.Context, ttl time.Duration) (out protocol.EnrollmentToken, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/hosts/enrollment-tokens",
		protocol.CreateEnrollmentTokenRequest{TTLSeconds: int(ttl.Seconds())}, &out)
}

// UpdateHost changes a host's update channel or version pin.
func (c *Client) UpdateHost(ctx context.Context, ref string, req protocol.UpdateHostRequest) (out protocol.Host, err error) {
	return out, c.do(ctx, http.MethodPatch, "/v1/hosts/"+esc(ref), req, &out)
}

func (c *Client) Databases(ctx context.Context) (out []protocol.Database, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases", nil, &out)
}

func (c *Client) Database(ctx context.Context, ref string) (out protocol.Database, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref), nil, &out)
}

func (c *Client) CreateDatabase(ctx context.Context, req protocol.CreateDatabaseRequest) (out protocol.CreateDatabaseResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases", req, &out)
}

func (c *Client) CreateTask(ctx context.Context, ref, typ string, params any) (out protocol.TaskView, err error) {
	req := protocol.CreateTaskRequest{Type: typ}
	if params != nil {
		if req.Params, err = json.Marshal(params); err != nil {
			return out, err
		}
	}
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/tasks", req, &out)
}

func (c *Client) Tasks(ctx context.Context, ref string, limit int) (out []protocol.TaskView, err error) {
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/databases/%s/tasks?limit=%d", esc(ref), limit), nil, &out)
}

func (c *Client) Task(ctx context.Context, id string) (out protocol.TaskView, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/tasks/"+esc(id), nil, &out)
}

func (c *Client) Backups(ctx context.Context, ref string, limit int) (out []protocol.Backup, err error) {
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/databases/%s/backups?limit=%d", esc(ref), limit), nil, &out)
}

func (c *Client) Drills(ctx context.Context, ref string, limit int) (out []protocol.Drill, err error) {
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/databases/%s/drills?limit=%d", esc(ref), limit), nil, &out)
}

// Org returns the authenticated org with its plan, limits and usage.
func (c *Client) Org(ctx context.Context) (out protocol.Org, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/org", nil, &out)
}

func (c *Client) APIKeys(ctx context.Context) (out []protocol.APIKey, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/api-keys", nil, &out)
}

// CreateAPIKey returns the new key's plaintext, which is shown only once.
// A read-only key can only make GET requests.
func (c *Client) CreateAPIKey(ctx context.Context, name string, readOnly bool) (out protocol.CreatedAPIKey, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/api-keys", protocol.CreateAPIKeyRequest{Name: name, ReadOnly: readOnly}, &out)
}

func (c *Client) RevokeAPIKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/api-keys/"+esc(id), nil, nil)
}

// ---- Service token only ----

// EnsureOrg creates the org for a dashboard organization, or returns the
// existing one with that external ID.
func (c *Client) EnsureOrg(ctx context.Context, name, externalID string) (out protocol.Org, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/internal/orgs",
		protocol.CreateOrgRequest{Name: name, ExternalID: externalID}, &out)
}

func (c *Client) OrgByExternalID(ctx context.Context, externalID string) (out protocol.Org, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/internal/orgs/by-external/"+esc(externalID), nil, &out)
}

func (c *Client) SetPlan(ctx context.Context, orgID string, req protocol.UpdatePlanRequest) (out protocol.Org, err error) {
	return out, c.do(ctx, http.MethodPut, "/v1/internal/orgs/"+esc(orgID)+"/plan", req, &out)
}

// TaskQuery filters AllTasks; zero fields match everything.
type TaskQuery struct {
	Database string // ID or name
	Status   string
	Type     string
	Limit    int // default 50, at most 500
}

// AllTasks lists the org's tasks, newest first.
func (c *Client) AllTasks(ctx context.Context, q TaskQuery) (out []protocol.TaskView, err error) {
	v := url.Values{}
	for k, val := range map[string]string{"database": q.Database, "status": q.Status, "type": q.Type} {
		if val != "" {
			v.Set(k, val)
		}
	}
	if q.Limit > 0 {
		v.Set("limit", fmt.Sprint(q.Limit))
	}
	path := "/v1/tasks"
	if len(v) > 0 {
		path += "?" + v.Encode()
	}
	return out, c.do(ctx, http.MethodGet, path, nil, &out)
}

// UpdateDatabase changes retention and schedules; nil fields are unchanged.
func (c *Client) UpdateDatabase(ctx context.Context, ref string, req protocol.UpdateDatabaseRequest) (out protocol.Database, err error) {
	return out, c.do(ctx, http.MethodPatch, "/v1/databases/"+esc(ref), req, &out)
}

// DeleteDatabase removes a database from Rowsafe. Once adoption has been
// applied, keepArchiving must be true: the host keeps archiving WAL.
func (c *Client) DeleteDatabase(ctx context.Context, ref string, keepArchiving bool) error {
	path := "/v1/databases/" + esc(ref)
	if keepArchiving {
		path += "?keep_archiving=true"
	}
	return c.do(ctx, http.MethodDelete, path, nil, nil)
}

// DeleteHost removes a host that has no databases and revokes its agent.
func (c *Client) DeleteHost(ctx context.Context, ref string) error {
	return c.do(ctx, http.MethodDelete, "/v1/hosts/"+esc(ref), nil, nil)
}

// AuditEvents returns the org's audit log, newest first.
func (c *Client) AuditEvents(ctx context.Context, limit int) (out []protocol.AuditEvent, err error) {
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/audit-events?limit=%d", limit), nil, &out)
}

// CreateRestorePoint queues a named restore point; wait for the returned
// task to know it is in the repository.
func (c *Client) CreateRestorePoint(ctx context.Context, ref, name string) (out protocol.TaskView, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/databases/"+esc(ref)+"/restore-points",
		protocol.CreateRestorePointRequest{Name: name}, &out)
}

func (c *Client) RestorePoints(ctx context.Context, ref string) (out []protocol.RestorePoint, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/restore-points", nil, &out)
}

// Protection reports whether the database is currently recoverable.
func (c *Client) Protection(ctx context.Context, ref string) (out protocol.Protection, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/protection", nil, &out)
}

// WaitTask polls until the task finishes or ctx ends.
func (c *Client) WaitTask(ctx context.Context, id string, onTick func(protocol.TaskView)) (protocol.TaskView, error) {
	for {
		t, err := c.Task(ctx, id)
		if err != nil {
			return t, err
		}
		if onTick != nil {
			onTick(t)
		}
		switch t.Status {
		case protocol.StatusSucceeded, protocol.StatusFailed, protocol.StatusLost, protocol.StatusCancelled:
			return t, nil
		}
		select {
		case <-ctx.Done():
			return t, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// ---- Monitoring and alerting ----

// MetricsQuery selects series for DatabaseMetrics and HostMetrics; zero
// fields use the server's defaults (all metrics, the last hour, automatic
// step).
type MetricsQuery struct {
	Metrics  []string
	From, To time.Time
	Step     time.Duration
}

func (q MetricsQuery) encode() string {
	v := url.Values{}
	if len(q.Metrics) > 0 {
		v.Set("metrics", strings.Join(q.Metrics, ","))
	}
	if !q.From.IsZero() {
		v.Set("from", fmt.Sprint(q.From.Unix()))
	}
	if !q.To.IsZero() {
		v.Set("to", fmt.Sprint(q.To.Unix()))
	}
	if q.Step > 0 {
		v.Set("step", fmt.Sprint(int(q.Step.Seconds())))
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

func (c *Client) DatabaseMetrics(ctx context.Context, ref string, q MetricsQuery) (out protocol.MetricsResponse, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/metrics"+q.encode(), nil, &out)
}

func (c *Client) HostMetrics(ctx context.Context, ref string, q MetricsQuery) (out protocol.MetricsResponse, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/hosts/"+esc(ref)+"/metrics"+q.encode(), nil, &out)
}

// Activity returns the newest snapshot of long-running sessions.
func (c *Client) Activity(ctx context.Context, ref string) (out protocol.Activity, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/databases/"+esc(ref)+"/activity", nil, &out)
}

// Alerts lists alerts by state: "firing", "resolved" or "all".
func (c *Client) Alerts(ctx context.Context, state string, limit int) (out []protocol.Alert, err error) {
	return out, c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/alerts?state=%s&limit=%d", url.QueryEscape(state), limit), nil, &out)
}

func (c *Client) AckAlert(ctx context.Context, id string) (out protocol.Alert, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/alerts/"+esc(id)+"/ack", nil, &out)
}

func (c *Client) AlertRules(ctx context.Context) (out []protocol.AlertRule, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/alert-rules", nil, &out)
}

// UpdateAlertRule replaces the org's override of a rule; nil fields go
// back to the default.
func (c *Client) UpdateAlertRule(ctx context.Context, rule string, req protocol.UpdateAlertRuleRequest) (out protocol.AlertRule, err error) {
	return out, c.do(ctx, http.MethodPut, "/v1/alert-rules/"+esc(rule), req, &out)
}

func (c *Client) NotificationChannels(ctx context.Context) (out []protocol.NotificationChannel, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/notification-channels", nil, &out)
}

// CreateNotificationChannel returns the channel; for a webhook it carries
// the signing secret, which is shown only once.
func (c *Client) CreateNotificationChannel(ctx context.Context, req protocol.CreateNotificationChannelRequest) (out protocol.NotificationChannel, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/notification-channels", req, &out)
}

func (c *Client) DeleteNotificationChannel(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/notification-channels/"+esc(id), nil, nil)
}

func (c *Client) TestNotificationChannel(ctx context.Context, id string) (out protocol.ChannelTestResult, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/notification-channels/"+esc(id)+"/test", nil, &out)
}

// ---- CLI login (device authorization) ----

// StartDeviceAuth begins a browser login; it needs no credentials.
func (c *Client) StartDeviceAuth(ctx context.Context, clientName string) (out protocol.DeviceAuthResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/auth/device", protocol.DeviceAuthRequest{ClientName: clientName}, &out)
}

// PollDeviceToken returns the new API key once the login is approved.
// Until then it fails with an *APIError whose Msg is one of the
// protocol.Device* codes.
func (c *Client) PollDeviceToken(ctx context.Context, deviceCode string) (out protocol.DeviceTokenResponse, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/auth/device/token", protocol.DeviceTokenRequest{DeviceCode: deviceCode}, &out)
}

// WhoAmI describes the credentials in use.
func (c *Client) WhoAmI(ctx context.Context) (out protocol.WhoAmI, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/whoami", nil, &out)
}

// Logout revokes the API key making the request.
func (c *Client) Logout(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/v1/auth/logout", nil, nil)
}

// DeviceAuthorization, ApproveDevice and DenyDevice need the service token.
func (c *Client) DeviceAuthorization(ctx context.Context, userCode string) (out protocol.DeviceAuthorization, err error) {
	return out, c.do(ctx, http.MethodGet, "/v1/internal/device/"+esc(userCode), nil, &out)
}

func (c *Client) ApproveDevice(ctx context.Context, userCode, orgID string) (out protocol.DeviceAuthorization, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/internal/device/"+esc(userCode)+"/approve",
		protocol.ApproveDeviceRequest{OrgID: orgID}, &out)
}

func (c *Client) DenyDevice(ctx context.Context, userCode, orgID string) (out protocol.DeviceAuthorization, err error) {
	return out, c.do(ctx, http.MethodPost, "/v1/internal/device/"+esc(userCode)+"/deny",
		protocol.DenyDeviceRequest{OrgID: orgID}, &out)
}
