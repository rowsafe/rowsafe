package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

type controlClient struct {
	baseURL string
	token   string
	http    *http.Client
}

func newControlClient(baseURL, token string) *controlClient {
	return &controlClient{baseURL: baseURL, token: token, http: &http.Client{Timeout: 30 * time.Second}}
}

func (c *controlClient) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, path, bytes.NewReader(body), out)
}

func (c *controlClient) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *controlClient) do(ctx context.Context, method, path string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "rowsafe-agent/"+Version)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 300 {
		var e protocol.Error
		_ = json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &httpError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

type httpError struct {
	Status int
	Msg    string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("control plane returned %d: %s", e.Status, e.Msg)
}

func (c *controlClient) enroll(ctx context.Context, req protocol.EnrollRequest) (protocol.EnrollResponse, error) {
	var resp protocol.EnrollResponse
	err := c.post(ctx, "/v1/agent/enroll", req, &resp)
	return resp, err
}

func (c *controlClient) heartbeat(ctx context.Context, req protocol.HeartbeatRequest) (protocol.HeartbeatResponse, error) {
	var resp protocol.HeartbeatResponse
	err := c.post(ctx, "/v1/agent/heartbeat", req, &resp)
	return resp, err
}

func (c *controlClient) claim(ctx context.Context) (*protocol.Task, error) {
	var resp protocol.ClaimResponse
	err := c.post(ctx, "/v1/agent/tasks/claim", struct{}{}, &resp)
	return resp.Task, err
}

// claimTypes claims only tasks of the given types.
func (c *controlClient) claimTypes(ctx context.Context, types []string) (*protocol.Task, error) {
	var resp protocol.ClaimResponse
	err := c.post(ctx, "/v1/agent/tasks/claim", protocol.ClaimRequest{Types: types}, &resp)
	return resp.Task, err
}

func (c *controlClient) complete(ctx context.Context, taskID string, req protocol.CompleteRequest) error {
	return c.post(ctx, "/v1/agent/tasks/"+taskID+"/complete", req, nil)
}

// ---- setup (rowsafe-agent setup, run by the installer) ----

func (c *controlClient) setupRegister(ctx context.Context, req protocol.SetupRegisterRequest) (protocol.SetupDatabase, error) {
	var resp protocol.SetupDatabase
	err := c.post(ctx, "/v1/agent/setup/databases", req, &resp)
	return resp, err
}

func (c *controlClient) setupList(ctx context.Context) ([]protocol.SetupDatabase, error) {
	var resp protocol.SetupDatabaseList
	err := c.get(ctx, "/v1/agent/setup/databases", &resp)
	return resp.Databases, err
}

func (c *controlClient) setupGet(ctx context.Context, id string) (protocol.SetupDatabase, error) {
	var resp protocol.SetupDatabase
	err := c.get(ctx, "/v1/agent/setup/databases/"+url.PathEscape(id), &resp)
	return resp, err
}

func (c *controlClient) setupApply(ctx context.Context, id string, req protocol.SetupApplyRequest) (protocol.SetupDatabase, error) {
	var resp protocol.SetupDatabase
	err := c.post(ctx, "/v1/agent/setup/databases/"+url.PathEscape(id)+"/apply", req, &resp)
	return resp, err
}
