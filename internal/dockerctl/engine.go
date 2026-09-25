package dockerctl

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// engine is a minimal Docker Engine API client over the Docker socket.
//
// AUDIT: these five methods are the only requests this program ever sends
// to Docker. Every container reference in a URL is either a full 64-hex
// container ID that Docker itself returned, or a name from this service's
// own configuration checked against nameRE; nothing from a request reaches
// a URL. Paths are unversioned (the daemon's current API version): the few
// fields read below have been stable since API 1.24.
type engine struct {
	hc *http.Client
}

var (
	containerIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// nameRE: compose service and project names, container names.
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
)

func newEngine(socket string) *engine {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
	}
	return &engine{hc: &http.Client{Transport: tr}}
}

// containerJSON is the part of GET /containers/{id}/json this service reads.
type containerJSON struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"` // "/myapp-postgres-1"
	State struct {
		Status    string `json:"Status"`
		ExitCode  int    `json:"ExitCode"`
		StartedAt string `json:"StartedAt"`
		Health    *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

// listEntry is one element of GET /containers/json.
type listEntry struct {
	ID     string            `json:"Id"`
	Names  []string          `json:"Names"`
	Labels map[string]string `json:"Labels"`
}

// errNotFound: Docker has no such container.
type errNotFound struct{ ref string }

func (e errNotFound) Error() string { return "no such container: " + e.ref }

func (e *engine) do(ctx context.Context, method, path string, q url.Values, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	u := "http://docker" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, nil, err
	}
	res, err := e.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("Docker API: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	return res.StatusCode, body, err
}

// dockerMessage is Docker's error body ({"message": "..."}), or the status.
func dockerMessage(status int, body []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &m) == nil && m.Message != "" {
		return m.Message
	}
	return "HTTP " + strconv.Itoa(status)
}

// validRef: a full container ID, or a configured name.
func validRef(ref string) bool { return containerIDRE.MatchString(ref) || nameRE.MatchString(ref) }

// inspect: GET /containers/{ref}/json.
func (e *engine) inspect(ctx context.Context, ref string) (containerJSON, error) {
	var c containerJSON
	if !validRef(ref) {
		return c, fmt.Errorf("refusing container reference %q", ref)
	}
	status, body, err := e.do(ctx, http.MethodGet, "/containers/"+ref+"/json", nil, 30*time.Second)
	if err != nil {
		return c, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return c, errNotFound{ref}
	default:
		return c, fmt.Errorf("inspecting the container: %s", dockerMessage(status, body))
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return c, fmt.Errorf("reading Docker's answer: %w", err)
	}
	if !containerIDRE.MatchString(c.ID) {
		return c, fmt.Errorf("unexpected container ID %q from Docker", c.ID)
	}
	return c, nil
}

// listByLabels: GET /containers/json?all=1 filtered by labels (key=value).
func (e *engine) listByLabels(ctx context.Context, labels ...string) ([]listEntry, error) {
	filters, _ := json.Marshal(map[string][]string{"label": labels})
	status, body, err := e.do(ctx, http.MethodGet, "/containers/json", url.Values{"all": {"1"}, "filters": {string(filters)}}, 30*time.Second)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("listing containers: %s", dockerMessage(status, body))
	}
	var out []listEntry
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("reading Docker's answer: %w", err)
	}
	return out, nil
}

// lifecycle: POST /containers/{id}/stop|start|restart. 304 (already
// stopped or started) counts as done.
func (e *engine) lifecycle(ctx context.Context, id, action string, stopTimeout time.Duration) error {
	if !containerIDRE.MatchString(id) {
		return fmt.Errorf("refusing container reference %q", id)
	}
	var q url.Values
	switch action {
	case ActionStop, ActionRestart:
		q = url.Values{"t": {strconv.Itoa(int(stopTimeout.Seconds()))}}
	case ActionStart:
	default:
		return fmt.Errorf("refusing action %q", action)
	}
	status, body, err := e.do(ctx, http.MethodPost, "/containers/"+id+"/"+action, q, stopTimeout+2*time.Minute)
	if err != nil {
		return err
	}
	switch status {
	case http.StatusNoContent, http.StatusNotModified, http.StatusOK:
		return nil
	case http.StatusNotFound:
		return errNotFound{id}
	}
	return fmt.Errorf("Docker couldn't %s the container: %s", action, strings.TrimSpace(dockerMessage(status, body)))
}
