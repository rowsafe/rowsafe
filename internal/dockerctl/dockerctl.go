// Package dockerctl is Rowsafe's container control for Docker: a tiny
// service (cmd/rowsafe-docker-control) that holds the Docker socket and
// stops, starts, restarts or inspects exactly one container, the PostgreSQL
// container next to it, when the Rowsafe agent asks over a Unix socket on a
// volume only the two of them share. The agent itself never sees the Docker
// socket.
//
// # Why a service of its own
//
// Access to the Docker socket is root on the Docker host: whoever can talk
// to it can start a privileged container that mounts the host's disk. A
// read-only mount (":ro") doesn't change that (it only stops the socket
// file from being replaced; requests still go through). So the socket goes
// to this service alone, and the policy is enforced here, in code small
// enough to read in one sitting:
//
//   - the only Docker Engine API calls in this package are GET
//     /containers/json (finding the target by its compose labels), GET
//     /containers/{id}/json (inspect) and POST /containers/{id}/stop,
//     /start and /restart. There is no code path to exec, create, pull,
//     remove, attach, read logs or touch any other object;
//   - the target is decided by this service's own configuration (the
//     compose service name, default "postgres", in the service's own
//     compose project; or one container name), resolved to a container ID
//     at start and checked against its labels before every action. A
//     request can't name a container: its only fields are an action and a
//     request ID for the log, and unknown fields are refused;
//   - actions are an allow list (inspect, stop, start, restart); restarts
//     are rate limited (one a minute), stops and restarts together capped
//     per hour; starting is never limited (a rollback must always be able
//     to start PostgreSQL again);
//   - only the configured peer uids (the postgres user of the images, 999
//     and 70) may connect (SO_PEERCRED), requests are small (4 KiB) and
//     must arrive within 10 seconds, one action runs at a time;
//   - every request is logged with the peer's uid and pid, the action, the
//     container and the outcome.
//
// Alternative considered: a generic Docker socket proxy (e.g.
// tecnativa/docker-socket-proxy) filters by API section ("CONTAINERS=1,
// POST=1"), not by container: it would let the agent stop, start, remove
// or create any container on the host. That is the socket with extra steps.
package dockerctl

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"
)

// Actions a request may ask for.
const (
	ActionInspect = "inspect"
	ActionStop    = "stop"
	ActionStart   = "start"
	ActionRestart = "restart"
)

// Actions is the allow list, in the order responses report it.
var Actions = []string{ActionInspect, ActionRestart, ActionStop, ActionStart}

// DefaultSocket is where the control service listens, on a volume shared
// with the agent container only.
const DefaultSocket = "/run/rowsafe-control/control.sock"

// maxRequest bounds a request line.
const maxRequest = 4096

// requestIDRE is the shape of request IDs (task and rewind IDs).
var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

// Request is one call. It deliberately has no field naming a container.
type Request struct {
	// ID identifies the request in the log (the agent's task or rewind ID).
	ID     string `json:"id"`
	Action string `json:"action"`
}

// Response is the answer: the outcome and the container's state after the
// action.
type Response struct {
	OK     bool   `json:"ok"`
	ID     string `json:"id,omitempty"`
	Action string `json:"action,omitempty"`
	// Container is the controlled container's name (e.g. myapp-postgres-1),
	// ContainerID its short ID, Project and Service its compose labels.
	Container   string `json:"container,omitempty"`
	ContainerID string `json:"container_id,omitempty"`
	Project     string `json:"project,omitempty"`
	Service     string `json:"service,omitempty"`
	// State is Docker's state: running, exited, restarting, created, paused,
	// dead. Health is the health check's status ("" without one).
	State     string     `json:"state,omitempty"`
	Health    string     `json:"health,omitempty"`
	ExitCode  int        `json:"exit_code,omitempty"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	// Actions are what this service allows.
	Actions []string `json:"actions,omitempty"`
	// Error is a plain explanation when OK is false.
	Error string `json:"error,omitempty"`
	// RetryAfter is set when a rate limit refused the action.
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

// Running reports whether the container runs (or is being restarted by
// Docker): PostgreSQL may be serving its data directory.
func (r Response) Running() bool {
	switch r.State {
	case "running", "restarting", "paused", "removing":
		return true
	}
	return false
}

// Ready reports whether the container runs and, if it has a health check,
// is healthy.
func (r Response) Ready() bool {
	return r.State == "running" && (r.Health == "" || r.Health == "healthy")
}

// ErrUnavailable wraps failures to reach the control service at all.
var ErrUnavailable = errors.New("the container control service is not reachable")

// Call sends req to the control service listening on socket and returns
// its response. A response with OK false is returned with a nil error;
// the error is for transport failures.
func Call(ctx context.Context, socket string, req Request) (Response, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return Response{}, fmt.Errorf("%w (%v)", ErrUnavailable, err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	data, _ := json.Marshal(req)
	if _, err := conn.Write(append(data, '\n')); err != nil {
		return Response{}, fmt.Errorf("%w (%v)", ErrUnavailable, err)
	}
	line, err := bufio.NewReader(io.LimitReader(conn, 64<<10)).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		if ctx.Err() != nil {
			return Response{}, ctx.Err()
		}
		return Response{}, fmt.Errorf("no answer from the container control service: %w", err)
	}
	var res Response
	if err := json.Unmarshal(line, &res); err != nil {
		return Response{}, fmt.Errorf("unreadable answer from the container control service: %w", err)
	}
	return res, nil
}
