package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/dockerctl"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restarting and stopping PostgreSQL in Docker.
//
// A docker-sidecar agent can't touch PostgreSQL's container, and it never
// gets the Docker socket. When the operator adds the rowsafe-docker-control
// service to the compose project (opt-in; cmd/rowsafe-docker-control), it
// listens on a Unix socket in a volume shared with the agent only, and
// stops, starts, restarts or inspects exactly one container: PostgreSQL's.
// The agent then does what the root helper does on a native host:
//
//   - Restart PostgreSQL: a restart of the container, then wait until it
//     runs (healthy, if it has a health check) and PostgreSQL answers;
//   - Rewind the whole database, and Undo: stop the container, swap the
//     data inside the data volume (rewind_contents.go; the volume must be
//     mounted read-write in the agent container for that), start it.
//
// The heartbeat reports what is possible (RestartPorts, RestartActions and
// DockerControl), so the dashboard offers only that.

// dockerControl is the agent's side of the control service.
type dockerControl struct {
	// call replaces dockerctl.Call in tests.
	call func(ctx context.Context, req dockerctl.Request) (dockerctl.Response, error)

	mu      sync.Mutex
	at      time.Time
	report  protocol.DockerControlReport
	dataDir string
}

// dockerReportTTL is how long a report the control service answered is
// reused (a missing socket, or a data directory not known yet, is checked
// again on every heartbeat).
var dockerReportTTL = time.Minute

// dockerHowToAllow is the plain next step when the control service is missing.
const dockerHowToAllow = `allow it in the Rowsafe dashboard (the database's Settings, "Allow Rowsafe to restart this container": ` +
	`it shows the lines to add to your compose file)`

var errNoDockerControl = errors.New("the container control service is not set up")

// dockerCall sends one request to the control service.
func (a *Agent) dockerCall(ctx context.Context, action, id string) (dockerctl.Response, error) {
	req := dockerctl.Request{ID: id, Action: action}
	if a.docker.call != nil {
		return a.docker.call(ctx, req)
	}
	if a.cfg.DockerControlSocket == "" {
		return dockerctl.Response{}, errNoDockerControl
	}
	if _, err := os.Stat(a.cfg.DockerControlSocket); err != nil {
		return dockerctl.Response{}, errNoDockerControl
	}
	return dockerctl.Call(ctx, a.cfg.DockerControlSocket, req)
}

// dockerControlReport is the heartbeat's DockerControl (nil when native).
func (a *Agent) dockerControlReport(ctx context.Context) *protocol.DockerControlReport {
	if !a.cfg.Sidecar() {
		return nil
	}
	r := a.dockerRefresh(ctx)
	return &r
}

// dockerUsable reports whether the control service answers for a container.
func dockerUsable(r protocol.DockerControlReport) bool {
	return r.Found && r.Error == "" && r.Container != ""
}

// dockerRefresh asks the control service about its container (at most once
// a minute) and checks whether the data directory is writable.
func (a *Agent) dockerRefresh(ctx context.Context) protocol.DockerControlReport {
	d := &a.docker
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.at.IsZero() && time.Since(d.at) < dockerReportTTL && d.report.Found && d.dataDir != "" {
		return d.report
	}
	var r protocol.DockerControlReport
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := a.dockerCall(cctx, dockerctl.ActionInspect, "heartbeat")
	switch {
	case errors.Is(err, errNoDockerControl):
		d.report, d.at = r, time.Now()
		return r
	case err != nil:
		r.Found, r.Error = true, "the container control service doesn't answer: "+err.Error()
	case !res.OK:
		r.Found, r.Error = true, res.Error
	default:
		r.Found, r.Container, r.Project, r.Service, r.State = true, res.Container, res.Project, res.Service, res.State
	}
	if d.dataDir == "" {
		d.dataDir = a.sidecarDataDir(cctx)
	}
	if d.dataDir != "" {
		r.DataDir = d.dataDir
		r.DataWritable = writable(d.dataDir)
	}
	d.report, d.at = r, time.Now()
	return r
}

// sidecarDataDir asks PostgreSQL for its data directory ("" if it can't).
func (a *Agent) sidecarDataDir(ctx context.Context) string {
	a.mu.Lock()
	dbs := append(append([]protocol.DatabaseSpec(nil), a.watched...), a.monitored...)
	a.mu.Unlock()
	if len(dbs) == 0 {
		return ""
	}
	conn, err := a.target(dbs[0]).Connect(ctx, "postgres")
	if err != nil {
		return ""
	}
	defer closeConn(ctx, conn)
	var dir string
	if err := conn.QueryRow(ctx, `SELECT current_setting('data_directory')`).Scan(&dir); err != nil {
		return ""
	}
	return filepath.Clean(dir)
}

// writable reports whether the agent may write in dir (a volume mounted
// read-only answers EROFS).
func writable(dir string) bool { return syscall.Access(dir, 2 /* W_OK */) == nil }

// dockerRestartPorts: with the control service answering, every database
// the agent sees lives in that one container.
func (a *Agent) dockerRestartPorts() []int {
	if !dockerUsable(a.dockerRefresh(context.Background())) {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var ports []int
	for _, db := range append(append([]protocol.DatabaseSpec(nil), a.watched...), a.monitored...) {
		if db.Port > 0 && !slices.Contains(ports, db.Port) {
			ports = append(ports, db.Port)
		}
	}
	slices.Sort(ports)
	return ports
}

// dockerActions: restart once the control service answers; stop and start
// (rewind in place) only if the data directory is writable too.
func (a *Agent) dockerActions() []string {
	r := a.dockerRefresh(context.Background())
	if !dockerUsable(r) {
		return nil
	}
	if r.DataWritable {
		return []string{helperRestart, helperStop, helperStart}
	}
	return []string{helperRestart}
}

// dockerRestart is the restart task in docker-sidecar mode.
func (a *Agent) dockerRestart(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.RestartResult, error) {
	start := time.Now()
	tl.Printf("asking the container control service to restart PostgreSQL's container")
	res, err := a.dockerCall(ctx, dockerctl.ActionRestart, taskID)
	switch {
	case errors.Is(err, errNoDockerControl):
		return nil, fmt.Errorf("Rowsafe can't restart PostgreSQL running in Docker yet: %s. Or restart the container yourself "+
			"(e.g. `docker compose restart postgres`); Rowsafe notices the restart by itself", dockerHowToAllow)
	case err != nil:
		return nil, err
	case !res.OK:
		return nil, fmt.Errorf("restarting PostgreSQL's container failed: %s", res.Error)
	}
	unit := res.Container
	tl.Printf("container %s restarted; waiting for it to run and PostgreSQL to answer", unit)
	out := &protocol.RestartResult{Restarted: true, Unit: unit}
	if err := a.waitContainerReady(ctx, restartBackTimeout); err != nil {
		out.DurationMs = time.Since(start).Milliseconds()
		return out, err
	}
	deadline := time.Now().Add(restartBackTimeout)
	for {
		mode, err := a.pgArchiveMode(ctx, a.target(db))
		if err == nil {
			out.ArchiveMode = mode
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			out.DurationMs = time.Since(start).Milliseconds()
			return out, fmt.Errorf("container %s restarted, but PostgreSQL is not answering after %s: %w", unit, restartBackTimeout, err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(4 * restartPoll):
		}
	}
	out.DurationMs = time.Since(start).Milliseconds()
	tl.Printf("PostgreSQL is back after %s; archive_mode is %s", time.Duration(out.DurationMs)*time.Millisecond, out.ArchiveMode)
	return out, nil
}

// waitContainerReady waits until the container runs and, if it has a
// health check, is healthy. A container that stops again fails at once.
func (a *Agent) waitContainerReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last dockerctl.Response
	for {
		res, err := a.dockerCall(ctx, dockerctl.ActionInspect, "wait-ready")
		if err == nil && res.OK {
			last = res
			switch {
			case res.Ready():
				return nil
			case res.State == "exited" || res.State == "dead":
				return fmt.Errorf("PostgreSQL's container %s stopped right after starting (exit code %d); its log says why "+
					"(docker compose logs %s)", res.Container, res.ExitCode, cmpOr(res.Service, "postgres"))
			}
		}
		if time.Now().After(deadline) {
			state := last.State
			if last.Health != "" {
				state += ", " + last.Health
			}
			if err == nil && !res.OK {
				state = res.Error
			} else if err != nil {
				state = err.Error()
			}
			return fmt.Errorf("PostgreSQL's container isn't running after %s (%s)", timeout, state)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(4 * restartPoll):
		}
	}
}

func cmpOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// dockerInPlaceAllowed is inPlaceAllowed for docker-sidecar mode: the
// control service answers and may stop the container. It returns the
// container's name.
func (a *Agent) dockerInPlaceAllowed() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := a.dockerCall(ctx, dockerctl.ActionInspect, "rewind-preflight")
	switch {
	case errors.Is(err, errNoDockerControl):
		return "", fmt.Errorf("Rowsafe can't stop PostgreSQL's container, which rewinding the whole database needs: %s. "+
			"Or restore a copy and bring back the rows you need instead", dockerHowToAllow)
	case err != nil:
		return "", err
	case !res.OK:
		return "", fmt.Errorf("the container control service can't act on PostgreSQL's container: %s", res.Error)
	case !slices.Contains(res.Actions, dockerctl.ActionStop) || !slices.Contains(res.Actions, dockerctl.ActionStart):
		return "", errors.New("the container control service doesn't allow stopping and starting the container; update it to the agent's version")
	}
	return res.Container, nil
}

// dockerHelper is inPlaceOps.helper in docker-sidecar mode.
func (a *Agent) dockerHelper(ctx context.Context, action, id string) error {
	res, err := a.dockerCall(ctx, action, id)
	if err != nil {
		return fmt.Errorf("asking the container control service to %s PostgreSQL's container: %w", action, err)
	}
	if !res.OK {
		return fmt.Errorf("the container control service couldn't %s PostgreSQL's container: %s", action, res.Error)
	}
	if action == helperStart {
		return a.waitContainerReady(ctx, inPlaceReadyWait)
	}
	return nil
}

// dockerRunning is inPlaceOps.running in docker-sidecar mode: our own
// private postmaster in this container, or, for the live data directory,
// the PostgreSQL container running at all. The pid in postmaster.pid
// belongs to the other container's pid namespace and means nothing here.
func (a *Agent) dockerRunning(dataDir string) bool {
	if localPostmaster(dataDir) {
		return true
	}
	if inAsideRoot(dataDir) {
		return false // data kept aside never runs in the container
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := a.dockerCall(ctx, dockerctl.ActionInspect, "running-check")
	if err != nil || !res.OK {
		return true // unknown: assume it runs (that only makes Rowsafe wait)
	}
	return res.Running()
}

// localPostmaster reports whether a postmaster of this container (Rowsafe's
// private recovery) serves dataDir: the pid in postmaster.pid is a process
// here whose working directory is dataDir (a postmaster chdirs into its
// data directory).
func localPostmaster(dataDir string) bool {
	data, err := os.ReadFile(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 0 {
		return false
	}
	cwd, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "cwd"))
	return err == nil && filepath.Clean(cwd) == filepath.Clean(dataDir)
}

// errNotLocalPostmaster: in Docker, pg_ctl must never signal a pid from
// PostgreSQL's container (in this container it is another process, often
// the agent itself: both run as pid 1).
var errNotLocalPostmaster = errors.New("PostgreSQL's container is still running; Rowsafe stops it only through the container control service")
