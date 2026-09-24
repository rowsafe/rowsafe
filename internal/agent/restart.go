package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Restarting PostgreSQL.
//
// Rowsafe never restarts PostgreSQL on its own. A restart task exists only
// because a person asked (Restart in the dashboard, `rowsafe restart`), and
// the agent, which runs unprivileged, cannot restart anything itself: it
// hands the request to a root helper that the installer sets up only when
// root allows it, and only for the clusters root listed:
//
//	/etc/rowsafe/restart-allowed        root, 0644: "PORT UNIT" per cluster
//	<state dir>/restart/request         written by the agent: "ID PORT"
//	/run/rowsafe-pg-restart/result      written by the helper: key=value lines
//
// rowsafe-pg-restart.path starts rowsafe-pg-restart.service (root) when the
// request appears; the helper reads and removes it as the agent user, checks
// the port against the allow list, runs systemctl restart UNIT and writes
// the result in its own directory (root never writes where the agent can).

// Timings of a restart task (variables for tests).
var (
	restartHelperTimeout = 150 * time.Second // the helper allows systemctl 120s
	restartBackTimeout   = 2 * time.Minute   // PostgreSQL answering again
	restartPoll          = 250 * time.Millisecond
)

var restartIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ReadRestartAllowed reads the allow list: port -> systemd unit. A missing
// file means restarting from Rowsafe is off.
func ReadRestartAllowed(path string) (map[int]string, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[int]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[int]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		port, err := strconv.Atoi(fields[0])
		if err != nil || port < 1 || port > 65535 || !strings.HasSuffix(fields[1], ".service") {
			continue
		}
		out[port] = fields[1]
	}
	return out, sc.Err()
}

// restartPorts are the ports reported in the heartbeat.
func (a *Agent) restartPorts() []int {
	if a.cfg.Sidecar() || a.cfg.RestartAllowFile == "" {
		return nil
	}
	allowed, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		a.log.Warn("reading the restart allow list", "path", a.cfg.RestartAllowFile, "err", err)
		return nil
	}
	var ports []int
	for p := range allowed {
		ports = append(ports, p)
	}
	slices.Sort(ports)
	return ports
}

func (a *Agent) restart(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.RestartResult, error) {
	host, _ := os.Hostname()
	if a.cfg.Sidecar() {
		return nil, fmt.Errorf("Rowsafe can't restart PostgreSQL running in Docker. Restart its container yourself " +
			"(e.g. `docker compose restart postgres`); Rowsafe notices the restart by itself")
	}
	allowed, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", a.cfg.RestartAllowFile, err)
	}
	unit, ok := allowed[db.Port]
	if !ok {
		return nil, fmt.Errorf("restarting PostgreSQL from Rowsafe is not turned on for port %d on %s. Restart it yourself on the server: %s "+
			"(to allow restarts from Rowsafe, run the installer again with --allow-restart)", db.Port, host, a.restartHint(ctx, db))
	}
	if st, err := os.Stat(a.cfg.RestartDir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("the restart helper is not set up on %s (%s is missing): run the installer again with --allow-restart, "+
			"or restart PostgreSQL yourself: sudo systemctl restart %s", host, a.cfg.RestartDir, strings.TrimSuffix(unit, ".service"))
	}

	start := time.Now()
	tl.Printf("asking the restart helper to restart %s (port %d)", unit, db.Port)
	res, err := a.askHelper(ctx, helperRestart, db.Port, taskID)
	if err != nil {
		if errors.Is(err, errRestartNoAnswer) {
			return nil, fmt.Errorf("%w, or restart PostgreSQL yourself: sudo systemctl restart %s", err, strings.TrimSuffix(unit, ".service"))
		}
		return nil, err
	}
	if res["ok"] != "1" {
		msg := res["error"]
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("restarting %s failed: %s", unit, msg)
	}
	if u := res["unit"]; u != "" {
		unit = u
	}
	tl.Printf("%s restarted; waiting for PostgreSQL to answer", unit)

	out := &protocol.RestartResult{Restarted: true, Unit: unit}
	deadline := time.Now().Add(restartBackTimeout)
	for {
		mode, err := a.pgArchiveMode(ctx, a.target(db))
		if err == nil {
			out.ArchiveMode = mode
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			out.DurationMs = time.Since(start).Milliseconds()
			return out, fmt.Errorf("%s restarted, but PostgreSQL is not answering on port %d after %s: %w", unit, db.Port, restartBackTimeout, err)
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

var errRestartNoAnswer = errors.New("no answer from the restart helper")

// Root helper actions.
const (
	helperRestart = "restart"
	helperStop    = "stop"
	helperStart   = "start"
)

// askHelper hands one request to the root helper and waits for its answer
// (key=value lines). Restarts use the "ID PORT" form every helper
// understands; stop and start need the helper from agent 0.4.0 on
// ("ID ACTION PORT"), and an older one answers "malformed request".
func (a *Agent) askHelper(ctx context.Context, action string, port int, id string) (map[string]string, error) {
	host, _ := os.Hostname()
	if !restartIDRE.MatchString(id) {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		id = hex.EncodeToString(b)
	}
	line := fmt.Sprintf("%s %s %d\n", id, action, port)
	if action == helperRestart {
		line = fmt.Sprintf("%s %d\n", id, port)
	}
	request := filepath.Join(a.cfg.RestartDir, "request")
	if err := writeFileAtomic(request, []byte(line), 0o600); err != nil {
		return nil, err
	}
	res, err := waitRestartResult(ctx, filepath.Join(a.cfg.RestartResultDir, "result"), id)
	if err != nil {
		_ = os.Remove(request)
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errRestartNoAnswer) {
			return nil, fmt.Errorf("%w: the restart helper on %s did not answer within %s; check `systemctl status rowsafe-pg-restart.path rowsafe-pg-restart.service`",
				errRestartNoAnswer, host, restartHelperTimeout)
		}
		return nil, err
	}
	if action != helperRestart && res["ok"] != "1" && res["error"] == "malformed request" {
		return nil, fmt.Errorf("%w: the helper that restarts PostgreSQL on %s is from an older Rowsafe and can't stop it. "+
			"Re-run the install command on the server to allow Rewind there", errOldHelper, host)
	}
	return res, nil
}

var errOldHelper = errors.New("old restart helper")

// helperActions reads what the installed root helper can do from its
// "# actions:" line (reported in the heartbeat). A helper without one only
// restarts.
func (a *Agent) helperActions() []string {
	if a.cfg.Sidecar() || a.cfg.RestartHelper == "" || len(a.restartPorts()) == 0 {
		return nil
	}
	data, err := os.ReadFile(a.cfg.RestartHelper)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "# actions:"); ok {
			var out []string
			for _, f := range strings.Fields(rest) {
				if f == helperRestart || f == helperStop || f == helperStart {
					out = append(out, f)
				}
			}
			return out
		}
	}
	return []string{helperRestart}
}

// waitRestartResult waits for the helper's result for request id.
func waitRestartResult(ctx context.Context, path, id string) (map[string]string, error) {
	deadline := time.Now().Add(restartHelperTimeout)
	for {
		if data, err := os.ReadFile(path); err == nil {
			res := parseKeyValues(string(data))
			if res["id"] == id {
				return res, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, errRestartNoAnswer
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(restartPoll):
		}
	}
}

func parseKeyValues(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

// restartHint is the command that restarts db's cluster, for messages.
func (a *Agent) restartHint(ctx context.Context, db protocol.DatabaseSpec) string {
	dataDir, major, cluster := "", 0, ""
	if in, err := summarizeCluster(ctx, a.target(db)); err == nil {
		dataDir, major = in.DataDirectory, in.Major()
		cluster = debianCluster(dataDir, major)
	}
	return RestartCommand(SystemdUnit(dataDir, major, cluster), major, cluster)
}

// Where systemd units and processes are looked up (variables for tests).
var (
	procRoot     = "/proc"
	unitFileDirs = []string{"/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"}
)

// SystemdUnit finds the systemd service running the cluster in dataDir: the
// unit whose cgroup holds the postmaster, else Debian's
// postgresql@MAJOR-CLUSTER.service when that template is installed. "" when
// neither is found.
func SystemdUnit(dataDir string, major int, cluster string) string {
	if dataDir != "" {
		if data, err := os.ReadFile(filepath.Join(dataDir, "postmaster.pid")); err == nil {
			pid, _, _ := strings.Cut(string(data), "\n")
			if n, err := strconv.Atoi(strings.TrimSpace(pid)); err == nil && n > 0 {
				if cg, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(n), "cgroup")); err == nil {
					if u := unitFromCgroup(string(cg)); u != "" {
						return u
					}
				}
			}
		}
	}
	if cluster != "" && major > 0 {
		for _, dir := range unitFileDirs {
			if _, err := os.Stat(filepath.Join(dir, "postgresql@.service")); err == nil {
				return fmt.Sprintf("postgresql@%d-%s.service", major, cluster)
			}
		}
	}
	return ""
}

var unitNameRE = regexp.MustCompile(`^[A-Za-z0-9@._\\-]+\.service$`)

// unitFromCgroup picks the system service from /proc/PID/cgroup (cgroup v2
// "0::/system.slice/x.service", or v1's name=systemd hierarchy).
func unitFromCgroup(s string) string {
	for _, line := range strings.Split(s, "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || !(parts[0] == "0" && parts[1] == "" || parts[1] == "name=systemd") {
			continue
		}
		path := parts[2]
		if !strings.HasPrefix(path, "/system.slice/") {
			continue
		}
		unit := strings.TrimPrefix(path, "/system.slice/")
		unit, _, _ = strings.Cut(unit, "/")
		if unitNameRE.MatchString(unit) {
			return unit
		}
	}
	return ""
}

var debianDataDirRE = regexp.MustCompile(`^/var/lib/postgresql/(\d+)/([^/]+)/?$`)

// debianCluster guesses the Debian cluster name from a data directory in
// the default layout (/var/lib/postgresql/18/main -> main).
func debianCluster(dataDir string, major int) string {
	m := debianDataDirRE.FindStringSubmatch(dataDir)
	if m == nil || m[1] != strconv.Itoa(major) {
		return ""
	}
	return m[2]
}

// RestartCommand is the command a person runs (as root) to restart a
// cluster.
func RestartCommand(unit string, major int, cluster string) string {
	switch {
	case unit != "":
		return "sudo systemctl restart " + strings.TrimSuffix(unit, ".service")
	case cluster != "" && major > 0:
		return fmt.Sprintf("sudo pg_ctlcluster %d %s restart", major, cluster)
	}
	return "sudo systemctl restart postgresql"
}
