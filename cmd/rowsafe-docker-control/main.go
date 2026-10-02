// Command rowsafe-docker-control lets the Rowsafe agent (a Docker sidecar)
// stop, start and restart exactly one container, the PostgreSQL container
// next to it, and, if its operator allows it, replace the agent's own
// container with the signed image of a newer release, without ever giving
// the agent the Docker socket. Opt-in: see
// https://rowsafe.sh/docs/guides/docker#let-rowsafe-restart-the-container
// and internal/dockerctl for the policy it enforces.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/dockerctl"
)

// version and releasePublicKey (base64 Ed25519, which verifies the signed
// agent images documents) are set at build time.
var (
	version          = "dev"
	releasePublicKey = ""
)

const usage = `rowsafe-docker-control - let the Rowsafe agent restart one container

Usage:
  rowsafe-docker-control run       serve the agent (default)
  rowsafe-docker-control version

Environment:
  ROWSAFE_CONTROL_SERVICE     compose service to control, in this container's own
                              compose project (default: postgres; e.g. clickhouse)
  ROWSAFE_CONTROL_CONTAINER   or: the name of the container to control (without compose)
  ROWSAFE_CONTROL_SOCKET      where the agent connects (default: ` + dockerctl.DefaultSocket + `)
  ROWSAFE_CONTROL_ALLOW_UIDS  uids allowed to connect (default: 999,70; the ClickHouse
                              agent image: 101)
  ROWSAFE_CONTROL_STOP_TIMEOUT  how long PostgreSQL may take to shut down (default: 2m)
  ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE  1: also let the agent ask for its own container to be
                              replaced by the signed image of a newer release (default: off)
  ROWSAFE_CONTROL_AGENT_SERVICE   the agent's compose service (default: rowsafe-agent)
  ROWSAFE_CONTROL_AGENT_CONTAINER or: the agent container's name (without compose)
  DOCKER_HOST                 unix:///var/run/docker.sock (only Unix sockets)
`

func main() {
	cmd := "run"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "run":
		if err := run(); err != nil {
			fmt.Fprintln(os.Stderr, "rowsafe-docker-control:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func env(name, def string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return def
}

func run() error {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dockerSock := "/var/run/docker.sock"
	if h := env("DOCKER_HOST", ""); h != "" {
		p, ok := strings.CutPrefix(h, "unix://")
		if !ok {
			return fmt.Errorf("DOCKER_HOST %q: only unix:// sockets are supported", h)
		}
		dockerSock = p
	}
	var uids []int
	for _, f := range strings.Split(env("ROWSAFE_CONTROL_ALLOW_UIDS", "999,70"), ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 {
			return fmt.Errorf("ROWSAFE_CONTROL_ALLOW_UIDS: %q is not a uid", f)
		}
		uids = append(uids, n)
	}
	stopTimeout, err := time.ParseDuration(env("ROWSAFE_CONTROL_STOP_TIMEOUT", "2m"))
	if err != nil {
		return fmt.Errorf("ROWSAFE_CONTROL_STOP_TIMEOUT: %w", err)
	}
	allowUpdate, err := parseAllow(env("ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE", "0"))
	if err != nil {
		return fmt.Errorf("ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE: %w", err)
	}
	srv, err := dockerctl.New(dockerctl.Config{
		DockerSocket:     dockerSock,
		Service:          env("ROWSAFE_CONTROL_SERVICE", ""),
		Container:        env("ROWSAFE_CONTROL_CONTAINER", ""),
		StopTimeout:      stopTimeout,
		AllowedUIDs:      uids,
		Log:              log,
		AllowAgentUpdate: allowUpdate,
		AgentService:     env("ROWSAFE_CONTROL_AGENT_SERVICE", ""),
		AgentContainer:   env("ROWSAFE_CONTROL_AGENT_CONTAINER", ""),
		ReleasePublicKey: releasePublicKey,
	})
	if err != nil {
		return err
	}
	if allowUpdate && releasePublicKey == "" {
		log.Warn("ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE is set, but this build has no release key: agent updates will be refused")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sock := env("ROWSAFE_CONTROL_SOCKET", dockerctl.DefaultSocket)
	ln, err := dockerctl.Listen(sock)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", sock, err)
	}
	defer os.Remove(sock)
	actions := dockerctl.Actions
	if allowUpdate {
		actions = append(append([]string(nil), actions...), dockerctl.AgentUpdateActions...)
	}
	log.Info("rowsafe-docker-control started", "version", version, "socket", sock, "allowed_uids", uids,
		"actions", actions)
	// The target may not exist yet (compose starts services in parallel):
	// a failure here is logged and retried on the first request.
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	if _, err := srv.Resolve(rctx); err != nil {
		log.Warn("the container to control isn't there yet; looking again on the first request", "err", err)
	}
	cancel()
	return srv.Serve(ctx, ln)
}

// parseAllow reads an on/off setting: 1/true/yes or 0/false/no.
func parseAllow(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q: use 1 or 0", v)
}
