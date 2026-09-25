// Command rowsafe-agent runs on each database host as the postgres user.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	_ "github.com/rowsafe/rowsafe/internal/engine/mysql" // MySQL and MariaDB
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/release"
)

const usage = `rowsafe-agent - Rowsafe database host agent

Usage:
  rowsafe-agent run                         enroll if needed, then execute tasks
  rowsafe-agent inspect [--port 5432] [--socket-dir /var/run/postgresql]
                                            print what the agent sees (read-only)
  rowsafe-agent setup discover|plan|apply|wait|status ...
                                            turn on backups for this server's PostgreSQL
                                            (used by the installer; see setup --help)
  rowsafe-agent selftest                    check this binary can run here (used before self-update)
  rowsafe-agent health                      container health check (docker-sidecar mode)
  rowsafe-agent version

Runs as the postgres OS user. Configuration comes from the environment,
normally /etc/rowsafe/agent.env; see https://rowsafe.sh/docs/reference/agent-configuration. In Docker, see
https://rowsafe.sh/docs/guides/docker.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "run":
		err = run(ctx)
	case "inspect":
		err = inspect(ctx, os.Args[2:])
	case "setup":
		os.Exit(setup(ctx, os.Args[2:]))
	case "selftest":
		os.Exit(selftest(ctx))
	case "health":
		os.Exit(health())
	case "version":
		fmt.Println(agent.Version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	cfg, err := agent.ConfigFromEnv()
	if os.Geteuid() == 0 {
		if err == nil && cfg.Sidecar() {
			return fmt.Errorf("refusing to run as root: run the agent container as the postgres user of the PostgreSQL image " +
				"(user: \"999:999\" for the Debian-based images, \"70:70\" for the Alpine ones; see https://rowsafe.sh/docs/guides/docker)")
		}
		return fmt.Errorf("refusing to run as root: run rowsafe-agent as the postgres user (see deploy/systemd/rowsafe-agent.service)")
	}
	if err != nil {
		return err
	}
	if err := cfg.Repo.Validate(); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	logger.Info("rowsafe-agent starting", "version", agent.Version, "control_url", cfg.ControlURL, "mode", cfg.Mode)
	err = agent.New(cfg, logger).Run(ctx)
	if errors.Is(err, agent.ErrRestartForUpdate) {
		// Exit cleanly; systemd (Restart=always) starts the newly linked version.
		logger.Info("exiting so systemd can start the new agent version")
		return nil
	}
	return err
}

// selftest checks, from the new binary's point of view, everything it needs
// to take over: configuration, pgBackRest, the control plane and every local
// Postgres the running agent watches. It prints JSON and exits non-zero on
// any failure.
func selftest(ctx context.Context) int {
	res := agent.SelfTestResult{Version: agent.Version, Platform: release.Platform()}
	check := func(name string, err error) {
		if err != nil {
			res.Errors = append(res.Errors, name+": "+err.Error())
		} else {
			res.Checks = append(res.Checks, name)
		}
	}
	cfg, err := agent.ConfigFromEnv()
	check("config", err)
	if err == nil {
		check("repository settings", cfg.Repo.Validate())
		check("pgbackrest", exec.CommandContext(ctx, cfg.PgBackRestBin, "version").Run())
		check("control plane", agent.CheckControlPlane(ctx, cfg))
		for _, t := range agent.WatchedTargets(cfg) {
			conn, err := t.Connect(ctx, "postgres")
			if err == nil {
				conn.Close(ctx)
			}
			check(fmt.Sprintf("postgres %s:%d", t.SocketDir, t.Port), err)
		}
	}
	res.OK = len(res.Errors) == 0
	json.NewEncoder(os.Stdout).Encode(res)
	if !res.OK {
		return 1
	}
	return 0
}

// health is the Docker HEALTHCHECK: the WAL spool pusher is running and no
// spool is stalled.
func health() int {
	cfg, err := agent.ConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	if !cfg.Sidecar() {
		fmt.Println("health checks are only kept in docker-sidecar mode")
		return 0
	}
	state, err := agent.CheckHealth(cfg, time.Now())
	if len(state) > 0 {
		fmt.Println(string(state))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	return 0
}

func inspect(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	port := fs.Int("port", 5432, "Postgres port")
	socketDir := fs.String("socket-dir", "/var/run/postgresql", "Unix socket directory")
	user := fs.String("user", "postgres", "database role")
	fs.Parse(args)
	res, err := pginspect.Inspect(ctx, pginspect.Target{SocketDir: *socketDir, Port: *port, User: *user})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}
