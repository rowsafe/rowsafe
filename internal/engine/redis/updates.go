package redis

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Minor updates (pg_update): the agent's engine_updates.go asks root's
// helper to install the newest redis-server (valkey-server) of the
// installed series; the engine only says which version runs, and in a
// Docker sidecar which one the agent's image bundles.

var (
	_ agent.EngineVersioner        = (*Engine)(nil)
	_ agent.EngineBundledVersioner = (*Engine)(nil)
)

// Version is the running server's version ("8.2.1"; Valkey's own, not the
// Redis version it says it is compatible with).
func (e *Engine) Version(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	defer c.Close()
	m, err := c.info(ctx, "server")
	if err != nil {
		return "", err
	}
	_, v := engineOf(m)
	if v = strings.TrimSpace(v); v == "" {
		return "", errors.New(e.display() + " didn't say its version")
	}
	return v, nil
}

// BundledVersion is the version of the server program next to the agent
// ("8.2.3"): in a sidecar, the official image the agent image is built on,
// the newest release of its series when Rowsafe built it.
func (e *Engine) BundledVersion(ctx context.Context) (string, error) {
	bin, err := serverBinary(e.name, "")
	if err != nil {
		return "", err
	}
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", err
	}
	return parseBinaryVersion(string(out))
}

// parseBinaryVersion reads `redis-server --version`: "Redis server v=8.2.1
// sha=00000000:0 malloc=jemalloc-5.3.0 bits=64 build=..." -> "8.2.1".
func parseBinaryVersion(out string) (string, error) {
	m := binVersionRE.FindStringSubmatch(strings.TrimSpace(out))
	if m == nil {
		return "", fmt.Errorf("unexpected --version output %q", firstLine(out))
	}
	return m[2], nil
}
