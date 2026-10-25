package opensearch

import (
	"context"
	"errors"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Updates (protocol.FeatureUpdates): OpenSearch comes from its own apt
// repository (artifacts.opensearch.org, one per major version: 2.x, 3.x).
// The agent reports the package installed and the newest one of the same
// major version (engine_updates.go, the package "opensearch"); the root
// helper installs it when a person asks (db-minor-update), after a Mark,
// and restarts opensearch.service. In Docker, Rowsafe never changes
// OpenSearch's image: the sidecar reports the release in its own image
// (BundledVersion), the newest one Rowsafe knows.

var (
	_ agent.EngineVersioner        = (*Engine)(nil)
	_ agent.EngineBundledVersioner = (*Engine)(nil)
)

// Version is the running server's version (agent.EngineVersioner).
func (e *Engine) Version(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	r, err := readRoot(ctx, c)
	if err != nil {
		return "", err
	}
	return r.Version.Number, nil
}

// BundledVersion is the OpenSearch program in the agent's Docker image
// (built on OpenSearch's own image: agent.EngineBundledVersioner). Only a
// sidecar has one to report.
func (e *Engine) BundledVersion(ctx context.Context) (string, error) {
	if !inDocker() {
		return "", errors.New("not a Docker sidecar")
	}
	v := installedVersion(openSearchHome())
	if v == "" {
		return "", ErrNoProgram
	}
	return v, nil
}
