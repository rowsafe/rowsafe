package qdrant

import (
	"context"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Updates (protocol.FeatureUpdates): Qdrant isn't from the distribution's
// package sources but from its release on GitHub, pinned by Rowsafe
// (protocol.QdrantVersion, the installer's QDRANT_* settings). The agent
// reports the program on disk and the server running; the newer pinned
// release of the same series is the update the root helper installs when
// a person asks (db-minor-update, qdrant_update).

// Version is the running server's version (agent.EngineVersioner).
func (e *Engine) Version(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return "", err
	}
	defer c.Close()
	r, err := c.root(ctx)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(r.Version, "v"), nil
}

// BundledVersion is the qdrant program in the agent's Docker image (the
// sidecar is built on Qdrant's own image: agent.EngineBundledVersioner).
func (e *Engine) BundledVersion(ctx context.Context) (string, error) {
	bin, err := serverBinary()
	if err != nil {
		return "", err
	}
	v, err := binaryVersion(bin)
	if err != nil {
		return "", err
	}
	return versionText(v), nil
}

// seriesOf: "1.19.2" -> "1.19".
func seriesOf(v string) string {
	if i := strings.LastIndex(v, "."); i > 0 {
		return v[:i]
	}
	return ""
}

// Software reports the program installed and the update Rowsafe pins
// (agent.EngineSoftwareReporter). ok false when there is no program here
// to update (Docker: the sidecar reports BundledVersion instead).
func (e *Engine) Software(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.ClusterSoftware, bool) {
	var cs protocol.ClusterSoftware
	if inDocker() {
		return cs, false
	}
	bin, err := serverBinary()
	if err != nil {
		return cs, false
	}
	v, err := binaryVersion(bin)
	if err != nil || v == 0 {
		return cs, false
	}
	cs.Installed = versionText(v)
	cs.InstalledPackage = cs.Installed
	cs.Series = seriesOf(cs.Installed)
	cs.Candidate, cs.CandidatePackage = cs.Installed, cs.Installed
	if pin := protocol.QdrantVersion; seriesOf(pin) == cs.Series && parseVersion(pin) > v {
		cs.Candidate, cs.CandidatePackage = pin, pin
	}
	cs.Major = protocol.SeriesNumber(cs.Series)
	return cs, true
}
