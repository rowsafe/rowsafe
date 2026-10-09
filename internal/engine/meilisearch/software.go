package meilisearch

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Updates (protocol.FeatureUpdates): Meilisearch isn't from the
// distribution's package sources but from its release on GitHub, pinned by
// Rowsafe (protocol.MeilisearchVersion). The agent reports the program the
// installer set up and the server running; a newer pinned release of the
// same major version is the update the root helper installs when a person
// asks (db-minor-update, meilisearch_update: Meilisearch's dumpless upgrade
// and a restart, after a Mark). An adopted Meilisearch is updated by its
// owner: nothing is reported for it.

// Version is the running server's version (agent.EngineVersioner).
func (e *Engine) Version(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (string, error) {
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return "", err
	}
	defer c.close()
	v, err := c.version(ctx)
	if err != nil {
		return "", err
	}
	return v.PkgVersion, nil
}

// installedLib is where the installer keeps Meilisearch's versions.
const installedLib = "/usr/local/lib/meilisearch/"

// Software reports the program installed and the update Rowsafe pins
// (agent.EngineSoftwareReporter).
func (e *Engine) Software(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.ClusterSoftware, bool) {
	var cs protocol.ClusterSoftware
	s, err := loadServer(env, db.Port)
	if err != nil || !s.Rowsafe || s.Binary == "" {
		return cs, false
	}
	real, err := filepath.EvalSymlinks(s.Binary)
	if err != nil || !strings.HasPrefix(real, installedLib) {
		return cs, false
	}
	v, err := binaryVersion(real)
	if err != nil || v == "" {
		return cs, false
	}
	cs.Installed, cs.InstalledPackage = v, v
	cs.Series = seriesOf(v)
	cs.Candidate, cs.CandidatePackage = v, v
	if pin := protocol.MeilisearchVersion; majorOf(pin) == majorOf(v) && versionNum(pin) > versionNum(v) {
		cs.Candidate, cs.CandidatePackage = pin, pin
	}
	cs.Major = protocol.SeriesNumber(cs.Series)
	return cs, true
}

// seriesOf: "1.54.3" -> "1.54".
func seriesOf(v string) string {
	if i := strings.LastIndex(v, "."); i > 0 {
		return v[:i]
	}
	return ""
}

func majorOf(v string) string {
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}
