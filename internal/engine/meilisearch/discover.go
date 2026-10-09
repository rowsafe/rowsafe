package meilisearch

import (
	"context"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Discover finds the Meilisearch instances on this server that the
// installer made Rowsafe's key for (`rowsafe-agent meilisearch login`):
// Meilisearch's API can't say where its files are, so the installer finds
// them first.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	var out []agent.DiscoveredDatabase
	for _, port := range knownPorts(env) {
		s, err := loadServer(env, port)
		if err != nil {
			fmt.Fprintf(env.Notes, "Meilisearch on port %d: %v\n", port, err)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := dial(cctx, s)
		if err != nil {
			cancel()
			fmt.Fprintf(env.Notes, "Meilisearch on port %d doesn't answer: %v\n", port, err)
			continue
		}
		in, err := inspect(cctx, c)
		c.close()
		cancel()
		if err != nil {
			fmt.Fprintf(env.Notes, "Meilisearch on port %d: Rowsafe's key doesn't work (%v): run the installer again\n", port, err)
			continue
		}
		d := agent.DiscoveredDatabase{Port: port, Version: in.Version, DataDir: s.DBPath, SizeBytes: in.DatabaseSize, Unit: s.Unit}
		if maj, _, ok := majorMinor(in.Version); ok {
			d.Major = maj
		}
		for _, i := range in.Indexes {
			d.Databases = append(d.Databases, i.UID)
		}
		out = append(out, d)
	}
	return out, nil
}
