package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Major upgrades (ClickHouse's version jumps, 25.3 -> 25.8): the agent's
// engine_upgrades.go runs the flow; here are ClickHouse's parts. The
// rehearsal restores the newest backup into a temporary server with the
// installed version, then opens the same data with the target version and
// reads every table back (settings and table engines the new version no
// longer accepts make it fail to start or to load them).

var _ agent.EngineUpgrader = (*Engine)(nil)

// UpgradeIssues: ClickHouse supports jumps between any versions, but
// recommends going from LTS to LTS (x.3 and x.8).
func (e *Engine) UpgradeIssues(_ context.Context, _ agent.EngineEnv, _ protocol.DatabaseSpec, from, to string) ([]string, []string, error) {
	var warnings []string
	if !strings.HasSuffix(to, ".3") && !strings.HasSuffix(to, ".8") {
		warnings = append(warnings, fmt.Sprintf("ClickHouse %s isn't a long-term support release (those end in .3 and .8): it gets fixes for a few months only", to))
	}
	warnings = append(warnings, fmt.Sprintf("Read ClickHouse's changelog between %s and %s for settings and behaviors that changed; the rehearsal opens your data with %s", from, to, to))
	return nil, warnings, nil
}

// ServerPackages: the static binary holds the whole server.
func (e *Engine) ServerPackages(string) []string { return []string{"clickhouse-common-static"} }

// AfterUpgrade has nothing to do: ClickHouse converts its data on the way.
func (e *Engine) AfterUpgrade(context.Context, agent.EngineEnv, protocol.DatabaseSpec, string, agent.TaskLogger) error {
	return nil
}

// RehearseUpgrade restores the newest backup with the installed version,
// then opens it with the target version (root/usr/bin/clickhouse) and checks
// every table.
func (e *Engine) RehearseUpgrade(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, root, to string, res *protocol.UpgradeRehearsalResult, tl agent.TaskLogger) error {
	bin := filepath.Join(root, "usr", "bin", "clickhouse")
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("ClickHouse %s's program isn't in its package (%v)", to, err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	b, err := pickBackup(ctx, r, restoreTarget{Latest: true})
	if err != nil {
		return err
	}
	stopped := b.StoppedAt
	res.BackupLabel, res.RecoveredTo = b.Label, &stopped
	dir := drillRoot(env)
	if err := ensureSpace(filepath.Dir(dir), int64(float64(b.DataBytes)*drillSpaceFactor)+512<<20); err != nil {
		return err
	}
	s, err := newScratch(dir, "upgrade-"+time.Now().UTC().Format("20060102T150405"), b.Macros, b.needsKeeper())
	if err != nil {
		return err
	}
	defer func() { _, _ = s.remove() }()
	t0 := time.Now()
	tl.Printf("restoring backup %s into a temporary server with the installed version", b.Label)
	c, err := s.start(ctx, env)
	if err != nil {
		return err
	}
	skip, err := restoreInto(ctx, env, r, b, c, tl)
	if err != nil {
		return err
	}
	if err := s.stop(); err != nil {
		return err
	}
	res.RestoreSeconds = time.Since(t0).Seconds()
	t1 := time.Now()
	s.Bin = bin
	tl.Printf("opening the restored data with ClickHouse %s", to)
	c, err = s.start(ctx, env)
	if err != nil {
		return fmt.Errorf("ClickHouse %s didn't start on the restored data: %w", to, err)
	}
	res.UpgradeSeconds = time.Since(t1).Seconds()
	if v, err := c.scalar(ctx, "SELECT version()", nil); err == nil {
		res.ToVersion = strings.TrimSpace(v)
	}
	dres := &protocol.DrillResult{}
	checkRestored(ctx, c, b, skip, dres, tl)
	res.Databases = dres.Databases
	res.Warnings = append(res.Warnings, dres.Warnings...)
	res.Issues = append(res.Issues, dres.Failures...)
	res.Passed = len(res.Issues) == 0
	if !res.Passed {
		return errors.New("the restored data doesn't read back in full with ClickHouse " + to)
	}
	tl.Printf("ClickHouse %s opened every table of the restored copy", to)
	return nil
}
