package redis

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Major upgrades of Redis (7.2 -> 7.4 -> 8.x) and Valkey (8 -> 9): the
// agent's engine_upgrades.go runs the flow (check, rehearsal on a restored
// copy, the root helper's db-upgrade with a copy of the data directory and
// the installed packages kept for 7 days, undo); here are the engine's
// parts. The rehearsal restores the newest backup and the changes since
// into a temporary server with the installed version, saves it, then opens
// the same file with the target version and checks every logical database
// has the same keys. A newer server reads older snapshots; an older one
// can't read a newer server's, which is why undo puts the kept data
// directory back rather than the newer data.

var _ agent.EngineUpgrader = (*Engine)(nil)

// UpgradeIssues says what to know before upgrading from one series to
// another. Nothing blocks a Redis or Valkey upgrade by itself: newer
// versions load older snapshots and append-only files.
func (e *Engine) UpgradeIssues(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, from, to string) ([]string, []string, error) {
	var warnings []string
	name := e.display()
	if e.name == protocol.EngineRedis && seriesMajor(from) < 8 && seriesMajor(to) >= 8 {
		warnings = append(warnings, "Redis 8 is published under other licenses than Redis 7 (RSALv2, SSPLv1 or AGPLv3): check they suit how you use it before upgrading")
	}
	if c, err := connectDB(ctx, env, db); err == nil {
		if mods := productionModules(ctx, c); len(mods) > 0 {
			var names []string
			for _, m := range mods {
				names = append(names, filepath.Base(m[0]))
			}
			warnings = append(warnings, fmt.Sprintf("%s loads modules (%s): they must exist in a version built for %s %s, or it won't start (the rehearsal tries them)",
				name, strings.Join(names, ", "), name, to))
		}
		c.Close()
	}
	warnings = append(warnings, fmt.Sprintf("Once %s %s has written data, %s %s can't read it: undo puts back the data from before the upgrade, and what was written since is kept aside", name, to, name, from))
	return nil, warnings, nil
}

// seriesMajor: "7.4" -> 7.
func seriesMajor(series string) int {
	n, _ := strconv.Atoi(strings.SplitN(series, ".", 2)[0])
	return n
}

// ServerPackages are the packages holding the server program: Debian's
// redis-server only links to the program in redis-tools (Valkey's
// likewise); Redis's own packages (packages.redis.io) keep it in
// redis-server.
func (e *Engine) ServerPackages(string) []string {
	if e.name == protocol.EngineValkey {
		return []string{"valkey-server", "valkey-tools"}
	}
	return []string{"redis-server", "redis-tools"}
}

// AfterUpgrade has nothing to do: the server converts its data as it
// writes it.
func (e *Engine) AfterUpgrade(context.Context, agent.EngineEnv, protocol.DatabaseSpec, string, agent.TaskLogger) error {
	return nil
}

// targetBinary finds the server program among the unpacked packages.
func (e *Engine) targetBinary(root string) (string, error) {
	name := "redis-server"
	if e.name == protocol.EngineValkey {
		name = "valkey-server"
	}
	for _, p := range []string{filepath.Join(root, "usr", "bin", name), filepath.Join(root, "usr", "local", "bin", name),
		filepath.Join(root, "opt", strings.TrimSuffix(name, "-server"), "bin", name)} {
		// Debian's server package links the program by a relative name:
		// resolve it inside root.
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("the %s program isn't in the downloaded packages (%s)", name, strings.Join(e.ServerPackages(""), ", "))
}

// RehearseUpgrade restores the newest backup and the changes since with the
// installed version, saves it, then opens the saved file with the target
// version (unpacked under root) and compares the keys of every logical
// database.
func (e *Engine) RehearseUpgrade(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, root, to string, res *protocol.UpgradeRehearsalResult, tl agent.TaskLogger) error {
	bin, err := e.targetBinary(root)
	if err != nil {
		return err
	}
	be, bv, err := binaryVersion(bin)
	if err != nil {
		return fmt.Errorf("%s %s's program doesn't run on this server: %w", e.display(), to, err)
	}
	if be != e.name {
		return fmt.Errorf("the downloaded program is %s, not %s", protocol.EngineDisplayName(be), e.display())
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	var prod serverInfo
	if c, err := connectDB(ctx, env, db); err == nil {
		prod, _ = inspect(ctx, c)
		c.Close()
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	s, err := newScratch(env, drillRoot(env, e.name), "upgrade-"+time.Now().UTC().Format("20060102T150405"))
	if err != nil {
		return err
	}
	defer func() { _, _ = s.remove() }()
	t0 := time.Now()
	tl.Printf("restoring the newest backup and the changes since into a temporary %s server with the installed version", e.display())
	out, c, err := e.restoreInto(ctx, env, r, restoreTarget{Latest: true}, &s, prod.Executable, tl)
	res.BackupLabel = out.Base.Label
	res.Warnings = append(res.Warnings, out.Warnings...)
	if err != nil {
		return err
	}
	rt := out.RecoveredTo
	res.RecoveredTo = &rt
	before, err := keyCounts(ctx, c)
	if err == nil {
		_, err = c.do(ctx, "SAVE")
	}
	c.Close()
	if err != nil {
		return fmt.Errorf("saving the restored copy: %w", err)
	}
	if err := s.stop(); err != nil {
		return err
	}
	res.RestoreSeconds = time.Since(t0).Seconds()

	t1 := time.Now()
	tl.Printf("opening the saved copy with %s %s (%s)", e.display(), to, majorMinor(bv))
	if err := s.switchBinary(bin); err != nil {
		return err
	}
	c, err = s.restart(ctx, env)
	if err != nil {
		return fmt.Errorf("%s %s didn't start on the restored data: %w", e.display(), to, err)
	}
	defer c.Close()
	res.UpgradeSeconds = time.Since(t1).Seconds()
	if m, err := c.info(ctx, "server"); err == nil {
		_, res.ToVersion = engineOf(m)
	}
	after, err := keyCounts(ctx, c)
	if err != nil {
		return fmt.Errorf("reading the copy with %s %s: %w", e.display(), to, err)
	}
	compareUpgrade(before, after, res)
	res.Passed = len(res.Issues) == 0
	if !res.Passed {
		return errors.New("the restored data doesn't read back in full with " + e.display() + " " + to)
	}
	tl.Printf("%s %s read every logical database of the restored copy back", e.display(), to)
	return nil
}

// compareUpgrade checks every logical database has the keys it had before
// (keys with an expiry may have expired in between).
func compareUpgrade(before, after map[int]dbKeys, res *protocol.UpgradeRehearsalResult) {
	var idx []int
	for n := range before {
		idx = append(idx, n)
	}
	for n := range after {
		if _, ok := before[n]; !ok {
			idx = append(idx, n)
		}
	}
	slices.Sort(idx)
	for _, n := range idx {
		b, a := before[n], after[n]
		res.Databases = append(res.Databases, protocol.DrillDatabase{Name: "db" + strconv.Itoa(n), SourceTables: clampInt(b.Keys),
			RestoredTables: clampInt(a.Keys), Present: a.Keys > 0 || b.Keys == 0})
		if a.Keys < b.Keys-b.Expires {
			res.Issues = append(res.Issues, fmt.Sprintf("db%d: %s keys read back with the new version, %s before", n, commas(a.Keys), commas(b.Keys)))
		}
	}
}

// switchBinary makes the scratch server's saved start options use bin
// (restart then starts the new version on the same data).
func (s scratch) switchBinary(bin string) error {
	var saved struct {
		Bin  string      `json:"bin"`
		Opts scratchOpts `json:"opts"`
	}
	if err := loadJSONFile(filepath.Join(s.Dir, "scratch.json"), &saved); err != nil {
		return err
	}
	saved.Bin = bin
	return saveJSONFile(filepath.Join(s.Dir, "scratch.json"), saved)
}
