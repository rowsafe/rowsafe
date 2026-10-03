package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Clones (protocol.FeatureFork): a backup (or a Mark's) of the source,
// restored straight into an empty ClickHouse server on the target host
// whose Rowsafe user may create databases (`clickhouse login --clones`,
// asked by the installer), as of any moment (pitr_restore.go) or a Mark.
// Its users and grants aren't in the backup and aren't copied.

var (
	_ agent.EngineFork    = (*Engine)(nil)
	_ agent.EngineTargets = (*Engine)(nil)
)

// ForkFacts reads the source's version and size.
func (e *Engine) ForkFacts(ctx context.Context, env agent.EngineEnv, source protocol.DatabaseSpec) (int, int64, map[string]int, error) {
	c, err := connectDB(ctx, env, source)
	if err != nil {
		return 0, 0, nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return 0, 0, nil, err
	}
	return in.VersionNum / 100, in.TotalBytes, nil, nil
}

// ForkRestore restores the source's backup for p.Target into the empty
// server on p.Port.
func (e *Engine) ForkRestore(ctx context.Context, env agent.EngineEnv, p protocol.ForkRestoreParams, tl agent.TaskLogger) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	if p.Placement != protocol.ForkEmptyServer || p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("a ClickHouse clone goes into an empty ClickHouse server (placement %q, port %d)", p.Placement, p.Port)
	}
	if p.Masking != nil {
		return nil, errors.New("masking isn't available for ClickHouse clones yet; nothing was restored")
	}
	target := restoreTarget{Mark: p.Target.Mark, BackupSet: p.Target.BackupSet}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if target.Mark != "" && !markNameRE.MatchString(target.Mark) {
		return nil, fmt.Errorf("invalid Mark name %q", target.Mark)
	}
	if target.BackupSet != "" && !validLabel(target.BackupSet) {
		return nil, fmt.Errorf("invalid backup %q", target.BackupSet)
	}
	if target.Mark == "" && target.Time.IsZero() && target.BackupSet == "" {
		target.Latest = true
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: p.Port})
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if reason := cloneTargetReason(in); reason != "" {
		return nil, fmt.Errorf("the ClickHouse server on port %d can't take the clone: %s; nothing was changed", p.Port, reason)
	}
	if p.Major > 0 && in.VersionNum/100 < p.Major {
		return nil, fmt.Errorf("the ClickHouse server on port %d runs %s, older than the source (%d.%d): a clone needs the same version or newer",
			p.Port, in.Version, p.Major/100, p.Major%100)
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: p.Source.Stanza})
	if err != nil {
		return nil, err
	}
	b, recovered, err := e.pickTarget(ctx, env, p.Source, r, target, tl)
	if err != nil {
		return nil, err
	}
	if b.needsKeeper() {
		return nil, errors.New("this backup has replicated databases or tables, which need ClickHouse Keeper on the clone's server; Rowsafe doesn't set that up, so nothing was restored")
	}
	tl.Printf("restoring %s as of %s into the ClickHouse server on port %d", p.Source.Name, target.describe(), p.Port)
	skip, err := restoreTo(ctx, env, r, b, c, false, tl)
	if err != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		for _, d := range b.Databases {
			if derr := c.exec(cctx, "DROP DATABASE IF EXISTS "+quoteIdent(d.Name)+" SYNC", nil); derr != nil {
				tl.Printf("emptying the server again: dropping %s: %s", d.Name, shortError(derr))
			}
		}
		return nil, err
	}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: p.Port, Major: in.VersionNum / 100,
		DurationMs: time.Since(start).Milliseconds()}
	recovered = recovered.UTC()
	res.RecoveredTo = &recovered
	if dbs, total, err := restoredDatabases(ctx, c); err == nil {
		for _, d := range dbs {
			if d.Name != "default" || d.Tables > 0 {
				res.Databases = append(res.Databases, d)
			}
		}
		res.SizeBytes = total
	}
	for k, why := range skip {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s was left out: %s.", k, why))
	}
	res.Warnings = append(res.Warnings, "ClickHouse users and grants aren't in backups: create the clone's users on it.")
	res.Summary = fmt.Sprintf("Cloned %s %s into the ClickHouse server on port %d (%s).", p.Source.Name, b.asOf(recovered),
		p.Port, countWord(len(res.Databases), "database", "databases"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// cloneTargetReason says why a server can't take a clone ("" when it can).
func cloneTargetReason(in serverInfo) string {
	switch {
	case !cloneRights(in.Grants):
		return "Rowsafe's user there may not create databases: run the Rowsafe installer on that server again and answer yes to receiving clones"
	}
	var names []string
	for _, d := range in.Databases {
		if d.Name == "default" && d.Tables == 0 {
			continue // every server has it
		}
		names = append(names, d.Name)
	}
	if len(names) > 0 {
		return "it isn't empty (databases: " + strings.Join(names, ", ") + ")"
	}
	return ""
}

var (
	targetsMu    sync.Mutex
	targetsAt    time.Time
	targetsCache []protocol.StandbyTarget
)

// StandbyTargets lists the local ClickHouse servers that could receive a
// clone (cached two minutes: it connects to each).
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() || inDocker() {
		return nil
	}
	targetsMu.Lock()
	defer targetsMu.Unlock()
	if time.Since(targetsAt) < 2*time.Minute {
		return targetsCache
	}
	var out []protocol.StandbyTarget
	seen := map[int]bool{}
	for _, p := range findServers() {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		t := protocol.StandbyTarget{Engine: protocol.EngineClickHouse, Port: p.Port}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, err := connectDB(cctx, env, protocol.DatabaseSpec{Port: p.Port})
		if err != nil {
			t.Reason = "Rowsafe has no login there: run the Rowsafe installer on this server and answer yes to receiving clones"
		} else if in, err := inspect(cctx, c); err != nil {
			t.Reason = shortError(err)
		} else {
			t.Version = in.Version
			t.Reason = cloneTargetReason(in)
		}
		cancel()
		t.Usable = t.Reason == ""
		out = append(out, t)
	}
	targetsAt, targetsCache = time.Now(), out
	return out
}

func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}
