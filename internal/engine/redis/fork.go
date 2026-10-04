package redis

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Clones (protocol.FeatureFork): the source as it was at a moment (or a
// Mark) restored from the bucket into a temporary server on the target host
// (Unix socket only), masked there when asked, then copied key by key
// (DUMP/RESTORE, times to live kept) into an empty server: one root handed
// to Rowsafe at install (--redis-clones), or a new one root's helper
// creates in its port range. The bucket settings and passphrase reach the
// target host sealed to its agent (the agent's fork handoff) and are only
// kept for the restore. Users aren't part of the data: a server Rowsafe
// created starts with its default user without a password, which Redis's
// protected mode lets in from that server only, until users are added.

var (
	_ agent.EngineFork    = (*Engine)(nil)
	_ agent.EngineTargets = (*Engine)(nil)
)

// settingDatabases is the source's databases setting (ForkPrepareResult
// and StandbyPrepareResult Settings).
const settingDatabases = "databases"

// ForkFacts reads the source's version, size and number of logical
// databases.
func (e *Engine) ForkFacts(ctx context.Context, env agent.EngineEnv, source protocol.DatabaseSpec) (int, int64, map[string]int, error) {
	c, err := connectDB(ctx, env, source)
	if err != nil {
		return 0, 0, nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c)
	if err != nil {
		return 0, 0, nil, err
	}
	return in.VersionNum / 100, in.UsedMemoryDataset, map[string]int{settingDatabases: in.Databases}, nil
}

// ForkRestore restores the source at p.Target into the empty server on
// p.Port.
func (e *Engine) ForkRestore(ctx context.Context, env agent.EngineEnv, p protocol.ForkRestoreParams, tl agent.TaskLogger) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	if p.Placement != protocol.ForkEmptyServer {
		return nil, fmt.Errorf("a %s clone goes into an empty %s server (placement %q)", e.display(), e.display(), p.Placement)
	}
	if !idRE.MatchString(p.ForkID) {
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	}
	target := restoreTarget{Mark: p.Target.Mark}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if target.Mark != "" && !markNameRE.MatchString(target.Mark) {
		return nil, fmt.Errorf("invalid Mark name %q", target.Mark)
	}
	if target.Mark == "" && target.Time.IsZero() {
		target.Latest = true
	}
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: p.Source.Stanza})
	if err != nil {
		return nil, err
	}
	dst, created, err := e.openTarget(ctx, env, p.Port, targetClones, tl)
	if err != nil {
		return nil, err
	}
	defer dst.Close()
	release := func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		e.releaseTarget(cctx, env, p.Port, tl)
	}
	in, err := inspect(ctx, dst)
	if err != nil {
		return nil, err
	}
	switch {
	case in.Engine != "" && in.Engine != e.name:
		return nil, fmt.Errorf("the server on port %d is %s, not %s; nothing was changed", p.Port, protocol.EngineDisplayName(in.Engine), e.display())
	case in.totalKeys() > 0:
		return nil, fmt.Errorf("the %s server on port %d isn't empty (%s keys): a clone needs an empty server; nothing was changed",
			e.display(), p.Port, commas(in.totalKeys()))
	case in.isReplica():
		return nil, fmt.Errorf("the %s server on port %d is a replica of another server; nothing was changed", e.display(), p.Port)
	case p.Major > 0 && in.VersionNum/100 < p.Major:
		if created {
			release()
		}
		return nil, fmt.Errorf("the %s server on port %d runs %s, older than the source (%s): a clone needs the same version or newer",
			e.display(), p.Port, in.Version, majorMinor(p.Major*100))
	}
	if n := p.Settings[settingDatabases]; n > in.Databases {
		if created {
			release()
		}
		return nil, fmt.Errorf("the %s server on port %d has %d logical databases and the source %d: raise its databases setting", e.display(), p.Port, in.Databases, n)
	}
	root := filepath.Join(env.Config.RewindDir, e.name+"-fork")
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	s, err := newScratch(env, root, "fork-"+p.ForkID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing a clone's temporary server", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("restoring %s as of %s into a temporary server on this host (Unix socket only, no network)", p.Source.Name, target.describe())
	out, sc, err := e.restoreInto(ctx, env, r, target, &s, in.Executable, tl)
	if err != nil {
		if created {
			release()
		}
		return nil, err
	}
	defer sc.Close()
	var maskReport *protocol.ForkMaskReport
	if p.Masking != nil {
		key, err := forkMaskKey(env)
		if err != nil {
			return nil, err
		}
		var rules []protocol.MaskingRule
		for _, r := range p.Masking.Rules {
			rules = append(rules, protocol.MaskingRule{DB: r.DB, Table: r.Table, Column: r.Column, Strategy: r.Strategy})
		}
		var report protocol.MaskingReport
		km := newKeyMasker(key, rules, p.Masking.Suggest, &report)
		tl.Printf("masking the clone on the temporary server, before any of it is copied")
		st, err := maskServer(ctx, sc, km, false, tl)
		if err != nil {
			if created {
				release()
			}
			return nil, fmt.Errorf("masking the clone: %w; nothing was copied", err)
		}
		report.Skipped = append(report.Skipped, maskNotes(st, false)...)
		maskReport = &protocol.ForkMaskReport{Tables: report.Tables, Columns: report.Columns, Rows: report.Rows,
			Strategies: report.Strategies, Skipped: report.Skipped}
	}
	ks, err := keyCounts(ctx, sc)
	if err != nil {
		return nil, err
	}
	dbs := make([]int, 0, len(ks))
	for n := range ks {
		dbs = append(dbs, n)
	}
	slices.Sort(dbs)
	tl.Printf("copying %s keys into the %s server on port %d (times to live kept)", commas(sumKeys(ks)), e.display(), p.Port)
	cs, err := copyKeys(ctx, sc, dst, copyOpts{DBs: dbs})
	if err != nil {
		release()
		return nil, fmt.Errorf("copying the clone into the server on port %d: %w", p.Port, err)
	}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: p.Port, Major: in.VersionNum / 100,
		Created: created, DurationMs: time.Since(start).Milliseconds(), Masking: maskReport}
	if created {
		res.Unit = fmt.Sprintf("rowsafe-redis@%d.service", p.Port)
	}
	rt := out.RecoveredTo
	res.RecoveredTo = &rt
	if after, err := inspect(ctx, dst); err == nil {
		res.Databases, res.SizeBytes, res.DataDir = after.dbInfos(), after.UsedMemoryDataset, after.Dir
	}
	res.Warnings = append(res.Warnings, out.Warnings...)
	if cs.Expired > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s expired while they were copied, as they would have on the source.", plural(cs.Expired, "key", "keys")))
	}
	res.Warnings = append(res.Warnings, "Users aren't part of the data, so the clone has none of the source's: add the users your apps need on it.")
	if created {
		res.Warnings = append(res.Warnings, "Until it has a user with a password, the clone accepts connections from its own server only (Redis's protected mode).")
	}
	res.Summary = fmt.Sprintf("Cloned %s as it was at %s into the %s server on port %d (%s keys in %d logical databases).", p.Source.Name,
		rt.UTC().Format("15:04:05 UTC on 2006-01-02"), e.display(), p.Port, commas(cs.Keys), len(dbs))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func sumKeys(ks map[int]dbKeys) int64 {
	var n int64
	for _, k := range ks {
		n += k.Keys
	}
	return n
}

// forkMaskKey is the host's masking key (a random one outside the agent).
func forkMaskKey(env agent.EngineEnv) ([]byte, error) {
	if env.Copies != nil {
		return env.Copies.MaskKey()
	}
	pw, err := randomPassword()
	return []byte(pw), err
}
