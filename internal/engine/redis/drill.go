package redis

import (
	"context"
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

// Proof for Redis and Valkey: restore the newest backup into an isolated
// temporary server, check it loads and that every logical database has the
// keys the backup recorded; then replay the changes since and compare with
// production now. The server is stopped and deleted afterwards.

func drillRoot(env agent.EngineEnv, engine string) string {
	return filepath.Join(env.Config.DrillDir, engine)
}

func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	var prod serverInfo
	if c, err := connectDB(ctx, env, db); err == nil {
		prod, _ = inspect(ctx, c)
		c.Close()
	}
	// Changes up to now reach the bucket first, so the test covers them.
	if f := e.existingFollower(strings.TrimSuffix(db.ID, "~copy2")); f != nil && !strings.HasSuffix(db.ID, "~copy2") && prod.ReplOffset > 0 {
		st := f.snapshot()
		if st.Mode == modeReplica && st.StreamID != "" {
			if err := f.flush(ctx, st.StreamID, prod.ReplOffset, 2*time.Minute); err != nil {
				tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", err)
			}
		}
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	// The engine's folder under the drills goes too once empty (nothing
	// else makes temporary servers there while copyMu is held).
	defer func() { _ = os.Remove(drillRoot(env, e.name)) }()
	fail := func(res *protocol.DrillResult, err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	res := &protocol.DrillResult{}

	// 1. The snapshot alone, checked against what it recorded.
	s, err := newScratch(env, drillRoot(env, e.name), taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the restore test failed", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("restoring the newest backup into an isolated %s server (Unix socket only, no network)", e.display())
	out, c, err := e.restoreInto(ctx, env, r, restoreTarget{Latest: true, SnapshotOnly: true}, &s, prod.Executable, tl)
	res.BackupLabel = out.Base.Label
	res.Warnings = append(res.Warnings, out.Warnings...)
	if err != nil {
		return fail(res, err)
	}
	got, err := keyCounts(ctx, c)
	c.Close()
	if err != nil {
		return fail(res, fmt.Errorf("reading the restored server: %w", err))
	}
	checkCounts(out.Base, got, res, tl)
	if _, err := s.remove(); err != nil {
		return fail(res, err)
	}

	// 2. The snapshot and every change since, compared with production now.
	t := out.Base.TakenAt
	res.RecoveredTo = &t
	if out.Base.Exact && len(res.Failures) == 0 {
		s2, err := newScratch(env, drillRoot(env, e.name), taskID+"-latest")
		if err != nil {
			return fail(res, err)
		}
		defer func() { _, _ = s2.remove() }()
		out2, c2, err := e.restoreInto(ctx, env, r, restoreTarget{Latest: true}, &s2, prod.Executable, tl)
		switch {
		case err != nil:
			return fail(res, fmt.Errorf("replaying the changes after the backup: %w", err))
		default:
			rt := out2.RecoveredTo
			res.RecoveredTo = &rt
			if out2.GapAfter != nil {
				res.Warnings = append(res.Warnings, fmt.Sprintf("changes after %s are missing from your bucket (Rowsafe's link was away longer than the server "+
					"keeps changes for it): the next backup starts a new unbroken chain", out2.GapAfter.Format(time.RFC3339)))
			}
			if latest, err := keyCounts(ctx, c2); err == nil {
				if len(prod.Keyspace) > 0 {
					compareWithProduction(latest, prod.Keyspace, res)
				}
				replayedCounts(latest, prod.Keyspace, res)
			}
			c2.Close()
			tl.Printf("replayed %s changes made after the backup", commas(out2.Replayed))
		}
	}
	res.RestoredBytes = out.Base.RDBBytes
	res.DurationSeconds = time.Since(started).Seconds()
	res.Passed = len(res.Failures) == 0
	if res.Passed {
		tl.Printf("Proof passed: backup %s restored and checked (%d logical databases) in %s", out.Base.Label, len(res.Databases),
			time.Since(started).Round(time.Second))
		return res, nil
	}
	return res, fmt.Errorf("Proof failed: %s", res.Failures[0])
}

// checkCounts compares a restored snapshot's keys with what the backup
// recorded: every key without an expiry must be there; keys with one may
// have expired since.
func checkCounts(b backupDoc, got map[int]dbKeys, res *protocol.DrillResult, tl agent.TaskLogger) {
	var idx []int
	for k := range b.Keyspace {
		if n, err := strconv.Atoi(k); err == nil {
			idx = append(idx, n)
		}
	}
	for n := range got {
		if _, ok := b.Keyspace[strconv.Itoa(n)]; !ok {
			idx = append(idx, n)
		}
	}
	slices.Sort(idx)
	idx = slices.Compact(idx)
	for _, n := range idx {
		want, rec := b.Keyspace[strconv.Itoa(n)]
		have := got[n]
		d := protocol.DrillDatabase{Name: "db" + strconv.Itoa(n), SourceTables: clampInt(want.Keys), RestoredTables: clampInt(have.Keys),
			Present: have.Keys > 0 || want.Keys == 0}
		res.Databases = append(res.Databases, d)
		if !rec {
			continue
		}
		// The counts were read a moment after the snapshot: allow for the
		// writes of that moment (and, for a snapshot from the server's file,
		// for the time between its save and the reading).
		slack := max(int64(10), want.Keys/1000)
		if b.Source == sourceFile {
			slack = max(int64(100), want.Keys/20)
		}
		low := want.Keys - want.Expires - slack
		switch {
		case have.Keys < low:
			res.Failures = append(res.Failures, fmt.Sprintf("db%d: %s keys restored, the backup recorded %s (%s of them without an expiry)",
				n, commas(have.Keys), commas(want.Keys), commas(want.Keys-want.Expires)))
		case have.Keys > want.Keys+slack:
			res.Warnings = append(res.Warnings, fmt.Sprintf("db%d: %s keys restored, more than the %s the backup recorded", n, commas(have.Keys), commas(want.Keys)))
		default:
			tl.Printf("db%d: %s keys restored (the backup recorded %s)", n, commas(have.Keys), commas(want.Keys))
		}
	}
}

// replayedCounts makes the result's per-database counts those of the
// fully restored server (the snapshot and every change since, as of
// RecoveredTo), next to production's when Proof started: what was restored
// is the data as it is now, not as of the backup.
func replayedCounts(latest, prod map[int]dbKeys, res *protocol.DrillResult) {
	seen := map[string]bool{}
	for i := range res.Databases {
		d := &res.Databases[i]
		seen[d.Name] = true
		n, err := strconv.Atoi(strings.TrimPrefix(d.Name, "db"))
		if err != nil {
			continue
		}
		d.RestoredTables = clampInt(latest[n].Keys)
		if p, ok := prod[n]; ok {
			d.SourceTables = clampInt(p.Keys)
		}
		d.Present = latest[n].Keys > 0 || d.SourceTables == 0
	}
	var idx []int
	for n := range latest {
		if !seen["db"+strconv.Itoa(n)] {
			idx = append(idx, n)
		}
	}
	slices.Sort(idx)
	for _, n := range idx {
		res.Databases = append(res.Databases, protocol.DrillDatabase{Name: "db" + strconv.Itoa(n), SourceTables: clampInt(prod[n].Keys),
			RestoredTables: clampInt(latest[n].Keys), Present: latest[n].Keys > 0})
	}
}

// compareWithProduction notes large differences between the fully restored
// server and production now (which kept changing meanwhile).
func compareWithProduction(restored, prod map[int]dbKeys, res *protocol.DrillResult) {
	for n, p := range prod {
		r := restored[n]
		diff := p.Keys - r.Keys
		if diff < 0 {
			diff = -diff
		}
		if diff > 1000 && float64(diff) > 0.05*float64(max(p.Keys, 1)) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("db%d: %s keys restored up to the newest change, production has %s now", n, commas(r.Keys), commas(p.Keys)))
		}
	}
}

func clampInt(n int64) int { return int(min(n, 1<<31-1)) }
