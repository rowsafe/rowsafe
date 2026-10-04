package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole server in place (and Undo), through the server itself:
// no restart, no file access, and never a moment without data.
//
//  1. restore the moment into a private temporary server, exactly like a
//     Rewind copy (production keeps running);
//  2. take a snapshot of production as it is now into the bucket
//     (kept/<rewind id>/): the data from before, for Undo;
//  3. for each logical database: load the restored keys into an empty
//     logical database of production (the spare), with a marker key, then
//     SWAPDB swaps it with the live one in an instant and the old keys
//     (now in the spare) are freed with FLUSHDB ASYNC.
//
// Undo does the same with the kept snapshot (after keeping the rewound data
// as kept/<rewind id>/after/). An agent stopped in the middle finds, by the
// marker, whether the database being swapped was swapped, and empties the
// spare; a rewind that swapped some databases stays undoable.

const (
	mipRestoring = "restoring" // into the temporary server: production untouched
	mipSnapshot  = "snapshot"  // production's data from before goes to the bucket
	mipLoading   = "loading"   // restored keys go into the spare, then SWAPDB
)

func rewindTag(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:4])
}

func swapMarker(tag string) string { return "__rowsafe_rewind_" + tag }

// inPlacePlan is checked before anything changes.
type inPlacePlan struct {
	in    serverInfo
	spare int
}

// preflightInPlace checks production can be rewound in place.
func (e *Engine) preflightInPlace(ctx context.Context, prod *conn, restored map[int]dbKeys, restoredBytes int64) (inPlacePlan, error) {
	var p inPlacePlan
	in, err := inspect(ctx, prod)
	if err != nil {
		return p, err
	}
	p.in = in
	if why := e.blocker(ctx, prod, in); why != "" {
		return p, errors.New(why)
	}
	if in.isReplica() {
		return p, errors.New("this server is a replica, which refuses writes: rewind its primary instead")
	}
	used := map[int]bool{}
	for n := range in.Keyspace {
		used[n] = true
	}
	for n := range restored {
		used[n] = true
	}
	p.spare = -1
	for n := in.Databases - 1; n >= 0; n-- {
		if !used[n] {
			p.spare = n
			break
		}
	}
	if p.spare < 0 {
		return p, fmt.Errorf("every one of the server's %d logical databases holds keys: rewinding in place needs an empty one to load into before "+
			"the swap. Restore a copy and bring keys back instead", in.Databases)
	}
	if _, err := prod.do(ctx, "SWAPDB", p.spare, p.spare); err != nil {
		if isRespError(err, "NOPERM") || isUnknownCommand(err) {
			return p, errors.New("Rowsafe's user can't swap logical databases (SWAPDB), which a rewind in place needs: run the Rowsafe installer " +
				"on the server again (it updates the user), or restore a copy and bring keys back instead")
		}
		return p, fmt.Errorf("SWAPDB: %w", err)
	}
	// Memory: the largest logical database is held twice for a moment.
	var largest int64
	total := int64(0)
	for _, k := range restored {
		total += k.Keys
	}
	for _, k := range restored {
		if total > 0 { // in floating point: bytes times keys overflows int64 on big servers
			largest = max(largest, int64(float64(restoredBytes)*float64(k.Keys)/float64(total)))
		}
	}
	limit := in.MaxMemory
	if limit == 0 && in.TotalSystemMemory > 0 {
		limit = in.TotalSystemMemory * 8 / 10
	}
	if limit > 0 && in.UsedMemory+largest*12/10 > limit*9/10 {
		return p, fmt.Errorf("%s uses %s of its %s memory limit; rewinding in place loads one logical database (up to %s) next to the live data "+
			"before the swap, which would push it over (and could make it evict keys). Restore a copy and bring keys back instead",
			e.display(), humanBytes(in.UsedMemory), humanBytes(limit), humanBytes(largest))
	}
	return p, nil
}

func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	target, err := targetFrom(p.Target)
	if err != nil {
		return nil, err
	}
	kept := env.Kept()
	for _, r := range kept.ForDatabase(db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	if _, err := e.preflightInPlace(ctx, prod, nil, 0); err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	e.flushForMoment(ctx, env, db, target)
	tag := rewindTag(p.RewindID)
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: db.ID, Status: protocol.RewindInProgress, CreatedAt: time.Now().UTC(),
		Target: p.Target, KeepDays: p.KeepDays, Phase: mipRestoring, Database: db, Extra: map[string]string{"tag": tag}}
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	abandon := func(err error) (*protocol.RewindInPlaceResult, error) {
		_ = r.deletePrefix(context.WithoutCancel(ctx), keptPrefix+p.RewindID+"/")
		_ = kept.Remove(rec.ID)
		return nil, err
	}

	// 1. The moment, privately.
	s, err := newScratch(env, copyRoot(env, e.name), "inplace-"+p.RewindID)
	if err != nil {
		return abandon(err)
	}
	defer func() { _, _ = s.remove() }()
	tl.Printf("restoring %s as of %s into an isolated server first (production keeps running meanwhile)", db.Name, target.describe())
	in0, _ := inspect(ctx, prod)
	out, src, err := e.restoreInto(ctx, env, r, target, &s, in0.Executable, tl)
	if err != nil {
		return abandon(err)
	}
	defer src.Close()
	restored, err := keyCounts(ctx, src)
	if err != nil {
		return abandon(err)
	}
	m, _ := src.info(ctx, "memory")
	pl, err := e.preflightInPlace(ctx, prod, restored, infoFrom(m).UsedMemoryDataset)
	if err != nil {
		return abandon(err)
	}
	recovered := out.RecoveredTo

	// 2. The data from before, for Undo.
	rec.Phase, rec.RecoveredTo = mipSnapshot, &recovered
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	tl.Printf("keeping a snapshot of %s as it is now in your bucket, so the rewind can be undone", db.Name)
	before, err := e.keepSnapshot(ctx, env, db, r, pl.in, keptPrefix+p.RewindID+"/", tl)
	if err != nil {
		return abandon(fmt.Errorf("keeping the data from before: %w", err))
	}

	// 3. Swap, one logical database at a time.
	rec.Phase, rec.Extra["spare"] = mipLoading, strconv.Itoa(pl.spare)
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	swapped, err := e.swapIn(ctx, prod, src, pl, restored, tag, &rec, kept, tl)
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: &recovered}
	until := agent.KeepUntil(p.KeepDays, time.Now())
	rec.Status, rec.Phase, rec.Expires, rec.SizeBytes = protocol.RewindKeptBefore, "", until, before.StoredBytes
	rec.Path = "a snapshot in your bucket (" + keptPrefix + p.RewindID + "/)"
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		if len(swapped) == 0 {
			return abandon(fmt.Errorf("the rewind failed before any logical database was swapped (nothing changed): %w", err))
		}
		_ = kept.Put(rec)
		res.OldDataDir, res.KeptUntil = rec.Path, &until
		return res, fmt.Errorf("the rewind stopped after swapping %s (%v); the data from before is kept: Undo puts everything back", dbList(swapped), err)
	}
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.OldDataDir, res.KeptUntil = rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Rewound %s to %s, without a restart. The data as it was before is kept in your bucket until %s so you can undo.",
		db.Name, recovered.UTC().Format("15:04:05 UTC on 2006-01-02"), until.UTC().Format("2006-01-02 15:04 UTC"))
	res.Warnings = out.Warnings
	tl.Printf("%s", res.Summary)
	return res, nil
}

// keepSnapshot keeps production's data as it is now under prefix: over
// replication, or with BGSAVE when the server refuses that.
func (e *Engine) keepSnapshot(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r *repo, in serverInfo, prefix string, tl agent.TaskLogger) (backupDoc, error) {
	doc, err := e.snapshotOverReplication(ctx, env, db, r, in, sourceRewind, prefix, tl)
	if errors.Is(err, errReplicationRefused) {
		doc, err = e.snapshotFromFile(ctx, env, db, r, in, prefix, tl)
	}
	return doc, err
}

func dbList(dbs []int) string {
	var s []string
	for _, n := range dbs {
		s = append(s, "db"+strconv.Itoa(n))
	}
	return strings.Join(s, ", ")
}

// swapIn replaces production's logical databases with src's, one at a
// time through the spare. It returns the databases swapped.
func (e *Engine) swapIn(ctx context.Context, prod, src *conn, pl inPlacePlan, restored map[int]dbKeys, tag string,
	rec *agent.KeptRecord, kept *agent.KeptStore, tl agent.TaskLogger) ([]int, error) {
	var dbs []int
	for n := range restored {
		dbs = append(dbs, n)
	}
	for n := range pl.in.Keyspace {
		dbs = append(dbs, n)
	}
	slices.Sort(dbs)
	dbs = slices.Compact(dbs)
	var swapped []int
	marker := swapMarker(tag)
	for _, n := range dbs {
		if n == pl.spare {
			continue
		}
		rec.Extra["current"] = strconv.Itoa(n)
		if err := kept.Put(*rec); err != nil {
			return swapped, err
		}
		if err := selectDB(ctx, prod, pl.spare); err != nil {
			return swapped, err
		}
		if size, err := prod.integer(ctx, "DBSIZE"); err != nil || size != 0 {
			return swapped, fmt.Errorf("the spare logical database db%d isn't empty any more (an application wrote to it)", pl.spare)
		}
		// The marker goes in with the restored keys (Rowsafe's user writes
		// only through RESTORE), so after a crash it says where they are.
		if err := selectDB(ctx, src, n); err != nil {
			return swapped, err
		}
		if _, err := src.do(ctx, "SET", marker, "1"); err != nil {
			return swapped, err
		}
		copied, err := copyDatabase(ctx, src, prod, n)
		if err != nil {
			_, _ = prod.do(context.WithoutCancel(ctx), "FLUSHDB", "ASYNC")
			return swapped, fmt.Errorf("loading db%d: %w", n, err)
		}
		if _, err := prod.do(ctx, "SWAPDB", n, pl.spare); err != nil {
			_, _ = prod.do(context.WithoutCancel(ctx), "FLUSHDB", "ASYNC")
			return swapped, fmt.Errorf("swapping db%d: %w", n, err)
		}
		swapped = append(swapped, n)
		rec.Extra["swapped"] = strings.Trim(rec.Extra["swapped"]+","+strconv.Itoa(n), ",")
		delete(rec.Extra, "current")
		_ = kept.Put(*rec)
		// The spare now holds the keys from before (kept in the bucket).
		if _, err := prod.do(ctx, "FLUSHDB", "ASYNC"); err != nil {
			return swapped, err
		}
		if err := selectDB(ctx, prod, n); err != nil {
			return swapped, err
		}
		_, _ = prod.do(ctx, "DEL", marker)
		tl.Printf("db%d: %s keys swapped in", n, commas(max(copied-1, 0)))
	}
	return swapped, nil
}

// copyDatabase copies every key of logical database n of src into the
// selected logical database of dst (DUMP, RESTORE with the expiry).
func copyDatabase(ctx context.Context, src, dst *conn, n int) (int64, error) {
	if err := selectDB(ctx, src, n); err != nil {
		return 0, err
	}
	var copied int64
	_, err := scanKeys(ctx, src, "*", 1<<62, func(keys []string) error {
		var out protocol.RewindTableRows
		if err := restoreKeys(ctx, src, dst, keys, false, &out); err != nil {
			return err
		}
		if out.Conflicts > 0 {
			return fmt.Errorf("%d keys were written to the spare logical database meanwhile", out.Conflicts)
		}
		copied += out.Inserted
		return nil
	})
	return copied, err
}

// rewindUndo puts the data from before the rewind back (keeping the
// rewound data for a while).
func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return nil, errors.New("there is nothing to undo: the data from before this rewind is no longer kept")
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, errors.New("this rewind was undone already")
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	if _, err := e.preflightInPlace(ctx, prod, nil, 0); err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	saved := rec
	saved.Extra = maps.Clone(rec.Extra)
	rec.Extra = maps.Clone(rec.Extra)
	if rec.Extra == nil {
		rec.Extra = map[string]string{}
	}
	rec.Status, rec.Phase, rec.Extra["undoing"] = protocol.RewindInProgress, mipRestoring, "1"
	delete(rec.Extra, "swapped")
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	giveUp := func(err error) (*protocol.RewindUndoResult, error) {
		_ = r.deletePrefix(context.WithoutCancel(ctx), keptPrefix+p.RewindID+"/after/")
		_ = kept.Put(saved)
		return nil, err
	}
	s, err := newScratch(env, copyRoot(env, e.name), "inplace-"+p.RewindID+"-undo")
	if err != nil {
		return giveUp(err)
	}
	defer func() { _, _ = s.remove() }()
	tl.Printf("loading the data from before the rewind into an isolated server first")
	in0, _ := inspect(ctx, prod)
	_, src, err := e.restoreInto(ctx, env, r, restoreTarget{Kept: p.RewindID}, &s, in0.Executable, tl)
	if err != nil {
		return giveUp(err)
	}
	defer src.Close()
	restored, err := keyCounts(ctx, src)
	if err != nil {
		return giveUp(err)
	}
	m, _ := src.info(ctx, "memory")
	pl, err := e.preflightInPlace(ctx, prod, restored, infoFrom(m).UsedMemoryDataset)
	if err != nil {
		return giveUp(err)
	}
	rec.Phase = mipSnapshot
	_ = kept.Put(rec)
	tl.Printf("keeping the rewound data (with anything written since) in your bucket first")
	after, err := e.keepSnapshot(ctx, env, db, r, pl.in, keptPrefix+p.RewindID+"/after/", tl)
	if err != nil {
		return giveUp(fmt.Errorf("keeping the rewound data: %w", err))
	}
	rec.Phase, rec.Extra["spare"] = mipLoading, strconv.Itoa(pl.spare)
	_ = kept.Put(rec)
	swapped, err := e.swapIn(ctx, prod, src, pl, restored, rewindTag(p.RewindID+"-undo"), &rec, kept, tl)
	res := &protocol.RewindUndoResult{RewindID: rec.ID}
	until := agent.KeepUntil(rec.KeepDays, time.Now())
	if err != nil && len(swapped) == 0 {
		res.DurationMs = time.Since(start).Milliseconds()
		return giveUp(fmt.Errorf("the undo failed before any logical database was swapped (nothing changed): %w", err))
	}
	delete(rec.Extra, "undoing")
	delete(rec.Extra, "current")
	rec.Status, rec.Phase, rec.Undo, rec.Expires = protocol.RewindKeptAfterUndo, "", true, until
	rec.SizeBytes = after.StoredBytes
	rec.Path = "a snapshot in your bucket (" + keptPrefix + p.RewindID + "/after/)"
	_ = kept.Put(rec)
	res.RewoundDataDir, res.KeptUntil = rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		return res, fmt.Errorf("the undo stopped after swapping %s: %w", dbList(swapped), err)
	}
	res.Summary = fmt.Sprintf("%s is back as it was before the rewind, without a restart. The rewound data (with anything written since) is kept in your bucket until %s.",
		db.Name, until.UTC().Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rewindCleanup deletes what a rewind kept.
func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept for this rewind any more."}, nil
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	var freed int64
	if objs, err := r.st.List(ctx, keptPrefix+p.RewindID+"/"); err == nil {
		for _, o := range objs {
			freed += o.Size
		}
	}
	if err := r.deletePrefix(ctx, keptPrefix+p.RewindID+"/after/"); err != nil {
		return nil, err
	}
	if err := r.deletePrefix(ctx, keptPrefix+p.RewindID+"/"); err != nil {
		return nil, err
	}
	if err := kept.Remove(rec.ID); err != nil {
		return nil, err
	}
	res := &protocol.RewindCleanupResult{RewindID: rec.ID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the snapshot kept by the rewind (%s freed in your bucket).", humanBytes(freed))}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// recoverInPlace finishes what an agent stopped in the middle of.
func (e *Engine) recoverInPlace(ctx context.Context, env agent.EngineEnv) {
	kept := env.Kept()
	for _, rec := range kept.All() {
		if rec.Status != protocol.RewindInProgress {
			continue
		}
		undoing := rec.Extra["undoing"] == "1"
		_ = os.RemoveAll(filepath.Join(copyRoot(env, e.name), "inplace-"+rec.ID))
		_ = os.RemoveAll(filepath.Join(copyRoot(env, e.name), "inplace-"+rec.ID+"-undo"))
		swapped := rec.Extra["swapped"]
		if rec.Phase == mipLoading {
			prod, err := connectDB(ctx, env, rec.Database)
			if err != nil {
				env.Log.Error("can't reach the server to finish an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
				continue
			}
			tag := rewindTag(rec.ID)
			if undoing {
				tag = rewindTag(rec.ID + "-undo")
			}
			spare, _ := strconv.Atoi(rec.Extra["spare"])
			if cur, err := strconv.Atoi(rec.Extra["current"]); err == nil && cur != spare {
				// Did the swap happen? The marker key says where the loaded keys are.
				if selectDB(ctx, prod, cur) == nil {
					if n, _ := prod.integer(ctx, "EXISTS", swapMarker(tag)); n == 1 {
						_, _ = prod.do(ctx, "DEL", swapMarker(tag))
						swapped = strings.Trim(swapped+","+strconv.Itoa(cur), ",")
					}
				}
			}
			if selectDB(ctx, prod, spare) == nil {
				_, _ = prod.do(ctx, "FLUSHDB", "ASYNC")
			}
			prod.Close()
		}
		delete(rec.Extra, "current")
		delete(rec.Extra, "undoing")
		rec.Phase = ""
		var err error
		switch {
		case swapped == "" && !undoing:
			if r, rerr := openRepo(env, rec.Database); rerr == nil {
				_ = r.deletePrefix(ctx, keptPrefix+rec.ID+"/")
			}
			err = kept.Remove(rec.ID)
		case swapped == "" && undoing:
			rec.Status = protocol.RewindKeptBefore
			err = kept.Put(rec)
		case undoing:
			rec.Status, rec.Undo = protocol.RewindKeptAfterUndo, true
			rec.Expires = agent.KeepUntil(rec.KeepDays, time.Now())
			err = kept.Put(rec)
		default:
			rec.Status = protocol.RewindKeptBefore
			rec.Expires = agent.KeepUntil(rec.KeepDays, time.Now())
			err = kept.Put(rec)
		}
		if err != nil {
			env.Log.Error("finishing an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
		} else {
			env.Log.Warn("an interrupted rewind in place was settled", "rewind_id", rec.ID, "swapped", swapped)
		}
	}
}

// expireKept deletes what rewinds kept past its expiry.
func (e *Engine) expireKept(ctx context.Context, env agent.EngineEnv, now time.Time) {
	kept := env.Kept()
	for _, rec := range kept.Expired(now) {
		r, err := openRepo(env, rec.Database)
		if err != nil {
			continue
		}
		if r.deletePrefix(ctx, keptPrefix+rec.ID+"/after/") == nil && r.deletePrefix(ctx, keptPrefix+rec.ID+"/") == nil {
			_ = kept.Remove(rec.ID)
			env.Log.Info("deleted the snapshot kept by a rewind in place (expired)", "rewind_id", rec.ID)
		}
	}
}
