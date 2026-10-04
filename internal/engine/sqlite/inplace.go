package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole database in place (and Undo). Nothing is stopped:
//
//  1. restore the moment into a separate file (production untouched);
//  2. keep a copy of the live file as it is now, for Undo (online backup
//     API, consistent while the app writes);
//  3. write the restored file into the live one with the online backup
//     API: one write transaction, so the app's writes wait for the few
//     seconds it takes and its open connections then see the new content.
//     In WAL mode the pages go through the WAL like any transaction, so
//     the change stream carries on across the rewind.
//
// Undo writes the kept copy back the same way, keeping the rewound
// content aside in turn. A failure before step 3 commits leaves the live
// file exactly as it was (SQLite rolls the transaction back).

const (
	keptDirName = "kept"
	mipRestore  = "restoring" // the moment is being restored: production untouched
	mipWrite    = "writing"   // the restored file is being written into production
)

func (e *Engine) kept(env agent.EngineEnv) *agent.KeptStore { return env.Kept() }

func keptDir(env agent.EngineEnv, id string) string {
	return filepath.Join(copyRoot(env), keptDirName, id)
}

// copyLive copies the live database into a new file at dst (the online
// backup API: consistent in WAL mode, a few pages at a time otherwise).
func (e *Engine) copyLive(ctx context.Context, db protocol.DatabaseSpec, dst string, tl agent.TaskLogger) error {
	b, err := openDB(ctx, db.SocketDir, openOpts{Busy: 5 * time.Second})
	if err != nil {
		return err
	}
	defer b.Close()
	defer withInterrupt(ctx, b)()
	mode, err := journalMode(b)
	if err != nil {
		return err
	}
	if mode == "wal" {
		if err := beginRead(b); err != nil {
			return err
		}
		defer rollback(b)
		return backupSteps(ctx, b, dst, walStepPages, 0, nil)
	}
	return backupRollback(ctx, b, dst, fileSize(db.SocketDir), e.busyFor(db.ID), tl)
}

// writeInto writes the database file src into the live database (one
// write transaction, the online backup API).
func (e *Engine) writeInto(ctx context.Context, db protocol.DatabaseSpec, src string) error {
	prod, err := openDB(ctx, db.SocketDir, openOpts{Busy: 30 * time.Second})
	if err != nil {
		return err
	}
	defer prod.Close()
	defer withInterrupt(ctx, prod)()
	if rp, err := realPath(src); err == nil {
		src = rp
	}
	if err := prod.Restore("main", src); err != nil {
		e.busyFor(db.ID).note(err)
		if isBusy(err) {
			return errors.New("your app kept the database busy for over 30 seconds, so nothing was written; try again in a quieter moment")
		}
		return err
	}
	if res, err := queryText(prod, `PRAGMA quick_check(1)`); err == nil && res != "ok" {
		return fmt.Errorf("the database was written, but SQLite's quick_check reports: %s", res)
	}
	return nil
}

// preflightInPlace checks the live file can take a rewritten content.
func (e *Engine) preflightInPlace(ctx context.Context, db protocol.DatabaseSpec, restored string) error {
	if fs := networkFS(filepath.Dir(db.SocketDir)); fs != "" {
		return fmt.Errorf("the database is on a network filesystem (%s): Rowsafe doesn't write to it", fs)
	}
	ph, _, err := readDBHeader(db.SocketDir)
	if err != nil {
		return err
	}
	if restored != "" {
		rh, _, err := readDBHeader(restored)
		if err != nil {
			return err
		}
		if ph.WAL && rh.PageSize != ph.PageSize {
			return fmt.Errorf("the database now uses %d-byte pages and the restored one %d-byte pages; in WAL mode SQLite can't write one into the other",
				ph.PageSize, rh.PageSize)
		}
	}
	return nil
}

func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	target, err := targetOf(p.Target)
	if err != nil {
		return nil, err
	}
	kept := e.kept(env)
	for _, r := range kept.ForDatabase(db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	if err := e.preflightInPlace(ctx, db, ""); err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	size := fileSize(db.SocketDir) + fileSize(db.SocketDir+"-wal")
	dir := keptDir(env, p.RewindID)
	// The restored file and the copy kept for Undo, here; in WAL mode the
	// rewrite also passes through the -wal file next to the database.
	if err := ensureSpace(dir, 2*size, "rewinding in place (the restored file and a copy of the current one for Undo)"); err != nil {
		return nil, err
	}
	if err := ensureSpace(filepath.Dir(db.SocketDir), size, "rewinding in place (SQLite writes the new content through its -wal or -journal file)"); err != nil {
		return nil, err
	}
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: db.ID, Status: protocol.RewindInProgress, CreatedAt: time.Now().UTC(),
		Target: p.Target, KeepDays: p.KeepDays, Phase: mipRestore, Database: db, Path: dir}
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	abandon := func(err error) (*protocol.RewindInPlaceResult, error) {
		_ = os.RemoveAll(dir)
		_ = kept.Remove(rec.ID)
		return nil, err
	}
	restored := filepath.Join(dir, "restored.db")
	before := filepath.Join(dir, "before.db")
	e.flushRecent(ctx, db, target)
	tl.Printf("restoring %s as of %s into a separate file first (your app keeps running meanwhile)", db.Name, target.describe())
	out, err := restoreTo(ctx, r, target, restored, tl)
	if err != nil {
		return abandon(err)
	}
	check, err := inspectCopy(ctx, restored, true)
	if err != nil {
		return abandon(err)
	}
	if check.Integrity != "ok" {
		return abandon(fmt.Errorf("the restored file doesn't pass integrity_check (%s), so nothing was changed", check.Integrity))
	}
	if err := e.preflightInPlace(ctx, db, restored); err != nil {
		return abandon(err)
	}
	tl.Printf("keeping a copy of the database as it is now, for Undo")
	if err := e.copyLive(ctx, db, before, tl); err != nil {
		return abandon(fmt.Errorf("copying the current database for Undo: %w", err))
	}
	rec.Phase = mipWrite
	recovered := out.RecoveredTo
	rec.RecoveredTo = &recovered
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	tl.Printf("writing the restored content into the live database (your app's writes wait until it's done)")
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: &recovered}
	if err := e.writeInto(context.WithoutCancel(ctx), db, restored); err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.RolledBack = true
		return res, e.failedWrite(kept, rec, before, err)
	}
	_ = os.Remove(restored)
	removeDB(restored)
	until := agent.KeepUntil(p.KeepDays, time.Now())
	rec.Status, rec.Phase, rec.Expires, rec.SizeBytes, rec.Path = protocol.RewindKeptBefore, "", until, fileSize(before), before
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.OldDataDir, res.KeptUntil = before, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Rewound %s to %s while your app kept running. The database as it was before is kept until %s so you can undo.",
		db.Name, recovered.UTC().Format("15:04:05 UTC on 2006-01-02"), until.UTC().Format("2006-01-02 15:04 UTC"))
	if out.Note != "" {
		res.Warnings = append(res.Warnings, out.Note)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// failedWrite handles a rewrite that didn't commit: SQLite rolled it back,
// production is as it was.
func (e *Engine) failedWrite(kept *agent.KeptStore, rec agent.KeptRecord, before string, err error) error {
	_ = os.RemoveAll(filepath.Dir(before))
	_ = kept.Remove(rec.ID)
	return fmt.Errorf("the rewind failed and the database is exactly as it was (nothing changed): %w", err)
}

func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := e.kept(env)
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return nil, errors.New("there is nothing to undo: the database from before this rewind is no longer kept")
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, errors.New("this rewind was undone already")
	}
	before := rec.Path
	if _, err := os.Stat(before); err != nil {
		return nil, fmt.Errorf("the copy kept from before the rewind (%s) is gone", before)
	}
	if err := e.preflightInPlace(ctx, db, before); err != nil {
		return nil, err
	}
	dir := filepath.Dir(before)
	after := filepath.Join(dir, "after.db")
	if err := ensureSpace(dir, fileSize(db.SocketDir), "undoing the rewind (a copy of the rewound database)"); err != nil {
		return nil, err
	}
	saved := rec
	rec.Status, rec.Phase = protocol.RewindInProgress, mipWrite
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	tl.Printf("keeping the rewound database (with anything written since) aside first")
	if err := e.copyLive(ctx, db, after, tl); err != nil {
		removeDB(after)
		_ = kept.Put(saved)
		return nil, fmt.Errorf("copying the rewound database aside: %w", err)
	}
	tl.Printf("writing the database from before the rewind back (your app's writes wait until it's done)")
	res := &protocol.RewindUndoResult{RewindID: rec.ID}
	if err := e.writeInto(context.WithoutCancel(ctx), db, before); err != nil {
		removeDB(after)
		_ = kept.Put(saved)
		res.RolledBack = true
		res.DurationMs = time.Since(start).Milliseconds()
		return res, fmt.Errorf("the undo failed and the database is exactly as it was (nothing changed): %w", err)
	}
	removeDB(before)
	until := agent.KeepUntil(rec.KeepDays, time.Now())
	rec.Status, rec.Phase, rec.Undo, rec.Expires, rec.SizeBytes, rec.Path = protocol.RewindKeptAfterUndo, "", true, until, fileSize(after), after
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.RewoundDataDir, res.KeptUntil = after, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s is back as it was before the rewind. The rewound database (with anything written since) is kept until %s.",
		db.Name, until.UTC().Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := e.kept(env)
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept for this rewind any more."}, nil
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	dir := keptDir(env, rec.ID)
	freed := dirSize(dir)
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := kept.Remove(rec.ID); err != nil {
		return nil, err
	}
	res := &protocol.RewindCleanupResult{RewindID: rec.ID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the copy kept by the rewind (%s freed).", humanBytes(freed))}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// recoverInPlace settles what an agent stopped in the middle of. A rewrite
// is one SQLite transaction: either it committed or the live file is as it
// was; the copy from before is kept either way, so Undo stays possible.
func (e *Engine) recoverInPlace(ctx context.Context, env agent.EngineEnv) {
	kept := e.kept(env)
	for _, rec := range kept.All() {
		if rec.Status != protocol.RewindInProgress {
			continue
		}
		dir := keptDir(env, rec.ID)
		switch {
		case rec.Phase == mipWrite && rec.Undo:
			// An undo of an undo can't happen; treat like the rewind.
			fallthrough
		case rec.Phase == mipWrite:
			before := filepath.Join(dir, "before.db")
			if _, err := os.Stat(before); err == nil {
				removeDB(filepath.Join(dir, "restored.db"))
				removeDB(filepath.Join(dir, "after.db"))
				rec.Status, rec.Phase, rec.Path = protocol.RewindKeptBefore, "", before
				rec.Expires = agent.KeepUntil(rec.KeepDays, time.Now())
				rec.SizeBytes = fileSize(before)
				_ = kept.Put(rec)
				env.Log.Warn("a SQLite rewind in place was interrupted; the database from before is kept so it can be undone", "rewind_id", rec.ID)
				continue
			}
			fallthrough
		default:
			_ = os.RemoveAll(dir)
			_ = kept.Remove(rec.ID)
			env.Log.Warn("a SQLite rewind in place was interrupted before it changed anything; removed its files", "rewind_id", rec.ID)
		}
	}
}

// expireKept deletes what rewinds kept past its expiry.
func (e *Engine) expireKept(env agent.EngineEnv, now time.Time) {
	kept := e.kept(env)
	for _, rec := range kept.Expired(now) {
		if err := os.RemoveAll(keptDir(env, rec.ID)); err == nil {
			_ = kept.Remove(rec.ID)
		}
	}
}
