package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restore a copy: the database as it was at a point in time (or a Mark),
// restored next to production with the restore test's machinery (see
// drill.go): its own directory under ROWSAFE_REWIND_DIR, tablespaces
// remapped inside it, a private Unix socket and no TCP listener, no WAL
// archiving (archive_mode=off and no archive_command: it can never write
// into the repository; restore_command only reads), no background workers,
// low CPU and IO priority. Unlike a drill it keeps running until it expires
// or is deleted, so people can compare it with production and bring rows
// back.

// copyMarker is written into every copy directory before anything else; a
// restarted agent only ever removes directories that carry it.
const copyMarker = ".rowsafe-rewind-copy"

// rewindRestoreArgs turns a target into pgbackrest restore's --type,
// --target and --set, refusing anything malformed.
func rewindRestoreArgs(t protocol.RewindTarget) (typ, target, set string, err error) {
	switch {
	case t.XID != 0 && (t.Mark != "" || t.Time == nil):
		return "", "", "", errors.New("a transaction to stop before comes with its commit time, and without a Mark")
	case t.XID != 0:
		if t.Time.IsZero() || t.Time.After(time.Now().Add(time.Minute)) {
			return "", "", "", fmt.Errorf("the time %s is in the future", t.Time.UTC().Format(time.RFC3339))
		}
		typ, target = "xid", strconv.FormatUint(uint64(t.XID), 10)
	case t.Time != nil && t.Mark != "":
		return "", "", "", errors.New("give a time or a Mark, not both")
	case t.Time != nil:
		if t.Time.IsZero() || t.Time.After(time.Now().Add(time.Minute)) {
			return "", "", "", fmt.Errorf("the time %s is in the future", t.Time.UTC().Format(time.RFC3339))
		}
		typ, target = "time", t.Time.UTC().Format("2006-01-02 15:04:05.999999")+"+00"
	case t.Mark != "":
		if !restorePointNameRE.MatchString(t.Mark) {
			return "", "", "", fmt.Errorf("invalid Mark name %q", t.Mark)
		}
		if t.BackupSet == "" {
			return "", "", "", fmt.Errorf("no backup to start from was given for the Mark %q", t.Mark)
		}
		typ, target = "name", t.Mark
	default:
		return "", "", "", errors.New("no point in time or Mark given")
	}
	if t.BackupSet != "" && !pgbackrest.ValidBackupLabel(t.BackupSet) {
		return "", "", "", fmt.Errorf("invalid backup set %q", t.BackupSet)
	}
	return typ, target, t.BackupSet, nil
}

// describeTarget: "14:04:00 UTC on 2026-09-24" or "the Mark before-migration".
func describeTarget(t protocol.RewindTarget) string {
	if t.Mark != "" {
		return "the Mark " + t.Mark
	}
	if t.XID != 0 && t.Time != nil {
		return fmt.Sprintf("just before transaction %d (committed at %s)", t.XID, t.Time.UTC().Format("15:04:05 UTC on 2006-01-02"))
	}
	if t.Time != nil {
		return t.Time.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	return "the chosen point"
}

// checkBackupSet makes sure the repository answers and holds the backup
// the restore starts from.
func checkBackupSet(stanzas []pgbackrest.Stanza, stanza, set string) error {
	if _, err := pgbackrest.LatestBackup(stanzas, stanza); err != nil {
		return fmt.Errorf("nothing to restore from: %w", err)
	}
	if set == "" {
		return nil
	}
	for _, s := range stanzas {
		if s.Name != stanza {
			continue
		}
		for _, b := range s.Backup {
			if b.Label == set && !b.Error {
				return nil
			}
		}
	}
	return fmt.Errorf("the backup %s is no longer in the repository (retention may have removed it); pick a later point", set)
}

// copyExpiry clamps the requested expiry: default 24h, at least an hour,
// at most 7 days.
func copyExpiry(requested, now time.Time) time.Time {
	switch {
	case requested.IsZero():
		return now.Add(defaultCopyLifetime)
	case requested.Before(now.Add(time.Hour)):
		return now.Add(time.Hour)
	case requested.After(now.Add(maxCopyLifetime)):
		return now.Add(maxCopyLifetime)
	}
	return requested.UTC()
}

func (a *Agent) copyTarget(r rewindRecord) pginspect.Target {
	return pginspect.Target{SocketDir: filepath.Join(r.Dir, "socket"), Port: r.Port, User: a.cfg.PGUser, AppName: rewindAppName}
}

// rewindCopy restores a copy and leaves it running.
func (a *Agent) rewindCopy(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl *taskLog) (*protocol.RewindCopyResult, error) {
	if !rewindIDRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	typ, target, set, err := rewindRestoreArgs(p.Target)
	if err != nil {
		return nil, err
	}
	st := a.rewindState()
	if r, ok := st.get(p.CopyID); ok {
		if r.Kind == protocol.RewindKindCopy && r.Status == protocol.RewindCopyReady && r.DatabaseID == db.ID {
			tl.Printf("the copy %s is already there", p.CopyID)
			return a.copyResult(ctx, r)
		}
		return nil, fmt.Errorf("a copy with id %s already exists", p.CopyID)
	}
	if other, ok := st.copyFor(db.ID); ok {
		return nil, fmt.Errorf("%s already has a copy (restored to %s); delete it first: there is one copy per database at a time",
			cmp.Or(db.Name, "this database"), describeTarget(other.Target))
	}

	prod, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	if err := a.writeConfig(db, prod); err != nil {
		return nil, err
	}
	cli := a.cli(db)
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return nil, fmt.Errorf("Rowsafe can't reach the backup repository from this server: %w", err)
	}
	if err := checkBackupSet(stanzas, db.Stanza, set); err != nil {
		return nil, err
	}
	dir, err := scratchDir(a.cfg.RewindDir, p.CopyID, prod.DataDirectory, "copy")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(a.cfg.RewindDir, 0o700); err != nil {
		return nil, fmt.Errorf("can't create %s for copies: %w", a.cfg.RewindDir, err)
	}
	need := int64(float64(prod.TotalSizeBytes)*drillSpaceFactor) + 1<<30
	if free, err := freeBytes(a.cfg.RewindDir); err == nil && free < need {
		return nil, fmt.Errorf("not enough free disk for a copy: %s free in %s, and a copy of %s needs about %s",
			humanBytes(free), a.cfg.RewindDir, humanBytes(prod.TotalSizeBytes), humanBytes(need))
	}
	dataDir := filepath.Join(dir, "data")
	socketDir := filepath.Join(dir, "socket")
	port := a.cfg.DrillPort
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(port)); n > maxSocketPath {
		return nil, fmt.Errorf("the copy's socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_REWIND_DIR", n, maxSocketPath)
	}

	now := time.Now().UTC()
	rec := rewindRecord{ID: p.CopyID, Kind: protocol.RewindKindCopy, DatabaseID: db.ID, Status: protocol.RewindCopyRestoring,
		CreatedAt: now, Expires: copyExpiry(p.Expires, now), Target: p.Target, Database: db, Dir: dir, Major: prod.Major(), Port: port}
	if err := st.put(rec); err != nil {
		return nil, err
	}
	taskCtx := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	running := st.startRunning(p.CopyID, cancel)
	defer st.finishRunning(p.CopyID, running)

	pgCtl := a.cfg.pgBin(prod.Major(), "pg_ctl")
	ok := false
	defer func() {
		if ok {
			return
		}
		if data, err := os.ReadFile(filepath.Join(dir, "postgres.log")); err == nil {
			tl.Output("copy postgres.log (tail)", tail(data, 8000))
		}
		if err := a.removeDrill(dir, pgCtl); err != nil {
			tl.Printf("cleaning up %s failed: %v", dir, err)
		} else {
			tl.Printf("removed %s", dir)
		}
		if err := st.remove(p.CopyID); err != nil {
			tl.Printf("updating the rewind state: %v", err)
		}
	}()
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		if ctx.Err() != nil && taskCtx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(dir, copyMarker), []byte(p.CopyID+"\n"), 0o600); err != nil {
		return fail(err)
	}
	for _, d := range []string{dataDir, socketDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fail(err)
		}
	}

	cli.Wrap = niceWrap()
	tl.Printf("restoring %s into a copy at %s (backup %s)", describeTarget(p.Target), dataDir, cmp.Or(set, "picked by pgBackRest"))
	out, err := cli.RestoreTo(ctx, pgbackrest.RestoreOptions{DataDir: dataDir, TablespaceDir: filepath.Join(dir, "tablespaces"),
		ArchiveOff: true, Type: typ, Target: target, Exclusive: typ == "xid", Set: set, Timeline: p.Target.Timeline})
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fail(err)
	}
	spec := scratchSpec{Name: "copy", Port: port, SocketDir: socketDir, Major: prod.Major()}
	if a.cfg.DrillPreload == DrillPreloadProduction {
		spec.Preload = prod.SharedPreloadLibraries
	}
	if err := a.writeScratchConf(dataDir, spec); err != nil {
		return fail(err)
	}
	timeout := 4 * time.Hour
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-5*time.Minute, time.Minute)
	}
	t := pginspect.Target{SocketDir: socketDir, Port: port, User: a.cfg.PGUser, AppName: rewindAppName}
	conn, spec, err := a.startScratchFallback(ctx, tl, spec, t, pgCtl, dir, timeout, prod.SharedPreloadLibraries)
	if err != nil {
		if strings.Contains(err.Error(), "stopped during recovery") && typ != "name" {
			err = fmt.Errorf("%w (if the time is after the last change that reached the backups, pick an earlier one)", err)
		}
		return fail(err)
	}
	var recoveredTo *time.Time
	qerr := conn.QueryRow(ctx, `SELECT pg_last_xact_replay_timestamp()`).Scan(&recoveredTo)
	if qerr == nil {
		qerr = checkScratchIsolation(ctx, conn, tl)
	}
	closeConn(ctx, conn)
	if qerr != nil {
		return fail(qerr)
	}
	if recoveredTo != nil {
		utc := recoveredTo.UTC()
		recoveredTo = &utc
	}
	size := dirSize(dataDir)
	if err := st.update(p.CopyID, func(r *rewindRecord) {
		r.Status, r.RecoveredTo, r.SizeBytes, r.Preload = protocol.RewindCopyReady, recoveredTo, size, spec.Preload
	}); err != nil {
		return fail(err)
	}
	ok = true
	rec, _ = st.get(p.CopyID)
	res, err := a.copyResult(ctx, rec)
	if err != nil {
		return res, err
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// copyResult describes a ready copy.
func (a *Agent) copyResult(ctx context.Context, r rewindRecord) (*protocol.RewindCopyResult, error) {
	t := a.copyTarget(r)
	res := &protocol.RewindCopyResult{CopyID: r.ID, RecoveredTo: r.RecoveredTo, SizeBytes: r.SizeBytes,
		SocketDir: t.SocketDir, Port: t.Port, Expires: r.Expires}
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return nil, fmt.Errorf("the copy is not answering: %w", err)
	}
	defer closeConn(ctx, conn)
	if res.Databases, err = pginspect.Databases(ctx, t, conn); err != nil {
		return nil, err
	}
	var names []string
	for _, d := range res.Databases {
		names = append(names, d.Name)
	}
	to := "the backup itself (no later changes were replayed)"
	if r.RecoveredTo != nil {
		to = "the last change before " + describeTarget(r.Target) + " (" + r.RecoveredTo.UTC().Format("15:04:05 UTC on 2006-01-02") + ")"
	}
	res.Summary = fmt.Sprintf("The copy is ready: %s, restored to %s. Databases: %s. It is deleted by itself at %s.",
		humanBytes(r.SizeBytes), to, strings.Join(names, ", "), r.Expires.UTC().Format("15:04 UTC on 2006-01-02"))
	return res, nil
}

// copyDirOK checks that dir is the copy directory of id: under
// ROWSAFE_REWIND_DIR, a real directory (not a symlink) and carrying the
// marker. Nothing else is ever stopped or deleted as a copy.
func (a *Agent) copyDirOK(id, dir string) error {
	want, err := scratchDir(a.cfg.RewindDir, id, "/nonexistent-production-data-dir", "copy")
	if err != nil {
		return err
	}
	if filepath.Clean(dir) != want {
		return fmt.Errorf("refusing to remove %s: it is not the copy directory %s", dir, want)
	}
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to remove %s: not a directory", dir)
	}
	if _, err := os.Lstat(filepath.Join(dir, copyMarker)); err != nil {
		return fmt.Errorf("refusing to remove %s: it has no copy marker", dir)
	}
	return nil
}

// removeCopy stops a copy's PostgreSQL, deletes its directory and forgets
// it. It returns the space freed (as last measured).
func (a *Agent) removeCopy(r rewindRecord) (int64, error) {
	err := a.copyDirOK(r.ID, r.Dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return 0, err
	default:
		pgCtl := "pg_ctl"
		if r.Major > 0 {
			pgCtl = a.cfg.pgBin(r.Major, "pg_ctl")
		}
		if err := a.removeDrill(r.Dir, pgCtl); err != nil {
			return 0, err
		}
	}
	return r.SizeBytes, a.rewindState().remove(r.ID)
}

// restartCopy starts a ready copy whose PostgreSQL isn't running (the
// agent's restart stopped it: it runs in the agent's service).
func (a *Agent) restartCopy(ctx context.Context, r rewindRecord) error {
	if err := a.copyDirOK(r.ID, r.Dir); err != nil {
		return err
	}
	dataDir := filepath.Join(r.Dir, "data")
	switch _, state := postmasterFor(dataDir); state {
	case postmasterRunning:
		return nil
	case postmasterNone:
		// A stale pid file (its process is gone, or is something else
		// after a reboot) would stop PostgreSQL from starting.
		_ = os.Remove(filepath.Join(dataDir, "postmaster.pid"))
	}
	pgCtl := a.cfg.pgBin(r.Major, "pg_ctl")
	args := append(niceWrap()[1:], pgCtl, "-D", dataDir, "-l", filepath.Join(r.Dir, "postgres.log"), "-w", "-t", "600", "start")
	sctx, cancel := context.WithTimeout(ctx, 11*time.Minute)
	defer cancel()
	if out, err := a.runner.Run(sctx, niceWrap()[0], args...); err != nil {
		return fmt.Errorf("pg_ctl start: %w: %s", err, strings.TrimSpace(string(out)))
	}
	conn, err := a.waitForScratch(sctx, a.copyTarget(r), pgCtl, dataDir, time.Now().Add(10*time.Minute))
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	return checkScratchIsolation(ctx, conn, &taskLog{})
}

// cleanupStaleCopies removes copy directories the rewind state doesn't
// know (e.g. the state file was lost). Directories without the marker are
// left alone.
func (a *Agent) cleanupStaleCopies(known map[string]bool) {
	entries, err := os.ReadDir(a.cfg.RewindDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !rewindIDRE.MatchString(e.Name()) || known[e.Name()] {
			continue
		}
		dir := filepath.Join(a.cfg.RewindDir, e.Name())
		if err := a.copyDirOK(e.Name(), dir); err != nil {
			a.log.Warn("leaving an unrecognised directory in the rewind directory alone", "dir", dir)
			continue
		}
		pgCtl := "pg_ctl"
		if v, err := os.ReadFile(filepath.Join(dir, "data", "PG_VERSION")); err == nil {
			if major, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil {
				pgCtl = a.cfg.pgBin(major, "pg_ctl")
			}
		}
		if err := a.removeDrill(dir, pgCtl); err != nil {
			a.log.Error("removing a leftover copy failed", "dir", dir, "err", err)
		} else {
			a.log.Warn("removed a leftover copy", "dir", dir)
		}
	}
}

// rewindDrop deletes a copy, cancelling its restore if it is still running.
func (a *Agent) rewindDrop(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindDropParams, tl *taskLog) (*protocol.RewindDropResult, error) {
	if !rewindIDRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	res := &protocol.RewindDropResult{CopyID: p.CopyID}
	st := a.rewindState()
	r, ok := st.get(p.CopyID)
	if !ok {
		res.Summary = "There was no copy to delete (it was already deleted or had expired)."
		tl.Printf("%s", res.Summary)
		return res, nil
	}
	if r.Kind != protocol.RewindKindCopy || r.DatabaseID != db.ID {
		return nil, fmt.Errorf("%s is not a copy of this database", p.CopyID)
	}
	if r.Status == protocol.RewindCopyRestoring && st.cancelRunning(p.CopyID, 3*time.Minute) {
		res.Removed = true
		res.Summary = "The copy was still being restored; Rowsafe stopped the restore and deleted what was there."
		if _, still := st.get(p.CopyID); still {
			return res, errors.New("the restore was stopped, but its files are still being cleaned up; they are removed when the agent next starts")
		}
		tl.Printf("%s", res.Summary)
		return res, nil
	}
	freed, err := a.removeCopy(r)
	if err != nil {
		return nil, err
	}
	res.Removed, res.FreedBytes = true, freed
	res.Summary = fmt.Sprintf("Deleted the copy; %s of disk is free again.", humanBytes(freed))
	tl.Printf("%s", res.Summary)
	return res, nil
}
