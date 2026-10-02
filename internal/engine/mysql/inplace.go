package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole server in place (and Undo).
//
// The restore happens while production keeps running: the backup and the
// binary logs up to the target go into a private server in Rowsafe's own
// folder, exactly like a Rewind copy, which is then shut down cleanly.
// Only then is production stopped, through the same root helper that
// restarts it (only the unit root listed in restart-allowed), and the data
// directory's entries are swapped, one rename each:
//
//	<rewind dir>/<engine>-inplace/<id>/restore/data   the restored data
//	<rewind dir>/<engine>-inplace/<id>/before         production's, kept for Undo
//	<rewind dir>/<engine>-inplace/<id>/after-<UTC>    the rewound data, set aside by Undo
//	<rewind dir>/<engine>-inplace/<id>/failed-<UTC>   a swap rolled back
//
// The data directory itself keeps its owner, mode and place. Files that
// belong to the server rather than to the data (SET PERSIST settings, TLS
// keys, Debian's flags) are copied over from production. Renames need the
// rewind folder on the same filesystem as the data directory; a server on
// a disk of its own, or with SELinux enforcing, is refused before anything
// changes (restore a copy and bring back rows instead).
//
// The binary log starts over on the rewound data (it isn't in the restored
// data directory, or it continues from production's own files when they
// live outside it): a "switch" note in the bucket tells later restores that
// a point after the rewind needs a backup taken after it (the control
// plane queues a full backup as soon as the rewind is done).
//
// Any failure after the stop puts production's entries back and starts it
// again; an agent that restarts in the middle does the same (recoverInPlace).

const (
	ipPreflight = "preflight" // nothing changed
	ipRestoring = "restoring" // restoring into the stage; production untouched
	ipStopped   = "stopped"   // production stopped (or being stopped), its data untouched
	ipMoved     = "moved"     // production's entries (some or all) in the aside folder
	ipSwapped   = "swapped"   // restored entries (some or all) in the data directory
	ipStarted   = "started"   // asked the helper to start the swapped data
)

var (
	inPlaceStopWait  = 2 * time.Minute
	inPlaceReadyWait = 5 * time.Minute
	inPlaceShipWait  = time.Minute
	selinuxEnforce   = "/sys/fs/selinux/enforce"
)

// carriedFile: files in the data directory that belong to the server, not
// to the data. They are copied over from production into the rewound data.
func carriedFile(name string) bool {
	return name == "mysqld-auto.cnf" || strings.HasSuffix(name, ".pem") ||
		strings.HasPrefix(name, "debian-") && strings.HasSuffix(name, ".flag")
}

// inPlaceRoot is where a rewind's folders live.
func (s *server) inPlaceRoot(id string) (string, error) {
	return safeDir(filepath.Join(s.env.Config.RewindDir, string(s.flavor)+"-inplace"), id)
}

// ipFacts are what the preflight reads from the running server.
type ipFacts struct {
	facts
	PIDFile  string
	Replicas int
	Size     int64
}

func (s *server) inPlaceFacts(ctx context.Context) (ipFacts, error) {
	var f ipFacts
	db, err := s.open(ctx)
	if err != nil {
		return f, err
	}
	defer db.Close()
	if f.facts, err = s.readFacts(ctx, db); err != nil {
		return f, err
	}
	var home, undo, logHome sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT @@pid_file, @@innodb_data_home_dir, @@innodb_undo_directory, @@innodb_log_group_home_dir`).
		Scan(&f.PIDFile, &home, &undo, &logHome); err != nil {
		return f, err
	}
	if !filepath.IsAbs(f.PIDFile) {
		f.PIDFile = filepath.Join(f.DataDir, f.PIDFile)
	}
	for _, d := range []string{home.String, undo.String, logHome.String} {
		if d == "" || d == "." || d == "./" {
			continue
		}
		abs := d
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(f.DataDir, abs)
		}
		if !within(f.DataDir, abs) {
			return f, fmt.Errorf("InnoDB keeps files outside the data directory (%s): rewinding in place isn't available for that layout yet; restore a copy and bring back rows instead", d)
		}
	}
	for _, stmt := range []string{"SHOW REPLICAS", "SHOW SLAVE HOSTS"} {
		rows, err := db.QueryContext(ctx, stmt)
		if err != nil {
			continue
		}
		for rows.Next() {
			f.Replicas++
		}
		rows.Close()
		break
	}
	f.Size = totalSize(ctx, s)
	return f, nil
}

// within reports whether p is dir or inside it.
func within(dir, p string) bool {
	dir, p = filepath.Clean(dir), filepath.Clean(p)
	return p == dir || strings.HasPrefix(p, dir+string(filepath.Separator))
}

func devOf(path string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Dev), nil
}

// preflightInPlace checks everything a rewind (or undo) needs before
// anything changes, and returns the data directory.
func (s *server) preflightInPlace(ctx context.Context, root string, needBytes int64) (ipFacts, error) {
	name := s.flavor.display()
	if s.env.Control == nil {
		return ipFacts{}, errors.New("this agent can't stop the database server")
	}
	if err := s.env.Control.Allowed(s.db); err != nil {
		return ipFacts{}, err
	}
	if b, err := os.ReadFile(selinuxEnforce); err == nil && strings.TrimSpace(string(b)) == "1" {
		return ipFacts{}, fmt.Errorf("SELinux is enforcing on this server, and files Rowsafe restores would keep the wrong label in %s's data directory: "+
			"rewinding in place isn't available here yet; restore a copy and bring back rows instead", name)
	}
	f, err := s.inPlaceFacts(ctx)
	if err != nil {
		return f, err
	}
	switch {
	case f.Replica:
		return f, fmt.Errorf("this %s server is a replica: rewind its primary instead", name)
	case f.Replicas > 0:
		return f, fmt.Errorf("%d replica(s) copy from this server; they would no longer match it after a rewind. Rewinding in place isn't available for a server with replicas yet: restore a copy and bring back rows instead", f.Replicas)
	case !f.LogBin:
		return f, fmt.Errorf("%s's binary log is off", name)
	}
	info, err := os.Lstat(f.DataDir)
	if err != nil {
		return f, fmt.Errorf("the data directory %s: %w", f.DataDir, err)
	}
	if !info.IsDir() {
		return f, fmt.Errorf("the data directory %s is not a directory (a symbolic link?): rewinding in place isn't available for that layout", f.DataDir)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return f, fmt.Errorf("the data directory %s doesn't belong to the agent's user", f.DataDir)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return f, err
	}
	d1, err1 := devOf(f.DataDir)
	d2, err2 := devOf(root)
	if err1 != nil || err2 != nil || d1 != d2 {
		return f, fmt.Errorf("%s's data directory (%s) is on another disk than Rowsafe's folder (%s): rewinding in place swaps the data with a rename, "+
			"which needs both on the same disk. Restore a copy and bring back rows instead", name, f.DataDir, s.env.Config.RewindDir)
	}
	if needBytes > 0 {
		if err := checkSpace(root, needBytes); err != nil {
			return f, err
		}
	}
	return f, nil
}

// rewindInPlace rewinds the whole server to p.Target.
func (s *server) rewindInPlace(ctx context.Context, p protocol.RewindInPlaceParams, log agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	kept := s.env.Kept()
	for _, r := range kept.ForDatabase(s.db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	root, err := s.inPlaceRoot(p.RewindID)
	if err != nil {
		return nil, err
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	target, err := s.rewindTarget(ctx, st, p.Target)
	if err != nil {
		return nil, err
	}
	f, err := s.preflightInPlace(ctx, root, 1) // space is checked below, once the size is known
	if err == nil && f.Size > 0 {
		err = checkSpace(root, f.Size)
	}
	if err != nil {
		_ = os.Remove(root) // empty: nothing was restored yet
		return nil, err
	}
	name := s.flavor.display()
	now := time.Now().UTC()
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: s.db.ID, Status: protocol.RewindInProgress, CreatedAt: now,
		Target: p.Target, KeepDays: p.KeepDays, Phase: ipRestoring, Database: s.db,
		Extra: map[string]string{"root": root, "data_dir": f.DataDir, "pid_file": f.PIDFile, "aside": filepath.Join(root, "before")}}
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	stage := filepath.Join(root, "restore")
	cleanStage := func() { _ = os.RemoveAll(stage) }
	abandon := func(err error) (*protocol.RewindInPlaceResult, error) {
		cleanStage()
		_ = os.RemoveAll(root)
		_ = kept.Remove(rec.ID)
		return nil, err
	}

	// 1. Restore next to production (production keeps running).
	log.Printf("restoring %s as it was at %s next to production (production keeps running meanwhile)", s.db.Name, target.describe())
	r, err := s.restoreData(ctx, st, stage, target, log)
	if err != nil {
		return abandon(err)
	}
	sc, err := s.startScratch(ctx, stage, r.Backup, drillStartTimeout)
	if err != nil {
		return abandon(err)
	}
	err = s.replay(ctx, sc, r, target, log)
	sc.stop(context.WithoutCancel(ctx))
	if err != nil {
		return abandon(err)
	}
	recovered := recoveredTo(r, target)
	if recovered == nil {
		t := r.Backup.StoppedAt
		recovered = &t
	}
	restored := filepath.Join(stage, "data")
	for _, n := range []string{"auto.cnf"} { // a new server UUID: the rewound server starts a new history
		_ = os.Remove(filepath.Join(restored, n))
	}
	log.Printf("restored to %s; now swapping it in", recovered.UTC().Format("15:04:05 UTC on 2006-01-02"))

	// 2. Get the last changes into the bucket (the time just before the
	// rewind stays restorable), best effort.
	s.shipNow(ctx, log)

	// 3. Stop, swap, start.
	rec.RecoveredTo = recovered
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: recovered, OldDataDir: rec.Extra["aside"]}
	if err := s.swap(ctx, &rec, restored, rec.Extra["aside"], "rewind", log); err != nil {
		res.RolledBack = errors.Is(err, errRolledBack)
		res.DurationMs = time.Since(start).Milliseconds()
		cleanStage()
		if res.RolledBack {
			_ = os.RemoveAll(root)
			_ = kept.Remove(rec.ID)
		}
		return res, err
	}
	cleanStage()
	until := agent.KeepUntil(p.KeepDays, time.Now())
	rec.Status, rec.Phase, rec.Expires, rec.Path = protocol.RewindKeptBefore, "", until, rec.Extra["aside"]
	rec.SizeBytes = dirSize(rec.Path)
	if err := kept.Put(rec); err != nil {
		log.Printf("warning: saving the rewind's state: %v", err)
	}
	res.KeptUntil = &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Rewound %s to %s. %s's data from before is kept until %s so you can undo.", s.db.Name,
		recovered.UTC().Format("15:04:05 UTC on 2006-01-02"), name, until.UTC().Format("2006-01-02 15:04 UTC"))
	log.Printf("%s", res.Summary)
	return res, nil
}

// rewindUndo puts production's data from before the rewind back; the
// rewound data is set aside in turn.
func (s *server) rewindUndo(ctx context.Context, p protocol.RewindUndoParams, log agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := s.env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != s.db.ID {
		return nil, errors.New("there is nothing to undo: the data from before this rewind is no longer kept")
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, errors.New("this rewind was undone already")
	}
	root := rec.Extra["root"]
	before := rec.Extra["aside"]
	if _, err := os.Stat(before); err != nil {
		return nil, fmt.Errorf("the data kept from before the rewind is gone (%v)", err)
	}
	f, err := s.preflightInPlace(ctx, root, 0)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(f.DataDir) != filepath.Clean(rec.Extra["data_dir"]) {
		return nil, fmt.Errorf("%s's data directory is now %s, not %s as when it was rewound: Undo would put the data in the wrong place", s.flavor.display(), f.DataDir, rec.Extra["data_dir"])
	}
	after := filepath.Join(root, "after-"+time.Now().UTC().Format("20060102T150405Z"))
	saved := rec
	saved.Extra = maps.Clone(rec.Extra)
	rec.Extra = maps.Clone(rec.Extra)
	rec.Status, rec.Phase = protocol.RewindInProgress, ipPreflight
	rec.Extra["pid_file"], rec.Extra["undo_aside"] = f.PIDFile, after
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	s.shipNow(ctx, log)
	res := &protocol.RewindUndoResult{RewindID: rec.ID, RewoundDataDir: after}
	if err := s.swap(ctx, &rec, before, after, "undo", log); err != nil {
		res.RolledBack = errors.Is(err, errRolledBack)
		res.DurationMs = time.Since(start).Milliseconds()
		if res.RolledBack {
			_ = kept.Put(saved)
		}
		return res, err
	}
	_ = os.Remove(before)
	until := agent.KeepUntil(rec.KeepDays, time.Now())
	rec.Status, rec.Phase, rec.Undo, rec.Expires, rec.Path = protocol.RewindKeptAfterUndo, "", true, until, after
	rec.Extra["aside"] = after
	delete(rec.Extra, "undo_aside")
	rec.SizeBytes = dirSize(after)
	if err := kept.Put(rec); err != nil {
		log.Printf("warning: saving the rewind's state: %v", err)
	}
	res.KeptUntil = &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s is back as it was before the rewind. The rewound data (with anything written since) is kept until %s.",
		s.db.Name, until.UTC().Format("2006-01-02 15:04 UTC"))
	log.Printf("%s", res.Summary)
	return res, nil
}

// rewindCleanup deletes what a rewind kept aside.
func (s *server) rewindCleanup(_ context.Context, p protocol.RewindCleanupParams, log agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := s.env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != s.db.ID {
		return &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept for this rewind any more."}, nil
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	freed := removeKept(rec)
	if err := kept.Remove(rec.ID); err != nil {
		return nil, err
	}
	res := &protocol.RewindCleanupResult{RewindID: rec.ID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the data kept aside by the rewind (%s freed).", humanBytes(freed))}
	log.Printf("%s", res.Summary)
	return res, nil
}

// removeKept deletes a rewind's folder, only inside Rowsafe's own.
func removeKept(rec agent.KeptRecord) int64 {
	root := rec.Extra["root"]
	if root == "" || !strings.Contains(filepath.Base(filepath.Dir(root)), "-inplace") {
		return 0
	}
	n := dirSize(root)
	_ = os.RemoveAll(root)
	return n
}

var errRolledBack = errors.New("rolled back")

// swap stops production, moves its entries to aside, moves src's entries
// into the data directory, starts it and waits until it answers. Any
// failure puts production's entries back and starts it (errRolledBack).
func (s *server) swap(ctx context.Context, rec *agent.KeptRecord, src, aside, what string, log agent.TaskLogger) error {
	kept := s.env.Kept()
	dataDir := rec.Extra["data_dir"]
	name := s.flavor.display()
	phase := func(p string) error {
		rec.Phase = p
		return kept.Put(*rec)
	}
	ctx = context.WithoutCancel(ctx) // once production is stopped, finish (or roll back) whatever happens to the task
	rollback := func(cause error) error {
		log.Printf("%s failed (%v); putting %s's data back", what, cause, name)
		if err := s.rollbackSwap(ctx, rec, log); err != nil {
			return fmt.Errorf("%s failed (%v), and putting the data back failed too: %w. %s's data from before is in %s", what, cause, err, name, aside)
		}
		return fmt.Errorf("%s failed, and %s runs on its data from before again (nothing changed): %v: %w", what, name, cause, errRolledBack)
	}
	if err := phase(ipStopped); err != nil {
		return err
	}
	log.Printf("stopping %s", name)
	if err := s.env.Control.Stop(ctx, s.db, rec.ID+"-stop"); err != nil {
		return rollback(err)
	}
	if err := waitGone(ctx, rec.Extra["pid_file"]); err != nil {
		return rollback(err)
	}
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return rollback(err)
	}
	if err := phase(ipMoved); err != nil {
		return rollback(err)
	}
	if err := moveEntries(dataDir, aside); err != nil {
		return rollback(fmt.Errorf("setting the current data aside: %w", err))
	}
	if err := phase(ipSwapped); err != nil {
		return rollback(err)
	}
	if err := moveEntries(src, dataDir); err != nil {
		return rollback(fmt.Errorf("moving the restored data in: %w", err))
	}
	if what == "rewind" {
		if err := copyCarried(aside, dataDir); err != nil {
			return rollback(fmt.Errorf("copying the server's own files (settings, TLS keys): %w", err))
		}
	}
	if err := s.recordSwitch(ctx, rec.ID, what); err != nil {
		return rollback(fmt.Errorf("noting the %s in your storage: %w", what, err))
	}
	if err := phase(ipStarted); err != nil {
		return rollback(err)
	}
	log.Printf("starting %s", name)
	if err := s.env.Control.Start(ctx, s.db, rec.ID+"-start"); err != nil {
		return rollback(err)
	}
	if err := s.waitReady(ctx); err != nil {
		return rollback(fmt.Errorf("%s didn't come back: %w", name, err))
	}
	shipperFor(s).restartLog()
	log.Printf("%s answers again", name)
	return nil
}

// rollbackSwap puts production's entries back (from the aside folder of
// rec) and starts the server. The switch noted in the bucket is removed.
func (s *server) rollbackSwap(ctx context.Context, rec *agent.KeptRecord, log agent.TaskLogger) error {
	dataDir, aside := rec.Extra["data_dir"], rec.Extra["aside"]
	if rec.Status == protocol.RewindInProgress && rec.Extra["undo_aside"] != "" {
		aside = rec.Extra["undo_aside"] // an undo sets production (the rewound data) aside there
	}
	if rec.Phase == ipStarted || rec.Phase == ipSwapped {
		_ = s.env.Control.Stop(ctx, s.db, rec.ID+"-rb-stop")
		if err := waitGone(ctx, rec.Extra["pid_file"]); err != nil {
			return err
		}
	}
	if rec.Phase == ipSwapped || rec.Phase == ipStarted {
		failed := filepath.Join(rec.Extra["root"], "failed-"+time.Now().UTC().Format("20060102T150405Z"))
		if err := os.MkdirAll(failed, 0o700); err != nil {
			return err
		}
		if rec.Undo || rec.Extra["undo_aside"] != "" {
			// an undo moved the kept data in: it goes back to where it was kept
			failed = rec.Extra["aside"]
		}
		if err := moveEntries(dataDir, failed); err != nil {
			return err
		}
		_ = s.removeSwitch(ctx, rec.ID)
	}
	if rec.Phase == ipMoved || rec.Phase == ipSwapped || rec.Phase == ipStarted {
		if err := moveEntries(aside, dataDir); err != nil {
			return err
		}
	}
	rec.Phase = ipStopped
	_ = s.env.Kept().Put(*rec)
	if err := s.env.Control.Start(ctx, s.db, rec.ID+"-rb-start"); err != nil {
		return err
	}
	if err := s.waitReady(ctx); err != nil {
		return err
	}
	log.Printf("%s runs on its data from before again", s.flavor.display())
	return nil
}

// waitGone waits until the process in pidFile has exited.
func waitGone(ctx context.Context, pidFile string) error {
	deadline := time.Now().Add(inPlaceStopWait)
	for {
		pid := 0
		if b, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		}
		if pid <= 0 || syscall.Kill(pid, 0) != nil || zombie(pid) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the server (process %d) is still running %s after it was asked to stop", pid, inPlaceStopWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// waitReady waits until production answers again.
func (s *server) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(inPlaceReadyWait)
	for {
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		db, err := s.open(cctx)
		if err == nil {
			err = db.PingContext(cctx)
			db.Close()
		}
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// shipNow uploads the binary log up to now, so the moment just before the
// rewind stays restorable (best effort: a minute at most).
func (s *server) shipNow(ctx context.Context, log agent.TaskLogger) {
	db, err := s.open(ctx)
	if err != nil {
		return
	}
	pos, err := s.currentPosition(ctx, db)
	var basename string
	if err == nil {
		err = db.QueryRowContext(ctx, "SELECT IFNULL(@@log_bin_basename, '')").Scan(&basename)
	}
	db.Close()
	if err != nil {
		return
	}
	if created, err := readBinlogCreated(filepath.Join(filepath.Dir(basename), pos.File.Name)); err == nil {
		pos.File.Created = created
	}
	if _, err := shipperFor(s).waitShipped(ctx, pos, inPlaceShipWait); err != nil {
		log.Printf("note: the last changes before the rewind may not all be in your storage yet (%v); they stay in the data kept aside", err)
	}
}

// moveEntries moves every entry of src into dst, one rename each; an entry
// already in dst is an error (nothing is overwritten).
func moveEntries(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		to := filepath.Join(dst, e.Name())
		if _, err := os.Lstat(to); err == nil {
			return fmt.Errorf("%s already exists", to)
		}
		if err := os.Rename(filepath.Join(src, e.Name()), to); err != nil {
			return err
		}
	}
	return nil
}

// copyCarried copies the server's own files from production's data (from)
// into the rewound data directory (to), replacing the restored ones.
func copyCarried(from, to string) error {
	entries, err := os.ReadDir(from)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !carriedFile(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		src, err := os.Open(filepath.Join(from, e.Name()))
		if err != nil {
			return err
		}
		dst := filepath.Join(to, e.Name())
		_ = os.Remove(dst)
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			src.Close()
			return err
		}
		_, err = io.Copy(out, src)
		src.Close()
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ---- switches: the data jumped (rewind or undo) ----

// switchRecord notes in the bucket that the server's data jumped at At: a
// restore to a point after At needs a backup that started after it.
type switchRecord struct {
	ID   string    `json:"id"`
	Kind string    `json:"kind"` // rewind | undo
	At   time.Time `json:"at"`
}

func switchKey(id, kind string) string { return "switches/" + id + "-" + kind + ".json" }

func (s *server) recordSwitch(ctx context.Context, id, kind string) error {
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return err
	}
	return st.putJSON(ctx, switchKey(id, kind), switchRecord{ID: id, Kind: kind, At: time.Now().UTC()})
}

func (s *server) removeSwitch(ctx context.Context, id string) error {
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return err
	}
	return st.remove(ctx, []string{switchKey(id, "rewind"), switchKey(id, "undo")})
}

// checkSwitches refuses a restore from backup b to t when the data jumped
// (a rewind in place or an undo) after b started and at or before t: the
// binary logs from b on would replay a history the server left.
func checkSwitches(ctx context.Context, st *objStore, b manifest, t restoreTarget) error {
	objs, err := st.list(ctx, "switches/")
	if err != nil || len(objs) == 0 {
		return nil
	}
	p := t.point()
	for _, o := range objs {
		var sw switchRecord
		if st.getJSON(ctx, o.Key, &sw) != nil || sw.At.IsZero() {
			continue
		}
		if sw.At.After(b.StartedAt) && (p.IsZero() || !sw.At.After(p)) {
			return fmt.Errorf("the database was rewound in place at %s, after the backup %s: restoring to %s needs a backup taken after that "+
				"(Rowsafe takes one right after a rewind; wait for it to finish)", sw.At.Format("15:04:05 UTC on 2006-01-02"), b.Label, t.describe())
		}
	}
	return nil
}

// ---- after an agent restart ----

// recoverInPlace rolls back a rewind or an undo the agent was running when
// it stopped, and drops a restore that was interrupted.
func (e *Engine) recoverInPlace(ctx context.Context, env agent.EngineEnv) {
	kept := env.Kept()
	for _, rec := range kept.All() {
		if rec.Status != protocol.RewindInProgress {
			continue
		}
		s := e.server(env, rec.Database)
		switch rec.Phase {
		case ipPreflight, ipRestoring, "":
			if rec.Extra["undo_aside"] != "" { // an undo that hadn't stopped anything
				rec.Status, rec.Phase = protocol.RewindKeptBefore, ""
				delete(rec.Extra, "undo_aside")
				_ = kept.Put(rec)
				continue
			}
			removeKept(rec)
			_ = kept.Remove(rec.ID)
		default:
			r := rec
			err := s.rollbackSwap(ctx, &r, discardLog{})
			if err != nil {
				env.Log.Error("rolling back an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
				continue
			}
			env.Log.Warn("an interrupted rewind in place was rolled back", "rewind_id", rec.ID)
			if r.Extra["undo_aside"] != "" {
				r.Status, r.Phase = protocol.RewindKeptBefore, ""
				_ = os.RemoveAll(r.Extra["undo_aside"])
				delete(r.Extra, "undo_aside")
				_ = kept.Put(r)
			} else {
				removeKept(r)
				_ = kept.Remove(r.ID)
			}
		}
	}
}

// expireKept deletes kept data past its expiry.
func expireKept(env agent.EngineEnv, now time.Time) {
	kept := env.Kept()
	for _, rec := range kept.Expired(now) {
		removeKept(rec)
		_ = kept.Remove(rec.ID)
		env.Log.Info("deleted the data kept aside by a rewind in place (expired)", "rewind_id", rec.ID)
	}
}

type discardLog struct{}

func (discardLog) Printf(string, ...any) {}
func (discardLog) Output(string, []byte) {}
