package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole database in place.
//
// The worst case: production itself goes back to a point in time. The agent
// runs unprivileged, so PostgreSQL is stopped and started by the root helper
// (rowsafe-pg-restart, "ID stop PORT" / "ID start PORT"), only for clusters
// root listed at install time. Everything else happens as the agent user:
//
//  1. preflight: native host, the port is in the allow list and the helper
//     can stop, not a replica, no tablespaces (v1), the data directory is
//     the agent user's, not a symlink or mount point, its parent writable,
//     free disk for a second copy (+10%), the repository answers and holds
//     the backup to start from. Nothing changes if any of it fails.
//  2. stop PostgreSQL through the helper and make sure it is stopped;
//  3. rename the data directory to <datadir>.before-rewind-<UTC> (same
//     directory, so the same filesystem: instant, no extra space);
//  4. pgbackrest restore into a fresh data directory with the original
//     mode, to the target, keeping production's archiving settings;
//  5. put back the configuration that lives in the data directory
//     (postgresql.auto.conf with Rowsafe's archive settings, and
//     postgresql.conf / pg_hba.conf / pg_ident.conf when they are there;
//     Debian keeps them in /etc);
//  6. replay WAL up to the target and promote, as the agent user on a
//     private socket (no TCP listener, so no application connects to a
//     half-recovered database, and no systemd start timeout can cut a long
//     replay short), then stop it cleanly;
//  7. start PostgreSQL through the helper and wait until it accepts
//     connections as a primary.
//
// Any failure after the stop puts the original data directory back and
// starts it (the rollback also runs when the agent restarts in the middle).
// The old data directory is kept aside for Undo, which swaps it back the
// same way, until it is deleted (Delete the old data now) or expires.

// inPlaceFacts are what the preflight reads from the running cluster.
type inPlaceFacts struct {
	DataDir     string
	Major       int
	InRecovery  bool
	Tablespaces int
	SizeBytes   int64
	Replicas    int
	ConfigFile  string
	HbaFile     string
	IdentFile   string
}

// inPlaceOps are the steps that touch PostgreSQL, the helper or pgBackRest
// (tests replace them; renames and files are always real).
type inPlaceOps interface {
	facts(ctx context.Context, db protocol.DatabaseSpec) (inPlaceFacts, error)
	// helper asks the root helper to stop or start db's unit.
	helper(ctx context.Context, action string, port int, id string) error
	// running reports whether a postmaster serves dataDir.
	running(dataDir string) bool
	// repo checks the repository answers and holds the backup set.
	repo(ctx context.Context, db protocol.DatabaseSpec, set string, which int) error
	restore(ctx context.Context, db protocol.DatabaseSpec, o pgbackrest.RestoreOptions) ([]byte, error)
	// recover starts the restored cluster privately, waits until it has
	// promoted, stops it and returns the last replayed commit time.
	recover(ctx context.Context, r privateRecovery) (*time.Time, error)
	// stopLocal stops a postmaster in dataDir with pg_ctl (rollback, when
	// the helper's stop didn't).
	stopLocal(dataDir string, major int) error
	// waitReady waits until db accepts connections as a primary.
	waitReady(ctx context.Context, db protocol.DatabaseSpec, dataDir string, timeout time.Duration) error
	freeBytes(path string) (int64, error)
}

// privateRecovery describes step 6.
type privateRecovery struct {
	DataDir    string
	Major      int
	Port       int
	SocketDir  string // private, 0700
	ConfigFile string // production's postgresql.conf when it lives outside the data directory
	LogFile    string
	Timeout    time.Duration
}

var (
	inPlaceStopWait  = 60 * time.Second // PostgreSQL gone after the helper's stop
	inPlaceReadyWait = 5 * time.Minute  // accepting connections after the start
	inPlacePoll      = time.Second
)

func (a *Agent) ops() inPlaceOps {
	if a.rewindOps != nil {
		return a.rewindOps
	}
	return realInPlaceOps{a}
}

// keptDirRE matches directories kept aside: <base>.before-rewind-<UTC> or
// <base>.after-rewind-<UTC>.
var keptDirRE = regexp.MustCompile(`^(.+)\.(before|after)-rewind-[0-9]{8}T[0-9]{6}Z$`)

func stampNow() string { return time.Now().UTC().Format("20060102T150405Z") }

// validKeptDir checks that kept is a directory kept aside for dataDir:
// next to it, named after it, a real directory the agent user owns.
func validKeptDir(dataDir, kept string) error {
	dataDir, kept = filepath.Clean(dataDir), filepath.Clean(kept)
	m := keptDirRE.FindStringSubmatch(filepath.Base(kept))
	inPlace := filepath.Dir(kept) == filepath.Dir(dataDir) || filepath.Dir(kept) == filepath.Join(dataDir, asideDirName) // Docker: rewind_contents.go
	if m == nil || m[1] != filepath.Base(dataDir) || !inPlace || kept == dataDir {
		return fmt.Errorf("refusing to touch %s: it is not a directory Rowsafe kept aside for %s", kept, dataDir)
	}
	info, err := os.Lstat(kept)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("refusing to touch %s: not a directory", kept)
	}
	if fileUID(info) != os.Getuid() {
		return fmt.Errorf("refusing to touch %s: it isn't owned by the agent's user", kept)
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// checkDataDir checks what steps 3 and 4 need of the data directory.
func checkDataDir(dataDir string) (os.FileInfo, error) {
	if !filepath.IsAbs(dataDir) || filepath.Clean(dataDir) != dataDir || dataDir == "/" {
		return nil, fmt.Errorf("unexpected data directory %q", dataDir)
	}
	info, err := os.Lstat(dataDir)
	if err != nil {
		return nil, fmt.Errorf("can't read the data directory %s: %w", dataDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("the data directory %s is a symbolic link; Rowsafe can't rewind it in place yet (restore a copy instead)", dataDir)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("the data directory %s is not a directory", dataDir)
	}
	if fileUID(info) != os.Getuid() {
		return nil, fmt.Errorf("the data directory %s isn't owned by the agent's user, so Rowsafe can't swap it", dataDir)
	}
	parent := filepath.Dir(dataDir)
	pinfo, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if devOf(pinfo) != devOf(info) {
		return nil, fmt.Errorf("the data directory %s is a mount point of its own; Rowsafe can't set it aside there yet (restore a copy instead)", dataDir)
	}
	probe, err := os.CreateTemp(parent, ".rowsafe-probe-*")
	if err != nil {
		return nil, fmt.Errorf("Rowsafe can't write in %s, where the old data would be kept aside: %v", parent, err)
	}
	probe.Close()
	os.Remove(probe.Name())
	return info, nil
}

func devOf(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev) //nolint:unconvert // int32 on darwin
	}
	return 0
}

// keepUntil clamps the keep days.
func keepUntil(days int, now time.Time) time.Time {
	if days <= 0 {
		days = defaultKeepDays
	}
	return now.Add(time.Duration(min(days, maxKeepDays)) * 24 * time.Hour)
}

// inPlaceAllowed checks the host side: native, the port listed, the helper
// set up and able to stop.
func (a *Agent) inPlaceAllowed(db protocol.DatabaseSpec) (string, error) {
	if a.cfg.Sidecar() {
		return a.dockerInPlaceAllowed() // docker_control.go
	}
	allowed, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", a.cfg.RestartAllowFile, err)
	}
	unit, ok := allowed[db.Port]
	if !ok {
		return "", fmt.Errorf("Rowsafe isn't allowed to stop PostgreSQL on port %d on this server, which a rewind in place needs. "+
			"Re-run the install command there and answer yes to \"Allow Rowsafe to restart or stop PostgreSQL when you ask?\" "+
			"(or restore a copy and bring back rows instead)", db.Port)
	}
	if st, err := os.Stat(a.cfg.RestartDir); err != nil || !st.IsDir() {
		return "", fmt.Errorf("the helper that stops PostgreSQL is not set up on this server (%s is missing): re-run the install command there", a.cfg.RestartDir)
	}
	if acts := a.helperActions(); len(acts) > 0 && !slices.Contains(acts, helperStop) {
		return "", errors.New("the helper that restarts PostgreSQL on this server is from an older Rowsafe and can't stop it. " +
			"Re-run the install command on the server to allow Rewind there")
	}
	return unit, nil
}

// rewindInPlace rewinds db's cluster to p.Target.
func (a *Agent) rewindInPlace(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl *taskLog) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !rewindIDRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	typ, target, set, err := rewindRestoreArgs(p.Target)
	if err != nil {
		return nil, err
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("another rewind is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	st := a.rewindState()
	if _, ok := st.get(p.RewindID); ok {
		return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
	}
	ops := a.ops()
	unit, err := a.inPlaceAllowed(db)
	if err != nil {
		return nil, err
	}

	// 1. Preflight: nothing has changed yet.
	f, err := ops.facts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading PostgreSQL's settings: %w", err)
	}
	switch {
	case f.InRecovery:
		return nil, errors.New("this PostgreSQL is a read-only replica; rewind the primary instead")
	case f.Tablespaces > 0:
		return nil, fmt.Errorf("this database uses %s; Rowsafe can't rewind those in place yet. Restore a copy and bring back rows instead",
			countNoun(f.Tablespaces, "tablespace", "tablespaces"))
	case f.Major == 0 || f.DataDir == "":
		return nil, errors.New("couldn't read the PostgreSQL version or data directory")
	}
	contents := a.contentsLayout() // Docker: move the entries inside the volume (rewind_contents.go)
	info, err := checkDataDirFor(contents, f.DataDir)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(f.DataDir)
	if contents {
		parent = f.DataDir
	}
	need := f.SizeBytes + f.SizeBytes/10
	if free, err := ops.freeBytes(parent); err != nil {
		return nil, err
	} else if free < need {
		return nil, fmt.Errorf("not enough free disk: rewinding keeps the current data aside for Undo, so it needs about %s free in %s (the database's size plus 10%%), and %s is free",
			humanBytes(need), parent, humanBytes(free))
	}
	if err := ops.repo(ctx, db, set, p.Target.Repo); err != nil {
		return nil, err
	}
	// One rewind in place runs at a time (inPlaceMu), so a fixed name.
	socketDir := filepath.Join(a.cfg.RewindDir, "inplace")
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(db.Port)); n > maxSocketPath {
		return nil, fmt.Errorf("the recovery socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_REWIND_DIR", n, maxSocketPath)
	}
	var warnings []string
	if f.Replicas > 0 {
		warnings = append(warnings, fmt.Sprintf("%s streamed from this server; after the rewind they no longer match it and have to be set up again",
			countNoun(f.Replicas, "replica", "replicas")))
	}
	kept := keptPath(contents, f.DataDir, "before")
	if exists(kept) {
		return nil, fmt.Errorf("%s already exists; try again in a second", kept)
	}
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, OldDataDir: kept, Warnings: warnings}
	rec := rewindRecord{ID: p.RewindID, Kind: protocol.RewindKindKeptData, DatabaseID: db.ID, Status: protocol.RewindInProgress,
		CreatedAt: time.Now().UTC(), Target: p.Target, Database: db, DataDir: f.DataDir, KeptDir: kept, Major: f.Major,
		Phase: phasePreflight, KeepDays: p.KeepDays, ConfigFile: f.ConfigFile, Contents: contents}
	if err := st.put(rec); err != nil {
		return nil, err
	}
	tl.Printf("preflight passed: PostgreSQL %d, data directory %s (%s), unit %s", f.Major, f.DataDir, humanBytes(f.SizeBytes), unit)
	phase := func(ph string) {
		if err := st.update(p.RewindID, func(r *rewindRecord) { r.Phase = ph }); err != nil {
			tl.Printf("recording progress: %v", err)
		}
	}
	fail := func(step string, cause error) (*protocol.RewindInPlaceResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		r, _ := st.get(p.RewindID)
		moved := exists(kept)
		if moved {
			tl.Printf("%s failed: %v; putting the original data back", step, cause)
		} else {
			tl.Printf("%s failed: %v", step, cause)
		}
		rbErr := a.rollbackRewind(context.WithoutCancel(ctx), r, tl)
		if rbErr != nil {
			res.Summary = fmt.Sprintf("Rewinding failed while %s: %v. Putting the original data back also failed: %v. "+
				"No data was deleted: your original data is in %s or %s; Rowsafe tries again when its agent restarts.", step, cause, rbErr, kept, f.DataDir)
			return res, errors.New(res.Summary)
		}
		res.RolledBack = moved
		res.OldDataDir = ""
		res.Summary = fmt.Sprintf("Rewinding failed while %s: %v. Rowsafe put the original data back and started PostgreSQL again; nothing was changed.",
			step, cause)
		if !moved {
			res.Summary = fmt.Sprintf("Rewinding failed while %s: %v. Nothing was changed; PostgreSQL runs as before.", step, cause)
		}
		return res, errors.New(res.Summary)
	}

	// 2. Stop.
	tl.Printf("stopping PostgreSQL (%s) through %s", unit, a.stopper())
	if err := ops.helper(ctx, helperStop, db.Port, p.RewindID+"-stop"); err != nil {
		if errors.Is(err, errOldHelper) && ops.running(f.DataDir) {
			_ = st.remove(p.RewindID)
			return nil, err
		}
		return fail("stopping PostgreSQL", err) // starts it again if it did stop
	}
	if err := waitStopped(ctx, ops, f.DataDir); err != nil {
		return fail("stopping PostgreSQL", err)
	}
	phase(phaseStopped)
	tl.Printf("PostgreSQL is stopped")

	// 3. Keep the data directory aside.
	if err := moveData(contents, f.DataDir, f.DataDir, kept); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			err = fmt.Errorf("the filesystem can't rename the data directory in place (%w); a container's overlay filesystem does this, "+
				"so rewinding in place needs the data directory on a volume (restore a copy instead)", err)
		}
		return fail("setting the current data aside", err)
	}
	phase(phaseMoved)
	tl.Printf("kept the current data aside in %s", kept)

	// 4. Restore into a fresh data directory.
	phase(phaseRestored) // from here the data directory is ours to remove
	restoreDir := f.DataDir
	if contents {
		// Docker: restore next to the data, then move it in (rewind_contents.go).
		restoreDir = stagingDir(f.DataDir, p.RewindID)
		if err := freshDir(restoreDir); err != nil {
			return fail("creating the new data directory", err)
		}
	} else {
		if err := os.Mkdir(f.DataDir, info.Mode().Perm()); err != nil {
			return fail("creating the new data directory", err)
		}
		if err := os.Chmod(f.DataDir, info.Mode().Perm()); err != nil {
			return fail("creating the new data directory", err)
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(f.DataDir, -1, int(st.Gid))
		}
	}
	tl.Printf("restoring %s (backup %s) into %s", describeTarget(p.Target), cmp.Or(set, "picked by pgBackRest"), restoreDir)
	out, err := ops.restore(ctx, db, pgbackrest.RestoreOptions{DataDir: restoreDir, Type: typ, Target: target, Set: set, Timeline: p.Target.Timeline, Repo: p.Target.Repo})
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fail("restoring the backup", err)
	}
	if contents {
		if err := moveData(true, f.DataDir, restoreDir, f.DataDir); err != nil {
			return fail("moving the restored data into place", err)
		}
		if err := retargetRestore(f.DataDir, restoreDir); err != nil {
			return fail("moving the restored data into place", err)
		}
	}

	// 5. Configuration that lives in the data directory.
	if err := keepConfig(kept, f, tl); err != nil {
		return fail("putting the configuration back", err)
	}

	// 6. Replay and promote privately.
	timeout := 4 * time.Hour
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-20*time.Minute, time.Minute)
	}
	pr := privateRecovery{DataDir: f.DataDir, Major: f.Major, Port: db.Port, SocketDir: socketDir,
		LogFile: filepath.Join(a.cfg.RewindDir, "inplace.log"), Timeout: timeout}
	if !strings.HasPrefix(f.ConfigFile, f.DataDir+string(filepath.Separator)) {
		pr.ConfigFile = f.ConfigFile
	}
	tl.Printf("replaying changes up to %s (private socket, no network connections)", describeTarget(p.Target))
	phase(phaseRecovering)
	recoveredTo, err := ops.recover(ctx, pr)
	if data, rerr := os.ReadFile(pr.LogFile); rerr == nil && err != nil {
		tl.Output("recovery log (tail)", tail(data, 8000))
	}
	_ = os.Remove(pr.LogFile)
	_ = os.RemoveAll(socketDir)
	if err != nil {
		if typ == "time" {
			err = fmt.Errorf("%w (if the time is after the last change that reached the backups, pick an earlier one)", err)
		}
		return fail("replaying changes", err)
	}
	res.RecoveredTo = recoveredTo

	// 7. Start.
	phase(phaseStarted)
	tl.Printf("starting PostgreSQL (%s) through %s", unit, a.stopper())
	if err := ops.helper(ctx, helperStart, db.Port, p.RewindID+"-start"); err != nil {
		if !strings.Contains(err.Error(), "did not finish") || !ops.running(f.DataDir) {
			return fail("starting PostgreSQL", err)
		}
	}
	if err := ops.waitReady(ctx, db, f.DataDir, inPlaceReadyWait); err != nil {
		return fail("starting PostgreSQL", err)
	}

	until := keepUntil(p.KeepDays, time.Now().UTC())
	size := dirSize(kept)
	if err := st.update(p.RewindID, func(r *rewindRecord) {
		r.Phase, r.Status, r.Expires, r.RecoveredTo, r.SizeBytes = phaseDone, protocol.RewindKeptBefore, until, recoveredTo, size
	}); err != nil {
		tl.Printf("recording the kept data: %v", err)
	}
	res.KeptUntil = &until
	res.DurationMs = time.Since(start).Milliseconds()
	to := describeTarget(p.Target)
	if recoveredTo != nil {
		to += " (last change kept: " + recoveredTo.UTC().Format("15:04:05 UTC") + ")"
	}
	res.Summary = fmt.Sprintf("Rewound the database to %s. The data from before the rewind (%s) is kept aside until %s so you can undo.",
		to, humanBytes(size), until.Format("2006-01-02 15:04 UTC"))
	for _, w := range warnings {
		res.Summary += " Note: " + w + "."
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// waitStopped waits until no postmaster serves dataDir.
func waitStopped(ctx context.Context, ops inPlaceOps, dataDir string) error {
	deadline := time.Now().Add(inPlaceStopWait)
	for ops.running(dataDir) {
		if time.Now().After(deadline) {
			return fmt.Errorf("PostgreSQL is still running from %s after %s", dataDir, inPlaceStopWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(inPlacePoll):
		}
	}
	return nil
}

// ensureStopped stops whatever runs in dataDir: through the helper, then
// with pg_ctl (our private recovery, or a unit the helper doesn't manage).
func (a *Agent) ensureStopped(ctx context.Context, ops inPlaceOps, r rewindRecord, tl *taskLog) error {
	if !ops.running(r.DataDir) {
		return nil
	}
	if err := ops.helper(ctx, helperStop, r.Database.Port, r.ID+"-rbstop"); err != nil {
		tl.Printf("stopping through the helper: %v", err)
	}
	if waitStopped(ctx, ops, r.DataDir) == nil {
		return nil
	}
	if err := ops.stopLocal(r.DataDir, r.Major); err != nil {
		return err
	}
	return waitStopped(ctx, ops, r.DataDir)
}

// rollbackRewind puts the original data directory back after a failed or
// interrupted rewind and starts it. It goes by what is on disk, not by the
// recorded phase: if the kept directory exists, whatever is at the data
// directory is the (partial) restore and is removed.
func (a *Agent) rollbackRewind(ctx context.Context, r rewindRecord, tl *taskLog) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	ops := a.ops()
	st := a.rewindState()
	if exists(r.KeptDir) {
		if err := validKeptDir(r.DataDir, r.KeptDir); err != nil {
			return err
		}
		if err := a.ensureStopped(ctx, ops, r, tl); err != nil {
			return fmt.Errorf("stopping PostgreSQL: %w", err)
		}
		// Docker: before phaseRestored the data directory holds what wasn't
		// moved aside yet: the original, which the kept part joins again.
		if dataPresent(r.Contents, r.DataDir) && !(r.Contents && phaseBefore(r.Phase, phaseRestored)) {
			failed := keptPath(r.Contents, r.DataDir, "failed")
			if err := moveData(r.Contents, r.DataDir, r.DataDir, failed); err != nil {
				return fmt.Errorf("moving the partial restore aside: %w", err)
			}
			_ = st.update(r.ID, func(x *rewindRecord) { x.FailedDir = failed })
		}
		if err := moveData(r.Contents, r.DataDir, r.KeptDir, r.DataDir); err != nil {
			return fmt.Errorf("moving %s back: %w", r.KeptDir, err)
		}
		tl.Printf("moved the original data back to %s", r.DataDir)
		if r.Phase == phaseRecovering || r.Phase == phaseStarted {
			// The restored data may have promoted and put its new
			// timeline's history in the repository: continue the original
			// on a newer timeline, or backups and restores would follow
			// the abandoned one.
			if err := a.newTimeline(ctx, ops, r, tl); err != nil {
				tl.Printf("moving the original data to a new timeline failed (%v); starting it as it is. "+
					"Take a full backup once it runs", err)
			}
		}
	}
	// Otherwise the data directory was never set aside (or is back
	// already): production's data is in place. Start it if it isn't
	// running; never stop it.
	if !ops.running(r.DataDir) {
		if !dataPresent(r.Contents, r.DataDir) {
			return fmt.Errorf("neither %s nor %s exists", r.DataDir, r.KeptDir)
		}
		if err := ops.helper(ctx, helperStart, r.Database.Port, r.ID+"-rbstart"); err != nil && !strings.Contains(err.Error(), "did not finish") {
			return fmt.Errorf("starting PostgreSQL: %w", err)
		}
	}
	if err := ops.waitReady(ctx, r.Database, r.DataDir, inPlaceReadyWait); err != nil {
		return fmt.Errorf("starting PostgreSQL: %w", err)
	}
	tl.Printf("PostgreSQL is running on the original data")
	if x, ok := st.get(r.ID); ok && x.FailedDir != "" {
		failed := x.FailedDir
		if isAsidePath(r.DataDir, failed, "failed") {
			if err := os.RemoveAll(failed); err != nil {
				tl.Printf("removing the partial restore %s: %v", failed, err)
			}
		}
	}
	if r.Contents {
		_ = os.RemoveAll(stagingDir(r.DataDir, r.ID))
		removeEmptyAsideRoot(r.DataDir)
	}
	return st.remove(r.ID)
}

// keepConfig puts production's current configuration into the restored data
// directory: postgresql.auto.conf (with pgBackRest's recovery settings
// added), and the other configuration files when they live in the data
// directory.
func keepConfig(kept string, f inPlaceFacts, tl *taskLog) error {
	current, err := os.ReadFile(filepath.Join(kept, "postgresql.auto.conf"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	autoPath := filepath.Join(f.DataDir, "postgresql.auto.conf")
	restored, err := os.ReadFile(autoPath)
	if err != nil {
		return fmt.Errorf("the restore wrote no postgresql.auto.conf: %w", err)
	}
	merged, ok := mergeAutoConf(string(current), string(restored))
	if !ok {
		tl.Printf("pgBackRest's recovery settings weren't where Rowsafe expected; keeping the restored postgresql.auto.conf")
	} else if err := writeFileAtomic(autoPath, []byte(merged), 0o600); err != nil {
		return err
	}
	for _, path := range []string{f.ConfigFile, f.HbaFile, f.IdentFile} {
		if !strings.HasPrefix(path, f.DataDir+string(filepath.Separator)) {
			continue // e.g. Debian's /etc/postgresql/...
		}
		rel := strings.TrimPrefix(path, f.DataDir+string(filepath.Separator))
		if err := copyConfFile(filepath.Join(kept, rel), filepath.Join(f.DataDir, rel)); err != nil {
			return err
		}
		tl.Printf("kept the current %s", rel)
	}
	return nil
}

func copyConfFile(from, to string) error {
	info, err := os.Lstat(from)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", from)
	}
	data, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(to, data, info.Mode().Perm())
}

// newTimeline moves the (stopped) cluster in r.DataDir to a new timeline:
// a short archive recovery to the end of its own WAL, as the agent user on
// a private socket, which ends by promoting to the next free timeline and
// archiving its history; then a clean stop. Undo and some rollbacks need
// it: once a rewind's timeline is in the repository, PostgreSQL's recovery
// (restore tests, copies, restores) follows the newest timeline, and the
// data put back must be on it. postgresql.auto.conf is left as it was.
func (a *Agent) newTimeline(ctx context.Context, ops inPlaceOps, r rewindRecord, tl *taskLog) error {
	cmd, err := pgbackrest.ArchiveGetCommand(a.cfg.PgBackRestBin, a.cfg.configPath(r.Database.Stanza), r.Database.Stanza)
	if err != nil {
		return err
	}
	autoPath := filepath.Join(r.DataDir, "postgresql.auto.conf")
	orig, err := os.ReadFile(autoPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	signal := filepath.Join(r.DataDir, "recovery.signal")
	defer func() {
		if err := writeFileAtomic(autoPath, orig, 0o600); err != nil {
			tl.Printf("putting postgresql.auto.conf back: %v", err)
		}
		_ = os.Remove(signal)
	}()
	block := "\n# Rowsafe: continue on a new timeline (removed again right after)\n" +
		renderSettings([]drillSetting{{"restore_command", cmd}, {"recovery_target_timeline", "current"}})
	if err := writeFileAtomic(autoPath, append(append([]byte{}, orig...), block...), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signal, nil, 0o600); err != nil {
		return err
	}
	pr := privateRecovery{DataDir: r.DataDir, Major: r.Major, Port: r.Database.Port, SocketDir: filepath.Join(a.cfg.RewindDir, "inplace"),
		LogFile: filepath.Join(a.cfg.RewindDir, "inplace.log"), Timeout: 30 * time.Minute}
	if !strings.HasPrefix(r.ConfigFile, r.DataDir+string(filepath.Separator)) {
		pr.ConfigFile = r.ConfigFile
	}
	tl.Printf("moving %s to a new timeline (a short recovery on a private socket)", r.DataDir)
	_, err = ops.recover(ctx, pr)
	if data, rerr := os.ReadFile(pr.LogFile); rerr == nil && err != nil {
		tl.Output("recovery log (tail)", tail(data, 8000))
	}
	_ = os.Remove(pr.LogFile)
	_ = os.RemoveAll(pr.SocketDir)
	return err
}

// recoverySettings are what pgBackRest's restore sets for recovery;
// production's current postgresql.auto.conf must not bring older ones.
var recoverySettings = []string{
	"restore_command", "recovery_target", "recovery_target_name", "recovery_target_time", "recovery_target_xid",
	"recovery_target_lsn", "recovery_target_inclusive", "recovery_target_timeline", "recovery_target_action",
	"primary_conninfo", "primary_slot_name", "standby_mode",
}

const pgbackrestRecoveryHeader = "# Recovery settings generated by pgBackRest restore"

// mergeAutoConf is production's current postgresql.auto.conf (its ALTER
// SYSTEM settings, Rowsafe's archiving among them) with any recovery
// settings commented out, followed by the recovery settings pgBackRest's
// restore wrote. ok is false when the restored file has no pgBackRest
// block.
func mergeAutoConf(current, restored string) (string, bool) {
	i := strings.Index(restored, pgbackrestRecoveryHeader)
	if i < 0 {
		return restored, false
	}
	block := restored[i:]
	var b strings.Builder
	for _, line := range strings.SplitAfter(current, "\n") {
		name, _, _ := strings.Cut(strings.TrimSpace(line), "=")
		if slices.Contains(recoverySettings, strings.ToLower(strings.TrimSpace(name))) {
			b.WriteString("# Removed by Rowsafe rewind: " + line)
			continue
		}
		b.WriteString(line)
	}
	if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(block)
	return b.String(), true
}

// ---- undo ----

func (a *Agent) rewindUndo(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl *taskLog) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	if !rewindIDRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("another rewind is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	st := a.rewindState()
	r, ok := st.get(p.RewindID)
	switch {
	case !ok || r.Kind != protocol.RewindKindKeptData:
		return nil, errors.New("there is nothing to undo: the data from before that rewind was already deleted")
	case r.DatabaseID != db.ID:
		return nil, errors.New("that rewind belongs to another database")
	case r.Status == protocol.RewindKeptAfterUndo:
		return nil, errors.New("that rewind was already undone")
	case r.Status != protocol.RewindKeptBefore:
		return nil, errors.New("that rewind hasn't finished")
	}
	for _, o := range st.all() {
		if o.Kind == protocol.RewindKindKeptData && o.DatabaseID == db.ID && o.ID != r.ID && o.CreatedAt.After(r.CreatedAt) {
			return nil, errors.New("the database was rewound again (or undone) since; only the latest rewind can be undone")
		}
	}
	ops := a.ops()
	unit, err := a.inPlaceAllowed(db)
	if err != nil {
		return nil, err
	}
	if err := validKeptDir(r.DataDir, r.KeptDir); err != nil {
		return nil, err
	}
	if _, err := checkDataDirFor(r.Contents, r.DataDir); err != nil {
		return nil, err
	}
	f, err := ops.facts(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading PostgreSQL's settings: %w", err)
	}
	if filepath.Clean(f.DataDir) != r.DataDir {
		return nil, fmt.Errorf("PostgreSQL now runs from %s, not %s", f.DataDir, r.DataDir)
	}
	aside := keptPath(r.Contents, r.DataDir, "after")
	if exists(aside) {
		return nil, fmt.Errorf("%s already exists; try again in a second", aside)
	}
	res := &protocol.RewindUndoResult{RewindID: r.ID}
	before := r
	if err := st.update(r.ID, func(x *rewindRecord) {
		x.Status, x.Undo, x.AsideDir, x.Phase, x.ConfigFile = protocol.RewindInProgress, true, aside, phasePreflight, f.ConfigFile
	}); err != nil {
		return nil, err
	}
	r, _ = st.get(r.ID)
	fail := func(step string, cause error) (*protocol.RewindUndoResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		tl.Printf("%s failed: %v; putting the data back as it was", step, cause)
		cur, _ := st.get(r.ID)
		if rbErr := a.rollbackUndo(context.WithoutCancel(ctx), cur, before, tl); rbErr != nil {
			res.Summary = fmt.Sprintf("Undoing the rewind failed while %s: %v. Putting things back also failed: %v. "+
				"No data was deleted: the rewound data is in %s or %s, the data from before the rewind in %s or %s; "+
				"Rowsafe tries again when its agent restarts.", step, cause, rbErr, r.DataDir, aside, r.KeptDir, r.DataDir)
			return res, errors.New(res.Summary)
		}
		res.RolledBack = true
		res.Summary = fmt.Sprintf("Undoing the rewind failed while %s: %v. Rowsafe put things back as they were and started PostgreSQL again.", step, cause)
		return res, errors.New(res.Summary)
	}
	phase := func(ph string) { _ = st.update(r.ID, func(x *rewindRecord) { x.Phase = ph }) }

	tl.Printf("stopping PostgreSQL (%s) through %s", unit, a.stopper())
	if err := ops.helper(ctx, helperStop, db.Port, r.ID+"-ustop"); err != nil {
		return fail("stopping PostgreSQL", err)
	}
	if err := waitStopped(ctx, ops, r.DataDir); err != nil {
		return fail("stopping PostgreSQL", err)
	}
	phase(phaseStopped)
	if err := moveData(r.Contents, r.DataDir, r.DataDir, aside); err != nil {
		return fail("setting the rewound data aside", err)
	}
	phase(phaseMoved)
	tl.Printf("kept the rewound data aside in %s", aside)
	if err := moveData(r.Contents, r.DataDir, r.KeptDir, r.DataDir); err != nil {
		return fail("moving the data from before the rewind back", err)
	}
	phase(phaseRestored)
	tl.Printf("moved the data from before the rewind back to %s", r.DataDir)
	// The rewind's timeline is in the repository; this data continues on a
	// newer one, so backups, restore tests and restores follow it.
	if err := a.newTimeline(ctx, ops, r, tl); err != nil {
		return fail("starting a new timeline for the data from before the rewind", err)
	}
	phase(phaseStarted)
	if err := ops.helper(ctx, helperStart, db.Port, r.ID+"-ustart"); err != nil {
		if !strings.Contains(err.Error(), "did not finish") || !ops.running(r.DataDir) {
			return fail("starting PostgreSQL", err)
		}
	}
	if err := ops.waitReady(ctx, db, r.DataDir, inPlaceReadyWait); err != nil {
		return fail("starting PostgreSQL", err)
	}
	until := keepUntil(r.KeepDays, time.Now().UTC())
	size := dirSize(aside)
	if err := st.update(r.ID, func(x *rewindRecord) {
		x.Status, x.KeptDir, x.AsideDir, x.Phase, x.Expires, x.SizeBytes = protocol.RewindKeptAfterUndo, aside, "", phaseDone, until, size
	}); err != nil {
		tl.Printf("recording the kept data: %v", err)
	}
	res.RewoundDataDir, res.KeptUntil = aside, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Undid the rewind: the database is back as it was before. The rewound data (with anything written to it since, %s) "+
		"is kept aside until %s.", humanBytes(size), until.Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rollbackUndo puts things back as they were before a failed undo: the
// rewound data at the data directory, the old data aside. It goes by what
// is on disk.
func (a *Agent) rollbackUndo(ctx context.Context, r, before rewindRecord, tl *taskLog) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	ops := a.ops()
	st := a.rewindState()
	if r.AsideDir != "" && exists(r.AsideDir) {
		if err := validKeptDir(r.DataDir, r.AsideDir); err != nil {
			return err
		}
		if err := a.ensureStopped(ctx, ops, r, tl); err != nil {
			return fmt.Errorf("stopping PostgreSQL: %w", err)
		}
		switch {
		case r.Contents && phaseBefore(r.Phase, phaseMoved):
			// Docker: the rewound data was being set aside entry by entry;
			// what is still in place joins the rest below.
		case dataPresent(r.Contents, r.DataDir):
			if exists(r.KeptDir) && !r.Contents {
				return fmt.Errorf("%s, %s and %s all exist; Rowsafe won't guess which is which", r.DataDir, r.KeptDir, r.AsideDir)
			}
			// The data from before the rewind was (partly, in Docker) moved in.
			if err := moveData(r.Contents, r.DataDir, r.DataDir, r.KeptDir); err != nil {
				return err
			}
		}
		if err := moveData(r.Contents, r.DataDir, r.AsideDir, r.DataDir); err != nil {
			return err
		}
		tl.Printf("moved the rewound data back to %s", r.DataDir)
	}
	if !ops.running(r.DataDir) {
		if err := ops.helper(ctx, helperStart, r.Database.Port, r.ID+"-urbstart"); err != nil && !strings.Contains(err.Error(), "did not finish") {
			return fmt.Errorf("starting PostgreSQL: %w", err)
		}
	}
	if err := ops.waitReady(ctx, r.Database, r.DataDir, inPlaceReadyWait); err != nil {
		return fmt.Errorf("starting PostgreSQL: %w", err)
	}
	return st.update(r.ID, func(x *rewindRecord) {
		x.Status, x.Undo, x.AsideDir, x.Phase = before.Status, false, "", phaseDone
		if x.Status == protocol.RewindInProgress || x.Status == "" {
			x.Status = protocol.RewindKeptBefore
		}
	})
}

// recoverInPlace finishes what an agent restart interrupted: a rewind or
// undo that was running is rolled back.
func (a *Agent) recoverInPlace(ctx context.Context, r rewindRecord) error {
	tl := &taskLog{}
	var err error
	if r.Undo {
		err = a.rollbackUndo(ctx, r, rewindRecord{Status: protocol.RewindKeptBefore}, tl)
	} else {
		err = a.rollbackRewind(ctx, r, tl)
	}
	for _, line := range strings.Split(strings.TrimSpace(tl.String()), "\n") {
		if line != "" {
			a.log.Warn("interrupted rewind: " + line)
		}
	}
	if err == nil {
		a.log.Warn("rolled back a rewind interrupted by an agent restart; PostgreSQL runs on the data it had before", "rewind_id", r.ID)
	}
	return err
}

// ---- cleanup ----

// removeKept deletes a kept data directory and forgets it. The caller holds
// inPlaceMu.
func (a *Agent) removeKept(r rewindRecord) (int64, error) {
	if err := validKeptDir(r.DataDir, r.KeptDir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, a.rewindState().remove(r.ID)
		}
		return 0, err
	}
	if a.ops().running(r.KeptDir) {
		return 0, fmt.Errorf("PostgreSQL is running from %s; Rowsafe won't delete it", r.KeptDir)
	}
	if err := os.RemoveAll(r.KeptDir); err != nil {
		return 0, err
	}
	if r.Contents {
		removeEmptyAsideRoot(r.DataDir)
	}
	return r.SizeBytes, a.rewindState().remove(r.ID)
}

func (a *Agent) rewindCleanup(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl *taskLog) (*protocol.RewindCleanupResult, error) {
	if !rewindIDRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("a rewind is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	res := &protocol.RewindCleanupResult{RewindID: p.RewindID}
	r, ok := a.rewindState().get(p.RewindID)
	switch {
	case !ok:
		res.Summary = "There was nothing to delete (it was already deleted)."
		tl.Printf("%s", res.Summary)
		return res, nil
	case r.Kind != protocol.RewindKindKeptData || r.DatabaseID != db.ID:
		return nil, errors.New("that rewind belongs to another database")
	case r.Status != protocol.RewindKeptBefore && r.Status != protocol.RewindKeptAfterUndo:
		return nil, errors.New("that rewind is still running")
	}
	freed, err := a.removeKept(r)
	if err != nil {
		return nil, err
	}
	res.Removed, res.FreedBytes = true, freed
	what := "the data from before the rewind"
	if r.Status == protocol.RewindKeptAfterUndo {
		what = "the rewound data set aside by Undo"
	}
	res.Summary = fmt.Sprintf("Deleted %s (%s); the rewind can no longer be undone.", what, humanBytes(freed))
	if r.Status == protocol.RewindKeptAfterUndo {
		res.Summary = fmt.Sprintf("Deleted %s (%s).", what, humanBytes(freed))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// ---- the real steps ----

type realInPlaceOps struct{ a *Agent }

func (o realInPlaceOps) facts(ctx context.Context, db protocol.DatabaseSpec) (inPlaceFacts, error) {
	var f inPlaceFacts
	conn, err := o.a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return f, err
	}
	defer closeConn(ctx, conn)
	var version int
	err = conn.QueryRow(ctx, `
		SELECT current_setting('data_directory'), current_setting('server_version_num')::int, pg_is_in_recovery(),
		       (SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default', 'pg_global'))::int,
		       (SELECT coalesce(sum(pg_database_size(oid)), 0) FROM pg_database)::bigint,
		       (SELECT count(*) FROM pg_stat_replication)::int,
		       current_setting('config_file'), current_setting('hba_file'), current_setting('ident_file')`).
		Scan(&f.DataDir, &version, &f.InRecovery, &f.Tablespaces, &f.SizeBytes, &f.Replicas, &f.ConfigFile, &f.HbaFile, &f.IdentFile)
	f.DataDir = filepath.Clean(f.DataDir)
	f.Major = version / 10000
	return f, err
}

func (o realInPlaceOps) helper(ctx context.Context, action string, port int, id string) error {
	if o.a.cfg.Sidecar() {
		return o.a.dockerHelper(ctx, action, id) // docker_control.go
	}
	res, err := o.a.askHelper(ctx, action, port, id)
	if err != nil {
		return err
	}
	if res["ok"] != "1" {
		return fmt.Errorf("the helper couldn't %s PostgreSQL: %s", action, cmp.Or(res["error"], "unknown error"))
	}
	return nil
}

func (o realInPlaceOps) running(dataDir string) bool {
	if o.a.cfg.Sidecar() {
		return o.a.dockerRunning(dataDir) // docker_control.go
	}
	return postmasterAlive(dataDir)
}

// postmasterAlive reports whether dataDir/postmaster.pid names a live
// process. Unlike postmasterFor it doesn't need the process's command line
// to name the directory exactly (units may start postgres with -D "dir/"):
// here a false "running" only makes Rowsafe wait, a false "stopped" would
// be dangerous.
func postmasterAlive(dataDir string) bool {
	data, err := os.ReadFile(filepath.Join(dataDir, "postmaster.pid"))
	if err != nil {
		return false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || pid <= 0 {
		return true // being written: assume it runs
	}
	err = syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func (o realInPlaceOps) repo(ctx context.Context, db protocol.DatabaseSpec, set string, which int) error {
	in, err := pginspect.Inspect(ctx, o.a.target(db))
	if err != nil {
		return err
	}
	if err := o.a.writeConfig(db, in); err != nil {
		return err
	}
	cli, err := o.a.repoCLI(db, which)
	if err != nil {
		return err
	}
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return fmt.Errorf("Rowsafe can't reach the backup repository from this server: %w", err)
	}
	return checkBackupSet(stanzas, db.Stanza, set)
}

func (o realInPlaceOps) restore(ctx context.Context, db protocol.DatabaseSpec, opts pgbackrest.RestoreOptions) ([]byte, error) {
	cli, err := o.a.repoCLI(db, opts.Repo)
	if err != nil {
		return nil, err
	}
	return cli.RestoreTo(ctx, opts)
}

func (o realInPlaceOps) recover(ctx context.Context, r privateRecovery) (*time.Time, error) {
	a := o.a
	_ = os.RemoveAll(r.SocketDir)
	if err := os.MkdirAll(r.SocketDir, 0o700); err != nil {
		return nil, err
	}
	pgCtl := a.cfg.pgBin(r.Major, "pg_ctl")
	// Production's own settings, except: no TCP listener, a private socket,
	// its own PID file, and the log in LogFile.
	opts := fmt.Sprintf("-c listen_addresses='' -c unix_socket_directories='%s' -c port=%d -c external_pid_file='%s' "+
		"-c logging_collector=off -c log_destination=stderr", r.SocketDir, r.Port, filepath.Join(r.SocketDir, "postmaster.pid"))
	if r.ConfigFile != "" {
		if !pgbackrestSafePath(r.ConfigFile) {
			return nil, fmt.Errorf("unexpected config file path %q", r.ConfigFile)
		}
		opts += " -c config_file='" + r.ConfigFile + "'"
	}
	if !pgbackrestSafePath(r.SocketDir) {
		return nil, fmt.Errorf("unexpected socket path %q", r.SocketDir)
	}
	out, err := a.runner.Run(ctx, pgCtl, "-D", r.DataDir, "-l", r.LogFile, "-o", opts, "-w", "-t", "60", "start")
	if err != nil && !strings.Contains(string(out), "still starting up") && !strings.Contains(string(out), "server did not start in time") {
		return nil, fmt.Errorf("PostgreSQL did not start on the restored data: %s", lastFatal(r.LogFile, err))
	}
	t := pginspect.Target{SocketDir: r.SocketDir, Port: r.Port, User: a.cfg.PGUser, AppName: rewindAppName}
	conn, err := a.waitForScratch(ctx, t, pgCtl, r.DataDir, time.Now().Add(r.Timeout))
	if err != nil {
		_ = o.stopLocal(r.DataDir, r.Major)
		return nil, fmt.Errorf("%s", lastFatal(r.LogFile, err))
	}
	var recoveredTo *time.Time
	err = conn.QueryRow(ctx, `SELECT pg_last_xact_replay_timestamp()`).Scan(&recoveredTo)
	closeConn(ctx, conn)
	if err != nil {
		_ = o.stopLocal(r.DataDir, r.Major)
		return nil, err
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 11*time.Minute)
	defer cancel()
	if out, err := a.runner.Run(sctx, pgCtl, "-D", r.DataDir, "-m", "fast", "-w", "-t", "600", "stop"); err != nil {
		return nil, fmt.Errorf("stopping PostgreSQL after the replay: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if recoveredTo != nil {
		utc := recoveredTo.UTC()
		recoveredTo = &utc
	}
	return recoveredTo, nil
}

// lastFatal is PostgreSQL's last FATAL or PANIC message in its log (e.g.
// "recovery ended before configured recovery target was reached"), or err.
func lastFatal(logFile string, err error) string {
	data, rerr := os.ReadFile(logFile)
	if rerr == nil {
		lines := strings.Split(string(data), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			for _, level := range []string{"FATAL:", "PANIC:"} {
				if j := strings.Index(lines[i], level); j >= 0 {
					return "PostgreSQL said: " + strings.TrimSpace(lines[i][j+len(level):])
				}
			}
		}
	}
	return err.Error()
}

// pgbackrestSafePath accepts paths safe inside a single-quoted -c option.
func pgbackrestSafePath(p string) bool { return safeOptPathRE.MatchString(p) }

var safeOptPathRE = regexp.MustCompile(`^/[A-Za-z0-9/_.@+-]+$`)

func (o realInPlaceOps) stopLocal(dataDir string, major int) error {
	if o.a.cfg.Sidecar() && !localPostmaster(dataDir) {
		if exists(filepath.Join(dataDir, "postmaster.pid")) {
			return errNotLocalPostmaster
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
	defer cancel()
	out, err := o.a.runner.Run(ctx, o.a.cfg.pgBin(major, "pg_ctl"), "-D", dataDir, "-m", "fast", "-w", "-t", "600", "stop")
	if err != nil && postmasterAlive(dataDir) {
		return fmt.Errorf("pg_ctl stop: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (o realInPlaceOps) waitReady(ctx context.Context, db protocol.DatabaseSpec, dataDir string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		conn, err := o.a.target(db).Connect(ctx, "postgres")
		if err == nil {
			var inRecovery bool
			err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery()`).Scan(&inRecovery)
			closeConn(ctx, conn)
			if err == nil && !inRecovery {
				return nil
			}
			if err == nil {
				err = errors.New("still in recovery")
			}
		}
		last = err
		if time.Now().After(deadline) {
			return fmt.Errorf("PostgreSQL didn't accept connections within %s: %w", timeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * inPlacePoll):
		}
	}
}

func (o realInPlaceOps) freeBytes(path string) (int64, error) { return freeBytes(path) }
