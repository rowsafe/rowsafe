package agent

import (
	"cmp"
	"context"
	"encoding/json"
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

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restoring a fork on this server.
//
// The cluster that receives the fork is either created for it by the root
// helper (fork_helper.go) or an existing empty one the helper may stop and
// start. Its own data directory is renamed aside (same filesystem: instant),
// the source is restored in its place to the chosen point, and replayed and
// promoted privately: a Unix socket in the agent's own directory and no TCP
// listener, so nobody can connect before it is masked. Only then is it
// started for real, through the helper.
//
// The fork never writes into the source's repository: the pgBackRest config
// that reads the source's backups (with the handed-over bucket settings on
// another server) is removed as soon as the replay is done, and the fork's
// archive_command discards WAL until the control plane turns on its own
// backups (its own stanza, this server's bucket and passphrase). Any failure
// after the stop puts the cluster's own data back and starts it; an agent
// restart in the middle does the same.

// forkReadyWait is how long a fork started for real may take to answer.
var forkReadyWait = 10 * time.Minute

// forkStanzaRE is a source stanza the agent accepts.
var forkStanzaRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// forkOps are the fork steps that touch PostgreSQL, the helper or
// pgBackRest (tests replace them; files and renames are always real).
type forkOps interface {
	facts(ctx context.Context, db protocol.DatabaseSpec) (inPlaceFacts, error)
	usage(ctx context.Context, db protocol.DatabaseSpec) (clusterUsage, error)
	sourceFacts(ctx context.Context, db protocol.DatabaseSpec) (primaryFacts, error)
	helper(ctx context.Context, action string, port int, id string) error
	createCluster(ctx context.Context, port, major int, name, id string) (string, error)
	running(dataDir string) bool
	stopLocal(dataDir string, major int) error
	freeBytes(path string) (int64, error)
	sourceInfo(ctx context.Context, cli pgbackrest.CLI) ([]pgbackrest.Stanza, error)
	restore(ctx context.Context, cli pgbackrest.CLI, o pgbackrest.RestoreOptions) ([]byte, error)
	// recover replays privately and promotes, runs during on the promoted
	// cluster, then stops it.
	recover(ctx context.Context, pr privateRecovery, during func(ctx context.Context, t pginspect.Target) error) (*time.Time, error)
	waitReady(ctx context.Context, db protocol.DatabaseSpec, dataDir string, timeout time.Duration) error
	databases(ctx context.Context, db protocol.DatabaseSpec) ([]protocol.DBInfo, error)
}

func (a *Agent) fops() forkOps {
	if a.fkOps != nil {
		return a.fkOps
	}
	return realForkOps{realStandbyOps{realInPlaceOps{a}}}
}

type realForkOps struct{ realStandbyOps }

func (o realForkOps) sourceFacts(ctx context.Context, db protocol.DatabaseSpec) (primaryFacts, error) {
	return o.a.readPrimaryFacts(ctx, db)
}

func (o realForkOps) createCluster(ctx context.Context, port, major int, name, id string) (string, error) {
	return o.a.askCreateCluster(ctx, port, major, name, id)
}

func (o realForkOps) sourceInfo(ctx context.Context, cli pgbackrest.CLI) ([]pgbackrest.Stanza, error) {
	return cli.Info(ctx)
}

func (o realForkOps) restore(ctx context.Context, cli pgbackrest.CLI, opts pgbackrest.RestoreOptions) ([]byte, error) {
	return cli.RestoreTo(ctx, opts)
}

func (o realForkOps) databases(ctx context.Context, db protocol.DatabaseSpec) ([]protocol.DBInfo, error) {
	t := o.a.target(db)
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return nil, err
	}
	defer closeConn(ctx, conn)
	return pginspect.Databases(ctx, t, conn)
}

// recover is the rewind's private recovery (rewind_inplace.go) that keeps
// the promoted cluster up for during.
func (o realForkOps) recover(ctx context.Context, r privateRecovery, during func(ctx context.Context, t pginspect.Target) error) (*time.Time, error) {
	a := o.a
	_ = os.RemoveAll(r.SocketDir)
	if err := os.MkdirAll(r.SocketDir, 0o700); err != nil {
		return nil, err
	}
	if !pgbackrestSafePath(r.SocketDir) {
		return nil, fmt.Errorf("unexpected socket path %q", r.SocketDir)
	}
	pgCtl := a.cfg.pgBin(r.Major, "pg_ctl")
	opts := fmt.Sprintf("-c listen_addresses='' -c unix_socket_directories='%s' -c port=%d -c external_pid_file='%s' "+
		"-c logging_collector=off -c log_destination=stderr", r.SocketDir, r.Port, filepath.Join(r.SocketDir, "postmaster.pid"))
	if r.ConfigFile != "" {
		if !pgbackrestSafePath(r.ConfigFile) {
			return nil, fmt.Errorf("unexpected config file path %q", r.ConfigFile)
		}
		opts += " -c config_file='" + r.ConfigFile + "'"
	}
	out, err := a.runner.Run(ctx, niceWrap()[0], append(niceWrap()[1:], pgCtl, "-D", r.DataDir, "-l", r.LogFile, "-o", opts, "-w", "-t", "60", "start")...)
	if err != nil && !strings.Contains(string(out), "still starting up") && !strings.Contains(string(out), "server did not start in time") {
		return nil, fmt.Errorf("PostgreSQL did not start on the restored data: %s", lastFatal(r.LogFile, err))
	}
	stop := func() error {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 11*time.Minute)
		defer cancel()
		if out, err := a.runner.Run(sctx, pgCtl, "-D", r.DataDir, "-m", "fast", "-w", "-t", "600", "stop"); err != nil && postmasterAlive(r.DataDir) {
			return fmt.Errorf("stopping PostgreSQL after the replay: %w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	t := pginspect.Target{SocketDir: r.SocketDir, Port: r.Port, User: a.cfg.PGUser, AppName: rewindAppName}
	conn, err := a.waitForScratch(ctx, t, pgCtl, r.DataDir, time.Now().Add(r.Timeout))
	if err != nil {
		_ = stop()
		return nil, fmt.Errorf("%s", lastFatal(r.LogFile, err))
	}
	var recoveredTo *time.Time
	err = conn.QueryRow(ctx, `SELECT pg_last_xact_replay_timestamp()`).Scan(&recoveredTo)
	closeConn(ctx, conn)
	if err == nil && during != nil {
		err = during(ctx, t)
	}
	if serr := stop(); err == nil {
		err = serr
	}
	if err != nil {
		return nil, err
	}
	if recoveredTo != nil {
		utc := recoveredTo.UTC()
		recoveredTo = &utc
	}
	return recoveredTo, nil
}

// forkSource is what the target knows about the source.
type forkSource struct {
	repo      pgbackrest.Repo
	major     int
	sizeBytes int64
	settings  map[string]int
}

// forkSourceFor opens the handoff (another server) or reads the source here
// (this server: nothing moved).
func (a *Agent) forkSourceFor(ctx context.Context, ops forkOps, p protocol.ForkRestoreParams, tl *taskLog) (forkSource, error) {
	s := forkSource{major: p.Major, sizeBytes: p.SizeBytes, settings: p.Settings}
	if p.Box == nil {
		if a.cfg.Sidecar() {
			return s, errors.New("a Docker fork target restores from another server's backups: the source's sealed bucket settings are missing")
		}
		f, err := ops.sourceFacts(ctx, p.Source)
		if err != nil {
			return s, fmt.Errorf("reading the source database on this server: %w", err)
		}
		if f.InRecovery {
			return s, errors.New("the source is a standby; fork its primary instead")
		}
		if f.Tablespaces > 0 {
			return s, fmt.Errorf("the source uses %s; Rowsafe can't fork those yet", countNoun(f.Tablespaces, "tablespace", "tablespaces"))
		}
		s.major, s.sizeBytes, s.settings = f.Major, f.SizeBytes, f.Settings
		s.repo = a.repoFor(p.Source)
		tl.Printf("the source %s runs on this server (PostgreSQL %d, %s): its backups are read with this server's own settings; nothing leaves the server",
			cmp.Or(p.Source.Name, p.Source.Stanza), s.major, humanBytes(s.sizeBytes))
	} else {
		rt := a.sb()
		if rt.key == nil {
			return s, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
		}
		if err := a.peerAllowed(p.Box.SenderKey, "the source's server"); err != nil {
			return s, err
		}
		plain, err := handoff.Open(rt.key, *p.Box, protocol.HandoffPurposeFork, protocol.ForkHandoffContext(p.Source.ID, p.ForkID), p.SenderKey)
		if err != nil {
			return s, fmt.Errorf("opening the source server's sealed bucket settings: %w", err)
		}
		var sec protocol.ForkSecrets
		err = json.Unmarshal(plain, &sec)
		clear(plain)
		if err != nil {
			return s, fmt.Errorf("reading the source server's handoff: %w", err)
		}
		r := sec.Repo
		s.repo = pgbackrest.Repo{Endpoint: r.Endpoint, Bucket: r.Bucket, Region: r.Region, Key: r.Key, KeySecret: r.KeySecret,
			CipherPass: r.CipherPass, PathPrefix: r.PathPrefix, URIStyle: r.URIStyle, Port: r.Port, SkipTLSVerify: r.SkipTLSVerify}
		if r.CAPEM != "" {
			ca := filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+"-ca.pem")
			if err := writeFileAtomic(ca, []byte(r.CAPEM), 0o600); err != nil {
				return s, err
			}
			s.repo.CAFile = ca
		}
		tl.Printf("opened the source server's sealed bucket settings (read access to %s's backups)", cmp.Or(p.Source.Name, p.Source.Stanza))
	}
	if err := s.repo.Validate(); err != nil {
		return s, fmt.Errorf("the source's backup settings: %w", err)
	}
	if s.major < 13 {
		return s, errors.New("the source's PostgreSQL version is unknown")
	}
	return s, nil
}

// forkAutoConf is Rowsafe's part of the fork's postgresql.auto.conf (the
// last setting wins): its port, WAL archiving on but discarding (its own
// backups are turned on once it is registered), the settings recovery needs
// at least as high as on the source, and the preloaded libraries this
// server has.
func forkAutoConf(port, major int, settings map[string]int, preload string, preloadSet bool) string {
	s := []drillSetting{{"port", strconv.Itoa(port)}, {"archive_mode", "on"}, {"archive_command", "true"}}
	if major >= 15 {
		s = append(s, drillSetting{"archive_library", ""})
	}
	for _, name := range hotStandbySettings {
		if v, ok := settings[name]; ok && v > 0 {
			s = append(s, drillSetting{name, strconv.Itoa(v)})
		}
	}
	if preloadSet {
		s = append(s, drillSetting{"shared_preload_libraries", preload})
	}
	return "\n# Rowsafe fork: archiving is off until the fork's own backups are turned on.\n" + renderSettings(s)
}

var autoConfPreloadRE = regexp.MustCompile(`(?m)^\s*shared_preload_libraries\s*=\s*'([^']*)'`)

// installedPreload keeps the libraries of a shared_preload_libraries value
// that are installed in pkgLibDir; missing are the others.
func installedPreload(value, pkgLibDir string) (keep string, missing []string) {
	var kept []string
	for _, lib := range strings.Split(value, ",") {
		lib = strings.Trim(strings.TrimSpace(lib), `"`)
		if lib == "" {
			continue
		}
		name := strings.TrimSuffix(filepath.Base(lib), ".so")
		if pkgLibDir == "" || exists(filepath.Join(pkgLibDir, name+".so")) || (filepath.IsAbs(lib) && exists(lib)) {
			kept = append(kept, lib)
		} else {
			missing = append(missing, name)
		}
	}
	return strings.Join(kept, ","), missing
}

// resetRecoverySQL removes the recovery settings pgBackRest wrote (they
// name the source's backups) from the promoted fork.
var resetRecoverySQL = []string{
	"ALTER SYSTEM RESET restore_command", "ALTER SYSTEM RESET recovery_target_time", "ALTER SYSTEM RESET recovery_target_name",
	"ALTER SYSTEM RESET recovery_target_action", "ALTER SYSTEM RESET recovery_target_timeline", "ALTER SYSTEM RESET recovery_target",
	"ALTER SYSTEM RESET recovery_target_inclusive",
}

func (a *Agent) forkRestore(ctx context.Context, p protocol.ForkRestoreParams, tl *taskLog) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	switch {
	case !forkIDRE.MatchString(p.ForkID):
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	case !forkNameRE.MatchString(p.Name):
		return nil, fmt.Errorf("invalid fork name %q", p.Name)
	case !forkStanzaRE.MatchString(p.Source.Stanza):
		return nil, errors.New("the fork names no source database")
	}
	typ, target, set, err := rewindRestoreArgs(p.Target)
	if err != nil {
		return nil, err
	}
	rt := a.fk()
	if !rt.opMu.TryLock() {
		return nil, errors.New("another fork is being restored on this server; try again when it has finished")
	}
	defer rt.opMu.Unlock()
	defer func() {
		rt.mu.Lock()
		delete(rt.progress, p.ForkID)
		rt.mu.Unlock()
	}()
	ops := a.fops()
	switch {
	case p.Placement == protocol.ForkDocker && !a.cfg.Sidecar():
		return nil, errors.New("this server isn't a Docker fork target")
	case p.Placement != protocol.ForkDocker && a.cfg.Sidecar():
		return nil, errors.New("PostgreSQL runs in Docker here: set up a Docker fork target (see the Fork guide) and fork to it")
	case p.Placement != protocol.ForkDocker && p.Placement != protocol.ForkNewCluster && p.Placement != protocol.ForkEmptyCluster:
		return nil, fmt.Errorf("unknown fork placement %q", p.Placement)
	}
	rt.step(p.ForkID, protocol.ForkStepCluster, "Checking the source's backups")
	src, err := a.forkSourceFor(ctx, ops, p, tl)
	defer func() { // the source's CA bundle (another server) goes with the restore
		_ = os.Remove(filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+"-ca.pem"))
	}()
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(a.cfg.pgBin(src.major, "postgres")); err != nil {
		return nil, fmt.Errorf("PostgreSQL %d isn't installed on this server, and the fork needs the same major version as the source", src.major)
	}

	rec := forkRecord{ID: p.ForkID, Placement: p.Placement, Major: src.major, Phase: phasePreflight, StartedAt: time.Now().UTC(),
		Private: filepath.Join(a.cfg.StateDir, "fork", p.ForkID)}
	var pkgLibDir string
	switch p.Placement {
	case protocol.ForkDocker:
		return a.forkRestoreDocker(ctx, ops, p, src, rec, typ, target, set, start, tl)
	case protocol.ForkNewCluster:
		if err := a.forkCreateCluster(ctx, ops, p, &rec, tl); err != nil {
			return nil, err
		}
		pkgLibDir = filepath.Join(filepath.Dir(filepath.Dir(a.cfg.pgBin(src.major, "postgres"))), "lib")
	case protocol.ForkEmptyCluster:
		u, err := a.forkTakeCluster(ctx, ops, p, src, &rec)
		if err != nil {
			return nil, err
		}
		pkgLibDir = u.PkgLibDir
		src.settings = mergeSettings(src.settings, u.Settings)
	}
	db := protocol.DatabaseSpec{Name: p.Name, Port: rec.Port, SocketDir: rec.SocketDir}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: rec.Port, SocketDir: rec.SocketDir, DataDir: rec.DataDir,
		Major: src.major, Unit: rec.Unit, Created: rec.Created}
	if rec.Created {
		tl.Printf("created PostgreSQL %d cluster %s on port %d (%s)", src.major, filepath.Base(rec.DataDir), rec.Port, rec.Unit)
	}

	// Preflight: nothing is stopped or moved if any of it fails.
	parent := filepath.Dir(rec.DataDir)
	need := src.sizeBytes + src.sizeBytes/10 + 256<<20
	if free, err := ops.freeBytes(parent); err != nil {
		return a.forkPreflightFailed(ctx, rec, res, err, tl)
	} else if free < need {
		return a.forkPreflightFailed(ctx, rec, res, fmt.Errorf("not enough free disk in %s: the fork needs about %s (the source's size plus 10%%) and %s is free",
			parent, humanBytes(need), humanBytes(free)), tl)
	}
	socketDir := filepath.Join(rec.Private, "socket")
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(rec.Port)); n > maxSocketPath {
		return a.forkPreflightFailed(ctx, rec, res, fmt.Errorf("the fork's private socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_STATE_DIR", n, maxSocketPath), tl)
	}
	if err := os.MkdirAll(rec.Private, 0o700); err != nil {
		return a.forkPreflightFailed(ctx, rec, res, err, tl)
	}
	rec.SourceConf = filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+".conf")
	if err := a.writeForkSourceConf(rec, p.Source, src.repo, socketDir); err != nil {
		return a.forkPreflightFailed(ctx, rec, res, err, tl)
	}
	if err := rt.put(rec); err != nil {
		return a.forkPreflightFailed(ctx, rec, res, err, tl)
	}
	cli := pgbackrest.CLI{Bin: a.cfg.PgBackRestBin, ConfigPath: rec.SourceConf, Stanza: p.Source.Stanza, Runner: a.runner}
	stanzas, err := ops.sourceInfo(ctx, cli)
	if err != nil {
		return a.forkPreflightFailed(ctx, rec, res, fmt.Errorf("Rowsafe can't read %s's backups from this server: %w", cmp.Or(p.Source.Name, p.Source.Stanza), err), tl)
	}
	if err := checkBackupSet(stanzas, p.Source.Stanza, set); err != nil {
		return a.forkPreflightFailed(ctx, rec, res, err, tl)
	}

	fail := func(step string, cause error) (*protocol.ForkRestoreResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		r := rec
		tl.Printf("%s failed: %v", step, cause)
		if rbErr := a.rollbackFork(context.WithoutCancel(ctx), r, tl); rbErr != nil {
			res.Summary = fmt.Sprintf("Forking failed while %s: %v. Putting the cluster back also failed: %v. No data was deleted; "+
				"Rowsafe tries again when its agent restarts.", step, cause, rbErr)
			return res, errors.New(res.Summary)
		}
		_ = rt.remove(p.ForkID)
		res.Summary = fmt.Sprintf("Forking failed while %s: %v. Nothing else changed on the server.", step, cause)
		if rec.KeptDir != "" && !rec.Created {
			res.Summary = fmt.Sprintf("Forking failed while %s: %v. The cluster on port %d has its own data back and runs as before.", step, cause, rec.Port)
		}
		return res, errors.New(res.Summary)
	}
	save := func(phase string) {
		rec.Phase = phase
		if err := rt.put(rec); err != nil {
			tl.Printf("recording progress: %v", err)
		}
	}

	// Stop (an empty cluster runs; a new one doesn't).
	if ops.running(rec.DataDir) {
		tl.Printf("stopping PostgreSQL on port %d through the root helper", rec.Port)
		if err := ops.helper(ctx, helperStop, rec.Port, p.ForkID+"-stop"); err != nil {
			return fail("stopping PostgreSQL", err)
		}
		if err := waitForkStopped(ctx, ops, rec.DataDir); err != nil {
			return fail("stopping PostgreSQL", err)
		}
	}
	save(phaseStopped)

	// Set the cluster's own data aside.
	info, err := checkDataDir(rec.DataDir)
	if err != nil {
		return fail("checking the data directory", err)
	}
	rec.KeptDir = rec.DataDir + ".before-fork-" + stampNow()
	save(phaseMoved)
	if err := os.Rename(rec.DataDir, rec.KeptDir); err != nil {
		rec.KeptDir = ""
		save(phaseStopped)
		if errors.Is(err, syscall.EXDEV) {
			err = fmt.Errorf("the filesystem can't rename the data directory in place (%w)", err)
		}
		return fail("setting the cluster's own data aside", err)
	}

	// Restore.
	save(phaseRestored)
	if err := os.Mkdir(rec.DataDir, info.Mode().Perm()); err != nil {
		return fail("creating the fork's data directory", err)
	}
	_ = os.Chmod(rec.DataDir, info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(rec.DataDir, -1, int(st.Gid))
	}
	rt.step(p.ForkID, protocol.ForkStepRestore, fmt.Sprintf("Downloading %s's backup (%s)", cmp.Or(p.Source.Name, p.Source.Stanza), humanBytes(src.sizeBytes)))
	tl.Printf("restoring %s as it was at %s (backup %s) into %s", cmp.Or(p.Source.Name, p.Source.Stanza), describeTarget(p.Target),
		cmp.Or(set, "picked by pgBackRest"), rec.DataDir)
	cli.Wrap = niceWrap()
	out, err := ops.restore(ctx, cli, pgbackrest.RestoreOptions{DataDir: rec.DataDir, TablespaceDir: filepath.Join(rec.Private, "tablespaces"),
		Type: typ, Target: target, Set: set, Timeline: p.Target.Timeline})
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fail("restoring the backup", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(rec.DataDir, "pg_tblspc")); len(entries) > 0 {
		return fail("restoring the backup", errors.New("the source uses tablespaces, which Rowsafe can't fork yet"))
	}
	// Configuration that lives in the data directory stays this cluster's
	// own (port, listen addresses, access rules).
	for _, path := range []string{rec.ConfigFile, rec.HbaFile, rec.IdentFile} {
		if path == "" || !strings.HasPrefix(path, rec.DataDir+string(filepath.Separator)) {
			continue
		}
		rel := strings.TrimPrefix(path, rec.DataDir+string(filepath.Separator))
		if err := copyConfFile(filepath.Join(rec.KeptDir, rel), filepath.Join(rec.DataDir, rel)); err != nil {
			return fail("keeping the cluster's configuration", err)
		}
	}
	if w, err := a.writeForkAutoConf(rec, src, pkgLibDir); err != nil {
		return fail("configuring the fork", err)
	} else if w != "" {
		res.Warnings = append(res.Warnings, w)
		tl.Printf("%s", w)
	}

	// Replay and promote privately, mask, stop.
	save(phaseRecovering)
	rt.step(p.ForkID, protocol.ForkStepRecover, "Replaying changes up to "+describeTarget(p.Target))
	recoveredTo, masking, err := a.forkRecover(ctx, ops, p, rec, socketDir, tl)
	_ = os.Remove(rec.SourceConf) // the source's backups aren't needed any more
	rec.SourceConf = ""
	save(phaseRecovering)
	if err != nil {
		if typ == "time" && strings.Contains(err.Error(), "recovery") {
			err = fmt.Errorf("%w (if the time is after the last change that reached the backups, pick an earlier one)", err)
		}
		return fail("replaying changes", err)
	}
	res.RecoveredTo, res.Masking = recoveredTo, masking

	// Start for real.
	save(phaseStarted)
	rt.step(p.ForkID, protocol.ForkStepStart, fmt.Sprintf("Starting the fork on port %d", rec.Port))
	tl.Printf("starting the fork on port %d through the root helper", rec.Port)
	if err := ops.helper(ctx, helperStart, rec.Port, p.ForkID+"-start"); err != nil {
		if !strings.Contains(err.Error(), "did not finish") || !ops.running(rec.DataDir) {
			return fail("starting the fork", err)
		}
	}
	if err := ops.waitReady(ctx, db, rec.DataDir, forkReadyWait); err != nil {
		return fail("starting the fork", err)
	}
	a.finishFork(ctx, ops, db, rec, res, start, tl)
	return res, nil
}

// mergeSettings keeps the higher value of each setting.
func mergeSettings(a, b map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = max(out[k], v)
	}
	return out
}

// forkPreflightFailed undoes what the preflight did (a created cluster is
// started, empty, so it can take the next fork).
func (a *Agent) forkPreflightFailed(ctx context.Context, rec forkRecord, res *protocol.ForkRestoreResult, err error, tl *taskLog) (*protocol.ForkRestoreResult, error) {
	rec.Phase = phasePreflight
	if rbErr := a.rollbackFork(context.WithoutCancel(ctx), rec, tl); rbErr != nil {
		tl.Printf("cleaning up: %v", rbErr)
	}
	_ = a.fk().remove(rec.ID)
	if rec.Created {
		res.Summary = fmt.Sprintf("Forking failed: %v. The new, empty cluster on port %d stays for the next try.", err, rec.Port)
		return res, errors.New(res.Summary)
	}
	return nil, err
}

// forkCreateCluster asks the root helper for a new cluster.
func (a *Agent) forkCreateCluster(ctx context.Context, ops forkOps, p protocol.ForkRestoreParams, rec *forkRecord, tl *taskLog) error {
	lo, hi, ok := createClusterPorts(a.cfg.CreateClusterAllowFile)
	if !ok {
		return errors.New("creating PostgreSQL clusters isn't allowed on this server: re-run the install command there and allow Rowsafe " +
			"to create PostgreSQL clusters (or fork into an empty cluster)")
	}
	if !slices.Contains(a.helperActionsAny(), helperCreateCluster) {
		return errors.New("the root helper on this server can't create clusters yet: re-run the install command there")
	}
	port := p.Port
	if port == 0 {
		free := a.freeClusterPorts(lo, hi, 1)
		if len(free) == 0 {
			return fmt.Errorf("no free port between %d and %d for the fork's cluster", lo, hi)
		}
		port = free[0]
	} else if port < lo || port > hi {
		return fmt.Errorf("port %d is outside the ports Rowsafe may create clusters on here (%d-%d)", port, lo, hi)
	} else if debianClusterPorts()[port] || !portFree(port) {
		return fmt.Errorf("port %d is already used on this server; pick another", port)
	}
	name := forkClusterName(p.Name, rec.Major)
	rt := a.fk()
	rt.step(p.ForkID, protocol.ForkStepCluster, fmt.Sprintf("Creating a PostgreSQL %d cluster on port %d", rec.Major, port))
	tl.Printf("asking the root helper to create PostgreSQL %d cluster %s on port %d", rec.Major, name, port)
	unit, err := ops.createCluster(ctx, port, rec.Major, name, p.ForkID+"-create")
	if err != nil {
		return err
	}
	cc, err := readCreatedCluster(rec.Major, name)
	if err != nil {
		return err
	}
	rec.Port, rec.DataDir, rec.ConfigFile, rec.HbaFile, rec.IdentFile, rec.SocketDir = port, cc.DataDir, cc.ConfigFile, cc.HbaFile, cc.IdentFile, cc.SocketDir
	rec.Unit, rec.Created = cmp.Or(unit, cc.Unit), true
	return nil
}

// forkTakeCluster checks an existing cluster is empty and may be stopped.
func (a *Agent) forkTakeCluster(ctx context.Context, ops forkOps, p protocol.ForkRestoreParams, src forkSource, rec *forkRecord) (clusterUsage, error) {
	if p.Port < 1 || p.Port > 65535 {
		return clusterUsage{}, errors.New("no cluster was chosen for the fork")
	}
	socketDir := cmp.Or(p.SocketDir, "/var/run/postgresql")
	if !filepath.IsAbs(socketDir) {
		return clusterUsage{}, fmt.Errorf("invalid socket directory %q", socketDir)
	}
	if err := a.helperCanStopStart(p.Port); err != nil {
		return clusterUsage{}, err
	}
	for _, r := range a.sb().standbys() {
		if r.Database.Port == p.Port {
			return clusterUsage{}, fmt.Errorf("the cluster on port %d runs a standby", p.Port)
		}
	}
	db := protocol.DatabaseSpec{Port: p.Port, SocketDir: socketDir}
	a.fk().step(p.ForkID, protocol.ForkStepCluster, fmt.Sprintf("Checking the cluster on port %d is empty", p.Port))
	f, err := ops.facts(ctx, db)
	if err != nil {
		return clusterUsage{}, fmt.Errorf("the cluster on port %d must be running so Rowsafe can check it's empty: %w", p.Port, err)
	}
	u, err := ops.usage(ctx, db)
	if err != nil {
		return u, err
	}
	switch {
	case f.InRecovery:
		return u, fmt.Errorf("the cluster on port %d is a standby of something else", p.Port)
	case u.UserDatabases > 0 || u.UserTables > 0:
		return u, fmt.Errorf("the cluster on port %d isn't empty (%s, %s): Rowsafe only forks into an empty cluster", p.Port,
			countNoun(u.UserDatabases, "database", "databases"), countNoun(u.UserTables, "table", "tables"))
	case f.Major != src.major:
		return u, fmt.Errorf("the cluster on port %d runs PostgreSQL %d and the source %d: a fork needs the same major version", p.Port, f.Major, src.major)
	case f.Tablespaces > 0:
		return u, fmt.Errorf("the cluster on port %d has tablespaces; use an empty cluster", p.Port)
	}
	allowed, _ := a.allowedClusters()
	rec.Port, rec.SocketDir, rec.DataDir, rec.ConfigFile, rec.HbaFile, rec.IdentFile = p.Port, socketDir, f.DataDir, f.ConfigFile, f.HbaFile, f.IdentFile
	rec.Unit, rec.WasRunning = allowed[p.Port], true
	return u, nil
}

// writeForkSourceConf writes the pgBackRest config that reads the source's
// backups (restore and archive-get only).
func (a *Agent) writeForkSourceConf(rec forkRecord, source protocol.DatabaseSpec, repo pgbackrest.Repo, socketDir string) error {
	if err := os.MkdirAll(a.cfg.ConfigDir, 0o700); err != nil {
		return err
	}
	logDir := a.cfg.LogDir
	if a.cfg.Sidecar() {
		logDir = ""
	} else if err := os.MkdirAll(logDir, 0o700); err != nil {
		return err
	}
	conf := pgbackrest.RenderConfig(repo, pgbackrest.ConfigInput{Stanza: source.Stanza, DataDir: rec.DataDir, Port: rec.Port, SocketDir: socketDir,
		User: a.cfg.PGUser, RetentionFull: max(source.RetentionFull, 1), LogPath: logDir, ProcessMax: pgbackrest.ProcessMax(numCPU())})
	return writeFileAtomic(rec.SourceConf, []byte(conf), 0o600)
}

// writeForkAutoConf appends Rowsafe's block to the fork's
// postgresql.auto.conf. It returns a warning about preloaded libraries this
// server lacks.
func (a *Agent) writeForkAutoConf(rec forkRecord, src forkSource, pkgLibDir string) (string, error) {
	path := filepath.Join(rec.DataDir, "postgresql.auto.conf")
	cur, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	warning := ""
	preload, preloadSet := "", false
	if m := autoConfPreloadRE.FindAllStringSubmatch(string(cur), -1); len(m) > 0 {
		var missing []string
		preload, missing = installedPreload(m[len(m)-1][1], pkgLibDir)
		if len(missing) > 0 {
			preloadSet = true
			warning = fmt.Sprintf("the source preloads %s, which this server doesn't have: the fork starts without %s",
				strings.Join(missing, ", "), itThem(len(missing)))
		}
	}
	block := forkAutoConf(rec.Port, rec.Major, src.settings, preload, preloadSet)
	s := strings.TrimRight(string(cur), "\n") + "\n" + block
	return warning, writeFileAtomic(path, []byte(s), 0o600)
}

// forkRecover replays privately, then masks.
func (a *Agent) forkRecover(ctx context.Context, ops forkOps, p protocol.ForkRestoreParams, rec forkRecord, socketDir string, tl *taskLog) (*time.Time, *protocol.ForkMaskReport, error) {
	timeout := 4 * time.Hour
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)-30*time.Minute, time.Minute)
	}
	pr := privateRecovery{DataDir: rec.DataDir, Major: rec.Major, Port: rec.Port, SocketDir: socketDir,
		LogFile: filepath.Join(rec.Private, "recovery.log"), Timeout: timeout}
	if rec.ConfigFile != "" && !strings.HasPrefix(rec.ConfigFile, rec.DataDir+string(filepath.Separator)) {
		pr.ConfigFile = rec.ConfigFile
	}
	tl.Printf("replaying changes up to %s (private socket, no network connections)", describeTarget(p.Target))
	var report *protocol.ForkMaskReport
	recoveredTo, err := ops.recover(ctx, pr, func(ctx context.Context, t pginspect.Target) error {
		conn, err := t.Connect(ctx, "postgres")
		if err != nil {
			return err
		}
		for _, stmt := range resetRecoverySQL {
			if _, err := conn.Exec(ctx, stmt); err != nil {
				closeConn(ctx, conn)
				return fmt.Errorf("%s: %w", stmt, err)
			}
		}
		closeConn(ctx, conn)
		if p.Masking != nil {
			a.fk().step(p.ForkID, protocol.ForkStepMask, "Masking personal data")
			r, err := a.maskFork(ctx, t, *p.Masking, tl)
			if err != nil {
				return fmt.Errorf("masking: %w (the fork was never reachable, and it was removed)", err)
			}
			report = &r
		}
		return nil
	})
	if data, rerr := os.ReadFile(pr.LogFile); rerr == nil && err != nil {
		tl.Output("recovery log (tail)", tail(data, 8000))
	}
	return recoveredTo, report, err
}

// finishFork fills the result once the fork runs.
func (a *Agent) finishFork(ctx context.Context, ops forkOps, db protocol.DatabaseSpec, rec forkRecord, res *protocol.ForkRestoreResult, start time.Time, tl *taskLog) {
	rt := a.fk()
	rt.step(rec.ID, protocol.ForkStepFinished, "")
	if dbs, err := ops.databases(ctx, db); err == nil {
		res.Databases = dbs
		for _, d := range dbs {
			res.SizeBytes += d.SizeBytes
		}
	} else {
		tl.Printf("listing the fork's databases: %v", err)
	}
	if rec.KeptDir != "" {
		if rec.Created {
			// The new cluster's own data was a fresh, empty initdb.
			if err := validKeptForkDir(rec.DataDir, rec.KeptDir); err == nil {
				_ = os.RemoveAll(rec.KeptDir)
			}
		} else {
			until := time.Now().UTC().AddDate(0, 0, forkKeepDays)
			_ = rt.keep(forkKept{Path: rec.KeptDir, DataDir: rec.DataDir, Until: until})
			res.KeptDataDir = rec.KeptDir
		}
	}
	_ = os.RemoveAll(rec.Private)
	_ = rt.remove(rec.ID)
	res.DurationMs = time.Since(start).Milliseconds()
	var names []string
	for _, d := range res.Databases {
		names = append(names, d.Name)
	}
	where := fmt.Sprintf("port %d", rec.Port)
	if rec.Created {
		where = fmt.Sprintf("a new PostgreSQL %d cluster on port %d", rec.Major, rec.Port)
	}
	to := "the backup itself"
	if res.RecoveredTo != nil {
		to = "the last change at " + res.RecoveredTo.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	res.Summary = fmt.Sprintf("The fork runs on %s: %s, restored to %s", where, humanBytes(res.SizeBytes), to)
	if len(names) > 0 {
		res.Summary += " (databases: " + strings.Join(names, ", ") + ")"
	}
	res.Summary += "."
	if m := res.Masking; m != nil {
		res.Summary += " " + forkMaskSummary(*m)
	}
	tl.Printf("%s", res.Summary)
}

func waitForkStopped(ctx context.Context, ops forkOps, dataDir string) error {
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

// rollbackFork puts a cluster back as it was before a failed fork: whatever
// runs in the data directory is stopped, a half-restored directory removed,
// the cluster's own data renamed back and started (a created cluster too:
// empty, it can take the next fork). It goes by what is on disk.
func (a *Agent) rollbackFork(ctx context.Context, rec forkRecord, tl *taskLog) error {
	ops := a.fops()
	if rec.SourceConf != "" && strings.HasPrefix(filepath.Base(rec.SourceConf), "fork-") {
		_ = os.Remove(rec.SourceConf)
	}
	if rec.Placement == protocol.ForkDocker {
		return a.rollbackForkDocker(ctx, ops, rec, tl)
	}
	if rec.DataDir == "" {
		return nil
	}
	if rec.Phase != phasePreflight && rec.Phase != "" {
		if ops.running(rec.DataDir) {
			if err := ops.helper(ctx, helperStop, rec.Port, rec.ID+"-rbstop"); err != nil || waitForkStopped(ctx, ops, rec.DataDir) != nil {
				if err := ops.stopLocal(rec.DataDir, rec.Major); err != nil {
					return err
				}
			}
		}
		if rec.KeptDir != "" && exists(rec.KeptDir) {
			if err := validKeptForkDir(rec.DataDir, rec.KeptDir); err != nil {
				return err
			}
			if exists(rec.DataDir) {
				failed := rec.DataDir + ".failed-fork-" + stampNow()
				if err := os.Rename(rec.DataDir, failed); err != nil {
					return err
				}
				if err := os.RemoveAll(failed); err != nil {
					tl.Printf("removing the half-restored data %s: %v", failed, err)
				}
			}
			if err := os.Rename(rec.KeptDir, rec.DataDir); err != nil {
				return err
			}
			tl.Printf("put the cluster's own data back in %s", rec.DataDir)
		}
	}
	if (rec.WasRunning || rec.Created) && !ops.running(rec.DataDir) && exists(filepath.Join(rec.DataDir, "PG_VERSION")) {
		if err := ops.helper(ctx, helperStart, rec.Port, rec.ID+"-rbstart"); err != nil && !ops.running(rec.DataDir) {
			tl.Printf("starting the cluster on port %d again: %v", rec.Port, err)
		}
	}
	if rec.Private != "" && strings.HasPrefix(rec.Private, filepath.Join(a.cfg.StateDir, "fork")+string(filepath.Separator)) {
		_ = os.RemoveAll(rec.Private)
	}
	return nil
}
