package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Creating a standby on this server.
//
// The chosen cluster (empty: no user databases or tables) is stopped
// through the root helper, its data directory is renamed aside (same
// filesystem: instant) and kept, the latest backup is restored in its place
// as a standby (standby.signal, restore_command from the primary's bucket,
// following the newest timeline), Rowsafe's standby settings are appended
// to postgresql.auto.conf (streaming connection when the primary answers,
// hot standby minimums, this server's own archive_command for after a
// promotion), and PostgreSQL is started through the helper. Any failure
// after the stop puts the cluster's own data back and starts it; an agent
// restart in the middle does the same.
//
// A rebuild turns a fenced old primary into the standby of the new one.
// When it stopped cleanly and the new primary replayed all of it, its data
// is already a prefix of the new timeline: it is started as a standby as is
// (reattach), which PostgreSQL itself refuses if the histories diverged.
// Otherwise (or if that doesn't follow the new timeline in time) its data
// is renamed aside, kept for KeepDays (writes it accepted after the
// promotion are in there, never thrown away) and the backup restored.

var keptStandbyDirRE = regexp.MustCompile(`^(.+)\.(before-standby|old-primary)-[0-9]{8}T[0-9]{6}Z$`)

// validKeptStandbyDir checks kept is a directory set aside for dataDir.
func validKeptStandbyDir(dataDir, kept string) error {
	dataDir, kept = filepath.Clean(dataDir), filepath.Clean(kept)
	m := keptStandbyDirRE.FindStringSubmatch(filepath.Base(kept))
	if m == nil || m[1] != filepath.Base(dataDir) || filepath.Dir(kept) != filepath.Dir(dataDir) {
		return fmt.Errorf("refusing to touch %s: it is not a directory Rowsafe set aside for %s", kept, dataDir)
	}
	info, err := os.Lstat(kept)
	if err != nil {
		return err
	}
	if !info.IsDir() || fileUID(info) != os.Getuid() {
		return fmt.Errorf("refusing to touch %s: not a directory the agent's user owns", kept)
	}
	return nil
}

// streamingPlan is how the standby connects to the primary.
type streamingPlan struct {
	Address, SSLMode string
	Note             string // why not streaming, in plain words
}

// planStreaming picks the first primary address that answers, and the TLS
// mode: required when the primary has TLS on; without TLS only over a
// private network.
func planStreaming(ops standbyOps, sec protocol.StandbySecrets) streamingPlan {
	if sec.ReplicationUser == "" {
		return streamingPlan{Note: "streaming isn't set up on the primary"}
	}
	public := ""
	for _, addr := range sec.PrimaryAddresses {
		ip := net.ParseIP(addr)
		if ip == nil || !ops.probe(addr, sec.PrimaryPort) {
			continue
		}
		switch {
		case sec.PrimaryTLS:
			return streamingPlan{Address: addr, SSLMode: "require"}
		case ip.IsPrivate():
			return streamingPlan{Address: addr, SSLMode: "prefer"}
		case public == "":
			public = addr
		}
	}
	if public != "" {
		return streamingPlan{Note: fmt.Sprintf("the primary answers on %s, a public address, but has TLS off, so Rowsafe doesn't stream over it "+
			"and the standby follows through the bucket (turn on ssl on the primary, or connect the servers over a private network)", public)}
	}
	return streamingPlan{Note: "this server can't reach the primary's PostgreSQL (firewall or listen_addresses), so the standby follows through the bucket"}
}

// standbyBlock is Rowsafe's part of the standby's postgresql.auto.conf
// (the last setting wins).
func (a *Agent) standbyBlock(id string, db protocol.DatabaseSpec, sec protocol.StandbySecrets, sp streamingPlan, settings map[string]int) (string, error) {
	restore, err := pgbackrest.ArchiveGetCommand(a.cfg.PgBackRestBin, a.cfg.configPath(db.Stanza), db.Stanza)
	if err != nil {
		return "", err
	}
	archive, err := pgbackrest.ArchiveCommand(a.cfg.PgBackRestBin, a.cfg.configPath(db.Stanza), db.Stanza)
	if err != nil {
		return "", err
	}
	s := []drillSetting{{"hot_standby", "on"}, {"restore_command", restore}, {"recovery_target_timeline", "latest"},
		{"archive_command", archive}}
	for _, name := range hotStandbySettings {
		if v, ok := settings[name]; ok && v > 0 {
			s = append(s, drillSetting{name, strconv.Itoa(v)})
		}
	}
	if sp.Address != "" {
		for _, v := range []string{sec.ReplicationUser, sec.ReplicationPassword, sp.Address, sp.SSLMode} {
			if strings.ContainsAny(v, " '\\\n\r\x00") {
				return "", errors.New("unexpected characters in the streaming settings")
			}
		}
		conninfo := fmt.Sprintf("host=%s port=%d user=%s password=%s sslmode=%s application_name=%s connect_timeout=10 keepalives_idle=30",
			sp.Address, sec.PrimaryPort, sec.ReplicationUser, sec.ReplicationPassword, sp.SSLMode, replicationRole(id))
		s = append(s, drillSetting{"primary_conninfo", conninfo})
	}
	return "\n" + hbaBegin(id) + "\n" + renderSettings(s) + hbaEnd(id) + "\n", nil
}

// setStandbyConf writes Rowsafe's block at the end of dataDir's
// postgresql.auto.conf, replacing an older one.
func setStandbyConf(dataDir, block string) error {
	path := filepath.Join(dataDir, "postgresql.auto.conf")
	cur, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s := strings.TrimRight(withoutHbaBlock(string(cur), ""), "\n") + "\n" + block
	return writeFileAtomic(path, []byte(s), 0o600)
}

func (a *Agent) standbyCreate(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyCreateParams, tl *taskLog) (*protocol.StandbyCreateResult, error) {
	start := time.Now()
	rt := a.sb()
	if !standbyIDRE.MatchString(p.StandbyID) || (p.FenceID != "" && !standbyIDRE.MatchString(p.FenceID)) {
		return nil, errors.New("invalid standby or fence id")
	}
	if p.Port < 1 || p.Port > 65535 || !filepath.IsAbs(p.SocketDir) {
		return nil, fmt.Errorf("invalid cluster %s:%d", p.SocketDir, p.Port)
	}
	if rt.key == nil {
		return nil, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
	}
	if !rt.opMu.TryLock() {
		return nil, errors.New("another standby change is running on this server; try again when it has finished")
	}
	defer rt.opMu.Unlock()
	if r, ok := rt.standby(p.StandbyID); ok && r.Phase == protocol.StandbyPhaseFollowing {
		return &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: r.Mode, DataDir: r.DataDir, KeptDataDir: r.KeptDir,
			Summary: "The standby is already running here."}, nil
	}
	for _, r := range rt.standbys() {
		if r.ID != p.StandbyID && r.Database.Port == p.Port {
			return nil, fmt.Errorf("the cluster on port %d already runs a standby here", p.Port)
		}
	}
	db.Port, db.SocketDir = p.Port, p.SocketDir
	plain, err := handoff.Open(rt.key, p.Box, protocol.HandoffPurposeStandby, protocol.StandbyHandoffContext(db.ID, p.StandbyID), p.SenderKey)
	if err != nil {
		return nil, fmt.Errorf("opening the primary's sealed handoff: %w", err)
	}
	var sec protocol.StandbySecrets
	err = json.Unmarshal(plain, &sec)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("reading the primary's handoff: %w", err)
	}
	if err := a.helperCanStopStart(p.Port); err != nil {
		return nil, err
	}
	ops := a.sops()
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID}
	rec := standbyRecord{ID: p.StandbyID, DatabaseID: db.ID, Database: db, Phase: protocol.StandbyPhaseCreating, Step: phasePreflight,
		PrimPort: sec.PrimaryPort, Role: sec.ReplicationUser, Rebuild: p.Rebuild, CreatedAt: time.Now().UTC()}

	// Preflight: nothing changes if any of it fails.
	settings := map[string]int{}
	for k, v := range p.Settings {
		settings[k] = v
	}
	if p.Rebuild {
		c, ok := rt.cluster(db.ID)
		if !ok || c.DataDir == "" || c.Major == 0 {
			return nil, errors.New("Rowsafe doesn't know where this server's copy of the database lives (its data directory): " +
				"it was never seen running here. Remove it from the database and create a standby on an empty cluster instead")
		}
		if p.SystemID != "" && c.SystemID != "" && c.SystemID != p.SystemID {
			return nil, errors.New("the cluster on this server is another database system than the primary's")
		}
		rec.DataDir, rec.Major, rec.ConfigFile, rec.HbaFile, rec.IdentFile = c.DataDir, c.Major, c.ConfigFile, c.HbaFile, c.IdentFile
	} else {
		f, err := ops.facts(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("the cluster on port %d must be running so Rowsafe can check it's empty: %w", p.Port, err)
		}
		u, err := ops.usage(ctx, db)
		if err != nil {
			return nil, err
		}
		switch {
		case f.InRecovery:
			return nil, fmt.Errorf("the cluster on port %d is already a standby of something else", p.Port)
		case u.UserDatabases > 0 || u.UserTables > 0:
			return nil, fmt.Errorf("the cluster on port %d isn't empty (%s, %s): Rowsafe only turns an empty cluster into a standby. "+
				"Create a new cluster for it (e.g. pg_createcluster %d standby --port 5433) and allow Rowsafe to stop and start it",
				p.Port, countNoun(u.UserDatabases, "database", "databases"), countNoun(u.UserTables, "table", "tables"), f.Major)
		case f.Major != p.Major:
			return nil, fmt.Errorf("the cluster on port %d runs PostgreSQL %d and the primary %d: a standby needs the same major version", p.Port, f.Major, p.Major)
		case f.Tablespaces > 0:
			return nil, fmt.Errorf("the cluster on port %d has tablespaces; use an empty cluster", p.Port)
		case p.SystemID != "" && u.SystemID == p.SystemID:
			return nil, errors.New("this cluster already is a copy of the primary; remove it and use an empty cluster")
		}
		for k, v := range u.Settings {
			settings[k] = max(settings[k], v)
		}
		rec.DataDir, rec.Major, rec.ConfigFile, rec.HbaFile, rec.IdentFile = f.DataDir, f.Major, f.ConfigFile, f.HbaFile, f.IdentFile
	}
	// The primary's bucket, from now on this database's repository here.
	hadRepo := exists(a.repoPath(db.ID))
	if err := a.saveHandedRepo(db.ID, sec.Repo); err != nil {
		return nil, err
	}
	dropRepo := func() {
		if !hadRepo && !p.Rebuild {
			_ = os.Remove(a.repoPath(db.ID))
			_ = os.Remove(a.caPath(db.ID))
		}
	}
	if err := a.writeConfig(db, protocol.InspectResult{DataDirectory: rec.DataDir}); err != nil {
		dropRepo()
		return nil, err
	}
	if err := ops.repo(ctx, db); err != nil {
		dropRepo()
		return nil, err
	}
	sp := planStreaming(ops, sec)
	rec.Address = sp.Address
	block, err := a.standbyBlock(p.StandbyID, db, sec, sp, settings)
	if err != nil {
		dropRepo()
		return nil, err
	}
	if sp.Address == "" {
		res.Warnings = append(res.Warnings, sp.Note)
		tl.Printf("%s", sp.Note)
	} else {
		tl.Printf("the primary answers on %s:%d: streaming with sslmode=%s, the bucket as a fallback", sp.Address, sec.PrimaryPort, sp.SSLMode)
	}
	if err := rt.putStandby(rec); err != nil {
		dropRepo()
		return nil, err
	}

	// A rebuild whose old primary stopped cleanly first tries to follow the
	// new timeline on the data it has.
	if p.Rebuild && p.Reattach {
		ok, err := a.reattach(ctx, ops, &rec, block, p, tl)
		if ok {
			return a.finishCreate(ctx, rt, rec, res, sp, start, p, tl)
		}
		tl.Printf("reusing the old primary's data didn't work (%v); restoring from the bucket instead, keeping that data aside", err)
	}
	if err := a.restoreAsStandby(ctx, ops, &rec, block, p, tl); err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		rbErr := a.rollbackStandby(context.WithoutCancel(ctx), rec, tl)
		_ = rt.removeStandby(p.StandbyID)
		dropRepo()
		switch {
		case rbErr != nil:
			res.Summary = fmt.Sprintf("Creating the standby failed: %v. Putting things back also failed: %v. No data was deleted (see %s); "+
				"Rowsafe tries again when its agent restarts.", err, rbErr, rec.KeptDir)
		case p.Rebuild:
			res.RolledBack = true
			res.Summary = fmt.Sprintf("Rebuilding failed: %v. PostgreSQL stays stopped on this server, as before.", err)
		default:
			res.RolledBack = true
			res.Summary = fmt.Sprintf("Creating the standby failed: %v. The cluster's own data is back and running; nothing else changed.", err)
		}
		return res, errors.New(res.Summary)
	}
	return a.finishCreate(ctx, rt, rec, res, sp, start, p, tl)
}

// restoreAsStandby stops the cluster, sets its data aside, restores and
// starts. rec is kept up to date (and on disk) for a rollback.
func (a *Agent) restoreAsStandby(ctx context.Context, ops standbyOps, rec *standbyRecord, block string, p protocol.StandbyCreateParams, tl *taskLog) error {
	rt := a.sb()
	step := func(s string) {
		rec.Step = s
		if err := rt.putStandby(*rec); err != nil {
			tl.Printf("recording progress: %v", err)
		}
	}
	if _, err := os.Lstat(rec.DataDir); err == nil {
		if _, err := checkDataDir(rec.DataDir); err != nil {
			return err
		}
	}
	parent := filepath.Dir(rec.DataDir)
	need := p.SizeBytes + p.SizeBytes/10
	if free, err := ops.freeBytes(parent); err != nil {
		return err
	} else if free < need {
		return fmt.Errorf("not enough free disk in %s: the standby needs about %s (the primary's size plus 10%%) and %s is free",
			parent, humanBytes(need), humanBytes(free))
	}
	// Stop.
	tl.Printf("stopping PostgreSQL on port %d", rec.Database.Port)
	step(phaseStopped)
	how, err := a.stopCluster(ctx, ops, rec.Database.Port, rec.DataDir, rec.Major, rec.ID+"-stop", tl)
	if err != nil {
		return fmt.Errorf("stopping PostgreSQL: %w", err)
	}
	tl.Printf("PostgreSQL is stopped (%s)", how)

	// Set the data aside.
	suffix := ".before-standby-"
	if p.Rebuild {
		suffix = ".old-primary-"
	}
	kept := rec.DataDir + suffix + stampNow()
	info, err := os.Lstat(rec.DataDir)
	if err != nil {
		return err
	}
	rec.KeptDir = kept
	step(phaseMoved)
	if err := os.Rename(rec.DataDir, kept); err != nil {
		rec.KeptDir = ""
		step(phaseStopped)
		if errors.Is(err, syscall.EXDEV) {
			err = fmt.Errorf("the filesystem can't rename the data directory in place (%w); the data directory needs to be on a volume", err)
		}
		return fmt.Errorf("setting the cluster's data aside: %w", err)
	}
	tl.Printf("set the cluster's own data aside in %s", kept)

	// Restore.
	step(phaseRestored)
	if err := os.Mkdir(rec.DataDir, info.Mode().Perm()); err != nil {
		return err
	}
	_ = os.Chmod(rec.DataDir, info.Mode().Perm())
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(rec.DataDir, -1, int(st.Gid))
	}
	tl.Printf("restoring the latest backup from the primary's bucket into %s", rec.DataDir)
	out, err := ops.restoreStandby(ctx, rec.Database, rec.DataDir)
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fmt.Errorf("restoring the backup: %w", err)
	}
	// Configuration that lives in the data directory stays this cluster's
	// own (port, listen addresses, access rules); postgresql.auto.conf is
	// the primary's, with Rowsafe's standby block.
	for _, path := range []string{rec.ConfigFile, rec.HbaFile, rec.IdentFile} {
		if path == "" || !strings.HasPrefix(path, rec.DataDir+string(filepath.Separator)) {
			continue
		}
		rel := strings.TrimPrefix(path, rec.DataDir+string(filepath.Separator))
		if err := copyConfFile(filepath.Join(kept, rel), filepath.Join(rec.DataDir, rel)); err != nil {
			return err
		}
	}
	if err := setStandbyConf(rec.DataDir, block); err != nil {
		return err
	}
	if !exists(filepath.Join(rec.DataDir, "standby.signal")) {
		if err := writeStandbySignal(rec.DataDir); err != nil {
			return err
		}
	}
	a.cleanLocalHba(rec.HbaFile, tl)

	// Start.
	step(phaseStarted)
	return a.startStandby(ctx, ops, rec, tl)
}

func (a *Agent) startStandby(ctx context.Context, ops standbyOps, rec *standbyRecord, tl *taskLog) error {
	tl.Printf("starting PostgreSQL on port %d as a standby through the root helper", rec.Database.Port)
	if err := ops.helper(ctx, helperStart, rec.Database.Port, rec.ID+"-start"); err != nil {
		if !strings.Contains(err.Error(), "did not finish") || !ops.running(rec.DataDir) {
			return fmt.Errorf("starting PostgreSQL: %w", err)
		}
	}
	if _, err := waitStandby(ctx, ops, rec.Database, standbyReadyWait); err != nil {
		return fmt.Errorf("starting PostgreSQL: %w", err)
	}
	return nil
}

// cleanLocalHba removes Rowsafe standby blocks left in this server's
// pg_hba.conf from when it was a primary (the roles are gone).
func (a *Agent) cleanLocalHba(hbaFile string, tl *taskLog) {
	if hbaFile == "" {
		return
	}
	info, err := os.Stat(hbaFile)
	if err != nil {
		return
	}
	old, err := os.ReadFile(hbaFile)
	if err != nil {
		return
	}
	if next := withoutHbaBlock(string(old), ""); next != string(old) {
		if os.WriteFile(hbaFile, []byte(next), info.Mode().Perm()) == nil {
			tl.Printf("removed old Rowsafe standby lines from %s", hbaFile)
		}
	}
}

// reattach starts a cleanly stopped old primary as a standby on its own
// data and waits until it replays the new timeline.
func (a *Agent) reattach(ctx context.Context, ops standbyOps, rec *standbyRecord, block string, p protocol.StandbyCreateParams, tl *taskLog) (bool, error) {
	rt := a.sb()
	if _, err := a.stopCluster(ctx, ops, rec.Database.Port, rec.DataDir, rec.Major, rec.ID+"-stop", tl); err != nil {
		return false, err
	}
	cd, err := ops.controlData(rec.DataDir, rec.Major)
	if err != nil {
		return false, err
	}
	if cd.State != "shut down" && cd.State != "shut down in recovery" {
		return false, fmt.Errorf("the old primary wasn't shut down cleanly (%s)", cd.State)
	}
	if p.SwitchLSN == "" || !lsnAtLeast(p.SwitchLSN, cd.CheckpointLSN) {
		return false, fmt.Errorf("the old primary's last checkpoint %s is past where the new primary took over (%s)", cd.CheckpointLSN, p.SwitchLSN)
	}
	if err := setStandbyConf(rec.DataDir, block); err != nil {
		return false, err
	}
	if err := writeStandbySignal(rec.DataDir); err != nil {
		return false, err
	}
	a.cleanLocalHba(rec.HbaFile, tl)
	rec.Step = phaseStarted
	_ = rt.putStandby(*rec)
	if err := a.startStandby(ctx, ops, rec, tl); err != nil {
		_, _ = a.stopCluster(context.WithoutCancel(ctx), ops, rec.Database.Port, rec.DataDir, rec.Major, rec.ID+"-rbstop", tl)
		return false, err
	}
	tl.Printf("the old primary runs as a standby on its own data; waiting until it replays the new primary's timeline (past %s)", p.SwitchLSN)
	deadline := time.Now().Add(reattachWait)
	for {
		st, err := ops.status(ctx, rec.Database)
		if err == nil && st.InRecovery && lsnDiff(st.ReplayLSN, p.SwitchLSN) > 0 {
			rec.Step = phaseDone
			return true, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Second):
		}
	}
	_, _ = a.stopCluster(context.WithoutCancel(ctx), ops, rec.Database.Port, rec.DataDir, rec.Major, rec.ID+"-rbstop", tl)
	rec.Step = phasePreflight
	_ = rt.putStandby(*rec)
	return false, fmt.Errorf("it didn't follow the new timeline within %s", reattachWait)
}

func (a *Agent) finishCreate(ctx context.Context, rt *standbyRuntime, rec standbyRecord, res *protocol.StandbyCreateResult,
	sp streamingPlan, start time.Time, p protocol.StandbyCreateParams, tl *taskLog) (*protocol.StandbyCreateResult, error) {
	ops := a.sops()
	rec.Step, rec.Phase = phaseDone, protocol.StandbyPhaseFollowing
	rec.Mode = protocol.StandbyModeArchive
	res.Reattached = rec.KeptDir == "" && p.Rebuild
	// Give streaming a moment to connect.
	if sp.Address != "" {
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			if st, err := ops.status(ctx, rec.Database); err == nil && st.ReceiverStatus == "streaming" {
				rec.Mode = protocol.StandbyModeStreaming
				break
			}
			time.Sleep(time.Second)
		}
		if rec.Mode != protocol.StandbyModeStreaming {
			res.Warnings = append(res.Warnings, fmt.Sprintf("the standby didn't manage to stream from %s yet (firewall, pg_hba.conf or TLS); "+
				"it follows through the bucket and keeps trying", sp.Address))
		}
	}
	if p.Rebuild && rec.KeptDir != "" {
		until := keepUntil(p.KeepDays, time.Now().UTC())
		res.KeptUntil = &until
		kd := keptData{Path: rec.KeptDir, DataDir: rec.DataDir, DatabaseID: rec.DatabaseID, Until: until}
		_ = rt.update(func(sf *standbyFile) { sf.Kept = append(sf.Kept, kd) })
		rec.KeptDir = "" // it is the old primary's data: never put back as a running cluster
		res.KeptDataDir = kd.Path
	} else {
		res.KeptDataDir = rec.KeptDir
	}
	if err := rt.putStandby(rec); err != nil {
		return nil, err
	}
	if p.Rebuild && p.FenceID != "" {
		if err := rt.releaseFence(p.FenceID); err != nil {
			tl.Printf("releasing the fence: %v", err)
		}
	}
	if st, err := ops.status(ctx, rec.Database); err == nil {
		res.ReplayLSN = st.ReplayLSN
	}
	res.Mode, res.PrimaryAddress, res.DataDir = rec.Mode, sp.Address, rec.DataDir
	res.DurationMs = time.Since(start).Milliseconds()
	how := "follows the primary through the bucket (about a minute behind)"
	if rec.Mode == protocol.StandbyModeStreaming {
		how = "streams from the primary (and falls back to the bucket)"
	}
	switch {
	case res.Reattached:
		res.Summary = "The old primary is now the standby, on its own data: it " + how + "."
	case p.Rebuild:
		res.Summary = fmt.Sprintf("The old primary is now the standby, restored from the bucket: it %s. Its data from before is kept in %s until %s.",
			how, res.KeptDataDir, res.KeptUntil.Format("2006-01-02"))
	default:
		res.Summary = "The standby is running: it " + how + ". It is readable: use it for reports and read-only queries."
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rollbackStandby puts a cluster back as it was before a failed create:
// whatever runs in the data directory is stopped, a half-restored directory
// removed, the cluster's own data renamed back and (not for a rebuild,
// which stays stopped) started. It goes by what is on disk.
func (a *Agent) rollbackStandby(ctx context.Context, rec standbyRecord, tl *taskLog) error {
	ops := a.sops()
	if rec.Step == phasePreflight || rec.Step == "" {
		return nil
	}
	if ops.running(rec.DataDir) {
		if _, err := a.stopCluster(ctx, ops, rec.Database.Port, rec.DataDir, rec.Major, rec.ID+"-rbstop", tl); err != nil {
			return err
		}
	}
	if rec.KeptDir != "" && exists(rec.KeptDir) {
		if err := validKeptStandbyDir(rec.DataDir, rec.KeptDir); err != nil {
			return err
		}
		if exists(rec.DataDir) {
			failed := rec.DataDir + ".failed-standby-" + stampNow()
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
	if rec.Rebuild {
		// A fenced old primary stays stopped, read-only if started.
		_ = writeStandbySignal(rec.DataDir)
		return nil
	}
	if err := ops.helper(ctx, helperStart, rec.Database.Port, rec.ID+"-rbstart"); err != nil {
		if !ops.running(rec.DataDir) {
			return fmt.Errorf("starting PostgreSQL again: %w", err)
		}
	}
	return nil
}

// recoverStandbys finishes what an agent restart interrupted: a create
// that was changing a cluster is rolled back.
func (a *Agent) recoverStandbys(ctx context.Context) {
	rt := a.sb()
	for _, r := range rt.standbys() {
		if r.Phase != protocol.StandbyPhaseCreating {
			if r.Phase == protocol.StandbyPhasePromoting {
				// The promotion ran or it didn't; standbyState reports which.
				r.Phase = protocol.StandbyPhaseFollowing
				_ = rt.putStandby(r)
			}
			continue
		}
		tl := &taskLog{}
		a.log.Warn("a standby creation was interrupted by an agent restart; putting the cluster back", "standby_id", r.ID, "step", r.Step)
		if err := a.rollbackStandby(ctx, r, tl); err != nil {
			a.log.Error("putting the cluster back after an interrupted standby creation failed; will retry at the next start",
				"standby_id", r.ID, "err", err, "log", tl.String())
			continue
		}
		_ = rt.removeStandby(r.ID)
	}
}

func (a *Agent) standbyRemove(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, tl *taskLog) (*protocol.StandbyRemoveResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.StandbyID) {
		return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
	}
	if !rt.opMu.TryLock() {
		return nil, errors.New("another standby change is running on this server; try again when it has finished")
	}
	defer rt.opMu.Unlock()
	res := &protocol.StandbyRemoveResult{StandbyID: p.StandbyID}
	rec, ok := rt.standby(p.StandbyID)
	if !ok {
		res.Summary = "There was no standby here any more; nothing to do."
		return res, nil
	}
	ops := a.sops()
	st, err := ops.status(ctx, rec.Database)
	if err == nil && !st.InRecovery {
		// Promoted meanwhile: this is the primary now, never stop it here.
		_ = rt.removeStandby(p.StandbyID)
		return nil, errors.New("this server's copy is no longer a standby (it was promoted); Rowsafe left it running")
	}
	how, err := a.stopCluster(ctx, ops, rec.Database.Port, rec.DataDir, rec.Major, p.StandbyID+"-stop", tl)
	if err != nil {
		return nil, fmt.Errorf("stopping the standby: %w", err)
	}
	tl.Printf("stopped the standby (%s)", how)
	if rec.KeptDir != "" && exists(rec.KeptDir) && !rec.Rebuild {
		if err := validKeptStandbyDir(rec.DataDir, rec.KeptDir); err != nil {
			return nil, err
		}
		gone := rec.DataDir + ".failed-standby-" + stampNow()
		if err := os.Rename(rec.DataDir, gone); err != nil {
			return nil, err
		}
		if err := os.Rename(rec.KeptDir, rec.DataDir); err != nil {
			_ = os.Rename(gone, rec.DataDir)
			return nil, err
		}
		if err := os.RemoveAll(gone); err != nil {
			tl.Printf("removing the standby's data %s: %v", gone, err)
		}
		if err := ops.helper(ctx, helperStart, rec.Database.Port, p.StandbyID+"-start"); err != nil && !ops.running(rec.DataDir) {
			tl.Printf("starting the cluster's own data again: %v", err)
		} else {
			res.Restored = true
		}
	}
	_ = os.Remove(a.repoPath(rec.DatabaseID))
	_ = os.Remove(a.caPath(rec.DatabaseID))
	_ = rt.removeStandby(p.StandbyID)
	switch {
	case res.Restored:
		res.Summary = fmt.Sprintf("Removed the standby: the cluster on port %d has its own data back and runs as before.", rec.Database.Port)
	case rec.Rebuild:
		res.Summary = fmt.Sprintf("Removed the standby: PostgreSQL on port %d is stopped; its data (a standby copy) stays in %s, read-only if started.",
			rec.Database.Port, rec.DataDir)
	default:
		res.Summary = fmt.Sprintf("Removed the standby: PostgreSQL on port %d is stopped (the cluster's own data wasn't kept).", rec.Database.Port)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// standbyState is one standby's heartbeat report.
func (a *Agent) standbyState(ctx context.Context, r standbyRecord) protocol.StandbyState {
	rt := a.sb()
	now := time.Now().UTC()
	s := protocol.StandbyState{StandbyID: r.ID, DatabaseID: r.DatabaseID, Port: r.Database.Port, Phase: r.Phase,
		PrimaryAddress: r.Address, CheckedAt: now, Mode: r.Mode}
	st, err := a.sops().status(ctx, r.Database)
	if err != nil {
		if r.Phase == protocol.StandbyPhaseFollowing {
			s.Phase = protocol.StandbyPhaseStopped
		}
		s.Error = err.Error()
	} else {
		s.Running, s.InRecovery, s.ReceiveLSN, s.ReplayLSN = true, st.InRecovery, st.ReceiveLSN, st.ReplayLSN
		s.LastReplayAt, s.ReplayPaused, s.ReceiverStatus = st.LastReplayAt, st.Paused, st.ReceiverStatus
		if st.InRecovery && r.Phase == protocol.StandbyPhaseFollowing {
			s.Mode = protocol.StandbyModeArchive
			if st.ReceiverStatus == "streaming" {
				s.Mode = protocol.StandbyModeStreaming
			}
		}
	}
	rt.mu.Lock()
	if s.ReceiverStatus == "streaming" {
		rt.streamingSeen[r.ID] = now
	}
	if t, ok := rt.streamingSeen[r.ID]; ok {
		s.StreamingSeenAt = &t
	}
	if r.Address != "" {
		t, down := rt.unreachableSince[r.ID]
		s.PrimaryReachable = !down
		if down {
			s.PrimaryUnreachableSince = &t
		}
	}
	rt.mu.Unlock()
	return s
}

// checkPrimary probes the primary from a standby and tracks since when it
// doesn't answer.
func (a *Agent) checkPrimary(r standbyRecord) {
	if r.Address == "" || r.PrimPort == 0 || r.Phase != protocol.StandbyPhaseFollowing {
		return
	}
	up := a.sops().probe(r.Address, r.PrimPort)
	rt := a.sb()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if up {
		delete(rt.unreachableSince, r.ID)
	} else if _, ok := rt.unreachableSince[r.ID]; !ok {
		rt.unreachableSince[r.ID] = time.Now().UTC()
	}
}
