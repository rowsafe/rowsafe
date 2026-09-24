package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Fencing: keeping an old primary stopped once its standby takes over, so
// two servers never both accept writes (split brain).
//
// Three layers, each enough on its own for the common case:
//
//  1. PostgreSQL is stopped (fast shutdown) through the root helper, or with
//     pg_ctl as the agent user (who owns the postmaster) where the helper
//     isn't allowed.
//  2. standby.signal is written into its data directory first: if anything
//     starts it again (a reboot, a person, a service manager), it comes up
//     read-only, and applications that ask for a read-write server
//     (target_session_attrs=read-write) skip it.
//  3. The agent keeps the fence on disk and checks every few seconds, even
//     with no control plane: a fenced cluster found running is stopped
//     again. It never starts one.
//
// Only a rebuild (the old primary becomes the new standby), an unfence
// (the promotion didn't happen) or a person forgetting the fence lifts it.

func (a *Agent) standbyFence(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, tl *taskLog) (*protocol.StandbyFenceResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.FenceID) {
		return nil, fmt.Errorf("invalid fence id %q", p.FenceID)
	}
	ops := a.sops()
	res := &protocol.StandbyFenceResult{FenceID: p.FenceID}
	c, _ := rt.cluster(db.ID)
	running := false
	if f, err := ops.facts(ctx, db); err == nil {
		st, _ := ops.status(ctx, db)
		if p.SystemID != "" && st.SystemID != "" && st.SystemID != p.SystemID {
			return nil, fmt.Errorf("the PostgreSQL on port %d is another database system (%s, not %s); Rowsafe left it alone", db.Port, st.SystemID, p.SystemID)
		}
		if f.InRecovery {
			tl.Printf("PostgreSQL on port %d is running read-only (in recovery)", db.Port)
		}
		c = clusterFacts{DataDir: f.DataDir, Major: f.Major, SystemID: st.SystemID, ConfigFile: f.ConfigFile, HbaFile: f.HbaFile, IdentFile: f.IdentFile}
		rt.setCluster(db.ID, c)
		running = true
	}
	if c.DataDir == "" {
		return nil, fmt.Errorf("PostgreSQL on port %d isn't answering and Rowsafe doesn't know its data directory, so it can't make sure it stays stopped", db.Port)
	}
	// Hold the fence before anything else: from here the agent keeps the
	// cluster stopped, whatever happens to this task.
	fence := fenceRecord{Fence: protocol.Fence{ID: p.FenceID, DatabaseID: db.ID, Port: db.Port, SocketDir: db.SocketDir,
		SystemID: p.SystemID, Since: time.Now().UTC()}, DataDir: c.DataDir, Major: c.Major}
	if err := rt.addFence(fence); err != nil {
		return nil, err
	}
	if err := writeStandbySignal(c.DataDir); err != nil {
		return nil, fmt.Errorf("writing standby.signal (so it can only come back read-only): %w", err)
	}
	tl.Printf("wrote standby.signal in %s: if this PostgreSQL is started again it comes up read-only", c.DataDir)
	if running || ops.running(c.DataDir) {
		how, err := a.stopCluster(ctx, ops, db.Port, c.DataDir, c.Major, p.FenceID+"-stop", tl)
		if err != nil {
			return nil, fmt.Errorf("stopping PostgreSQL: %w", err)
		}
		res.Method = how
	} else {
		res.Method = "already_stopped"
	}
	res.Stopped = true
	now := time.Now().UTC()
	rt.updateFence(p.FenceID, func(f *fenceRecord) { f.StoppedAt, f.Running = &now, false })
	tl.Printf("PostgreSQL is stopped (%s)", res.Method)

	cd, err := ops.controlData(c.DataDir, c.Major)
	if err != nil {
		res.Warnings = append(res.Warnings, "couldn't read the stopped cluster's last checkpoint: "+err.Error())
	} else {
		res.CheckpointLSN, res.Timeline = cd.CheckpointLSN, cd.Timeline
		if cd.State != "shut down" && cd.State != "shut down in recovery" {
			res.Warnings = append(res.Warnings, "PostgreSQL wasn't shut down cleanly ("+cd.State+")")
			res.CheckpointLSN = ""
		}
	}
	// Push what WAL is left to the bucket, the last (partial) segment too,
	// so a standby that follows through the bucket gets every change.
	if res.CheckpointLSN != "" {
		pushed, err := a.pushFinalWAL(ctx, ops, db, c.DataDir, cd.RedoWALFile, tl)
		switch {
		case err != nil:
			res.Warnings = append(res.Warnings, "pushing the last WAL to the bucket: "+err.Error())
		default:
			res.FinalWALPushed = pushed
		}
	}
	res.Summary = fmt.Sprintf("Stopped PostgreSQL on port %d for good (%s): standby.signal keeps it read-only if started again, and the agent keeps it stopped.",
		db.Port, res.Method)
	if res.CheckpointLSN != "" {
		res.Summary += " Its last change is at " + res.CheckpointLSN + "."
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// pushFinalWAL pushes the WAL files still waiting for archiving and the
// segment holding the shutdown checkpoint.
func (a *Agent) pushFinalWAL(ctx context.Context, ops standbyOps, db protocol.DatabaseSpec, dataDir, redoFile string, tl *taskLog) (bool, error) {
	walDir := filepath.Join(dataDir, "pg_wal")
	var files []string
	if entries, err := os.ReadDir(filepath.Join(walDir, "archive_status")); err == nil {
		for _, e := range entries {
			if name, ok := strings.CutSuffix(e.Name(), ".ready"); ok && walFileRE.MatchString(name) {
				files = append(files, name)
			}
		}
	}
	sort.Strings(files)
	if walFileRE.MatchString(redoFile) {
		files = append(files, redoFile)
	}
	if len(files) == 0 {
		return false, errors.New("no WAL file to push")
	}
	for _, f := range files {
		out, err := ops.archivePush(ctx, db, filepath.Join(walDir, f))
		tl.Output("pgbackrest archive-push "+f, out)
		if err != nil {
			return false, err
		}
	}
	tl.Printf("pushed %s to the bucket", countNoun(len(files), "WAL file", "WAL files"))
	return true, nil
}

// holdFence makes sure a fenced cluster is stopped (standbyLoop).
func (a *Agent) holdFence(ctx context.Context, f fenceRecord) {
	rt := a.sb()
	// A rebuild in progress (or done) owns the cluster now.
	for _, r := range rt.standbys() {
		if r.DatabaseID == f.DatabaseID && r.Database.Port == f.Port {
			return
		}
	}
	if !f.LastTry.IsZero() && time.Since(f.LastTry) < fenceRetry && f.Running {
		return
	}
	ops := a.sops()
	spec := protocol.DatabaseSpec{ID: f.DatabaseID, Port: f.Port, SocketDir: f.SocketDir}
	st, err := ops.status(ctx, spec)
	dataDir, major := f.DataDir, f.Major
	running := false
	switch {
	case err == nil && f.SystemID != "" && st.SystemID != "" && st.SystemID != f.SystemID:
		rt.updateFence(f.ID, func(x *fenceRecord) { x.Other, x.Running, x.LastError = true, false, "" })
		return
	case err == nil:
		running = true
		if st.DataDir != "" {
			dataDir = filepath.Clean(st.DataDir)
		}
	case dataDir != "" && ops.running(dataDir):
		running = true
	}
	if !running {
		if f.StoppedAt == nil || f.Running {
			now := time.Now().UTC()
			rt.updateFence(f.ID, func(x *fenceRecord) { x.Running, x.Other, x.LastError = false, false, ""; x.StoppedAt = &now })
		}
		if dataDir != "" && !exists(filepath.Join(dataDir, "standby.signal")) && exists(filepath.Join(dataDir, "PG_VERSION")) {
			_ = writeStandbySignal(dataDir)
		}
		return
	}
	now := time.Now().UTC()
	rt.updateFence(f.ID, func(x *fenceRecord) { x.Running, x.LastTry, x.DataDir = true, now, dataDir })
	a.log.Error("a fenced PostgreSQL is running: this server's copy of the database is no longer the primary; stopping it",
		"database_id", f.DatabaseID, "port", f.Port, "data_dir", dataDir, "in_recovery", st.InRecovery)
	if major == 0 {
		if c, ok := rt.cluster(f.DatabaseID); ok {
			major = c.Major
		}
	}
	if dataDir != "" {
		if err := writeStandbySignal(dataDir); err != nil {
			a.log.Warn("writing standby.signal into the fenced cluster", "err", err)
		}
	}
	if !rt.hasFence(f.ID) {
		return // lifted meanwhile (unfence, rebuild)
	}
	tl := &taskLog{}
	how, err := a.stopCluster(ctx, ops, f.Port, dataDir, major, f.ID+"-hold", tl)
	if err != nil {
		rt.updateFence(f.ID, func(x *fenceRecord) { x.LastError = err.Error() })
		a.log.Error("stopping the fenced PostgreSQL failed", "port", f.Port, "err", err, "log", tl.String())
		return
	}
	stopped := time.Now().UTC()
	rt.updateFence(f.ID, func(x *fenceRecord) { x.Running, x.LastError, x.StoppedAt = false, "", &stopped })
	a.log.Warn("stopped the fenced PostgreSQL", "port", f.Port, "how", how)
}

// standbyUnfence starts a fenced primary again when the promotion that
// fenced it didn't happen.
func (a *Agent) standbyUnfence(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyUnfenceParams, tl *taskLog) (*protocol.StandbyUnfenceResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.FenceID) {
		return nil, fmt.Errorf("invalid fence id %q", p.FenceID)
	}
	res := &protocol.StandbyUnfenceResult{FenceID: p.FenceID}
	var fence *fenceRecord
	for _, f := range rt.fences() {
		if f.ID == p.FenceID {
			fence = &f
		}
	}
	if fence == nil {
		return nil, errors.New("this server holds no such fence")
	}
	if err := a.helperCanStopStart(fence.Port); err != nil {
		return nil, err
	}
	if err := rt.releaseFence(p.FenceID); err != nil {
		return nil, err
	}
	if fence.DataDir != "" {
		if err := os.Remove(filepath.Join(fence.DataDir, "standby.signal")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	ops := a.sops()
	tl.Printf("removed standby.signal; starting PostgreSQL on port %d through the root helper", fence.Port)
	if err := ops.helper(ctx, helperStart, fence.Port, p.FenceID+"-start"); err != nil && !ops.running(fence.DataDir) {
		return nil, fmt.Errorf("starting PostgreSQL: %w", err)
	}
	if err := ops.waitReady(ctx, db, fence.DataDir, inPlaceReadyWait); err != nil {
		return nil, err
	}
	res.Started = true
	res.Summary = fmt.Sprintf("PostgreSQL on port %d is running again as the primary.", fence.Port)
	tl.Printf("%s", res.Summary)
	return res, nil
}
