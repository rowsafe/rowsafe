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
	"github.com/rowsafe/rowsafe/protocol"
)

// A Docker fork target: a new postgres service whose container waits until
// Rowsafe has restored the fork into its (empty) volume, and a sidecar agent
// with that volume mounted read-write and ROWSAFE_FORK_TARGET_DIR set to its
// PGDATA. The sidecar restores, replays and masks privately (its own
// PostgreSQL binaries, a socket in its own state directory), stops, and
// writes forkReadyFile: the postgres container's command waits for it, then
// starts PostgreSQL on the fork as usual. See the Fork guide for the
// compose file.

// forkReadyFile is written into PGDATA once the fork is ready to start.
const forkReadyFile = "rowsafe-fork.done"

// forkDockerWait is how long the sidecar waits for the postgres container
// to start on the fork.
var forkDockerWait = 15 * time.Minute

// forkTargetEmpty reports whether nothing was restored into dir yet.
func forkTargetEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	for _, e := range entries {
		if e.Name() != "lost+found" {
			return false
		}
	}
	return true
}

// forkDockerTarget is what a Docker fork target reports in its heartbeat.
func (a *Agent) forkDockerTarget() *protocol.ForkDockerTarget {
	if !a.cfg.Sidecar() || a.cfg.ForkTargetDir == "" {
		return nil
	}
	t := &protocol.ForkDockerTarget{Empty: forkTargetEmpty(a.cfg.ForkTargetDir)}
	if majors := a.installedMajors(); len(majors) > 0 {
		t.Major = majors[len(majors)-1]
	}
	return t
}

// dockerDefaultConf is what the official postgres image writes into a new
// PGDATA: a restore from a server whose configuration lives in /etc gets
// it, so the container can start.
const dockerDefaultConf = "listen_addresses = '*'\n"

const dockerDefaultHba = `# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     trust
host    all             all             127.0.0.1/32            trust
host    all             all             ::1/128                 trust
local   replication     all                                     trust
host    replication     all             127.0.0.1/32            trust
host    replication     all             ::1/128                 trust
host    all             all             all                     scram-sha-256
`

func (a *Agent) forkRestoreDocker(ctx context.Context, ops forkOps, p protocol.ForkRestoreParams, src forkSource, rec forkRecord,
	typ, target, set string, start time.Time, tl *taskLog) (*protocol.ForkRestoreResult, error) {
	rt := a.fk()
	dir := a.cfg.ForkTargetDir
	switch {
	case dir == "":
		return nil, errors.New("this Docker agent isn't set up to receive a fork (ROWSAFE_FORK_TARGET_DIR)")
	case !forkTargetEmpty(dir):
		return nil, fmt.Errorf("the fork target's data directory %s already holds a database: a Docker fork target takes one fork", dir)
	}
	if majors := a.installedMajors(); len(majors) == 0 || majors[len(majors)-1] != src.major {
		return nil, fmt.Errorf("this Docker fork target runs PostgreSQL %v and the source %d: use the image of the same major version", majors, src.major)
	}
	rec.DataDir, rec.Port, rec.SocketDir = dir, cmp.Or(p.Port, 5432), cmp.Or(p.SocketDir, "/var/run/postgresql")
	db := protocol.DatabaseSpec{Name: p.Name, Port: rec.Port, SocketDir: rec.SocketDir}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID, Placement: p.Placement, Port: rec.Port, SocketDir: rec.SocketDir, DataDir: dir, Major: src.major}
	fail := func(step string, cause error) (*protocol.ForkRestoreResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		tl.Printf("%s failed: %v", step, cause)
		if rbErr := a.rollbackForkDocker(context.WithoutCancel(ctx), ops, rec, tl); rbErr != nil {
			res.Summary = fmt.Sprintf("Forking failed while %s: %v. Emptying the target's volume also failed: %v.", step, cause, rbErr)
			return res, errors.New(res.Summary)
		}
		_ = rt.remove(p.ForkID)
		res.Summary = fmt.Sprintf("Forking failed while %s: %v. The target's volume is empty again, ready for another try.", step, cause)
		return res, errors.New(res.Summary)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	need := src.sizeBytes + src.sizeBytes/10 + 256<<20
	if free, err := ops.freeBytes(dir); err == nil && free < need {
		return nil, fmt.Errorf("not enough free disk in the fork target's volume: the fork needs about %s and %s is free", humanBytes(need), humanBytes(free))
	}
	socketDir := filepath.Join(rec.Private, "socket")
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(rec.Port)); n > maxSocketPath {
		return nil, fmt.Errorf("the fork's private socket path would be %d bytes: use a shorter ROWSAFE_STATE_DIR", n)
	}
	if err := os.MkdirAll(rec.Private, 0o700); err != nil {
		return nil, err
	}
	rec.SourceConf = filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+".conf")
	if err := a.writeForkSourceConf(rec, p.Source, src.repo, socketDir); err != nil {
		return nil, err
	}
	rec.Phase = phasePreflight
	if err := rt.put(rec); err != nil {
		return nil, err
	}
	cli := pgbackrest.CLI{Bin: a.cfg.PgBackRestBin, ConfigPath: rec.SourceConf, Stanza: p.Source.Stanza, Runner: a.runner}
	stanzas, err := ops.sourceInfo(ctx, cli)
	if err == nil {
		err = checkBackupSet(stanzas, p.Source.Stanza, set)
	} else {
		err = fmt.Errorf("Rowsafe can't read %s's backups from here: %w", cmp.Or(p.Source.Name, p.Source.Stanza), err)
	}
	if err != nil {
		_ = a.rollbackFork(ctx, rec, tl)
		_ = rt.remove(p.ForkID)
		return nil, err
	}

	rec.Phase = phaseRestored
	_ = rt.put(rec)
	rt.step(p.ForkID, protocol.ForkStepRestore, fmt.Sprintf("Downloading %s's backup (%s)", cmp.Or(p.Source.Name, p.Source.Stanza), humanBytes(src.sizeBytes)))
	tl.Printf("restoring %s as it was at %s into the fork target's volume (%s)", cmp.Or(p.Source.Name, p.Source.Stanza), describeTarget(p.Target), dir)
	out, err := ops.restore(ctx, cli, pgbackrest.RestoreOptions{DataDir: dir, TablespaceDir: filepath.Join(rec.Private, "tablespaces"),
		Type: typ, Target: target, Set: set, Timeline: p.Target.Timeline})
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fail("restoring the backup", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(dir, "pg_tblspc")); len(entries) > 0 {
		return fail("restoring the backup", errors.New("the source uses tablespaces, which Rowsafe can't fork yet"))
	}
	// A source whose configuration lives outside its data directory (Debian)
	// gets the image's defaults.
	for name, content := range map[string]string{"postgresql.conf": dockerDefaultConf, "pg_hba.conf": dockerDefaultHba, "pg_ident.conf": ""} {
		path := filepath.Join(dir, name)
		if !exists(path) {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				return fail("configuring the fork", err)
			}
			tl.Printf("wrote the postgres image's default %s (the source keeps its configuration outside its data directory)", name)
		}
	}
	if w, err := a.writeForkAutoConf(rec, src, ""); err != nil {
		return fail("configuring the fork", err)
	} else if w != "" {
		res.Warnings = append(res.Warnings, w)
	}
	rec.Phase = phaseRecovering
	_ = rt.put(rec)
	rt.step(p.ForkID, protocol.ForkStepRecover, "Replaying changes up to "+describeTarget(p.Target))
	recoveredTo, masking, err := a.forkRecover(ctx, ops, p, rec, socketDir, tl)
	_ = os.Remove(rec.SourceConf)
	rec.SourceConf = ""
	_ = rt.put(rec)
	if err != nil {
		return fail("replaying changes", err)
	}
	res.RecoveredTo, res.Masking = recoveredTo, masking

	rec.Phase = phaseStarted
	_ = rt.put(rec)
	rt.step(p.ForkID, protocol.ForkStepStart, "Starting the fork's PostgreSQL container")
	if err := os.WriteFile(filepath.Join(dir, forkReadyFile), []byte(p.ForkID+"\n"), 0o600); err != nil {
		return fail("starting the fork", err)
	}
	tl.Printf("the fork is ready in the volume; waiting for the PostgreSQL container to start on it")
	if err := ops.waitReady(ctx, db, dir, forkDockerWait); err != nil {
		return fail("starting the fork", fmt.Errorf("%w: the PostgreSQL container didn't start on the fork. Its compose command must wait for %s (see the Fork guide)",
			err, forkReadyFile))
	}
	a.finishFork(ctx, ops, db, rec, res, start, tl)
	return res, nil
}

// rollbackForkDocker empties the fork target's volume again.
func (a *Agent) rollbackForkDocker(ctx context.Context, ops forkOps, rec forkRecord, tl *taskLog) error {
	if rec.SourceConf != "" {
		_ = os.Remove(rec.SourceConf)
	}
	if rec.Private != "" && strings.HasPrefix(rec.Private, filepath.Join(a.cfg.StateDir, "fork")+string(filepath.Separator)) {
		defer os.RemoveAll(rec.Private)
	}
	dir := a.cfg.ForkTargetDir
	if rec.Phase == phasePreflight || rec.Phase == "" || dir == "" || filepath.Clean(rec.DataDir) != filepath.Clean(dir) {
		return nil
	}
	if ops.running(dir) {
		if err := ops.stopLocal(dir, rec.Major); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == "lost+found" {
			continue
		}
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	tl.Printf("emptied the fork target's volume %s", dir)
	return nil
}
