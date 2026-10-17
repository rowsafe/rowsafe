package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof on another server (protocol.ForkRestoreParams.Verify).
//
// When a database's own server lacks the disk for its restore test, the
// control plane runs it here: a fork that is only checked. fork_prepare on
// the source's server sealed the bucket settings to this agent's key (as
// for any fork) and read what the test checks against
// (protocol.ForkVerifyFacts). fork_restore with Verify restores the newest
// point in the source's backups into this server's drill directory with the
// drill's own restore and checks, reports a DrillResult and deletes the
// copy, whatever happens. It never registers a database, never creates or
// takes a cluster, writes no forks.json record and starts no backups.

// EngineForkVerify is optionally implemented by an engine whose restore
// test can run on another server (protocol.FeatureProofElsewhere).
type EngineForkVerify interface {
	// VerifyFacts runs on the source's server (fork_prepare with Verify):
	// what the test elsewhere checks the restored copy against.
	VerifyFacts(ctx context.Context, env EngineEnv, source protocol.DatabaseSpec) (*protocol.ForkVerifyFacts, error)
	// ForkVerify runs on the other server: it restores p.Source's newest
	// point from env.Repo (the source's backups) into a scratch directory
	// under env.Config.DrillDir named after id, runs the engine's drill
	// checks against p.VerifyFacts (nothing on the source can be asked),
	// and deletes the copy before it returns. Like the drill, a failed
	// check returns the result with the error.
	ForkVerify(ctx context.Context, env EngineEnv, p protocol.ForkRestoreParams, id string, log TaskLogger) (*protocol.DrillResult, error)
}

func engineForkVerify(engine string) EngineForkVerify {
	e := engineFor(protocol.NormalizeEngine(engine))
	if e == nil {
		return nil
	}
	v, _ := e.(EngineForkVerify)
	return v
}

// verifyFacts reads what a restore test elsewhere checks against, on the
// source's server.
func (a *Agent) verifyFacts(ctx context.Context, source protocol.DatabaseSpec) (*protocol.ForkVerifyFacts, error) {
	if !isPostgres(source) {
		v := engineForkVerify(source.Engine)
		if v == nil {
			return nil, fmt.Errorf("restore tests of %s databases on another server aren't available with this agent (%s)",
				protocol.EngineDisplayName(source.Engine), Version)
		}
		return v.VerifyFacts(ctx, a.engineEnvFor(source), source)
	}
	prod, err := pginspect.Inspect(ctx, a.target(source))
	if err != nil {
		return nil, err
	}
	return &protocol.ForkVerifyFacts{Databases: prod.Databases, SizeBytes: prod.TotalSizeBytes,
		Version: strconv.Itoa(prod.VersionNum), Preload: prod.SharedPreloadLibraries}, nil
}

// drillFreeBytes is the free disk where restore tests run here (the
// heartbeat's DrillFreeBytes).
func (a *Agent) drillFreeBytes() int64 {
	if a.cfg.DrillDir == "" {
		return 0
	}
	return freeBytesNear(a.cfg.DrillDir)
}

// forkVerifyID is the scratch directory name of a restore test elsewhere.
func forkVerifyID(forkID string) string { return "verify-" + forkID }

// forkVerify runs a restore test of another server's database here.
func (a *Agent) forkVerify(ctx context.Context, p protocol.ForkRestoreParams, tl *taskLog) (*protocol.ForkRestoreResult, error) {
	start := time.Now()
	switch {
	case !forkIDRE.MatchString(p.ForkID):
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	case !forkStanzaRE.MatchString(p.Source.Stanza) && protocol.NormalizeEngine(p.Source.Engine) != protocol.EngineSQLite:
		return nil, errors.New("the restore test names no source database")
	case p.Source.Stanza == "":
		return nil, errors.New("the restore test names no source database")
	case p.VerifyFacts == nil:
		return nil, errors.New("the restore test has nothing to check the restore against: the source's server didn't report its databases")
	case p.Target.Time != nil || p.Target.Mark != "":
		return nil, errors.New("a restore test restores the newest point in the backups, not a moment or a Mark")
	}
	res := &protocol.ForkRestoreResult{ForkID: p.ForkID}
	var dr *protocol.DrillResult
	var err error
	if isPostgres(p.Source) {
		dr, err = a.pgForkVerify(ctx, p, tl)
	} else {
		dr, err = a.engineVerify(ctx, p, tl)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if dr == nil && err != nil {
		return nil, err
	}
	res.Drill = dr
	if dr != nil && dr.Passed {
		res.Summary = fmt.Sprintf("Restore test of %s passed on this server; the restored copy was deleted.", cmp.Or(p.Source.Name, p.Source.Stanza))
	} else {
		res.Summary = fmt.Sprintf("Restore test of %s failed on this server; the restored copy was deleted.", cmp.Or(p.Source.Name, p.Source.Stanza))
	}
	return res, err
}

// engineForkRepo is the repository a fork or restore test of a database
// of another engine reads the source's backups from: the sealed handoff
// (another server), this server's own (the source runs here), or this
// server's own settings for a lost source (OwnRepo). cleanup removes what
// it wrote (a CA bundle).
func (a *Agent) engineForkRepo(ctx context.Context, p protocol.ForkRestoreParams, tl *taskLog) (repo pgbackrest.Repo, cleanup func(), err error) {
	cleanup = func() {}
	switch {
	case p.Box == nil && p.OwnRepo:
		r, err := a.lostSourceRepo(ctx, p)
		if err != nil {
			return r, cleanup, err
		}
		tl.Printf("the source's server is lost: reading %s's backups with this server's own storage settings; nothing was handed over",
			cmp.Or(p.Source.Name, p.Source.Stanza))
		return r, cleanup, nil
	case p.Box == nil:
		tl.Printf("the source %s runs on this server: its backups are read with this server's own settings; nothing leaves the server",
			cmp.Or(p.Source.Name, p.Source.Stanza))
		return a.repoFor(p.Source), cleanup, nil
	}
	rt := a.sb()
	if rt.key == nil {
		return repo, cleanup, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
	}
	if err := a.peerAllowed(p.Box.SenderKey, "the source's server"); err != nil {
		return repo, cleanup, err
	}
	plain, err := handoff.Open(rt.key, *p.Box, protocol.HandoffPurposeFork, protocol.ForkHandoffContext(p.Source.ID, p.ForkID), p.SenderKey)
	if err != nil {
		return repo, cleanup, fmt.Errorf("opening the source server's sealed bucket settings: %w", err)
	}
	var sec protocol.ForkSecrets
	err = json.Unmarshal(plain, &sec)
	clear(plain)
	if err != nil {
		return repo, cleanup, fmt.Errorf("reading the source server's handoff: %w", err)
	}
	ca := filepath.Join(a.standbyDir(), "fork-"+safeFileID(p.ForkID)+"-ca.pem")
	if sec.Repo.CAPEM != "" {
		if err := os.MkdirAll(a.standbyDir(), 0o700); err != nil {
			return repo, cleanup, err
		}
		cleanup = func() { _ = os.Remove(ca) }
	}
	// In Rowsafe Storage: this agent's own credentials (same organization).
	if repo, err = a.repoFromHandoff(ctx, sec.Repo, ca); err != nil {
		cleanup()
		return repo, func() {}, err
	}
	tl.Printf("opened the source server's sealed bucket settings (read access to %s's backups)", cmp.Or(p.Source.Name, p.Source.Stanza))
	return repo, cleanup, nil
}

// engineVerify runs a restore test of a database of another engine.
func (a *Agent) engineVerify(ctx context.Context, p protocol.ForkRestoreParams, tl *taskLog) (*protocol.DrillResult, error) {
	v := engineForkVerify(p.Source.Engine)
	if v == nil {
		return nil, fmt.Errorf("restore tests of %s databases from another server aren't available with this agent (%s)",
			protocol.EngineDisplayName(p.Source.Engine), Version)
	}
	if a.cfg.Sidecar() {
		return nil, errors.New("restore tests of another server's databases need the agent installed on the server itself, not in Docker")
	}
	env := a.engineEnv(protocol.NormalizeEngine(p.Source.Engine))
	repo, cleanup, err := a.engineForkRepo(ctx, p, tl)
	defer cleanup()
	if err != nil {
		return nil, err
	}
	if err := repo.Validate(); err != nil {
		return nil, fmt.Errorf("the source's backup settings: %w", err)
	}
	env.Repo = repo
	if free, need := a.drillFreeBytes(), protocol.ProofSpaceNeeded(p.VerifyFacts.SizeBytes); free > 0 && free < need {
		return nil, fmt.Errorf("not enough disk for the restore test here: %s free in %s, need about %s",
			humanBytes(free), a.cfg.DrillDir, humanBytes(need))
	}
	return v.ForkVerify(ctx, env, p, forkVerifyID(p.ForkID), tl)
}

// pgForkVerify restores a PostgreSQL source's newest point into the drill
// directory with the drill's own restore and checks (drillRestore).
func (a *Agent) pgForkVerify(ctx context.Context, p protocol.ForkRestoreParams, tl *taskLog) (*protocol.DrillResult, error) {
	rt := a.fk()
	if !rt.opMu.TryLock() {
		return nil, errors.New("a fork or another restore test is running on this server; it runs again at the next Proof")
	}
	defer rt.opMu.Unlock()
	src, err := a.forkSourceFor(ctx, a.fops(), p, tl)
	ca := filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+"-ca.pem")
	defer os.Remove(ca)
	if err != nil {
		return nil, err
	}
	major := src.major
	if v, err := strconv.Atoi(p.VerifyFacts.Version); err == nil && v/10000 >= 13 {
		major = v / 10000
	}
	if _, err := os.Stat(a.cfg.pgBin(major, "postgres")); err != nil {
		return nil, fmt.Errorf("PostgreSQL %d isn't installed on this server, and a restore test needs the source's major version", major)
	}
	id := forkVerifyID(p.ForkID)
	dir, err := a.drillDir(id, "")
	if err != nil {
		return nil, err
	}
	// The pgBackRest config that reads the source's backups, pointed at the
	// scratch cluster; WAL replay reads through it, so it goes last.
	conf := filepath.Join(a.cfg.ConfigDir, "fork-"+p.ForkID+".conf")
	defer os.Remove(conf)
	rec := forkRecord{ID: p.ForkID, DataDir: filepath.Join(dir, "data"), Port: a.cfg.DrillPort, SourceConf: conf}
	if err := a.writeForkSourceConf(rec, p.Source, src.repo, filepath.Join(dir, "socket")); err != nil {
		return nil, err
	}
	cli := pgbackrest.CLI{Bin: a.cfg.PgBackRestBin, ConfigPath: conf, Stanza: p.Source.Stanza, Runner: a.runner}
	// Without an account the source's server can't be asked (sudo rowsafe
	// proof NAME --from-bucket): the backups give the size, and the
	// restored databases are listed rather than compared.
	size, list := cmp.Or(p.VerifyFacts.SizeBytes, src.sizeBytes), p.OwnRepo && len(p.VerifyFacts.Databases) == 0
	tl.Printf("restore test of %s (PostgreSQL %d, %s) from its backups, on this server", cmp.Or(p.Source.Name, p.Source.Stanza), major,
		humanBytes(size))
	res := &protocol.DrillResult{}
	err = a.drillRestore(ctx, drillSource{cli: cli, stanza: p.Source.Stanza, major: major, sizeBytes: size,
		preload: p.VerifyFacts.Preload, databases: p.VerifyFacts.Databases, listRestored: list}, id, res, tl)
	return res, err
}
