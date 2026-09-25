package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/protocol"
)

// Fork: a new, independent database cloned from another at any point in its
// recovery window.
//
// fork_prepare runs on the source's server when the fork goes to another
// one: it seals the source's bucket settings to the target agent's key (the
// fingerprint a person confirmed). fork_restore runs on the target server
// (fork_restore.go): it creates or takes a cluster, restores the source to
// the point privately, masks personal data when asked (fork_mask.go) and
// starts it. The control plane then registers it as a new database whose
// backups go to the target server's own bucket, under its own name.
//
// What survives an agent restart lives in <state dir>/forks.json: the fork
// restore running (so an interrupted one is rolled back) and the empty
// clusters' data kept aside (deleted after a week).

// forkIDRE is the shape of fork IDs.
var forkIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// forkNameRE is a Rowsafe database name.
var forkNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)

// forkKeepDays is how long an empty cluster's own data stays aside.
const forkKeepDays = 7

// forkRecord is a fork restore in progress on this server.
type forkRecord struct {
	ID        string `json:"id"`
	Placement string `json:"placement"`
	Port      int    `json:"port"`
	Major     int    `json:"major"`
	DataDir   string `json:"data_dir"`
	// KeptDir is the cluster's own data, set aside while the fork is
	// restored in its place (put back on a failure).
	KeptDir    string `json:"kept_dir,omitempty"`
	ConfigFile string `json:"config_file,omitempty"`
	HbaFile    string `json:"hba_file,omitempty"`
	IdentFile  string `json:"ident_file,omitempty"`
	SocketDir  string `json:"socket_dir"`
	Unit       string `json:"unit,omitempty"`
	Created    bool   `json:"created,omitempty"` // Rowsafe created the cluster for this fork
	// WasRunning: the cluster ran before (it is started again on a
	// rollback).
	WasRunning bool `json:"was_running,omitempty"`
	// SourceConf is the pgBackRest config that reads the source's backups
	// (0600, removed as soon as the restore is done).
	SourceConf string `json:"source_conf,omitempty"`
	// Private is the private recovery's directory (socket and log).
	Private   string    `json:"private,omitempty"`
	Phase     string    `json:"phase"` // phase* (rewind_state.go)
	StartedAt time.Time `json:"started_at"`
}

// forkKept is an empty cluster's own data set aside by a fork.
type forkKept struct {
	Path    string    `json:"path"`
	DataDir string    `json:"data_dir"`
	Until   time.Time `json:"until"`
}

type forkFile struct {
	Running []forkRecord `json:"running,omitempty"`
	Kept    []forkKept   `json:"kept,omitempty"`
}

// forkRuntime is the agent's Fork state.
type forkRuntime struct {
	mu   sync.Mutex
	path string
	file forkFile
	// progress is each running fork restore's latest step (heartbeat).
	progress map[string]protocol.ForkState
	// opMu is held by a fork restore: one at a time per server.
	opMu sync.Mutex
}

// fk returns the Fork runtime, loading it on first use.
func (a *Agent) fk() *forkRuntime {
	a.fkOnce.Do(func() {
		rt := &forkRuntime{path: filepath.Join(a.cfg.StateDir, "forks.json"), progress: map[string]protocol.ForkState{}}
		if data, err := os.ReadFile(rt.path); err == nil {
			if err := json.Unmarshal(data, &rt.file); err != nil {
				a.log.Error("reading the fork state; an interrupted fork can't be rolled back until it is fixed", "path", rt.path, "err", err)
			}
		}
		a.fkRT = rt
	})
	return a.fkRT
}

func (rt *forkRuntime) saveLocked() error {
	data, err := json.MarshalIndent(rt.file, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(rt.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(rt.path, data, 0o600)
}

func (rt *forkRuntime) put(r forkRecord) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for i, x := range rt.file.Running {
		if x.ID == r.ID {
			rt.file.Running[i] = r
			return rt.saveLocked()
		}
	}
	rt.file.Running = append(rt.file.Running, r)
	return rt.saveLocked()
}

func (rt *forkRuntime) remove(id string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.file.Running = slices.DeleteFunc(rt.file.Running, func(r forkRecord) bool { return r.ID == id })
	delete(rt.progress, id)
	return rt.saveLocked()
}

func (rt *forkRuntime) running() []forkRecord {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return slices.Clone(rt.file.Running)
}

func (rt *forkRuntime) keep(k forkKept) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.file.Kept = append(rt.file.Kept, k)
	return rt.saveLocked()
}

// step records a fork's progress for the heartbeat.
func (rt *forkRuntime) step(id, step, detail string) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.progress[id] = protocol.ForkState{ForkID: id, Step: step, Detail: detail, At: time.Now().UTC()}
}

// forkHeartbeat is the Fork part of a heartbeat.
func (a *Agent) forkHeartbeat() protocol.ForkHeartbeat {
	var hb protocol.ForkHeartbeat
	if a.cfg.Sidecar() && a.cfg.Standby != StandbyOff {
		// Native agents report their key with Standby (box_key); a Docker
		// sidecar reports it for forks only.
		if k := a.sb().key; k != nil {
			hb.ForkBoxKey = k.PublicKey()
		}
	}
	hb.ForkClusters = a.forkClusters()
	hb.ForkTarget = a.forkDockerTarget()
	rt := a.fk()
	rt.mu.Lock()
	for _, s := range rt.progress {
		hb.Forks = append(hb.Forks, s)
	}
	rt.mu.Unlock()
	slices.SortFunc(hb.Forks, func(x, y protocol.ForkState) int { return x.At.Compare(y.At) })
	return hb
}

// forkLoop rolls back a fork restore an agent restart interrupted, and
// deletes kept data whose week is up.
func (a *Agent) forkLoop(ctx context.Context) {
	a.recoverForks(ctx)
	for {
		a.expireForkKept(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

// recoverForks puts back the clusters of fork restores that were running
// when the agent stopped.
func (a *Agent) recoverForks(ctx context.Context) {
	rt := a.fk()
	for _, r := range rt.running() {
		tl := &taskLog{}
		a.log.Warn("a fork restore was interrupted by an agent restart; putting the cluster back", "fork_id", r.ID, "phase", r.Phase)
		if err := a.rollbackFork(ctx, r, tl); err != nil {
			a.log.Error("putting the cluster back after an interrupted fork failed; will retry at the next start",
				"fork_id", r.ID, "err", err, "log", tl.String())
			continue
		}
		_ = rt.remove(r.ID)
	}
}

// keptForkDirRE matches an empty cluster's data set aside by a fork.
var keptForkDirRE = regexp.MustCompile(`^(.+)\.before-fork-[0-9]{8}T[0-9]{6}Z$`)

// validKeptForkDir checks kept is a directory a fork set aside for dataDir.
func validKeptForkDir(dataDir, kept string) error {
	dataDir, kept = filepath.Clean(dataDir), filepath.Clean(kept)
	m := keptForkDirRE.FindStringSubmatch(filepath.Base(kept))
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

func (a *Agent) expireForkKept(now time.Time) {
	rt := a.fk()
	rt.mu.Lock()
	var due []forkKept
	for _, k := range rt.file.Kept {
		if now.After(k.Until) {
			due = append(due, k)
		}
	}
	rt.mu.Unlock()
	for _, k := range due {
		if err := validKeptForkDir(k.DataDir, k.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("not deleting data kept aside by a fork", "path", k.Path, "err", err)
		} else if err := os.RemoveAll(k.Path); err != nil {
			a.log.Warn("deleting data kept aside by a fork", "path", k.Path, "err", err)
			continue
		} else {
			a.log.Info("deleted an empty cluster's data kept aside by a fork", "path", k.Path)
		}
		rt.mu.Lock()
		rt.file.Kept = slices.DeleteFunc(rt.file.Kept, func(x forkKept) bool { return x.Path == k.Path })
		_ = rt.saveLocked()
		rt.mu.Unlock()
	}
}

// ---- dispatch ----

// fork_prepare runs beside the main loop (it only seals a few settings), so
// it never waits behind a backup of the source.
func init() { sideTypes = append(sideTypes, protocol.TaskForkPrepare) }

func (a *Agent) runForkTask(ctx context.Context, task *protocol.Task, tl *taskLog) (any, error) {
	switch task.Type {
	case protocol.TaskForkPrepare:
		var p protocol.ForkPrepareParams
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
		}
		res, err := a.forkPrepare(ctx, p, tl)
		if res == nil {
			return nil, err
		}
		return res, err
	case protocol.TaskForkRestore:
		var p protocol.ForkRestoreParams
		if err := json.Unmarshal(task.Params, &p); err != nil {
			return nil, fmt.Errorf("invalid %s params: %w", task.Type, err)
		}
		res, err := a.forkRestore(ctx, p, tl)
		if res == nil {
			return nil, err
		}
		return res, err
	}
	return nil, fmt.Errorf("unsupported task type %q (agent %s)", task.Type, Version)
}

// ---- the source's side ----

// forkPrepare seals the source's repository settings for the target agent.
func (a *Agent) forkPrepare(ctx context.Context, p protocol.ForkPrepareParams, tl *taskLog) (*protocol.ForkPrepareResult, error) {
	if !forkIDRE.MatchString(p.ForkID) {
		return nil, fmt.Errorf("invalid fork id %q", p.ForkID)
	}
	if p.Source.ID == "" || p.Source.Stanza == "" || p.Source.Port < 1 {
		return nil, errors.New("the fork names no source database")
	}
	if a.cfg.Standby == StandbyOff {
		return nil, errors.New("handing this database's bucket settings to another server is turned off here (ROWSAFE_STANDBY=off in /etc/rowsafe/agent.env); fork it on this same server instead")
	}
	rt := a.sb()
	if rt.key == nil {
		return nil, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
	}
	fp, err := handoff.Fingerprint(p.RecipientKey)
	if err != nil {
		return nil, fmt.Errorf("the target server's key: %w", err)
	}
	if !handoff.SameFingerprint(fp, p.RecipientFingerprint) {
		return nil, fmt.Errorf("the target server's key has fingerprint %s, not %s as confirmed: nothing was sent", fp, p.RecipientFingerprint)
	}
	if err := a.peerAllowed(p.RecipientKey, "the target server"); err != nil {
		return nil, err
	}
	res := &protocol.ForkPrepareResult{ForkID: p.ForkID}
	f, err := a.readPrimaryFacts(ctx, p.Source)
	if err != nil {
		return nil, fmt.Errorf("reading PostgreSQL's settings: %w", err)
	}
	if f.Tablespaces > 0 {
		return nil, fmt.Errorf("this database uses %s; Rowsafe can't fork those to another server yet", countNoun(f.Tablespaces, "tablespace", "tablespaces"))
	}
	res.Major, res.SystemID, res.SizeBytes, res.Settings = f.Major, f.SystemID, f.SizeBytes, f.Settings
	repo, err := a.handedRepo(p.Source)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(protocol.ForkSecrets{Repo: repo})
	if err != nil {
		return nil, err
	}
	box, err := handoff.Seal(rt.key, p.RecipientKey, protocol.HandoffPurposeFork, protocol.ForkHandoffContext(p.Source.ID, p.ForkID), plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	res.Box = box
	a.log.Warn("sealed this database's bucket settings for a fork on another server (read access to its backups)",
		"database", p.Source.Name, "fork_id", p.ForkID, "recipient_fingerprint", fp)
	res.Summary = fmt.Sprintf("Sealed the bucket settings for the fork's server (key %s): it can read this database's backups to restore the fork.", fp)
	tl.Printf("%s", res.Summary)
	return res, nil
}
