package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/protocol"
)

// EngineStandby is optionally implemented by an engine whose databases can
// have a standby server (protocol.FeatureStandby). The agent keeps what is
// the same for every engine: the sealed handoff between the two agents (the
// primary's bucket settings and the replication login), the bucket a
// primary handed over, the fences' bookkeeping and the heartbeat. The
// engine does the database's part.
type EngineStandby interface {
	// StandbyPrepare runs on the primary: it checks the database can be
	// followed and, with p.Stream, creates the standby's replication login
	// for p.StandbyAddresses. It fills sec (the agent sets sec.Repo, then
	// seals it to the standby's agent) and res (except Box).
	StandbyPrepare(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams,
		sec *protocol.StandbySecrets, res *protocol.StandbyPrepareResult, log TaskLogger) error
	// StandbyCreate runs on the standby's server: db.Port and db.SocketDir
	// are the (empty) server there that becomes the standby, env.Repo is
	// the primary's bucket and sec what the primary sealed.
	StandbyCreate(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams,
		sec protocol.StandbySecrets, log TaskLogger) (*protocol.StandbyCreateResult, error)
	// StandbyPromote makes the standby the primary.
	StandbyPromote(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, log TaskLogger) (*protocol.StandbyPromoteResult, error)
	// StandbyRemove stops following on the standby's server.
	StandbyRemove(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, log TaskLogger) (*protocol.StandbyRemoveResult, error)
	// StandbyRelease drops what prepare made on the primary.
	StandbyRelease(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, log TaskLogger) (*protocol.StandbyReleaseResult, error)
	// StandbyFence makes the old primary stop taking writes for good,
	// before its standby is promoted. On an error the database must be as
	// it was (still the primary): the agent then drops the fence.
	StandbyFence(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, log TaskLogger) (*protocol.StandbyFenceResult, error)
	// HoldFence makes sure a fenced database still takes no writes; it is
	// called every few seconds while the fence holds (and must leave a
	// server rebuilt as the new primary's standby alone). enforced: it was
	// taking writes again and was fenced again just now; other: another
	// database server runs on the port now (left alone).
	HoldFence(ctx context.Context, env EngineEnv, f protocol.Fence) (enforced, other bool, err error)
	// StandbyUnfence lets a fenced old primary take writes again (the
	// promotion that fenced it did not happen).
	StandbyUnfence(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, f protocol.Fence, log TaskLogger) (*protocol.StandbyUnfenceResult, error)
	// StandbyStates are the standbys this server runs (heartbeat).
	StandbyStates(ctx context.Context, env EngineEnv) []protocol.StandbyState
	// PrimaryState is db's position as a primary (heartbeat); false when
	// it isn't one or doesn't answer.
	PrimaryState(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (protocol.PrimaryState, bool)
	EngineTargets
}

// EngineTargets is optionally implemented by an engine that reports the
// servers on this host that could hold a standby or a clone: empty, and
// Rowsafe's account there may load data into them (heartbeat).
type EngineTargets interface {
	StandbyTargets(ctx context.Context, env EngineEnv) []protocol.StandbyTarget
}

// engineStandby is the EngineStandby of db's engine (nil when it has none).
func engineStandby(engine string) EngineStandby {
	e := engineFor(protocol.NormalizeEngine(engine))
	if e == nil {
		return nil
	}
	s, _ := e.(EngineStandby)
	return s
}

// engineEnvFor is the EngineEnv for one of db's tasks: the bucket is the
// one its primary handed over when this server became its standby (and
// stays so once promoted), else the agent's own.
func (a *Agent) engineEnvFor(db protocol.DatabaseSpec) EngineEnv {
	env := a.engineEnv(protocol.NormalizeEngine(db.Engine))
	env.Repo = a.repoFor(db)
	return env
}

// runEngineStandby runs a standby task for a database of another engine.
func (a *Agent) runEngineStandby(ctx context.Context, task *protocol.Task, tl *taskLog, db protocol.DatabaseSpec) (any, error) {
	es := engineStandby(db.Engine)
	if es == nil {
		return nil, fmt.Errorf("standby servers aren't available for %s databases with this agent (%s)", protocol.EngineDisplayName(db.Engine), Version)
	}
	switch task.Type {
	case protocol.TaskStandbyPrepare:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams, tl *taskLog) (*protocol.StandbyPrepareResult, error) {
			return a.engineStandbyPrepare(ctx, es, db, p, tl)
		})
	case protocol.TaskStandbyCreate:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyCreateParams, tl *taskLog) (*protocol.StandbyCreateResult, error) {
			return a.engineStandbyCreate(ctx, es, db, p, tl)
		})
	case protocol.TaskStandbyPromote:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, tl *taskLog) (*protocol.StandbyPromoteResult, error) {
			if !standbyIDRE.MatchString(p.StandbyID) {
				return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
			}
			return es.StandbyPromote(ctx, a.engineEnvFor(db), db, p, tl)
		})
	case protocol.TaskStandbyRemove:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, tl *taskLog) (*protocol.StandbyRemoveResult, error) {
			if !standbyIDRE.MatchString(p.StandbyID) {
				return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
			}
			res, err := es.StandbyRemove(ctx, a.engineEnvFor(db), db, p, tl)
			if err == nil && db.ID != "" && !a.watches(db.ID) {
				_ = os.Remove(a.repoPath(db.ID))
				_ = os.Remove(a.caPath(db.ID))
			}
			return res, err
		})
	case protocol.TaskStandbyRelease:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, tl *taskLog) (*protocol.StandbyReleaseResult, error) {
			if !standbyIDRE.MatchString(p.StandbyID) {
				return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
			}
			return es.StandbyRelease(ctx, a.engineEnvFor(db), db, p, tl)
		})
	case protocol.TaskStandbyFence:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, tl *taskLog) (*protocol.StandbyFenceResult, error) {
			return a.engineStandbyFence(ctx, es, db, p, tl)
		})
	case protocol.TaskStandbyUnfence:
		return runRewind(ctx, task, tl, db, func(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyUnfenceParams, tl *taskLog) (*protocol.StandbyUnfenceResult, error) {
			return a.engineStandbyUnfence(ctx, es, db, p, tl)
		})
	}
	return nil, fmt.Errorf("unsupported task type %q (agent %s)", task.Type, Version)
}

// watches reports whether this agent watches database id (it is the
// primary here).
func (a *Agent) watches(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.watched {
		if d.ID == id {
			return true
		}
	}
	return false
}

func (a *Agent) engineStandbyPrepare(ctx context.Context, es EngineStandby, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams, tl *taskLog) (*protocol.StandbyPrepareResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.StandbyID) {
		return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
	}
	if rt.key == nil {
		return nil, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
	}
	fp, err := handoff.Fingerprint(p.RecipientKey)
	if err != nil {
		return nil, fmt.Errorf("the standby server's key: %w", err)
	}
	if !handoff.SameFingerprint(fp, p.RecipientFingerprint) {
		return nil, fmt.Errorf("the standby server's key has fingerprint %s, not %s as confirmed: nothing was sent. "+
			"Compare again with `rowsafe-agent key` on that server", fp, p.RecipientFingerprint)
	}
	if err := a.peerAllowed(p.RecipientKey, "the standby server"); err != nil {
		return nil, err
	}
	repo, err := a.handedRepo(db)
	if err != nil {
		return nil, err
	}
	res := &protocol.StandbyPrepareResult{StandbyID: p.StandbyID}
	sec := protocol.StandbySecrets{PrimaryPort: db.Port, PrimaryAddresses: localAddresses()}
	if err := es.StandbyPrepare(ctx, a.engineEnvFor(db), db, p, &sec, res, tl); err != nil {
		return res, err
	}
	sec.Repo = repo
	plain, err := json.Marshal(sec)
	if err != nil {
		return res, err
	}
	box, err := handoff.Seal(rt.key, p.RecipientKey, protocol.HandoffPurposeStandby, protocol.StandbyHandoffContext(db.ID, p.StandbyID), plain)
	clear(plain)
	if err != nil {
		return res, err
	}
	res.Box = box
	a.log.Warn("sealed this database's bucket settings for a standby server", "database", db.Name, "engine", db.Engine,
		"standby_id", p.StandbyID, "recipient_fingerprint", fp, "streaming", res.Streaming)
	if res.Summary == "" {
		res.Summary = fmt.Sprintf("Sealed the bucket settings for the standby (key %s).", fp)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (a *Agent) engineStandbyCreate(ctx context.Context, es EngineStandby, db protocol.DatabaseSpec, p protocol.StandbyCreateParams, tl *taskLog) (*protocol.StandbyCreateResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.StandbyID) || (p.FenceID != "" && !standbyIDRE.MatchString(p.FenceID)) {
		return nil, errors.New("invalid standby or fence id")
	}
	if p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", p.Port)
	}
	if rt.key == nil {
		return nil, errors.New("this agent's key for sealed handoffs isn't available (see the agent's log)")
	}
	if !rt.opMu.TryLock() {
		return nil, errors.New("another standby change is running on this server; try again when it has finished")
	}
	defer rt.opMu.Unlock()
	db.Port, db.SocketDir = p.Port, p.SocketDir
	if err := a.peerAllowed(p.Box.SenderKey, "the primary"); err != nil {
		return nil, err
	}
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
	// The primary's bucket, from now on this database's repository here.
	// In Rowsafe Storage this agent uses its own credentials for it.
	if sec.Repo.RowsafeStorage() {
		if err := a.ensureStorageCredentials(ctx); err != nil {
			return nil, err
		}
	}
	hadRepo := exists(a.repoPath(db.ID))
	if err := a.saveHandedRepo(db.ID, sec.Repo); err != nil {
		return nil, err
	}
	res, err := es.StandbyCreate(ctx, a.engineEnvFor(db), db, p, sec, tl)
	if err != nil && !hadRepo && !p.Rebuild {
		_ = os.Remove(a.repoPath(db.ID))
		_ = os.Remove(a.caPath(db.ID))
	}
	return res, err
}

func (a *Agent) engineStandbyFence(ctx context.Context, es EngineStandby, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, tl *taskLog) (*protocol.StandbyFenceResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.FenceID) {
		return nil, fmt.Errorf("invalid fence id %q", p.FenceID)
	}
	// Hold the fence first: from here the agent keeps the database from
	// taking writes, whatever happens to this task.
	f := protocol.Fence{ID: p.FenceID, DatabaseID: db.ID, Port: db.Port, SocketDir: db.SocketDir, SystemID: p.SystemID,
		Since: time.Now().UTC(), Engine: protocol.NormalizeEngine(db.Engine)}
	if err := rt.addFence(fenceRecord{Fence: f}); err != nil {
		return nil, err
	}
	res, err := es.StandbyFence(ctx, a.engineEnvFor(db), db, p, tl)
	if err != nil {
		_ = rt.releaseFence(p.FenceID)
		tl.Printf("the database is still the primary: dropped the fence")
		return nil, err
	}
	now := time.Now().UTC()
	rt.updateFence(p.FenceID, func(x *fenceRecord) { x.StoppedAt, x.Running = &now, false })
	return res, nil
}

func (a *Agent) engineStandbyUnfence(ctx context.Context, es EngineStandby, db protocol.DatabaseSpec, p protocol.StandbyUnfenceParams, tl *taskLog) (*protocol.StandbyUnfenceResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.FenceID) {
		return nil, fmt.Errorf("invalid fence id %q", p.FenceID)
	}
	var fence *fenceRecord
	for _, f := range rt.fences() {
		if f.ID == p.FenceID {
			fence = &f
		}
	}
	if fence == nil {
		return nil, errors.New("this server holds no such fence")
	}
	if err := rt.releaseFence(p.FenceID); err != nil {
		return nil, err
	}
	res, err := es.StandbyUnfence(ctx, a.engineEnvFor(db), db, fence.Fence, tl)
	if err != nil {
		_ = rt.update(func(sf *standbyFile) { // hold it again: nothing changed
			sf.Released = deleteString(sf.Released, p.FenceID)
			sf.Fences = append(sf.Fences, fence)
		})
		return nil, err
	}
	return res, nil
}

func deleteString(s []string, v string) []string {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// holdEngineFence enforces the fence of a database of another engine.
func (a *Agent) holdEngineFence(ctx context.Context, f fenceRecord) {
	rt := a.sb()
	es := engineStandby(f.Engine)
	if es == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	enforced, other, err := es.HoldFence(cctx, a.engineEnvFor(protocol.DatabaseSpec{ID: f.DatabaseID, Engine: f.Engine, Port: f.Port, SocketDir: f.SocketDir}), f.Fence)
	now := time.Now().UTC()
	rt.updateFence(f.ID, func(x *fenceRecord) {
		x.Other = other
		x.Running = false
		x.LastTry = now
		x.LastError = ""
		if err != nil {
			x.LastError = err.Error()
		}
		if enforced || x.StoppedAt == nil {
			x.StoppedAt = &now
		}
	})
	if enforced {
		a.log.Error("a fenced database was taking writes again: this server's copy is no longer the primary; made it read-only again",
			"database_id", f.DatabaseID, "engine", f.Engine, "port", f.Port)
	}
}

// engineStandbyHeartbeat adds the other engines' standbys, primaries and
// targets to a heartbeat.
func (a *Agent) engineStandbyHeartbeat(ctx context.Context, hb *protocol.StandbyHeartbeat) {
	for _, e := range registeredEngines() {
		env := a.engineEnv(e.Name())
		if es, ok := e.(EngineStandby); ok {
			hb.Standbys = append(hb.Standbys, es.StandbyStates(ctx, env)...)
		}
	}
	hb.Targets = append(hb.Targets, a.engineTargets(ctx)...)
	a.mu.Lock()
	watched := append([]protocol.DatabaseSpec(nil), a.watched...)
	a.mu.Unlock()
	for _, db := range watched {
		if isPostgres(db) {
			continue
		}
		es := engineStandby(db.Engine)
		if es == nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, ok := es.PrimaryState(cctx, a.engineEnvFor(db), db)
		cancel()
		if ok {
			st.DatabaseID = db.ID
			hb.Primaries = append(hb.Primaries, st)
		}
	}
}

// engineTargetsEvery is how often the engines look for servers that could
// receive a standby or a clone.
const engineTargetsEvery = time.Minute

// engineTargetsCache holds the engines' standby and clone targets. Finding
// them connects to servers (and a server that doesn't answer takes the
// driver's whole timeout), so it runs beside the heartbeat, never in it.
type engineTargetsCache struct {
	mu      sync.Mutex
	at      time.Time
	running bool
	out     []protocol.StandbyTarget
}

// engineTargets is the latest list (empty until the first search ends) and
// starts a new search when it is older than engineTargetsEvery.
func (a *Agent) engineTargets(ctx context.Context) []protocol.StandbyTarget {
	c := &a.engTargets
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.running && time.Since(c.at) >= engineTargetsEvery {
		c.running = true
		go func() {
			var out []protocol.StandbyTarget
			for _, e := range registeredEngines() {
				if et, ok := e.(EngineTargets); ok {
					out = append(out, et.StandbyTargets(ctx, a.engineEnv(e.Name()))...)
				}
			}
			c.mu.Lock()
			c.out, c.at, c.running = out, time.Now(), false
			c.mu.Unlock()
		}()
	}
	return slices.Clone(c.out)
}
