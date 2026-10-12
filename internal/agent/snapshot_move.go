package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Moving by snapshots (protocol/snapshot_move.go): Rowsafe Cloud's "Take it
// with you" for engines without replication (OpenSearch, Qdrant,
// Meilisearch). The control plane drives it with the standby tasks, like a
// move of any other engine; the agent turns them into the engine's
// snapshot steps (EngineSnapshotMove) and keeps the bookkeeping: which
// standby this server holds, the snapshot it restored, the newer snapshots
// it takes in the background so the last restore is short.

// EngineSnapshotMove is implemented by an engine whose databases move by
// snapshots. Every method gets the database (db.ID, db.Stanza: its folder
// in env.Repo, the primary's bucket handed over to this server); the ones
// that act on the receiving server get its port.
type EngineSnapshotMove interface {
	// StandbyTargets (EngineTargets) are the empty servers here that the
	// Rowsafe installer set up to receive a database (Standby true).
	EngineTargets
	// SnapshotMoveSource describes db on the primary for standby_prepare:
	// its version (Major: protocol.SeriesNumber-like), identity and size,
	// and the newest snapshot in its bucket folder (an error when there is
	// none yet, in plain words).
	SnapshotMoveSource(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (SnapshotMoveSource, error)
	// SnapshotMoveNewest is the newest snapshot of db in its bucket folder
	// (Label "" when there is none).
	SnapshotMoveNewest(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (SnapshotRef, error)
	// SnapshotMoveRestore restores snapshot label of db from the bucket into
	// the server on port, replacing what an earlier restore put there.
	// first: the first restore of this move (the server must be empty and
	// at least o.Major: refuse otherwise with an error wrapping
	// ErrMoveRefused, before changing anything); prev is the snapshot restored before ("" when
	// first), so an engine can skip what didn't change.
	SnapshotMoveRestore(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, port int, label string, o SnapshotMoveRestoreOptions,
		log TaskLogger) (SnapshotRef, error)
	// SnapshotMoveFreeze stops apps writing to db (reads go on). It may be
	// called again at any time (the fence holds): changed reports that
	// something had lifted the block and it was put back.
	SnapshotMoveFreeze(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, log TaskLogger) (changed bool, err error)
	// SnapshotMoveThaw lifts what SnapshotMoveFreeze did.
	SnapshotMoveThaw(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, log TaskLogger) error
	// SnapshotMoveTake takes a snapshot of db now into its bucket folder
	// (the switchover's last one) and returns it.
	SnapshotMoveTake(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, log TaskLogger) (SnapshotRef, error)
	// SnapshotMovePromote makes the server on port db's own once the last
	// snapshot is restored: it takes writes, and its backups continue in
	// the same bucket folder (anything tying the folder to the old server
	// moves to this one).
	SnapshotMovePromote(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, port int, log TaskLogger) error
	// SnapshotMoveClear removes what restores put into the server on port
	// (the move was cancelled, or a first restore failed halfway): only what
	// this move restored, never the server's own data.
	SnapshotMoveClear(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, port int, log TaskLogger) error
}

// ErrMoveRefused wraps a first restore's refusal made before anything
// changed on the receiving server (it holds data, an older version...):
// nothing is cleared after it, so a server's own data is never touched.
var ErrMoveRefused = errors.New("nothing was changed")

// SnapshotRef is one snapshot of a database in its bucket folder.
type SnapshotRef struct {
	Label string
	At    time.Time
}

// SnapshotMoveSource is what the primary tells the receiving server.
type SnapshotMoveSource struct {
	Major     int
	Version   string
	SystemID  string
	SizeBytes int64
	Newest    SnapshotRef
}

// SnapshotMoveRestoreOptions are a restore's context.
type SnapshotMoveRestoreOptions struct {
	First    bool
	Prev     string // the label restored before ("" when First)
	Major    int    // the primary's version (StandbyCreateParams.Major), first restore only
	SystemID string
}

// snapshotFollowEvery is how often a receiving server looks for a newer
// snapshot of the database it holds.
const snapshotFollowEvery = 10 * time.Minute

// snapshotStandby adapts an EngineSnapshotMove to EngineStandby.
type snapshotStandby struct {
	m      EngineSnapshotMove
	engine string
}

var _ EngineStandby = (*snapshotStandby)(nil)

// standbyOf is e's EngineStandby: its own, or its snapshot moves'.
func standbyOf(e Engine) EngineStandby {
	if s, ok := e.(EngineStandby); ok {
		return s
	}
	if m, ok := e.(EngineSnapshotMove); ok {
		return &snapshotStandby{m: m, engine: e.Name()}
	}
	return nil
}

// snapRecord is a database this server receives (<state>/snapshot-moves.json).
type snapRecord struct {
	ID         string     `json:"id"` // the standby's
	DatabaseID string     `json:"database_id"`
	Name       string     `json:"name"`
	Stanza     string     `json:"stanza"`
	Port       int        `json:"port"`
	Phase      string     `json:"phase"` // protocol.StandbyPhase*
	Label      string     `json:"label,omitempty"`
	At         *time.Time `json:"at,omitempty"`
	Major      int        `json:"major,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FollowedAt *time.Time `json:"followed_at,omitempty"`
	Error      string     `json:"error,omitempty"`
}

func (r snapRecord) spec(engine string) protocol.DatabaseSpec {
	return protocol.DatabaseSpec{ID: r.DatabaseID, Name: r.Name, Engine: engine, Stanza: r.Stanza, Port: r.Port}
}

var (
	snapMu    sync.Mutex               // snapshot-moves.json files
	snapLocks sync.Map                 // standby id -> *sync.Mutex: one restore at a time
	snapFlwMu sync.Mutex               // snapFollow
	snapFlw   = map[string]time.Time{} // state dir -> last background pass
)

func snapPath(env EngineEnv) string { return filepath.Join(env.StateDir, "snapshot-moves.json") }

func snapLoad(env EngineEnv) []snapRecord {
	var out []snapRecord
	data, err := os.ReadFile(snapPath(env))
	if err == nil {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

func snapSave(env EngineEnv, recs []snapRecord) error {
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(recs, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(snapPath(env), data, 0o600)
}

func snapGet(env EngineEnv, id string) (snapRecord, bool) {
	snapMu.Lock()
	defer snapMu.Unlock()
	for _, r := range snapLoad(env) {
		if r.ID == id {
			return r, true
		}
	}
	return snapRecord{}, false
}

func snapUpdate(env EngineEnv, id string, fn func(r *snapRecord)) error {
	snapMu.Lock()
	defer snapMu.Unlock()
	recs := snapLoad(env)
	i := slices.IndexFunc(recs, func(r snapRecord) bool { return r.ID == id })
	if i < 0 {
		recs = append(recs, snapRecord{ID: id})
		i = len(recs) - 1
	}
	fn(&recs[i])
	return snapSave(env, recs)
}

func snapRemove(env EngineEnv, id string) error {
	snapMu.Lock()
	defer snapMu.Unlock()
	recs := slices.DeleteFunc(snapLoad(env), func(r snapRecord) bool { return r.ID == id })
	return snapSave(env, recs)
}

func snapLock(id string) *sync.Mutex {
	l, _ := snapLocks.LoadOrStore(id, &sync.Mutex{})
	return l.(*sync.Mutex)
}

func (s *snapshotStandby) name() string { return protocol.EngineDisplayName(s.engine) }

// StandbyPrepare checks the database has a snapshot to start from. The
// agent seals the bucket settings (sec.Repo) itself.
func (s *snapshotStandby) StandbyPrepare(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams,
	sec *protocol.StandbySecrets, res *protocol.StandbyPrepareResult, log TaskLogger) error {
	src, err := s.m.SnapshotMoveSource(ctx, env, db)
	if err != nil {
		return err
	}
	if src.Newest.Label == "" {
		return fmt.Errorf("%s has no snapshot in its bucket yet: the move starts from one (the first backup)", db.Name)
	}
	res.Major, res.SystemID, res.SizeBytes = src.Major, src.SystemID, src.SizeBytes
	res.Summary = fmt.Sprintf("Sealed the bucket settings for the new server: it restores snapshot %s (taken %s) first.",
		src.Newest.Label, src.Newest.At.UTC().Format("2006-01-02 15:04 UTC"))
	log.Printf("%s %s, newest snapshot %s", s.name(), src.Version, src.Newest.Label)
	return nil
}

// StandbyCreate restores the newest snapshot into the empty server on
// p.Port.
func (s *snapshotStandby) StandbyCreate(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams,
	sec protocol.StandbySecrets, log TaskLogger) (*protocol.StandbyCreateResult, error) {
	start := time.Now()
	if p.Rebuild {
		return nil, fmt.Errorf("switching back isn't available for %s: the old server keeps the data as it was at the switchover", s.name())
	}
	l := snapLock(p.StandbyID)
	l.Lock()
	defer l.Unlock()
	if r, ok := snapGet(env, p.StandbyID); ok && r.Phase == protocol.StandbyPhaseFollowing {
		return &protocol.StandbyCreateResult{StandbyID: r.ID, Mode: protocol.StandbyModeArchive,
			Summary: fmt.Sprintf("%s on port %d already holds snapshot %s.", s.name(), r.Port, r.Label)}, nil
	}
	snapMu.Lock()
	for _, r := range snapLoad(env) {
		if r.Port == p.Port && r.ID != p.StandbyID {
			snapMu.Unlock()
			return nil, fmt.Errorf("the %s server on port %d already receives another database", s.name(), p.Port)
		}
	}
	snapMu.Unlock()
	newest, err := s.m.SnapshotMoveNewest(ctx, env, db)
	if err != nil {
		return nil, fmt.Errorf("reading the snapshots in the bucket: %w", err)
	}
	if newest.Label == "" {
		return nil, errors.New("there is no snapshot in the bucket to start from yet")
	}
	now := time.Now().UTC()
	if err := snapUpdate(env, p.StandbyID, func(r *snapRecord) {
		*r = snapRecord{ID: p.StandbyID, DatabaseID: db.ID, Name: db.Name, Stanza: db.Stanza, Port: p.Port, Phase: protocol.StandbyPhaseCreating,
			Major: p.Major, CreatedAt: now}
	}); err != nil {
		return nil, err
	}
	log.Printf("restoring snapshot %s of %s (taken %s) into %s on port %d", newest.Label, db.Name, newest.At.UTC().Format(time.RFC3339), s.name(), p.Port)
	got, err := s.m.SnapshotMoveRestore(ctx, env, db, p.Port, newest.Label,
		SnapshotMoveRestoreOptions{First: true, Major: p.Major, SystemID: p.SystemID}, log)
	if err != nil {
		if !errors.Is(err, ErrMoveRefused) {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
			if cerr := s.m.SnapshotMoveClear(cctx, env, db, p.Port, log); cerr != nil {
				log.Printf("note: removing what the restore left failed: %v", cerr)
			}
			cancel()
		}
		_ = snapRemove(env, p.StandbyID)
		return &protocol.StandbyCreateResult{StandbyID: p.StandbyID, RolledBack: true}, err
	}
	at := got.At
	if err := snapUpdate(env, p.StandbyID, func(r *snapRecord) {
		r.Phase, r.Label, r.At, r.FollowedAt, r.Error = protocol.StandbyPhaseFollowing, got.Label, &at, &now, ""
	}); err != nil {
		return nil, err
	}
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeArchive, ReplayLSN: got.Label,
		DurationMs: time.Since(start).Milliseconds(),
		Summary: fmt.Sprintf("Restored snapshot %s (taken %s) into %s on port %d. It takes the newer snapshots as they come; "+
			"at the switchover, apps' writes stop on the old server, one last snapshot is taken and restored here.",
			got.Label, got.At.UTC().Format("2006-01-02 15:04 UTC"), s.name(), p.Port)}
	log.Printf("%s", res.Summary)
	return res, nil
}

// follow restores a newer snapshot than the one held, if there is one.
func (s *snapshotStandby) follow(ctx context.Context, env EngineEnv, id string, log TaskLogger) error {
	l := snapLock(id)
	if !l.TryLock() {
		return nil // a restore or the promotion is running
	}
	defer l.Unlock()
	rec, ok := snapGet(env, id)
	if !ok || rec.Phase != protocol.StandbyPhaseFollowing {
		return nil
	}
	db := rec.spec(s.engine)
	if env.RepoFor != nil {
		env.Repo = env.RepoFor(db.ID)
	}
	newest, err := s.m.SnapshotMoveNewest(ctx, env, db)
	now := time.Now().UTC()
	if err == nil && newest.Label != "" && newest.Label != rec.Label && (rec.At == nil || newest.At.After(*rec.At)) {
		var got SnapshotRef
		got, err = s.m.SnapshotMoveRestore(ctx, env, db, rec.Port, newest.Label, SnapshotMoveRestoreOptions{Prev: rec.Label}, log)
		if err == nil {
			at := got.At
			return snapUpdate(env, id, func(r *snapRecord) { r.Label, r.At, r.FollowedAt, r.Error = got.Label, &at, &now, "" })
		}
	}
	return snapUpdate(env, id, func(r *snapRecord) {
		r.FollowedAt = &now
		r.Error = ""
		if err != nil {
			r.Error = "taking the newer snapshot: " + err.Error()
		}
	})
}

// StandbyPromote restores the old server's last snapshot (p.WaitForLSN)
// and makes the server the database's own.
func (s *snapshotStandby) StandbyPromote(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams,
	log TaskLogger) (*protocol.StandbyPromoteResult, error) {
	l := snapLock(p.StandbyID)
	l.Lock()
	defer l.Unlock()
	rec, ok := snapGet(env, p.StandbyID)
	if !ok {
		return nil, fmt.Errorf("this server holds no copy of %s to switch over to", db.Name)
	}
	if db.Stanza == "" {
		db.Stanza = rec.Stanza
	}
	res := &protocol.StandbyPromoteResult{StandbyID: p.StandbyID, ReplayLSN: rec.Label}
	if rec.At != nil {
		res.LastReplayAt = rec.At
	}
	switch {
	case p.WaitForLSN != "" && p.WaitForLSN != rec.Label:
		log.Printf("restoring the old server's last snapshot %s", p.WaitForLSN)
		got, err := s.m.SnapshotMoveRestore(ctx, env, db, rec.Port, p.WaitForLSN, SnapshotMoveRestoreOptions{Prev: rec.Label}, log)
		if err != nil {
			if !p.Force {
				return nil, fmt.Errorf("restoring the old server's last snapshot: %w", err)
			}
			// A failed restore may have left the server half-replaced: put
			// the snapshot held before back first.
			log.Printf("note: restoring the last snapshot failed (%v); switching over with snapshot %s", err, rec.Label)
			if _, rerr := s.m.SnapshotMoveRestore(ctx, env, db, rec.Port, rec.Label, SnapshotMoveRestoreOptions{}, log); rerr != nil {
				return nil, fmt.Errorf("restoring the last snapshot failed (%v), and so did restoring snapshot %s again: %w", err, rec.Label, rerr)
			}
			break
		}
		at := got.At
		rec.Label, rec.At = got.Label, &at
		res.ReplayLSN, res.LastReplayAt, res.CaughtUp = got.Label, &at, true
	case p.WaitForLSN != "":
		res.CaughtUp = true
	}
	if err := s.m.SnapshotMovePromote(ctx, env, db, rec.Port, log); err != nil {
		return nil, err
	}
	if err := snapRemove(env, rec.ID); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	res.Promoted, res.PromotedAt = true, &now
	res.Summary = fmt.Sprintf("%s on port %d holds %s as it was at the switchover (snapshot %s) and takes writes. Backups go on from here, in the same folder.",
		s.name(), rec.Port, db.Name, rec.Label)
	if !res.CaughtUp {
		res.Summary = fmt.Sprintf("%s on port %d holds %s as of snapshot %s and takes writes; changes after that snapshot may be missing.",
			s.name(), rec.Port, db.Name, rec.Label)
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRemove empties the receiving server again.
func (s *snapshotStandby) StandbyRemove(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams,
	log TaskLogger) (*protocol.StandbyRemoveResult, error) {
	l := snapLock(p.StandbyID)
	l.Lock()
	defer l.Unlock()
	res := &protocol.StandbyRemoveResult{StandbyID: p.StandbyID}
	rec, ok := snapGet(env, p.StandbyID)
	if !ok {
		res.Summary = "This server holds no such copy any more."
		return res, nil
	}
	if db.Stanza == "" {
		db.Stanza = rec.Stanza
	}
	if err := s.m.SnapshotMoveClear(ctx, env, db, rec.Port, log); err != nil {
		return nil, err
	}
	if err := snapRemove(env, rec.ID); err != nil {
		return nil, err
	}
	res.Summary = fmt.Sprintf("Removed the copy of %s: %s on port %d is empty again.", db.Name, s.name(), rec.Port)
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRelease: nothing was made on the primary.
func (s *snapshotStandby) StandbyRelease(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams,
	log TaskLogger) (*protocol.StandbyReleaseResult, error) {
	return &protocol.StandbyReleaseResult{StandbyID: p.StandbyID, Summary: "Nothing to undo on this server."}, nil
}

// StandbyFence stops apps' writes and takes the last snapshot. On an
// error the writes are allowed again (the agent drops the fence).
func (s *snapshotStandby) StandbyFence(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyFenceParams,
	log TaskLogger) (*protocol.StandbyFenceResult, error) {
	if _, err := s.m.SnapshotMoveFreeze(ctx, env, db, log); err != nil {
		s.thaw(ctx, env, db, log)
		return nil, fmt.Errorf("stopping apps' writes: %w", err)
	}
	log.Printf("apps' writes to %s are stopped (reads go on); taking the last snapshot", db.Name)
	snap, err := s.m.SnapshotMoveTake(ctx, env, db, log)
	if err != nil {
		s.thaw(ctx, env, db, log)
		return nil, fmt.Errorf("the last snapshot failed, so nothing moved and apps write again: %w", err)
	}
	res := &protocol.StandbyFenceResult{FenceID: p.FenceID, Stopped: true, Method: "writes_blocked", CheckpointLSN: snap.Label,
		Summary: fmt.Sprintf("Apps' writes to %s stopped here (reads go on) and the last snapshot, %s, is in the bucket.", db.Name, snap.Label)}
	log.Printf("%s", res.Summary)
	return res, nil
}

func (s *snapshotStandby) thaw(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, log TaskLogger) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	if err := s.m.SnapshotMoveThaw(cctx, env, db, log); err != nil {
		log.Printf("note: allowing writes again failed: %v", err)
	}
}

// HoldFence puts the write block back if anything lifted it.
func (s *snapshotStandby) HoldFence(ctx context.Context, env EngineEnv, f protocol.Fence) (enforced, other bool, err error) {
	db := protocol.DatabaseSpec{ID: f.DatabaseID, Engine: f.Engine, Port: f.Port}
	changed, err := s.m.SnapshotMoveFreeze(ctx, env, db, discardLog{})
	return changed, false, err
}

// StandbyUnfence lets apps write again (the switchover didn't happen).
func (s *snapshotStandby) StandbyUnfence(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, f protocol.Fence,
	log TaskLogger) (*protocol.StandbyUnfenceResult, error) {
	if db.Port == 0 {
		db.Port = f.Port
	}
	if err := s.m.SnapshotMoveThaw(ctx, env, db, log); err != nil {
		return nil, err
	}
	res := &protocol.StandbyUnfenceResult{FenceID: f.ID, Started: true, Summary: fmt.Sprintf("Apps can write to %s here again.", s.name())}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyStates reports the databases this server receives, and takes
// newer snapshots in the background.
func (s *snapshotStandby) StandbyStates(ctx context.Context, env EngineEnv) []protocol.StandbyState {
	snapMu.Lock()
	recs := snapLoad(env)
	snapMu.Unlock()
	var out []protocol.StandbyState
	now := time.Now().UTC()
	for _, r := range recs {
		st := protocol.StandbyState{StandbyID: r.ID, DatabaseID: r.DatabaseID, Port: r.Port, Phase: r.Phase, Mode: protocol.StandbyModeArchive,
			Running: true, InRecovery: true, ReplayLSN: r.Label, ReceiveLSN: r.Label, LastReplayAt: r.At, Error: r.Error, CheckedAt: now}
		out = append(out, st)
		if r.Phase == protocol.StandbyPhaseFollowing && (r.FollowedAt == nil || now.Sub(*r.FollowedAt) >= snapshotFollowEvery) {
			s.startFollow(env, r.ID)
		}
	}
	return out
}

// startFollow runs follow beside the heartbeat, once at a time per state
// directory.
func (s *snapshotStandby) startFollow(env EngineEnv, id string) {
	key := env.StateDir + "\x00" + id
	snapFlwMu.Lock()
	if t, ok := snapFlw[key]; ok && time.Since(t) < snapshotFollowEvery {
		snapFlwMu.Unlock()
		return
	}
	snapFlw[key] = time.Now()
	snapFlwMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
		defer cancel()
		if err := s.follow(ctx, env, id, discardLog{}); err != nil && env.Log != nil {
			env.Log.Error("taking a newer snapshot of a database this server receives", "standby_id", id, "err", err)
		}
	}()
}

// PrimaryState: there is no position to follow.
func (s *snapshotStandby) PrimaryState(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec) (protocol.PrimaryState, bool) {
	return protocol.PrimaryState{}, false
}

// StandbyTargets are the engine's empty servers set up to receive.
func (s *snapshotStandby) StandbyTargets(ctx context.Context, env EngineEnv) []protocol.StandbyTarget {
	return s.m.StandbyTargets(ctx, env)
}

// discardLog drops task log lines (background work).
type discardLog struct{}

func (discardLog) Printf(string, ...any) {}
func (discardLog) Output(string, []byte) {}
