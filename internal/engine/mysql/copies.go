package mysql

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind copies: the database as it was at a point in time (or a Mark),
// restored next to production like a restore test but kept running on its
// private socket until it expires or is deleted, so people can compare it
// with production and bring rows back. At most one copy per database. A
// copy started again after the agent restarts; an expired one is deleted
// even when Rowsafe can't be reached.

const (
	defaultCopyLifetime = 24 * time.Hour
	maxCopyLifetime     = 7 * 24 * time.Hour
	copyMarker          = ".rowsafe-mysql-copy"
)

// copyRecord is one copy on this host.
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	Engine      string                `json:"engine"`
	Status      string                `json:"status"` // protocol.RewindCopyRestoring or RewindCopyReady
	Dir         string                `json:"dir"`
	Args        []string              `json:"args,omitempty"`
	PID         int                   `json:"pid,omitempty"`
	Target      protocol.RewindTarget `json:"target"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	Expires     time.Time             `json:"expires"`
	CreatedAt   time.Time             `json:"created_at"`
	SizeBytes   int64                 `json:"size_bytes"`
	Databases   []protocol.DBInfo     `json:"databases,omitempty"`
}

func (r *copyRecord) scratch() *scratch {
	return &scratch{Dir: r.Dir, DataDir: filepath.Join(r.Dir, "data"), Socket: filepath.Join(r.Dir, "socket", "mysqld.sock"),
		PID: r.PID, Args: r.Args}
}

// copyStore keeps an engine's copies (copies.json in its state directory).
type copyStore struct {
	mu        sync.Mutex
	path      string
	recs      map[string]*copyRecord
	loaded    bool
	lastHK    time.Time
	restoring map[string]context.CancelFunc // copies being restored by this process
	drills    map[string]bool               // restore test directories in use
	cleaned   bool
}

var (
	copyStoresMu sync.Mutex
	copyStores   = map[string]*copyStore{}
)

// rewinds returns the copy store of an engine (by its state directory).
func rewinds(env agent.EngineEnv) *copyStore {
	copyStoresMu.Lock()
	defer copyStoresMu.Unlock()
	cs := copyStores[env.StateDir]
	if cs == nil {
		cs = &copyStore{path: filepath.Join(env.StateDir, "copies.json"), recs: map[string]*copyRecord{},
			restoring: map[string]context.CancelFunc{}, drills: map[string]bool{}}
		copyStores[env.StateDir] = cs
	}
	return cs
}

func (cs *copyStore) loadLocked() {
	if cs.loaded {
		return
	}
	cs.loaded = true
	b, err := os.ReadFile(cs.path)
	if err != nil {
		return
	}
	var recs []*copyRecord
	if json.Unmarshal(b, &recs) == nil {
		for _, r := range recs {
			cs.recs[r.ID] = r
		}
	}
}

func (cs *copyStore) saveLocked() error {
	recs := make([]*copyRecord, 0, len(cs.recs))
	for _, r := range cs.recs {
		recs = append(recs, r)
	}
	slices.SortFunc(recs, func(a, b *copyRecord) int { return strings.Compare(a.ID, b.ID) })
	b, _ := json.MarshalIndent(recs, "", "  ")
	if err := os.MkdirAll(filepath.Dir(cs.path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(cs.path, b, 0o600)
}

func (cs *copyStore) get(id string) (copyRecord, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	r, ok := cs.recs[id]
	if !ok {
		return copyRecord{}, false
	}
	return *r, true
}

func (cs *copyStore) forDatabase(dbID string) (copyRecord, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	for _, r := range cs.recs {
		if r.DatabaseID == dbID {
			return *r, true
		}
	}
	return copyRecord{}, false
}

func (cs *copyStore) put(r copyRecord) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	cs.recs[r.ID] = &r
	return cs.saveLocked()
}

func (cs *copyStore) delete(id string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	delete(cs.recs, id)
	_ = cs.saveLocked()
}

// states are the engine's copies for the heartbeat.
func (cs *copyStore) states(engine string) []protocol.RewindState {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	var out []protocol.RewindState
	for _, r := range cs.recs {
		if r.Engine != engine {
			continue
		}
		exp := r.Expires
		out = append(out, protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindCopy,
			Status: r.Status, SizeBytes: r.SizeBytes, Expires: &exp, CreatedAt: r.CreatedAt,
			RecoveredTo: r.RecoveredTo, Path: r.Dir})
	}
	slices.SortFunc(out, func(a, b protocol.RewindState) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// setExpiries applies Extend.
func (cs *copyStore) setExpiries(exp []protocol.RewindExpiry) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.loadLocked()
	changed := false
	now := time.Now()
	for _, e := range exp {
		if r, ok := cs.recs[e.ID]; ok {
			r.Expires = copyExpiry(e.Expires, now)
			changed = true
		}
	}
	if changed {
		_ = cs.saveLocked()
	}
}

// copyExpiry clamps a requested expiry: default 24 h, at least an hour,
// at most 7 days.
func copyExpiry(requested, now time.Time) time.Time {
	switch {
	case requested.IsZero():
		return now.Add(defaultCopyLifetime).UTC()
	case requested.Before(now.Add(time.Hour)):
		return now.Add(time.Hour).UTC()
	case requested.After(now.Add(maxCopyLifetime)):
		return now.Add(maxCopyLifetime).UTC()
	}
	return requested.UTC()
}

// housekeeping deletes expired copies, starts copies again after an agent
// restart, drops copies whose restore was interrupted and removes leftover
// restore test directories. It runs at most every 30 seconds.
func (cs *copyStore) housekeeping(env agent.EngineEnv) {
	cs.mu.Lock()
	if time.Since(cs.lastHK) < 30*time.Second {
		cs.mu.Unlock()
		return
	}
	cs.lastHK = time.Now()
	cs.loadLocked()
	var expired, restart, interrupted []copyRecord
	now := time.Now()
	for _, r := range cs.recs {
		_, active := cs.restoring[r.ID]
		switch {
		case active:
		case r.Status == protocol.RewindCopyRestoring:
			interrupted = append(interrupted, *r)
		case now.After(r.Expires):
			expired = append(expired, *r)
		case !r.scratch().alive():
			restart = append(restart, *r)
		}
	}
	cleanDrills := !cs.cleaned
	cs.cleaned = true
	cs.mu.Unlock()

	for _, r := range append(expired, interrupted...) {
		env.Log.Info("removing a Rewind copy", "copy_id", r.ID, "expired", now.After(r.Expires))
		removeCopy(r)
		cs.delete(r.ID)
	}
	for _, r := range restart {
		r := r
		go func() {
			sc := r.scratch()
			if len(sc.Args) == 0 {
				return
			}
			if err := sc.start(); err != nil {
				env.Log.Warn("starting a Rewind copy again failed", "copy_id", r.ID, "err", err)
				return
			}
			cs.mu.Lock()
			if rec, ok := cs.recs[r.ID]; ok {
				rec.PID = sc.PID
				_ = cs.saveLocked()
			}
			cs.mu.Unlock()
			if err := sc.wait(context.Background(), 10*time.Minute); err != nil {
				env.Log.Warn("a Rewind copy didn't start again", "copy_id", r.ID, "err", err)
			}
		}()
	}
	if cleanDrills {
		cs.cleanDrills(env.Config.DrillDir)
	}
}

// removeCopy stops a copy's server and deletes its directory.
func removeCopy(r copyRecord) int64 {
	r.scratch().stop(context.Background())
	if _, err := os.Stat(filepath.Join(r.Dir, copyMarker)); err != nil {
		return 0 // never delete a directory that isn't one of ours
	}
	size := dirSize(r.Dir)
	_ = os.RemoveAll(r.Dir)
	return size
}

// cleanDrills removes restore test directories an earlier agent process
// left behind.
func (cs *copyStore) cleanDrills(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "mysql-") {
			continue
		}
		cs.mu.Lock()
		busy := cs.drills[e.Name()]
		cs.mu.Unlock()
		if !busy {
			_ = os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// drillBusy marks a restore test directory in use.
func (cs *copyStore) drillBusy(name string, busy bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if busy {
		cs.drills[name] = true
	} else {
		delete(cs.drills, name)
	}
}

// rewindTarget turns the task's target into a restore target.
func (s *server) rewindTarget(ctx context.Context, st *objStore, t protocol.RewindTarget) (restoreTarget, error) {
	var rt restoreTarget
	switch {
	case t.Time != nil && t.Mark != "":
		return rt, errors.New("give a time or a Mark, not both")
	case t.Time != nil:
		if t.Time.IsZero() || t.Time.After(time.Now().Add(time.Minute)) {
			return rt, fmt.Errorf("the time %s is in the future", t.Time.UTC().Format(time.RFC3339))
		}
		tt := t.Time.UTC().Truncate(time.Second)
		rt.Time = &tt
	case t.Mark != "":
		m, err := s.loadMark(ctx, st, t.Mark)
		if err != nil {
			return rt, err
		}
		rt.Mark = &m
	default:
		return rt, errors.New("no point in time or Mark given")
	}
	rt.BackupSet = t.BackupSet
	return rt, nil
}

// rewindCopy restores a copy and leaves it running.
func (s *server) rewindCopy(ctx context.Context, p protocol.RewindCopyParams, log agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	cs := rewinds(s.env)
	if r, ok := cs.get(p.CopyID); ok {
		if r.Status == protocol.RewindCopyReady && r.DatabaseID == s.db.ID {
			log.Printf("the copy %s is already there", p.CopyID)
			return copyResult(r), nil
		}
		return nil, fmt.Errorf("a copy with id %s already exists", p.CopyID)
	}
	if _, ok := cs.forDatabase(s.db.ID); ok {
		return nil, fmt.Errorf("%s already has a copy; delete it first: there is one copy per database at a time", s.db.Name)
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	target, err := s.rewindTarget(ctx, st, p.Target)
	if err != nil {
		return nil, err
	}
	root := s.env.Config.RewindDir
	dir, err := safeDir(root, p.CopyID)
	if err != nil {
		return nil, err
	}
	if size := totalSize(ctx, s); size > 0 {
		if err := checkSpace(root, size); err != nil {
			return nil, err
		}
	}
	if _, err := os.Stat(dir); err == nil {
		return nil, fmt.Errorf("%s already exists", dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, copyMarker), []byte(s.db.ID+"\n"), 0o600); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: s.db.ID, Engine: string(s.flavor), Status: protocol.RewindCopyRestoring,
		Dir: dir, Target: p.Target, Expires: copyExpiry(p.Expires, now), CreatedAt: now}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.mu.Lock()
	cs.restoring[rec.ID] = cancel
	cs.mu.Unlock()
	defer func() {
		cs.mu.Lock()
		delete(cs.restoring, rec.ID)
		cs.mu.Unlock()
	}()
	if err := cs.put(rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		removeCopy(rec)
		cs.delete(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted while it was being restored")
		}
		return nil, err
	}
	log.Printf("restoring a copy of %s as it was at %s", s.db.Name, target.describe())
	r, err := s.restoreData(cctx, st, dir, target, log)
	if err != nil {
		return fail(err)
	}
	sc, err := s.startScratch(cctx, dir, r.Backup, drillStartTimeout)
	if err != nil {
		return fail(err)
	}
	rec.PID, rec.Args = sc.PID, sc.Args
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	if err := s.replay(cctx, sc, r, target, log); err != nil {
		return fail(err)
	}
	rec.RecoveredTo = recoveredTo(r, target)
	if rec.RecoveredTo == nil {
		t := r.Backup.StoppedAt
		rec.RecoveredTo = &t
	}
	cdb, err := sc.connect(cctx)
	if err != nil {
		return fail(err)
	}
	if !s.flavor.mariadb() {
		_, _ = cdb.ExecContext(cctx, "SET GLOBAL super_read_only = ON")
	} else {
		_, _ = cdb.ExecContext(cctx, "SET GLOBAL read_only = ON")
	}
	rec.Databases, _, err = schemaSizes(cctx, cdb)
	cdb.Close()
	if err != nil {
		return fail(err)
	}
	rec.SizeBytes = dirSize(dir)
	rec.Status = protocol.RewindCopyReady
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	res := copyResult(rec)
	log.Printf("%s", res.Summary)
	return res, nil
}

func copyResult(r copyRecord) *protocol.RewindCopyResult {
	res := &protocol.RewindCopyResult{CopyID: r.ID, RecoveredTo: r.RecoveredTo, SizeBytes: r.SizeBytes, Databases: r.Databases,
		SocketDir: filepath.Join(r.Dir, "socket"), Expires: r.Expires}
	at := "the backup"
	if r.RecoveredTo != nil {
		at = r.RecoveredTo.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	res.Summary = fmt.Sprintf("Copy ready: %s as they were at %s (%s). It is deleted at %s.",
		plural(int64(len(r.Databases)), "database", "databases"), at, humanBytes(r.SizeBytes), r.Expires.UTC().Format("15:04 UTC on 2006-01-02"))
	return res
}

// rewindDrop stops and deletes a copy (cancelling its restore).
func (s *server) rewindDrop(ctx context.Context, p protocol.RewindDropParams, log agent.TaskLogger) (*protocol.RewindDropResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	cs := rewinds(s.env)
	res := &protocol.RewindDropResult{CopyID: p.CopyID}
	r, ok := cs.get(p.CopyID)
	if !ok {
		res.Summary = "The copy was already gone."
		return res, nil
	}
	if r.DatabaseID != s.db.ID {
		return nil, fmt.Errorf("the copy %s belongs to another database", p.CopyID)
	}
	cs.mu.Lock()
	cancel, restoring := cs.restoring[p.CopyID]
	cs.mu.Unlock()
	if restoring {
		log.Printf("cancelling the restore of the copy")
		cancel()
		for range 120 {
			if _, ok := cs.get(p.CopyID); !ok {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	res.FreedBytes = removeCopy(r)
	cs.delete(p.CopyID)
	res.Removed = true
	res.Summary = fmt.Sprintf("Deleted the copy (%s freed).", humanBytes(res.FreedBytes))
	log.Printf("%s", res.Summary)
	return res, nil
}

// readyCopy returns the database's copy if it is ready.
func (s *server) readyCopy(id string) (copyRecord, error) {
	if !idRE.MatchString(id) {
		return copyRecord{}, fmt.Errorf("invalid copy id %q", id)
	}
	r, ok := rewinds(s.env).get(id)
	switch {
	case !ok:
		return r, fmt.Errorf("the copy %s doesn't exist any more (it expired or was deleted)", id)
	case r.DatabaseID != s.db.ID:
		return r, fmt.Errorf("the copy %s belongs to another database", id)
	case r.Status != protocol.RewindCopyReady:
		return r, fmt.Errorf("the copy %s is still being restored", id)
	}
	return r, nil
}
