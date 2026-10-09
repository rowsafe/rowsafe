package qdrant

import (
	"context"
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

// Rewind copies for Qdrant: a backup (the newest at or before a moment, or
// a Mark's) restored into a private temporary Qdrant next to production,
// on 127.0.0.1 only behind a key only the agent knows, up until it expires.

const (
	defaultCopyHours = 24
	maxCopyAge       = 7 * 24 * time.Hour
)

func copyRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.RewindDir, protocol.EngineQdrant)
}

// copyRecord is a copy the engine keeps (<state>/copies.json).
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	Dir         string                `json:"dir"`
	Status      string                `json:"status"`
	Target      protocol.RewindTarget `json:"target"`
	Label       string                `json:"label,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	SizeBytes   int64                 `json:"size_bytes"`
}

type copyStore struct {
	mu      sync.Mutex
	path    string
	records map[string]copyRecord
	running map[string]context.CancelFunc
}

func (e *Engine) copyState(env agent.EngineEnv) *copyStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.copies == nil {
		cs := &copyStore{path: filepath.Join(env.StateDir, "copies.json"), records: map[string]copyRecord{}, running: map[string]context.CancelFunc{}}
		var list []copyRecord
		if err := loadJSONFile(cs.path, &list); err != nil && !errors.Is(err, os.ErrNotExist) {
			env.Log.Error("reading the copies' state; starting empty", "err", err)
		}
		for _, r := range list {
			cs.records[r.ID] = r
		}
		e.copies = cs
	}
	return e.copies
}

func (cs *copyStore) saveLocked() error {
	list := make([]copyRecord, 0, len(cs.records))
	for _, r := range cs.records {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b copyRecord) int { return strings.Compare(a.ID, b.ID) })
	return saveJSONFile(cs.path, list)
}

func (cs *copyStore) put(r copyRecord) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.records[r.ID] = r
	return cs.saveLocked()
}

func (cs *copyStore) remove(id string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.records, id)
	return cs.saveLocked()
}

func (cs *copyStore) get(id string) (copyRecord, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	r, ok := cs.records[id]
	return r, ok
}

func (cs *copyStore) all() []copyRecord {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]copyRecord, 0, len(cs.records))
	for _, r := range cs.records {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b copyRecord) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (cs *copyStore) forDatabase(dbID string) (copyRecord, bool) {
	for _, r := range cs.all() {
		if r.DatabaseID == dbID {
			return r, true
		}
	}
	return copyRecord{}, false
}

func clampExpiry(want, now time.Time) time.Time {
	if want.IsZero() || !want.After(now) {
		return now.Add(defaultCopyHours * time.Hour)
	}
	if limit := now.Add(maxCopyAge); want.After(limit) {
		return limit
	}
	return want
}

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	target, err := targetFrom(p.Target)
	if err != nil {
		return nil, err
	}
	cs := e.copyState(env)
	if r, ok := cs.forDatabase(db.ID); ok {
		if r.ID == p.CopyID && r.Status == protocol.RewindCopyReady {
			return e.copyResult(ctx, r)
		}
		return nil, errors.New("this database already has a copy: delete it before restoring another")
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	root := copyRoot(env)
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Dir: filepath.Join(root, p.CopyID),
		Status: protocol.RewindCopyRestoring, Target: p.Target, CreatedAt: now, Expires: clampExpiry(p.Expires, now)}
	s, err := newScratch(root, p.CopyID)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.mu.Lock()
	cs.running[rec.ID] = cancel
	cs.mu.Unlock()
	defer func() {
		cs.mu.Lock()
		delete(cs.running, rec.ID)
		cs.mu.Unlock()
	}()
	if err := cs.put(rec); err != nil {
		_, _ = s.remove()
		return nil, err
	}
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		if _, rerr := s.remove(); rerr != nil {
			env.Log.Error("removing a failed copy", "dir", s.Dir, "err", rerr)
		}
		_ = cs.remove(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted while it was being restored")
		}
		return nil, err
	}
	tl.Printf("restoring a copy of %s as of %s into a private Qdrant (127.0.0.1 only)", db.Name, target.describe())
	out, c, err := restoreInto(cctx, env, r, target, &s, tl)
	if err != nil {
		return fail(err)
	}
	for _, cd := range out.Doc.Collections {
		if cd.Name != protocol.QdrantKeysCollection {
			if _, err := waitLoaded(cctx, c, cd.Name, 2*time.Minute); err != nil {
				c.Close()
				return fail(fmt.Errorf("collection %s: %w", cd.Name, err))
			}
		}
	}
	c.Close()
	rec.Status, rec.Label = protocol.RewindCopyReady, out.Doc.Label
	rt := out.Doc.TakenAt
	rec.RecoveredTo = &rt
	rec.SizeBytes = dirSize(s.Dir)
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	res, err := e.copyResult(ctx, rec)
	if err != nil {
		return nil, err
	}
	if !target.Time.IsZero() && target.Mark == "" {
		tl.Printf("note: Qdrant backups are snapshots: the copy is the newest one taken at or before %s (%s)",
			target.Time.UTC().Format("15:04:05 UTC"), out.Doc.TakenAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) copyResult(ctx context.Context, rec copyRecord) (*protocol.RewindCopyResult, error) {
	s := scratchAt(rec.Dir)
	c, err := s.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	defer c.Close()
	in, err := inspect(ctx, c, true)
	if err != nil {
		return nil, err
	}
	st, _ := s.loadState()
	when := "the backup"
	if rec.RecoveredTo != nil {
		when = rec.RecoveredTo.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return &protocol.RewindCopyResult{CopyID: rec.ID, RecoveredTo: rec.RecoveredTo, SizeBytes: rec.SizeBytes, Databases: in.dbInfos(),
		Port: st.HTTPPort, Expires: rec.Expires,
		Summary: fmt.Sprintf("The copy is ready: %d collections, %s points, as of %s. It is deleted by itself on %s.",
			len(in.userCollections()), commas(in.totalPoints()), when, rec.Expires.UTC().Format("2006-01-02 15:04 UTC"))}, nil
}

func (e *Engine) rewindDrop(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindDropParams, tl agent.TaskLogger) (*protocol.RewindDropResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	cs := e.copyState(env)
	cs.mu.Lock()
	cancel := cs.running[p.CopyID]
	cs.mu.Unlock()
	if cancel != nil {
		tl.Printf("the copy is still being restored: stopping that first")
		cancel()
		for range 120 {
			cs.mu.Lock()
			_, still := cs.running[p.CopyID]
			cs.mu.Unlock()
			if !still {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	rec, ok := cs.get(p.CopyID)
	if !ok {
		dir := filepath.Join(copyRoot(env), p.CopyID)
		if _, err := os.Lstat(dir); err != nil {
			return &protocol.RewindDropResult{CopyID: p.CopyID, Summary: "There was no such copy (already deleted)."}, nil
		}
		rec = copyRecord{ID: p.CopyID, Dir: dir}
	}
	if rec.DatabaseID != "" && rec.DatabaseID != db.ID {
		return nil, errors.New("that copy belongs to another database")
	}
	freed, err := scratchAt(rec.Dir).remove()
	if err != nil {
		return nil, err
	}
	if err := cs.remove(p.CopyID); err != nil {
		return nil, err
	}
	tl.Printf("deleted the copy, freeing %s", humanBytes(freed))
	return &protocol.RewindDropResult{CopyID: p.CopyID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the copy (%s freed).", humanBytes(freed))}, nil
}

// recoverCopies runs at start: interrupted restores are removed, ready
// copies started again, leftovers without a record removed; leftover
// restore tests too.
func (e *Engine) recoverCopies(ctx context.Context, env agent.EngineEnv) {
	cs := e.copyState(env)
	known := map[string]bool{}
	for _, r := range cs.all() {
		known[filepath.Base(r.Dir)] = true
		s := scratchAt(r.Dir)
		switch {
		case r.Status != protocol.RewindCopyReady:
			if _, err := s.remove(); err == nil {
				_ = cs.remove(r.ID)
				env.Log.Warn("removed a copy whose restore was interrupted", "copy_id", r.ID)
			}
		case time.Now().After(r.Expires):
		case s.pid() == 0:
			go func() {
				c, err := s.restart(ctx, env)
				if err != nil {
					env.Log.Error("starting a copy again failed; it stays until it expires or is deleted", "copy_id", r.ID, "err", err)
					return
				}
				c.Close()
				env.Log.Info("started a copy again after an agent restart", "copy_id", r.ID)
			}()
		}
	}
	for _, root := range []string{copyRoot(env), drillRoot(env)} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() || known[ent.Name()] && root == copyRoot(env) {
				continue
			}
			if strings.HasPrefix(ent.Name(), "inplace-") {
				continue // recoverInPlace
			}
			dir := filepath.Join(root, ent.Name())
			if _, err := os.Lstat(filepath.Join(dir, scratchMarker)); err != nil {
				continue
			}
			if _, err := scratchAt(dir).remove(); err != nil {
				env.Log.Error("removing a leftover temporary server failed", "dir", dir, "err", err)
			}
		}
	}
}

// expireCopies deletes copies past their expiry.
func (e *Engine) expireCopies(env agent.EngineEnv, now time.Time) {
	cs := e.copyState(env)
	for _, r := range cs.all() {
		if r.Status != protocol.RewindCopyReady || now.Before(r.Expires) {
			continue
		}
		freed, err := scratchAt(r.Dir).remove()
		if err != nil {
			env.Log.Error("removing an expired copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		_ = cs.remove(r.ID)
		env.Log.Info("removed an expired copy", "copy_id", r.ID, "freed", humanBytes(freed))
	}
}

// RewindStates reports the copies and kept data (heartbeat).
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range e.copyState(env).all() {
		exp := r.Expires
		out = append(out, protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindCopy, Status: r.Status,
			SizeBytes: r.SizeBytes, Expires: &exp, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.Dir})
	}
	return append(out, env.Kept().States()...)
}

// SetRewindExpiries applies Extend from the control plane.
func (e *Engine) SetRewindExpiries(env agent.EngineEnv, exps []protocol.RewindExpiry) {
	cs := e.copyState(env)
	now := time.Now()
	for _, x := range exps {
		if r, ok := cs.get(x.ID); ok && !x.Expires.Equal(r.Expires) {
			r.Expires = clampExpiry(x.Expires, now)
			_ = cs.put(r)
		}
	}
}
