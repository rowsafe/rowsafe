package sqlite

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

// Safe copies (Guard) for SQLite are new files on the server, never
// served on a port: a masked copy (the newest point in the bucket restored
// into a new file, then masked: copies_mask.go) or a structure-only copy
// (production's schema without a row: copies_schema.go). A file has no
// login, so there is no password, role or allowed address: what protects
// it is that it stays on the server, in a folder only the agent's user can
// enter (0700), as a file only the agent's user can read (0600) — and root.
// People copy it to their computer themselves (scp or rsync as root, or
// docker cp from a sidecar); Rowsafe has no download path for it. The
// copies are reported with every heartbeat and deleted at their expiry
// (24 hours by default, at most 7 days), on Delete, or when they fail.

var _ agent.EngineSafeCopies = (*Engine)(nil)

// safeRoot holds the safe copies, one folder per copy, apart from the
// Rewind copies.
func safeRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.RewindDir, "sqlite-copies")
}

// safeRecord is a safe copy the engine keeps (<state>/safecopies.json).
type safeRecord struct {
	ID          string     `json:"id"`
	DatabaseID  string     `json:"database_id"`
	Dir         string     `json:"dir"`
	File        string     `json:"file"`
	Status      string     `json:"status"` // protocol.CopyRestoring | CopyMasking | CopyReady
	SchemaOnly  bool       `json:"schema_only,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	Expires     time.Time  `json:"expires"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
}

type safeStore struct {
	mu      sync.Mutex
	path    string
	records map[string]safeRecord
	running map[string]context.CancelFunc
}

// safeState is the engine's safe copy store, loaded on first use.
func (e *Engine) safeState(env agent.EngineEnv) *safeStore {
	root := e.stateRootFor(env)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.safe != nil {
		return e.safe
	}
	s := &safeStore{path: filepath.Join(root, "safecopies.json"), records: map[string]safeRecord{}, running: map[string]context.CancelFunc{}}
	var list []safeRecord
	if err := loadJSONFile(s.path, &list); err == nil {
		for _, r := range list {
			s.records[r.ID] = r
		}
	}
	e.safe = s
	return s
}

func (s *safeStore) saveLocked() error {
	list := make([]safeRecord, 0, len(s.records))
	for _, r := range s.records {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b safeRecord) int { return strings.Compare(a.ID, b.ID) })
	return saveJSONFile(s.path, list)
}

func (s *safeStore) put(r safeRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[r.ID] = r
	return s.saveLocked()
}

func (s *safeStore) remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, id)
	return s.saveLocked()
}

func (s *safeStore) get(id string) (safeRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[id]
	return r, ok
}

func (s *safeStore) all() []safeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]safeRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b safeRecord) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// safeFileName is the copy's file name: the database's own, so the app
// finds what it expects ("production.sqlite3").
func safeFileName(dbPath string) string {
	name := filepath.Base(dbPath)
	if name == "" || name == "." || name == "/" || strings.HasPrefix(name, ".") {
		return "copy.db"
	}
	return name
}

func (e *Engine) safeCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.SafeCopyParams, tl agent.TaskLogger) (*protocol.SafeCopyResult, error) {
	tools := env.Copies
	switch {
	case tools == nil:
		return nil, errors.New("safe copies need the Rowsafe agent")
	case !idRE.MatchString(p.CopyID):
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	case !p.SchemaOnly && p.Masking.Mode != protocol.MaskingRules && p.Masking.Mode != protocol.MaskingNone:
		return nil, fmt.Errorf("unknown masking mode %q", p.Masking.Mode)
	}
	if p.Access.PasswordVerifier != "" || p.Access.Port != 0 {
		tl.Printf("a SQLite copy is a file on this server: no port, login or password (ignoring them)")
	}
	ss := e.safeState(env)
	if n := len(ss.all()); n >= agent.MaxSafeCopies {
		return nil, fmt.Errorf("this server already has %d safe copies, the most it can hold; delete one first", n)
	}
	if _, ok := ss.get(p.CopyID); ok {
		return nil, fmt.Errorf("a copy with id %s already exists", p.CopyID)
	}
	if err := os.MkdirAll(safeRoot(env), 0o700); err != nil {
		return nil, err
	}
	_ = os.Chmod(safeRoot(env), 0o700)
	now := time.Now().UTC()
	rec := safeRecord{ID: p.CopyID, DatabaseID: db.ID, Dir: filepath.Join(safeRoot(env), p.CopyID), Status: protocol.CopyRestoring,
		SchemaOnly: p.SchemaOnly, CreatedAt: now, Expires: tools.Expiry(p.Expires)}
	rec.File = filepath.Join(rec.Dir, safeFileName(db.SocketDir))
	if err := os.Mkdir(rec.Dir, 0o700); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ss.mu.Lock()
	ss.running[rec.ID] = cancel
	ss.mu.Unlock()
	defer func() {
		ss.mu.Lock()
		delete(ss.running, rec.ID)
		ss.mu.Unlock()
	}()
	if err := ss.put(rec); err != nil {
		_ = os.RemoveAll(rec.Dir)
		return nil, err
	}
	fail := func(err error) (*protocol.SafeCopyResult, error) {
		_ = os.RemoveAll(rec.Dir)
		_ = ss.remove(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted before it was ready")
		}
		return nil, err
	}

	var report protocol.MaskingReport
	var made string
	if p.SchemaOnly {
		tl.Printf("copying the structure of %s (tables, indexes, views, triggers; no rows) into a new file", db.Name)
		so, err := schemaOnlyCopy(cctx, db.SocketDir, rec.File, tl)
		if err != nil {
			return fail(err)
		}
		at := time.Now().UTC()
		rec.RecoveredTo = &at
		report = protocol.MaskingReport{Mode: protocol.MaskingRules, Tables: so.Tables, Skipped: so.LeftOut, Strategies: map[string]int{}}
		made = fmt.Sprintf("The structure-only copy is ready: %s, no rows", so.describe())
		if len(so.LeftOut) > 0 {
			made += fmt.Sprintf(" (%d left out: see the copy's notes)", len(so.LeftOut))
		}
	} else {
		r, err := openRepo(env, db)
		if err != nil {
			return fail(err)
		}
		// The newest changes reach the bucket first.
		if s := e.existingShipper(db.ID); s != nil {
			_, _ = s.flush(cctx, 2*time.Minute)
		}
		tl.Printf("restoring the newest point of %s from your bucket into a new file (the live database isn't touched)", db.Name)
		out, err := restoreTo(cctx, r, restoreTarget{Latest: true}, rec.File, tl)
		if err != nil {
			return fail(err)
		}
		rt := out.RecoveredTo
		rec.RecoveredTo = &rt
		rec.Status = protocol.CopyMasking
		_ = ss.put(rec)
		key, err := tools.MaskKey()
		if err != nil {
			return fail(err)
		}
		if p.Masking.Mode == protocol.MaskingNone {
			tl.Printf("no masking: an admin chose a copy with the real data")
		}
		report, err = maskCopy(cctx, rec.File, p.Masking, key, tl)
		if err != nil {
			return fail(err)
		}
		if p.Masking.Mode == protocol.MaskingNone {
			made = "The copy is ready, NOT masked (it holds the real data)"
		} else {
			made = fmt.Sprintf("The masked copy is ready: %d columns masked in %d tables", report.Columns, report.Tables)
		}
		made += ", data as of " + rt.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	removeSideFiles(rec.File)
	if err := os.Chmod(rec.File, 0o600); err != nil {
		return fail(err)
	}
	check, err := inspectCopy(cctx, rec.File, false)
	if err != nil {
		return fail(err)
	}
	if check.Integrity != "ok" {
		return fail(fmt.Errorf("SQLite's check of the copy found a problem: %s", check.Integrity))
	}
	removeSideFiles(rec.File)
	rec.SizeBytes = fileSize(rec.File)
	rec.Status = protocol.CopyReady
	if err := ss.put(rec); err != nil {
		return fail(err)
	}
	res := &protocol.SafeCopyResult{CopyID: rec.ID, Databases: []string{"main"}, SizeBytes: rec.SizeBytes, RecoveredTo: rec.RecoveredTo,
		Expires: rec.Expires, Masking: report, Path: rec.File, SchemaOnly: rec.SchemaOnly}
	res.Summary = fmt.Sprintf("%s (%s). It is the file %s on this server, readable only by the Rowsafe agent's user and root, and is deleted by itself at %s.",
		made, humanBytes(rec.SizeBytes), rec.File, rec.Expires.UTC().Format("15:04 UTC on 2006-01-02"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// removeSideFiles removes a copy's empty or leftover SQLite side files (a
// rollback-journal copy is one file).
func removeSideFiles(path string) {
	for _, suf := range []string{"-wal", "-shm", "-journal"} {
		_ = os.Remove(path + suf)
	}
}

// CopyStates reports the safe copies and the kept preview copies
// (heartbeat).
func (e *Engine) CopyStates(env agent.EngineEnv) []protocol.CopyState {
	out := e.previewCopyStates(env) // preview_copy.go
	for _, r := range e.safeState(env).all() {
		exp := r.Expires
		out = append(out, protocol.CopyState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.CopyKindSafe, Status: r.Status,
			SizeBytes: r.SizeBytes, CreatedAt: r.CreatedAt, Expires: &exp, RecoveredTo: r.RecoveredTo})
	}
	return out
}

// CopyPorts: a SQLite copy is a file, it uses no port.
func (e *Engine) CopyPorts(env agent.EngineEnv) []int { return nil }

// DropCopy deletes a preview or safe copy (stopping it being made).
func (e *Engine) DropCopy(ctx context.Context, env agent.EngineEnv, id string) bool {
	if e.dropPreviewCopy(env, id) {
		return true
	}
	ss := e.safeState(env)
	r, ok := ss.get(id)
	if !ok {
		return false
	}
	ss.mu.Lock()
	cancel, running := ss.running[id]
	ss.mu.Unlock()
	if running {
		cancel() // the task removes it
		return true
	}
	e.removeSafe(env, r, "deleted from Rowsafe")
	return true
}

func (e *Engine) removeSafe(env agent.EngineEnv, r safeRecord, why string) {
	freed := dirSize(r.Dir)
	if err := os.RemoveAll(r.Dir); err != nil {
		e.logFor(env).Error("removing a SQLite safe copy failed", "copy_id", r.ID, "err", err)
		return
	}
	_ = e.safeState(env).remove(r.ID)
	e.logFor(env).Info("removed a SQLite safe copy", "copy_id", r.ID, "why", why, "freed", humanBytes(freed))
}

// SetCopyExpiries applies Extend (at most 7 days from now).
func (e *Engine) SetCopyExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	e.setPreviewCopyExpiries(env, exp)
	ss := e.safeState(env)
	now := time.Now()
	for _, x := range exp {
		if r, ok := ss.get(x.ID); ok && !x.Expires.Equal(r.Expires) {
			r.Expires = clampExpiry(x.Expires, now)
			_ = ss.put(r)
		}
	}
}

// SetCopyPassword: a file has no login; the copy is the engine's, so the
// instruction is consumed.
func (e *Engine) SetCopyPassword(ctx context.Context, env agent.EngineEnv, p protocol.CopyPassword) bool {
	if _, ok := e.safeState(env).get(p.ID); !ok {
		return false
	}
	e.logFor(env).Warn("ignoring a password for a SQLite copy: a file copy has no login", "copy_id", p.ID)
	return true
}

// expireSafeCopies deletes ready copies past their expiry.
func (e *Engine) expireSafeCopies(env agent.EngineEnv, now time.Time) {
	for _, r := range e.safeState(env).all() {
		if r.Status == protocol.CopyReady && !now.Before(r.Expires) {
			e.removeSafe(env, r, "expired")
		}
	}
}

// recoverSafeCopies runs at start: copies an agent restart interrupted
// are removed, and folders no record knows.
func (e *Engine) recoverSafeCopies(env agent.EngineEnv) {
	ss := e.safeState(env)
	known := map[string]bool{}
	for _, r := range ss.all() {
		if r.Status != protocol.CopyReady {
			e.removeSafe(env, r, "interrupted by an agent restart")
			continue
		}
		known[filepath.Base(r.Dir)] = true
	}
	if entries, err := os.ReadDir(safeRoot(env)); err == nil {
		for _, ent := range entries {
			if !known[ent.Name()] {
				_ = os.RemoveAll(filepath.Join(safeRoot(env), ent.Name()))
			}
		}
	}
}
