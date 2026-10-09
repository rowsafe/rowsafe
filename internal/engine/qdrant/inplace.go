package qdrant

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole server in place (and Undo), through Qdrant's own API:
// no restart, no file access.
//
//  1. download the backup and unpack its collection snapshots on this
//     server (production keeps running);
//  2. take a full snapshot of production as it is now into the bucket
//     (kept/<rewind id>/): the data from before, for Undo;
//  3. restore each collection from its snapshot (uploaded with priority
//     "snapshot": the collection becomes exactly what the snapshot holds),
//     remove the collections that didn't exist then, and put the aliases
//     back as they were.
//
// Rowsafe's own collection (the keys of Databases & users) is left alone.
// Undo does the same with the kept snapshot (after keeping the rewound data
// as kept/<rewind id>/after/). An agent stopped in the middle of step 3
// leaves the data from before kept: Undo puts everything back.

const (
	mipRestoring = "restoring" // downloading and unpacking: production untouched
	mipSnapshot  = "snapshot"  // production's data from before goes to the bucket
	mipLoading   = "loading"   // collections are being restored
)

// unpacked is a full snapshot unpacked into a directory.
type unpacked struct {
	Dir     string
	Config  snapshotConfig
	Members map[string]string // collection -> file path
}

// unpackSnapshot downloads the snapshot under prefix, decrypts it and
// writes its collection snapshots into dir.
func unpackSnapshot(ctx context.Context, r *repo, prefix, dir string) (unpacked, error) {
	u := unpacked{Dir: dir, Members: map[string]string{}}
	pr, closer, err := r.getSealed(ctx, prefix+snapshotName)
	if err != nil {
		return u, fmt.Errorf("downloading the snapshot: %w", err)
	}
	defer closer.Close()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return u, err
	}
	files := map[string]string{}
	tr := tar.NewReader(pr)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return u, fmt.Errorf("reading the snapshot: %w", err)
		}
		name := h.Name
		if h.Typeflag != tar.TypeReg || name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
			continue
		}
		if name == "config.json" {
			data, err := io.ReadAll(io.LimitReader(tr, 16<<20))
			if err != nil {
				return u, err
			}
			if err := json.Unmarshal(data, &u.Config); err != nil {
				return u, fmt.Errorf("the snapshot's config.json: %w", err)
			}
			found = true
			continue
		}
		path := filepath.Join(dir, "c-"+fmt.Sprintf("%04d", len(files))+".snapshot")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return u, err
		}
		_, err = io.Copy(f, tr)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return u, fmt.Errorf("unpacking the snapshot: %w", err)
		}
		files[name] = path
	}
	if !found {
		return u, errors.New("the snapshot has no config.json")
	}
	for coll, file := range u.Config.Collections {
		p, ok := files[file]
		if !ok {
			return u, fmt.Errorf("the snapshot lists collection %s but doesn't hold its data", coll)
		}
		u.Members[coll] = p
	}
	return u, nil
}

// uploadCollection restores collection name from a collection snapshot
// file: it becomes exactly what the snapshot holds (created if missing).
func uploadCollection(ctx context.Context, c *client, name, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile("snapshot", "collection.snapshot")
		if err == nil {
			_, err = io.Copy(part, f)
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()
	q := url.Values{"priority": {"snapshot"}, "wait": {"true"}}
	resp, err := c.request(ctx, http.MethodPost, collPath(name)+"/snapshots/upload", q, pr, mw.FormDataContentType())
	pr.CloseWithError(errors.New("upload stopped"))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// deleteCollection removes a collection.
func (c *client) deleteCollection(ctx context.Context, name string) error {
	err := c.call(ctx, http.MethodDelete, collPath(name), url.Values{"timeout": {"300"}}, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// setAliases makes the server's aliases exactly want, in one change.
func (c *client) setAliases(ctx context.Context, want map[string]string, keep func(collection string) bool) error {
	have, err := c.aliases(ctx)
	if err != nil {
		return err
	}
	var actions []map[string]any
	for alias, coll := range have {
		if keep(coll) {
			continue
		}
		if want[alias] != coll {
			actions = append(actions, map[string]any{"delete_alias": map[string]any{"alias_name": alias}})
		}
	}
	for _, alias := range slices.Sorted(maps.Keys(want)) {
		coll := want[alias]
		if have[alias] == coll || keep(coll) {
			continue
		}
		actions = append(actions, map[string]any{"create_alias": map[string]any{"alias_name": alias, "collection_name": coll}})
	}
	if len(actions) == 0 {
		return nil
	}
	return c.call(ctx, http.MethodPost, "/collections/aliases", url.Values{"timeout": {"60"}}, map[string]any{"actions": actions}, nil)
}

func ownColl(name string) bool { return name == protocol.QdrantKeysCollection }

// loadInto makes production what the unpacked snapshot holds. done
// records each collection restored (for the record, as it goes).
func loadInto(ctx context.Context, c *client, u unpacked, done func(step string), tl agent.TaskLogger) error {
	names := slices.Sorted(maps.Keys(u.Members))
	for _, name := range names {
		if ownColl(name) {
			continue
		}
		tl.Printf("restoring collection %s", name)
		if err := uploadCollection(ctx, c, name, u.Members[name]); err != nil {
			return fmt.Errorf("restoring collection %s: %w", name, err)
		}
		done("+" + name)
	}
	current, err := c.collectionNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range current {
		if _, ok := u.Members[name]; ok || ownColl(name) {
			continue
		}
		tl.Printf("removing collection %s (it didn't exist then)", name)
		if err := c.deleteCollection(ctx, name); err != nil {
			return fmt.Errorf("removing collection %s: %w", name, err)
		}
		done("-" + name)
	}
	want := map[string]string{}
	maps.Copy(want, u.Config.Aliases)
	if err := c.setAliases(ctx, want, ownColl); err != nil {
		return fmt.Errorf("putting the aliases back: %w", err)
	}
	return nil
}

func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	target, err := targetFrom(p.Target)
	if err != nil {
		return nil, err
	}
	kept := env.Kept()
	for _, r := range kept.ForDatabase(db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	in, err := inspect(ctx, prod, true)
	if err != nil {
		return nil, err
	}
	if why := in.supported(); why != "" {
		return nil, errors.New(why)
	}
	prefix, doc, err := pick(ctx, r, target)
	if err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	l := e.dbLock(db.ID)
	l.Lock()
	defer l.Unlock()
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: db.ID, Status: protocol.RewindInProgress, CreatedAt: time.Now().UTC(),
		Target: p.Target, KeepDays: p.KeepDays, Phase: mipRestoring, Database: db, Extra: map[string]string{"label": doc.Label}}
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	abandon := func(err error) (*protocol.RewindInPlaceResult, error) {
		_ = r.deletePrefix(context.WithoutCancel(ctx), keptPrefix+p.RewindID+"/")
		_ = kept.Remove(rec.ID)
		return nil, err
	}
	work := filepath.Join(copyRoot(env), "inplace-"+p.RewindID)
	defer os.RemoveAll(work)
	if err := ensureSpace(copyRoot(env), doc.SnapshotBytes+256<<20, "rewinding in place"); err != nil {
		return abandon(err)
	}
	tl.Printf("downloading backup %s (taken %s) and unpacking it on this server first (production keeps running meanwhile)",
		doc.Label, doc.TakenAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	u, err := unpackSnapshot(ctx, r, prefix, work)
	if err != nil {
		return abandon(err)
	}
	recovered := doc.TakenAt
	rec.Phase, rec.RecoveredTo = mipSnapshot, &recovered
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	tl.Printf("keeping a snapshot of %s as it is now in your bucket, so the rewind can be undone", db.Name)
	before, err := e.storeSnapshot(ctx, prod, r, in, sourceRewind, keptPrefix+p.RewindID+"/", tl)
	if err != nil {
		return abandon(fmt.Errorf("keeping the data from before: %w", err))
	}
	rec.Phase = mipLoading
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	steps := 0
	err = loadInto(ctx, prod, u, func(step string) {
		steps++
		rec.Extra["done"] = strings.Trim(rec.Extra["done"]+","+step, ",")
		_ = kept.Put(rec)
	}, tl)
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: &recovered}
	until := agent.KeepUntil(p.KeepDays, time.Now())
	rec.Status, rec.Phase, rec.Expires, rec.SizeBytes = protocol.RewindKeptBefore, "", until, before.StoredBytes
	rec.Path = "a snapshot in your bucket (" + keptPrefix + p.RewindID + "/)"
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		if steps == 0 {
			return abandon(fmt.Errorf("the rewind failed before any collection was changed (nothing changed): %w", err))
		}
		_ = kept.Put(rec)
		res.OldDataDir, res.KeptUntil = rec.Path, &until
		return res, fmt.Errorf("the rewind stopped part way (%v); the data from before is kept: Undo puts everything back", err)
	}
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.OldDataDir, res.KeptUntil = rec.Path, &until
	res.Summary = fmt.Sprintf("Rewound %s to the backup of %s, without a restart. The data as it was before is kept in your bucket until %s so you can undo.",
		db.Name, recovered.UTC().Format("15:04:05 UTC on 2006-01-02"), until.UTC().Format("2006-01-02 15:04 UTC"))
	if !target.Time.IsZero() && target.Mark == "" && target.Time.Sub(recovered) > time.Minute {
		res.Warnings = append(res.Warnings, fmt.Sprintf("Qdrant backups are snapshots: the newest one at or before %s was taken at %s",
			target.Time.UTC().Format("15:04:05 UTC"), recovered.UTC().Format("15:04:05 UTC")))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rewindUndo puts the data from before the rewind back (keeping the
// rewound data for a while).
func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return nil, errors.New("there is nothing to undo: the data from before this rewind is no longer kept")
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, errors.New("this rewind was undone already")
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	in, err := inspect(ctx, prod, true)
	if err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	l := e.dbLock(db.ID)
	l.Lock()
	defer l.Unlock()
	saved := rec
	saved.Extra = maps.Clone(rec.Extra)
	rec.Extra = maps.Clone(rec.Extra)
	if rec.Extra == nil {
		rec.Extra = map[string]string{}
	}
	rec.Status, rec.Phase, rec.Extra["undoing"] = protocol.RewindInProgress, mipRestoring, "1"
	delete(rec.Extra, "done")
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	giveUp := func(err error) (*protocol.RewindUndoResult, error) {
		_ = r.deletePrefix(context.WithoutCancel(ctx), keptPrefix+p.RewindID+"/after/")
		_ = kept.Put(saved)
		return nil, err
	}
	work := filepath.Join(copyRoot(env), "inplace-"+p.RewindID+"-undo")
	defer os.RemoveAll(work)
	tl.Printf("downloading the data from before the rewind and unpacking it on this server first")
	u, err := unpackSnapshot(ctx, r, keptPrefix+p.RewindID+"/", work)
	if err != nil {
		return giveUp(err)
	}
	rec.Phase = mipSnapshot
	_ = kept.Put(rec)
	tl.Printf("keeping the rewound data (with anything written since) in your bucket first")
	after, err := e.storeSnapshot(ctx, prod, r, in, sourceRewind, keptPrefix+p.RewindID+"/after/", tl)
	if err != nil {
		return giveUp(fmt.Errorf("keeping the rewound data: %w", err))
	}
	rec.Phase = mipLoading
	_ = kept.Put(rec)
	steps := 0
	err = loadInto(ctx, prod, u, func(step string) {
		steps++
		rec.Extra["done"] = strings.Trim(rec.Extra["done"]+","+step, ",")
		_ = kept.Put(rec)
	}, tl)
	res := &protocol.RewindUndoResult{RewindID: rec.ID}
	until := agent.KeepUntil(rec.KeepDays, time.Now())
	if err != nil && steps == 0 {
		return giveUp(fmt.Errorf("the undo failed before any collection was changed (nothing changed): %w", err))
	}
	delete(rec.Extra, "undoing")
	rec.Status, rec.Phase, rec.Undo, rec.Expires = protocol.RewindKeptAfterUndo, "", true, until
	rec.SizeBytes = after.StoredBytes
	rec.Path = "a snapshot in your bucket (" + keptPrefix + p.RewindID + "/after/)"
	_ = kept.Put(rec)
	res.RewoundDataDir, res.KeptUntil = rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		return res, fmt.Errorf("the undo stopped part way: %w", err)
	}
	res.Summary = fmt.Sprintf("%s is back as it was before the rewind, without a restart. The rewound data (with anything written since) is kept in your bucket until %s.",
		db.Name, until.UTC().Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rewindCleanup deletes what a rewind kept.
func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept for this rewind any more."}, nil
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	var freed int64
	if objs, err := r.st.List(ctx, keptPrefix+p.RewindID+"/"); err == nil {
		for _, o := range objs {
			freed += o.Size
		}
	}
	if err := r.deletePrefix(ctx, keptPrefix+p.RewindID+"/after/"); err != nil {
		return nil, err
	}
	if err := r.deletePrefix(ctx, keptPrefix+p.RewindID+"/"); err != nil {
		return nil, err
	}
	if err := kept.Remove(rec.ID); err != nil {
		return nil, err
	}
	res := &protocol.RewindCleanupResult{RewindID: rec.ID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the snapshot kept by the rewind (%s freed in your bucket).", humanBytes(freed))}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// recoverInPlace settles what an agent stopped in the middle of: before
// any collection changed, the rewind is dropped; after, the data from
// before is kept (Undo puts it back).
func (e *Engine) recoverInPlace(ctx context.Context, env agent.EngineEnv) {
	kept := env.Kept()
	for _, rec := range kept.All() {
		if rec.Status != protocol.RewindInProgress {
			continue
		}
		undoing := rec.Extra["undoing"] == "1"
		_ = os.RemoveAll(filepath.Join(copyRoot(env), "inplace-"+rec.ID))
		_ = os.RemoveAll(filepath.Join(copyRoot(env), "inplace-"+rec.ID+"-undo"))
		changed := rec.Phase == mipLoading && rec.Extra["done"] != ""
		delete(rec.Extra, "undoing")
		phase := rec.Phase
		rec.Phase = ""
		var err error
		switch {
		case !changed && !undoing:
			if r, rerr := openRepo(env, rec.Database); rerr == nil {
				_ = r.deletePrefix(ctx, keptPrefix+rec.ID+"/")
			}
			err = kept.Remove(rec.ID)
		case !changed && undoing:
			if phase != mipRestoring {
				if r, rerr := openRepo(env, rec.Database); rerr == nil {
					_ = r.deletePrefix(ctx, keptPrefix+rec.ID+"/after/")
				}
			}
			rec.Status = protocol.RewindKeptBefore
			err = kept.Put(rec)
		case undoing:
			rec.Status, rec.Undo = protocol.RewindKeptAfterUndo, true
			rec.Expires = agent.KeepUntil(rec.KeepDays, time.Now())
			err = kept.Put(rec)
		default:
			rec.Status = protocol.RewindKeptBefore
			rec.Expires = agent.KeepUntil(rec.KeepDays, time.Now())
			err = kept.Put(rec)
		}
		if err != nil {
			env.Log.Error("settling an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
		} else {
			env.Log.Warn("an interrupted rewind in place was settled", "rewind_id", rec.ID, "changed", changed)
		}
	}
}

// expireKept deletes what rewinds kept past its expiry.
func (e *Engine) expireKept(ctx context.Context, env agent.EngineEnv, now time.Time) {
	kept := env.Kept()
	for _, rec := range kept.Expired(now) {
		r, err := openRepo(env, rec.Database)
		if err != nil {
			continue
		}
		if r.deletePrefix(ctx, keptPrefix+rec.ID+"/after/") == nil && r.deletePrefix(ctx, keptPrefix+rec.ID+"/") == nil {
			_ = kept.Remove(rec.ID)
			env.Log.Info("deleted the snapshot kept by a rewind in place (expired)", "rewind_id", rec.ID)
		}
	}
}
