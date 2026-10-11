package qdrant

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// Backups take one snapshot per collection (POST /collections/<name>/
// snapshots), and only of the collections that changed since the newest
// backup (changes.go): the others are named again. Each snapshot is read
// over the API as Qdrant writes it, encrypted on this server on the way to
// the bucket (data/<label>-<n>.snapshot) and deleted from the server's
// disk right after, so the server holds at most one collection's snapshot
// at a time. Restores put the collections' snapshots and a config.json
// together into what Qdrant's full storage snapshot is (storageReader), so
// everything that starts from one works unchanged.

// collectionSnapshot is POST /collections/<name>/snapshots.
func (c *client) collectionSnapshot(ctx context.Context, name string) (snapshotInfo, error) {
	var s snapshotInfo
	err := c.call(ctx, http.MethodPost, collPath(name)+"/snapshots", url.Values{"wait": {"true"}}, nil, &s)
	if err == nil && s.Name == "" {
		err = errors.New("Qdrant took a snapshot but didn't name it")
	}
	return s, err
}

func (c *client) deleteCollectionSnapshot(ctx context.Context, coll, name string) error {
	err := c.call(ctx, http.MethodDelete, collPath(coll)+"/snapshots/"+url.PathEscape(name), url.Values{"wait": {"true"}}, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// pendingColl names a collection snapshot in the pending list (engine.go).
func pendingColl(coll, name string) string { return "collection\x00" + coll + "\x00" + name }

// dataKey is where backup label keeps its n-th collection snapshot.
func dataKey(label string, n int) string {
	return fmt.Sprintf("%s%s-%04d.snapshot", dataPrefix, label, n)
}

// storeCollection snapshots one collection and stores it under key.
func (e *Engine) storeCollection(ctx context.Context, c *client, r *repo, name, key string) (collDoc, int64, error) {
	d := collDoc{Name: name, Object: key}
	snap, err := c.collectionSnapshot(ctx, name)
	if err != nil {
		return d, 0, err
	}
	d.TakenAt = time.Now().UTC()
	if t, err := time.Parse("2006-01-02T15:04:05", snap.CreationTime); err == nil {
		d.TakenAt = t.UTC()
	}
	e.pendingAdd(pendingColl(name, snap.Name))
	defer func() {
		if err := c.deleteCollectionSnapshot(context.WithoutCancel(ctx), name, snap.Name); err == nil {
			e.pendingDone(pendingColl(name, snap.Name))
		}
	}()
	resp, err := c.request(ctx, http.MethodGet, collPath(name)+"/snapshots/"+url.PathEscape(snap.Name), nil, nil, "")
	if err != nil {
		return d, 0, fmt.Errorf("reading the snapshot: %w", err)
	}
	defer resp.Body.Close()
	sum := sha256.New()
	var n int64
	stored, err := r.putSealed(ctx, key, io.TeeReader(&countReader{r: resp.Body, n: &n}, sum))
	if err != nil {
		_ = r.st.Delete(context.WithoutCancel(ctx), key)
		return d, 0, fmt.Errorf("copying the snapshot to your bucket: %w", err)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if snap.Checksum != "" && !strings.EqualFold(snap.Checksum, got) {
		_ = r.st.Delete(context.WithoutCancel(ctx), key)
		return d, 0, fmt.Errorf("the snapshot changed on the way (Qdrant's checksum %s, read %s)", snap.Checksum, got)
	}
	if snap.Size > 0 && n != snap.Size {
		_ = r.st.Delete(context.WithoutCancel(ctx), key)
		return d, 0, fmt.Errorf("the snapshot was cut short (%d of %d bytes)", n, snap.Size)
	}
	d.Bytes, d.Checksum = n, got
	return d, stored, nil
}

// reuseMaxAge: a collection's snapshot is named again at most this long
// after Qdrant took it, then taken again even when nothing seems to have
// changed. That bounds what a change Qdrant's numbers can't tell apart
// (a recovery that brings back an operation number and segments seen
// before) could cost, and keeps every object a backup names young (bucket
// lifecycle rules).
const reuseMaxAge = 24 * time.Hour

// maxRounds bounds the extra rounds a backup makes for collections created
// (or changed) while it ran: a reindex into a new collection with an alias
// moved to it ends up in the backup, aliases as they are at the end.
const maxRounds = 3

// storeCollections makes a backup: a snapshot of each collection that
// changed since prev (the newest backup made this way, or nil), prev's
// snapshot of the others; full snapshots every collection. The caller
// holds the database's lock.
func (e *Engine) storeCollections(ctx context.Context, c *client, r *repo, in serverInfo, prev *backupDoc, full bool, source, mark string, tl agent.TaskLogger) (backupDoc, error) {
	started := time.Now().UTC()
	doc := backupDoc{Source: source, Mark: mark, Version: in.Version, VersionNum: in.VersionNum, StartedAt: started, TakenAt: started,
		Aliases: in.Aliases, DataBytes: in.totalBytes(), Format: formatCollections}
	if doc.Aliases == nil {
		doc.Aliases = map[string]string{}
	}
	var err error
	if doc.Label, err = r.freshLabel(ctx, started); err != nil {
		return doc, err
	}
	names := make([]string, 0, len(in.Collections))
	for _, ci := range in.Collections {
		names = append(names, ci.Name)
	}
	marks := c.changeMarks(ctx, names)
	before := map[string]collDoc{}
	if prev != nil && prev.Format == formatCollections && prev.Version == in.Version && !full {
		for _, cd := range prev.Collections {
			before[cd.Name] = cd
		}
	}
	reused := map[string]bool{} // named again, not taken by this backup
	var changed []collInfo
	for _, ci := range in.Collections {
		if old, ok := before[ci.Name]; ok && old.Object != "" && old.Change != "" && old.Change == marks[ci.Name] &&
			!old.TakenAt.IsZero() && started.Sub(old.TakenAt) <= reuseMaxAge {
			doc.Collections = append(doc.Collections, old)
			reused[ci.Name] = true
			continue
		}
		changed = append(changed, ci)
	}
	switch {
	case full:
		tl.Printf("taking a snapshot of each of the %d collections (%s points), one at a time, after a restore of this server",
			len(in.userCollections()), commas(in.totalPoints()))
	case len(changed) == 0 && prev != nil:
		tl.Printf("nothing changed in the %d collections since backup %s: this backup names their snapshots again", len(in.userCollections()), prev.Label)
	case len(before) > 0:
		tl.Printf("%d of %d collections changed since backup %s (or their snapshot is a day old): taking a snapshot of those, one at a time",
			len(changed), len(in.Collections), prev.Label)
	default:
		tl.Printf("taking a snapshot of each of the %d collections (%s points), one at a time", len(in.userCollections()), commas(in.totalPoints()))
	}
	written := []string{}
	fail := func(err error) (backupDoc, error) {
		for _, k := range written {
			_ = r.st.Delete(context.WithoutCancel(ctx), k)
		}
		return doc, err
	}
	n := 0
	take := func(ci collInfo, mark string) error {
		pointsBefore, cerr := c.exactCount(ctx, ci.Name)
		if cerr != nil {
			pointsBefore = ci.Points
		}
		key := dataKey(doc.Label, n)
		n++
		cd, stored, err := e.storeCollection(ctx, c, r, ci.Name, key)
		if err != nil {
			if isStatus(err, http.StatusNotFound) {
				tl.Printf("collection %s was removed meanwhile", ci.Name)
				return nil
			}
			return fmt.Errorf("the snapshot of collection %s: %w", ci.Name, err)
		}
		written = append(written, key)
		cd.Change, cd.Status, cd.Sparse, cd.Points = mark, ci.Status, ci.Sparse, pointsBefore
		for _, v := range ci.Vectors {
			cd.Vectors = append(cd.Vectors, v.Name)
		}
		// Point counts as of the snapshot: read before and just after it,
		// Proof allows for writes of that moment.
		if after, err := c.exactCount(ctx, ci.Name); err == nil && after != pointsBefore {
			cd.Points = (after + pointsBefore) / 2
		}
		doc.Collections = append(doc.Collections, cd)
		doc.StoredBytes += stored
		doc.TakenAt = cd.TakenAt
		if !ownColl(ci.Name) {
			tl.Printf("collection %s: %s points, a %s snapshot, %s stored", ci.Name, commas(cd.Points), humanBytes(cd.Bytes), humanBytes(stored))
		}
		return nil
	}
	for _, ci := range changed {
		if err := take(ci, marks[ci.Name]); err != nil {
			return fail(err)
		}
	}
	// What changed while the snapshots were taken: collections made
	// meanwhile (a reindex into a new one, an alias moved to it), named
	// ones written to since their mark was read, ones removed. A few rounds
	// at most; the aliases as they are at the end.
	for range maxRounds {
		now, err := c.collectionNames(ctx)
		if err != nil {
			break
		}
		if al, err := c.aliases(ctx); err == nil {
			doc.Aliases = al
		}
		live := map[string]bool{}
		for _, name := range now {
			live[name] = true
		}
		doc.Collections = slices.DeleteFunc(doc.Collections, func(cd collDoc) bool { return !live[cd.Name] })
		have := map[string]bool{}
		for _, cd := range doc.Collections {
			have[cd.Name] = true
		}
		marks = c.changeMarks(ctx, now)
		var todo []string
		for _, name := range now {
			if !have[name] || reused[name] && doc.collection(name).Change != marks[name] {
				todo = append(todo, name)
			}
		}
		if len(todo) == 0 {
			break
		}
		tl.Printf("%d collections were made or written to while this backup ran: taking a snapshot of those too", len(todo))
		for _, name := range todo {
			ci, err := c.collection(ctx, name)
			if err != nil {
				if isStatus(err, http.StatusNotFound) {
					continue
				}
				return fail(fmt.Errorf("reading collection %s: %w", name, err))
			}
			doc.Collections = slices.DeleteFunc(doc.Collections, func(cd collDoc) bool { return cd.Name == name })
			delete(reused, name)
			if err := take(ci, marks[name]); err != nil {
				return fail(err)
			}
		}
	}
	slices.SortFunc(doc.Collections, func(a, b collDoc) int { return strings.Compare(a.Name, b.Name) })
	doc.SnapshotBytes = 0
	for i := range doc.Collections {
		doc.Collections[i].Snapshot = fmt.Sprintf("%04d.snapshot", i) // its name in the storage snapshot put together on restore
		doc.SnapshotBytes += doc.Collections[i].Bytes
	}
	doc.StoppedAt = time.Now().UTC()
	if err := r.putDoc(ctx, doc); err != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), backupPrefix+doc.Label+"/")
		return fail(fmt.Errorf("saving the backup's description: %w", err))
	}
	return doc, nil
}

// collection is the backup's record of collection name (zero if none).
func (d backupDoc) collection(name string) collDoc {
	for _, cd := range d.Collections {
		if cd.Name == name {
			return cd
		}
	}
	return collDoc{}
}

// storageReader reads the full storage snapshot a backup holds: the
// stored one, or the collections' snapshots put together as Qdrant's own
// (each collection's snapshot, then config.json naming them and the
// aliases).
func storageReader(ctx context.Context, r *repo, prefix string, doc backupDoc) (io.ReadCloser, error) {
	if doc.Format != formatCollections {
		pr, closer, err := r.getSealed(ctx, prefix+snapshotName)
		if err != nil {
			return nil, err
		}
		return readCloser{pr, closer}, nil
	}
	cfg := snapshotConfig{Collections: map[string]string{}, Aliases: map[string]string{}}
	maps.Copy(cfg.Aliases, doc.Aliases)
	for _, cd := range doc.Collections {
		if cd.Object == "" || !strings.HasPrefix(cd.Object, dataPrefix) || strings.Contains(cd.Object, "..") {
			return nil, fmt.Errorf("backup %s names an unexpected object for collection %s", doc.Label, cd.Name)
		}
		cfg.Collections[cd.Name] = cd.Snapshot
	}
	config, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		err := func() error {
			for _, cd := range doc.Collections {
				src, closer, err := r.getSealed(ctx, cd.Object)
				if err != nil {
					return fmt.Errorf("downloading the snapshot of collection %s: %w", cd.Name, err)
				}
				err = func() error {
					defer closer.Close()
					if err := tw.WriteHeader(&tar.Header{Name: cd.Snapshot, Mode: 0o600, Size: cd.Bytes, ModTime: cd.TakenAt, Typeflag: tar.TypeReg}); err != nil {
						return err
					}
					sum := sha256.New()
					n, err := io.Copy(tw, io.TeeReader(src, sum))
					if err != nil {
						return fmt.Errorf("downloading the snapshot of collection %s: %w", cd.Name, err)
					}
					if n != cd.Bytes || cd.Checksum != "" && hex.EncodeToString(sum.Sum(nil)) != cd.Checksum {
						return fmt.Errorf("the snapshot of collection %s in your bucket isn't the one Rowsafe stored", cd.Name)
					}
					return nil
				}()
				if err != nil {
					return err
				}
			}
			if err := tw.WriteHeader(&tar.Header{Name: "config.json", Mode: 0o644, Size: int64(len(config)), ModTime: doc.TakenAt, Typeflag: tar.TypeReg}); err != nil {
				return err
			}
			if _, err := tw.Write(config); err != nil {
				return err
			}
			return tw.Close()
		}()
		pw.CloseWithError(err)
	}()
	return pr, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// gcData deletes the collection snapshots no backup names any more (those
// of backups retention removed, and of backups that failed part way). The
// caller holds the database's lock, so no backup is being written. docs
// must hold current, the backup just made: a listing without it isn't
// trusted to say what is named.
func gcData(ctx context.Context, r *repo, docs []backupDoc, current string) (int, error) {
	if !slices.ContainsFunc(docs, func(d backupDoc) bool { return d.Label == current }) {
		return 0, nil
	}
	named := map[string]bool{}
	for _, d := range docs {
		for _, cd := range d.Collections {
			if cd.Object != "" {
				named[cd.Object] = true
			}
		}
	}
	objs, err := r.st.List(ctx, dataPrefix)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range objs {
		if named[o.Key] {
			continue
		}
		if err := r.st.Delete(ctx, o.Key); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
