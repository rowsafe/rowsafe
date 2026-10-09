package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Backups: Meilisearch writes a snapshot of every index, its settings, the
// task queue and the API keys into its snapshot folder (one file,
// <data folder name>.snapshot, replaced each time; POST /snapshots, run
// after the tasks already waiting). The agent reads that file, encrypts it
// on the server and uploads it. The file stays in Meilisearch's folder,
// where it was written, until the next snapshot replaces it.

// snapshotTimeout bounds one snapshot: Meilisearch copies every index.
var snapshotTimeout = 6 * time.Hour

// takeSnapshot has Meilisearch write a snapshot and uploads it under a new
// label. Indexes are counted again once it is written: when nothing
// changed since it started, the counts are the snapshot's exactly.
func (e *Engine) takeSnapshot(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r *repo, source, mark string, tl agent.TaskLogger) (backupDoc, error) {
	// One snapshot at a time: Meilisearch writes each to the same file.
	e.snapMu.Lock()
	defer e.snapMu.Unlock()
	doc := backupDoc{Source: source, Mark: mark, StartedAt: time.Now().UTC()}
	c, s, err := connect(ctx, env, db)
	if err != nil {
		return doc, err
	}
	defer c.close()
	v, err := c.version(ctx)
	if err != nil {
		return doc, err
	}
	doc.Version = v.PkgVersion
	if err := readable(s.SnapshotDir); err != nil && !notExist(err) {
		return doc, fmt.Errorf("Rowsafe can't read Meilisearch's snapshot folder %s (%v): run the Rowsafe installer on the server again, "+
			"it gives Rowsafe's user read access to it", s.SnapshotDir, err)
	}
	before, _ := os.Stat(s.snapshotFile())

	tl.Printf("asking Meilisearch for a snapshot (it runs after the tasks already waiting; searches go on)")
	enq, err := c.enqueue(ctx, http.MethodPost, "/snapshots", nil, nil)
	if err != nil {
		return doc, fmt.Errorf("asking for a snapshot: %w", err)
	}
	t, err := c.waitTask(ctx, enq, snapshotTimeout)
	if err != nil {
		return doc, err
	}
	doc.TakenAt = doc.StartedAt
	if t.StartedAt != nil {
		doc.TakenAt = t.StartedAt.UTC()
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return doc, err
	}
	doc.DatabaseBytes, doc.Indexes = in.DatabaseSize, indexDocs(ctx, c, in)
	if st, err := c.stats(ctx); err == nil && st.LastUpdate != nil && t.StartedAt != nil && st.LastUpdate.After(*t.StartedAt) {
		for i := range doc.Indexes {
			doc.Indexes[i].Documents = -1 // changed meanwhile: unknown exactly
		}
		tl.Printf("documents changed while the snapshot was written: Proof checks its indexes and settings, not exact counts")
	}

	f, err := os.Open(s.snapshotFile())
	if err != nil {
		return doc, fmt.Errorf("Meilisearch wrote its snapshot, but Rowsafe can't read %s (%v): run the Rowsafe installer on the server again",
			s.snapshotFile(), err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return doc, err
	}
	// The file must be the one just written, not an older snapshot left
	// in a folder Meilisearch no longer uses.
	if before != nil && os.SameFile(before, fi) && !fi.ModTime().After(before.ModTime()) ||
		t.StartedAt != nil && fi.ModTime().Before(t.StartedAt.Add(-2*time.Second)) {
		return doc, fmt.Errorf("Meilisearch didn't write its snapshot to %s: check its snapshot folder (--snapshot-dir) is %s, "+
			"then run the Rowsafe installer on the server again", s.snapshotFile(), s.SnapshotDir)
	}
	doc.SnapshotBytes = fi.Size()
	if doc.Label, err = r.freshLabel(ctx, doc.TakenAt); err != nil {
		return doc, err
	}
	tl.Printf("uploading the snapshot (%s), encrypted on this server", humanBytes(doc.SnapshotBytes))
	stored, err := r.putSealed(ctx, backupKey(doc.Label, snapshotName), f)
	if err != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), doc.Label)
		return doc, fmt.Errorf("uploading the snapshot: %w", err)
	}
	doc.StoredBytes, doc.StoppedAt = stored, time.Now().UTC()
	if err := r.putJSON(ctx, backupKey(doc.Label, backupDocName), doc); err != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), doc.Label)
		return doc, fmt.Errorf("saving the backup's description: %w", err)
	}
	return doc, nil
}

func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	if p.Type != "" && p.Type != protocol.BackupFull {
		tl.Printf("Meilisearch backups are always whole snapshots; taking one instead of a %s backup", p.Type)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	doc, err := e.takeSnapshot(ctx, env, db, r, sourceScheduled, "", tl)
	if err != nil {
		return nil, err
	}
	tl.Printf("backup %s complete: %s in %s, %s stored (encrypted on this server)", doc.Label,
		plural(int64(len(doc.Indexes)), "index", "indexes"), humanBytes(doc.DatabaseBytes), humanBytes(doc.StoredBytes))
	if err := retention(ctx, r, db, doc.Label, time.Now(), tl); err != nil {
		tl.Printf("note: removing old backups failed (%v); it is tried again after the next backup", err)
	}
	return backupResult(doc), nil
}

func backupResult(d backupDoc) *protocol.BackupResult {
	return &protocol.BackupResult{Label: d.Label, Type: protocol.BackupFull, StartedAt: d.StartedAt, StoppedAt: d.StoppedAt,
		SizeBytes: d.DatabaseBytes, RepoSizeBytes: d.StoredBytes}
}

// Retention: RetentionFull is how many days of snapshots are kept. Every
// snapshot of the last 48 hours stays; older ones, the newest of each day
// (UTC) and those Marks point at; nothing older than the window, except
// the newest snapshot, which always stays.
const keepAllFor = 48 * time.Hour

func retention(ctx context.Context, r *repo, db protocol.DatabaseSpec, current string, now time.Time, tl agent.TaskLogger) error {
	docs, unfinished, err := r.listBackups(ctx)
	if err != nil {
		return err
	}
	for _, l := range unfinished {
		if l == current {
			continue
		}
		if t, err := time.Parse("20060102-150405", strings.TrimSuffix(l, "F")); err == nil && now.Sub(t) > 24*time.Hour {
			if err := r.deleteBackup(ctx, l); err != nil {
				return err
			}
		}
	}
	marked, err := r.markedLabels(ctx)
	if err != nil {
		return err
	}
	drop := retainDrop(docs, marked, max(db.RetentionFull, 1), now)
	for _, l := range drop {
		if err := r.deleteBackup(ctx, l); err != nil {
			return err
		}
	}
	if tl != nil && len(drop) > 0 {
		tl.Printf("removed %s past the retention window (%d days)", plural(int64(len(drop)), "older snapshot", "older snapshots"), max(db.RetentionFull, 1))
	}
	return nil
}

// retainDrop picks the labels to delete (docs oldest first).
func retainDrop(docs []backupDoc, marked map[string]bool, days int, now time.Time) []string {
	if len(docs) <= 1 {
		return nil
	}
	window := time.Duration(days) * 24 * time.Hour
	newestOfDay := map[string]string{}
	for _, d := range docs {
		newestOfDay[d.TakenAt.UTC().Format("2006-01-02")] = d.Label // oldest first: the last one wins
	}
	var drop []string
	for _, d := range docs[:len(docs)-1] { // the newest always stays
		age := now.Sub(d.TakenAt)
		switch {
		case age <= keepAllFor:
		case age > window:
			drop = append(drop, d.Label)
		case marked[d.Label], newestOfDay[d.TakenAt.UTC().Format("2006-01-02")] == d.Label:
		default:
			drop = append(drop, d.Label)
		}
	}
	return drop
}

var errNoBackup = errors.New("there is no finished backup in your bucket yet")
