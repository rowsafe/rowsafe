package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof for Meilisearch: download the newest snapshot, start a temporary
// Meilisearch from it on 127.0.0.1 and check every index the snapshot
// recorded is there, with its primary key, its settings and (when the
// snapshot recorded them exactly) its number of documents, and that a
// search answers. The instance is stopped and deleted afterwards.

func drillRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.DrillDir, protocol.EngineMeilisearch)
}

func copyRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.RewindDir, protocol.EngineMeilisearch)
}

func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	res := &protocol.DrillResult{}
	fail := func(err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	s, err := loadServer(env, db.Port)
	if err != nil {
		return fail(err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return fail(err)
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return fail(fmt.Errorf("listing backups: %w", err))
	}
	if len(docs) == 0 {
		return fail(errNoBackup)
	}
	doc := docs[len(docs)-1]
	res.BackupLabel = doc.Label
	taken := doc.TakenAt
	res.RecoveredTo = &taken
	tl.Printf("testing backup %s (taken %s): %s, %s", doc.Label, doc.TakenAt.Format(time.RFC3339),
		plural(int64(len(doc.Indexes)), "index", "indexes"), humanBytes(doc.SnapshotBytes))

	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	defer func() { _ = os.Remove(drillRoot(env)) }() // empty once the test's folder is gone
	sc, err := restoreScratch(ctx, env, r, s, doc, drillRoot(env), taskID, tl)
	if err != nil {
		return fail(err)
	}
	defer func() {
		sc.stop()
		_ = sc.remove()
	}()
	res.RestoredBytes = dirSize(sc.dbPath())
	c := sc.client()
	defer c.close()
	got, err := inspect(ctx, c)
	if err != nil {
		return fail(fmt.Errorf("reading the restored Meilisearch: %w", err))
	}
	have := map[string]indexState{}
	for _, i := range got.Indexes {
		have[i.UID] = i
	}
	for _, want := range doc.Indexes {
		dd := protocol.DrillDatabase{Name: want.UID, SourceTables: int(max(want.Documents, 0))}
		g, ok := have[want.UID]
		if !ok {
			res.Databases = append(res.Databases, dd)
			res.Failures = append(res.Failures, fmt.Sprintf("the index %s is missing from the restored snapshot", want.UID))
			continue
		}
		dd.Present, dd.RestoredTables = true, int(g.Stats.NumberOfDocuments)
		res.Databases = append(res.Databases, dd)
		if want.Documents >= 0 && g.Stats.NumberOfDocuments != want.Documents {
			res.Failures = append(res.Failures, fmt.Sprintf("the index %s has %s, the snapshot recorded %s", want.UID,
				plural(g.Stats.NumberOfDocuments, "document", "documents"), commas(want.Documents)))
		}
		if want.PrimaryKey != "" && g.PrimaryKey != want.PrimaryKey {
			res.Failures = append(res.Failures, fmt.Sprintf("the index %s's primary key is %q, not %q", want.UID, g.PrimaryKey, want.PrimaryKey))
		}
		if want.SettingsHash != "" {
			if st, err := c.settings(ctx, want.UID); err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("reading the index %s's settings: %v", want.UID, err))
			} else if h := settingsHash(st); h != want.SettingsHash {
				res.Warnings = append(res.Warnings, fmt.Sprintf("the index %s's settings read back differently than when the snapshot was taken "+
					"(a Meilisearch update can add new settings)", want.UID))
			}
		}
		if g.Stats.NumberOfDocuments > 0 {
			var sr struct {
				Hits []map[string]any `json:"hits"`
			}
			if err := c.do(ctx, http.MethodPost, "/indexes/"+want.UID+"/search", nil, map[string]any{"q": "", "limit": 1, "attributesToRetrieve": []string{}}, &sr); err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("a search in the index %s failed: %v", want.UID, err))
			} else if len(sr.Hits) == 0 {
				res.Failures = append(res.Failures, fmt.Sprintf("a search in the index %s found nothing", want.UID))
			}
		}
	}
	res.DurationSeconds = time.Since(started).Seconds()
	if len(res.Failures) > 0 {
		for _, f := range res.Failures {
			tl.Printf("FAILED: %s", f)
		}
		return res, errors.New(res.Failures[0])
	}
	res.Passed = true
	tl.Printf("Proof passed: %s restored with %s, searches answer (%s on disk, %s)",
		plural(int64(len(doc.Indexes)), "index", "indexes"), plural(got.documents(), "document", "documents"),
		humanBytes(res.RestoredBytes), time.Since(started).Round(time.Second))
	return res, nil
}

// ---- Marks: a snapshot taken on the spot, named.

func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	var prev markDoc
	switch err := r.getJSON(ctx, markKey(p.Name), &prev); {
	case err == nil:
		return nil, fmt.Errorf("there is already a Mark named %s", p.Name)
	case !errors.Is(err, objstore.ErrNotFound):
		return nil, fmt.Errorf("reading your bucket: %w", err)
	}
	tl.Printf("Mark %s: taking a snapshot now", p.Name)
	doc, err := e.takeSnapshot(ctx, env, db, r, sourceMark, p.Name, tl)
	if err != nil {
		return nil, err
	}
	if err := r.putJSON(ctx, markKey(p.Name), markDoc{Name: p.Name, Label: doc.Label, CreatedAt: doc.TakenAt}); err != nil {
		return nil, fmt.Errorf("saving the Mark in your bucket: %w", err)
	}
	now := time.Now().UTC()
	tl.Printf("Mark %s is in your bucket (snapshot %s): Rewind can go back exactly to it", p.Name, doc.Label)
	return &protocol.RestorePointResult{Name: p.Name, LSN: doc.Label, CreatedAt: doc.TakenAt, Archived: true, ArchivedAt: &now}, nil
}

// pick is the snapshot a rewind target restores: a Mark's, or the newest
// taken at or before a moment.
func pick(ctx context.Context, r *repo, t protocol.RewindTarget) (backupDoc, error) {
	if (t.Mark == "") == (t.Time == nil) {
		return backupDoc{}, errors.New("pick a moment or a Mark (exactly one)")
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return backupDoc{}, fmt.Errorf("listing backups: %w", err)
	}
	if len(docs) == 0 {
		return backupDoc{}, errNoBackup
	}
	if t.Mark != "" {
		if !markNameRE.MatchString(t.Mark) {
			return backupDoc{}, fmt.Errorf("invalid Mark name %q", t.Mark)
		}
		var m markDoc
		if err := r.getJSON(ctx, markKey(t.Mark), &m); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return backupDoc{}, fmt.Errorf("the Mark %q isn't in your bucket", t.Mark)
			}
			return backupDoc{}, fmt.Errorf("reading the Mark: %w", err)
		}
		for _, d := range docs {
			if d.Label == m.Label {
				return d, nil
			}
		}
		return backupDoc{}, fmt.Errorf("the snapshot of the Mark %q is no longer in your bucket (past the retention window)", t.Mark)
	}
	at := t.Time.UTC().Truncate(time.Second).Add(time.Second - time.Nanosecond)
	if t.BackupSet != "" {
		for _, d := range docs {
			if d.Label == t.BackupSet && !d.TakenAt.After(at) {
				return d, nil
			}
		}
	}
	for i := len(docs) - 1; i >= 0; i-- {
		if !docs[i].TakenAt.After(at) {
			return docs[i], nil
		}
	}
	return backupDoc{}, fmt.Errorf("there is no snapshot from before %s in your bucket: the oldest is from %s",
		t.Time.UTC().Format("2006-01-02 15:04:05 UTC"), docs[0].TakenAt.UTC().Format("2006-01-02 15:04:05 UTC"))
}
