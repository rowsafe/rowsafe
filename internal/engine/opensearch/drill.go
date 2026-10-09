package opensearch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof for OpenSearch: download the newest snapshot from the bucket (not
// from the server's own disk: the test proves the bucket's copy restores),
// restore it into a temporary OpenSearch, check every index and data stream
// is there and green and holds the documents counted when it was taken.
// The temporary server is stopped and deleted afterwards.

func drillRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.DrillDir, protocol.EngineOpenSearch)
}

// restored is a snapshot restored into a temporary server.
type restored struct {
	Doc   backupDoc
	Bytes int64
}

// restoreDoc downloads doc's snapshot from the bucket into s, starts s and
// restores the snapshot there; s is left running (the caller stops it).
func restoreDoc(ctx context.Context, r *repo, doc backupDoc, s scratch, tl agent.TaskLogger) (restored, *client, error) {
	out := restored{Doc: doc}
	if _, err := checkProgram(); err != nil {
		return out, nil, err
	}
	need := doc.SizeBytes*2 + 512<<20
	if err := ensureSpace(s.Dir, need, "the restored copy"); err != nil {
		return out, nil, err
	}
	tl.Printf("downloading snapshot %s from your bucket and decrypting it on this server", doc.Snapshot)
	n, err := r.download(ctx, s.repoDir(), doc.Snapshot)
	out.Bytes = n
	if err != nil {
		return out, nil, err
	}
	tl.Printf("downloaded %s; starting a temporary OpenSearch (127.0.0.1 only, its own login)", humanBytes(n))
	if err := s.start(ctx); err != nil {
		return out, nil, err
	}
	st, err := s.loadState()
	if err != nil {
		return out, nil, err
	}
	c := s.client(st)
	tl.Printf("restoring snapshot %s into it", doc.Snapshot)
	if err := s.restore(ctx, c, doc.Snapshot); err != nil {
		return out, c, err
	}
	return out, c, nil
}

// pickDoc is the snapshot to restore: label's, else the newest finished one
// at or before at (nil: the newest).
func pickDoc(docs []backupDoc, label string, at *time.Time) (backupDoc, error) {
	var best *backupDoc
	for i := range docs {
		d := &docs[i]
		if d.Kind == kindRewind {
			continue
		}
		switch {
		case label != "":
			if d.Label == label {
				return *d, nil
			}
		case at != nil && d.StoppedAt.After(*at):
		default:
			if best == nil || d.StoppedAt.After(best.StoppedAt) {
				best = d
			}
		}
	}
	if label != "" {
		return backupDoc{}, fmt.Errorf("the snapshot %s isn't in your bucket any more (retention removed it?)", label)
	}
	if best == nil {
		return backupDoc{}, errors.New("there is no snapshot in your bucket yet: Proof runs once the first backup has finished")
	}
	return *best, nil
}

func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	res := &protocol.DrillResult{}
	fail := func(err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	docs, err := r.listDocs(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading your bucket: %w", err)
	}
	doc, err := pickDoc(docs, "", nil)
	if err != nil {
		return nil, err
	}
	res.BackupLabel = doc.Label
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	defer func() { _ = os.Remove(drillRoot(env)) }()
	s, err := newScratch(drillRoot(env), taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the restore test failed", "dir", s.Dir, "err", err)
		}
	}()
	out, c, err := restoreDoc(ctx, r, doc, s, tl)
	res.RestoredBytes = out.Bytes
	if err != nil {
		return fail(err)
	}
	at := doc.StoppedAt
	res.RecoveredTo = &at
	in, err := inspect(ctx, c)
	if err != nil {
		return fail(fmt.Errorf("reading the restored copy: %w", err))
	}
	got := refreshCounts(ctx, c, in)
	present := map[string]indexInfo{}
	for _, i := range in.Indices {
		present[i.Name] = i
	}
	for _, want := range doc.Indices {
		i, ok := present[want.Name]
		dd := protocol.DrillDatabase{Name: want.Name, Present: ok, SourceTables: int(want.DocsAfter), RestoredTables: int(got[want.Name])}
		res.Databases = append(res.Databases, dd)
		switch {
		case !ok:
			res.Failures = append(res.Failures, fmt.Sprintf("the index %s is missing from the restored copy", want.Name))
		case i.Health != "green":
			res.Failures = append(res.Failures, fmt.Sprintf("the index %s came back %s, not green", want.Name, i.Health))
		case want.DocsBefore == want.DocsAfter && got[want.Name] != want.DocsAfter:
			res.Failures = append(res.Failures, fmt.Sprintf("the index %s has %s documents in the restored copy, but %s when the snapshot was taken",
				want.Name, commas(got[want.Name]), commas(want.DocsAfter)))
		case got[want.Name] < min(want.DocsBefore, want.DocsAfter) || got[want.Name] > max(want.DocsBefore, want.DocsAfter):
			res.Warnings = append(res.Warnings, fmt.Sprintf("the index %s has %s documents in the restored copy; it had %s to %s while the snapshot was taken (writes went on meanwhile)",
				want.Name, commas(got[want.Name]), commas(want.DocsBefore), commas(want.DocsAfter)))
		}
		tl.Printf("%s: %s documents, %s", want.Name, commas(got[want.Name]), i.Health)
	}
	// Every index answers a search.
	for _, i := range in.Indices {
		if err := c.get(ctx, "/"+pathEscape(i.Name)+"/_search?size=1", nil); err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("searching %s in the restored copy failed: %v", i.Name, err))
		}
	}
	res.DurationSeconds = time.Since(started).Seconds()
	if len(res.Failures) > 0 {
		return res, fmt.Errorf("restore test failed: %s", res.Failures[0])
	}
	res.Passed = true
	tl.Printf("restore test passed: snapshot %s (taken %s) restored from your bucket, %d indices green with their documents",
		doc.Label, doc.StoppedAt.Format(time.RFC3339), len(doc.Indices))
	return res, nil
}
