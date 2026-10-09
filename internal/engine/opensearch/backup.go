package opensearch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// blocker says why a server can't be protected ("" when it can).
func blocker(in serverInfo) string { return in.supported() }

func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	tl.Printf("found OpenSearch %s on port %d: %d indices, %s documents, %s", in.Version, db.Port, len(snapshotIndices(in)),
		commas(in.totalDocs()), humanBytes(in.totalBytes()))
	res := &protocol.AdoptResult{Inspect: in.inspectResult(db.Port)}
	dir, dirErr := repoDir(in)
	res.Plan = []protocol.Change{
		{Kind: "command", Description: "Prepare your bucket for this database (a folder with its own encrypted backups)"},
		{Kind: "command", Description: "Take OpenSearch's own snapshots into " + dir + " on this server, every 30 minutes and on every Mark"},
		{Kind: "command", Description: "Copy each snapshot's new files to your bucket, encrypted on this server; OpenSearch never sees the bucket"},
	}
	res.Warnings = append(res.Warnings, "OpenSearch keeps no log of its changes: restores go back to a snapshot (a backup or a Mark), not to any second.")
	if !in.Security {
		res.Warnings = append(res.Warnings, "OpenSearch runs without its security plugin: anyone who can reach port "+fmt.Sprint(db.Port)+
			" can read and change everything. Pulse explains how to turn it on.")
	}
	if dirErr != nil {
		res.Warnings = append(res.Warnings, firstSentence(dirErr))
		res.RestartRequired = true
	}
	if !p.Apply {
		tl.Printf("plan only: nothing was changed")
		return res, nil
	}
	if why := blocker(in); why != "" {
		return res, errors.New(why)
	}
	if dirErr != nil {
		return res, dirErr
	}
	if err := ensureRepo(ctx, c, dir); err != nil {
		return res, err
	}
	tl.Printf("OpenSearch's snapshot repository %q is set up in %s", repoName, dir)
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	if err := r.ensureMarker(ctx, db.Name); err != nil {
		return res, err
	}
	res.Applied = true
	tl.Printf("backups are on: the first snapshot runs now, then every 30 minutes")
	return res, nil
}

func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult(db.Port)}
	if why := blocker(in); why != "" {
		return res, errors.New(why)
	}
	dir, err := repoDir(in)
	if err != nil {
		return res, err
	}
	if err := ensureRepo(ctx, c, dir); err != nil {
		return res, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	if err := r.ensureMarker(ctx, db.Name); err != nil {
		return res, err
	}
	if err := r.putJSON(ctx, "check.json", map[string]time.Time{"checked_at": time.Now().UTC()}); err != nil {
		return res, fmt.Errorf("writing to your bucket: %w", err)
	}
	var back map[string]time.Time
	if err := r.getJSON(ctx, "check.json", &back); err != nil {
		return res, fmt.Errorf("reading back from your bucket: %w", err)
	}
	tl.Printf("snapshots work: OpenSearch writes to %s, the agent reads it, and your bucket takes Rowsafe's encrypted files", dir)
	res.OK = true
	return res, nil
}

// takeResult is a snapshot taken and copied to the bucket.
type takeResult struct {
	Doc  backupDoc
	Sync syncStats
}

// take snapshots everything (kind F, D, M or R), copies the repository to
// the bucket and writes the snapshot's description. The caller holds the
// database's repository lock.
func (e *Engine) take(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, c *client, r *repo, in serverInfo,
	kind, mark string, tl agent.TaskLogger) (takeResult, error) {
	var res takeResult
	dir, err := repoDir(in)
	if err != nil {
		return res, err
	}
	if err := ensureRepo(ctx, c, dir); err != nil {
		return res, err
	}
	now := time.Now().UTC()
	label := newLabel(now, kind)
	// Two snapshots in the same second (a Mark right after a backup) get
	// the next second.
	if snaps, err := listSnapshots(ctx, c); err == nil {
		for taken := true; taken; {
			taken = false
			for _, s := range snaps {
				if s.Snapshot == snapshotName(label) {
					now = now.Add(time.Second)
					label, taken = newLabel(now, kind), true
				}
			}
		}
	}
	indices := snapshotIndices(in)
	before := refreshCounts(ctx, c, in)
	meta := map[string]any{"taken_by": "rowsafe", "label": label}
	if mark != "" {
		meta["mark"] = mark
	}
	tl.Printf("taking OpenSearch snapshot %s of %d indices and data streams", snapshotName(label), len(indices))
	snap, err := createSnapshot(ctx, c, label, indices, meta)
	if err != nil {
		return res, err
	}
	after := refreshCounts(ctx, c, in)
	doc := backupDoc{Label: label, Snapshot: snap.Snapshot, UUID: snap.UUID, Kind: kind, Mark: mark, Version: in.Version,
		StartedAt: snap.start(), StoppedAt: snap.end(), DataStreams: snap.DataStreams, SizeBytes: in.totalBytes()}
	for _, i := range in.Indices {
		doc.Indices = append(doc.Indices, docIndex{Name: i.Name, DataStream: i.DataStream, DocsBefore: before[i.Name], DocsAfter: after[i.Name]})
	}
	tl.Printf("snapshot done in %s; copying its new files to your bucket, encrypted on this server", snap.end().Sub(snap.start()).Round(time.Millisecond))
	st, err := r.syncRepo(ctx, dir)
	if err != nil {
		return res, err
	}
	doc.StoredBytes = st.StoredBytes
	if err := r.putJSON(ctx, docKey(label), doc); err != nil {
		return res, fmt.Errorf("saving the snapshot's description: %w", err)
	}
	tl.Printf("copied %d new files (%s, %s stored); the repository holds %d files (%s)", st.Uploaded, humanBytes(st.UploadedBytes),
		humanBytes(st.StoredBytes), st.Files, humanBytes(st.RepoBytes))
	res.Doc, res.Sync = doc, st
	return res, nil
}

func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	kind := kindFull
	if p.Type == protocol.BackupDiff || p.Type == protocol.BackupIncr {
		kind = kindDiff
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if why := blocker(in); why != "" {
		return nil, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	lock := e.repoLock(db)
	lock.Lock()
	defer lock.Unlock()
	t, err := e.take(ctx, env, db, c, r, in, kind, "", tl)
	if err != nil {
		return nil, err
	}
	if err := e.retention(ctx, c, r, db, in, tl); err != nil {
		tl.Printf("note: removing old snapshots failed (%v); it is tried again after the next backup", err)
	}
	typ := protocol.BackupFull
	if kind == kindDiff {
		typ = protocol.BackupDiff
	}
	tl.Printf("backup %s complete", t.Doc.Label)
	return &protocol.BackupResult{Label: t.Doc.Label, Type: typ, StartedAt: t.Doc.StartedAt, StoppedAt: t.Doc.StoppedAt,
		SizeBytes: in.totalBytes(), RepoSizeBytes: t.Sync.RepoBytes}, nil
}

// retention keeps the newest RetentionFull full snapshots and every
// snapshot and Mark newer than the oldest of them; a snapshot kept for an
// Undo stays until its time is up (inplace.go). OpenSearch deletes the files no kept
// snapshot needs; the bucket then follows. tl may be nil.
func (e *Engine) retention(ctx context.Context, c *client, r *repo, db protocol.DatabaseSpec, in serverInfo, tl agent.TaskLogger) error {
	keep := max(db.RetentionFull, 1)
	snaps, err := listSnapshots(ctx, c)
	if err != nil {
		return err
	}
	var fulls []time.Time
	for _, s := range snaps {
		if l := labelOf(s.Snapshot); labelKind(l) == kindFull && s.State == "SUCCESS" {
			fulls = append(fulls, s.start())
		}
	}
	if len(fulls) <= keep {
		return syncAfter(ctx, r, in)
	}
	oldest := fulls[len(fulls)-keep]
	removed := 0
	for _, s := range snaps {
		l := labelOf(s.Snapshot)
		if l == "" || labelKind(l) == kindRewind || !s.start().Before(oldest) {
			continue
		}
		if err := deleteSnapshot(ctx, c, s.Snapshot); err != nil {
			return err
		}
		_ = r.st.Delete(ctx, docKey(l))
		removed++
	}
	if removed > 0 && tl != nil {
		tl.Printf("kept the newest %d full snapshots and everything since: removed %d older snapshots", keep, removed)
	}
	return syncAfter(ctx, r, in)
}

// syncAfter copies the repository to the bucket after deletions.
func syncAfter(ctx context.Context, r *repo, in serverInfo) error {
	dir, err := repoDir(in)
	if err != nil {
		return err
	}
	_, err = r.syncRepo(ctx, dir)
	return err
}

// mark takes a Mark: a snapshot on the spot, named after it (its label is
// the restore point's LSN).
func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if strings.TrimSpace(p.Name) == "" {
		return nil, errors.New("a Mark needs a name")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	lock := e.repoLock(db)
	lock.Lock()
	defer lock.Unlock()
	t, err := e.take(ctx, env, db, c, r, in, kindMark, p.Name, tl)
	if err != nil {
		return nil, err
	}
	at := t.Doc.StoppedAt
	tl.Printf("Mark %s saved: snapshot %s, in your bucket", p.Name, t.Doc.Snapshot)
	return &protocol.RestorePointResult{Name: p.Name, LSN: t.Doc.Label, Archived: true, CreatedAt: t.Doc.StartedAt, ArchivedAt: &at}, nil
}

// firstSentence is an error's text up to its first colon-separated
// explanation, for warnings.
func firstSentence(err error) string {
	s := err.Error()
	s = strings.TrimPrefix(s, errNoRepoPath.Error()+": ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}
