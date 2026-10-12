package opensearch

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
		{Kind: "command", Description: "Take OpenSearch's own snapshots into " + dir + " on this server, every 5 minutes by default and on every Mark"},
		{Kind: "command", Description: "Copy each snapshot's new files to your bucket, encrypted on this server; OpenSearch never sees the bucket"},
	}
	res.Warnings = append(res.Warnings, "OpenSearch keeps no log of its changes: restores go back to a snapshot (a backup or a Mark), not to any second.")
	if !in.Security {
		res.Warnings = append(res.Warnings, "OpenSearch runs without its security plugin: anyone who can reach port "+fmt.Sprint(db.Port)+
			" can read and change everything. Pulse explains how to turn it on.")
	}
	if dirErr != nil {
		// Not RestartRequired: OpenSearch keeps no change log for the control
		// plane to watch; the apply below says what is missing, and a new
		// adopt after the restart turns backups on.
		res.Warnings = append(res.Warnings, firstSentence(dirErr))
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
	if err := r.ensureMarker(ctx, db.Name, in.ClusterUUID); err != nil {
		return res, err
	}
	res.Applied = true
	tl.Printf("backups are on: the first snapshot runs now, then every 5 minutes by default (each copies only what is new)")
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
	if err := r.ensureMarker(ctx, db.Name, in.ClusterUUID); err != nil {
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
	if fz, ok := loadFreeze(env, db.ID); ok {
		// Apps' writes are stopped for a move: the new server lifts these
		// blocks and makes the templates and pipelines (snapshot_move.go).
		doc.MoveBlocked = slices.Clone(fz.Blocked)
		doc.Globals = readGlobals(ctx, c)
	}
	tl.Printf("snapshot done in %s; copying its new files to your bucket, encrypted on this server", snap.end().Sub(snap.start()).Round(time.Millisecond))
	st, err := r.syncRepo(ctx, dir, in.ClusterUUID, nil)
	if err != nil {
		return res, err
	}
	if st.Held != "" {
		tl.Printf("note: %s", st.Held)
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
	res := &protocol.BackupResult{Label: t.Doc.Label, Type: typ, StartedAt: t.Doc.StartedAt, StoppedAt: t.Doc.StoppedAt,
		SizeBytes: in.totalBytes(), RepoSizeBytes: t.Sync.RepoBytes}
	if snaps, err := listSnapshots(ctx, c); err == nil { // what retention kept (protocol.BackupResult.Kept)
		res.Kept = []string{}
		for _, s := range snaps {
			if l := labelOf(s.Snapshot); l != "" {
				res.Kept = append(res.Kept, l)
			}
		}
	}
	return res, nil
}

// Retention: the newest RetentionFull full snapshots (one a day by
// default) start the window; inside it every snapshot of the last
// keepAllFor stays, then the newest of each hour up to keepHourlyFor, then
// only the full ones (one a day). Marks stay for the whole window, and the
// newest snapshot always stays. A snapshot kept for an Undo stays until its
// time is up (inplace.go). Snapshots every few minutes stay cheap: each one
// copies only new files, and the tiers keep their number bounded (about
// 300 a day for a day, then 24 a day for a week).
const (
	keepAllFor    = 24 * time.Hour
	keepHourlyFor = 7 * 24 * time.Hour
)

// minWindow is the shortest retention window (a variable for tests).
var minWindow = 24 * time.Hour

// retainDrop picks the snapshots retention deletes (snaps as OpenSearch
// lists them, oldest first): Rowsafe's own only, never one kept for Undo.
func retainDrop(snaps []snapInfo, keepFull int, now time.Time) []string {
	keepFull = max(keepFull, 1)
	var fulls []time.Time
	newest := ""
	for _, s := range snaps {
		l := labelOf(s.Snapshot)
		if l == "" || labelKind(l) == kindRewind {
			continue
		}
		if s.State == "SUCCESS" {
			newest = s.Snapshot
			if labelKind(l) == kindFull {
				fulls = append(fulls, s.start())
			}
		}
	}
	var oldest time.Time // the window's start (zero: everything is in it)
	if len(fulls) > keepFull {
		oldest = fulls[len(fulls)-keepFull]
	}
	// Full snapshots more often than daily (a person's schedule) never
	// shrink the window below a day: Marks and the last day's snapshots stay.
	if oldest.After(now.Add(-minWindow)) {
		oldest = now.Add(-minWindow)
	}
	// The newest snapshot of each hour, among those between the tiers.
	hourly := map[string]string{}
	for _, s := range snaps {
		if l := labelOf(s.Snapshot); l != "" && labelKind(l) == kindDiff && s.State == "SUCCESS" {
			hourly[s.start().UTC().Format("2006010215")] = s.Snapshot // oldest first: the last one wins
		}
	}
	var drop []string
	for _, s := range snaps {
		l := labelOf(s.Snapshot)
		if l == "" || labelKind(l) == kindRewind || s.Snapshot == newest {
			continue
		}
		if s.start().Before(oldest) {
			drop = append(drop, s.Snapshot)
			continue
		}
		if labelKind(l) != kindDiff {
			continue // full snapshots and Marks stay for the window
		}
		age := now.Sub(s.start())
		switch {
		case s.State != "SUCCESS" && age > time.Hour:
			drop = append(drop, s.Snapshot) // a failed or partial one
		case age <= keepAllFor:
		case age <= keepHourlyFor && hourly[s.start().UTC().Format("2006010215")] == s.Snapshot:
		default:
			drop = append(drop, s.Snapshot)
		}
	}
	return drop
}

// retention deletes what retainDrop picks through OpenSearch (which
// deletes only the files no kept snapshot needs); the bucket then follows.
// tl may be nil.
func (e *Engine) retention(ctx context.Context, c *client, r *repo, db protocol.DatabaseSpec, in serverInfo, tl agent.TaskLogger) error {
	snaps, err := listSnapshots(ctx, c)
	if err != nil {
		return err
	}
	drop := retainDrop(snaps, db.RetentionFull, time.Now())
	if len(drop) == 0 {
		return nil
	}
	dir, err := repoDir(in)
	if err != nil {
		return err
	}
	before, err := localSet(dir)
	if err != nil {
		return err
	}
	removed := 0
	for _, name := range drop {
		if err := deleteSnapshot(ctx, c, name); err != nil {
			return err
		}
		_ = r.st.Delete(ctx, docKey(labelOf(name)))
		removed++
	}
	if removed > 0 && tl != nil {
		tl.Printf("removed %d older snapshots (kept: every snapshot of the last day, one an hour for a week, the newest %d full ones and their Marks)",
			removed, max(db.RetentionFull, 1))
	}
	after, err := localSet(dir)
	if err != nil {
		return err
	}
	st, err := r.syncRepo(ctx, dir, in.ClusterUUID, gone(before, after))
	if err == nil && st.Held != "" && tl != nil {
		tl.Printf("note: %s", st.Held)
	}
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
