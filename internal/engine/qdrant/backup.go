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
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Backups: Qdrant's own full storage snapshot (every collection and alias),
// taken by the server into its snapshots folder, downloaded over the API as
// it is (no file access: works across containers), encrypted on this
// server on the way to the bucket, then deleted from the server's disk.

// snapshotInfo is Qdrant's description of a snapshot.
type snapshotInfo struct {
	Name         string `json:"name"`
	CreationTime string `json:"creation_time"`
	Size         int64  `json:"size"`
	Checksum     string `json:"checksum"`
}

// fullSnapshot asks the server for a full storage snapshot and waits for it.
func (c *client) fullSnapshot(ctx context.Context) (snapshotInfo, error) {
	var s snapshotInfo
	err := c.call(ctx, http.MethodPost, "/snapshots", url.Values{"wait": {"true"}}, nil, &s)
	if err == nil && s.Name == "" {
		err = errors.New("Qdrant took a snapshot but didn't name it")
	}
	return s, err
}

// deleteFullSnapshot removes a full snapshot from the server's disk.
func (c *client) deleteFullSnapshot(ctx context.Context, name string) error {
	err := c.call(ctx, http.MethodDelete, "/snapshots/"+url.PathEscape(name), url.Values{"wait": {"true"}}, nil, nil)
	if isStatus(err, http.StatusNotFound) {
		return nil
	}
	return err
}

// snapshotConfig is config.json inside a full snapshot.
type snapshotConfig struct {
	Collections map[string]string `json:"collections_mapping"`
	Aliases     map[string]string `json:"collections_aliases"`
}

// readSnapshotTar reads a full snapshot's table of contents as it streams
// by (the tar's config.json and member names), for checking it.
func readSnapshotTar(r io.Reader) (snapshotConfig, []string, error) {
	var cfg snapshotConfig
	var names []string
	tr := tar.NewReader(r)
	found := false
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return cfg, names, err
		}
		names = append(names, h.Name)
		if h.Name == "config.json" {
			data, err := io.ReadAll(io.LimitReader(tr, 16<<20))
			if err != nil {
				return cfg, names, err
			}
			if err := json.Unmarshal(data, &cfg); err != nil {
				return cfg, names, fmt.Errorf("the snapshot's config.json: %w", err)
			}
			found = true
		}
	}
	// Drain what follows the tar's end (padding).
	_, _ = io.Copy(io.Discard, r)
	if !found {
		return cfg, names, errors.New("the snapshot has no config.json")
	}
	return cfg, names, nil
}

// storeSnapshot takes a full snapshot of the server and stores it, sealed,
// under prefix (backup/<label>/ or kept/<id>/): doc describes it.
func (e *Engine) storeSnapshot(ctx context.Context, c *client, r *repo, in serverInfo, source, prefix string, tl agent.TaskLogger) (backupDoc, error) {
	started := time.Now().UTC()
	doc := backupDoc{Source: source, Version: in.Version, VersionNum: in.VersionNum, StartedAt: started, Aliases: in.Aliases, DataBytes: in.totalBytes()}
	tl.Printf("asking Qdrant for a full snapshot of its %d collections (%s points)", len(in.userCollections()), commas(in.totalPoints()))
	snap, err := c.fullSnapshot(ctx)
	if err != nil {
		return doc, fmt.Errorf("taking the snapshot: %w", err)
	}
	doc.TakenAt = started
	if t, err := time.Parse("2006-01-02T15:04:05", snap.CreationTime); err == nil {
		doc.TakenAt = t.UTC()
	}
	e.pendingAdd(snap.Name)
	defer func() {
		if err := c.deleteFullSnapshot(context.WithoutCancel(ctx), snap.Name); err != nil {
			tl.Printf("note: deleting the snapshot from the server's disk failed (%v); it is tried again at the next backup", err)
			return
		}
		e.pendingDone(snap.Name)
	}()
	if prefix == backupPrefix {
		if doc.Label, err = r.freshLabel(ctx, doc.TakenAt); err != nil {
			return doc, err
		}
		prefix = backupPrefix + doc.Label + "/"
	} else {
		doc.Label = strings.Trim(strings.TrimPrefix(prefix, keptPrefix), "/")
	}
	tl.Printf("encrypting the snapshot (%s) on this server and copying it to your bucket", humanBytes(snap.Size))
	resp, err := c.request(ctx, http.MethodGet, "/snapshots/"+url.PathEscape(snap.Name), nil, nil, "")
	if err != nil {
		return doc, fmt.Errorf("reading the snapshot: %w", err)
	}
	defer resp.Body.Close()
	sum := sha256.New()
	var n int64
	pr, pw := io.Pipe()
	tarDone := make(chan error, 1)
	var cfg snapshotConfig
	go func() {
		var err error
		cfg, _, err = readSnapshotTar(pr)
		pr.CloseWithError(err)
		tarDone <- err
	}()
	src := io.TeeReader(io.TeeReader(&countReader{r: resp.Body, n: &n}, sum), pw)
	stored, err := r.putSealed(ctx, prefix+snapshotName, readerFunc(func(p []byte) (int, error) {
		k, err := src.Read(p)
		if err == io.EOF {
			pw.Close()
		}
		return k, err
	}))
	pw.Close()
	terr := <-tarDone
	if err != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("copying the snapshot to your bucket: %w", err)
	}
	if terr != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("the snapshot Qdrant gave isn't readable: %w", terr)
	}
	got := hex.EncodeToString(sum.Sum(nil))
	if snap.Checksum != "" && !strings.EqualFold(snap.Checksum, got) {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("the snapshot changed on the way (Qdrant's checksum %s, read %s)", snap.Checksum, got)
	}
	if snap.Size > 0 && n != snap.Size {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("the snapshot was cut short (%d of %d bytes)", n, snap.Size)
	}
	doc.SnapshotBytes, doc.StoredBytes, doc.Checksum = n, stored, got
	if len(cfg.Aliases) > 0 || doc.Aliases == nil {
		doc.Aliases = cfg.Aliases
	}
	// Point counts as of the snapshot: read before and just after it (the
	// snapshot was taken between), Proof allows for writes of that moment.
	after := map[string]int64{}
	for _, ci := range in.Collections {
		if n, err := c.exactCount(ctx, ci.Name); err == nil {
			after[ci.Name] = n
		}
	}
	for _, ci := range in.Collections {
		if _, ok := cfg.Collections[ci.Name]; !ok {
			continue // created and removed around the snapshot
		}
		d := collDoc{Name: ci.Name, Points: ci.Points, Status: ci.Status, Sparse: ci.Sparse, Snapshot: cfg.Collections[ci.Name]}
		if a, ok := after[ci.Name]; ok && a != ci.Points {
			d.Points = (a + ci.Points) / 2
		}
		for _, v := range ci.Vectors {
			d.Vectors = append(d.Vectors, v.Name)
		}
		doc.Collections = append(doc.Collections, d)
	}
	for name, file := range cfg.Collections {
		if !hasColl(doc.Collections, name) {
			doc.Collections = append(doc.Collections, collDoc{Name: name, Points: -1, Snapshot: file})
		}
	}
	doc.StoppedAt = time.Now().UTC()
	if err := r.putJSON(ctx, prefix+backupDocName, doc); err != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("saving the backup's description: %w", err)
	}
	return doc, nil
}

func hasColl(cs []collDoc, name string) bool {
	for _, c := range cs {
		if c.Name == name {
			return true
		}
	}
	return false
}

type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

type countReader struct {
	r io.Reader
	n *int64
}

func (c *countReader) Read(p []byte) (int, error) {
	k, err := c.r.Read(p)
	*c.n += int64(k)
	return k, err
}

func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	if p.Type != "" && p.Type != protocol.BackupFull {
		tl.Printf("Qdrant backups are always full snapshots; taking one instead of a %s backup", p.Type)
	}
	doc, err := e.takeBackup(ctx, env, db, sourceScheduled, "", tl)
	if err != nil {
		return nil, err
	}
	res := backupResult(doc)
	if r, err := openRepo(env, db); err == nil {
		if docs, _, err := r.listBackups(ctx); err == nil {
			res.Kept = []string{}
			for _, d := range docs {
				res.Kept = append(res.Kept, d.Label)
			}
		}
	}
	return res, nil
}

func backupResult(d backupDoc) *protocol.BackupResult {
	return &protocol.BackupResult{Label: d.Label, Type: protocol.BackupFull, StartedAt: d.StartedAt, StoppedAt: d.StoppedAt,
		SizeBytes: max(d.DataBytes, d.SnapshotBytes), RepoSizeBytes: d.StoredBytes}
}

// takeBackup takes a new backup (for the schedule or a Mark) and applies
// the retention.
func (e *Engine) takeBackup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, source, mark string, tl agent.TaskLogger) (backupDoc, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return backupDoc{}, err
	}
	defer c.Close()
	in, err := inspect(ctx, c, false)
	if err != nil {
		return backupDoc{}, err
	}
	if why := in.supported(); why != "" {
		return backupDoc{}, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return backupDoc{}, err
	}
	if err := r.ensureMarker(ctx, db.Name); err != nil {
		return backupDoc{}, err
	}
	e.cleanPending(ctx, c, tl)
	l := e.dbLock(db.ID)
	l.Lock()
	defer l.Unlock()
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return backupDoc{}, fmt.Errorf("reading your bucket: %w", err)
	}
	var prev *backupDoc
	if len(docs) > 0 {
		prev = &docs[len(docs)-1]
	}
	e.opsWatch(ctx, env, db, c) // fullnext.go: operation numbers that went back since last seen
	why := e.fullNext(env, db.ID)
	if why != "" {
		tl.Printf("every collection is taken again: %s", why)
	}
	doc, err := e.storeCollections(ctx, c, r, in, prev, why != "", source, mark, tl)
	if err != nil {
		return doc, err
	}
	if why != "" && e.fullNext(env, db.ID) == why {
		e.setFullNext(env, db.ID, "")
	}
	tl.Printf("backup %s complete: %d collections, %s points, %s stored (encrypted on this server)",
		doc.Label, doc.userCollections(), commas(doc.totalPoints()), humanBytes(doc.StoredBytes))
	if err := retention(ctx, r, db, doc.Label, time.Now(), tl); err != nil {
		tl.Printf("note: removing old backups failed (%v); it is tried again after the next backup", err)
	}
	return doc, nil
}

// Retention: the newest RetentionFull backups (defaultRetention when the
// control plane doesn't say), plus the newest backup of each hour of the
// last hourlyFor and of each of the last dailyDays days, so the backups
// reach back a week while the latest hours have one every few minutes.
// Marks' backups stay while they are newer than the oldest backup kept, and
// go with their Mark after that. A collection's snapshot stays while a kept
// backup names it (gcData).
const (
	defaultRetention = 24
	hourlyFor        = 24 * time.Hour
	dailyDays        = 7
)

// keepSet decides which snapshots stay (docs oldest first).
func keepSet(docs []backupDoc, keepN int, now time.Time) map[string]bool {
	keep := map[string]bool{}
	var plain []backupDoc
	for _, d := range docs {
		if d.Source != sourceMark {
			plain = append(plain, d)
		}
	}
	for i := len(plain) - 1; i >= 0 && len(plain)-i <= keepN; i-- {
		keep[plain[i].Label] = true
	}
	days, hours := map[string]bool{}, map[string]bool{}
	for i := len(plain) - 1; i >= 0; i-- {
		d := plain[i]
		age := now.Sub(d.TakenAt)
		if age > dailyDays*24*time.Hour {
			break
		}
		if day := d.TakenAt.UTC().Format("2006-01-02"); !days[day] {
			days[day] = true
			keep[d.Label] = true
		}
		if hour := d.TakenAt.UTC().Format("2006-01-02T15"); age <= hourlyFor && !hours[hour] {
			hours[hour] = true
			keep[d.Label] = true
		}
	}
	oldest := time.Time{}
	for _, d := range plain {
		if keep[d.Label] {
			oldest = d.TakenAt
			break
		}
	}
	for _, d := range docs {
		if d.Source == sourceMark && (oldest.IsZero() || !d.TakenAt.Before(oldest)) {
			keep[d.Label] = true
		}
	}
	return keep
}

func retention(ctx context.Context, r *repo, db protocol.DatabaseSpec, current string, now time.Time, tl agent.TaskLogger) error {
	keepN := db.RetentionFull
	if keepN <= 0 {
		keepN = defaultRetention
	}
	docs, unfinished, err := r.listBackups(ctx)
	if err != nil {
		return err
	}
	for _, l := range unfinished {
		if t, err := time.Parse("20060102-150405", strings.TrimSuffix(l, "F")); err == nil && l != current && now.Sub(t) > 24*time.Hour {
			if err := r.deletePrefix(ctx, backupPrefix+l+"/"); err != nil {
				return err
			}
		}
	}
	keep := keepSet(docs, keepN, now)
	keep[current] = true
	gone := map[string]bool{}
	for _, d := range docs {
		if !keep[d.Label] {
			if err := r.deletePrefix(ctx, backupPrefix+d.Label+"/"); err != nil {
				return err
			}
			gone[d.Label] = true
		}
	}
	kept := slices.DeleteFunc(slices.Clone(docs), func(d backupDoc) bool { return gone[d.Label] })
	freed, err := gcData(ctx, r, kept, current)
	if err != nil {
		return err
	}
	if len(gone) == 0 {
		if freed > 0 {
			tl.Printf("removed %d collection snapshots no backup names any more", freed)
		}
		return nil
	}
	marks, err := r.marks(ctx)
	if err != nil {
		return err
	}
	dropped := 0
	for name, label := range marks {
		if gone[label] {
			if err := r.st.Delete(ctx, markKey(name)); err != nil {
				return err
			}
			dropped++
		}
	}
	tl.Printf("kept the newest %d backups, one an hour for a day and one a day for %d days: removed %d older backups (%d collection snapshots no backup names any more) and %d Marks",
		keepN, dailyDays, len(gone), freed, dropped)
	return nil
}
