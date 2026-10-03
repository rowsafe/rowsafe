package redis

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// reuseWithin: a snapshot the replication link received this recently is
// the backup a task asks for (the server isn't asked to fork twice).
const reuseWithin = 10 * time.Minute

func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	if p.Type != "" && p.Type != protocol.BackupFull {
		tl.Printf("%s backups are always whole snapshots; taking one instead of a %s backup", e.display(), p.Type)
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	c.Close()
	if err != nil {
		return nil, err
	}
	if why := in.supported(e.name); why != "" {
		return nil, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	if docs, _, err := r.listBackups(ctx); err == nil && len(docs) > 0 {
		last := docs[len(docs)-1]
		if last.Source == sourceAutomatic && time.Since(last.TakenAt) < reuseWithin {
			tl.Printf("the replication link received a whole snapshot %s ago (backup %s): that is this backup",
				time.Since(last.TakenAt).Round(time.Second), last.Label)
			return backupResult(last, in), nil
		}
	}
	var doc backupDoc
	if f := e.existingFollower(strings.TrimSuffix(db.ID, "~copy2")); f != nil && f.snapshot().Mode == modeSnapshots {
		tl.Printf("Rowsafe can't follow this server's changes (%s): taking a snapshot with BGSAVE instead", f.snapshot().Problem)
		doc, err = e.snapshotFromFile(ctx, env, db, r, in, backupPrefix, tl)
	} else {
		doc, err = e.snapshotOverReplication(ctx, env, db, r, in, sourceScheduled, backupPrefix, tl)
		if errors.Is(err, errReplicationRefused) {
			tl.Printf("the server refused to send its snapshot over the replication handshake: taking one with BGSAVE instead")
			doc, err = e.snapshotFromFile(ctx, env, db, r, in, backupPrefix, tl)
		}
	}
	if err != nil {
		return nil, err
	}
	tl.Printf("backup %s complete: %s snapshot, %s stored (compressed by %s, encrypted on this server)",
		doc.Label, humanBytes(doc.RDBBytes), humanBytes(doc.StoredBytes), e.display())
	if err := retention(ctx, r, db, doc.Label, tl); err != nil {
		tl.Printf("note: removing old backups failed (%v); it is tried again after the next backup", err)
	}
	return backupResult(doc, in), nil
}

func backupResult(d backupDoc, in serverInfo) *protocol.BackupResult {
	return &protocol.BackupResult{Label: d.Label, Type: protocol.BackupFull, StartedAt: d.StartedAt, StoppedAt: d.StoppedAt,
		SizeBytes: max(d.UsedMemoryDataset, in.UsedMemoryDataset), RepoSizeBytes: d.StoredBytes, WALStart: d.position(), WALStop: d.position()}
}

// snapshotOverReplication asks the server for a whole snapshot over the
// replication handshake (rdb-only: nothing follows it) and stores it under
// prefix (backup/<label>/ or kept/<id>/). It goes through a local file when
// there is room (the server's fork lives shorter), else straight to the
// bucket.
func (e *Engine) snapshotOverReplication(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r *repo, in serverInfo,
	source, prefix string, tl agent.TaskLogger) (backupDoc, error) {
	started := time.Now().UTC()
	doc := backupDoc{Source: source, Engine: e.name, Version: in.Version, VersionNum: in.VersionNum, Exact: true,
		StartedAt: started, UsedMemoryDataset: in.UsedMemoryDataset, Databases: in.Databases, Modules: in.Modules}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return doc, err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	tl.Printf("asking %s for a snapshot (%s of data), the way a new replica gets one: it streams it from memory, nothing is written to its disk",
		e.display(), humanBytes(in.UsedMemoryDataset))
	reply, err := startSync(ctx, c, "", 0, true)
	if err != nil {
		return doc, err
	}
	if !reply.Full {
		return doc, errors.New("the server answered a snapshot request without a snapshot")
	}
	doc.ReplID, doc.Offset, doc.TakenAt = reply.ReplID, reply.Offset, time.Now().UTC()
	doc.Keyspace = keyspaceNow(ctx, env, db)

	if prefix == backupPrefix {
		if doc.Label, err = r.freshLabel(ctx, doc.TakenAt); err != nil {
			return doc, err
		}
		prefix = backupPrefix + doc.Label + "/"
	} else {
		doc.Label = strings.TrimSuffix(strings.TrimPrefix(prefix, keptPrefix), "/")
	}
	tmpDir := filepath.Join(env.StateDir, db.Stanza, "tmp")
	local := ensureSpace(tmpDir, in.UsedMemoryDataset+diskReserve, "the snapshot") == nil
	var stored int64
	if local {
		if err := os.MkdirAll(tmpDir, 0o700); err != nil {
			return doc, err
		}
		path := filepath.Join(tmpDir, "snapshot-"+started.Format("20060102T150405.000")+".rdb")
		defer os.Remove(path)
		fh, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return doc, err
		}
		free, _ := freeBytes(tmpDir)
		n, err := receiveRDB(ctx, c, fh, max(free-diskReserve, 0), 5*time.Minute)
		if err != nil {
			fh.Close()
			return doc, fmt.Errorf("receiving the snapshot: %w", err)
		}
		c.Close()
		doc.RDBBytes = n
		tl.Printf("received the snapshot (%s); uploading it, encrypted", humanBytes(n))
		if _, err := fh.Seek(0, io.SeekStart); err != nil {
			fh.Close()
			return doc, err
		}
		stored, err = r.putSealed(ctx, prefix+rdbName, fh)
		fh.Close()
		if err != nil {
			_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
			return doc, fmt.Errorf("uploading the snapshot: %w", err)
		}
	} else {
		tl.Printf("not enough room on this server's disk to hold the snapshot: sending it straight to your bucket (slower for the server)")
		pr, pw := io.Pipe()
		got := make(chan int64, 1)
		go func() {
			n, err := receiveRDB(ctx, c, pw, 1<<62, 5*time.Minute)
			got <- n
			pw.CloseWithError(err)
		}()
		stored, err = r.putSealed(ctx, prefix+rdbName, pr)
		pr.CloseWithError(errors.New("upload stopped"))
		c.Close()
		n := <-got
		if err != nil {
			_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
			return doc, fmt.Errorf("receiving and uploading the snapshot: %w", err)
		}
		doc.RDBBytes = n
	}
	doc.StoredBytes, doc.StoppedAt = stored, time.Now().UTC()
	if err := r.putJSON(ctx, prefix+backupDocName, doc); err != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("saving the backup's description: %w", err)
	}
	return doc, nil
}

// dataDirEnv maps the server's data folder for a sidecar (where the data
// volume is mounted, read only, in the agent's container).
const dataDirEnv = "ROWSAFE_REDIS_DATA_DIR"

// snapshotFromFile takes a snapshot with BGSAVE and uploads the server's own
// file (snapshot mode: the server won't send it over replication).
func (e *Engine) snapshotFromFile(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r *repo, in serverInfo, prefix string, tl agent.TaskLogger) (backupDoc, error) {
	started := time.Now().UTC()
	doc := backupDoc{Source: sourceFile, Engine: e.name, Version: in.Version, VersionNum: in.VersionNum,
		StartedAt: started, UsedMemoryDataset: in.UsedMemoryDataset, Databases: in.Databases, Modules: in.Modules,
		Note: "Taken with BGSAVE from the server's own file: restores go back to this snapshot, not to any second."}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return doc, err
	}
	defer c.Close()
	dir := cmpOr(strings.TrimSpace(os.Getenv(dataDirEnv)), in.Dir)
	if dir == "" || in.DBFilename == "" {
		return doc, errors.New("Rowsafe can't tell where the server keeps its snapshot file (its user can't read the dir and dbfilename settings): run the Rowsafe installer on the server again")
	}
	path := filepath.Join(dir, in.DBFilename)
	if err := waitBgsave(ctx, c, 0); err != nil {
		return doc, err
	}
	before, err := c.integer(ctx, "LASTSAVE")
	if err != nil {
		return doc, fmt.Errorf("LASTSAVE: %w", err)
	}
	doc.Keyspace = keyspaceNow(ctx, env, db)
	if _, err := c.do(ctx, "BGSAVE"); err != nil && !strings.Contains(err.Error(), "in progress") {
		return doc, fmt.Errorf("BGSAVE: %w", err)
	}
	tl.Printf("%s is writing a snapshot to its own disk (BGSAVE)", e.display())
	if err := waitBgsave(ctx, c, before); err != nil {
		return doc, err
	}
	m, err := c.info(ctx, "persistence")
	if err != nil {
		return doc, err
	}
	if m["rdb_last_bgsave_status"] != "ok" {
		return doc, fmt.Errorf("%s couldn't write its snapshot (BGSAVE failed: see its log)", e.display())
	}
	doc.TakenAt = time.Unix(m.int("rdb_last_save_time"), 0).UTC()
	fh, err := os.Open(path)
	if err != nil {
		return doc, fmt.Errorf("Rowsafe can't read the server's snapshot file %s (%v): the installer gives Rowsafe's user read access to it; "+
			"in Docker, mount the server's data volume into the agent's container, read only", path, errorsTail(err))
	}
	defer fh.Close()
	if st, err := fh.Stat(); err == nil {
		doc.RDBBytes = st.Size()
	}
	if prefix == backupPrefix {
		if doc.Label, err = r.freshLabel(ctx, doc.TakenAt); err != nil {
			return doc, err
		}
		prefix = backupPrefix + doc.Label + "/"
	} else {
		doc.Label = strings.TrimSuffix(strings.TrimPrefix(prefix, keptPrefix), "/")
	}
	stored, err := r.putSealed(ctx, prefix+rdbName, fh)
	if err != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, fmt.Errorf("uploading the snapshot: %w", err)
	}
	doc.StoredBytes, doc.StoppedAt = stored, time.Now().UTC()
	if err := r.putJSON(ctx, prefix+backupDocName, doc); err != nil {
		_ = r.deletePrefix(context.WithoutCancel(ctx), prefix)
		return doc, err
	}
	return doc, nil
}

func errorsTail(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// waitBgsave waits until no BGSAVE runs (and, with after > 0, until the
// last save is newer than after).
func waitBgsave(ctx context.Context, c *conn, after int64) error {
	deadline := time.Now().Add(6 * time.Hour)
	for {
		m, err := c.info(ctx, "persistence")
		if err != nil {
			return err
		}
		if m["rdb_bgsave_in_progress"] != "1" && (after == 0 || m.int("rdb_last_save_time") > after || m["rdb_last_bgsave_status"] != "ok") {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("the server's snapshot took longer than 6 hours")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// retention keeps the newest RetentionFull snapshots and the stream they
// need, and removes unfinished uploads older than a day. tl may be nil.
func retention(ctx context.Context, r *repo, db protocol.DatabaseSpec, current string, tl agent.TaskLogger) error {
	keep := max(db.RetentionFull, 1)
	docs, unfinished, err := r.listBackups(ctx)
	if err != nil {
		return err
	}
	for _, l := range unfinished {
		if l == current {
			continue
		}
		if t, err := time.Parse("20060102-150405", strings.TrimSuffix(l, "F")); err == nil && time.Since(t) > 24*time.Hour {
			if err := r.deleteBackup(ctx, l); err != nil {
				return err
			}
		}
	}
	if len(docs) <= keep {
		return nil
	}
	old, kept := docs[:len(docs)-keep], docs[len(docs)-keep:]
	for _, d := range old {
		if err := r.deleteBackup(ctx, d.Label); err != nil {
			return err
		}
	}
	// A segment is needed when a kept snapshot's stream reaches it: same id
	// and ending after the snapshot, or newer than the oldest kept one.
	oldest := kept[0].TakenAt
	segs, err := r.listSegments(ctx)
	if err != nil {
		return err
	}
	removed := 0
	for _, s := range segs {
		needed := s.To.After(oldest)
		for _, d := range kept {
			if d.Exact && d.ReplID == s.ReplID && s.End > d.Offset {
				needed = true
			}
		}
		if !needed {
			if err := r.st.Delete(ctx, s.Key); err != nil {
				return err
			}
			removed++
		}
	}
	if tl != nil {
		tl.Printf("kept the newest %d backups: removed %d older ones and %d pieces of the stream of changes only they needed", keep, len(old), removed)
	}
	return nil
}
