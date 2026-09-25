package mongodb

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// tailBuffer keeps the last max bytes written to it (a command's stderr).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if t.max == 0 {
		t.max = 16 << 10
	}
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.buf)
}

// command builds a command at low CPU and IO priority (env.LowPriority).
func command(ctx context.Context, env agent.EngineEnv, low bool, name string, args ...string) *exec.Cmd {
	if low && len(env.LowPriority) > 0 {
		full := append(append(append([]string{}, env.LowPriority[1:]...), name), args...)
		return exec.CommandContext(ctx, env.LowPriority[0], full...)
	}
	return exec.CommandContext(ctx, name, args...)
}

func (e *Engine) backup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.BackupParams, tl agent.TaskLogger) (*protocol.BackupResult, error) {
	if p.Type != "" && p.Type != protocol.BackupFull {
		tl.Printf("MongoDB backups are always full (mongodump); taking a full backup instead of %s", p.Type)
	}
	if err := checkTools(env); err != nil {
		return nil, err
	}
	dump, _ := tool("mongodump")
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if in.SetName == "" {
		return nil, ErrStandalone
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	s, err := e.shipperFor(env, db)
	if err != nil {
		return nil, err
	}
	l, err := loadLogin(env, db.Port)
	if err != nil {
		return nil, err
	}

	started := time.Now().UTC()
	label := newLabel(started)
	start, err := latestOpTime(ctx, c)
	if err != nil {
		return nil, err
	}
	tmp := filepath.Join(env.StateDir, db.Stanza, "tmp-"+label)
	defer os.RemoveAll(tmp)
	cfg, err := toolConfig(tmp, l.uri(db.Port))
	if err != nil {
		return nil, err
	}
	tl.Printf("starting a full backup of %s (%d databases): mongodump, compressed and encrypted on this server, straight to your bucket",
		humanBytes(in.TotalBytes), len(in.Databases))
	cmd := command(ctx, env, true, dump, "--config="+cfg, "--oplog", "--archive", "--gzip", "--quiet")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr tailBuffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting mongodump: %w", err)
	}
	stored, upErr := r.putSealed(ctx, backupKey(label, archiveName), stdout)
	waitErr := cmd.Wait()
	tl.Output("mongodump", stderr.Bytes())
	if upErr != nil || waitErr != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), label)
		if waitErr != nil {
			return nil, fmt.Errorf("mongodump failed: %v: %s", waitErr, lastLine(stderr.Bytes()))
		}
		return nil, fmt.Errorf("uploading the backup: %w", upErr)
	}
	end, err := latestOpTime(ctx, c)
	if err != nil {
		return nil, err
	}
	stopped := time.Now().UTC()
	// The changes made during the dump must reach the bucket too, so the
	// backup can be restored (and carried forward) right away.
	if err := s.flush(ctx, fromBSON(end), 3*time.Minute); err != nil {
		tl.Printf("note: the newest changes haven't reached your bucket yet (%v); the backup is usable once they do", err)
	}
	doc := backupDoc{Label: label, StartTS: fromBSON(start), EndTS: fromBSON(end), StartedAt: started, StoppedAt: stopped,
		DataBytes: in.TotalBytes, ArchiveBytes: stored, Version: in.Version, SetName: in.SetName, Databases: in.Databases}
	if err := r.putJSON(ctx, backupKey(label, backupDocName), doc); err != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), label)
		return nil, fmt.Errorf("saving the backup's description: %w", err)
	}
	tl.Printf("backup %s complete: %s of data, %s stored (compressed and encrypted)", label, humanBytes(in.TotalBytes), humanBytes(stored))
	if err := e.retention(ctx, r, db, label, tl); err != nil {
		tl.Printf("note: removing old backups failed (%v); it is tried again after the next backup", err)
	}
	return &protocol.BackupResult{Label: label, Type: protocol.BackupFull, StartedAt: started, StoppedAt: stopped,
		SizeBytes: in.TotalBytes, RepoSizeBytes: stored, WALStart: doc.StartTS.String(), WALStop: doc.EndTS.String()}, nil
}

// retention keeps the newest RetentionFull backups and the oplog chunks
// they need, and removes unfinished uploads older than a day.
func (e *Engine) retention(ctx context.Context, r *repo, db protocol.DatabaseSpec, current string, tl agent.TaskLogger) error {
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
	old := docs[:len(docs)-keep]
	for _, d := range old {
		if err := r.deleteBackup(ctx, d.Label); err != nil {
			return err
		}
	}
	oldest := docs[len(docs)-keep].StartTS
	chunks, err := r.listChunks(ctx)
	if err != nil {
		return err
	}
	removed := 0
	for _, c := range chunks {
		// A chunk whose entries all precede the oldest backup kept.
		if !c.Last.After(oldest) {
			if err := r.st.Delete(ctx, c.Key); err != nil {
				return err
			}
			removed++
		}
	}
	tl.Printf("kept the newest %d full backups: removed %d older backups and %d chunks of changes only they needed", keep, len(old), removed)
	return nil
}

func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return firstLine(lines[len(lines)-1])
}
