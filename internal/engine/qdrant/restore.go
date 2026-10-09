package qdrant

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// restoreTarget is what a restore goes back to.
type restoreTarget struct {
	Latest bool
	Time   time.Time
	Mark   string
	Label  string // BackupSet
	Kept   string // a rewind's kept data: kept/<id>/ (After: kept/<id>/after/)
	After  bool
}

func targetFrom(t protocol.RewindTarget) (restoreTarget, error) {
	var rt restoreTarget
	switch {
	case t.Mark != "":
		if !markNameRE.MatchString(t.Mark) {
			return rt, fmt.Errorf("invalid Mark name %q", t.Mark)
		}
		rt.Mark = t.Mark
	case t.Time != nil:
		rt.Time = t.Time.UTC()
	default:
		return rt, errors.New("say what to restore: a moment or a Mark")
	}
	if t.BackupSet != "" {
		if !labelRE.MatchString(t.BackupSet) {
			return rt, fmt.Errorf("invalid backup %q", t.BackupSet)
		}
		rt.Label = t.BackupSet
	}
	if t.XID != 0 {
		return rt, errors.New("Qdrant has no transactions to stop before; restore a moment or a Mark")
	}
	return rt, nil
}

func (t restoreTarget) describe() string {
	switch {
	case t.Mark != "":
		return "Mark " + t.Mark
	case t.Kept != "":
		return "the data kept by the rewind"
	case !t.Time.IsZero():
		return t.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return "the newest backup"
}

// pick finds the snapshot a target restores: its prefix in the bucket and
// its description.
func pick(ctx context.Context, r *repo, t restoreTarget) (string, backupDoc, error) {
	if t.Kept != "" {
		prefix := keptPrefix + t.Kept + "/"
		if t.After {
			prefix += "after/"
		}
		var d backupDoc
		if err := r.getJSON(ctx, prefix+backupDocName, &d); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return "", d, errors.New("the data kept by this rewind is no longer in your bucket")
			}
			return "", d, err
		}
		return prefix, d, nil
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return "", backupDoc{}, err
	}
	if len(docs) == 0 {
		return "", backupDoc{}, errors.New("there is no backup to restore yet")
	}
	label := t.Label
	if t.Mark != "" && label == "" {
		var m markDoc
		if err := r.getJSON(ctx, markKey(t.Mark), &m); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return "", backupDoc{}, fmt.Errorf("Mark %s isn't in your bucket (it went with its backup when that was removed)", t.Mark)
			}
			return "", backupDoc{}, err
		}
		label = m.Label
	}
	if label != "" {
		for _, d := range docs {
			if d.Label == label {
				return backupPrefix + d.Label + "/", d, nil
			}
		}
		return "", backupDoc{}, fmt.Errorf("backup %s isn't in your bucket any more", label)
	}
	if t.Latest || t.Time.IsZero() {
		d := docs[len(docs)-1]
		return backupPrefix + d.Label + "/", d, nil
	}
	var best *backupDoc
	for i := range docs {
		if !docs[i].TakenAt.After(t.Time) {
			best = &docs[i]
		}
	}
	if best == nil {
		return "", backupDoc{}, fmt.Errorf("the oldest backup is from %s, after %s: Qdrant backups are snapshots, so there is nothing to restore from before it",
			docs[0].TakenAt.UTC().Format("2006-01-02 15:04 UTC"), t.Time.UTC().Format("2006-01-02 15:04 UTC"))
	}
	return backupPrefix + best.Label + "/", *best, nil
}

// downloadSnapshot decrypts the snapshot under prefix into path.
func downloadSnapshot(ctx context.Context, r *repo, prefix, path string) (int64, error) {
	pr, closer, err := r.getSealed(ctx, prefix+snapshotName)
	if err != nil {
		return 0, fmt.Errorf("downloading the snapshot: %w", err)
	}
	defer closer.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, pr)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return n, fmt.Errorf("downloading the snapshot: %w", err)
	}
	return n, nil
}

// restoreOut is what restoreInto restored.
type restoreOut struct {
	Doc    backupDoc
	Prefix string
	Bytes  int64
}

// restoreInto downloads the target's snapshot into scratch s and starts a
// temporary Qdrant on it.
func restoreInto(ctx context.Context, env agent.EngineEnv, r *repo, t restoreTarget, s *scratch, tl agent.TaskLogger) (restoreOut, *client, error) {
	var out restoreOut
	prefix, doc, err := pick(ctx, r, t)
	if err != nil {
		return out, nil, err
	}
	out.Doc, out.Prefix = doc, prefix
	bin, err := serverBinary()
	if err != nil {
		return out, nil, err
	}
	ver, err := checkBinary(bin, doc.VersionNum)
	if err != nil {
		return out, nil, err
	}
	need := doc.SnapshotBytes*2 + 256<<20
	if err := ensureSpace(s.Dir, need, "restoring the snapshot"); err != nil {
		return out, nil, err
	}
	tl.Printf("downloading backup %s (taken %s, %s) and decrypting it on this server", doc.Label,
		doc.TakenAt.UTC().Format("2006-01-02 15:04:05 UTC"), humanBytes(doc.SnapshotBytes))
	if out.Bytes, err = downloadSnapshot(ctx, r, prefix, s.snapshotFile()); err != nil {
		return out, nil, err
	}
	port, err := freePort()
	if err != nil {
		return out, nil, err
	}
	key, err := randomKey()
	if err != nil {
		return out, nil, err
	}
	tl.Printf("starting a private Qdrant %s on the snapshot (127.0.0.1 only, its own key)", versionText(ver))
	c, err := s.start(ctx, env, scratchState{Bin: bin, HTTPPort: port, Key: key, Version: ver})
	if err != nil {
		return out, nil, err
	}
	return out, c, nil
}
