package sqlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
)

// Restores: the newest full copy at or before the target, then every
// transaction of its generation after the copy's position, in order, up to
// the target (applied as SQLite's checkpoint does: each page written to its
// place, the file cut to the commit's size). Every step is checked: the
// segments must follow each other without a gap, each transaction must
// start right after the previous one, the frames' page size must match.
// Nothing is written next to production: the result is a new file.

// restoreTarget is where to go: a moment, a Mark, or the newest point.
type restoreTarget struct {
	Time   time.Time
	Mark   string
	Latest bool
	// BaseBefore, with Time, starts from the newest full copy at or before
	// it instead of before Time (Find the moment replays the range).
	BaseBefore time.Time
}

func (t restoreTarget) describe() string {
	switch {
	case t.Mark != "":
		return "the Mark " + t.Mark
	case t.Latest:
		return "the newest point in your bucket"
	}
	return t.Time.UTC().Format("2006-01-02 15:04:05 UTC")
}

// restoreOut is what a restore reached.
type restoreOut struct {
	Snapshot    snapDoc
	RecoveredTo time.Time
	Txns        int
	// GapAfter: the stream stops before the target at this moment (a
	// missing segment, or the generation broke and its full copy came
	// later).
	GapAfter *time.Time
	Note     string
}

// pickSnapshot chooses the full copy a restore starts from.
func pickSnapshot(ctx context.Context, r *repo, t restoreTarget) (snapDoc, *markDoc, error) {
	snaps, _, err := r.listSnapshots(ctx)
	if err != nil {
		return snapDoc{}, nil, err
	}
	if len(snaps) == 0 {
		return snapDoc{}, nil, errors.New("there is no finished backup of this database in your bucket yet")
	}
	sortSnaps(snaps)
	switch {
	case t.Mark != "":
		if !markNameRE.MatchString(t.Mark) {
			return snapDoc{}, nil, fmt.Errorf("invalid Mark name %q", t.Mark)
		}
		var md markDoc
		if err := r.getJSON(ctx, markKey(t.Mark), &md); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return snapDoc{}, nil, fmt.Errorf("the Mark %s isn't in your bucket", t.Mark)
			}
			return snapDoc{}, nil, err
		}
		var best *snapDoc
		for i := range snaps {
			s := snaps[i]
			if s.Gen == md.Gen && s.Pos.Compare(md.Pos) <= 0 && (best == nil || s.Pos.Compare(best.Pos) > 0) {
				best = &snaps[i]
			}
		}
		if best == nil {
			return snapDoc{}, nil, fmt.Errorf("the Mark %s is older than the backups Rowsafe still keeps, so it can't be restored any more", t.Mark)
		}
		return *best, &md, nil
	case t.Latest:
		return snaps[len(snaps)-1], nil, nil
	}
	at := t.Time
	if !t.BaseBefore.IsZero() && t.BaseBefore.Before(at) {
		at = t.BaseBefore
	}
	var best *snapDoc
	for i := range snaps {
		if !snaps[i].At.After(at) {
			best = &snaps[i]
		}
	}
	if best == nil {
		return snapDoc{}, nil, fmt.Errorf("the earliest moment Rowsafe can restore is %s (older backups are no longer kept); pick a later time",
			snaps[0].At.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	return *best, nil, nil
}

// restoreTo restores t into a new file at dst (replaced if it exists).
func restoreTo(ctx context.Context, r *repo, t restoreTarget, dst string, tl agent.TaskLogger) (restoreOut, error) {
	return restoreWith(ctx, r, t, dst, tl, nil)
}

// replayHook watches a restore's replay, transaction by transaction
// (Find the moment).
type replayHook interface {
	// beforeApply runs before a piece of a transaction (frames) is written
	// into f; commit is the transaction's size in pages after it when this
	// piece ends it (0 otherwise).
	beforeApply(f *os.File, pageSize int, frames []byte, at time.Time, commit uint32) error
	// committed runs once a transaction committed at `at` is in f; end is
	// its position in the generation's stream.
	committed(f *os.File, at time.Time, gen string, end pos) error
}

// restoreWith is restoreTo with a hook on the replay (nil: none).
func restoreWith(ctx context.Context, r *repo, t restoreTarget, dst string, tl agent.TaskLogger, hook replayHook) (restoreOut, error) {
	base, md, err := pickSnapshot(ctx, r, t)
	out := restoreOut{Snapshot: base, RecoveredTo: base.At}
	if err != nil {
		return out, err
	}
	if err := ensureSpace(filepath.Dir(dst), base.SizeBytes, "the restored database"); err != nil {
		return out, err
	}
	part := dst + ".part"
	removeDB(part)
	f, err := os.OpenFile(part, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return out, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(part)
		}
	}()
	tl.Printf("downloading the backup %s (%s, as of %s)", base.Label, humanBytes(base.SizeBytes), base.At.UTC().Format(time.RFC3339))
	rc, err := r.getCompressed(ctx, snapKey(base.Label, snapDataName))
	if err != nil {
		return out, fmt.Errorf("downloading the backup %s: %w", base.Label, err)
	}
	n, err := io.Copy(f, rc)
	rc.Close()
	if err != nil {
		return out, fmt.Errorf("downloading the backup %s: %w", base.Label, err)
	}
	if n != base.SizeBytes {
		return out, fmt.Errorf("the backup %s is %d bytes, its description says %d", base.Label, n, base.SizeBytes)
	}
	if base.Gen != "" {
		if err := replay(ctx, r, f, base, t, md, &out, tl, hook); err != nil {
			return out, err
		}
	} else if !t.Latest && t.Mark == "" && t.Time.After(base.At) {
		out.Note = "This database was in rollback-journal mode, so it is restored as of its backup, not to the second."
	}
	if err := f.Sync(); err != nil {
		return out, err
	}
	if err := f.Close(); err != nil {
		return out, err
	}
	removeDB(dst)
	if err := os.Rename(part, dst); err != nil {
		return out, err
	}
	ok = true
	return out, nil
}

// replay applies the generation's transactions after base's position.
func replay(ctx context.Context, r *repo, f *os.File, base snapDoc, t restoreTarget, md *markDoc, out *restoreOut, tl agent.TaskLogger, hook replayHook) error {
	segs, err := r.listSegments(ctx, base.Gen)
	if err != nil {
		return err
	}
	cur := base.Pos
	lastSeq := int64(0)
	stop := false
	stopReason := ""
	var lastAt time.Time
	for _, sg := range segs {
		if stop {
			break
		}
		if (pos{W: sg.W, Frame: sg.Last}).Compare(cur) <= 0 {
			continue // all before the copy
		}
		if !t.Latest && t.Mark == "" && sg.T0.After(t.Time) {
			break
		}
		if md != nil && (pos{W: sg.W, Frame: sg.First}).Compare(md.Pos) > 0 {
			break
		}
		if lastSeq != 0 && sg.Seq != lastSeq+1 {
			stopReason = fmt.Sprintf("a segment of changes is missing after %s", lastAt.UTC().Format(time.RFC3339))
			break
		}
		if lastSeq == 0 && !(sg.W == cur.W && sg.First <= cur.Frame+1) && !(sg.W == cur.W+1 && sg.First == 1) {
			stopReason = "the changes right after the backup are missing from your bucket"
			break
		}
		rc, err := r.getCompressed(ctx, sg.Key)
		if err != nil {
			return fmt.Errorf("downloading changes %s: %w", sg.Key, err)
		}
		started := false
		_, err = readSegment(rc, func(h segHeader, tx segTxn, frames []byte) error {
			if stop {
				return nil
			}
			if h.PageSize != base.PageSize {
				return fmt.Errorf("the changes use %d-byte pages, the backup %d-byte pages", h.PageSize, base.PageSize)
			}
			txEnd := pos{W: h.W, Frame: tx.Last}
			if txEnd.Compare(cur) <= 0 && !started {
				return nil // in the copy already
			}
			if !started || tx.First != cur.Frame+1 || h.W != cur.W {
				// The first piece of a transaction: does it qualify?
				if !t.Latest && t.Mark == "" && time.UnixMilli(tx.At).After(t.Time) {
					stop = true
					return nil
				}
				if md != nil && txEnd.Compare(md.Pos) > 0 {
					stop = true
					return nil
				}
				contiguous := (h.W == cur.W && tx.First == cur.Frame+1) || (h.W == cur.W+1 && tx.First == 1)
				if !contiguous {
					stop, stopReason = true, fmt.Sprintf("the changes jump from %s to %s", lsn(base.Gen, cur), lsn(base.Gen, pos{W: h.W, Frame: tx.First}))
					return nil
				}
				started = true
			}
			if hook != nil {
				if err := hook.beforeApply(f, h.PageSize, frames, time.UnixMilli(tx.At).UTC(), tx.Commit); err != nil {
					return err
				}
			}
			if err := applyFrames(f, h.PageSize, frames, tx.Commit); err != nil {
				return err
			}
			if tx.Commit != 0 {
				cur = txEnd
				lastAt = time.UnixMilli(tx.At).UTC()
				out.Txns++
				started = false
				if hook != nil {
					if err := hook.committed(f, lastAt, base.Gen, cur); err != nil {
						return err
					}
				}
			}
			return nil
		})
		rc.Close()
		if err != nil {
			return fmt.Errorf("applying changes %s: %w", sg.Key, err)
		}
		lastSeq = sg.Seq
	}
	if md != nil && cur.Compare(md.Pos) < 0 {
		return fmt.Errorf("the changes up to the Mark %s aren't all in your bucket (%s)", md.Name, orText(stopReason, "they stop earlier"))
	}
	if !lastAt.IsZero() {
		out.RecoveredTo = lastAt
	}
	if stopReason != "" {
		at := out.RecoveredTo
		out.GapAfter = &at
		out.Note = "Restored up to " + at.UTC().Format("2006-01-02 15:04:05 UTC") + ": " + stopReason + "."
		tl.Printf("note: %s", out.Note)
		return nil
	}
	// The stream may be complete beyond its last transaction (an idle
	// database): say the moment asked for.
	var cv covered
	if err := r.getJSON(ctx, coveredKey(base.Gen), &cv); err == nil && cv.Pos.Compare(cur) <= 0 {
		switch {
		case t.Mark != "":
		case t.Latest && cv.Until.After(out.RecoveredTo):
			out.RecoveredTo = cv.Until
		case !t.Latest && !cv.Until.Before(t.Time) && t.Time.After(out.RecoveredTo):
			out.RecoveredTo = t.Time
		}
	}
	tl.Printf("applied %d transactions: restored as of %s", out.Txns, out.RecoveredTo.UTC().Format(time.RFC3339))
	return nil
}

func orText(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
