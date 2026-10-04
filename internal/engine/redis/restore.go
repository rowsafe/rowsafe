package redis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// restoreTarget is where a restore stops: the newest change in the bucket
// (Latest), a moment (Time: every change that arrived up to the end of that
// second), a Mark, or a snapshot kept by a rewind in place (Kept: that
// snapshot exactly).
type restoreTarget struct {
	Latest bool
	Time   time.Time
	Mark   string
	Kept   string
	// SnapshotOnly restores the snapshot without replaying (Proof's first
	// step).
	SnapshotOnly bool
}

func (t restoreTarget) describe() string {
	switch {
	case t.Mark != "":
		return "Mark " + t.Mark
	case t.Kept != "":
		return "the data from before the rewind"
	case !t.Time.IsZero():
		return t.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return "the newest change in your bucket"
}

func targetFrom(t protocol.RewindTarget) (restoreTarget, error) {
	rt := restoreTarget{Mark: t.Mark}
	if t.Time != nil {
		rt.Time = t.Time.UTC()
	}
	if (rt.Mark == "") == rt.Time.IsZero() {
		return rt, errors.New("pick a moment or a Mark (exactly one)")
	}
	if rt.Mark != "" && !markNameRE.MatchString(rt.Mark) {
		return rt, fmt.Errorf("invalid Mark name %q", rt.Mark)
	}
	return rt, nil
}

// restorePlan is the snapshot and the stream a restore uses.
type restorePlan struct {
	Base     backupDoc
	BaseKey  string // the snapshot's object
	Chain    []segment
	StopAt   int64     // replay commands ending at or before this offset (a Mark); 0: no offset limit
	StopTime time.Time // replay commands that arrived up to this moment; zero: no time limit
	Replay   bool
	GapAfter *time.Time // the stream in the bucket stops at a gap there
}

// plan picks the snapshot and the stream for target.
func plan(ctx context.Context, r *repo, target restoreTarget) (restorePlan, error) {
	var p restorePlan
	if target.Kept != "" {
		if err := r.getJSON(ctx, keptKey(target.Kept, backupDocName), &p.Base); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return p, errors.New("the data kept from before this rewind is no longer in your bucket")
			}
			return p, err
		}
		p.BaseKey = keptKey(target.Kept, rdbName)
		return p, nil
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return p, fmt.Errorf("listing backups: %w", err)
	}
	if len(docs) == 0 {
		return p, errors.New("there is no finished backup in your bucket yet")
	}
	var mark markDoc
	stop := time.Time{}
	switch {
	case target.Mark != "":
		if err := r.getJSON(ctx, markKey(target.Mark), &mark); err != nil {
			if errors.Is(err, objstore.ErrNotFound) {
				return p, fmt.Errorf("the Mark %q isn't in your bucket", target.Mark)
			}
			return p, fmt.Errorf("reading the Mark: %w", err)
		}
	case !target.Time.IsZero():
		stop = target.Time.Truncate(time.Second).Add(time.Second - time.Nanosecond)
	}
	var markSegs []segment
	if target.Mark != "" {
		if markSegs, err = r.listSegments(ctx); err != nil {
			return p, fmt.Errorf("listing the stream of changes: %w", err)
		}
	}
	var base *backupDoc
	for i := len(docs) - 1; i >= 0; i-- {
		d := docs[i]
		switch {
		case target.Latest:
		case target.Mark != "":
			if !markReachable(d, mark, markSegs) {
				continue
			}
		default:
			if d.TakenAt.After(stop) {
				continue
			}
		}
		base = &docs[i]
		break
	}
	if base == nil {
		if target.Mark != "" {
			return p, fmt.Errorf("no backup in your bucket comes before the Mark %q (it is older than the oldest backup kept)", target.Mark)
		}
		return p, fmt.Errorf("the oldest backup in your bucket is from %s: pick a later moment", docs[0].TakenAt.Format(time.RFC3339))
	}
	p.Base, p.BaseKey = *base, backupKey(base.Label, rdbName)
	if target.SnapshotOnly {
		return p, nil
	}
	if !base.Exact {
		// A snapshot from the server's file: nothing to replay after it.
		if target.Mark != "" {
			return p, errors.New("that Mark can't be reached: Rowsafe couldn't follow the server's changes")
		}
		return p, nil
	}
	segs, err := r.listSegments(ctx)
	if err != nil {
		return p, fmt.Errorf("listing the stream of changes: %w", err)
	}
	chain, reach, until, gap := chainFrom(segs, base.ReplID, base.Offset)
	p.Chain, p.Replay = chain, len(chain) > 0
	if gap {
		t := until
		p.GapAfter = &t
	}
	switch {
	case target.Mark != "":
		if reach < mark.Offset {
			return p, fmt.Errorf("can't restore to Mark %s: the changes up to it aren't all in your bucket", target.Mark)
		}
		p.StopAt = mark.Offset
	case !stop.IsZero():
		if until.Before(stop) && !gap && time.Since(stop) < 0 {
			return p, fmt.Errorf("can't restore to %s: that moment hasn't come yet", target.describe())
		}
		if until.Before(target.Time.Truncate(time.Second)) {
			why := "the newest change copied to your bucket arrived at " + until.Format(time.RFC3339) + " (changes arrive about every minute)"
			if until.IsZero() {
				why = "no changes after the backup from " + base.TakenAt.Format(time.RFC3339) + " are in your bucket"
			}
			if gap {
				why = "the changes after " + until.Format(time.RFC3339) + " are missing from your bucket (Rowsafe's link was away longer than the server keeps changes for it); " +
					"the next backup after that moment works"
			}
			return p, fmt.Errorf("can't restore to %s: %s", target.describe(), why)
		}
		p.StopTime = stop
	}
	return p, nil
}

// markReachable: the backup comes before the Mark in the stream, the same
// replication id or one the stream continues into from the backup's. A
// server restarted from its own snapshot answers its replicas' PSYNC with
// a new replication id and the same offsets (Redis 7+), so a Mark saved
// after a restart has another id than the backups before it.
func markReachable(d backupDoc, mark markDoc, segs []segment) bool {
	if !d.Exact || d.Offset > mark.Offset {
		return false
	}
	if d.ReplID == mark.ReplID {
		return true
	}
	chain, reach, _, _ := chainFrom(segs, d.ReplID, d.Offset)
	if reach < mark.Offset {
		return false
	}
	for _, s := range chain {
		if s.ReplID == mark.ReplID {
			return true
		}
	}
	return false
}

// restoreOutcome says what a restore reached.
type restoreOutcome struct {
	Base        backupDoc
	RecoveredTo time.Time // the last change replayed (the snapshot's moment without any)
	Replayed    int64
	Failed      int64
	FirstFail   string
	GapAfter    *time.Time
	Warnings    []string
}

// restoreInto restores target into a new scratch server in s (not started
// yet) and leaves it running; the caller closes the returned connection.
func (e *Engine) restoreInto(ctx context.Context, env agent.EngineEnv, r *repo, target restoreTarget, s *scratch, executable string, tl agent.TaskLogger) (restoreOutcome, *conn, error) {
	var out restoreOutcome
	p, err := plan(ctx, r, target)
	if err != nil {
		return out, nil, err
	}
	out.Base, out.GapAfter, out.RecoveredTo = p.Base, p.GapAfter, p.Base.TakenAt
	b := p.Base
	if err := ensureSpace(s.Dir, 2*b.RDBBytes+256<<20, "the restored data"); err != nil {
		return out, nil, err
	}
	need := max(b.UsedMemoryDataset, 2*b.RDBBytes)*5/4 + 64<<20
	if err := ensureMemory(need, "a temporary "+e.display()+" server with the restored data"); err != nil {
		return out, nil, err
	}
	bin, err := serverBinary(cmpOr(b.Engine, e.name), executable)
	if err != nil {
		return out, nil, err
	}
	if err := checkBinary(bin, cmpOr(b.Engine, e.name), b.VersionNum); err != nil {
		return out, nil, err
	}
	s.Bin = bin
	if target.Kept != "" {
		tl.Printf("downloading the snapshot kept by the rewind (%s, taken %s)", humanBytes(b.StoredBytes), b.TakenAt.Format(time.RFC3339))
	} else {
		tl.Printf("downloading backup %s (%s, taken %s)", b.Label, humanBytes(b.StoredBytes), b.TakenAt.Format(time.RFC3339))
	}
	if err := downloadTo(ctx, r, p.BaseKey, s.rdbPath()); err != nil {
		return out, nil, err
	}
	mods, missing := localModules(b.Modules)
	if len(missing) > 0 {
		out.Warnings = append(out.Warnings, "modules the server loaded aren't on this server ("+strings.Join(missing, ", ")+"): their keys can't be read here")
	}
	// The cap: what the agent checked was free, with room for the changes
	// replayed; noeviction, so replaying fails rather than dropping keys.
	maxMem := need * 2
	if avail, ok := memAvailable(); ok {
		maxMem = min(maxMem, avail*9/10)
	}
	maxMem = max(maxMem, need)
	c, err := s.start(ctx, env, scratchOpts{MaxMemory: maxMem, Databases: max(b.Databases, 16), Modules: mods})
	if err != nil {
		if len(missing) > 0 {
			return out, nil, fmt.Errorf("%w (the backup holds data of modules that aren't on this server: %s)", err, strings.Join(missing, ", "))
		}
		return out, nil, err
	}
	_ = os.Remove(s.rdbPath()) // loaded: the memory has it now (a copy saves it again)
	if !p.Replay {
		return out, c, nil
	}
	tl.Printf("replaying the changes made after the backup, up to %s", target.describe())
	if err := replay(ctx, r, p, c, &out); err != nil {
		c.Close()
		return out, nil, err
	}
	if out.Replayed > 0 {
		tl.Printf("replayed %s changes, up to %s", commas(out.Replayed), out.RecoveredTo.Format(time.RFC3339))
	}
	return out, c, nil
}

// downloadTo writes an object's plaintext to path.
func downloadTo(ctx context.Context, r *repo, key, path string) error {
	pr, closer, err := r.getSealed(ctx, key)
	if err != nil {
		return fmt.Errorf("downloading the backup: %w", err)
	}
	defer closer.Close()
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(fh, pr); err != nil {
		fh.Close()
		os.Remove(path)
		return fmt.Errorf("downloading the backup: %w", err)
	}
	return fh.Close()
}

// skipOnReplay are stream commands that carry no data.
func skipOnReplay(name string) bool { return name == "PING" || name == "REPLCONF" }

// replay applies the plan's stream to a scratch server.
func replay(ctx context.Context, r *repo, p restorePlan, c *conn, out *restoreOutcome) error {
	c.timeout = time.Hour
	defer func() { c.timeout = defaultIOTTL }()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	// Replies are read as commands go out (a bounded number in flight).
	pending := make(chan struct{}, 4096)
	readDone := make(chan error, 1)
	go func() {
		for range pending {
			_ = c.nc.SetReadDeadline(time.Now().Add(time.Hour))
			_, err := readReply(c.br)
			if err != nil {
				if !isRespError(err) {
					readDone <- err
					for range pending {
					}
					return
				}
				out.Failed++
				if out.FirstFail == "" {
					out.FirstFail = clip(err.Error(), 200)
				}
			}
		}
		readDone <- nil
	}()
	send := func(write func() error) error {
		if err := write(); err != nil {
			return err
		}
		select {
		case pending <- struct{}{}:
		default:
			c.wmu.Lock()
			err := c.bw.Flush()
			c.wmu.Unlock()
			if err != nil {
				return err
			}
			pending <- struct{}{}
		}
		return nil
	}
	appliedDB, inMulti := 0, false
	var last time.Time
	err := func() error {
		for _, sg := range p.Chain {
			sr, done, err := openSegmentObject(ctx, r, sg)
			if err != nil {
				return err
			}
			streamDB := sr.DB
			finished, err := replaySegment(sr, p, func(rec record, name, arg1 string, body *bufio.Reader, head []byte) error {
				if name == "SELECT" {
					if n, err := strconv.Atoi(arg1); err == nil {
						streamDB = n
					}
				}
				apply := rec.Start >= p.Base.Offset && !skipOnReplay(name) && name != "SELECT"
				if !apply {
					return skipRest(body, rec.Len-int64(len(head)))
				}
				if streamDB != appliedDB {
					db := streamDB
					if err := send(func() error { return c.writeCommand("SELECT", db) }); err != nil {
						return err
					}
					appliedDB = streamDB
				}
				switch name {
				case "MULTI":
					inMulti = true
				case "EXEC", "DISCARD":
					inMulti = false
				}
				err := send(func() error {
					c.wmu.Lock()
					defer c.wmu.Unlock()
					_ = c.nc.SetWriteDeadline(time.Now().Add(time.Hour))
					if _, err := c.bw.Write(head); err != nil {
						return err
					}
					_, err := io.CopyN(c.bw, body, rec.Len-int64(len(head)))
					return noEOF(err)
				})
				if err != nil {
					return err
				}
				out.Replayed++
				last = rec.At
				return nil
			})
			done()
			if err != nil {
				return err
			}
			if finished {
				break
			}
		}
		if inMulti {
			if err := send(func() error { return c.writeCommand("DISCARD") }); err != nil {
				return err
			}
		}
		return nil
	}()
	c.wmu.Lock()
	ferr := c.bw.Flush()
	c.wmu.Unlock()
	close(pending)
	rerr := <-readDone
	switch {
	case err != nil:
		return fmt.Errorf("replaying the changes: %w", err)
	case ferr != nil:
		return fmt.Errorf("replaying the changes: %w", ferr)
	case rerr != nil:
		return fmt.Errorf("replaying the changes: %w", rerr)
	}
	if !last.IsZero() {
		out.RecoveredTo = last
	}
	if out.Failed > 0 {
		return fmt.Errorf("%s of the changes replayed failed (first: %s)", commas(out.Failed), out.FirstFail)
	}
	return nil
}

func skipRest(body *bufio.Reader, n int64) error {
	_, err := io.CopyN(io.Discard, body, n)
	return noEOF(err)
}

// replaySegment calls fn for each record of a segment within the plan's
// limits; finished is true once a record past them was met.
func replaySegment(sr *segReader, p restorePlan, fn func(rec record, name, arg1 string, body *bufio.Reader, head []byte) error) (finished bool, err error) {
	body := sr.body()
	for {
		rec, err := sr.next()
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		end := rec.Start + rec.Len
		past := (p.StopAt > 0 && end > p.StopAt) || (!p.StopTime.IsZero() && rec.At.After(p.StopTime))
		if past && rec.Start >= p.Base.Offset {
			return true, nil
		}
		head := make([]byte, min(rec.Len, 256))
		if _, err := io.ReadFull(body, head); err != nil {
			return false, noEOF(err)
		}
		name, arg1 := commandName(head)
		if err := fn(rec, name, arg1, body, head); err != nil {
			return false, err
		}
	}
}

// keyCounts reads the keys per logical database of a server.
func keyCounts(ctx context.Context, c *conn) (map[int]dbKeys, error) {
	m, err := c.info(ctx, "keyspace")
	if err != nil {
		return nil, err
	}
	return infoFrom(m).Keyspace, nil
}
