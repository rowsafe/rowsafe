package redis

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// sentinelWatched reports whether Sentinel watches the server (its
// connections name themselves sentinel-...).
func sentinelWatched(ctx context.Context, c *conn) bool {
	s, err := c.str(ctx, "CLIENT", "LIST")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(s, "\n") {
		for _, f := range strings.Fields(line) {
			if name, ok := strings.CutPrefix(f, "name="); ok && strings.HasPrefix(name, "sentinel-") {
				return true
			}
		}
	}
	return false
}

// blocker says why a server can't be protected ("" when it can).
func (e *Engine) blocker(ctx context.Context, c *conn, in serverInfo) string {
	if why := in.supported(e.name); why != "" {
		return why
	}
	if sentinelWatched(ctx, c) {
		return e.display() + " is managed by Sentinel, which Rowsafe doesn't support yet: Sentinel would see Rowsafe's link as one of its replicas. " +
			"Only standalone servers, with or without replicas of their own"
	}
	return ""
}

func (e *Engine) adopt(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.AdoptParams, tl agent.TaskLogger) (*protocol.AdoptResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	tl.Printf("found %s %s on port %d: %s keys in %d logical databases, %s of data", e.display(), in.Version, db.Port,
		commas(in.totalKeys()), len(in.Keyspace), humanBytes(in.UsedMemoryDataset))
	mode := "on"
	if in.MinReplicasToWrite > 0 {
		mode = protocol.RedisArchiveSnapshots
	}
	res := &protocol.AdoptResult{Inspect: in.inspectResult(e.name, db.Port, mode)}
	res.Plan = []protocol.Change{
		{Kind: "command", Description: "Prepare your bucket for this database (a folder with its own encrypted backups)"},
		{Kind: "command", Description: "Follow every change as a hidden replica (it never serves anything) and copy the changes to your bucket about every minute, encrypted on this server, so you can restore to any second"},
		{Kind: "command", Description: "Keep the whole snapshot " + e.display() + " sends the replica first as your first backup, then take one on the schedule you choose"},
	}
	if in.MinReplicasToWrite > 0 {
		res.Warnings = append(res.Warnings, snapshotProblem(nil, in.MinReplicasToWrite))
	}
	if in.isReplica() {
		res.Warnings = append(res.Warnings, "This server is a replica: backups and restores to any second work from it, but bringing keys back and "+
			"rewinding in place need its primary (a replica refuses writes)")
	}
	if in.BacklogSize > 0 && in.BacklogSize < 16<<20 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s keeps only %s of recent changes for replicas (repl-backlog-size): if Rowsafe's link "+
			"drops for longer than that holds, the server sends a whole new snapshot. Pulse offers a larger backlog when that happens often.",
			e.display(), humanBytes(in.BacklogSize)))
	}
	blocker := e.blocker(ctx, c, in)
	if !p.Apply {
		tl.Printf("plan only: nothing was changed")
		return res, nil
	}
	if blocker != "" {
		return res, errors.New(blocker)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("preparing the bucket folder for %s", db.Name)
	var existing marker
	switch err := r.getJSON(ctx, markerKey, &existing); {
	case err == nil:
		if existing.Engine != e.name {
			return res, fmt.Errorf("the bucket folder %s already holds %s backups", db.Stanza, protocol.EngineDisplayName(existing.Engine))
		}
	case errors.Is(err, objstore.ErrNotFound):
		if err := r.putJSON(ctx, markerKey, marker{Engine: e.name, Database: db.Name, CreatedAt: time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("writing to your bucket: %w", err)
		}
	default:
		return res, fmt.Errorf("reading your bucket: %w", err)
	}
	if _, err := e.followerFor(env, db); err != nil {
		return res, err
	}
	res.Applied = true
	tl.Printf("backups are on: Rowsafe follows %s's changes and copies them to your bucket about every minute", e.display())
	return res, nil
}

func (e *Engine) check(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (*protocol.CheckResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	res := &protocol.CheckResult{Inspect: in.inspectResult(e.name, db.Port, "on")}
	if why := e.blocker(ctx, c, in); why != "" {
		return res, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	f, err := e.followerFor(env, db)
	if err != nil {
		return res, err
	}
	tl.Printf("waiting for Rowsafe's link to follow %s (when it starts, the server sends it a whole snapshot first)", e.display())
	err = f.waitFollowing(ctx, 30*time.Minute)
	var sm *snapshotModeError
	if errors.As(err, &sm) {
		res.Inspect.ArchiveMode = protocol.RedisArchiveSnapshots
		tl.Printf("%s", sm.Problem)
		if err := checkSnapshotFile(env, in); err != nil {
			return res, err
		}
		if err := r.putJSON(ctx, "check.json", map[string]time.Time{"checked_at": time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("writing to your bucket: %w", err)
		}
		tl.Printf("snapshot backups work: the server's snapshot file is readable and your bucket takes Rowsafe's encrypted files")
		res.OK = true
		return res, nil
	}
	if err != nil {
		return res, err
	}
	m, err := c.info(ctx, "replication")
	if err != nil {
		return res, err
	}
	ls := f.snapshot()
	// At least one command past where the link stands (the server pings
	// every 10 seconds), so a piece of the stream makes the whole trip.
	until, replid := max(m.int("master_repl_offset"), ls.Offset+1), ls.StreamID
	tl.Printf("waiting for the changes up to now to reach your bucket")
	if err := f.flush(ctx, replid, until, 3*time.Minute); err != nil {
		return res, fmt.Errorf("copying %s's changes to your bucket: %w", e.display(), err)
	}
	segs, err := r.listSegments(ctx)
	if err != nil {
		return res, err
	}
	if len(segs) == 0 {
		return res, errors.New("no changes reached your bucket")
	}
	newest := segs[0]
	for _, s := range segs {
		if s.To.After(newest.To) {
			newest = s
		}
	}
	n, err := countSegment(ctx, r, newest)
	if err != nil {
		return res, fmt.Errorf("reading the copied changes back: %w", err)
	}
	tl.Printf("copying works: the newest piece of the stream (%d commands) is in your bucket and opens with this server's key", n)
	res.OK = true
	return res, nil
}

// checkSnapshotFile makes sure the agent can read the server's snapshot
// file (snapshot mode).
func checkSnapshotFile(env agent.EngineEnv, in serverInfo) error {
	dir := cmpOr(strings.TrimSpace(os.Getenv(dataDirEnv)), in.Dir)
	if dir == "" || in.DBFilename == "" {
		return errors.New("Rowsafe can't tell where the server keeps its snapshot file: run the Rowsafe installer on the server again")
	}
	path := filepath.Join(dir, in.DBFilename)
	fh, err := os.Open(path)
	if err == nil {
		fh.Close()
		return nil
	}
	if notExist(err) {
		if st, derr := os.Stat(dir); derr == nil && st.IsDir() {
			return nil // no snapshot yet: the first backup writes one
		}
	}
	return fmt.Errorf("Rowsafe can't read the server's snapshot file %s (%s): the installer gives Rowsafe's user read access to it; "+
		"in Docker, mount the server's data volume into the agent's container, read only", path, errorsTail(err))
}

// openSegment downloads and opens an uploaded segment.
func openSegmentObject(ctx context.Context, r *repo, s segment) (*segReader, func(), error) {
	pr, closer, err := r.getSealed(ctx, s.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("downloading changes: %w", err)
	}
	zr, err := gzip.NewReader(bufio.NewReaderSize(pr, 256<<10))
	if err != nil {
		closer.Close()
		return nil, nil, err
	}
	sr, err := newSegReader(zr)
	if err != nil {
		closer.Close()
		return nil, nil, err
	}
	return sr, func() { closer.Close() }, nil
}

// countSegment counts an uploaded segment's commands.
func countSegment(ctx context.Context, r *repo, s segment) (int, error) {
	sr, done, err := openSegmentObject(ctx, r, s)
	if err != nil {
		return 0, err
	}
	defer done()
	n := 0
	for {
		rec, err := sr.next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		if err := sr.skip(rec.Len); err != nil {
			return n, err
		}
		n++
	}
}
