package redis

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The replication link: for every database with backups on, the agent
// stays attached to the server as a replica (that never serves anything),
// writes every command of the replication stream to local segment files
// with the moment it arrived, and uploads each segment, gzipped and sealed,
// about every minute (rotateEvery; five when the server is idle). The
// reading never waits for the bucket, so the server never has to hold
// changes for the agent (its replica output buffer stays small); segments
// wait on the local disk instead, within a cap (spoolMax).
//
// Where the link got to is saved locally: after an agent restart it asks
// the server to continue from there (PSYNC). When the server can't (its
// backlog no longer holds those changes), it sends a whole snapshot, which
// is uploaded as a new backup by itself.
//
// A server that refuses replication (SYNC/PSYNC renamed or not allowed) or
// uses min-replicas-to-write (the link would count as one of its replicas)
// isn't followed: the link goes to snapshot mode (backups are scheduled
// snapshots only) and says why.

const (
	modeReplica   = "replica"
	modeSnapshots = "snapshots"
)

// Rotation: a segment is uploaded after rotateEvery when it holds changes,
// after idleRotateEvery when it holds only the server's pings, or as soon
// as it reaches rotateBytes.
var (
	rotateEvery     = envDuration("ROWSAFE_REDIS_ARCHIVE_INTERVAL", time.Minute)
	idleRotateEvery = 5 * time.Minute
	rotateBytes     = int64(16 << 20)
)

// spoolMax caps the segments waiting on the local disk for the bucket
// (ROWSAFE_REDIS_SPOOL_MAX bytes, default 2 GiB); past it the link stops
// and the changes since aren't kept until the bucket takes them again.
func spoolMax() int64 {
	if v, err := strconv.ParseInt(os.Getenv("ROWSAFE_REDIS_SPOOL_MAX"), 10, 64); err == nil && v >= 16<<20 {
		return v
	}
	return 2 << 30
}

// diskReserve is the free space the link always leaves on its disk.
const diskReserve = 512 << 20

func envDuration(name string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(os.Getenv(name)); err == nil && d >= time.Second && d <= time.Hour {
		return d
	}
	return def
}

// linkState is what the link saved (<state>/<stanza>/link/state.json).
type linkState struct {
	// ServerReplID is the id PSYNC asks for; StreamID the id segments are
	// filed under (the snapshot's); Offset where the local stream ends; DB
	// the logical database selected there.
	ServerReplID string `json:"server_replid,omitempty"`
	StreamID     string `json:"stream_id,omitempty"`
	Offset       int64  `json:"offset"`
	DB           int    `json:"db"`

	Mode         string     `json:"mode,omitempty"`
	Problem      string     `json:"problem,omitempty"`
	ProblemSince *time.Time `json:"problem_since,omitempty"`

	FullSyncs []time.Time `json:"full_syncs,omitempty"` // the last day's whole snapshots
	// Sinks are the storages the link uploads to besides the first ("2":
	// the second copy), with when they were last asked for.
	Sinks map[string]time.Time `json:"sinks,omitempty"`
}

// sinkStats are one storage's upload counters.
type sinkStats struct {
	Shipped       int64
	Failed        int64
	LastShippedAt *time.Time
	LastFailedAt  *time.Time
	LastError     string
	// Uploaded is how far the stream of each id is in this storage;
	// Covered until when the link is known to have been up in it.
	Uploaded map[string]int64
	Covered  time.Time
}

type sink struct {
	name string
	env  agent.EngineEnv
	db   protocol.DatabaseSpec
	wake chan struct{}
	st   sinkStats
}

type follower struct {
	e   *Engine
	dir string

	mu         sync.Mutex
	env        agent.EngineEnv
	db         protocol.DatabaseSpec
	st         linkState
	lastSeen   time.Time
	connected  bool
	err        error // the link's newest error (nil while it runs)
	sinks      map[string]*sink
	rotateNow  bool
	changed    chan struct{} // closed and replaced when uploads or the link move on
	stop       context.CancelFunc
	ctx        context.Context
	sessionCtx context.CancelFunc // the running session (to restart it)
}

func linkDir(env agent.EngineEnv, stanza string) string {
	return filepath.Join(env.StateDir, stanza, "link")
}

// followerFor returns the database's link, starting it when needed.
func (e *Engine) followerFor(env agent.EngineEnv, db protocol.DatabaseSpec) (*follower, error) {
	if standbys(env).fenced(db.ID) {
		return nil, errFenced // standby.go
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if f := e.followers[db.ID]; f != nil {
		f.mu.Lock()
		f.env, f.db, f.lastSeen = env, db, time.Now() // storage keys can change (rotation)
		if s := f.sinks["1"]; s != nil {
			s.env, s.db = env, db
		}
		f.mu.Unlock()
		return f, nil
	}
	if !stanzaRE.MatchString(db.Stanza) {
		return nil, fmt.Errorf("invalid stanza %q", db.Stanza)
	}
	dir := linkDir(env, db.Stanza)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f := &follower{e: e, dir: dir, env: env, db: db, lastSeen: time.Now(), sinks: map[string]*sink{}, changed: make(chan struct{})}
	if err := f.recover(); err != nil {
		return nil, err
	}
	base := e.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	f.ctx, f.stop = ctx, cancel
	if e.followers == nil {
		e.followers = map[string]*follower{}
	}
	e.followers[db.ID] = f
	f.addSinkLocked("1", env, db)
	go f.run(ctx)
	return f, nil
}

// stopIdleFollowers stops the links of databases no longer watched.
func (e *Engine) stopIdleFollowers(idle time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, f := range e.followers {
		f.mu.Lock()
		old := time.Since(f.lastSeen) > idle
		f.mu.Unlock()
		if old {
			f.stop()
			delete(e.followers, id)
		}
	}
}

// existingFollower is the database's link when it runs.
func (e *Engine) existingFollower(dbID string) *follower {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.followers[dbID]
}

func (f *follower) statePath() string { return filepath.Join(f.dir, "state.json") }

func (f *follower) saveLocked() error { return saveJSONFile(f.statePath(), f.st) }

func (f *follower) snapshot() linkState {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.st
	st.FullSyncs = slices.Clone(f.st.FullSyncs)
	return st
}

// notifyLocked wakes everything waiting for the link to move on.
func (f *follower) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

// recover reads the saved state and finishes what an agent stopped in the
// middle of: a segment being written is closed at its last whole record, a
// snapshot being received is dropped.
func (f *follower) recover() error {
	if err := loadJSONFile(f.statePath(), &f.st); err != nil && !notExist(err) {
		return fmt.Errorf("reading %s: %w", f.statePath(), err)
	}
	_ = os.Remove(filepath.Join(f.dir, "incoming.rdb"))
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return err
	}
	for _, ent := range entries {
		name := ent.Name()
		if !strings.HasSuffix(name, ".open") {
			continue
		}
		replid, startS, ok := strings.Cut(strings.TrimSuffix(name, ".open"), "-")
		start, err := strconv.ParseInt(startS, 10, 64)
		path := filepath.Join(f.dir, name)
		if !ok || err != nil || !replIDRE.MatchString(replid) {
			_ = os.Remove(path)
			continue
		}
		end, last, db, valid, err := scanSegmentFile(path, start)
		if err != nil || end == start {
			_ = os.Remove(path)
			continue
		}
		_ = os.Truncate(path, valid)
		info, _ := os.Stat(path)
		from := last
		if info != nil && info.ModTime().Before(last) {
			from = info.ModTime()
		}
		if err := os.Rename(path, filepath.Join(f.dir, localSegName(replid, start, end, from, last))); err != nil {
			return err
		}
		if replid == f.st.StreamID && end > f.st.Offset {
			f.st.Offset, f.st.DB = end, db
		}
	}
	return nil
}

// localSegName is a finished local segment's file name.
func localSegName(replid string, start, end int64, from, to time.Time) string {
	return fmt.Sprintf("%s_%019d_%019d_%013d_%013d.seg", replid, start, end, from.UnixMilli(), to.UnixMilli())
}

func parseLocalSeg(name string) (segment, bool) {
	base, ok := strings.CutSuffix(name, ".seg")
	if !ok {
		return segment{}, false
	}
	p := strings.Split(base, "_")
	if len(p) != 5 || !replIDRE.MatchString(p[0]) {
		return segment{}, false
	}
	var n [4]int64
	for i := range n {
		v, err := strconv.ParseInt(p[i+1], 10, 64)
		if err != nil {
			return segment{}, false
		}
		n[i] = v
	}
	return segment{Key: name, ReplID: p[0], Start: n[0], End: n[1], From: time.UnixMilli(n[2]).UTC(), To: time.UnixMilli(n[3]).UTC()}, true
}

// ---- the session loop

var errSnapshotMode = errors.New("snapshot mode")

func (f *follower) run(ctx context.Context) {
	backoff := time.Duration(0)
	for {
		failedDuringSnapshot, err := f.session(ctx)
		if ctx.Err() != nil {
			return
		}
		f.mu.Lock()
		f.connected = false
		mode := f.st.Mode
		if err != nil && !errors.Is(err, errSnapshotMode) {
			f.err = err
		}
		f.notifyLocked()
		log, id := f.env.Log, f.db.ID
		f.mu.Unlock()
		var wait time.Duration
		switch {
		case mode == modeSnapshots:
			// Check now and then whether replication was allowed since.
			wait = 15 * time.Minute
		case failedDuringSnapshot:
			// A whole snapshot costs the server a fork: don't ask again at once.
			backoff = min(max(2*backoff, 2*time.Minute), time.Hour)
			wait = backoff
		case err != nil:
			backoff = min(max(2*backoff, 2*time.Second), time.Minute)
			wait = backoff
		default:
			backoff = 0
			wait = time.Second
		}
		if err != nil && !errors.Is(err, errSnapshotMode) {
			log.Warn("the replication link to Redis stopped", "database_id", id, "err", err, "retry_in", wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// setSnapshotMode records that the server can't be followed, and why.
func (f *follower) setSnapshotMode(problem string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.st.Mode != modeSnapshots || f.st.Problem != problem {
		now := time.Now().UTC()
		f.st.Mode, f.st.Problem, f.st.ProblemSince = modeSnapshots, problem, &now
		_ = f.saveLocked()
	}
	f.err = nil
	f.notifyLocked()
}

// snapshotProblem is the plain sentence for a server that can't be
// followed.
func snapshotProblem(err error, minReplicas int) string {
	if minReplicas > 0 {
		return fmt.Sprintf("The server uses min-replicas-to-write %d: Rowsafe's link would count as one of its replicas and weaken that guarantee, "+
			"so Rowsafe doesn't follow it. Backups are scheduled snapshots only, and restores go back to those snapshots, not to any second.", minReplicas)
	}
	return "The server doesn't let Rowsafe follow its changes (" + strings.TrimPrefix(err.Error(), "the server doesn't let Rowsafe follow it as a replica ") +
		". Backups are scheduled snapshots only, and restores go back to those snapshots, not to any second. Running the Rowsafe installer " +
		"on the server again gives Rowsafe's user what it needs, unless SYNC and PSYNC are renamed in the server's configuration."
}

// session connects, catches up and follows the stream until it fails.
func (f *follower) session(parent context.Context) (failedDuringSnapshot bool, err error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	f.mu.Lock()
	env, db, st := f.env, f.db, f.st
	f.sessionCtx = cancel
	f.mu.Unlock()

	c, err := connectDB(ctx, env, db)
	if err != nil {
		return false, err
	}
	defer c.Close()
	in, err := inspect(ctx, c)
	if err != nil {
		return false, err
	}
	if why := in.supported(f.e.name); why != "" {
		return false, errors.New(why)
	}
	if in.MinReplicasToWrite > 0 {
		f.setSnapshotMode(snapshotProblem(nil, in.MinReplicasToWrite))
		return false, errSnapshotMode
	}
	// Room for the whole snapshot the server sends a new link (a link that
	// continues needs none; if the server sends one anyway, receiving it
	// stops at the room there is).
	if st.ServerReplID == "" {
		if err := ensureSpace(f.dir, in.UsedMemoryDataset+diskReserve, "receiving the server's snapshot"); err != nil {
			return false, err
		}
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	reply, err := startSync(ctx, c, st.ServerReplID, st.Offset, false)
	if errors.Is(err, errReplicationRefused) {
		f.setSnapshotMode(snapshotProblem(err, 0))
		return false, errSnapshotMode
	}
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	if f.st.Mode != modeReplica {
		f.st.Mode, f.st.Problem, f.st.ProblemSince = modeReplica, "", nil
		_ = f.saveLocked()
	}
	f.mu.Unlock()
	if reply.Full {
		if err := f.receiveSnapshot(ctx, env, db, c, reply, in, st.ServerReplID != ""); err != nil {
			return true, err
		}
	} else if reply.ReplID != st.StreamID {
		// The server continued under a new id (after a failover): file the
		// stream under it from here.
		f.mu.Lock()
		f.st.ServerReplID, f.st.StreamID = reply.ReplID, reply.ReplID
		_ = f.saveLocked()
		f.mu.Unlock()
	}
	f.mu.Lock()
	f.connected, f.err = true, nil
	f.notifyLocked()
	f.mu.Unlock()
	return false, f.stream(ctx, c)
}

// receiveSnapshot stores the snapshot that follows +FULLRESYNC, to be
// uploaded as a backup, and moves the link to its place in the stream.
func (f *follower) receiveSnapshot(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, c *conn, reply syncReply, in serverInfo, resumed bool) error {
	started := time.Now().UTC()
	doc := backupDoc{Source: sourceAutomatic, Engine: f.e.name, Version: in.Version, VersionNum: in.VersionNum,
		ReplID: reply.ReplID, Offset: reply.Offset, Exact: true, TakenAt: started, StartedAt: started,
		UsedMemoryDataset: in.UsedMemoryDataset, Databases: in.Databases, Modules: in.Modules}
	if resumed {
		doc.Note = "The server couldn't continue its stream of changes where Rowsafe's link stopped (its backlog no longer held them), " +
			"so it sent a whole snapshot, kept as this backup."
	}
	doc.Keyspace = keyspaceNow(ctx, env, db)
	tmp := filepath.Join(f.dir, "incoming.rdb")
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	free, _ := freeBytes(f.dir)
	n, err := receiveRDB(ctx, c, out, max(free-diskReserve, 0), 5*time.Minute)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("receiving the server's snapshot: %w", err)
	}
	doc.RDBBytes, doc.StoppedAt = n, time.Now().UTC()
	name := fmt.Sprintf("base-%013d-%s-%019d", started.UnixMilli(), reply.ReplID, reply.Offset)
	if err := saveJSONFile(filepath.Join(f.dir, name+".json"), doc); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(f.dir, name+".rdb")); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.st.ServerReplID, f.st.StreamID, f.st.Offset, f.st.DB = reply.ReplID, reply.ReplID, reply.Offset, 0
	cut := time.Now().Add(-24 * time.Hour)
	f.st.FullSyncs = append(slices.DeleteFunc(f.st.FullSyncs, func(t time.Time) bool { return t.Before(cut) }), started)
	if err := f.saveLocked(); err != nil {
		return err
	}
	f.wakeSinksLocked()
	f.env.Log.Info("received a whole snapshot from Redis over the replication link", "database_id", db.ID, "bytes", n, "resumed", resumed)
	return nil
}

// keyspaceNow reads the keys per logical database (for Proof) on a
// connection of its own.
func keyspaceNow(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) map[string]dbKeys {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil
	}
	defer c.Close()
	m, err := c.info(ctx, "keyspace")
	if err != nil {
		return nil
	}
	out := map[string]dbKeys{}
	for k, v := range infoFrom(m).Keyspace {
		out[strconv.Itoa(k)] = v
	}
	return out
}

// stream follows the replication stream into segment files.
func (f *follower) stream(ctx context.Context, c *conn) error {
	f.mu.Lock()
	replid, offset, db := f.st.StreamID, f.st.Offset, f.st.DB
	sessionStart := offset
	f.mu.Unlock()
	seg, err := f.openSegment(replid, offset, db)
	if err != nil {
		return err
	}
	defer func() {
		if seg != nil {
			_ = f.finishSegment(seg, time.Now())
		}
	}()
	// ACK every second: the server drops a replica that stays silent for
	// repl-timeout. The offset acknowledged is what reached the bucket, so
	// WAIT never counts changes that live only on this server's disk.
	ackDone := make(chan struct{})
	defer close(ackDone)
	var ackMu sync.Mutex
	received := offset
	ack := func() {
		ackMu.Lock()
		got := received
		ackMu.Unlock()
		off := min(max(f.uploadedEnd(replid), sessionStart), got)
		c.wmu.Lock()
		_ = c.nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := c.writeCommand("REPLCONF", "ACK", off); err == nil {
			_ = c.bw.Flush()
		}
		c.wmu.Unlock()
	}
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ackDone:
				return
			case <-t.C:
				ack()
			}
		}
	}()
	limit := spoolMax()
	for {
		_ = c.nc.SetReadDeadline(time.Now().Add(3 * time.Minute))
		seg.begin()
		start := offset
		info, err := readCommand(c.br, seg.emit)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("the replication link dropped: %w", err)
		}
		now := time.Now()
		if err := seg.end(now, start, info); err != nil {
			return fmt.Errorf("writing the stream to this server's disk: %w", err)
		}
		offset += info.Size
		ackMu.Lock()
		received = offset
		ackMu.Unlock()
		if info.Name == "REPLCONF" && strings.EqualFold(info.Arg1, "GETACK") {
			ack()
		}
		f.mu.Lock()
		force := f.rotateNow
		f.rotateNow = false
		f.mu.Unlock()
		age := now.Sub(seg.From)
		if force || seg.Size() >= rotateBytes || (seg.Data > 0 && age >= rotateEvery) || age >= idleRotateEvery {
			if err := f.finishSegment(seg, now); err != nil {
				seg = nil
				return err
			}
			seg = nil
			if pending := f.pendingBytes(); pending > limit {
				return fmt.Errorf("%s of changes are waiting on this server for your bucket, more than the %s Rowsafe allows: "+
					"the link stops until the bucket takes them (check its keys and that it is reachable)", humanBytes(pending), humanBytes(limit))
			}
			if free, err := freeBytes(f.dir); err == nil && free < diskReserve {
				return fmt.Errorf("this server's disk is almost full (%s free): the link stops until there is room again", humanBytes(free))
			}
			if seg, err = f.openSegment(replid, offset, f.snapshot().DB); err != nil {
				return err
			}
		}
	}
}

func (f *follower) openSegment(replid string, start int64, db int) (*segWriter, error) {
	path := filepath.Join(f.dir, fmt.Sprintf("%s-%019d.open", replid, start))
	_ = os.Remove(path) // an empty leftover of a session that ended at once
	return createSegment(path, replid, start, db, time.Now())
}

// finishSegment closes a segment and hands it to the uploaders (an empty
// one is dropped).
func (f *follower) finishSegment(w *segWriter, now time.Time) error {
	if err := w.close(); err != nil {
		_ = os.Remove(w.path)
		return err
	}
	if w.Records == 0 {
		return os.Remove(w.path)
	}
	if err := os.Rename(w.path, filepath.Join(f.dir, localSegName(w.ReplID, w.Start, w.End, w.From, now))); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if w.ReplID == f.st.StreamID && w.End >= f.st.Offset {
		f.st.Offset, f.st.DB = w.End, w.DB
	}
	if err := f.saveLocked(); err != nil {
		return err
	}
	f.wakeSinksLocked()
	return nil
}

// pendingBytes is the size of what waits on the local disk.
func (f *follower) pendingBytes() int64 {
	var n int64
	entries, _ := os.ReadDir(f.dir)
	for _, ent := range entries {
		if strings.HasSuffix(ent.Name(), ".seg") || strings.HasSuffix(ent.Name(), ".rdb") {
			if info, err := ent.Info(); err == nil {
				n += info.Size()
			}
		}
	}
	return n
}

// requestRotate asks the link to close its segment at the next command
// (the server pings every 10 seconds, so it comes soon).
func (f *follower) requestRotate() {
	f.mu.Lock()
	f.rotateNow = true
	f.mu.Unlock()
}

// ---- uploads

// addSinkLocked starts uploading to a storage.
func (f *follower) addSinkLocked(name string, env agent.EngineEnv, db protocol.DatabaseSpec) *sink {
	if s := f.sinks[name]; s != nil {
		s.env, s.db = env, db
		return s
	}
	s := &sink{name: name, env: env, db: db, wake: make(chan struct{}, 1), st: sinkStats{Uploaded: map[string]int64{}}}
	f.sinks[name] = s
	if name != "1" {
		if f.st.Sinks == nil {
			f.st.Sinks = map[string]time.Time{}
		}
		f.st.Sinks[name] = time.Now().UTC()
		_ = f.saveLocked()
	}
	ctx := f.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	go f.uploadLoop(ctx, s)
	return s
}

// registerSink keeps the second copy's uploads going (Archiver for its id).
func (f *follower) registerSink(name string, env agent.EngineEnv, db protocol.DatabaseSpec) *sink {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.addSinkLocked(name, env, db)
	if f.st.Sinks == nil {
		f.st.Sinks = map[string]time.Time{}
	}
	if t := f.st.Sinks[name]; time.Since(t) > time.Minute {
		f.st.Sinks[name] = time.Now().UTC()
		_ = f.saveLocked()
	}
	return s
}

func (f *follower) wakeSinksLocked() {
	for _, s := range f.sinks {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// sinkNamesLocked are the storages every local file must reach before it
// is deleted: the first, and the second copy while it was asked for in
// the last hour (or since this agent started, before its first heartbeat).
func (f *follower) sinkNamesLocked() []string {
	out := []string{"1"}
	for name, t := range f.st.Sinks {
		if _, live := f.sinks[name]; live || time.Since(t) < time.Hour {
			out = append(out, name)
		}
	}
	return out
}

// uploadedEnd is how far the first storage has the stream of replid.
func (f *follower) uploadedEnd(replid string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s := f.sinks["1"]; s != nil {
		return s.st.Uploaded[replid]
	}
	return 0
}

func (f *follower) uploadLoop(ctx context.Context, s *sink) {
	backoff := time.Duration(0)
	for {
		err := f.uploadPending(ctx, s)
		wait := 30 * time.Second
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			now := time.Now().UTC()
			f.mu.Lock()
			s.st.Failed++
			s.st.LastFailedAt, s.st.LastError = &now, err.Error()
			log := f.env.Log
			f.notifyLocked()
			f.mu.Unlock()
			log.Warn("uploading Redis changes failed", "database_id", s.db.ID, "storage", s.name, "err", err)
			backoff = min(max(2*backoff, 5*time.Second), time.Minute)
			wait = backoff
		} else {
			backoff = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
		case <-time.After(wait):
		}
	}
}

// pendingFiles lists the local files to upload: snapshots first, then
// segments in stream order.
func (f *follower) pendingFiles() (bases []string, segs []segment) {
	entries, _ := os.ReadDir(f.dir)
	for _, ent := range entries {
		name := ent.Name()
		switch {
		case strings.HasPrefix(name, "base-") && strings.HasSuffix(name, ".rdb"):
			bases = append(bases, strings.TrimSuffix(name, ".rdb"))
		case strings.HasSuffix(name, ".seg"):
			if s, ok := parseLocalSeg(name); ok {
				segs = append(segs, s)
			}
		}
	}
	slices.Sort(bases)
	slices.SortFunc(segs, func(a, b segment) int {
		if a.ReplID != b.ReplID {
			return strings.Compare(a.ReplID, b.ReplID)
		}
		return cmpInt(a.Start, b.Start)
	})
	return bases, segs
}

func (f *follower) doneMarker(file, sink string) string { return filepath.Join(f.dir, file+".up"+sink) }

// uploadPending uploads what this storage doesn't have yet.
func (f *follower) uploadPending(ctx context.Context, s *sink) error {
	f.mu.Lock()
	env, db := s.env, s.db
	f.mu.Unlock()
	bases, segs := f.pendingFiles()
	if len(bases) == 0 && len(segs) == 0 {
		return nil
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	for _, b := range bases {
		if fileExists(f.doneMarker(b+".rdb", s.name)) {
			f.maybeDelete(b + ".rdb")
			continue
		}
		if err := f.uploadBase(ctx, r, s, b); err != nil {
			return err
		}
	}
	for _, sg := range segs {
		if fileExists(f.doneMarker(sg.Key, s.name)) {
			f.noteUploaded(s, sg, false)
			f.maybeDelete(sg.Key)
			continue
		}
		if err := f.uploadSegment(ctx, r, s, sg); err != nil {
			return err
		}
	}
	return nil
}

func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }

func (f *follower) uploadBase(ctx context.Context, r *repo, s *sink, name string) error {
	var doc backupDoc
	if err := loadJSONFile(filepath.Join(f.dir, name+".json"), &doc); err != nil {
		return err
	}
	label, err := r.freshLabel(ctx, doc.TakenAt)
	if err != nil {
		return err
	}
	doc.Label = label
	fh, err := os.Open(filepath.Join(f.dir, name+".rdb"))
	if err != nil {
		return err
	}
	stored, err := r.putSealed(ctx, backupKey(label, rdbName), fh)
	fh.Close()
	if err != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), label)
		return fmt.Errorf("uploading the snapshot: %w", err)
	}
	doc.StoredBytes = stored
	if err := r.putJSON(ctx, backupKey(label, backupDocName), doc); err != nil {
		_ = r.deleteBackup(context.WithoutCancel(ctx), label)
		return err
	}
	if err := os.WriteFile(f.doneMarker(name+".rdb", s.name), nil, 0o600); err != nil {
		return err
	}
	f.mu.Lock()
	log := f.env.Log
	f.mu.Unlock()
	log.Info("a snapshot Redis sent over the replication link is now a backup", "database_id", s.db.ID, "label", label, "storage", s.name)
	if err := retention(ctx, r, s.db, label, nil); err != nil {
		log.Warn("removing old Redis backups failed", "database_id", s.db.ID, "err", err)
	}
	f.maybeDelete(name + ".rdb")
	return nil
}

func (f *follower) uploadSegment(ctx context.Context, r *repo, s *sink, sg segment) error {
	fh, err := os.Open(filepath.Join(f.dir, sg.Key))
	if err != nil {
		return err
	}
	defer fh.Close()
	pr, pw := io.Pipe()
	go func() {
		zw, _ := gzip.NewWriterLevel(pw, gzip.BestSpeed)
		_, err := io.Copy(zw, fh)
		if cerr := zw.Close(); err == nil {
			err = cerr
		}
		pw.CloseWithError(err)
	}()
	_, err = r.putSealed(ctx, segmentKey(sg.ReplID, sg.Start, sg.End, sg.From, sg.To), pr)
	pr.CloseWithError(errors.New("upload stopped"))
	if err != nil {
		return fmt.Errorf("uploading changes: %w", err)
	}
	if err := os.WriteFile(f.doneMarker(sg.Key, s.name), nil, 0o600); err != nil {
		return err
	}
	f.noteUploaded(s, sg, true)
	f.maybeDelete(sg.Key)
	return nil
}

func (f *follower) noteUploaded(s *sink, sg segment, fresh bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sg.End > s.st.Uploaded[sg.ReplID] {
		s.st.Uploaded[sg.ReplID] = sg.End
	}
	if sg.To.After(s.st.Covered) {
		s.st.Covered = sg.To
	}
	if fresh {
		now := time.Now().UTC()
		s.st.Shipped++
		s.st.LastShippedAt, s.st.LastError = &now, ""
	}
	f.notifyLocked()
}

// maybeDelete removes a local file once every storage has it.
func (f *follower) maybeDelete(file string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := f.sinkNamesLocked()
	for _, n := range names {
		if !fileExists(f.doneMarker(file, n)) {
			return
		}
	}
	_ = os.Remove(filepath.Join(f.dir, file))
	if base, ok := strings.CutSuffix(file, ".rdb"); ok {
		_ = os.Remove(filepath.Join(f.dir, base+".json"))
	}
	matches, _ := filepath.Glob(filepath.Join(f.dir, file+".up*"))
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

// ---- waiting for the link

// waitFollowing waits until the link follows the server (after its first
// snapshot), or says why it can't.
func (f *follower) waitFollowing(ctx context.Context, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		f.mu.Lock()
		connected, mode, problem, err, ch := f.connected, f.st.Mode, f.st.Problem, f.err, f.changed
		f.mu.Unlock()
		switch {
		case mode == modeSnapshots:
			return &snapshotModeError{problem}
		case connected:
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			if err != nil {
				return err
			}
			return fmt.Errorf("the replication link isn't following the server yet (after %s)", timeout)
		case <-ch:
		}
	}
}

// snapshotModeError: the server can't be followed (Problem says why).
type snapshotModeError struct{ Problem string }

func (e *snapshotModeError) Error() string { return e.Problem }

// flush waits until the first storage has the stream of replid up to
// offset (at most timeout).
func (f *follower) flush(ctx context.Context, replid string, offset int64, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		f.mu.Lock()
		var up int64
		if s := f.sinks["1"]; s != nil {
			up = s.st.Uploaded[replid]
		}
		mode, problem, lerr, ch := f.st.Mode, f.st.Problem, f.err, f.changed
		var uerr string
		if s := f.sinks["1"]; s != nil {
			uerr = s.st.LastError
		}
		f.rotateNow = true
		f.mu.Unlock()
		if up >= offset {
			return nil
		}
		if mode == modeSnapshots {
			return &snapshotModeError{problem}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			switch {
			case uerr != "":
				return errors.New(uerr)
			case lerr != nil:
				return lerr
			}
			return fmt.Errorf("the changes haven't reached your bucket within %s", timeout)
		case <-ch:
		case <-time.After(2 * time.Second):
		}
	}
}

// flushTime waits until the first storage covers the moment t (a segment
// closed after it is there), at most timeout.
func (f *follower) flushTime(ctx context.Context, t time.Time, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		f.mu.Lock()
		var covered time.Time
		if s := f.sinks["1"]; s != nil {
			covered = s.st.Covered
		}
		mode, problem, connected, ch := f.st.Mode, f.st.Problem, f.connected, f.changed
		f.rotateNow = true
		f.mu.Unlock()
		switch {
		case !covered.Before(t):
			return nil
		case mode == modeSnapshots:
			return &snapshotModeError{problem}
		case !connected:
			return errors.New("Rowsafe's link isn't following the server right now")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("the changes up to %s haven't reached your bucket within %s", t.Format(time.RFC3339), timeout)
		case <-ch:
		case <-time.After(2 * time.Second):
		}
	}
}

// ---- heartbeat

// Archiver reports the replication link for the heartbeat and keeps it
// running. The second copy's id gets its own storage's counters.
func (e *Engine) Archiver(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error) {
	if base, ok := strings.CutSuffix(db.ID, "~copy2"); ok {
		f := e.existingFollower(base)
		if f == nil {
			return nil, nil
		}
		s := f.registerSink("2", env, db)
		return f.stats(s), nil
	}
	f, err := e.followerFor(env, db)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	s := f.sinks["1"]
	f.mu.Unlock()
	return f.stats(s), nil
}

func (f *follower) stats(s *sink) *protocol.ArchiverStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := &protocol.ArchiverStats{ArchiveMode: "on", ArchivedCount: s.st.Shipped, FailedCount: s.st.Failed,
		LastArchivedTime: s.st.LastShippedAt, LastFailedTime: s.st.LastFailedAt}
	switch {
	case f.st.Mode == modeSnapshots:
		out.ArchiveMode = protocol.RedisArchiveSnapshots
		out.Error = f.st.Problem
	case s.st.LastError != "":
		out.Error = s.st.LastError
	case f.err != nil:
		out.Error = f.err.Error()
	}
	return out
}
