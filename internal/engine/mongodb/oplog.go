package mongodb

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Continuous archiving: every database with backups on has a shipper that
// reads new entries from MongoDB's oplog (local.oplog.rs) about once a
// minute, gzips and seals them, and uploads them as one chunk. With a full
// backup (mongodump --oplog) the chunks allow a restore to any second.
// Where it got to is saved in the engine's state directory, so an agent
// restart carries on where it stopped (as long as the oplog still holds
// those entries: its window is reported and checked).

// shipInterval is how often new oplog entries are copied
// (ROWSAFE_MONGODB_ARCHIVE_INTERVAL, default 60s).
func shipInterval() time.Duration {
	if v := os.Getenv("ROWSAFE_MONGODB_ARCHIVE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second && d <= 10*time.Minute {
			return d
		}
	}
	return time.Minute
}

// maxChunkBytes caps one chunk's raw oplog bytes; a busy minute is split.
var maxChunkBytes = 32 << 20

// shipState is what a shipper saved (<state>/<stanza>/oplog.json).
type shipState struct {
	Last          ts         `json:"last"` // newest entry in the bucket
	LastShippedAt *time.Time `json:"last_shipped_at,omitempty"`
	Shipped       int64      `json:"shipped"`
	Failed        int64      `json:"failed"`
	LastFailedAt  *time.Time `json:"last_failed_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	// GapFrom..GapTo is the latest span the oplog lost before it was
	// copied (it was overwritten while the agent was stopped or failing).
	GapFrom *time.Time `json:"gap_from,omitempty"`
	GapTo   *time.Time `json:"gap_to,omitempty"`
	SetName string     `json:"set_name,omitempty"`
}

type shipper struct {
	env agent.EngineEnv

	mu       sync.Mutex
	db       protocol.DatabaseSpec
	st       shipState
	lastSeen time.Time
	running  bool
	err      error // the newest error (cleared by a successful round)
	client   *mongo.Client
	wake     chan struct{}
	done     chan struct{} // closed when a round finishes
	stop     context.CancelFunc
}

func statePath(env agent.EngineEnv, stanza string, name string) string {
	return filepath.Join(env.StateDir, stanza, name)
}

func loadShipState(env agent.EngineEnv, stanza string) (shipState, error) {
	var st shipState
	data, err := os.ReadFile(statePath(env, stanza, "oplog.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

func saveJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// shipperFor returns the database's shipper, starting it when needed.
func (e *Engine) shipperFor(env agent.EngineEnv, db protocol.DatabaseSpec) (*shipper, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s := e.shippers[db.ID]; s != nil {
		s.mu.Lock()
		s.db, s.lastSeen = db, time.Now()
		s.mu.Unlock()
		return s, nil
	}
	st, err := loadShipState(env, db.Stanza)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(e.baseCtx())
	s := &shipper{env: env, db: db, st: st, lastSeen: time.Now(), wake: make(chan struct{}, 1),
		done: make(chan struct{}), stop: cancel, running: true}
	if e.shippers == nil {
		e.shippers = map[string]*shipper{}
	}
	e.shippers[db.ID] = s
	go s.run(ctx)
	return s, nil
}

// stopIdleShippers stops shippers of databases no longer watched.
func (e *Engine) stopIdleShippers(idle time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, s := range e.shippers {
		s.mu.Lock()
		old := time.Since(s.lastSeen) > idle
		s.mu.Unlock()
		if old {
			s.stop()
			delete(e.shippers, id)
		}
	}
}

func (s *shipper) run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.running = false
		if s.client != nil {
			disconnect(s.client)
			s.client = nil
		}
		s.mu.Unlock()
	}()
	backoff := time.Duration(0)
	for {
		err := s.round(ctx)
		s.mu.Lock()
		s.err = err
		close(s.done)
		s.done = make(chan struct{})
		s.mu.Unlock()
		wait := shipInterval()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.env.Log.Warn("copying MongoDB's oplog failed", "database_id", s.db.ID, "err", err)
			backoff = min(max(2*backoff, 5*time.Second), wait)
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

// flush copies everything up to until (or the newest entry when zero) and
// waits for it, at most timeout.
func (s *shipper) flush(ctx context.Context, until ts, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		s.mu.Lock()
		last, done, err, running := s.st.Last, s.done, s.err, s.running
		s.mu.Unlock()
		if !running {
			return errors.New("the oplog copier stopped")
		}
		if !until.IsZero() && !last.Before(until) {
			return nil
		}
		select {
		case s.wake <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			if err != nil {
				return err
			}
			return fmt.Errorf("the oplog wasn't copied up to %s within %s", until.Time().Format(time.RFC3339), timeout)
		case <-done:
			s.mu.Lock()
			last, err = s.st.Last, s.err
			s.mu.Unlock()
			if until.IsZero() {
				return err
			}
			if !last.Before(until) {
				return nil
			}
		}
	}
}

func (s *shipper) snapshot() (shipState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, s.err
}

func (s *shipper) save(st shipState) error {
	s.mu.Lock()
	s.st = st
	db := s.db
	s.mu.Unlock()
	return saveJSONFile(statePath(s.env, db.Stanza, "oplog.json"), st)
}

func (s *shipper) conn(ctx context.Context) (*mongo.Client, error) {
	s.mu.Lock()
	c, db := s.client, s.db
	s.mu.Unlock()
	if c != nil {
		return c, nil
	}
	c, err := connectDB(ctx, s.env, db)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.client = c
	s.mu.Unlock()
	return c, nil
}

func (s *shipper) dropConn() {
	s.mu.Lock()
	c := s.client
	s.client = nil
	s.mu.Unlock()
	if c != nil {
		disconnect(c)
	}
}

// round copies what is new; it keeps going while chunks are full.
func (s *shipper) round(ctx context.Context) (err error) {
	s.mu.Lock()
	st, db := s.st, s.db
	s.mu.Unlock()
	defer func() {
		if err != nil && ctx.Err() == nil {
			now := time.Now().UTC()
			st, _ := s.snapshot()
			st.Failed++
			st.LastFailedAt, st.LastError = &now, err.Error()
			_ = s.save(st)
		}
	}()
	c, err := s.conn(ctx)
	if err != nil {
		return err
	}
	r, err := openRepo(s.env, db)
	if err != nil {
		return err
	}
	for {
		n, full, err := s.shipOne(ctx, c, r, &st)
		if err != nil {
			if isNetworkError(err) {
				s.dropConn()
			}
			return err
		}
		if n == 0 || !full {
			return nil
		}
	}
}

func isNetworkError(err error) bool {
	return mongo.IsNetworkError(err) || mongo.IsTimeout(err)
}

// shipOne uploads one chunk. It returns how many entries it copied and
// whether the chunk was full (more may be waiting).
func (s *shipper) shipOne(ctx context.Context, c *mongo.Client, r *repo, st *shipState) (int, bool, error) {
	oplog := c.Database("local").Collection("oplog.rs")
	if st.Last.IsZero() {
		// The first round starts from now: backups taken from here on
		// can be carried forward.
		latest, err := latestOpTime(ctx, c)
		if err != nil {
			return 0, false, err
		}
		st.Last = fromBSON(latest)
		if err := s.save(*st); err != nil {
			return 0, false, err
		}
	}
	oldest, err := oldestOpTime(ctx, c)
	if err != nil {
		return 0, false, err
	}
	prev := st.Last
	filter := bson.D{{Key: "ts", Value: bson.D{{Key: "$gt", Value: st.Last.bson()}}}}
	var gapErr error
	if fromBSON(oldest).After(st.Last) {
		// The oplog was overwritten past what we copied: record the gap
		// and carry on from the oldest entry left. The chunk's prev is
		// set right before that entry, so a restore sees the gap.
		o := fromBSON(oldest)
		from, to := st.Last.Time(), o.Time()
		st.GapFrom, st.GapTo = &from, &to
		prev = ts{T: o.T, I: o.I - 1}
		if o.I == 0 {
			prev = ts{T: o.T - 1, I: ^uint32(0)}
		}
		filter = bson.D{{Key: "ts", Value: bson.D{{Key: "$gte", Value: oldest}}}}
		gapErr = fmt.Errorf("MongoDB's oplog no longer holds the changes from %s to %s: they were overwritten before Rowsafe copied them "+
			"(the agent was stopped or failing for longer than the oplog's window). Restoring to a moment in that span isn't possible; "+
			"everything after it is copied again", from.Format(time.RFC3339), to.Format(time.RFC3339))
	}
	cur, err := oplog.Find(ctx, filter, options.Find().SetSort(bson.D{{Key: "$natural", Value: 1}}).SetBatchSize(1000))
	if err != nil {
		return 0, false, fmt.Errorf("reading the oplog: %w", err)
	}
	defer cur.Close(ctx)
	var raw bytes.Buffer
	var first, last ts
	n, full := 0, false
	for cur.Next(ctx) {
		var e struct {
			TS bson.Timestamp `bson:"ts"`
		}
		if err := bson.Unmarshal(cur.Current, &e); err != nil {
			return 0, false, err
		}
		t := fromBSON(e.TS)
		if n == 0 {
			first = t
		}
		last = t
		raw.Write(cur.Current)
		n++
		if raw.Len() >= maxChunkBytes {
			full = true
			break
		}
	}
	if err := cur.Err(); err != nil {
		return 0, false, fmt.Errorf("reading the oplog: %w", err)
	}
	if n == 0 {
		if gapErr != nil {
			return 0, false, gapErr
		}
		return 0, false, nil
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
	zw.Write(raw.Bytes())
	if err := zw.Close(); err != nil {
		return 0, false, err
	}
	if _, err := r.putSealed(ctx, chunkKey(first, last, prev), &gz); err != nil {
		return 0, false, err
	}
	now := time.Now().UTC()
	st.Last, st.LastShippedAt = last, &now
	st.Shipped++
	st.LastError = ""
	if gapErr != nil {
		st.Failed++
		st.LastFailedAt, st.LastError = &now, gapErr.Error()
	}
	if err := s.save(*st); err != nil {
		return n, full, err
	}
	return n, full, nil
}

// readChunk reads a chunk's entries (raw BSON documents) in order.
func readChunk(ctx context.Context, r *repo, c chunk, fn func(doc bson.Raw, t ts) error) error {
	pr, closer, err := r.getSealed(ctx, c.Key)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", c.Key, err)
	}
	defer closer.Close()
	zr, err := gzip.NewReader(pr)
	if err != nil {
		return fmt.Errorf("%s: %w", c.Key, err)
	}
	return readBSONStream(zr, func(doc bson.Raw) error {
		v, err := doc.LookupErr("ts")
		if err != nil {
			return fmt.Errorf("%s: an oplog entry without ts", c.Key)
		}
		t, i, ok := v.TimestampOK()
		if !ok {
			return fmt.Errorf("%s: an oplog entry with a bad ts", c.Key)
		}
		return fn(doc, ts{T: t, I: i})
	})
}

// readBSONStream calls fn for each document of a concatenation of BSON
// documents.
func readBSONStream(r io.Reader, fn func(bson.Raw) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var head [4]byte
	for {
		if _, err := io.ReadFull(br, head[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("corrupt oplog data: %w", err)
		}
		size := int(binary.LittleEndian.Uint32(head[:]))
		if size < 5 || size > 64<<20 {
			return fmt.Errorf("corrupt oplog data (document size %d)", size)
		}
		doc := make([]byte, size)
		copy(doc, head[:])
		if _, err := io.ReadFull(br, doc[4:]); err != nil {
			return fmt.Errorf("corrupt oplog data: %w", err)
		}
		if err := fn(bson.Raw(doc)); err != nil {
			return err
		}
	}
}

// archiverStats is the heartbeat's report of a shipper.
func archiverStats(st shipState, err error, setName string) *protocol.ArchiverStats {
	out := &protocol.ArchiverStats{ArchivedCount: st.Shipped, FailedCount: st.Failed,
		LastArchivedTime: st.LastShippedAt, LastFailedTime: st.LastFailedAt, ArchiveMode: "on"}
	if setName == "" && st.SetName == "" && st.Last.IsZero() {
		out.ArchiveMode = "off"
	}
	if err != nil {
		out.Error = err.Error()
	}
	return out
}
