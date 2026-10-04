package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// A sink is one bucket the stream goes to: the first storage ("primary")
// and, when the server has one, the second copy ("copy2", its own bucket
// and passphrase). Each uploads the spool's chunks in order, on its own,
// and remembers the last one it has (sinks.json); a chunk leaves the spool
// once every active sink has it.

const (
	sinkPrimary = "primary"
	sinkCopy2   = "copy2"
	// sinkIdle: a sink not asked about for this long (the second copy was
	// removed) stops holding chunks.
	sinkIdle = 15 * time.Minute
	// coveredEvery: how often a caught-up sink records in its bucket that
	// the stream is complete up to now (an idle database's restores reach
	// the moment asked for).
	coveredEvery = time.Minute
)

// sinkState is what a sink saved.
type sinkState struct {
	Acked          int64      `json:"acked"` // the last spool chunk uploaded
	Uploaded       int64      `json:"uploaded"`
	LastUploadedAt *time.Time `json:"last_uploaded_at,omitempty"`
	LastTxnAt      *time.Time `json:"last_txn_at,omitempty"` // newest transaction in the bucket
	CaughtUpAt     *time.Time `json:"caught_up_at,omitempty"`
	CoveredSaved   *time.Time `json:"covered_saved,omitempty"`
	Failed         int64      `json:"failed"`
	LastFailedAt   *time.Time `json:"last_failed_at,omitempty"`
	LastError      string     `json:"last_error,omitempty"`
	Missed         bool       `json:"missed,omitempty"`
}

type sink struct {
	name     string
	env      agent.EngineEnv
	db       protocol.DatabaseSpec
	st       sinkState
	lastSeen time.Time
	wake     chan struct{}
	repo     *repo
	repoKey  string
}

func (k *sink) active() bool { return time.Since(k.lastSeen) < sinkIdle }

// covered is a sink's record that the stream of a generation is complete
// up to Until (wal/<gen>/covered.json).
type covered struct {
	Until time.Time `json:"until"`
	Pos   pos       `json:"pos"`
}

func coveredKey(gen string) string { return walPrefix + gen + "/covered.json" }

func (s *shipper) sinksPath() string { return filepath.Join(s.dir, "sinks.json") }

func (s *shipper) saveSinks() {
	s.mu.Lock()
	out := map[string]sinkState{}
	for name, k := range s.sinks {
		out[name] = k.st
	}
	s.mu.Unlock()
	if err := saveJSONFile(s.sinksPath(), out); err != nil {
		s.logger().Warn("saving the SQLite copier's state", "err", err)
	}
}

func (s *shipper) loadSinks() map[string]sinkState {
	out := map[string]sinkState{}
	_ = loadJSONFile(s.sinksPath(), &out)
	return out
}

// sinkFor registers (or refreshes) the sink for env's bucket and starts
// its upload loop.
func (s *shipper) sinkFor(name string, env agent.EngineEnv, db protocol.DatabaseSpec) *sink {
	s.mu.Lock()
	k := s.sinks[name]
	if k != nil {
		k.env, k.db, k.lastSeen = env, db, time.Now()
		s.mu.Unlock()
		return k
	}
	saved := s.loadSinks()
	k = &sink{name: name, env: env, db: db, lastSeen: time.Now(), wake: make(chan struct{}, 1)}
	if st, ok := saved[name]; ok {
		k.st = st
	} else {
		// A new bucket starts with what is in the spool now.
		k.st.Acked = s.sp.oldest() - 1
		if k.st.Acked < 0 {
			k.st.Acked = 0
		}
	}
	s.sinks[name] = k
	s.mu.Unlock()
	go s.sinkLoop(k)
	return k
}

func (s *shipper) wakeSinks() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.sinks {
		select {
		case k.wake <- struct{}{}:
		default:
		}
	}
}

// sinkLoop uploads chunks to one bucket, in order, until the shipper
// stops.
func (s *shipper) sinkLoop(k *sink) {
	backoff := time.Duration(0)
	for {
		err := s.uploadPending(k)
		wait := time.Second
		if err != nil {
			backoff = min(max(2*backoff, time.Second), time.Minute)
			wait = backoff
		} else {
			backoff = 0
		}
		select {
		case <-s.ctx.Done():
			return
		case <-k.wake:
		case <-time.After(wait):
		}
	}
}

func (s *shipper) sinkRepo(k *sink) (*repo, error) {
	s.mu.Lock()
	env, db := k.env, k.db
	s.mu.Unlock()
	key := fmt.Sprintf("%s|%s|%s|%s|%s", env.Repo.Endpoint, env.Repo.Bucket, env.Repo.PathPrefix, env.Repo.Key, db.Stanza)
	if k.repo != nil && k.repoKey == key {
		return k.repo, nil
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	k.repo, k.repoKey = r, key
	return r, nil
}

// uploadPending uploads the chunks the bucket doesn't have yet.
func (s *shipper) uploadPending(k *sink) error {
	s.mu.Lock()
	acked, active := k.st.Acked, k.active()
	s.mu.Unlock()
	if !active {
		return nil
	}
	pending := s.sp.after(acked)
	if len(pending) > 0 {
		r, err := s.sinkRepo(k)
		if err != nil {
			s.sinkFailed(k, err)
			return err
		}
		for _, c := range pending {
			if err := s.uploadChunk(r, c); err != nil {
				s.sinkFailed(k, err)
				return err
			}
			now := time.Now().UTC()
			t1 := c.Hdr.t1()
			s.mu.Lock()
			k.st.Acked, k.st.Uploaded, k.st.LastUploadedAt, k.st.LastTxnAt = c.N, k.st.Uploaded+1, &now, &t1
			k.st.LastError = ""
			s.mu.Unlock()
			s.saveSinks()
			s.trimSpool()
		}
	}
	s.noteCaughtUp(k)
	return nil
}

func (s *shipper) uploadChunk(r *repo, c chunk) error {
	rd, err := s.sp.reader(c)
	if err != nil {
		return err
	}
	defer rd.Close()
	h := c.Hdr
	key := segKey(h.Gen, h.Seq, h.W, h.Txns[0].First, h.Txns[len(h.Txns)-1].Last, h.t0(), h.t1())
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	defer cancel()
	_, err = r.putCompressed(ctx, key, rd)
	return err
}

func (s *shipper) sinkFailed(k *sink, err error) {
	if s.ctx.Err() != nil {
		return
	}
	now := time.Now().UTC()
	s.mu.Lock()
	k.st.Failed++
	k.st.LastFailedAt, k.st.LastError = &now, plainBucketError(err)
	s.mu.Unlock()
	s.saveSinks()
}

func plainBucketError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "no such host") || strings.Contains(msg, "connection refused") || strings.Contains(msg, "timeout") {
		return "can't reach your bucket: " + firstLine(msg)
	}
	return "uploading to your bucket failed: " + firstLine(msg)
}

// trimSpool removes chunks every active sink has.
func (s *shipper) trimSpool() {
	s.mu.Lock()
	low := int64(-1)
	for _, k := range s.sinks {
		if !k.active() {
			continue
		}
		if low < 0 || k.st.Acked < low {
			low = k.st.Acked
		}
	}
	s.mu.Unlock()
	if low > 0 {
		s.sp.trim(low)
	}
}

// noteCaughtUp records that the bucket has every transaction committed as
// of the shipper's last poll, and every minute says so in the bucket.
func (s *shipper) noteCaughtUp(k *sink) {
	s.mu.Lock()
	poll, gen, p := s.lastPoll, s.st.Gen, s.st.pos()
	open := !s.sp.oldestOpenAt().IsZero()
	behind := k.st.Acked < s.sp.last()
	attached := s.attached && s.off == ""
	s.mu.Unlock()
	if open || behind || poll.IsZero() || !attached || gen == "" {
		return
	}
	poll = poll.UTC()
	s.mu.Lock()
	k.st.CaughtUpAt = &poll
	due := k.st.CoveredSaved == nil || poll.Sub(*k.st.CoveredSaved) >= coveredEvery
	s.mu.Unlock()
	if !due {
		return
	}
	r, err := s.sinkRepo(k)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, time.Minute)
	defer cancel()
	if err := r.putJSON(ctx, coveredKey(gen), covered{Until: poll, Pos: p}); err != nil {
		s.sinkFailed(k, err)
		return
	}
	s.mu.Lock()
	k.st.CoveredSaved = &poll
	s.mu.Unlock()
	s.saveSinks()
}

// archiverStats is the heartbeat's report of one sink.
func (s *shipper) archiverStats(name string) *protocol.ArchiverStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &protocol.ArchiverStats{ArchiveMode: "on"}
	if s.off != "" {
		out.ArchiveMode = "off"
	}
	k := s.sinks[name]
	if k == nil {
		return out
	}
	out.ArchivedCount, out.FailedCount, out.LastFailedTime = k.st.Uploaded, k.st.Failed, k.st.LastFailedAt
	last := k.st.LastTxnAt
	if c := k.st.CaughtUpAt; c != nil && (last == nil || c.After(*last)) {
		last = c
	}
	out.LastArchivedTime = last
	switch {
	case s.off != "":
	case k.st.LastError != "":
		out.Error = k.st.LastError
	case s.err != nil:
		out.Error = s.err.Error()
	}
	return out
}

// lag is how old the oldest committed change not yet in the primary
// bucket is (0 when caught up).
func (s *shipper) lag() time.Duration {
	s.mu.Lock()
	k := s.sinks[sinkPrimary]
	acked := int64(0)
	if k != nil {
		acked = k.st.Acked
	}
	s.mu.Unlock()
	oldest := time.Time{}
	for _, c := range s.sp.after(acked) {
		oldest = c.Hdr.t0()
		break
	}
	if o := s.sp.oldestOpenAt(); !o.IsZero() && (oldest.IsZero() || o.Before(oldest)) {
		oldest = o
	}
	if oldest.IsZero() {
		return 0
	}
	return time.Since(oldest)
}

var errNoShipper = errors.New("no change copier for this database")
