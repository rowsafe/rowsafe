package sqlite

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/protocol"
)

// Continuous archiving for SQLite in WAL mode (restores to any second),
// the technique Litestream made known (github.com/benbjohnson/litestream,
// Apache-2.0), reimplemented for Rowsafe's encryption and buckets:
//
//   - The shipper keeps a read transaction open on its own connection (R).
//     While a reader uses the WAL, SQLite never restarts the WAL file from
//     its beginning, so frames the shipper hasn't copied yet can't be
//     overwritten; the app's checkpoints still copy frames into the
//     database file up to R's snapshot.
//   - Every 250 ms it reads the -shm header: when more frames are
//     committed, it copies them (whole transactions, checksums verified)
//     into the local spool, time-stamped; every few seconds the spool's
//     chunk becomes an encrypted segment in each bucket (sinks).
//   - Every 10 s, or after 1,000 new frames, a "window": it takes SQLite's
//     write lock for a few milliseconds (BEGIN IMMEDIATE on a second
//     connection, W), reads what's left up to the last committed frame,
//     renews R's snapshot there, lets go of the lock and runs a PASSIVE
//     checkpoint (never waits, never blocks the app). The WAL can then be
//     reset by the app's next write, but only once every frame in it has
//     been copied: R, renewed under the write lock, either holds a read
//     mark (no reset at all) or, if the WAL was fully checkpointed, read
//     lock 0, which also stops any further checkpoint until the next
//     window. A WAL reset seen while R has been held since a window is
//     therefore a clean continuation (the next "W": frames count from 1).
//   - Anything else breaks the chain: a reset while R wasn't held (agent
//     restart, a long write lock it yielded to), a replaced file, frames
//     that don't verify. The shipper then starts a new generation from the
//     current position and takes a fresh full copy by itself.
//
// The write lock is only ever tried for 100 ms at a time; if the app holds
// it for over 2 s (a long transaction, or the app's own RESTART/TRUNCATE
// checkpoint waiting for R), the shipper lets go of R briefly so the app
// can carry on, and treats a reset that follows as a break.

var (
	pollInterval   = 250 * time.Millisecond
	windowInterval = 10 * time.Second
	windowFrames   = uint32(1000)
	yieldAfter     = 2 * time.Second
	yieldEvery     = 30 * time.Second
	maxChunkBytes  = int64(16 << 20)
	attachRetry    = 5 * time.Second
	identityEvery  = 5 * time.Second
	autoSnapEvery  = 15 * time.Minute
)

// segmentInterval is how often a segment is cut while the database changes
// (ROWSAFE_SQLITE_SEGMENT_INTERVAL, 1s to 60s, default 5s).
func segmentInterval() time.Duration {
	if v := os.Getenv("ROWSAFE_SQLITE_SEGMENT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second && d <= time.Minute {
			return d
		}
	}
	return 5 * time.Second
}

// shipState is what the shipper saved (<state>/<stanza>/stream.json): the
// position after the last transaction safely in the spool.
type shipState struct {
	Gen        string    `json:"gen,omitempty"`
	GenStarted time.Time `json:"gen_started"`
	GenReason  string    `json:"gen_reason,omitempty"`
	W          int       `json:"w"`
	Salt       string    `json:"salt,omitempty"` // hex of the WAL's 8 salt bytes
	Frame      uint32    `json:"frame"`
	Ck1        uint32    `json:"ck1"`
	Ck2        uint32    `json:"ck2"`
	PageSize   int       `json:"page_size"`
	Seq        int64     `json:"seq"` // the next segment's number in Gen
	Dev        uint64    `json:"dev,omitempty"`
	Ino        uint64    `json:"ino,omitempty"`
	// NeedSnapshot: the generation started after a break and has no full
	// copy yet; the shipper takes one by itself.
	NeedSnapshot bool       `json:"need_snapshot,omitempty"`
	Breaks       int64      `json:"breaks"`
	LastBreakAt  *time.Time `json:"last_break_at,omitempty"`
	LastBreak    string     `json:"last_break,omitempty"`
}

func (st shipState) pos() pos { return pos{W: st.W, Frame: st.Frame} }

// shipReq is work for the shipper's goroutine.
type shipReq struct {
	kind string // "flush", "snapshot", "truncate"
	done chan shipRes
	conn *sqlite3.Conn // snapshot: the connection that gets the read transaction
}

type shipRes struct {
	gen   string
	pos   pos
	at    time.Time
	chunk int64 // the spool chunk holding the position (0: none needed)
	note  string
	err   error
}

type shipper struct {
	e    *Engine
	id   string // the database's id (the first storage's)
	dir  string // <state root>/<stanza>
	path string // as configured
	real string // with symbolic links resolved (attach)
	sp   *spool
	busy *busyCount

	mu       sync.Mutex
	db       protocol.DatabaseSpec
	st       shipState
	sinks    map[string]*sink
	err      error  // the newest problem (nil after a good round)
	off      string // why copying is off ("": on)
	lastPoll time.Time
	lastSeen time.Time
	lastCkpt ckptResult
	walSizes []int64 // -wal size after recent windows (monitoring)
	autoSnap time.Time
	snapping bool
	log      *slog.Logger

	reqs chan shipReq
	ctx  context.Context
	stop context.CancelFunc
	done chan struct{}

	// owned by the run goroutine
	r, w          *sqlite3.Conn
	held          bool
	lastWindow    time.Time
	sinceWindow   uint32
	lockFailSince time.Time
	lastYield     time.Time
	lastAttempt   time.Time
	lastIdentity  time.Time
	lastProbe     time.Time
}

type ckptResult struct {
	At       time.Time
	Log      int
	Ckpt     int
	Complete bool
}

func newGenName(t time.Time) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return t.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// file is the database's real path (its -wal and -shm are next to it).
func (s *shipper) file() string {
	if s.real != "" {
		return s.real
	}
	return s.path
}

func (s *shipper) statePath() string { return filepath.Join(s.dir, "stream.json") }

func (s *shipper) logger() *slog.Logger {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log
}

// loadState reads the saved position and carries it forward over spool
// chunks completed after it was saved.
func (s *shipper) loadState() error {
	var st shipState
	if err := loadJSONFile(s.statePath(), &st); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if ch := s.sp.after(0); len(ch) > 0 {
		h := ch[len(ch)-1].Hdr
		if h.Gen == st.Gen && h.Seq >= st.Seq && len(h.Txns) > 0 {
			st.W, st.Salt, st.Frame = h.W, h.Salt, h.Txns[len(h.Txns)-1].Last
			st.Ck1, st.Ck2, st.Seq = h.EndCk1, h.EndCk2, h.Seq+1
		}
	}
	s.st = st
	return nil
}

func (s *shipper) saveState() error {
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	return saveJSONFile(s.statePath(), st)
}

func (s *shipper) setErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

func (s *shipper) setOff(why string) {
	s.mu.Lock()
	s.off = why
	s.mu.Unlock()
}

// run is the shipper's goroutine.
func (s *shipper) run() {
	defer close(s.done)
	defer s.detach()
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case req := <-s.reqs:
			s.handle(req)
		case <-t.C:
			s.step()
		}
	}
}

func (s *shipper) detach() {
	if s.r != nil {
		rollback(s.r)
		s.r.Close()
		s.r = nil
	}
	if s.w != nil {
		rollback(s.w)
		s.w.Close()
		s.w = nil
	}
	s.held = false
	s.sp.discardOpen()
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	// Back to the last position in a complete chunk.
	if ch := s.sp.after(0); len(ch) > 0 {
		h := ch[len(ch)-1].Hdr
		if h.Gen == st.Gen && len(h.Txns) > 0 {
			st.W, st.Salt, st.Frame, st.Ck1, st.Ck2, st.Seq = h.W, h.Salt, h.Txns[len(h.Txns)-1].Last, h.EndCk1, h.EndCk2, h.Seq+1
		}
	}
	var saved shipState
	if loadJSONFile(s.statePath(), &saved) == nil && saved.Gen == st.Gen && saved.pos().Compare(st.pos()) > 0 {
		st = saved
	}
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
}

func (s *shipper) step() {
	if s.r == nil {
		if time.Since(s.lastAttempt) < attachRetry {
			return
		}
		s.lastAttempt = time.Now()
		if err := s.attach(); err != nil {
			s.setErr(err)
		}
		return
	}
	if time.Since(s.lastIdentity) >= identityEvery {
		s.lastIdentity = time.Now()
		if why := s.changedFile(); why != "" {
			s.logger().Warn("SQLite database changed under the shipper; attaching again", "path", s.path, "why", why)
			s.detach()
			return
		}
	}
	if err := s.poll(); err != nil {
		s.setErr(err)
		return
	}
	if err := s.maybeCut(false); err != nil {
		s.setErr(err)
		return
	}
	s.enforceSpoolLimit()
	switch {
	case s.sinceWindow >= windowFrames || (s.sinceWindow > 0 && time.Since(s.lastWindow) >= windowInterval) ||
		(!s.held && time.Since(s.lastWindow) >= time.Second):
		s.window()
	case time.Since(s.lastProbe) >= time.Second:
		// Nothing new: is the app holding the write lock without
		// writing (its own RESTART/TRUNCATE checkpoint waiting for R)?
		s.lastProbe = time.Now()
		s.probe()
	}
	s.mu.Lock()
	need := s.st.NeedSnapshot && !s.snapping && time.Since(s.autoSnap) >= autoSnapEvery && s.held
	s.mu.Unlock()
	if need {
		s.startAutoSnapshot()
	}
}

// attach opens R and W on a WAL database.
func (s *shipper) attach() error {
	if rp, err := realPath(s.path); err == nil {
		s.real = rp
	}
	h, fi, err := readDBHeader(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the database file %s doesn't exist (moved or deleted?)", s.path)
		}
		return err
	}
	if !h.WAL {
		s.setOff("the database is in rollback-journal mode, so only its backups can be restored (turn on continuous backups: WAL)")
		s.setErr(nil)
		return nil
	}
	if fs := networkFS(filepath.Dir(s.file())); fs != "" {
		return fmt.Errorf("the database is on a network filesystem (%s): SQLite's locking isn't reliable there, so Rowsafe doesn't copy its changes", fs)
	}
	r, err := openDB(s.ctx, s.path, openOpts{Busy: time.Second})
	if err != nil {
		return err
	}
	w, err := openDB(s.ctx, s.path, openOpts{Busy: 100 * time.Millisecond})
	if err != nil {
		r.Close()
		return err
	}
	if m, err := journalMode(r); err != nil || m != "wal" {
		r.Close()
		w.Close()
		if err != nil {
			s.busy.note(err)
			return err
		}
		s.setOff("the database is in " + m + " journal mode, so only its backups can be restored (turn on continuous backups: WAL)")
		s.setErr(nil)
		return nil
	}
	if err := beginRead(r); err != nil {
		s.busy.note(err)
		r.Close()
		w.Close()
		return err
	}
	s.r, s.w, s.held = r, w, false
	s.setOff("")
	dev, ino := fileID(fi)
	s.mu.Lock()
	if s.st.Gen != "" && s.st.Ino != 0 && (s.st.Dev != dev || s.st.Ino != ino) {
		s.st.Salt = "replaced" // never matches: the next poll starts a new generation
	}
	s.mu.Unlock()
	s.lastIdentity = time.Now()
	return nil
}

// changedFile says why the open database is no longer the file at path
// (replaced, deleted, out of WAL mode), or "".
func (s *shipper) changedFile() string {
	h, fi, err := readDBHeader(s.path)
	if err != nil {
		return err.Error()
	}
	if !h.WAL {
		return "it left WAL mode"
	}
	dev, ino := fileID(fi)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Ino != 0 && (s.st.Dev != dev || s.st.Ino != ino) {
		return "the file was replaced"
	}
	return ""
}

func fileID(fi os.FileInfo) (uint64, uint64) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev), uint64(st.Ino)
	}
	return 0, 0
}

// poll reads the transactions committed since the last position.
func (s *shipper) poll() error {
	hdr, err := readShmHeader(s.file())
	if err != nil {
		return fmt.Errorf("reading SQLite's -shm file: %w", err)
	}
	salt := hex.EncodeToString(hdr.Salt[:])
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	switch {
	case st.Gen == "":
		return s.newGeneration(hdr, "", false)
	case salt != st.Salt:
		if !s.held {
			why := "the -wal file was reset while Rowsafe wasn't reading it (the agent was stopped, or your app held the write lock for long)"
			if st.Salt == "replaced" {
				why = "the database file was replaced"
			}
			return s.newGeneration(hdr, why, true)
		}
		// A clean reset: every frame of the previous WAL is copied.
		if err := s.maybeCut(true); err != nil {
			return err
		}
		s.mu.Lock()
		s.st.W++
		s.st.Salt, s.st.Frame, s.st.Ck1, s.st.Ck2 = salt, 0, 0, 0
		st = s.st
		s.mu.Unlock()
	case hdr.MaxFrame < st.Frame:
		return s.newGeneration(hdr, "the -wal file is shorter than what Rowsafe already copied", true)
	}
	if hdr.MaxFrame == st.Frame {
		s.mu.Lock()
		s.lastPoll = time.Now()
		s.err = nil
		s.mu.Unlock()
		return nil
	}
	return s.scan(st, hdr)
}

// scan copies frames st.Frame+1..hdr.MaxFrame into the spool.
func (s *shipper) scan(st shipState, hdr shmHeader) error {
	f, err := os.Open(s.file() + "-wal")
	if err != nil {
		return err
	}
	defer f.Close()
	hb := make([]byte, walHeaderSize)
	if _, err := f.ReadAt(hb, 0); err != nil {
		return fmt.Errorf("reading the -wal file's header: %w", err)
	}
	wh, err := parseWALHeader(hb)
	if err != nil {
		return err
	}
	if hex.EncodeToString(hb[16:24]) != st.Salt {
		return nil // the header isn't rewritten yet (a reset in progress): next round
	}
	if st.PageSize != 0 && wh.PageSize != st.PageSize {
		return s.newGeneration(hdr, "the database's page size changed", true)
	}
	ck1, ck2 := st.Ck1, st.Ck2
	if st.Frame == 0 {
		ck1, ck2 = wh.Cksum1, wh.Cksum2
	}
	frameSize := walFrameHeaderSize + wh.PageSize
	buf := make([]byte, frameSize)
	seg := segHeader{Gen: st.Gen, Seq: st.Seq, W: st.W, PageSize: wh.PageSize, Salt: st.Salt}
	first := st.Frame + 1
	for n := st.Frame + 1; n <= hdr.MaxFrame; n++ {
		if _, err := f.ReadAt(buf, int64(walHeaderSize)+int64(n-1)*int64(frameSize)); err != nil {
			_ = s.sp.abortPartial()
			return fmt.Errorf("reading frame %d of the -wal file: %w", n, err)
		}
		fh := parseFrameHeader(buf)
		c1, c2 := walChecksum(wh.BigEndian, buf[:8], ck1, ck2)
		c1, c2 = walChecksum(wh.BigEndian, buf[walFrameHeaderSize:], c1, c2)
		if fh.Salt1 != wh.Salt1 || fh.Salt2 != wh.Salt2 || c1 != fh.Cksum1 || c2 != fh.Cksum2 || fh.Pgno == 0 {
			_ = s.sp.abortPartial()
			if !s.held {
				return s.newGeneration(hdr, fmt.Sprintf("frame %d of the -wal file doesn't continue what Rowsafe copied", n), true)
			}
			return fmt.Errorf("frame %d of the -wal file doesn't verify yet; reading it again", n)
		}
		ck1, ck2 = c1, c2
		if err := s.sp.appendFrame(seg, buf); err != nil {
			_ = s.sp.abortPartial()
			return err
		}
		if fh.Commit == 0 {
			continue
		}
		s.sp.commit(segTxn{First: first, Last: n, Commit: fh.Commit, At: time.Now().UnixMilli()}, ck1, ck2)
		s.mu.Lock()
		s.st.Frame, s.st.Ck1, s.st.Ck2, s.st.PageSize = n, ck1, ck2, wh.PageSize
		s.mu.Unlock()
		s.sinceWindow += n - first + 1
		first = n + 1
		if b, _, _ := s.sp.openInfo(); b >= maxChunkBytes {
			if err := s.maybeCut(true); err != nil {
				return err
			}
			s.mu.Lock()
			seg.Seq = s.st.Seq
			s.mu.Unlock()
		}
	}
	if first != hdr.MaxFrame+1 {
		_ = s.sp.abortPartial()
		return fmt.Errorf("the -wal file's last committed frame (%d) isn't a commit; reading it again", hdr.MaxFrame)
	}
	s.mu.Lock()
	s.lastPoll = time.Now()
	s.err = nil
	s.mu.Unlock()
	return nil
}

// maybeCut completes the spool's open chunk when it is due (or now).
func (s *shipper) maybeCut(now bool) error {
	b, since, txns := s.sp.openInfo()
	if txns == 0 || (!now && b < maxChunkBytes && time.Since(since) < segmentInterval()) {
		return nil
	}
	c, ok, err := s.sp.cut()
	if err != nil || !ok {
		return err
	}
	s.mu.Lock()
	s.st.Seq = c.Hdr.Seq + 1
	s.mu.Unlock()
	if err := s.saveState(); err != nil {
		return err
	}
	s.wakeSinks()
	return nil
}

// newGeneration starts a new stream at the WAL's current end.
func (s *shipper) newGeneration(hdr shmHeader, reason string, isBreak bool) error {
	if s.r == nil {
		return errors.New("not attached")
	}
	_ = s.sp.abortPartial()
	if err := s.maybeCut(true); err != nil {
		return err
	}
	ck1, ck2, ps, err := walChainAt(s.file(), hdr)
	if err != nil {
		return err
	}
	_, fi, err := readDBHeader(s.path)
	if err != nil {
		return err
	}
	dev, ino := fileID(fi)
	now := time.Now().UTC()
	s.mu.Lock()
	prev := s.st
	st := shipState{Gen: newGenName(now), GenStarted: now, GenReason: reason, Salt: hex.EncodeToString(hdr.Salt[:]),
		Frame: hdr.MaxFrame, Ck1: ck1, Ck2: ck2, PageSize: ps, Seq: 1, Dev: dev, Ino: ino,
		NeedSnapshot: isBreak || prev.NeedSnapshot, Breaks: prev.Breaks, LastBreakAt: prev.LastBreakAt, LastBreak: prev.LastBreak}
	if isBreak {
		st.Breaks++
		st.LastBreakAt, st.LastBreak = &now, reason
	}
	s.st = st
	log := s.log
	s.mu.Unlock()
	if isBreak {
		log.Warn("SQLite change stream broken; starting a new one with a fresh full copy", "path", s.path, "why", reason)
	}
	return s.saveState()
}

// walChainAt verifies the WAL up to hdr.MaxFrame and returns the
// cumulative checksum after it (the header's when there are no frames)
// and the page size.
func walChainAt(path string, hdr shmHeader) (uint32, uint32, int, error) {
	f, err := os.Open(path + "-wal")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && hdr.MaxFrame == 0 {
			return 0, 0, hdr.PageSize, nil
		}
		return 0, 0, 0, err
	}
	defer f.Close()
	hb := make([]byte, walHeaderSize)
	if _, err := f.ReadAt(hb, 0); err != nil {
		if hdr.MaxFrame == 0 {
			return 0, 0, hdr.PageSize, nil
		}
		return 0, 0, 0, err
	}
	wh, err := parseWALHeader(hb)
	if err != nil {
		if hdr.MaxFrame == 0 {
			return 0, 0, hdr.PageSize, nil
		}
		return 0, 0, 0, err
	}
	if string(hb[16:24]) != string(hdr.Salt[:]) {
		if hdr.MaxFrame == 0 {
			return 0, 0, hdr.PageSize, nil // the header is rewritten with the first frame
		}
		return 0, 0, 0, errors.New("the -wal file's header doesn't match its index yet")
	}
	if hdr.MaxFrame == 0 {
		return wh.Cksum1, wh.Cksum2, wh.PageSize, nil
	}
	_, last, c1, c2, err := walScan(f, wh, 0, wh.Cksum1, wh.Cksum2, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	if last < hdr.MaxFrame {
		return 0, 0, 0, fmt.Errorf("the -wal file holds %d verified frames, its index says %d", last, hdr.MaxFrame)
	}
	if last > hdr.MaxFrame {
		// Count only up to the committed end the index names.
		_, _, c1, c2, err = walScanTo(f, wh, hdr.MaxFrame)
		if err != nil {
			return 0, 0, 0, err
		}
	}
	return c1, c2, wh.PageSize, nil
}

// walScanTo is the cumulative checksum after frame `to`.
func walScanTo(r io.ReaderAt, h walHeader, to uint32) (uint32, uint32, uint32, uint32, error) {
	frameSize := walFrameHeaderSize + h.PageSize
	buf := make([]byte, frameSize)
	s1, s2 := h.Cksum1, h.Cksum2
	for n := uint32(1); n <= to; n++ {
		if _, err := r.ReadAt(buf, int64(walHeaderSize)+int64(n-1)*int64(frameSize)); err != nil {
			return 0, 0, 0, 0, err
		}
		s1, s2 = walChecksum(h.BigEndian, buf[:8], s1, s2)
		s1, s2 = walChecksum(h.BigEndian, buf[walFrameHeaderSize:], s1, s2)
	}
	return to, 0, s1, s2, nil
}

// ckptUnderLock: a window checkpoints while it holds the write lock (so
// the WAL can be reset by the app's next write) only when this few frames
// wait; more are checkpointed after it lets go, and the rest next time.
const ckptUnderLock = 4096

// window renews R's snapshot under SQLite's write lock (see the package
// comment) and checkpoints what's copied. It reports whether it ran.
func (s *shipper) window() bool {
	if err := s.w.Exec(`BEGIN IMMEDIATE`); err != nil {
		s.busy.note(err)
		if !isBusy(err) {
			s.setErr(err)
			s.detach()
			return false
		}
		if s.lockFailSince.IsZero() {
			s.lockFailSince = time.Now()
		}
		if time.Since(s.lockFailSince) > yieldAfter && time.Since(s.lastYield) > yieldEvery {
			s.yield()
		}
		return false
	}
	s.lockFailSince = time.Time{}
	return s.windowLocked(nil) == nil
}

// windowLocked is a window's work once W holds the write lock (it lets go
// of it): every committed frame is read, the frames are checkpointed when
// few, conn (when not nil) gets a read transaction at this exact point, R
// is renewed, the lock released, and the rest checkpointed.
func (s *shipper) windowLocked(conn *sqlite3.Conn) error {
	err := s.poll()
	if err == nil && conn != nil {
		err = beginRead(conn)
	}
	var ck ckptResult
	if err == nil {
		rollback(s.r)
		s.held = false
		if s.sinceWindow <= ckptUnderLock {
			// Nothing can be written meanwhile and R doesn't hold an old
			// snapshot: the checkpoint can take every frame, and the
			// app's next write then starts the WAL over.
			nl, nc, cerr := s.r.WALCheckpoint("main", sqlite3.CHECKPOINT_PASSIVE)
			s.busy.note(cerr)
			ck = ckptResult{At: time.Now(), Log: nl, Ckpt: nc, Complete: cerr == nil && nl == nc}
		}
		if err = beginRead(s.r); err == nil {
			s.held = true
		}
	}
	rollback(s.w)
	if err != nil {
		if conn != nil {
			rollback(conn)
		}
		s.busy.note(err)
		s.setErr(err)
		if !s.held {
			s.detach()
		}
		return err
	}
	if !ck.Complete {
		// Up to R's snapshot, without the write lock.
		nl, nc, cerr := s.w.WALCheckpoint("main", sqlite3.CHECKPOINT_PASSIVE)
		s.busy.note(cerr)
		ck = ckptResult{At: time.Now(), Log: nl, Ckpt: nc, Complete: cerr == nil && nl == nc}
	}
	wal := fileSize(s.file() + "-wal")
	s.mu.Lock()
	s.lastCkpt = ck
	s.walSizes = append(s.walSizes, wal)
	if len(s.walSizes) > 12 {
		s.walSizes = s.walSizes[len(s.walSizes)-12:]
	}
	s.mu.Unlock()
	s.lastWindow, s.sinceWindow = time.Now(), 0
	return nil
}

// probe takes the write lock for an instant (nothing is written): when
// the app has held it for over yieldAfter without writing, the shipper
// yields.
func (s *shipper) probe() {
	err := s.w.Exec(`BEGIN IMMEDIATE`)
	if err == nil {
		rollback(s.w)
		s.lockFailSince = time.Time{}
		return
	}
	if !isBusy(err) {
		s.setErr(err)
		s.detach()
		return
	}
	if s.lockFailSince.IsZero() {
		s.lockFailSince = time.Now()
	}
	if time.Since(s.lockFailSince) > yieldAfter && time.Since(s.lastYield) > yieldEvery {
		s.yield()
	}
}

// yield lets go of R: the app has held the write lock for over yieldAfter
// (a long transaction, or its own RESTART/TRUNCATE checkpoint waiting for
// readers). The shipper takes the write lock as soon as the app lets go of
// it (at most 10 s later) and renews R there; a WAL reset meanwhile starts
// a new generation.
func (s *shipper) yield() {
	s.lastYield = time.Now()
	_ = s.poll()
	_ = s.maybeCut(true)
	rollback(s.r)
	s.held = false
	s.logger().Info("letting go of SQLite's WAL: the app holds the write lock", "path", s.path)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if s.ctx.Err() != nil {
			return
		}
		if err := s.w.Exec(`BEGIN IMMEDIATE`); err == nil {
			_ = s.windowLocked(nil)
			return
		} else if !isBusy(err) {
			break
		}
	}
	if err := beginRead(s.r); err != nil {
		s.busy.note(err)
		s.detach()
		return
	}
	_ = s.poll()
}

func (s *shipper) handle(req shipReq) {
	var res shipRes
	switch req.kind {
	case "flush":
		res = s.flushNow()
	case "snapshot":
		res = s.snapshotNow(req.conn)
	case "truncate":
		res = s.truncateNow()
	default:
		res.err = fmt.Errorf("unknown request %q", req.kind)
	}
	req.done <- res
}

// lockWrite takes SQLite's write lock on W, trying for up to d (100 ms at
// a time, so the app's writers never wait long).
func (s *shipper) lockWrite(d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		err := s.w.Exec(`BEGIN IMMEDIATE`)
		if err == nil {
			return nil
		}
		s.busy.note(err)
		if !isBusy(err) || time.Now().After(deadline) {
			if isBusy(err) {
				return errors.New("the app held SQLite's write lock the whole time; try again in a moment")
			}
			return err
		}
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// flushNow reads every committed transaction (under the write lock: the
// exact end), completes the chunk and says where the stream stands.
func (s *shipper) flushNow() shipRes {
	if s.r == nil {
		if err := s.attach(); err != nil || s.r == nil {
			return shipRes{err: s.notCopyingErr(err)}
		}
	}
	if err := s.lockWrite(10 * time.Second); err != nil {
		return shipRes{err: err}
	}
	if err := s.windowLocked(nil); err != nil {
		return shipRes{err: err}
	}
	if err := s.maybeCut(true); err != nil {
		return shipRes{err: err}
	}
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	return shipRes{gen: st.Gen, pos: st.pos(), at: time.Now().UTC(), chunk: s.sp.last()}
}

// snapshotNow gives conn a read transaction at the stream's exact current
// position (under the write lock), for a full copy.
func (s *shipper) snapshotNow(conn *sqlite3.Conn) shipRes {
	if s.r == nil {
		if err := s.attach(); err != nil || s.r == nil {
			return shipRes{err: s.notCopyingErr(err)}
		}
	}
	if err := s.lockWrite(10 * time.Second); err != nil {
		return shipRes{err: err}
	}
	at := time.Now().UTC()
	if err := s.windowLocked(conn); err != nil {
		return shipRes{err: err}
	}
	_ = s.maybeCut(true)
	s.mu.Lock()
	st := s.st
	s.mu.Unlock()
	return shipRes{gen: st.Gen, pos: st.pos(), at: at}
}

// truncateNow copies everything, checkpoints and shrinks the -wal file
// (TRUNCATE), then starts a new generation: between letting go of R and
// the truncation, a transaction of the app could slip in uncopied.
func (s *shipper) truncateNow() shipRes {
	if s.r == nil {
		return shipRes{err: s.notCopyingErr(nil)}
	}
	before := fileSize(s.file() + "-wal")
	if err := s.lockWrite(10 * time.Second); err != nil {
		return shipRes{err: err}
	}
	err := s.poll()
	rollback(s.w)
	if err != nil {
		return shipRes{err: err}
	}
	if err := s.maybeCut(true); err != nil {
		return shipRes{err: err}
	}
	rollback(s.r)
	s.held = false
	_ = s.w.BusyTimeout(3 * time.Second)
	nLog, nCkpt, cerr := s.w.WALCheckpoint("main", sqlite3.CHECKPOINT_TRUNCATE)
	_ = s.w.BusyTimeout(100 * time.Millisecond)
	if err := beginRead(s.r); err != nil {
		s.detach()
		return shipRes{err: err}
	}
	after := fileSize(s.file() + "-wal")
	res := shipRes{}
	switch {
	case cerr != nil && isBusy(cerr):
		s.busy.note(cerr)
		res.note = fmt.Sprintf("Copied the waiting changes into the database file (%d of %d pages), but couldn't shrink the -wal file: "+
			"your app keeps a transaction or a read open. It shrinks once that ends.", max(nCkpt, 0), max(nLog, 0))
	case cerr != nil:
		res.err = cerr
	default:
		res.note = fmt.Sprintf("Copied the waiting changes into the database file and shrank the -wal file from %s to %s.",
			humanBytes(before), humanBytes(after))
	}
	// The WAL may have been reset without R: start again, with a full copy.
	if hdr, herr := readShmHeader(s.file()); herr == nil {
		s.held = true // R is renewed and the stream restarts here
		if gerr := s.newGeneration(hdr, "the -wal file was shrunk", true); gerr != nil && res.err == nil {
			res.err = gerr
		}
		s.mu.Lock()
		s.autoSnap = time.Time{}
		s.mu.Unlock()
	}
	s.lastWindow = time.Now()
	return res
}

func (s *shipper) notCopyingErr(err error) error {
	s.mu.Lock()
	off := s.off
	s.mu.Unlock()
	if off != "" {
		return errors.New(off)
	}
	if err != nil {
		return err
	}
	return errors.New("Rowsafe isn't copying this database's changes right now")
}

// request hands work to the shipper's goroutine and waits.
func (s *shipper) request(ctx context.Context, kind string, conn *sqlite3.Conn) shipRes {
	req := shipReq{kind: kind, done: make(chan shipRes, 1), conn: conn}
	select {
	case s.reqs <- req:
	case <-ctx.Done():
		return shipRes{err: ctx.Err()}
	case <-s.done:
		return shipRes{err: errors.New("the change copier stopped")}
	}
	select {
	case res := <-req.done:
		return res
	case <-ctx.Done():
		return shipRes{err: ctx.Err()}
	}
}

// flush makes everything committed so far reach the primary bucket (and
// the other sinks), within timeout, and returns where the stream stands.
func (s *shipper) flush(ctx context.Context, timeout time.Duration) (shipRes, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := s.request(ctx, "flush", nil)
	if res.err != nil {
		return res, res.err
	}
	if err := s.waitUploaded(ctx, res.chunk); err != nil {
		return res, err
	}
	return res, nil
}

// waitUploaded waits until every active sink has uploaded spool chunk n.
func (s *shipper) waitUploaded(ctx context.Context, n int64) error {
	for {
		s.mu.Lock()
		done, last := true, ""
		for _, k := range s.sinks {
			if k.active() && k.st.Acked < n {
				done = false
				last = k.st.LastError
			}
		}
		s.mu.Unlock()
		if done {
			return nil
		}
		s.wakeSinks()
		select {
		case <-ctx.Done():
			if last != "" {
				return fmt.Errorf("the newest changes haven't reached your bucket: %s", last)
			}
			return errors.New("the newest changes haven't reached your bucket yet")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// enforceSpoolLimit drops the oldest chunks past the spool's limit (a
// bucket unreachable for long); buckets that hadn't received them restart
// with a fresh copy.
func (s *shipper) enforceSpoolLimit() {
	if s.sp.size() <= 16<<20 {
		return
	}
	limit := spoolLimit(s.sp.dir)
	if s.sp.size() <= limit {
		return
	}
	var dropped int64
	for s.sp.size() > limit {
		o := s.sp.oldest()
		if o == 0 {
			break
		}
		s.sp.trim(o)
		dropped = o
	}
	if dropped == 0 {
		return
	}
	primaryMissed := false
	s.mu.Lock()
	for name, k := range s.sinks {
		if k.st.Acked < dropped {
			k.st.Acked, k.st.Missed = dropped, true
			k.st.LastError = "changes waited on this server longer than it has room for and were dropped; Rowsafe takes a fresh full copy"
			if name == sinkPrimary {
				primaryMissed = true
			}
		}
	}
	s.mu.Unlock()
	s.saveSinks()
	s.logger().Warn("SQLite changes waited too long for the bucket; dropped the oldest from this server", "path", s.path)
	if primaryMissed {
		if hdr, err := readShmHeader(s.file()); err == nil && s.r != nil {
			_ = s.newGeneration(hdr, "your bucket was unreachable for longer than this server could keep the changes", true)
		}
	}
}

// spoolLimit: the spool may use up to ROWSAFE_SQLITE_SPOOL_MAX (default 2
// GiB), and never more than a quarter of the free space where it is.
func spoolLimit(dir string) int64 {
	limit := int64(2 << 30)
	if v := os.Getenv("ROWSAFE_SQLITE_SPOOL_MAX"); v != "" {
		if n, err := parseSize(v); err == nil && n >= 16<<20 {
			limit = n
		}
	}
	if _, free, err := diskSpace(dir); err == nil && free/4 < limit {
		limit = max(free/4, 16<<20)
	}
	return limit
}

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"GIB", 1 << 30}, {"MIB", 1 << 20}, {"KIB", 1 << 10}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"G", 1 << 30}, {"M", 1 << 20}, {"K", 1 << 10}} {
		if strings.HasSuffix(s, u.suf) {
			s, mult = strings.TrimSuffix(s, u.suf), u.m
			break
		}
	}
	var n int64
	if _, err := fmt.Sscan(s, &n); err != nil {
		return 0, err
	}
	return n * mult, nil
}

// startAutoSnapshot takes the full copy a new generation needs, in the
// background, into every bucket.
func (s *shipper) startAutoSnapshot() {
	s.mu.Lock()
	s.snapping, s.autoSnap = true, time.Now()
	sinks := make([]*sink, 0, len(s.sinks))
	for _, k := range s.sinks {
		if k.active() {
			sinks = append(sinks, k)
		}
	}
	gen := s.st.Gen
	s.mu.Unlock()
	go func() {
		defer func() {
			s.mu.Lock()
			s.snapping = false
			s.mu.Unlock()
		}()
		ok := len(sinks) > 0
		for _, k := range sinks {
			s.mu.Lock()
			env, db := k.env, k.db
			s.mu.Unlock()
			if _, err := s.e.takeSnapshot(s.ctx, env, db, true, nopLog{}); err != nil {
				ok = false
				s.logger().Warn("taking a fresh full copy of a SQLite database failed; trying again later", "path", s.path, "err", err)
			}
		}
		if ok {
			s.mu.Lock()
			if s.st.Gen == gen {
				s.st.NeedSnapshot = false
			}
			s.mu.Unlock()
			_ = s.saveState()
		}
	}()
}

// snapshotTaken notes a full copy of the current generation (a scheduled
// backup counts).
func (s *shipper) snapshotTaken(gen string) {
	s.mu.Lock()
	changed := s.st.Gen == gen && s.st.NeedSnapshot
	if changed {
		s.st.NeedSnapshot = false
	}
	s.mu.Unlock()
	if changed {
		_ = s.saveState()
	}
}

// nopLog is a TaskLogger that drops everything (background work).
type nopLog struct{}

func (nopLog) Printf(string, ...any) {}
func (nopLog) Output(string, []byte) {}
