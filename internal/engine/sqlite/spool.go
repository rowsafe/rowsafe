package sqlite

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
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
)

// The spool: committed transactions the shipper read from the WAL, on the
// agent's own disk, until every bucket (the first storage and the second
// copy) has them. One chunk per segment: <n>.frames (the frames as SQLite
// wrote them) and <n>.json (what they are), written in that order and
// complete once the .json exists. n numbers chunks across generations.
// The spool is bounded (spoolMax): past it the oldest chunks are dropped
// and the buckets that hadn't received them start again later with a
// fresh full copy.

// segHeader describes a segment's transactions (the .json of a chunk and
// the head of a segment object).
type segHeader struct {
	Gen      string   `json:"gen"`
	Seq      int64    `json:"seq"` // 1, 2, 3... within the generation
	W        int      `json:"w"`
	PageSize int      `json:"page_size"`
	Salt     string   `json:"salt"` // the WAL's salts (hex), for checks
	Txns     []segTxn `json:"txns"`
	// End is the stream position and cumulative checksum after the last
	// frame (the shipper carries on from there after a restart).
	EndCk1 uint32 `json:"end_ck1"`
	EndCk2 uint32 `json:"end_ck2"`
}

// segTxn is one committed transaction in a segment.
type segTxn struct {
	First  uint32 `json:"first"`
	Last   uint32 `json:"last"`
	Commit uint32 `json:"commit"` // database size in pages after it
	At     int64  `json:"at"`     // Unix ms when the agent saw it committed
}

func (h segHeader) frames() int64 {
	if len(h.Txns) == 0 {
		return 0
	}
	return int64(h.Txns[len(h.Txns)-1].Last - h.Txns[0].First + 1)
}

func (h segHeader) t0() time.Time { return time.UnixMilli(h.Txns[0].At).UTC() }
func (h segHeader) t1() time.Time { return time.UnixMilli(h.Txns[len(h.Txns)-1].At).UTC() }

// segMagic starts a segment object's plaintext; then the header's length
// (4 bytes, big-endian), the header (JSON) and the frames.
const segMagic = "RSQLSEG1"

// chunk is a complete chunk in the spool.
type chunk struct {
	N     int64
	Hdr   segHeader
	Bytes int64 // frames' size
}

type spool struct {
	dir string
	mu  sync.Mutex
	// the chunk being built
	open      *os.File
	openHdr   segHeader
	openBytes int64 // committed transactions' frames
	partial   int64 // frames of the transaction being read
	openedAt  time.Time
	next      int64 // the next chunk number
	chunks    []chunk
}

const openName = "open.frames"

func openSpool(dir string) (*spool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &spool{dir: dir, next: 1}
	_ = os.Remove(filepath.Join(dir, openName)) // an interrupted chunk: its frames are read again
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		name := e.Name()
		base, ok := strings.CutSuffix(name, ".json")
		if !ok {
			if b, ok := strings.CutSuffix(name, ".frames"); ok {
				if _, err := os.Stat(filepath.Join(dir, b+".json")); err != nil {
					_ = os.Remove(filepath.Join(dir, name)) // never completed
				}
			}
			if strings.HasSuffix(name, ".tmp") {
				_ = os.Remove(filepath.Join(dir, name))
			}
			continue
		}
		n, err := strconv.ParseInt(base, 10, 64)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		var h segHeader
		fi, ferr := os.Stat(filepath.Join(dir, base+".frames"))
		if json.Unmarshal(data, &h) != nil || ferr != nil || len(h.Txns) == 0 {
			_ = os.Remove(filepath.Join(dir, name))
			_ = os.Remove(filepath.Join(dir, base+".frames"))
			continue
		}
		s.chunks = append(s.chunks, chunk{N: n, Hdr: h, Bytes: fi.Size()})
		s.next = max(s.next, n+1)
	}
	slices.SortFunc(s.chunks, func(a, b chunk) int { return cmpInt(int(a.N), int(b.N)) })
	return s, nil
}

func (s *spool) framesPath(n int64) string {
	return filepath.Join(s.dir, fmt.Sprintf("%016d.frames", n))
}
func (s *spool) jsonPath(n int64) string { return filepath.Join(s.dir, fmt.Sprintf("%016d.json", n)) }

// appendFrame adds one frame (header and page, as in the WAL) of a
// transaction being read to the open chunk, starting one with hdr's
// generation, seq, W and page size when none is open. The frames count
// once commit records their transaction; abortPartial drops them.
func (s *spool) appendFrame(hdr segHeader, frame []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		f, err := os.OpenFile(filepath.Join(s.dir, openName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		s.open, s.openHdr, s.openBytes, s.partial, s.openedAt = f, hdr, 0, 0, time.Now()
		s.openHdr.Txns = nil
	}
	if s.openHdr.Gen != hdr.Gen || s.openHdr.W != hdr.W || s.openHdr.Seq != hdr.Seq {
		return errors.New("spool: a frame for another segment")
	}
	if _, err := s.open.Write(frame); err != nil {
		return err
	}
	s.partial += int64(len(frame))
	return nil
}

// commit records the transaction whose frames were just appended.
func (s *spool) commit(t segTxn, ck1, ck2 uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		return
	}
	s.openBytes += s.partial
	s.partial = 0
	if len(s.openHdr.Txns) == 0 {
		s.openedAt = time.UnixMilli(t.At)
	}
	s.openHdr.Txns = append(s.openHdr.Txns, t)
	s.openHdr.EndCk1, s.openHdr.EndCk2 = ck1, ck2
}

// abortPartial drops the frames appended since the last commit.
func (s *spool) abortPartial() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil || s.partial == 0 {
		return nil
	}
	s.partial = 0
	if err := s.open.Truncate(s.openBytes); err != nil {
		return err
	}
	_, err := s.open.Seek(s.openBytes, io.SeekStart)
	return err
}

// openInfo is the open chunk's size and age (0 when none is open).
func (s *spool) openInfo() (bytes int64, since time.Time, txns int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		return 0, time.Time{}, 0
	}
	return s.openBytes, s.openedAt, len(s.openHdr.Txns)
}

// oldestOpenAt is when the oldest transaction not yet in a complete chunk
// was seen (zero when none).
func (s *spool) oldestOpenAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil || len(s.openHdr.Txns) == 0 {
		return time.Time{}
	}
	return time.UnixMilli(s.openHdr.Txns[0].At)
}

// cut completes the open chunk (synced to disk) and returns it; ok is
// false when nothing was open.
func (s *spool) cut() (chunk, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open == nil {
		return chunk{}, false, nil
	}
	if s.partial != 0 {
		return chunk{}, false, errors.New("spool: cut in the middle of a transaction")
	}
	f, h, size := s.open, s.openHdr, s.openBytes
	s.open = nil
	if len(h.Txns) == 0 {
		f.Close()
		_ = os.Remove(f.Name())
		return chunk{}, false, nil
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return chunk{}, false, err
	}
	if err := f.Close(); err != nil {
		return chunk{}, false, err
	}
	n := s.next
	if err := os.Rename(f.Name(), s.framesPath(n)); err != nil {
		return chunk{}, false, err
	}
	data, _ := json.Marshal(h)
	if err := writeFileSync(s.jsonPath(n), data); err != nil {
		_ = os.Remove(s.framesPath(n))
		return chunk{}, false, err
	}
	syncDir(s.dir)
	s.next = n + 1
	c := chunk{N: n, Hdr: h, Bytes: size}
	s.chunks = append(s.chunks, c)
	return c, true, nil
}

// discardOpen drops the open chunk (its transactions are read again).
func (s *spool) discardOpen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.open != nil {
		s.open.Close()
		_ = os.Remove(s.open.Name())
		s.open, s.partial, s.openBytes = nil, 0, 0
	}
}

// after returns the complete chunks numbered above n, in order.
func (s *spool) after(n int64) []chunk {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []chunk
	for _, c := range s.chunks {
		if c.N > n {
			out = append(out, c)
		}
	}
	return out
}

// last is the newest complete chunk's number (0 when none was ever cut in
// this spool's life and none is kept).
func (s *spool) last() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.next - 1
}

// size is the bytes the spool holds.
func (s *spool) size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.openBytes + s.partial
	for _, c := range s.chunks {
		n += c.Bytes
	}
	return n
}

// trim removes the chunks numbered n and below.
func (s *spool) trim(n int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	keep := s.chunks[:0]
	for _, c := range s.chunks {
		if c.N <= n {
			_ = os.Remove(s.jsonPath(c.N))
			_ = os.Remove(s.framesPath(c.N))
			continue
		}
		keep = append(keep, c)
	}
	s.chunks = keep
}

// oldest is the oldest kept chunk's number (0 when none).
func (s *spool) oldest() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.chunks) == 0 {
		return 0
	}
	return s.chunks[0].N
}

// reader streams a chunk as a segment object's plaintext.
func (s *spool) reader(c chunk) (io.ReadCloser, error) {
	f, err := os.Open(s.framesPath(c.N))
	if err != nil {
		return nil, err
	}
	hdr, _ := json.Marshal(c.Hdr)
	head := make([]byte, 0, len(segMagic)+4+len(hdr))
	head = append(head, segMagic...)
	head = binary.BigEndian.AppendUint32(head, uint32(len(hdr)))
	head = append(head, hdr...)
	return &readCloser{Reader: io.MultiReader(strings.NewReader(string(head)), bufio.NewReaderSize(f, 1<<20)), close: f.Close}, nil
}

// readSegment parses a segment object's plaintext: its header, then fn is
// called with each transaction and its frames, in order.
func readSegment(r io.Reader, fn func(h segHeader, t segTxn, frames []byte) error) (segHeader, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	head := make([]byte, len(segMagic)+4)
	if _, err := io.ReadFull(br, head); err != nil || string(head[:len(segMagic)]) != segMagic {
		return segHeader{}, errors.New("not a Rowsafe SQLite change segment")
	}
	n := binary.BigEndian.Uint32(head[len(segMagic):])
	if n > 64<<20 {
		return segHeader{}, errors.New("corrupt change segment header")
	}
	hb := make([]byte, n)
	if _, err := io.ReadFull(br, hb); err != nil {
		return segHeader{}, err
	}
	var h segHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return segHeader{}, fmt.Errorf("corrupt change segment header: %w", err)
	}
	if h.PageSize < 512 || h.PageSize > 65536 {
		return h, errors.New("corrupt change segment header (page size)")
	}
	frameSize := int64(walFrameHeaderSize + h.PageSize)
	for _, t := range h.Txns {
		if t.Last < t.First {
			return h, errors.New("corrupt change segment header (frames)")
		}
		size := int64(t.Last-t.First+1) * frameSize
		if fn == nil {
			if _, err := io.CopyN(io.Discard, br, size); err != nil {
				return h, err
			}
			continue
		}
		// A transaction can be large (a VACUUM writes every page): read
		// it in pieces of whole frames.
		const piece = 4 << 20
		for size > 0 {
			k := min(size, max(piece/frameSize, 1)*frameSize)
			buf := make([]byte, k)
			if _, err := io.ReadFull(br, buf); err != nil {
				return h, fmt.Errorf("a change segment ends early: %w", err)
			}
			size -= k
			last := t
			if size > 0 {
				last.Commit = 0 // not the end of the transaction yet
			}
			if err := fn(h, last, buf); err != nil {
				return h, err
			}
		}
	}
	return h, nil
}

func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

func saveJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(v, "", "  ")
	return writeFileSync(path, data)
}

func loadJSONFile(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
