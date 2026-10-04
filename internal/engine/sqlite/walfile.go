package sqlite

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// SQLite's WAL file format (https://sqlite.org/fileformat2.html#walformat):
// a 32-byte header, then frames of a 24-byte header and one page. A frame
// belongs to the WAL's current generation when its salts match the
// header's and its checksum, cumulative from the header, matches. A
// transaction ends with a commit frame (its "database size after commit"
// field is not zero). The checksum also detects a frame the app is still
// writing: the reader only ever takes whole, committed transactions.

const (
	walHeaderSize      = 32
	walFrameHeaderSize = 24
	walMagicLE         = 0x377f0682 // checksums over little-endian words
	walMagicBE         = 0x377f0683 // big-endian words
	walVersion         = 3007000
)

// walHeader is a WAL file's header.
type walHeader struct {
	BigEndian    bool
	PageSize     int
	CheckpointNo uint32
	Salt1, Salt2 uint32
	Cksum1       uint32
	Cksum2       uint32
}

var errNoWAL = errors.New("no WAL header")

// parseWALHeader reads and checks a WAL header.
func parseWALHeader(b []byte) (walHeader, error) {
	if len(b) < walHeaderSize {
		return walHeader{}, errNoWAL
	}
	magic := binary.BigEndian.Uint32(b[0:])
	if magic != walMagicLE && magic != walMagicBE {
		return walHeader{}, errNoWAL
	}
	h := walHeader{BigEndian: magic == walMagicBE}
	if v := binary.BigEndian.Uint32(b[4:]); v != walVersion {
		return walHeader{}, fmt.Errorf("unknown WAL format version %d", v)
	}
	h.PageSize = int(binary.BigEndian.Uint32(b[8:]))
	if h.PageSize < 512 || h.PageSize > 65536 || h.PageSize&(h.PageSize-1) != 0 {
		return walHeader{}, fmt.Errorf("invalid WAL page size %d", h.PageSize)
	}
	h.CheckpointNo = binary.BigEndian.Uint32(b[12:])
	h.Salt1 = binary.BigEndian.Uint32(b[16:])
	h.Salt2 = binary.BigEndian.Uint32(b[20:])
	h.Cksum1 = binary.BigEndian.Uint32(b[24:])
	h.Cksum2 = binary.BigEndian.Uint32(b[28:])
	s1, s2 := walChecksum(h.BigEndian, b[:24], 0, 0)
	if s1 != h.Cksum1 || s2 != h.Cksum2 {
		return walHeader{}, errors.New("WAL header checksum mismatch")
	}
	return h, nil
}

// walChecksum continues SQLite's WAL checksum (s1, s2) over b (a multiple
// of 8 bytes).
func walChecksum(bigEndian bool, b []byte, s1, s2 uint32) (uint32, uint32) {
	if bigEndian {
		for i := 0; i+8 <= len(b); i += 8 {
			s1 += binary.BigEndian.Uint32(b[i:]) + s2
			s2 += binary.BigEndian.Uint32(b[i+4:]) + s1
		}
		return s1, s2
	}
	for i := 0; i+8 <= len(b); i += 8 {
		s1 += binary.LittleEndian.Uint32(b[i:]) + s2
		s2 += binary.LittleEndian.Uint32(b[i+4:]) + s1
	}
	return s1, s2
}

// walFrame is one frame's header.
type walFrame struct {
	Pgno   uint32
	Commit uint32 // database size in pages after this commit; 0: not a commit frame
	Salt1  uint32
	Salt2  uint32
	Cksum1 uint32
	Cksum2 uint32
}

func parseFrameHeader(b []byte) walFrame {
	return walFrame{
		Pgno: binary.BigEndian.Uint32(b[0:]), Commit: binary.BigEndian.Uint32(b[4:]),
		Salt1: binary.BigEndian.Uint32(b[8:]), Salt2: binary.BigEndian.Uint32(b[12:]),
		Cksum1: binary.BigEndian.Uint32(b[16:]), Cksum2: binary.BigEndian.Uint32(b[20:]),
	}
}

// walTxn is a committed transaction: its frames (header and page each,
// as in the file) from frame First to frame Last.
type walTxn struct {
	First, Last uint32 // frame numbers, 1-based
	Commit      uint32 // database size in pages after it
	Data        []byte // (Last-First+1) frames
}

// walScan reads committed transactions from a WAL file, starting after
// frame `after` whose cumulative checksum is (s1, s2) (the header's for
// after == 0). It stops at the first frame that isn't valid (another
// generation's, torn, or past the end), returning only whole committed
// transactions, at most maxBytes of frames (at least one transaction),
// and the frame number and checksum after the last one it returns.
func walScan(r io.ReaderAt, h walHeader, after uint32, s1, s2 uint32, maxBytes int) (txns []walTxn, last uint32, c1, c2 uint32, err error) {
	frameSize := walFrameHeaderSize + h.PageSize
	last, c1, c2 = after, s1, s2
	buf := make([]byte, frameSize)
	var pending []byte
	pendingFirst := after + 1
	total := 0
	for n := after + 1; ; n++ {
		off := int64(walHeaderSize) + int64(n-1)*int64(frameSize)
		if _, rerr := r.ReadAt(buf, off); rerr != nil {
			if errors.Is(rerr, io.EOF) || errors.Is(rerr, io.ErrUnexpectedEOF) {
				return txns, last, c1, c2, nil
			}
			return txns, last, c1, c2, rerr
		}
		f := parseFrameHeader(buf)
		if f.Salt1 != h.Salt1 || f.Salt2 != h.Salt2 || f.Pgno == 0 {
			return txns, last, c1, c2, nil
		}
		ps1, ps2 := walChecksum(h.BigEndian, buf[:8], s1, s2)
		ps1, ps2 = walChecksum(h.BigEndian, buf[walFrameHeaderSize:], ps1, ps2)
		if ps1 != f.Cksum1 || ps2 != f.Cksum2 {
			return txns, last, c1, c2, nil
		}
		s1, s2 = ps1, ps2
		pending = append(pending, buf...)
		if f.Commit == 0 {
			continue
		}
		txns = append(txns, walTxn{First: pendingFirst, Last: n, Commit: f.Commit, Data: pending})
		total += len(pending)
		last, c1, c2 = n, s1, s2
		pending, pendingFirst = nil, n+1
		if maxBytes > 0 && total >= maxBytes {
			return txns, last, c1, c2, nil
		}
	}
}

// applyFrames writes a transaction's pages into a database file (what a
// checkpoint does) and sets its size to the commit's page count.
func applyFrames(w interface {
	io.WriterAt
	Truncate(int64) error
}, pageSize int, data []byte, commit uint32) error {
	frameSize := walFrameHeaderSize + pageSize
	if len(data)%frameSize != 0 {
		return fmt.Errorf("a change segment holds a partial frame (%d bytes, %d per frame)", len(data), frameSize)
	}
	for off := 0; off < len(data); off += frameSize {
		pgno := binary.BigEndian.Uint32(data[off:])
		if pgno == 0 {
			return errors.New("a change segment holds a frame for page 0")
		}
		if _, err := w.WriteAt(data[off+walFrameHeaderSize:off+frameSize], int64(pgno-1)*int64(pageSize)); err != nil {
			return err
		}
	}
	if commit > 0 {
		return w.Truncate(int64(commit) * int64(pageSize))
	}
	return nil
}
