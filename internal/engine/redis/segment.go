package redis

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// A segment file holds part of the replication stream, each command with
// the moment it arrived:
//
//	"RSRSEG1\n"                       magic
//	uint32 selected database          the logical database selected when it starts
//	records:
//	  int64 arrival (Unix ns), int64 start offset, int64 length, raw command (RESP)
//
// Big-endian. Records are written whole; a file cut short (the agent
// stopped in the middle) is read up to its last whole record.

const (
	segMagic     = "RSRSEG1\n"
	segHeaderLen = 8 + 4 // the magic and the database
	recHeaderLen = 24
	// spillAt: a command bigger than this is written straight to the file
	// instead of being held in memory first.
	spillAt = 8 << 20
)

// cmdInfo is what the agent needs to know about a command of the stream.
type cmdInfo struct {
	Name string // upper case
	Arg1 string // the first argument (up to 64 bytes)
	Size int64  // bytes on the wire
}

// readCommand reads one command (an array of bulk strings) from br,
// passing its raw bytes to emit in chunks.
func readCommand(br *bufio.Reader, emit func([]byte) error) (cmdInfo, error) {
	var info cmdInfo
	line, err := br.ReadSlice('\n')
	if err != nil {
		if err == bufio.ErrBufferFull {
			return info, errors.New("replication stream: line too long")
		}
		return info, err
	}
	if len(line) < 4 || line[0] != '*' || line[len(line)-2] != '\r' {
		return info, fmt.Errorf("replication stream: unexpected %q", clip(string(line), 40))
	}
	n, err := strconv.Atoi(string(line[1 : len(line)-2]))
	if err != nil || n < 1 || n > maxArray {
		return info, fmt.Errorf("replication stream: bad array %q", clip(string(line), 40))
	}
	info.Size += int64(len(line))
	if err := emit(line); err != nil {
		return info, err
	}
	buf := make([]byte, 0, 4096)
	for i := 0; i < n; i++ {
		line, err := br.ReadSlice('\n')
		if err != nil {
			return info, noEOF(err)
		}
		if len(line) < 4 || line[0] != '$' || line[len(line)-2] != '\r' {
			return info, fmt.Errorf("replication stream: unexpected %q", clip(string(line), 40))
		}
		size, err := strconv.ParseInt(string(line[1:len(line)-2]), 10, 64)
		if err != nil || size < 0 || size > 4<<30 {
			return info, fmt.Errorf("replication stream: bad bulk %q", clip(string(line), 40))
		}
		info.Size += int64(len(line))
		if err := emit(line); err != nil {
			return info, err
		}
		left := size + 2
		first := true
		for left > 0 {
			chunk := min(left, 256<<10)
			if int64(cap(buf)) < chunk {
				buf = make([]byte, chunk)
			}
			b := buf[:chunk]
			if _, err := io.ReadFull(br, b); err != nil {
				return info, noEOF(err)
			}
			if first && i < 2 {
				arg := b[:min(int64(len(b)), size, 64)]
				if i == 0 {
					info.Name = strings.ToUpper(string(arg))
				} else {
					info.Arg1 = string(arg)
				}
			}
			first = false
			left -= chunk
			info.Size += chunk
			if left == 0 && chunk >= 2 && (b[len(b)-2] != '\r' || b[len(b)-1] != '\n') {
				return info, errors.New("replication stream: bulk string without CRLF")
			}
			if err := emit(b); err != nil {
				return info, err
			}
		}
	}
	return info, nil
}

func noEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}

// segWriter writes one segment file.
type segWriter struct {
	f    *os.File
	bw   *bufio.Writer
	path string
	pos  int64 // bytes in the file

	ReplID     string
	Start, End int64
	From, Last time.Time
	DB         int
	Records    int
	Data       int // records other than PING/REPLCONF

	// the record being written
	cur     bytes.Buffer
	spilled bool
	spillAt int64 // file position of the spilled record's header
	recLen  int64
}

func createSegment(path, replid string, start int64, db int, now time.Time) (*segWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	w := &segWriter{f: f, bw: bufio.NewWriterSize(f, 256<<10), path: path, ReplID: replid, Start: start, End: start, From: now, DB: db}
	var h [segHeaderLen]byte
	copy(h[:], segMagic)
	binary.BigEndian.PutUint32(h[len(segMagic):], uint32(db))
	if _, err := w.bw.Write(h[:]); err != nil {
		f.Close()
		return nil, err
	}
	w.pos = segHeaderLen
	return w, nil
}

// begin starts a record.
func (w *segWriter) begin() {
	w.cur.Reset()
	w.spilled, w.recLen = false, 0
}

// emit takes the next bytes of the record being written.
func (w *segWriter) emit(p []byte) error {
	w.recLen += int64(len(p))
	if w.spilled {
		_, err := w.bw.Write(p)
		return err
	}
	w.cur.Write(p)
	if w.cur.Len() < spillAt {
		return nil
	}
	// Too big to hold: write a header now and fix its length at the end.
	w.spilled, w.spillAt = true, w.pos
	var h [recHeaderLen]byte
	if _, err := w.bw.Write(h[:]); err != nil {
		return err
	}
	_, err := w.bw.Write(w.cur.Bytes())
	w.cur.Reset()
	return err
}

// end finishes the record: it arrived at t, started at offset start.
func (w *segWriter) end(t time.Time, start int64, info cmdInfo) error {
	var h [recHeaderLen]byte
	binary.BigEndian.PutUint64(h[0:], uint64(t.UnixNano()))
	binary.BigEndian.PutUint64(h[8:], uint64(start))
	binary.BigEndian.PutUint64(h[16:], uint64(w.recLen))
	if w.spilled {
		if err := w.bw.Flush(); err != nil {
			return err
		}
		if _, err := w.f.WriteAt(h[:], w.spillAt); err != nil {
			return err
		}
	} else {
		if _, err := w.bw.Write(h[:]); err != nil {
			return err
		}
		if _, err := w.bw.Write(w.cur.Bytes()); err != nil {
			return err
		}
	}
	w.pos += recHeaderLen + w.recLen
	w.End = start + info.Size
	w.Last = t
	w.Records++
	if info.Name != "PING" && info.Name != "REPLCONF" {
		w.Data++
	}
	if info.Name == "SELECT" {
		if n, err := strconv.Atoi(info.Arg1); err == nil {
			w.DB = n
		}
	}
	return nil
}

// Size is the file's size so far.
func (w *segWriter) Size() int64 { return w.pos }

// close flushes and syncs the file.
func (w *segWriter) close() error {
	err := w.bw.Flush()
	if serr := w.f.Sync(); err == nil {
		err = serr
	}
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	return err
}

// record is one command read back from a segment.
type record struct {
	At    time.Time
	Start int64
	Len   int64
}

// segReader reads a segment's records.
type segReader struct {
	r  *bufio.Reader
	DB int
}

func newSegReader(r io.Reader) (*segReader, error) {
	br := bufio.NewReaderSize(r, 256<<10)
	var h [segHeaderLen]byte
	if _, err := io.ReadFull(br, h[:]); err != nil {
		return nil, fmt.Errorf("not a Rowsafe stream segment: %w", err)
	}
	if string(h[:len(segMagic)]) != segMagic {
		return nil, errors.New("not a Rowsafe stream segment")
	}
	return &segReader{r: br, DB: int(binary.BigEndian.Uint32(h[len(segMagic):]))}, nil
}

// next reads a record's header; the caller then reads exactly Len bytes
// of the command from body (or skips them). io.EOF at the end.
func (s *segReader) next() (record, error) {
	var h [recHeaderLen]byte
	if _, err := io.ReadFull(s.r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return record{}, io.EOF // cut short: the last whole record was the end
		}
		return record{}, err
	}
	rec := record{At: time.Unix(0, int64(binary.BigEndian.Uint64(h[0:]))).UTC(),
		Start: int64(binary.BigEndian.Uint64(h[8:])), Len: int64(binary.BigEndian.Uint64(h[16:]))}
	if rec.Len <= 0 || rec.Len > 8<<30 {
		return record{}, fmt.Errorf("corrupt stream segment (record of %d bytes)", rec.Len)
	}
	return rec, nil
}

func (s *segReader) body() *bufio.Reader { return s.r }

// skip discards n bytes of the current record.
func (s *segReader) skip(n int64) error {
	_, err := io.CopyN(io.Discard, s.r, n)
	return noEOF(err)
}

// commandName reads the command's name from the start of a raw command
// (without consuming it from a bufio.Reader: Peek).
func commandName(raw []byte) (name, arg1 string) {
	br := bufio.NewReader(bytes.NewReader(raw))
	var args []string
	line, err := readLine(br)
	if err != nil || len(line) < 2 || line[0] != '*' {
		return "", ""
	}
	n, _ := strconv.Atoi(line[1:])
	for i := 0; i < min(n, 2); i++ {
		l, err := readLine(br)
		if err != nil || len(l) < 2 || l[0] != '$' {
			break
		}
		size, _ := strconv.Atoi(l[1:])
		b := make([]byte, min(size, 64))
		if _, err := io.ReadFull(br, b); err != nil {
			break
		}
		args = append(args, string(b))
		if _, err := br.Discard(size - len(b) + 2); err != nil {
			break
		}
	}
	if len(args) > 0 {
		name = strings.ToUpper(args[0])
	}
	if len(args) > 1 {
		arg1 = args[1]
	}
	return name, arg1
}

// scanSegmentFile reads a local segment file to its last whole record:
// where it ends in the stream, its last arrival, the database selected at
// its end, and the file position after the last whole record.
func scanSegmentFile(path string, start int64) (end int64, last time.Time, db int, valid int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, time.Time{}, 0, 0, err
	}
	defer f.Close()
	sr, err := newSegReader(f)
	if err != nil {
		return 0, time.Time{}, 0, 0, err
	}
	end, db, valid = start, sr.DB, segHeaderLen
	for {
		rec, err := sr.next()
		if err == io.EOF {
			return end, last, db, valid, nil
		}
		if err != nil {
			return end, last, db, valid, nil
		}
		head := make([]byte, min(rec.Len, 256))
		if _, err := io.ReadFull(sr.body(), head); err != nil {
			return end, last, db, valid, nil
		}
		if err := sr.skip(rec.Len - int64(len(head))); err != nil {
			return end, last, db, valid, nil
		}
		if name, arg := commandName(head); name == "SELECT" {
			if n, err := strconv.Atoi(arg); err == nil {
				db = n
			}
		}
		end, last = rec.Start+rec.Len, rec.At
		valid += recHeaderLen + rec.Len
	}
}
