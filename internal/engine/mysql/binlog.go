package mysql

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Binary log files. A file is identified by its name and the time it was
// created (the timestamp of its first event, the format description): a
// server that starts over (RESET MASTER, a new data directory) reuses
// names, never both.

const (
	binlogMagic          = "\xfebin"
	binlogMagicEncrypted = "\xfdbin" // MySQL's binlog_encryption
	eventHeaderLen       = 19
)

// Event types used here.
const (
	evQuery              = 2
	evStop               = 3
	evRotate             = 4
	evFormatDescription  = 15
	evXID                = 16
	evTransactionPayload = 40  // MySQL binlog_transaction_compression
	evMariaStartEncrypt  = 164 // MariaDB encrypt_binlog
)

// binlogFile is one binary log file.
type binlogFile struct {
	Name    string `json:"name"`    // mysql-bin.000012
	Created int64  `json:"created"` // unix seconds
}

// dir is the file's folder in the bucket.
func (f binlogFile) dir() string { return fmt.Sprintf("binlogs/%s~%d", f.Name, f.Created) }

// chunkKey names the bytes [from, to) of a file.
func chunkKey(f binlogFile, from, to int64) string {
	return fmt.Sprintf("%s/%012d-%012d.zst.age", f.dir(), from, to)
}

var chunkKeyRE = regexp.MustCompile(`^binlogs/([A-Za-z0-9._-]+)~(\d+)/(\d{12})-(\d{12})\.zst\.age$`)

// parseChunkKey reads a chunk key.
func parseChunkKey(key string) (f binlogFile, from, to int64, ok bool) {
	m := chunkKeyRE.FindStringSubmatch(key)
	if m == nil {
		return f, 0, 0, false
	}
	f.Name = m[1]
	f.Created, _ = strconv.ParseInt(m[2], 10, 64)
	from, _ = strconv.ParseInt(m[3], 10, 64)
	to, _ = strconv.ParseInt(m[4], 10, 64)
	return f, from, to, to > from
}

var binlogNameRE = regexp.MustCompile(`^([A-Za-z0-9._-]+)\.(\d{6,})$`)

// binlogSeq splits "mysql-bin.000012" into its base name and number.
func binlogSeq(name string) (base string, n int64, ok bool) {
	m := binlogNameRE.FindStringSubmatch(name)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.ParseInt(m[2], 10, 64)
	return m[1], n, err == nil
}

// errBinlogEncrypted: the server encrypts its binary logs, which Rowsafe
// can't read from the files.
var errBinlogEncrypted = errors.New("the binary logs are encrypted by the server (binlog_encryption / encrypt_binlog), which Rowsafe doesn't support yet")

// eventHeader is a binary log event's common header.
type eventHeader struct {
	Timestamp uint32
	Type      byte
	ServerID  uint32
	Size      uint32
	NextPos   uint32
	Flags     uint16
}

func parseEventHeader(b []byte) eventHeader {
	return eventHeader{
		Timestamp: binary.LittleEndian.Uint32(b[0:4]),
		Type:      b[4],
		ServerID:  binary.LittleEndian.Uint32(b[5:9]),
		Size:      binary.LittleEndian.Uint32(b[9:13]),
		NextPos:   binary.LittleEndian.Uint32(b[13:17]),
		Flags:     binary.LittleEndian.Uint16(b[17:19]),
	}
}

// readBinlogCreated reads when a binary log file was created.
func readBinlogCreated(path string) (int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var b [4 + eventHeaderLen]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, fmt.Errorf("%s: too short to be a binary log", path)
	}
	switch string(b[:4]) {
	case binlogMagic:
	case binlogMagicEncrypted:
		return 0, errBinlogEncrypted
	default:
		return 0, fmt.Errorf("%s is not a binary log", path)
	}
	h := parseEventHeader(b[4:])
	if h.Type != evFormatDescription {
		return 0, fmt.Errorf("%s: unexpected first event %d", path, h.Type)
	}
	return int64(h.Timestamp), nil
}

// scanEvents walks the events of a binary log file (from its start) until
// fn returns false or the file ends. A partial event at the end (a file
// still being written) ends the walk without error. body is the event's
// body for query events (at most 64 KiB of it), nil for the others.
func scanEvents(r io.Reader, fn func(pos int64, h eventHeader, body []byte) bool) error {
	br := bufio.NewReaderSize(r, 1<<20)
	magic := make([]byte, 4)
	if _, err := io.ReadFull(br, magic); err != nil {
		return fmt.Errorf("not a binary log: %w", err)
	}
	if string(magic) == binlogMagicEncrypted {
		return errBinlogEncrypted
	}
	if string(magic) != binlogMagic {
		return errors.New("not a binary log")
	}
	pos := int64(4)
	hdr := make([]byte, eventHeaderLen)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			return nil
		}
		h := parseEventHeader(hdr)
		if h.Size < eventHeaderLen {
			return fmt.Errorf("corrupt event at %d", pos)
		}
		if h.Type == evMariaStartEncrypt {
			return errBinlogEncrypted
		}
		rest := int(h.Size) - eventHeaderLen
		var body []byte
		if h.Type == evQuery {
			n := min(rest, 64<<10)
			body = make([]byte, n)
			if _, err := io.ReadFull(br, body); err != nil {
				return nil
			}
			rest -= n
		}
		if !fn(pos, h, body) {
			return nil
		}
		if _, err := br.Discard(rest); err != nil {
			return nil
		}
		pos += int64(h.Size)
	}
}

// queryText is the statement of a query event body ("" when it can't be
// read).
func queryText(body []byte) string {
	const post = 13 // thread id, exec time, db length, error code, status vars length
	if len(body) < post {
		return ""
	}
	dbLen := int(body[8])
	statusLen := int(binary.LittleEndian.Uint16(body[11:13]))
	start := post + statusLen + dbLen + 1
	if start > len(body) {
		return ""
	}
	return string(body[start:])
}

// lastCommitBefore returns the time of the last transaction (or statement
// outside one) that ended in r strictly before stop and before stopPos,
// from startPos on; ok is false when there is none.
func lastCommitBefore(r io.Reader, startPos int64, stop time.Time, stopPos int64) (time.Time, bool, error) {
	var last uint32
	found := false
	err := scanEvents(r, func(pos int64, h eventHeader, body []byte) bool {
		if stopPos > 0 && pos >= stopPos {
			return false
		}
		if !stop.IsZero() && int64(h.Timestamp) >= stop.Unix() {
			return false
		}
		if pos < startPos {
			return true
		}
		switch h.Type {
		case evXID, evTransactionPayload:
			last, found = h.Timestamp, true
		case evQuery:
			q := strings.ToUpper(strings.TrimSpace(queryText(body)))
			if !strings.HasPrefix(q, "BEGIN") && !strings.HasPrefix(q, "XA START") && !strings.HasPrefix(q, "XA END") {
				last, found = h.Timestamp, true
			}
		}
		return true
	})
	if !found {
		return time.Time{}, false, err
	}
	return time.Unix(int64(last), 0).UTC(), true, err
}

// binlogChunk is one stored piece of a binary log file.
type binlogChunk struct {
	File     binlogFile
	From, To int64
	Key      string
}

// binlogIndex is what the bucket holds of the binary logs, by file.
type binlogIndex map[binlogFile][]binlogChunk

func indexBinlogs(objs []objInfo) binlogIndex {
	idx := binlogIndex{}
	for _, o := range objs {
		f, from, to, ok := parseChunkKey(o.Key)
		if !ok {
			continue
		}
		idx[f] = append(idx[f], binlogChunk{File: f, From: from, To: to, Key: o.Key})
	}
	for f := range idx {
		slices.SortFunc(idx[f], func(a, b binlogChunk) int { return int(a.From - b.From) })
	}
	return idx
}

// contiguous returns the chunks that cover [0, end) without a hole (the
// longest such run from the start) and its end. Overlapping chunks (a
// re-upload) are skipped.
func (idx binlogIndex) contiguous(f binlogFile) ([]binlogChunk, int64) {
	var out []binlogChunk
	end := int64(0)
	for _, c := range idx[f] {
		switch {
		case c.From == end:
			out = append(out, c)
			end = c.To
		case c.From < end && c.To <= end:
			// already covered
		case c.From < end:
			// overlaps: keep what we have; a later chunk may start at end
		}
	}
	return out, end
}

// next finds the file that follows f: the next number, created at or after
// f (the earliest such, if the server started over later).
func (idx binlogIndex) next(f binlogFile) (binlogFile, bool) {
	base, n, ok := binlogSeq(f.Name)
	if !ok {
		return binlogFile{}, false
	}
	var best binlogFile
	found := false
	for g := range idx {
		gb, gn, ok := binlogSeq(g.Name)
		if !ok || gb != base || gn != n+1 || g.Created < f.Created {
			continue
		}
		if !found || g.Created < best.Created {
			best, found = g, true
		}
	}
	return best, found
}

// find returns the stored file named name created at created, or, when
// created is 0, the newest one created at or before notAfter.
func (idx binlogIndex) find(name string, created int64, notAfter time.Time) (binlogFile, bool) {
	if created != 0 {
		f := binlogFile{Name: name, Created: created}
		_, ok := idx[f]
		return f, ok
	}
	var best binlogFile
	found := false
	for g := range idx {
		if g.Name != name || (!notAfter.IsZero() && g.Created > notAfter.Unix()) {
			continue
		}
		if !found || g.Created > best.Created {
			best, found = g, true
		}
	}
	return best, found
}

// showBinaryLogs parses SHOW BINARY LOGS rows.
type serverBinlog struct {
	Name string
	Size int64
}

// sortBinlogs orders files by number.
func sortBinlogs(files []serverBinlog) {
	slices.SortStableFunc(files, func(a, b serverBinlog) int {
		_, na, _ := binlogSeq(a.Name)
		_, nb, _ := binlogSeq(b.Name)
		return int(na - nb)
	})
}

// position is a place in the binary logs: "mysql-bin.000012:4711".
type position struct {
	File    binlogFile `json:"file"`
	Pos     int64      `json:"pos"`
	GTIDSet string     `json:"gtid_set,omitempty"`
}

func (p position) String() string {
	if p.File.Name == "" {
		return ""
	}
	return p.File.Name + ":" + strconv.FormatInt(p.Pos, 10)
}

// isBinlogName guards names that end up in paths.
func isBinlogName(s string) bool {
	_, _, ok := binlogSeq(s)
	return ok && !strings.Contains(s, "/")
}
