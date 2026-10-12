package mysql

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Binary log files. A file is identified by its name, the time it was
// created (the timestamp of its first event, the format description) and
// the server that wrote it (that event's server_id): a server that starts
// over (RESET MASTER, a new data directory) reuses names, never both, and
// the two servers of a standby pair name theirs alike (binlog.000001...):
// after a switchover the bucket holds both servers' files, and a chain
// never goes from one server's file to the other's.

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
	// GTIDs (gtid.go).
	evGTID          = 33  // MySQL: the next transaction's GTID
	evAnonymousGTID = 34  // MySQL: a transaction without a GTID
	evPreviousGTIDs = 35  // MySQL: the GTIDs of every earlier file
	evGTIDTagged    = 42  // MySQL 8.3+: a tagged GTID
	evMariaGTID     = 162 // MariaDB: the next event group's GTID
	evMariaGTIDList = 163 // MariaDB: the binary log state at the file's start
)

// bodyLimit: scanEvents hands the body of these events to its callback
// (at most this many bytes of it).
var bodyLimit = map[byte]int{evQuery: 64 << 10, evGTID: 64, evPreviousGTIDs: 16 << 20, evGTIDTagged: 64,
	evMariaGTID: 64, evMariaGTIDList: 16 << 20}

// binlogFile is one binary log file.
type binlogFile struct {
	Name    string `json:"name"`    // mysql-bin.000012
	Created int64  `json:"created"` // unix seconds
	// Server is the server_id of the server that wrote it; "" for files
	// shipped by older agents (and positions recorded by them).
	Server string `json:"server,omitempty"`
}

// dir is the file's folder in the bucket.
func (f binlogFile) dir() string {
	if f.Server == "" {
		return fmt.Sprintf("binlogs/%s~%d", f.Name, f.Created)
	}
	return fmt.Sprintf("binlogs/%s~%d~%s", f.Name, f.Created, f.Server)
}

// same reports whether f and g are one file (the server compared when both
// say).
func (f binlogFile) same(g binlogFile) bool {
	return f.Name == g.Name && f.Created == g.Created && (f.Server == "" || g.Server == "" || f.Server == g.Server)
}

// chunkKey names the bytes [from, to) of a file.
func chunkKey(f binlogFile, from, to int64) string {
	return fmt.Sprintf("%s/%012d-%012d.zst.age", f.dir(), from, to)
}

var chunkKeyRE = regexp.MustCompile(`^binlogs/([A-Za-z0-9._-]+)~(\d+)(?:~(\d{1,10}))?/(\d{12})-(\d{12})\.zst\.age$`)

// parseChunkKey reads a chunk key.
func parseChunkKey(key string) (f binlogFile, from, to int64, ok bool) {
	m := chunkKeyRE.FindStringSubmatch(key)
	if m == nil {
		return f, 0, 0, false
	}
	f.Name, f.Server = m[1], m[3]
	f.Created, _ = strconv.ParseInt(m[2], 10, 64)
	from, _ = strconv.ParseInt(m[4], 10, 64)
	to, _ = strconv.ParseInt(m[5], 10, 64)
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

// readBinlogFile reads a binary log file's identity: its name, when it was
// created and the server that wrote it.
func readBinlogFile(path string) (binlogFile, error) {
	created, server, err := readBinlogHeader(path)
	if err != nil {
		return binlogFile{}, err
	}
	return binlogFile{Name: filepath.Base(path), Created: created, Server: strconv.FormatUint(uint64(server), 10)}, nil
}

// readBinlogHeader reads when a binary log file was created and by which
// server (the format description event's timestamp and server_id).
func readBinlogHeader(path string) (int64, uint32, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	var b [4 + eventHeaderLen]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return 0, 0, fmt.Errorf("%s: too short to be a binary log", path)
	}
	switch string(b[:4]) {
	case binlogMagic:
	case binlogMagicEncrypted:
		return 0, 0, errBinlogEncrypted
	default:
		return 0, 0, fmt.Errorf("%s is not a binary log", path)
	}
	h := parseEventHeader(b[4:])
	if h.Type != evFormatDescription {
		return 0, 0, fmt.Errorf("%s: unexpected first event %d", path, h.Type)
	}
	return int64(h.Timestamp), h.ServerID, nil
}

// scanEvents walks the events of a binary log file (from its start) until
// fn returns false or the file ends. A partial event at the end (a file
// still being written) ends the walk without error. body is the event's
// body for query and GTID events (at most bodyLimit of it), nil for the
// others.
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
		if limit, ok := bodyLimit[h.Type]; ok {
			n := min(rest, limit)
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

// next finds the file that follows f, written by server (f's own, or the
// one its contents say for a file from an older agent; "" when not known):
// the next number, created at or after f (the earliest such, if the server
// started over later), never another server's (candidates).
func (idx binlogIndex) next(f binlogFile, server string) (binlogFile, bool) {
	c := idx.candidates(f, server)
	if len(c) == 0 {
		return binlogFile{}, false
	}
	return c[0], true
}

// candidates are the files that may follow f, best first: the same
// server's (known), then files from older agents (which don't say whose
// they are: the caller checks their first event), each by creation.
func (idx binlogIndex) candidates(f binlogFile, server string) []binlogFile {
	base, n, ok := binlogSeq(f.Name)
	if !ok {
		return nil
	}
	if f.Server != "" {
		server = f.Server
	}
	var out []binlogFile
	for g := range idx {
		gb, gn, ok := binlogSeq(g.Name)
		if !ok || gb != base || gn != n+1 || g.Created < f.Created {
			continue
		}
		if server != "" && g.Server != "" && g.Server != server {
			continue // the other server's file of that name (a standby pair)
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b binlogFile) int {
		if (a.Server == server) != (b.Server == server) {
			if a.Server == server {
				return -1
			}
			return 1
		}
		return int(a.Created - b.Created)
	})
	return out
}

// find returns the stored file f names (by name and creation, and server
// when f says), the most complete when an agent update shipped it twice;
// or, when f.Created is 0, the newest one named so created at or before
// notAfter.
func (idx binlogIndex) find(f binlogFile, notAfter time.Time) (binlogFile, bool) {
	var best binlogFile
	found := false
	bestEnd := int64(-1)
	for g := range idx {
		if g.Name != f.Name || f.Server != "" && g.Server != "" && g.Server != f.Server {
			continue
		}
		if f.Created != 0 {
			if g.Created != f.Created {
				continue
			}
			if _, end := idx.contiguous(g); end > bestEnd {
				best, bestEnd, found = g, end, true
			}
			continue
		}
		if !notAfter.IsZero() && g.Created > notAfter.Unix() {
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

// ---- switches between servers ----

// binlogLink records that the database moved to another server (a
// standby's promotion, StandbyPromote): the old primary's history ends at
// From (its file and position, as the new primary applied it), and the new
// primary's own begins with To, a file it started for that at the
// promotion. A restore whose chain reaches From, and the old primary
// shipped nothing more, goes on in To; until the new primary's first
// backup, that is the only way to a moment after the switch.
type binlogLink struct {
	From linkFrom   `json:"from"`
	To   binlogFile `json:"to"`
	At   time.Time  `json:"at"`
}

// linkFrom is where the old primary's history ends.
type linkFrom struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	Pos    int64  `json:"pos"`
}

// linkKey is the link to f in the bucket.
func linkKey(f binlogFile) string {
	return fmt.Sprintf("binlogs/links/%s~%d~%s.json.age", f.Name, f.Created, f.Server)
}

var linkKeyRE = regexp.MustCompile(`^binlogs/links/([A-Za-z0-9._-]+)~(\d+)~(\d{1,10})\.json\.age$`)

// parseLinkKey reads a link key: the file it leads to.
func parseLinkKey(key string) (binlogFile, bool) {
	m := linkKeyRE.FindStringSubmatch(key)
	if m == nil {
		return binlogFile{}, false
	}
	created, err := strconv.ParseInt(m[2], 10, 64)
	return binlogFile{Name: m[1], Created: created, Server: m[3]}, err == nil
}

// linksTo lists the links in the bucket (the files they lead to), newest
// first.
func linksTo(objs []objInfo) []binlogFile {
	var out []binlogFile
	for _, o := range objs {
		if f, ok := parseLinkKey(o.Key); ok {
			out = append(out, f)
		}
	}
	slices.SortFunc(out, func(a, b binlogFile) int { return int(b.Created - a.Created) })
	return out
}
