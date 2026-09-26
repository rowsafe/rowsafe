package pglog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Position is where reading a log resumes: a file and offset, or a
// journald cursor. It is saved in the agent's state directory so a
// restart neither resends nor skips.
type Position struct {
	Path   string `json:"path,omitempty"`
	Inode  uint64 `json:"inode,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	// Mark is the bytes just before Offset: when they change, the file was
	// truncated and rewritten (copytruncate) past our offset.
	Mark   string `json:"mark,omitempty"`
	Cursor string `json:"cursor,omitempty"` // journald
}

// markLen is how many bytes before the offset Mark keeps.
const markLen = 32

// Limits on reading.
const (
	// backfill is how much of an existing log a newly watched database
	// sends (the most recent part), so the page isn't empty at first.
	backfill = 64 << 10
	// maxLag: further behind than this, the agent skips ahead (and counts
	// what it skipped) instead of catching up line by line.
	maxLag = 64 << 20
)

// fileTail follows one log file across rotation (a new file under the
// same name, or copytruncate) and the collector's switches to a new file.
type fileTail struct {
	pos Position
	f   *os.File
}

func inode(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

// readResult is one round of reading.
type readResult struct {
	data    []byte // complete lines only
	skipped int64  // bytes skipped because the reader was too far behind
	// reset: the file changed under the reader (rotated, truncated,
	// switched); a message being assembled is complete.
	reset bool
}

// read returns up to max bytes of complete lines from path, following
// rotation. A reader without a position starts near the end (backfill).
func (t *fileTail) read(path string, max int) (readResult, error) {
	var res readResult
	fi, err := os.Stat(path)
	if err != nil {
		return res, err
	}
	ino := inode(fi)
	switch {
	case t.pos.Path == "":
		t.pos = Position{Path: path, Inode: ino, Offset: startOffset(path, fi.Size())}
	case t.pos.Path != path || t.pos.Inode != ino:
		// A new file: finish the old one (it may have got lines after
		// our last read), then start the new one from its beginning.
		if t.f != nil {
			rest, _ := t.drain(max)
			res.data = rest
		}
		t.close()
		t.pos = Position{Path: path, Inode: ino}
		res.reset = true
	case fi.Size() < t.pos.Offset || !t.markMatches(path): // truncated (copytruncate)
		t.close()
		t.pos.Offset, t.pos.Mark = 0, ""
		res.reset = true
	}
	if lag := fi.Size() - t.pos.Offset; lag > maxLag {
		res.skipped = lag - backfill
		t.pos.Offset, t.pos.Mark = startOffset(path, fi.Size()), ""
		t.close()
		res.reset = true
	}
	if t.f == nil {
		f, err := os.Open(path)
		if err != nil {
			return res, err
		}
		t.f = f
	}
	if len(res.data) >= max {
		return res, nil
	}
	more, err := t.readFrom(max - len(res.data))
	res.data = append(res.data, more...)
	return res, err
}

// readFrom reads complete lines from the open file at the position.
func (t *fileTail) readFrom(max int) ([]byte, error) {
	buf := make([]byte, max)
	n, err := t.f.ReadAt(buf, t.pos.Offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	buf = buf[:n]
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		if n == max { // one line longer than max: take it in pieces
			t.pos.Offset += int64(n)
			return append(buf, '\n'), nil
		}
		return nil, nil
	}
	t.pos.Offset += int64(end + 1)
	t.setMark(buf[:end+1])
	return buf[:end+1], nil
}

// setMark keeps the last markLen bytes read (with the previous mark when
// the read was shorter).
func (t *fileTail) setMark(read []byte) {
	m := t.pos.Mark + string(read)
	if len(m) > markLen {
		m = m[len(m)-markLen:]
	}
	t.pos.Mark = m
}

// markMatches reports whether the bytes before the offset are still the
// ones read there.
func (t *fileTail) markMatches(path string) bool {
	if t.pos.Mark == "" || t.pos.Offset < int64(len(t.pos.Mark)) {
		return true
	}
	f := t.f
	if f == nil {
		var err error
		if f, err = os.Open(path); err != nil {
			return true
		}
		defer f.Close()
	}
	buf := make([]byte, len(t.pos.Mark))
	if _, err := f.ReadAt(buf, t.pos.Offset-int64(len(buf))); err != nil {
		return true
	}
	return string(buf) == t.pos.Mark
}

// drain reads what is left of the old file.
func (t *fileTail) drain(max int) ([]byte, error) {
	data, err := t.readFrom(max)
	return data, err
}

func (t *fileTail) close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// startOffset is where a new reader starts: the start of the first line
// in the last backfill bytes.
func startOffset(path string, size int64) int64 {
	if size <= backfill {
		return 0
	}
	f, err := os.Open(path)
	if err != nil {
		return size
	}
	defer f.Close()
	start := size - backfill
	buf := make([]byte, 64<<10)
	n, _ := f.ReadAt(buf, start)
	if i := bytes.IndexByte(buf[:n], '\n'); i >= 0 {
		return start + int64(i) + 1
	}
	return size
}

// ---- journald ----

// journalTail reads a systemd unit's journal with journalctl.
type journalTail struct {
	journalctl string
	pos        Position
}

type journalRecord struct {
	Cursor    string          `json:"__CURSOR"`
	Realtime  string          `json:"__REALTIME_TIMESTAMP"`
	Message   json.RawMessage `json:"MESSAGE"`
	SyslogPID string          `json:"SYSLOG_PID"`
}

// journalLine is one journal message: a stderr line as PostgreSQL wrote it.
type journalLine struct {
	at   time.Time
	text string
}

// read returns up to max journal lines after the saved cursor (the last
// few lines for a new reader).
func (j *journalTail) read(ctx context.Context, unit string, max int) ([]journalLine, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	args := []string{"-u", unit, "-o", "json", "--no-pager", "-q"}
	if j.pos.Path != unit {
		j.pos = Position{Path: unit}
	}
	if j.pos.Cursor != "" {
		args = append(args, "--after-cursor="+j.pos.Cursor, "-n", strconv.Itoa(max))
	} else {
		args = append(args, "-n", "200")
	}
	out, err := exec.CommandContext(ctx, j.journalctl, args...).Output()
	if err != nil {
		return nil, err
	}
	var lines []journalLine
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		var r journalRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		j.pos.Cursor = r.Cursor
		msg := journalMessage(r.Message)
		at := time.Now()
		if us, err := strconv.ParseInt(r.Realtime, 10, 64); err == nil {
			at = time.UnixMicro(us)
		}
		for _, l := range strings.Split(msg, "\n") {
			lines = append(lines, journalLine{at: at, text: l})
		}
	}
	return lines, sc.Err()
}

// journalMessage decodes MESSAGE: a string, or an array of bytes when it
// isn't valid UTF-8.
func journalMessage(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b []byte
	var ints []int
	if json.Unmarshal(raw, &ints) == nil {
		for _, i := range ints {
			b = append(b, byte(i))
		}
		return strings.ToValidUTF8(string(b), "")
	}
	return ""
}

// ---- saved positions ----

type positions struct {
	path string
	m    map[string]Position
}

func loadPositions(stateDir string) *positions {
	p := &positions{m: map[string]Position{}}
	if stateDir == "" {
		return p
	}
	p.path = filepath.Join(stateDir, "logs", "positions.json")
	if b, err := os.ReadFile(p.path); err == nil {
		_ = json.Unmarshal(b, &p.m)
	}
	return p
}

func (p *positions) save() error {
	if p.path == "" {
		return nil
	}
	b, err := json.Marshal(p.m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}
