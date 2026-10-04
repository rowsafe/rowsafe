package sqlite

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// The bucket, under <path prefix>/<stanza>/, everything compressed (zstd)
// and encrypted on the server (objstore.Seal) before it is uploaded:
//
//	rowsafe-sqlite.json                       what this folder is
//	snapshots/<label>/db.zst                  a page-exact copy of the file (online backup API)
//	snapshots/<label>/snapshot.json           its description, written last
//	wal/<gen>/<seq>_<w>_<first>-<last>_<t0>-<t1>.seg
//	                                          committed transactions: WAL frames as
//	                                          SQLite wrote them, in order
//	marks/<name>.json                         a Mark: a position in the stream
//
// A generation is one unbroken stream of changes; seq numbers its segments
// one by one, w counts the WAL file's resets within it (frame numbers
// start again at 1 after each), first-last are the frames inside, t0-t1
// (Unix milliseconds) when the agent saw the first and last transaction.
// Names say when, never what.

const (
	markerKey    = "rowsafe-sqlite.json"
	snapPrefix   = "snapshots/"
	walPrefix    = "wal/"
	marksPrefix  = "marks/"
	snapDataName = "db.zst"
	snapDocName  = "snapshot.json"
)

var stanzaRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// repo is one database's folder in a bucket.
type repo struct {
	st   *objstore.Store
	pass string
}

func openRepo(env agent.EngineEnv, db protocol.DatabaseSpec) (*repo, error) {
	if err := env.Repo.Validate(); err != nil {
		return nil, err
	}
	if !stanzaRE.MatchString(db.Stanza) {
		return nil, fmt.Errorf("invalid stanza %q", db.Stanza)
	}
	st, err := objstore.New(env.Repo, db.Stanza)
	if err != nil {
		return nil, err
	}
	return &repo{st: st, pass: env.Repo.CipherPass}, nil
}

func (r *repo) putJSON(ctx context.Context, key string, v any) error {
	plain, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	w, err := objstore.Seal(&buf, r.pass)
	if err != nil {
		return err
	}
	if _, err := w.Write(plain); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return r.st.PutBytes(ctx, key, buf.Bytes())
}

func (r *repo) getJSON(ctx context.Context, key string, v any) error {
	data, err := r.st.GetBytes(ctx, key)
	if err != nil {
		return err
	}
	pr, err := objstore.Open(bytes.NewReader(data), r.pass)
	if err != nil {
		return err
	}
	plain, err := io.ReadAll(pr)
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// newEncoder is a zstd encoder that stays gentle on the server's CPU.
func newEncoder(w io.Writer) (*zstd.Encoder, error) {
	return zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1),
		zstd.WithLowerEncoderMem(true))
}

// putCompressed streams src, compressed and sealed, into key; it returns
// the bytes stored.
func (r *repo) putCompressed(ctx context.Context, key string, src io.Reader) (int64, error) {
	pr, pw := io.Pipe()
	go func() {
		sw, err := objstore.Seal(pw, r.pass)
		if err == nil {
			var zw *zstd.Encoder
			if zw, err = newEncoder(sw); err == nil {
				_, err = io.Copy(zw, src)
				if cerr := zw.Close(); err == nil {
					err = cerr
				}
			}
			if cerr := sw.Close(); err == nil {
				err = cerr
			}
		}
		pw.CloseWithError(err)
	}()
	n, err := r.st.Put(ctx, key, pr)
	pr.CloseWithError(errors.New("upload stopped"))
	return n, err
}

// getCompressed opens key for reading its plaintext.
func (r *repo) getCompressed(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := r.st.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	pr, err := objstore.Open(rc, r.pass)
	if err != nil {
		rc.Close()
		return nil, err
	}
	zr, err := zstd.NewReader(pr, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
	if err != nil {
		rc.Close()
		return nil, err
	}
	return &readCloser{Reader: zr, close: func() error { zr.Close(); return rc.Close() }}, nil
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r *readCloser) Close() error { return r.close() }

// marker describes the folder.
type marker struct {
	Engine    string    `json:"engine"`
	Database  string    `json:"database"`
	Path      string    `json:"path"`
	CreatedAt time.Time `json:"created_at"`
}

// ---- stream positions

// pos is a position in a generation's stream: after frame Frame of the
// WAL's W-th reset (frames count from 1; Frame 0 is the start of that WAL).
type pos struct {
	W     int    `json:"w"`
	Frame uint32 `json:"frame"`
}

func (p pos) Compare(o pos) int {
	switch {
	case p.W != o.W:
		return cmpInt(p.W, o.W)
	case p.Frame != o.Frame:
		return cmpInt(int(p.Frame), int(o.Frame))
	}
	return 0
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// lsn is a position as people and the control plane see it.
func lsn(gen string, p pos) string { return fmt.Sprintf("%s/%d/%d", gen, p.W, p.Frame) }

func parseLSN(s string) (gen string, p pos, ok bool) {
	parts := strings.Split(s, "/")
	if len(parts) != 3 || !genRE.MatchString(parts[0]) {
		return "", pos{}, false
	}
	w, err1 := strconv.Atoi(parts[1])
	f, err2 := strconv.ParseUint(parts[2], 10, 32)
	if err1 != nil || err2 != nil || w < 0 {
		return "", pos{}, false
	}
	return parts[0], pos{W: w, Frame: uint32(f)}, true
}

// genRE: a generation is named after when it started, plus a random tag.
var genRE = regexp.MustCompile(`^\d{8}T\d{6}Z-[0-9a-f]{8}$`)

// ---- snapshots

// snapDoc describes one full copy.
type snapDoc struct {
	Label string `json:"label"`
	// Gen and Pos: the copy holds every transaction up to Pos of Gen ("":
	// taken without a stream, in rollback-journal mode).
	Gen string `json:"gen,omitempty"`
	Pos pos    `json:"pos"`
	// At is the moment the copy shows (its read transaction began).
	At          time.Time    `json:"at"`
	StartedAt   time.Time    `json:"started_at"`
	StoppedAt   time.Time    `json:"stopped_at"`
	PageSize    int          `json:"page_size"`
	SizeBytes   int64        `json:"size_bytes"`
	StoredBytes int64        `json:"stored_bytes"`
	JournalMode string       `json:"journal_mode"`
	Version     string       `json:"version,omitempty"` // SQLite that last wrote the file
	Tables      []tableCount `json:"tables"`
	Integrity   string       `json:"integrity"` // "ok", or quick_check's first problem
	// Auto: taken by the agent itself to start a new generation (not a
	// scheduled backup).
	Auto bool `json:"auto,omitempty"`
}

type tableCount struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

var labelRE = regexp.MustCompile(`^\d{8}-\d{6}F$`)

// newLabel is pgBackRest-like: 20261004-101500F.
func newLabel(t time.Time) string { return t.UTC().Format("20060102-150405") + "F" }

func snapKey(label, name string) string { return snapPrefix + label + "/" + name }

// listSnapshots returns the finished copies, oldest first, and the labels
// of unfinished ones.
func (r *repo) listSnapshots(ctx context.Context) ([]snapDoc, []string, error) {
	objs, err := r.st.List(ctx, snapPrefix)
	if err != nil {
		return nil, nil, err
	}
	var labels, unfinished []string
	seen, finished := map[string]bool{}, map[string]bool{}
	for _, o := range objs {
		label, name, ok := strings.Cut(strings.TrimPrefix(o.Key, snapPrefix), "/")
		if !ok || !labelRE.MatchString(label) {
			continue
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
		if name == snapDocName {
			finished[label] = true
		}
	}
	var docs []snapDoc
	for _, l := range labels {
		if !finished[l] {
			unfinished = append(unfinished, l)
			continue
		}
		var d snapDoc
		if err := r.getJSON(ctx, snapKey(l, snapDocName), &d); err != nil {
			return nil, nil, fmt.Errorf("reading backup %s: %w", l, err)
		}
		docs = append(docs, d)
	}
	slices.SortFunc(docs, func(a, b snapDoc) int { return a.At.Compare(b.At) })
	return docs, unfinished, nil
}

// deleteSnapshot removes a copy (its description first, so a partly
// deleted copy is never taken for a finished one).
func (r *repo) deleteSnapshot(ctx context.Context, label string) error {
	if err := r.st.Delete(ctx, snapKey(label, snapDocName)); err != nil {
		return err
	}
	objs, err := r.st.List(ctx, snapPrefix+label+"/")
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := r.st.Delete(ctx, o.Key); err != nil {
			return err
		}
	}
	return nil
}

// ---- segments

// segment is one segment object's name, parsed.
type segment struct {
	Key         string
	Gen         string
	Seq         int64
	W           int
	First, Last uint32
	T0, T1      time.Time
	Size        int64
}

func segKey(gen string, seq int64, w int, first, last uint32, t0, t1 time.Time) string {
	return fmt.Sprintf("%s%s/%010d_%06d_%010d-%010d_%013d-%013d.seg", walPrefix, gen, seq, w, first, last,
		t0.UnixMilli(), t1.UnixMilli())
}

var segRE = regexp.MustCompile(`^wal/(\d{8}T\d{6}Z-[0-9a-f]{8})/(\d{10})_(\d{6})_(\d{10})-(\d{10})_(\d{13})-(\d{13})\.seg$`)

func parseSegKey(key string) (segment, bool) {
	m := segRE.FindStringSubmatch(key)
	if m == nil {
		return segment{}, false
	}
	n := func(s string) int64 { v, _ := strconv.ParseInt(s, 10, 64); return v }
	s := segment{Key: key, Gen: m[1], Seq: n(m[2]), W: int(n(m[3])), First: uint32(n(m[4])), Last: uint32(n(m[5])),
		T0: time.UnixMilli(n(m[6])).UTC(), T1: time.UnixMilli(n(m[7])).UTC()}
	if s.Last < s.First || s.First == 0 {
		return segment{}, false
	}
	return s, true
}

// listSegments lists a generation's segments ("" for every generation) in
// order.
func (r *repo) listSegments(ctx context.Context, gen string) ([]segment, error) {
	prefix := walPrefix
	if gen != "" {
		prefix += gen + "/"
	}
	objs, err := r.st.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []segment
	for _, o := range objs {
		if s, ok := parseSegKey(o.Key); ok {
			s.Size = o.Size
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b segment) int {
		if c := strings.Compare(a.Gen, b.Gen); c != 0 {
			return c
		}
		return cmpInt(int(a.Seq), int(b.Seq))
	})
	return out, nil
}

// ---- marks

type markDoc struct {
	Name      string    `json:"name"`
	Gen       string    `json:"gen"`
	Pos       pos       `json:"pos"`
	CreatedAt time.Time `json:"created_at"`
}

var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func markKey(name string) string { return marksPrefix + name + ".json" }
