package mongodb

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

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// The bucket, under <path prefix>/<stanza>/, everything encrypted on the
// server (objstore.Seal) before it is uploaded:
//
//	rowsafe-mongodb.json                     what this folder is (sealed)
//	backup/<label>/archive.gz                mongodump --archive --gzip --oplog (sealed)
//	backup/<label>/backup.json               the backup's description, written last (sealed)
//	oplog/<first>_<last>_<prev>.bson.gz      oplog entries first..last; prev is the
//	                                         entry before first (sealed, gzip)
//	marks/<name>.json                        a Mark: its oplog timestamp (sealed)
//
// Timestamps in names are <seconds>-<increment>, zero-padded so names sort
// in time order. Names say when, never what.

const (
	markerKey     = "rowsafe-mongodb.json"
	backupPrefix  = "backup/"
	oplogPrefix   = "oplog/"
	marksPrefix   = "marks/"
	archiveName   = "archive.gz"
	backupDocName = "backup.json"
)

// repo is one database's folder in the bucket.
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

var stanzaRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

// putJSON seals v and stores it at key.
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

// getJSON reads and opens a sealed JSON object.
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

// putSealed streams r, sealed, into key and returns the bytes stored.
func (r *repo) putSealed(ctx context.Context, key string, src io.Reader) (int64, error) {
	pr, pw := io.Pipe()
	go func() {
		w, err := objstore.Seal(pw, r.pass)
		if err == nil {
			_, err = io.Copy(w, src)
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
		pw.CloseWithError(err)
	}()
	n, err := r.st.Put(ctx, key, pr)
	pr.CloseWithError(errors.New("upload stopped"))
	return n, err
}

// getSealed opens key for reading its plaintext.
func (r *repo) getSealed(ctx context.Context, key string) (io.Reader, io.Closer, error) {
	rc, err := r.st.Get(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	pr, err := objstore.Open(rc, r.pass)
	if err != nil {
		rc.Close()
		return nil, nil, err
	}
	return pr, rc, nil
}

// marker describes the folder.
type marker struct {
	Engine    string    `json:"engine"`
	Database  string    `json:"database"`
	SetName   string    `json:"set_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ---- timestamps

// ts is an oplog timestamp, JSON {"t":..., "i":...}.
type ts struct {
	T uint32 `json:"t"`
	I uint32 `json:"i"`
}

func fromBSON(t bson.Timestamp) ts { return ts{T: t.T, I: t.I} }
func (t ts) bson() bson.Timestamp  { return bson.Timestamp{T: t.T, I: t.I} }
func (t ts) IsZero() bool          { return t.T == 0 && t.I == 0 }
func (t ts) Time() time.Time       { return time.Unix(int64(t.T), 0).UTC() }
func (t ts) String() string        { return fmt.Sprintf("%d:%d", t.T, t.I) }
func (t ts) key() string           { return fmt.Sprintf("%010d-%010d", t.T, t.I) }

func (t ts) Compare(o ts) int {
	switch {
	case t.T != o.T:
		if t.T < o.T {
			return -1
		}
		return 1
	case t.I != o.I:
		if t.I < o.I {
			return -1
		}
		return 1
	}
	return 0
}

func (t ts) After(o ts) bool  { return t.Compare(o) > 0 }
func (t ts) Before(o ts) bool { return t.Compare(o) < 0 }

func parseTSKey(s string) (ts, bool) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return ts{}, false
	}
	t, err1 := strconv.ParseUint(a, 10, 32)
	i, err2 := strconv.ParseUint(b, 10, 32)
	if err1 != nil || err2 != nil {
		return ts{}, false
	}
	return ts{T: uint32(t), I: uint32(i)}, true
}

// parseTS reads "T:I" (a Mark's LSN).
func parseTS(s string) (ts, bool) {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return ts{}, false
	}
	t, err1 := strconv.ParseUint(a, 10, 32)
	i, err2 := strconv.ParseUint(b, 10, 32)
	if err1 != nil || err2 != nil {
		return ts{}, false
	}
	return ts{T: uint32(t), I: uint32(i)}, true
}

// ---- backups

// backupDoc describes one full backup.
type backupDoc struct {
	Label        string            `json:"label"`
	StartTS      ts                `json:"start_ts"` // newest oplog entry before the dump began
	EndTS        ts                `json:"end_ts"`   // newest oplog entry after it ended
	StartedAt    time.Time         `json:"started_at"`
	StoppedAt    time.Time         `json:"stopped_at"`
	DataBytes    int64             `json:"data_bytes"`
	ArchiveBytes int64             `json:"archive_bytes"`
	Version      string            `json:"version"`
	SetName      string            `json:"set_name"`
	Databases    []protocol.DBInfo `json:"databases"`
}

func backupKey(label, name string) string { return backupPrefix + label + "/" + name }

var labelRE = regexp.MustCompile(`^\d{8}-\d{6}F$`)

// newLabel is pgBackRest-like: 20260925-101500F.
func newLabel(t time.Time) string { return t.UTC().Format("20060102-150405") + "F" }

// listBackups returns the finished backups (those with backup.json),
// oldest first. Folders without one are unfinished uploads.
func (r *repo) listBackups(ctx context.Context) ([]backupDoc, []string, error) {
	objs, err := r.st.List(ctx, backupPrefix)
	if err != nil {
		return nil, nil, err
	}
	var labels, unfinished []string
	seen := map[string]bool{}
	finished := map[string]bool{}
	for _, o := range objs {
		rest := strings.TrimPrefix(o.Key, backupPrefix)
		label, name, ok := strings.Cut(rest, "/")
		if !ok || !labelRE.MatchString(label) {
			continue
		}
		if !seen[label] {
			seen[label] = true
			labels = append(labels, label)
		}
		if name == backupDocName {
			finished[label] = true
		}
	}
	var docs []backupDoc
	for _, l := range labels {
		if !finished[l] {
			unfinished = append(unfinished, l)
			continue
		}
		var d backupDoc
		if err := r.getJSON(ctx, backupKey(l, backupDocName), &d); err != nil {
			return nil, nil, fmt.Errorf("reading backup %s: %w", l, err)
		}
		docs = append(docs, d)
	}
	slices.SortFunc(docs, func(a, b backupDoc) int { return strings.Compare(a.Label, b.Label) })
	return docs, unfinished, nil
}

// deleteBackup removes a backup's objects (backup.json first, so a partly
// deleted backup is never taken for a finished one).
func (r *repo) deleteBackup(ctx context.Context, label string) error {
	if err := r.st.Delete(ctx, backupKey(label, backupDocName)); err != nil {
		return err
	}
	objs, err := r.st.List(ctx, backupPrefix+label+"/")
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

// ---- oplog chunks

type chunk struct {
	Key               string
	First, Last, Prev ts
	Size              int64
}

func chunkKey(first, last, prev ts) string {
	return oplogPrefix + first.key() + "_" + last.key() + "_" + prev.key() + ".bson.gz"
}

func parseChunkKey(key string) (chunk, bool) {
	name, ok := strings.CutPrefix(key, oplogPrefix)
	if !ok {
		return chunk{}, false
	}
	name, ok = strings.CutSuffix(name, ".bson.gz")
	if !ok {
		return chunk{}, false
	}
	parts := strings.Split(name, "_")
	if len(parts) != 3 {
		return chunk{}, false
	}
	var c chunk
	var ok1, ok2, ok3 bool
	c.First, ok1 = parseTSKey(parts[0])
	c.Last, ok2 = parseTSKey(parts[1])
	c.Prev, ok3 = parseTSKey(parts[2])
	if !ok1 || !ok2 || !ok3 || c.Last.Before(c.First) || !c.Prev.Before(c.First) {
		return chunk{}, false
	}
	c.Key = key
	return c, true
}

// listChunks lists the oplog chunks in time order.
func (r *repo) listChunks(ctx context.Context) ([]chunk, error) {
	objs, err := r.st.List(ctx, oplogPrefix)
	if err != nil {
		return nil, err
	}
	var out []chunk
	for _, o := range objs {
		if c, ok := parseChunkKey(o.Key); ok {
			c.Size = o.Size
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b chunk) int { return a.First.Compare(b.First) })
	return out, nil
}

// chainFrom returns the chunks (sorted by First) that carry the oplog on,
// without a gap, from the entry after `from`: each chunk must start right
// after an entry the chain already has (Prev at or before it). It returns
// the chain, the newest entry it reaches, and whether it stops at a gap
// (a later chunk exists but starts after an entry that was never copied).
func chainFrom(chunks []chunk, from ts) (chain []chunk, reach ts, gap bool) {
	reach = from
	for _, c := range chunks {
		if !c.Last.After(reach) {
			continue // nothing new (a retried upload)
		}
		if c.Prev.After(reach) {
			return chain, reach, true
		}
		chain = append(chain, c)
		reach = c.Last
	}
	return chain, reach, false
}

// ---- marks

type markDoc struct {
	Name      string    `json:"name"`
	TS        ts        `json:"ts"`
	CreatedAt time.Time `json:"created_at"`
}

var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func markKey(name string) string { return marksPrefix + name + ".json" }
