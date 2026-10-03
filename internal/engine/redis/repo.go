package redis

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

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// The bucket, under <path prefix>/<stanza>/, everything encrypted on the
// server (objstore.Seal) before it is uploaded:
//
//	rowsafe-redis.json                      what this folder is (sealed)
//	backup/<label>/dump.rdb                 a snapshot (RDB, sealed)
//	backup/<label>/backup.json              its description, written last (sealed)
//	stream/<replid>/<start>-<end>-<t0>-<t1>.seg
//	                                        the replication stream from byte offset
//	                                        start to end, received between t0 and t1
//	                                        (Unix ms): each command with the moment it
//	                                        arrived (gzip, sealed)
//	marks/<name>.json                       a Mark: its replication offset (sealed)
//	kept/<rewind id>/dump.rdb, backup.json  the data from before a rewind in place (Undo)
//
// Names say when and where in the stream, never what.

const (
	markerKey     = "rowsafe-redis.json"
	backupPrefix  = "backup/"
	streamPrefix  = "stream/"
	marksPrefix   = "marks/"
	keptPrefix    = "kept/"
	rdbName       = "dump.rdb"
	backupDocName = "backup.json"
)

// repo is one database's folder in the bucket.
type repo struct {
	st   *objstore.Store
	pass string
}

var stanzaRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)

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

// putSealed streams src, sealed, into key and returns the bytes stored.
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
	CreatedAt time.Time `json:"created_at"`
}

// ---- snapshots (backups)

// Snapshot sources.
const (
	sourceScheduled = "scheduled" // a backup task, over the replication handshake
	sourceAutomatic = "automatic" // the server sent a whole snapshot to the replication link
	sourceFile      = "file"      // BGSAVE and the server's own file (snapshot mode)
	sourceRewind    = "rewind"    // the data from before a rewind in place
)

// backupDoc describes one snapshot.
type backupDoc struct {
	Label  string `json:"label"`
	Source string `json:"source"`
	Engine string `json:"engine"`
	// Version is the server's; VersionNum major*10000+minor*100+patch.
	Version    string `json:"version"`
	VersionNum int    `json:"version_num"`
	// ReplID and Offset place the snapshot in the replication stream; when
	// Exact, every change after Offset is in the stream from there.
	ReplID string `json:"replid,omitempty"`
	Offset int64  `json:"offset,omitempty"`
	Exact  bool   `json:"exact"`
	// TakenAt is the moment the snapshot holds.
	TakenAt   time.Time `json:"taken_at"`
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at"`
	// RDBBytes is the snapshot's size, StoredBytes what it takes in the
	// bucket.
	RDBBytes    int64 `json:"rdb_bytes"`
	StoredBytes int64 `json:"stored_bytes"`
	// Keyspace is the keys (and keys with an expiry) per logical database
	// when the snapshot was taken, for Proof.
	Keyspace          map[string]dbKeys `json:"keyspace"`
	UsedMemoryDataset int64             `json:"used_memory_dataset"`
	Databases         int               `json:"databases"`
	// Modules are the modules the server had loaded (path and arguments):
	// a temporary server loads them too to read their data types.
	Modules [][]string `json:"modules,omitempty"`
	Note    string     `json:"note,omitempty"`
}

func (d backupDoc) position() string {
	if d.ReplID == "" {
		return ""
	}
	return d.ReplID + ":" + strconv.FormatInt(d.Offset, 10)
}

func backupKey(label, name string) string { return backupPrefix + label + "/" + name }
func keptKey(id, name string) string      { return keptPrefix + id + "/" + name }

var labelRE = regexp.MustCompile(`^\d{8}-\d{6}F$`)

// newLabel is pgBackRest-like: 20260925-101500F.
func newLabel(t time.Time) string { return t.UTC().Format("20060102-150405") + "F" }

// freshLabel is a label no other snapshot of this folder has (two snapshots
// in the same second take the next free second).
func (r *repo) freshLabel(ctx context.Context, t time.Time) (string, error) {
	for range 30 {
		l := newLabel(t)
		objs, err := r.st.List(ctx, backupPrefix+l+"/")
		if err != nil {
			return "", err
		}
		if len(objs) == 0 {
			return l, nil
		}
		t = t.Add(time.Second)
	}
	return "", errors.New("too many snapshots in the same moment")
}

// listBackups returns the finished snapshots (with backup.json), oldest
// first, and the labels of unfinished uploads.
func (r *repo) listBackups(ctx context.Context) ([]backupDoc, []string, error) {
	objs, err := r.st.List(ctx, backupPrefix)
	if err != nil {
		return nil, nil, err
	}
	var labels, unfinished []string
	seen, finished := map[string]bool{}, map[string]bool{}
	for _, o := range objs {
		label, name, ok := strings.Cut(strings.TrimPrefix(o.Key, backupPrefix), "/")
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

// deletePrefix removes every object under prefix, the description first so
// a partly deleted snapshot is never taken for a finished one.
func (r *repo) deletePrefix(ctx context.Context, prefix string) error {
	if err := r.st.Delete(ctx, prefix+backupDocName); err != nil && !errors.Is(err, objstore.ErrNotFound) {
		return err
	}
	objs, err := r.st.List(ctx, prefix)
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := r.st.Delete(ctx, o.Key); err != nil && !errors.Is(err, objstore.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (r *repo) deleteBackup(ctx context.Context, label string) error {
	return r.deletePrefix(ctx, backupPrefix+label+"/")
}

// ---- stream segments

// segment is one uploaded piece of the replication stream.
type segment struct {
	Key        string
	ReplID     string
	Start, End int64     // byte offsets: the first command starts at Start, the last ends at End
	From, To   time.Time // the link was up and receiving from From to To
	Size       int64
}

var replIDRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

func segmentKey(replid string, start, end int64, from, to time.Time) string {
	return fmt.Sprintf("%s%s/%019d-%019d-%013d-%013d.seg", streamPrefix, replid, start, end, from.UnixMilli(), to.UnixMilli())
}

func parseSegmentKey(key string) (segment, bool) {
	rest, ok := strings.CutPrefix(key, streamPrefix)
	if !ok {
		return segment{}, false
	}
	replid, name, ok := strings.Cut(rest, "/")
	if !ok || !replIDRE.MatchString(replid) {
		return segment{}, false
	}
	name, ok = strings.CutSuffix(name, ".seg")
	if !ok {
		return segment{}, false
	}
	parts := strings.Split(name, "-")
	if len(parts) != 4 {
		return segment{}, false
	}
	var n [4]int64
	for i, p := range parts {
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil || v < 0 {
			return segment{}, false
		}
		n[i] = v
	}
	s := segment{Key: key, ReplID: replid, Start: n[0], End: n[1], From: time.UnixMilli(n[2]).UTC(), To: time.UnixMilli(n[3]).UTC()}
	if s.End < s.Start || s.To.Before(s.From) {
		return segment{}, false
	}
	return s, true
}

// listSegments lists the stream segments of every replication id, by id
// then offset.
func (r *repo) listSegments(ctx context.Context) ([]segment, error) {
	objs, err := r.st.List(ctx, streamPrefix)
	if err != nil {
		return nil, err
	}
	var out []segment
	for _, o := range objs {
		if s, ok := parseSegmentKey(o.Key); ok {
			s.Size = o.Size
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b segment) int {
		if c := strings.Compare(a.ReplID, b.ReplID); c != 0 {
			return c
		}
		if a.Start != b.Start {
			return cmpInt(a.Start, b.Start)
		}
		return cmpInt(a.End, b.End)
	})
	return out, nil
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// chainFrom returns the segments of replid that carry the stream on,
// without a gap, from offset: the first must start at or before it, each
// next one where the previous ended. reach is the offset the chain gets
// to, until the moment the link was last known up (the end of the newest
// segment), gap whether a later segment exists past a hole.
func chainFrom(segs []segment, replid string, offset int64) (chain []segment, reach int64, until time.Time, gap bool) {
	reach = offset
	for _, s := range segs {
		if s.ReplID != replid || s.End < reach || s.End == reach && s.Start < reach {
			continue
		}
		if s.Start > reach {
			return chain, reach, until, true
		}
		chain = append(chain, s)
		reach = max(reach, s.End)
		if s.To.After(until) {
			until = s.To
		}
	}
	return chain, reach, until, false
}

// ---- Marks

type markDoc struct {
	Name      string    `json:"name"`
	ReplID    string    `json:"replid"`
	Offset    int64     `json:"offset"`
	CreatedAt time.Time `json:"created_at"`
}

var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func markKey(name string) string { return marksPrefix + name + ".json" }

// parsePosition reads "<replid>:<offset>".
func parsePosition(s string) (string, int64, bool) {
	id, off, ok := strings.Cut(s, ":")
	if !ok || !replIDRE.MatchString(id) {
		return "", 0, false
	}
	n, err := strconv.ParseInt(off, 10, 64)
	return id, n, err == nil && n >= 0
}
