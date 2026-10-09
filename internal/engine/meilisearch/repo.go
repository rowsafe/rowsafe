package meilisearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// The bucket, under <path prefix>/<stanza>/, everything encrypted on the
// server (objstore.Seal) before it is uploaded:
//
//	rowsafe-meilisearch.json         what this folder is (sealed)
//	backup/<label>/data.snapshot     a snapshot as Meilisearch wrote it (tar.gz, sealed)
//	backup/<label>/backup.json       its description, written last (sealed)
//	marks/<name>.json                a Mark: the label of its snapshot (sealed)
//
// Names say when, never what.

const (
	markerKey     = "rowsafe-meilisearch.json"
	backupPrefix  = "backup/"
	marksPrefix   = "marks/"
	snapshotName  = "data.snapshot"
	backupDocName = "backup.json"
)

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

type marker struct {
	Engine    string    `json:"engine"`
	Database  string    `json:"database"`
	CreatedAt time.Time `json:"created_at"`
}

// Snapshot sources.
const (
	sourceScheduled = "scheduled" // a backup task
	sourceMark      = "mark"      // taken for a Mark
)

// backupDoc describes one snapshot.
type backupDoc struct {
	Label   string `json:"label"`
	Source  string `json:"source"`
	Mark    string `json:"mark,omitempty"`
	Version string `json:"version"`
	// TakenAt is the moment the snapshot holds (when Meilisearch started
	// writing it).
	TakenAt   time.Time `json:"taken_at"`
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at"`
	// SnapshotBytes is the snapshot file's size, StoredBytes what it takes
	// in the bucket, DatabaseBytes the instance's size on disk then.
	SnapshotBytes int64 `json:"snapshot_bytes"`
	StoredBytes   int64 `json:"stored_bytes"`
	DatabaseBytes int64 `json:"database_bytes"`
	// Indexes are the indexes when the snapshot was taken, for Proof.
	Indexes []indexDoc `json:"indexes"`
}

// indexDoc is one index in a snapshot: its documents and a fingerprint of
// its settings (SHA-256 of their JSON), never their content.
type indexDoc struct {
	UID          string `json:"uid"`
	PrimaryKey   string `json:"primary_key,omitempty"`
	Documents    int64  `json:"documents"`
	SettingsHash string `json:"settings_hash,omitempty"`
}

func (d backupDoc) documents() int64 {
	var n int64
	for _, i := range d.Indexes {
		n += i.Documents
	}
	return n
}

func backupKey(label, name string) string { return backupPrefix + label + "/" + name }

var labelRE = regexp.MustCompile(`^\d{8}-\d{6}F$`)

// newLabel is pgBackRest-like: 20260925-101500F.
func newLabel(t time.Time) string { return t.UTC().Format("20060102-150405") + "F" }

// freshLabel is a label no other snapshot of this folder has.
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

// listBackups returns the finished snapshots, oldest first, and the labels
// of unfinished uploads.
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

// deleteBackup removes a snapshot, its description first so a partly
// deleted one is never taken for a finished one.
func (r *repo) deleteBackup(ctx context.Context, label string) error {
	prefix := backupPrefix + label + "/"
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

// ---- Marks

type markDoc struct {
	Name      string    `json:"name"`
	Label     string    `json:"label"`
	CreatedAt time.Time `json:"created_at"`
}

var markNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

func markKey(name string) string { return marksPrefix + name + ".json" }

// markedLabels are the snapshots Marks point at, each with its Marks'
// records (keys under marks/).
func (r *repo) markedLabels(ctx context.Context) (map[string][]string, error) {
	objs, err := r.st.List(ctx, marksPrefix)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, o := range objs {
		var m markDoc
		if err := r.getJSON(ctx, o.Key, &m); err == nil && m.Label != "" {
			out[m.Label] = append(out[m.Label], o.Key)
		}
	}
	return out, nil
}
