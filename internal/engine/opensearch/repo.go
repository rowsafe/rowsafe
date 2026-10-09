package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// The bucket, under <path prefix>/<stanza>/, everything encrypted on the
// server (objstore.Seal) before it is uploaded:
//
//	rowsafe-opensearch.json   what this folder is
//	repo/<path>               each file of OpenSearch's snapshot repository,
//	                          under the same name (OpenSearch names data
//	                          files and index folders by random ids; the
//	                          repository keeps the default fixed shard paths,
//	                          so snapshot_shard_paths/, whose file names would
//	                          carry index names, stays empty: names never say
//	                          what; the integration test checks it)
//	repo-pending-deletions.json  files waiting out the grace period (syncRepo)
//	backups/<label>.json      what a snapshot holds: its indices and their
//	                          documents (for Proof and the dashboard)
//
// The repository's files never change once written, except index.latest
// (which root index-N is current): new files go up first, index-N next,
// index.latest last, so the bucket always holds a whole repository. Files
// leave the bucket only as syncRepo allows (what Rowsafe's own deletions
// removed, after a grace period, never a recorded snapshot's).

const (
	markerKey  = "rowsafe-opensearch.json"
	repoPrefix = "repo/"
	docsPrefix = "backups/"
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

// getSealedTo downloads key and writes its plaintext to path (0600).
func (r *repo) getSealedTo(ctx context.Context, key, path string) (int64, error) {
	rc, err := r.st.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	pr, err := objstore.Open(rc, r.pass)
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return 0, err
	}
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(fh, pr)
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// marker describes the folder. ClusterUUID is the OpenSearch cluster whose
// snapshot repository the folder copies: another one (a rebuilt or
// re-enrolled server, an empty repository) never overwrites it.
type marker struct {
	Engine      string    `json:"engine"`
	Database    string    `json:"database"`
	CreatedAt   time.Time `json:"created_at"`
	ClusterUUID string    `json:"cluster_uuid,omitempty"`
}

// errOtherCluster: the folder copies another OpenSearch's repository.
var errOtherCluster = errors.New("this database's folder in your bucket holds the snapshots of another OpenSearch (an earlier server, or one set up again). " +
	"Rowsafe doesn't overwrite them: set this server up as a new database (a new folder), or restore those snapshots first")

// ensureMarker writes the folder's marker (with the cluster's id), refusing
// a folder of another engine or of another OpenSearch cluster.
func (r *repo) ensureMarker(ctx context.Context, name, clusterUUID string) error {
	var m marker
	switch err := r.getJSON(ctx, markerKey, &m); {
	case err == nil:
		if m.Engine != protocol.EngineOpenSearch {
			return fmt.Errorf("the bucket folder already holds %s backups", protocol.EngineDisplayName(m.Engine))
		}
		if m.ClusterUUID != "" && clusterUUID != "" && m.ClusterUUID != clusterUUID {
			return errOtherCluster
		}
		if m.ClusterUUID == "" && clusterUUID != "" {
			m.ClusterUUID = clusterUUID
			if err := r.putJSON(ctx, markerKey, m); err != nil {
				return fmt.Errorf("writing to your bucket: %w", err)
			}
		}
		return nil
	case errors.Is(err, objstore.ErrNotFound):
		if err := r.putJSON(ctx, markerKey, marker{Engine: protocol.EngineOpenSearch, Database: name, CreatedAt: time.Now().UTC(), ClusterUUID: clusterUUID}); err != nil {
			return fmt.Errorf("writing to your bucket: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("reading your bucket: %w", err)
	}
}

// backupDoc describes one snapshot (backups/<label>.json).
type backupDoc struct {
	Label     string    `json:"label"`
	Snapshot  string    `json:"snapshot"`
	UUID      string    `json:"uuid"`
	Kind      string    `json:"kind"` // F, D, M, R
	Mark      string    `json:"mark,omitempty"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at"`
	// Indices are the indices in the snapshot with their documents counted
	// just before and just after it (equal when nothing was written
	// meanwhile); DataStreams the data streams.
	Indices     []docIndex `json:"indices"`
	DataStreams []string   `json:"data_streams,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
	// StoredBytes is what the copy to the bucket added.
	StoredBytes int64 `json:"stored_bytes"`
	// KeepUntil (R: before a rewind in place) is when it may be deleted.
	KeepUntil *time.Time `json:"keep_until,omitempty"`
}

// docIndex is one index of a snapshot.
type docIndex struct {
	Name       string `json:"name"`
	DataStream string `json:"data_stream,omitempty"`
	DocsBefore int64  `json:"docs_before"`
	DocsAfter  int64  `json:"docs_after"`
}

func docKey(label string) string { return docsPrefix + label + ".json" }

// listDocs reads every backups/*.json, oldest first.
func (r *repo) listDocs(ctx context.Context) ([]backupDoc, error) {
	objs, err := r.st.List(ctx, docsPrefix)
	if err != nil {
		return nil, err
	}
	var out []backupDoc
	for _, o := range objs {
		label := strings.TrimSuffix(strings.TrimPrefix(o.Key, docsPrefix), ".json")
		if !labelRE.MatchString(label) {
			continue
		}
		var d backupDoc
		if err := r.getJSON(ctx, o.Key, &d); err != nil {
			return nil, fmt.Errorf("reading %s: %w", o.Key, err)
		}
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b backupDoc) int { return a.StartedAt.Compare(b.StartedAt) })
	return out, nil
}

// ---- the repository's copy in the bucket

// repoFile is one file of the local repository.
type repoFile struct {
	Rel  string // slash-separated, relative to the repository
	Size int64
}

// localRepoFiles lists the repository's files.
func localRepoFiles(dir string) ([]repoFile, error) {
	var out []repoFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out = append(out, repoFile{Rel: filepath.ToSlash(rel), Size: info.Size()})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading the snapshot folder %s: %w", dir, err)
	}
	return out, nil
}

// uploadOrder: data first, then the files that point at it, the root
// index-N next and index.latest last.
func uploadOrder(rel string) int {
	base := filepath.Base(rel)
	switch {
	case rel == "index.latest":
		return 4
	case !strings.Contains(rel, "/") && strings.HasPrefix(base, "index-"):
		return 3
	case strings.HasPrefix(base, "__"):
		return 0
	case strings.HasPrefix(rel, "indices/"):
		return 1
	}
	return 2
}

// syncStats says what a copy to the bucket did.
type syncStats struct {
	Uploaded      int
	UploadedBytes int64 // plain bytes read
	StoredBytes   int64 // bytes stored in the bucket
	Deleted       int
	Files         int
	RepoBytes     int64
	// Held says why deletions were held back ("" when none were).
	Held string
}

// Deletions from the bucket are careful: the bucket is the copy that
// survives the server. A file is removed only when Rowsafe itself deleted
// the snapshot that needed it (the files that disappeared from the
// repository while Rowsafe deleted snapshots: removed), or when it is a
// superseded root index-N; never a snapshot's own files while a backup
// record (backups/*.json) still names the snapshot; only after a grace
// period (deleteGrace) during which the file stayed gone from the
// repository; and never more than maxDeleteShare of the bucket's files in
// one go (something emptied the repository: the copy is kept and the task
// log says so).
const (
	pendingKey     = "repo-pending-deletions.json"
	maxDeleteShare = 0.5
)

// deleteGrace (a variable for tests).
var deleteGrace = 24 * time.Hour

// localSet is the repository's files, by relative path.
func localSet(dir string) (map[string]bool, error) {
	files, err := localRepoFiles(dir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(files))
	for _, f := range files {
		out[f.Rel] = true
	}
	return out, nil
}

// gone lists what was in before and isn't in after.
func gone(before, after map[string]bool) []string {
	var out []string
	for f := range before {
		if !after[f] {
			out = append(out, f)
		}
	}
	slices.Sort(out)
	return out
}

var rootIndexRE = regexp.MustCompile(`^index-([0-9]+)$`)

// syncRepo copies the local repository dir to the bucket's repo/: new and
// changed files go up; removed (files that disappeared while Rowsafe
// deleted snapshots) and superseded root index-N files are deleted after
// the grace period. clusterUUID is the server's: the folder must be its
// (ensureMarker). The caller holds the database's lock.
func (r *repo) syncRepo(ctx context.Context, dir, clusterUUID string, removed []string) (syncStats, error) {
	var st syncStats
	if err := r.ensureMarker(ctx, "", clusterUUID); err != nil {
		return st, err
	}
	local, err := localRepoFiles(dir)
	if err != nil {
		return st, err
	}
	remote, err := r.st.List(ctx, repoPrefix)
	if err != nil {
		return st, fmt.Errorf("listing your bucket: %w", err)
	}
	have := make(map[string]int64, len(remote))
	for _, o := range remote {
		have[strings.TrimPrefix(o.Key, repoPrefix)] = o.Size
	}
	if len(local) == 0 && len(remote) > 0 {
		return st, errors.New("OpenSearch's snapshot folder on this server is empty, but your bucket holds its snapshots: Rowsafe keeps them and copies nothing until the folder is OpenSearch's again")
	}
	var todo []repoFile
	keep := make(map[string]bool, len(local))
	latest := int64(-1)
	for _, f := range local {
		keep[f.Rel] = true
		st.Files++
		st.RepoBytes += f.Size
		if m := rootIndexRE.FindStringSubmatch(f.Rel); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			latest = max(latest, n)
		}
		size, ok := have[f.Rel]
		if ok && size == objstore.SealedSize(f.Size) && f.Rel != "index.latest" {
			continue
		}
		todo = append(todo, f)
	}
	slices.SortStableFunc(todo, func(a, b repoFile) int { return uploadOrder(a.Rel) - uploadOrder(b.Rel) })
	// Files of one order go up in parallel; the next order waits for them.
	for i := 0; i < len(todo); {
		j := i
		for j < len(todo) && uploadOrder(todo[j].Rel) == uploadOrder(todo[i].Rel) {
			j++
		}
		if err := r.uploadAll(ctx, dir, todo[i:j], &st); err != nil {
			return st, err
		}
		i = j
	}

	// What may go: what Rowsafe's deletions removed, superseded index-N.
	cand := map[string]bool{}
	for _, f := range removed {
		cand[f] = true
	}
	for rel := range have {
		if m := rootIndexRE.FindStringSubmatch(rel); m != nil {
			if n, _ := strconv.ParseInt(m[1], 10, 64); latest >= 0 && n < latest {
				cand[rel] = true
			}
		}
	}
	// Never a recorded snapshot's own files.
	if docs, err := r.listDocs(ctx); err == nil {
		for _, d := range docs {
			if d.UUID != "" {
				delete(cand, "snap-"+d.UUID+".dat")
				delete(cand, "meta-"+d.UUID+".dat")
			}
		}
	} else {
		return st, fmt.Errorf("reading the backup records in your bucket: %w", err)
	}
	var pending map[string]time.Time
	if err := r.getJSON(ctx, pendingKey, &pending); err != nil && !errors.Is(err, objstore.ErrNotFound) {
		return st, fmt.Errorf("reading your bucket: %w", err)
	}
	if pending == nil {
		pending = map[string]time.Time{}
	}
	now := time.Now().UTC()
	for rel := range pending {
		if keep[rel] {
			delete(pending, rel) // back in the repository: keep it
		}
	}
	for rel := range cand {
		if _, ok := have[rel]; ok && !keep[rel] {
			if _, ok := pending[rel]; !ok {
				pending[rel] = now
			}
		}
	}
	var due []string
	for rel, since := range pending {
		if _, ok := have[rel]; !ok {
			delete(pending, rel)
			continue
		}
		if now.Sub(since) >= deleteGrace {
			due = append(due, rel)
		}
	}
	slices.Sort(due)
	if len(due) > 20 && float64(len(due)) > maxDeleteShare*float64(len(have)) {
		st.Held = fmt.Sprintf("%d of the %d files in your bucket would go at once: Rowsafe keeps them (something may have emptied the snapshot folder)", len(due), len(have))
		due = nil
	}
	for _, rel := range due {
		if err := r.st.Delete(ctx, repoPrefix+rel); err != nil {
			return st, fmt.Errorf("removing %s from your bucket: %w", rel, err)
		}
		delete(pending, rel)
		st.Deleted++
	}
	if err := r.putJSON(ctx, pendingKey, pending); err != nil {
		return st, fmt.Errorf("writing to your bucket: %w", err)
	}
	return st, nil
}

// uploadAll uploads files (four at a time).
func (r *repo) uploadAll(ctx context.Context, dir string, files []repoFile, st *syncStats) error {
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			fh, err := os.Open(filepath.Join(dir, filepath.FromSlash(f.Rel)))
			var n int64
			if err == nil {
				n, err = r.putSealed(ctx, repoPrefix+f.Rel, fh)
				fh.Close()
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("copying %s to your bucket: %w", f.Rel, err)
				}
				return
			}
			st.Uploaded++
			st.UploadedBytes += f.Size
			st.StoredBytes += n
		}()
	}
	wg.Wait()
	return firstErr
}

// repoData is the part of the repository's root index-N Rowsafe reads.
type repoData struct {
	Snapshots []struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"snapshots"`
	Indices map[string]struct {
		ID        string   `json:"id"`
		Snapshots []string `json:"snapshots"`
	} `json:"indices"`
}

// download writes into dir the part of the bucket's repository a restore
// of snapshot name needs: the root files, the shard paths and the folders
// of the snapshot's indices. It returns the plain bytes written.
func (r *repo) download(ctx context.Context, dir, name string) (int64, error) {
	objs, err := r.st.List(ctx, repoPrefix)
	if err != nil {
		return 0, fmt.Errorf("listing your bucket: %w", err)
	}
	var total int64
	get := func(rel string) error {
		if strings.Contains(rel, "..") {
			return fmt.Errorf("unexpected file %q in the bucket", rel)
		}
		n, err := r.getSealedTo(ctx, repoPrefix+rel, filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("downloading %s: %w", rel, err)
		}
		total += n
		return nil
	}
	if err := get("index.latest"); err != nil {
		return total, err
	}
	gen, err := os.ReadFile(filepath.Join(dir, "index.latest"))
	if err != nil || len(gen) != 8 {
		return total, errors.New("the repository in your bucket has no readable index.latest")
	}
	n := int64(0)
	for _, b := range gen {
		n = n<<8 | int64(b)
	}
	indexN := "index-" + strconv.FormatInt(n, 10)
	if err := get(indexN); err != nil {
		return total, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, indexN))
	if err != nil {
		return total, err
	}
	var rd repoData
	if err := json.Unmarshal(raw, &rd); err != nil {
		return total, fmt.Errorf("reading the repository's %s: %w", indexN, err)
	}
	uuid := ""
	for _, s := range rd.Snapshots {
		if s.Name == name {
			uuid = s.UUID
		}
	}
	if uuid == "" {
		return total, fmt.Errorf("the snapshot %s isn't in the repository in your bucket (retention removed it?)", name)
	}
	ids := map[string]bool{}
	for _, idx := range rd.Indices {
		if slices.Contains(idx.Snapshots, uuid) {
			ids[idx.ID] = true
		}
	}
	var todo []string
	for _, o := range objs {
		rel := strings.TrimPrefix(o.Key, repoPrefix)
		if rel == "index.latest" || rel == indexN {
			continue
		}
		switch {
		case !strings.Contains(rel, "/"):
			todo = append(todo, rel)
		case strings.HasPrefix(rel, "snapshot_shard_paths/"):
			todo = append(todo, rel)
		case strings.HasPrefix(rel, "indices/"):
			parts := strings.SplitN(rel, "/", 3)
			if len(parts) == 3 && ids[parts[1]] {
				todo = append(todo, rel)
			}
		}
	}
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, rel := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if strings.Contains(rel, "..") {
				return
			}
			nb, err := r.getSealedTo(ctx, repoPrefix+rel, filepath.Join(dir, filepath.FromSlash(rel)))
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("downloading %s: %w", rel, err)
			}
			total += nb
		}()
	}
	wg.Wait()
	return total, firstErr
}

// deleteAll removes the folder's repository copy and documents (never the
// marker); used when a database is removed with its backups.
func (r *repo) deletePrefix(ctx context.Context, prefix string) error {
	objs, err := r.st.List(ctx, prefix)
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

// Backups lists a folder's snapshots for people (download-backup): one
// line each, oldest first.
func Backups(ctx context.Context, env agent.EngineEnv, stanza string) ([]string, error) {
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return nil, err
	}
	docs, err := r.listDocs(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range docs {
		note := ""
		if d.Mark != "" {
			note = "  Mark " + d.Mark
		}
		out = append(out, fmt.Sprintf("%-18s %-28s finished %s, %d indices%s", d.Label, d.Snapshot, d.StoppedAt.UTC().Format("2006-01-02 15:04:05Z"), len(d.Indices), note))
	}
	return out, nil
}

// DownloadBackup decrypts what snapshot label needs into dir (empty or
// new) and returns the snapshot's name in that repository.
func DownloadBackup(ctx context.Context, env agent.EngineEnv, stanza, label, dir string) (string, error) {
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: stanza})
	if err != nil {
		return "", err
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return "", fmt.Errorf("%s isn't empty", dir)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := snapshotName(strings.ToUpper(label))
	if _, err := r.download(ctx, dir, name); err != nil {
		return "", err
	}
	return name, nil
}
