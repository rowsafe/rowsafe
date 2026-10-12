package opensearch

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeOS is a single-node OpenSearch good enough for moves: indices with
// write blocks, data streams, cluster settings, an fs snapshot repository
// on disk (the files the agent copies), templates and pipelines.
type fakeOS struct {
	mu       sync.Mutex
	uuid     string
	version  string
	pathRepo string
	indices  map[string]*fIndex
	streams  map[string][]string
	settings map[string]map[string]any // persistent, transient
	repo     map[string]any            // the rowsafe repository's settings (nil: none)
	globals  map[string]map[string]json.RawMessage
	forbid   []string // "METHOD path-prefix" answered 403
	srv      *httptest.Server
}

type fIndex struct {
	Blocked bool   `json:"blocked"`
	DS      string `json:"ds,omitempty"`
}

// snapMeta is what the fake writes into snap-<uuid>.dat.
type snapMeta struct {
	Name    string             `json:"name"`
	UUID    string             `json:"uuid"`
	Indices map[string]*fIndex `json:"indices"`
	Streams map[string][]string
	StartMS int64 `json:"start"`
}

func newFakeOS(t *testing.T, uuid, version, pathRepo string) *fakeOS {
	f := &fakeOS{uuid: uuid, version: version, pathRepo: pathRepo, indices: map[string]*fIndex{}, streams: map[string][]string{},
		settings: map[string]map[string]any{"persistent": {}, "transient": {}}, globals: map[string]map[string]json.RawMessage{}}
	f.indices[".opendistro_security"] = &fIndex{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOS) use(t *testing.T) {
	t.Setenv(urlEnv, f.srv.URL)
	t.Setenv(repoDirEnv, f.pathRepo)
}

func randHex() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func osErr(w http.ResponseWriter, status int, typ, reason string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"type": typ, "reason": reason}, "status": status})
}

var globalPaths = map[string]string{"_ingest": "pipeline", "_component_template": "component", "_index_template": "index", "_template": "legacy"}

func (f *fakeOS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.Path
	for _, x := range f.forbid {
		m, pre, _ := strings.Cut(x, " ")
		if r.Method == m && strings.HasPrefix(p, pre) {
			writeJSON(w, http.StatusForbidden, map[string]any{"status": 403, "message": "no permissions"})
			return
		}
	}
	var body map[string]any
	if data, _ := io.ReadAll(r.Body); len(data) > 0 {
		_ = json.Unmarshal(data, &body)
	}
	seg := strings.Split(strings.TrimPrefix(p, "/"), "/")
	switch {
	case p == "/":
		writeJSON(w, 200, map[string]any{"cluster_name": "c", "cluster_uuid": f.uuid, "version": map[string]any{"number": f.version, "distribution": "opensearch"}})
	case p == "/_cluster/health":
		writeJSON(w, 200, map[string]any{"status": "green", "number_of_nodes": 1})
	case p == "/_nodes/_local/settings":
		writeJSON(w, 200, map[string]any{"nodes": map[string]any{"n1": map[string]any{"settings": map[string]any{"path": map[string]any{"repo": []string{f.pathRepo}}}}}})
	case p == "/_plugins/_security/authinfo":
		osErr(w, 404, "", "no handler")
	case p == "/_cat/indices":
		var rows []map[string]string
		for n := range f.indices {
			rows = append(rows, map[string]string{"index": n, "health": "green", "status": "open", "docs.count": "1", "store.size": "10", "rep": "0"})
		}
		writeJSON(w, 200, rows)
	case p == "/_data_stream" && r.Method == http.MethodGet:
		var out []map[string]any
		for n, idx := range f.streams {
			var is []map[string]string
			for _, i := range idx {
				is = append(is, map[string]string{"index_name": i})
			}
			out = append(out, map[string]any{"name": n, "indices": is})
		}
		writeJSON(w, 200, map[string]any{"data_streams": out})
	case seg[0] == "_data_stream" && r.Method == http.MethodDelete:
		idx, ok := f.streams[seg[1]]
		if !ok {
			osErr(w, 404, "resource_not_found_exception", "no such data stream")
			return
		}
		for _, i := range idx {
			delete(f.indices, i)
		}
		delete(f.streams, seg[1])
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case p == "/_cluster/settings" && r.Method == http.MethodGet:
		writeJSON(w, 200, f.settings)
	case p == "/_cluster/settings" && r.Method == http.MethodPut:
		for _, k := range []string{"persistent", "transient"} {
			if m, ok := body[k].(map[string]any); ok {
				for kk, v := range m {
					if v == nil {
						delete(f.settings[k], kk)
					} else {
						f.settings[k][kk] = fmt.Sprint(v)
					}
				}
			}
		}
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case p == "/_refresh":
		writeJSON(w, 200, map[string]any{})
	case globalPaths[seg[0]] != "":
		kind := globalPaths[seg[0]]
		if seg[0] == "_ingest" {
			seg = seg[1:]
		}
		g := f.globals[kind]
		if g == nil {
			g = map[string]json.RawMessage{}
			f.globals[kind] = g
		}
		name := ""
		if len(seg) > 1 {
			name = seg[1]
		}
		switch r.Method {
		case http.MethodGet:
			if name != "" {
				if _, ok := g[name]; !ok {
					osErr(w, 404, "resource_not_found_exception", "missing")
					return
				}
			}
			switch kind {
			case "component", "index":
				key, item := map[string]string{"component": "component_templates", "index": "index_templates"}[kind], map[string]string{"component": "component_template", "index": "index_template"}[kind]
				var out []map[string]any
				for n, v := range g {
					if name == "" || n == name {
						out = append(out, map[string]any{"name": n, item: v})
					}
				}
				writeJSON(w, 200, map[string]any{key: out})
			default:
				writeJSON(w, 200, g)
			}
		case http.MethodPut:
			b, _ := json.Marshal(body)
			g[name] = b
			writeJSON(w, 200, map[string]any{"acknowledged": true})
		case http.MethodDelete:
			delete(g, name)
			writeJSON(w, 200, map[string]any{"acknowledged": true})
		}
	case seg[0] == "_snapshot":
		f.snapshot(w, r, seg, body)
	case len(seg) >= 2 && seg[1] == "_settings":
		names := strings.Split(seg[0], ",")
		if r.Method == http.MethodGet {
			out := map[string]any{}
			for _, n := range names {
				if i, ok := f.indices[n]; ok {
					s := map[string]any{}
					if i.Blocked {
						s["index.blocks.write"] = "true"
					}
					out[n] = map[string]any{"settings": s}
				}
			}
			writeJSON(w, 200, out)
			return
		}
		for _, n := range names {
			if i, ok := f.indices[n]; ok {
				i.Blocked = body["index.blocks.write"] == true
			}
		}
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case len(seg) == 2 && seg[1] == "_count":
		writeJSON(w, 200, map[string]any{"count": 1})
	case len(seg) == 1 && r.Method == http.MethodDelete:
		for _, n := range strings.Split(seg[0], ",") {
			delete(f.indices, n)
		}
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case len(seg) == 1 && r.Method == http.MethodPut:
		f.indices[seg[0]] = &fIndex{}
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	default:
		osErr(w, 400, "illegal_argument_exception", "fake: no handler for "+r.Method+" "+p)
	}
}

func (f *fakeOS) location() string {
	if f.repo == nil {
		return ""
	}
	return fmt.Sprint(f.repo["location"])
}

// repoState reads the repository's current generation and snapshots.
func (f *fakeOS) repoState() (int64, []snapMeta) {
	loc := f.location()
	g, err := os.ReadFile(filepath.Join(loc, "index.latest"))
	if err != nil || len(g) != 8 {
		return -1, nil
	}
	n := int64(binary.BigEndian.Uint64(g))
	raw, err := os.ReadFile(filepath.Join(loc, fmt.Sprintf("index-%d", n)))
	if err != nil {
		return n, nil
	}
	var rd struct {
		Snapshots []struct{ Name, UUID string } `json:"snapshots"`
	}
	_ = json.Unmarshal(raw, &rd)
	var out []snapMeta
	for _, s := range rd.Snapshots {
		var m snapMeta
		data, err := os.ReadFile(filepath.Join(loc, "snap-"+s.UUID+".dat"))
		if err == nil && json.Unmarshal(data, &m) == nil {
			out = append(out, m)
		}
	}
	return n, out
}

func (m snapMeta) info() map[string]any {
	var idx []string
	for n := range m.Indices {
		idx = append(idx, n)
	}
	sort.Strings(idx)
	var ds []string
	for n := range m.Streams {
		ds = append(ds, n)
	}
	sort.Strings(ds)
	return map[string]any{"snapshot": m.Name, "uuid": m.UUID, "state": "SUCCESS", "indices": idx, "data_streams": ds,
		"start_time_in_millis": m.StartMS, "end_time_in_millis": m.StartMS + 10}
}

func (f *fakeOS) snapshot(w http.ResponseWriter, r *http.Request, seg []string, body map[string]any) {
	if len(seg) < 2 || seg[1] != repoName {
		osErr(w, 404, "repository_missing_exception", "missing")
		return
	}
	switch {
	case len(seg) == 2 && r.Method == http.MethodGet:
		if f.repo == nil {
			osErr(w, 404, "repository_missing_exception", "missing")
			return
		}
		writeJSON(w, 200, map[string]any{repoName: map[string]any{"type": "fs", "settings": f.repo}})
	case len(seg) == 2 && r.Method == http.MethodPut:
		s, _ := body["settings"].(map[string]any)
		if fmt.Sprint(s["location"]) != f.pathRepo {
			osErr(w, 500, "repository_exception", "location doesn't match any of the locations specified by path.repo")
			return
		}
		f.repo = s
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case len(seg) == 2 && r.Method == http.MethodDelete:
		if f.repo == nil {
			osErr(w, 404, "repository_missing_exception", "missing")
			return
		}
		f.repo = nil
		writeJSON(w, 200, map[string]any{"acknowledged": true})
	case len(seg) == 3 && r.Method == http.MethodGet:
		if f.repo == nil {
			osErr(w, 404, "repository_missing_exception", "missing")
			return
		}
		_, snaps := f.repoState()
		var out []map[string]any
		for _, s := range snaps {
			if seg[2] == "_all" || s.Name == seg[2] {
				out = append(out, s.info())
			}
		}
		if seg[2] != "_all" && len(out) == 0 {
			osErr(w, 404, "snapshot_missing_exception", "missing")
			return
		}
		writeJSON(w, 200, map[string]any{"snapshots": out})
	case len(seg) == 3 && r.Method == http.MethodPut:
		if f.repo == nil || f.repo["readonly"] == true {
			osErr(w, 500, "repository_exception", "cannot create snapshot in a readonly repository")
			return
		}
		loc := f.location()
		n, snaps := f.repoState()
		m := snapMeta{Name: seg[2], UUID: randHex(), Indices: map[string]*fIndex{}, Streams: map[string][]string{}, StartMS: time.Now().UnixMilli()}
		for name, i := range f.indices {
			if !strings.HasPrefix(name, ".") || i.DS != "" {
				c := *i
				m.Indices[name] = &c
				if err := os.MkdirAll(filepath.Join(loc, "indices", "id-"+name, "0"), 0o755); err == nil {
					_ = os.WriteFile(filepath.Join(loc, "indices", "id-"+name, "0", "__"+m.UUID), []byte("data of "+name), 0o644)
				}
			}
		}
		for k, v := range f.streams {
			m.Streams[k] = slices.Clone(v)
		}
		data, _ := json.Marshal(m)
		_ = os.WriteFile(filepath.Join(loc, "snap-"+m.UUID+".dat"), data, 0o644)
		snaps = append(snaps, m)
		var list []map[string]string
		for _, s := range snaps {
			list = append(list, map[string]string{"name": s.Name, "uuid": s.UUID})
		}
		rd, _ := json.Marshal(map[string]any{"snapshots": list, "indices": map[string]any{}})
		_ = os.WriteFile(filepath.Join(loc, fmt.Sprintf("index-%d", n+1)), rd, 0o644)
		_ = os.WriteFile(filepath.Join(loc, "index.latest"), []byte(gen(n+1)), 0o644)
		writeJSON(w, 200, map[string]any{"snapshot": m.info()})
	case len(seg) == 4 && seg[3] == "_restore":
		_, snaps := f.repoState()
		for _, s := range snaps {
			if s.Name != seg[2] {
				continue
			}
			for n := range s.Indices {
				if _, ok := f.indices[n]; ok {
					osErr(w, 500, "snapshot_restore_exception", "an open index with same name already exists")
					return
				}
			}
			for n, i := range s.Indices {
				c := *i
				f.indices[n] = &c
			}
			for k, v := range s.Streams {
				f.streams[k] = slices.Clone(v)
			}
			writeJSON(w, 200, map[string]any{"snapshot": map[string]any{"shards": map[string]any{"total": len(s.Indices), "failed": 0}}})
			return
		}
		osErr(w, 404, "snapshot_missing_exception", "missing")
	default:
		osErr(w, 400, "illegal_argument_exception", "fake: no snapshot handler")
	}
}

func (f *fakeOS) has(name string) (exists, blocked bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.indices[name]
	return ok, ok && i.Blocked
}

func (f *fakeOS) setting(kind string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.settings[kind][autoCreate]
}

type tlog struct{ t *testing.T }

func (l tlog) Printf(format string, a ...any) { l.t.Logf(format, a...) }
func (l tlog) Output(string, []byte)          {}

// moveEnv is one server's agent: its own state folder, a NoAuth login for
// port, the shared bucket.
func moveEnv(t *testing.T, s3 *fakes3.Server, port int) agent.EngineEnv {
	env := agent.EngineEnv{StateDir: t.TempDir(), Repo: pgbackrest.Repo{Endpoint: "http://" + s3.Host(), Bucket: "b", Key: "k", KeySecret: "s",
		Region: "us-east-1", CipherPass: "test-passphrase-123456"}}
	if err := saveLogin(env, port, Login{NoAuth: true}); err != nil {
		t.Fatal(err)
	}
	return env
}

func blockedSet(names ...string) []string { slices.Sort(names); return names }

// A whole move: the new server receives the bucket's snapshots, the old
// one stops writes (holding the block when something lifts it), takes the
// last snapshot, the new one restores it without Rowsafe's blocks but with
// the indices' own, makes the templates and pipelines and takes the bucket
// folder over; the old server can't copy into the folder any more.
func TestSnapshotMove(t *testing.T) {
	ctx := context.Background()
	s3 := fakes3.New("b")
	defer s3.Close()
	db := protocol.DatabaseSpec{ID: "db-1", Name: "search", Engine: protocol.EngineOpenSearch, Stanza: "search", Port: 9200}
	e := &Engine{}

	src := newFakeOS(t, "old-cluster", "3.1.0", t.TempDir())
	src.indices["products"] = &fIndex{}
	src.indices["archive"] = &fIndex{Blocked: true} // a block of its own
	src.indices[".ds-logs-000001"] = &fIndex{DS: "logs"}
	src.streams["logs"] = []string{".ds-logs-000001"}
	src.globals["pipeline"] = map[string]json.RawMessage{"p1": json.RawMessage(`{"processors":[]}`)}
	src.globals["index"] = map[string]json.RawMessage{"t1": json.RawMessage(`{"index_patterns":["logs*"],"data_stream":{}}`)}
	srcEnv := moveEnv(t, s3, 9200)

	dst := newFakeOS(t, "new-cluster", "3.2.0", t.TempDir())
	if err := os.Chmod(dst.pathRepo, 0o2770); err != nil {
		t.Fatal(err)
	}
	dstEnv := moveEnv(t, s3, 9201)

	// The old server's first backup.
	src.use(t)
	if _, err := e.backup(ctx, srcEnv, db, protocol.BackupParams{Type: protocol.BackupFull}, tlog{t}); err != nil {
		t.Fatal(err)
	}
	from, err := e.SnapshotMoveSource(ctx, srcEnv, db)
	if err != nil || from.Major != 301 || from.SystemID != "old-cluster" || from.Newest.Label == "" {
		t.Fatalf("source %+v %v", from, err)
	}

	// The new server takes it.
	dst.use(t)
	if tg := targetOf(ctx, dstEnv, 9201, ""); !tg.Usable || !tg.Standby || tg.Version != "3.2.0" {
		t.Fatalf("target %+v", tg)
	}
	got, err := e.SnapshotMoveRestore(ctx, dstEnv, db, 9201, from.Newest.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: from.Major}, tlog{t})
	if err != nil || got.Label != from.Newest.Label {
		t.Fatalf("first restore %+v %v", got, err)
	}
	if ok, b := dst.has("products"); !ok || b {
		t.Error("products restored without a block")
	}
	if ok, b := dst.has("archive"); !ok || !b {
		t.Error("archive keeps its own block")
	}
	if dst.setting("persistent") != "false" {
		t.Error("automatic index creation is paused while the server receives")
	}
	if dst.repo["readonly"] != true {
		t.Errorf("the repository is read-only while receiving: %v", dst.repo)
	}
	if tg := targetOf(ctx, dstEnv, 9201, ""); tg.Usable {
		t.Error("a server receiving a database isn't a target any more")
	}

	// The switchover: writes stop on the old server.
	src.use(t)
	if changed, err := e.SnapshotMoveFreeze(ctx, srcEnv, db, tlog{t}); err != nil || changed {
		t.Fatalf("freeze %v %v", changed, err)
	}
	for _, n := range []string{"products", "archive", ".ds-logs-000001"} {
		if _, b := src.has(n); !b {
			t.Errorf("%s isn't blocked", n)
		}
	}
	if src.setting("persistent") != "false" {
		t.Error("automatic index creation isn't paused")
	}
	hold := protocol.DatabaseSpec{ID: db.ID, Engine: db.Engine, Port: db.Port} // what HoldFence passes
	if changed, err := e.SnapshotMoveFreeze(ctx, srcEnv, hold, tlog{t}); err != nil || changed {
		t.Fatalf("hold, nothing lifted: %v %v", changed, err)
	}
	src.mu.Lock()
	src.indices["products"].Blocked = false        // someone lifts the block
	src.indices["new1"] = &fIndex{}                // and creates an index
	src.settings["transient"][autoCreate] = "true" // and turns index creation on
	src.mu.Unlock()
	if changed, err := e.SnapshotMoveFreeze(ctx, srcEnv, hold, tlog{t}); err != nil || !changed {
		t.Fatalf("hold, block lifted: %v %v", changed, err)
	}
	if _, b := src.has("products"); !b {
		t.Error("the block is back")
	}
	if _, b := src.has("new1"); !b {
		t.Error("the new index is blocked")
	}
	if src.setting("transient") != "false" {
		t.Error("index creation is paused again")
	}
	last, err := e.SnapshotMoveTake(ctx, srcEnv, db, tlog{t})
	if err != nil || last.Label == "" || last.Label == from.Newest.Label {
		t.Fatalf("take %+v %v", last, err)
	}
	r, _ := openRepo(srcEnv, db)
	var doc backupDoc
	if err := r.getJSON(ctx, docKey(last.Label), &doc); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(blockedSet(doc.MoveBlocked...), blockedSet(".ds-logs-000001", "new1", "products")) || doc.Globals == nil ||
		doc.Globals.Pipelines["p1"] == nil || doc.Globals.IndexTemplates["t1"] == nil {
		t.Fatalf("the last snapshot's record: %+v %+v", doc.MoveBlocked, doc.Globals)
	}

	// The new server restores the last one and becomes the database's.
	dst.use(t)
	if newest, err := e.SnapshotMoveNewest(ctx, dstEnv, db); err != nil || newest.Label != last.Label {
		t.Fatalf("newest %+v %v", newest, err)
	}
	if _, err := e.SnapshotMoveRestore(ctx, dstEnv, db, 9201, last.Label, agent.SnapshotMoveRestoreOptions{Prev: got.Label}, tlog{t}); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]bool{"products": false, "new1": false, ".ds-logs-000001": false, "archive": true} {
		if ok, b := dst.has(n); !ok || b != want {
			t.Errorf("%s on the new server: exists %v, blocked %v", n, ok, b)
		}
	}
	if dst.globals["pipeline"]["p1"] == nil || dst.globals["index"]["t1"] == nil {
		t.Error("the pipeline and template were made")
	}
	if err := e.SnapshotMovePromote(ctx, dstEnv, db, 9201, tlog{t}); err != nil {
		t.Fatal(err)
	}
	var m marker
	if err := r.getJSON(ctx, markerKey, &m); err != nil || m.ClusterUUID != "new-cluster" {
		t.Fatalf("marker %+v %v", m, err)
	}
	if dst.repo["readonly"] != nil || dst.setting("persistent") != nil {
		t.Errorf("after the switchover: repository %v, auto create %v", dst.repo, dst.setting("persistent"))
	}
	// Backups go on on the new server, in the same repository.
	moved := db
	moved.Port = 9201
	if res, err := e.backup(ctx, dstEnv, moved, protocol.BackupParams{Type: protocol.BackupFull}, tlog{t}); err != nil || len(res.Kept) < 3 {
		t.Fatalf("backup on the new server: %+v %v", res, err)
	}

	// The old server can't copy into the folder any more; a thaw lifts only
	// Rowsafe's blocks.
	src.use(t)
	if _, err := e.backup(ctx, srcEnv, db, protocol.BackupParams{Type: protocol.BackupFull}, tlog{t}); !errors.Is(err, errOtherCluster) {
		t.Errorf("a backup on the old server after the switchover: %v", err)
	}
	if err := e.SnapshotMoveThaw(ctx, srcEnv, db, tlog{t}); err != nil {
		t.Fatal(err)
	}
	for n, want := range map[string]bool{"products": false, "new1": false, ".ds-logs-000001": false, "archive": true} {
		if _, b := src.has(n); b != want {
			t.Errorf("%s after the thaw: blocked %v", n, b)
		}
	}
	if src.setting("persistent") != nil || src.setting("transient") != nil { // as before the freeze
		t.Errorf("index creation as it was: %v %v", src.setting("persistent"), src.setting("transient"))
	}
}

// A first restore refuses, before changing anything (ErrMoveRefused), a
// server that holds data, an older version or a snapshot folder in use; a
// cancelled move removes only what it restored.
func TestSnapshotMoveRefuseAndClear(t *testing.T) {
	ctx := context.Background()
	s3 := fakes3.New("b")
	defer s3.Close()
	db := protocol.DatabaseSpec{ID: "db-2", Name: "search", Engine: protocol.EngineOpenSearch, Stanza: "search2", Port: 9200}
	e := &Engine{}
	src := newFakeOS(t, "old", "3.1.0", t.TempDir())
	src.indices["products"] = &fIndex{}
	srcEnv := moveEnv(t, s3, 9200)
	src.use(t)
	if _, err := e.backup(ctx, srcEnv, db, protocol.BackupParams{}, tlog{t}); err != nil {
		t.Fatal(err)
	}
	newest, err := e.SnapshotMoveNewest(ctx, srcEnv, db)
	if err != nil {
		t.Fatal(err)
	}
	first := agent.SnapshotMoveRestoreOptions{First: true, Major: 301}

	dst := newFakeOS(t, "new", "3.1.0", t.TempDir())
	_ = os.Chmod(dst.pathRepo, 0o2770)
	dstEnv := moveEnv(t, s3, 9201)
	dst.use(t)

	refused := func(what string) {
		t.Helper()
		_, err := e.SnapshotMoveRestore(ctx, dstEnv, db, 9201, newest.Label, first, tlog{t})
		if !errors.Is(err, agent.ErrMoveRefused) {
			t.Fatalf("%s: %v", what, err)
		}
		if ok, _ := loadMoveState(dstEnv, "target", db.ID, &targetState{}); ok {
			t.Fatalf("%s: a refusal recorded a move", what)
		}
	}
	dst.indices["mine"] = &fIndex{}
	refused("a server with data")
	if tg := targetOf(ctx, dstEnv, 9201, ""); tg.Usable || !strings.Contains(tg.NoStandby, "holds data") {
		t.Errorf("target with data %+v", tg)
	}
	delete(dst.indices, "mine")
	dst.version = "3.0.1"
	refused("an older OpenSearch")
	dst.version = "3.1.0"
	writeFile(t, dst.pathRepo, "index-3", "{}")
	refused("a snapshot folder in use")
	_ = os.Remove(filepath.Join(dst.pathRepo, "index-3"))
	if tg := targetOf(ctx, dstEnv, 9300, ""); tg.Usable || !strings.Contains(tg.NoStandby, "--move-target") {
		t.Errorf("no login %+v", tg)
	}

	if _, err := e.SnapshotMoveRestore(ctx, dstEnv, db, 9201, newest.Label, first, tlog{t}); err != nil {
		t.Fatal(err)
	}
	dst.mu.Lock()
	dst.indices["mine"] = &fIndex{} // made on the new server meanwhile
	dst.mu.Unlock()
	if err := e.SnapshotMoveClear(ctx, dstEnv, db, 9201, tlog{t}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := dst.has("products"); ok {
		t.Error("the restored index is removed")
	}
	if ok, _ := dst.has("mine"); !ok {
		t.Error("the server's own index stays")
	}
	if files, _ := localRepoFiles(dst.pathRepo); len(files) != 0 || dst.repo != nil || dst.setting("persistent") != nil {
		t.Errorf("after clearing: %d files, repository %v, auto create %v", len(files), dst.repo, dst.setting("persistent"))
	}
}

// Rowsafe's role from an older Rowsafe: a plain sentence to run the
// installer again.
func TestSnapshotMoveFreezeOldRole(t *testing.T) {
	ctx := context.Background()
	s3 := fakes3.New("b")
	defer s3.Close()
	f := newFakeOS(t, "c", "3.1.0", t.TempDir())
	f.indices["products"] = &fIndex{}
	f.forbid = []string{"PUT /products/_settings"}
	env := moveEnv(t, s3, 9200)
	f.use(t)
	db := protocol.DatabaseSpec{ID: "db-3", Port: 9200}
	if _, err := (&Engine{}).SnapshotMoveFreeze(ctx, env, db, tlog{t}); err == nil || !strings.Contains(err.Error(), "installer") {
		t.Fatalf("%v", err)
	}
	// What was recorded is lifted by a thaw all the same.
	f.forbid = nil
	if err := (&Engine{}).SnapshotMoveThaw(ctx, env, db, tlog{t}); err != nil {
		t.Fatal(err)
	}
	if _, ok := loadFreeze(env, db.ID); ok {
		t.Error("the freeze is forgotten after a thaw")
	}
}

func TestNameChunksAndSeries(t *testing.T) {
	var names []string
	for i := 0; i < 400; i++ {
		names = append(names, fmt.Sprintf("index-with-a-long-name-%04d", i))
	}
	chunks := nameChunks(names)
	n := 0
	for _, c := range chunks {
		if len(c) > maxURLNames {
			t.Errorf("chunk of %d bytes", len(c))
		}
		n += len(strings.Split(c, ","))
	}
	if len(chunks) < 2 || n != len(names) {
		t.Errorf("%d chunks, %d names", len(chunks), n)
	}
	if seriesOf("3.2.0") != 302 || seriesOf("2.19.1") != 219 || seriesOf("x") != 0 {
		t.Error("seriesOf")
	}
	if safeRel("../x") || safeRel("/etc") || safeRel("a//b") || !safeRel("indices/a/0/__b") {
		t.Error("safeRel")
	}
}

// TestWriteSharedModes: the folders a receiving server's copy makes are
// group-writable, its files group-readable, all in the snapshot folder's
// group, and nothing asks for a setgid bit (the agent's unit refuses
// that: RestrictSUIDSGID=yes, found by the cloud-takeout-search e2e).
func TestWriteSharedModes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := writeShared(dir, "indices/abc/0/__blob", strings.NewReader("data")); err != nil {
		t.Fatal(err)
	}
	if err := writeShared(dir, "indices/abc/0/__blob2", strings.NewReader("more")); err != nil {
		t.Fatal(err)
	}
	gid := func(p string) uint32 {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi.Sys().(*syscall.Stat_t).Gid
	}
	want := gid(dir)
	for _, d := range []string{"indices", "indices/abc", "indices/abc/0"} {
		fi, err := os.Stat(filepath.Join(dir, d))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o770 || gid(filepath.Join(dir, d)) != want {
			t.Errorf("%s: %v gid %d, want 0770 gid %d", d, fi.Mode(), gid(filepath.Join(dir, d)), want)
		}
	}
	f := filepath.Join(dir, "indices/abc/0/__blob")
	if fi, err := os.Stat(f); err != nil || fi.Mode().Perm() != 0o640 || gid(f) != want {
		t.Errorf("file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(f); string(b) != "data" {
		t.Errorf("content %q", b)
	}
}
