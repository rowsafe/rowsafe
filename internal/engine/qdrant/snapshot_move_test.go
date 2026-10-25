package qdrant

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeQdrant answers the part of Qdrant's REST API moves use.
type fakeQdrant struct {
	mu       sync.Mutex
	version  string
	colls    map[string][]byte            // collection -> its data (what a snapshot holds)
	aliases  map[string]string            // alias -> collection
	keys     map[string]map[string]string // rowsafe_keys: point id -> payload
	uploads  []string
	snaps    map[string][]byte
	needAuth bool
}

func newFakeQdrant(t *testing.T, version string, colls ...string) (*fakeQdrant, *httptest.Server) {
	t.Helper()
	f := &fakeQdrant{version: version, colls: map[string][]byte{protocol.QdrantKeysCollection: nil}, aliases: map[string]string{},
		keys: map[string]map[string]string{}, snaps: map[string][]byte{}, needAuth: true}
	for _, c := range colls {
		f.colls[c] = []byte("data of " + c)
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := listenerCheck
	listenerCheck = func(int) error { return nil }
	t.Cleanup(func() { listenerCheck = old })
	return f, srv
}

func (f *fakeQdrant) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok := func(v any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"result": v, "status": "ok"})
	}
	fail := func(code int, msg string) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"error": msg}})
	}
	p := r.URL.Path
	if p == "/" {
		_ = json.NewEncoder(w).Encode(map[string]any{"title": "qdrant - vector search engine", "version": f.version})
		return
	}
	if f.needAuth && r.Header.Get("authorization") == "" && r.Header.Get("api-key") == "" {
		fail(http.StatusUnauthorized, "Must provide an API key or an Authorization bearer token")
		return
	}
	var body map[string]any
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch {
	case p == "/cluster":
		ok(map[string]any{"status": "disabled"})
	case p == "/telemetry":
		ok(map[string]any{})
	case p == "/collections" && r.Method == http.MethodGet:
		var list []map[string]any
		for _, n := range slices.Sorted(mapsKeys(f.colls)) {
			list = append(list, map[string]any{"name": n})
		}
		ok(map[string]any{"collections": list})
	case p == "/aliases":
		var list []map[string]any
		for a, c := range f.aliases {
			list = append(list, map[string]any{"alias_name": a, "collection_name": c})
		}
		ok(map[string]any{"aliases": list})
	case p == "/collections/aliases":
		for _, a := range body["actions"].([]any) {
			m := a.(map[string]any)
			if d, ok := m["delete_alias"].(map[string]any); ok {
				delete(f.aliases, d["alias_name"].(string))
			}
			if c, ok := m["create_alias"].(map[string]any); ok {
				f.aliases[c["alias_name"].(string)] = c["collection_name"].(string)
			}
		}
		ok(true)
	case strings.HasPrefix(p, "/collections/"):
		rest := strings.TrimPrefix(p, "/collections/")
		name, sub, _ := strings.Cut(rest, "/")
		name, _ = url.PathUnescape(name)
		data, exists := f.colls[name]
		switch {
		case sub == "snapshots/upload":
			mr, err := r.MultipartReader()
			if err != nil {
				fail(http.StatusBadRequest, err.Error())
				return
			}
			part, err := mr.NextPart()
			if err != nil {
				fail(http.StatusBadRequest, err.Error())
				return
			}
			got, err := io.ReadAll(part)
			if err == nil {
				_, err = mr.NextPart()
				if err == io.EOF {
					err = nil
				}
			}
			if err != nil {
				fail(http.StatusBadRequest, "the upload was cut: "+err.Error())
				return
			}
			f.colls[name] = got
			f.uploads = append(f.uploads, name)
			ok(true)
		case !exists:
			fail(http.StatusNotFound, "Collection `"+name+"` doesn't exist!")
		case sub == "" && r.Method == http.MethodGet:
			ok(map[string]any{"status": "green", "points_count": len(data), "config": map[string]any{"params": map[string]any{
				"vectors": map[string]any{"size": 4, "distance": "Cosine"}}}})
		case sub == "" && r.Method == http.MethodDelete:
			delete(f.colls, name)
			for a, c := range f.aliases {
				if c == name {
					delete(f.aliases, a)
				}
			}
			ok(true)
		case sub == "" && r.Method == http.MethodPut:
			ok(true)
		case sub == "index":
			ok(true)
		case sub == "points/count":
			ok(map[string]any{"count": len(data)})
		case sub == "snapshots" && r.Method == http.MethodPost:
			sn := fmt.Sprintf("%s-%d.snapshot", name, len(f.snaps))
			f.snaps[sn] = slices.Clone(data)
			s := sha256.Sum256(data)
			ok(map[string]any{"name": sn, "creation_time": "2026-10-12T10:00:00", "size": len(data), "checksum": hex.EncodeToString(s[:])})
		case strings.HasPrefix(sub, "snapshots/") && r.Method == http.MethodGet:
			_, _ = w.Write(f.snaps[strings.TrimPrefix(sub, "snapshots/")])
		case strings.HasPrefix(sub, "snapshots/") && r.Method == http.MethodDelete:
			delete(f.snaps, strings.TrimPrefix(sub, "snapshots/"))
			ok(true)
		case name == protocol.QdrantKeysCollection && sub == "points/scroll":
			var pts []map[string]any
			for _, id := range slices.Sorted(mapsKeys(f.keys)) {
				pts = append(pts, map[string]any{"id": id, "payload": f.keys[id]})
			}
			ok(map[string]any{"points": pts, "next_page_offset": nil})
		case name == protocol.QdrantKeysCollection && sub == "points" && r.Method == http.MethodPut:
			for _, x := range body["points"].([]any) {
				m := x.(map[string]any)
				pl := m["payload"].(map[string]any)
				f.keys[m["id"].(string)] = map[string]string{"key": pl["key"].(string), "nonce": pl["nonce"].(string)}
			}
			ok(true)
		case name == protocol.QdrantKeysCollection && sub == "points/delete":
			if ids, isList := body["points"].([]any); isList {
				for _, id := range ids {
					delete(f.keys, id.(string))
				}
			} else {
				must := body["filter"].(map[string]any)["must"].([]any)[0].(map[string]any)
				v := must["match"].(map[string]any)["value"].(string)
				for id, pl := range f.keys {
					if pl["key"] == v {
						delete(f.keys, id)
					}
				}
			}
			ok(true)
		default:
			fail(http.StatusNotFound, "no such endpoint in the fake: "+r.Method+" "+p)
		}
	default:
		fail(http.StatusNotFound, "no such endpoint in the fake: "+r.Method+" "+p)
	}
}

func mapsKeys[V any](m map[string]V) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

func (f *fakeQdrant) keyNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, pl := range f.keys {
		out = append(out, pl["key"]+":"+pl["nonce"])
	}
	slices.Sort(out)
	return out
}

func (f *fakeQdrant) collNames() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Sorted(mapsKeys(f.colls))
}

// moveEnv is an engine environment with a fake bucket and a saved login
// for the fake server srv (on port).
func moveEnv(t *testing.T, srv *httptest.Server, port int) agent.EngineEnv {
	t.Helper()
	s3 := fakes3.New("b")
	t.Cleanup(s3.Close)
	dir := t.TempDir()
	env := agent.EngineEnv{Config: agent.Config{StateDir: dir, RewindDir: filepath.Join(dir, "rewind")}, StateDir: filepath.Join(dir, "engines", "qdrant"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + s3.Host(), Bucket: "b", Key: "k", KeySecret: "s", Region: "us-east-1", CipherPass: "test-passphrase-123456"}}
	if srv != nil {
		if err := saveLogin(env, port, Login{Key: "rowsafe-key", JWT: true, URL: srv.URL, Source: "alt"}); err != nil {
			t.Fatal(err)
		}
	}
	return env
}

func portOfURL(t *testing.T, raw string) int {
	t.Helper()
	u, _ := url.Parse(raw)
	var p int
	_, _ = fmt.Sscan(u.Port(), &p)
	return p
}

type logLines struct{ lines []string }

func (l *logLines) Printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *logLines) Output(string, []byte) {}
func (l *logLines) String() string        { return strings.Join(l.lines, "\n") }

// Freeze takes the writing keys' points out (read-only keys keep theirs),
// reconcile leaves them out while frozen, a point put back is removed
// again (changed), and Thaw puts the same points back.
func TestMoveFreezeThawHold(t *testing.T) {
	f, srv := newFakeQdrant(t, "1.19.2", "docs")
	port := portOfURL(t, srv.URL)
	env := moveEnv(t, srv, port)
	db := protocol.DatabaseSpec{ID: "db1", Name: "vectors", Stanza: "vectors", Port: port}
	ctx := context.Background()
	keys := []keyEntry{
		{Name: "adm", Nonce: "n1", Access: protocol.DBAccessOwner},
		{Name: "app", Nonce: "n2", Access: protocol.DBAccessReadWrite, Collections: []string{"docs"}},
		{Name: "ro", Nonce: "n3", Access: protocol.DBAccessReadOnly},
	}
	if err := saveKeyList(env, port, keyList{Keys: keys}); err != nil {
		t.Fatal(err)
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		t.Fatal(err)
	}
	if err := putKeyPoints(ctx, c, keys); err != nil {
		t.Fatal(err)
	}
	all := []string{"adm:n1", "app:n2", "ro:n3"}
	if got := f.keyNames(); !slices.Equal(got, all) {
		t.Fatalf("points %v", got)
	}
	e := &Engine{}
	var log logLines
	changed, err := e.SnapshotMoveFreeze(ctx, env, db, &log)
	if err != nil || changed {
		t.Fatalf("freeze: %v %v", changed, err)
	}
	if got := f.keyNames(); !slices.Equal(got, []string{"ro:n3"}) {
		t.Fatalf("after freeze: %v", got)
	}
	if !strings.Contains(log.String(), "adm, app") {
		t.Errorf("log: %s", log.String())
	}
	// The monitoring pass's reconcile leaves them out, and isn't a repair.
	list, rr, err := reconcile(ctx, env, port, c)
	if err != nil || rr.Restored != 0 || rr.Removed != 0 || list.Frozen == nil {
		t.Fatalf("reconcile while frozen: %+v %+v %v", list, rr, err)
	}
	if got := f.keyNames(); !slices.Equal(got, []string{"ro:n3"}) {
		t.Fatalf("after reconcile: %v", got)
	}
	// Holding: nothing lifted it.
	if changed, err := e.SnapshotMoveFreeze(ctx, env, db, &log); err != nil || changed {
		t.Fatalf("hold: %v %v", changed, err)
	}
	// Someone puts a writing key's point back: it goes again.
	f.mu.Lock()
	f.keys[keyPointID("app")] = map[string]string{"key": "app", "nonce": "n2"}
	f.mu.Unlock()
	if changed, err := e.SnapshotMoveFreeze(ctx, env, db, &log); err != nil || !changed {
		t.Fatalf("hold after a lift: %v %v", changed, err)
	}
	if got := f.keyNames(); !slices.Equal(got, []string{"ro:n3"}) {
		t.Fatalf("after hold: %v", got)
	}
	// No new key that can write while frozen; a read-only one is fine.
	l, _, _ := loadLogin(env, port)
	list, _, _ = loadKeyList(env, port)
	if _, _, err := makeKey(ctx, env, port, c, l, &list, protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "w2",
		Access: protocol.DBAccessReadWrite, Databases: []string{"docs"}}); err == nil || !strings.Contains(err.Error(), "new server") {
		t.Fatalf("a writing key made while frozen: %v", err)
	}
	// Thaw: the same points (same nonces) are back; reconcile reports nothing.
	if err := e.SnapshotMoveThaw(ctx, env, db, &log); err != nil {
		t.Fatal(err)
	}
	if got := f.keyNames(); !slices.Equal(got, all) {
		t.Fatalf("after thaw: %v", got)
	}
	list, rr, err = reconcile(ctx, env, port, c)
	if err != nil || rr.Restored != 0 || rr.Removed != 0 || list.Frozen != nil || list.Repair != nil {
		t.Fatalf("reconcile after thaw: %+v %+v %v", list, rr, err)
	}
}

// putBackup stores a backup of collections (name -> data) in r; reuse
// names collections whose snapshot is prev's.
func putBackup(t *testing.T, r *repo, label, version string, colls map[string]string, reuse []string, prev *backupDoc, aliases map[string]string) backupDoc {
	t.Helper()
	ctx := context.Background()
	at, _ := time.Parse("20060102-150405", strings.TrimSuffix(label, "F"))
	d := backupDoc{Label: label, Source: sourceScheduled, Version: version, VersionNum: parseVersion(version), TakenAt: at, StartedAt: at, StoppedAt: at,
		Format: formatCollections, Aliases: aliases}
	n := 0
	for _, name := range slices.Sorted(mapsKeys(colls)) {
		data := []byte(colls[name])
		key := dataKey(label, n)
		n++
		if _, err := r.putSealed(ctx, key, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		d.Collections = append(d.Collections, collDoc{Name: name, Object: key, Bytes: int64(len(data)), Checksum: sum(data), TakenAt: at})
	}
	for _, name := range reuse {
		d.Collections = append(d.Collections, prev.collection(name))
	}
	if err := r.putDoc(ctx, d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestMoveRestore(t *testing.T) {
	f, srv := newFakeQdrant(t, "1.19.2")
	port := portOfURL(t, srv.URL)
	env := moveEnv(t, srv, port)
	db := protocol.DatabaseSpec{ID: "db1", Name: "vectors", Stanza: "vectors", Port: 6333}
	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	b1 := putBackup(t, r, "20261012-100000F", "1.19.1", map[string]string{"a": "A1", "b": "B1", protocol.QdrantKeysCollection: "keys"}, nil, nil,
		map[string]string{"al": "a"})
	b2 := putBackup(t, r, "20261012-101000F", "1.19.1", map[string]string{"c": "C2"}, []string{"a"}, &b1, map[string]string{"al": "a", "cl": "c"})
	e := &Engine{}
	var log logLines

	// Newest is the last backup; the source says 1.19.
	if n, err := e.SnapshotMoveNewest(ctx, env, db); err != nil || n.Label != b2.Label {
		t.Fatalf("newest %+v %v", n, err)
	}

	// An older server is refused, nothing changed.
	f.version = "1.17.0"
	if _, err := e.SnapshotMoveRestore(ctx, env, db, port, b1.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: 119}, &log); err == nil ||
		!strings.Contains(err.Error(), "older") {
		t.Fatalf("an older target: %v", err)
	}
	f.version = "1.19.2"

	got, err := e.SnapshotMoveRestore(ctx, env, db, port, b1.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: 119}, &log)
	if err != nil || got.Label != b1.Label || !got.At.Equal(b1.TakenAt) {
		t.Fatalf("first restore: %+v %v\n%s", got, err, log.String())
	}
	if !slices.Equal(f.uploads, []string{"a", "b"}) || string(f.colls["a"]) != "A1" || f.aliases["al"] != "a" {
		t.Fatalf("after the first restore: uploads %v colls %v aliases %v", f.uploads, f.collNames(), f.aliases)
	}
	if f.colls[protocol.QdrantKeysCollection] != nil {
		t.Fatal("Rowsafe's keys collection was restored")
	}

	// Someone makes a collection of their own on the new server meanwhile.
	f.colls["mine"] = []byte("x")
	// The follow restore skips a (same snapshot), adds c, removes b.
	f.uploads = nil
	if _, err := e.SnapshotMoveRestore(ctx, env, db, port, b2.Label, agent.SnapshotMoveRestoreOptions{Prev: b1.Label}, &log); err != nil {
		t.Fatalf("follow: %v\n%s", err, log.String())
	}
	if !slices.Equal(f.uploads, []string{"c"}) {
		t.Fatalf("follow uploaded %v, want only c", f.uploads)
	}
	if got := f.collNames(); !slices.Equal(got, []string{"a", "c", "mine", protocol.QdrantKeysCollection}) {
		t.Fatalf("collections after follow: %v", got)
	}
	if f.aliases["cl"] != "c" || f.aliases["al"] != "a" {
		t.Fatalf("aliases %v", f.aliases)
	}

	// A snapshot that isn't the one stored: the upload fails.
	b3 := putBackup(t, r, "20261012-102000F", "1.19.1", map[string]string{"a": "A3"}, []string{"c"}, &b2, nil)
	if err := r.st.PutBytes(ctx, b3.collection("a").Object, mustSeal(t, r, "tampered")); err != nil {
		t.Fatal(err)
	}
	f.uploads = nil
	_, err = e.SnapshotMoveRestore(ctx, env, db, port, b3.Label, agent.SnapshotMoveRestoreOptions{Prev: b2.Label}, &log)
	if err == nil || !strings.Contains(err.Error(), "restoring collection a") {
		t.Fatalf("a tampered snapshot was restored: %v", err)
	}
	t.Logf("tampered snapshot refused: %v", err)
	if string(f.colls["a"]) != "A1" {
		t.Fatalf("collection a changed by a failed upload: %q", f.colls["a"])
	}

	// A snapshot from a newer Qdrant than the server's is refused.
	b4 := putBackup(t, r, "20261012-103000F", "1.20.0", map[string]string{"a": "A4"}, nil, nil, nil)
	if _, err := e.SnapshotMoveRestore(ctx, env, db, port, b4.Label, agent.SnapshotMoveRestoreOptions{Prev: b2.Label}, &log); err == nil ||
		!strings.Contains(err.Error(), "newer") {
		t.Fatalf("a newer snapshot: %v", err)
	}

	// Cancelled: only what the move restored goes.
	if err := e.SnapshotMoveClear(ctx, env, db, port, &log); err != nil {
		t.Fatal(err)
	}
	if got := f.collNames(); !slices.Equal(got, []string{"mine", protocol.QdrantKeysCollection}) {
		t.Fatalf("collections after clear: %v", got)
	}

	// A first restore into a server that holds data is refused, and the
	// clear that follows removes nothing.
	f.uploads = nil
	if _, err := e.SnapshotMoveRestore(ctx, env, db, port, b2.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: 119}, &log); err == nil ||
		!strings.Contains(err.Error(), "only an empty server") {
		t.Fatalf("a target with data: %v", err)
	}
	if err := e.SnapshotMoveClear(ctx, env, db, port, &log); err != nil {
		t.Fatal(err)
	}
	if len(f.uploads) != 0 || !slices.Contains(f.collNames(), "mine") {
		t.Fatalf("the refused restore changed the server: %v %v", f.uploads, f.collNames())
	}
}

func mustSeal(t *testing.T, r *repo, s string) []byte {
	t.Helper()
	ctx := context.Background()
	if _, err := r.putSealed(ctx, "tmp", strings.NewReader(s)); err != nil {
		t.Fatal(err)
	}
	b, err := r.st.GetBytes(ctx, "tmp")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Promote: the next backup takes every collection, and a later clear no
// longer removes the database's collections.
func TestMovePromote(t *testing.T) {
	f, srv := newFakeQdrant(t, "1.19.2")
	port := portOfURL(t, srv.URL)
	env := moveEnv(t, srv, port)
	db := protocol.DatabaseSpec{ID: "db1", Name: "vectors", Stanza: "vectors", Port: 6333}
	r, _ := openRepo(env, db)
	ctx := context.Background()
	b1 := putBackup(t, r, "20261012-100000F", "1.19.1", map[string]string{"a": "A1"}, nil, nil, nil)
	e := &Engine{}
	var log logLines
	if _, err := e.SnapshotMoveRestore(ctx, env, db, port, b1.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: 119}, &log); err != nil {
		t.Fatal(err)
	}
	if err := e.SnapshotMovePromote(ctx, env, db, port, &log); err != nil {
		t.Fatal(err)
	}
	if e.fullNext(env, db.ID) == "" {
		t.Fatal("the next backup doesn't take every collection")
	}
	if err := r.getJSON(ctx, markerKey, &marker{}); err != nil {
		t.Fatalf("the folder's marker: %v", err)
	}
	if err := e.SnapshotMoveClear(ctx, env, db, port, &log); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.collNames(), "a") {
		t.Fatal("a clear after the promotion removed the database's collection")
	}
}

// Take is an ordinary backup; Source reports its version and it.
func TestMoveTakeAndSource(t *testing.T) {
	_, srv := newFakeQdrant(t, "1.19.2", "docs")
	port := portOfURL(t, srv.URL)
	env := moveEnv(t, srv, port)
	db := protocol.DatabaseSpec{ID: "db1", Name: "vectors", Stanza: "vectors", Port: port}
	ctx := context.Background()
	e := &Engine{}
	var log logLines
	snap, err := e.SnapshotMoveTake(ctx, env, db, &log)
	if err != nil || !labelRE.MatchString(snap.Label) {
		t.Fatalf("take: %+v %v\n%s", snap, err, log.String())
	}
	src, err := e.SnapshotMoveSource(ctx, env, db)
	if err != nil || src.Major != 119 || src.Version != "1.19.2" || src.Newest.Label != snap.Label {
		t.Fatalf("source: %+v %v", src, err)
	}
	r, _ := openRepo(env, db)
	docs, _, _ := r.listBackups(ctx)
	if len(docs) != 1 || docs[0].collection("docs").Object == "" {
		t.Fatalf("backups: %+v", docs)
	}
}

func TestMoveTargets(t *testing.T) {
	ctx := context.Background()
	e := &Engine{}
	// Empty (Rowsafe's own collection only), with Rowsafe's key: usable.
	_, srv := newFakeQdrant(t, "1.19.2")
	port := portOfURL(t, srv.URL)
	env := moveEnv(t, srv, port)
	tg, ok := e.target(ctx, env, port)
	if !ok || !tg.Usable || !tg.Standby || tg.Version != "1.19.2" || tg.Engine != protocol.EngineQdrant {
		t.Fatalf("empty server: %+v %v", tg, ok)
	}
	// Holding data.
	_, srv2 := newFakeQdrant(t, "1.19.2", "docs")
	port2 := portOfURL(t, srv2.URL)
	env2 := moveEnv(t, srv2, port2)
	if tg, _ := e.target(ctx, env2, port2); tg.Usable || tg.Standby || !strings.Contains(tg.Reason, "holds data") || tg.NoStandby != tg.Reason {
		t.Fatalf("server with data: %+v", tg)
	}
	// No key saved: the installer's --move-target.
	_, srv3 := newFakeQdrant(t, "1.19.2")
	port3 := portOfURL(t, srv3.URL)
	env3 := moveEnv(t, nil, port3)
	if tg, ok := e.target(ctx, env3, port3); !ok || tg.Usable || !strings.Contains(tg.Reason, "--move-target") {
		t.Fatalf("server without Rowsafe's key: %+v %v", tg, ok)
	}
	// Receiving a database already.
	if err := saveMoveTarget(env, port, &moveTarget{DatabaseID: "db1", Collections: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	if tg, _ := e.target(ctx, env, port); tg.Usable || !strings.Contains(tg.Reason, "receiving") {
		t.Fatalf("receiving server: %+v", tg)
	}
	// Nothing answers.
	if _, ok := e.target(ctx, env, 1); ok {
		t.Fatal("a port where nothing answers was reported")
	}
}
