package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeMeili is a small Meilisearch: keys (values derived from the uid and
// the master key, as Meilisearch does), indexes with a document count,
// and a task queue whose tasks finish at once unless held.
type fakeMeili struct {
	mu      sync.Mutex
	t       *testing.T
	version string
	master  string
	keys    []apiKey
	indexes map[string]int64
	tasks   []task
	snap    string // the snapshot file POST /snapshots writes
	// held: tasks still processing, and how many more reads of the queue
	// they take to finish.
	held     map[int64]int
	snapshot []time.Time // when each snapshot task was asked for
	srv      *httptest.Server
	port     int
}

func newFakeMeili(t *testing.T) *fakeMeili {
	t.Helper()
	old := checkListeners
	checkListeners = false
	t.Cleanup(func() { checkListeners = old })
	f := &fakeMeili{t: t, version: "1.54.3", master: "master", indexes: map[string]int64{}, held: map[int64]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.port, _ = strconv.Atoi(f.srv.URL[strings.LastIndex(f.srv.URL, ":")+1:])
	return f
}

func (f *fakeMeili) keyValue(uid string) string {
	sum := sha256.Sum256([]byte(uid + f.master))
	return hex.EncodeToString(sum[:])
}

func (f *fakeMeili) addKey(uid, name string, actions ...string) apiKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := name
	k := apiKey{UID: uid, Key: f.keyValue(uid), Name: &n, Actions: actions, Indexes: []string{"*"}}
	f.keys = append(f.keys, k)
	return k
}

func (f *fakeMeili) keyUIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, k := range f.keys {
		out = append(out, k.UID)
	}
	slices.Sort(out)
	return out
}

// addTask records a finished (or held) task enqueued at.
func (f *fakeMeili) addTask(typ string, at time.Time, holdFor int) task {
	t := task{UID: int64(len(f.tasks)), Type: typ, Status: "succeeded"}
	at = at.UTC()
	t.EnqueuedAt, t.StartedAt = &at, &at
	if holdFor > 0 {
		t.Status = "processing"
		f.held[t.UID] = holdFor
	}
	f.tasks = append(f.tasks, t)
	return t
}

func (f *fakeMeili) reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeMeili) fail(w http.ResponseWriter, status int, code string) {
	f.reply(w, status, map[string]string{"code": code, "message": code})
}

func (f *fakeMeili) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	p := r.URL.Path
	switch {
	case p == "/health":
		f.reply(w, 200, map[string]string{"status": "available"})
	case p == "/version":
		f.reply(w, 200, map[string]string{"pkgVersion": f.version})
	case p == "/stats":
		st := globalStats{Indexes: map[string]indexStats{}}
		for uid, n := range f.indexes {
			st.Indexes[uid] = indexStats{NumberOfDocuments: n}
		}
		f.reply(w, 200, st)
	case p == "/indexes" && r.Method == http.MethodGet:
		var res []indexInfo
		for uid := range f.indexes {
			res = append(res, indexInfo{UID: uid})
		}
		slices.SortFunc(res, func(a, b indexInfo) int { return strings.Compare(a.UID, b.UID) })
		f.reply(w, 200, map[string]any{"results": res, "total": len(res)})
	case strings.HasPrefix(p, "/indexes/"):
		uid := strings.TrimPrefix(p, "/indexes/")
		if _, ok := f.indexes[uid]; !ok {
			f.fail(w, 404, "index_not_found")
			return
		}
		if r.Method == http.MethodDelete {
			delete(f.indexes, uid)
			f.reply(w, 202, f.addTask("indexDeletion", time.Now(), 0))
			return
		}
		f.reply(w, 200, indexInfo{UID: uid})
	case p == "/swap-indexes":
		var req []struct {
			Indexes []string `json:"indexes"`
			Rename  bool     `json:"rename"`
		}
		_ = json.Unmarshal(body, &req)
		for _, s := range req {
			a, b := s.Indexes[0], s.Indexes[1]
			if s.Rename {
				f.indexes[b] = f.indexes[a]
				delete(f.indexes, a)
			} else {
				f.indexes[a], f.indexes[b] = f.indexes[b], f.indexes[a]
			}
		}
		f.reply(w, 202, f.addTask("indexSwap", time.Now(), 0))
	case p == "/snapshots":
		f.snapshot = append(f.snapshot, time.Now())
		if f.snap != "" {
			_ = os.WriteFile(f.snap, []byte("snapshot "+strconv.Itoa(len(f.snapshot))), 0o600)
		}
		f.reply(w, 202, f.addTask("snapshotCreation", time.Now(), 0))
	case p == "/keys" && r.Method == http.MethodGet:
		f.reply(w, 200, map[string]any{"results": f.keys, "total": len(f.keys)})
	case p == "/keys" && r.Method == http.MethodPost:
		var k apiKey
		_ = json.Unmarshal(body, &k)
		if k.UID == "" {
			k.UID = fmt.Sprintf("generated-%d", len(f.keys))
		}
		if slices.ContainsFunc(f.keys, func(x apiKey) bool { return x.UID == k.UID }) {
			f.fail(w, 409, "api_key_already_exists")
			return
		}
		k.Key = f.keyValue(k.UID)
		f.keys = append(f.keys, k)
		f.reply(w, 201, k)
	case strings.HasPrefix(p, "/keys/") && r.Method == http.MethodDelete:
		uid := strings.TrimPrefix(p, "/keys/")
		i := slices.IndexFunc(f.keys, func(x apiKey) bool { return x.UID == uid })
		if i < 0 {
			f.fail(w, 404, "api_key_not_found")
			return
		}
		f.keys = slices.Delete(f.keys, i, i+1)
		w.WriteHeader(204)
	case p == "/tasks":
		q := r.URL.Query()
		var res []task
		for i := len(f.tasks) - 1; i >= 0; i-- {
			t := f.tasks[i]
			if n, ok := f.held[t.UID]; ok {
				if n <= 1 {
					delete(f.held, t.UID)
					f.tasks[i].Status = "succeeded"
					t = f.tasks[i]
				} else {
					f.held[t.UID] = n - 1
				}
			}
			if s := q.Get("statuses"); s != "" && !slices.Contains(strings.Split(s, ","), t.Status) {
				continue
			}
			if b := q.Get("beforeEnqueuedAt"); b != "" {
				bt, err := time.Parse(time.RFC3339Nano, b)
				if err != nil {
					f.t.Errorf("beforeEnqueuedAt %q: %v", b, err)
				}
				if !t.EnqueuedAt.Before(bt) {
					continue
				}
			}
			res = append(res, t)
		}
		total := len(res)
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l < len(res) {
			res = res[:l]
		}
		f.reply(w, 200, map[string]any{"results": res, "total": total})
	case strings.HasPrefix(p, "/tasks/"):
		n, _ := strconv.ParseInt(strings.TrimPrefix(p, "/tasks/"), 10, 64)
		if n < 0 || int(n) >= len(f.tasks) {
			f.fail(w, 404, "task_not_found")
			return
		}
		f.reply(w, 200, f.tasks[n])
	default:
		f.fail(w, 404, "not_found")
	}
}

const rowsafeUID = "rowsafe-key-uid"

// moveEnv is an agent environment with a bucket, and the fake saved as a
// server Rowsafe has a key for.
func moveEnv(t *testing.T, fs ...*fakeMeili) (agent.EngineEnv, []server) {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	env := agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "meilisearch"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "unit-test-passphrase-123456", PathPrefix: "/rowsafe"},
		Log: slog.New(slog.DiscardHandler),
	}
	var out []server
	for i, f := range fs {
		k := f.addKey(rowsafeUID, agentKeyName, agentKeyActions...)
		snaps := filepath.Join(dir, "snapshots-"+strconv.Itoa(i))
		if err := os.MkdirAll(snaps, 0o700); err != nil {
			t.Fatal(err)
		}
		s := server{Port: f.port, Key: k.Key, KeyUID: rowsafeUID, Binary: "/usr/bin/meilisearch", SnapshotDir: snaps,
			DBPath: filepath.Join(dir, "data-"+strconv.Itoa(i), "data.ms")}
		f.snap = s.snapshotFile()
		if err := saveServer(env, s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return env, out
}

type moveLog struct{ lines []string }

func (l *moveLog) Printf(format string, args ...any) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *moveLog) Output(string, []byte) {}

func TestMoveFreezeThawHold(t *testing.T) {
	ctx := context.Background()
	f := newFakeMeili(t)
	env, _ := moveEnv(t, f)
	db := protocol.DatabaseSpec{ID: "db_1", Name: "search", Stanza: "search", Port: f.port, Engine: protocol.EngineMeilisearch}
	past := time.Now().Add(-time.Hour)
	f.addKey("search-key", "frontend", "search")
	rw := f.addKey("rw-key", "backend", protocol.MeilisearchKeyActions[protocol.DBAccessReadWrite]...)
	admin := f.addKey("admin-key", "Default Admin API Key", "*")
	f.addKey("stats-key", "monitoring", "stats.get", "tasks.get", "version")
	f.mu.Lock()
	n := "old"
	f.keys = append(f.keys, apiKey{UID: "expired-key", Name: &n, Actions: []string{"documents.add"}, Indexes: []string{"*"}, ExpiresAt: &past})
	f.mu.Unlock()
	e := &Engine{}
	log := &moveLog{}

	changed, err := e.SnapshotMoveFreeze(ctx, env, db, log)
	if err != nil || changed {
		t.Fatalf("freeze: %v %v", changed, err)
	}
	if got, want := f.keyUIDs(), []string{"expired-key", rowsafeUID, "search-key", "stats-key"}; !slices.Equal(got, want) {
		t.Fatalf("keys after the freeze %v, want %v", got, want)
	}
	fi, err := os.Stat(freezeFile(env, db.Port))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved keys: %v %v", fi, err)
	}
	data, _ := os.ReadFile(freezeFile(env, db.Port))
	if strings.Contains(string(data), rw.Key) || strings.Contains(string(data), admin.Key) {
		t.Fatal("a key's value was saved")
	}
	// Held: nothing lifted it.
	if changed, err := e.SnapshotMoveFreeze(ctx, env, protocol.DatabaseSpec{ID: db.ID, Port: db.Port}, &moveLog{}); err != nil || changed {
		t.Fatalf("hold: %v %v", changed, err)
	}
	// Someone puts a writing key back, and makes a new one.
	f.addKey("rw-key", "backend", "documents.*")
	f.addKey("new-key", "sneaky", "settings.update")
	if changed, err := e.SnapshotMoveFreeze(ctx, env, protocol.DatabaseSpec{ID: db.ID, Port: db.Port}, &moveLog{}); err != nil || !changed {
		t.Fatalf("hold after a key came back: %v %v", changed, err)
	}
	if got := f.keyUIDs(); slices.Contains(got, "rw-key") || slices.Contains(got, "new-key") {
		t.Fatalf("writing keys stayed: %v", got)
	}

	// Thaw: the same uids, so the same values; the first definition saved.
	if err := e.SnapshotMoveThaw(ctx, env, db, log); err != nil {
		t.Fatal(err)
	}
	got := map[string]apiKey{}
	f.mu.Lock()
	for _, k := range f.keys {
		got[k.UID] = k
	}
	f.mu.Unlock()
	if k := got["rw-key"]; k.Key != rw.Key || !slices.Equal(k.Actions, rw.Actions) || k.name() != "backend" {
		t.Errorf("rw key given back as %+v", k)
	}
	if k := got["admin-key"]; k.Key != admin.Key || !slices.Equal(k.Actions, []string{"*"}) {
		t.Errorf("admin key given back as %+v", k)
	}
	if _, ok := got["new-key"]; !ok {
		t.Error("the key made during the freeze wasn't given back")
	}
	if _, err := os.Stat(freezeFile(env, db.Port)); !os.IsNotExist(err) {
		t.Errorf("saved keys stay after the thaw: %v", err)
	}
	if err := e.SnapshotMoveThaw(ctx, env, db, log); err != nil {
		t.Errorf("a second thaw: %v", err)
	}

	// Without a master key there is nothing to take back: refused.
	s, _ := loadServer(env, f.port)
	s.NoAuth, s.Key = true, ""
	_ = saveServer(env, s)
	if _, err := e.SnapshotMoveFreeze(ctx, env, db, log); err == nil || !strings.Contains(err.Error(), "no master key") {
		t.Errorf("no master key: %v", err)
	}
}

func TestCanWrite(t *testing.T) {
	for _, tc := range []struct {
		actions []string
		want    bool
	}{
		{[]string{"search"}, false},
		{[]string{"search", "documents.get", "indexes.get", "stats.get", "tasks.get"}, false},
		{protocol.MeilisearchKeyActions[protocol.DBAccessReadWrite], true},
		{protocol.MeilisearchKeyActions[protocol.DBAccessOwner], true},
		{[]string{"*"}, true},
		{[]string{"keys.create"}, true},
		{[]string{"indexes.*"}, true},
		{[]string{"someNewAction"}, true},
	} {
		if got := canWrite(tc.actions); got != tc.want {
			t.Errorf("canWrite(%v) = %v", tc.actions, got)
		}
	}
}

// The last snapshot waits for apps' tasks enqueued before the freeze, and
// goes through the normal backup path.
func TestMoveTakeWaitsForEarlierTasks(t *testing.T) {
	ctx := context.Background()
	f := newFakeMeili(t)
	env, _ := moveEnv(t, f)
	db := protocol.DatabaseSpec{ID: "db_1", Name: "search", Stanza: "search", Port: f.port, Engine: protocol.EngineMeilisearch, RetentionFull: 7}
	f.mu.Lock()
	f.indexes["movies"] = 10
	earlier := f.addTask("documentAdditionOrUpdate", time.Now().Add(-time.Second), 3)
	f.mu.Unlock()
	e := &Engine{}
	if _, err := e.SnapshotMoveFreeze(ctx, env, db, &moveLog{}); err != nil {
		t.Fatal(err)
	}
	ref, err := e.SnapshotMoveTake(ctx, env, db, &moveLog{})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	done := f.tasks[earlier.UID].Status
	nsnap := len(f.snapshot)
	f.mu.Unlock()
	if done != "succeeded" || nsnap != 1 {
		t.Fatalf("snapshot taken before the earlier task finished (%s, %d snapshots)", done, nsnap)
	}
	newest, err := e.SnapshotMoveNewest(ctx, env, db)
	if err != nil || newest.Label != ref.Label || ref.Label == "" {
		t.Fatalf("newest %+v, taken %+v (%v)", newest, ref, err)
	}
	src, err := e.SnapshotMoveSource(ctx, env, db)
	if err != nil || src.Major != 154 || src.Version != "1.54.3" || src.Newest.Label != ref.Label {
		t.Fatalf("source %+v %v", src, err)
	}

	// A promoted server's first backup is whole even when nothing seems
	// changed; the next one may name it again.
	r, _ := openRepo(env, db)
	if d, err := e.takeSnapshot(ctx, env, db, r, sourceScheduled, "", &moveLog{}); err != nil || d.Data == "" {
		t.Fatalf("nothing changed: reused expected (%+v, %v)", d, err)
	}
	if err := os.WriteFile(freshFile(env, db.ID), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := e.takeSnapshot(ctx, env, db, r, sourceScheduled, "", &moveLog{}); err != nil || d.Data != "" {
		t.Fatalf("after a move: whole snapshot expected (%+v, %v)", d, err)
	}
	if freshNeeded(env, db) {
		t.Error("the mark stays after a whole snapshot")
	}
}

func TestMoveTargets(t *testing.T) {
	ctx := context.Background()
	empty, full, tlsOwn, old := newFakeMeili(t), newFakeMeili(t), newFakeMeili(t), newFakeMeili(t)
	full.indexes["movies"] = 3
	empty.indexes[protocol.MeilisearchRestorePrefix+"0011aabb-x"] = 1 // Rowsafe's own: not data
	old.version = "1.12.0"
	env, servers := moveEnv(t, empty, full, tlsOwn, old)
	servers[2].TLS = true
	_ = saveServer(env, servers[2])
	// A port whose saved key is damaged.
	_ = os.WriteFile(serverFile(env, 7799), []byte(`{"port":7799,"key":"bad"}`), 0o600)
	// A port receiving a database already.
	recv := newFakeMeili(t)
	recv.addKey(rowsafeUID, agentKeyName, agentKeyActions...)
	_ = saveServer(env, server{Port: recv.port, Key: recv.keyValue(rowsafeUID), KeyUID: rowsafeUID, Binary: "/usr/bin/meilisearch", SnapshotDir: "/x"})
	_ = saveJSONFile(moveStateFile(env, recv.port), moveState{DatabaseID: "db_x"})

	e := &Engine{}
	got := map[int]protocol.StandbyTarget{}
	for _, tg := range e.StandbyTargets(ctx, env) {
		got[tg.Port] = tg
	}
	if tg := got[empty.port]; !tg.Standby || !tg.Usable || tg.Version != "1.54.3" || tg.Engine != protocol.EngineMeilisearch {
		t.Errorf("empty: %+v", tg)
	}
	for port, want := range map[int]string{full.port: "holds data", tlsOwn.port: "TLS", old.port: "1.18", 7799: "--move-target",
		recv.port: "receiving"} {
		if tg := got[port]; tg.Standby || tg.Usable || !strings.Contains(tg.NoStandby, want) || tg.Reason != tg.NoStandby {
			t.Errorf("port %d: %+v, want a reason with %q", port, tg, want)
		}
	}
	env.Config.Mode = agent.ModeDockerSidecar
	if got := (&Engine{}).StandbyTargets(ctx, env); got != nil {
		t.Errorf("in a sidecar: %+v", got)
	}
}

func putDoc(t *testing.T, r *repo, d backupDoc) {
	t.Helper()
	if err := r.putJSON(context.Background(), backupKey(d.Label, backupDocName), d); err != nil {
		t.Fatal(err)
	}
}

func TestMoveRestorePlan(t *testing.T) {
	ctx := context.Background()
	f := newFakeMeili(t)
	env, _ := moveEnv(t, f)
	db := protocol.DatabaseSpec{ID: "db_1", Name: "search", Stanza: "search", Engine: protocol.EngineMeilisearch}
	r, err := openRepo(env, db)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	a := backupDoc{Label: newLabel(t0), TakenAt: t0, Version: "1.54.3"}
	b := backupDoc{Label: newLabel(t0.Add(15 * time.Minute)), TakenAt: t0.Add(15 * time.Minute), Version: "1.54.3", Data: a.Label}
	putDoc(t, r, a)
	putDoc(t, r, b)
	e := &Engine{}

	// Not empty: refused, nothing changed.
	f.indexes["mine"] = 2
	_, err = e.SnapshotMoveRestore(ctx, env, db, f.port, a.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: 154}, &moveLog{})
	if !errors.Is(err, agent.ErrMoveRefused) || !strings.Contains(err.Error(), "only an empty server") || f.indexes["mine"] != 2 {
		t.Fatalf("non-empty target: %v", err)
	}
	delete(f.indexes, "mine")
	// Older than the database's Meilisearch: refused.
	f.version = "1.53.0"
	_, err = e.SnapshotMoveRestore(ctx, env, db, f.port, a.Label, agent.SnapshotMoveRestoreOptions{First: true, Major: 154}, &moveLog{})
	if !errors.Is(err, agent.ErrMoveRefused) || !strings.Contains(err.Error(), "older than") || !strings.Contains(err.Error(), "1.54") {
		t.Fatalf("older target: %v", err)
	}
	f.version = "1.54.3"
	// A snapshot that isn't there.
	if _, err := e.SnapshotMoveRestore(ctx, env, db, f.port, "20200101-000000F", agent.SnapshotMoveRestoreOptions{First: true}, &moveLog{}); !errors.Is(err, agent.ErrMoveRefused) {
		t.Fatalf("a missing snapshot: %v", err)
	}
	// A server Rowsafe can't copy into (TLS of its own): refused too.
	s, _ := loadServer(env, f.port)
	s.TLS = true
	_ = saveServer(env, s)
	if _, err := e.SnapshotMoveRestore(ctx, env, db, f.port, a.Label, agent.SnapshotMoveRestoreOptions{First: true}, &moveLog{}); !errors.Is(err, agent.ErrMoveRefused) {
		t.Fatalf("TLS: %v", err)
	}
	s.TLS = false
	_ = saveServer(env, s)
	// Clear after a refusal (the generic layer skips it, but even so)
	// leaves the server's own data alone: only what the move recorded goes.
	f.indexes["mine"] = 2
	if err := e.SnapshotMoveClear(ctx, env, db, f.port, &moveLog{}); err != nil || f.indexes["mine"] != 2 {
		t.Fatalf("Clear touched the server's own index: %v %v", f.indexes, err)
	}
	delete(f.indexes, "mine")
	// A follow restore of a backup that records the snapshot held: skipped.
	_ = saveJSONFile(moveStateFile(env, f.port), moveState{DatabaseID: db.ID, Stanza: db.Stanza, Label: a.Label, Indexes: []string{"movies"}})
	ref, err := e.SnapshotMoveRestore(ctx, env, db, f.port, b.Label, agent.SnapshotMoveRestoreOptions{Prev: a.Label}, &moveLog{})
	if err != nil || ref.Label != b.Label || !ref.At.Equal(b.TakenAt) {
		t.Fatalf("unchanged follow: %+v %v", ref, err)
	}
	if st, _ := loadMoveState(env, f.port); st.Label != b.Label || !slices.Equal(st.Indexes, []string{"movies"}) {
		t.Fatalf("state after the follow: %+v", st)
	}
}

// One swap replaces what an earlier restore put there; indexes someone
// else made stay.
func TestInstallRestored(t *testing.T) {
	ctx := context.Background()
	f := newFakeMeili(t)
	env, servers := moveEnv(t, f)
	prefix := movePrefix("db_1")
	f.indexes = map[string]int64{"a": 1, "b": 1, "x": 7, prefix + "a": 5, prefix + "c": 6}
	c, err := dial(ctx, servers[0])
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	_ = env
	if err := installRestored(ctx, c, prefix, []string{"a", "c"}, []string{"a", "b"}, &moveLog{}); err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"a": 5, "c": 6, "x": 7}
	if fmt.Sprint(f.indexes) != fmt.Sprint(want) {
		t.Fatalf("indexes %v, want %v", f.indexes, want)
	}
}

func TestMovePromoteAndClear(t *testing.T) {
	ctx := context.Background()
	f := newFakeMeili(t)
	env, _ := moveEnv(t, f)
	db := protocol.DatabaseSpec{ID: "db_1", Name: "search", Stanza: "search", Engine: protocol.EngineMeilisearch}
	prefix := movePrefix(db.ID)
	f.indexes = map[string]int64{"a": 1, "b": 2, "x": 3, prefix + "a": 1}
	_ = saveJSONFile(moveStateFile(env, f.port), moveState{DatabaseID: db.ID, Indexes: []string{"a", "b", "gone"}})
	e := &Engine{}
	if err := e.SnapshotMoveClear(ctx, env, db, f.port, &moveLog{}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.indexes) != fmt.Sprint(map[string]int64{"x": 3}) {
		t.Fatalf("after Clear: %v", f.indexes)
	}
	if _, ok := loadMoveState(env, f.port); ok {
		t.Error("the move's record stays after Clear")
	}

	f.indexes = map[string]int64{"a": 1, prefix + "a": 1}
	_ = saveJSONFile(moveStateFile(env, f.port), moveState{DatabaseID: db.ID, Indexes: []string{"a"}})
	if err := e.SnapshotMovePromote(ctx, env, db, f.port, &moveLog{}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(f.indexes) != fmt.Sprint(map[string]int64{"a": 1}) {
		t.Fatalf("after Promote: %v", f.indexes)
	}
	if !freshNeeded(env, protocol.DatabaseSpec{ID: db.ID}) {
		t.Error("the next backup after Promote may reuse the old server's snapshot")
	}
	if _, ok := loadMoveState(env, f.port); ok {
		t.Error("Clear could still remove the promoted indexes")
	}
}
