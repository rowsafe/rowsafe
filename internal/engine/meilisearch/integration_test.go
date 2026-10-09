//go:build meilisearch_integration

// Integration test against a real Meilisearch: the test starts a
// "production" instance from the program in ROWSAFE_TEST_MEILISEARCH_BIN
// (Meilisearch Community Edition) and runs every task on it:
//
//	ROWSAFE_TEST_MEILISEARCH_BIN=/path/to/meilisearch \
//	    go test -tags meilisearch_integration ./internal/engine/meilisearch/
package meilisearch

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type testLog struct {
	t  *testing.T
	mu sync.Mutex
	b  strings.Builder
}

func (l *testLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := fmt.Sprintf(format, args...)
	l.b.WriteString(s + "\n")
	l.t.Log(s)
}

func (l *testLog) Output(label string, out []byte) {
	if len(out) > 0 {
		l.Printf("%s output:\n%s", label, out)
	}
}

func run[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) (*T, error) {
	t.Helper()
	return runID[T](t, e, env, db, "task_"+strconv.FormatInt(time.Now().UnixNano(), 36), typ, params)
}

func runID[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, id, typ string, params any) (*T, error) {
	t.Helper()
	raw, _ := json.Marshal(params)
	task := &protocol.Task{ID: id, Type: typ, Database: &db, Params: raw}
	res, err := e.Run(context.Background(), env, task, &testLog{t: t})
	if res == nil {
		return nil, err
	}
	return res.(*T), err
}

func mustRun[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) *T {
	t.Helper()
	v, err := run[T](t, e, env, db, typ, params)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustRunID[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, id, typ string, params any) *T {
	t.Helper()
	v, err := runID[T](t, e, env, db, id, typ, params)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// prod is the "production" instance.
type prod struct {
	sc     *scratch
	master string
	snaps  string
}

func startProd(t *testing.T, bin string) *prod {
	t.Helper()
	dir := t.TempDir()
	sc, err := newScratch(dir, "prod", bin)
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.start(context.Background(), startOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sc.stop)
	return &prod{sc: sc, master: sc.Key, snaps: filepath.Join(sc.Dir, "snapshots")}
}

func (p *prod) admin() *client { return newClient("http", p.sc.Port, p.master) }

func addDocs(t *testing.T, c *client, uid string, from, to int) {
	t.Helper()
	var docs []map[string]any
	for i := from; i < to; i++ {
		docs = append(docs, map[string]any{"id": i, "title": fmt.Sprintf("movie %d", i), "genre": []string{"drama", "comedy"}[i%2]})
	}
	tk, err := c.enqueue(context.Background(), http.MethodPost, "/indexes/"+uid+"/documents", nil, docs)
	if err == nil {
		_, err = c.waitTask(context.Background(), tk, time.Minute)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func deleteDocs(t *testing.T, c *client, uid string, ids ...int) {
	t.Helper()
	tk, err := c.enqueue(context.Background(), http.MethodPost, "/indexes/"+uid+"/documents/delete-batch", nil, ids)
	if err == nil {
		_, err = c.waitTask(context.Background(), tk, time.Minute)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func count(t *testing.T, c *client, uid string) int64 {
	t.Helper()
	st, err := c.stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	s, ok := st.Indexes[uid]
	if !ok {
		return -1
	}
	return s.NumberOfDocuments
}

func TestIntegration(t *testing.T) {
	bin := os.Getenv("ROWSAFE_TEST_MEILISEARCH_BIN")
	if bin == "" {
		t.Skip("ROWSAFE_TEST_MEILISEARCH_BIN is not set")
	}
	ctx := context.Background()
	p := startProd(t, bin)
	admin := p.admin()
	defer admin.close()

	dir := t.TempDir()
	srv := fakes3.New("bkt")
	defer srv.Close()
	env := agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "meilisearch"), MainStateDir: filepath.Join(dir, "engines", "meilisearch"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Notes: os.Stderr,
	}
	e := &Engine{}
	db := protocol.DatabaseSpec{ID: "db_meili", Name: "search", Stanza: "search", Port: p.sc.Port, RetentionFull: 7, Engine: protocol.EngineMeilisearch}

	// The installer's login: the master key once, Rowsafe's own key kept.
	if _, err := Login(ctx, env, LoginOptions{Port: db.Port, Binary: bin, SnapshotDir: p.snaps, DBPath: p.sc.dbPath(), Listen: "127.0.0.1"}, ""); err != ErrNeedMasterKey {
		t.Fatalf("no master key given: %v", err)
	}
	if _, err := Login(ctx, env, LoginOptions{Port: db.Port, Binary: bin, SnapshotDir: p.snaps, DBPath: p.sc.dbPath()}, "wrong-key-wrong-key"); err == nil {
		t.Fatal("a wrong master key was taken")
	}
	lr, err := Login(ctx, env, LoginOptions{Port: db.Port, Binary: bin, SnapshotDir: p.snaps, DBPath: p.sc.dbPath(), Listen: "127.0.0.1"}, p.master)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(serverFile(env, db.Port))
	if strings.Contains(string(data), p.master) {
		t.Fatal("the master key was saved")
	}
	// Again (a re-run of the installer): one Rowsafe key, a new one.
	lr2, err := Login(ctx, env, LoginOptions{Port: db.Port, Binary: bin, SnapshotDir: p.snaps, DBPath: p.sc.dbPath(), Listen: "127.0.0.1"}, p.master)
	if err != nil || lr2.KeyUID == lr.KeyUID {
		t.Fatalf("re-run: %+v %v", lr2, err)
	}
	keys, _ := admin.keys(ctx)
	n := 0
	for _, k := range keys {
		if k.name() == agentKeyName {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d Rowsafe keys", n)
	}
	if st := ServerStatus(ctx, env, db.Port); !st.Answers || st.Login != "ok" || st.Version == "" {
		t.Fatalf("status %+v", st)
	}

	// Data: two indexes.
	addDocs(t, admin, "movies", 0, 50)
	tk, _ := admin.enqueue(ctx, http.MethodPatch, "/indexes/movies/settings", nil, map[string]any{"searchableAttributes": []string{"title"}, "filterableAttributes": []string{"genre"}})
	if _, err := admin.waitTask(ctx, tk, time.Minute); err != nil {
		t.Fatal(err)
	}
	addDocs(t, admin, "books", 0, 7)

	found, err := e.Discover(ctx, env)
	if err != nil || len(found) != 1 || found[0].Port != db.Port || !slices.Contains(found[0].Databases, "movies") {
		t.Fatalf("discover %+v %v", found, err)
	}
	ad := mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if !ad.Applied || len(ad.Inspect.Databases) != 2 || ad.Inspect.Engine != protocol.EngineMeilisearch {
		t.Fatalf("adopt %+v", ad)
	}
	if ck := mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil); !ck.OK {
		t.Fatal("check")
	}
	b := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff})
	if b.Label == "" || b.RepoSizeBytes == 0 || b.Type != protocol.BackupFull {
		t.Fatalf("backup %+v", b)
	}
	for _, k := range srv.Keys() {
		if obj, _ := srv.Object(k); strings.Contains(string(obj), "movie 1") {
			t.Fatalf("%s holds plain text", k)
		}
	}
	mk := mustRun[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-delete"})
	if !mk.Archived || mk.LSN == "" {
		t.Fatalf("mark %+v", mk)
	}
	if _, err := run[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-delete"}); err == nil {
		t.Fatal("a second Mark with the same name")
	}
	drill := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if !drill.Passed || len(drill.Databases) != 2 || drill.Databases[1].RestoredTables != 50 && drill.Databases[0].RestoredTables != 50 {
		t.Fatalf("drill %+v", drill)
	}

	// A mistake: documents deleted, an index added.
	deleteDocs(t, admin, "movies", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
	addDocs(t, admin, "extra", 0, 3)
	if count(t, admin, "movies") != 40 {
		t.Fatal("delete")
	}

	// A copy at the Mark: compare, bring the documents back.
	cp := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "c1", Target: protocol.RewindTarget{Mark: "before-delete"}, Expires: time.Now().Add(time.Hour)})
	if cp.Port == 0 || len(cp.Databases) != 2 {
		t.Fatalf("copy %+v", cp)
	}
	// Production's keys don't open the copy.
	if _, err := newClient("http", cp.Port, p.master).stats(ctx); err == nil || !isAuthError(err) {
		t.Fatalf("the master key opens the copy: %v", err)
	}
	cmp := mustRun[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1"})
	var mv protocol.RewindTableDiff
	for _, d := range cmp.Tables {
		if d.Table == "movies" {
			mv = d
		}
	}
	if mv.MissingInProduction != 10 || mv.Changed != 0 {
		t.Fatalf("compare %+v", cmp)
	}
	rows := mustRun[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows,
		protocol.RewindRowsParams{CopyID: "c1", Tables: []protocol.RewindTable{{Table: "movies"}}})
	if len(rows.Tables) != 1 || rows.Tables[0].Inserted != 10 || count(t, admin, "movies") != 50 {
		t.Fatalf("rows %+v (%d)", rows, count(t, admin, "movies"))
	}
	if st := e.RewindStates(env); len(st) != 1 || st[0].Status != protocol.RewindCopyReady {
		t.Fatalf("states %+v", st)
	}
	// An agent restart: the copy comes back.
	e.stopCopies(env)
	if _, err := run[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1"}); err != nil {
		t.Fatalf("compare after a restart: %v", err)
	}
	drop := mustRun[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"})
	if !drop.Removed {
		t.Fatal("drop")
	}

	// Rewind in place to the Mark, through a swap; Undo; clean up.
	deleteDocs(t, admin, "movies", 20, 21, 22, 23, 24)
	ip := mustRun[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
		protocol.RewindInPlaceParams{RewindID: "rw1", Target: protocol.RewindTarget{Mark: "before-delete"}, KeepDays: 7})
	if ip.KeptUntil == nil || count(t, admin, "movies") != 50 || count(t, admin, "books") != 7 || count(t, admin, "extra") != -1 {
		t.Fatalf("in place %+v: movies %d books %d extra %d", ip, count(t, admin, "movies"), count(t, admin, "books"), count(t, admin, "extra"))
	}
	if st, _ := admin.settings(ctx, "movies"); !strings.Contains(string(st["filterableAttributes"]), "genre") {
		t.Fatalf("settings after the rewind: %s", st["filterableAttributes"])
	}
	undo := mustRun[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "rw1"})
	if undo.KeptUntil == nil || count(t, admin, "movies") != 45 || count(t, admin, "extra") != 3 {
		t.Fatalf("undo: movies %d extra %d", count(t, admin, "movies"), count(t, admin, "extra"))
	}
	cl := mustRun[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rw1"})
	if !cl.Removed {
		t.Fatal("cleanup")
	}
	idx, _ := admin.indexes(ctx)
	for _, i := range idx {
		if isTemporary(i.UID) {
			t.Fatalf("left behind: %s", i.UID)
		}
	}
	keys, _ = admin.keys(ctx)
	for _, k := range keys {
		if strings.HasPrefix(k.name(), "Rowsafe rewind") {
			t.Fatal("the rewind's key was left")
		}
	}

	// Databases & users: a search-only key, sealed to the requester.
	priv, _ := ecdh.P256().GenerateKey(rand.Reader)
	pub := protocol.EncodeSealKey(priv.PublicKey())
	da := mustRunID[protocol.DBAdminResult](t, e, env, db, "task_key1", protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminCreateUser,
		User: "front_search", Access: protocol.DBAccessReadOnly, Databases: []string{"movies"}, PublicKey: pub})
	if da.Secret == nil || da.Connection == nil || da.Connection.Port != db.Port {
		t.Fatalf("create_user %+v", da)
	}
	plain, err := protocol.Open(priv, []byte("task_key1"), da.Secret)
	if err != nil {
		t.Fatal(err)
	}
	var secret protocol.DBSecret
	if err := json.Unmarshal(plain, &secret); err != nil || !keyRE.MatchString(secret.Password) || secret.URL != "http://127.0.0.1:"+strconv.Itoa(db.Port) && !strings.HasPrefix(secret.URL, "http://") {
		t.Fatalf("secret %+v %v", secret, err)
	}
	if raw, _ := json.Marshal(da); strings.Contains(string(raw), secret.Password) {
		t.Fatal("the key is in the result in the clear")
	}
	front := newClient("http", db.Port, secret.Password)
	var sr struct {
		Hits []map[string]any `json:"hits"`
	}
	if err := front.do(ctx, http.MethodPost, "/indexes/movies/search", nil, map[string]any{"q": "movie"}, &sr); err != nil || len(sr.Hits) == 0 {
		t.Fatalf("search with the new key: %v", err)
	}
	if _, err := front.enqueue(ctx, http.MethodPost, "/indexes/movies/documents", nil, []map[string]any{{"id": 999}}); !isAuthError(err) {
		t.Fatalf("a search key added documents: %v", err)
	}
	if err := front.do(ctx, http.MethodPost, "/indexes/books/search", nil, map[string]any{"q": ""}, &sr); !isAuthError(err) {
		t.Fatalf("a key for movies searched books: %v", err)
	}
	front.close()
	inv := da.Inventory
	var fs protocol.DBUser
	for _, u := range inv.Users {
		if u.Name == "front_search" {
			fs = u
		}
		if u.Name == agentKeyName && !u.System {
			t.Error("Rowsafe's key isn't protected")
		}
	}
	if fs.Access != protocol.DBAccessReadOnly || !slices.Equal(fs.Databases, []string{"movies"}) {
		t.Fatalf("the new key %+v", fs)
	}
	if _, err := run[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: agentKeyName}); err == nil {
		t.Fatal("Rowsafe's key was dropped")
	}
	mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: "front_search", PublicKey: pub})
	mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "front_search"})
	mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: "new-index"})
	if count(t, admin, "new-index") != 0 {
		t.Fatal("create_database")
	}
	mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase, Database: "new-index", Confirm: "new-index"})

	// Fixes.
	mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintMeiliCompactIndex, Tables: []string{"movies"}})
	mr := mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintMeiliClearTasks})
	if !strings.Contains(mr.Summary, "nothing to delete") {
		t.Errorf("clear tasks: %s", mr.Summary)
	}

	// Pulse and security.
	dm, err := e.Monitor(ctx, env, db)
	if err != nil || dm.Error != "" || dm.Metrics[collect.MMeiliDocuments] != 45+7+3 || dm.Meilisearch == nil || len(dm.Meilisearch.Indexes) != 3 {
		t.Fatalf("monitor %+v %v", dm, err)
	}
	rep, err := e.SecurityReport(ctx, env, db)
	if err != nil || rep.EngineSecurity.AuthDisabled || rep.SSL || !slices.ContainsFunc(rep.Roles, func(r protocol.RoleInfo) bool { return r.Name == agentKeyName }) {
		t.Fatalf("security %+v %v", rep, err)
	}
	if note, err := e.Ready(ctx, env, db); err != nil || !strings.Contains(note, "3 indexes") {
		t.Fatalf("ready %q %v", note, err)
	}
	if objs, prefix, _, err := e.StoredObjects(ctx, env, db); err != nil || prefix != backupPrefix || len(objs) < 4 {
		t.Fatalf("stored %d %q %v", len(objs), prefix, err)
	}
}
