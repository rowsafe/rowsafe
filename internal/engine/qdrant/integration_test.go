//go:build qdrant_integration

// Integration test against a real Qdrant with TLS, keys and JWT access
// control on, its program installed (Proof and copies start their own).
// Run it with scripts/test-qdrant.sh, which runs it inside Qdrant's image:
//
//	ROWSAFE_TEST_QDRANT_PORT=6333 ROWSAFE_TEST_QDRANT_ADMIN_KEY=... ROWSAFE_TEST_QDRANT_ALT_KEY=... \
//	    ROWSAFE_QDRANT_BIN=/qdrant/qdrant go test -tags qdrant_integration ./internal/engine/qdrant/
//
// With ROWSAFE_QDRANT_URL set, it tests a Docker sidecar (the server in
// another container).
package qdrant

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	raw, _ := json.Marshal(params)
	task := &protocol.Task{ID: "task_" + strconv.FormatInt(time.Now().UnixNano(), 36), Type: typ, Database: &db, Params: raw}
	res, err := e.Run(context.Background(), env, task, &testLog{t: t})
	if res == nil {
		return nil, err
	}
	return res.(*T), err
}

func mustRun[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) *T {
	t.Helper()
	r, err := run[T](t, e, env, db, typ, params)
	if err != nil {
		t.Fatalf("%s: %v", typ, err)
	}
	return r
}

// admin is a client with the server's own admin key.
func admin(t *testing.T, port int) *client {
	t.Helper()
	c, err := newClient(context.Background(), Login{Key: os.Getenv("ROWSAFE_TEST_QDRANT_ADMIN_KEY")}, port)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func vec(n int) []float64 {
	v := make([]float64, n)
	var s float64
	for i := range v {
		v[i] = mrand.Float64() - 0.5
		s += v[i] * v[i]
	}
	for i := range v {
		v[i] /= math.Sqrt(s)
	}
	return v
}

// addPoints upserts n points with ids from first into coll (unnamed 8-dim
// vectors).
func addPoints(t *testing.T, c *client, coll string, first, n int) {
	t.Helper()
	var pts []map[string]any
	for i := range n {
		id := first + i
		pts = append(pts, map[string]any{"id": id, "vector": vec(8), "payload": map[string]any{"n": id, "city": []string{"Berlin", "Paris", "Rome"}[id%3]}})
	}
	must(t, c.call(context.Background(), http.MethodPut, collPath(coll)+"/points", map[string][]string{"wait": {"true"}}, map[string]any{"points": pts}, nil))
}

func count(t *testing.T, c *client, coll string) int64 {
	t.Helper()
	n, err := c.exactCount(context.Background(), coll)
	if err != nil {
		t.Fatalf("counting %s: %v", coll, err)
	}
	return n
}

func setup(t *testing.T) (e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, a *client, srv *fakes3.Server) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_QDRANT_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_QDRANT_PORT not set")
	}
	dir := t.TempDir()
	srv = fakes3.New("bkt")
	t.Cleanup(srv.Close)
	env = agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "qdrant"), MainStateDir: filepath.Join(dir, "engines", "qdrant"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Notes: os.Stderr,
	}
	db = protocol.DatabaseSpec{ID: "db_qd", Name: "vectors", Stanza: "vectors", Port: port, Engine: protocol.EngineQdrant, RetentionFull: 3}
	a = admin(t, port)
	ctx := context.Background()
	names, err := a.collectionNames(ctx)
	must(t, err)
	for _, n := range names {
		must(t, a.deleteCollection(ctx, n))
	}
	must(t, a.call(ctx, http.MethodPut, collPath("docs"), nil, map[string]any{"vectors": map[string]any{"size": 8, "distance": "Cosine"}}, nil))
	addPoints(t, a, "docs", 1, 200)
	must(t, a.call(ctx, http.MethodPut, collPath("named"), nil, map[string]any{
		"vectors": map[string]any{"img": map[string]any{"size": 4, "distance": "Dot"}}, "sparse_vectors": map[string]any{"txt": map[string]any{}}}, nil))
	must(t, a.call(ctx, http.MethodPut, collPath("named")+"/points", map[string][]string{"wait": {"true"}}, map[string]any{"points": []any{
		map[string]any{"id": 1, "vector": map[string]any{"img": []float64{0.1, 0.2, 0.3, 0.4}, "txt": map[string]any{"indices": []int{1, 7}, "values": []float64{0.5, 0.2}}}},
		map[string]any{"id": "5c56c793-69f3-4fbf-87e6-c4bf54c28c26", "vector": map[string]any{"img": []float64{0.4, 0.3, 0.2, 0.1}}},
	}}, nil))
	must(t, a.call(ctx, http.MethodPost, "/collections/aliases", nil, map[string]any{"actions": []any{
		map[string]any{"create_alias": map[string]any{"collection_name": "docs", "alias_name": "prod-docs"}}}}, nil))
	if snaps, err := a.listFullSnapshots(ctx); err == nil {
		for _, s := range snaps {
			_ = a.deleteFullSnapshot(ctx, s.Name)
		}
	}
	e = &Engine{}
	// Rowsafe's key: the alternative key root set.
	res, err := SaveLogin(ctx, env, port, os.Getenv("ROWSAFE_TEST_QDRANT_ALT_KEY"), "alt", "")
	must(t, err)
	if !res.JWT {
		t.Fatal("the login should sign tokens (jwt_rbac is on)")
	}
	return e, env, db, a, srv
}

func TestQdrant(t *testing.T) {
	e, env, db, a, srv := setup(t)
	ctx := context.Background()

	t.Run("status and discovery", func(t *testing.T) {
		st, err := ServerStatus(ctx, env, db.Port)
		must(t, err)
		if st.Login != "ok" || st.JWT != "yes" || st.Collections != 2 || st.Binary == "" {
			t.Fatalf("status: %+v", st)
		}
		if !inDocker() && !st.TLS {
			t.Fatalf("status: TLS should be on: %+v", st)
		}
		var b bytes.Buffer
		st.Print(&b)
		if !strings.Contains(b.String(), "login=ok\n") {
			t.Fatalf("print: %s", b.String())
		}
		found, err := e.Discover(ctx, env)
		must(t, err)
		if len(found) == 0 || found[0].Port != db.Port || len(found[0].Databases) != 2 {
			t.Fatalf("discover: %+v", found)
		}
	})

	t.Run("a wrong key is refused", func(t *testing.T) {
		if _, err := SaveLogin(ctx, agent.EngineEnv{StateDir: t.TempDir()}, db.Port, "not-the-key", "key", ""); err == nil {
			t.Fatal("a wrong key was saved")
		}
	})

	adopt := mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if !adopt.Applied || len(adopt.Inspect.Databases) != 2 || adopt.Inspect.Engine != protocol.EngineQdrant {
		t.Fatalf("adopt: %+v", adopt)
	}
	chk := mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	if !chk.OK {
		t.Fatal("check not OK")
	}

	b1 := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if b1.Label == "" || b1.RepoSizeBytes == 0 {
		t.Fatalf("backup: %+v", b1)
	}
	if snaps, err := a.listFullSnapshots(ctx); err != nil || len(snaps) != 0 {
		t.Fatalf("snapshots left on the server: %v %v", snaps, err)
	}
	t.Run("the bucket holds only sealed data", func(t *testing.T) {
		n := 0
		for _, k := range srv.Keys() {
			data, _ := srv.Object(k)
			if !bytes.HasPrefix(data, []byte("RWSF1\n")) {
				t.Errorf("%s isn't sealed", k)
			}
			if strings.Contains(k, "docs") || bytes.Contains(data, []byte("Berlin")) || bytes.Contains(data, []byte("collections_mapping")) {
				t.Errorf("%s shows what it holds", k)
			}
			n++
		}
		if n < 3 {
			t.Fatalf("only %d objects: %v", n, srv.Keys())
		}
	})

	addPoints(t, a, "docs", 1001, 50)
	mk := mustRun[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "after-load"})
	if !mk.Archived || mk.LSN == "" {
		t.Fatalf("mark: %+v", mk)
	}

	t.Run("Proof", func(t *testing.T) {
		dr := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
		if !dr.Passed || dr.BackupLabel != mk.LSN || len(dr.Databases) != 2 {
			t.Fatalf("drill: %+v", dr)
		}
		for _, d := range dr.Databases {
			if d.Name == "docs" && (d.RestoredTables != 250 || d.SourceTables != 250 || !d.Present) {
				t.Fatalf("docs: %+v", d)
			}
		}
		if entries, _ := os.ReadDir(env.Config.DrillDir); len(entries) > 0 {
			t.Fatalf("the restore test left %v", entries)
		}
	})

	t.Run("a copy at the Mark answers searches", func(t *testing.T) {
		cp := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
			protocol.RewindCopyParams{CopyID: "cp1", Target: protocol.RewindTarget{Mark: "after-load"}})
		if cp.Port == 0 || len(cp.Databases) != 2 {
			t.Fatalf("copy: %+v", cp)
		}
		rec, _ := e.copyState(env).get("cp1")
		c, err := scratchAt(rec.Dir).connect(ctx)
		must(t, err)
		defer c.Close()
		if n := count(t, c, "docs"); n != 250 {
			t.Fatalf("copy has %d points in docs", n)
		}
		ci, err := c.collection(ctx, "docs")
		must(t, err)
		if hits, err := sampleSearch(ctx, c, ci); err != nil || hits < 1 {
			t.Fatalf("search on the copy: %d %v", hits, err)
		}
		ci, err = c.collection(ctx, "named")
		must(t, err)
		if hits, err := sampleSearch(ctx, c, ci); err != nil || hits < 1 {
			t.Fatalf("search on named: %d %v", hits, err)
		}
		// Not on the network, and not without its key.
		anon := &client{base: c.base, http: c.http}
		if _, err := anon.collectionNames(ctx); err == nil {
			t.Fatal("the copy answers without its key")
		}
		if len(e.RewindStates(env)) != 1 {
			t.Fatalf("states: %+v", e.RewindStates(env))
		}
		dropped := mustRun[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "cp1"})
		if !dropped.Removed {
			t.Fatalf("drop: %+v", dropped)
		}
	})

	t.Run("rewind in place and undo", func(t *testing.T) {
		must(t, a.call(ctx, http.MethodPost, collPath("docs")+"/points/delete", map[string][]string{"wait": {"true"}},
			map[string]any{"filter": map[string]any{"must": []any{map[string]any{"key": "n", "range": map[string]any{"lte": 100}}}}}, nil))
		must(t, a.deleteCollection(ctx, "named"))
		must(t, a.call(ctx, http.MethodPut, collPath("extra"), nil, map[string]any{"vectors": map[string]any{"size": 2, "distance": "Euclid"}}, nil))
		before := count(t, a, "docs")
		ip := mustRun[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
			protocol.RewindInPlaceParams{RewindID: "rw1", Target: protocol.RewindTarget{Mark: "after-load"}, KeepDays: 2})
		if ip.KeptUntil == nil {
			t.Fatalf("in place: %+v", ip)
		}
		names, _ := a.collectionNames(ctx)
		if strings.Join(names, ",") != "docs,named" || count(t, a, "docs") != 250 || count(t, a, "named") != 2 {
			t.Fatalf("after the rewind: %v docs=%d", names, count(t, a, "docs"))
		}
		al, _ := a.aliases(ctx)
		if al["prod-docs"] != "docs" {
			t.Fatalf("aliases: %v", al)
		}
		un := mustRun[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "rw1"})
		if un.KeptUntil == nil {
			t.Fatalf("undo: %+v", un)
		}
		names, _ = a.collectionNames(ctx)
		if strings.Join(names, ",") != "docs,extra" || count(t, a, "docs") != before {
			t.Fatalf("after the undo: %v docs=%d (want %d)", names, count(t, a, "docs"), before)
		}
		cl := mustRun[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rw1"})
		if !cl.Removed {
			t.Fatalf("cleanup: %+v", cl)
		}
	})

	t.Run("keys in Databases & users", func(t *testing.T) {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		must(t, err)
		pub := protocol.EncodeSealKey(priv.PublicKey())
		raw, _ := json.Marshal(protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "reader", Access: protocol.DBAccessReadOnly,
			Databases: []string{"docs"}, PublicKey: pub})
		task := &protocol.Task{ID: "task_key1", Type: protocol.TaskDBAdmin, Database: &db, Params: raw}
		out, err := e.Run(ctx, env, task, &testLog{t: t})
		must(t, err)
		res := out.(*protocol.DBAdminResult)
		if res.Secret == nil || res.Connection == nil {
			t.Fatalf("no secret: %+v", res)
		}
		plain, err := protocol.Open(priv, []byte("task_key1"), res.Secret)
		must(t, err)
		var sec protocol.DBSecret
		must(t, json.Unmarshal(plain, &sec))
		if sec.Password == "" || strings.Contains(sec.URL, sec.Password) || !strings.HasPrefix(sec.URL, "http") {
			t.Fatalf("secret: url %q", sec.URL)
		}
		reader := tokenClient(t, sec.Password, db.Port)
		defer reader.Close()
		if names, err := reader.collectionNames(ctx); err != nil || strings.Join(names, ",") != "docs" {
			t.Fatalf("the reader sees %v (%v)", names, err)
		}
		if err := reader.call(ctx, http.MethodPut, collPath("docs")+"/points", nil, map[string]any{"points": []any{map[string]any{"id": 9999, "vector": vec(8)}}}, nil); err == nil {
			t.Fatal("a read-only key could write")
		}
		inv := res.Inventory
		if inv == nil || len(inv.Users) < 2 {
			t.Fatalf("inventory: %+v", inv)
		}
		mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "reader"})
		if _, err := reader.collectionNames(ctx); err == nil {
			t.Fatal("a removed key still works")
		}

		// An admin key (it always expires) can write Rowsafe's collection:
		// it brings the removed key back, and adds an entry of its own. The
		// next check (monitoring) undoes both and reports it.
		boss := makeTestKey(t, e, env, db, priv, pub, protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "boss", Access: protocol.DBAccessOwner})
		if boss.user.ValidUntil == nil || boss.user.ValidUntil.Sub(time.Now()) < 29*24*time.Hour || boss.user.ValidUntil.Sub(time.Now()) > 31*24*time.Hour {
			t.Fatalf("an admin key expires in 30 days by default: %+v", boss.user)
		}
		if !strings.Contains(boss.summary, "expires on") {
			t.Fatalf("summary: %s", boss.summary)
		}
		bc := tokenClient(t, boss.token, db.Port)
		defer bc.Close()
		readerNonce := tokenNonce(t, sec.Password)
		must(t, bc.call(ctx, http.MethodPut, collPath(protocol.QdrantKeysCollection)+"/points", url.Values{"wait": {"true"}}, map[string]any{"points": []any{
			map[string]any{"id": keyPointID("reader"), "vector": map[string]any{}, "payload": map[string]any{"key": "reader", "nonce": readerNonce}},
			map[string]any{"id": "6f1d8d3e-0000-4000-8000-000000000001", "vector": map[string]any{}, "payload": map[string]any{"key": "reader", "nonce": readerNonce}},
		}}, nil))
		if _, err := reader.collectionNames(ctx); err != nil {
			t.Fatalf("the admin key didn't bring the key back (the test's premise): %v", err)
		}
		dm, err := e.Monitor(ctx, env, db)
		must(t, err)
		if _, err := reader.collectionNames(ctx); err == nil {
			t.Fatal("a removed key brought back by an admin key still works after the check")
		}
		if dm.Qdrant == nil || dm.Qdrant.KeyListRepaired == nil || dm.Qdrant.KeyListRepaired.Removed != 2 ||
			dm.Qdrant.KeyListRepaired.AdminKeys != 1 || strings.Join(dm.Qdrant.KeyListRepaired.Keys, ",") != "reader" {
			t.Fatalf("the repair isn't reported: %+v", dm.Qdrant)
		}
		// Deleting a key's entry (another admin-key trick) is undone too.
		must(t, deleteKeyByName(ctx, bc, "boss"))
		if _, err := bc.collectionNames(ctx); err == nil {
			t.Fatal("the premise: without its entry a key's token stops")
		}
		dm, err = e.Monitor(ctx, env, db)
		must(t, err)
		if _, err := bc.collectionNames(ctx); err != nil || dm.Qdrant.KeyListRepaired.Restored != 1 {
			t.Fatalf("a key's entry deleted by someone else isn't written back: %v %+v", err, dm.Qdrant.KeyListRepaired)
		}

		// Removing a collection: keys limited to it go, keys that also
		// reached it need a new token.
		must(t, a.call(ctx, http.MethodPut, collPath("tmp"), nil, map[string]any{"vectors": map[string]any{"size": 8, "distance": "Cosine"}}, nil))
		both := makeTestKey(t, e, env, db, priv, pub, protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "both",
			Access: protocol.DBAccessReadWrite, Databases: []string{"docs", "tmp"}})
		only := makeTestKey(t, e, env, db, priv, pub, protocol.DBAdminParams{Action: protocol.DBAdminCreateUser, User: "only",
			Access: protocol.DBAccessReadOnly, Databases: []string{"tmp"}})
		drop := mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropDatabase,
			Database: "tmp", Confirm: "tmp"})
		if !strings.Contains(drop.Summary, "(only) were removed") || !strings.Contains(drop.Summary, "(both)") || !strings.Contains(drop.Summary, "make a new token") {
			t.Fatalf("summary: %s", drop.Summary)
		}
		for _, k := range []testKey{both, only} {
			kc := tokenClient(t, k.token, db.Port)
			if _, err := kc.collectionNames(ctx); err == nil {
				t.Fatalf("%s's token still works after its collection went", k.user.Name)
			}
			kc.Close()
		}
		renewed := makeTestKey(t, e, env, db, priv, pub, protocol.DBAdminParams{Action: protocol.DBAdminResetPassword, User: "both"})
		rc := tokenClient(t, renewed.token, db.Port)
		if names, err := rc.collectionNames(ctx); err != nil || strings.Join(names, ",") != "docs" {
			t.Fatalf("both's new token: %v %v", names, err)
		}
		rc.Close()
		gone := mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintQdrantRevokeAdminKeys})
		if _, err := bc.collectionNames(ctx); err == nil || !strings.Contains(gone.Summary, "boss") {
			t.Fatalf("admin keys removed: %v %s", err, gone.Summary)
		}
		mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminDropUser, User: "both"})
		// Rowsafe's own collection stays out of the lists.
		lst := mustRun[protocol.DBAdminResult](t, e, env, db, protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminList})
		for _, d := range lst.Inventory.Databases {
			if d.Name == protocol.QdrantKeysCollection {
				t.Fatal("the keys collection is listed")
			}
		}
	})

	t.Run("Pulse, fixes and security", func(t *testing.T) {
		dm, err := e.Monitor(ctx, env, db)
		must(t, err)
		if dm.Error != "" || dm.Qdrant == nil || dm.Metrics["qdrant_collections"] < 2 || dm.Metrics["qdrant_resident_bytes"] <= 0 {
			t.Fatalf("monitor: %+v %+v", dm, dm.Metrics)
		}
		res := mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
			protocol.MaintenanceParams{Action: protocol.MaintQdrantVectorsOnDisk, DB: "docs"})
		ci, err := a.collection(ctx, "docs")
		must(t, err)
		if len(ci.Vectors) != 1 || !ci.Vectors[0].OnDisk {
			t.Fatalf("vectors on disk: %+v (%s)", ci.Vectors, res.Summary)
		}
		rep, err := e.SecurityReport(ctx, env, db)
		must(t, err)
		qs := rep.EngineSecurity.Qdrant
		if !qs.APIKey || !qs.JWT || rep.EngineSecurity.AuthDisabled {
			t.Fatalf("security: %+v %+v", rep, qs)
		}
		if !inDocker() && (!rep.SSL || rep.Cert == nil || len(rep.OutsidePorts) != 1) {
			t.Fatalf("security TLS: %+v", rep)
		}
		if msg, err := e.Ready(ctx, env, db); err != nil {
			t.Fatalf("ready: %s %v", msg, err)
		}
	})

	t.Run("retention keeps the newest and the Marks within", func(t *testing.T) {
		for range 3 {
			mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, nil)
			time.Sleep(1100 * time.Millisecond)
		}
		r, err := openRepo(env, db)
		must(t, err)
		docs, _, err := r.listBackups(ctx)
		must(t, err)
		plain := 0
		for _, d := range docs {
			if d.Source != sourceMark {
				plain++
			}
		}
		// The newest 3 plus one a day (today's newest is among them).
		if plain != 3 {
			t.Fatalf("%d scheduled snapshots kept: %+v", plain, docs)
		}
	})
}

// tokenClient reaches the server with a key's token, as an app would.
func tokenClient(t *testing.T, token string, port int) *client {
	t.Helper()
	c, err := newClient(context.Background(), Login{}, port)
	must(t, err)
	c.bearer = token
	return c
}

// tokenNonce reads a key token's nonce (its value_exists claim).
func tokenNonce(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	must(t, err)
	var c struct {
		ValueExists struct {
			Matches []struct{ Key, Value string } `json:"matches"`
		} `json:"value_exists"`
	}
	must(t, json.Unmarshal(raw, &c))
	for _, m := range c.ValueExists.Matches {
		if m.Key == "nonce" {
			return m.Value
		}
	}
	t.Fatal("no nonce in the token")
	return ""
}

type testKey struct {
	token   string
	summary string
	user    protocol.DBUser
}

// makeTestKey runs create_user or reset_password and opens the token.
func makeTestKey(t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, priv *ecdh.PrivateKey, pub string, p protocol.DBAdminParams) testKey {
	t.Helper()
	p.PublicKey = pub
	raw, _ := json.Marshal(p)
	id := "task_" + p.User + strconv.Itoa(mrand.IntN(1_000_000))
	out, err := e.Run(context.Background(), env, &protocol.Task{ID: id, Type: protocol.TaskDBAdmin, Database: &db, Params: raw}, &testLog{t: t})
	must(t, err)
	res := out.(*protocol.DBAdminResult)
	plain, err := protocol.Open(priv, []byte(id), res.Secret)
	must(t, err)
	var sec protocol.DBSecret
	must(t, json.Unmarshal(plain, &sec))
	k := testKey{token: sec.Password, summary: res.Summary}
	for _, u := range res.Inventory.Users {
		if u.Name == p.User {
			k.user = u
		}
	}
	return k
}
