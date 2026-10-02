//go:build mongodb_integration

package mongodb

import (
	"context"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestMongoDBInPlace rewinds a real replica set in place, undoes it and
// deletes what was kept (scripts/test-mongodb.sh runs it too).
func TestMongoDBInPlace(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT not set")
	}
	t.Setenv("ROWSAFE_MONGODB_ARCHIVE_INTERVAL", "2s")
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.Start(sctx, env)
	if _, err := CreateLogin(ctx, env, port, os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")); err != nil {
		t.Fatal("CreateLogin:", err)
	}
	db := protocol.DatabaseSpec{ID: "db_mip", Name: "inv", Stanza: "inv-mongo", Port: port, RetentionFull: 1, Engine: protocol.EngineMongoDB}
	adminLogin := Login{}
	if u := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"); u != "" {
		adminLogin = Login{User: u, Password: os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")}
	}
	admin, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(admin)
	for _, d := range []string{"inv", "inv2"} {
		_ = admin.Database(d).Drop(ctx)
	}
	inv := admin.Database("inv")
	items, notes := inv.Collection("items"), inv.Collection("notes")
	insert := func(coll *mongo.Collection, from, to int) {
		t.Helper()
		var docs []any
		for i := from; i < to; i++ {
			docs = append(docs, bson.D{{Key: "_id", Value: i}, {Key: "n", Value: i}})
		}
		if _, err := coll.InsertMany(ctx, docs); err != nil {
			t.Fatal(err)
		}
	}
	count := func(c *mongo.Collection) int64 {
		t.Helper()
		n, err := c.CountDocuments(ctx, bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	colls := func(d string) string {
		t.Helper()
		names, err := admin.Database(d).ListCollectionNames(ctx, bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, n := range names {
			if !strings.HasPrefix(n, "system.") {
				out = append(out, n)
			}
		}
		slices.Sort(out)
		return strings.Join(out, ",")
	}
	insert(items, 0, 100)
	insert(notes, 0, 10)
	if _, err := items.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "n", Value: -1}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	insert(items, 100, 120)
	time.Sleep(1100 * time.Millisecond)
	t1 := time.Now().UTC().Truncate(time.Second)
	time.Sleep(1100 * time.Millisecond)
	// The accident: deleted items, a dropped collection, a new one, a new database.
	if _, err := items.DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$lt", Value: 50}}}}); err != nil {
		t.Fatal(err)
	}
	if err := notes.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	insert(inv.Collection("extra"), 0, 3)
	insert(admin.Database("inv2").Collection("x"), 0, 2)

	res, err := run[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
		protocol.RewindInPlaceParams{RewindID: "rwd_test1", Target: protocol.RewindTarget{Time: &t1}, KeepDays: 7})
	if err != nil {
		t.Fatal("rewind:", err)
	}
	tag := rewindTag("rwd_test1")
	if n := count(items); n != 120 {
		t.Fatalf("items after the rewind: %d (%+v)", n, res)
	}
	if n := count(notes); n != 10 {
		t.Fatalf("notes after the rewind: %d", n)
	}
	if got, want := colls("inv"), "items,notes,"+beforePrefix(tag)+"extra,"+beforePrefix(tag)+"items"; got != want {
		t.Fatalf("collections after the rewind: %s, want %s", got, want)
	}
	if got := colls("inv2"); got != beforePrefix(tag)+"x" {
		t.Fatalf("inv2 after the rewind: %s", got)
	}
	ix, _ := items.Indexes().ListSpecifications(ctx)
	if len(ix) != 2 {
		t.Fatalf("indexes after the rewind: %+v", ix)
	}
	if st := e.RewindStates(env); len(st) != 1 || st[0].Status != protocol.RewindKeptBefore {
		t.Fatalf("states %+v", st)
	}
	insert(items, 9000, 9001) // written to the rewound data

	if _, err := run[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "rwd_test1"}); err != nil {
		t.Fatal("undo:", err)
	}
	if n := count(items); n != 70 {
		t.Fatalf("items after the undo: %d", n)
	}
	if got := colls("inv"); got != "extra,items,"+afterPrefix(tag)+"items,"+afterPrefix(tag)+"notes" {
		t.Fatalf("collections after the undo: %s", got)
	}
	if got := colls("inv2"); got != "x" {
		t.Fatalf("inv2 after the undo: %s", got)
	}

	// Restores to any second still work across the swaps (they are in the oplog).
	time.Sleep(3 * time.Second)
	now := time.Now().UTC().Truncate(time.Second)
	time.Sleep(1100 * time.Millisecond)
	cp, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c1", Target: protocol.RewindTarget{Time: &now}})
	if err != nil {
		t.Fatal("copy:", err)
	}
	cc, err := connect(ctx, scratchAt(env, mustCopyDir(t, e, env, "c1")).uri())
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := cc.Database("inv").Collection("items").CountDocuments(ctx, bson.D{}); n != 70 {
		t.Fatalf("copy after the swaps has %d items (%+v)", n, cp)
	}
	disconnect(cc)
	if _, err := run[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := run[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rwd_test1"}); err != nil {
		t.Fatal("cleanup:", err)
	}
	if got := colls("inv"); got != "extra,items" {
		t.Fatalf("collections after the cleanup: %s", got)
	}
	if st := e.RewindStates(env); len(st) != 0 {
		t.Fatalf("states after cleanup %+v", st)
	}
}

func mustCopyDir(t *testing.T, e *Engine, env agent.EngineEnv, id string) string {
	t.Helper()
	r, ok := e.copyState(env).get(id)
	if !ok {
		t.Fatalf("no copy %s", id)
	}
	return r.Dir
}
