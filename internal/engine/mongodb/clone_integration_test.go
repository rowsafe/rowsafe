//go:build mongodb_integration

package mongodb

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestMongoDBClone clones a database into a second, empty server as it was
// at a moment (scripts/test-mongodb.sh with MONGO_CLONE=1 starts it).
func TestMongoDBClone(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_CLONE_PORT"))
	if port == 0 || port2 == 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT and ROWSAFE_TEST_MONGODB_CLONE_PORT not set")
	}
	t.Setenv("ROWSAFE_MONGODB_ARCHIVE_INTERVAL", "2s")
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.Start(sctx, env)
	adminUser, adminPW := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")
	if _, err := CreateLogin(ctx, env, port, adminUser, adminPW); err != nil {
		t.Fatal("login:", err)
	}
	if adminUser != "" {
		// Without the restore role the second server can't take a clone.
		if _, err := CreateLoginWith(ctx, env, port2, adminUser, adminPW, false); err != nil {
			t.Fatal("login 2:", err)
		}
		c2, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: port2})
		if err != nil {
			t.Fatal(err)
		}
		in2, err := inspect(ctx, c2)
		disconnect(c2)
		if err != nil || !strings.Contains(cloneTargetReason(in2), "may not load") {
			t.Fatalf("a login without the restore role: %q %v", cloneTargetReason(in2), err)
		}
		if _, err := CreateLoginWith(ctx, env, port2, adminUser, adminPW, true); err != nil {
			t.Fatal("login 2 with clones:", err)
		}
	}
	adminLogin := Login{}
	if adminUser != "" {
		adminLogin = Login{User: adminUser, Password: adminPW}
	}
	admin, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(admin)
	admin2, err := connect(ctx, strings.Replace(adminLogin.uri(port2), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(admin2)
	shop := admin.Database("shopc")
	_ = shop.Drop(ctx)
	orders := shop.Collection("orders")
	insert := func(from, to int) {
		var docs []any
		for i := from; i < to; i++ {
			docs = append(docs, bson.D{{Key: "_id", Value: i}, {Key: "email", Value: fmt.Sprintf("u%d@example.com", i)}})
		}
		if _, err := orders.InsertMany(ctx, docs); err != nil {
			t.Fatal(err)
		}
	}
	insert(0, 100)
	if _, err := orders.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "email", Value: 1}}}); err != nil {
		t.Fatal(err)
	}
	db := protocol.DatabaseSpec{ID: "db_mongo_clone", Name: "shopc", Stanza: "shop-mongo-clone", Port: port, RetentionFull: 1, Engine: protocol.EngineMongoDB}
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal("adopt:", err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal("backup:", err)
	}
	insert(100, 150)
	time.Sleep(1100 * time.Millisecond)
	at := time.Now().UTC().Truncate(time.Second)
	time.Sleep(1100 * time.Millisecond)
	if _, err := orders.DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$lt", Value: 10}}}}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second) // the changes reach the bucket

	if ts := e.StandbyTargets(ctx, env); len(ts) > 0 {
		t.Logf("targets: %+v", ts)
	}
	major, size, _, err := e.ForkFacts(ctx, env, db)
	if err != nil || major == 0 {
		t.Fatalf("facts: %d %v", major, err)
	}
	tl := &testLog{t: t}
	res, err := e.ForkRestore(ctx, env, protocol.ForkRestoreParams{ForkID: "fork_m", Name: "shop-staging", Source: db,
		Target: protocol.RewindTarget{Time: &at}, Placement: protocol.ForkEmptyServer, Port: port2, Major: major, SizeBytes: size}, tl)
	if err != nil {
		t.Fatal("clone:", err)
	}
	t.Logf("clone: %+v", res)
	n, err := admin2.Database("shopc").Collection("orders").CountDocuments(ctx, bson.D{})
	if err != nil || n != 150 {
		t.Fatalf("the clone has %d orders (%v), want 150 (as it was before the delete)", n, err)
	}
	idx, _ := admin2.Database("shopc").Collection("orders").Indexes().ListSpecifications(ctx)
	if len(idx) != 2 {
		t.Fatalf("indexes: %+v", idx)
	}
	if res.RecoveredTo == nil || res.RecoveredTo.After(at.Add(time.Second)) {
		t.Fatalf("result: %+v", res)
	}
	// Not empty any more: a second clone is refused.
	if _, err := e.ForkRestore(ctx, env, protocol.ForkRestoreParams{ForkID: "fork_m2", Name: "x", Source: db,
		Target: protocol.RewindTarget{Time: &at}, Placement: protocol.ForkEmptyServer, Port: port2}, tl); err == nil ||
		!strings.Contains(err.Error(), "isn't empty") {
		t.Fatalf("second clone: %v", err)
	}
	_ = admin2.Database("shopc").Drop(ctx)
}
