//go:build mongodb_integration

package mongodb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/protocol/e2e"
)

// TestMongoDBMoveIn moves a database from the first server (playing Atlas)
// into the second with a one-time copy (MONGO_CLONE=1 starts the second).
func TestMongoDBMoveIn(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_CLONE_PORT"))
	if port == 0 || port2 == 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT and ROWSAFE_TEST_MONGODB_CLONE_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	adminUser, adminPW := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")
	if _, err := CreateLoginWith(ctx, env, port2, adminUser, adminPW, true); err != nil {
		t.Fatal("login:", err)
	}
	adminLogin := Login{}
	if adminUser != "" {
		adminLogin = Login{User: adminUser, Password: adminPW}
	}
	src, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(src)
	tgt, err := connect(ctx, strings.Replace(adminLogin.uri(port2), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(tgt)
	_ = src.Database("atlasdb").Drop(ctx)
	var docs []any
	for i := 0; i < 250; i++ {
		docs = append(docs, bson.D{{Key: "_id", Value: i}, {Key: "v", Value: fmt.Sprint(i)}})
	}
	if _, err := src.Database("atlasdb").Collection("items").InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Database("atlasdb").Collection("other").InsertOne(ctx, bson.D{{Key: "x", Value: 1}}); err != nil {
		t.Fatal(err)
	}
	spec := protocol.DatabaseSpec{ID: "db_target", Name: "target", Port: port2, Engine: protocol.EngineMongoDB}
	m := agent.MigrateEnv{ID: "mig1", Dir: filepath.Join(t.TempDir(), "mig1"), Progress: func(protocol.MigrationStatus) {}}
	phase := ""
	m.SetPhase = func(p string) { phase = p }
	tl := &testLog{t: t}
	run := func(typ string, p protocol.MigrateParams) any {
		t.Helper()
		p.MigrationID = m.ID
		m.Phase = phase
		res, err := e.Migrate(ctx, env, spec, m, typ, p, tl)
		if err != nil {
			t.Fatalf("%s %s: %v", typ, p.Action, err)
		}
		return res
	}
	key := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateKey}).(*protocol.MigrateKeyResult)
	pub, err := e2e.ParsePublicKey(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	su := url.URL{Scheme: "mongodb", Host: "127.0.0.1:" + strconv.Itoa(port), Path: "/atlasdb", RawQuery: "directConnection=true"}
	if adminUser != "" {
		su.User = url.UserPassword(adminUser, adminPW)
	}
	box, err := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(m.ID), []byte(su.String()))
	if err != nil {
		t.Fatal(err)
	}
	check := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: &box, TargetDB: "moved"}).(*protocol.MigrateCheckResult)
	t.Logf("check: %s %+v", check.Summary, check.Checks)
	if !check.DumpOK || !check.LiveSync || check.Source.Tables != 2 {
		t.Fatalf("check: %+v", check)
	}
	browser, _ := e2e.GenerateKey()
	cp := run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodDump, TargetDB: "moved",
		BrowserKey: e2e.PublicKeyString(browser.PublicKey()), Host: "127.0.0.1"}).(*protocol.MigrateCopyResult)
	t.Logf("copy: %s", cp.Summary)
	if cp.Switchover == nil || cp.Switchover.Mismatches != 0 || phase != protocol.MigratePhaseSwitched {
		t.Fatalf("copy: %+v", cp)
	}
	if n, _ := tgt.Database("moved").Collection("items").CountDocuments(ctx, bson.D{}); n != 250 {
		t.Fatalf("moved %d items", n)
	}
	if adminUser != "" {
		plain, err := e2e.Open(browser, protocol.MigrateInfo, protocol.MigrateCredentialsAAD(m.ID), *cp.Switchover.Credentials)
		if err != nil {
			t.Fatal(err)
		}
		app, err := connect(ctx, string(plain)+"?directConnection=true")
		if err != nil {
			t.Fatalf("the app login: %v", err)
		}
		defer disconnect(app)
		if _, err := app.Database("moved").Collection("items").InsertOne(ctx, bson.D{{Key: "_id", Value: 1000}}); err != nil {
			t.Fatalf("the app login can't write: %v", err)
		}
	}
	run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCancel, DropTarget: true})
	if names, _ := tgt.Database("moved").ListCollectionNames(ctx, bson.D{}); len(names) != 0 {
		t.Fatalf("cancel left %v", names)
	}
	_ = src.Database("atlasdb").Drop(ctx)
}

// TestMongoDBMoveInLive moves a database with a live sync: the copy, the
// changes made during and after it, then the switchover.
func TestMongoDBMoveInLive(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_CLONE_PORT"))
	if port == 0 || port2 == 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT and ROWSAFE_TEST_MONGODB_CLONE_PORT not set")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	adminUser, adminPW := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")
	if _, err := CreateLoginWith(ctx, env, port2, adminUser, adminPW, true); err != nil {
		t.Fatal("login:", err)
	}
	adminLogin := Login{}
	if adminUser != "" {
		adminLogin = Login{User: adminUser, Password: adminPW}
	}
	src, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(src)
	tgt, err := connect(ctx, strings.Replace(adminLogin.uri(port2), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(tgt)
	_ = src.Database("livedb").Drop(ctx)
	items := src.Database("livedb").Collection("items")
	var docs []any
	for i := 0; i < 500; i++ {
		docs = append(docs, bson.D{{Key: "_id", Value: i}, {Key: "v", Value: 1}})
	}
	if _, err := items.InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	spec := protocol.DatabaseSpec{ID: "db_target", Name: "target", Port: port2, Engine: protocol.EngineMongoDB}
	m := agent.MigrateEnv{ID: "mig2", Dir: filepath.Join(t.TempDir(), "mig2"), Progress: func(protocol.MigrationStatus) {}}
	phase := ""
	m.SetPhase = func(p string) { phase = p }
	tl := &testLog{t: t}
	run := func(typ string, p protocol.MigrateParams) any {
		t.Helper()
		p.MigrationID = m.ID
		m.Phase = phase
		res, err := e.Migrate(ctx, env, spec, m, typ, p, tl)
		if err != nil {
			t.Fatalf("%s %s: %v", typ, p.Action, err)
		}
		return res
	}
	key := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateKey}).(*protocol.MigrateKeyResult)
	pub, _ := e2e.ParsePublicKey(key.PublicKey)
	su := url.URL{Scheme: "mongodb", Host: "127.0.0.1:" + strconv.Itoa(port), Path: "/livedb", RawQuery: "directConnection=true"}
	if adminUser != "" {
		su.User = url.UserPassword(adminUser, adminPW)
	}
	box, _ := e2e.Seal(pub, protocol.MigrateInfo, protocol.MigrateSourceAAD(m.ID), []byte(su.String()))
	check := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCheck, Source: &box, TargetDB: "moved_live"}).(*protocol.MigrateCheckResult)
	if !check.LiveSync {
		t.Fatalf("check: %+v", check)
	}
	run(protocol.TaskMigrateCopy, protocol.MigrateParams{Method: protocol.MigrateMethodLive, TargetDB: "moved_live"})
	// Changes after the copy.
	if _, err := items.InsertOne(ctx, bson.D{{Key: "_id", Value: 500}, {Key: "v", Value: 1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := items.UpdateOne(ctx, bson.D{{Key: "_id", Value: 7}}, bson.D{{Key: "$set", Value: bson.D{{Key: "v", Value: 2}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := items.DeleteOne(ctx, bson.D{{Key: "_id", Value: 8}}); err != nil {
		t.Fatal(err)
	}
	moved := tgt.Database("moved_live").Collection("items")
	var status protocol.MigrationStatus
	for i := 0; i < 30; i++ {
		m.Phase = phase
		status, _ = e.MigrateStatus(ctx, env, spec, m)
		n, _ := moved.CountDocuments(ctx, bson.D{})
		var d struct {
			V int `bson:"v"`
		}
		_ = moved.FindOne(ctx, bson.D{{Key: "_id", Value: 7}}).Decode(&d)
		if phase == protocol.MigratePhaseSyncing && n == 500 && d.V == 2 {
			break
		}
		time.Sleep(time.Second)
	}
	t.Logf("status: %+v", status)
	if phase != protocol.MigratePhaseSyncing {
		t.Fatalf("phase %s: %+v", phase, status)
	}
	var doc struct {
		V int `bson:"v"`
	}
	if err := moved.FindOne(ctx, bson.D{{Key: "_id", Value: 7}}).Decode(&doc); err != nil || doc.V != 2 {
		t.Fatalf("the update didn't come along: %+v %v", doc, err)
	}
	browser, _ := e2e.GenerateKey()
	sw := run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateSwitchover, BrowserKey: e2e.PublicKeyString(browser.PublicKey()),
		Host: "127.0.0.1"}).(*protocol.MigrateSwitchoverResult)
	t.Logf("switchover: %s", sw.Summary)
	if sw.Mismatches != 0 || phase != protocol.MigratePhaseSwitched {
		t.Fatalf("switchover: %+v", sw)
	}
	run(protocol.TaskMigrate, protocol.MigrateParams{Action: protocol.MigrateCancel, DropTarget: true})
	_ = src.Database("livedb").Drop(ctx)
}
