//go:build mongodb_integration

// Integration test against a real MongoDB replica set of one, with the
// MongoDB tools on PATH (run it with scripts/test-mongodb.sh, which uses the
// official mongo images):
//
//	ROWSAFE_TEST_MONGODB_PORT=27017 go test -tags mongodb_integration ./internal/engine/mongodb/
package mongodb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	rsclient "github.com/rowsafe/rowsafe/client"
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

func testEnv(t *testing.T) (agent.EngineEnv, *fakes3.Server) {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	env := agent.EngineEnv{
		Config: agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind"),
			RestorePointTimeout: 60 * time.Second},
		StateDir: filepath.Join(dir, "engines", "mongodb"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Notes: os.Stderr,
	}
	return env, srv
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

func TestMongoDBEndToEnd(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT not set")
	}
	t.Setenv("ROWSAFE_MONGODB_ARCHIVE_INTERVAL", "2s")
	ctx := context.Background()
	env, srv := testEnv(t)
	e := &Engine{}
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	e.Start(sctx, env)

	// The installer's login step.
	roles, err := CreateLogin(ctx, env, port, os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD"))
	if err != nil {
		t.Fatal("CreateLogin:", err)
	}
	t.Log("roles:", roles)
	st, err := ServerStatus(ctx, env, port)
	if err != nil || st.Login != "ok" || st.ReplSet == "" {
		t.Fatalf("status: %+v %v", st, err)
	}

	db := protocol.DatabaseSpec{ID: "db_mongo", Name: "shop", Stanza: "shop-mongo", Port: port, RetentionFull: 1, Engine: protocol.EngineMongoDB}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(c)
	adminLogin := Login{}
	if u := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"); u != "" {
		adminLogin = Login{User: u, Password: os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")}
	}
	// Not connect(): its appName marks the agent's own operations.
	admin, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(admin)
	shop := admin.Database("shop")
	_ = shop.Drop(ctx)
	orders, notes := shop.Collection("orders"), shop.Collection("notes")
	insert := func(coll *mongo.Collection, from, to int) {
		var docs []any
		for i := from; i < to; i++ {
			docs = append(docs, bson.D{{Key: "_id", Value: i}, {Key: "total", Value: i * 10}, {Key: "email", Value: fmt.Sprintf("u%d@example.com", i)}})
		}
		if _, err := coll.InsertMany(ctx, docs); err != nil {
			t.Fatal(err)
		}
	}
	insert(orders, 0, 1000)
	insert(notes, 0, 50)
	if _, err := orders.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "email", Value: 1}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := notes.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "total", Value: -1}}}); err != nil {
		t.Fatal(err)
	}

	// Plan, then apply.
	plan, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{})
	if err != nil || plan.Applied || plan.Inspect.ArchiveMode != "on" || len(plan.Plan) == 0 {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	applied, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	if err != nil || !applied.Applied || applied.RestartRequired {
		t.Fatalf("apply: %+v %v", applied, err)
	}
	check, err := run[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	if err != nil || !check.OK {
		t.Fatalf("check: %+v %v", check, err)
	}

	// A full backup, then more changes.
	b1, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if err != nil || b1.RepoSizeBytes == 0 || b1.Type != protocol.BackupFull {
		t.Fatalf("backup: %+v %v", b1, err)
	}
	insert(orders, 1000, 1200)
	mark, err := run[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-cleanup"})
	if err != nil || !mark.Archived || mark.LSN == "" {
		t.Fatalf("mark: %+v %v", mark, err)
	}
	time.Sleep(1100 * time.Millisecond)
	t1 := time.Now().UTC().Truncate(time.Second)
	time.Sleep(1100 * time.Millisecond)
	// The accident: deleted orders, a changed one, a dropped collection.
	if _, err := orders.DeleteMany(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$gte", Value: 100}, {Key: "$lt", Value: 130}}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := orders.UpdateOne(ctx, bson.D{{Key: "_id", Value: 5}}, bson.D{{Key: "$set", Value: bson.D{{Key: "total", Value: -1}}}}); err != nil {
		t.Fatal(err)
	}
	if err := notes.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	insert(orders, 5000, 5003) // added since

	// Archiver stats.
	as, err := e.Archiver(ctx, env, db)
	if err != nil || as.ArchivedCount == 0 || as.ArchiveMode != "on" || as.LastArchivedTime == nil {
		t.Fatalf("archiver: %+v %v", as, err)
	}

	// Proof: restore everything to the newest change and check.
	dr, err := run[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if err != nil || !dr.Passed {
		t.Fatalf("drill: %+v %v", dr, err)
	}
	if left, _ := os.ReadDir(drillRoot(env)); len(left) != 0 {
		t.Fatalf("drill left %d entries", len(left))
	}

	// Guard: a migration preview on a copy; production is untouched.
	pv, err := run[protocol.PreviewResult](t, e, env, db, protocol.TaskPreviewMigration, protocol.PreviewParams{PreviewID: "p1", DB: "shop",
		SQL: "// archive old orders\n" +
			"db.orders.updateMany({ total: { $lt: 500 } }, { $set: { archived: true } });\n" +
			"db.orders.createIndex({ archived: 1, total: -1 })\n" +
			"db.orders.find({})\n" +
			"db.createCollection('events')\n" +
			"db.events.insertMany([{ a: 1 }, { a: 2 }])\n" +
			"db.orders.deleteMany({})\n" +
			"db.events.insertOne({ _id: ObjectId('64b7f0000000000000000000') })\n" +
			"db.events.insertOne({ _id: ObjectId('64b7f0000000000000000000') })\n"})
	if err != nil {
		t.Fatal("preview:", err)
	}
	t.Logf("preview: %s", pv.Summary)
	if pv.Verdict != protocol.PreviewFailed || pv.Error == nil || pv.Error.Statement != 8 || pv.Error.Code != "11000" {
		t.Fatalf("preview: %+v %+v", pv, pv.Error)
	}
	if s := pv.Statements[0]; s.Rows == nil || *s.Rows != 50 {
		t.Errorf("updateMany: %+v", s)
	}
	if s := pv.Statements[1]; len(s.IndexBuilds) != 1 || s.IndexBuilds[0].Name != "shop.orders.archived_1_total_-1" {
		t.Errorf("createIndex: %+v", s)
	}
	if s := pv.Statements[2]; s.Ran {
		t.Errorf("find ran: %+v", s)
	}
	if s := pv.Statements[5]; s.Rows == nil || *s.Rows < 1000 {
		t.Errorf("deleteMany: %+v", s)
	}
	if !slices.ContainsFunc(pv.Findings, func(f protocol.PreviewFinding) bool { return f.Rule == "delete_all" }) {
		t.Errorf("findings: %+v", pv.Findings)
	}
	if n, _ := orders.CountDocuments(ctx, bson.D{{Key: "archived", Value: true}}); n != 0 {
		t.Fatalf("the preview changed production: %d archived", n)
	}
	if bad, err := run[protocol.PreviewResult](t, e, env, db, protocol.TaskPreviewMigration, protocol.PreviewParams{PreviewID: "p2",
		SQL: "for (const d of db.orders.find()) { db.orders.updateOne({_id: d._id}, {$set: {x: 1}}) }"}); err != nil || bad.Verdict != protocol.PreviewFailed || bad.RestoreMs != 0 {
		t.Fatalf("unsupported script: %+v %v", bad, err)
	}
	if left, _ := os.ReadDir(drillRoot(env)); len(left) != 0 {
		t.Fatalf("preview left %d entries", len(left))
	}
	safeCopyIntegration(t, e, env, db)

	// Rewind: a copy at t1 (before the accident).
	cp, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "copy1", Target: protocol.RewindTarget{Time: &t1}})
	if err != nil {
		t.Fatal("copy:", err)
	}
	t.Log(cp.Summary)
	if states := e.RewindStates(env); len(states) != 1 || states[0].Status != protocol.RewindCopyReady {
		t.Fatalf("states: %+v", states)
	}
	cmp, err := run[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "copy1"})
	if err != nil {
		t.Fatal("compare:", err)
	}
	t.Log(cmp.Summary)
	got := map[string]protocol.RewindTableDiff{}
	for _, d := range cmp.Tables {
		got[d.Table] = d
	}
	if d := got["orders"]; d.MissingInProduction != 30 || d.Changed != 1 || d.OnlyInProduction != 3 {
		t.Fatalf("orders diff: %+v", d)
	}
	if d := got["notes"]; d.MissingInProduction != 50 || d.Note == "" {
		t.Fatalf("notes diff: %+v", d)
	}
	rows, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "copy1",
		Tables: []protocol.RewindTable{{DB: "shop", Table: "orders"}, {DB: "shop", Table: "notes"}}})
	if err != nil {
		t.Fatal("rows:", err)
	}
	t.Log(rows.Summary)
	if n, _ := orders.CountDocuments(ctx, bson.D{}); n != 1203 {
		t.Fatalf("orders after bringing back: %d", n)
	}
	var o5 bson.M
	_ = orders.FindOne(ctx, bson.D{{Key: "_id", Value: 5}}).Decode(&o5)
	if toInt(o5["total"]) != -1 {
		t.Fatalf("a changed document was overwritten without include_changed: %v", o5)
	}
	if n, _ := notes.CountDocuments(ctx, bson.D{}); n != 50 {
		t.Fatalf("notes brought back: %d", n)
	}
	if ix, _ := indexNames(ctx, notes); len(ix) != 2 {
		t.Fatalf("notes indexes: %v", ix)
	}
	// Again, with changed ones: idempotent, and the changed order goes back.
	rows2, err := run[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "copy1",
		Tables: []protocol.RewindTable{{DB: "shop", Table: "orders"}}, IncludeChanged: true})
	if err != nil || rows2.Tables[0].Inserted != 0 || rows2.Tables[0].Updated != 1 {
		t.Fatalf("rows again: %+v %v", rows2, err)
	}
	drop, err := run[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "copy1"})
	if err != nil || !drop.Removed {
		t.Fatalf("drop: %+v %v", drop, err)
	}

	// A copy at the Mark: 1200 orders, notes present.
	cp2, err := run[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "copy2", Target: protocol.RewindTarget{Mark: "before-cleanup"}})
	if err != nil {
		t.Fatal("copy at mark:", err)
	}
	cc, err := connect(ctx, socketURI(filepath.Join(cp2.SocketDir, "mongodb-27017.sock")))
	if err != nil {
		t.Fatal(err)
	}
	n, _ := cc.Database("shop").Collection("orders").CountDocuments(ctx, bson.D{})
	disconnect(cc)
	if n != 1200 {
		t.Fatalf("copy at the Mark has %d orders, want 1200", n)
	}
	if _, err := run[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "copy2"}); err != nil {
		t.Fatal(err)
	}

	// Monitoring.
	if _, err := e.Monitor(ctx, env, db); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	dm, _ := e.Monitor(ctx, env, db)
	if dm.Error != "" || dm.Metrics["connections_total"] == 0 || dm.Metrics["mongodb_oplog_window_hours"] <= 0 {
		t.Fatalf("monitoring: %+v", dm)
	}

	// Stopping a long operation (Apply fix).
	opDone := make(chan error, 1)
	go func() {
		_, err := admin.Database("shop").Collection("orders").Find(ctx,
			bson.D{{Key: "$where", Value: "sleep(100) || true"}})
		opDone <- err
	}()
	var victim *protocol.ActivityQuery
	for range 60 {
		act, _ := longOps(ctx, c, true, nil)
		for _, q := range act.Queries {
			if strings.Contains(q.Query, "sleep") {
				victim = &q
			}
		}
		if victim != nil {
			break
		}
		// Operations show in Activity after a minute; look at every op.
		var res struct {
			Inprog []bson.M `bson:"inprog"`
		}
		_ = c.Database("admin").RunCommand(ctx, bson.D{{Key: "currentOp", Value: 1}, {Key: "active", Value: true}}).Decode(&res)
		for _, op := range res.Inprog {
			if b, _ := json.Marshal(op["command"]); strings.Contains(string(b), "sleep") && clientOp(op) {
				secs := toFloat(op["microsecs_running"]) / 1e6
				start := time.Now().Add(-time.Duration(secs * float64(time.Second)))
				victim = &protocol.ActivityQuery{PID: toInt(op["opid"]), BackendStart: &start}
			}
		}
		if victim != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if victim == nil {
		t.Fatal("the long operation never showed up")
	}
	mr, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance,
		protocol.MaintenanceParams{Action: protocol.MaintKillOp, PID: victim.PID, BackendStart: victim.BackendStart})
	if err != nil {
		t.Fatalf("kill op: %v", err)
	}
	t.Log(mr.Summary)
	select {
	case err := <-opDone:
		if err == nil {
			t.Fatal("the operation wasn't stopped")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the operation is still running")
	}

	// A second backup: retention 1 removes the first and its chunks.
	b2, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range srv.Keys() {
		if strings.Contains(k, "/backup/"+b1.Label+"/") {
			t.Fatalf("backup %s kept after retention", b1.Label)
		}
	}
	if !strings.Contains(strings.Join(srv.Keys(), " "), "/backup/"+b2.Label+"/backup.json") {
		t.Fatal("second backup missing")
	}
	// Nothing readable in the bucket.
	for _, k := range srv.Keys() {
		b, _ := srv.Object(k)
		if strings.Contains(string(b), "example.com") {
			t.Fatalf("%s holds plaintext", k)
		}
	}
	// Discovery sees the server.
	found, err := e.Discover(ctx, env)
	if err != nil || len(found) == 0 || found[0].Port != port || found[0].Version == "" {
		t.Fatalf("discover: %+v %v", found, err)
	}
}

// safeCopyIntegration makes a masked safe copy, signs in over TLS with the
// password made here, sets a new one and deletes it.
func safeCopyIntegration(t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec) {
	t.Helper()
	ctx := context.Background()
	env.Config.Copies = agent.CopiesConfig{Dir: filepath.Join(env.Config.StateDir, "copies"), PortMin: 55440, PortMax: 55460}
	env.Copies = agent.NewCopyTools(env.Config)
	sr, err := run[protocol.CopySchemaResult](t, e, env, db, protocol.TaskCopySchema, nil)
	if err != nil || !slices.ContainsFunc(sr.Databases, func(d protocol.SchemaDatabase) bool {
		return d.Name == "shop" && slices.ContainsFunc(d.Tables, func(t protocol.SchemaTable) bool {
			return t.Name == "orders" && slices.ContainsFunc(t.Columns, func(c protocol.SchemaColumn) bool { return c.Name == "email" && c.Type == "string" })
		})
	}) {
		t.Fatalf("copy_schema: %+v %v", sr, err)
	}
	pw, verifier, _ := rsclient.NewCopyPasswordFor(protocol.EngineMongoDB)
	sc, err := run[protocol.SafeCopyResult](t, e, env, db, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc1",
		Masking: protocol.MaskingPlan{Mode: protocol.MaskingRules},
		Access:  protocol.CopyAccess{Listen: "*", AllowFrom: []string{"127.0.0.1"}, Role: "dev_ana", PasswordVerifier: verifier}})
	if err != nil {
		t.Fatal("safe copy:", err)
	}
	t.Logf("safe copy: %s", sc.Summary)
	login := func(user, pass string) (*mongo.Client, error) {
		return connect(ctx, fmt.Sprintf("mongodb://%s:%s@127.0.0.1:%d/?authSource=admin&tls=true&tlsInsecure=true&directConnection=true", user, pass, sc.Port))
	}
	c, err := login("dev_ana", pw)
	if err != nil {
		t.Fatal("signing in to the safe copy:", err)
	}
	var doc struct {
		Email string `bson:"email"`
	}
	if err := c.Database("shop").Collection("orders").FindOne(ctx, bson.D{{Key: "_id", Value: 5}}).Decode(&doc); err != nil || doc.Email == "" || doc.Email == "u5@example.com" {
		t.Fatalf("not masked: %q %v", doc.Email, err)
	}
	if _, err := c.Database("shop").Collection("orders").InsertOne(ctx, bson.D{{Key: "_id", Value: 999999}}); err != nil {
		t.Errorf("the copy should be writable: %v", err)
	}
	disconnect(c)
	if c, err := login("dev_ana", "wrong"); err == nil {
		disconnect(c)
		t.Error("a wrong password signed in")
	}
	if c, err := connect(ctx, fmt.Sprintf("mongodb://127.0.0.1:%d/?directConnection=true", sc.Port)); err == nil {
		disconnect(c)
		t.Error("the copy answered without TLS")
	}
	pw2, v2, _ := rsclient.NewCopyPasswordFor(protocol.EngineMongoDB)
	if !e.SetCopyPassword(ctx, env, protocol.CopyPassword{ID: "sc1", Version: 2, Verifier: v2}) {
		t.Fatal("SetCopyPassword: not the engine's")
	}
	if c, err := login("dev_ana", pw2); err != nil {
		t.Fatal("new password:", err)
	} else {
		disconnect(c)
	}
	if states := e.CopyStates(env); len(states) != 1 || states[0].PasswordVersion != 2 {
		t.Fatalf("states: %+v", states)
	}
	if !e.DropCopy(ctx, env, "sc1") || len(e.CopyStates(env)) != 0 {
		t.Fatal("drop")
	}
}
