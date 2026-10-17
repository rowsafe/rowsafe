//go:build !windows

package local

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestUnreachableMongoDB(t *testing.T) {
	d, err := Open("mongodb://app:s3cret@127.0.0.1:1/shop?serverSelectionTimeoutMS=500")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Health(t.Context(), Options{})
	if err == nil || !strings.Contains(err.Error(), "can't read MongoDB on 127.0.0.1:1 as app") || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("unreachable: %v", err)
	}
}

// dockerMongo starts MongoDB (a single-member replica set, as Rowsafe
// sets it up) on a free local port and returns its connection string. It
// skips without Docker or with -short.
func dockerMongo(t *testing.T, image string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: no Docker databases")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("no Docker")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	out, err := exec.Command("docker", "run", "-d", "-p", addr+":27017", image, "--replSet", "rs0", "--bind_ip_all").CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	uri := "mongodb://" + addr + "/?directConnection=true"
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	for {
		c, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(2 * time.Second))
		if err == nil {
			err = c.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetInitiate", Value: bson.D{{Key: "_id", Value: "rs0"},
				{Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: "127.0.0.1:27017"}}}}}}}).Err()
			if err != nil && strings.Contains(err.Error(), "already initialized") {
				err = nil
			}
			if err == nil {
				var hello struct {
					Primary bool `bson:"isWritablePrimary"`
				}
				err = c.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
				if err == nil && !hello.Primary {
					err = fmt.Errorf("not primary yet")
				}
			}
			_ = c.Disconnect(context.Background())
			if err == nil {
				return uri
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("%s didn't start: %v", image, err)
		}
		time.Sleep(time.Second)
	}
}

func TestMongoDBDirect(t *testing.T) {
	uri := dockerMongo(t, "mongo:8.0")
	ctx := t.Context()
	c, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(context.Background())
	orders := c.Database("shop").Collection("orders")
	docs := make([]any, 0, 2000)
	for i := range 2000 {
		docs = append(docs, bson.D{{Key: "n", Value: i}, {Key: "a", Value: i % 7}, {Key: "b", Value: i % 11}})
	}
	if _, err := orders.InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	if _, err := orders.Indexes().CreateMany(ctx, []mongo.IndexModel{{Keys: bson.D{{Key: "a", Value: 1}}}, {Keys: bson.D{{Key: "a", Value: 1}, {Key: "b", Value: 1}}}}); err != nil {
		t.Fatal(err)
	}

	d, err := Open(uri)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Local() || d.Engine() != protocol.EngineMongoDB {
		t.Fatalf("local %v engine %s", d.Local(), d.Engine())
	}
	s, err := d.Check(ctx)
	if err != nil || !strings.HasPrefix(s.Version, "8.0") {
		t.Fatalf("check %+v %v", s, err)
	}
	h, err := d.Health(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(h)
	if !slices.Contains(got, "mongodb_profiler_off") || !slices.Contains(got, "duplicate_indexes") {
		t.Fatalf("findings %v", got)
	}
	for _, c := range h.Checks {
		if c.Category == "replication" && c.Status != "ok" {
			t.Errorf("oplog %+v", c)
		}
	}
	ins, err := d.Insights(ctx)
	if err != nil || len(ins.LargestTables) == 0 || ins.LargestTables[0].Table != "orders" {
		t.Fatalf("insights %+v %v", ins, err)
	}
	ov, err := d.Settings(ctx, Options{})
	if err != nil || !ov.Available || ov.CanChange || !strings.Contains(ov.ChangeReason, "mongod.conf") {
		t.Errorf("settings %+v %v", ov, err)
	}
	if st, err := d.Statements(ctx); err != nil || len(st.Statements) != 0 {
		t.Errorf("statements %+v %v", st, err)
	}

	// Turn the profiler on, then drop the redundant index.
	res, err := d.ApplyFix(ctx, "mongodb_profiler_off", "profile", Options{})
	if err != nil || !strings.Contains(res.Summary, "shop") {
		t.Fatalf("profile: %+v %v", res, err)
	}
	res, err = d.ApplyFix(ctx, "duplicate_indexes", "drop:shop.orders.a_1", Options{})
	if err != nil || !strings.Contains(res.Summary, "Dropped the index a_1") {
		t.Fatalf("drop: %+v %v", res, err)
	}
	h, err = d.Health(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(h); slices.Contains(got, "mongodb_profiler_off") || slices.Contains(got, "duplicate_indexes") {
		t.Errorf("after the fixes: %v", got)
	}

	// A slow operation, seen and stopped.
	go func() {
		_, _ = orders.Find(context.Background(), bson.D{{Key: "$where", Value: "sleep(100) || false"}})
	}()
	var op protocol.ActivityQuery
	for deadline := time.Now().Add(2 * time.Minute); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		a, err := d.Activity(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(a.Queries) > 0 {
			op = a.Queries[0]
			break
		}
	}
	if op.PID == 0 || op.BackendStart == nil || !strings.Contains(op.Query, "$where") {
		t.Fatalf("no long operation: %+v", op)
	}
	params, _ := json.Marshal(protocol.MaintenanceParams{Action: protocol.MaintKillOp, PID: op.PID, BackendStart: op.BackendStart})
	res, err = d.Apply(ctx, protocol.FindingFix{Kind: protocol.FixMaintenance, Available: true,
		Params: params})
	if err != nil || !strings.Contains(res.Summary, "Stopped the operation") {
		t.Errorf("kill: %+v %v", res, err)
	}
}
