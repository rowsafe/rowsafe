//go:build mongodb_integration

package mongodb

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestMongoDBStandby makes the second (empty) server a member of the first
// one's replica set, fences the first and promotes the second
// (MONGO_CLONE=1; runs last: it changes the second server). Root's helper
// is played by the test (it runs as root in the container): it writes the
// key file and restarts the second mongod with the set's options.
func TestMongoDBStandby(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_PORT"))
	port2, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_MONGODB_CLONE_PORT"))
	if port == 0 || port2 == 0 || os.Getuid() != 0 {
		t.Skip("ROWSAFE_TEST_MONGODB_PORT and ROWSAFE_TEST_MONGODB_CLONE_PORT not set (or not root)")
	}
	ctx := context.Background()
	envA, _ := testEnv(t)
	envB, _ := testEnv(t)
	envA.Config.RestartDir, envB.Config.RestartDir = t.TempDir(), t.TempDir()
	adminUser, adminPW := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"), os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")
	auth := adminUser != ""
	e := &Engine{}
	if _, err := CreateLoginRoles(ctx, envA, port, adminUser, adminPW, false, true); err != nil {
		t.Fatal("login:", err)
	}
	if _, err := CreateLoginRoles(ctx, envB, port2, adminUser, adminPW, false, false); err != nil {
		t.Fatal("login 2:", err)
	}
	var ip string
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			ip = n.IP.String()
		}
	}
	// Root's helper, as the test.
	var setName, keyPath string
	can := func(string, int) bool { return true }
	envA.HelperCan, envB.HelperCan = can, can
	envA.Helper = func(ctx context.Context, action string, args ...string) (map[string]string, error) {
		if action != helperKeyExport {
			return nil, fmt.Errorf("unexpected %s", action)
		}
		data, err := os.ReadFile("/tmp/keyfile")
		if err != nil {
			return nil, err
		}
		return map[string]string{"ok": "1"}, os.WriteFile(filepath.Join(envA.Config.RestartDir, "mongodb-key-out"), data, 0o600)
	}
	var bindAddr string
	envB.Helper = func(ctx context.Context, action string, args ...string) (map[string]string, error) {
		switch action {
		case helperStandbyConfig:
			setName, bindAddr = args[1], args[3]
			if args[2] == "key" {
				data, err := os.ReadFile(filepath.Join(envB.Config.RestartDir, "mongodb-key-in"))
				if err != nil {
					return nil, err
				}
				keyPath = "/tmp/keyfile2"
				_ = os.Remove(keyPath)
				if err := os.WriteFile(keyPath, data, 0o400); err != nil {
					return nil, err
				}
			}
			return map[string]string{"ok": "1"}, nil
		case "restart":
			_ = exec.Command("mongod", "--shutdown", "--dbpath", "/data/c").Run()
			cmdArgs := []string{"--dbpath", "/data/c", "--port", strconv.Itoa(port2), "--bind_ip", "127.0.0.1," + bindAddr, "--fork",
				"--logpath", "/tmp/m2.log", "--replSet", setName}
			if keyPath != "" {
				cmdArgs = append(cmdArgs, "--keyFile", keyPath)
			} else if auth {
				cmdArgs = append(cmdArgs, "--auth")
			}
			out, err := exec.Command("mongod", cmdArgs...).CombinedOutput()
			if err != nil {
				return nil, fmt.Errorf("mongod: %v: %s", err, out)
			}
			return map[string]string{"ok": "1"}, nil
		}
		return nil, fmt.Errorf("unexpected %s", action)
	}

	adminLogin := Login{}
	if auth {
		adminLogin = Login{User: adminUser, Password: adminPW}
	}
	src, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(src)
	_ = src.Database("sbdb").Drop(ctx)
	var docs []any
	for i := 0; i < 300; i++ {
		docs = append(docs, bson.D{{Key: "_id", Value: i}})
	}
	if _, err := src.Database("sbdb").Collection("items").InsertMany(ctx, docs); err != nil {
		t.Fatal(err)
	}
	specA := protocol.DatabaseSpec{ID: "db_mongo_sb", Name: "shop", Port: port, Engine: protocol.EngineMongoDB}
	specB := protocol.DatabaseSpec{ID: "db_mongo_sb", Name: "shop", Port: port2, Engine: protocol.EngineMongoDB}
	tl := &testLog{t: t}
	sec := protocol.StandbySecrets{PrimaryPort: port, PrimaryAddresses: []string{ip}}
	var prep protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, envA, specA, protocol.StandbyPrepareParams{StandbyID: "sb1", StandbyAddresses: []string{ip}, Stream: true},
		&sec, &prep, tl); err != nil {
		t.Fatal("prepare:", err)
	}
	if _, err := e.StandbyCreate(ctx, envB, specB, protocol.StandbyCreateParams{StandbyID: "sb1", Port: port2, Major: prep.Major}, sec, tl); err == nil ||
		!strings.Contains(err.Error(), "restart") {
		t.Fatalf("create without the confirmed restart: %v", err)
	}
	cres, err := e.StandbyCreate(ctx, envB, specB, protocol.StandbyCreateParams{StandbyID: "sb1", Port: port2, Major: prep.Major,
		SystemID: prep.SystemID, RestartOK: true}, sec, tl)
	if err != nil {
		t.Fatal("create:", err)
	}
	t.Logf("create: %s", cres.Summary)
	if _, err := src.Database("sbdb").Collection("items").InsertOne(ctx, bson.D{{Key: "_id", Value: 300}}); err != nil {
		t.Fatal(err)
	}
	sbLogin, _ := loadLogin(envB, port2)
	sbc, err := connect(ctx, sbLogin.uri(port2))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(sbc)
	coll := sbc.Database("sbdb").Collection("items")
	var n int64
	for i := 0; i < 30; i++ {
		n, _ = coll.CountDocuments(ctx, bson.D{})
		if n == 301 {
			break
		}
		time.Sleep(time.Second)
	}
	if n != 301 {
		t.Fatalf("the standby has %d items", n)
	}
	states := e.StandbyStates(ctx, envB)
	if len(states) != 1 || !states[0].InRecovery || states[0].ReplayLSN == "" || states[0].Error != "" {
		t.Fatalf("states: %+v", states)
	}
	if ps, ok := e.PrimaryState(ctx, envA, specA); !ok || ps.WALLSN == "" {
		t.Fatalf("primary state: %+v", ps)
	}

	// Fence the primary, promote the standby.
	fres, err := e.StandbyFence(ctx, envA, specA, protocol.StandbyFenceParams{FenceID: "f1", StandbyID: "sb1", SystemID: prep.SystemID}, tl)
	if err != nil || fres.CheckpointLSN == "" {
		t.Fatalf("fence: %+v %v", fres, err)
	}
	if _, err := src.Database("sbdb").Collection("items").InsertOne(ctx, bson.D{{Key: "_id", Value: 999}}); err == nil {
		t.Fatal("the fenced primary took a write")
	}
	if enforced, other, err := e.HoldFence(ctx, envA, protocol.Fence{ID: "f1", Port: port, SystemID: prep.SystemID}); enforced || other || err != nil {
		t.Fatalf("hold: %v %v %v", enforced, other, err)
	}
	pres, err := e.StandbyPromote(ctx, envB, specB, protocol.StandbyPromoteParams{StandbyID: "sb1", WaitForLSN: fres.CheckpointLSN}, tl)
	if err != nil || !pres.Promoted || !pres.CaughtUp {
		t.Fatalf("promote: %+v %v", pres, err)
	}
	if _, err := coll.InsertOne(ctx, bson.D{{Key: "_id", Value: 301}}); err != nil {
		t.Fatalf("the new primary refused a write: %v", err)
	}
	if n, _ := coll.CountDocuments(ctx, bson.D{}); n != 302 {
		t.Fatalf("the new primary has %d items", n)
	}
}
