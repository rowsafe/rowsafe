//go:build mongodb_integration

package mongodb

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestMongoDBUpgradeRehearsal rehearses an upgrade with the installed
// mongod standing in for the target version, and checks the issues.
func TestMongoDBUpgradeRehearsal(t *testing.T) {
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
		t.Fatal(err)
	}
	db := protocol.DatabaseSpec{ID: "db_mup", Name: "up", Stanza: "up-mongo", Port: port, RetentionFull: 1, Engine: protocol.EngineMongoDB}
	adminLogin := Login{}
	if u := os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN"); u != "" {
		adminLogin = Login{User: u, Password: os.Getenv("ROWSAFE_TEST_MONGODB_ADMIN_PASSWORD")}
	}
	admin, err := connect(ctx, strings.Replace(adminLogin.uri(port), "?", "?appName=rowsafe-test&", 1))
	if err != nil {
		t.Fatal(err)
	}
	defer disconnect(admin)
	_ = admin.Database("upg").Drop(ctx)
	if _, err := admin.Database("upg").Collection("c").InsertMany(ctx, []any{bson.D{{Key: "_id", Value: 1}}, bson.D{{Key: "_id", Value: 2}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	in, err := inspect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	series := strings.Join(strings.SplitN(in.Version, ".", 3)[:2], ".")
	issues, _, err := e.UpgradeIssues(ctx, env, db, series, "99.0")
	if err != nil || len(issues) != 1 || !strings.Contains(issues[0], "one major version at a time") {
		t.Fatalf("issues %v %v", issues, err)
	}
	if issues, _, err := e.UpgradeIssues(ctx, env, db, series, nextMajor(series)); err != nil || len(issues) != 0 {
		t.Fatalf("issues for the next major %v %v", issues, err)
	}
	mongod, err := exec.LookPath("mongod")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755)
	if out, err := exec.Command("cp", mongod, filepath.Join(root, "usr", "bin", "mongod")).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	res := &protocol.UpgradeRehearsalResult{}
	if err := e.RehearseUpgrade(ctx, env, db, root, series, res, &testLog{t: t}); err != nil || !res.Passed || res.ToVersion == "" {
		t.Fatalf("rehearsal: %v %+v", err, res)
	}
	if err := e.AfterUpgrade(ctx, env, db, series, &testLog{t: t}); err != nil {
		t.Fatalf("after upgrade: %v", err)
	}
}
