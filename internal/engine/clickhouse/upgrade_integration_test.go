//go:build clickhouse_integration

package clickhouse

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestClickHouseUpgradeRehearsal rehearses an upgrade with the installed
// program standing in for the target version.
func TestClickHouseUpgradeRehearsal(t *testing.T) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_CLICKHOUSE_PORT"))
	if port == 0 || os.Getenv("ROWSAFE_TEST_CLICKHOUSE_USERSD") != "" {
		t.Skip("ROWSAFE_TEST_CLICKHOUSE_PORT not set, or a users.d login")
	}
	ctx := context.Background()
	env, _ := testEnv(t)
	e := &Engine{}
	adminUser, adminPass := os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN"), os.Getenv("ROWSAFE_TEST_CLICKHOUSE_ADMIN_PASSWORD")
	admin := newClient(serverURL(port), Login{User: cmpOr(adminUser, "default"), Password: adminPass})
	admin.ua = "rowsafe-test"
	if err := CreateLogin(ctx, env, port, adminUser, adminPass); err != nil {
		t.Fatal(err)
	}
	db := protocol.DatabaseSpec{ID: "db_chup", Name: "up", Stanza: "up-ch", Port: port, RetentionFull: 2, Engine: protocol.EngineClickHouse}
	must(t, admin, "DROP DATABASE IF EXISTS upg SYNC")
	must(t, admin, "CREATE DATABASE upg")
	must(t, admin, "CREATE TABLE upg.t (x UInt32) ENGINE = MergeTree ORDER BY x")
	must(t, admin, "INSERT INTO upg.t SELECT number FROM numbers(500)")
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	bin, _, err := clickhouseBinary()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755)
	if out, err := exec.Command("cp", bin, filepath.Join(root, "usr", "bin", "clickhouse")).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	res := &protocol.UpgradeRehearsalResult{}
	if err := e.RehearseUpgrade(ctx, env, db, root, "99.3", res, &testLog{t: t}); err != nil || !res.Passed || res.ToVersion == "" {
		t.Fatalf("rehearsal: %v %+v", err, res)
	}
	t.Logf("rehearsal: restore %.1fs, start %.1fs, %d databases", res.RestoreSeconds, res.UpgradeSeconds, len(res.Databases))
}
