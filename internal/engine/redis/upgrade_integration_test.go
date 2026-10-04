//go:build redis_integration

package redis

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// TestRedisUpgradeRehearsal rehearses a major upgrade with the installed
// program standing in for the target version (unpacked under a root as the
// agent does with the target's packages, linked by a relative name like
// Debian's redis-server package).
func TestRedisUpgradeRehearsal(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	if inDocker() {
		t.Skip("the rehearsal runs where the server's program is (native installs)")
	}
	seed(t, a)
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	rd(t, a, "SET", "after:backup", "1")
	bin, err := serverBinary(e.name, "")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	name := filepath.Base(bin)
	usrBin := filepath.Join(root, "usr", "bin")
	if err := os.MkdirAll(usrBin, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cp", "-L", bin, filepath.Join(usrBin, "check-rdb")).CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
	if err := os.Symlink("check-rdb", filepath.Join(usrBin, name)); err != nil {
		t.Fatal(err)
	}
	// The test server keeps nothing on disk: the upgrade's restart would
	// empty it, so it is blocked until snapshots are on.
	if issues, _, err := e.UpgradeIssues(ctx, env, db, "7.4", "8.2"); err != nil || len(issues) != 1 || !strings.Contains(issues[0], "keeps nothing on its own disk") {
		t.Fatalf("issues without persistence: %v %v", issues, err)
	}
	rd(t, a, "CONFIG", "SET", "save", "3600 1")
	t.Cleanup(func() { _, _ = a.do(context.Background(), "CONFIG", "SET", "save", "") })
	if issues, warnings, err := e.UpgradeIssues(ctx, env, db, "7.4", "8.2"); err != nil || len(issues) != 0 || len(warnings) == 0 {
		t.Fatalf("issues: %v %v %v", issues, warnings, err)
	}
	res := &protocol.UpgradeRehearsalResult{}
	if err := e.RehearseUpgrade(ctx, env, db, root, "99.9", res, &testLog{t: t}); err != nil || !res.Passed || res.ToVersion == "" {
		t.Fatalf("rehearsal: %v %+v", err, res)
	}
	var db0 protocol.DrillDatabase
	for _, d := range res.Databases {
		if d.Name == "db0" {
			db0 = d
		}
	}
	if db0.RestoredTables < 2305 || db0.RestoredTables != db0.SourceTables {
		t.Fatalf("db0 after the rehearsal: %+v", res.Databases)
	}
	t.Logf("rehearsal: restore %.1fs, start %.1fs, %d logical databases, %s", res.RestoreSeconds, res.UpgradeSeconds, len(res.Databases), res.ToVersion)
	if entries, _ := os.ReadDir(drillRoot(env, e.name)); len(entries) != 0 {
		t.Fatalf("the rehearsal left %d entries behind", len(entries))
	}
}
