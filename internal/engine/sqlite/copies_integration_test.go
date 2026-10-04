package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Safe copies end to end through the engine: a live WAL database with
// backups in the bucket, a masked copy of the newest point (changes made
// after the backup included), a structure-only copy, both as files only
// the agent's user can read, reported in the heartbeat, extended, deleted
// and expired (their files removed); copy_schema for the masking review.
func TestSQLiteSafeCopies(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	env, _ := testEnv(t)
	env.Copies = agent.NewCopyTools(env.Config)
	appDir := t.TempDir()
	if d := os.Getenv("ROWSAFE_TEST_SQLITE_DIR"); d != "" {
		appDir = d // the app's own folder (scripts/test-sqlite.sh)
	}
	path := filepath.Join(appDir, fmt.Sprintf("shop-%d.sqlite3", time.Now().UnixNano()))
	createRichDB(t, path, true, 30)
	db := testSpec(path)
	e := startEngine(t, env)
	if _, err := run[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := run[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Archiver(context.Background(), env, db); err != nil {
		t.Fatal(err)
	}
	addRichUsers(t, path, 31, 45) // after the backup: reach the copy through the change stream

	// copy_schema for the masking review: catalog only.
	sch, err := run[protocol.CopySchemaResult](t, e, env, db, protocol.TaskCopySchema, protocol.CopySchemaParams{})
	if err != nil || len(sch.Databases) != 1 || len(sch.Databases[0].Tables) != 5 {
		t.Fatalf("copy_schema: %+v %v", sch, err)
	}

	// A masked copy.
	exp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	mc, err := run[protocol.SafeCopyResult](t, e, env, db, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc_masked", Expires: exp,
		Masking: protocol.MaskingPlan{Mode: protocol.MaskingRules, Rules: maskRules}})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("masked: %s", mc.Summary)
	if mc.Path == "" || mc.Port != 0 || mc.Role != "" || mc.SchemaOnly || !mc.Expires.Equal(exp) || mc.SizeBytes == 0 || mc.RecoveredTo == nil {
		t.Errorf("result: %+v", mc)
	}
	if filepath.Base(mc.Path) != filepath.Base(path) || !strings.HasPrefix(mc.Path, safeRoot(env)) {
		t.Errorf("path %s", mc.Path)
	}
	checkPrivate(t, mc.Path)
	checkMaskedCopy(t, mc.Path, mc.Masking, 45)

	// A structure-only copy.
	so, err := run[protocol.SafeCopyResult](t, e, env, db, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc_schema", SchemaOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("structure only: %s", so.Summary)
	if !so.SchemaOnly || so.Path == "" || so.Path == mc.Path || so.Masking.Tables < 7 || len(so.Masking.Skipped) != 1 {
		t.Errorf("result: %+v", so)
	}
	if d := so.Expires.Sub(time.Now()); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("default expiry in %s, want 24h", d)
	}
	checkPrivate(t, so.Path)
	checkSchemaOnly(t, path, so.Path, schemaOut{LeftOut: so.Masking.Skipped})

	// The heartbeat reports both; a third copy id is refused when taken.
	states := e.CopyStates(env)
	if len(states) != 2 {
		t.Fatalf("copy states: %+v", states)
	}
	for _, st := range states {
		if st.Status != protocol.CopyReady || st.Kind != protocol.CopyKindSafe || st.DatabaseID != db.ID || st.SizeBytes == 0 || st.Port != 0 || st.Expires == nil {
			t.Errorf("state: %+v", st)
		}
	}
	if _, err := run[protocol.SafeCopyResult](t, e, env, db, protocol.TaskSafeCopy, protocol.SafeCopyParams{CopyID: "sc_schema", SchemaOnly: true}); err == nil {
		t.Error("a copy id in use should be refused")
	}
	if len(e.CopyPorts(env)) != 0 {
		t.Error("a file copy uses no port")
	}
	if !e.SetCopyPassword(context.Background(), env, protocol.CopyPassword{ID: "sc_schema", Version: 2, Verifier: "x"}) ||
		e.SetCopyPassword(context.Background(), env, protocol.CopyPassword{ID: "pg_copy", Version: 2}) {
		t.Error("SetCopyPassword should consume its own copies' instructions only")
	}

	// Extend (clamped to 7 days), expiry, Delete.
	e.SetCopyExpiries(env, []protocol.RewindExpiry{{ID: "sc_schema", Expires: time.Now().Add(30 * 24 * time.Hour)}})
	r, _ := e.safeState(env).get("sc_schema")
	if d := time.Until(r.Expires); d < 6*24*time.Hour || d > 7*24*time.Hour+time.Minute {
		t.Errorf("extended to %s from now, want at most 7 days", d)
	}
	e.expireSafeCopies(env, time.Now().Add(72*time.Hour)) // the masked copy expired, not the extended one
	if _, err := os.Stat(filepath.Dir(mc.Path)); !os.IsNotExist(err) {
		t.Errorf("the expired copy's folder is still there: %v", err)
	}
	if st := e.CopyStates(env); len(st) != 1 || st[0].ID != "sc_schema" {
		t.Errorf("after expiry: %+v", st)
	}
	if !e.DropCopy(context.Background(), env, "sc_schema") || e.DropCopy(context.Background(), env, "nope") {
		t.Error("DropCopy")
	}
	if _, err := os.Stat(filepath.Dir(so.Path)); !os.IsNotExist(err) {
		t.Errorf("the deleted copy's folder is still there: %v", err)
	}
	if st := e.CopyStates(env); len(st) != 0 {
		t.Errorf("after delete: %+v", st)
	}

	// A copy being made when the agent stops is removed at the next start.
	e.safeState(env).put(safeRecord{ID: "sc_half", DatabaseID: db.ID, Dir: filepath.Join(safeRoot(env), "sc_half"), Status: protocol.CopyMasking})
	_ = os.MkdirAll(filepath.Join(safeRoot(env), "sc_half"), 0o700)
	_ = os.MkdirAll(filepath.Join(safeRoot(env), "stray"), 0o700)
	e.recoverSafeCopies(env)
	if entries, _ := os.ReadDir(safeRoot(env)); len(entries) != 0 || len(e.CopyStates(env)) != 0 {
		t.Errorf("after recovery: %v %+v", entries, e.CopyStates(env))
	}
}

// checkPrivate checks a copy file is readable only by the agent's user
// (and root): the file 0600, its folder 0700.
func checkPrivate(t *testing.T, path string) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("%s: mode %v, want 0600", path, fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("%s: folder mode %v %v, want 0700", path, di.Mode().Perm(), err)
	}
}
