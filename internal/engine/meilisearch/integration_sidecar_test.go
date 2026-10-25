//go:build meilisearch_integration

// The Docker sidecar against a real Meilisearch in another container: the
// test runs in the agent's own image (the program for Proof and copies is
// the image's), reaches "production" at ROWSAFE_TEST_MEILISEARCH_URL on a
// compose-like network and reads its snapshots from a shared volume
// (scripts/test-meilisearch.sh sets it up).
package meilisearch

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestSidecarIntegration(t *testing.T) {
	base, master := os.Getenv("ROWSAFE_TEST_MEILISEARCH_URL"), os.Getenv("ROWSAFE_TEST_MEILISEARCH_MASTER")
	if base == "" || master == "" {
		t.Skip("ROWSAFE_TEST_MEILISEARCH_URL and ROWSAFE_TEST_MEILISEARCH_MASTER are not set")
	}
	t.Setenv("ROWSAFE_MODE", "docker-sidecar")
	t.Setenv(urlEnv, base)
	ctx := context.Background()
	u, err := sidecarURL()
	if err != nil {
		t.Fatal(err)
	}
	admin, err := newRemoteClient(u, master)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.close()

	dir := t.TempDir()
	srv := fakes3.New("bkt")
	defer srv.Close()
	env := agent.EngineEnv{
		Config: agent.Config{Mode: agent.ModeDockerSidecar, StateDir: dir, DrillDir: filepath.Join(dir, "drills"),
			RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "meilisearch"), MainStateDir: filepath.Join(dir, "engines", "meilisearch"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"},
		Log:   slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Notes: os.Stderr,
	}
	e := &Engine{}
	db := protocol.DatabaseSpec{ID: "db_meili", Name: "search", Stanza: "search", Port: protocol.MeilisearchPort, RetentionFull: 7,
		Engine: protocol.EngineMeilisearch}

	// The login inside the agent's container: only the master key, the
	// rest from the image and the compose file.
	if _, err := Login(ctx, env, LoginOptions{Port: db.Port}, master); err != nil {
		t.Fatal(err)
	}
	s, err := loadServer(env, db.Port)
	if err != nil || s.URL != u.String() || s.Binary != os.Getenv(binEnv) || s.SnapshotDir != os.Getenv(snapDirEnv) || s.Unit != "" {
		t.Fatalf("saved %+v %v", s, err)
	}
	if st := ServerStatus(ctx, env, db.Port); !st.Answers || st.Login != "ok" {
		t.Fatalf("status %+v", st)
	}

	addDocs(t, admin, "movies", 0, 50)
	addDocs(t, admin, "books", 0, 7)
	if found, err := e.Discover(ctx, env); err != nil || len(found) != 1 || len(found[0].Databases) != 2 {
		t.Fatalf("discover %+v %v", found, err)
	}
	if ad := mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); !ad.Applied {
		t.Fatalf("adopt %+v", ad)
	}
	b := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if b.Label == "" || b.RepoSizeBytes == 0 {
		t.Fatalf("backup %+v", b)
	}
	mk := mustRun[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-delete"})
	if !mk.Archived {
		t.Fatalf("mark %+v", mk)
	}
	if drill := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil); !drill.Passed || len(drill.Databases) != 2 {
		t.Fatalf("drill %+v", drill)
	}

	// A mistake, a copy, documents brought back.
	deleteDocs(t, admin, "movies", 1, 2, 3, 4, 5)
	cp := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy,
		protocol.RewindCopyParams{CopyID: "c1", Target: protocol.RewindTarget{Mark: "before-delete"}, Expires: time.Now().Add(time.Hour)})
	if cp.Port == 0 {
		t.Fatalf("copy %+v", cp)
	}
	rows := mustRun[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows,
		protocol.RewindRowsParams{CopyID: "c1", Tables: []protocol.RewindTable{{Table: "movies"}}})
	if len(rows.Tables) != 1 || rows.Tables[0].Inserted != 5 || count(t, admin, "movies") != 50 {
		t.Fatalf("rows %+v", rows)
	}
	mustRun[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"})

	// Rewind in place: the temporary Meilisearch in this container exports
	// into production's container (the only address it may reach).
	deleteDocs(t, admin, "movies", 20, 21, 22)
	addDocs(t, admin, "extra", 0, 3)
	if ip := mustRun[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace,
		protocol.RewindInPlaceParams{RewindID: "rw1", Target: protocol.RewindTarget{Mark: "before-delete"}, KeepDays: 7}); ip.KeptUntil == nil ||
		count(t, admin, "movies") != 50 || count(t, admin, "extra") != -1 {
		t.Fatalf("in place: movies %d extra %d", count(t, admin, "movies"), count(t, admin, "extra"))
	}
	mustRun[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "rw1"})
	if count(t, admin, "movies") != 47 || count(t, admin, "extra") != 3 {
		t.Fatalf("undo: movies %d extra %d", count(t, admin, "movies"), count(t, admin, "extra"))
	}
	mustRun[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rw1"})

	// Databases & users: apps on the compose network reach it by name.
	da := mustRunID[protocol.DBAdminResult](t, e, env, db, "task_inv", protocol.TaskDBAdmin, protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: "new-index"})
	if da.Inventory == nil || da.Inventory.SuggestedHost != u.Hostname() {
		t.Fatalf("inventory %+v", da.Inventory)
	}

	// Pulse and security.
	if dm, err := e.Monitor(ctx, env, db); err != nil || dm.Error != "" || dm.Meilisearch == nil {
		t.Fatalf("monitor %+v %v", dm, err)
	}
	rep, err := e.SecurityReport(ctx, env, db)
	if err != nil || rep.EngineSecurity.AuthDisabled || !strings.Contains(strings.Join(rep.Notes, " "), "Docker") {
		t.Fatalf("security %+v %v", rep, err)
	}
	// Nothing to update from here: Rowsafe never changes Meilisearch's image.
	if _, ok := e.Software(ctx, env, db); ok {
		t.Error("a sidecar reported an update")
	}
}
