//go:build rewind_e2e

package agent

// A real rewind on a real server: scripts/test-rewind.sh builds this test
// (go test -c -tags rewind_e2e) and runs it as postgres in a Debian
// container with systemd, PostgreSQL, pgBackRest, a MinIO repository and
// the root helper installed from this repository. Every step is the agent's
// own code: adopt, restart through the helper, backup, a restore point, a
// copy, compare, bring back rows, a failed rewind in place (rolled back), a
// rewind in place, undo and cleanup.

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestRealRewind(t *testing.T) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	a := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	db := protocol.DatabaseSpec{ID: "db_e2e", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}

	step := func(name string, fn func(tl *taskLog) error) {
		t.Helper()
		start := time.Now()
		tl := &taskLog{}
		err := fn(tl)
		t.Logf("---- %s (%s)\n%s", name, time.Since(start).Round(time.Millisecond), tl.String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	sql := func(dbname, q string, args ...any) {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	query := func(dbname, q string, dest ...any) {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if err := conn.QueryRow(ctx, q).Scan(dest...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	items := func() (n, maxID int64) {
		query("shop", `SELECT count(*), coalesce(max(id), 0) FROM items`, &n, &maxID)
		return n, maxID
	}

	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(in.DataDirectory) // e.g. /var/lib/postgresql/17

	step("adopt", func(tl *taskLog) error {
		res, err := a.adopt(ctx, db, protocol.AdoptParams{Apply: true}, tl)
		if err == nil && !res.RestartRequired {
			t.Log("no restart needed")
		}
		return err
	})
	step("restart through the root helper", func(tl *taskLog) error {
		res, err := a.restart(ctx, db, "e2e_restart", tl)
		if err == nil && res.ArchiveMode != "on" {
			t.Fatalf("archive_mode %q after the restart", res.ArchiveMode)
		}
		return err
	})
	step("check", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	if got := a.helperActions(); strings.Join(got, " ") != "restart stop start" {
		t.Fatalf("helper actions %v", got)
	}

	sql("postgres", `CREATE DATABASE shop`)
	sql("shop", `CREATE TABLE items (id serial PRIMARY KEY, note text NOT NULL, created timestamptz NOT NULL DEFAULT clock_timestamp())`)
	sql("shop", `INSERT INTO items (note) SELECT 'first ' || i FROM generate_series(1, 100) i`)

	var label string
	step("full backup", func(tl *taskLog) error {
		res, err := a.backup(ctx, db, protocol.BackupFull, tl)
		if err == nil {
			label = res.Label
		}
		return err
	})
	sql("shop", `INSERT INTO items (note) SELECT 'second ' || i FROM generate_series(1, 50) i`) // ids 101-150
	time.Sleep(1500 * time.Millisecond)
	var target time.Time
	query("postgres", `SELECT clock_timestamp()`, &target)
	time.Sleep(1500 * time.Millisecond)
	sql("shop", `INSERT INTO items (note) SELECT 'third ' || i FROM generate_series(1, 50) i`) // ids 151-200
	sql("shop", `DELETE FROM items WHERE id <= 10`)                                            // the mistake
	step("restore point (archives the WAL)", func(tl *taskLog) error {
		_, err := a.restorePoint(ctx, db, protocol.RestorePointParams{Name: "after-the-mistake"}, tl)
		return err
	})
	if n, maxID := items(); n != 190 || maxID != 200 {
		t.Fatalf("production before: %d rows, max id %d", n, maxID)
	}

	// ---- a copy at the target, compare, bring rows back ----
	var cp *protocol.RewindCopyResult
	step("restore a copy", func(tl *taskLog) error {
		var err error
		cp, err = a.rewindCopy(ctx, db, protocol.RewindCopyParams{CopyID: "cp_e2e", Target: protocol.RewindTarget{Time: &target, BackupSet: label},
			Expires: time.Now().Add(2 * time.Hour)}, tl)
		return err
	})
	t.Logf("copy: %s", cp.Summary)
	if cp.RecoveredTo == nil || cp.RecoveredTo.After(target) {
		t.Fatalf("copy recovered to %v, target %v", cp.RecoveredTo, target)
	}
	rec, _ := a.rewindState().get("cp_e2e")
	cconn, err := a.copyTarget(rec).Connect(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	var cn, cmax int64
	var archiveMode, listen string
	if err := cconn.QueryRow(ctx, `SELECT count(*), max(id), current_setting('archive_mode'), current_setting('listen_addresses') FROM items`).
		Scan(&cn, &cmax, &archiveMode, &listen); err != nil {
		t.Fatal(err)
	}
	cconn.Close(ctx)
	if cn != 150 || cmax != 150 || archiveMode != "off" || listen != "" {
		t.Fatalf("copy: %d rows, max %d, archive_mode %s, listen_addresses %q", cn, cmax, archiveMode, listen)
	}
	if hb := a.rewindState().states(); len(hb) != 1 || hb[0].Kind != protocol.RewindKindCopy || hb[0].Status != protocol.RewindCopyReady {
		t.Fatalf("heartbeat %+v", hb)
	}
	// The agent restarts (an update, a crash): the copy's PostgreSQL runs in
	// the agent's service and stops with it; the next agent starts it again.
	if out, err := a.runner.Run(ctx, a.cfg.pgBin(in.Major(), "pg_ctl"), "-D", rec.Dir+"/data", "-m", "immediate", "-w", "stop"); err != nil {
		t.Fatalf("stopping the copy: %v: %s", err, out)
	}
	b := New(cfg, a.log)
	b.recoverRewinds(ctx)
	deadline := time.Now().Add(2 * time.Minute)
	for {
		c, err := a.copyTarget(rec).Connect(ctx, "shop")
		if err == nil {
			c.Close(ctx)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the copy didn't come back after the agent restarted: %v", err)
		}
		time.Sleep(time.Second)
	}
	t.Log("the copy is back after an agent restart")

	step("compare", func(tl *taskLog) error {
		res, err := a.rewindCompare(ctx, db, protocol.RewindCompareParams{CopyID: "cp_e2e"}, tl)
		if err != nil {
			return err
		}
		t.Log(res.Summary)
		for _, d := range res.Tables {
			if d.Table == "public.items" && (d.MissingInProduction != 10 || d.Changed != 0 || d.OnlyInProduction != 50) {
				t.Fatalf("items: %+v", d)
			}
		}
		return nil
	})
	step("bring back rows", func(tl *taskLog) error {
		res, err := a.rewindRows(ctx, db, protocol.RewindRowsParams{CopyID: "cp_e2e", Tables: []protocol.RewindTable{{DB: "shop", Table: "items"}}}, tl)
		if err == nil && res.Tables[0].Inserted != 10 {
			t.Fatalf("rows %+v", res)
		}
		return err
	})
	if n, maxID := items(); n != 200 || maxID != 200 {
		t.Fatalf("production after bringing rows back: %d rows, max id %d", n, maxID)
	}

	// ---- a rewind in place that fails is rolled back ----
	// A Mark that isn't in the WAL: recovery ends before reaching it, so
	// PostgreSQL refuses to start on the restored data.
	tl := &taskLog{}
	_, err = a.rewindInPlace(ctx, db, protocol.RewindInPlaceParams{RewindID: "rw_fail",
		Target: protocol.RewindTarget{Mark: "no-such-mark", BackupSet: label}, KeepDays: 7}, tl)
	t.Logf("---- rewind to a Mark that doesn't exist (must fail and roll back)\n%s", tl.String())
	if err == nil || !strings.Contains(err.Error(), "put the original data back") {
		t.Fatalf("rewind before the backup: %v", err)
	}
	if n, maxID := items(); n != 200 || maxID != 200 {
		t.Fatalf("production after the rollback: %d rows, max id %d", n, maxID)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("left behind next to the data directory: %v", entries)
	}

	// ---- rewind in place ----
	var rw *protocol.RewindInPlaceResult
	step("rewind in place", func(tl *taskLog) error {
		var err error
		rw, err = a.rewindInPlace(ctx, db, protocol.RewindInPlaceParams{RewindID: "rw_e2e",
			Target: protocol.RewindTarget{Time: &target, BackupSet: label}, KeepDays: 7}, tl)
		return err
	})
	t.Log(rw.Summary)
	if n, maxID := items(); n != 150 || maxID != 150 {
		t.Fatalf("production after the rewind: %d rows, max id %d (want the 150 rows from before the target)", n, maxID)
	}
	var inRecovery bool
	var timeline int
	var archiveCommand string
	query("postgres", `SELECT pg_is_in_recovery(), (SELECT timeline_id FROM pg_control_checkpoint()), current_setting('archive_command')`,
		&inRecovery, &timeline, &archiveCommand)
	if inRecovery || timeline < 2 || !strings.Contains(archiveCommand, "pgbackrest") {
		t.Fatalf("after the rewind: in recovery %v, timeline %d, archive_command %q", inRecovery, timeline, archiveCommand)
	}
	step("check after the rewind (WAL of the new timeline reaches the repository)", func(tl *taskLog) error {
		_, err := a.check(ctx, db, tl)
		return err
	})
	// Backups and restore tests follow the new timeline (the control plane
	// queues a full backup after a rewind).
	step("full backup after the rewind", func(tl *taskLog) error {
		_, err := a.backup(ctx, db, protocol.BackupFull, tl)
		return err
	})
	step("restore test after the rewind", func(tl *taskLog) error {
		res, err := a.drill(ctx, db, "drill_after_rewind", tl)
		if err == nil && !res.Passed {
			t.Fatalf("drill %+v", res)
		}
		return err
	})
	sql("shop", `INSERT INTO items (id, note) VALUES (1000, 'written after the rewind')`)

	// ---- undo ----
	var undo *protocol.RewindUndoResult
	step("undo", func(tl *taskLog) error {
		var err error
		undo, err = a.rewindUndo(ctx, db, protocol.RewindUndoParams{RewindID: "rw_e2e"}, tl)
		return err
	})
	if n, maxID := items(); n != 200 || maxID != 200 {
		t.Fatalf("production after the undo: %d rows, max id %d", n, maxID)
	}
	if _, err := os.Stat(undo.RewoundDataDir); err != nil {
		t.Fatalf("the rewound data isn't kept: %v", err)
	}
	var tlAfterUndo int
	query("postgres", `SELECT timeline_id FROM pg_control_checkpoint()`, &tlAfterUndo)
	if tlAfterUndo <= timeline {
		t.Fatalf("after the undo the data is on timeline %d; the rewind's was %d (restores would follow the rewind's)", tlAfterUndo, timeline)
	}
	if n, _ := items(); n != 200 {
		t.Fatalf("the new timeline lost rows: %d", n)
	}
	step("check after the undo", func(tl *taskLog) error {
		_, err := a.check(ctx, db, tl)
		return err
	})
	step("full backup after the undo", func(tl *taskLog) error {
		_, err := a.backup(ctx, db, protocol.BackupFull, tl)
		return err
	})
	step("restore test after the undo", func(tl *taskLog) error {
		res, err := a.drill(ctx, db, "drill_after_undo", tl)
		if err == nil && !res.Passed {
			t.Fatalf("drill %+v", res)
		}
		return err
	})
	// And a copy just now sees the data as it is after the undo.
	var now time.Time
	query("postgres", `SELECT clock_timestamp()`, &now)
	time.Sleep(time.Second)
	sql("postgres", `CREATE TABLE after_undo (x int)`) // a commit after the target, so recovery knows it got there
	step("restore a copy after the undo", func(tl *taskLog) error {
		if _, err := a.rewindDrop(ctx, db, protocol.RewindDropParams{CopyID: "cp_e2e"}, tl); err != nil {
			return err
		}
		if _, err := a.rewindRestorePointForTest(ctx, db, tl); err != nil {
			return err
		}
		_, err = a.rewindCopy(ctx, db, protocol.RewindCopyParams{CopyID: "cp_after", Target: protocol.RewindTarget{Time: &now}}, tl)
		return err
	})
	rec2, _ := a.rewindState().get("cp_after")
	c2, err := a.copyTarget(rec2).Connect(ctx, "shop")
	if err != nil {
		t.Fatal(err)
	}
	var n2 int64
	if err := c2.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n2); err != nil || n2 != 200 {
		t.Fatalf("copy after the undo: %d rows (%v)", n2, err)
	}
	c2.Close(ctx)
	step("drop the second copy", func(tl *taskLog) error {
		_, err := a.rewindDrop(ctx, db, protocol.RewindDropParams{CopyID: "cp_after"}, tl)
		return err
	})

	// ---- cleanup ----
	step("cleanup", func(tl *taskLog) error {
		_, err := a.rewindCleanup(ctx, db, protocol.RewindCleanupParams{RewindID: "rw_e2e"}, tl)
		return err
	})
	if _, err := os.Stat(undo.RewoundDataDir); !os.IsNotExist(err) {
		t.Fatalf("kept data still there: %v", err)
	}
	step("drop the copy", func(tl *taskLog) error {
		_, err := a.rewindDrop(ctx, db, protocol.RewindDropParams{CopyID: "cp_e2e"}, tl)
		return err
	})
	if hb := a.rewindState().states(); len(hb) != 0 {
		t.Fatalf("still reported: %+v", hb)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("left behind next to the data directory: %v", entries)
	}
	var stanzas []pgbackrest.Stanza
	if stanzas, err = a.cli(db).Info(ctx); err != nil || len(stanzas) != 1 {
		t.Fatalf("pgbackrest info: %v", err)
	}
}

// rewindRestorePointForTest archives the WAL up to now (a restore point
// forces a segment switch and waits until it is in the repository).
func (a *Agent) rewindRestorePointForTest(ctx context.Context, db protocol.DatabaseSpec, tl *taskLog) (*protocol.RestorePointResult, error) {
	return a.restorePoint(ctx, db, protocol.RestorePointParams{Name: "e2e-" + time.Now().UTC().Format("150405")}, tl)
}
