//go:build secondcopy_e2e

package agent

// The second copy for real: scripts/test-secondcopy.sh builds this test
// (go test -c -tags secondcopy_e2e) and runs it as postgres in a Debian
// container with PostgreSQL and pgBackRest, and two local repositories
// standing in for two storage providers. Every step is the agent's own
// code: adopt (archive_command with the second copy), WAL to both, a full
// backup to each, the second storage going away (PostgreSQL keeps
// archiving, the copy reports failing), coming back (it catches up), Proof
// and a Rewind copy from the second copy, storage use, a gap closed by a
// full backup, and removing the second copy again.

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

func TestRealSecondCopy(t *testing.T) {
	w := os.Getenv("SC_WORK")
	if w == "" {
		t.Fatal("SC_WORK is not set")
	}
	cfg := Config{
		StateDir: filepath.Join(w, "state"), ConfigDir: filepath.Join(w, "conf"), LogDir: filepath.Join(w, "log"),
		DrillDir: filepath.Join(w, "drills"), DrillPort: 55432, DrillPreload: DrillPreloadAuto, PGUser: "postgres",
		PGBinDir: "/usr/lib/postgresql/%d/bin", PgBackRestBin: "/usr/bin/pgbackrest", Mode: ModeNative,
		PollInterval: time.Second, HeartbeatPeriod: time.Second, RestorePointTimeout: time.Minute,
		RewindDir: filepath.Join(w, "rewind"), SecondCopyQueueDir: filepath.Join(w, "queue"),
		Repo:  pgbackrest.Repo{Type: "posix", Path: filepath.Join(w, "repo1"), CipherPass: "first-storage-passphrase-0123456789"},
		Repo2: pgbackrest.Repo{Type: "posix", Path: filepath.Join(w, "repo2"), CipherPass: "second-storage-passphrase-9876543210"},
	}
	for _, d := range []string{cfg.StateDir, cfg.Repo.Path, cfg.Repo2.Path} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	a := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	db := protocol.DatabaseSpec{ID: "db_sc", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}
	a.watched = []protocol.DatabaseSpec{db}

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
	sql := func(dbname, q string) {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, q); err != nil {
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
	status := func() protocol.SecondCopyStatus {
		t.Helper()
		sts := a.secondCopyStatuses()
		if len(sts) != 1 {
			t.Fatalf("statuses %+v", sts)
		}
		return sts[0]
	}
	waitFor := func(what string, timeout time.Duration, ok func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for !ok() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s (second copy: %+v)", what, status())
			}
			a.second.pusher.Wake()
			time.Sleep(500 * time.Millisecond)
		}
	}
	switchWAL := func(n int) {
		for range n {
			sql("shop", `INSERT INTO items (note) SELECT 'more ' || i FROM generate_series(1, 2000) i`)
			sql("postgres", `SELECT pg_switch_wal()`)
		}
	}
	archiver := func() (archived, failed int64) {
		query("postgres", `SELECT archived_count, failed_count FROM pg_stat_archiver`, &archived, &failed)
		return
	}

	step("adopt (archive_command with the second copy)", func(tl *taskLog) error {
		res, err := a.adopt(ctx, db, protocol.AdoptParams{Apply: true}, tl)
		if err == nil && res.RestartRequired {
			t.Fatal("restart required: the test cluster should start with archive_mode on")
		}
		return err
	})
	var cmd string
	query("postgres", `SHOW archive_command`, &cmd)
	if !strings.Contains(cmd, cfg.SecondCopyQueueDir) || !a.ownArchiveCommand(db)(cmd) {
		t.Fatalf("archive_command %q", cmd)
	}
	a.startSecondCopy(ctx)
	step("check", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	waitFor("the second copy to be set up", time.Minute, func() bool { return status().Ready })

	sql("postgres", `CREATE DATABASE shop`)
	sql("shop", `CREATE TABLE items (id serial PRIMARY KEY, note text NOT NULL)`)
	sql("shop", `INSERT INTO items (note) SELECT 'first ' || i FROM generate_series(1, 100) i`)
	step("full backup to the first storage", func(tl *taskLog) error {
		_, err := a.backup(ctx, db, protocol.BackupFull, tl)
		return err
	})
	switchWAL(2)
	waitFor("WAL in the second copy", time.Minute, func() bool { s := status(); return s.SentCount >= 2 && s.QueuedFiles == 0 })
	step("full backup to the second copy", func(tl *taskLog) error {
		res, err := a.secondCopyBackup(ctx, db, protocol.BackupFull, tl)
		if err == nil && res.Repo != protocol.RepoSecond {
			t.Fatalf("result repo %d", res.Repo)
		}
		return err
	})

	// ---- the second storage goes away: PostgreSQL doesn't notice ----
	if err := os.Chmod(cfg.Repo2.Path, 0); err != nil {
		t.Fatal(err)
	}
	archivedBefore, failedBefore := archiver()
	switchWAL(4)
	time.Sleep(3 * time.Second)
	archivedAfter, failedAfter := archiver()
	if failedAfter != failedBefore || archivedAfter < archivedBefore+4 {
		t.Fatalf("PostgreSQL's archiving was affected: archived %d -> %d, failed %d -> %d", archivedBefore, archivedAfter, failedBefore, failedAfter)
	}
	waitFor("the second copy to report failing", time.Minute, func() bool {
		s := status()
		return s.FailingSince != nil && s.QueuedFiles >= 4 && s.LastError != ""
	})
	t.Logf("while the second storage is away: %+v", status())
	step("check (the first storage is fine)", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })

	// ---- it comes back: the copy catches up ----
	if err := os.Chmod(cfg.Repo2.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	waitFor("the second copy to catch up", 2*time.Minute, func() bool {
		s := status()
		return s.QueuedFiles == 0 && s.FailingSince == nil
	})
	var mark time.Time
	time.Sleep(1100 * time.Millisecond)
	query("postgres", `SELECT clock_timestamp()`, &mark)
	time.Sleep(1100 * time.Millisecond)
	sql("shop", `DELETE FROM items WHERE id <= 10`)
	switchWAL(1)
	waitFor("the deletion's WAL in the second copy", time.Minute, func() bool { return status().QueuedFiles == 0 })

	// ---- restore from the second copy ----
	step("Proof from the second copy", func(tl *taskLog) error {
		res, err := a.drillFrom(ctx, db, "drill_copy2", protocol.RepoSecond, tl)
		if err == nil && (!res.Passed || res.Repo != protocol.RepoSecond) {
			t.Fatalf("drill %+v", res)
		}
		return err
	})
	step("Proof from the first storage", func(tl *taskLog) error {
		res, err := a.drillFrom(ctx, db, "drill_copy1", 0, tl)
		if err == nil && !res.Passed {
			t.Fatalf("drill %+v", res)
		}
		return err
	})
	var stanzas []pgbackrest.Stanza
	cli2, err := a.repoCLI(db, protocol.RepoSecond)
	if err != nil {
		t.Fatal(err)
	}
	if stanzas, err = cli2.Info(ctx); err != nil {
		t.Fatal(err)
	}
	set, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		t.Fatal(err)
	}
	step("Rewind copy from the second copy, before the deletion", func(tl *taskLog) error {
		cp, err := a.rewindCopy(ctx, db, protocol.RewindCopyParams{CopyID: "cp_sc",
			Target: protocol.RewindTarget{Time: &mark, BackupSet: set.Label, Repo: protocol.RepoSecond}, Expires: time.Now().Add(time.Hour)}, tl)
		if err != nil {
			return err
		}
		rec, _ := a.rewindState().get("cp_sc")
		conn, err := a.copyTarget(rec).Connect(ctx, "shop")
		if err != nil {
			return err
		}
		defer conn.Close(ctx)
		var n int64
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM items WHERE id <= 10`).Scan(&n); err != nil {
			return err
		}
		if n != 10 {
			t.Fatalf("the copy from the second storage has %d of the deleted rows, want 10 (%s)", n, cp.Summary)
		}
		_, err = a.rewindDrop(ctx, db, protocol.RewindDropParams{CopyID: "cp_sc"}, tl)
		return err
	})

	// ---- storage use ----
	a.measureAll(ctx, true)
	rep := a.storageReports()
	if len(rep) != 2 {
		t.Fatalf("storage reports %+v", rep)
	}
	for _, r := range rep {
		t.Logf("storage %d: total %s, WAL %s (%d files), backups %s (%d)", r.Repo, humanBytes(r.TotalBytes), humanBytes(r.WALBytes), r.WALFiles,
			humanBytes(r.BackupBytes), len(r.Backups))
		if r.Error != "" || r.TotalBytes == 0 || r.WALBytes == 0 || r.BackupBytes == 0 || len(r.Backups) == 0 || r.Provider != protocol.ProviderPosix {
			t.Fatalf("storage %+v", r)
		}
	}

	// ---- a gap, closed by a full backup to the second copy ----
	dir, _ := a.cfg.secondCopyQueue(db.Stanza)
	appendGap(dir, "0000000100000000000000FF")
	if s := status(); s.GapSince == nil || s.SkippedFiles != 1 {
		t.Fatalf("gap not reported: %+v", s)
	}
	time.Sleep(1100 * time.Millisecond)
	step("full backup to the second copy closes the gap", func(tl *taskLog) error {
		_, err := a.secondCopyBackup(ctx, db, protocol.BackupFull, tl)
		return err
	})
	if s := status(); s.GapSince != nil {
		t.Fatalf("gap still reported: %+v", s)
	}

	// ---- removing the second copy puts the plain command back ----
	a.cfg.Repo2 = pgbackrest.Repo{}
	if err := a.syncArchiveCommand(ctx, db); err != nil {
		t.Fatal(err)
	}
	query("postgres", `SHOW archive_command`, &cmd)
	plain, _ := pgbackrest.ArchiveCommand(cfg.PgBackRestBin, cfg.configPath(db.Stanza), db.Stanza)
	if cmd != plain {
		t.Fatalf("archive_command after removing the second copy: %q", cmd)
	}
	step("check without the second copy", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	in, _ := pginspect.Inspect(ctx, a.target(db))
	t.Logf("done: PostgreSQL %s, %s", in.ServerVersion, humanBytes(in.TotalSizeBytes))
}
