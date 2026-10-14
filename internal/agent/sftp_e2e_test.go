//go:build sftp_e2e

package agent

// Backups to an SFTP server for real: scripts/test-sftp.sh builds this test
// (go test -c -tags sftp_e2e) and runs it as postgres in a Debian container
// with PostgreSQL, pgBackRest and an OpenSSH server, after the installer's
// own SFTP setup made the SSH key and pinned the host key. The settings
// come from the environment exactly as agent.env has them. Every step is
// the agent's own code: adopt (stanza-create before archive_command), check,
// a full backup, Proof, a Rewind copy to a second before a deletion,
// storage use reported as provider "sftp", the storage test, and a host key
// that stops matching (everything fails, nothing is accepted by itself).

import (
	"bytes"
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

func TestRealSFTP(t *testing.T) {
	w := os.Getenv("SFTP_WORK")
	if w == "" {
		t.Fatal("SFTP_WORK is not set")
	}
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example")
	env, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if err := env.ValidateRepo(); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		StateDir: filepath.Join(w, "state"), ConfigDir: filepath.Join(w, "conf"), LogDir: filepath.Join(w, "log"),
		DrillDir: filepath.Join(w, "drills"), DrillPort: 55432, DrillPreload: DrillPreloadAuto, PGUser: "postgres",
		PGBinDir: "/usr/lib/postgresql/%d/bin", PgBackRestBin: "/usr/bin/pgbackrest", Mode: ModeNative,
		PollInterval: time.Second, HeartbeatPeriod: time.Second, RestorePointTimeout: time.Minute,
		RewindDir: filepath.Join(w, "rewind"), SecondCopyQueueDir: filepath.Join(w, "queue"),
		Storage: protocol.StorageOwn, Repo: env.Repo,
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	a := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	db := protocol.DatabaseSpec{ID: "db_sftp", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}
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
	sql := func(dbname, q string, dest ...any) {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, dbname)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if len(dest) == 0 {
			_, err = conn.Exec(ctx, q)
		} else {
			err = conn.QueryRow(ctx, q).Scan(dest...)
		}
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	step("adopt", func(tl *taskLog) error {
		res, err := a.adopt(ctx, db, protocol.AdoptParams{Apply: true}, tl)
		if err == nil && res.RestartRequired {
			t.Fatal("restart required: the test cluster should start with archive_mode on")
		}
		return err
	})
	conf, _ := os.ReadFile(cfg.configPath(db.Stanza))
	for _, want := range []string{"repo1-type=sftp\n", "repo1-sftp-host-key-check-type=fingerprint\n", "repo1-cipher-type=aes-256-cbc\n",
		"repo1-path=" + strings.TrimRight(cfg.Repo.Path, "/") + "/shop\n"} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("config misses %q:\n%s", want, conf)
		}
	}
	step("check", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })

	sql("postgres", `CREATE DATABASE shop`)
	sql("shop", `CREATE TABLE items (id serial PRIMARY KEY, note text NOT NULL)`)
	sql("shop", `INSERT INTO items (note) SELECT 'first ' || i FROM generate_series(1, 100) i`)
	step("full backup", func(tl *taskLog) error {
		res, err := a.backup(ctx, db, protocol.BackupFull, tl)
		if err == nil && res.Label == "" {
			t.Fatalf("backup %+v", res)
		}
		return err
	})
	var mark time.Time
	sql("postgres", `SELECT clock_timestamp()`, &mark)
	time.Sleep(1100 * time.Millisecond)
	sql("shop", `DELETE FROM items WHERE id <= 10`)
	sql("postgres", `SELECT pg_switch_wal()`)
	var archived, failed int64
	deadline := time.Now().Add(time.Minute)
	for {
		sql("postgres", `SELECT archived_count, failed_count FROM pg_stat_archiver`, &archived, &failed)
		if archived >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("WAL not archived to the SFTP server: archived %d, failed %d", archived, failed)
		}
		time.Sleep(500 * time.Millisecond)
	}

	step("Proof", func(tl *taskLog) error {
		res, err := a.drillFrom(ctx, db, "drill_sftp", 0, tl)
		if err == nil && !res.Passed {
			t.Fatalf("drill %+v", res)
		}
		return err
	})
	stanzas, err := a.cli(db).Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	set, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		t.Fatal(err)
	}
	step("Rewind copy, a second before the deletion", func(tl *taskLog) error {
		_, err := a.rewindCopy(ctx, db, protocol.RewindCopyParams{CopyID: "cp_sftp",
			Target: protocol.RewindTarget{Time: &mark, BackupSet: set.Label}, Expires: time.Now().Add(time.Hour)}, tl)
		if err != nil {
			return err
		}
		rec, _ := a.rewindState().get("cp_sftp")
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
			t.Fatalf("the copy has %d of the deleted rows, want 10", n)
		}
		_, err = a.rewindDrop(ctx, db, protocol.RewindDropParams{CopyID: "cp_sftp"}, tl)
		return err
	})

	// Storage use, where the platform sees it.
	a.measureAll(ctx, true)
	rep := a.storageReports()
	if len(rep) != 1 {
		t.Fatalf("storage reports %+v", rep)
	}
	r := rep[0]
	t.Logf("storage: %+v total %d WAL %d backups %d", r.RepoInfo, r.TotalBytes, r.WALBytes, r.BackupBytes)
	if r.Error != "" || r.TotalBytes == 0 || r.WALBytes == 0 || r.BackupBytes == 0 || len(r.Backups) == 0 ||
		r.Provider != protocol.ProviderSFTP || r.Endpoint != cfg.Repo.SFTPEndpoint() || r.Bucket != strings.TrimRight(cfg.Repo.Path, "/") {
		t.Fatalf("storage %+v", r)
	}
	if st := a.storageStatus(); st.Repo == "" || st.Mode != protocol.StorageOwn {
		t.Fatalf("storage status %+v", st)
	}
	var out bytes.Buffer
	if err := StorageTest(ctx, cfg, &out, time.Second, false); err != nil {
		t.Fatalf("storage test: %v\n%s", err, out.String())
	}
	t.Log(strings.TrimSpace(out.String()))

	// A host key that isn't the pinned one: everything stops, loudly, and
	// is explained; nothing accepts the new key.
	bad := a.cfg.Repo
	bad.SFTPHostKey = "SHA256:" + strings.Repeat("A", 43)
	a.cfg.Repo = bad
	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.writeConfig(db, in); err != nil {
		t.Fatal(err)
	}
	_, err = a.check(ctx, db, &taskLog{})
	te := a.taskErrorOf(err)
	if err == nil || te == nil || te.Code != protocol.TaskErrSFTPHostKey {
		t.Fatalf("a changed host key: %v (%+v)", err, te)
	}
	cfgBad := cfg
	cfgBad.Repo = bad
	if err := StorageTest(ctx, cfgBad, &out, time.Second, false); err == nil || !strings.Contains(err.Error(), "not the one pinned") {
		t.Fatalf("storage test with a changed host key: %v", err)
	}
	conf2, _ := os.ReadFile(cfg.configPath(db.Stanza))
	if !strings.Contains(string(conf2), "repo1-sftp-host-fingerprint="+strings.Repeat("00", 32)) {
		t.Fatalf("the pinned fingerprint changed by itself:\n%s", conf2)
	}
}
