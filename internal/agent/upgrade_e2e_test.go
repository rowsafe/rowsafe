//go:build upgrade_e2e

package agent

// Real updates and upgrades on a real server: scripts/test-upgrade.sh
// builds this test (go test -c -tags upgrade_e2e) and runs it as postgres
// in a Debian container with systemd, PostgreSQL 16 (an older minor
// release) from apt.postgresql.org, pgBackRest, a MinIO repository and the
// root helper (restart and update services) installed from this
// repository. Every step is the agent's own code, and every package change
// the helper's: a minor update, the preflight, a rehearsal to 18 (which
// installs it), a Safe upgrade, its undo, removing the kept version, a Fast
// upgrade and its undo from the backup, and security updates.

import (
	"context"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestRealUpgrade(t *testing.T) {
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	a := New(cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	a.skipAnalyze = true // the background refresh would race the next step's stop
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Minute)
	defer cancel()
	db := protocol.DatabaseSpec{ID: "db_e2e", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 4}
	a.monitored = []protocol.DatabaseSpec{db}
	to := 18
	if v := os.Getenv("UPGRADE_TO"); v != "" {
		to, _ = strconv.Atoi(v)
	}

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
	items := func() (n int64) {
		t.Helper()
		conn, err := a.target(db).Connect(ctx, "shop")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM items`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	version := func() (string, int) {
		t.Helper()
		v, m, err := a.runningVersion(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		return v, m
	}
	backup := func(name string) string {
		var label string
		step(name, func(tl *taskLog) error {
			res, err := a.backup(ctx, db, protocol.BackupFull, tl)
			if err == nil {
				label = res.Label
			}
			return err
		})
		return label
	}

	step("adopt", func(tl *taskLog) error { _, err := a.adopt(ctx, db, protocol.AdoptParams{Apply: true}, tl); return err })
	step("restart through the root helper", func(tl *taskLog) error { _, err := a.restart(ctx, db, "e2e_restart", tl); return err })
	step("check", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	sql("postgres", `CREATE DATABASE shop`)
	sql("shop", `CREATE EXTENSION pg_cron`)
	sql("shop", `CREATE TABLE items (id serial PRIMARY KEY, note text NOT NULL)`)
	sql("shop", `INSERT INTO items (note) SELECT 'row ' || i FROM generate_series(1, 1000) i`)
	backup("full backup on 16")

	// ---- what the heartbeat reports ----
	sw := a.buildSoftware(ctx)
	t.Logf("software report: %+v", *sw)
	if len(sw.Clusters) != 1 || sw.PackageManager != "apt" {
		t.Fatalf("software %+v", sw)
	}
	c := sw.Clusters[0]
	if c.Major != 16 || c.Cluster != "main" || c.Origin != "apt.postgresql.org" || !newerMinor(c.Installed, c.Candidate) ||
		c.Running != c.Installed || !slices.Contains(c.Majors, to) || !slices.Contains(c.ExtensionPackages, "postgresql-16-cron") {
		t.Fatalf("cluster %+v", c)
	}
	if !slices.Equal(sw.Allowed, []string{"postgresql", "security"}) || !slices.Contains(sw.HelperActions, actUpgrade) {
		t.Fatalf("allowed %v, helper actions %v", sw.Allowed, sw.HelperActions)
	}

	// ---- minor update ----
	step("minor update", func(tl *taskLog) error {
		res, err := a.pgUpdate(ctx, db, protocol.PGUpdateParams{ToVersion: c.Candidate}, "task_minor", tl)
		if err == nil {
			t.Log(res.Summary)
			if res.ToVersion != c.Candidate || !res.Restarted || !res.ArchivingOK {
				t.Fatalf("update %+v", res)
			}
		}
		return err
	})
	if items() != 1000 {
		t.Fatal("rows lost in the minor update")
	}
	step("minor update again (nothing to do)", func(tl *taskLog) error {
		res, err := a.pgUpdate(ctx, db, protocol.PGUpdateParams{}, "task_minor2", tl)
		if err == nil && (res.Restarted || !strings.Contains(res.Summary, "already the newest")) {
			t.Fatalf("second update %+v", res)
		}
		return err
	})

	// ---- preflight and rehearsal ----
	step("upgrade check", func(tl *taskLog) error {
		res, err := a.upgradeCheck(ctx, db, protocol.UpgradeCheckParams{ToMajor: to}, tl)
		if err == nil {
			t.Logf("%s %+v", res.Summary, res.Checks)
			if !res.CanRehearse || !res.CanUpgrade {
				t.Fatalf("check %+v", res)
			}
		}
		return err
	})
	step("rehearsal", func(tl *taskLog) error {
		res, err := a.upgradeRehearsal(ctx, db, protocol.UpgradeRehearsalParams{ToMajor: to}, "task_rehearsal", tl)
		if res != nil {
			t.Logf("%s %+v", res.Summary, *res)
		}
		if err == nil && (!res.Passed || !res.PgBackRestOK || !slices.Contains(res.PackagesInstalled, "postgresql-"+strconv.Itoa(to))) {
			t.Fatalf("rehearsal %+v", res)
		}
		return err
	})
	if v, m := version(); m != 16 {
		t.Fatalf("production changed by the rehearsal: %s", v)
	}
	if out, _ := a.runner.Run(ctx, "pg_lsclusters", "--no-header"); strings.Count(strings.TrimSpace(string(out)), "\n") != 0 {
		t.Fatalf("clusters after the rehearsal (the package's own %d/main must be gone):\n%s", to, out)
	}

	// ---- Safe upgrade, undo, cleanup ----
	var up *protocol.UpgradeResult
	step("safe upgrade", func(tl *taskLog) error {
		var err error
		up, err = a.upgrade(ctx, db, protocol.UpgradeParams{UpgradeID: "up_safe", ToMajor: to, Mode: protocol.UpgradeSafe}, "task_up1", tl)
		return err
	})
	t.Log(up.Summary)
	if _, m := version(); m != to || items() != 1000 || !up.BackupsReady {
		t.Fatalf("after the upgrade: major %d, %d rows, backups ready %v", m, items(), up.BackupsReady)
	}
	sql("shop", `INSERT INTO items (note) VALUES ('written on the new version')`)
	step("check on the new version", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	backup("full backup on the new version")
	if st := a.upgradeState().states(); len(st) != 1 || st[0].Status != protocol.UpgradeDone {
		t.Fatalf("state %+v", st)
	}
	step("undo (Safe)", func(tl *taskLog) error {
		res, err := a.upgradeUndo(ctx, db, protocol.UpgradeUndoParams{UpgradeID: "up_safe"}, "task_undo1", tl)
		if err == nil {
			t.Log(res.Summary)
			if !res.BackupsReady {
				t.Fatalf("undo %+v", res)
			}
		}
		return err
	})
	if _, m := version(); m != 16 || items() != 1000 {
		t.Fatalf("after the undo: major %d, %d rows", m, items())
	}
	step("check after the undo", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	markBackup := backup("full backup after the undo")
	// The agent's user owns /etc/postgresql: it can repoint where the kept
	// PostgreSQL 18's data lives. The root helper must refuse to remove
	// anything but the data directory it recorded.
	decoy := "/var/lib/postgresql/decoy"
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(decoy+"/PG_VERSION", []byte(strconv.Itoa(to)+"\n"), 0o600)
	os.WriteFile(decoy+"/canary", []byte("keep me"), 0o600)
	conftool := func(args ...string) {
		t.Helper()
		if out, err := a.runner.Run(ctx, "pg_conftool", append([]string{strconv.Itoa(to), "main"}, args...)...); err != nil {
			t.Fatalf("pg_conftool %v: %v %s", args, err, out)
		}
	}
	conftool("set", "data_directory", decoy)
	rtl := &taskLog{}
	_, err = a.upgradeCleanup(ctx, db, protocol.UpgradeCleanupParams{UpgradeID: "up_safe"}, rtl)
	t.Logf("---- remove the kept version after repointing its data directory (must be refused)\n%s", rtl.String())
	if err == nil || !strings.Contains(err.Error(), "not /var/lib/postgresql/"+strconv.Itoa(to)+"/main as recorded") {
		t.Fatalf("a repointed data directory wasn't refused: %v", err)
	}
	if data, err := os.ReadFile(decoy + "/canary"); err != nil || string(data) != "keep me" {
		t.Fatalf("the decoy was touched: %v", err)
	}
	conftool("set", "data_directory", "/var/lib/postgresql/"+strconv.Itoa(to)+"/main")
	os.RemoveAll(decoy)
	step("remove the kept version", func(tl *taskLog) error {
		res, err := a.upgradeCleanup(ctx, db, protocol.UpgradeCleanupParams{UpgradeID: "up_safe"}, tl)
		if err == nil {
			t.Log(res.Summary)
		}
		return err
	})
	if out, _ := a.runner.Run(ctx, "pg_lsclusters", "--no-header"); strings.Count(strings.TrimSpace(string(out)), "\n") != 0 {
		t.Fatalf("clusters after the cleanup:\n%s", out)
	}

	// ---- Fast upgrade and its undo from the backup ----
	if !pathExists(a.cfg.pgBin(to, "pg_upgrade")) {
		step("install the target again", func(tl *taskLog) error {
			ans, err := a.askUpdateHelper(ctx, "e2e-install", []string{actInstallMajor, "5432", strconv.Itoa(to)}, time.Hour)
			if err == nil {
				err = helperOK(ans)
			}
			return err
		})
	}
	sql("shop", `INSERT INTO items (note) VALUES ('before the fast upgrade')`)
	step("Mark before the fast upgrade", func(tl *taskLog) error {
		_, err := a.restorePoint(ctx, db, protocol.RestorePointParams{Name: "before-upgrade-e2e"}, tl)
		return err
	})
	step("fast upgrade", func(tl *taskLog) error {
		res, err := a.upgrade(ctx, db, protocol.UpgradeParams{UpgradeID: "up_fast", ToMajor: to, Mode: protocol.UpgradeFast,
			Mark: "before-upgrade-e2e", MarkBackupSet: markBackup}, "task_up2", tl)
		if err == nil {
			t.Log(res.Summary)
		}
		return err
	})
	if _, m := version(); m != to || items() != 1001 {
		t.Fatalf("after the fast upgrade: major %d, %d rows", m, items())
	}
	sql("shop", `INSERT INTO items (note) VALUES ('lost by the fast undo')`)
	step("undo (Fast: restore from the backup)", func(tl *taskLog) error {
		res, err := a.upgradeUndo(ctx, db, protocol.UpgradeUndoParams{UpgradeID: "up_fast"}, "task_undo2", tl)
		if err == nil {
			t.Log(res.Summary)
			if res.RestoredTo == nil || !res.BackupsReady {
				t.Fatalf("fast undo %+v", res)
			}
		}
		return err
	})
	if _, m := version(); m != 16 || items() != 1001 {
		t.Fatalf("after the fast undo: major %d, %d rows (want 16 and 1001)", m, items())
	}
	step("check after the fast undo", func(tl *taskLog) error { _, err := a.check(ctx, db, tl); return err })
	backup("full backup after the fast undo")
	step("restore test after everything", func(tl *taskLog) error {
		res, err := a.drill(ctx, db, "drill_after_upgrades", tl)
		if err == nil && !res.Passed {
			t.Fatalf("drill %+v", res)
		}
		return err
	})
	step("remove the kept version (fast)", func(tl *taskLog) error {
		_, err := a.upgradeCleanup(ctx, db, protocol.UpgradeCleanupParams{UpgradeID: "up_fast"}, tl)
		return err
	})
	if len(a.upgradeState().all()) != 0 {
		t.Fatal("upgrade records left")
	}

	// ---- security updates ----
	step("security updates", func(tl *taskLog) error {
		res, err := a.securityUpdates(ctx, db, "task_security", tl)
		if err == nil {
			t.Log(res.Summary)
		}
		return err
	})
	if items() != 1001 {
		t.Fatal("rows changed by the security updates")
	}
	var stanzas []pgbackrest.Stanza
	if stanzas, err = a.cli(db).Info(ctx); err != nil || len(stanzas) != 1 {
		t.Fatalf("pgbackrest info: %v", err)
	}
}
