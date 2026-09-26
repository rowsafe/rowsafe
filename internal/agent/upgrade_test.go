package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestParseAptPolicy(t *testing.T) {
	out := `postgresql-16:
  Installed: 16.9-1.pgdg13+1
  Candidate: 16.10-1.pgdg13+1
  Version table:
     16.10-1.pgdg13+1 500
        500 https://apt.postgresql.org/pub/repos/apt trixie-pgdg/main arm64 Packages
 *** 16.9-1.pgdg13+1 100
        100 /var/lib/dpkg/status
postgresql-17:
  Installed: (none)
  Candidate: 17.11-0+deb13u1
  Version table:
     17.11-0+deb13u1 500
        500 http://deb.debian.org/debian trixie/main arm64 Packages
        500 http://deb.debian.org/debian-security trixie-security/main arm64 Packages
postgresql-19:
  Installed: (none)
  Candidate: (none)
  Version table:
`
	p := parseAptPolicy([]byte(out))
	if got := p["postgresql-16"]; got != (aptPolicy{Installed: "16.9-1.pgdg13+1", Candidate: "16.10-1.pgdg13+1", Origin: "apt.postgresql.org"}) {
		t.Errorf("16: %+v", got)
	}
	if got := p["postgresql-17"]; got != (aptPolicy{Candidate: "17.11-0+deb13u1", Origin: "Debian"}) {
		t.Errorf("17: %+v", got)
	}
	if got, ok := p["postgresql-19"]; !ok || got != (aptPolicy{}) {
		t.Errorf("19: %+v %v", got, ok)
	}
}

func TestVersions(t *testing.T) {
	for in, want := range map[string]string{"16.10-1.pgdg13+1": "16.10", "1:15.8-0+deb12u1": "15.8", "18.1-1": "18.1", "": ""} {
		if got := minorOf(in); got != want {
			t.Errorf("minorOf(%q) = %q", in, got)
		}
	}
	if !newerMinor("16.9", "16.10") || newerMinor("16.10", "16.9") || newerMinor("16.10", "16.10") || newerMinor("", "16.1") {
		t.Error("newerMinor")
	}
	if !versionLess("2.54.2", "2.55") || versionLess("2.55", "2.55.0") || versionLess("2.57.0", "2.55") {
		t.Error("versionLess")
	}
	if shortVersion("16.9 (Debian 16.9-1.pgdg13+1)") != "16.9" {
		t.Error("shortVersion")
	}
	if humanDuration(12*time.Second) != "12 s" || humanDuration(125*time.Second) != "2 min 5 s" || humanDuration(time.Hour+3*time.Minute) != "1 h 3 min" {
		t.Error("humanDuration")
	}
}

func TestSecurityUpgrades(t *testing.T) {
	out := `NOTE: This is only a simulation!
Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
Inst linux-image-6.12.0-9-arm64 (6.12.41-1 Debian-Security:13/stable-security [arm64])
Inst tzdata [2025a-1] (2025b-0+deb13u1 Debian:13.1/stable [all])
Inst libc6 [2.35-0ubuntu3.1] (2.35-0ubuntu3.4 Ubuntu:22.04/jammy-updates, Ubuntu:22.04/jammy-security [amd64])
Inst postgresql-16 [16.9-1] (16.10-1 Debian-Security:13/stable-security [arm64])
Conf libssl3t64 (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
`
	got := securityUpgrades([]byte(out))
	if want := []string{"libc6", "libssl3t64", "postgresql-16"}; !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestInitdbArgs(t *testing.T) {
	p := initdbParams{Super: "postgres", Encoding: "UTF8", Collate: "C.UTF-8", Ctype: "C.UTF-8", Provider: "c", WalSegMB: 16}
	got := strings.Join(initdbArgs("/d", p, 18), " ")
	if !strings.Contains(got, "--no-data-checksums") || !strings.Contains(got, "--wal-segsize=16") || !strings.Contains(got, "-U postgres") {
		t.Errorf("18 without checksums: %s", got)
	}
	p.Checksums, p.Provider, p.Locale = true, "i", "und-x-icu"
	got = strings.Join(initdbArgs("/d", p, 17), " ")
	if !strings.Contains(got, "--data-checksums") || !strings.Contains(got, "--locale-provider=icu --icu-locale=und-x-icu") {
		t.Errorf("17 with checksums and ICU: %s", got)
	}
}

func TestPgUpgradeProblems(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "pg_upgrade_output.d", "20260925T1"), 0o700)
	os.WriteFile(filepath.Join(dir, "pg_upgrade_output.d", "20260925T1", "loadable_libraries.txt"),
		[]byte("could not load library \"$libdir/postgis-3\": ERROR:  could not access file\nIn database: shop\n"), 0o600)
	out := []byte("Checking for presence of required libraries                   fatal\n\nYour installation references loadable libraries that are missing\n")
	got := pgUpgradeProblems(out, dir)
	if !strings.Contains(got, "required libraries") || !strings.Contains(got, "postgis-3") {
		t.Errorf("got %q", got)
	}
}

// scriptRunner answers commands from a table (the longest matching prefix
// of "name arg1 arg2...") and records them.
type scriptRunner struct {
	mu    sync.Mutex
	outs  map[string]string
	errs  map[string]error
	calls []string
}

func (r *scriptRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cmd := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, cmd)
	best := ""
	for k := range r.outs {
		if strings.HasPrefix(cmd, k) && len(k) > len(best) {
			best = k
		}
	}
	for k := range r.errs {
		if strings.HasPrefix(cmd, k) && len(k) >= len(best) {
			return []byte(r.outs[k]), r.errs[k]
		}
	}
	if best == "" {
		return nil, nil
	}
	return []byte(r.outs[best]), nil
}

type upgradeEnv struct {
	t       *testing.T
	a       *Agent
	ops     *fakeOps
	run     *scriptRunner
	db      protocol.DatabaseSpec
	root    string
	version string // what the running server reports
	helper  func(id string, args []string) map[string]string
	asked   []string
}

func newUpgradeEnv(t *testing.T) *upgradeEnv {
	root := t.TempDir()
	e := &upgradeEnv{t: t, root: root, version: "16.9 (Debian 16.9-1.pgdg13+1)",
		db: protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql"}}
	pgdata := filepath.Join(root, "postgresql", "16", "main")
	os.MkdirAll(pgdata, 0o700)
	os.WriteFile(filepath.Join(pgdata, "MARKER"), []byte("ORIGINAL"), 0o600)
	e.ops = newFakeOps(pgdata)
	e.ops.f.Major = 16
	e.ops.f.ConfigFile = "/etc/postgresql/16/main/postgresql.conf"
	e.run = &scriptRunner{outs: map[string]string{
		"pg_lsclusters --no-header":                                          "16 main 5432 online postgres " + pgdata + " /var/log/postgresql/postgresql-16-main.log\n",
		"apt-cache pkgnames postgresql-":                                     "postgresql-16\npostgresql-17\npostgresql-18\npostgresql-common\n",
		"apt-cache policy postgresql-17":                                     "postgresql-17:\n  Installed: (none)\n  Candidate: 17.6-1.pgdg13+1\npostgresql-18:\n  Installed: (none)\n  Candidate: 18.1-1.pgdg13+1\n",
		"dpkg-query -W -f=${db:Status-Abbrev} ${Package}\\n postgresql-16-*": "ii  postgresql-16-cron\n",
		"apt-cache policy postgresql-18-cron":                                "postgresql-18-cron:\n  Installed: (none)\n  Candidate: 1.6.5-1.pgdg13+1\n",
		"apt-cache policy postgresql-17-cron":                                "postgresql-17-cron:\n  Installed: (none)\n  Candidate: 1.6.5-1.pgdg13+1\n",
		"/usr/bin/pgbackrest version":                                        "pgBackRest 2.57.0\n",
	}, errs: map[string]error{"cp --reflink": errors.New("not supported")}}
	allow := filepath.Join(root, "restart-allowed")
	os.WriteFile(allow, []byte("5432 postgresql@16-main.service\n"), 0o644)
	upd := filepath.Join(root, "updates-allowed")
	os.WriteFile(upd, []byte("# allowed\npostgresql\nsecurity\nreboot\n"), 0o644)
	helper := filepath.Join(root, "rowsafe-pg-restart")
	os.WriteFile(helper, []byte("#!/bin/sh\n# actions: restart stop start\n# update-actions: pg-minor-update pg-install-major pg-upgrade pg-upgrade-undo pg-upgrade-cleanup security-updates reboot\n"), 0o755)
	unit := filepath.Join(root, "rowsafe-pg-update.path")
	os.WriteFile(unit, nil, 0o644)
	oldUnit := updatePathUnit
	updatePathUnit = unit
	oldSum := summarizeCluster
	summarizeCluster = func(context.Context, pginspect.Target) (pginspect.Summary, error) {
		major := 16
		if strings.HasPrefix(e.version, "18") {
			major = 18
		}
		return pginspect.Summary{ServerVersion: e.version, VersionNum: major * 10000}, nil
	}
	t.Cleanup(func() { updatePathUnit, summarizeCluster = oldUnit, oldSum })
	bins := filepath.Join(root, "bin", "%d")
	os.MkdirAll(filepath.Join(root, "bin", "18"), 0o755)
	os.WriteFile(filepath.Join(root, "bin", "18", "pg_upgrade"), nil, 0o755)
	os.MkdirAll(filepath.Join(root, "restart"), 0o700)
	e.a = &Agent{cfg: Config{StateDir: filepath.Join(root, "state"), RestartDir: filepath.Join(root, "restart"), RestartAllowFile: allow,
		UpdateAllowFile: upd, RestartHelper: helper, PGBinDir: bins, PgBackRestBin: "/usr/bin/pgbackrest", PGUser: "postgres",
		DrillDir: filepath.Join(root, "drills"), RewindDir: filepath.Join(root, "rewind")},
		log: slog.New(slog.DiscardHandler), runner: e.run, rewindOps: e.ops, skipAnalyze: true,
		pingDB:           func(context.Context, protocol.DatabaseSpec) error { return nil },
		checkArchivingFn: func(context.Context, protocol.DatabaseSpec) error { return nil },
		finishBackupsFn:  func(context.Context, protocol.DatabaseSpec) error { return nil }}
	e.a.updateHelperFn = func(_ context.Context, id string, args []string, _ time.Duration) (map[string]string, error) {
		e.asked = append(e.asked, strings.Join(args, " "))
		if e.helper == nil {
			return nil, errors.New("no helper in this test")
		}
		return e.helper(id, args), nil
	}
	return e
}

func TestUpgradeChecks(t *testing.T) {
	e := newUpgradeEnv(t)
	res, err := e.a.upgradeCheck(context.Background(), e.db, protocol.UpgradeCheckParams{}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ToMajor != 18 || res.ToVersion != "18.1" || !slices.Equal(res.Majors, []int{17, 18}) || res.FromVersion != "16.9" {
		t.Fatalf("target: %+v", res)
	}
	if !res.CanRehearse || !res.CanUpgrade {
		t.Fatalf("should be ready: %+v", res.Checks)
	}
	safe := modeOf(res.Modes, protocol.UpgradeSafe)
	if safe == nil || safe.Method != "copy" || !safe.Available {
		t.Errorf("safe mode %+v", safe)
	}
	// An extension without a package for the target blocks both.
	e.run.outs["apt-cache policy postgresql-18-cron"] = "postgresql-18-cron:\n  Installed: (none)\n  Candidate: (none)\n"
	res, _ = e.a.upgradeCheck(context.Background(), e.db, protocol.UpgradeCheckParams{ToMajor: 18}, &taskLog{})
	if res.CanRehearse || res.CanUpgrade || !strings.Contains(res.Summary, "extension package") {
		t.Errorf("missing extension: %s", res.Summary)
	}
	e.run.outs["apt-cache policy postgresql-18-cron"] = "postgresql-18-cron:\n  Candidate: 1.6.5-1\n"
	// Updates not allowed: rehearsal still possible (18 is installed), the upgrade isn't.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("security\n"), 0o644)
	res, _ = e.a.upgradeCheck(context.Background(), e.db, protocol.UpgradeCheckParams{ToMajor: 18}, &taskLog{})
	if !res.CanRehearse || res.CanUpgrade {
		t.Errorf("not allowed: %+v", res)
	}
	// A replica, and an old pgBackRest.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("postgresql\n"), 0o644)
	e.ops.f.InRecovery = true
	e.run.outs["/usr/bin/pgbackrest version"] = "pgBackRest 2.50\n"
	res, _ = e.a.upgradeCheck(context.Background(), e.db, protocol.UpgradeCheckParams{ToMajor: 18}, &taskLog{})
	var ids []string
	for _, c := range res.Checks {
		if c.Status == protocol.CheckBlocker {
			ids = append(ids, c.ID)
		}
	}
	if !slices.Contains(ids, "replica") || !slices.Contains(ids, "pgbackrest") || res.CanRehearse {
		t.Errorf("blockers %v", ids)
	}
}

func TestPGUpdate(t *testing.T) {
	e := newUpgradeEnv(t)
	e.helper = func(id string, args []string) map[string]string {
		e.version = "16.10 (Debian 16.10-1.pgdg13+1)"
		return map[string]string{"id": id, "ok": "1", "package": "16.10-1.pgdg13+1", "packages": "postgresql-16 postgresql-client-16 libpq5",
			"restarted": "1", "other_clusters": ""}
	}
	res, err := e.a.pgUpdate(context.Background(), e.db, protocol.PGUpdateParams{ToVersion: "16.10"}, "task_1", &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if res.FromVersion != "16.9" || res.ToVersion != "16.10" || !res.Restarted || !res.ArchivingOK || !strings.HasPrefix(res.Summary, "Updated PostgreSQL from 16.9 to 16.10") {
		t.Errorf("%+v", res)
	}
	if e.asked[0] != "pg-minor-update 5432" {
		t.Errorf("asked %v", e.asked)
	}
	// Not allowed: nothing is asked.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("security\n"), 0o644)
	e.asked = nil
	if _, err := e.a.pgUpdate(context.Background(), e.db, protocol.PGUpdateParams{}, "task_2", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "--allow-updates") || len(e.asked) != 0 {
		t.Errorf("not allowed: %v %v", err, e.asked)
	}
	// A failed update says PostgreSQL runs as before.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("postgresql\n"), 0o644)
	e.helper = func(id string, _ []string) map[string]string {
		return map[string]string{"id": id, "ok": "0", "error": "installing the update failed: E: Unable to locate package"}
	}
	if _, err := e.a.pgUpdate(context.Background(), e.db, protocol.PGUpdateParams{}, "task_3", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "runs as before") {
		t.Errorf("failed update: %v", err)
	}
}

func TestSecurityUpdatesTask(t *testing.T) {
	e := newUpgradeEnv(t)
	e.helper = func(id string, _ []string) map[string]string {
		return map[string]string{"id": id, "ok": "1", "installed": "2", "packages": "libssl3t64 openssh-server", "held_back": "postgresql-16",
			"reboot_required": "1"}
	}
	res, err := e.a.securityUpdates(context.Background(), e.db, "task_1", &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Installed != 2 || !res.RebootRequired || res.Summary != "Installed 2 security updates. PostgreSQL's own updates are left for Update PostgreSQL. The server needs a reboot to finish." {
		t.Errorf("%+v", res)
	}
}

func TestUpgradeSafeUndoCleanup(t *testing.T) {
	e := newUpgradeEnv(t)
	ctx := context.Background()
	e.helper = func(id string, args []string) map[string]string {
		switch args[0] {
		case actUpgrade:
			if strings.Join(args, " ") != "pg-upgrade 5432 18 copy" {
				t.Errorf("upgrade request %v", args)
			}
			e.version = "18.1 (Debian 18.1-1.pgdg13+1)"
			return map[string]string{"id": id, "ok": "1", "aside_port": "5433", "new_data_dir": "/var/lib/postgresql/18/main"}
		case actUpgradeUndo:
			if strings.Join(args, " ") != "pg-upgrade-undo 5432 start" {
				t.Errorf("undo request %v", args)
			}
			e.version = "16.9 (Debian 16.9-1.pgdg13+1)"
			return map[string]string{"id": id, "ok": "1", "aside_port": "5433"}
		case actUpgradeCleanup:
			return map[string]string{"id": id, "ok": "1", "freed": "1048576", "packages_removed": "postgresql-18"}
		}
		return map[string]string{"id": id, "ok": "0", "error": "unexpected"}
	}
	res, err := e.a.upgrade(ctx, e.db, protocol.UpgradeParams{UpgradeID: "up_1", ToMajor: 18, Mode: protocol.UpgradeSafe}, "task_1", &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if res.FromVersion != "16.9" || res.ToVersion != "18.1" || !res.BackupsReady || res.KeptUntil == nil || !strings.Contains(res.Summary, "Undo switches back") {
		t.Fatalf("%+v", res)
	}
	st := e.a.upgradeState().states()
	if len(st) != 1 || st[0].Status != protocol.UpgradeDone || st[0].KeptCluster != "16/main (port 5433, stopped)" || !st[0].BackupsReady {
		t.Fatalf("state %+v", st)
	}
	// A second upgrade is refused while the old version is kept.
	chk, _ := e.a.upgradeCheck(ctx, e.db, protocol.UpgradeCheckParams{ToMajor: 18}, &taskLog{})
	if chk.CanUpgrade {
		t.Error("upgrade allowed while the previous one keeps a version")
	}

	ures, err := e.a.upgradeUndo(ctx, e.db, protocol.UpgradeUndoParams{UpgradeID: "up_1"}, "task_2", &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if ures.Version != "16.9" || !strings.Contains(ures.Summary, "Back on PostgreSQL 16.9") || !strings.Contains(ures.Summary, "PostgreSQL 18 is kept aside") {
		t.Errorf("%+v", ures)
	}
	if _, err := e.a.upgradeUndo(ctx, e.db, protocol.UpgradeUndoParams{UpgradeID: "up_1"}, "task_3", &taskLog{}); err == nil {
		t.Error("undone twice")
	}
	st = e.a.upgradeState().states()
	if st[0].Status != protocol.UpgradeUndone || st[0].KeptCluster != "18/main (port 5433, stopped)" {
		t.Errorf("after undo %+v", st)
	}
	cres, err := e.a.upgradeCleanup(ctx, e.db, protocol.UpgradeCleanupParams{UpgradeID: "up_1"}, &taskLog{})
	if err != nil || !cres.Removed || cres.FreedBytes != 1<<20 || cres.Summary != "Removed PostgreSQL 18/main (1.0 MiB freed) and its programs." {
		t.Errorf("cleanup %+v %v", cres, err)
	}
	if len(e.a.upgradeState().all()) != 0 {
		t.Error("record kept after cleanup")
	}
}

func TestUpgradeRolledBackOrRefused(t *testing.T) {
	e := newUpgradeEnv(t)
	e.helper = func(id string, _ []string) map[string]string {
		return map[string]string{"id": id, "ok": "0", "rolled_back": "1", "error": "pg_upgrade failed, and PostgreSQL 16 runs as before: ..."}
	}
	res, err := e.a.upgrade(context.Background(), e.db, protocol.UpgradeParams{UpgradeID: "up_1", ToMajor: 18, Mode: protocol.UpgradeSafe}, "task_1", &taskLog{})
	if err == nil || !res.RolledBack || len(e.a.upgradeState().all()) != 0 {
		t.Errorf("rolled back: %+v %v", res, err)
	}
	// Fast mode needs the Mark.
	if _, err := e.a.upgrade(context.Background(), e.db, protocol.UpgradeParams{UpgradeID: "up_2", ToMajor: 18, Mode: protocol.UpgradeFast}, "task_2", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "Mark") {
		t.Errorf("fast without a Mark: %v", err)
	}
}

func TestUpgradeFastFailureRestoresFromBackup(t *testing.T) {
	e := newUpgradeEnv(t)
	ctx := context.Background()
	e.helper = func(id string, args []string) map[string]string {
		switch args[0] {
		case actUpgrade:
			e.ops.live = false // the new version didn't start; the old one can't
			return map[string]string{"id": id, "ok": "0", "kept": "16/main", "error": "PostgreSQL 18 did not start: ..."}
		case actUpgradeUndo:
			if args[2] != "nostart" {
				t.Errorf("fast undo must not start the old version before restoring it: %v", args)
			}
			os.WriteFile(e.a.cfg.RestartAllowFile, []byte("5432 postgresql@16-main.service\n"), 0o644)
			return map[string]string{"id": id, "ok": "1", "aside_port": "5433"}
		}
		return map[string]string{"id": id, "ok": "0"}
	}
	res, err := e.a.upgrade(ctx, e.db, protocol.UpgradeParams{UpgradeID: "up_1", ToMajor: 18, Mode: protocol.UpgradeFast,
		Mark: "before-upgrade", MarkBackupSet: "20260925-010000F"}, "task_1", &taskLog{})
	if err == nil || !res.RolledBack || !strings.Contains(res.Summary, "restored PostgreSQL 16 from the backup at the Mark before-upgrade") {
		t.Fatalf("%+v %v", res, err)
	}
	if !slices.Contains(e.ops.calls, "restore name before-upgrade") || marker(e.ops.f.DataDir) != "RESTORED" || !e.ops.live {
		t.Errorf("calls %v, marker %q", e.ops.calls, marker(e.ops.f.DataDir))
	}
	st := e.a.upgradeState().states()
	if len(st) != 1 || st[0].Status != protocol.UpgradeUndone {
		t.Errorf("state %+v", st)
	}
}

func TestAfterReboot(t *testing.T) {
	e := newUpgradeEnv(t)
	os.MkdirAll(e.a.cfg.StateDir, 0o700)
	os.WriteFile(e.a.rebootMarkPath(), []byte(`{"task_id":"task_9","requested_at":"2026-09-25T03:00:00Z","boot_id":"not-this-boot","database":{"id":"db_1","port":5432}}`), 0o600)
	if _, ok := e.a.afterReboot(context.Background(), "task_other"); ok {
		t.Error("matched another task")
	}
	req, ok := e.a.afterReboot(context.Background(), "task_9")
	if !ok || req.Status != protocol.StatusSucceeded || !strings.Contains(string(req.Result), "rebooted") {
		t.Errorf("%v %+v %s", ok, req, req.Result)
	}
	if pathExists(e.a.rebootMarkPath()) {
		t.Error("reboot mark kept")
	}
}

func TestUpgradeExpiry(t *testing.T) {
	e := newUpgradeEnv(t)
	now := time.Now().UTC()
	e.a.upgradeState().put(upgradeRecord{ID: "up_1", DatabaseID: "db_1", Database: e.db, FromMajor: 16, ToMajor: 18, Cluster: "main",
		Status: protocol.UpgradeDone, BackupsReady: true, CreatedAt: now.Add(-8 * 24 * time.Hour), Expires: now.Add(-time.Minute)})
	e.helper = func(id string, args []string) map[string]string {
		return map[string]string{"id": id, "ok": "1", "freed": "10"}
	}
	e.a.upgradeTick(context.Background(), now)
	if len(e.a.upgradeState().all()) != 0 || !slices.Contains(e.asked, "pg-upgrade-cleanup 5432") {
		t.Errorf("expired upgrade kept: %v", e.asked)
	}
}
