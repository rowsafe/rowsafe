package agent

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// versionEngine is a MySQL engine that answers with a version.
type versionEngine struct {
	readyEngine
	version string
}

func (v *versionEngine) Version(context.Context, EngineEnv, protocol.DatabaseSpec) (string, error) {
	return v.version, nil
}

func TestEngineUpdate(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("3306 mysql.service\n"), 0o644)
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("database\nsecurity\n"), 0o644)
	os.WriteFile(e.a.cfg.RestartHelper, []byte("#!/bin/sh\n# update-actions: security-updates reboot db-minor-update\n"), 0o755)
	eng := &versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineMySQL}, tries: 5}, version: "8.0.40"}
	withEngine(t, eng)
	db := protocol.DatabaseSpec{ID: "db_m", Name: "shop", Port: 3306, Engine: protocol.EngineMySQL}
	e.helper = func(id string, args []string) map[string]string {
		eng.version = "8.0.43"
		return map[string]string{"id": id, "ok": "1", "package": "8.0.43-1debian12", "packages": "mysql-community-server mysql-community-client", "restarted": "1"}
	}
	res, err := e.a.runTask(context.Background(), &protocol.Task{ID: "t1", Type: protocol.TaskPGUpdate, Database: &db}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*protocol.PGUpdateResult)
	if r.FromVersion != "8.0.40" || r.ToVersion != "8.0.43" || !r.Restarted || !r.ArchivingOK || !strings.HasPrefix(r.Summary, "Updated MySQL from 8.0.40 to 8.0.43") {
		t.Errorf("%+v", r)
	}
	if e.asked[0] != "db-minor-update 3306" {
		t.Errorf("asked %v", e.asked)
	}
	// Not allowed: refused before the helper is asked.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("security\n"), 0o644)
	e.asked = nil
	if _, err := e.a.runTask(context.Background(), &protocol.Task{ID: "t2", Type: protocol.TaskPGUpdate, Database: &db}, &taskLog{}); err == nil || len(e.asked) != 0 {
		t.Errorf("not allowed: %v %v", err, e.asked)
	}
}

func TestEngineSoftware(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("27017 mongod.service\n"), 0o644)
	eng := &versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineMongoDB}, tries: 5}, version: "7.0.40"}
	withEngine(t, eng)
	e.a.watched = []protocol.DatabaseSpec{{ID: "db_g", Port: 27017, Engine: protocol.EngineMongoDB}}
	e.run.outs["dpkg-query -W -f=${Version} mongodb-org-server"] = "7.0.40"
	e.run.outs["apt-cache madison mongodb-org-server"] = " mongodb-org-server |     7.0.43 | https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0/multiverse arm64 Packages\n" +
		" mongodb-org-server |     7.0.41 | https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0/multiverse arm64 Packages\n" +
		" mongodb-org-server |     8.0.4 | https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/8.0/multiverse arm64 Packages\n"
	cs := e.a.engineSoftware(context.Background())
	if len(cs) != 1 {
		t.Fatalf("%+v", cs)
	}
	c := cs[0]
	if c.Engine != "mongodb" || c.Series != "7.0" || c.Installed != "7.0.40" || c.Candidate != "7.0.43" || c.Running != "7.0.40" ||
		strings.Join(c.NextSeries, ",") != "8.0" || c.Unit != "mongod.service" || c.Major != 700 || len(c.Majors) != 1 || c.Majors[0] != 800 {
		t.Errorf("%+v", c)
	}
	if seriesOf("1:10.11.9+maria~deb12") != "10.11" || upstreamVersion("25.8.15.35") != "25.8.15.35" || seriesOf("8.0.39-0ubuntu0.24.04.2") != "8.0" {
		t.Error("versions")
	}
}

// upgradeEngine is a ClickHouse engine that can be upgraded.
type upgradeEngine struct {
	versionEngine
	rehearsed, after string
}

func (u *upgradeEngine) UpgradeIssues(_ context.Context, _ EngineEnv, _ protocol.DatabaseSpec, from, to string) ([]string, []string, error) {
	return nil, []string{"read the release notes of " + to}, nil
}
func (u *upgradeEngine) ServerPackages(string) []string { return []string{"clickhouse-common-static"} }
func (u *upgradeEngine) RehearseUpgrade(_ context.Context, _ EngineEnv, _ protocol.DatabaseSpec, root, to string, res *protocol.UpgradeRehearsalResult, _ TaskLogger) error {
	u.rehearsed = to
	res.Passed = true
	return nil
}
func (u *upgradeEngine) AfterUpgrade(_ context.Context, _ EngineEnv, _ protocol.DatabaseSpec, to string, _ TaskLogger) error {
	u.after = to
	return nil
}

func TestEngineUpgrade(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("9000 clickhouse-server.service\n"), 0o644)
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("database\n"), 0o644)
	os.WriteFile(e.a.cfg.RestartHelper, []byte("#!/bin/sh\n# update-actions: db-minor-update db-upgrade db-upgrade-undo db-upgrade-cleanup\n"), 0o755)
	eng := &upgradeEngine{versionEngine: versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineClickHouse}, tries: 5}, version: "25.3.14.14"}}
	withEngine(t, eng)
	db := protocol.DatabaseSpec{ID: "db_c", Name: "events", Port: 9000, Engine: protocol.EngineClickHouse}
	e.a.watched = []protocol.DatabaseSpec{db}
	e.a.cfg.DrillDir = t.TempDir()
	e.run.outs["dpkg-query -W -f=${Version} clickhouse-server"] = "25.3.14.14"
	e.run.outs["apt-cache madison clickhouse-server"] = " clickhouse-server | 25.8.33.6 | x\n clickhouse-server | 25.3.14.14 | x\n"
	e.run.outs["apt-cache madison clickhouse-common-static"] = " clickhouse-common-static | 25.8.33.6 | x\n"
	run := func(typ string, p any) (any, error) {
		raw, _ := json.Marshal(p)
		return e.a.runTask(context.Background(), &protocol.Task{ID: "t_" + typ, Type: typ, Database: &db, Params: raw}, &taskLog{})
	}
	res, err := run(protocol.TaskUpgradeCheck, protocol.UpgradeCheckParams{})
	if err != nil {
		t.Fatal(err)
	}
	chk := res.(*protocol.UpgradeCheckResult)
	if chk.FromMajor != 2503 || chk.ToMajor != 2508 || !chk.CanRehearse || !chk.CanUpgrade || chk.ToVersion != "25.8.33.6" {
		t.Fatalf("check %+v", chk)
	}
	res, err = run(protocol.TaskUpgradeRehearsal, protocol.UpgradeRehearsalParams{ToMajor: 2508})
	if err != nil || !res.(*protocol.UpgradeRehearsalResult).Passed || eng.rehearsed != "25.8" {
		t.Fatalf("rehearsal %+v %v", res, err)
	}
	e.helper = func(id string, args []string) map[string]string {
		switch args[0] {
		case "db-upgrade":
			eng.version = "25.8.33.6"
			return map[string]string{"id": id, "ok": "1", "downtime_seconds": "12", "kept_bytes": "1000", "datadir": "/var/lib/clickhouse"}
		case "db-upgrade-undo":
			eng.version = "25.3.14.14"
			return map[string]string{"id": id, "ok": "1", "downtime_seconds": "9"}
		}
		return map[string]string{"id": id, "ok": "1", "freed_bytes": "2000"}
	}
	res, err = run(protocol.TaskUpgrade, protocol.UpgradeParams{UpgradeID: "up1", ToMajor: 2508, Mode: protocol.UpgradeSafe})
	if err != nil {
		t.Fatal(err)
	}
	if up := res.(*protocol.UpgradeResult); up.ToVersion != "25.8.33.6" || up.DowntimeMs != 12000 || eng.after != "25.8" || e.asked[len(e.asked)-1] != "db-upgrade 9000 25.8" {
		t.Fatalf("upgrade %+v %v", up, e.asked)
	}
	if st := e.a.upgradeState().states(); len(st) != 1 || st[0].Status != protocol.UpgradeDone || st[0].ToMajor != 2508 {
		t.Fatalf("states %+v", st)
	}
	if _, err := run(protocol.TaskUpgradeUndo, protocol.UpgradeUndoParams{UpgradeID: "up1"}); err != nil {
		t.Fatal(err)
	}
	if st := e.a.upgradeState().states(); len(st) != 1 || st[0].Status != protocol.UpgradeUndone {
		t.Fatalf("states after undo %+v", st)
	}
	if _, err := run(protocol.TaskUpgradeCleanup, protocol.UpgradeCleanupParams{UpgradeID: "up1"}); err != nil {
		t.Fatal(err)
	}
	if st := e.a.upgradeState().states(); len(st) != 0 {
		t.Fatalf("states after cleanup %+v", st)
	}
}

// Debian's redis-server: the security source ships fixes of the same
// release (7.0.15-1~deb12u7 -> deb12u10), a package update.
func TestEngineSoftwareRedisDebian(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("6379 redis-server.service\n"), 0o644)
	eng := &versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineRedis}, tries: 5}, version: "7.0.15"}
	withEngine(t, eng)
	e.a.watched = []protocol.DatabaseSpec{{ID: "db_r", Port: 6379, Engine: protocol.EngineRedis}}
	e.run.outs["dpkg-query -W -f=${Version} redis-server"] = "5:7.0.15-1~deb12u7"
	e.run.outs["apt-cache madison redis-server"] = "redis-server | 5:7.0.15-1~deb12u10 | http://deb.debian.org/debian-security bookworm-security/main arm64 Packages\n" +
		"redis-server | 5:7.0.15-1~deb12u7 | http://deb.debian.org/debian bookworm/main arm64 Packages\n"
	cs := e.a.engineSoftware(context.Background())
	if len(cs) != 1 {
		t.Fatalf("%+v", cs)
	}
	c := cs[0]
	if c.Engine != "redis" || c.Series != "7.0" || c.Installed != "7.0.15" || c.Candidate != "7.0.15" || c.CandidatePackage != "5:7.0.15-1~deb12u10" ||
		!c.PackageUpdate || !c.SecurityUpdate || c.Major != 700 || c.Unit != "redis-server.service" {
		t.Errorf("%+v", c)
	}
	// packages.redis.io: a newer release of the series, not a security source.
	e.run.outs["dpkg-query -W -f=${Version} redis-server"] = "6:8.2.1-1rl1~bookworm1"
	e.run.outs["apt-cache madison redis-server"] = "redis-server | 6:8.4.0-1rl1~bookworm1 | https://packages.redis.io/deb bookworm/main arm64 Packages\n" +
		"redis-server | 6:8.2.10-1rl1~bookworm1 | https://packages.redis.io/deb bookworm/main arm64 Packages\n" +
		"redis-server | 6:8.2.2-1rl1~bookworm1 | https://packages.redis.io/deb bookworm/main arm64 Packages\n" +
		"redis-server | 6:8.2.1-1rl1~bookworm1 | https://packages.redis.io/deb bookworm/main arm64 Packages\n"
	eng.version = "8.2.1"
	c = e.a.engineSoftware(context.Background())[0]
	if c.Candidate != "8.2.10" || c.PackageUpdate || c.SecurityUpdate || strings.Join(c.NextSeries, ",") != "8.4" {
		t.Errorf("%+v", c)
	}
	// Up to date, listed by both sources: nothing to install.
	e.run.outs["dpkg-query -W -f=${Version} redis-server"] = "5:7.0.15-1~deb12u10"
	e.run.outs["apt-cache madison redis-server"] = "redis-server | 5:7.0.15-1~deb12u10 | http://deb.debian.org/debian bookworm/main arm64 Packages\n" +
		"redis-server | 5:7.0.15-1~deb12u10 | http://deb.debian.org/debian-security bookworm-security/main arm64 Packages\n"
	eng.version = "7.0.15"
	if c = e.a.engineSoftware(context.Background())[0]; c.PackageUpdate || c.SecurityUpdate || c.Candidate != "7.0.15" {
		t.Errorf("%+v", c)
	}
}

// bundledEngine is a Redis engine whose sidecar image bundles a version.
type bundledEngine struct {
	versionEngine
	bundled string
}

func (b *bundledEngine) BundledVersion(context.Context) (string, error) { return b.bundled, nil }

// A Redis sidecar: the version bundled in the agent's image is the newest
// Rowsafe knows for the series.
func TestEngineContainerSoftware(t *testing.T) {
	e := newUpgradeEnv(t)
	e.a.cfg.ImageVariant = "redis8.2"
	eng := &bundledEngine{versionEngine: versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineRedis}, tries: 5}, version: "8.2.1"}, bundled: "8.2.3"}
	withEngine(t, eng)
	e.a.watched = []protocol.DatabaseSpec{{ID: "db_r", Port: 6379, Engine: protocol.EngineRedis}}
	r := e.a.buildSoftware(context.Background())
	if !r.Container || len(r.Clusters) != 1 {
		t.Fatalf("%+v", r)
	}
	c := r.Clusters[0]
	if c.Running != "8.2.1" || c.Candidate != "8.2.3" || c.CandidateSource != protocol.CandidateAgentImage || c.Series != "8.2" || c.Installed != "" || c.Major != 802 {
		t.Errorf("%+v", c)
	}
	// Another series in the image than on the server: nothing known.
	eng.bundled = "7.4.6"
	if c = e.a.buildSoftware(context.Background()).Clusters[0]; c.Candidate != "8.2.1" || c.CandidateSource != "" {
		t.Errorf("%+v", c)
	}
	// The image is older than the server: the running version is the newest.
	eng.bundled = "8.2.0"
	if c = e.a.buildSoftware(context.Background()).Clusters[0]; c.Candidate != "8.2.1" {
		t.Errorf("%+v", c)
	}
}

// A Redis server Rowsafe can't follow keeps its snapshots: the update isn't
// a failure, and the summary says so.
func TestEngineUpdateRedisSnapshots(t *testing.T) {
	e := newUpgradeEnv(t)
	os.WriteFile(e.a.cfg.RestartAllowFile, []byte("6379 redis-server.service\n"), 0o644)
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("database\n"), 0o644)
	os.WriteFile(e.a.cfg.RestartHelper, []byte("#!/bin/sh\n# update-actions: security-updates reboot db-minor-update\n"), 0o755)
	eng := &snapshotsEngine{versionEngine: versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineRedis}, tries: 5}, version: "7.0.15"}}
	withEngine(t, eng)
	db := protocol.DatabaseSpec{ID: "db_r", Name: "cache", Port: 6379, Engine: protocol.EngineRedis}
	e.helper = func(id string, args []string) map[string]string {
		return map[string]string{"id": id, "ok": "1", "package": "5:7.0.15-1~deb12u10", "packages": "redis-server redis-tools", "restarted": "1"}
	}
	res, err := e.a.runTask(context.Background(), &protocol.Task{ID: "t1", Type: protocol.TaskPGUpdate, Database: &db}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*protocol.PGUpdateResult)
	if !r.ArchivingOK || len(r.Warnings) != 0 || !strings.HasPrefix(r.Summary, "Installed the newest Redis 7.0.15 package (5:7.0.15-1~deb12u10) and restarted Redis") ||
		!strings.HasSuffix(r.Summary, "Backups continue as scheduled snapshots, as before.") {
		t.Errorf("%+v", r)
	}
	if e.asked[0] != "db-minor-update 6379" {
		t.Errorf("asked %v", e.asked)
	}
}

// snapshotsEngine answers after a restart in snapshots mode.
type snapshotsEngine struct{ versionEngine }

func (s *snapshotsEngine) Ready(context.Context, EngineEnv, protocol.DatabaseSpec) (string, error) {
	return protocol.RedisArchiveSnapshots, nil
}

func TestDebCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"5:7.0.15-1~deb12u10", "5:7.0.15-1~deb12u7", 1},
		{"6:8.2.10-1rl1~bookworm1", "6:8.2.2-1rl1~bookworm1", 1},
		{"8.1.1+dfsg1-3+deb13u2", "8.1.1+dfsg1-3+deb13u2", 0},
		{"1.0~rc1", "1.0", -1},
		{"1:1.0", "2.0", 1},
		{"8.0.40-1debian12", "8.0.43-1debian12", -1},
		{"1:10.11.6-0+deb12u1", "1:10.11.9+maria~deb12", -1},
		{"7.0.15-1", "7.0.15-1build1", -1},
	} {
		if got := debCompare(c.a, c.b); got != c.want {
			t.Errorf("debCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := debCompare(c.b, c.a); got != -c.want {
			t.Errorf("debCompare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}
