package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestForkAutoConf(t *testing.T) {
	got := forkAutoConf(5441, 17, map[string]int{"max_connections": 200}, "pg_stat_statements", true)
	for _, want := range []string{"port = '5441'", "archive_mode = 'on'", "archive_command = 'true'", "archive_library = ''",
		"max_connections = '200'", "shared_preload_libraries = 'pg_stat_statements'"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if strings.Contains(forkAutoConf(5441, 14, nil, "", false), "archive_library") {
		t.Error("archive_library doesn't exist before PostgreSQL 15")
	}
	if strings.Contains(forkAutoConf(5441, 17, nil, "", false), "shared_preload_libraries") {
		t.Error("preload set without a reason")
	}
}

func TestInstalledPreload(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"pg_stat_statements.so", "pg_cron.so"} {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	keep, missing := installedPreload(`pg_stat_statements, "timescaledb", pg_cron`, dir)
	if keep != "pg_stat_statements,pg_cron" || len(missing) != 1 || missing[0] != "timescaledb" {
		t.Fatalf("keep %q missing %v", keep, missing)
	}
}

func TestCreateClusterPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allow")
	if _, _, ok := createClusterPorts(path); ok {
		t.Fatal("missing file allowed")
	}
	for content, want := range map[string]bool{
		"# comment\nports 5440-5499\n": true, "ports 80-90\n": false, "ports 5499-5440\n": false, "ports x\n": false,
		"# Creating PostgreSQL clusters for forks is off\n": false,
	} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		lo, hi, ok := createClusterPorts(path)
		if ok != want || (ok && (lo != 5440 || hi != 5499)) {
			t.Errorf("%q: %d %d %v", content, lo, hi, ok)
		}
	}
}

func TestForkClusterNameAndLayout(t *testing.T) {
	old := debianConfRoot
	debianConfRoot = t.TempDir()
	t.Cleanup(func() { debianConfRoot = old })
	if n := forkClusterName("shop-staging", 18); n != "shop_staging" {
		t.Fatal(n)
	}
	conf := filepath.Join(debianConfRoot, "18", "shop_staging")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	if n := forkClusterName("shop-staging", 18); n != "shop_staging_2" {
		t.Fatal(n)
	}
	if err := os.WriteFile(filepath.Join(conf, "postgresql.conf"), []byte("data_directory = '/var/lib/postgresql/18/shop_staging'\n"+
		"hba_file = '/etc/postgresql/18/shop_staging/pg_hba.conf'\nport = 5440\nunix_socket_directories = '/var/run/postgresql'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := readCreatedCluster(18, "shop_staging")
	if err != nil || c.DataDir != "/var/lib/postgresql/18/shop_staging" || c.Unit != "postgresql@18-shop_staging.service" ||
		c.HbaFile != "/etc/postgresql/18/shop_staging/pg_hba.conf" || c.SocketDir != "/var/run/postgresql" {
		t.Fatalf("%+v %v", c, err)
	}
	if !debianClusterPorts()[5440] {
		t.Fatal("port of the Debian cluster not seen")
	}
}

func TestMaskSuggest(t *testing.T) {
	cases := []struct{ table, column, typ, want string }{
		{"public.users", "email", "text", maskEmail},
		{"public.users", "EmailAddress", "character varying(255)", maskEmail},
		{"public.users", "name", "text", maskFullName},
		{"public.products", "name", "text", ""},
		{"public.customers", "first_name", "text", maskFirstName},
		{"public.customers", "phone_number", "text", maskFormat},
		{"public.users", "encrypted_password", "character varying", maskPassword},
		{"public.sessions", "ip", "inet", maskIP},
		{"public.users", "last_sign_in_ip", "text", maskIP},
		{"public.users", "date_of_birth", "date", maskDateShift},
		{"public.orders", "total", "numeric(10,2)", ""},
		{"public.addresses", "street", "text", maskAddress},
		{"public.orders", "id", "bigint", ""},
	}
	for _, c := range cases {
		if got := maskSuggest(c.table, c.column, c.typ); got != c.want {
			t.Errorf("%s.%s %s: %q, want %q", c.table, c.column, c.typ, got, c.want)
		}
	}
}

func TestMaskExpr(t *testing.T) {
	if _, ok := maskExpr(maskEmail, `"total"`, "numeric", true, false); ok {
		t.Error("email on a number")
	}
	if _, ok := maskExpr(maskNull, `"email"`, "text", false, false); ok {
		t.Error("NULL into a NOT NULL column")
	}
	e, ok := maskExpr(maskEmail, `"email"`, "character varying(64)", true, false)
	if !ok || !strings.Contains(e, "@example.com") || !strings.Contains(e, "left(") || !strings.Contains(e, ", 64)") {
		t.Fatalf("%s", e)
	}
	u, _ := maskExpr(maskFullName, `"name"`, "text", true, true)
	if !strings.Contains(u, "substr(md5(") {
		t.Fatalf("unique name not made unique: %s", u)
	}
	if formatCount(1204) != "1,204" || formatCount(48210) != "48,210" || formatCount(7) != "7" {
		t.Fatal("formatCount")
	}
}

// fakeForkOps runs a fork restore without PostgreSQL, pgBackRest or the
// helper; files and renames are real.
type fakeForkOps struct {
	dataDir    string
	up         bool
	restoreErr error
	calls      []string
}

func (f *fakeForkOps) facts(ctx context.Context, db protocol.DatabaseSpec) (inPlaceFacts, error) {
	return inPlaceFacts{DataDir: f.dataDir, Major: 17, ConfigFile: filepath.Join(f.dataDir, "postgresql.conf"),
		HbaFile: filepath.Join(f.dataDir, "pg_hba.conf")}, nil
}
func (f *fakeForkOps) usage(ctx context.Context, db protocol.DatabaseSpec) (clusterUsage, error) {
	return clusterUsage{Settings: map[string]int{"max_connections": 100}}, nil
}
func (f *fakeForkOps) sourceFacts(ctx context.Context, db protocol.DatabaseSpec) (primaryFacts, error) {
	return primaryFacts{clusterFacts: clusterFacts{Major: 17}, SizeBytes: 1 << 20, Settings: map[string]int{"max_connections": 300}}, nil
}
func (f *fakeForkOps) helper(ctx context.Context, action string, port int, id string) error {
	f.calls = append(f.calls, action)
	f.up = action == helperStart
	return nil
}
func (f *fakeForkOps) createCluster(ctx context.Context, port, major int, name, id string) (string, error) {
	return "", errors.New("not in this test")
}
func (f *fakeForkOps) stopLocal(string, int) error {
	f.up = false
	return nil
}
func (f *fakeForkOps) freeBytes(string) (int64, error) { return 1 << 40, nil }
func (f *fakeForkOps) sourceInfo(ctx context.Context, cli pgbackrest.CLI) ([]pgbackrest.Stanza, error) {
	f.calls = append(f.calls, "info "+cli.Stanza)
	return []pgbackrest.Stanza{{Name: cli.Stanza, Backup: []pgbackrest.BackupInfo{{Label: "20260924-010000F"}}}}, nil
}
func (f *fakeForkOps) restore(ctx context.Context, cli pgbackrest.CLI, o pgbackrest.RestoreOptions) ([]byte, error) {
	f.calls = append(f.calls, "restore "+o.Type+" "+o.Target)
	conf, err := os.ReadFile(cli.ConfigPath)
	if err != nil || !strings.Contains(string(conf), "repo1-cipher-pass=") {
		return nil, errors.New("no source config")
	}
	if f.restoreErr != nil {
		return nil, f.restoreErr
	}
	_ = os.WriteFile(filepath.Join(o.DataDir, "PG_VERSION"), []byte("17\n"), 0o600)
	_ = os.WriteFile(filepath.Join(o.DataDir, "postgresql.conf"), []byte("# the source's\n"), 0o600)
	return nil, os.WriteFile(filepath.Join(o.DataDir, "postgresql.auto.conf"), []byte("restore_command = 'x'\n"), 0o600)
}
func (f *fakeForkOps) recover(ctx context.Context, pr privateRecovery, during func(context.Context, pginspect.Target) error) (*time.Time, error) {
	f.calls = append(f.calls, "recover")
	at := time.Date(2026, 9, 24, 14, 4, 0, 0, time.UTC)
	return &at, nil
}
func (f *fakeForkOps) waitReady(ctx context.Context, db protocol.DatabaseSpec, dataDir string, timeout time.Duration) error {
	return nil
}
func (f *fakeForkOps) databases(ctx context.Context, db protocol.DatabaseSpec) ([]protocol.DBInfo, error) {
	return []protocol.DBInfo{{Name: "app", SizeBytes: 4096}}, nil
}

func (f *fakeForkOps) running(string) bool { return f.up }

func forkTestAgent(t *testing.T, ops forkOps) (*Agent, string) {
	t.Helper()
	root := t.TempDir()
	bin := filepath.Join(root, "pg", "17", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(bin, "postgres"), nil, 0o755)
	helper := filepath.Join(root, "helper")
	_ = os.WriteFile(helper, []byte("#!/bin/sh\n# actions: restart stop start create-cluster\n"), 0o755)
	allow := filepath.Join(root, "restart-allowed")
	_ = os.WriteFile(allow, []byte("5433 postgresql@17-empty.service\n"), 0o644)
	// A short state directory: the private socket's path must fit.
	state, err := os.MkdirTemp("/tmp", "rsf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(state) })
	cfg := Config{StateDir: state, ConfigDir: filepath.Join(root, "conf"), LogDir: filepath.Join(root, "log"),
		PGBinDir: filepath.Join(root, "pg", "%d", "bin"), PGUser: "postgres", PgBackRestBin: "/usr/bin/pgbackrest",
		RestartAllowFile: allow, CreatedClustersFile: filepath.Join(root, "created"), RestartDir: filepath.Join(state, "restart"),
		RestartHelper: helper, Standby: StandbyOn, Mode: ModeNative,
		Repo: pgbackrest.Repo{Endpoint: "s3.example.com", Bucket: "b", Key: "k", KeySecret: "s", CipherPass: "a-long-enough-cipher-passphrase"}}
	_ = os.MkdirAll(cfg.RestartDir, 0o700)
	a := &Agent{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil)), fkOps: ops}
	clusters := filepath.Join(root, "clusters")
	return a, clusters
}

func TestForkRestoreEmptyCluster(t *testing.T) {
	ops := &fakeForkOps{up: true}
	a, clusters := forkTestAgent(t, ops)
	ops.dataDir = filepath.Join(clusters, "17", "empty")
	if err := os.MkdirAll(ops.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(ops.dataDir, "PG_VERSION"), []byte("17\n"), 0o600)
	_ = os.WriteFile(filepath.Join(ops.dataDir, "postgresql.conf"), []byte("port = 5433 # its own\n"), 0o600)
	at := time.Date(2026, 9, 24, 14, 4, 0, 0, time.UTC)
	p := protocol.ForkRestoreParams{ForkID: "fork_1", Name: "shop-staging", Source: protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop", Port: 5432},
		Target: protocol.RewindTarget{Time: &at, BackupSet: "20260924-010000F"}, Placement: protocol.ForkEmptyCluster, Port: 5433}
	res, err := a.forkRestore(context.Background(), p, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Port != 5433 || res.RecoveredTo == nil || len(res.Databases) != 1 || res.KeptDataDir == "" || !strings.Contains(res.Summary, "restored to the last change at 14:04:00") {
		t.Fatalf("%+v", res)
	}
	auto, _ := os.ReadFile(filepath.Join(ops.dataDir, "postgresql.auto.conf"))
	for _, want := range []string{"port = '5433'", "archive_command = 'true'", "max_connections = '300'"} {
		if !strings.Contains(string(auto), want) {
			t.Errorf("auto.conf lacks %q:\n%s", want, auto)
		}
	}
	if conf, _ := os.ReadFile(filepath.Join(ops.dataDir, "postgresql.conf")); !strings.Contains(string(conf), "its own") {
		t.Error("the cluster's own postgresql.conf wasn't kept")
	}
	if entries, _ := filepath.Glob(filepath.Join(a.cfg.ConfigDir, "fork-*")); len(entries) != 0 {
		t.Errorf("the source's settings were left behind: %v", entries)
	}
	if strings.Join(ops.calls, ",") != "info shop,stop,restore time 2026-09-24 14:04:00+00,recover,start" {
		t.Errorf("calls %v", ops.calls)
	}
	if len(a.fk().running()) != 0 || len(a.fk().file.Kept) != 1 {
		t.Fatalf("state %+v", a.fk().file)
	}
}

func TestForkRestoreRollsBack(t *testing.T) {
	ops := &fakeForkOps{up: true, restoreErr: errors.New("bucket unreachable")}
	a, clusters := forkTestAgent(t, ops)
	ops.dataDir = filepath.Join(clusters, "17", "empty")
	_ = os.MkdirAll(ops.dataDir, 0o700)
	_ = os.WriteFile(filepath.Join(ops.dataDir, "PG_VERSION"), []byte("17\n"), 0o600)
	_ = os.WriteFile(filepath.Join(ops.dataDir, "marker"), []byte("own"), 0o600)
	p := protocol.ForkRestoreParams{ForkID: "fork_2", Name: "shop-staging", Source: protocol.DatabaseSpec{ID: "db_1", Stanza: "shop", Port: 5432},
		Target: protocol.RewindTarget{Mark: "before-migration", BackupSet: "20260924-010000F"}, Placement: protocol.ForkEmptyCluster, Port: 5433}
	res, err := a.forkRestore(context.Background(), p, &taskLog{})
	if err == nil || !strings.Contains(err.Error(), "own data back") || res == nil {
		t.Fatalf("%v %+v", err, res)
	}
	if data, _ := os.ReadFile(filepath.Join(ops.dataDir, "marker")); string(data) != "own" {
		t.Fatal("the cluster's own data isn't back")
	}
	if !ops.up {
		t.Fatal("the cluster wasn't started again")
	}
	if left, _ := filepath.Glob(ops.dataDir + ".*"); len(left) != 0 {
		t.Fatalf("left behind: %v", left)
	}
	if len(a.fk().running()) != 0 {
		t.Fatal("the fork is still recorded as running")
	}
}

func TestForkRestoreRefusesNonEmptyAndBadInput(t *testing.T) {
	a, _ := forkTestAgent(t, &fakeForkOps{})
	at := time.Now().Add(-time.Hour)
	base := protocol.ForkRestoreParams{ForkID: "fork_3", Name: "shop-staging", Source: protocol.DatabaseSpec{Stanza: "shop", Port: 5432},
		Target: protocol.RewindTarget{Time: &at}, Placement: protocol.ForkEmptyCluster, Port: 5499}
	for name, mut := range map[string]func(p *protocol.ForkRestoreParams){
		"bad name":       func(p *protocol.ForkRestoreParams) { p.Name = "Shop Staging" },
		"no point":       func(p *protocol.ForkRestoreParams) { p.Target = protocol.RewindTarget{} },
		"not allowed":    func(p *protocol.ForkRestoreParams) {},
		"bad placement":  func(p *protocol.ForkRestoreParams) { p.Placement = "somewhere" },
		"docker here":    func(p *protocol.ForkRestoreParams) { p.Placement = protocol.ForkDocker },
		"no create here": func(p *protocol.ForkRestoreParams) { p.Placement = protocol.ForkNewCluster },
	} {
		p := base
		mut(&p)
		if _, err := a.forkRestore(context.Background(), p, &taskLog{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestForkPrepareChecksFingerprint(t *testing.T) {
	a, _ := forkTestAgent(t, &fakeForkOps{})
	other, _ := handoff.Generate()
	p := protocol.ForkPrepareParams{ForkID: "fork_4", Source: protocol.DatabaseSpec{ID: "db_1", Stanza: "shop", Port: 5432},
		RecipientKey: other.PublicKey(), RecipientFingerprint: "0000-0000-0000-0000"}
	if _, err := a.forkPrepare(context.Background(), p, &taskLog{}); err == nil || !strings.Contains(err.Error(), "nothing was sent") {
		t.Fatalf("%v", err)
	}
	a.cfg.Standby = StandbyOff
	if _, err := a.forkPrepare(context.Background(), p, &taskLog{}); err == nil || !strings.Contains(err.Error(), "turned off") {
		t.Fatalf("%v", err)
	}
}

func TestValidKeptForkDir(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "main")
	kept := data + ".before-fork-20260924T140400Z"
	_ = os.Mkdir(kept, 0o700)
	if err := validKeptForkDir(data, kept); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{filepath.Join(root, "other.before-fork-20260924T140400Z"), data + ".before-rewind-20260924T140400Z", "/etc"} {
		if validKeptForkDir(data, bad) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
