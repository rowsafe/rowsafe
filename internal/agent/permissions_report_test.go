package agent

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// permTestPaths is a server with PostgreSQL 17 and no allow files yet.
func permTestPaths(t *testing.T) PermissionPaths {
	t.Helper()
	dir := t.TempDir()
	pg := filepath.Join(dir, "pg")
	if err := os.MkdirAll(filepath.Join(pg, "17", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	permWriteFile(t, filepath.Join(pg, "17", "bin", "postgres"), "")
	return PermissionPaths{
		RestartAllowFile:       filepath.Join(dir, "restart-allowed"),
		CreateClusterAllowFile: filepath.Join(dir, "create-cluster-allowed"),
		UpdatesAllowFile:       filepath.Join(dir, "updates-allowed"),
		PoolerAllowFile:        filepath.Join(dir, "pooler-allowed"),
		FirewallAllowFile:      filepath.Join(dir, "firewall-allowed"),
		TuningAllowFile:        filepath.Join(dir, "tuning-allowed"),
		OwnersFile:             filepath.Join(dir, "owners"),
		AllowCommand:           filepath.Join(dir, "rowsafe-allow"),
		PGRoot:                 pg,
	}
}

func permWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stubPermHave(t *testing.T, have ...string) {
	t.Helper()
	old := permHave
	have = append(have, "mongod") // Tuning applies (a MongoDB here too)
	permHave = func(name string) bool { return slices.Contains(have, name) }
	t.Cleanup(func() { permHave = old })
}

func TestReadPermissionsNeverAsked(t *testing.T) {
	stubPermHave(t, "pg_createcluster", "nft", "apt-get")
	r := ReadPermissions(permTestPaths(t))
	if r.Allowed == nil || len(r.Allowed) != 0 || len(r.Denied) != 0 || len(r.Unavailable) != 0 || r.AllowCommand || len(r.Owners) != 0 {
		t.Fatalf("report = %+v", r)
	}
}

func TestReadPermissions(t *testing.T) {
	stubPermHave(t, "pg_createcluster", "apt-get") // no nftables
	p := permTestPaths(t)
	permWriteFile(t, p.RestartAllowFile, "# PostgreSQL clusters Rowsafe may restart\n# PORT UNIT\n5432 postgresql@17-main.service\n")
	permWriteFile(t, p.CreateClusterAllowFile, "# Creating PostgreSQL clusters for forks is off on this server.\n")
	permWriteFile(t, p.UpdatesAllowFile, "# What Rowsafe may install (postgresql, security, reboot)\npostgresql   # PostgreSQL minor updates\nsecurity     # security updates\n")
	permWriteFile(t, p.PoolerAllowFile, "# PostgreSQL clusters ... \"public\": PgBouncer may listen\n# PORT\n5432\n")
	permWriteFile(t, p.FirewallAllowFile, "# Limiting who can reach PostgreSQL with the firewall is off for Rowsafe.\n")
	permWriteFile(t, p.OwnersFile, `[
  {"credential_id": "Y3JlZC0x", "public_key": "pQECAyYgASFYIA", "alg": -7, "name": "ana@example.com",
   "fingerprint": "3F2A-91C3-0B7E-55D4", "rp_id": "app.rowsafe.sh", "origin": "https://app.rowsafe.sh",
   "added_at": "2026-10-01T10:00:00Z"},
  {"credential_id": "", "name": "broken"}
]`)
	r := ReadPermissions(p)
	if want := []string{protocol.PermRestart, protocol.PermPooler, protocol.PermUpdates, protocol.PermSecurityUpdates}; !slices.Equal(r.Allowed, want) {
		t.Errorf("allowed = %v, want %v", r.Allowed, want)
	}
	if want := []string{protocol.PermCreateCluster, protocol.PermPoolerPublic, protocol.PermFirewall, protocol.PermReboot}; !slices.Equal(r.Denied, want) {
		t.Errorf("denied = %v, want %v", r.Denied, want)
	}
	if len(r.Unavailable) != 1 || r.Unavailable[protocol.PermFirewall] != permReasonNoNft {
		t.Errorf("unavailable = %v", r.Unavailable)
	}
	want := protocol.PermissionOwner{CredentialID: "Y3JlZC0x", Name: "ana@example.com", Fingerprint: "3F2A-91C3-0B7E-55D4", AddedAt: time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)}
	if len(r.Owners) != 1 || r.Owners[0] != want {
		t.Errorf("owners = %+v", r.Owners)
	}

	// PgBouncer on public addresses; the firewall allowed for a port.
	permWriteFile(t, p.PoolerAllowFile, "5432\npublic\n")
	permWriteFile(t, p.FirewallAllowFile, "# PORT\n5432\n")
	r = ReadPermissions(p)
	for _, name := range []string{protocol.PermPoolerPublic, protocol.PermFirewall} {
		if !slices.Contains(r.Allowed, name) {
			t.Errorf("%s not allowed: %+v", name, r)
		}
	}
	if r.Unavailable != nil {
		t.Errorf("an allowed permission is listed unavailable: %v", r.Unavailable)
	}

	// "public" without a port: PgBouncer isn't allowed at all.
	permWriteFile(t, p.PoolerAllowFile, "public\n")
	r = ReadPermissions(p)
	if slices.Contains(r.Allowed, protocol.PermPoolerPublic) || !slices.Contains(r.Denied, protocol.PermPooler) {
		t.Errorf("public without a port: %+v", r)
	}

	// Garbage owners file: no owners, no failure.
	permWriteFile(t, p.OwnersFile, "not json")
	if r = ReadPermissions(p); r.Owners != nil {
		t.Errorf("owners from garbage: %+v", r.Owners)
	}
}

func TestPermissionsUnavailable(t *testing.T) {
	stubPermHave(t) // nothing installed
	p := permTestPaths(t)
	r := ReadPermissions(p)
	for name, why := range map[string]string{
		protocol.PermCreateCluster:   permReasonNoCluster,
		protocol.PermFirewall:        permReasonNoNft,
		protocol.PermUpdates:         permReasonNoApt,
		protocol.PermSecurityUpdates: permReasonNoApt,
		protocol.PermReboot:          permReasonNoApt,
	} {
		if r.Unavailable[name] != why {
			t.Errorf("%s: %q, want %q", name, r.Unavailable[name], why)
		}
	}
	if _, ok := r.Unavailable[protocol.PermRestart]; ok {
		t.Errorf("restart unavailable: %v", r.Unavailable)
	}

	// No PostgreSQL (a MySQL server): only the firewall applies, and what
	// needs an unavailable permission is unavailable too.
	if err := os.RemoveAll(p.PGRoot); err != nil {
		t.Fatal(err)
	}
	stubPermHave(t, "pg_createcluster", "nft", "apt-get")
	r = ReadPermissions(p)
	for _, name := range protocol.Permissions {
		want := permReasonPostgresOnly
		if anyEnginePermission[name] {
			want = ""
		}
		if r.Unavailable[name] != want {
			t.Errorf("%s: %q", name, r.Unavailable[name])
		}
	}
	got := permissionsUnavailable(PermissionPaths{PGRoot: t.TempDir()}, nil)
	if got[protocol.PermRestart] != permReasonPostgresOnly {
		t.Errorf("no PostgreSQL: %v", got)
	}
}

func TestPermissionsNeedsPropagate(t *testing.T) {
	// Only apt is missing: reboot needs security-updates, both unavailable
	// for the same reason; restart and the rest stay available.
	stubPermHave(t, "pg_createcluster", "nft")
	got := permissionsUnavailable(permTestPaths(t), nil)
	if len(got) != 3 || got[protocol.PermReboot] != permReasonNoApt {
		t.Fatalf("unavailable = %v", got)
	}
	// An allowed permission is never listed, whatever the server lacks.
	got = permissionsUnavailable(permTestPaths(t), []string{protocol.PermUpdates})
	if _, ok := got[protocol.PermUpdates]; ok {
		t.Errorf("allowed but unavailable: %v", got)
	}
}

func TestRootOwnedExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rowsafe-allow")
	if rootOwnedExecutable(path) {
		t.Error("a missing file counts as the command")
	}
	permWriteFile(t, path, "#!/bin/sh\n")
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, root := rootOwnedExecutable(path), os.Geteuid() == 0; got != root {
		t.Errorf("rootOwnedExecutable = %v as uid %d", got, os.Geteuid())
	}
	if rootOwnedExecutable("/") {
		t.Error("a directory counts as the command")
	}
	want := "the Rowsafe installer with --allow-restart"
	if rootOwnedExecutable("/usr/local/sbin/rowsafe-allow") {
		want = "sudo rowsafe-allow restart"
	}
	if got := AllowHint("restart"); got != want {
		t.Errorf("hint = %q, want %q", got, want)
	}
}

func TestPermissionsHeartbeatRefreshesSoftware(t *testing.T) {
	stubPermHave(t, "pg_createcluster", "nft", "apt-get")
	p := permTestPaths(t)
	oldFirewall := firewallAllowFile
	firewallAllowFile = p.FirewallAllowFile
	t.Cleanup(func() { firewallAllowFile = oldFirewall })
	permWriteFile(t, p.RestartAllowFile, "5432 postgresql@17-main.service\n")
	permWriteFile(t, p.UpdatesAllowFile, "postgresql\n")
	a := &Agent{swKick: make(chan struct{}, 1), cfg: Config{
		RestartAllowFile: p.RestartAllowFile, UpdateAllowFile: p.UpdatesAllowFile,
		CreateClusterAllowFile: p.CreateClusterAllowFile, Pooler: PoolerConfig{AllowFile: p.PoolerAllowFile},
	}}
	a.sw = &protocol.SoftwareReport{Allowed: []string{protocol.UpdateAllowPostgres}, SecurityUpdates: 3}

	hb := a.permissionsHeartbeat()
	if hb.Permissions == nil || !slices.Equal(hb.Permissions.Allowed, []string{protocol.PermRestart, protocol.PermUpdates}) {
		t.Fatalf("first heartbeat = %+v", hb.Permissions)
	}
	select {
	case <-a.swKick:
		t.Fatal("the first heartbeat asked for a software refresh")
	default:
	}

	// Root allows security updates: the next heartbeat has them, in the
	// permissions and in the software report, and a full refresh is asked.
	permWriteFile(t, p.UpdatesAllowFile, "postgresql\nsecurity\n")
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(p.UpdatesAllowFile, future, future); err != nil {
		t.Fatal(err)
	}
	hb = a.permissionsHeartbeat()
	if !slices.Contains(hb.Permissions.Allowed, protocol.PermSecurityUpdates) {
		t.Errorf("permissions = %+v", hb.Permissions)
	}
	sw := a.softwareForHeartbeat()
	if !slices.Equal(sw.Allowed, []string{protocol.UpdateAllowPostgres, protocol.UpdateAllowSecurity}) || sw.SecurityUpdates != 3 {
		t.Errorf("software = %+v", sw)
	}
	select {
	case <-a.swKick:
	default:
		t.Error("no software refresh asked")
	}

	// Unchanged: nothing asked.
	a.permissionsHeartbeat()
	select {
	case <-a.swKick:
		t.Error("a refresh without a change")
	default:
	}

	// Docker sidecar: no report (root's permissions don't apply).
	a.cfg.Mode = ModeDockerSidecar
	if hb := a.permissionsHeartbeat(); hb.Permissions != nil {
		t.Errorf("sidecar report = %+v", hb.Permissions)
	}
}

func TestPermissionsTuning(t *testing.T) {
	old := permHave
	permHave = func(name string) bool { return name == "nft" }
	t.Cleanup(func() { permHave = old })
	got := permissionsUnavailable(PermissionPaths{PGRoot: t.TempDir()}, nil)
	if got[protocol.PermTuning] != permReasonTuning || got[protocol.PermFirewall] != "" {
		t.Errorf("no MongoDB or ClickHouse: %v", got)
	}
	p := permTestPaths(t)
	permWriteFile(t, p.TuningAllowFile, "# ENGINE PATH\nmongodb /etc/mongod.conf\n")
	if r := ReadPermissions(p); !slices.Contains(r.Allowed, protocol.PermTuning) {
		t.Errorf("tuning not allowed: %+v", r)
	}
}
