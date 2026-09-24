package agent

import (
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestHbaBlock(t *testing.T) {
	orig := "# TYPE DATABASE USER ADDRESS METHOD\nlocal all all peer\nhost all all 0.0.0.0/0 reject\n"
	lines, err := hbaLines("rowsafe_standby_x", []string{"10.0.0.2", "2001:db8::5"}, true)
	if err != nil {
		t.Fatal(err)
	}
	got := withHbaBlock(orig, "sby_x", lines)
	want := hbaBegin("sby_x") + "\nhostssl replication rowsafe_standby_x 10.0.0.2/32 scram-sha-256\n" +
		"hostssl replication rowsafe_standby_x 2001:db8::5/128 scram-sha-256\n" + hbaEnd("sby_x") + "\n" + orig
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	// Idempotent, another block kept, removal exact.
	again := withHbaBlock(got, "sby_x", lines)
	if again != got {
		t.Fatalf("second insert changed the file:\n%s", again)
	}
	two := withHbaBlock(got, "sby_y", []string{"host replication r 10.0.0.3/32 scram-sha-256"})
	if !strings.Contains(two, "sby_x") || !strings.Contains(two, "sby_y") {
		t.Fatal(two)
	}
	if withoutHbaBlock(withoutHbaBlock(two, "sby_y"), "sby_x") != orig {
		t.Fatalf("removal left:\n%s", withoutHbaBlock(withoutHbaBlock(two, "sby_y"), "sby_x"))
	}
	if withoutHbaBlock(two, "") != orig {
		t.Fatal("removing every block")
	}
	for _, bad := range []string{"not-an-ip", "127.0.0.1", "0.0.0.0", "10.0.0.0/8"} {
		if _, err := hbaLines("r", []string{bad}, false); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestScramVerifier(t *testing.T) {
	// RFC 7677's example: password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==,
	// 4096 iterations; StoredKey and ServerKey as PostgreSQL stores them.
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	v, err := scramVerifierSalt("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=:wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU="
	if v != want {
		t.Fatalf("verifier %s", v)
	}
	a, _ := scramVerifier("x")
	b, _ := scramVerifier("x")
	if a == b {
		t.Fatal("same salt twice")
	}
}

func TestParseControlData(t *testing.T) {
	out := `pg_control version number:            1700
Database system identifier:           7412345678901234567
Database cluster state:               shut down
Latest checkpoint location:           0/3004FD0
Latest checkpoint's REDO location:    0/3004FD0
Latest checkpoint's REDO WAL file:    000000010000000000000003
Latest checkpoint's TimeLineID:       1
`
	c := parseControlData([]byte(out))
	if c.State != "shut down" || c.CheckpointLSN != "0/3004FD0" || c.Timeline != 1 || c.RedoWALFile != "000000010000000000000003" ||
		c.SystemID != "7412345678901234567" {
		t.Fatalf("%+v", c)
	}
}

func TestLSN(t *testing.T) {
	if lsnDiff("1/0", "0/FFFFFFFF") != 1 || lsnDiff("0/10", "0/20") != 0 || lsnDiff("x", "0/1") != 0 {
		t.Fatal("lsnDiff")
	}
	if !lsnAtLeast("0/3005048", "0/3004FD0") || lsnAtLeast("0/3004FD0", "0/3005048") || lsnAtLeast("", "0/1") {
		t.Fatal("lsnAtLeast")
	}
}

type probeOps struct {
	standbyOps
	up map[string]bool
}

func (p probeOps) probe(addr string, port int) bool { return p.up[addr] }

func TestPlanStreaming(t *testing.T) {
	sec := protocol.StandbySecrets{ReplicationUser: "r", ReplicationPassword: "p", PrimaryPort: 5432,
		PrimaryAddresses: []string{"203.0.113.7", "10.0.0.1"}}
	ops := probeOps{up: map[string]bool{"203.0.113.7": true, "10.0.0.1": true}}
	if sp := planStreaming(ops, sec); sp.Address != "10.0.0.1" || sp.SSLMode != "prefer" {
		t.Fatalf("without TLS, prefer the private address: %+v", sp)
	}
	ops.up["10.0.0.1"] = false
	if sp := planStreaming(ops, sec); sp.Address != "" || !strings.Contains(sp.Note, "public address") {
		t.Fatalf("no plaintext streaming over a public address: %+v", sp)
	}
	sec.PrimaryTLS = true
	if sp := planStreaming(ops, sec); sp.Address != "203.0.113.7" || sp.SSLMode != "require" {
		t.Fatalf("TLS on: %+v", sp)
	}
	ops.up["203.0.113.7"] = false
	if sp := planStreaming(ops, sec); sp.Address != "" || !strings.Contains(sp.Note, "can't reach") {
		t.Fatalf("unreachable: %+v", sp)
	}
	sec.ReplicationUser = ""
	if sp := planStreaming(ops, sec); sp.Address != "" {
		t.Fatalf("archive only: %+v", sp)
	}
}

func TestStandbyBlockAndConf(t *testing.T) {
	a := &Agent{cfg: Config{PgBackRestBin: "/usr/bin/pgbackrest", ConfigDir: "/etc/rowsafe/pgbackrest"}}
	db := protocol.DatabaseSpec{ID: "db_1", Stanza: "shop"}
	sec := protocol.StandbySecrets{ReplicationUser: "rowsafe_standby_sby_1", ReplicationPassword: "abc123", PrimaryPort: 5432}
	block, err := a.standbyBlock("sby_1", db, sec, streamingPlan{Address: "10.0.0.1", SSLMode: "require"}, map[string]int{"max_connections": 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"primary_conninfo = 'host=10.0.0.1 port=5432 user=rowsafe_standby_sby_1 password=abc123 sslmode=require application_name=rowsafe_standby_sby_1",
		"restore_command = '/usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/shop.conf --stanza=shop archive-get %f \"%p\"'",
		"archive_command = '/usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/shop.conf --stanza=shop archive-push %p'",
		"recovery_target_timeline = 'latest'", "max_connections = '200'", "hot_standby = 'on'"} {
		if !strings.Contains(block, want) {
			t.Errorf("block lacks %q:\n%s", want, block)
		}
	}
	if _, err := a.standbyBlock("sby_1", db, protocol.StandbySecrets{ReplicationUser: "x y", PrimaryPort: 1},
		streamingPlan{Address: "10.0.0.1", SSLMode: "require"}, nil); err == nil {
		t.Fatal("accepted a space in the conninfo")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "postgresql.auto.conf"), []byte("archive_mode = 'on'\n"), 0o600)
	if err := setStandbyConf(dir, block); err != nil {
		t.Fatal(err)
	}
	if err := setStandbyConf(dir, block); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "postgresql.auto.conf"))
	if strings.Count(string(got), "BEGIN Rowsafe standby") != 1 || !strings.HasPrefix(string(got), "archive_mode = 'on'\n") {
		t.Fatalf("auto.conf:\n%s", got)
	}
}

func TestFencesAndRepo(t *testing.T) {
	dir := t.TempDir()
	repo := pgbackrest.Repo{Endpoint: "own", Bucket: "b", Key: "k", KeySecret: "s", CipherPass: strings.Repeat("c", 24)}
	a := &Agent{cfg: Config{StateDir: dir, Repo: repo}, log: slog.New(slog.DiscardHandler)}
	rt := a.sb()
	if rt.key == nil {
		t.Fatal("no key")
	}
	if info, _ := os.Stat(filepath.Join(dir, "box.key")); info.Mode().Perm() != 0o600 {
		t.Fatal("key mode")
	}
	rt.setCluster("db_1", clusterFacts{DataDir: "/var/lib/postgresql/18/main", Major: 18})
	rt.setFences([]protocol.Fence{{ID: "fen_1", DatabaseID: "db_1", Port: 5432, SocketDir: "/run/postgresql", Since: time.Now()}})
	f := rt.fences()
	if len(f) != 1 || f[0].DataDir != "/var/lib/postgresql/18/main" {
		t.Fatalf("fences %+v", f)
	}
	// Persisted: a restarted agent holds it without the control plane.
	b := &Agent{cfg: Config{StateDir: dir, Repo: repo}, log: slog.New(slog.DiscardHandler)}
	if len(b.sb().fences()) != 1 || b.sb().key.PublicKey() != rt.key.PublicKey() {
		t.Fatal("state not reloaded")
	}
	if err := rt.releaseFence("fen_1"); err != nil {
		t.Fatal(err)
	}
	rt.setFences([]protocol.Fence{{ID: "fen_1", DatabaseID: "db_1", Port: 5432}})
	if len(rt.fences()) != 0 {
		t.Fatal("a released fence came back")
	}
	rt.setFences([]protocol.Fence{{ID: "fen_2", DatabaseID: "db_1", Port: 5432}, {ID: "../x", DatabaseID: "db_1"}})
	if len(rt.fences()) != 1 {
		t.Fatalf("fences %+v", rt.fences())
	}
	rt.setFences(nil)
	if len(rt.fences()) != 0 {
		t.Fatal("a lifted fence stayed")
	}

	// The handed-over bucket replaces the agent's own for that database only.
	db := protocol.DatabaseSpec{ID: "db_1", Stanza: "shop"}
	if a.repoFor(db).Endpoint != "own" {
		t.Fatal("own repo")
	}
	if err := a.saveHandedRepo("db_1", protocol.StandbyRepo{Endpoint: "theirs", Bucket: "b", Key: "k", KeySecret: "s",
		CipherPass: strings.Repeat("d", 24), CAPEM: "-----BEGIN CERTIFICATE-----\n"}); err != nil {
		t.Fatal(err)
	}
	if r := a.repoFor(db); r.Endpoint != "theirs" || r.CAFile != a.caPath("db_1") {
		t.Fatalf("handed repo %+v", r)
	}
	if a.repoFor(protocol.DatabaseSpec{ID: "db_2"}).Endpoint != "own" {
		t.Fatal("another database uses the handed repo")
	}
	if info, _ := os.Stat(a.repoPath("db_1")); info.Mode().Perm() != 0o600 {
		t.Fatal("repo file mode")
	}
	h, err := a.handedRepo(db)
	if err != nil || h.Endpoint != "theirs" || !strings.HasPrefix(h.CAPEM, "-----BEGIN") {
		t.Fatalf("handedRepo %+v %v", h, err)
	}
	if err := a.saveHandedRepo("db_3", protocol.StandbyRepo{Endpoint: "x"}); err == nil {
		t.Fatal("saved an incomplete repo")
	}
}

func TestStandbyRoleName(t *testing.T) {
	if got := replicationRole("sby_AB-c9"); got != "rowsafe_standby_sby_abc9" {
		t.Fatal(got)
	}
	if !standbyAppRE.MatchString(replicationRole("sby_" + strings.Repeat("x", 80))) {
		t.Fatal("long id")
	}
	if len(replicationRole(strings.Repeat("x", 80))) > 63 {
		t.Fatal("role name too long")
	}
}

func TestKeptStandbyDir(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "main")
	kept := data + ".before-standby-20260101T000000Z"
	os.Mkdir(kept, 0o700)
	if err := validKeptStandbyDir(data, kept); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{filepath.Join(root, "other.before-standby-20260101T000000Z"), data, filepath.Join(root, "x", "main.old-primary-20260101T000000Z")} {
		if validKeptStandbyDir(data, bad) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
