package agent

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestDerivedReplicationPassword(t *testing.T) {
	pass := strings.Repeat("p", 32)
	a, b := derivedReplicationPassword(pass, "sb_shop"), derivedReplicationPassword(pass, "sb_shop")
	if a != b || len(a) != 48 || strings.Trim(a, "0123456789abcdef") != "" {
		t.Fatalf("not one stable hex password: %q %q", a, b)
	}
	if derivedReplicationPassword(pass, "sb_crm") == a || derivedReplicationPassword(strings.Repeat("q", 32), "sb_shop") == a {
		t.Fatal("the same password for another standby or passphrase")
	}
}

// pairAgents are two servers sharing one (posix) repository and passphrase.
func pairAgents(t *testing.T, pass string) (primary, standby *Agent, db protocol.DatabaseSpec) {
	t.Helper()
	repoDir := t.TempDir()
	mk := func(p string) *Agent {
		repo := pgbackrest.Repo{Type: "posix", Path: repoDir, CipherPass: p}
		return &Agent{cfg: Config{StateDir: t.TempDir(), ConfigDir: t.TempDir(), Repo: repo}, log: slog.New(slog.DiscardHandler)}
	}
	return mk(strings.Repeat("c", 24)), mk(pass), protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop", Port: 5432}
}

func TestPairRecord(t *testing.T) {
	ctx := context.Background()
	p, s, db := pairAgents(t, strings.Repeat("c", 24))
	if r, err := s.readRecord(ctx, db); r != nil || err != nil {
		t.Fatalf("no record yet: %+v %v", r, err)
	}
	// The primary stops for a switchover: the standby reads where.
	if err := p.writeRecord(ctx, db, protocol.PrimaryRecord{SystemID: "7412", State: protocol.PrimaryRecordStopped, Timeline: 1,
		CheckpointLSN: "0/3004FD0"}); err != nil {
		t.Fatal(err)
	}
	r, err := s.readRecord(ctx, db)
	if err != nil || r == nil || r.State != protocol.PrimaryRecordStopped || r.CheckpointLSN != "0/3004FD0" || r.Database != "shop" {
		t.Fatalf("read %+v %v", r, err)
	}
	if !p.mine(r) || s.mine(r) {
		t.Fatal("whose record")
	}
	if _, err := os.Stat(filepath.Join(p.cfg.Repo.Path, "shop", "rowsafe", "primary.json")); err != nil {
		t.Fatalf("the record isn't in the database's folder: %v", err)
	}
	// The standby is promoted: the old primary, on timeline 1 of the same
	// system, is superseded; a primary on a later timeline or another
	// system isn't, and a record of its own never supersedes it.
	if err := s.writeRecord(ctx, db, protocol.PrimaryRecord{SystemID: "7412", State: protocol.PrimaryRecordPrimary, Timeline: 2, SwitchLSN: "0/3005000"}); err != nil {
		t.Fatal(err)
	}
	r, _ = p.readRecord(ctx, db)
	if !p.superseded(r, "7412", 1) || p.superseded(r, "7412", 2) || p.superseded(r, "9999", 1) || s.superseded(r, "7412", 1) {
		t.Fatal("superseded")
	}
	// A record not made with this passphrase doesn't count.
	_, other, _ := pairAgents(t, strings.Repeat("x", 24))
	other.cfg.Repo.Path = p.cfg.Repo.Path
	if _, err := other.readRecord(ctx, db); err != errRecordForeign {
		t.Fatalf("another passphrase: %v", err)
	}
	path := filepath.Join(p.cfg.Repo.Path, "shop", "rowsafe", "primary.json")
	data, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), `"timeline":2`, `"timeline":9`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.readRecord(ctx, db); err != errRecordForeign {
		t.Fatalf("a changed record: %v", err)
	}
}

func TestRecordWatch(t *testing.T) {
	_, s, db := pairAgents(t, strings.Repeat("c", 24))
	rt := s.sb()
	rt.setRecordIDs([]string{db.ID})
	rt.mu.Lock()
	rt.records.states = map[string]protocol.PrimaryRecordState{db.ID: {DatabaseID: db.ID}, "db_gone": {DatabaseID: "db_gone"}}
	rt.mu.Unlock()
	if got := rt.recordStates(); len(got) != 1 || got[0].DatabaseID != db.ID {
		t.Fatalf("states %+v", got)
	}
	rt.setRecordIDs(nil)
	if len(rt.recordStates()) != 0 || len(rt.records.states) != 0 {
		t.Fatal("states of databases no longer named")
	}
}

func TestRaiseSettings(t *testing.T) {
	block := "\n" + hbaBegin("sb_shop") + "\nhot_standby = 'on'\nmax_connections = '100'\nmax_wal_senders = '20'\n" + hbaEnd("sb_shop") + "\n"
	got := raiseSettings(block, map[string]int{"max_connections": 250, "max_wal_senders": 10, "max_worker_processes": 16})
	for _, want := range []string{"max_connections = '250'", "max_wal_senders = '20'", "max_worker_processes = '16'\n" + hbaEnd("sb_shop")} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	if raiseSettings(block, nil) != block {
		t.Fatal("changed without settings")
	}
}

func TestBucketSecrets(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("-----BEGIN CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	repo := pgbackrest.Repo{Endpoint: "minio", Port: 9000, Bucket: "b", Key: "k", KeySecret: "s", CipherPass: strings.Repeat("c", 24), CAFile: ca}
	a := &Agent{cfg: Config{StateDir: dir, Repo: repo}, log: slog.New(slog.DiscardHandler)}
	sec, err := a.bucketSecrets(protocol.StandbyCreateParams{StandbyID: "sb_shop", Folder: "shop-20261018-120000"})
	if err != nil {
		t.Fatal(err)
	}
	if sec.Repo.Endpoint != "minio" || sec.Repo.Port != 9000 || sec.Repo.Folder != "shop-20261018-120000" || !strings.HasPrefix(sec.Repo.CAPEM, "-----BEGIN") ||
		sec.ReplicationUser != "" {
		t.Fatalf("archive only: %+v", sec)
	}
	// Streaming: the password the primary derives too; nothing answers on
	// the address here, so no TLS is known.
	sec, err = a.bucketSecrets(protocol.StandbyCreateParams{StandbyID: "sb_shop", PrimaryAddresses: []string{"127.0.0.1"}, PrimaryPort: 1})
	if err != nil {
		t.Fatal(err)
	}
	if sec.ReplicationUser != "rowsafe_standby_sb_shop" || sec.ReplicationPassword != derivedReplicationPassword(repo.CipherPass, "sb_shop") ||
		sec.PrimaryPort != 1 || sec.PrimaryTLS {
		t.Fatalf("streaming: %+v", sec)
	}
	if _, err := a.bucketSecrets(protocol.StandbyCreateParams{StandbyID: "sb_shop", Folder: "../x"}); err == nil {
		t.Fatal("a folder outside the bucket's")
	}
	a.cfg.Repo = pgbackrest.Repo{Type: "sftp", SFTPHost: "h"}
	if _, err := a.bucketSecrets(protocol.StandbyCreateParams{StandbyID: "sb_shop"}); err == nil || !strings.Contains(err.Error(), "bucket") {
		t.Fatalf("SFTP: %v", err)
	}
}
