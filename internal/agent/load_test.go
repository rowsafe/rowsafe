package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Backups run at low CPU and IO priority, like restore tests.
func TestBackupRunsNiced(t *testing.T) {
	fr := &fakeRunner{}
	a := &Agent{cfg: Config{PgBackRestBin: "/usr/bin/pgbackrest", ConfigDir: "/etc/rowsafe/pgbackrest"}, runner: fr}
	db := protocol.DatabaseSpec{Stanza: "app"}
	if _, err := a.backupCLI(db).Backup(context.Background(), protocol.BackupFull); err != nil {
		t.Fatal(err)
	}
	if _, err := a.cli(db).Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	backup, check := fr.calls[0], fr.calls[1]
	wrap := niceWrap()
	if !slices.Equal(backup[:len(wrap)], wrap) || !slices.Contains(backup, "/usr/bin/pgbackrest") || backup[len(backup)-1] != "backup" ||
		!slices.Contains(backup, "--type=full") {
		t.Errorf("backup command %q is not wrapped in %q", backup, wrap)
	}
	if check[0] != "/usr/bin/pgbackrest" {
		t.Errorf("check should run pgBackRest directly: %q", check)
	}
}

// The rendered config's process-max follows the host's CPU count.
func TestWriteConfigProcessMax(t *testing.T) {
	old := numCPU
	defer func() { numCPU = old }()
	dir := t.TempDir()
	repo := pgbackrest.Repo{Endpoint: "acct.r2.cloudflarestorage.com", Bucket: "b", Key: "k", KeySecret: "s",
		CipherPass: strings.Repeat("x", 24), PathPrefix: "/rowsafe"}
	a := &Agent{cfg: Config{ConfigDir: filepath.Join(dir, "conf"), LogDir: filepath.Join(dir, "log"), PGUser: "postgres", Repo: repo}}
	db := protocol.DatabaseSpec{Stanza: "app", Port: 5432, SocketDir: "/var/run/postgresql", RetentionFull: 2}
	for cpus, want := range map[int]string{2: "process-max=1\n", 4: "process-max=1\n", 16: "process-max=2\n"} {
		numCPU = func() int { return cpus }
		if err := a.writeConfig(db, protocol.InspectResult{DataDirectory: "/var/lib/postgresql/18/main"}); err != nil {
			t.Fatal(err)
		}
		conf, _ := os.ReadFile(filepath.Join(dir, "conf", "app.conf"))
		if !strings.Contains(string(conf), want) {
			t.Errorf("%d CPUs: config lacks %q", cpus, want)
		}
	}
}
