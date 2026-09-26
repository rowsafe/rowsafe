package pgbackrest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// runArchiveCommand runs cmd the way PostgreSQL does: %p and %f replaced,
// in the data directory, through sh.
func runArchiveCommand(t *testing.T, cmd, dataDir, walName string) error {
	t.Helper()
	c := strings.NewReplacer("%p", "pg_wal/"+walName, "%f", walName).Replace(cmd)
	sh := exec.Command("sh", "-c", c)
	sh.Dir = dataDir
	out, err := sh.CombinedOutput()
	if len(out) > 0 {
		t.Logf("archive_command output: %s", out)
	}
	return err
}

func TestSecondCopyArchiveCommand(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	queue := filepath.Join(dir, "queue")
	for _, d := range []string{filepath.Join(data, "pg_wal"), queue} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A fake pgbackrest: succeeds unless the "fail" file exists.
	bin := filepath.Join(dir, "pgbackrest")
	fail := filepath.Join(dir, "fail")
	script := fmt.Sprintf("#!/bin/sh\ntest ! -e %s\n", fail)
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd, err := SecondCopyArchiveCommand(bin, "/etc/rowsafe/pgbackrest/app.conf", "app", queue+"/")
	if err != nil {
		t.Fatal(err)
	}
	if !IsOwnArchiveCommand(cmd, bin, "/etc/rowsafe/pgbackrest/app.conf", "app") {
		t.Fatal("IsOwnArchiveCommand doesn't recognize the second copy command")
	}
	plain, _ := ArchiveCommand(bin, "/etc/rowsafe/pgbackrest/app.conf", "app")
	if !IsOwnArchiveCommand(plain, bin, "/etc/rowsafe/pgbackrest/app.conf", "app") {
		t.Fatal("IsOwnArchiveCommand doesn't recognize the plain command")
	}
	for _, other := range []string{plain + "; rm -rf /", "cp %p /mnt/%f", strings.Replace(cmd, "app.conf", "other.conf", 1)} {
		if IsOwnArchiveCommand(other, bin, "/etc/rowsafe/pgbackrest/app.conf", "app") {
			t.Fatalf("IsOwnArchiveCommand accepted %q", other)
		}
	}
	wal := func(i int) string {
		name := fmt.Sprintf("0000000100000000%08X", i)
		if err := os.WriteFile(filepath.Join(data, "pg_wal", name), []byte("wal "+name), 0o600); err != nil {
			t.Fatal(err)
		}
		return name
	}

	// Archived: queued too.
	w1 := wal(1)
	if err := runArchiveCommand(t, cmd, data, w1); err != nil {
		t.Fatalf("archive_command failed: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(queue, w1)); err != nil || string(b) != "wal "+w1 {
		t.Fatalf("not queued: %q %v", b, err)
	}
	// The first storage fails: the command fails and nothing is queued.
	os.WriteFile(fail, nil, 0o600)
	w2 := wal(2)
	if err := runArchiveCommand(t, cmd, data, w2); err == nil {
		t.Fatal("archive_command succeeded while the first storage failed")
	}
	if _, err := os.Stat(filepath.Join(queue, w2)); !os.IsNotExist(err) {
		t.Fatal("queued a file the first storage didn't take")
	}
	os.Remove(fail)
	// A retry keeps the file already queued.
	os.WriteFile(filepath.Join(queue, w1), []byte("kept"), 0o600)
	if err := runArchiveCommand(t, cmd, data, w1); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(queue, w1)); string(b) != "kept" {
		t.Fatal("a queued file was overwritten")
	}
	// A full queue: the command still succeeds, the file is left out and
	// the gap is marked.
	for i := 100; i < 100+protocol.SecondCopyQueueMaxFiles; i++ {
		os.WriteFile(filepath.Join(queue, fmt.Sprintf("0000000100000000%08X", i)), nil, 0o600)
	}
	w3 := wal(3)
	if err := runArchiveCommand(t, cmd, data, w3); err != nil {
		t.Fatalf("archive_command failed with a full queue: %v", err)
	}
	if _, err := os.Stat(filepath.Join(queue, w3)); !os.IsNotExist(err) {
		t.Fatal("queued past the limit")
	}
	if b, err := os.ReadFile(filepath.Join(queue, SecondCopyGapFile)); err != nil || string(b) != w3+"\n" {
		t.Fatalf("gap not marked: %q %v", b, err)
	}
	// No queue directory at all: still succeeds.
	os.RemoveAll(queue)
	w4 := wal(4)
	if err := runArchiveCommand(t, cmd, data, w4); err != nil {
		t.Fatalf("archive_command failed without a queue directory: %v", err)
	}
	if _, err := SecondCopyArchiveCommand(bin, "/etc/x.conf", "app", "/tmp/a b"); err == nil {
		t.Fatal("accepted an unsafe queue directory")
	}
}

func TestParseRepoUsage(t *testing.T) {
	data := []byte(`WARN: something
{".":{"type":"path"},"archive/db/17-1/0000000100000000/000000010000000000000003-08d2.zst":{"type":"file","size":720,"time":1},` +
		`"archive/db/17-1/0000000100000000/000000010000000000000003.00000028.backup":{"type":"file","size":400,"time":1},` +
		`"archive/db/archive.info":{"type":"file","size":368,"time":1},` +
		`"backup/db/20260924-224918F/backup.manifest":{"type":"file","size":1000,"time":1},` +
		`"backup/db/20260924-224918F/bundle/1":{"type":"file","size":5000,"time":1},` +
		`"backup/db/20260924-224918F_20260924-224919D/bundle/1":{"type":"file","size":300,"time":1},` +
		`"backup/db/backup.info":{"type":"file","size":200,"time":1}}`)
	u, err := ParseRepoUsage(data, "db")
	if err != nil {
		t.Fatal(err)
	}
	if u.TotalBytes != 720+400+368+1000+5000+300+200 || u.WALBytes != 720+400+368 || u.BackupBytes != 6500 || u.WALFiles != 1 {
		t.Fatalf("usage %+v", u)
	}
	if u.ByLabel["20260924-224918F"] != 6000 || u.ByLabel["20260924-224918F_20260924-224919D"] != 300 {
		t.Fatalf("by label %v", u.ByLabel)
	}
}

func TestProviderOf(t *testing.T) {
	for ep, want := range map[string]string{
		"0123456789abcdef0123456789abcdef.eu.r2.cloudflarestorage.com": protocol.ProviderR2,
		"s3.eu-central-1.amazonaws.com":                                protocol.ProviderS3,
		"s3.us-west-004.backblazeb2.com":                               protocol.ProviderB2,
		"s3.eu-central-2.wasabisys.com":                                protocol.ProviderWasabi,
		"fra1.digitaloceanspaces.com":                                  protocol.ProviderSpaces,
		"minio:9000":                                                   protocol.ProviderOther,
	} {
		if got := ProviderOf(Repo{Endpoint: ep}); got != want {
			t.Errorf("%s: %s, want %s", ep, got, want)
		}
	}
	if got := (Repo{Endpoint: "minio", Port: 9000, Bucket: "b"}).Info(2); got.Endpoint != "minio:9000" || got.Repo != 2 {
		t.Errorf("info %+v", got)
	}
}

func TestRenderConfigPosix(t *testing.T) {
	conf := RenderConfig(Repo{Type: "posix", Path: "/srv/copy2/", CipherPass: strings.Repeat("x", 24)}, ConfigInput{Stanza: "app", DataDir: "/d", Port: 5432, SocketDir: "/s", User: "postgres", RetentionFull: 3})
	for _, want := range []string{"repo1-type=posix\n", "repo1-path=/srv/copy2/app\n", "repo1-cipher-type=aes-256-cbc\n", "repo1-retention-full=3\n"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q in\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "s3") {
		t.Errorf("posix config mentions s3:\n%s", conf)
	}
	if err := (Repo{Type: "posix", Path: "relative"}).ValidateAs("ROWSAFE_REPO2_"); err == nil {
		t.Error("accepted a relative posix path")
	}
	err := (Repo{Endpoint: "x"}).ValidateAs("ROWSAFE_REPO2_")
	if err == nil || !strings.Contains(err.Error(), "ROWSAFE_REPO2_S3_BUCKET") {
		t.Errorf("error doesn't name the second copy's settings: %v", err)
	}
}
