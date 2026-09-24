package pgbackrest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSpoolArchiveCommand(t *testing.T) {
	cmd, err := SpoolArchiveCommand("/rowsafe-spool/", "app")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cmd, `f=/rowsafe-spool/app/%f; `) || !strings.Contains(cmd, "pgbackrest") {
		t.Errorf("unexpected command %q", cmd)
	}
	for _, c := range []string{"\\", "\n", "'"} {
		if strings.Contains(cmd, c) {
			t.Errorf("command must not contain %q (it is written with ALTER SYSTEM)", c)
		}
	}
	dir, ok := ParseSpoolArchiveCommand(cmd)
	if !ok || dir != "/rowsafe-spool/app" {
		t.Errorf("ParseSpoolArchiveCommand = %q, %v", dir, ok)
	}
	if IsPushArchiveCommand(cmd) {
		t.Error("the spool command is not a native pgBackRest command")
	}
	for _, bad := range [][2]string{{"relative", "app"}, {"/sp ool", "app"}, {"/a/../b", "app"}, {"/spool;rm", "app"}, {"/spool", "App"}, {"/spool", "a/b"}} {
		if _, err := SpoolArchiveCommand(bad[0], bad[1]); err == nil {
			t.Errorf("SpoolArchiveCommand(%q, %q) should fail", bad[0], bad[1])
		}
	}
}

func TestArchiveCommandKinds(t *testing.T) {
	native, _ := ArchiveCommand("/usr/bin/pgbackrest", "/etc/rowsafe/pgbackrest/app.conf", "app")
	cases := map[string]bool{
		native: true,
		"pgbackrest --stanza=main archive-push %p": true,
		"wal-g wal-push %p":                        false,
		"cp %p /mnt/wal/%f":                        false,
		"":                                         false,
	}
	for cmd, want := range cases {
		if got := IsPushArchiveCommand(cmd); got != want {
			t.Errorf("IsPushArchiveCommand(%q) = %v, want %v", cmd, got, want)
		}
		if _, ok := ParseSpoolArchiveCommand(cmd); ok {
			t.Errorf("%q is not a spool command", cmd)
		}
	}
}

func TestIsWALFileName(t *testing.T) {
	for name, want := range map[string]bool{
		"000000010000000000000003":                 true,
		"00000002.history":                         true,
		"000000010000000000000002.00000028.backup": true,
		"000000010000000000000003.partial":         true,
		"000000010000000000000003.tmp":             false,
		"00000001000000000000000g":                 false,
		"archive_status":                           false,
		".rowsafe-write-test-1":                    false,
	} {
		if IsWALFileName(name) != want {
			t.Errorf("IsWALFileName(%q) = %v", name, !want)
		}
	}
}

// TestSpoolArchiveCommandShell runs the command the way PostgreSQL does
// (sh -c, in the data directory, with %p and %f substituted).
func TestSpoolArchiveCommandShell(t *testing.T) {
	for _, tool := range []string{"sh", "cmp", "cp", "mv", "sync"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	root := t.TempDir()
	pgdata := filepath.Join(root, "data")
	spool := filepath.Join(root, "spool")
	must(t, os.MkdirAll(filepath.Join(pgdata, "pg_wal"), 0o700))
	must(t, os.MkdirAll(filepath.Join(spool, "app"), 0o700))
	cmd, err := SpoolArchiveCommand(spool, "app")
	if err != nil {
		t.Fatal(err)
	}
	archive := func(name string) error {
		c := strings.NewReplacer("%p", "pg_wal/"+name, "%f", name).Replace(cmd)
		sh := exec.Command("sh", "-c", c)
		sh.Dir = pgdata
		out, err := sh.CombinedOutput()
		if err != nil {
			t.Logf("archive_command output: %s", out)
		}
		return err
	}
	seg := "000000010000000000000001"
	wal := filepath.Join(pgdata, "pg_wal", seg)
	spooled := filepath.Join(spool, "app", seg)
	must(t, os.WriteFile(wal, []byte("segment one"), 0o600))

	// A leftover temporary file from an interrupted attempt is overwritten.
	must(t, os.WriteFile(spooled+".tmp", []byte("partial garbage"), 0o600))
	if err := archive(seg); err != nil {
		t.Fatalf("first archive failed: %v", err)
	}
	if b, _ := os.ReadFile(spooled); string(b) != "segment one" {
		t.Fatalf("spooled content %q", b)
	}
	if _, err := os.Stat(spooled + ".tmp"); !os.IsNotExist(err) {
		t.Error("temporary file left behind")
	}
	// PostgreSQL retrying a file it already handed over succeeds.
	if err := archive(seg); err != nil {
		t.Errorf("retry of an identical file must succeed: %v", err)
	}
	// A different file with the same name is refused and never overwritten.
	must(t, os.WriteFile(wal, []byte("something else"), 0o600))
	if err := archive(seg); err == nil {
		t.Error("a different file with the same name must fail")
	}
	if b, _ := os.ReadFile(spooled); string(b) != "segment one" {
		t.Errorf("spooled file was overwritten: %q", b)
	}
	// A missing source fails and leaves nothing that looks archived.
	if err := archive("000000010000000000000002"); err == nil {
		t.Error("a missing WAL file must fail")
	}
	if _, err := os.Stat(filepath.Join(spool, "app", "000000010000000000000002")); !os.IsNotExist(err) {
		t.Error("a failed copy must not leave a spooled file")
	}
	// History files take the same path.
	must(t, os.WriteFile(filepath.Join(pgdata, "pg_wal", "00000002.history"), []byte("1\t0/3000000\tno recovery target"), 0o600))
	if err := archive("00000002.history"); err != nil {
		t.Errorf("history file: %v", err)
	}
	// An unwritable spool fails.
	must(t, os.Chmod(filepath.Join(spool, "app"), 0o500))
	defer os.Chmod(filepath.Join(spool, "app"), 0o700)
	must(t, os.WriteFile(filepath.Join(pgdata, "pg_wal", "000000010000000000000003"), []byte("three"), 0o600))
	if os.Geteuid() != 0 {
		if err := archive("000000010000000000000003"); err == nil {
			t.Error("an unwritable spool must fail")
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
