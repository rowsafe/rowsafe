package sqlite

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// FindOpen sees a SQLite file a running program has open (Linux; the
// program runs as this test's user, whose /proc entries it can read).
func TestFindOpen(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "shop", "db", "production.sqlite3")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", `import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1]); c.execute("PRAGMA journal_mode=WAL"); c.execute("CREATE TABLE t (x)"); c.commit()
c.execute("SELECT * FROM t").fetchall(); print("ready", flush=True); time.sleep(30)`, path)
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	buf := make([]byte, 6)
	_, _ = out.Read(buf)
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, f := range FindOpen("") {
			if f.Path == path || f.ContainerPath == path {
				if f.JournalMode != "wal" || f.Suggested != "shop-production" || f.PID != cmd.Process.Pid {
					t.Errorf("found %+v", f)
				}
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("FindOpen didn't find %s", path)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
