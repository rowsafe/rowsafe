package pginspect

import (
	"context"
	"os"
	"os/user"
	"strconv"
	"testing"
)

// localTarget is the developer's PostgreSQL on /tmp:5432, connecting as the
// current OS user (ROWSAFE_TEST_PG_SOCKET and ROWSAFE_TEST_PG_PORT
// override). Tests using it skip when it isn't running.
func localTarget(t *testing.T) Target {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	tg := Target{SocketDir: "/tmp", Port: 5432, User: u.Username}
	if v := os.Getenv("ROWSAFE_TEST_PG_SOCKET"); v != "" {
		tg.SocketDir = v
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_PORT"); v != "" {
		tg.Port, _ = strconv.Atoi(v)
	}
	if v := os.Getenv("ROWSAFE_TEST_PG_USER"); v != "" {
		tg.User = v
	}
	conn, err := tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Skipf("no local PostgreSQL at %s:%d: %v", tg.SocketDir, tg.Port, err)
	}
	conn.Close(context.Background())
	return tg
}

// The heartbeat's archiver stats carry the running archive_mode, read in
// the same query as pg_stat_archiver.
func TestArchiverReportsArchiveMode(t *testing.T) {
	tg := localTarget(t)
	a, err := Archiver(t.Context(), tg)
	if err != nil {
		t.Fatal(err)
	}
	switch a.ArchiveMode {
	case "off", "on", "always":
	default:
		t.Fatalf("archive_mode = %q", a.ArchiveMode)
	}
	mode, err := ArchiveMode(t.Context(), tg)
	if err != nil || mode != a.ArchiveMode {
		t.Fatalf("ArchiveMode() = %q, %v; Archiver said %q", mode, err, a.ArchiveMode)
	}
}

func TestSummarize(t *testing.T) {
	tg := localTarget(t)
	s, err := Summarize(t.Context(), tg)
	if err != nil {
		t.Fatal(err)
	}
	if s.Major() < 13 || s.DataDirectory == "" || s.ServerVersion == "" {
		t.Fatalf("summary %+v", s)
	}
	found := false
	var total int64
	for _, d := range s.Databases {
		total += d.SizeBytes
		if d.Name == "postgres" {
			found = true
		}
		if d.Name == "template0" || d.Name == "template1" {
			t.Errorf("template database listed: %s", d.Name)
		}
	}
	if !found || total != s.TotalSizeBytes || total <= 0 {
		t.Fatalf("databases %+v, total %d", s.Databases, s.TotalSizeBytes)
	}
}
