package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

func TestReadSettingsLocalPostgres(t *testing.T) {
	tg := localTarget(t)
	proc := t.TempDir()
	if err := os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal:       16384000 kB\nMemFree: 1 kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	snap, err := ReadSettings(t.Context(), tg, proc)
	if err != nil {
		t.Fatal(err)
	}
	if snap.VersionNum < 130000 {
		t.Errorf("version %d", snap.VersionNum)
	}
	if snap.Host.MemoryBytes != 16_384_000*1024 || snap.Host.CPUs < 1 {
		t.Errorf("host facts %+v", snap.Host)
	}
	if snap.Host.DataDiskBytes <= 0 {
		t.Errorf("data disk size unknown: %+v", snap.Host)
	}
	if snap.DatabaseBytes <= 0 {
		t.Error("database size unknown")
	}
	got := tune.SettingsMap(snap.Settings)
	for _, name := range []string{"shared_buffers", "work_mem", "max_connections", "archive_mode", "shared_preload_libraries"} {
		if _, ok := got[name]; !ok {
			t.Errorf("%s missing from the snapshot", name)
		}
	}
	sb := got["shared_buffers"]
	if sb.Unit != "8kB" || sb.Context != "postmaster" || sb.VarType != "integer" {
		t.Errorf("shared_buffers %+v", sb)
	}
	// The session's own settings never leak in: the monitoring connection
	// sets statement_timeout, this one doesn't.
	if st := got["statement_timeout"]; st.Source == "client" || st.Source == "session" {
		t.Errorf("statement_timeout from the session: %+v", st)
	}
	if hp := got["huge_pages"]; len(hp.EnumVals) == 0 {
		t.Errorf("huge_pages has no enum values: %+v", hp)
	}
	if snap.PgStatStatements != "" && snap.PgStatStatements != "available" && snap.PgStatStatements != "loaded" {
		t.Errorf("pg_stat_statements %q", snap.PgStatStatements)
	}
	for _, s := range snap.Settings {
		if _, ok := tune.Lookup(s.Name); !ok && s.Source != "configuration file" && s.Source != "command line" && s.Source != "environment variable" {
			t.Errorf("%s (source %s) is neither in the catalog nor set in a file", s.Name, s.Source)
		}
	}
}

func TestRotationalKind(t *testing.T) {
	for in, want := range map[string]string{"0\n": protocol.DiskSSD, "1\n": protocol.DiskHDD, "": "", "x": ""} {
		if got := rotationalKind([]byte(in)); got != want {
			t.Errorf("rotationalKind(%q) = %q, want %q", in, got, want)
		}
	}
}
