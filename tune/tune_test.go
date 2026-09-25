package tune

import (
	"errors"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// pgDefaults are PostgreSQL 17's defaults on Linux, as pg_settings shows
// them (shared_buffers is 128 MB as initdb writes it).
func pgDefaults() map[string]protocol.PGSetting {
	rows := []protocol.PGSetting{
		{Name: "shared_buffers", Setting: "16384", Unit: "8kB", VarType: "integer", Context: "postmaster", Source: "configuration file", BootVal: "16384", SourceFile: "postgresql.conf"},
		{Name: "effective_cache_size", Setting: "524288", Unit: "8kB", VarType: "integer", Context: "user", Source: "default", BootVal: "524288"},
		{Name: "work_mem", Setting: "4096", Unit: "kB", VarType: "integer", Context: "user", Source: "default", BootVal: "4096"},
		{Name: "maintenance_work_mem", Setting: "65536", Unit: "kB", VarType: "integer", Context: "user", Source: "default", BootVal: "65536"},
		{Name: "huge_pages", Setting: "try", VarType: "enum", Context: "postmaster", Source: "default", BootVal: "try", EnumVals: []string{"off", "on", "try"}},
		{Name: "max_connections", Setting: "100", VarType: "integer", Context: "postmaster", Source: "configuration file", BootVal: "100"},
		{Name: "superuser_reserved_connections", Setting: "3", VarType: "integer", Context: "postmaster", Source: "default", BootVal: "3"},
		{Name: "reserved_connections", Setting: "0", VarType: "integer", Context: "postmaster", Source: "default", BootVal: "0"},
		{Name: "max_wal_senders", Setting: "10", VarType: "integer", Context: "postmaster", Source: "default", BootVal: "10"},
		{Name: "wal_level", Setting: "replica", VarType: "enum", Context: "postmaster", Source: "default", BootVal: "replica", EnumVals: []string{"minimal", "replica", "logical"}},
		{Name: "wal_buffers", Setting: "512", Unit: "8kB", VarType: "integer", Context: "postmaster", Source: "override", BootVal: "-1"},
		{Name: "max_wal_size", Setting: "1024", Unit: "MB", VarType: "integer", Context: "sighup", Source: "configuration file", BootVal: "1024"},
		{Name: "min_wal_size", Setting: "80", Unit: "MB", VarType: "integer", Context: "sighup", Source: "configuration file", BootVal: "80"},
		{Name: "checkpoint_completion_target", Setting: "0.9", VarType: "real", Context: "sighup", Source: "default", BootVal: "0.9"},
		{Name: "random_page_cost", Setting: "4", VarType: "real", Context: "user", Source: "default", BootVal: "4"},
		{Name: "effective_io_concurrency", Setting: "1", VarType: "integer", Context: "user", Source: "default", BootVal: "1"},
		{Name: "default_statistics_target", Setting: "100", VarType: "integer", Context: "user", Source: "default", BootVal: "100"},
		{Name: "max_worker_processes", Setting: "8", VarType: "integer", Context: "postmaster", Source: "default", BootVal: "8"},
		{Name: "max_parallel_workers", Setting: "8", VarType: "integer", Context: "user", Source: "default", BootVal: "8"},
		{Name: "max_parallel_workers_per_gather", Setting: "2", VarType: "integer", Context: "user", Source: "default", BootVal: "2"},
		{Name: "max_parallel_maintenance_workers", Setting: "2", VarType: "integer", Context: "user", Source: "default", BootVal: "2"},
		{Name: "autovacuum_vacuum_scale_factor", Setting: "0.2", VarType: "real", Context: "sighup", Source: "default", BootVal: "0.2"},
		{Name: "autovacuum_analyze_scale_factor", Setting: "0.1", VarType: "real", Context: "sighup", Source: "default", BootVal: "0.1"},
		{Name: "idle_in_transaction_session_timeout", Setting: "0", Unit: "ms", VarType: "integer", Context: "user", Source: "default", BootVal: "0"},
		{Name: "shared_preload_libraries", Setting: "", VarType: "string", Context: "postmaster", Source: "default", BootVal: ""},
		{Name: "archive_command", Setting: "pgbackrest archive-push %p", VarType: "string", Context: "sighup", Source: "configuration file"},
		{Name: "listen_addresses", Setting: "localhost", VarType: "string", Context: "postmaster", Source: "configuration file"},
		{Name: "block_size", Setting: "8192", VarType: "integer", Context: "internal", Source: "default"},
		{Name: "log_lock_waits", Setting: "off", VarType: "bool", Context: "superuser", Source: "default", BootVal: "off"},
	}
	return SettingsMap(rows)
}

func recs(in Input) map[string]protocol.Recommendation {
	out := map[string]protocol.Recommendation{}
	for _, r := range Recommend(in) {
		out[r.Name] = r
	}
	return out
}

func wantValues(t *testing.T, got map[string]protocol.Recommendation, want map[string]string) {
	t.Helper()
	for name, v := range want {
		r, ok := got[name]
		switch {
		case v == "" && ok:
			t.Errorf("%s: recommended %q, want no change", name, r.Value)
		case v != "" && !ok:
			t.Errorf("%s: no recommendation, want %q", name, v)
		case v != "" && r.Value != v:
			t.Errorf("%s = %q, want %q", name, r.Value, v)
		}
	}
}

func TestRecommendWeb16GB(t *testing.T) {
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: 16 * GB, CPUs: 4, Disk: protocol.DiskSSD, DataDiskBytes: 200 * GB},
		Workload: protocol.WorkloadWeb, Settings: pgDefaults(), PgStatStatements: "available"})
	wantValues(t, got, map[string]string{
		"shared_buffers":       "4GB",
		"effective_cache_size": "12GB",
		"maintenance_work_mem": "1GB",
		// (16 GB - 4 GB) / ((100 + 8) * 3) / 2 per gather = 18.96 MB
		"work_mem":                            "18MB",
		"max_wal_size":                        "4GB",
		"min_wal_size":                        "1GB",
		"random_page_cost":                    "1.1",
		"effective_io_concurrency":            "200",
		"max_parallel_workers":                "4",
		"max_worker_processes":                "", // never lowered
		"max_parallel_workers_per_gather":     "", // already 2
		"max_parallel_maintenance_workers":    "",
		"checkpoint_completion_target":        "",
		"default_statistics_target":           "",
		"wal_buffers":                         "",
		"autovacuum_vacuum_scale_factor":      "", // small databases
		"idle_in_transaction_session_timeout": "10min",
		"shared_preload_libraries":            "pg_stat_statements",
	})
	if !got["shared_buffers"].Restart || got["work_mem"].Restart {
		t.Errorf("restart flags: shared_buffers %v, work_mem %v", got["shared_buffers"].Restart, got["work_mem"].Restart)
	}
	if !got["idle_in_transaction_session_timeout"].Optional || got["shared_buffers"].Optional {
		t.Error("only the timeout is optional")
	}
	if r := got["shared_buffers"]; r.Current != "128 MB" || r.Display != "4 GB" || !strings.Contains(r.Why, "16 GB") {
		t.Errorf("shared_buffers: %+v", r)
	}
	// Catalog order.
	list := Recommend(Input{Host: protocol.SettingsHost{MemoryBytes: 16 * GB, CPUs: 4}, Settings: pgDefaults()})
	if list[0].Name != "shared_buffers" {
		t.Errorf("first recommendation %s, want shared_buffers", list[0].Name)
	}
}

func TestRecommendSmallServer(t *testing.T) {
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: 1 * GB, CPUs: 1, Disk: protocol.DiskHDD}, Settings: pgDefaults()})
	wantValues(t, got, map[string]string{
		"shared_buffers":           "256MB",
		"effective_cache_size":     "768MB",
		"maintenance_work_mem":     "", // 1 GB / 16 = 64 MB, the default
		"work_mem":                 "", // the 4 MB floor
		"random_page_cost":         "", // not on a spinning (or unknown) disk
		"effective_io_concurrency": "",
		"max_parallel_workers":     "", // fewer than 4 CPUs
	})
}

func TestRecommendAnalytics64GB(t *testing.T) {
	s := pgDefaults()
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: 64 * GB, CPUs: 16, Disk: protocol.DiskSSD},
		Workload: protocol.WorkloadAnalytics, Settings: s, DatabaseBytes: 300 * GB})
	wantValues(t, got, map[string]string{
		"shared_buffers":       "16GB",
		"effective_cache_size": "48GB",
		"maintenance_work_mem": "2GB", // 64 GB / 8, at most 2 GB
		// 48 GB / ((100 + 16) * 3) / 8 per gather / 2 = 8.8 MB
		"work_mem":                            "8MB",
		"max_worker_processes":                "16",
		"max_parallel_workers":                "16",
		"max_parallel_workers_per_gather":     "8", // no cap of 4 for analytics
		"max_parallel_maintenance_workers":    "4",
		"default_statistics_target":           "500",
		"max_wal_size":                        "16GB",
		"min_wal_size":                        "4GB",
		"autovacuum_vacuum_scale_factor":      "0.05",
		"autovacuum_analyze_scale_factor":     "0.02",
		"idle_in_transaction_session_timeout": "",
		"shared_preload_libraries":            "", // not installed
	})
}

func TestRecommendMixedCapsWALByDisk(t *testing.T) {
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: 8 * GB, CPUs: 2, DataDiskBytes: 20 * GB}, Settings: pgDefaults()})
	wantValues(t, got, map[string]string{
		"shared_buffers": "2GB",
		// (8 GB - 2 GB) / 324 / 2 per gather / 2 (mixed) = 4.7 MB: close to the default
		"work_mem":     "",
		"max_wal_size": "2GB", // a tenth of the 20 GB disk
		"min_wal_size": "512MB",
	})
}

func TestRecommendLeavesChosenAndPendingValues(t *testing.T) {
	s := pgDefaults()
	sb := s["shared_buffers"]
	sb.Setting = "786432" // 6 GB, chosen on purpose: 1.5x the recommendation
	s["shared_buffers"] = sb
	ecs := s["effective_cache_size"]
	ecs.Setting, ecs.Source = "131072", "configuration file" // 1 GB: far below
	s["effective_cache_size"] = ecs
	mwm := s["maintenance_work_mem"]
	mwm.PendingRestart, mwm.PendingValue = true, "1GB" // not a restart setting, but pending values win
	s["maintenance_work_mem"] = mwm
	lib := s["shared_preload_libraries"]
	lib.PendingRestart, lib.PendingValue = true, "pg_stat_statements"
	s["shared_preload_libraries"] = lib
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: 16 * GB, CPUs: 2}, Settings: s, PgStatStatements: "available"})
	wantValues(t, got, map[string]string{
		"shared_buffers":           "",
		"effective_cache_size":     "12GB",
		"maintenance_work_mem":     "",
		"shared_preload_libraries": "",
	})
}

func TestRecommendUnknownMemory(t *testing.T) {
	got := recs(Input{Host: protocol.SettingsHost{CPUs: 8}, Settings: pgDefaults()})
	for _, name := range []string{"shared_buffers", "effective_cache_size", "work_mem", "maintenance_work_mem"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s recommended without knowing the memory", name)
		}
	}
	if got["max_wal_size"].Value != "4GB" {
		t.Error("max_wal_size doesn't depend on memory")
	}
}

func TestRecommendKeepsExistingLibraries(t *testing.T) {
	s := pgDefaults()
	lib := s["shared_preload_libraries"]
	lib.Setting, lib.Source = "auto_explain", "configuration file"
	s["shared_preload_libraries"] = lib
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: 4 * GB}, Settings: s, PgStatStatements: "available"})
	if v := got["shared_preload_libraries"].Value; v != "auto_explain,pg_stat_statements" {
		t.Errorf("shared_preload_libraries = %q", v)
	}
}

func TestRecommendRoundsMemory(t *testing.T) {
	// A "16 GB" server shows a little less.
	ram := int64(16_384_000) * KB
	got := recs(Input{Host: protocol.SettingsHost{MemoryBytes: ram}, Settings: pgDefaults()})
	if v := got["shared_buffers"].Value; v != "3840MB" {
		t.Errorf("shared_buffers = %q, want 3840MB (256 MB steps)", v)
	}
}

func TestUnits(t *testing.T) {
	cases := []struct {
		value, unit string
		want        float64
	}{
		{"16384", "8kB", float64(128 * MB)},
		{"4GB", "8kB", float64(4 * GB)},
		{"512 MB", "kB", float64(512 * MB)},
		{"1024", "MB", float64(GB)},
		{"250", "ms", 250},
		{"10min", "ms", 600_000},
		{"1.5h", "s", 5_400_000},
		{"30", "s", 30_000},
		{"0.9", "", 0.9},
	}
	for _, c := range cases {
		got, ok := Quantity(c.value, c.unit)
		if !ok || got != c.want {
			t.Errorf("Quantity(%q, %q) = %v, %v; want %v", c.value, c.unit, got, ok, c.want)
		}
	}
	for _, bad := range [][2]string{{"4 gigs", "kB"}, {"lots", "8kB"}, {"4GB", "ms"}} {
		if _, ok := Quantity(bad[0], bad[1]); ok {
			t.Errorf("Quantity(%q, %q) accepted", bad[0], bad[1])
		}
	}
	for b, want := range map[int64]string{4 * GB: "4GB", 3840 * MB: "3840MB", 64 * KB: "64kB", 1500: "1500B"} {
		if got := PGBytes(b); got != want {
			t.Errorf("PGBytes(%d) = %q, want %q", b, got, want)
		}
	}
	for b, want := range map[int64]string{128 * MB: "128 MB", 3840 * MB: "3.75 GB", 16 * GB: "16 GB", 512: "512 B"} {
		if got := HumanBytes(b); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", b, got, want)
		}
	}
	for _, c := range [][5]string{
		{"shared_buffers", "16384", "8kB", "integer", "128 MB"},
		{"idle_in_transaction_session_timeout", "0", "ms", "integer", "off"},
		{"idle_in_transaction_session_timeout", "600000", "ms", "integer", "10 min"},
		{"log_min_duration_statement", "-1", "ms", "integer", "off"},
		{"wal_buffers", "-1", "8kB", "integer", "automatic"},
		{"shared_preload_libraries", "", "", "string", "(none)"},
		{"checkpoint_timeout", "300", "s", "integer", "5 min"},
		{"jit", "on", "", "bool", "on"},
	} {
		if got := Display(c[0], c[1], c[2], c[3]); got != c[4] {
			t.Errorf("Display(%s=%s) = %q, want %q", c[0], c[1], got, c[4])
		}
	}
}

func refusal(t *testing.T, changes []protocol.SettingChange, f Facts) string {
	t.Helper()
	err := Validate(Normalize(changes), f)
	if err == nil {
		return ""
	}
	var r *Refusal
	if !errors.As(err, &r) {
		t.Fatalf("not a refusal: %v", err)
	}
	return r.Error()
}

func TestValidate(t *testing.T) {
	f := Facts{Host: protocol.SettingsHost{MemoryBytes: 16 * GB}, Settings: pgDefaults()}
	set := func(name, value string) []protocol.SettingChange {
		return []protocol.SettingChange{{Name: name, Value: value}}
	}
	ok := [][]protocol.SettingChange{
		set("shared_buffers", "4GB"),
		set("Work_Mem", " 64MB "),
		set("log_lock_waits", "on"),
		set("wal_level", "logical"),
		set("shared_preload_libraries", "pg_stat_statements"),
		{{Name: "max_connections", Value: "200"}, {Name: "shared_buffers", Value: "4GB"}},
		{{Name: "work_mem", Reset: true}},
		set("some_unknown_setting", "1"), // left to the agent, which knows every setting
	}
	f.PgStatStatements = "available"
	for _, c := range ok {
		if msg := refusal(t, c, f); msg != "" {
			t.Errorf("%v refused: %s", c, msg)
		}
	}
	refused := []struct {
		changes []protocol.SettingChange
		want    string
	}{
		{set("archive_command", "cp %p /x"), "never changes"},
		{set("archive_mode", "off"), "stop backups"},
		{set("recovery_target_time", "2026-01-01"), "never changes"},
		{set("port", "5433"), "agent reaches"},
		{set("shared_buffers", "12GB"), "more than 60%"},
		{set("work_mem", "8GB"), "a quarter"},
		{set("maintenance_work_mem", "10GB"), "half"},
		{set("effective_cache_size", "32GB"), "more than the server"},
		{set("wal_level", "minimal"), "replica"},
		{set("huge_pages", "on"), "refuses to start"},
		{set("shared_preload_libraries", "pg_stat_statements,timescaledb"), "timescaledb"},
		{set("max_connections", "3"), "kept for administrators"},
		{set("max_connections", "50000"), "pooler"},
		{set("listen_addresses", "*"), "restart settings it knows"},
		{set("block_size", "4096"), "doesn't allow"},
		{set("log_lock_waits", "maybe"), "on or off"},
		{set("huge_pages", "sometimes"), "one of"},
		{set("work_mem", "lots"), "unit"},
		{set("work_mem", ""), "give a value"},
		{set("work_mem", "1\\2"), "backslashes"},
		{set("bad name;", "1"), "not a setting name"},
		{[]protocol.SettingChange{{Name: "work_mem", Value: "8MB"}, {Name: "work_mem", Value: "16MB"}}, "twice"},
		{nil, "no settings"},
	}
	for _, c := range refused {
		msg := refusal(t, c.changes, f)
		if !strings.Contains(msg, c.want) {
			t.Errorf("%v: refusal %q, want it to mention %q", c.changes, msg, c.want)
		}
	}
	// The agent knows every setting: unknown names are refused there.
	f.Complete = true
	if msg := refusal(t, set("some_unknown_setting", "1"), f); !strings.Contains(msg, "no setting") {
		t.Errorf("unknown setting on the agent: %q", msg)
	}
	// And checks libraries on disk.
	f.LibraryInstalled = func(lib string) bool { return lib == "timescaledb" }
	if msg := refusal(t, set("shared_preload_libraries", "timescaledb"), f); msg != "" {
		t.Errorf("installed library refused: %s", msg)
	}
	// huge_pages=on stays allowed where it is on already.
	hp := f.Settings["huge_pages"]
	hp.Setting = "on"
	f.Settings["huge_pages"] = hp
	if msg := refusal(t, set("huge_pages", "on"), f); msg != "" {
		t.Errorf("huge_pages=on where it is on: %s", msg)
	}
}

func TestLibraries(t *testing.T) {
	if got := WithLibrary("", "pg_stat_statements"); got != "pg_stat_statements" {
		t.Errorf("WithLibrary empty = %q", got)
	}
	if got := WithLibrary(`auto_explain, "pg_stat_statements"`, "pg_stat_statements"); got != "auto_explain,pg_stat_statements" {
		t.Errorf("WithLibrary present = %q", got)
	}
}
