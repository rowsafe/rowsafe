package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

func TestAlterSystemStmtLists(t *testing.T) {
	cases := map[protocol.SettingChange]string{
		{Name: "shared_preload_libraries", Value: "pg_stat_statements, auto_explain"}: `ALTER SYSTEM SET "shared_preload_libraries" = 'pg_stat_statements', 'auto_explain'`,
		{Name: "shared_preload_libraries", Value: `"pg_stat_statements"`}:             `ALTER SYSTEM SET "shared_preload_libraries" = 'pg_stat_statements'`,
		{Name: "shared_preload_libraries", Reset: true}:                               `ALTER SYSTEM RESET "shared_preload_libraries"`,
		{Name: "work_mem", Value: "64MB"}:                                             `ALTER SYSTEM SET "work_mem" = '64MB'`,
		{Name: "log_line_prefix", Value: "%m [%p] it's"}:                              `ALTER SYSTEM SET "log_line_prefix" = '%m [%p] it''s'`,
	}
	for c, want := range cases {
		got, err := alterSystemStmt(c)
		if err != nil || got != want {
			t.Errorf("alterSystemStmt(%+v) = %q, %v; want %q", c, got, err, want)
		}
	}
	if _, err := alterSystemStmt(protocol.SettingChange{Name: "shared_preload_libraries", Value: "a', 'b"}); err == nil {
		t.Error("a quote inside a list element was accepted")
	}
}

func TestSameValue(t *testing.T) {
	mem := protocol.PGSetting{Name: "work_mem", Setting: "65536", Unit: "kB", VarType: "integer"}
	sb := protocol.PGSetting{Name: "shared_buffers", Setting: "8193", Unit: "8kB", VarType: "integer"}
	for _, c := range []struct {
		s    protocol.PGSetting
		want string
		same bool
	}{
		{mem, "64MB", true},
		{mem, "65536", true},
		{mem, "32MB", false},
		{sb, "64MB", true}, // within one 8kB page
		{protocol.PGSetting{Setting: "on", VarType: "bool"}, "true", true},
		{protocol.PGSetting{Setting: "off", VarType: "bool"}, "on", false},
		{protocol.PGSetting{Setting: "0.9", VarType: "real"}, "0.90", true},
		{protocol.PGSetting{Setting: "600000", Unit: "ms", VarType: "integer"}, "10min", true},
		{protocol.PGSetting{Setting: "Try", VarType: "enum"}, "try", true},
		{protocol.PGSetting{Name: "shared_preload_libraries", Setting: "pg_stat_statements, auto_explain", VarType: "string"}, "pg_stat_statements,auto_explain", true},
	} {
		if got := tune.SameValue(c.s, c.want); got != c.same {
			t.Errorf("sameValue(%s=%s, %s) = %v", c.s.Name, c.s.Setting, c.want, got)
		}
	}
}

func TestSettingsSummary(t *testing.T) {
	before := map[string]protocol.PGSetting{"work_mem": {Unit: "kB", VarType: "integer"}}
	for _, c := range []struct {
		changes []protocol.SettingChange
		pending int
		want    string
	}{
		{[]protocol.SettingChange{{Name: "work_mem", Value: "64MB"}}, 0, "Set work_mem to 64 MB. It is in effect now."},
		{[]protocol.SettingChange{{Name: "shared_buffers", Value: "4GB"}}, 1, "Set shared_buffers to 4GB. It takes effect when PostgreSQL restarts."},
		{[]protocol.SettingChange{{Name: "work_mem", Reset: true}}, 0, "Reset work_mem to its default. It is in effect now."},
		{[]protocol.SettingChange{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}, {Name: "c", Value: "3"}}, 1, "Changed 3 settings. 2 take effect at once; 1 when PostgreSQL restarts."},
		{[]protocol.SettingChange{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}, 2, "Changed 2 settings. They take effect when PostgreSQL restarts."},
	} {
		if got := settingsSummary(c.changes, c.pending, before); got != c.want {
			t.Errorf("summary = %q, want %q", got, c.want)
		}
	}
}

// settingsEnv runs settings tasks against the developer's PostgreSQL
// (/tmp:5432). ALTER SYSTEM changes the whole server, so the test touches
// only harmless settings and puts every one back as it was.
type settingsEnv struct {
	t    *testing.T
	a    *Agent
	spec protocol.DatabaseSpec
}

var settingsTestNames = []string{"log_lock_waits", "checkpoint_completion_target", "autovacuum_max_workers", "shared_preload_libraries", "work_mem"}

func newSettingsEnv(t *testing.T, memory string) *settingsEnv {
	tg := fixTestTarget(t)
	proc := t.TempDir()
	if err := os.WriteFile(filepath.Join(proc, "meminfo"), []byte("MemTotal: "+memory+" kB\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldProc, oldExt, oldWait := settingsProcRoot, settingsCreateExtension, settingsReloadWait
	settingsProcRoot, settingsCreateExtension, settingsReloadWait = proc, false, 3*time.Second
	e := &settingsEnv{t: t, a: &Agent{cfg: Config{PGUser: tg.User}}, spec: protocol.DatabaseSpec{SocketDir: tg.SocketDir, Port: tg.Port}}

	// Remember postgresql.auto.conf's lines for the settings used here.
	conn, err := tg.Connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	orig := map[string]string{}
	rows, err := conn.Query(t.Context(), `SELECT name, setting FROM pg_file_settings
		WHERE sourcefile LIKE '%postgresql.auto.conf' AND name = ANY($1) ORDER BY seqno`, settingsTestNames)
	if err != nil {
		t.Skipf("pg_file_settings: %v", err)
	}
	for rows.Next() {
		var n, v string
		if err := rows.Scan(&n, &v); err != nil {
			t.Fatal(err)
		}
		orig[n] = v
	}
	rows.Close()
	t.Cleanup(func() {
		settingsProcRoot, settingsCreateExtension, settingsReloadWait = oldProc, oldExt, oldWait
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := tg.Connect(ctx, "postgres")
		if err != nil {
			t.Errorf("restoring settings: %v", err)
			return
		}
		defer c.Close(ctx)
		for _, name := range settingsTestNames {
			ch := protocol.SettingChange{Name: name, Reset: true}
			if v, ok := orig[name]; ok {
				ch = protocol.SettingChange{Name: name, Value: v}
			}
			stmt, _ := alterSystemStmt(ch)
			if _, err := c.Exec(ctx, stmt); err != nil {
				t.Errorf("restoring %s: %v", name, err)
			}
		}
		_, _ = c.Exec(ctx, `SELECT pg_reload_conf()`)
	})
	return e
}

func (e *settingsEnv) run(kind string, changes ...protocol.SettingChange) (*protocol.SettingsResult, error, string) {
	e.t.Helper()
	tl := &taskLog{}
	res, err := e.a.changeSettings(e.t.Context(), e.spec, protocol.SettingsParams{Kind: kind, Changes: changes}, tl)
	return res, err, tl.String()
}

func (e *settingsEnv) setting(name string) protocol.PGSetting {
	e.t.Helper()
	snap, err := collect.ReadSettings(e.t.Context(), e.a.settingsTarget(e.spec), settingsProcRoot)
	if err != nil {
		e.t.Fatal(err)
	}
	s, ok := tune.SettingsMap(snap.Settings)[name]
	if !ok {
		e.t.Fatalf("%s not in the snapshot", name)
	}
	return s
}

// undo builds the revert of a result, as the control plane does.
func undo(res *protocol.SettingsResult) []protocol.SettingChange {
	var out []protocol.SettingChange
	for _, ap := range res.Applied {
		if ap.Previous == nil {
			out = append(out, protocol.SettingChange{Name: ap.Name, Reset: true})
		} else {
			out = append(out, protocol.SettingChange{Name: ap.Name, Value: *ap.Previous})
		}
	}
	return out
}

func TestSettingsAgainstPostgres(t *testing.T) {
	e := newSettingsEnv(t, "8388608") // 8 GB
	lockWaits := e.setting("log_lock_waits")
	target := "0.85"
	if e.setting("checkpoint_completion_target").Setting == "0.85" {
		target = "0.8"
	}
	newLock := "on"
	if lockWaits.Setting == "on" {
		newLock = "off"
	}

	// Two settings that apply at once.
	res, err, log := e.run(protocol.SettingsKindSet,
		protocol.SettingChange{Name: "log_lock_waits", Value: newLock},
		protocol.SettingChange{Name: "Checkpoint_Completion_Target", Value: target})
	if err != nil {
		t.Fatalf("%v\n%s", err, log)
	}
	if res.Summary != "Changed 2 settings. They are in effect now." || len(res.Applied) != 2 || res.Applied[0].Restart {
		t.Fatalf("result %+v", res)
	}
	if !strings.Contains(log, `ALTER SYSTEM SET "checkpoint_completion_target" = '`+target+`'`) || !strings.Contains(log, "configuration reloaded") {
		t.Errorf("log:\n%s", log)
	}
	if got := e.setting("log_lock_waits").Setting; got != newLock {
		t.Errorf("log_lock_waits = %s after the change, want %s", got, newLock)
	}
	if res.Snapshot == nil || tune.SettingsMap(res.Snapshot.Settings)["checkpoint_completion_target"].Setting != target {
		t.Error("the result's snapshot doesn't show the change")
	}

	// Undo puts the previous postgresql.auto.conf lines back.
	if _, err, log := e.run(protocol.SettingsKindRevert, undo(res)...); err != nil {
		t.Fatalf("undo: %v\n%s", err, log)
	}
	if got := e.setting("log_lock_waits").Setting; got != lockWaits.Setting {
		t.Errorf("log_lock_waits = %s after undo, want %s", got, lockWaits.Setting)
	}

	// A restart setting waits for a restart; nothing restarts.
	workers := e.setting("autovacuum_max_workers")
	if workers.Context == "postmaster" {
		n, _ := strconv.Atoi(workers.Setting)
		res, err, log := e.run(protocol.SettingsKindSet, protocol.SettingChange{Name: "autovacuum_max_workers", Value: strconv.Itoa(n + 1)})
		if err != nil {
			t.Fatalf("%v\n%s", err, log)
		}
		if !res.Applied[0].Restart || !slices.Contains(res.PendingRestart, "autovacuum_max_workers") ||
			!strings.Contains(res.Summary, "takes effect when PostgreSQL restarts") {
			t.Errorf("restart setting: %+v", res)
		}
		if s := e.setting("autovacuum_max_workers"); !s.PendingRestart || s.PendingValue != strconv.Itoa(n+1) || s.Setting != workers.Setting {
			t.Errorf("pending: %+v", s)
		}
		if _, err, log := e.run(protocol.SettingsKindRevert, undo(res)...); err != nil {
			t.Fatalf("undo: %v\n%s", err, log)
		}
		if s := e.setting("autovacuum_max_workers"); s.PendingRestart {
			t.Errorf("still pending after undo: %+v", s)
		}
	}

	// Libraries: one literal each, or PostgreSQL wouldn't start.
	var both bool
	conn, err := e.a.target(e.spec).Connect(t.Context(), "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	both = libraryInstalled(t.Context(), conn, "pg_stat_statements") && libraryInstalled(t.Context(), conn, "auto_explain")
	if libraryInstalled(t.Context(), conn, "no_such_library_here") {
		t.Error("a missing library counts as installed")
	}
	if both && e.setting("shared_preload_libraries").Setting == "" {
		res, err, log := e.run(protocol.SettingsKindSet, protocol.SettingChange{Name: "shared_preload_libraries", Value: "pg_stat_statements,auto_explain"})
		if err != nil {
			t.Fatalf("%v\n%s", err, log)
		}
		s := e.setting("shared_preload_libraries")
		if got := tune.Libraries(s.PendingValue); !slices.Equal(got, []string{"pg_stat_statements", "auto_explain"}) {
			t.Errorf("pending libraries %q (%+v)", got, s)
		}
		if _, err, log := e.run(protocol.SettingsKindRevert, undo(res)...); err != nil {
			t.Fatalf("undo: %v\n%s", err, log)
		}
	} else {
		t.Log("pg_stat_statements and auto_explain not both installed, or libraries already loaded: library list not tested")
	}
}

func TestSettingsRefusals(t *testing.T) {
	e := newSettingsEnv(t, "1048576") // 1 GB
	lockWaits := e.setting("log_lock_waits").Setting
	for _, c := range []struct {
		changes []protocol.SettingChange
		want    string
	}{
		{[]protocol.SettingChange{{Name: "archive_command", Value: "true"}}, "never changes"},
		{[]protocol.SettingChange{{Name: "no_such_setting_xyz", Value: "1"}}, "no setting"},
		{[]protocol.SettingChange{{Name: "shared_buffers", Value: "900MB"}}, "more than 60%"},
		{[]protocol.SettingChange{{Name: "shared_preload_libraries", Value: "no_such_library_here"}}, "isn't installed"},
		{[]protocol.SettingChange{{Name: "listen_addresses", Value: "*"}}, "restart settings it knows"},
		{[]protocol.SettingChange{{Name: "work_mem", Value: "lots"}}, "unit"},
	} {
		_, err, log := e.run(protocol.SettingsKindSet, c.changes...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: err %v, want %q\n%s", c.changes, err, c.want, log)
		}
		if strings.Contains(log, "ALTER SYSTEM") {
			t.Errorf("%v: refused, yet ran ALTER SYSTEM:\n%s", c.changes, log)
		}
	}

	// PostgreSQL refuses a value Rowsafe let through: the settings already
	// changed go back.
	other := "on"
	if lockWaits == "on" {
		other = "off"
	}
	_, err, log := e.run(protocol.SettingsKindSet,
		protocol.SettingChange{Name: "log_lock_waits", Value: other},
		protocol.SettingChange{Name: "checkpoint_completion_target", Value: "2"})
	if err == nil || !strings.Contains(err.Error(), "PostgreSQL refused") || !strings.Contains(err.Error(), "put the previous values back") {
		t.Fatalf("err %v\n%s", err, log)
	}
	if got := e.setting("log_lock_waits").Setting; got != lockWaits {
		t.Errorf("log_lock_waits = %s after the rollback, want %s", got, lockWaits)
	}
	if _, err, _ := e.run("bogus", protocol.SettingChange{Name: "work_mem", Value: "8MB"}); err == nil {
		t.Error("unknown kind accepted")
	}
}
