package agent

import (
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

const ourCmd = "/usr/bin/pgbackrest --config=/etc/rowsafe/pgbackrest/app.conf --stanza=app archive-push %p"

// appToday mirrors TvHub production as documented in ~/code/infra:
// PostgreSQL 18.4 with archive_mode=off.
func appToday() protocol.InspectResult {
	return protocol.InspectResult{
		ServerVersion: "18.4", VersionNum: 180004, DataDirectory: "/var/lib/postgresql/18/main",
		IsSuperuser: true, WalLevel: "replica", ArchiveMode: "off", ArchiveCommand: "(disabled)",
	}
}

func settings(p Plan) map[string]string { return p.Settings }

func TestPlanAdoptFreshCluster(t *testing.T) {
	p, err := PlanAdopt(appToday(), "/etc/rowsafe/pgbackrest/app.conf", ourCmd, false)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"archive_mode": "on", "archive_command": ourCmd, "archive_timeout": "60"}
	for k, v := range want {
		if settings(p)[k] != v {
			t.Errorf("setting %s = %q, want %q", k, settings(p)[k], v)
		}
	}
	if _, ok := settings(p)["wal_level"]; ok {
		t.Error("wal_level is already replica and should not change")
	}
	if !p.Restart {
		t.Error("turning on archive_mode needs a restart")
	}
}

func TestPlanAdoptAlreadyAdoptedIsNoop(t *testing.T) {
	in := appToday()
	in.ArchiveMode, in.ArchiveCommand, in.ArchiveTimeoutSeconds = "on", ourCmd, 60
	p, err := PlanAdopt(in, "/etc/rowsafe/pgbackrest/app.conf", ourCmd, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Settings) != 0 || p.Restart {
		t.Errorf("expected no setting changes and no restart, got %v restart=%v", p.Settings, p.Restart)
	}
}

func TestPlanAdoptPendingRestartStillNeedsRestart(t *testing.T) {
	in := appToday()
	in.ArchiveMode, in.ArchiveCommand, in.ArchiveTimeoutSeconds = "on", ourCmd, 60
	in.PendingRestart = []string{"archive_mode"}
	p, err := PlanAdopt(in, "x", ourCmd, false)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Restart {
		t.Error("a pending archive_mode change still requires a restart")
	}
}

func TestPlanAdoptMinimalWalLevel(t *testing.T) {
	in := appToday()
	in.WalLevel = "minimal"
	p, err := PlanAdopt(in, "x", ourCmd, false)
	if err != nil {
		t.Fatal(err)
	}
	if settings(p)["wal_level"] != "replica" {
		t.Errorf("wal_level should become replica, got %q", settings(p)["wal_level"])
	}
}

func TestPlanAdoptRefusesForeignArchiver(t *testing.T) {
	in := appToday()
	in.ArchiveMode, in.ArchiveCommand = "on", "wal-g wal-push %p"
	if _, err := PlanAdopt(in, "x", ourCmd, false); err == nil || !strings.Contains(err.Error(), "wal-g") {
		t.Fatalf("expected refusal naming the existing archive_command, got %v", err)
	}
	p, err := PlanAdopt(in, "x", ourCmd, true)
	if err != nil {
		t.Fatal(err)
	}
	if settings(p)["archive_command"] != ourCmd || len(p.Warnings) == 0 {
		t.Errorf("force should replace with a warning; got %v %v", p.Settings, p.Warnings)
	}
	if p.Restart {
		t.Error("changing archive_command alone only needs a reload")
	}
}

func TestPlanAdoptRefusesArchiveLibrary(t *testing.T) {
	in := appToday()
	in.ArchiveMode, in.ArchiveCommand, in.ArchiveLibrary = "on", "", "basic_archive"
	if _, err := PlanAdopt(in, "x", ourCmd, false); err == nil {
		t.Fatal("expected refusal when archive_library is set")
	}
	p, err := PlanAdopt(in, "x", ourCmd, true)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := settings(p)["archive_library"]; !ok || v != "" {
		t.Errorf("force should reset archive_library, got %v", p.Settings)
	}
}

func TestPlanAdoptPreconditions(t *testing.T) {
	cases := map[string]func(*protocol.InspectResult){
		"not superuser": func(in *protocol.InspectResult) { in.IsSuperuser = false },
		"standby":       func(in *protocol.InspectResult) { in.InRecovery = true },
		"too old":       func(in *protocol.InspectResult) { in.VersionNum, in.ServerVersion = 120015, "12.15" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := appToday()
			mutate(&in)
			if _, err := PlanAdopt(in, "x", ourCmd, true); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestPlanAdoptLowersArchiveTimeoutToAMinute(t *testing.T) {
	in := appToday()
	in.ArchiveMode, in.ArchiveCommand, in.ArchiveTimeoutSeconds = "on", ourCmd, 300
	p, err := PlanAdopt(in, "x", ourCmd, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := settings(p)["archive_timeout"]; got != "60" || p.Restart {
		t.Errorf("archive_timeout 300 -> %q (restart %v); want 60 with a reload only", got, p.Restart)
	}
}

func TestPlanAdoptKeepsShorterArchiveTimeout(t *testing.T) {
	in := appToday()
	in.ArchiveTimeoutSeconds = 30
	p, _ := PlanAdopt(in, "x", ourCmd, false)
	if _, ok := settings(p)["archive_timeout"]; ok {
		t.Error("a stricter archive_timeout should be left alone")
	}
}

// ---- docker-sidecar mode ----

const spoolCmd = `f=/rowsafe-spool/app/%f; if test -f "$f"; then cmp -s %p "$f"; else cp %p "$f.tmp" && sync "$f.tmp" && mv "$f.tmp" "$f" && sync /rowsafe-spool/app; fi # rowsafe spool: the rowsafe-agent sidecar pushes these files with pgbackrest archive-push`

func sidecarInput(force bool) PlanInput {
	return PlanInput{Mode: ModeDockerSidecar, ConfigPath: "/var/lib/rowsafe/pgbackrest/app.conf",
		ArchiveCommand: spoolCmd, SpoolDir: "/rowsafe-spool/app", Force: force}
}

// dockerToday is a stock postgres:17 container: archive_mode off.
func dockerToday() protocol.InspectResult {
	return protocol.InspectResult{
		ServerVersion: "17.6 (Debian 17.6-1.pgdg13+1)", VersionNum: 170006, DataDirectory: "/var/lib/postgresql/data",
		IsSuperuser: true, WalLevel: "replica", ArchiveMode: "off", ArchiveCommand: "(disabled)",
	}
}

func TestSpoolCommandMatchesGenerator(t *testing.T) {
	cmd, err := pgbackrest.SpoolArchiveCommand("/rowsafe-spool", "app")
	if err != nil || cmd != spoolCmd {
		t.Fatalf("generator changed; update the test fixture:\n%s", cmd)
	}
}

func TestPlanSidecarFreshContainer(t *testing.T) {
	p, err := PlanAdoptInput(dockerToday(), sidecarInput(false))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"archive_mode": "on", "archive_command": spoolCmd, "archive_timeout": "60"}
	for k, v := range want {
		if p.Settings[k] != v {
			t.Errorf("setting %s = %q, want %q", k, p.Settings[k], v)
		}
	}
	if !p.Restart || !strings.Contains(strings.Join(p.Warnings, " "), "docker compose restart") {
		t.Errorf("restart warning should tell how to restart the container: %v", p.Warnings)
	}
	var spool bool
	for _, c := range p.Changes {
		spool = spool || strings.Contains(c.Description, "/rowsafe-spool/app")
	}
	if !spool {
		t.Error("the plan should say it creates the spool directory")
	}
}

func TestPlanSidecarIdempotent(t *testing.T) {
	in := dockerToday()
	in.ArchiveMode, in.ArchiveCommand, in.ArchiveTimeoutSeconds = "on", spoolCmd, 60
	p, err := PlanAdoptInput(in, sidecarInput(false))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Settings) != 0 || p.Restart || len(p.Warnings) != 0 {
		t.Errorf("re-plan after apply must change nothing: %v %v %v", p.Settings, p.Restart, p.Warnings)
	}
	// Applied but not yet restarted: the command is read from the file.
	in.ArchiveMode, in.PendingRestart = "off", []string{"archive_mode"}
	p, err = PlanAdoptInput(in, sidecarInput(false))
	if _, changed := p.Settings["archive_command"]; err != nil || changed || !p.Restart {
		t.Errorf("pending restart: %v %v %v", p.Settings, p.Restart, err)
	}
}

func TestPlanSidecarUpdatesItsOwnOlderCommand(t *testing.T) {
	in := dockerToday()
	in.ArchiveMode, in.ArchiveTimeoutSeconds = "on", 60
	in.ArchiveCommand = `f=/rowsafe-spool/app/%f; test ! -f "$f" && cp %p "$f" # rowsafe spool (older agent)`
	p, err := PlanAdoptInput(in, sidecarInput(false))
	if err != nil {
		t.Fatalf("our own older spool command needs no force: %v", err)
	}
	if p.Settings["archive_command"] != spoolCmd {
		t.Errorf("settings %v", p.Settings)
	}
}

func TestPlanSidecarRefusesNativeCommandEvenWithForce(t *testing.T) {
	for _, cmd := range []string{ourCmd, "pgbackrest --stanza=main archive-push %p"} {
		in := dockerToday()
		in.ArchiveMode, in.ArchiveCommand = "on", cmd
		for _, force := range []bool{false, true} {
			_, err := PlanAdoptInput(in, sidecarInput(force))
			if err == nil || !strings.Contains(err.Error(), "docker-sidecar") || !strings.Contains(err.Error(), "ALTER SYSTEM RESET archive_command") {
				t.Errorf("force=%v cmd=%q: expected refusal, got %v", force, cmd, err)
			}
		}
	}
}

func TestPlanNativeRefusesSpoolCommandEvenWithForce(t *testing.T) {
	in := appToday()
	in.ArchiveMode, in.ArchiveCommand = "on", spoolCmd
	for _, force := range []bool{false, true} {
		_, err := PlanAdopt(in, "/etc/rowsafe/pgbackrest/app.conf", ourCmd, force)
		if err == nil || !strings.Contains(err.Error(), "native") || !strings.Contains(err.Error(), "/rowsafe-spool/app") {
			t.Errorf("force=%v: expected refusal, got %v", force, err)
		}
	}
}

func TestPlanSidecarOtherSpoolNeedsForce(t *testing.T) {
	in := dockerToday()
	in.ArchiveMode = "on"
	in.ArchiveCommand = strings.ReplaceAll(spoolCmd, "/rowsafe-spool/app", "/rowsafe-spool/other")
	if _, err := PlanAdoptInput(in, sidecarInput(false)); err == nil || !strings.Contains(err.Error(), "/rowsafe-spool/other") {
		t.Fatalf("expected refusal naming the other spool, got %v", err)
	}
	p, err := PlanAdoptInput(in, sidecarInput(true))
	if err != nil || p.Settings["archive_command"] != spoolCmd || len(p.Warnings) == 0 {
		t.Errorf("force: %v %v %v", p.Settings, p.Warnings, err)
	}
}

func TestPlanSidecarForeignArchiverNeedsForce(t *testing.T) {
	in := dockerToday()
	in.ArchiveMode, in.ArchiveCommand = "on", "wal-g wal-push %p"
	if _, err := PlanAdoptInput(in, sidecarInput(false)); err == nil || !strings.Contains(err.Error(), "wal-g") {
		t.Fatalf("expected refusal, got %v", err)
	}
	if p, err := PlanAdoptInput(in, sidecarInput(true)); err != nil || p.Settings["archive_command"] != spoolCmd {
		t.Errorf("force: %v %v", p.Settings, err)
	}
}
