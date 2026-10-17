package localcp

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// softwareBeat is a heartbeat with a software report: PostgreSQL 16.9 on
// port 5432, 17 and 18 offered, what root allowed, and the upgrades.
func softwareBeat(a *fakeAgent, allowed []string, ups ...protocol.UpgradeState) {
	a.t.Helper()
	sw := &protocol.SoftwareReport{CheckedAt: time.Now(), PackageManager: "apt", Allowed: allowed,
		HelperActions: []string{"pg-minor-update", "pg-install-major", "pg-upgrade", "pg-upgrade-undo", "pg-upgrade-cleanup"},
		Clusters: []protocol.ClusterSoftware{{Port: 5432, Major: 16, Cluster: "main", Running: "16.9", Installed: "16.9",
			Candidate: "16.9", Majors: []int{17, 18}}},
		Upgrades: ups}
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.22",
		RestartPorts: []int{5432}, Software: sw}, nil)
}

func taskTypes(ts []protocol.TaskView) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.Type)
	}
	return out
}

func TestUpgrade(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)

	// Before the agent looked at the packages: no upgrade.
	info, err := c.Upgrades(ctx, "shop")
	if err != nil || !strings.Contains(info.UpgradeReason, "hasn't looked") {
		t.Fatalf("upgrades before a software report: %+v %v", info, err)
	}
	// Root didn't allow it.
	softwareBeat(a, nil)
	if info, _ = c.Upgrades(ctx, "shop"); !strings.Contains(info.UpgradeReason, "sudo rowsafe-allow updates") {
		t.Fatalf("not allowed: %q", info.UpgradeReason)
	}
	softwareBeat(a, []string{protocol.UpdateAllowPostgres})
	info, err = c.Upgrades(ctx, "shop")
	if err != nil || info.UpgradeReason != "" || info.Version != "16.9" || info.Major != 16 || !slices.Equal(info.Majors, []int{17, 18}) {
		t.Fatalf("upgrades: %+v %v", info, err)
	}

	// The upgrade needs a rehearsal first.
	if _, err := c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 17, Mode: protocol.UpgradeSafe, Confirm: "shop"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "Rehearse the upgrade to PostgreSQL 17 first") {
		t.Fatalf("an upgrade without a rehearsal: %v", err)
	}
	if _, err := c.CheckUpgrade(ctx, "shop", 16); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("checking an upgrade to the same major: %v", err)
	}
	resp, err := c.CheckUpgrade(ctx, "shop", 17)
	if err != nil || len(resp.Tasks) != 1 {
		t.Fatalf("check: %+v %v", resp, err)
	}
	if _, err := c.RehearseUpgrade(ctx, "shop", 17); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a rehearsal while the check is open: %v", err)
	}
	chk := a.claimOne(protocol.TaskUpgradeCheck)
	var cp protocol.UpgradeCheckParams
	_ = json.Unmarshal(chk.Params, &cp)
	if cp.ToMajor != 17 {
		t.Fatalf("check params: %s", chk.Params)
	}
	a.done(chk, protocol.StatusSucceeded, protocol.UpgradeCheckResult{FromMajor: 16, ToMajor: 17, CanRehearse: true, CanUpgrade: true})
	if _, err := c.RehearseUpgrade(ctx, "shop", 17); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	a.done(a.claimOne(protocol.TaskUpgradeRehearsal), protocol.StatusSucceeded, protocol.UpgradeRehearsalResult{FromMajor: 16, ToMajor: 17,
		Passed: true, SafeDowntimeSeconds: 40, FastDowntimeSeconds: 8})
	softwareBeat(a, []string{protocol.UpdateAllowPostgres})
	info, _ = c.Upgrades(ctx, "shop")
	if !info.RehearsalValid || info.Rehearsal.ToMajor != 17 || info.Check == nil || len(info.Tasks) != 2 {
		t.Fatalf("after the rehearsal: %+v", info)
	}

	// A rehearsal of 17 doesn't allow 18; the name confirms.
	if _, err := c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 18, Mode: protocol.UpgradeSafe, Confirm: "shop"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("an upgrade to 18 after rehearsing 17: %v", err)
	}
	if _, err := c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 17, Mode: protocol.UpgradeSafe, Confirm: "nope"}); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), "stops it for about 40 seconds") {
		t.Fatalf("a wrong confirmation: %v", err)
	}
	if _, err := c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 17, Mode: "slow", Confirm: "shop"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("an unknown mode: %v", err)
	}
	resp, err = c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 17, Mode: protocol.UpgradeSafe, Confirm: "shop"})
	if err != nil || !slices.Equal(taskTypes(resp.Tasks), []string{protocol.TaskRestorePoint, protocol.TaskUpgrade}) {
		t.Fatalf("upgrade: %+v %v", resp, err)
	}
	if _, err := c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 17, Mode: protocol.UpgradeSafe, Confirm: "shop"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second upgrade while one is queued: %v", err)
	}
	// The Mark first: the upgrade waits for it.
	if task := a.claimOne("", protocol.TaskUpgrade); task != nil {
		t.Fatal("the upgrade ran before its Mark")
	}
	mark := a.claimOne(protocol.TaskRestorePoint)
	var rp protocol.RestorePointParams
	_ = json.Unmarshal(mark.Params, &rp)
	a.done(mark, protocol.StatusSucceeded, protocol.RestorePointResult{Name: rp.Name, LSN: "0/5000000", Archived: true, CreatedAt: *now})
	up := a.claimOne(protocol.TaskUpgrade)
	var p protocol.UpgradeParams
	_ = json.Unmarshal(up.Params, &p)
	if p.ToMajor != 17 || p.Mode != protocol.UpgradeSafe || p.Mark != rp.Name || !strings.HasPrefix(p.Mark, "before-upgrade-17-") ||
		p.MarkBackupSet != "20261014-120000F" || p.KeepDays != upgradeKeepDays || p.UpgradeID == "" {
		t.Fatalf("upgrade params: %+v (Mark %s)", p, rp.Name)
	}
	// Nothing that needs PostgreSQL running beside it.
	if _, err := c.CreateRestorePoint(ctx, "shop", "during"); err != nil {
		t.Fatal(err)
	}
	if task := a.claimOne(""); task != nil {
		t.Fatalf("%s ran while PostgreSQL is stopped for the upgrade", task.Type)
	}
	a.done(up, protocol.StatusSucceeded, protocol.UpgradeResult{UpgradeID: p.UpgradeID, FromMajor: 16, ToMajor: 17, Mode: protocol.UpgradeSafe, BackupsReady: true})
	// Then the new version is inspected, backed up in full and proven.
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "during", LSN: "0/6000000", CreatedAt: *now})
	a.done(a.claimOne(protocol.TaskInspect), protocol.StatusSucceeded, protocol.InspectResult{ServerVersion: "17.6", VersionNum: 170006})
	backup := a.claimOne(protocol.TaskBackup)
	var bp protocol.BackupParams
	_ = json.Unmarshal(backup.Params, &bp)
	if bp.Type != protocol.BackupFull {
		t.Fatalf("the backup after the upgrade: %s", backup.Params)
	}
	a.done(backup, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-140000F", Type: protocol.BackupFull, StartedAt: *now, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})

	// The agent reports the upgrade it keeps PostgreSQL 16 for.
	kept := protocol.UpgradeState{ID: p.UpgradeID, DatabaseID: db.ID, Port: 5432, FromMajor: 16, ToMajor: 17, Mode: protocol.UpgradeSafe,
		Status: protocol.UpgradeDone, CreatedAt: *now, BackupsReady: true, Mark: p.Mark}
	softwareBeat(a, []string{protocol.UpdateAllowPostgres}, kept)
	info, _ = c.Upgrades(ctx, "shop")
	if info.Upgrade == nil || info.Upgrade.ID != p.UpgradeID {
		t.Fatalf("the kept upgrade: %+v", info.Upgrade)
	}
	if _, err := c.Upgrade(ctx, "shop", protocol.UpgradeRequest{To: 18, Mode: protocol.UpgradeSafe, Confirm: "shop"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "still keeps PostgreSQL 16") {
		t.Fatalf("upgrading again while 16 is kept: %v", err)
	}

	// Undo: confirmed, after a Mark.
	if _, err := c.UndoUpgrade(ctx, "shop", "upg_other", "shop"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("undo of another upgrade: %v", err)
	}
	if _, err := c.UndoUpgrade(ctx, "shop", p.UpgradeID, "nope"); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("undo without the name: %v", err)
	}
	resp, err = c.UndoUpgrade(ctx, "shop", p.UpgradeID, "shop")
	if err != nil || !slices.Equal(taskTypes(resp.Tasks), []string{protocol.TaskRestorePoint, protocol.TaskUpgradeUndo}) {
		t.Fatalf("undo: %+v %v", resp, err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{LSN: "0/7000000", CreatedAt: *now})
	undo := a.claimOne(protocol.TaskUpgradeUndo)
	a.done(undo, protocol.StatusSucceeded, protocol.UpgradeUndoResult{UpgradeID: p.UpgradeID, Version: "16.9", BackupsReady: true})
	if task := a.claimOne(protocol.TaskInspect); task == nil {
		t.Fatal("no inspect after the undo")
	}
	kept.Status = protocol.UpgradeUndone
	softwareBeat(a, []string{protocol.UpdateAllowPostgres}, kept)
	if _, err := c.UndoUpgrade(ctx, "shop", p.UpgradeID, "shop"); apiStatus(err) != http.StatusConflict {
		t.Fatalf("undoing twice: %v", err)
	}

	// Removing the kept 17.
	if _, err := c.CleanupUpgrade(ctx, "shop", p.UpgradeID, "nope"); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), "Removing PostgreSQL 17") {
		t.Fatalf("cleanup without the name: %v", err)
	}
	resp, err = c.CleanupUpgrade(ctx, "shop", p.UpgradeID, "shop")
	if err != nil || !slices.Equal(taskTypes(resp.Tasks), []string{protocol.TaskUpgradeCleanup}) {
		t.Fatalf("cleanup: %+v %v", resp, err)
	}

	// The state survives a restart of the control plane.
	s2, err := Open(fileDir(s), nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.st.read(func(st *state) {
		if st.Host.Software == nil || len(st.Host.Software.Upgrades) != 1 {
			t.Fatalf("the software report wasn't kept: %+v", st.Host.Software)
		}
	})
}

func TestUpgradeRefusals(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	activeDB(t, a, c, now)

	// In Docker, the image is the compose file's to change.
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", RestartPorts: []int{5432},
		Software: &protocol.SoftwareReport{Container: true}}, nil)
	if info, _ := c.Upgrades(ctx, "shop"); !info.Sidecar || !strings.Contains(info.UpgradeReason, "Docker") {
		t.Fatalf("in Docker: %+v", info)
	}
	// Restarts not allowed.
	sw := &protocol.SoftwareReport{PackageManager: "apt", Allowed: []string{protocol.UpdateAllowPostgres}, HelperActions: []string{"pg-upgrade"}}
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", Software: sw}, nil)
	if info, _ := c.Upgrades(ctx, "shop"); !strings.Contains(info.UpgradeReason, "sudo rowsafe-allow restart") {
		t.Fatalf("without restarts: %q", info.UpgradeReason)
	}
	// The agent stopped.
	*now = now.Add(10 * time.Minute)
	if info, _ := c.Upgrades(ctx, "shop"); !strings.Contains(info.UpgradeReason, "isn't running") {
		t.Fatalf("agent away: %q", info.UpgradeReason)
	}
	if _, err := c.RehearseUpgrade(ctx, "shop", 17); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a rehearsal with the agent away: %v", err)
	}
	if _, err := c.Upgrades(ctx, "nope"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("an unknown database: %v", err)
	}
}

func TestUpgradeNeedsActive(t *testing.T) {
	_, a, c, _ := setup(t)
	ctx := context.Background()
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "shop", Port: 5432}); err != nil {
		t.Fatal(err)
	}
	softwareBeat(a, []string{protocol.UpdateAllowPostgres})
	if _, err := c.RehearseUpgrade(ctx, "shop", 17); apiStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "Turn on backups") {
		t.Fatalf("a rehearsal before backups: %v", err)
	}
}

func fileDir(s *Server) string { return strings.TrimSuffix(s.st.path, "/"+StateFile) }
