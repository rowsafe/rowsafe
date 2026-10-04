package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

const needrestartSample = `NEEDRESTART-VER: 3.6
NEEDRESTART-KCUR: 6.1.0-18-amd64
NEEDRESTART-KEXP: 6.1.0-21-amd64
NEEDRESTART-KSTA: 3
NEEDRESTART-UCSTA: 1
NEEDRESTART-SVC: postgresql@17-main.service
NEEDRESTART-SVC: pgbouncer.service
NEEDRESTART-SVC: postgresql@17-main.service
`

func TestParseNeedrestartBatch(t *testing.T) {
	b := parseNeedrestartBatch(needrestartSample)
	if !b.KernelPending || b.KernelRunning != "6.1.0-18-amd64" || b.KernelInstalled != "6.1.0-21-amd64" {
		t.Errorf("kernel: %+v", b)
	}
	if !slices.Equal(b.Services, []string{"postgresql@17-main.service", "pgbouncer.service"}) {
		t.Errorf("services: %q", b.Services)
	}
	for ksta, want := range map[string]bool{"0": false, "1": false, "2": true, "3": true} {
		if got := parseNeedrestartBatch("NEEDRESTART-KCUR: 6.1.0-21-amd64\nNEEDRESTART-KSTA: " + ksta + "\n").KernelPending; got != want {
			t.Errorf("KSTA %s: pending %v", ksta, got)
		}
	}
	if b := parseNeedrestartBatch(""); b.KernelPending || len(b.Services) > 0 {
		t.Errorf("empty: %+v", b)
	}
}

const historySample = `
Start-Date: 2026-09-28  06:12:01
Commandline: /usr/bin/unattended-upgrade
Upgrade: libssl3:amd64 (3.0.15-1~deb12u1, 3.0.16-1~deb12u1), openssl:amd64 (3.0.15-1~deb12u1, 3.0.16-1~deb12u1)
End-Date: 2026-09-28  06:12:09

Start-Date: 2026-09-29  14:03:44
Commandline: apt-get install -y -q --no-install-recommends pgbackrest
Requested-By: admin (1000)
Install: pgbackrest:amd64 (2.57.0-1.pgdg120+1), libssh2-1:amd64 (1.10.0-3+b1, automatic)
End-Date: 2026-09-29  14:03:50

Start-Date: 2026-09-30  06:25:13
Commandline: /usr/bin/unattended-upgrade
Install: linux-image-6.1.0-21-amd64:amd64 (6.1.90-1, automatic)
Upgrade: libssl3:amd64 (3.0.16-1~deb12u1, 3.0.17-1~deb12u2), openssl:amd64 (3.0.16-1~deb12u1, 3.0.17-1~deb12u2), linux-image-amd64:amd64 (6.1.85-1, 6.1.90-1)
End-Date: 2026-09-30  06:25:40

Start-Date: 2026-10-01  09:00:00
Commandline: apt-get -q -o DPkg::Lock::Timeout=600 install -y --only-upgrade openssh-server
Upgrade: openssh-server:amd64 (1:9.2p1-2+deb12u5, 1:9.2p1-2+deb12u6)
End-Date: 2026-10-01  09:00:05
`

func TestLastUnattendedInstall(t *testing.T) {
	at, pkgs := lastUnattendedInstall(strings.NewReader(historySample), time.UTC)
	if want := time.Date(2026, 9, 30, 6, 25, 13, 0, time.UTC); !at.Equal(want) {
		t.Errorf("at %v, want %v", at, want)
	}
	want := []string{"linux-image-6.1.0-21-amd64 6.1.90-1", "libssl3 3.0.17-1~deb12u2", "openssl 3.0.17-1~deb12u2", "linux-image-amd64 6.1.90-1"}
	if !slices.Equal(pkgs, want) {
		t.Errorf("pkgs %q, want %q", pkgs, want)
	}
	// Local time: the log is written in the server's zone.
	berlin := time.FixedZone("CEST", 2*3600)
	if at, _ := lastUnattendedInstall(strings.NewReader(historySample), berlin); !at.Equal(time.Date(2026, 9, 30, 4, 25, 13, 0, time.UTC)) {
		t.Errorf("local time: %v", at)
	}
	// No entry by unattended-upgrades.
	if at, pkgs := lastUnattendedInstall(strings.NewReader("Start-Date: 2026-09-29  14:03:44\nCommandline: apt-get install x\nInstall: x:amd64 (1)\n"), time.UTC); !at.IsZero() || pkgs != nil {
		t.Errorf("other entries: %v %q", at, pkgs)
	}
}

// autoSecurityFiles points the sources at a temporary directory.
func autoSecurityFiles(t *testing.T) string {
	dir := t.TempDir()
	old := []string{autoSecurityMarker, unattendedStamp, aptHistoryLog, needrestartReport}
	autoSecurityMarker = filepath.Join(dir, "auto-security-updates")
	unattendedStamp = filepath.Join(dir, "unattended-upgrades-stamp")
	aptHistoryLog = filepath.Join(dir, "history.log")
	needrestartReport = filepath.Join(dir, "needrestart")
	t.Cleanup(func() {
		autoSecurityMarker, unattendedStamp, aptHistoryLog, needrestartReport = old[0], old[1], old[2], old[3]
	})
	return dir
}

func TestBuildAutoSecurity(t *testing.T) {
	autoSecurityFiles(t)
	if r := buildAutoSecurity(); r != nil {
		t.Fatalf("no sources: %+v", r)
	}
	// unattended-upgrades runs (the distribution's default), not Rowsafe's.
	os.WriteFile(unattendedStamp, nil, 0o644)
	stamp := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	os.Chtimes(unattendedStamp, stamp, stamp)
	r := buildAutoSecurity()
	if r == nil || r.Enabled || r.LastRunAt == nil || !r.LastRunAt.Equal(stamp) {
		t.Fatalf("stamp only: %+v", r)
	}
	os.WriteFile(autoSecurityMarker, []byte("# Rowsafe set up automatic security updates here\n"), 0o644)
	os.WriteFile(aptHistoryLog, []byte(historySample), 0o644)
	os.WriteFile(needrestartReport, []byte(needrestartSample), 0o644)
	r = buildAutoSecurity()
	if r == nil || !r.Enabled || r.LastInstalledAt == nil || len(r.LastInstalled) != 4 || r.LastInstalled[1] != "libssl3 3.0.17-1~deb12u2" {
		t.Fatalf("all sources: %+v", r)
	}
	if r.RestartCheckedAt == nil || !r.KernelPending || r.KernelInstalled != "6.1.0-21-amd64" ||
		!slices.Equal(r.Services, []string{"postgresql@17-main.service", "pgbouncer.service"}) {
		t.Errorf("restart list: %+v", r)
	}
}

func TestAutoSecurityUpdatesTask(t *testing.T) {
	autoSecurityFiles(t)
	e := newUpgradeEnv(t)
	// The test helper predates auto-security-updates.
	if _, err := e.a.autoSecurityUpdates(context.Background(), "task_1", &taskLog{}); err == nil || err.Error() != autoSecurityOlderHelper {
		t.Fatalf("older helper: %v", err)
	}
	if len(e.asked) != 0 {
		t.Fatalf("asked the helper: %q", e.asked)
	}
	os.WriteFile(e.a.cfg.RestartHelper, []byte("#!/bin/sh\n# update-actions: security-updates auto-security-updates reboot\n"), 0o755)
	e.helper = func(id string, args []string) map[string]string {
		if id != "task_1-autosec" || !slices.Equal(args, []string{protocol.ActAutoSecurityUpdates}) {
			t.Errorf("request %s %q", id, args)
		}
		return map[string]string{"id": id, "ok": "1", "enabled": "1", "summary": "Automatic security updates are on."}
	}
	res, err := e.a.runTask(context.Background(), &protocol.Task{ID: "task_1", Type: protocol.TaskAutoSecurityUpdates}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := res.(*protocol.AutoSecurityUpdatesResult); !ok || !r.Enabled || r.Summary != "Automatic security updates are on." {
		t.Errorf("%#v", res)
	}
	// Not allowed: the allow list's refusal, not the older helper's.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("postgresql\n"), 0o644)
	if _, err := e.a.autoSecurityUpdates(context.Background(), "task_2", &taskLog{}); err == nil || !strings.Contains(err.Error(), "isn't allowed") {
		t.Errorf("not allowed: %v", err)
	}
	// The helper's refusal.
	os.WriteFile(e.a.cfg.UpdateAllowFile, []byte("security\n"), 0o644)
	e.helper = func(id string, _ []string) map[string]string {
		return map[string]string{"id": id, "ok": "0", "error": "auto-security-updates ran less than 5 minutes ago; try again later"}
	}
	if _, err := e.a.autoSecurityUpdates(context.Background(), "task_3", &taskLog{}); err == nil || !strings.Contains(err.Error(), "less than 5 minutes") {
		t.Errorf("refused: %v", err)
	}
}
