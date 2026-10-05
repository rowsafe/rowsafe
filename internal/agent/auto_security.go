package agent

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Automatic security updates (Rowsafe Cloud servers): the installer's
// --auto-security-updates, or the update helper's auto-security-updates
// request (TaskAutoSecurityUpdates), sets up unattended-upgrades for the
// distribution's security updates only, PostgreSQL's packages held back,
// and needrestart, which never restarts PostgreSQL. What the agent sees of
// it (SoftwareReport.AutoSecurity) is read as the agent user from files
// anyone can read.

// Where the agent looks (variables for tests).
var (
	// Rowsafe's marker: automatic security updates are on.
	autoSecurityMarker = "/etc/rowsafe/auto-security-updates"
	// unattended-upgrades' stamp: touched each time it runs.
	unattendedStamp = "/var/lib/apt/periodic/unattended-upgrades-stamp"
	// apt's history: what unattended-upgrades installed (0644 on Debian).
	aptHistoryLog = "/var/log/apt/history.log"
	// The restart list root's rowsafe-needrestart.service writes
	// (needrestart -b -r l: it lists, it never restarts).
	needrestartReport = "/run/rowsafe-updates/needrestart"
)

// buildAutoSecurity reads automatic security updates' state; nil when none
// of its sources is there.
func buildAutoSecurity() *protocol.AutoSecurityReport {
	r := &protocol.AutoSecurityReport{}
	found := false
	if _, err := os.Stat(autoSecurityMarker); err == nil {
		r.Enabled, found = true, true
	}
	if st, err := os.Stat(unattendedStamp); err == nil {
		t := st.ModTime().UTC()
		r.LastRunAt, found = &t, true
	}
	if f, err := os.Open(aptHistoryLog); err == nil {
		at, pkgs := lastUnattendedInstall(f, time.Local)
		f.Close()
		if !at.IsZero() {
			r.LastInstalledAt, r.LastInstalled, found = &at, firstN(pkgs, 30), true
		}
	}
	if st, err := os.Stat(needrestartReport); err == nil {
		if data, err := os.ReadFile(needrestartReport); err == nil {
			t := st.ModTime().UTC()
			r.RestartCheckedAt, found = &t, true
			nr := parseNeedrestartBatch(string(data))
			r.Services = firstN(nr.Services, 50)
			r.KernelPending, r.KernelRunning, r.KernelInstalled = nr.KernelPending, nr.KernelRunning, nr.KernelInstalled
		}
	}
	if !found {
		return nil
	}
	return r
}

// needrestartBatch is what `needrestart -b` printed.
type needrestartBatch struct {
	Services        []string
	KernelPending   bool
	KernelRunning   string
	KernelInstalled string
}

// parseNeedrestartBatch reads needrestart's batch output:
//
//	NEEDRESTART-VER: 3.6
//	NEEDRESTART-KCUR: 6.1.0-18-amd64
//	NEEDRESTART-KEXP: 6.1.0-21-amd64
//	NEEDRESTART-KSTA: 3
//	NEEDRESTART-SVC: postgresql@17-main.service
//
// KSTA: 0 unknown, 1 current, 2 an ABI-compatible newer kernel, 3 a newer
// kernel version (2 and 3: a reboot is needed to run it).
func parseNeedrestartBatch(out string) needrestartBatch {
	var b needrestartBatch
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "NEEDRESTART-KCUR":
			b.KernelRunning = val
		case "NEEDRESTART-KEXP":
			b.KernelInstalled = val
		case "NEEDRESTART-KSTA":
			b.KernelPending = val == "2" || val == "3"
		case "NEEDRESTART-SVC":
			if val != "" && !slices.Contains(b.Services, val) {
				b.Services = append(b.Services, val)
			}
		}
	}
	return b
}

// historyPkgRE is one package of a history.log Install/Upgrade line:
// "libssl3:amd64 (3.0.15-1~deb12u1, 3.0.17-1~deb12u2)".
var historyPkgRE = regexp.MustCompile(`([^\s,()]+) \(([^)]*)\)`)

// lastUnattendedInstall finds the newest entry of apt's history log run by
// unattended-upgrades that installed or upgraded something: when it
// started and what ("openssl 3.0.17-1~deb12u2"). Dates in the log are the
// server's local time (loc).
func lastUnattendedInstall(r io.Reader, loc *time.Location) (time.Time, []string) {
	var (
		bestAt   time.Time
		bestPkgs []string
		at       time.Time
		pkgs     []string
		byUU     bool
	)
	flush := func() {
		if byUU && len(pkgs) > 0 && !at.IsZero() && !at.Before(bestAt) {
			bestAt, bestPkgs = at, pkgs
		}
		at, pkgs, byUU = time.Time{}, nil, false
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		key, val, ok := strings.Cut(line, ": ")
		if !ok {
			if strings.TrimSpace(line) == "" {
				flush()
			}
			continue
		}
		switch key {
		case "Start-Date":
			flush() // an entry without its blank line
			if t, err := time.ParseInLocation("2006-01-02 15:04:05", strings.Join(strings.Fields(val), " "), loc); err == nil {
				at = t.UTC()
			}
		case "Commandline":
			f := strings.Fields(val)
			byUU = len(f) > 0 && (f[0] == "/usr/bin/unattended-upgrade" || f[0] == "unattended-upgrade" ||
				strings.HasSuffix(f[0], "/unattended-upgrade"))
		case "Install", "Upgrade":
			for _, m := range historyPkgRE.FindAllStringSubmatch(val, -1) {
				name, _, _ := strings.Cut(m[1], ":")
				vers := strings.Split(m[2], ",")
				v := strings.TrimSpace(vers[0]) // Install: (new[, automatic])
				if key == "Upgrade" && len(vers) >= 2 {
					v = strings.TrimSpace(vers[1]) // Upgrade: (old, new)
				}
				pkgs = append(pkgs, strings.TrimSpace(name+" "+v))
			}
		}
	}
	flush()
	return bestAt, bestPkgs
}

// autoSecurityOlderHelper is the refusal when the helper predates the
// auto-security-updates request.
const autoSecurityOlderHelper = "The helper on this server is from an older Rowsafe: run the install command there again to turn on automatic security updates."

// autoSecurityUpdates turns on automatic security updates through the
// update helper (TaskAutoSecurityUpdates).
func (a *Agent) autoSecurityUpdates(ctx context.Context, taskID string, tl *taskLog) (*protocol.AutoSecurityUpdatesResult, error) {
	if a.cfg.Container() {
		return nil, errors.New("the agent runs in Docker here: automatic security updates are set up on the server itself")
	}
	if slices.Contains(a.updateAllowed(), protocol.UpdateAllowSecurity) &&
		!slices.Contains(a.updateHelperActions(), protocol.ActAutoSecurityUpdates) {
		return nil, errors.New(autoSecurityOlderHelper)
	}
	if err := a.updatesAllowed(protocol.UpdateAllowSecurity, protocol.ActAutoSecurityUpdates); err != nil {
		return nil, err
	}
	tl.Printf("turning on automatic security updates through the update helper")
	ans, err := a.updateHelper()(ctx, taskID+"-autosec", []string{protocol.ActAutoSecurityUpdates}, 20*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		return nil, fmt.Errorf("turning on automatic security updates failed: %w", err)
	}
	res := &protocol.AutoSecurityUpdatesResult{Enabled: ans["enabled"] == "1",
		Summary: cmp.Or(ans["summary"], "Automatic security updates are on.")}
	a.refreshSoftware()
	tl.Printf("%s", res.Summary)
	return res, nil
}
