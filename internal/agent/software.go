package agent

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// The server's software: which PostgreSQL versions run and are installed,
// which newer minor releases and majors the package sources offer, pending
// security updates and whether a reboot is needed. Read as the agent user
// (apt-cache, dpkg-query, a simulated apt-get), about every hour and right
// after an update, and reported in the heartbeat (SoftwareReport).

// Where the agent looks (variables for tests).
var (
	softwareEvery      = time.Hour
	rebootRequiredFile = "/run/reboot-required"
	aptListsDir        = "/var/lib/apt/lists"
	updatePathUnit     = "/etc/systemd/system/rowsafe-pg-update.path"
	procStat           = "/proc/stat"
)

// Update helper actions (the helper's "# update-actions:" line).
const (
	actMinorUpdate    = "pg-minor-update"
	actInstallMajor   = "pg-install-major"
	actUpgrade        = "pg-upgrade"
	actUpgradeUndo    = "pg-upgrade-undo"
	actUpgradeCleanup = "pg-upgrade-cleanup"
	actSecurity       = "security-updates"
	actReboot         = "reboot"
)

// softwareLoop refreshes the software report every hour, or sooner when
// asked (refreshSoftware).
func (a *Agent) softwareLoop(ctx context.Context) {
	for {
		rctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		r := a.buildSoftware(rctx)
		cancel()
		a.swMu.Lock()
		a.sw = r
		a.swMu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(softwareEvery):
		case <-a.swKick:
		}
	}
}

// refreshSoftware asks for a new software report soon (after an update).
func (a *Agent) refreshSoftware() {
	if a.swKick == nil {
		return
	}
	select {
	case a.swKick <- struct{}{}:
	default:
	}
}

// softwareForHeartbeat is the newest report with the upgrades as they are
// now (nil before the first report).
func (a *Agent) softwareForHeartbeat() *protocol.SoftwareReport {
	a.swMu.Lock()
	r := a.sw
	a.swMu.Unlock()
	ups := a.upgradeState().states()
	if r == nil && len(ups) == 0 {
		return nil
	}
	out := protocol.SoftwareReport{}
	if r != nil {
		out = *r
	}
	out.Upgrades = ups
	return &out
}

// updateAllowed reads the words root allowed in the updates allow list.
func (a *Agent) updateAllowed() []string {
	if a.cfg.Sidecar() || a.cfg.UpdateAllowFile == "" {
		return nil
	}
	data, err := os.ReadFile(a.cfg.UpdateAllowFile)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case protocol.UpdateAllowPostgres, protocol.UpdateAllowSecurity, protocol.UpdateAllowReboot:
			if !slices.Contains(out, f[0]) {
				out = append(out, f[0])
			}
		}
	}
	return out
}

// updateHelperActions reads what the installed helper can do in update mode
// (nothing when its update service isn't installed).
func (a *Agent) updateHelperActions() []string {
	if a.cfg.Sidecar() || a.cfg.RestartHelper == "" {
		return nil
	}
	if _, err := os.Stat(updatePathUnit); err != nil {
		return nil
	}
	data, err := os.ReadFile(a.cfg.RestartHelper)
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "# update-actions:"); ok {
			return strings.Fields(rest)
		}
	}
	return nil
}

func (a *Agent) buildSoftware(ctx context.Context) *protocol.SoftwareReport {
	r := &protocol.SoftwareReport{CheckedAt: time.Now().UTC()}
	if a.cfg.Sidecar() {
		return r
	}
	r.Allowed = a.updateAllowed()
	r.HelperActions = a.updateHelperActions()
	if bt := bootTime(); !bt.IsZero() {
		r.BootedAt = &bt
	}
	if _, err := os.Stat(rebootRequiredFile); err == nil {
		r.RebootRequired = true
		if data, err := os.ReadFile(rebootRequiredFile + ".pkgs"); err == nil {
			r.RebootPackages = firstN(uniqueLines(string(data)), 30)
		}
	}
	if _, err := exec.LookPath("apt-cache"); err != nil {
		return r
	}
	r.PackageManager = "apt"
	if st, err := os.Stat(aptListsDir); err == nil {
		t := st.ModTime().UTC()
		r.ListsUpdatedAt = &t
	}
	r.Clusters = a.clusterSoftware(ctx)
	if out, err := a.runner.Run(ctx, "apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"); err == nil {
		pkgs := securityUpgrades(out)
		r.SecurityUpdates = len(pkgs)
		r.SecurityPackages = firstN(pkgs, 30)
	} else if r.Error == "" {
		r.Error = "apt-get -s dist-upgrade: " + firstLineOf(string(out))
	}
	return r
}

// clusterSoftware lists the local clusters (pg_lsclusters) with their
// running, installed and available versions.
func (a *Agent) clusterSoftware(ctx context.Context) []protocol.ClusterSoftware {
	out, err := a.runner.Run(ctx, "pg_lsclusters", "--no-header")
	if err != nil {
		return nil
	}
	clusters := parseLsclusters(out)
	if len(clusters) == 0 {
		return nil
	}
	running := a.runningVersions(ctx)
	majors := map[int]bool{}
	minMajor := 0
	for _, c := range clusters {
		majors[c.Major] = true
		if minMajor == 0 || c.Major < minMajor {
			minMajor = c.Major
		}
	}
	pkgs := []string{}
	for m := range majors {
		pkgs = append(pkgs, "postgresql-"+strconv.Itoa(m))
	}
	if names, err := a.runner.Run(ctx, "apt-cache", "pkgnames", "postgresql-"); err == nil {
		for _, n := range strings.Fields(string(names)) {
			if m, ok := serverPackageMajor(n); ok && m > minMajor && !slices.Contains(pkgs, n) {
				pkgs = append(pkgs, n)
			}
		}
	}
	slices.Sort(pkgs)
	policy := map[string]aptPolicy{}
	if out, err := a.runner.Run(ctx, "apt-cache", append([]string{"policy"}, pkgs...)...); err == nil {
		policy = parseAptPolicy(out)
	}
	var cs []protocol.ClusterSoftware
	for _, c := range clusters {
		cs2 := protocol.ClusterSoftware{Port: c.Port, Major: c.Major, Cluster: c.Name,
			Unit: "postgresql@" + strconv.Itoa(c.Major) + "-" + c.Name + ".service", Running: running[c.Port]}
		if p, ok := policy["postgresql-"+strconv.Itoa(c.Major)]; ok {
			cs2.InstalledPackage, cs2.Installed = p.Installed, minorOf(p.Installed)
			cs2.CandidatePackage, cs2.Candidate = p.Candidate, minorOf(p.Candidate)
			cs2.Origin = p.Origin
		}
		for name, p := range policy {
			if m, ok := serverPackageMajor(name); ok && m > c.Major && p.Candidate != "" {
				cs2.Majors = append(cs2.Majors, m)
			}
		}
		slices.Sort(cs2.Majors)
		if out, err := a.runner.Run(ctx, "dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package}\\n",
			"postgresql-"+strconv.Itoa(c.Major)+"-*"); err == nil || len(out) > 0 {
			cs2.ExtensionPackages = parseInstalledPackages(out)
		}
		cs = append(cs, cs2)
	}
	return cs
}

// runningVersions maps ports to the running server's version ("16.9"),
// for the databases this agent monitors.
func (a *Agent) runningVersions(ctx context.Context) map[int]string {
	out := map[int]string{}
	for _, db := range a.monitoredDatabases() {
		if _, done := out[db.Port]; done {
			continue
		}
		s, err := pginspect.Summarize(ctx, a.target(db))
		if err == nil {
			out[db.Port] = shortVersion(s.ServerVersion)
		}
	}
	return out
}

// shortVersion: "16.9 (Debian 16.9-1.pgdg13+1)" -> "16.9".
func shortVersion(v string) string {
	f := strings.Fields(v)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

var serverPkgRE = regexp.MustCompile(`^postgresql-([1-9][0-9])$`)

// serverPackageMajor: "postgresql-18" -> 18.
func serverPackageMajor(name string) (int, bool) {
	m := serverPkgRE.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, true
}

var minorRE = regexp.MustCompile(`^(?:[0-9]+:)?([0-9]+\.[0-9]+)`)

// minorOf: "16.10-1.pgdg13+1" -> "16.10", "1:15.8-0+deb12u1" -> "15.8".
func minorOf(pkgVersion string) string {
	m := minorRE.FindStringSubmatch(pkgVersion)
	if m == nil {
		return ""
	}
	return m[1]
}

// newerMinor reports whether minor version b ("16.10") is newer than a
// ("16.9").
func newerMinor(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := range min(len(pa), len(pb)) {
		if pa[i] != pb[i] {
			return pb[i] > pa[i]
		}
	}
	return len(pb) > len(pa)
}

func versionParts(v string) []int {
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// aptPolicy is one package in `apt-cache policy`.
type aptPolicy struct {
	Installed, Candidate string // "" for (none)
	Origin               string // of the candidate: apt.postgresql.org, Debian, Ubuntu or ""
}

// parseAptPolicy reads `apt-cache policy PKG...`:
//
//	postgresql-16:
//	  Installed: 16.9-1.pgdg13+1
//	  Candidate: 16.10-1.pgdg13+1
//	  Version table:
//	     16.10-1.pgdg13+1 500
//	        500 https://apt.postgresql.org/pub/repos/apt trixie-pgdg/main arm64 Packages
//	 *** 16.9-1.pgdg13+1 100
//	        100 /var/lib/dpkg/status
func parseAptPolicy(out []byte) map[string]aptPolicy {
	res := map[string]aptPolicy{}
	var name string
	var cur aptPolicy
	var tableVersion string
	flush := func() {
		if name != "" {
			res[name] = cur
		}
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case line != "" && !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			flush()
			name, cur, tableVersion = strings.TrimSuffix(line, ":"), aptPolicy{}, ""
		case name == "":
		case strings.HasPrefix(trimmed, "Installed:"):
			cur.Installed = noneEmpty(strings.TrimSpace(strings.TrimPrefix(trimmed, "Installed:")))
		case strings.HasPrefix(trimmed, "Candidate:"):
			cur.Candidate = noneEmpty(strings.TrimSpace(strings.TrimPrefix(trimmed, "Candidate:")))
		case strings.HasPrefix(trimmed, "Version table:"):
		default:
			f := strings.Fields(strings.TrimPrefix(trimmed, "*** "))
			switch {
			case len(f) >= 2 && isNumber(f[0]):
				// "500 https://apt.postgresql.org/... Packages" under a version.
				if tableVersion != "" && tableVersion == cur.Candidate && cur.Origin == "" {
					cur.Origin = originOf(f[1])
				}
			case len(f) == 2 && isNumber(f[1]):
				tableVersion = f[0] // "16.10-1.pgdg13+1 500"
			}
		}
	}
	flush()
	return res
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func noneEmpty(s string) string {
	if s == "(none)" {
		return ""
	}
	return s
}

func originOf(src string) string {
	switch {
	case strings.Contains(src, "apt.postgresql.org") || strings.Contains(src, "apt-archive.postgresql.org"):
		return "apt.postgresql.org"
	case strings.Contains(src, "debian.org"):
		return "Debian"
	case strings.Contains(src, "ubuntu.com"):
		return "Ubuntu"
	}
	return ""
}

// parseInstalledPackages reads dpkg-query "${db:Status-Abbrev} ${Package}"
// lines: installed ("ii") packages, without debug or doc packages.
func parseInstalledPackages(out []byte) []string {
	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || f[0] != "ii" {
			continue
		}
		if strings.HasSuffix(f[1], "-dbgsym") || strings.HasSuffix(f[1], "-dbg") || strings.HasSuffix(f[1], "-doc") {
			continue
		}
		pkgs = append(pkgs, f[1])
	}
	slices.Sort(pkgs)
	return pkgs
}

var instRE = regexp.MustCompile(`^Inst (\S+) \[[^\]]*\] \((.*)\)`)

// securityUpgrades reads a simulated `apt-get -s dist-upgrade`: upgrades of
// installed packages from a security origin, e.g.
//
//	Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [arm64])
func securityUpgrades(out []byte) []string {
	var pkgs []string
	for _, line := range strings.Split(string(out), "\n") {
		m := instRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if strings.Contains(m[2], "-security") || strings.Contains(m[2], "Debian-Security") {
			if !slices.Contains(pkgs, m[1]) {
				pkgs = append(pkgs, m[1])
			}
		}
	}
	slices.Sort(pkgs)
	return pkgs
}

func uniqueLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// bootTime reads the kernel's boot time (btime in /proc/stat).
func bootTime() time.Time {
	data, err := os.ReadFile(procStat)
	if err != nil {
		return time.Time{}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "btime "); ok {
			if n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64); err == nil {
				return time.Unix(n, 0).UTC()
			}
		}
	}
	return time.Time{}
}

// bootID identifies the current boot (it changes with every reboot).
func bootID() string {
	data, err := os.ReadFile(filepath.Join("/proc/sys/kernel/random", "boot_id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
