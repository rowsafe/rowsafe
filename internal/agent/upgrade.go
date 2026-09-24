package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Major upgrades (16 -> 18).
//
//  1. upgrade_check: read-only preflight (target available, extensions
//     packaged for it, disk, not a replica, standbys, pgBackRest support,
//     what root allowed, the cluster managed by postgresql-common).
//  2. upgrade_rehearsal (required before the upgrade): the latest backup is
//     restored into a scratch copy (the restore test's isolation), the
//     target major installed if needed (root helper: pg-install-major),
//     pg_upgrade --check and then pg_upgrade run on the copy, the upgraded
//     copy started privately and checked, statistics refreshed and
//     pgBackRest tried on it; timings give the expected downtime. The copy
//     is deleted; production is never touched.
//  3. upgrade: the root helper runs Debian's pg_upgradecluster (it moves
//     the configuration in /etc/postgresql, ports and the systemd unit),
//     Safe mode copying (or cloning) the data and keeping the old version
//     stopped on another port, Fast mode hard-linking it; then starts the
//     new version on the original port. A failure before it accepts
//     connections puts the old version back (Safe mode), or restores it
//     from the backup taken just before (Fast mode). The agent then moves
//     pgBackRest to the new version (stanza-upgrade, check) and refreshes
//     planner statistics in the background; the control plane queues a
//     full backup and a Proof.
//  4. upgrade_undo: back to the old version (Safe: switch clusters; Fast:
//     restore it from the backup at the Mark saved before the upgrade).
//  5. upgrade_cleanup (or expiry, default 7 days): remove the kept version.

var (
	upgradeHelperWait = 12*time.Hour + 30*time.Minute
	// pgBackRest's first release supporting each major.
	pgbackrestSupports = map[int]string{15: "2.41", 16: "2.47", 17: "2.53", 18: "2.55"}
	// copySpeedDefault is the disk copy speed assumed when it can't be
	// measured (bytes per second).
	copySpeedDefault = float64(200 << 20)
)

// upgradeFacts are what the checks read from the running cluster.
type upgradeFacts struct {
	inPlaceFacts
	Version string // running, "16.9"
	Cluster string // Debian cluster name ("" when not managed by postgresql-common)
	// ClusterDataDir is pg_lsclusters' data directory for the port.
	ClusterDataDir string
}

func (a *Agent) readUpgradeFacts(ctx context.Context, db protocol.DatabaseSpec) (upgradeFacts, error) {
	var f upgradeFacts
	var err error
	if f.inPlaceFacts, err = a.ops().facts(ctx, db); err != nil {
		return f, fmt.Errorf("reading PostgreSQL's settings: %w", err)
	}
	if f.Version, _, err = a.runningVersion(ctx, db); err != nil {
		return f, err
	}
	if out, err := a.runner.Run(ctx, "pg_lsclusters", "--no-header"); err == nil {
		for _, c := range parseLsclusters(out) {
			if c.Port == db.Port && c.Major == f.Major {
				f.Cluster, f.ClusterDataDir = c.Name, filepath.Clean(c.DataDir)
			}
		}
	}
	return f, nil
}

// aptPolicies runs `apt-cache policy` for pkgs.
func (a *Agent) aptPolicies(ctx context.Context, pkgs ...string) map[string]aptPolicy {
	if len(pkgs) == 0 {
		return map[string]aptPolicy{}
	}
	out, err := a.runner.Run(ctx, "apt-cache", append([]string{"policy"}, pkgs...)...)
	if err != nil && len(out) == 0 {
		return map[string]aptPolicy{}
	}
	return parseAptPolicy(out)
}

// newerMajors lists the server majors newer than from that the package
// sources offer, with their policies.
func (a *Agent) newerMajors(ctx context.Context, from int) ([]int, map[string]aptPolicy) {
	var pkgs []string
	if names, err := a.runner.Run(ctx, "apt-cache", "pkgnames", "postgresql-"); err == nil {
		for _, n := range strings.Fields(string(names)) {
			if m, ok := serverPackageMajor(n); ok && m > from {
				pkgs = append(pkgs, n)
			}
		}
	}
	policy := a.aptPolicies(ctx, pkgs...)
	var majors []int
	for name, p := range policy {
		if m, ok := serverPackageMajor(name); ok && m > from && (p.Candidate != "" || p.Installed != "") {
			majors = append(majors, m)
		}
	}
	slices.Sort(majors)
	return majors, policy
}

// installedPackages lists installed packages matching a dpkg pattern.
func (a *Agent) installedPackages(ctx context.Context, pattern string) []string {
	out, _ := a.runner.Run(ctx, "dpkg-query", "-W", "-f=${db:Status-Abbrev} ${Package}\\n", pattern)
	return parseInstalledPackages(out)
}

// canClone reports whether dir's filesystem copies files by reference
// (pg_upgrade --clone): cp --reflink=always works there.
func (a *Agent) canClone(ctx context.Context, dir string) bool {
	src, err := os.CreateTemp(dir, ".rowsafe-reflink-*")
	if err != nil {
		return false
	}
	_, _ = src.WriteString("rowsafe")
	src.Close()
	defer os.Remove(src.Name())
	dst := src.Name() + ".clone"
	defer os.Remove(dst)
	_, err = a.runner.Run(ctx, "cp", "--reflink=always", src.Name(), dst)
	return err == nil
}

func pgbackrestVersion(ctx context.Context, r pgbackrest.Runner, bin string) string {
	out, err := r.Run(ctx, bin, "version")
	if err != nil {
		return ""
	}
	v, _ := strings.CutPrefix(strings.TrimSpace(string(out)), "pgBackRest ")
	return strings.Fields(v + " ")[0]
}

// upgradeCheck runs the preflight. It never changes anything.
func (a *Agent) upgradeCheck(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeCheckParams, tl *taskLog) (*protocol.UpgradeCheckResult, error) {
	res, _, err := a.runUpgradeChecks(ctx, db, p.ToMajor, tl)
	if err != nil {
		return nil, err
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// runUpgradeChecks builds the preflight result.
func (a *Agent) runUpgradeChecks(ctx context.Context, db protocol.DatabaseSpec, to int, tl *taskLog) (*protocol.UpgradeCheckResult, upgradeFacts, error) {
	f, err := a.readUpgradeFacts(ctx, db)
	if err != nil {
		return nil, f, err
	}
	res := &protocol.UpgradeCheckResult{FromMajor: f.Major, FromVersion: f.Version, SizeBytes: f.SizeBytes, Sidecar: a.cfg.Sidecar()}
	blockUpgrade, blockRehearsal := false, false
	add := func(id, status, title, detail string, rehearsalToo bool) {
		res.Checks = append(res.Checks, protocol.UpgradeCheck{ID: id, Status: status, Title: title, Detail: detail})
		if status == protocol.CheckBlocker {
			blockUpgrade = true
			if rehearsalToo {
				blockRehearsal = true
			}
		}
	}

	// The target and its packages.
	var policy map[string]aptPolicy
	if a.cfg.Sidecar() {
		for m := f.Major + 1; m <= f.Major+6; m++ {
			if _, err := os.Stat(a.cfg.pgBin(m, "pg_upgrade")); err == nil {
				res.Majors = append(res.Majors, m)
			}
		}
	} else {
		res.Majors, policy = a.newerMajors(ctx, f.Major)
	}
	if to == 0 && len(res.Majors) > 0 {
		to = res.Majors[len(res.Majors)-1]
	}
	res.ToMajor = to
	switch {
	case to == 0:
		add("target", protocol.CheckBlocker, "No newer PostgreSQL is available",
			"This server's package sources offer no newer major version of PostgreSQL. The PostgreSQL project's apt repository (apt.postgresql.org) has every supported version.", true)
	case to <= f.Major:
		add("target", protocol.CheckBlocker, fmt.Sprintf("PostgreSQL %d is not newer than %d", to, f.Major), "", true)
	case !slices.Contains(res.Majors, to):
		detail := "This server's package sources don't offer it. The PostgreSQL project's apt repository (apt.postgresql.org) has every supported version."
		if a.cfg.Sidecar() {
			detail = fmt.Sprintf("The Rowsafe agent's image has no PostgreSQL %d programs to rehearse with; use a newer agent image.", to)
		}
		add("target", protocol.CheckBlocker, fmt.Sprintf("PostgreSQL %d is not available", to), detail, true)
	default:
		if p, ok := policy["postgresql-"+strconv.Itoa(to)]; ok {
			res.ToVersion = minorOf(cmp.Or(p.Candidate, p.Installed))
		}
		add("target", protocol.CheckOK, fmt.Sprintf("PostgreSQL %s is available", cmp.Or(res.ToVersion, strconv.Itoa(to))), "", true)
	}

	// Extensions packaged for the target.
	if !a.cfg.Sidecar() && to > f.Major {
		exts := a.installedPackages(ctx, fmt.Sprintf("postgresql-%d-*", f.Major))
		var want []string
		for _, p := range exts {
			want = append(want, fmt.Sprintf("postgresql-%d-%s", to, strings.TrimPrefix(p, fmt.Sprintf("postgresql-%d-", f.Major))))
		}
		pol := a.aptPolicies(ctx, want...)
		var missing []string
		for _, w := range want {
			if p, ok := pol[w]; !ok || (p.Candidate == "" && p.Installed == "") {
				missing = append(missing, w)
			}
		}
		switch {
		case len(missing) > 0:
			add("extensions", protocol.CheckBlocker, fmt.Sprintf("%s not available for PostgreSQL %d", countNoun(len(missing), "extension package is", "extension packages are"), to),
				"Missing: "+strings.Join(missing, ", ")+". Upgrade when the extension's maintainers publish them, or remove the extension first.", true)
		case len(exts) > 0:
			add("extensions", protocol.CheckOK, fmt.Sprintf("Extensions are available for PostgreSQL %d", to), strings.Join(want, ", "), true)
		default:
			add("extensions", protocol.CheckOK, "No extension packages to carry over", "", true)
		}
	}

	// Where it runs.
	switch {
	case a.cfg.Sidecar():
		res.DockerSteps = dockerUpgradeSteps(f.Major, to)
		add("docker", protocol.CheckBlocker, "PostgreSQL runs in Docker",
			"Rowsafe can check and rehearse the upgrade, but can't change your container's image: the upgrade itself is a change to your compose file (see the steps).", false)
	case f.Cluster == "" || filepath.Clean(f.DataDir) != f.ClusterDataDir:
		add("layout", protocol.CheckBlocker, "Not managed by Debian's PostgreSQL tools",
			"Rowsafe upgrades PostgreSQL installed from Debian or Ubuntu packages (pg_lsclusters lists it). The rehearsal still works.", false)
	default:
		add("layout", protocol.CheckOK, fmt.Sprintf("Debian cluster %d/%s", f.Major, f.Cluster), "", false)
	}
	if !a.cfg.Sidecar() {
		targetInstalled := pathExists(a.cfg.pgBin(to, "pg_upgrade"))
		if _, err := a.pgAllowed(db, actUpgrade); err != nil {
			add("allowed", protocol.CheckBlocker, "Upgrades from Rowsafe aren't allowed on this server", err.Error(), !targetInstalled)
		} else {
			add("allowed", protocol.CheckOK, "Rowsafe may upgrade PostgreSQL here", "", false)
		}
	}

	// Replicas.
	if f.InRecovery {
		add("replica", protocol.CheckBlocker, "This is a read-only replica", "Upgrade the primary; replicas are set up again afterwards.", false)
	}
	if f.Replicas > 0 {
		add("standbys", protocol.CheckWarning, fmt.Sprintf("%s stream from this server", countNoun(f.Replicas, "replica", "replicas")),
			fmt.Sprintf("After the upgrade they no longer match it and must be set up again for PostgreSQL %d.", to), false)
	}
	if r, ok := a.upgradeState().forDatabase(db.ID); ok {
		add("previous", protocol.CheckBlocker, "The previous upgrade still keeps a version",
			fmt.Sprintf("Remove PostgreSQL %d, kept by the upgrade on %s, before upgrading again.", map[bool]int{true: r.FromMajor, false: r.ToMajor}[r.Status != protocol.UpgradeUndone],
				r.CreatedAt.UTC().Format("2006-01-02")), false)
	}

	// pgBackRest.
	if v := pgbackrestVersion(ctx, a.runner, a.cfg.PgBackRestBin); v != "" && to > 0 {
		need, known := pgbackrestSupports[to]
		switch {
		case !known:
			add("pgbackrest", protocol.CheckWarning, fmt.Sprintf("pgBackRest %s", v), fmt.Sprintf("Rowsafe doesn't know yet which pgBackRest supports PostgreSQL %d; the rehearsal tries it.", to), false)
		case versionLess(v, need):
			add("pgbackrest", protocol.CheckBlocker, fmt.Sprintf("pgBackRest %s can't back up PostgreSQL %d", v, to),
				fmt.Sprintf("PostgreSQL %d needs pgBackRest %s or newer: install it from apt.postgresql.org (re-running the Rowsafe install command does it).", to, need), true)
		default:
			add("pgbackrest", protocol.CheckOK, fmt.Sprintf("pgBackRest %s supports PostgreSQL %d", v, to), "", true)
		}
	}

	// Disk.
	if f.Tablespaces > 0 {
		add("tablespaces", protocol.CheckWarning, fmt.Sprintf("%s", countNoun(f.Tablespaces, "tablespace", "tablespaces")),
			"They are upgraded too. Fast mode's Undo can't restore databases with tablespaces yet, so only Safe mode is offered.", false)
	}
	if !a.cfg.Sidecar() && f.DataDir != "" {
		base := filepath.Dir(filepath.Dir(f.DataDir)) // /var/lib/postgresql/16/main -> /var/lib/postgresql
		free, ferr := freeBytes(base)
		res.FreeBytes = free
		clone := ferr == nil && a.canClone(ctx, base)
		safe := protocol.UpgradeMode{Mode: protocol.UpgradeSafe, Method: "copy", NeedBytes: f.SizeBytes + f.SizeBytes/10 + 1<<30}
		if clone {
			safe.Method, safe.NeedBytes = "clone", f.SizeBytes/20+1<<30
		}
		fast := protocol.UpgradeMode{Mode: protocol.UpgradeFast, Method: "link", NeedBytes: f.SizeBytes/20 + 1<<30}
		for _, m := range []*protocol.UpgradeMode{&safe, &fast} {
			m.Available = ferr == nil && free >= m.NeedBytes
			if !m.Available {
				m.Reason = fmt.Sprintf("Needs about %s free in %s; %s is free.", humanBytes(m.NeedBytes), base, humanBytes(free))
			}
		}
		if f.Tablespaces > 0 {
			fast.Available, fast.Reason = false, "Not with tablespaces (Undo couldn't restore them)."
		}
		res.Modes = []protocol.UpgradeMode{safe, fast}
		switch {
		case safe.Available:
			add("disk", protocol.CheckOK, fmt.Sprintf("Enough disk: %s free", humanBytes(free)), "", false)
		case fast.Available:
			add("disk", protocol.CheckWarning, "Only enough disk for Fast mode", safe.Reason, false)
		default:
			add("disk", protocol.CheckBlocker, "Not enough disk to upgrade", fast.Reason, false)
		}
		dfree, derr := freeBytes(filepath.Dir(filepath.Clean(a.cfg.DrillDir)))
		if st, err := os.Stat(a.cfg.DrillDir); err == nil && st.IsDir() {
			dfree, derr = freeBytes(a.cfg.DrillDir)
		}
		if need := int64(float64(f.SizeBytes)*drillSpaceFactor) + 1<<30; derr == nil && dfree < need {
			add("rehearsal_disk", protocol.CheckBlocker, "Not enough disk for the rehearsal",
				fmt.Sprintf("The rehearsal restores a copy: about %s free needed in %s, %s is free.", humanBytes(need), a.cfg.DrillDir, humanBytes(dfree)), true)
		}
	}

	res.CanRehearse = !blockRehearsal
	res.CanUpgrade = !blockUpgrade
	var blockers []string
	for _, c := range res.Checks {
		if c.Status == protocol.CheckBlocker {
			blockers = append(blockers, c.Title)
		}
	}
	switch {
	case res.CanUpgrade:
		res.Summary = fmt.Sprintf("Ready to rehearse the upgrade from PostgreSQL %s to %d.", f.Version, to)
	case res.CanRehearse:
		res.Summary = fmt.Sprintf("The upgrade to PostgreSQL %d can be rehearsed; the upgrade itself needs: %s.", to, strings.Join(blockers, "; "))
	default:
		res.Summary = fmt.Sprintf("Not ready to upgrade to PostgreSQL %d: %s.", to, strings.Join(blockers, "; "))
	}
	return res, f, nil
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// versionLess compares dotted versions ("2.54.2" < "2.55").
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	if pa == nil || pb == nil {
		return false
	}
	for len(pa) < len(pb) {
		pa = append(pa, 0)
	}
	for len(pb) < len(pa) {
		pb = append(pb, 0)
	}
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}

// dockerUpgradeSteps is the compose change, in plain words.
func dockerUpgradeSteps(from, to int) []string {
	return []string{
		"Save a Mark in Rowsafe and make sure a backup finished after it.",
		fmt.Sprintf("Stop your app and the PostgreSQL %d container (docker compose stop).", from),
		fmt.Sprintf("Upgrade the data volume with pg_upgrade in a one-off container that has both versions, e.g. the tianon/postgres-upgrade:%d-to-%d image with the old and new data directories mounted.", from, to),
		fmt.Sprintf("Change the image to postgres:%d in your compose file (from PostgreSQL 18 on, mount the volume at /var/lib/postgresql) and start it.", to),
		"Run Check in Rowsafe: it moves the backups to the new version (stanza-upgrade) and takes a full backup.",
	}
}

// ---- rehearsal ----

// initdbParams are what the upgraded copy's initdb must match.
type initdbParams struct {
	Super, Encoding, Collate, Ctype string
	Provider, Locale                string // "c", "i" (ICU) or "b" (builtin), and its locale
	Checksums                       bool
	WalSegMB                        int64
}

func readInitdbParams(ctx context.Context, conn *pgx.Conn, major int) (initdbParams, error) {
	var p initdbParams
	var walSeg int64
	var checksums string
	q := `SELECT (SELECT rolname FROM pg_authid WHERE oid = 10), pg_encoding_to_char(encoding), datcollate, datctype,
	             'c', '', current_setting('data_checksums'),
	             (SELECT setting::bigint FROM pg_settings WHERE name = 'wal_segment_size')
	      FROM pg_database WHERE datname = 'template1'`
	switch {
	case major >= 17:
		q = strings.Replace(q, "'c', ''", "datlocprovider::text, coalesce(datlocale, '')", 1)
	case major >= 15:
		q = strings.Replace(q, "'c', ''", "datlocprovider::text, coalesce(daticulocale, '')", 1)
	}
	err := conn.QueryRow(ctx, q).Scan(&p.Super, &p.Encoding, &p.Collate, &p.Ctype, &p.Provider, &p.Locale, &checksums, &walSeg)
	p.Checksums = checksums == "on"
	p.WalSegMB = walSeg >> 20
	return p, err
}

// initdbArgs builds the target's initdb command line.
func initdbArgs(dataDir string, p initdbParams, to int) []string {
	args := []string{"-D", dataDir, "-U", p.Super, "-E", p.Encoding, "--lc-collate=" + p.Collate, "--lc-ctype=" + p.Ctype, "--auth=trust"}
	if p.WalSegMB > 0 {
		args = append(args, "--wal-segsize="+strconv.FormatInt(p.WalSegMB, 10))
	}
	switch p.Provider {
	case "i":
		args = append(args, "--locale-provider=icu", "--icu-locale="+p.Locale)
	case "b":
		args = append(args, "--locale-provider=builtin", "--builtin-locale="+p.Locale)
	}
	if p.Checksums {
		args = append(args, "--data-checksums")
	} else if to >= 18 {
		args = append(args, "--no-data-checksums")
	}
	return args
}

// pgUpgradeProblems pulls what pg_upgrade --check complained about out of
// its output and the report files it left.
func pgUpgradeProblems(out []byte, newDataDir string) string {
	var lines []string
	fatal := false
	for _, l := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(l)
		if strings.Contains(t, "fatal") || strings.Contains(t, "*failure*") {
			fatal = true
		}
		if fatal && t != "" {
			lines = append(lines, t)
		}
	}
	_ = filepath.WalkDir(filepath.Join(newDataDir, "pg_upgrade_output.d"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".txt") {
			if data, err := os.ReadFile(p); err == nil {
				lines = append(lines, filepath.Base(p)+": "+strings.Join(firstN(uniqueLines(string(data)), 10), "; "))
			}
		}
		return nil
	})
	if len(lines) == 0 {
		return strings.TrimSpace(string(tail(out, 1500)))
	}
	return strings.Join(firstN(lines, 25), " ")
}

// measureCopySpeed times copying the largest data file under dir (up to 1
// GiB), in bytes per second; 0 when there is too little to measure.
func measureCopySpeed(ctx context.Context, r pgbackrest.Runner, dir string) float64 {
	var biggest string
	var size int64
	_ = filepath.WalkDir(filepath.Join(dir, "base"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil && info.Size() > size {
				biggest, size = p, info.Size()
			}
		}
		return nil
	})
	if size < 32<<20 {
		return 0
	}
	dst := filepath.Join(dir, ".rowsafe-copy-speed")
	defer os.Remove(dst)
	start := time.Now()
	if _, err := r.Run(ctx, "cp", biggest, dst); err != nil {
		return 0
	}
	if f, err := os.Open(dst); err == nil {
		_ = f.Sync()
		f.Close()
	}
	return float64(size) / max(time.Since(start).Seconds(), 0.001)
}

func (a *Agent) upgradeRehearsal(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeRehearsalParams, taskID string, tl *taskLog) (*protocol.UpgradeRehearsalResult, error) {
	start := time.Now()
	chk, f, err := a.runUpgradeChecks(ctx, db, p.ToMajor, tl)
	if err != nil {
		return nil, err
	}
	to := chk.ToMajor
	res := &protocol.UpgradeRehearsalResult{FromMajor: f.Major, ToMajor: to, FromVersion: f.Version, ToVersion: chk.ToVersion}
	if !chk.CanRehearse {
		var why []string
		for _, c := range chk.Checks {
			if c.Status == protocol.CheckBlocker {
				why = append(why, c.Title+(map[bool]string{true: ": " + c.Detail, false: ""}[c.Detail != ""]))
			}
		}
		return nil, fmt.Errorf("the rehearsal can't run: %s", strings.Join(why, "; "))
	}
	finish := func(err error) (*protocol.UpgradeRehearsalResult, error) {
		res.TotalSeconds = time.Since(start).Seconds()
		if err != nil {
			res.Passed = false
			res.Issues = append(res.Issues, err.Error())
		}
		if !res.Passed && len(res.Issues) > 0 {
			res.Summary = fmt.Sprintf("The rehearsal of the upgrade to PostgreSQL %d found %s: %s", to,
				countNoun(len(res.Issues), "problem", "problems"), strings.Join(res.Issues, " "))
			tl.Printf("%s", res.Summary)
			return res, errors.New(res.Summary)
		}
		tl.Printf("%s", res.Summary)
		return res, nil
	}

	// The target's programs.
	oldBin := filepath.Dir(a.cfg.pgBin(f.Major, "pg_ctl"))
	newBin := filepath.Dir(a.cfg.pgBin(to, "pg_ctl"))
	if !pathExists(filepath.Join(newBin, "pg_upgrade")) {
		tl.Printf("installing PostgreSQL %d through the update helper (it stays installed for the upgrade; production isn't touched)", to)
		ans, err := a.updateHelper()(ctx, taskID+"-install", []string{actInstallMajor, strconv.Itoa(db.Port), strconv.Itoa(to)}, 65*time.Minute)
		if err == nil {
			err = helperOK(ans)
		}
		if err != nil {
			return finish(fmt.Errorf("installing PostgreSQL %d failed: %w", to, err))
		}
		res.PackagesInstalled = strings.Fields(ans["packages"])
		if m := strings.TrimSpace(ans["missing"]); m != "" {
			res.Warnings = append(res.Warnings, "not available for PostgreSQL "+strconv.Itoa(to)+": "+m)
		}
		a.refreshSoftware()
		if !pathExists(filepath.Join(newBin, "pg_upgrade")) {
			return finish(fmt.Errorf("PostgreSQL %d was installed, but %s is missing", to, filepath.Join(newBin, "pg_upgrade")))
		}
	}
	if res.ToVersion == "" {
		if out, err := a.runner.Run(ctx, filepath.Join(newBin, "postgres"), "--version"); err == nil {
			fs := strings.Fields(string(out))
			res.ToVersion = fs[len(fs)-1]
		}
	}

	// Restore the latest backup into a scratch copy.
	prod, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	if err := a.writeConfig(db, prod); err != nil {
		return nil, err
	}
	cli := a.cli(db)
	stanzas, err := cli.Info(ctx)
	if err != nil {
		return finish(fmt.Errorf("Rowsafe can't reach the backup repository from this server: %w", err))
	}
	backup, err := pgbackrest.LatestBackup(stanzas, db.Stanza)
	if err != nil {
		return finish(fmt.Errorf("nothing to rehearse with: %w", err))
	}
	res.BackupLabel = backup.Label
	dir, err := a.drillDir(taskID, prod.DataDirectory)
	if err != nil {
		return finish(err)
	}
	if err := os.MkdirAll(a.cfg.DrillDir, 0o700); err != nil {
		return finish(err)
	}
	dataDir, newDir, socketDir := filepath.Join(dir, "data"), filepath.Join(dir, "new"), filepath.Join(dir, "socket")
	port := a.cfg.DrillPort
	if n := len(socketDir) + len("/.s.PGSQL.") + len(strconv.Itoa(port)); n > maxSocketPath {
		return finish(fmt.Errorf("the rehearsal's socket path would be %d bytes, over the %d byte limit: use a shorter ROWSAFE_DRILL_DIR", n, maxSocketPath))
	}
	method := "link"
	if free, err := freeBytes(a.cfg.DrillDir); err == nil && free >= int64(float64(prod.TotalSizeBytes)*(drillSpaceFactor+1))+1<<30 {
		method = "copy"
	}
	res.Method = method
	oldCtl, newCtl := filepath.Join(oldBin, "pg_ctl"), filepath.Join(newBin, "pg_ctl")
	defer func() {
		if !res.Passed {
			if data, err := os.ReadFile(filepath.Join(dir, "postgres.log")); err == nil {
				tl.Output("postgres.log (tail)", tail(data, 4000))
			}
		}
		a.stopRehearsalLeftover(dir)
		if err := a.removeDrill(dir, a.scratchPgCtl(dataDir)); err != nil {
			tl.Printf("cleaning up %s failed: %v", dir, err)
		} else {
			tl.Printf("removed the rehearsal directory %s", dir)
		}
	}()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return finish(err)
	}
	if err := os.WriteFile(filepath.Join(dir, drillMarker), []byte(taskID+"\n"), 0o600); err != nil {
		return finish(err)
	}
	for _, d := range []string{dataDir, socketDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return finish(err)
		}
	}
	cli.Wrap = niceWrap()
	tl.Printf("restoring backup %s and the WAL after it into %s", backup.Label, dataDir)
	t0 := time.Now()
	out, err := cli.Restore(ctx, dataDir, filepath.Join(dir, "tablespaces"))
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return finish(fmt.Errorf("restoring the backup failed: %w", err))
	}
	spec := scratchSpec{Name: "rehearsal", Port: port, SocketDir: socketDir, Major: f.Major}
	if a.cfg.DrillPreload == DrillPreloadProduction {
		spec.Preload = prod.SharedPreloadLibraries
	}
	if err := a.writeScratchConf(dataDir, spec); err != nil {
		return finish(err)
	}
	timeout := 4 * time.Hour
	if dl, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(dl)/3, time.Minute)
	}
	scratch := pginspect.Target{SocketDir: socketDir, Port: port, User: a.cfg.PGUser}
	conn, spec, err := a.startScratchFallback(ctx, tl, spec, scratch, oldCtl, dir, timeout, prod.SharedPreloadLibraries)
	if err != nil {
		return finish(fmt.Errorf("the restored copy didn't start: %w", err))
	}
	res.RestoreSeconds = time.Since(t0).Seconds()
	var recoveredTo *time.Time
	qerr := conn.QueryRow(ctx, `SELECT pg_last_xact_replay_timestamp()`).Scan(&recoveredTo)
	var ip initdbParams
	var restored []protocol.DBInfo
	if qerr == nil {
		qerr = checkScratchIsolation(ctx, conn, tl)
	}
	if qerr == nil {
		ip, qerr = readInitdbParams(ctx, conn, f.Major)
	}
	if qerr == nil {
		restored, qerr = pginspect.Databases(ctx, scratch, conn)
	}
	closeConn(ctx, conn)
	if qerr != nil {
		return finish(qerr)
	}
	res.RecoveredTo = recoveredTo
	if out, err := a.runner.Run(ctx, oldCtl, "-D", dataDir, "-m", "fast", "-w", "-t", "600", "stop"); err != nil {
		return finish(fmt.Errorf("stopping the restored copy: %w: %s", err, strings.TrimSpace(string(out))))
	}

	// A fresh target cluster matching the copy, then pg_upgrade.
	if out, err := a.runner.Run(ctx, filepath.Join(newBin, "initdb"), initdbArgs(newDir, ip, to)...); err != nil {
		return finish(fmt.Errorf("creating the PostgreSQL %d cluster failed: %w: %s", to, err, tail(out, 1000)))
	}
	jobs := strconv.Itoa(min(max(numCPU(), 1), 8))
	upArgs := []string{"-C", dir, filepath.Join(newBin, "pg_upgrade"), "-b", oldBin, "-B", newBin, "-d", dataDir, "-D", newDir,
		"-p", strconv.Itoa(port), "-P", strconv.Itoa(port), "-U", ip.Super, "--socketdir", socketDir, "-j", jobs, "--" + method}
	tl.Printf("pg_upgrade --check (PostgreSQL %d -> %d)", f.Major, to)
	out, err = a.runner.Run(ctx, "env", append(upArgs, "--check")...)
	tl.Output("pg_upgrade --check", tail(out, 6000))
	if err != nil {
		res.Issues = append(res.Issues, "pg_upgrade --check found problems: "+pgUpgradeProblems(out, newDir))
		return finish(nil)
	}
	tl.Printf("pg_upgrade --%s", method)
	t1 := time.Now()
	out, err = a.runner.Run(ctx, "env", upArgs...)
	res.UpgradeSeconds = time.Since(t1).Seconds()
	tl.Output("pg_upgrade", tail(out, 6000))
	if err != nil {
		res.Issues = append(res.Issues, "pg_upgrade failed: "+pgUpgradeProblems(out, newDir))
		return finish(nil)
	}

	// Start the upgraded copy privately and check it. It takes the old
	// copy's place (dir/data), where a restarted agent looks for leftovers.
	if err := os.Rename(dataDir, filepath.Join(dir, "old")); err != nil {
		return finish(err)
	}
	if err := os.Rename(newDir, dataDir); err != nil {
		return finish(err)
	}
	_ = os.Remove(filepath.Join(dir, "postgres.log"))
	nspec := scratchSpec{Name: "rehearsal", Port: port, SocketDir: socketDir, Major: to, Preload: spec.Preload}
	if err := a.writeScratchConf(dataDir, nspec); err != nil {
		return finish(err)
	}
	nconn, err := a.startScratch(ctx, tl, nspec, scratch, newCtl, dir, 10*time.Minute)
	if err != nil {
		return finish(fmt.Errorf("the upgraded copy didn't start: %w", err))
	}
	upgraded, qerr := pginspect.Databases(ctx, scratch, nconn)
	if qerr == nil {
		qerr = checkScratchIsolation(ctx, nconn, tl)
	}
	closeConn(ctx, nconn)
	if qerr != nil {
		return finish(qerr)
	}
	var failures, warnings []string
	res.Databases, failures, warnings = compareDatabases(restored, upgraded)
	res.Issues = append(res.Issues, failures...)
	res.Warnings = append(res.Warnings, warnings...)

	// Planner statistics, as after the real upgrade.
	vargs := []string{"PGOPTIONS=-c default_transaction_read_only=off", filepath.Join(newBin, "vacuumdb"), "-h", socketDir, "-p", strconv.Itoa(port),
		"-U", ip.Super, "--all", "--analyze-in-stages"}
	if to >= 18 {
		vargs = append(vargs, "--missing-stats-only")
	}
	t2 := time.Now()
	out, err = a.runner.Run(ctx, "env", vargs...)
	res.AnalyzeSeconds = time.Since(t2).Seconds()
	if err != nil {
		res.Warnings = append(res.Warnings, "refreshing statistics failed: "+strings.TrimSpace(string(tail(out, 500))))
	}

	// pgBackRest on the upgraded copy (a local repository in the rehearsal
	// directory): does it support the target?
	res.PgBackRestOK = a.rehearsePgBackRest(ctx, dir, dataDir, socketDir, port, ip.Super, tl) == nil
	if !res.PgBackRestOK {
		v := pgbackrestVersion(ctx, a.runner, a.cfg.PgBackRestBin)
		res.Issues = append(res.Issues, fmt.Sprintf("pgBackRest %s couldn't back up PostgreSQL %d: install a newer pgBackRest from apt.postgresql.org first", cmp.Or(v, ""), to))
	}

	// Expected downtime: stopping and starting take a few seconds each.
	speed := measureCopySpeed(ctx, a.runner, dataDir)
	if speed == 0 {
		speed = copySpeedDefault
	}
	copySecs := float64(prod.TotalSizeBytes) / speed
	const overhead = 10
	if method == "link" {
		res.FastDowntimeSeconds = res.UpgradeSeconds + overhead
		res.SafeDowntimeSeconds = res.UpgradeSeconds + copySecs + overhead
		if safe := modeOf(chk.Modes, protocol.UpgradeSafe); safe != nil && safe.Method == "clone" {
			res.SafeDowntimeSeconds = res.UpgradeSeconds + overhead + 5
		}
	} else {
		res.SafeDowntimeSeconds = res.UpgradeSeconds + overhead
		res.FastDowntimeSeconds = max(res.UpgradeSeconds-copySecs, res.UpgradeSeconds/10) + overhead
	}
	res.DowntimeEstimated = true
	res.Passed = len(res.Issues) == 0
	res.TotalSeconds = time.Since(start).Seconds()
	if res.Passed {
		res.Summary = fmt.Sprintf("The rehearsal passed: a copy of %s upgraded from PostgreSQL %s to %s in %s, every database opened and pgBackRest took it. "+
			"Expected downtime: about %s in Safe mode, %s in Fast mode.", humanBytes(prod.TotalSizeBytes), f.Version, cmp.Or(res.ToVersion, strconv.Itoa(to)),
			humanDuration(time.Duration(res.UpgradeSeconds*float64(time.Second))),
			humanDuration(time.Duration(res.SafeDowntimeSeconds*float64(time.Second))), humanDuration(time.Duration(res.FastDowntimeSeconds*float64(time.Second))))
	}
	return finish(nil)
}

func modeOf(modes []protocol.UpgradeMode, mode string) *protocol.UpgradeMode {
	for i := range modes {
		if modes[i].Mode == mode {
			return &modes[i]
		}
	}
	return nil
}

// rehearsePgBackRest runs pgbackrest stanza-create against the upgraded
// copy with a local repository inside the rehearsal directory.
func (a *Agent) rehearsePgBackRest(ctx context.Context, dir, dataDir, socketDir string, port int, user string, tl *taskLog) error {
	conf := fmt.Sprintf("[global]\nrepo1-path=%[1]s/pgbackrest-repo\nlock-path=%[1]s/pgbackrest-lock\nlog-path=%[1]s/pgbackrest-log\n"+
		"spool-path=%[1]s/pgbackrest-spool\nlog-level-file=off\n\n[rehearsal]\npg1-path=%[2]s\npg1-socket-path=%[3]s\npg1-port=%[4]d\npg1-user=%[5]s\n",
		dir, dataDir, socketDir, port, user)
	path := filepath.Join(dir, "pgbackrest.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		return err
	}
	out, err := a.runner.Run(ctx, a.cfg.PgBackRestBin, "--config="+path, "--stanza=rehearsal", "stanza-create")
	tl.Output("pgbackrest stanza-create (rehearsal repository)", out)
	return err
}

// scratchPgCtl is the pg_ctl for the cluster in dataDir (its PG_VERSION).
func (a *Agent) scratchPgCtl(dataDir string) string {
	if v, err := os.ReadFile(filepath.Join(dataDir, "PG_VERSION")); err == nil {
		if major, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil {
			return a.cfg.pgBin(major, "pg_ctl")
		}
	}
	return "pg_ctl"
}

// stopRehearsalLeftover stops an upgraded copy a rehearsal left running in
// dir/new (the agent stopped in the middle).
func (a *Agent) stopRehearsalLeftover(dir string) {
	newDir := filepath.Join(dir, "new")
	v, err := os.ReadFile(filepath.Join(newDir, "PG_VERSION"))
	if err != nil {
		return
	}
	if major, err := strconv.Atoi(strings.TrimSpace(string(v))); err == nil {
		_ = a.stopScratch(newDir, a.cfg.pgBin(major, "pg_ctl"))
	}
}

// ---- upgrade ----

var upgradeIDRE = rewindIDRE

func (a *Agent) upgrade(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeParams, taskID string, tl *taskLog) (*protocol.UpgradeResult, error) {
	start := time.Now()
	if !upgradeIDRE.MatchString(p.UpgradeID) {
		return nil, fmt.Errorf("invalid upgrade id %q", p.UpgradeID)
	}
	if p.Mode != protocol.UpgradeSafe && p.Mode != protocol.UpgradeFast {
		return nil, fmt.Errorf("unknown upgrade mode %q (safe or fast)", p.Mode)
	}
	if a.cfg.Sidecar() {
		return nil, errors.New("PostgreSQL runs in Docker here: Rowsafe can't change your container's image. The upgrade check lists the compose change")
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("a rewind or another upgrade is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	st := a.upgradeState()
	if _, ok := st.get(p.UpgradeID); ok {
		return nil, fmt.Errorf("the upgrade %s already ran", p.UpgradeID)
	}
	chk, f, err := a.runUpgradeChecks(ctx, db, p.ToMajor, tl)
	if err != nil {
		return nil, err
	}
	if chk.ToMajor != p.ToMajor {
		return nil, fmt.Errorf("PostgreSQL %d is not available here", p.ToMajor)
	}
	if !chk.CanUpgrade {
		var why []string
		for _, c := range chk.Checks {
			if c.Status == protocol.CheckBlocker {
				why = append(why, c.Title+(map[bool]string{true: ": " + c.Detail, false: ""}[c.Detail != ""]))
			}
		}
		return nil, fmt.Errorf("the upgrade can't start: %s", strings.Join(why, "; "))
	}
	mode := modeOf(chk.Modes, p.Mode)
	if mode == nil || !mode.Available {
		reason := "it isn't available here"
		if mode != nil && mode.Reason != "" {
			reason = mode.Reason
		}
		return nil, fmt.Errorf("%s mode can't be used: %s", p.Mode, reason)
	}
	if p.Mode == protocol.UpgradeFast && (p.Mark == "" || p.MarkBackupSet == "") {
		return nil, errors.New("Fast mode needs the Mark saved just before and its backup, so that it can be undone")
	}
	if !pathExists(a.cfg.pgBin(p.ToMajor, "pg_upgrade")) {
		return nil, fmt.Errorf("PostgreSQL %d isn't installed: rehearse the upgrade first (it installs it)", p.ToMajor)
	}
	unit, _ := a.pgAllowed(db, actUpgrade)

	res := &protocol.UpgradeResult{UpgradeID: p.UpgradeID, FromMajor: f.Major, ToMajor: p.ToMajor, FromVersion: f.Version, Mode: p.Mode, Method: mode.Method}
	helperID := p.UpgradeID + "-up"
	rec := upgradeRecord{ID: p.UpgradeID, DatabaseID: db.ID, Database: db, FromMajor: f.Major, ToMajor: p.ToMajor, FromVersion: f.Version,
		Cluster: f.Cluster, Mode: p.Mode, Method: mode.Method, Status: protocol.UpgradeInProgress, Phase: upPhaseHelper,
		CreatedAt: time.Now().UTC(), KeepDays: p.KeepDays, OldDataDir: f.DataDir, ConfigFile: f.ConfigFile,
		Mark: p.Mark, MarkBackupSet: p.MarkBackupSet, HelperID: helperID}
	if err := st.put(rec); err != nil {
		return nil, err
	}
	tl.Printf("preflight passed: PostgreSQL %s (%s, %s), upgrading to %d in %s mode (pg_upgrade --%s) through the update helper",
		f.Version, unit, humanBytes(f.SizeBytes), p.ToMajor, p.Mode, mode.Method)
	w := a.watchDowntime(ctx, db)
	ans, err := a.updateHelper()(context.WithoutCancel(ctx), helperID, []string{actUpgrade, strconv.Itoa(db.Port), strconv.Itoa(p.ToMajor), mode.Method}, upgradeHelperWait)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		downFor := w.stop()
		res.DurationMs = time.Since(start).Milliseconds()
		if ans != nil && ans["rolled_back"] == "1" {
			_ = st.remove(p.UpgradeID)
			res.RolledBack = true
			res.Summary = fmt.Sprintf("The upgrade failed and PostgreSQL %s runs as before (it was unavailable for %s): %v", f.Version, humanDuration(downFor), err)
			return res, errors.New(res.Summary)
		}
		if ans != nil && ans["ok"] == "0" && ans["kept"] == "" {
			// Refused before anything changed.
			_ = st.remove(p.UpgradeID)
			res.Summary = fmt.Sprintf("The upgrade didn't start: %v. Nothing was changed.", err)
			return res, errors.New(res.Summary)
		}
		if p.Mode == protocol.UpgradeFast && ans != nil && ans["kept"] != "" {
			// The new version didn't start and the old one can't simply be
			// started again: restore it from the backup at the Mark.
			_ = st.update(p.UpgradeID, func(r *upgradeRecord) {
				r.Status, r.Phase, r.AsidePort, r.NewDataDir = protocol.UpgradeDone, upPhaseStarted, atoi(ans["aside_port"]), ans["new_data_dir"]
			})
			tl.Printf("PostgreSQL %d didn't start (%v); restoring PostgreSQL %d from the backup at the Mark %s", p.ToMajor, err, f.Major, p.Mark)
			r, _ := st.get(p.UpgradeID)
			ures, uerr := a.undoFast(ctx, r, protocol.RewindTarget{Mark: p.Mark, BackupSet: p.MarkBackupSet}, taskID, tl)
			if uerr != nil {
				res.Summary = fmt.Sprintf("The upgrade failed (%v), and restoring PostgreSQL %d afterwards failed too: %v", err, f.Major, uerr)
				return res, errors.New(res.Summary)
			}
			res.RolledBack = true
			res.Summary = fmt.Sprintf("The upgrade failed (%v). Rowsafe restored PostgreSQL %d from the backup at the Mark %s: %s", err, f.Major, p.Mark, ures.Summary)
			return res, errors.New(res.Summary)
		}
		res.Summary = fmt.Sprintf("The upgrade failed: %v", err)
		return res, errors.New(res.Summary)
	}
	until := keepUntil(p.KeepDays, time.Now().UTC())
	_ = st.update(p.UpgradeID, func(r *upgradeRecord) {
		r.Phase, r.AsidePort, r.NewDataDir, r.Expires = upPhaseStarted, atoi(ans["aside_port"]), ans["new_data_dir"], until
	})
	if err := a.waitAnswering(ctx, db, updateReadyWait); err != nil {
		w.stop()
		_ = st.update(p.UpgradeID, func(r *upgradeRecord) { r.Status = protocol.UpgradeDone })
		res.Summary = fmt.Sprintf("PostgreSQL %d was started but isn't answering: %v. Use Undo to go back to PostgreSQL %d.", p.ToMajor, err, f.Major)
		return res, errors.New(res.Summary)
	}
	res.DowntimeMs = w.stop().Milliseconds()
	res.ToVersion, _, _ = a.runningVersion(ctx, db)
	_ = st.update(p.UpgradeID, func(r *upgradeRecord) {
		r.Status, r.ToVersion = protocol.UpgradeDone, res.ToVersion
		r.KeptSizeBytes = dirSize(r.OldDataDir)
	})
	res.OldCluster = fmt.Sprintf("PostgreSQL %d/%s on port %s, stopped", f.Major, f.Cluster, ans["aside_port"])
	res.KeptUntil = &until
	r, _ := st.get(p.UpgradeID)
	if err := a.finishBackups(ctx, r, tl); err != nil {
		res.Warnings = append(res.Warnings, "backups aren't set up for the new version yet ("+err.Error()+"); Rowsafe keeps trying every minute")
	} else {
		res.BackupsReady = true
	}
	go a.analyzeAfterUpgrade(context.WithoutCancel(ctx), db, p.ToMajor)
	a.refreshSoftware()
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Upgraded PostgreSQL %s to %s in %s; it didn't accept connections for %s.", f.Version, res.ToVersion,
		humanDuration(time.Duration(res.DurationMs)*time.Millisecond), humanDuration(time.Duration(res.DowntimeMs)*time.Millisecond))
	if p.Mode == protocol.UpgradeSafe {
		res.Summary += fmt.Sprintf(" PostgreSQL %d is kept, stopped, until %s: Undo switches back to it in seconds.", f.Major, until.Format("2006-01-02"))
	} else {
		res.Summary += fmt.Sprintf(" Until %s, Undo restores PostgreSQL %d from the backup taken just before the upgrade, without what was written since.", until.Format("2006-01-02"), f.Major)
	}
	if !res.BackupsReady {
		res.Summary += " Backups for the new version aren't set up yet; Rowsafe keeps trying."
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// finishBackups moves pgBackRest to the version now running
// (stanza-upgrade) and checks archiving.
func (a *Agent) finishBackups(ctx context.Context, r upgradeRecord, tl *taskLog) error {
	db := r.Database
	want := r.ToMajor
	if r.Status == protocol.UpgradeUndone {
		want = r.FromMajor
	}
	var err error
	if a.finishBackupsFn != nil {
		err = a.finishBackupsFn(ctx, db)
	} else {
		var in protocol.InspectResult
		if in, err = pginspect.Inspect(ctx, a.target(db)); err == nil && in.Major() != want {
			err = fmt.Errorf("PostgreSQL %d is running, not %d", in.Major(), want)
		}
		if err == nil {
			err = a.writeConfig(db, in)
		}
		if err == nil {
			var out []byte
			out, err = a.cli(db).StanzaUpgrade(ctx)
			tl.Output("pgbackrest stanza-upgrade", out)
		}
		if err == nil {
			err = a.archivingWorks(ctx, db, tl)
		}
	}
	if err != nil {
		return err
	}
	return a.upgradeState().update(r.ID, func(x *upgradeRecord) { x.BackupsReady, x.Phase = true, upPhaseDone })
}

// analyzeAfterUpgrade refreshes planner statistics at low priority
// (vacuumdb --analyze-in-stages; only what is missing from 18 on, which
// keeps statistics across upgrades).
func (a *Agent) analyzeAfterUpgrade(ctx context.Context, db protocol.DatabaseSpec, major int) {
	if a.skipAnalyze {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
	defer cancel()
	args := append(niceWrap()[1:], a.cfg.pgBin(major, "vacuumdb"), "-h", db.SocketDir, "-p", strconv.Itoa(db.Port), "-U", a.cfg.PGUser,
		"--all", "--analyze-in-stages")
	if major >= 18 {
		args = append(args, "--missing-stats-only")
	}
	start := time.Now()
	if out, err := a.runner.Run(ctx, niceWrap()[0], args...); err != nil {
		a.log.Warn("refreshing statistics after the upgrade failed", "err", err, "output", string(tail(out, 500)))
		return
	}
	a.log.Info("refreshed planner statistics after the upgrade", "took", time.Since(start).Round(time.Second).String())
}

// ---- undo ----

func (a *Agent) upgradeUndo(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeUndoParams, taskID string, tl *taskLog) (*protocol.UpgradeUndoResult, error) {
	if !upgradeIDRE.MatchString(p.UpgradeID) {
		return nil, fmt.Errorf("invalid upgrade id %q", p.UpgradeID)
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("a rewind or an upgrade is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	st := a.upgradeState()
	r, ok := st.get(p.UpgradeID)
	switch {
	case !ok:
		return nil, errors.New("there is nothing to undo: the version kept by that upgrade was already removed")
	case r.DatabaseID != db.ID:
		return nil, errors.New("that upgrade belongs to another database")
	case r.Status == protocol.UpgradeUndone:
		return nil, errors.New("that upgrade was already undone")
	case r.Status != protocol.UpgradeDone:
		return nil, errors.New("that upgrade hasn't finished")
	}
	if _, err := a.pgAllowed(db, actUpgradeUndo); err != nil {
		return nil, err
	}
	if r.Mode == protocol.UpgradeFast {
		t := protocol.RewindTarget{Mark: r.Mark, BackupSet: r.MarkBackupSet}
		if p.Target != nil && p.Target.Mark != "" {
			t = *p.Target
		}
		return a.undoFast(ctx, r, t, taskID, tl)
	}
	start := time.Now()
	res := &protocol.UpgradeUndoResult{UpgradeID: r.ID}
	helperID := taskID + "-undo"
	_ = st.update(r.ID, func(x *upgradeRecord) {
		x.Status, x.Phase, x.HelperID = protocol.UpgradeInProgress, upPhaseUndo, helperID
	})
	tl.Printf("switching back to PostgreSQL %d through the update helper", r.FromMajor)
	w := a.watchDowntime(ctx, db)
	ans, err := a.updateHelper()(context.WithoutCancel(ctx), helperID, []string{actUpgradeUndo, strconv.Itoa(db.Port), "start"}, 15*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		w.stop()
		_ = st.update(r.ID, func(x *upgradeRecord) { x.Status, x.Phase = protocol.UpgradeDone, upPhaseDone })
		res.Summary = fmt.Sprintf("Undoing the upgrade failed: %v", err)
		return res, errors.New(res.Summary)
	}
	if err := a.waitAnswering(ctx, db, updateReadyWait); err != nil {
		w.stop()
		_ = st.update(r.ID, func(x *upgradeRecord) { x.Status, x.Phase = protocol.UpgradeUndone, upPhaseDone })
		res.Summary = fmt.Sprintf("Switched back to PostgreSQL %d, but it isn't answering: %v", r.FromMajor, err)
		return res, errors.New(res.Summary)
	}
	res.DowntimeMs = w.stop().Milliseconds()
	res.Version, _, _ = a.runningVersion(ctx, db)
	return a.afterUndo(ctx, r, res, atoi(ans["aside_port"]), start, tl), nil
}

// afterUndo records an undo that brought the old version back, and moves
// the backups to it.
func (a *Agent) afterUndo(ctx context.Context, r upgradeRecord, res *protocol.UpgradeUndoResult, asidePort int, start time.Time, tl *taskLog) *protocol.UpgradeUndoResult {
	st := a.upgradeState()
	until := keepUntil(r.KeepDays, time.Now().UTC())
	_ = st.update(r.ID, func(x *upgradeRecord) {
		x.Status, x.Phase, x.Expires, x.BackupsReady, x.HelperID = protocol.UpgradeUndone, upPhaseDone, until, false, ""
		if asidePort > 0 {
			x.AsidePort = asidePort
		}
		x.KeptSizeBytes = dirSize(x.NewDataDir)
	})
	r, _ = st.get(r.ID)
	if err := a.finishBackups(ctx, r, tl); err != nil {
		tl.Printf("backups aren't set up for PostgreSQL %d yet (%v); Rowsafe keeps trying every minute", r.FromMajor, err)
	} else {
		res.BackupsReady = true
	}
	a.refreshSoftware()
	res.KeptUntil = &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Back on PostgreSQL %s after %s (it didn't accept connections for %s).", res.Version,
		humanDuration(time.Duration(res.DurationMs)*time.Millisecond), humanDuration(time.Duration(res.DowntimeMs)*time.Millisecond))
	if res.RestoredTo != nil {
		res.Summary += fmt.Sprintf(" It was restored from the backup to %s: what was written after that is not in it.", res.RestoredTo.UTC().Format("15:04:05 UTC on 2006-01-02"))
	} else {
		res.Summary += fmt.Sprintf(" What was written to PostgreSQL %d since the upgrade is not in it; PostgreSQL %d is kept aside, stopped, until %s.",
			r.ToMajor, r.ToMajor, until.Format("2006-01-02"))
	}
	if !res.BackupsReady {
		res.Summary += " Backups aren't set up for it yet; Rowsafe keeps trying."
	}
	tl.Printf("%s", res.Summary)
	return res
}

// undoFast brings the old version back after a Fast mode upgrade: its data
// files were hard-linked into the new version, so it is restored from the
// backup at the Mark saved before the upgrade, like a rewind in place.
func (a *Agent) undoFast(ctx context.Context, r upgradeRecord, t protocol.RewindTarget, taskID string, tl *taskLog) (*protocol.UpgradeUndoResult, error) {
	start := time.Now()
	db := r.Database
	st := a.upgradeState()
	res := &protocol.UpgradeUndoResult{UpgradeID: r.ID}
	typ, target, set, err := rewindRestoreArgs(t)
	if err != nil {
		return nil, fmt.Errorf("the Mark to restore to: %w", err)
	}
	if r.OldDataDir == "" {
		return nil, errors.New("the upgrade record doesn't say where PostgreSQL's old data lived")
	}
	ops := a.ops()
	if err := ops.repo(ctx, db, set); err != nil {
		return nil, err
	}
	helperID := taskID + "-undo"
	_ = st.update(r.ID, func(x *upgradeRecord) {
		x.Status, x.Phase, x.HelperID = protocol.UpgradeInProgress, upPhaseUndo, helperID
	})
	fail := func(step string, cause error) (*protocol.UpgradeUndoResult, error) {
		_ = st.update(r.ID, func(x *upgradeRecord) { x.Status = protocol.UpgradeDone })
		res.Summary = fmt.Sprintf("Undoing the upgrade failed while %s: %v. PostgreSQL %d's data is untouched and kept; run Undo again, or see the docs for doing it by hand.",
			step, cause, r.ToMajor)
		return res, errors.New(res.Summary)
	}
	w := a.watchDowntime(ctx, db)
	defer w.stop()
	allowed, _ := ReadRestartAllowed(a.cfg.RestartAllowFile)
	oldUnit := fmt.Sprintf("postgresql@%d-%s.service", r.FromMajor, r.Cluster)
	asidePort := r.AsidePort
	if allowed[db.Port] != oldUnit { // not switched yet (an interrupted undo is run again)
		tl.Printf("stopping PostgreSQL %d and switching the port back to PostgreSQL %d (not started yet)", r.ToMajor, r.FromMajor)
		ans, err := a.updateHelper()(context.WithoutCancel(ctx), helperID, []string{actUpgradeUndo, strconv.Itoa(db.Port), "nostart"}, 15*time.Minute)
		if err == nil {
			err = helperOK(ans)
		}
		if err != nil {
			return fail("switching the clusters", err)
		}
		asidePort = atoi(ans["aside_port"])
	}
	_ = st.update(r.ID, func(x *upgradeRecord) { x.Phase, x.AsidePort = upPhaseRestoring, asidePort })
	info, err := os.Lstat(r.OldDataDir)
	if err != nil || !info.IsDir() || fileUID(info) != os.Getuid() {
		return fail("reading the old data directory", fmt.Errorf("%s is missing or not the agent user's", r.OldDataDir))
	}
	if ops.running(r.OldDataDir) {
		return fail("reading the old data directory", fmt.Errorf("PostgreSQL is running from %s", r.OldDataDir))
	}
	stale := r.OldDataDir + ".after-upgrade-" + stampNow()
	if err := os.Rename(r.OldDataDir, stale); err != nil {
		return fail("setting the old data aside", err)
	}
	if err := os.Mkdir(r.OldDataDir, info.Mode().Perm()); err != nil {
		return fail("creating a fresh data directory", err)
	}
	if st2, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Lchown(r.OldDataDir, -1, int(st2.Gid))
	}
	tl.Printf("restoring PostgreSQL %d to %s (backup %s) into %s", r.FromMajor, describeTarget(t), cmp.Or(set, "picked by pgBackRest"), r.OldDataDir)
	out, err := ops.restore(ctx, db, pgbackrest.RestoreOptions{DataDir: r.OldDataDir, Type: typ, Target: target, Set: set, Timeline: t.Timeline})
	tl.Output("pgbackrest restore", out)
	if err != nil {
		return fail("restoring the backup", err)
	}
	f := inPlaceFacts{DataDir: r.OldDataDir, Major: r.FromMajor, ConfigFile: r.ConfigFile}
	if err := keepConfig(stale, f, tl); err != nil {
		return fail("putting the configuration back", err)
	}
	socketDir := filepath.Join(a.cfg.RewindDir, "inplace")
	pr := privateRecovery{DataDir: r.OldDataDir, Major: r.FromMajor, Port: db.Port, SocketDir: socketDir,
		LogFile: filepath.Join(a.cfg.RewindDir, "inplace.log"), Timeout: 4 * time.Hour}
	if !strings.HasPrefix(r.ConfigFile, r.OldDataDir+string(filepath.Separator)) {
		pr.ConfigFile = r.ConfigFile
	}
	_ = os.MkdirAll(a.cfg.RewindDir, 0o700)
	tl.Printf("replaying changes up to %s (private socket, no network connections)", describeTarget(t))
	recoveredTo, err := ops.recover(ctx, pr)
	if data, rerr := os.ReadFile(pr.LogFile); rerr == nil && err != nil {
		tl.Output("recovery log (tail)", tail(data, 8000))
	}
	_ = os.Remove(pr.LogFile)
	_ = os.RemoveAll(socketDir)
	if err != nil {
		return fail("replaying changes", err)
	}
	res.RestoredTo = recoveredTo
	_ = st.update(r.ID, func(x *upgradeRecord) { x.Phase = upPhaseUndoStart })
	if err := ops.helper(ctx, helperStart, db.Port, taskID+"-ustart"); err != nil && (!strings.Contains(err.Error(), "did not finish") || !ops.running(r.OldDataDir)) {
		return fail("starting PostgreSQL", err)
	}
	if err := ops.waitReady(ctx, db, r.OldDataDir, inPlaceReadyWait); err != nil {
		return fail("starting PostgreSQL", err)
	}
	res.DowntimeMs = w.stop().Milliseconds()
	res.Version, _, _ = a.runningVersion(ctx, db)
	if err := os.RemoveAll(stale); err != nil {
		tl.Printf("removing %s: %v", stale, err)
	}
	return a.afterUndo(ctx, r, res, asidePort, start, tl), nil
}

// ---- cleanup ----

func (a *Agent) upgradeCleanup(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeCleanupParams, tl *taskLog) (*protocol.UpgradeCleanupResult, error) {
	if !upgradeIDRE.MatchString(p.UpgradeID) {
		return nil, fmt.Errorf("invalid upgrade id %q", p.UpgradeID)
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("a rewind or an upgrade is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	r, ok := a.upgradeState().get(p.UpgradeID)
	switch {
	case !ok:
		res := &protocol.UpgradeCleanupResult{UpgradeID: p.UpgradeID, Summary: "There was nothing to remove (it was already removed)."}
		tl.Printf("%s", res.Summary)
		return res, nil
	case r.DatabaseID != db.ID:
		return nil, errors.New("that upgrade belongs to another database")
	case r.Status == protocol.UpgradeInProgress:
		return nil, errors.New("that upgrade (or its undo) is still running")
	}
	return a.removeKeptVersion(ctx, r, tl)
}

// removeKeptVersion asks the helper to remove the version an upgrade kept
// aside and forgets the upgrade. The caller holds inPlaceMu.
func (a *Agent) removeKeptVersion(ctx context.Context, r upgradeRecord, tl *taskLog) (*protocol.UpgradeCleanupResult, error) {
	res := &protocol.UpgradeCleanupResult{UpgradeID: r.ID}
	kept := r.FromMajor
	if r.Status == protocol.UpgradeUndone {
		kept = r.ToMajor
	}
	tl.Printf("removing PostgreSQL %d/%s, kept aside by the upgrade, through the update helper", kept, r.Cluster)
	ans, err := a.updateHelper()(ctx, r.ID+"-clean"+strconv.FormatInt(time.Now().Unix()%100000, 10),
		[]string{actUpgradeCleanup, strconv.Itoa(r.Database.Port)}, 35*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		if strings.Contains(err.Error(), "there is no upgrade on port") {
			_ = a.upgradeState().remove(r.ID)
			res.Summary = "There was nothing to remove (it was already removed)."
			return res, nil
		}
		return nil, fmt.Errorf("removing PostgreSQL %d failed: %w", kept, err)
	}
	if err := a.upgradeState().remove(r.ID); err != nil {
		return nil, err
	}
	res.Removed = true
	res.FreedBytes, _ = strconv.ParseInt(strings.TrimSpace(ans["freed"]), 10, 64)
	res.PackagesRemoved = strings.Fields(ans["packages_removed"])
	res.Summary = fmt.Sprintf("Removed PostgreSQL %d/%s (%s freed)", kept, r.Cluster, humanBytes(res.FreedBytes))
	if len(res.PackagesRemoved) > 0 {
		res.Summary += fmt.Sprintf(" and its programs")
	}
	if r.Status == protocol.UpgradeUndone {
		res.Summary += "."
	} else {
		res.Summary += "; the upgrade can no longer be undone."
	}
	a.refreshSoftware()
	tl.Printf("%s", res.Summary)
	return res, nil
}

// resumeUpgrade follows through an upgrade or undo the agent's restart
// interrupted, from the helper's answer.
func (a *Agent) resumeUpgrade(ctx context.Context, r upgradeRecord) error {
	st := a.upgradeState()
	tl := &taskLog{}
	defer func() {
		for _, line := range strings.Split(strings.TrimSpace(tl.String()), "\n") {
			if line != "" {
				a.log.Warn("interrupted upgrade: " + line)
			}
		}
	}()
	switch r.Phase {
	case upPhaseHelper:
		ans, err := a.waitUpdateResult(ctx, r.HelperID, upgradeHelperWait)
		if err != nil {
			return err
		}
		if helperOK(ans) != nil {
			if ans["kept"] == "" {
				tl.Printf("the upgrade failed while the agent was stopped, and PostgreSQL %d runs as before: %s", r.FromMajor, ans["error"])
				return st.remove(r.ID)
			}
			return st.update(r.ID, func(x *upgradeRecord) { x.Status, x.Phase = protocol.UpgradeDone, upPhaseStarted })
		}
		_ = st.update(r.ID, func(x *upgradeRecord) {
			x.Status, x.Phase, x.AsidePort, x.NewDataDir = protocol.UpgradeDone, upPhaseStarted, atoi(ans["aside_port"]), ans["new_data_dir"]
			x.Expires = keepUntil(x.KeepDays, time.Now().UTC())
		})
		tl.Printf("the upgrade to PostgreSQL %d finished while the agent was stopped", r.ToMajor)
		r, _ = st.get(r.ID)
		return a.finishBackups(ctx, r, tl)
	case upPhaseStarted, upPhaseDone:
		return st.update(r.ID, func(x *upgradeRecord) { x.Status = protocol.UpgradeDone })
	case upPhaseUndo:
		if r.Mode == protocol.UpgradeSafe {
			ans, err := a.waitUpdateResult(ctx, r.HelperID, 20*time.Minute)
			if err == nil && helperOK(ans) == nil {
				res := &protocol.UpgradeUndoResult{UpgradeID: r.ID}
				a.afterUndo(ctx, r, res, atoi(ans["aside_port"]), time.Now(), tl)
				return nil
			}
		}
		fallthrough
	default:
		// A Fast undo stopped in the middle: Undo can run again.
		tl.Printf("an undo of the upgrade was interrupted; run Undo again")
		return st.update(r.ID, func(x *upgradeRecord) { x.Status = protocol.UpgradeDone })
	}
}
