package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Major upgrades of MySQL, MariaDB, MongoDB and ClickHouse.
//
// They reuse PostgreSQL's tasks and the control plane's flow (check,
// rehearsal on a restored copy, upgrade with a Mark first, undo for 7 days,
// cleanup), with the release series as numbers where PostgreSQL has majors
// (8.4 -> 804, protocol.SeriesNumber).
//
//   - Check: the newer series this server's package sources offer, what
//     blocks it (the engine's own rules: MongoDB one major at a time), the
//     permissions.
//   - Rehearsal: the target version's server packages are downloaded as
//     the agent's user (apt-get download, checked by apt like any package)
//     and unpacked in Rowsafe's own folder; the engine restores the newest
//     backup into a private copy with the installed version, then starts
//     the target version on it, runs its upgrade steps and checks the data.
//     Nothing on the server changes.
//   - Upgrade: the root helper's db-upgrade keeps the installed packages and
//     a copy of the data directory, installs the newer series and starts it
//     (rolling back on failure); the engine then finishes (MongoDB's
//     setFeatureCompatibilityVersion).
//   - Undo: db-upgrade-undo puts both back; cleanup (or 7 days) deletes them.

// EngineUpgrader is implemented by an engine that can be upgraded to a
// newer release series.
type EngineUpgrader interface {
	// UpgradeIssues says what blocks upgrading the running server to series
	// to (plain words), and what to know first.
	UpgradeIssues(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, from, to string) (issues, warnings []string, err error)
	// ServerPackages are the packages holding the server's programs in
	// series to (downloaded for the rehearsal), e.g. mongodb-org-server.
	ServerPackages(installed string) []string
	// RehearseUpgrade restores the newest backup into a private copy with
	// the installed version, then runs the target version (its packages
	// unpacked under root) on it, with the engine's upgrade steps, and
	// checks the data. It fills res (Passed, Issues, Warnings, Databases,
	// timings).
	RehearseUpgrade(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, root, to string, res *protocol.UpgradeRehearsalResult, tl TaskLogger) error
	// AfterUpgrade runs once the new version answers.
	AfterUpgrade(ctx context.Context, env EngineEnv, db protocol.DatabaseSpec, to string, tl TaskLogger) error
}

func engineUpgrader(db protocol.DatabaseSpec) EngineUpgrader {
	if isPostgres(db) {
		return nil
	}
	u, _ := engineFor(protocol.NormalizeEngine(db.Engine)).(EngineUpgrader)
	return u
}

// Engine upgrade helper actions.
const (
	actDBUpgrade        = "db-upgrade"
	actDBUpgradeUndo    = "db-upgrade-undo"
	actDBUpgradeCleanup = "db-upgrade-cleanup"
)

// engineSeries is what the software report says about db's server now.
func (a *Agent) engineSeries(ctx context.Context, db protocol.DatabaseSpec) (protocol.ClusterSoftware, bool) {
	for _, c := range a.engineSoftware(ctx) {
		if c.Port == db.Port {
			return c, c.Series != ""
		}
	}
	return protocol.ClusterSoftware{}, false
}

// candidateIn is the newest version of pkg the package sources offer in
// series ("" when none).
func (a *Agent) candidateIn(ctx context.Context, pkg, series string) string {
	b, err := a.runner.Run(ctx, "apt-cache", "madison", pkg)
	if err != nil {
		return ""
	}
	best := ""
	for _, v := range parseMadison(b) {
		if seriesOf(v) == series && (best == "" || newerMinor(upstreamVersion(best), upstreamVersion(v))) {
			best = v
		}
	}
	return best
}

func check(id, status, title, detail string) protocol.UpgradeCheck {
	return protocol.UpgradeCheck{ID: id, Status: status, Title: title, Detail: detail}
}

// engineUpgradeCheck is upgrade_check for the other engines.
func (a *Agent) engineUpgradeCheck(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeCheckParams, tl *taskLog) (*protocol.UpgradeCheckResult, error) {
	res, _, err := a.engineUpgradeChecks(ctx, db, p.ToMajor)
	if err == nil {
		tl.Printf("%s", res.Summary)
	}
	return res, err
}

func (a *Agent) engineUpgradeChecks(ctx context.Context, db protocol.DatabaseSpec, toMajor int) (*protocol.UpgradeCheckResult, protocol.ClusterSoftware, error) {
	name := protocol.EngineDisplayName(db.Engine)
	u := engineUpgrader(db)
	if u == nil {
		return nil, protocol.ClusterSoftware{}, fmt.Errorf("This agent can't upgrade %s yet; update the agent (this is %s).", name, Version)
	}
	cs, ok := a.engineSeries(ctx, db)
	if !ok {
		return nil, cs, fmt.Errorf("Rowsafe can't tell which %s packages run on port %d (it upgrades %s installed from packages, on Debian and Ubuntu)", name, db.Port, name)
	}
	res := &protocol.UpgradeCheckResult{FromMajor: cs.Major, FromVersion: cmpStr(cs.Running, cs.Installed), Majors: cs.Majors,
		Modes: []protocol.UpgradeMode{{Mode: protocol.UpgradeSafe, Method: "copy", Available: true}}}
	if toMajor == 0 && len(cs.Majors) > 0 {
		toMajor = cs.Majors[0] // one series at a time
	}
	res.ToMajor = toMajor
	to := protocol.SeriesString(toMajor)
	add := func(c protocol.UpgradeCheck) { res.Checks = append(res.Checks, c) }
	blockRehearsal := false
	if to == "" || !slices.Contains(cs.Majors, toMajor) {
		add(check("packages", protocol.CheckBlocker, fmt.Sprintf("This server's package sources don't offer a newer %s", name),
			fmt.Sprintf("Add the vendor's repository for the version you want first; Rowsafe installs only from the server's own package sources. %s %s runs now.", name, cs.Series)))
		blockRehearsal = true
	} else {
		main := engineServerPackages[protocol.NormalizeEngine(db.Engine)]
		for _, pkg := range main {
			if v := a.candidateIn(ctx, pkg, to); v != "" {
				res.ToVersion = upstreamVersion(v)
				break
			}
		}
		add(check("packages", protocol.CheckOK, fmt.Sprintf("%s %s is available from this server's package sources", name, cmpStr(res.ToVersion, to)), ""))
	}
	if to != "" {
		issues, warnings, err := u.UpgradeIssues(ctx, a.engineEnv(protocol.NormalizeEngine(db.Engine)), db, cs.Series, to)
		if err != nil {
			return nil, cs, err
		}
		for _, s := range issues {
			add(check("engine", protocol.CheckBlocker, s, ""))
			blockRehearsal = true
		}
		for _, s := range warnings {
			add(check("engine", protocol.CheckWarning, s, ""))
		}
	}
	upgradeBlocked := blockRehearsal
	if a.cfg.Container() {
		res.Sidecar = true
		res.DockerSteps = []string{
			fmt.Sprintf("Change the image of your %s service to the %s %s image (rehearse it first: Rowsafe's rehearsal on this server shows whether the data opens).", dockerServiceHint(db), name, cmpStr(to, "newer")),
			fmt.Sprintf("Run docker compose up -d %s; Rowsafe notices the new version by itself.", dockerServiceHint(db)),
		}
		add(check("docker", protocol.CheckBlocker, fmt.Sprintf("%s runs in Docker here: the upgrade is a change to your compose file", name), ""))
		upgradeBlocked = true
	} else {
		if err := a.updatesAllowed(protocol.UpdateAllowDatabase, actDBUpgrade); err != nil {
			add(check("helper", protocol.CheckBlocker, "Rowsafe may not upgrade the database on this server", err.Error()))
			upgradeBlocked = true
		} else {
			add(check("helper", protocol.CheckOK, "Rowsafe may install and restart the database on this server", ""))
		}
		if allowed, _ := a.allowedClusters(); allowed[db.Port] == "" {
			add(check("restart", protocol.CheckBlocker, fmt.Sprintf("Rowsafe may not restart %s here", name),
				"Root allows it on the server with "+AllowHint(protocol.PermRestart)))
			upgradeBlocked = true
		}
	}
	add(check("undo", protocol.CheckOK, "The upgrade can be undone for 7 days",
		fmt.Sprintf("Rowsafe keeps a copy of the data directory and %s %s's packages on the server; it needs free disk about the data's size.", name, cs.Series)))
	res.CanRehearse = !blockRehearsal
	res.CanUpgrade = !upgradeBlocked
	switch {
	case to == "":
		res.Summary = fmt.Sprintf("%s %s is the newest series this server's package sources offer.", name, cs.Series)
	case res.CanUpgrade:
		res.Summary = fmt.Sprintf("%s can be upgraded from %s to %s here, after a rehearsal on a restored copy.", name, cs.Series, to)
	case res.CanRehearse:
		res.Summary = fmt.Sprintf("The upgrade of %s from %s to %s can be rehearsed; the upgrade itself needs the items above first.", name, cs.Series, to)
	default:
		res.Summary = fmt.Sprintf("%s can't be upgraded from %s to %s yet: see the items above.", name, cs.Series, to)
	}
	return res, cs, nil
}

// engineUpgradeRehearsal is upgrade_rehearsal for the other engines.
func (a *Agent) engineUpgradeRehearsal(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeRehearsalParams, taskID string, tl *taskLog) (*protocol.UpgradeRehearsalResult, error) {
	start := time.Now()
	name := protocol.EngineDisplayName(db.Engine)
	chk, cs, err := a.engineUpgradeChecks(ctx, db, p.ToMajor)
	if err != nil {
		return nil, err
	}
	to := protocol.SeriesString(chk.ToMajor)
	if !chk.CanRehearse || to == "" {
		return nil, fmt.Errorf("the rehearsal can't run: %s", chk.Summary)
	}
	res := &protocol.UpgradeRehearsalResult{FromMajor: chk.FromMajor, ToMajor: chk.ToMajor, FromVersion: chk.FromVersion, Method: "copy"}
	dir := filepath.Join(a.cfg.DrillDir, "upgrade-"+safeName(taskID))
	if err := os.MkdirAll(filepath.Join(dir, "debs"), 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	u := engineUpgrader(db)
	var specs []string
	for _, pkg := range u.ServerPackages(cs.InstalledPackage) {
		if v := a.candidateIn(ctx, pkg, to); v != "" {
			specs = append(specs, pkg+"="+v)
		}
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("%s %s's server packages aren't in this server's package sources", name, to)
	}
	tl.Printf("downloading %s %s's server programs (%s) to rehearse with; nothing is installed", name, to, strings.Join(specs, " "))
	args := append([]string{"-c", `cd "$1" && shift && exec apt-get -q download "$@"`, "rowsafe", filepath.Join(dir, "debs")}, specs...)
	if out, err := a.runner.Run(ctx, "sh", args...); err != nil {
		tl.Output("apt-get download", out)
		return nil, fmt.Errorf("downloading %s %s failed: %w", name, to, err)
	}
	root := filepath.Join(dir, "root")
	debs, _ := filepath.Glob(filepath.Join(dir, "debs", "*.deb"))
	for _, d := range debs {
		if out, err := a.runner.Run(ctx, "dpkg-deb", "-x", d, root); err != nil {
			tl.Output("dpkg-deb", out)
			return nil, fmt.Errorf("unpacking %s failed: %w", filepath.Base(d), err)
		}
	}
	res.ToVersion = chk.ToVersion
	if err := u.RehearseUpgrade(ctx, a.engineEnv(protocol.NormalizeEngine(db.Engine)), db, root, to, res, tl); err != nil {
		res.Passed = false
		res.Issues = append(res.Issues, err.Error())
	}
	res.TotalSeconds = time.Since(start).Seconds()
	// The real upgrade stops the server for about the copy of the data
	// (reflinks make it instant where the filesystem has them) plus the
	// package installation and the start the rehearsal measured.
	res.SafeDowntimeSeconds = res.UpgradeSeconds + 60
	res.DowntimeEstimated = true
	if res.Passed {
		res.Summary = fmt.Sprintf("Rehearsal passed: %s %s opened a copy of %s restored from the latest backup and the checks passed (%s).",
			name, cmpStr(res.ToVersion, to), db.Name, humanDuration(time.Duration(res.TotalSeconds*float64(time.Second))))
	} else {
		res.Summary = fmt.Sprintf("Rehearsal failed: %s", strings.Join(res.Issues, "; "))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// engineUpgrade is the upgrade task for the other engines.
func (a *Agent) engineUpgrade(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeParams, taskID string, tl *taskLog) (*protocol.UpgradeResult, error) {
	start := time.Now()
	name := protocol.EngineDisplayName(db.Engine)
	if !upgradeIDRE.MatchString(p.UpgradeID) {
		return nil, fmt.Errorf("invalid upgrade id %q", p.UpgradeID)
	}
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("a rewind or another upgrade is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	st := a.upgradeState()
	if _, ok := st.get(p.UpgradeID); ok {
		return nil, fmt.Errorf("the upgrade %s already ran", p.UpgradeID)
	}
	if r, ok := st.forDatabase(db.ID); ok {
		return nil, fmt.Errorf("the upgrade %s is still kept: undo it or delete it first", r.ID)
	}
	chk, cs, err := a.engineUpgradeChecks(ctx, db, p.ToMajor)
	if err != nil {
		return nil, err
	}
	if chk.ToMajor != p.ToMajor || !chk.CanUpgrade {
		return nil, fmt.Errorf("the upgrade can't start: %s", chk.Summary)
	}
	to := protocol.SeriesString(p.ToMajor)
	env := a.engineEnv(protocol.NormalizeEngine(db.Engine))
	rec := upgradeRecord{ID: p.UpgradeID, DatabaseID: db.ID, Database: db, FromMajor: chk.FromMajor, ToMajor: p.ToMajor,
		FromVersion: chk.FromVersion, Mode: protocol.UpgradeSafe, Method: "copy", Status: protocol.UpgradeInProgress, Phase: upPhaseHelper,
		CreatedAt: time.Now().UTC(), KeepDays: p.KeepDays, Mark: p.Mark, BackupsReady: true, HelperID: taskID + "-upgrade"}
	if err := st.put(rec); err != nil {
		return nil, err
	}
	tl.Printf("upgrading %s from %s to %s through the update helper: it keeps a copy of the data and the installed packages, stops %s, installs %s and starts it", name, cs.Series, to, name, to)
	ans, err := a.updateHelper()(ctx, rec.HelperID, []string{actDBUpgrade, strconv.Itoa(db.Port), to}, upgradeHelperWait)
	if err == nil {
		err = helperOK(ans)
	}
	res := &protocol.UpgradeResult{UpgradeID: rec.ID, FromMajor: rec.FromMajor, ToMajor: rec.ToMajor, FromVersion: rec.FromVersion, Mode: rec.Mode, Method: "copy"}
	if err != nil {
		_ = st.remove(rec.ID)
		res.RolledBack = true
		res.DurationMs = time.Since(start).Milliseconds()
		return res, fmt.Errorf("upgrading %s failed: %w", name, err)
	}
	out := &protocol.RestartResult{}
	if err := a.waitBackWithin(ctx, db, out, updateReadyWait); err != nil {
		_ = st.update(rec.ID, func(x *upgradeRecord) { x.Status, x.Phase = protocol.UpgradeDone, upPhaseStarted })
		return res, fmt.Errorf("%s %s is installed, but it isn't answering: %w. Undo puts %s %s back", name, to, err, name, cs.Series)
	}
	if err := engineUpgrader(db).AfterUpgrade(ctx, env, db, to, tl); err != nil {
		res.Warnings = append(res.Warnings, err.Error())
	}
	if vr := engineVersioner(db); vr != nil {
		res.ToVersion, _ = vr.Version(ctx, env, db)
	}
	res.DowntimeMs = int64(atoi(ans["downtime_seconds"])) * 1000
	until := keepUntil(p.KeepDays, time.Now().UTC())
	kept, _ := strconv.ParseInt(ans["kept_bytes"], 10, 64)
	_ = st.update(rec.ID, func(x *upgradeRecord) {
		x.Status, x.Phase, x.ToVersion, x.Expires, x.KeptSizeBytes, x.OldDataDir = protocol.UpgradeDone, upPhaseDone, res.ToVersion, until, kept, ans["datadir"]
	})
	res.BackupsReady = true
	res.KeptUntil = &until
	res.OldCluster = fmt.Sprintf("a copy of the data directory and %s %s's packages, kept by Rowsafe's helper", name, cs.Series)
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Upgraded %s from %s to %s; it didn't accept connections for %s. %s %s is kept until %s so you can undo.",
		name, rec.FromVersion, cmpStr(res.ToVersion, to), downtimeText(res.DowntimeMs), name, cs.Series, until.Format("2006-01-02 15:04 UTC"))
	a.refreshSoftware()
	tl.Printf("%s", res.Summary)
	return res, nil
}

// engineUpgradeUndo is upgrade_undo for the other engines.
func (a *Agent) engineUpgradeUndo(ctx context.Context, db protocol.DatabaseSpec, p protocol.UpgradeUndoParams, taskID string, tl *taskLog) (*protocol.UpgradeUndoResult, error) {
	start := time.Now()
	name := protocol.EngineDisplayName(db.Engine)
	if !a.inPlaceMu.TryLock() {
		return nil, errors.New("a rewind or another upgrade is running on this server; try again when it has finished")
	}
	defer a.inPlaceMu.Unlock()
	st := a.upgradeState()
	r, ok := st.get(p.UpgradeID)
	switch {
	case !ok || r.DatabaseID != db.ID:
		return nil, errors.New("there is nothing to undo: that upgrade's kept version is gone")
	case r.Status != protocol.UpgradeDone:
		return nil, errors.New("that upgrade was undone already, or is still running")
	}
	if err := a.restartRefusal(ctx, db); err != nil { // engine.go: undo restarts it
		return nil, err
	}
	from := protocol.SeriesString(r.FromMajor)
	_ = st.update(r.ID, func(x *upgradeRecord) {
		x.Status, x.Phase, x.HelperID = protocol.UpgradeInProgress, upPhaseUndo, taskID+"-undo"
	})
	tl.Printf("putting %s %s and its data from before the upgrade back", name, from)
	ans, err := a.updateHelper()(ctx, taskID+"-undo", []string{actDBUpgradeUndo, strconv.Itoa(db.Port)}, upgradeHelperWait)
	if err == nil {
		err = helperOK(ans)
	}
	res := &protocol.UpgradeUndoResult{UpgradeID: r.ID}
	if err != nil {
		_ = st.update(r.ID, func(x *upgradeRecord) { x.Status, x.Phase = protocol.UpgradeDone, upPhaseDone })
		return nil, fmt.Errorf("undoing the upgrade failed: %w", err)
	}
	out := &protocol.RestartResult{}
	werr := a.waitBackWithin(ctx, db, out, updateReadyWait)
	until := keepUntil(r.KeepDays, time.Now().UTC())
	_ = st.update(r.ID, func(x *upgradeRecord) { x.Status, x.Phase, x.Expires = protocol.UpgradeUndone, upPhaseDone, until })
	if vr := engineVersioner(db); vr != nil {
		res.Version, _ = vr.Version(ctx, a.engineEnv(protocol.NormalizeEngine(db.Engine)), db)
	}
	res.DowntimeMs = int64(atoi(ans["downtime_seconds"])) * 1000
	res.DurationMs = time.Since(start).Milliseconds()
	res.BackupsReady = true
	res.KeptUntil = &until
	if werr != nil {
		return res, fmt.Errorf("%s %s is back, but it isn't answering: %w", name, from, werr)
	}
	res.Summary = fmt.Sprintf("%s %s runs again on its data from before the upgrade. What was written since is kept aside until %s.", name, cmpStr(res.Version, from), until.Format("2006-01-02 15:04 UTC"))
	a.refreshSoftware()
	tl.Printf("%s", res.Summary)
	return res, nil
}

// engineRemoveKept is removeKeptVersion for the other engines.
func (a *Agent) engineRemoveKept(ctx context.Context, r upgradeRecord, tl *taskLog) (*protocol.UpgradeCleanupResult, error) {
	res := &protocol.UpgradeCleanupResult{UpgradeID: r.ID}
	ans, err := a.updateHelper()(ctx, r.ID+"-cleanup", []string{actDBUpgradeCleanup, strconv.Itoa(r.Database.Port)}, 10*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		return nil, fmt.Errorf("deleting what the upgrade kept failed: %w", err)
	}
	res.Removed = true
	res.FreedBytes, _ = strconv.ParseInt(ans["freed_bytes"], 10, 64)
	if err := a.upgradeState().remove(r.ID); err != nil {
		return nil, err
	}
	res.Summary = fmt.Sprintf("Deleted the data and packages the upgrade kept (%s freed). The upgrade can't be undone any more.", humanBytes(res.FreedBytes))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// safeName keeps letters, digits, - and _.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
