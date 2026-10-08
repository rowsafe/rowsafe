package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/tune"
)

// The extensions Rowsafe installs (protocol.PGPackagedExtensions: pgvector,
// PostGIS and TimescaleDB's Apache-2.0 edition). Their packages are
// installed by the root helper's update service ("ID pg-install-extension
// PORT NAME": root allowed PostgreSQL updates, the port is in
// restart-allowed; the helper knows the package of each name and nothing
// else). TimescaleDB is also added to shared_preload_libraries (ALTER
// SYSTEM, so backups, Proof, copies and forks carry it) and needs one
// restart, only when the person confirmed it (DBAdminParams.Restart; the
// control plane saved a Mark first). Its telemetry is turned off before
// the extension is created.

// actInstallExtension is the update helper's action.
const actInstallExtension = "pg-install-extension"

// extensionInstallTimeout bounds one package installation (apt).
var extensionInstallTimeout = 20 * time.Minute

// extensionOps are what turning on a packaged extension needs from the
// server; tests replace them.
type extensionOps struct {
	// blocked says why the package can't be installed here ("" when it can).
	blocked func(major int) string
	// install installs ext's package for the cluster on the database's port.
	install func(ctx context.Context, ext protocol.PGPackagedExtension, id string) error
	// canRestart says whether Rowsafe may restart this PostgreSQL ("" yes,
	// else why not); restart restarts it and waits until it answers.
	canRestart func() string
	restart    func(ctx context.Context, id string) error
	// start starts PostgreSQL (after a failed restart) and waits until it
	// answers.
	start func(ctx context.Context, id string) error
}

// extensionOps for db.
func (a *Agent) extensionOps(db protocol.DatabaseSpec, tl *taskLog) extensionOps {
	return extensionOps{
		blocked: func(major int) string { return a.extensionInstallBlocked(db, major) },
		install: func(ctx context.Context, ext protocol.PGPackagedExtension, id string) error {
			return a.installExtensionPackage(ctx, db, ext, id, tl)
		},
		canRestart: func() string { return a.restartBlocked(db) },
		restart: func(ctx context.Context, id string) error {
			_, err := a.restart(ctx, db, id, tl)
			return err
		},
		start: func(ctx context.Context, id string) error {
			res, err := a.askHelper(ctx, helperStart, db.Port, id)
			if err == nil && res["ok"] != "1" {
				err = errors.New(cmp.Or(res["error"], "the helper couldn't start it"))
			}
			if err != nil {
				return err
			}
			return a.waitBack(ctx, db, &protocol.RestartResult{})
		},
	}
}

// restorePreload puts shared_preload_libraries in dataDir's
// postgresql.auto.conf back to prev (nil: no such line), while PostgreSQL
// is down. The file is the agent user's, like the rest of the data
// directory.
func restorePreload(dataDir string, prev *string) error {
	path := filepath.Join(dataDir, "postgresql.auto.conf")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if autoConfPreloadLineRE.MatchString(line) {
			continue
		}
		out = append(out, line)
	}
	if prev != nil {
		out = append(out, "shared_preload_libraries = '"+strings.ReplaceAll(*prev, "'", "''")+"'")
	}
	return writeFileAtomic(path, []byte(strings.Join(out, "\n")+"\n"), 0o600)
}

var autoConfPreloadLineRE = regexp.MustCompile(`^\s*shared_preload_libraries\s*=`)

// extensionInstallBlocked says in plain words why Rowsafe can't install an
// extension's package for db here ("" when it can).
func (a *Agent) extensionInstallBlocked(db protocol.DatabaseSpec, major int) string {
	if !protocol.PGExtensionsMajorOK(major) {
		return fmt.Sprintf("Rowsafe installs these extensions for PostgreSQL %d to %d; this server runs PostgreSQL %d.",
			protocol.PGExtensionsMinMajor, protocol.PGExtensionsMaxMajor, major)
	}
	if err := a.updatesAllowed(protocol.UpdateAllowPostgres, actInstallExtension); err != nil {
		return sentence(err).Error()
	}
	allowed, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		return sentence(err).Error()
	}
	if _, ok := allowed[db.Port]; !ok {
		return fmt.Sprintf("Rowsafe installs packages only for the PostgreSQL it may restart, and port %d isn't one: root allows it with %s.",
			db.Port, AllowHint(protocol.PermRestart))
	}
	return ""
}

// restartBlocked says why Rowsafe can't restart db's PostgreSQL ("" when
// it can).
func (a *Agent) restartBlocked(db protocol.DatabaseSpec) string {
	if a.cfg.Container() && !a.cfg.Sidecar() {
		return "the agent runs in Docker here, so Rowsafe can't restart PostgreSQL."
	}
	allowed, err := a.allowedClusters()
	if err != nil {
		return sentence(err).Error()
	}
	if _, ok := allowed[db.Port]; !ok {
		return fmt.Sprintf("Rowsafe isn't allowed to restart PostgreSQL on port %d: root allows it with %s.", db.Port, AllowHint(protocol.PermRestart))
	}
	return ""
}

// installExtensionPackage asks the update helper to install ext's package
// for the PostgreSQL on db's port.
func (a *Agent) installExtensionPackage(ctx context.Context, db protocol.DatabaseSpec, ext protocol.PGPackagedExtension, id string, tl *taskLog) error {
	tl.Printf("installing %s's package through the update helper (port %d)", ext.Title, db.Port)
	ans, err := a.updateHelper()(ctx, id, []string{actInstallExtension, strconv.Itoa(db.Port), ext.Name}, extensionInstallTimeout)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		return fmt.Errorf("installing %s failed: %w", ext.Title, err)
	}
	tl.Printf("installed %s %s", ans["package"], ans["version"])
	a.refreshSoftware()
	return nil
}

// packagedInventory is the inventory's Packaged list: the extensions
// Rowsafe installs, whether they are here (avail: pg_available_extensions)
// and loaded (preload: shared_preload_libraries now).
func packagedInventory(avail map[string]string, preload string, major int, ops extensionOps) []protocol.DBPackagedExtension {
	var blocked, noRestart *string
	out := make([]protocol.DBPackagedExtension, 0, len(protocol.PGPackagedExtensions))
	for _, e := range protocol.PGPackagedExtensions {
		x := protocol.DBPackagedExtension{Name: e.Name, Title: e.Title, Preload: e.Preload}
		_, x.Installed = avail[e.Name]
		if e.Preload {
			x.Loaded = slices.Contains(tune.Libraries(preload), e.Name)
			if noRestart == nil && ops.canRestart != nil {
				s := ops.canRestart()
				noRestart = &s
			}
			x.CanRestart = noRestart != nil && *noRestart == ""
		}
		if !x.Installed {
			if blocked == nil {
				s := "this agent can't install extensions"
				if ops.blocked != nil {
					s = ops.blocked(major)
				}
				blocked = &s
			}
			x.CanInstall, x.Blocked = *blocked == "", *blocked
		}
		out = append(out, x)
	}
	return out
}

// pendingPreload is shared_preload_libraries as PostgreSQL will load it at
// its next start: the last value in its configuration files (an earlier
// ALTER SYSTEM that waits for a restart included), else the running one.
func pendingPreload(ctx context.Context, q querier) (string, error) {
	var v string
	err := q.QueryRow(ctx, `
		SELECT coalesce((SELECT setting FROM pg_file_settings
		                 WHERE name = 'shared_preload_libraries' AND error IS NULL
		                 ORDER BY seqno DESC LIMIT 1),
		                current_setting('shared_preload_libraries'))`).Scan(&v)
	return v, err
}

// enablePackaged gets a packaged extension ready in the server before
// CREATE EXTENSION: its package installed (avail is updated), and for one
// loaded at start, loaded (a restart the person confirmed) and, for
// TimescaleDB, telemetry off. c is a session in the target database; it
// returns the session to use afterwards (a new one after a restart).
func (d *dba) enablePackaged(ctx context.Context, c *pgx.Conn, ext protocol.PGPackagedExtension, avail map[string]string) (*pgx.Conn, error) {
	major := d.vnum / 10000
	// Loaded at start and not loaded yet: the restart must be confirmed and
	// allowed before anything is installed.
	needRestart := false
	if ext.Preload {
		var running string
		if err := c.QueryRow(ctx, `SELECT current_setting('shared_preload_libraries')`).Scan(&running); err != nil {
			return c, err
		}
		needRestart = !slices.Contains(tune.Libraries(running), ext.Name)
	}
	if needRestart {
		if !d.p.Restart {
			return c, fmt.Errorf("%s is loaded when PostgreSQL starts, so turning it on restarts PostgreSQL once (apps are disconnected for a few seconds); confirm the restart to turn it on", ext.Title)
		}
		if why := d.ext.canRestart(); why != "" {
			return c, fmt.Errorf("%s needs PostgreSQL restarted once: %s", ext.Title, strings.TrimSuffix(why, "."))
		}
	}
	if _, ok := avail[ext.Name]; !ok {
		if why := d.ext.blocked(major); why != "" {
			return c, fmt.Errorf("%s isn't installed on this server, and Rowsafe can't install it here: %s", ext.Title, strings.TrimSuffix(why, "."))
		}
		if err := d.ext.install(ctx, ext, d.taskID+"-pkg"); err != nil {
			return c, err
		}
		got, err := availableExtensions(ctx, c)
		if err != nil {
			return c, err
		}
		if _, ok := got[ext.Name]; !ok {
			return c, fmt.Errorf("%s's package is installed, but PostgreSQL %d doesn't list the %s extension", ext.Title, major, ext.Name)
		}
		d.res.Details = append(d.res.Details, fmt.Sprintf("Installed %s's package (%s).", ext.Title, ext.Package(major)))
		for k, v := range got {
			avail[k] = v
		}
	}
	if needRestart {
		next, err := pendingPreload(ctx, c)
		if err != nil {
			return c, err
		}
		var dataDir string
		var prev *string // shared_preload_libraries in postgresql.auto.conf now (nil: none)
		if err := c.QueryRow(ctx, `
			SELECT current_setting('data_directory'),
			       (SELECT setting FROM pg_file_settings WHERE name = 'shared_preload_libraries'
			          AND sourcefile LIKE '%/postgresql.auto.conf' ORDER BY seqno DESC LIMIT 1)`).Scan(&dataDir, &prev); err != nil {
			return c, err
		}
		if !slices.Contains(tune.Libraries(next), ext.Name) {
			want := tune.WithLibrary(next, ext.Name)
			// Every library must be there, or PostgreSQL wouldn't start.
			for _, lib := range tune.Libraries(want) {
				if !libraryInstalled(ctx, c, lib) {
					return c, fmt.Errorf("the library %s (in shared_preload_libraries) isn't installed on the server, and PostgreSQL wouldn't start without it; Rowsafe changed nothing", lib)
				}
			}
			stmt, err := alterSystemStmt(protocol.SettingChange{Name: "shared_preload_libraries", Value: want})
			if err != nil {
				return c, err
			}
			d.tl.Printf("%s", stmt)
			if _, err := c.Exec(ctx, stmt); err != nil {
				return c, plainPGError(err)
			}
		}
		closeConn(ctx, c)
		d.tl.Printf("restarting PostgreSQL to load %s", ext.Name)
		if err := d.ext.restart(ctx, d.taskID+"-restart"); err != nil {
			d.restarted = true // the next session is a new one either way
			// Put shared_preload_libraries back as it was and start
			// PostgreSQL again, so the database runs as before.
			if rerr := restorePreload(dataDir, prev); rerr != nil {
				return nil, fmt.Errorf("%s is set to load when PostgreSQL starts, but the restart failed (%v), and putting the previous setting back failed too: %v. "+
					"Check postgresql.auto.conf in %s", ext.Title, err, rerr, dataDir)
			}
			d.tl.Printf("the restart failed (%v); put shared_preload_libraries back as it was, starting PostgreSQL again", err)
			if serr := d.ext.start(ctx, d.taskID+"-start"); serr != nil {
				return nil, fmt.Errorf("loading %s failed (the restart: %v); Rowsafe put the previous setting back, but starting PostgreSQL again failed too: %v", ext.Title, err, serr)
			}
			return nil, fmt.Errorf("PostgreSQL didn't start with %s loaded (%v), so Rowsafe put the previous setting back and started it again as before", ext.Title, err)
		}
		d.restarted = true
		d.res.Details = append(d.res.Details, fmt.Sprintf("Restarted PostgreSQL once to load %s.", ext.Title))
		nc, err := d.connectDB(ctx, d.p.Database)
		if err != nil {
			return nil, err
		}
		c = nc
		var running string
		if err := c.QueryRow(ctx, `SELECT current_setting('shared_preload_libraries')`).Scan(&running); err != nil {
			return c, err
		}
		if !slices.Contains(tune.Libraries(running), ext.Name) {
			return c, fmt.Errorf("PostgreSQL restarted but didn't load %s (shared_preload_libraries is %q): a setting in its configuration files may override it", ext.Title, running)
		}
	}
	if ext.Name == "timescaledb" {
		if err := timescaleTelemetryOff(ctx, c, d.exec); err != nil {
			return c, err
		}
	}
	return c, nil
}

// timescaleTelemetryOff makes sure TimescaleDB sends nothing to Timescale
// (timescaledb.telemetry_level = off, with ALTER SYSTEM and a reload).
func timescaleTelemetryOff(ctx context.Context, c *pgx.Conn, exec func(context.Context, querier, string, string, ...string) error) error {
	var cur string
	if err := c.QueryRow(ctx, `SELECT coalesce(current_setting('timescaledb.telemetry_level', true), '')`).Scan(&cur); err != nil {
		return err
	}
	if cur == "off" {
		return nil
	}
	if err := exec(ctx, c, "", `ALTER SYSTEM SET timescaledb.telemetry_level = %L`, "off"); err != nil {
		return err
	}
	_, err := c.Exec(ctx, `SELECT pg_reload_conf()`)
	return err
}

// scratchPreload is shared_preload_libraries for a scratch cluster restored
// from production (whose own value is prod): production's with
// ROWSAFE_DRILL_PRELOAD=production, else scratchPreloadAuto.
func (a *Agent) scratchPreload(prod string, major int) string {
	if a.cfg.DrillPreload == DrillPreloadProduction {
		return prod
	}
	lib := ""
	if major > 0 {
		lib = filepath.Join(filepath.Dir(filepath.Dir(a.cfg.pgBin(major, "postgres"))), "lib")
	}
	return scratchPreloadAuto(prod, lib)
}

// scratchPreloadAuto is what a scratch cluster (Proof, copies, the index
// check, upgrade rehearsals) loads by default: of production's
// shared_preload_libraries, only the extensions Rowsafe installs that must
// be loaded to use their data (TimescaleDB), and only when this server has
// them. Their background workers stay off (drillSettings).
func scratchPreloadAuto(prod string, pkgLibDir string) string {
	var keep []string
	for _, lib := range tune.Libraries(prod) {
		e, ok := protocol.PGPackagedExtensionFor(lib)
		if !ok || !e.Preload || e.Name != lib {
			continue
		}
		if pkgLibDir != "" {
			if _, err := os.Stat(filepath.Join(pkgLibDir, lib+".so")); err != nil {
				continue
			}
		}
		keep = append(keep, lib)
	}
	return strings.Join(keep, ",")
}

// ---- updating an extension in the databases ----

func init() { maintenanceTimeouts[protocol.MaintUpdateExtension] = 30 * time.Minute }

// maxExtensionUpdateDatabases caps one update_extension.
const maxExtensionUpdateDatabases = 100

// validateUpdateExtension checks an update_extension's params.
func validateUpdateExtension(p protocol.MaintenanceParams) error {
	if e, ok := protocol.PGPackagedExtensionFor(p.Extension); !ok || e.Name != p.Extension {
		return fmt.Errorf("Rowsafe updates only the extensions it installs (%s), not %q", protocol.PGExtensionsText(), p.Extension)
	}
	if len(p.Databases) == 0 || len(p.Databases) > maxExtensionUpdateDatabases {
		return fmt.Errorf("give 1 to %d databases", maxExtensionUpdateDatabases)
	}
	for _, d := range p.Databases {
		if err := validDatName(d); err != nil {
			return err
		}
	}
	return nil
}

// updateExtension is MaintUpdateExtension.
func (m *maint) updateExtension(ctx context.Context) error {
	ext, _ := protocol.PGPackagedExtensionFor(m.p.Extension)
	done, err := updateExtensionIn(ctx, m.t, ext, m.p.Databases, m.tl)
	m.res.Summary = extensionUpdateSummary(ext, done)
	return err
}

// extensionUpdate is one database's update.
type extensionUpdate struct{ database, to string }

// updateExtensionIn runs ALTER EXTENSION ext UPDATE in each database, as
// the first statement of a new session (TimescaleDB requires it: its old
// version must not be loaded yet), with a lock timeout so it never queues
// in front of the app's queries for long. A database where the extension
// isn't on is skipped. It stops at the first failure.
func updateExtensionIn(ctx context.Context, t pginspect.Target, ext protocol.PGPackagedExtension, dbs []string, tl *taskLog) ([]extensionUpdate, error) {
	var done []extensionUpdate
	for _, db := range dbs {
		cfg, err := pgx.ParseConfig("")
		if err != nil {
			return done, err
		}
		cfg.Host, cfg.Port, cfg.User, cfg.Database = t.SocketDir, uint16(t.Port), t.User, db
		cfg.RuntimeParams["application_name"] = cmp.Or(t.AppName, "rowsafe-agent")
		cfg.RuntimeParams["lock_timeout"] = "10s"
		cfg.RuntimeParams["statement_timeout"] = "20min"
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		c, err := pgx.ConnectConfig(cctx, cfg)
		cancel()
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "3D000" { // removed since
				tl.Printf("the database %s no longer exists; skipped", db)
				continue
			}
			return done, fmt.Errorf("connecting to the database %s: %w", db, err)
		}
		stmt := "ALTER EXTENSION " + pgx.Identifier{ext.Name}.Sanitize() + " UPDATE"
		tl.Printf("%s (in %s)", stmt, db)
		_, err = c.Exec(ctx, stmt, pgx.QueryExecModeSimpleProtocol)
		var to string
		if err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "42704" { // undefined_object: not on here
				closeConn(ctx, c)
				tl.Printf("%s isn't on in %s; skipped", ext.Name, db)
				continue
			}
			closeConn(ctx, c)
			if isLockTimeout(err) {
				return done, fmt.Errorf("something in %s is using %s right now, so the update waited and gave up; try again in a quiet moment", db, ext.Title)
			}
			return done, fmt.Errorf("updating %s in %s: %w", ext.Title, db, plainPGError(err))
		}
		_ = c.QueryRow(ctx, `SELECT extversion FROM pg_extension WHERE extname = $1`, ext.Name).Scan(&to)
		closeConn(ctx, c)
		done = append(done, extensionUpdate{database: db, to: to})
	}
	return done, nil
}

func extensionUpdateSummary(ext protocol.PGPackagedExtension, done []extensionUpdate) string {
	if len(done) == 0 {
		return fmt.Sprintf("%s needed no update.", ext.Title)
	}
	dbs := make([]string, len(done))
	for i, d := range done {
		dbs[i] = d.database
	}
	return fmt.Sprintf("Updated %s to %s in %s.", ext.Title, cmp.Or(done[len(done)-1].to, "its newest version"), protocol.JoinWords(dbs, 5))
}

// updateOutdatedExtensions updates every extension Rowsafe installs that
// runs an older version in some database than its package (after a minor
// update installed newer packages). It returns what it did, in plain words
// ("" for nothing).
func (a *Agent) updateOutdatedExtensions(ctx context.Context, db protocol.DatabaseSpec, tl *taskLog) (string, error) {
	t := a.fixTarget(db)
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return "", err
	}
	uses, err := collect.ExtensionUse(ctx, a.settingsTarget(db), conn)
	closeConn(ctx, conn)
	if err != nil {
		return "", err
	}
	var said []string
	for _, u := range uses {
		outdated := u.Outdated()
		if len(outdated) == 0 || (u.Preload && !u.Loaded) {
			continue // not loaded: updating it needs it loaded (Pulse says so)
		}
		ext, _ := protocol.PGPackagedExtensionFor(u.Name)
		done, err := updateExtensionIn(ctx, t, ext, outdated, tl)
		if len(done) > 0 {
			said = append(said, extensionUpdateSummary(ext, done))
		}
		if err != nil {
			return strings.Join(said, " "), err
		}
	}
	return strings.Join(said, " "), nil
}

// ---- major upgrades with TimescaleDB ----

// upgradeTimescaleCheck is the upgrade check about TimescaleDB, when it is
// on in a database: pg_upgrade needs PostgreSQL to's package to have the
// TimescaleDB version each database runs, and the PostgreSQL project's
// package carries one version (target, from apt), so every database must
// run exactly that one. current is the newest version from's package
// offers (the installed one, ts.DefaultVersion, may be older). ok is false
// when TimescaleDB isn't in use (no check).
func upgradeTimescaleCheck(ts protocol.ExtensionUse, from, to int, target, current string) (c protocol.UpgradeCheck, ok bool) {
	if len(ts.Databases) == 0 {
		return c, false
	}
	var older, newer []string
	for _, d := range ts.Databases {
		switch {
		case target != "" && protocol.ExtensionVersionLess(d.Version, target):
			older = append(older, fmt.Sprintf("%s (%s)", d.Database, d.Version))
		case target != "" && protocol.ExtensionVersionLess(target, d.Version):
			newer = append(newer, fmt.Sprintf("%s (%s)", d.Database, d.Version))
		}
	}
	reach := cmp.Or(current, ts.DefaultVersion)
	c.ID = "timescaledb"
	switch {
	case target == "":
		c.Status, c.Title = protocol.CheckBlocker, fmt.Sprintf("TimescaleDB isn't available for PostgreSQL %d", to)
		c.Detail = fmt.Sprintf("The PostgreSQL project's repository has no TimescaleDB package for PostgreSQL %d on this server, and the upgrade needs one for the databases that use it (%s). Upgrade once it is published.",
			to, protocol.JoinWords(ts.DatabaseNames(), 4))
	case len(newer) > 0:
		c.Status, c.Title = protocol.CheckBlocker, fmt.Sprintf("TimescaleDB is newer here than PostgreSQL %d's package", to)
		c.Detail = fmt.Sprintf("%s run a newer TimescaleDB than PostgreSQL %d's package (%s), and the upgrade needs the same version on both sides. Upgrade once the PostgreSQL project publishes it for PostgreSQL %d.",
			protocol.JoinWords(newer, 4), to, target, to)
	case len(older) > 0 && !protocol.ExtensionVersionLess(ts.DefaultVersion, target):
		// The installed package already has the target's version: updating
		// the extension in the databases is enough.
		c.Status, c.Title = protocol.CheckBlocker, "Update TimescaleDB first"
		c.Detail = fmt.Sprintf("The upgrade needs every database on TimescaleDB %s, the version PostgreSQL %d's package has, and %s run an older one. "+
			"Update TimescaleDB in them first (it locks their time-series tables briefly; Rowsafe saves a Mark first), then rehearse again.",
			target, to, protocol.JoinWords(older, 4))
		c.FixFinding, c.FixID = protocol.FindingExtensionOutdated+"timescaledb", protocol.FixUpdateExtension
	case len(older) > 0 && !protocol.ExtensionVersionLess(reach, target):
		c.Status, c.Title = protocol.CheckBlocker, "Update PostgreSQL first"
		c.Detail = fmt.Sprintf("The upgrade needs every database on TimescaleDB %s, the version PostgreSQL %d's package has, and %s run an older one. "+
			"Install PostgreSQL %d's update first (Update PostgreSQL: it brings TimescaleDB %s and updates it in the databases), then rehearse again.",
			target, to, protocol.JoinWords(older, 4), from, reach)
	case len(older) > 0:
		c.Status, c.Title = protocol.CheckBlocker, fmt.Sprintf("TimescaleDB can't move to PostgreSQL %d yet", to)
		c.Detail = fmt.Sprintf("The upgrade needs every database on the same TimescaleDB version before and after, but PostgreSQL %d's package stops at TimescaleDB %s and PostgreSQL %d's has only %s (%s run %s). "+
			"Rowsafe can't upgrade this server while TimescaleDB is on: upgrade to a PostgreSQL version whose package has %s, or move the data with a dump and restore into a new server.",
			from, reach, to, target, protocol.JoinWords(ts.DatabaseNames(), 4), reach, reach)
	default:
		c.Status, c.Title = protocol.CheckOK, fmt.Sprintf("TimescaleDB %s moves to PostgreSQL %d", target, to)
		c.Detail = fmt.Sprintf("PostgreSQL %d's TimescaleDB package has %s, the version %s run.", to, target, protocol.JoinWords(ts.DatabaseNames(), 4))
		if !ts.Loaded && ts.Preload {
			c.Status = protocol.CheckWarning
			c.Detail += " TimescaleDB isn't loaded right now (shared_preload_libraries): Pulse offers putting it back."
		}
	}
	return c, true
}

// debUpstream is a Debian package version's upstream part
// ("2.30.2~debian12-1615" -> "2.30.2").
func debUpstream(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.IndexAny(v, "~-+"); i >= 0 {
		v = v[:i]
	}
	return v
}

// timescaleUpgradeCheck reads what upgradeTimescaleCheck needs from the
// server.
func (a *Agent) timescaleUpgradeCheck(ctx context.Context, db protocol.DatabaseSpec, from, to int) (protocol.UpgradeCheck, bool) {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return protocol.UpgradeCheck{}, false
	}
	uses, err := collect.ExtensionUse(ctx, a.settingsTarget(db), conn)
	closeConn(ctx, conn)
	if err != nil {
		return protocol.UpgradeCheck{}, false
	}
	i := slices.IndexFunc(uses, func(u protocol.ExtensionUse) bool { return u.Name == "timescaledb" })
	if i < 0 {
		return protocol.UpgradeCheck{}, false
	}
	pkg := func(m int) string { return "postgresql-" + strconv.Itoa(m) + "-timescaledb" }
	pol := a.aptPolicies(ctx, pkg(to), pkg(from))
	target := debUpstream(cmp.Or(pol[pkg(to)].Candidate, pol[pkg(to)].Installed))
	current := debUpstream(cmp.Or(pol[pkg(from)].Candidate, pol[pkg(from)].Installed))
	return upgradeTimescaleCheck(uses[i], from, to, target, current)
}

// timescaleLibrariesMissing lists the TimescaleDB versions the databases
// run that PostgreSQL to's library folder doesn't have (after it was
// installed for a rehearsal).
func (a *Agent) timescaleLibrariesMissing(ctx context.Context, db protocol.DatabaseSpec, to int) []string {
	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return nil
	}
	uses, err := collect.ExtensionUse(ctx, a.settingsTarget(db), conn)
	closeConn(ctx, conn)
	if err != nil {
		return nil
	}
	lib := filepath.Join(filepath.Dir(filepath.Dir(a.cfg.pgBin(to, "postgres"))), "lib")
	var missing []string
	for _, u := range uses {
		if u.Name != "timescaledb" {
			continue
		}
		for _, d := range u.Databases {
			if !pathExists(filepath.Join(lib, "timescaledb-"+d.Version+".so")) && !slices.Contains(missing, d.Version) {
				missing = append(missing, d.Version)
			}
		}
	}
	return missing
}

// ---- creating them safely ----

// createExtension runs CREATE EXTENSION name as the agent's superuser. For
// the extensions Rowsafe installs, hardened: their scripts run with
// PostgreSQL's own functions first in search_path and the objects go into
// public explicitly, and it is refused when public holds functions,
// operators or casts other users own that could stand in for PostgreSQL's
// own while the script runs as the superuser (CVE-2018-1058 class); inTx
// for a transaction (SET LOCAL), else for the session (set back after).
func (d *dba) createExtension(ctx context.Context, q querier, name string, inTx bool) error {
	if e, ok := protocol.PGPackagedExtensionFor(name); !ok || e.Name != name {
		return d.exec(ctx, q, "", `CREATE EXTENSION IF NOT EXISTS %I CASCADE`, name)
	}
	if risky, err := publicShadows(ctx, q); err != nil {
		return err
	} else if len(risky) > 0 {
		return fmt.Errorf("Rowsafe turns %s on as PostgreSQL's superuser, and the public schema here has objects other users own that could take the place of PostgreSQL's own while it does (%s). "+
			"Drop or rename them, or move them to another schema, then try again", name, protocol.JoinWords(risky, 3))
	}
	set := `SET search_path = pg_catalog, public`
	if inTx {
		set = `SET LOCAL search_path = pg_catalog, public`
	}
	if _, err := q.Exec(ctx, set); err != nil {
		return err
	}
	err := d.exec(ctx, q, "", `CREATE EXTENSION IF NOT EXISTS %I SCHEMA public CASCADE`, name)
	if !inTx {
		if _, rerr := q.Exec(ctx, `RESET search_path`); rerr != nil && err == nil {
			err = rerr
		}
	}
	return err
}

// publicShadows lists what in the public schema, owned by a role that
// isn't a superuser, could be called instead of PostgreSQL's own while an
// extension's script runs: functions named like one of pg_catalog's,
// operators, and casts through a non-superuser's function.
func publicShadows(ctx context.Context, q querier) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT 'function ' || p.oid::regprocedure::text
		FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
		WHERE p.pronamespace = 'public'::regnamespace AND NOT r.rolsuper
		  AND EXISTS (SELECT 1 FROM pg_proc c WHERE c.pronamespace = 'pg_catalog'::regnamespace AND c.proname = p.proname)
		UNION ALL
		SELECT 'operator ' || o.oid::regoperator::text
		FROM pg_operator o JOIN pg_roles r ON r.oid = o.oprowner
		WHERE o.oprnamespace = 'public'::regnamespace AND NOT r.rolsuper
		UNION ALL
		SELECT 'cast ' || format_type(c.castsource, NULL) || ' -> ' || format_type(c.casttarget, NULL)
		FROM pg_cast c JOIN pg_proc p ON p.oid = c.castfunc JOIN pg_roles r ON r.oid = p.proowner
		WHERE NOT r.rolsuper
		LIMIT 10`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
