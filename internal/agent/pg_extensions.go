package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

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
	}
}

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
		if !slices.Contains(tune.Libraries(next), ext.Name) {
			stmt, err := alterSystemStmt(protocol.SettingChange{Name: "shared_preload_libraries", Value: tune.WithLibrary(next, ext.Name)})
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
			d.restarted = true // maybe: the next session is a new one either way
			return nil, fmt.Errorf("%s is set to load when PostgreSQL starts, but the restart failed: %w", ext.Title, err)
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
