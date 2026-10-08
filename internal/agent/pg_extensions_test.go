package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestScratchPreloadAuto(t *testing.T) {
	dir := t.TempDir()
	if got := scratchPreloadAuto(`pg_stat_statements, "timescaledb", pg_cron`, dir); got != "" {
		t.Errorf("without timescaledb.so: %q", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "timescaledb.so"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := scratchPreloadAuto(`pg_stat_statements, "timescaledb", pg_cron`, dir); got != "timescaledb" {
		t.Errorf("got %q, want timescaledb only", got)
	}
	if got := scratchPreloadAuto("pg_stat_statements,vector", dir); got != "" {
		t.Errorf("vector isn't loaded at start: %q", got)
	}
	a := &Agent{cfg: Config{DrillPreload: DrillPreloadProduction}}
	if got := a.scratchPreload("pg_cron,timescaledb", 17); got != "pg_cron,timescaledb" {
		t.Errorf("production: %q", got)
	}
}

func TestPackagedInventory(t *testing.T) {
	calls := 0
	ops := extensionOps{
		blocked:    func(int) string { calls++; return "root hasn't allowed PostgreSQL updates." },
		canRestart: func() string { return "" },
	}
	inv := packagedInventory(map[string]string{"vector": "0.8.1"}, "pg_stat_statements", 17, ops)
	if len(inv) != 3 || calls != 1 {
		t.Fatalf("inventory %+v (blocked asked %d times)", inv, calls)
	}
	v, g, ts := inv[0], inv[1], inv[2]
	if !v.Installed || v.Blocked != "" || v.CanInstall || v.Title != "pgvector" {
		t.Errorf("vector %+v", v)
	}
	if g.Installed || g.CanInstall || g.Blocked == "" {
		t.Errorf("postgis %+v", g)
	}
	if ts.Installed || !ts.Preload || ts.Loaded || !ts.CanRestart {
		t.Errorf("timescaledb %+v", ts)
	}
	inv = packagedInventory(map[string]string{"timescaledb": "2.30.2"}, "timescaledb", 17, extensionOps{blocked: func(int) string { return "" }})
	if !inv[2].Loaded || !inv[2].Installed || !inv[0].CanInstall {
		t.Errorf("loaded: %+v", inv)
	}
}

// TestEnablePackagedAgainstPostgres turns on extensions Rowsafe installs
// with the server's side stood in (installing packages, restarting).
func TestEnablePackagedAgainstPostgres(t *testing.T) {
	e := newDBAEnv(t)
	ctx := t.Context()
	db := e.name("ext")
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: db, CreateOwner: true}, "Created the database")

	var installs, restarts []string
	blocked, cantRestart := "", ""
	e.a.extOpsFn = func(protocol.DatabaseSpec, *taskLog) extensionOps {
		return extensionOps{
			blocked: func(int) string { return blocked },
			install: func(_ context.Context, ext protocol.PGPackagedExtension, id string) error {
				installs = append(installs, ext.Name+" "+id)
				return nil // installs nothing: PostgreSQL still doesn't list it
			},
			canRestart: func() string { return cantRestart },
			restart: func(context.Context, string) error {
				restarts = append(restarts, "restart")
				return errors.New("no restarts in tests")
			},
			start: func(context.Context, string) error { return nil },
		}
	}
	avail, err := availableExtensions(ctx, e.admin)
	if err != nil {
		t.Fatal(err)
	}

	// TimescaleDB is loaded at start: refused without a confirmed restart,
	// before anything is installed.
	if _, ok := avail["timescaledb"]; !ok {
		e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "timescaledb"}, "confirm the restart")
		cantRestart = "Rowsafe isn't allowed to restart PostgreSQL on port 5432."
		e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "timescaledb", Restart: true},
			"needs PostgreSQL restarted once: Rowsafe isn't allowed to restart")
		if len(installs)+len(restarts) != 0 {
			t.Fatalf("installed %v, restarted %v before the restart was confirmed and allowed", installs, restarts)
		}
		cantRestart = ""
	}

	// PostGIS when it isn't there: the reason Rowsafe can't install it, or
	// the install asked for (here, it installs nothing).
	if _, ok := avail["postgis"]; !ok {
		blocked = "that isn't allowed on this server: root allows it there with sudo rowsafe-allow updates."
		e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "postgis"},
			"PostGIS isn't installed on this server, and Rowsafe can't install it here: that isn't allowed")
		if len(installs) != 0 {
			t.Fatalf("installed %v while blocked", installs)
		}
		blocked = ""
		e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "postgis"},
			"PostGIS's package is installed, but PostgreSQL")
		if want := "postgis task_"; len(installs) != 1 || !strings.HasPrefix(installs[0], want) || !strings.HasSuffix(installs[0], "-pkg") {
			t.Fatalf("installs %v", installs)
		}
	}

	// pgvector where PostgreSQL has it: refused while public holds a
	// function another user owns named like one of PostgreSQL's (it could
	// run as the superuser), then no install, no restart, in public.
	if _, ok := avail["vector"]; ok {
		owner := e.as(db, db)
		mustExec(t, owner, `CREATE FUNCTION public.lower(text) RETURNS text LANGUAGE sql AS 'SELECT $1'`)
		e.mustRefuse(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "vector"},
			"could take the place of PostgreSQL's own")
		mustExec(t, owner, `DROP FUNCTION public.lower(text)`)
		installs = nil
		res := e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "vector"}, "Turned on vector")
		if len(installs)+len(restarts) != 0 {
			t.Errorf("installed %v, restarted %v", installs, restarts)
		}
		var schema string
		if err := e.as(db, db).QueryRow(ctx, `SELECT extnamespace::regnamespace::text FROM pg_extension WHERE extname = 'vector'`).Scan(&schema); err != nil || schema != "public" {
			t.Errorf("vector in schema %q (%v)", schema, err)
		}
		i := slices.IndexFunc(res.Inventory.Packaged, func(p protocol.DBPackagedExtension) bool { return p.Name == "vector" })
		if i < 0 || !res.Inventory.Packaged[i].Installed {
			t.Errorf("inventory's packaged extensions: %+v", res.Inventory.Packaged)
		}
	} else {
		t.Log("the local PostgreSQL has no pgvector: skipping turning it on")
	}
}

func TestUpgradeTimescaleCheck(t *testing.T) {
	ts := func(installed string, versions ...string) protocol.ExtensionUse {
		u := protocol.ExtensionUse{Name: "timescaledb", Preload: true, Loaded: true, DefaultVersion: installed}
		for i, v := range versions {
			u.Databases = append(u.Databases, protocol.ExtensionInDatabase{Database: fmt.Sprintf("db%d", i), Version: v})
		}
		return u
	}
	for _, c := range []struct {
		name                     string
		use                      protocol.ExtensionUse
		from, to                 int
		target, current          string
		status, title, fix, want string
	}{
		{"same version", ts("2.30.2", "2.30.2"), 16, 17, "2.30.2", "2.30.2", protocol.CheckOK, "TimescaleDB 2.30.2 moves to PostgreSQL 17", "", "has 2.30.2"},
		{"15 to 16: no common version", ts("2.28.3", "2.28.3"), 15, 16, "2.30.2", "2.28.3", protocol.CheckBlocker, "TimescaleDB can't move to PostgreSQL 16 yet", "",
			"PostgreSQL 15's package stops at TimescaleDB 2.28.3 and PostgreSQL 16's has only 2.30.2"},
		{"outdated in a database", ts("2.30.2", "2.30.2", "2.30.0"), 16, 17, "2.30.2", "2.30.2", protocol.CheckBlocker, "Update TimescaleDB first", protocol.FixUpdateExtension, "db1 (2.30.0)"},
		{"package update pending", ts("2.30.0", "2.30.0"), 16, 17, "2.30.2", "2.30.2", protocol.CheckBlocker, "Update PostgreSQL first", "", "Install PostgreSQL 16's update first"},
		{"newer than the target", ts("2.31.0", "2.31.0"), 16, 17, "2.30.2", "2.31.0", protocol.CheckBlocker, "TimescaleDB is newer here than PostgreSQL 17's package", "", "db0 (2.31.0)"},
		{"no package", ts("2.30.2", "2.30.2"), 17, 18, "", "2.30.2", protocol.CheckBlocker, "TimescaleDB isn't available for PostgreSQL 18", "", "db0"},
	} {
		got, ok := upgradeTimescaleCheck(c.use, c.from, c.to, c.target, c.current)
		if !ok || got.Status != c.status || got.Title != c.title || got.FixID != c.fix || !strings.Contains(got.Detail, c.want) {
			t.Errorf("%s: %+v", c.name, got)
		}
	}
	if _, ok := upgradeTimescaleCheck(protocol.ExtensionUse{Name: "timescaledb"}, 16, 17, "2.30.2", ""); ok {
		t.Error("a check without TimescaleDB in use")
	}
	if debUpstream("2.30.2+dfsg-1.pgdg12+1") != "2.30.2" || debUpstream("1:3.6.4+dfsg-2.pgdg13+1") != "3.6.4" {
		t.Error(debUpstream("2.30.2+dfsg-1.pgdg12+1"))
	}
}

func TestRestorePreload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "postgresql.auto.conf")
	conf := "# Do not edit this file manually!\nwork_mem = '8MB'\nshared_preload_libraries = 'pg_stat_statements, timescaledb'\n"
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := "pg_stat_statements"
	if err := restorePreload(dir, &prev); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "# Do not edit this file manually!\nwork_mem = '8MB'\nshared_preload_libraries = 'pg_stat_statements'\n" {
		t.Errorf("got %q", got)
	}
	if err := restorePreload(dir, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), "shared_preload") {
		t.Errorf("no previous line: %q", got)
	}
}

func TestUpdateExtensionAgainstPostgres(t *testing.T) {
	for _, p := range []protocol.MaintenanceParams{
		{Action: protocol.MaintUpdateExtension, Extension: "pg_trgm", Databases: []string{"app"}},
		{Action: protocol.MaintUpdateExtension, Extension: "vector"},
	} {
		if err := validateMaintenance(p); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	e := newDBAEnv(t)
	db := e.name("upd")
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminCreateDatabase, Database: db, CreateOwner: true}, "Created the database")
	avail, err := availableExtensions(t.Context(), e.admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := avail["vector"]; !ok {
		t.Skip("the local PostgreSQL has no pgvector")
	}
	e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "vector"}, "Turned on vector")
	res, err := e.a.maintenance(t.Context(), e.spec, protocol.MaintenanceParams{Action: protocol.MaintUpdateExtension, Extension: "vector",
		Databases: []string{db, e.name("no_such_db_is_skipped_or_fails")}}, &taskLog{})
	if err != nil || res.Summary != "Updated pgvector to "+avail["vector"]+" in "+db+"." {
		t.Fatalf("%+v %v", res, err)
	}
}
