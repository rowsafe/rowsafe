package agent

import (
	"context"
	"errors"
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

	// pgvector where PostgreSQL has it: no install, no restart.
	if _, ok := avail["vector"]; ok {
		installs = nil
		res := e.mustRun(protocol.DBAdminParams{Action: protocol.DBAdminEnableExtension, Database: db, Extension: "vector"}, "Turned on vector")
		if len(installs)+len(restarts) != 0 {
			t.Errorf("installed %v, restarted %v", installs, restarts)
		}
		i := slices.IndexFunc(res.Inventory.Packaged, func(p protocol.DBPackagedExtension) bool { return p.Name == "vector" })
		if i < 0 || !res.Inventory.Packaged[i].Installed {
			t.Errorf("inventory's packaged extensions: %+v", res.Inventory.Packaged)
		}
	} else {
		t.Log("the local PostgreSQL has no pgvector: skipping turning it on")
	}
}
