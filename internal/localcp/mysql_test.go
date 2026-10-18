package localcp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Every engine this control plane protects has every feature it offers.
func TestLocalEnginesHaveLocalFeatures(t *testing.T) {
	for _, e := range localEngines {
		for _, f := range localFeatures {
			if !protocol.EngineHas(e, f) {
				t.Errorf("%s lacks %s, which this control plane offers it", e, f)
			}
		}
	}
}

// MySQL through rowsafe add: the hosted control plane's flow (plan, apply,
// a restart for the binary log, the check, the first full backup and
// Proof), its defaults and its words.
func TestMySQL(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()

	resp, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "crm", Engine: protocol.EngineMySQL})
	if err != nil || resp.Task.Type != protocol.TaskAdopt {
		t.Fatalf("add: %+v %v", resp, err)
	}
	d := resp.Database
	if d.Engine != protocol.EngineMySQL || d.Port != 3306 || d.SocketDir != "/var/run/mysqld/mysqld.sock" || d.Stanza != "crm" {
		t.Fatalf("defaults: %+v", d)
	}
	// The same server under another name, whatever its socket's path.
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "crm2", Port: 3306, SocketDir: "/run/mysqld/mysqld.sock",
		Engine: protocol.EngineMySQL}); apiStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "the MySQL on port 3306 is already protected as crm") {
		t.Fatalf("the same MySQL twice: %v", err)
	}
	// The agent gets the engine with every task and heartbeat.
	plan := a.claimOne(protocol.TaskAdopt)
	if plan.Database == nil || plan.Database.Engine != protocol.EngineMySQL || plan.Database.SocketDir != "/var/run/mysqld/mysqld.sock" {
		t.Fatalf("the plan's database: %+v", plan.Database)
	}
	if hb := heartbeat(a); len(hb.Monitored) != 1 || hb.Monitored[0].Engine != protocol.EngineMySQL || len(hb.Databases) != 0 {
		t.Fatalf("heartbeat while pending: %+v", hb)
	}
	a.done(plan, protocol.StatusSucceeded, protocol.AdoptResult{RestartRequired: true,
		Inspect: protocol.InspectResult{MySQL: &protocol.MySQLInspect{Engine: protocol.EngineMySQL, Version: "8.4.3"}}})
	if _, err := c.CreateTask(ctx, "crm", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true, RestartRequired: true})
	if db, _ := c.Database(ctx, "crm"); db.Status != protocol.DBAwaitingRestart {
		t.Fatalf("after apply: %s", db.Status)
	}
	// Restarts aren't allowed here: root's own command for MySQL.
	if _, err := c.CreateTask(ctx, "crm", protocol.TaskRestart, nil); apiStatus(err) != http.StatusForbidden ||
		!strings.Contains(err.Error(), "sudo systemctl restart mysql") {
		t.Fatalf("restart: %v", err)
	}
	p, err := c.Protection(ctx, "crm")
	if err != nil || p.Protected || !strings.Contains(strings.Join(p.Reasons, "\n"), "continuous backup to the bucket is not proven") ||
		strings.Contains(strings.Join(p.Reasons, "\n"), "WAL") {
		t.Fatalf("protection while waiting: %+v %v", p, err)
	}

	// Someone restarts MySQL: the binary log is on, the check runs.
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "on"})
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	backup := a.claimOne(protocol.TaskBackup)
	if backup.Database.Engine != protocol.EngineMySQL {
		t.Fatalf("backup's database: %+v", backup.Database)
	}
	started := *now
	*now = now.Add(5 * time.Minute)
	a.done(backup, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014T120000Z-full", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})

	// A Mark is a binary log position.
	*now = now.Add(time.Minute)
	if _, err := c.CreateRestorePoint(ctx, "crm", "before-import"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-import",
		LSN: "binlog.000003:1547", WALFile: "binlog.000003", Archived: true, CreatedAt: *now})
	*now = now.Add(time.Minute)
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "on", LastArchivedTime: &last})
	if p, err := c.Protection(ctx, "crm"); err != nil || !p.Protected {
		t.Fatalf("protection once active: %+v %v", p, err)
	}
	marks, err := c.RestorePoints(ctx, "crm")
	if err != nil || len(marks) != 1 || marks[0].LSN != "binlog.000003:1547" || marks[0].RestoreFromBackup != "20261014T120000Z-full" {
		t.Fatalf("marks: %+v %v", marks, err)
	}

	// The schedules run for it: a daily backup the next night.
	*now = time.Date(2026, 10, 15, 1, 0, 30, 0, time.UTC)
	s.Tick()
	diff := a.claimOne(protocol.TaskBackup)
	if !strings.Contains(string(diff.Params), protocol.BackupDiff) {
		t.Fatalf("scheduled backup: %s", diff.Params)
	}
	a.done(diff, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261015T010030Z-incr", Type: protocol.BackupIncr, StartedAt: *now, StoppedAt: now.Add(time.Minute)})

	// Rewind: a copy at the Mark, then rows back.
	copyResp, err := c.CreateRewindCopy(ctx, "crm", protocol.CreateRewindCopyRequest{Mark: "before-import"})
	if err != nil || copyResp.Copy == nil {
		t.Fatalf("copy: %+v %v", copyResp, err)
	}
	cp := a.claimOne(protocol.TaskRewindCopy)
	if cp.Database.Engine != protocol.EngineMySQL {
		t.Fatalf("copy's database: %+v", cp.Database)
	}
	copyID := copyResp.Copy.ID
	a.done(cp, protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: copyID, Expires: copyResp.Copy.Expires})
	// MySQL's tables: a database and a name, no schema.
	if _, err := c.CompareRewindCopy(ctx, "crm", copyID, []protocol.RewindTable{{DB: "mysql", Table: "user"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("compare the system database: %v", err)
	}
	if _, err := c.CompareRewindCopy(ctx, "crm", copyID, []protocol.RewindTable{{DB: "crm", Table: "orders"}}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRewindCompare), protocol.StatusSucceeded, protocol.RewindCompareResult{CopyID: copyID})
	rows, err := c.RestoreRows(ctx, "crm", copyID, protocol.RewindRowsRequest{Tables: []protocol.RewindTable{{DB: "crm", Table: "orders"}}, Confirm: "crm"})
	if err != nil || len(rows.Tasks) != 2 || rows.Tasks[0].Type != protocol.TaskRestorePoint {
		t.Fatalf("rows back: %+v %v", rows, err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{LSN: "binlog.000003:2001", Archived: true, CreatedAt: *now})
	a.done(a.claimOne(protocol.TaskRewindRows), protocol.StatusSucceeded, protocol.RewindRowsResult{})

	// Its alerts speak of MySQL.
	*now = now.Add(time.Hour) // no archiver report for an hour
	s.Tick()
	*now = now.Add(10 * time.Minute)
	s.Tick()
	firing, err := c.Alerts(ctx, "firing", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, al := range firing {
		if al.Rule == "postgres_unreachable" {
			found = true
			if al.Summary != "Rowsafe can't reach MySQL for crm" || strings.Contains(al.Description+al.NextStep, "PostgreSQL") ||
				!strings.Contains(al.NextStep, "systemctl status mysql") {
				t.Fatalf("alert: %+v", al)
			}
		}
	}
	if !found {
		t.Fatalf("no unreachable alert: %+v", firing)
	}
}

// MariaDB from the installer (the setup API): its own socket default, and
// a PostgreSQL next to it on its own port.
func TestMariaDBRegister(t *testing.T) {
	_, a, c, _ := setup(t)
	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "shop", Port: 3307, Engine: "MariaDB"}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	if sd.Engine != protocol.EngineMariaDB || sd.SocketDir != "/run/mysqld/mysqld.sock" || sd.Port != 3307 || sd.PlanTaskID == "" {
		t.Fatalf("registered: %+v", sd)
	}
	// Again (the installer run twice): the same database.
	var again protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "shop", Port: 3307, Engine: protocol.EngineMariaDB}, &again); code != http.StatusOK || again.ID != sd.ID {
		t.Fatalf("register again: %d %+v", code, again)
	}
	resp, err := c.CreateDatabase(context.Background(), protocol.CreateDatabaseRequest{Name: "app", Port: 5432})
	if err != nil || resp.Database.Engine != protocol.EnginePostgreSQL || resp.Database.SocketDir != "/var/run/postgresql" {
		t.Fatalf("PostgreSQL next to it: %+v %v", resp, err)
	}
	if _, err := c.CreateDatabase(context.Background(), protocol.CreateDatabaseRequest{Name: "cache", Engine: protocol.EngineValkey}); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), "Valkey needs the dashboard") {
		t.Fatalf("Valkey: %v", err)
	}
	if _, err := c.CreateDatabase(context.Background(), protocol.CreateDatabaseRequest{Name: "x", Engine: "oracle"}); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), "unknown engine") {
		t.Fatalf("an unknown engine: %v", err)
	}
}
