package localcp

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// SQLite from the installer (the setup API, --sqlite PATH): a file, not a
// server (port 0, its path), the hosted flow, a whole copy every day kept 7
// days, Marks in WAL mode, Rewind on "main" tables without overwriting, no
// restart; a file in rollback-journal mode (no Marks, not protected to any
// second, rows back without a Mark); its own alert.
func TestSQLite(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	const path = "/srv/app/storage/database.sqlite"

	for _, bad := range []protocol.SetupRegisterRequest{{Name: "app", Port: 5432, SocketDir: path, Engine: protocol.EngineSQLite},
		{Name: "app", SocketDir: path + "-wal", Engine: protocol.EngineSQLite}, {Name: "app", Engine: protocol.EngineSQLite}} {
		if code := a.call("POST", "/v1/agent/setup/databases", bad, nil); code != http.StatusBadRequest {
			t.Fatalf("register %+v: %d", bad, code)
		}
	}
	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "app", SocketDir: path, Engine: protocol.EngineSQLite}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	d, _ := c.Database(ctx, "app")
	if d.Engine != protocol.EngineSQLite || d.Port != 0 || d.SocketDir != path || d.ScheduleFull != sqliteScheduleFull || d.ScheduleDiff != "" || d.RetentionFull != 7 {
		t.Fatalf("defaults: %+v", d)
	}
	// Another file is another database; the same file twice isn't.
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "app2", SocketDir: path, Engine: protocol.EngineSQLite}, nil); code != http.StatusConflict {
		t.Fatalf("the same file twice: %d", code)
	}
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "jobs", SocketDir: "/srv/app/storage/jobs.sqlite", Engine: protocol.EngineSQLite}, nil); code != http.StatusCreated {
		t.Fatalf("another file: %d", code)
	}

	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{})
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{})
	if _, err := c.CreateTask(ctx, "app", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	started := *now
	*now = now.Add(time.Minute)
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014T120000Z", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})
	*now = now.Add(time.Minute)
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "on", LastArchivedTime: &last})
	if p, err := c.Protection(ctx, "app"); err != nil || !p.Protected {
		t.Fatalf("protection in WAL mode: %+v %v", p, err)
	}
	if _, err := c.CreateRestorePoint(ctx, "app", "before-migrate"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-migrate",
		LSN: "g1/3/17", Archived: true, CreatedAt: *now})
	if _, err := c.CreateTask(ctx, "app", protocol.TaskRestart, nil); apiStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), "no database server to restart") {
		t.Fatalf("restart: %v", err)
	}

	// Rewind: "main" and a table's name; never overwriting a row.
	copyResp, err := c.CreateRewindCopy(ctx, "app", protocol.CreateRewindCopyRequest{Mark: "before-migrate"})
	if err != nil {
		t.Fatal(err)
	}
	copyID := copyResp.Copy.ID
	a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: copyID, Expires: copyResp.Copy.Expires})
	for _, bad := range []protocol.RewindTable{{DB: "public", Table: "orders"}, {DB: "main", Table: "sqlite_master"}} {
		if _, err := c.CompareRewindCopy(ctx, "app", copyID, []protocol.RewindTable{bad}); apiStatus(err) != http.StatusBadRequest {
			t.Fatalf("compare %+v: %v", bad, err)
		}
	}
	orders := []protocol.RewindTable{{DB: "main", Table: "orders"}}
	if _, err := c.RestoreRows(ctx, "app", copyID, protocol.RewindRowsRequest{Tables: orders, Confirm: "app", IncludeChanged: true}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("overwriting rows: %v", err)
	}

	// The app switches the file to rollback-journal mode: daily backups only.
	*now = now.Add(time.Minute)
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "off"})
	p, _ := c.Protection(ctx, "app")
	if p.Protected || !strings.Contains(strings.Join(p.Reasons, "\n"), "doesn't use WAL mode") || strings.Contains(strings.Join(p.Reasons, "\n"), "WAL archiving") {
		t.Fatalf("protection in rollback-journal mode: %+v", p)
	}
	if _, err := c.CreateRestorePoint(ctx, "app", "again"); apiStatus(err) != http.StatusConflict || !strings.Contains(err.Error(), "doesn't use WAL mode") {
		t.Fatalf("a Mark in rollback-journal mode: %v", err)
	}
	rows, err := c.RestoreRows(ctx, "app", copyID, protocol.RewindRowsRequest{Tables: orders, Confirm: "app"})
	if err != nil || len(rows.Tasks) != 1 {
		t.Fatalf("rows back without a Mark: %+v %v", rows, err)
	}
	a.done(a.claimOne(protocol.TaskRewindRows), protocol.StatusSucceeded, protocol.RewindRowsResult{})

	// A damaged file.
	damaged := false
	a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{CollectedAt: *now, Databases: []protocol.DatabaseMonitoring{{
		DatabaseID: d.ID, SQLite: &protocol.SQLiteStatus{Path: path, IntegrityOK: &damaged}}}}, nil)
	s.Tick()
	firing, err := c.Alerts(ctx, "firing", 20)
	if err != nil || !slices.ContainsFunc(firing, func(al protocol.Alert) bool {
		return al.Rule == "sqlite_integrity_failed" && strings.Contains(al.Description, path)
	}) {
		t.Fatalf("integrity alert: %+v %v", firing, err)
	}
	if slices.ContainsFunc(firing, func(al protocol.Alert) bool { return al.Rule == "wal_archiving_failing" }) {
		t.Errorf("rollback-journal mode isn't a failure: %+v", firing)
	}
}
