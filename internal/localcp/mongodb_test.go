package localcp

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// MongoDB from the installer (the setup API) and rowsafe add: the hosted
// control plane's flow (plan, apply with no restart, the check, the first
// full backup and Proof), a full backup every day, Marks at an oplog
// position, Rewind on collections, and its own alerts.
func TestMongoDB(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()

	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "docs", Engine: protocol.EngineMongoDB}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	d, err := c.Database(ctx, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if d.Engine != protocol.EngineMongoDB || d.Port != 27017 || d.SocketDir != "" || d.ScheduleFull != mongoScheduleFull || d.ScheduleDiff != "" {
		t.Fatalf("defaults: %+v", d)
	}
	// The same server under another name; a socket that isn't a path.
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "docs2", Port: 27017, Engine: protocol.EngineMongoDB}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "the MongoDB on port 27017 is already protected as docs") {
		t.Fatalf("the same MongoDB twice: %v", err)
	}
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "docs3", Port: 27018, SocketDir: "tmp", Engine: protocol.EngineMongoDB}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a relative socket: %v", err)
	}

	plan := a.claimOne(protocol.TaskAdopt)
	if plan.Database == nil || plan.Database.Engine != protocol.EngineMongoDB || plan.Database.Port != 27017 {
		t.Fatalf("the plan's database: %+v", plan.Database)
	}
	a.done(plan, protocol.StatusSucceeded, protocol.AdoptResult{})
	if _, err := c.CreateTask(ctx, "docs", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	// Turning on backups copies the oplog: nothing restarts.
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	if db, _ := c.Database(ctx, "docs"); db.Status != protocol.DBVerifying {
		t.Fatalf("after apply: %s", db.Status)
	}
	p, err := c.Protection(ctx, "docs")
	if err != nil || p.Protected || !strings.Contains(strings.Join(p.Reasons, "\n"), "copying MongoDB's changes (the oplog) to the bucket is not proven") ||
		strings.Contains(strings.Join(p.Reasons, "\n"), "WAL") {
		t.Fatalf("protection while verifying: %+v %v", p, err)
	}
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	started := *now
	*now = now.Add(5 * time.Minute)
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014T120000Z", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})

	// A Mark is an oplog position.
	*now = now.Add(time.Minute)
	if _, err := c.CreateRestorePoint(ctx, "docs", "before-import"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-import",
		LSN: "{1760443320 1}", Archived: true, CreatedAt: *now})
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "on", LastArchivedTime: &last})
	if p, err := c.Protection(ctx, "docs"); err != nil || !p.Protected {
		t.Fatalf("protection once active: %+v %v", p, err)
	}

	// A full backup every night (MongoDB has no differential ones).
	*now = time.Date(2026, 10, 15, 1, 0, 30, 0, time.UTC)
	s.Tick()
	full := a.claimOne(protocol.TaskBackup)
	if !strings.Contains(string(full.Params), protocol.BackupFull) {
		t.Fatalf("scheduled backup: %s", full.Params)
	}
	a.done(full, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261015T010030Z", Type: protocol.BackupFull, StartedAt: *now, StoppedAt: now.Add(time.Minute)})

	// Rewind names a database and a collection, never MongoDB's own.
	copyResp, err := c.CreateRewindCopy(ctx, "docs", protocol.CreateRewindCopyRequest{Mark: "before-import"})
	if err != nil || copyResp.Copy == nil {
		t.Fatalf("copy: %+v %v", copyResp, err)
	}
	copyID := copyResp.Copy.ID
	a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: copyID, Expires: copyResp.Copy.Expires})
	for _, bad := range []protocol.RewindTable{{DB: "admin", Table: "system.users"}, {DB: "shop", Table: "system.profile"}, {DB: "a.b", Table: "c"}} {
		if _, err := c.CompareRewindCopy(ctx, "docs", copyID, []protocol.RewindTable{bad}); apiStatus(err) != http.StatusBadRequest {
			t.Fatalf("compare %+v: %v", bad, err)
		}
	}
	if _, err := c.CompareRewindCopy(ctx, "docs", copyID, []protocol.RewindTable{{DB: "shop", Table: "orders"}}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRewindCompare), protocol.StatusSucceeded, protocol.RewindCompareResult{CopyID: copyID})

	// Its own alert: the oplog reaches back 3 hours.
	report := func(m map[string]float64) {
		a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{CollectedAt: *now,
			Databases: []protocol.DatabaseMonitoring{{DatabaseID: d.ID, Metrics: m}}}, nil)
	}
	report(map[string]float64{collect.MMongoOplogWindow: 3, collect.MConnUsedPct: 10, collect.MDiskFreePct: 60})
	s.Tick()
	*now = now.Add(31 * time.Minute)
	report(map[string]float64{collect.MMongoOplogWindow: 3, collect.MConnUsedPct: 10, collect.MDiskFreePct: 60})
	s.Tick()
	firing, err := c.Alerts(ctx, "firing", 20)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(firing, func(al protocol.Alert) bool { return al.Rule == "mongodb_oplog_window" })
	if i < 0 || firing[i].Summary != "MongoDB for docs keeps only 3 hours of changes" || firing[i].Value == nil || *firing[i].Value != 3 {
		t.Fatalf("oplog window alert: %+v", firing)
	}
	// The rules listed are the shared ones and MongoDB's.
	rules, err := c.AlertRules(ctx)
	if err != nil || !slices.ContainsFunc(rules, func(r protocol.AlertRule) bool { return r.Rule == "mongodb_queued_ops" }) {
		t.Fatalf("rules: %+v %v", rules, err)
	}

	// Without an archiver report: the shared rule, in MongoDB's words.
	*now = now.Add(time.Hour)
	s.Tick()
	*now = now.Add(10 * time.Minute)
	s.Tick()
	firing, _ = c.Alerts(ctx, "firing", 20)
	i = slices.IndexFunc(firing, func(al protocol.Alert) bool { return al.Rule == "postgres_unreachable" })
	if i < 0 || firing[i].Summary != "Rowsafe can't reach MongoDB for docs" || strings.Contains(firing[i].Description+firing[i].NextStep, "PostgreSQL") ||
		!strings.Contains(firing[i].NextStep, "systemctl status mongod") {
		t.Fatalf("unreachable: %+v", firing)
	}
	if _, err := c.CreateTask(ctx, "docs", protocol.TaskRestart, nil); apiStatus(err) != http.StatusForbidden ||
		!strings.Contains(err.Error(), "sudo systemctl restart mongod") {
		t.Fatalf("restart: %v", err)
	}
}
