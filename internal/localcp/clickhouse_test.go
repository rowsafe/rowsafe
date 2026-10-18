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

// ClickHouse from the installer: its HTTP port, the hosted flow, a full
// backup weekly and a differential one every hour, Marks in the record of
// new parts, Rewind on a database's tables, and its own alerts.
func TestClickHouse(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()

	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "events", Engine: protocol.EngineClickHouse}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	d, _ := c.Database(ctx, "events")
	if d.Engine != protocol.EngineClickHouse || d.Port != 8123 || d.SocketDir != "" || d.ScheduleFull != clickhouseScheduleFull || d.ScheduleDiff != clickhouseScheduleDiff {
		t.Fatalf("defaults: %+v", d)
	}
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "events2", Engine: protocol.EngineClickHouse}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "the ClickHouse on port 8123 is already protected as events") {
		t.Fatalf("the same server twice: %v", err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{})
	if _, err := c.CreateTask(ctx, "events", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	if p, _ := c.Protection(ctx, "events"); !strings.Contains(strings.Join(p.Reasons, "\n"), "copying of ClickHouse's changes (each new part) to the bucket is not proven") {
		t.Fatalf("protection while verifying: %+v", p)
	}
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	started := *now
	*now = now.Add(time.Minute)
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "full-1", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})
	*now = now.Add(time.Minute)
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "on", LastArchivedTime: &last})
	if p, err := c.Protection(ctx, "events"); err != nil || !p.Protected {
		t.Fatalf("protection once active: %+v %v", p, err)
	}

	// A differential backup every hour.
	*now = now.Truncate(time.Hour).Add(time.Hour + 30*time.Second)
	s.Tick()
	diff := a.claimOne(protocol.TaskBackup)
	if !strings.Contains(string(diff.Params), protocol.BackupDiff) {
		t.Fatalf("hourly backup: %s", diff.Params)
	}
	a.done(diff, protocol.StatusSucceeded, protocol.BackupResult{Label: "diff-1", Type: protocol.BackupDiff, StartedAt: *now, StoppedAt: now.Add(time.Minute)})

	if _, err := c.CreateRestorePoint(ctx, "events", "before-ttl"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-ttl", LSN: "42", Archived: true, CreatedAt: *now})
	copyResp, err := c.CreateRewindCopy(ctx, "events", protocol.CreateRewindCopyRequest{Mark: "before-ttl"})
	if err != nil {
		t.Fatal(err)
	}
	copyID := copyResp.Copy.ID
	a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: copyID, Expires: copyResp.Copy.Expires})
	if _, err := c.CompareRewindCopy(ctx, "events", copyID, []protocol.RewindTable{{DB: "system", Table: "parts"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("compare a system table: %v", err)
	}
	if _, err := c.CompareRewindCopy(ctx, "events", copyID, []protocol.RewindTable{{DB: "analytics", Table: "hits"}}); err != nil {
		t.Fatal(err)
	}

	// Its own alert: inserts refused.
	report := func() {
		a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{CollectedAt: *now, Databases: []protocol.DatabaseMonitoring{{
			DatabaseID: d.ID, Metrics: map[string]float64{collect.MCHRejectedInserts: 2, collect.MConnUsedPct: 3}}}}, nil)
	}
	report()
	s.Tick()
	*now = now.Add(3 * time.Minute)
	report()
	s.Tick()
	firing, err := c.Alerts(ctx, "firing", 20)
	if err != nil || !slices.ContainsFunc(firing, func(al protocol.Alert) bool {
		return al.Rule == "clickhouse_inserts_rejected" && al.Severity == protocol.SeverityCritical
	}) {
		t.Fatalf("inserts rejected: %+v %v", firing, err)
	}
	if _, err := c.CreateTask(ctx, "events", protocol.TaskRestart, nil); apiStatus(err) != http.StatusForbidden ||
		!strings.Contains(err.Error(), "sudo systemctl restart clickhouse-server") {
		t.Fatalf("restart: %v", err)
	}
}
