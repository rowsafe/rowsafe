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

// Valkey from the installer and Redis through rowsafe add: the hosted flow
// (plan, apply with no restart, the check, the first snapshot and Proof), a
// snapshot every day, Marks in the recorded stream, Rewind on key
// patterns, its own alerts, and a server Rowsafe can't follow (snapshots
// only: not protected to any second, no Marks, keys brought back without
// a Mark first).
func TestRedis(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()

	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "cache", Engine: protocol.EngineValkey}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	d, err := c.Database(ctx, "cache")
	if err != nil {
		t.Fatal(err)
	}
	if d.Engine != protocol.EngineValkey || d.Port != 6379 || d.SocketDir != "" || d.ScheduleFull != redisScheduleFull || d.ScheduleDiff != "" {
		t.Fatalf("defaults: %+v", d)
	}
	// One server per port, Redis or Valkey.
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "cache2", Engine: protocol.EngineRedis}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "the Valkey on port 6379 is already protected as cache") {
		t.Fatalf("the same server twice: %v", err)
	}
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "sessions", Port: 6380, Engine: protocol.EngineRedis}); err != nil {
		t.Fatalf("a Redis on another port: %v", err)
	}

	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{})
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{}) // sessions'
	if _, err := c.CreateTask(ctx, "cache", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	p, _ := c.Protection(ctx, "cache")
	if reasons := strings.Join(p.Reasons, "\n"); !strings.Contains(reasons, "recording of Valkey's changes to the bucket is not proven") || strings.Contains(reasons, "WAL") {
		t.Fatalf("protection while verifying: %+v", p)
	}
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	started := *now
	*now = now.Add(time.Minute)
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014T120000Z", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: "on", LastArchivedTime: &last})
	if p, err := c.Protection(ctx, "cache"); err != nil || !p.Protected {
		t.Fatalf("protection once active: %+v %v", p, err)
	}
	*now = now.Add(time.Minute)
	if _, err := c.CreateRestorePoint(ctx, "cache", "before-flush"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-flush",
		LSN: "8f2a:123456", Archived: true, CreatedAt: *now})

	// A snapshot every night.
	*now = time.Date(2026, 10, 15, 1, 0, 30, 0, time.UTC)
	s.Tick()
	full := a.claimOne(protocol.TaskBackup)
	if !strings.Contains(string(full.Params), protocol.BackupFull) {
		t.Fatalf("scheduled backup: %s", full.Params)
	}
	a.done(full, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261015T010030Z", Type: protocol.BackupFull, StartedAt: *now, StoppedAt: now.Add(time.Minute)})

	// Rewind names a logical database and a key pattern.
	copyResp, err := c.CreateRewindCopy(ctx, "cache", protocol.CreateRewindCopyRequest{Mark: "before-flush"})
	if err != nil {
		t.Fatal(err)
	}
	copyID := copyResp.Copy.ID
	a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: copyID, Expires: copyResp.Copy.Expires})
	for _, bad := range []protocol.RewindTable{{DB: "shop", Table: "user:*"}, {DB: "0", Table: ""}} {
		if _, err := c.CompareRewindCopy(ctx, "cache", copyID, []protocol.RewindTable{bad}); apiStatus(err) != http.StatusBadRequest {
			t.Fatalf("compare %+v: %v", bad, err)
		}
	}
	if _, err := c.CompareRewindCopy(ctx, "cache", copyID, []protocol.RewindTable{{DB: "0", Table: "user:*"}}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRewindCompare), protocol.StatusSucceeded, protocol.RewindCompareResult{CopyID: copyID})

	// The server stops letting Rowsafe follow it: snapshots only.
	*now = now.Add(time.Minute)
	last = *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: protocol.RedisArchiveSnapshots, LastArchivedTime: &last,
		Error: "Valkey refuses replication to Rowsafe's user (NOPERM)."})
	p, _ = c.Protection(ctx, "cache")
	if p.Protected || !strings.Contains(strings.Join(p.Reasons, "\n"), "restores go back to its scheduled snapshots, not to any second: Valkey refuses replication") ||
		strings.Contains(strings.Join(p.Reasons, "\n"), "can't read") {
		t.Fatalf("protection, snapshots only: %+v", p)
	}
	if _, err := c.CreateRestorePoint(ctx, "cache", "again"); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "Marks need Rowsafe to follow the server's changes") {
		t.Fatalf("a Mark, snapshots only: %v", err)
	}
	rows, err := c.RestoreRows(ctx, "cache", copyID, protocol.RewindRowsRequest{Tables: []protocol.RewindTable{{DB: "0", Table: "user:*"}}, Confirm: "cache"})
	if err != nil || len(rows.Tasks) != 1 || rows.Tasks[0].Type != protocol.TaskRewindRows {
		t.Fatalf("keys back without a Mark: %+v %v", rows, err)
	}
	a.done(a.claimOne(protocol.TaskRewindRows), protocol.StatusSucceeded, protocol.RewindRowsResult{})

	// Alerts: snapshots only, and memory nearly full with noeviction.
	report := func() {
		heartbeat(a, protocol.ArchiverStats{DatabaseID: d.ID, ArchiveMode: protocol.RedisArchiveSnapshots, LastArchivedTime: &last,
			Error: "Valkey refuses replication to Rowsafe's user (NOPERM)."})
		a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{CollectedAt: *now, Databases: []protocol.DatabaseMonitoring{{
			DatabaseID: d.ID, Metrics: map[string]float64{collect.MRedisMemoryUsedPct: 95, collect.MConnUsedPct: 3},
			Redis: &protocol.RedisStatus{MaxMemoryPolicy: "noeviction"}}}}, nil)
	}
	report()
	s.Tick()
	*now = now.Add(31 * time.Minute)
	report()
	s.Tick()
	firing, err := c.Alerts(ctx, "firing", 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{"redis_snapshots_only", "redis_memory_high"} {
		if !slices.ContainsFunc(firing, func(al protocol.Alert) bool { return al.Rule == rule }) {
			t.Errorf("no %s alert: %+v", rule, firing)
		}
	}
	if slices.ContainsFunc(firing, func(al protocol.Alert) bool { return al.Rule == "wal_archiving_failing" }) {
		t.Errorf("snapshots only isn't a failure: %+v", firing)
	}
	if _, err := c.CreateTask(ctx, "cache", protocol.TaskRestart, nil); apiStatus(err) != http.StatusForbidden ||
		!strings.Contains(err.Error(), "sudo systemctl restart valkey-server") {
		t.Fatalf("restart: %v", err)
	}
}
