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

// OpenSearch, Qdrant and Meilisearch from the installer: their ports and
// snapshot schedules (Qdrant's every 15 minutes once its version allows),
// protected with no continuous backup to report, Marks, Rewind on indexes
// (none for Qdrant), unreachable from the agent's readings, and their own
// alerts.
func TestSnapshotEngines(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()

	for _, eng := range []string{protocol.EngineOpenSearch, protocol.EngineQdrant, protocol.EngineMeilisearch} {
		if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: eng, Engine: eng}, nil); code != http.StatusCreated {
			t.Fatalf("register %s: %d", eng, code)
		}
	}
	os, _ := c.Database(ctx, "opensearch")
	qd, _ := c.Database(ctx, "qdrant")
	me, _ := c.Database(ctx, "meilisearch")
	if os.Port != 9200 || os.ScheduleFull != protocol.OpenSearchScheduleFull || os.ScheduleDiff != protocol.OpenSearchScheduleDiff ||
		qd.Port != 6333 || qd.ScheduleFull != protocol.QdrantScheduleBefore || me.Port != 7700 || me.ScheduleFull != protocol.MeilisearchSchedule {
		t.Fatalf("defaults: %+v %+v %+v", os, qd, me)
	}

	// Plans: Qdrant 1.19 can take snapshots every 15 minutes.
	for range 3 {
		plan := a.claimOne(protocol.TaskAdopt)
		res := protocol.AdoptResult{}
		if plan.Database.Engine == protocol.EngineQdrant {
			res.Inspect = protocol.InspectResult{Engine: protocol.EngineQdrant, ServerVersion: "1.19.2"}
		}
		a.done(plan, protocol.StatusSucceeded, res)
	}
	if qd, _ = c.Database(ctx, "qdrant"); qd.ScheduleFull != protocol.QdrantSchedule {
		t.Fatalf("Qdrant 1.19's schedule: %s", qd.ScheduleFull)
	}

	// Meilisearch through setup: protected with snapshots alone.
	if _, err := c.CreateTask(ctx, "meilisearch", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	if p, _ := c.Protection(ctx, "meilisearch"); !strings.Contains(strings.Join(p.Reasons, "\n"), "backups are not set up yet") ||
		strings.Contains(strings.Join(p.Reasons, "\n"), "WAL") {
		t.Fatalf("protection while verifying: %+v", p)
	}
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	started := *now
	*now = now.Add(time.Minute)
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "snap-1", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})
	if p, err := c.Protection(ctx, "meilisearch"); err != nil || !p.Protected || len(p.Reasons) != 0 {
		t.Fatalf("protection with snapshots: %+v %v", p, err)
	}
	*now = now.Add(time.Minute)
	if _, err := c.CreateRestorePoint(ctx, "meilisearch", "before-reindex"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-reindex", LSN: "snap-2", Archived: true, CreatedAt: *now})

	// A snapshot every 15 minutes.
	*now = now.Truncate(15 * time.Minute).Add(15*time.Minute + 30*time.Second)
	s.Tick()
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "snap-3", Type: protocol.BackupFull, StartedAt: *now, StoppedAt: now.Add(time.Second)})

	// Rewind: Meilisearch's indexes (no database).
	copyResp, err := c.CreateRewindCopy(ctx, "meilisearch", protocol.CreateRewindCopyRequest{Mark: "before-reindex"})
	if err != nil {
		t.Fatal(err)
	}
	copyID := copyResp.Copy.ID
	a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: copyID, Expires: copyResp.Copy.Expires})
	if _, err := c.CompareRewindCopy(ctx, "meilisearch", copyID, []protocol.RewindTable{{DB: "main", Table: "products"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("compare with a database: %v", err)
	}
	if _, err := c.CompareRewindCopy(ctx, "meilisearch", copyID, []protocol.RewindTable{{Table: "products"}}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRewindCompare), protocol.StatusSucceeded, protocol.RewindCompareResult{CopyID: copyID})
	if err := snapshotTables(protocol.EngineOpenSearch, []protocol.RewindTable{{DB: "products", Table: "*"}}, 5); err != nil {
		t.Errorf("an OpenSearch index: %v", err)
	}
	if err := snapshotTables(protocol.EngineOpenSearch, []protocol.RewindTable{{DB: ".kibana", Table: "*"}}, 5); err == nil {
		t.Error("OpenSearch's own index")
	}
	if err := snapshotTables(protocol.EngineQdrant, []protocol.RewindTable{{Table: "docs"}}, 5); err == nil || !strings.Contains(err.Error(), "restore a copy instead") {
		t.Errorf("Qdrant rows: %v", err)
	}

	// Unreachable from the agent's readings, not from an archiver.
	report := func(up float64) {
		a.call("POST", "/v1/agent/monitoring", protocol.MonitoringReport{CollectedAt: *now, Databases: []protocol.DatabaseMonitoring{{
			DatabaseID: me.ID, Metrics: map[string]float64{collect.MPostgresUp: up}}}}, nil)
	}
	report(1)
	s.Tick()
	*now = now.Add(6 * time.Minute)
	report(1)
	s.Tick()
	firing, _ := c.Alerts(ctx, "firing", 20)
	if slices.ContainsFunc(firing, func(al protocol.Alert) bool { return al.Database != nil && al.Database.Name == "meilisearch" }) {
		t.Fatalf("a healthy Meilisearch alerts: %+v", firing)
	}
	report(0)
	s.Tick()
	*now = now.Add(6 * time.Minute)
	report(0)
	s.Tick()
	firing, _ = c.Alerts(ctx, "firing", 20)
	i := slices.IndexFunc(firing, func(al protocol.Alert) bool {
		return al.Rule == "postgres_unreachable" && al.Database != nil && al.Database.Name == "meilisearch"
	})
	if i < 0 || firing[i].Summary != "Rowsafe can't reach Meilisearch for meilisearch" || !strings.Contains(firing[i].NextStep, "systemctl status meilisearch") {
		t.Fatalf("unreachable: %+v", firing)
	}

	// OpenSearch's own rule, from its health detail.
	if v := openSearchValues(&protocol.OpenSearchStatus{Status: "red", DiskTotalBytes: 100, DiskAvailableBytes: 3, HeapMaxBytes: 1, HeapPercent: 91}); v[valueOSRed] != 1 || v[valueOSFlood] != 1 || v[valueOSHeapPct] != 91 {
		t.Errorf("OpenSearch values: %v", v)
	}
	if _, err := c.CreateTask(ctx, "qdrant", protocol.TaskRestart, nil); apiStatus(err) != http.StatusForbidden || !strings.Contains(err.Error(), "sudo systemctl restart qdrant") {
		t.Fatalf("restart: %v", err)
	}
}
