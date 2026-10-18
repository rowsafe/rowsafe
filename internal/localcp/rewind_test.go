package localcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

func apiStatus(err error) int {
	var ae *client.APIError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// activeDB takes shop through rowsafe add (the user API): register, plan,
// apply, the check, a full backup and an archived Mark.
func activeDB(t *testing.T, a *fakeAgent, c *client.Client, now *time.Time) protocol.Database {
	t.Helper()
	ctx := context.Background()
	resp, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "shop", Port: 5432, SocketDir: "/var/run/postgresql"})
	if err != nil || resp.Task.Type != protocol.TaskAdopt || resp.Database.Status != protocol.DBPendingAdopt {
		t.Fatalf("add: %+v %v", resp, err)
	}
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "other", Port: 5432, SocketDir: "/var/run/postgresql"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "already protected as shop") {
		t.Fatalf("the same PostgreSQL under another name: %v", err)
	}
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "crm", Port: 27017, Engine: protocol.EngineMongoDB}); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), "MongoDB needs the dashboard") {
		t.Fatalf("MongoDB: %v", err)
	}
	// Applying before the plan finished is refused.
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("apply while planning: %v", err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{})
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskAdopt, protocol.AdoptParams{Apply: true}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskAdopt), protocol.StatusSucceeded, protocol.AdoptResult{Applied: true})
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	backup := a.claimOne(protocol.TaskBackup)
	started := *now
	*now = now.Add(10 * time.Minute)
	a.done(backup, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-120000F", Type: protocol.BackupFull, StartedAt: started, StoppedAt: *now})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskAdopt, nil); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a plan once active: %v", err)
	}
	*now = now.Add(time.Hour)
	if _, err := c.CreateRestorePoint(ctx, "shop", "before-drop"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-drop", LSN: "0/3000000",
		Archived: true, CreatedAt: *now})
	*now = now.Add(time.Hour)
	db, err := c.Database(ctx, "shop")
	if err != nil || db.Status != protocol.DBActive {
		t.Fatalf("shop: %+v %v", db, err)
	}
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last})
	return db
}

func TestRewind(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)

	info, err := c.RewindInfo(ctx, "shop")
	if err != nil || info.Earliest == nil || info.Latest == nil || !info.Latest.Equal(*now) || len(info.Marks) != 1 || info.Copy != nil ||
		info.CanRewindInPlace || info.InPlaceReason == "" {
		t.Fatalf("rewind info: %+v %v", info, err)
	}

	// Points outside the window, and unknown Marks, are refused.
	before, future := info.Earliest.Add(-time.Minute), now.Add(time.Hour)
	for _, req := range []protocol.CreateRewindCopyRequest{{Time: &before}, {Time: &future}, {Mark: "nope"}, {}, {Time: now, Mark: "before-drop"}} {
		if _, err := c.CreateRewindCopy(ctx, "shop", req); err == nil {
			t.Errorf("copy %+v: no error", req)
		}
	}

	// A copy to the Mark: the backup before it, a day by default.
	resp, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Mark: "before-drop"})
	if err != nil || resp.Copy == nil || resp.Copy.Status != protocol.RewindCopyRestoring || len(resp.Tasks) != 1 {
		t.Fatalf("copy: %+v %v", resp, err)
	}
	cp := *resp.Copy
	if cp.Target.Mark != "before-drop" || cp.Target.BackupSet != "20261014-120000F" || !cp.Expires.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("copy target: %+v", cp)
	}
	if _, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Time: now}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second copy: %v", err)
	}
	if _, err := c.CompareRewindCopy(ctx, "shop", cp.ID, nil); apiStatus(err) != http.StatusConflict {
		t.Fatalf("compare while restoring: %v", err)
	}
	task := a.claimOne(protocol.TaskRewindCopy)
	var p protocol.RewindCopyParams
	if err := json.Unmarshal(task.Params, &p); err != nil || p.CopyID != cp.ID || p.Target.BackupSet != "20261014-120000F" {
		t.Fatalf("copy params: %+v %v", p, err)
	}
	clamped := now.Add(23 * time.Hour)
	a.done(task, protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: cp.ID, SizeBytes: 1 << 20, Expires: clamped,
		Databases: []protocol.DBInfo{{Name: "shop"}}})
	var hb protocol.HeartbeatResponse
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Rewinds: []protocol.RewindState{{ID: cp.ID, DatabaseID: db.ID,
		Kind: protocol.RewindKindCopy, Status: protocol.RewindCopyReady, SizeBytes: 2 << 20, Expires: &clamped}}}, &hb)
	if len(hb.RewindExpires) != 0 {
		t.Fatalf("expiry already as the agent applied it: %+v", hb.RewindExpires)
	}
	info, _ = c.RewindInfo(ctx, "shop")
	if info.Copy == nil || info.Copy.Status != protocol.RewindCopyReady || info.Copy.SizeBytes != 2<<20 || !info.Copy.Expires.Equal(clamped) {
		t.Fatalf("ready copy: %+v", info.Copy)
	}

	// Extend: the next heartbeat tells the agent.
	ext, err := c.ExtendRewindCopy(ctx, "shop", cp.ID, 48)
	if err != nil || !ext.Expires.Equal(now.Add(48*time.Hour)) {
		t.Fatalf("extend: %+v %v", ext, err)
	}
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Rewinds: []protocol.RewindState{{ID: cp.ID, DatabaseID: db.ID,
		Kind: protocol.RewindKindCopy, Expires: &clamped}}}, &hb)
	if len(hb.RewindExpires) != 1 || !hb.RewindExpires[0].Expires.Equal(ext.Expires) {
		t.Fatalf("extend sent to the agent: %+v", hb.RewindExpires)
	}

	// Compare, on the side lane.
	cmp, err := c.CompareRewindCopy(ctx, "shop", cp.ID, []protocol.RewindTable{{DB: "shop", Table: "public.orders"}})
	if err != nil || len(cmp.Tasks) != 1 {
		t.Fatalf("compare: %+v %v", cmp, err)
	}
	if _, err := c.CompareRewindCopy(ctx, "shop", cp.ID, []protocol.RewindTable{{DB: "shop", Table: "orders"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a table without its schema: %v", err)
	}
	a.done(a.claimOne(protocol.TaskRewindCompare), protocol.StatusSucceeded, protocol.RewindCompareResult{CopyID: cp.ID})

	// Bringing rows back: typed confirmation, then a Mark first.
	rows := protocol.RewindRowsRequest{Tables: []protocol.RewindTable{{DB: "shop", Table: "public.orders"}}}
	if _, err := c.RestoreRows(ctx, "shop", cp.ID, rows); apiStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `"confirm": "shop"`) {
		t.Fatalf("rows without confirming: %v", err)
	}
	rows.Confirm = "shop"
	rr, err := c.RestoreRows(ctx, "shop", cp.ID, rows)
	if err != nil || len(rr.Tasks) != 2 || rr.Tasks[0].Type != protocol.TaskRestorePoint || rr.Tasks[1].Type != protocol.TaskRewindRows {
		t.Fatalf("rows: %+v %v", rr, err)
	}
	if _, err := c.RestoreRows(ctx, "shop", cp.ID, rows); apiStatus(err) != http.StatusConflict {
		t.Fatalf("rows twice: %v", err)
	}
	a.claimOne("", protocol.TaskRewindRows) // waits for the Mark
	mark := a.claimOne(protocol.TaskRestorePoint)
	a.done(mark, protocol.StatusSucceeded, protocol.RestorePointResult{Name: "x", LSN: "0/4000000", CreatedAt: *now})
	a.done(a.claimOne(protocol.TaskRewindRows), protocol.StatusSucceeded, protocol.RewindRowsResult{Summary: "Brought back 3 rows."})

	// The whole database in place: not here.
	if _, err := c.RewindInPlace(ctx, "shop", protocol.RewindInPlaceRequest{Mark: "before-drop", Confirm: "shop"}); apiStatus(err) != http.StatusForbidden ||
		!strings.Contains(err.Error(), "rowsafe login") {
		t.Fatalf("in place: %v", err)
	}

	// Drop: queued once; the copy is gone when it succeeds.
	if _, err := c.DeleteRewindCopy(ctx, "shop", cp.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteRewindCopy(ctx, "shop", cp.ID); apiStatus(err) != http.StatusConflict {
		t.Fatalf("drop twice: %v", err)
	}
	a.done(a.claimOne(protocol.TaskRewindDrop), protocol.StatusSucceeded, protocol.RewindDropResult{CopyID: cp.ID, Removed: true})
	info, _ = c.RewindInfo(ctx, "shop")
	if info.Copy != nil || len(info.Tasks) != 4 {
		t.Fatalf("after the drop: copy %+v, %d tasks", info.Copy, len(info.Tasks))
	}

	// A new copy at a time; the agent stops reporting it once it expired.
	at := now.Add(-30 * time.Minute)
	resp, err = c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Time: &at, Hours: 2})
	if err != nil || resp.Copy.Target.Time == nil || resp.Copy.Target.BackupSet != "20261014-120000F" {
		t.Fatalf("copy at a time: %+v %v", resp, err)
	}
	a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: resp.Copy.ID})
	*now = now.Add(3 * time.Hour)
	heartbeat(a)
	info, _ = c.RewindInfo(ctx, "shop")
	if info.Copy != nil {
		t.Fatalf("an expired copy: %+v", info.Copy)
	}

	// A copy that failed shows why for a day, and a new one can start.
	resp, _ = c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Time: &at})
	task = a.claimOne(protocol.TaskRewindCopy)
	if code := a.call("POST", "/v1/agent/tasks/"+task.ID+"/complete", protocol.CompleteRequest{Status: protocol.StatusFailed, Error: "disk full"}, nil); code != http.StatusNoContent {
		t.Fatal(code)
	}
	info, _ = c.RewindInfo(ctx, "shop")
	if info.Copy == nil || info.Copy.Status != "failed" || info.Copy.Error != "disk full" {
		t.Fatalf("failed copy: %+v", info.Copy)
	}
	if _, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Time: &at}); err != nil {
		t.Fatalf("a copy after a failed one: %v", err)
	}
}

func TestRewindNeedsActive(t *testing.T) {
	_, _, c, now := setup(t)
	ctx := context.Background()
	if _, err := c.CreateDatabase(ctx, protocol.CreateDatabaseRequest{Name: "shop", Port: 5432}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Time: now}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "backups are on") {
		t.Fatalf("copy while pending: %v", err)
	}
	if _, err := c.RewindInfo(ctx, "nope"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("unknown database: %v", err)
	}
}
