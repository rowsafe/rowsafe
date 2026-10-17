package localcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// copyReport is a heartbeat with the archiver and the second copy's state.
func copyReport(a *fakeAgent, db protocol.Database, archived time.Time, copies ...protocol.SecondCopyStatus) {
	a.t.Helper()
	req := protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.18",
		Archivers:    []protocol.ArchiverStats{{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &archived}},
		SecondCopies: copies}
	if code := a.call("POST", "/v1/agent/heartbeat", req, nil); code != http.StatusOK {
		a.t.Fatalf("heartbeat: %d", code)
	}
}

func copy2(db protocol.Database, ready bool) protocol.SecondCopyStatus {
	return protocol.SecondCopyStatus{DatabaseID: db.ID, Ready: ready,
		RepoInfo: protocol.RepoInfo{Repo: protocol.RepoSecond, Provider: protocol.ProviderB2, Endpoint: "s3.eu-central-003.backblazeb2.com", Bucket: "shop-copy2"}}
}

func repoOf(t *testing.T, task *protocol.Task) int {
	t.Helper()
	var p protocol.BackupParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		t.Fatal(err)
	}
	return p.Repo
}

func TestSecondCopy(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now) // Wednesday 14:10, a full backup at 12:10 and the Mark before-drop at 13:10

	// None yet: how to add one, and what needs one is refused.
	ov, err := c.Storage(ctx, "shop")
	if err != nil || ov.SecondCopy != nil || ov.AddSecondCopy.Command != "sudo rowsafe secondcopy add shop" ||
		!strings.Contains(ov.AddSecondCopy.Why, "agent.env") {
		t.Fatalf("storage without a second copy: %+v %v", ov, err)
	}
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull, Repo: protocol.RepoSecond}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "secondcopy add") {
		t.Fatalf("backup to a second copy that isn't there: %v", err)
	}
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull, Repo: 3}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("repo 3: %v", err)
	}
	if _, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Mark: "before-drop", Repo: protocol.RepoSecond}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("restore from a second copy that isn't there: %v", err)
	}

	// The agent reports it, not set up yet: nothing is queued.
	setting := copy2(db, false)
	setting.LastError = "the second storage (bucket shop-copy2) can't be set up: InvalidAccessKeyId"
	copyReport(a, db, *now, setting)
	s.Tick()
	if sc := mustStorage(t, c).SecondCopy; sc == nil || sc.State != protocol.SecondCopySettingUp || sc.ProviderName != "Backblaze B2" {
		t.Fatalf("setting up: %+v", sc)
	}
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull, Repo: protocol.RepoSecond}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "InvalidAccessKeyId") {
		t.Fatalf("backup before it is set up: %v", err)
	}
	if a.claimOne("", protocol.TaskBackup) != nil {
		t.Fatal("a backup before the second copy is set up")
	}

	// Set up: its first full backup is queued, once.
	copyReport(a, db, *now, copy2(db, true))
	s.Tick()
	s.Tick()
	if sc := mustStorage(t, c).SecondCopy; sc.State != protocol.SecondCopyNoBackup {
		t.Fatalf("no backup yet: %+v", sc)
	}
	// The scheduled full backup to the first storage isn't held up by it.
	_ = s.st.update(func(st *state) error {
		if st.covered(db.ID, kindFull) {
			t.Error("the second copy's backup covers the first storage's")
		}
		return nil
	})
	backup := a.claimOne(protocol.TaskBackup)
	if repoOf(t, backup) != protocol.RepoSecond || a.claimOne("") != nil {
		t.Fatalf("first backup to the second copy: %s, another task queued", backup.Params)
	}
	started := *now
	*now = now.Add(20 * time.Minute) // 14:30
	a.done(backup, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-141000F", Type: protocol.BackupFull, Repo: protocol.RepoSecond,
		StartedAt: started, StoppedAt: *now, Kept: []string{"20261014-141000F"}})
	if bs, _ := c.Backups(ctx, "shop", 10); len(bs) != 1 {
		t.Fatalf("the first storage's backups: %+v", bs)
	}
	if bs, err := c.SecondCopyBackups(ctx, "shop", 10); err != nil || len(bs) != 1 || bs[0].Label != "20261014-141000F" {
		t.Fatalf("the second copy's backups: %+v %v", bs, err)
	}
	copyReport(a, db, *now, copy2(db, true))
	s.Tick()
	if a.claimOne("") != nil {
		t.Fatal("another backup to the second copy once it has one")
	}
	p, err := c.Protection(ctx, "shop")
	if err != nil || p.SecondCopy == nil || p.SecondCopy.State != protocol.SecondCopyOK || p.SecondCopy.LastFullAt == nil ||
		!strings.Contains(p.SecondCopy.Summary, "bucket shop-copy2") {
		t.Fatalf("status: %+v %v", p.SecondCopy, err)
	}

	// A Mark after it reaches the second copy once nothing waits to be sent.
	*now = now.Add(10 * time.Minute) // 14:40
	if _, err := c.CreateRestorePoint(ctx, "shop", "after-copy"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{Name: "after-copy", LSN: "0/5000000",
		Archived: true, CreatedAt: *now})
	*now = now.Add(time.Minute)
	behind := copy2(db, true)
	queued := now.Add(-5 * time.Minute)
	behind.QueuedFiles, behind.OldestQueued = 2, &queued
	copyReport(a, db, *now, behind)
	if _, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Mark: "after-copy", Repo: protocol.RepoSecond}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "hasn't reached the second copy") {
		t.Fatalf("a Mark not in the second copy yet: %v", err)
	}
	// The Mark before the second copy's first backup can't come from it.
	if _, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Mark: "before-drop", Repo: protocol.RepoSecond}); err == nil {
		t.Fatal("restored from the second copy to before its oldest backup")
	}
	copyReport(a, db, *now, copy2(db, true))
	resp, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Mark: "after-copy", Repo: protocol.RepoSecond})
	if err != nil || resp.Copy == nil || resp.Copy.Target.Repo != protocol.RepoSecond || resp.Copy.Target.BackupSet != "20261014-141000F" {
		t.Fatalf("restore from the second copy: %+v %v", resp, err)
	}
	var cp protocol.RewindCopyParams
	task := a.claimOne(protocol.TaskRewindCopy)
	if err := json.Unmarshal(task.Params, &cp); err != nil || cp.Target.Repo != protocol.RepoSecond || cp.Target.Mark != "after-copy" {
		t.Fatalf("copy task: %s", task.Params)
	}
	a.done(task, protocol.StatusFailed, nil)

	// Proof alternates: the next one restores from the second copy, the one
	// after from the first storage.
	*now = time.Date(2026, 10, 18, 21, 16, 0, 0, time.UTC) // Sunday evening
	copyReport(a, db, *now, copy2(db, true))
	s.Tick()
	var drill, full1, full2 *protocol.Task
	for task := claimAny(a); task != nil; task = claimAny(a) {
		switch {
		case task.Type == protocol.TaskDrill:
			drill = task
		case repoOf(t, task) == protocol.RepoSecond:
			full2 = task
		default:
			full1 = task
		}
		res := any(protocol.BackupResult{Label: "20261018-010000F", Type: protocol.BackupFull, StartedAt: *now, StoppedAt: *now})
		if task == full2 {
			res = protocol.BackupResult{Label: "20261018-033000F", Type: protocol.BackupFull, Repo: protocol.RepoSecond, StartedAt: *now, StoppedAt: *now}
		} else if task == drill {
			res = protocol.DrillResult{Passed: true, Repo: protocol.RepoSecond}
		}
		a.done(task, protocol.StatusSucceeded, res)
	}
	var dp protocol.DrillParams
	if drill == nil || json.Unmarshal(drill.Params, &dp) != nil || dp.Repo != protocol.RepoSecond || full1 == nil || full2 == nil {
		t.Fatalf("Sunday: drill %+v, full %v, full to the second copy %v", drill, full1 != nil, full2 != nil)
	}
	if sc := mustStorage(t, c).SecondCopy; sc.LastProofAt == nil || sc.LastProofPassed == nil || !*sc.LastProofPassed {
		t.Fatalf("the Proof from the second copy: %+v", sc)
	}
	*now = time.Date(2026, 10, 25, 21, 16, 0, 0, time.UTC)
	copyReport(a, db, *now, copy2(db, true))
	s.Tick()
	for task := claimAny(a); task != nil; task = claimAny(a) {
		if task.Type == protocol.TaskDrill && len(task.Params) > 0 && string(task.Params) != "null" {
			t.Fatalf("two Proofs in a row from the second copy: %s", task.Params)
		}
		a.done(task, protocol.StatusSucceeded, protocol.BackupResult{Type: protocol.BackupFull, StartedAt: *now, StoppedAt: *now})
	}

	// Failing for half an hour: second_copy_failing, after its 5 minutes.
	failing := copy2(db, true)
	since := now.Add(-40 * time.Minute)
	failing.FailingSince, failing.LastError = &since, "unable to connect to s3.eu-central-003.backblazeb2.com"
	copyReport(a, db, *now, failing)
	s.Tick()
	if alert(s, "second_copy_failing") != nil {
		t.Fatal("fired before its 5 minutes")
	}
	*now = now.Add(6 * time.Minute)
	copyReport(a, db, *now, failing)
	s.Tick()
	al := alert(s, "second_copy_failing")
	if al == nil || al.State != "firing" || !strings.Contains(al.Summary, "isn't getting backups") || !strings.Contains(al.NextStep, "sudo rowsafe secondcopy add shop") {
		t.Fatalf("second_copy_failing: %+v", al)
	}
	if sc := mustStorage(t, c).SecondCopy; sc.State != protocol.SecondCopyFailing {
		t.Fatalf("failing: %+v", sc)
	}
	copyReport(a, db, *now, copy2(db, true))
	s.Tick()
	if al := alert(s, "second_copy_failing"); al.State != "resolved" {
		t.Fatalf("not resolved: %+v", al)
	}
	if rules, _ := c.AlertRules(ctx); !strings.Contains(mustJSON(rules), "second_copy_failing") {
		t.Fatal("the rule isn't listed")
	}

	// The agent restarted: its first heartbeat has no second copy yet.
	copyReport(a, db, *now)
	s.Tick()
	if ov := mustStorage(t, c); ov.SecondCopy == nil {
		t.Fatal("forgot the second copy at the agent's first heartbeat")
	}
	copyReport(a, db, *now, copy2(db, true))
	*now = now.Add(5 * time.Minute)
	copyReport(a, db, *now)
	if bs, _ := c.SecondCopyBackups(ctx, "shop", 10); len(bs) == 0 {
		t.Fatal("forgot the second copy's backups after a restart")
	}

	// Removed (sudo rowsafe secondcopy remove): gone after two minutes.
	*now = now.Add(2 * time.Minute)
	copyReport(a, db, *now)
	s.Tick()
	if ov := mustStorage(t, c); ov.SecondCopy != nil {
		t.Fatalf("still there: %+v", ov.SecondCopy)
	}
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull, Repo: protocol.RepoSecond}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("backup to a removed second copy: %v", err)
	}
	if bs, _ := c.SecondCopyBackups(ctx, "shop", 10); len(bs) != 0 {
		t.Fatalf("its backups are still listed: %+v", bs)
	}
}

// claimAny claims whatever task is next (nil: none).
func claimAny(a *fakeAgent) *protocol.Task {
	var resp protocol.ClaimResponse
	a.call("POST", "/v1/agent/tasks/claim", protocol.ClaimRequest{}, &resp)
	return resp.Task
}

func mustStorage(t *testing.T, c interface {
	Storage(context.Context, string) (protocol.StorageOverview, error)
}) protocol.StorageOverview {
	t.Helper()
	ov, err := c.Storage(context.Background(), "shop")
	if err != nil {
		t.Fatal(err)
	}
	return ov
}

func alert(s *Server, rule string) *protocol.Alert {
	var out *protocol.Alert
	s.st.read(func(st *state) {
		for _, a := range st.Alerts {
			if a.Rule == rule {
				v := a.Alert
				out = &v
			}
		}
	})
	return out
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// A first backup to the second copy that failed is tried again an hour
// later, not every tick; one to another bucket starts over.
func TestSecondCopyRetryAndMove(t *testing.T) {
	s, a, c, now := setup(t)
	db := activeDB(t, a, c, now)
	copyReport(a, db, *now, copy2(db, true))
	s.Tick()
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusFailed, nil)
	*now = now.Add(30 * time.Minute)
	s.Tick()
	if a.claimOne("") != nil {
		t.Fatal("retried within the hour")
	}
	*now = now.Add(31 * time.Minute)
	s.Tick()
	task := a.claimOne(protocol.TaskBackup)
	if repoOf(t, task) != protocol.RepoSecond {
		t.Fatalf("the retry: %s", task.Params)
	}
	a.done(task, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-150000F", Type: protocol.BackupFull, Repo: protocol.RepoSecond, StartedAt: *now, StoppedAt: *now})
	if bs, _ := c.SecondCopyBackups(context.Background(), "shop", 10); len(bs) != 1 {
		t.Fatalf("backups: %+v", bs)
	}
	moved := copy2(db, true)
	moved.Bucket = "shop-copy3"
	copyReport(a, db, *now, moved)
	if bs, _ := c.SecondCopyBackups(context.Background(), "shop", 10); len(bs) != 0 {
		t.Fatalf("the old bucket's backups after a move: %+v", bs)
	}
}
