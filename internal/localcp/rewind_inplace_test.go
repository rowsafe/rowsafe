package localcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// The hosted control plane's table (internal/server/rewind_window_test.go
// there): which backup and timeline a restore to a point follows.
func TestRewindWindowTimelines(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	at := func(h float64) time.Time { return base.Add(time.Duration(h * float64(time.Hour))) }
	ptr := func(t time.Time) *time.Time { return &t }
	now := at(100)
	tls := map[string]int64{}
	bk := func(label, typ string, start float64, tl int64) protocol.Backup {
		tls[label] = tl
		return protocol.Backup{ID: label, DatabaseID: "db_1", Label: label, Type: typ, StartedAt: at(start), StoppedAt: at(start + 0.5)}
	}
	last := at(99.9)
	d := &dbRec{Database: protocol.Database{ID: "db_1", RetentionFull: 2, Archiver: &protocol.ArchiverStats{LastArchivedTime: &last}}}
	win := func(backups []protocol.Backup, rewinds ...*inPlaceRec) window {
		// The state keeps backups oldest first.
		s := &state{Timelines: tls, Rewinds: rewinds}
		for i := len(backups) - 1; i >= 0; i-- {
			s.Backups = append(s.Backups, backups[i])
		}
		return s.windowOf(d, now)
	}

	if _, _, err := win(nil).pick(at(50)); err == nil {
		t.Fatal("pick without backups")
	}
	// Newest first: three fulls (retention keeps two), a diff after the newest.
	w := win([]protocol.Backup{bk("D3", "diff", 60, 1), bk("F3", "full", 48, 1), bk("F2", "full", 24, 1), bk("F1", "full", 0, 1)})
	if !w.Earliest.Equal(at(24.5)) || !w.Latest.Equal(at(99.9)) {
		t.Fatalf("window %v to %v", w.Earliest, w.Latest)
	}
	for _, c := range []struct {
		p       float64
		set, tl string
		bad     bool
	}{
		{p: 10, bad: true}, {p: 99.95, bad: true},
		{p: 30, set: "F2"}, {p: 48.4, set: "F2"}, {p: 48.6, set: "F3"}, {p: 50, set: "F3"}, {p: 70, set: "D3"},
	} {
		set, tl, err := w.pick(at(c.p))
		switch {
		case c.bad && err == nil:
			t.Errorf("pick(%v) = %s, want a refusal", c.p, set)
		case !c.bad && (err != nil || set != c.set || tl != c.tl):
			t.Errorf("pick(%v) = %s %q %v, want %s %q", c.p, set, tl, err, c.set, c.tl)
		}
	}
	var he *httpErr
	if _, _, err := w.pick(at(10)); !errors.As(err, &he) || he.status != http.StatusBadRequest {
		t.Errorf("before the window: %v", err)
	}

	// A rewind in place at 80 back to 55 (timeline 2 leaves timeline 1 at
	// 55), a full backup right after (F4, timeline 2), then an undo at 90
	// (timeline 3 continues timeline 1's data) and its full backup (F5).
	d.RetentionFull = 4
	rewound := []protocol.Backup{bk("F5", "full", 91, 3), bk("F4", "full", 81, 2), bk("I1", "incr", 70, 1), bk("D3", "diff", 60, 1),
		bk("F3", "full", 48, 1), bk("F2", "full", 24, 1)}
	undone := &inPlaceRec{ID: "rwd_1", DatabaseID: "db_1", RewoundAt: ptr(at(80)), RecoveredTo: ptr(at(55)), UndoneAt: ptr(at(90))}
	w = win(rewound, undone)
	for _, c := range []struct {
		name    string
		p       float64
		set, tl string
	}{
		{"before the branch, rewind later: follow the backup's own timeline", 50, "F3", "current"},
		{"after the branch on the old timeline (rewound away, undone later)", 72, "I1", "current"},
		{"inside the undone rewind, after its backup", 85, "F4", "current"},
		{"inside the undone rewind, before its backup finished: an old backup from before the branch, then timeline 2", 81.2, "F3", "2"},
		{"after the undo, before its backup: the old timeline's backups", 90.5, "I1", ""},
		{"after the undo and its backup", 95, "F5", ""},
	} {
		if set, tl, err := w.pick(at(c.p)); err != nil || set != c.set || tl != c.tl {
			t.Errorf("%s: pick(%v) = %s %q %v, want %s %q", c.name, c.p, set, tl, err, c.set, c.tl)
		}
	}

	// Not undone: after the rewind, the new timeline (the default) holds
	// everything; the old timeline's backups after the branch can't reach it.
	w = win(rewound[1:], &inPlaceRec{ID: "rwd_1", DatabaseID: "db_1", RewoundAt: ptr(at(80)), RecoveredTo: ptr(at(55))})
	for _, c := range []struct {
		p       float64
		set, tl string
	}{
		{50, "F3", "current"}, {72, "I1", "current"}, {80.2, "F3", ""}, {85, "F4", ""},
	} {
		if set, tl, err := w.pick(at(c.p)); err != nil || set != c.set || tl != c.tl {
			t.Errorf("not undone: pick(%v) = %s %q %v, want %s %q", c.p, set, tl, err, c.set, c.tl)
		}
	}

	// Inside an undone rewind whose own backup never happened: no telling
	// which timeline, so refused.
	w = win([]protocol.Backup{bk("F5", "full", 91, 3), bk("F3", "full", 48, 1), bk("F2", "full", 24, 1)}, undone)
	if _, _, err := w.pick(at(85)); !errors.As(err, &he) || he.status != http.StatusConflict {
		t.Errorf("an unknown timeline: %v", err)
	}
}

func TestTimelineOf(t *testing.T) {
	for wal, want := range map[string]int64{"000000010000000000000003": 1, "0000000A0000000100000003": 10, "": 0, "nope": 0, "zz0000010000000000000003": 0} {
		if got := timelineOf(wal); got != want {
			t.Errorf("timelineOf(%q) = %d, want %d", wal, got, want)
		}
	}
}

// allowStop is a heartbeat from an agent whose root helper may stop and
// start PostgreSQL on 5432, reporting kept data.
func allowStop(a *fakeAgent, kept ...protocol.RewindState) {
	archived(a, protocol.ArchiverStats{}, kept...)
}

// archived is that heartbeat with an archiving report.
func archived(a *fakeAgent, arch protocol.ArchiverStats, kept ...protocol.RewindState) {
	req := protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.18", RestartPorts: []int{5432}, Rewinds: kept}
	if arch.DatabaseID != "" {
		req.Archivers = []protocol.ArchiverStats{arch}
	}
	a.call("POST", "/v1/agent/heartbeat", req, nil)
}

// TestRewindInPlace rewinds shop in place, writes more (a full backup on
// the new timeline), restores copies before and after the rewind, undoes
// it and deletes the kept data: every restore follows the right timeline.
func TestRewindInPlace(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now) // F1 12:00-12:10, the Mark before-drop at 13:10; now 14:10
	markAt := now.Add(-time.Hour)
	_ = s.st.update(func(st *state) error { st.db("shop").RetentionFull = 4; return nil }) // F1 stays in the window

	// The first full backup with its timeline, as the agent reports it.
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); err != nil {
		t.Fatal(err)
	}
	started := *now
	*now = now.Add(10 * time.Minute) // 14:20
	a.done(a.claimOne(protocol.TaskBackup), protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-141000F", Type: protocol.BackupFull,
		StartedAt: started, StoppedAt: *now, WALStart: "000000010000000000000005"})

	info, err := c.RewindInfo(ctx, "shop")
	if err != nil || info.CanRewindInPlace {
		t.Fatalf("before root allows stopping PostgreSQL: %+v %v", info, err)
	}
	allowStop(a)
	if info, err = c.RewindInfo(ctx, "shop"); err != nil || !info.CanRewindInPlace || info.InPlaceReason != "" {
		t.Fatalf("rewind info: %+v %v", info, err)
	}

	// A typed confirmation, then a Mark first; one at a time.
	req := protocol.RewindInPlaceRequest{Mark: "before-drop"}
	if _, err := c.RewindInPlace(ctx, "shop", req); apiStatus(err) != http.StatusBadRequest || !strings.Contains(err.Error(), `"confirm": "shop"`) ||
		!strings.Contains(err.Error(), "after the Mark before-drop") {
		t.Fatalf("without confirming: %v", err)
	}
	req.Confirm = "shop"
	resp, err := c.RewindInPlace(ctx, "shop", req)
	if err != nil || len(resp.Tasks) != 2 || resp.Tasks[0].Type != protocol.TaskRestorePoint || resp.Tasks[1].Type != protocol.TaskRewindInPlace {
		t.Fatalf("rewind: %+v %v", resp, err)
	}
	if _, err := c.RewindInPlace(ctx, "shop", req); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second rewind: %v", err)
	}
	a.claimOne("", protocol.TaskRewindInPlace) // waits for the Mark
	a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{LSN: "0/6000000", CreatedAt: *now})
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskDrill, nil); err != nil { // a Proof queued meanwhile
		t.Fatal(err)
	}
	task := a.claimOne(protocol.TaskRewindInPlace)
	var p protocol.RewindInPlaceParams
	if err := json.Unmarshal(task.Params, &p); err != nil || p.KeepDays != 7 || p.Target.Mark != "before-drop" ||
		p.Target.BackupSet != "20261014-120000F" || p.Target.Timeline != "" {
		t.Fatalf("rewind params: %+v %v", p, err)
	}
	*now = now.Add(5 * time.Minute) // 14:25
	rewoundAt, keptUntil := *now, now.Add(7*24*time.Hour)
	a.done(task, protocol.StatusSucceeded, protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: &markAt, KeptUntil: &keptUntil,
		Summary: "Rewound shop."})

	// A full backup starts the new timeline; the Proof waits for it, then
	// a check.
	backup := a.claimOne(protocol.TaskBackup)
	var bp protocol.BackupParams
	if json.Unmarshal(backup.Params, &bp); bp.Type != protocol.BackupFull {
		t.Fatalf("after the rewind: %+v", bp)
	}
	*now = now.Add(10 * time.Minute) // 14:35
	a.done(backup, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-142500F", Type: protocol.BackupFull,
		StartedAt: rewoundAt, StoppedAt: *now, WALStart: "000000020000000000000007"})
	a.done(a.claimOne(protocol.TaskDrill), protocol.StatusSucceeded, protocol.DrillResult{Passed: true})
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})

	// The kept data, as the agent reports it.
	kept := protocol.RewindState{ID: p.RewindID, DatabaseID: db.ID, Kind: protocol.RewindKindKeptData, Status: protocol.RewindKeptBefore,
		SizeBytes: 3 << 20, Expires: &keptUntil}
	*now = now.Add(20 * time.Minute) // 14:55: more writes, archived
	last := *now
	archived(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last}, kept)
	info, _ = c.RewindInfo(ctx, "shop")
	if len(info.Kept) != 1 || info.Kept[0].Status != protocol.RewindKeptBefore || info.Kept[0].SizeBytes != 3<<20 ||
		info.CanRewindInPlace || info.InPlaceReason != errRewindKept {
		t.Fatalf("kept data: %+v", info)
	}
	if _, err := c.RewindInPlace(ctx, "shop", protocol.RewindInPlaceRequest{Mark: "before-drop", Confirm: "shop"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "rowsafe rewind undo") {
		t.Fatalf("rewinding again while data is kept: %v", err)
	}

	// Copies: before the rewind, on the old timeline; after it, on the new one.
	copyAt := func(at *time.Time, mark string) protocol.RewindTarget {
		t.Helper()
		resp, err := c.CreateRewindCopy(ctx, "shop", protocol.CreateRewindCopyRequest{Time: at, Mark: mark})
		if err != nil {
			t.Fatalf("copy at %v %s: %v", at, mark, err)
		}
		a.done(a.claimOne(protocol.TaskRewindCopy), protocol.StatusSucceeded, protocol.RewindCopyResult{CopyID: resp.Copy.ID})
		if _, err := c.DeleteRewindCopy(ctx, "shop", resp.Copy.ID); err != nil {
			t.Fatal(err)
		}
		a.done(a.claimOne(protocol.TaskRewindDrop), protocol.StatusSucceeded, protocol.RewindDropResult{CopyID: resp.Copy.ID, Removed: true})
		return resp.Copy.Target
	}
	if tg := copyAt(nil, "before-drop"); tg.BackupSet != "20261014-120000F" || tg.Timeline != "current" {
		t.Fatalf("a copy at the Mark, from before the rewind: %+v", tg)
	}
	oldTimeline := rewoundAt.Add(-2 * time.Minute) // 14:23, rewound away
	if tg := copyAt(&oldTimeline, ""); tg.BackupSet != "20261014-141000F" || tg.Timeline != "current" {
		t.Fatalf("a copy just before the rewind: %+v", tg)
	}
	afterBackup := now.Add(-5 * time.Minute) // 14:50, written since
	if tg := copyAt(&afterBackup, ""); tg.BackupSet != "20261014-142500F" || tg.Timeline != "" {
		t.Fatalf("a copy after the rewind: %+v", tg)
	}
	beforeBackup := rewoundAt.Add(time.Minute) // 14:26: the new full backup hadn't finished
	if tg := copyAt(&beforeBackup, ""); tg.BackupSet != "20261014-120000F" || tg.Timeline != "" {
		t.Fatalf("a copy after the rewind, before its backup: %+v", tg)
	}

	// The state (rewinds, timelines) survives the agent restarting.
	s2, err := Open(filepath.Dir(s.st.path), nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.st.read(func(st *state) {
		if len(st.Rewinds) != 1 || st.Rewinds[0].RewoundAt == nil || st.Timelines[st.Backups[len(st.Backups)-1].ID] != 2 {
			t.Errorf("state after reopening: %+v %+v", st.Rewinds, st.Timelines)
		}
	})

	// Undo: confirmed, one at a time; it starts another timeline.
	if _, err := c.UndoRewind(ctx, "shop", p.RewindID, ""); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("undo without confirming: %v", err)
	}
	if _, err := c.UndoRewind(ctx, "shop", "rwd_nope", "shop"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("undo an unknown rewind: %v", err)
	}
	undo, err := c.UndoRewind(ctx, "shop", p.RewindID, "shop")
	if err != nil || len(undo.Tasks) != 1 || undo.Tasks[0].Type != protocol.TaskRewindUndo {
		t.Fatalf("undo: %+v %v", undo, err)
	}
	if _, err := c.UndoRewind(ctx, "shop", p.RewindID, "shop"); apiStatus(err) != http.StatusConflict {
		t.Fatalf("undo twice: %v", err)
	}
	if _, err := c.CleanupRewind(ctx, "shop", p.RewindID); apiStatus(err) != http.StatusConflict {
		t.Fatalf("cleanup during the undo: %v", err)
	}
	*now = now.Add(5 * time.Minute) // 15:00
	allowStop(a)                    // the kept data isn't reported while the undo runs: still kept
	undoneAt := *now
	a.done(a.claimOne(protocol.TaskRewindUndo), protocol.StatusSucceeded, protocol.RewindUndoResult{RewindID: p.RewindID, KeptUntil: &keptUntil})
	backup = a.claimOne(protocol.TaskBackup)
	*now = now.Add(10 * time.Minute) // 15:10
	a.done(backup, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-150000F", Type: protocol.BackupFull,
		StartedAt: undoneAt, StoppedAt: *now, WALStart: "000000030000000000000009"})
	a.done(a.claimOne(protocol.TaskCheck), protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	kept.Status = protocol.RewindKeptAfterUndo
	allowStop(a, kept)
	info, _ = c.RewindInfo(ctx, "shop")
	if len(info.Kept) != 1 || info.Kept[0].Status != protocol.RewindKeptAfterUndo {
		t.Fatalf("after the undo: %+v", info.Kept)
	}
	if _, err := c.UndoRewind(ctx, "shop", p.RewindID, "shop"); apiStatus(err) != http.StatusConflict {
		t.Fatalf("undo after the undo: %v", err)
	}
	last = *now
	archived(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last}, kept)
	// Inside the undone rewind, after its backup: that backup's timeline.
	if tg := copyAt(&afterBackup, ""); tg.BackupSet != "20261014-142500F" || tg.Timeline != "current" {
		t.Fatalf("a copy inside the undone rewind: %+v", tg)
	}
	// After the undo, before its backup: the old timeline's backup, then
	// the newest timeline.
	afterUndo := undoneAt.Add(time.Minute)
	if tg := copyAt(&afterUndo, ""); tg.BackupSet != "20261014-141000F" || tg.Timeline != "" {
		t.Fatalf("a copy after the undo: %+v", tg)
	}

	// Cleanup: the kept data goes; rewinding in place is possible again.
	clean, err := c.CleanupRewind(ctx, "shop", p.RewindID)
	if err != nil || len(clean.Tasks) != 1 || clean.Tasks[0].Type != protocol.TaskRewindCleanup {
		t.Fatalf("cleanup: %+v %v", clean, err)
	}
	if _, err := c.CleanupRewind(ctx, "shop", p.RewindID); apiStatus(err) != http.StatusConflict {
		t.Fatalf("cleanup twice: %v", err)
	}
	a.done(a.claimOne(protocol.TaskRewindCleanup), protocol.StatusSucceeded, protocol.RewindCleanupResult{RewindID: p.RewindID, Removed: true})
	allowStop(a)
	info, _ = c.RewindInfo(ctx, "shop")
	if len(info.Kept) != 0 || !info.CanRewindInPlace || len(info.Tasks) < 3 {
		t.Fatalf("after the cleanup: %+v", info)
	}
	// The rewind still says which timeline a point before the undo is on.
	if tg := copyAt(&afterBackup, ""); tg.Timeline != "current" {
		t.Fatalf("a copy inside the undone rewind, after the cleanup: %+v", tg)
	}
}

// A rewind that failed (the original data was put back) keeps nothing and
// changes no timeline; kept data the agent stops reporting (deleted after
// 7 days) is gone.
func TestRewindInPlaceFailedAndExpired(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)
	allowStop(a)
	run := func() string {
		t.Helper()
		resp, err := c.RewindInPlace(ctx, "shop", protocol.RewindInPlaceRequest{Mark: "before-drop", Confirm: "shop"})
		if err != nil {
			t.Fatal(err)
		}
		a.done(a.claimOne(protocol.TaskRestorePoint), protocol.StatusSucceeded, protocol.RestorePointResult{LSN: "0/7000000", CreatedAt: *now})
		return resp.Tasks[1].ID
	}

	run()
	task := a.claimOne(protocol.TaskRewindInPlace)
	if code := a.call("POST", "/v1/agent/tasks/"+task.ID+"/complete", protocol.CompleteRequest{Status: protocol.StatusFailed,
		Error: "restore failed; the original data is back"}, nil); code != http.StatusNoContent {
		t.Fatal(code)
	}
	info, _ := c.RewindInfo(ctx, "shop")
	if len(info.Kept) != 0 || !info.CanRewindInPlace {
		t.Fatalf("after a failed rewind: %+v", info)
	}
	a.claimOne("") // no full backup after a failed rewind

	*now = now.Add(time.Second) // another Mark name
	run()
	task = a.claimOne(protocol.TaskRewindInPlace)
	var p protocol.RewindInPlaceParams
	_ = json.Unmarshal(task.Params, &p)
	a.done(task, protocol.StatusSucceeded, protocol.RewindInPlaceResult{RewindID: p.RewindID})
	kept := protocol.RewindState{ID: p.RewindID, DatabaseID: db.ID, Kind: protocol.RewindKindKeptData, Status: protocol.RewindKeptBefore}
	allowStop(a, kept)
	if info, _ = c.RewindInfo(ctx, "shop"); len(info.Kept) != 1 {
		t.Fatalf("kept: %+v", info.Kept)
	}
	*now = now.Add(time.Minute)
	allowStop(a) // a heartbeat built before the task finished
	if info, _ = c.RewindInfo(ctx, "shop"); len(info.Kept) != 1 {
		t.Fatalf("gone too soon: %+v", info.Kept)
	}
	*now = now.Add(8 * 24 * time.Hour)
	allowStop(a)
	if info, _ = c.RewindInfo(ctx, "shop"); len(info.Kept) != 0 {
		t.Fatalf("expired kept data: %+v", info.Kept)
	}
	if _, err := c.UndoRewind(ctx, "shop", p.RewindID, "shop"); apiStatus(err) != http.StatusConflict {
		t.Fatalf("undo after the kept data expired: %v", err)
	}
}
