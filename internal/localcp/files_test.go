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

// filesSync posts a files report as the agent does and returns the answer.
func filesSync(t *testing.T, a *fakeAgent, rep protocol.FilesReport) protocol.FilesSync {
	t.Helper()
	var out protocol.FilesSync
	if code := a.call("POST", "/v1/agent/files", rep, &out); code != http.StatusOK {
		t.Fatalf("files report: %d", code)
	}
	return out
}

func TestFilesWithADatabase(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	db := activeDB(t, a, c, now)

	// Nothing protected: the agent gets no folders (and keeps none).
	if sync := filesSync(t, a, protocol.FilesReport{Engine: "0.18.0", Mode: "native"}); len(sync.Databases) != 0 || sync.Host != nil || sync.IntervalSeconds != filesSyncSeconds {
		t.Fatalf("empty sync: %+v", sync)
	}
	for _, bad := range []string{"uploads", "/etc/app", "/var/lib/postgresql/17", "/srv", "/home/a/../b", "/var/lib/docker/volumes"} {
		if _, err := c.AddFilesFolder(ctx, "shop", protocol.AddFilesFolderRequest{Path: bad}); apiStatus(err) != http.StatusBadRequest {
			t.Errorf("%s: %v", bad, err)
		}
	}
	f, err := c.AddFilesFolder(ctx, "shop", protocol.AddFilesFolderRequest{Path: "/var/www/uploads/", Excludes: []string{"cache", "cache"}})
	if err != nil || f.Path != "/var/www/uploads" || len(f.Excludes) != 1 || f.State.Status != protocol.FilesPending {
		t.Fatalf("add: %+v %v", f, err)
	}
	for _, overlap := range []string{"/var/www/uploads", "/var/www/uploads/cvs", "/var/www"} {
		if _, err := c.AddFilesFolder(ctx, "shop", protocol.AddFilesFolderRequest{Path: overlap}); apiStatus(err) != http.StatusConflict {
			t.Errorf("%s: %v", overlap, err)
		}
	}
	// The installer's --files (sudo rowsafe-allow --files) adds through the agent.
	var vol protocol.FilesFolderView
	if code := a.call("POST", "/v1/agent/setup/databases/"+db.ID+"/files/folders",
		protocol.AddFilesFolderRequest{Path: "/var/lib/docker/volumes/media/_data"}, &vol); code != http.StatusCreated {
		t.Fatalf("installer add: %d", code)
	}
	var listed struct{ Folders []protocol.FilesFolderView }
	a.call("GET", "/v1/agent/setup/databases/"+db.ID+"/files/folders", nil, &listed)
	if len(listed.Folders) != 2 {
		t.Fatalf("installer list: %+v", listed)
	}

	// The agent gets both folders, in shop's repository, kept as long as
	// its backups (2 weekly fulls).
	sync := filesSync(t, a, protocol.FilesReport{Engine: "0.18.0", Mode: "native"})
	if len(sync.Databases) != 1 || sync.Databases[0].Stanza != "shop" || len(sync.Databases[0].Folders) != 2 ||
		sync.Databases[0].RetentionDays != 14 || !sync.Databases[0].ListNames || sync.Databases[0].IntervalMinutes != 15 {
		t.Fatalf("sync: %+v", sync)
	}

	// Its report: a snapshot of each.
	snapAt := now.Add(-5 * time.Minute)
	snap := protocol.FilesSnapshot{ID: "aaaaaaaa", Time: snapAt, Files: 3, SizeBytes: 300}
	filesSync(t, a, protocol.FilesReport{Engine: "0.18.0", Mode: "native", Databases: []protocol.FilesDatabaseState{{DatabaseID: db.ID,
		Folders: []protocol.FilesFolderState{
			{ID: f.ID, Path: f.Path, Status: protocol.FilesOK, LastSnapshot: &snap, Snapshots: 1, Recent: []protocol.FilesSnapshot{snap}},
			{ID: vol.ID, Path: vol.Path, Status: protocol.FilesUnreadable, Problem: "Rowsafe can't read it"},
		}}}})
	info, err := c.FilesInfo(ctx, "shop")
	if err != nil || len(info.Folders) != 2 || info.Folders[0].State.LastSnapshot == nil || info.Folders[0].State.LastSnapshot.FolderID != f.ID ||
		info.Folders[1].State.Status != protocol.FilesUnreadable || info.Settings.RetentionDays != 14 || info.Host.Engine != "0.18.0" || info.Host.CanPutBack {
		t.Fatalf("info: %+v %v", info, err)
	}
	if !strings.Contains(info.Host.Reason, "--into") {
		t.Errorf("reason: %q", info.Host.Reason)
	}
	if n, err := c.FilesNearest(ctx, "shop", *now); err != nil || n.Folders[0].Snapshot == nil || n.Folders[0].GapSeconds != 300 || n.Folders[1].Snapshot != nil {
		t.Fatalf("nearest: %+v %v", n, err)
	}

	// Back up now: on the files lane, once at a time.
	if _, err := c.FilesBackup(ctx, "shop", protocol.FilesBackupParams{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.FilesBackup(ctx, "shop", protocol.FilesBackupParams{}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("twice: %v", err)
	}
	bt := a.claimOne(protocol.TaskFilesBackup, protocol.FilesTaskTypes...)
	if bt.Database == nil || bt.Database.Stanza != "shop" {
		t.Fatalf("backup task: %+v", bt)
	}
	snap2 := protocol.FilesSnapshot{ID: "bbbbbbbb", FolderID: f.ID, Time: *now, Files: 4}
	a.done(bt, protocol.StatusSucceeded, protocol.FilesBackupResult{Snapshots: []protocol.FilesSnapshot{snap2}})
	info, _ = c.FilesInfo(ctx, "shop")
	if s := info.Folders[0].State; s.LastSnapshot == nil || s.LastSnapshot.ID != "bbbbbbbb" || len(s.Recent) != 2 || s.Recent[0].ID != "bbbbbbbb" {
		t.Fatalf("after the backup: %+v", s)
	}

	// Restoring in place needs the name, then a Mark comes first.
	at := *now
	req := protocol.FilesRestoreRequest{Time: &at, FolderIDs: []string{f.ID}}
	if _, err := c.FilesRestore(ctx, "shop", req); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("no confirmation: %v", err)
	}
	future := now.Add(time.Hour)
	if _, err := c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{Time: &future, Confirm: "shop"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("the future: %v", err)
	}
	req.Confirm = "shop"
	resp, err := c.FilesRestore(ctx, "shop", req)
	if err != nil || len(resp.Tasks) != 2 || resp.Tasks[0].Type != protocol.TaskRestorePoint || resp.Tasks[1].Type != protocol.TaskFilesRestore {
		t.Fatalf("restore: %+v %v", resp, err)
	}
	a.claimOne("", protocol.FilesTaskTypes...) // waits for the Mark
	mark := a.claimOne(protocol.TaskRestorePoint)
	a.done(mark, protocol.StatusSucceeded, protocol.RestorePointResult{Name: "x", LSN: "0/5000000", Archived: true, CreatedAt: *now})
	rt := a.claimOne(protocol.TaskFilesRestore, protocol.FilesTaskTypes...)
	var p protocol.FilesRestoreParams
	_ = json.Unmarshal(rt.Params, &p)
	if p.Mode != protocol.FilesRestoreMissing || p.Target.Time == nil || p.RestoreID == "" || p.Into != "" {
		t.Fatalf("restore params: %+v", p)
	}
	a.done(rt, protocol.StatusSucceeded, protocol.FilesRestoreResult{RestoreID: p.RestoreID, Summary: "Brought back 1 file."})
	if marks, _ := c.RestorePoints(ctx, "shop"); !strings.HasPrefix(marks[0].Name, filesMarkNamePrefix) {
		t.Fatalf("marks: %+v", marks)
	}

	// Into another folder: nothing live changes, so no name and no Mark;
	// one folder, apart from the protected ones.
	if _, err := c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{Time: &at, Into: "/srv/restored"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("two folders into one: %v", err)
	}
	if _, err := c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{Time: &at, FolderIDs: []string{f.ID}, Into: "/var/www/uploads/old"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("into the folder itself: %v", err)
	}
	if _, err := c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{SnapshotID: "aaaaaaaa", Mode: protocol.FilesRestoreFolder, Into: "/srv/restored"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a whole-folder restore into: %v", err)
	}
	resp, err = c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{SnapshotID: "aaaaaaaa", Into: "/srv/restored"})
	if err != nil || len(resp.Tasks) != 1 {
		t.Fatalf("into: %+v %v", resp, err)
	}
	rt = a.claimOne(protocol.TaskFilesRestore, protocol.FilesTaskTypes...)
	p = protocol.FilesRestoreParams{}
	_ = json.Unmarshal(rt.Params, &p)
	if p.Into != "/srv/restored" || p.Target.SnapshotID != "aaaaaaaa" || len(p.FolderIDs) != 1 || p.FolderIDs[0] != f.ID {
		t.Fatalf("into params: %+v", p)
	}
	a.done(rt, protocol.StatusSucceeded, protocol.FilesRestoreResult{RestoreID: p.RestoreID})

	// To a Mark: its time goes along.
	resp, err = c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{Mark: "before-drop", Confirm: "shop", Preview: true})
	if err != nil || len(resp.Tasks) != 1 {
		t.Fatalf("preview to a Mark: %+v %v", resp, err)
	}
	if _, err := c.FilesRestore(ctx, "shop", protocol.FilesRestoreRequest{Mark: "nope", Preview: true}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("an unknown Mark: %v", err)
	}

	// Settings: the interval; retention follows the backups.
	iv := 30
	if info, err := c.UpdateFilesSettings(ctx, "shop", protocol.UpdateFilesSettingsRequest{IntervalMinutes: &iv}); err != nil || info.Settings.IntervalMinutes != 30 {
		t.Fatalf("settings: %+v %v", info, err)
	}
	days := 60
	if _, err := c.UpdateFilesSettings(ctx, "shop", protocol.UpdateFilesSettingsRequest{RetentionDays: &days}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("retention of a database's files: %v", err)
	}

	// Removing a folder: the agent stops snapshotting it.
	if err := c.RemoveFilesFolder(ctx, "shop", vol.ID); err != nil {
		t.Fatal(err)
	}
	if sync := filesSync(t, a, protocol.FilesReport{}); len(sync.Databases[0].Folders) != 1 || sync.Databases[0].IntervalMinutes != 30 {
		t.Fatalf("sync after remove: %+v", sync)
	}
}

func TestFilesOfTheServer(t *testing.T) {
	_, a, c, now := setup(t)
	ctx := context.Background()
	heartbeat(a)

	// No database on this server: a folder and a Docker volume of its own.
	if _, err := c.HostAddFilesFolder(ctx, "other", protocol.AddFilesFolderRequest{Path: "/srv/app"}); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("another server: %v", err)
	}
	f, err := c.HostAddFilesFolder(ctx, "db1", protocol.AddFilesFolderRequest{Path: "/srv/app/storage"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.HostAddFilesFolder(ctx, "db1", protocol.AddFilesFolderRequest{Path: "/var/lib/docker/volumes/app_data/_data"}); err != nil {
		t.Fatal(err)
	}
	info, err := c.HostFilesInfo(ctx, "db1")
	if err != nil || info.HostID == "" || info.DatabaseID != "" || len(info.Folders) != 2 || info.Settings.RetentionDays != protocol.FilesHostDefaultRetentionDays {
		t.Fatalf("info: %+v %v", info, err)
	}
	sync := filesSync(t, a, protocol.FilesReport{Engine: "0.18.0"})
	if h := sync.Host; h == nil || h.HostID != info.HostID || h.Stanza != protocol.FilesHostStanza(info.HostID) || h.DatabaseID != "" ||
		len(h.Folders) != 2 || h.RetentionDays != 30 || h.Name != "db1" {
		t.Fatalf("host sync: %+v", sync.Host)
	}
	snap := protocol.FilesSnapshot{ID: "cccccccc", Time: now.Add(-time.Minute)}
	filesSync(t, a, protocol.FilesReport{Host: &protocol.FilesDatabaseState{HostID: info.HostID,
		Folders: []protocol.FilesFolderState{{ID: f.ID, Path: f.Path, Status: protocol.FilesOK, LastSnapshot: &snap, Snapshots: 1}}}})
	if info, _ = c.HostFilesInfo(ctx, "db1"); info.Folders[0].State.LastSnapshot == nil {
		t.Fatalf("host report not kept: %+v", info.Folders[0])
	}

	// Its tasks have no database.
	if _, err := c.HostFilesBackup(ctx, info.HostID, protocol.FilesBackupParams{}); err != nil {
		t.Fatal(err)
	}
	if bt := a.claimOne(protocol.TaskFilesBackup, protocol.FilesTaskTypes...); bt.Database != nil {
		t.Fatalf("a server's task with a database: %+v", bt.Database)
	}
	if _, err := c.HostFilesRestore(ctx, "db1", protocol.FilesRestoreRequest{Mark: "x", Confirm: "db1"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a Mark for a server's folders: %v", err)
	}
	if _, err := c.HostFilesRestore(ctx, "db1", protocol.FilesRestoreRequest{Confirm: "shop"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("confirmed with another name: %v", err)
	}
	resp, err := c.HostFilesRestore(ctx, "db1", protocol.FilesRestoreRequest{Mode: protocol.FilesRestoreFolder, Confirm: "db1"})
	if err != nil || len(resp.Tasks) != 1 || resp.Tasks[0].DatabaseID != "" {
		t.Fatalf("restore: %+v %v", resp, err)
	}
	days := 90
	if info, err := c.UpdateHostFilesSettings(ctx, "db1", protocol.UpdateFilesSettingsRequest{RetentionDays: &days}); err != nil || info.Settings.RetentionDays != 90 {
		t.Fatalf("retention: %+v %v", info, err)
	}
	// A folder of the server can't also go with a database.
	db := activeDB(t, a, c, now)
	if _, err := c.AddFilesFolder(ctx, "shop", protocol.AddFilesFolderRequest{Path: "/srv/app/storage"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "the server itself") {
		t.Fatalf("the same folder with a database: %v", err)
	}
	_ = db
}

func TestFilesAlerts(t *testing.T) {
	s, a, c, now := setup(t)
	s.allowHTTP = true
	ctx := context.Background()
	heartbeat(a)
	url, got := receiver(t)
	addChannel(t, c, protocol.ChannelSlack, url)
	f, err := c.HostAddFilesFolder(ctx, "db1", protocol.AddFilesFolderRequest{Path: "/srv/app/storage"})
	if err != nil {
		t.Fatal(err)
	}
	report := func(state protocol.FilesFolderState, check *protocol.FilesCheckResult) {
		state.ID, state.Path = f.ID, f.Path
		filesSync(t, a, protocol.FilesReport{Host: &protocol.FilesDatabaseState{Folders: []protocol.FilesFolderState{state}, LastCheck: check}})
	}
	s.Tick()
	none(t, got)

	// No snapshot for over 2 hours (the folder can't be read): after 15 minutes.
	*now = now.Add(2*time.Hour + time.Minute)
	report(protocol.FilesFolderState{Status: protocol.FilesUnreadable, Problem: "Rowsafe can't read /srv/app/storage."}, nil)
	s.Tick()
	none(t, got)
	*now = now.Add(16 * time.Minute)
	s.Tick()
	r := next(t, got)
	if !strings.Contains(r.body, "Files of db1 aren't being backed up") || !strings.Contains(r.body, "can't read") ||
		!strings.Contains(r.body, "sudo rowsafe files backup --server") {
		t.Fatalf("stale: %s", r.body)
	}
	if firing, _ := c.Alerts(ctx, "firing", 10); len(firing) != 1 || firing[0].Database != nil || firing[0].Rule != "files_backup_stale" {
		t.Fatalf("firing: %+v", firing)
	}
	// A snapshot: resolved.
	snap := protocol.FilesSnapshot{ID: "dddddddd", Time: *now}
	report(protocol.FilesFolderState{Status: protocol.FilesOK, LastSnapshot: &snap}, nil)
	s.Tick()
	if r := next(t, got); !strings.Contains(r.body, "[RESOLVED]") {
		t.Fatalf("resolved: %s", r.body)
	}
	// A failed files Proof fires at once.
	report(protocol.FilesFolderState{Status: protocol.FilesOK, LastSnapshot: &snap},
		&protocol.FilesCheckResult{At: *now, Passed: false, Summary: "2 of 5 files differ from the snapshot."})
	s.Tick()
	if r := next(t, got); !strings.Contains(r.body, "Files Proof failed for db1") || !strings.Contains(r.body, "2 of 5 files differ") {
		t.Fatalf("proof: %s", r.body)
	}
	rules, _ := c.AlertRules(ctx)
	names := ""
	for _, r := range rules {
		names += r.Rule + " "
	}
	if !strings.Contains(names, "files_backup_stale") || !strings.Contains(names, "files_proof_failed") {
		t.Fatalf("rules: %s", names)
	}
}
