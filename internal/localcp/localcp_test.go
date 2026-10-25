package localcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeAgent drives the agent API over HTTP as rowsafe-agent does.
type fakeAgent struct {
	t     *testing.T
	url   string
	token string
}

func (a *fakeAgent) call(method, path string, in, out any) int {
	a.t.Helper()
	var body bytes.Buffer
	if in != nil {
		_ = json.NewEncoder(&body).Encode(in)
	}
	req, _ := http.NewRequest(method, a.url+path, &body)
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil && resp.StatusCode < 300 {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			a.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

// claimOne claims a task and checks its type.
func (a *fakeAgent) claimOne(want string, types ...string) *protocol.Task {
	a.t.Helper()
	var resp protocol.ClaimResponse
	a.call("POST", "/v1/agent/tasks/claim", protocol.ClaimRequest{Types: types}, &resp)
	if resp.Task == nil {
		if want != "" {
			a.t.Fatalf("no task, want %s", want)
		}
		return nil
	}
	if resp.Task.Type != want {
		a.t.Fatalf("claimed %s, want %s", resp.Task.Type, want)
	}
	return resp.Task
}

func (a *fakeAgent) done(task *protocol.Task, status string, result any) {
	a.t.Helper()
	raw, _ := json.Marshal(result)
	if code := a.call("POST", "/v1/agent/tasks/"+task.ID+"/complete", protocol.CompleteRequest{Status: status, Result: raw}, nil); code != http.StatusNoContent {
		a.t.Fatalf("complete %s: %d", task.ID, code)
	}
}

// advance moves the test clock once the notifications on their way are
// sent: they record their delivery in the state, which reads the clock.
func advance(s *Server, now *time.Time, d time.Duration) {
	s.sending.Wait()
	*now = now.Add(d)
}

func setup(t *testing.T) (*Server, *fakeAgent, *client.Client, *time.Time) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC) // a Wednesday
	s.now = func() time.Time { return now }
	t.Cleanup(s.sending.Wait) // before the state's folder goes
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	a := &fakeAgent{t: t, url: ts.URL}
	if code := a.call("POST", "/v1/agent/enroll", protocol.EnrollRequest{Token: "rse_wrong"}, nil); code != http.StatusUnauthorized {
		t.Fatalf("enroll with another token: %d", code)
	}
	var er protocol.EnrollResponse
	a.call("POST", "/v1/agent/enroll", protocol.EnrollRequest{Token: protocol.LocalEnrollToken, Hostname: "db1", AgentVersion: "0.10.18"}, &er)
	if er.AgentToken == "" || er.HostID == "" {
		t.Fatalf("enroll: %+v", er)
	}
	a.token = er.AgentToken
	return s, a, client.New(ts.URL, "local"), &now
}

func heartbeat(a *fakeAgent, archivers ...protocol.ArchiverStats) protocol.HeartbeatResponse {
	var hb protocol.HeartbeatResponse
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.18", Archivers: archivers}, &hb)
	return hb
}

func TestLifecycle(t *testing.T) {
	s, a, c, now := setup(t)
	ctx := context.Background()

	// Without the agent's token, nothing.
	other := &fakeAgent{t: t, url: a.url, token: "nope"}
	if code := other.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{}, nil); code != http.StatusUnauthorized {
		t.Fatalf("heartbeat with another token: %d", code)
	}

	// The installer registers the database: a plan is queued.
	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "shop", Port: 5432, SocketDir: "/var/run/postgresql"}, &sd); code != http.StatusCreated {
		t.Fatalf("register: %d", code)
	}
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "crm", Port: 1521, Engine: "oracle"}, nil); code != http.StatusBadRequest {
		t.Fatalf("an unknown engine: %d", code)
	}
	// Pending: monitored, not yet protected.
	hb := heartbeat(a)
	if len(hb.Databases) != 0 || len(hb.Monitored) != 1 {
		t.Fatalf("heartbeat while pending: %+v", hb)
	}
	plan := a.claimOne(protocol.TaskAdopt)
	if plan.Database == nil || plan.Database.Stanza != "shop" || plan.Database.RetentionFull != 2 {
		t.Fatalf("plan task database: %+v", plan.Database)
	}
	a.done(plan, protocol.StatusSucceeded, protocol.AdoptResult{Inspect: protocol.InspectResult{ServerVersion: "17.6"}})
	a.call("GET", "/v1/agent/setup/databases/"+sd.ID, nil, &sd)
	if sd.PlanTaskStatus != protocol.StatusSucceeded || sd.Plan == nil {
		t.Fatalf("setup after the plan: %+v", sd)
	}

	// Apply: archiving needs a restart.
	if code := a.call("POST", "/v1/agent/setup/databases/"+sd.ID+"/apply", protocol.SetupApplyRequest{}, &sd); code != http.StatusAccepted {
		t.Fatalf("apply: %d", code)
	}
	if code := a.call("POST", "/v1/agent/setup/databases/"+sd.ID+"/apply", protocol.SetupApplyRequest{}, nil); code != http.StatusConflict {
		t.Fatalf("apply twice: %d", code)
	}
	apply := a.claimOne(protocol.TaskAdopt)
	a.done(apply, protocol.StatusSucceeded, protocol.AdoptResult{Applied: true, RestartRequired: true})
	db, _ := c.Database(ctx, "shop")
	if db.Status != protocol.DBAwaitingRestart {
		t.Fatalf("after apply: %s", db.Status)
	}
	// Someone restarts PostgreSQL: the heartbeat shows archiving on, a check runs.
	last := *now
	heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: &last})
	check := a.claimOne(protocol.TaskCheck)
	a.done(check, protocol.StatusSucceeded, protocol.CheckResult{OK: true})
	db, _ = c.Database(ctx, "shop")
	if db.Status != protocol.DBActive {
		t.Fatalf("after the check: %s", db.Status)
	}

	// Active: the first full backup, then the first Proof after it.
	if task := a.claimOne(protocol.TaskBackup); task != nil {
		// Proof waits for the backup.
		a.claimOne("")
		*now = now.Add(20 * time.Minute)
		a.done(task, protocol.StatusSucceeded, protocol.BackupResult{Label: "20261014-120000F", Type: protocol.BackupFull,
			StartedAt: now.Add(-20 * time.Minute), StoppedAt: *now, SizeBytes: 1 << 30})
	}
	drill := a.claimOne(protocol.TaskDrill)
	a.done(drill, protocol.StatusSucceeded, protocol.DrillResult{Passed: true, BackupLabel: "20261014-120000F"})

	heartbeat(a, protocol.ArchiverStats{DatabaseID: db.ID, ArchiveMode: "on", LastArchivedTime: now})
	p, err := c.Protection(ctx, "shop")
	if err != nil || !p.Protected || p.RecoveryWindowStart == nil {
		t.Fatalf("protection: %+v %v", p, err)
	}
	if bs, _ := c.Backups(ctx, "shop", 10); len(bs) != 1 {
		t.Errorf("backups: %+v", bs)
	}
	if ds, _ := c.Drills(ctx, "shop", 10); len(ds) != 1 || !ds[0].Passed {
		t.Errorf("drills: %+v", ds)
	}

	// A Mark, on its own lane beside a running backup.
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff}); err == nil {
		t.Error("the same backup twice")
	}
	running := a.claimOne(protocol.TaskBackup)
	*now = now.Add(time.Minute)
	mark, err := c.CreateRestorePoint(ctx, "shop", "before-drop")
	if err != nil {
		t.Fatal(err)
	}
	rp := a.claimOne(protocol.TaskRestorePoint, protocol.TaskRestorePoint)
	if rp.ID != mark.ID {
		t.Fatalf("claimed %s, want the Mark %s", rp.ID, mark.ID)
	}
	a.done(rp, protocol.StatusSucceeded, protocol.RestorePointResult{Name: "before-drop", LSN: "0/3000000", Archived: true, CreatedAt: *now})
	marks, _ := c.RestorePoints(ctx, "shop")
	if len(marks) != 1 || marks[0].ArchivedAt == nil || marks[0].Status != protocol.RestorePointArchived || marks[0].RestoreFromBackup != "20261014-120000F" {
		t.Fatalf("marks: %+v", marks)
	}
	a.done(running, protocol.StatusFailed, nil)
	p, _ = c.Protection(ctx, "shop")
	if len(p.OpenFailedTasks) != 1 {
		t.Errorf("failed backup not listed: %+v", p.OpenFailedTasks)
	}

	// The state survives a restart of the agent (and of this server).
	s2, err := Open(filepath.Dir(s.st.path), nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.st.read(func(st *state) {
		if len(st.Databases) != 1 || st.Databases[0].Status != protocol.DBActive || len(st.Backups) != 1 {
			t.Errorf("reloaded state: %+v", st.Databases)
		}
	})

	// What rowsafe login hands over to an account: the history, no secret.
	x, err := ReadExport(s.st.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(x.Databases) != 1 || x.Databases[0].Name != "shop" || x.Databases[0].Status != protocol.DBActive || len(x.Open) != 0 {
		t.Fatalf("export: %+v open %+v", x.Databases, x.Open)
	}
	h := x.History.Databases[0]
	if h.Name != "shop" || len(h.Backups) != 1 || len(h.Drills) != 1 || len(h.RestorePoints) != 1 || h.RestorePoints[0].LSN != "0/3000000" {
		t.Fatalf("history: %+v", h)
	}
	raw, _ := json.Marshal(x)
	if strings.Contains(string(raw), a.token) {
		t.Error("the export holds the agent's token")
	}

	// Things that need an account say so.
	if _, err := c.Hosts(ctx); err != nil {
		t.Error(err)
	}
	_, err = c.Availability(ctx, "shop")
	if err == nil || !strings.Contains(err.Error(), "rowsafe login") {
		t.Errorf("availability without an account: %v", err)
	}
}

func TestSchedules(t *testing.T) {
	s, _, _, now := setup(t)
	_ = s.st.update(func(st *state) error {
		st.Databases = append(st.Databases, &dbRec{Database: protocol.Database{ID: "db_1", Name: "shop", Status: protocol.DBActive,
			ScheduleFull: defaultScheduleFull, ScheduleDiff: defaultScheduleDiff, ScheduleDrill: defaultScheduleDrill}})
		return nil
	})
	count := func(typ, kind string) int {
		n := 0
		s.st.read(func(st *state) {
			for _, t := range st.Tasks {
				if t.Type == typ && (kind == "" || openKey(t.Type, t.Params) == typ+":"+kind) && t.Scheduled {
					n++
				}
			}
		})
		return n
	}
	s.Tick() // first sight: schedules count from now
	if count(protocol.TaskBackup, "") != 0 {
		t.Fatal("backup queued at once")
	}
	*now = time.Date(2026, 10, 15, 1, 0, 30, 0, time.UTC) // Thursday 01:00
	s.Tick()
	if count(protocol.TaskBackup, protocol.BackupDiff) != 1 || count(protocol.TaskBackup, protocol.BackupFull) != 0 {
		t.Fatalf("Thursday: diff %d full %d", count(protocol.TaskBackup, protocol.BackupDiff), count(protocol.TaskBackup, protocol.BackupFull))
	}
	s.Tick()                                              // same minute: nothing more
	*now = time.Date(2026, 10, 16, 1, 0, 30, 0, time.UTC) // Friday: the diff still open, skipped
	s.Tick()
	if count(protocol.TaskBackup, protocol.BackupDiff) != 1 {
		t.Fatal("piled up a second diff")
	}
	*now = time.Date(2026, 10, 18, 21, 16, 0, 0, time.UTC) // Sunday evening: full (01:00) and Proof
	s.Tick()
	if count(protocol.TaskBackup, protocol.BackupFull) != 1 || count(protocol.TaskDrill, "") != 1 {
		t.Fatalf("Sunday: full %d drill %d", count(protocol.TaskBackup, protocol.BackupFull), count(protocol.TaskDrill, ""))
	}
}

func TestLostAndWaiting(t *testing.T) {
	s, a, _, now := setup(t)
	_ = s.st.update(func(st *state) error {
		d := &dbRec{Database: protocol.Database{ID: "db_1", Name: "shop", Status: protocol.DBVerifying}}
		st.Databases = append(st.Databases, d)
		return st.activate(d, *now)
	})
	backup := a.claimOne(protocol.TaskBackup)
	// The agent dies mid-backup: the lease runs out, the backup is lost
	// and the Proof that waited for it is cancelled.
	*now = now.Add(protocol.TaskTimeout(protocol.TaskBackup) + 6*time.Minute)
	s.Tick()
	s.st.read(func(st *state) {
		if st.task(backup.ID).Status != protocol.StatusLost {
			t.Errorf("backup %s", st.task(backup.ID).Status)
		}
	})
	a.claimOne("")
	s.st.read(func(st *state) {
		for _, x := range st.Tasks {
			if x.Type == protocol.TaskDrill && x.Status != protocol.StatusCancelled {
				t.Errorf("drill %s", x.Status)
			}
		}
	})
	// A late completion of the lost task is refused.
	if code := a.call("POST", "/v1/agent/tasks/"+backup.ID+"/complete", protocol.CompleteRequest{Status: protocol.StatusSucceeded}, nil); code != http.StatusConflict {
		t.Errorf("completing a lost task: %d", code)
	}
}

func TestRegisterSocketDir(t *testing.T) {
	_, a, _, _ := setup(t)
	var sd protocol.SetupDatabase
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "shop", Port: 5432}, &sd); code != http.StatusCreated || sd.SocketDir != "/var/run/postgresql" {
		t.Fatalf("without a socket directory: %d %+v", code, sd)
	}
	if code := a.call("POST", "/v1/agent/setup/databases", protocol.SetupRegisterRequest{Name: "crm", Port: 5433, SocketDir: "tmp"}, nil); code != http.StatusBadRequest {
		t.Fatalf("a relative socket directory: %d", code)
	}
}
