package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestSanitizeAndSuggestName(t *testing.T) {
	for in, want := range map[string]string{
		"shop":                         "shop",
		"TV_Hub prod":                  "tv-hub-prod",
		"42app":                        "db-42app",
		"--a--b--":                     "a-b",
		"x":                            "",
		"ö":                            "",
		strings.Repeat("a", 50):        strings.Repeat("a", 40),
		"a" + strings.Repeat("-b", 30): strings.TrimRight(("a" + strings.Repeat("-b", 30))[:40], "-"),
	} {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
		if got := SanitizeName(in); got != "" && !ValidName(got) {
			t.Errorf("SanitizeName(%q) = %q is not valid", in, got)
		}
	}
	for _, tc := range []struct {
		dbs  []string
		host string
		want string
	}{
		{[]string{"shop"}, "web-1.example.com", "shop"},
		{[]string{"app", "analytics"}, "web-1.example.com", "web-1"},
		{nil, "DB01", "db01"},
		{nil, "!!!", "postgres"},
	} {
		if got := suggestName(tc.dbs, tc.host); got != tc.want {
			t.Errorf("suggestName(%v, %q) = %q, want %q", tc.dbs, tc.host, got, tc.want)
		}
	}
	if got := userDatabases([]protocol.DatabaseSize{{Name: "postgres"}, {Name: "shop"}, {Name: "template1"}}); len(got) != 1 || got[0] != "shop" {
		t.Errorf("userDatabases = %v", got)
	}
}

func TestParseLsclusters(t *testing.T) {
	out := "16  main    5433 down   postgres /var/lib/postgresql/16/main /var/log/postgresql/postgresql-16-main.log\n" +
		"18  main    5432 online postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log\n" +
		"garbage\n"
	cs := parseLsclusters([]byte(out))
	if len(cs) != 2 || cs[1] != (lsCluster{Major: 18, Name: "main", Port: 5432, Status: "online", DataDir: "/var/lib/postgresql/18/main"}) {
		t.Fatalf("parsed %+v", cs)
	}
}

// listenUnix makes a real Unix socket (a plain file with the right name
// doesn't count).
func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "rs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestFindSockets(t *testing.T) {
	a, b := shortTempDir(t), shortTempDir(t)
	listenUnix(t, filepath.Join(a, ".s.PGSQL.5432"))
	listenUnix(t, filepath.Join(b, ".s.PGSQL.5432")) // same port elsewhere: the first wins
	listenUnix(t, filepath.Join(b, ".s.PGSQL.5433"))
	os.WriteFile(filepath.Join(b, ".s.PGSQL.5434"), nil, 0o600) // not a socket
	os.WriteFile(filepath.Join(b, ".s.PGSQL.5433.lock"), nil, 0o600)
	link := filepath.Join(shortTempDir(t), "link")
	os.Symlink(a, link)
	sockets, ports := findSockets([]string{a, link, b, "/nonexistent"})
	if len(ports) != 2 || ports[0] != 5432 || ports[1] != 5433 || sockets[5432] != a || sockets[5433] != b {
		t.Fatalf("sockets %v ports %v", sockets, ports)
	}
}

func TestSystemdUnit(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/postgresql@18-main.service\n":                                      "postgresql@18-main.service",
		"12:pids:/system.slice/x.service\n1:name=systemd:/system.slice/postgresql.service\n": "postgresql.service",
		"0::/user.slice/user-1000.slice/session-3.scope\n":                                   "",
		"0::/docker/abcdef\n":                "",
		"0::/system.slice/evil;rm.service\n": "",
	} {
		if got := unitFromCgroup(in); got != want {
			t.Errorf("unitFromCgroup(%q) = %q, want %q", in, got, want)
		}
	}

	root := t.TempDir()
	oldProc, oldDirs := procRoot, unitFileDirs
	defer func() { procRoot, unitFileDirs = oldProc, oldDirs }()
	procRoot = filepath.Join(root, "proc")
	unitFileDirs = []string{filepath.Join(root, "units")}
	data := filepath.Join(root, "data")
	os.MkdirAll(filepath.Join(procRoot, "4242"), 0o755)
	os.MkdirAll(data, 0o700)
	os.MkdirAll(unitFileDirs[0], 0o755)
	os.WriteFile(filepath.Join(procRoot, "4242", "cgroup"), []byte("0::/system.slice/postgresql@18-main.service\n"), 0o644)

	if got := SystemdUnit(data, 18, "main"); got != "" {
		t.Errorf("no postmaster.pid, no template: %q", got)
	}
	os.WriteFile(filepath.Join(unitFileDirs[0], "postgresql@.service"), nil, 0o644)
	if got := SystemdUnit(data, 17, "main"); got != "postgresql@17-main.service" {
		t.Errorf("Debian template: %q", got)
	}
	os.WriteFile(filepath.Join(data, "postmaster.pid"), []byte("4242\n/var/lib/postgresql/18/main\n"), 0o600)
	if got := SystemdUnit(data, 17, "main"); got != "postgresql@18-main.service" {
		t.Errorf("from the postmaster's cgroup: %q", got)
	}
	if debianCluster("/var/lib/postgresql/18/main", 18) != "main" || debianCluster("/srv/pg", 18) != "" || debianCluster("/var/lib/postgresql/17/main", 18) != "" {
		t.Error("debianCluster")
	}
	for _, tc := range []struct{ unit, cluster, want string }{
		{"postgresql@18-main.service", "main", "sudo systemctl restart postgresql@18-main"},
		{"", "main", "sudo pg_ctlcluster 18 main restart"},
		{"", "", "sudo systemctl restart postgresql"},
	} {
		if got := RestartCommand(tc.unit, 18, tc.cluster); got != tc.want {
			t.Errorf("RestartCommand(%q, %q) = %q", tc.unit, tc.cluster, got)
		}
	}
}

// fakeSetupAPI is the control plane's setup endpoints for one host.
type fakeSetupAPI struct {
	mu             sync.Mutex
	dbs            map[string]*protocol.SetupDatabase
	gets           int                                         // GETs of a database since its last task
	finish         func(d *protocol.SetupDatabase, apply bool) // run on the 2nd GET after a task is queued
	apply          bool
	forced         bool
	registerStatus int
	registerMsg    string
}

func newFakeSetupAPI() *fakeSetupAPI {
	return &fakeSetupAPI{dbs: map[string]*protocol.SetupDatabase{}}
}

func (f *fakeSetupAPI) server(t *testing.T) *httptest.Server {
	j := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/setup/databases", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.registerStatus != 0 {
			j(w, f.registerStatus, protocol.Error{Error: f.registerMsg})
			return
		}
		var req protocol.SetupRegisterRequest
		json.NewDecoder(r.Body).Decode(&req)
		for _, d := range f.dbs {
			if d.Port == req.Port {
				if d.Status == protocol.DBPendingAdopt {
					d.PlanTaskID, d.PlanTaskStatus, f.gets, f.apply = d.PlanTaskID+"x", protocol.StatusQueued, 0, false
				}
				j(w, 200, d)
				return
			}
		}
		d := &protocol.SetupDatabase{ID: "db_" + req.Name, Name: req.Name, Port: req.Port, Status: protocol.DBPendingAdopt,
			PlanTaskID: "task_1", PlanTaskStatus: protocol.StatusQueued}
		f.dbs[d.ID] = d
		f.gets, f.apply = 0, false
		j(w, 201, d)
	})
	mux.HandleFunc("GET /v1/agent/setup/databases", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		list := protocol.SetupDatabaseList{Databases: []protocol.SetupDatabase{}}
		for _, d := range f.dbs {
			list.Databases = append(list.Databases, *d)
		}
		j(w, 200, list)
	})
	mux.HandleFunc("GET /v1/agent/setup/databases/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		d, ok := f.dbs[r.PathValue("id")]
		if !ok {
			j(w, 404, protocol.Error{Error: "no such database on this host"})
			return
		}
		f.gets++
		if f.gets == 2 && f.finish != nil && d.PlanTaskStatus == protocol.StatusQueued {
			f.finish(d, f.apply)
		}
		j(w, 200, d)
	})
	mux.HandleFunc("POST /v1/agent/setup/databases/{id}/apply", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var req protocol.SetupApplyRequest
		json.NewDecoder(r.Body).Decode(&req)
		d := f.dbs[r.PathValue("id")]
		if d.PlanTaskStatus != protocol.StatusSucceeded && !req.Force {
			j(w, 409, protocol.Error{Error: "the plan hasn't succeeded"})
			return
		}
		f.forced = req.Force
		d.PlanTaskID, d.PlanTaskStatus, f.gets, f.apply = "task_apply", protocol.StatusQueued, 0, true
		j(w, 202, d)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func testSetup(t *testing.T, f *fakeSetupAPI) (*Setup, *bytes.Buffer, *bytes.Buffer) {
	ts := f.server(t)
	var out, notes bytes.Buffer
	return &Setup{cfg: Config{PGUser: "postgres"}, client: newControlClient(ts.URL, "rsa_x"), Out: &out, Notes: &notes, Poll: 5 * time.Millisecond}, &out, &notes
}

func exitCode(err error) int {
	var e *ExitError
	if errors.As(err, &e) {
		return e.Code
	}
	if err != nil {
		return 1
	}
	return 0
}

var planNeedingRestart = protocol.AdoptResult{
	Inspect: protocol.InspectResult{ServerVersion: "18.1 (Debian 18.1-1.pgdg13+1)", Port: 5432, TotalSizeBytes: 1288490189,
		Databases: []protocol.DBInfo{{Name: "postgres"}, {Name: "shop"}}},
	Plan: []protocol.Change{
		{Kind: "file", Description: "write pgBackRest config (0600, contains repository credentials) to /etc/rowsafe/pgbackrest/shop.conf"},
		{Kind: "command", Description: "pgbackrest stanza-create: initialise the repository for this cluster"},
		{Kind: "setting", Setting: "archive_mode", From: "off", To: "on", Restart: true},
		{Kind: "setting", Setting: "archive_command", To: "pgbackrest ... archive-push %p"},
		{Kind: "setting", Setting: "archive_timeout", From: "0", To: "300"},
	},
	RestartRequired: true,
	Warnings:        []string{restartWarning(false, "shop")},
}

func TestSetupPlanApplyWait(t *testing.T) {
	t.Setenv("LANG", "C.UTF-8")
	f := newFakeSetupAPI()
	f.finish = func(d *protocol.SetupDatabase, apply bool) {
		d.PlanTaskStatus = protocol.StatusSucceeded
		p := planNeedingRestart
		if apply {
			p.Applied = true
			d.Status = protocol.DBAwaitingRestart
		}
		d.Plan = &p
	}
	s, out, _ := testSetup(t, f)
	idFile := filepath.Join(t.TempDir(), "id")
	err := s.Plan(t.Context(), "shop", 5432, "/var/run/postgresql", idFile, time.Second)
	if err != nil {
		t.Fatal(err, out)
	}
	if id, _ := os.ReadFile(idFile); string(id) != "db_shop\n" {
		t.Errorf("id file %q", id)
	}
	for _, want := range []string{
		"PostgreSQL 18.1 on port 5432: 1.2 GiB, 1 database (shop).",
		"Save the backup settings in /etc/rowsafe/pgbackrest/shop.conf",
		"Prepare your bucket for this database",
		"Turn on copying of every change to your bucket (archive_mode: off → on, needs a restart)",
		"Copy the changes with Rowsafe (archive_command)",
		"at least every 5 minutes",
		"Restart: PostgreSQL needs one quick restart",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out.String(), RestartWarningPrefix) || strings.Contains(out.String(), "WAL") {
		t.Errorf("plan repeats the restart warning or says WAL:\n%s", out)
	}

	out.Reset()
	if code := exitCode(s.Apply(t.Context(), "db_shop", false, time.Second)); code != SetupRestartNeeded {
		t.Fatalf("apply exit %d, want %d\n%s", code, SetupRestartNeeded, out)
	}
	// Planning again once applied says so, without a new plan.
	out.Reset()
	if code := exitCode(s.Plan(t.Context(), "shop", 5432, "", "", time.Second)); code != SetupRestartNeeded || !strings.Contains(out.String(), "needs a restart") {
		t.Fatalf("re-plan exit %d: %s", code, out)
	}

	// Wait: restart -> verifying -> active -> first backup running.
	out.Reset()
	steps := []func(d *protocol.SetupDatabase){
		func(d *protocol.SetupDatabase) {},
		func(d *protocol.SetupDatabase) { d.Status = protocol.DBVerifying },
		func(d *protocol.SetupDatabase) { d.Status = protocol.DBActive },
		func(d *protocol.SetupDatabase) { d.BackupRunning = true; d.DashboardURL = "https://app.example/db/1" },
	}
	var calls int
	f.finish = nil
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		d := f.dbs["db_shop"]
		steps[min(calls, len(steps)-1)](d)
		calls++
		json.NewEncoder(w).Encode(d)
		f.mu.Unlock()
	}))
	defer ts.Close()
	s.client = newControlClient(ts.URL, "rsa_x")
	if err := s.Wait(t.Context(), "db_shop", time.Second); err != nil {
		t.Fatal(err)
	}
	want := "Waiting for PostgreSQL to restart...\nChecking that changes reach your storage...\n" +
		"Protected. Starting the first full backup...\n✓ shop is protected. The first full backup is running.\n"
	if out.String() != want {
		t.Errorf("wait printed:\n%s\nwant:\n%s", out, want)
	}
	out.Reset()
	if err := s.Status(t.Context(), "db_shop"); err != nil || out.String() != "db_shop\tshop\tactive\trunning\thttps://app.example/db/1\n" {
		t.Errorf("status %q %v", out, err)
	}
}

func TestSetupWaitTimesOut(t *testing.T) {
	f := newFakeSetupAPI()
	f.dbs["db_a"] = &protocol.SetupDatabase{ID: "db_a", Name: "a", Status: protocol.DBAwaitingRestart}
	s, out, _ := testSetup(t, f)
	if code := exitCode(s.Wait(t.Context(), "db_a", 30*time.Millisecond)); code != SetupTimedOut {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), "Rowsafe keeps going on its own") {
		t.Error(out)
	}
	if code := exitCode(s.Wait(t.Context(), "db_nope", time.Second)); code != 1 {
		t.Errorf("unknown database: exit %d", code)
	}
}

func TestSetupPlanOutcomes(t *testing.T) {
	t.Run("no restart needed", func(t *testing.T) {
		f := newFakeSetupAPI()
		f.finish = func(d *protocol.SetupDatabase, apply bool) {
			d.PlanTaskStatus = protocol.StatusSucceeded
			d.Plan = &protocol.AdoptResult{Inspect: protocol.InspectResult{ServerVersion: "17.6", Port: 5432},
				Plan: []protocol.Change{{Kind: "setting", Setting: "archive_command", From: "", To: "x"}}, Applied: apply}
		}
		s, out, _ := testSetup(t, f)
		if err := s.Plan(t.Context(), "app", 5432, "", "", time.Second); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "No downtime") {
			t.Error(out)
		}
		if err := s.Apply(t.Context(), "db_app", false, time.Second); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("another archiver", func(t *testing.T) {
		f := newFakeSetupAPI()
		f.finish = func(d *protocol.SetupDatabase, apply bool) {
			if apply {
				d.PlanTaskStatus = protocol.StatusSucceeded
				d.Plan = &protocol.AdoptResult{Applied: true}
				d.Status = protocol.DBVerifying
				return
			}
			d.PlanTaskStatus = protocol.StatusFailed
			d.PlanError = `archive_command is already set to "wal-g wal-push %p": another archiver may be running; re-run with force to replace it`
			d.Plan = &protocol.AdoptResult{Inspect: protocol.InspectResult{ArchiveCommand: "wal-g wal-push %p"}}
		}
		s, out, _ := testSetup(t, f)
		if code := exitCode(s.Plan(t.Context(), "app", 5432, "", "", time.Second)); code != SetupRefused {
			t.Fatalf("exit %d: %s", code, out)
		}
		if !strings.Contains(out.String(), "another backup tool is set up") || !strings.Contains(out.String(), "wal-g wal-push") ||
			!strings.Contains(out.String(), "--force") {
			t.Error(out)
		}
		if code := exitCode(s.Apply(t.Context(), "db_app", false, time.Second)); code != 1 {
			t.Errorf("apply without force: exit %d", code)
		}
		if err := s.Apply(t.Context(), "db_app", true, time.Second); err != nil || !f.forced {
			t.Fatalf("apply --force: %v", err)
		}
	})
	t.Run("plan failed otherwise", func(t *testing.T) {
		f := newFakeSetupAPI()
		f.finish = func(d *protocol.SetupDatabase, apply bool) {
			d.PlanTaskStatus, d.PlanError = protocol.StatusFailed, "PostgreSQL 12 is not supported"
		}
		s, _, _ := testSetup(t, f)
		err := s.Plan(t.Context(), "app", 5432, "", "", time.Second)
		if exitCode(err) != 1 || !strings.Contains(err.Error(), "not supported") {
			t.Fatal(err)
		}
	})
	t.Run("agent never answers", func(t *testing.T) {
		s, _, _ := testSetup(t, newFakeSetupAPI())
		err := s.Plan(t.Context(), "app", 5432, "", "", 30*time.Millisecond)
		if exitCode(err) != 1 || !strings.Contains(err.Error(), "systemctl status rowsafe-agent") {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		status int
		code   int
	}{{409, SetupNameTaken}, {402, SetupPlanLimit}, {500, 1}} {
		f := newFakeSetupAPI()
		f.registerStatus, f.registerMsg = tc.status, "the server says why"
		s, _, _ := testSetup(t, f)
		err := s.Plan(t.Context(), "app", 5432, "", "", time.Second)
		if exitCode(err) != tc.code || !strings.Contains(err.Error(), "the server says why") {
			t.Errorf("HTTP %d: exit %d, %v", tc.status, exitCode(err), err)
		}
	}
	s, _, _ := testSetup(t, newFakeSetupAPI())
	if err := s.Plan(t.Context(), "Bad Name", 5432, "", "", time.Second); exitCode(err) != 1 || !strings.Contains(err.Error(), NameRule) {
		t.Errorf("invalid name: %v", err)
	}
	f := newFakeSetupAPI()
	f.dbs["db_x"] = &protocol.SetupDatabase{ID: "db_x", Name: "xy", Port: 5432, Status: protocol.DBActive}
	s, out, _ := testSetup(t, f)
	if code := exitCode(s.Plan(t.Context(), "xy", 5432, "", "", time.Second)); code != SetupAlreadyDone || !strings.Contains(out.String(), "already protected") {
		t.Errorf("active: exit %d %s", code, out)
	}
}

func TestSetupDiscover(t *testing.T) {
	dir := shortTempDir(t)
	listenUnix(t, filepath.Join(dir, ".s.PGSQL.5432"))
	listenUnix(t, filepath.Join(dir, ".s.PGSQL.5433"))
	listenUnix(t, filepath.Join(dir, ".s.PGSQL.5434"))
	listenUnix(t, filepath.Join(dir, ".s.PGSQL.5435"))
	oldDirs, oldLs, oldSum := socketDirs, lsclusters, summarizeCluster
	defer func() { socketDirs, lsclusters, summarizeCluster = oldDirs, oldLs, oldSum }()
	socketDirs = []string{dir}
	lsclusters = func(context.Context) ([]byte, error) {
		return []byte("18 main 5432 online postgres /var/lib/postgresql/18/main x\n16 old 5440 down postgres /var/lib/postgresql/16/old x\n"), nil
	}
	summarizeCluster = func(_ context.Context, tg pginspect.Target) (pginspect.Summary, error) {
		switch tg.Port {
		case 5432:
			return pginspect.Summary{ServerVersion: "18.1", VersionNum: 180001, DataDirectory: "/var/lib/postgresql/18/main", TotalSizeBytes: 1288490189,
				Databases: []protocol.DatabaseSize{{Name: "postgres"}, {Name: "TV hub"}}}, nil
		case 5433:
			return pginspect.Summary{VersionNum: 170000, DataDirectory: "/srv/pg", InRecovery: true}, nil
		case 5434:
			return pginspect.Summary{}, errors.New("peer authentication failed")
		}
		return pginspect.Summary{VersionNum: 170006, DataDirectory: "/srv/b", Databases: []protocol.DatabaseSize{{Name: "a"}, {Name: "b"}}}, nil
	}
	f := newFakeSetupAPI()
	f.dbs["db_1"] = &protocol.SetupDatabase{ID: "db_1", Name: "billing", Port: 5435, Status: protocol.DBAwaitingRestart}
	s, _, notes := testSetup(t, f)
	cs, err := s.Discover(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	WriteClusters(&out, cs)
	want := "5432\t" + dir + "\t18\tmain\t/var/lib/postgresql/18/main\t1288490189\ttv-hub\tno\t-\tTV hub\t1.2 GiB\t-\t-\n" +
		"5435\t" + dir + "\t17\t-\t/srv/b\t0\tbilling\tyes\tawaiting_restart\ta,b\t0 B\t-\tdb_1\n"
	if out.String() != want {
		t.Errorf("discover:\n%s\nwant:\n%s", out.String(), want)
	}
	for _, n := range []string{"port 5440 is not running", "port 5433 is a replica", "port 5434: can't connect"} {
		if !strings.Contains(notes.String(), n) {
			t.Errorf("notes lack %q:\n%s", n, notes)
		}
	}
}
