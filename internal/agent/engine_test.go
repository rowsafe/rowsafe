package agent

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeEngine is a MySQL engine that records what it was asked to do.
type fakeEngine struct {
	name     string
	mu       sync.Mutex
	ran      []string
	env      EngineEnv
	monitor  *protocol.DatabaseMonitoring
	archiver *protocol.ArchiverStats
	found    []DiscoveredDatabase
	err      error
}

func (f *fakeEngine) Name() string    { return f.name }
func (f *fakeEngine) Tasks() []string { return []string{protocol.TaskBackup, protocol.TaskInspect} }

func (f *fakeEngine) Run(_ context.Context, env EngineEnv, task *protocol.Task, log TaskLogger) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ran = append(f.ran, task.Type+":"+task.Database.ID)
	f.env = env
	log.Printf("fake %s on port %d", task.Type, task.Database.Port)
	if f.err != nil {
		return nil, f.err
	}
	return map[string]string{"engine": f.name}, nil
}

func (f *fakeEngine) Monitor(_ context.Context, _ EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	if f.monitor == nil {
		return nil, nil
	}
	dm := *f.monitor
	return &dm, nil
}

func (f *fakeEngine) Discover(_ context.Context, env EngineEnv) ([]DiscoveredDatabase, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.found, nil
}

func (f *fakeEngine) Archiver(_ context.Context, _ EngineEnv, db protocol.DatabaseSpec) (*protocol.ArchiverStats, error) {
	return f.archiver, nil
}

// withEngine registers e for the test.
func withEngine(t *testing.T, e Engine) {
	t.Helper()
	RegisterEngine(e)
	t.Cleanup(func() {
		enginesMu.Lock()
		delete(engines, e.Name())
		enginesMu.Unlock()
	})
}

func TestRunTaskRoutesToEngine(t *testing.T) {
	dir := t.TempDir()
	a := &Agent{cfg: Config{StateDir: dir}}
	mysqlDB := &protocol.DatabaseSpec{ID: "db_m", Name: "shop", Port: 3306, Engine: protocol.EngineMySQL}

	// No engine registered: a plain error, nothing runs.
	tl := &taskLog{}
	_, err := a.runTask(t.Context(), &protocol.Task{ID: "t1", Type: protocol.TaskBackup, Database: mysqlDB}, tl)
	if err == nil || !strings.Contains(err.Error(), "This agent doesn't support MySQL yet; update the agent") {
		t.Fatalf("without the engine: %v", err)
	}

	f := &fakeEngine{name: protocol.EngineMySQL}
	withEngine(t, f)
	res, err := a.runTask(t.Context(), &protocol.Task{ID: "t2", Type: protocol.TaskBackup, Database: mysqlDB}, tl)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := res.(map[string]string); m["engine"] != protocol.EngineMySQL {
		t.Errorf("result = %#v", res)
	}
	if len(f.ran) != 1 || f.ran[0] != "backup:db_m" || !strings.Contains(tl.String(), "fake backup on port 3306") {
		t.Errorf("ran %v, log %q", f.ran, tl.String())
	}
	if f.env.StateDir != filepath.Join(dir, "engines", "mysql") || f.env.Runner == nil || f.env.Log == nil || f.env.Notes == nil {
		t.Errorf("env = %+v", f.env)
	}

	// A task type the engine doesn't handle.
	_, err = a.runTask(t.Context(), &protocol.Task{ID: "t3", Type: protocol.TaskRestorePoint, Database: mysqlDB}, tl)
	if err == nil || !strings.Contains(err.Error(), "can't run restore_point tasks for MySQL yet") {
		t.Errorf("unhandled type: %v", err)
	}

	// Errors pass through.
	f.err = errors.New("mysqldump failed")
	if _, err := a.runTask(t.Context(), &protocol.Task{ID: "t4", Type: protocol.TaskBackup, Database: mysqlDB}, tl); err == nil || err.Error() != "mysqldump failed" {
		t.Errorf("error = %v", err)
	}

	// MariaDB isn't registered even though MySQL is.
	maria := &protocol.DatabaseSpec{ID: "db_x", Port: 3307, Engine: protocol.EngineMariaDB}
	if _, err := a.runTask(t.Context(), &protocol.Task{ID: "t5", Type: protocol.TaskBackup, Database: maria}, tl); err == nil || !strings.Contains(err.Error(), "doesn't support MariaDB") {
		t.Errorf("mariadb: %v", err)
	}

	// PostgreSQL ("" and "postgresql") never reaches an engine.
	for _, eng := range []string{"", protocol.EnginePostgreSQL} {
		pg := &protocol.DatabaseSpec{ID: "db_p", Port: 5432, Engine: eng}
		_, err := a.runTask(t.Context(), &protocol.Task{ID: "t6", Type: "no_such_type", Database: pg}, tl)
		if err == nil || !strings.Contains(err.Error(), "unsupported task type") {
			t.Errorf("postgres %q: %v", eng, err)
		}
	}
	if len(f.ran) != 2 {
		t.Errorf("engine ran %v", f.ran)
	}
}

func TestEngineMonitorAndArchiver(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir()}}
	db := protocol.DatabaseSpec{ID: "db_m", Port: 3306, Engine: protocol.EngineMySQL}
	if dm, err := a.monitorEngine(t.Context(), db); dm != nil || err != nil {
		t.Errorf("without the engine: %v %v", dm, err)
	}
	a.watched = []protocol.DatabaseSpec{db}
	if got := a.archiverStats(t.Context()); len(got) != 0 {
		t.Errorf("archiver without the engine: %+v", got)
	}

	f := &fakeEngine{name: protocol.EngineMySQL}
	withEngine(t, f)
	if dm, err := a.monitorEngine(t.Context(), db); dm != nil || err != nil {
		t.Errorf("engine without monitoring: %v %v", dm, err)
	}
	if got := a.archiverStats(t.Context()); len(got) != 0 {
		t.Errorf("engine without archiving: %+v", got)
	}
	f.monitor = &protocol.DatabaseMonitoring{Metrics: map[string]float64{"up": 1}}
	f.archiver = &protocol.ArchiverStats{ArchivedCount: 7, ArchiveMode: "on"}
	dm, err := a.monitorEngine(t.Context(), db)
	if err != nil || dm == nil || dm.DatabaseID != "db_m" || dm.Metrics["up"] != 1 {
		t.Errorf("monitor = %+v, %v", dm, err)
	}
	got := a.archiverStats(t.Context())
	if len(got) != 1 || got[0].DatabaseID != "db_m" || got[0].ArchivedCount != 7 {
		t.Errorf("archiver = %+v", got)
	}
}

func TestRegisterEngineRejects(t *testing.T) {
	for _, name := range []string{protocol.EnginePostgreSQL, "", "MySQL", "oracle"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("RegisterEngine(%q) did not panic", name)
				}
			}()
			RegisterEngine(&fakeEngine{name: name})
		}()
	}
	withEngine(t, &fakeEngine{name: protocol.EngineMongoDB})
	defer func() {
		if recover() == nil {
			t.Error("registering twice did not panic")
		}
	}()
	RegisterEngine(&fakeEngine{name: protocol.EngineMongoDB})
}

func TestEngineEnvRunLow(t *testing.T) {
	fr := &recordRunner{}
	env := EngineEnv{Runner: fr, LowPriority: []string{"ionice", "-c2", "nice"}}
	if _, err := env.RunLow(t.Context(), "mysqldump", "--all"); err != nil {
		t.Fatal(err)
	}
	env.LowPriority = nil
	env.RunLow(t.Context(), "mongodump")
	want := []string{"ionice -c2 nice mysqldump --all", "mongodump"}
	if strings.Join(fr.calls, "|") != strings.Join(want, "|") {
		t.Errorf("calls = %q", fr.calls)
	}
}

type recordRunner struct{ calls []string }

func (r *recordRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	return nil, nil
}

func TestSetupDiscoverEngines(t *testing.T) {
	oldDirs, oldLs := socketDirs, lsclusters
	defer func() { socketDirs, lsclusters = oldDirs, oldLs }()
	socketDirs = []string{t.TempDir()} // no PostgreSQL
	lsclusters = func(context.Context) ([]byte, error) { return nil, errors.New("not installed") }

	f := newFakeSetupAPI()
	// A MySQL database registered on 3306; a PostgreSQL one on 3307 must
	// not be taken for the MySQL server on that port.
	f.dbs["db_m"] = &protocol.SetupDatabase{ID: "db_m", Name: "shop", Port: 3306, Status: protocol.DBActive, Engine: protocol.EngineMySQL}
	f.dbs["db_p"] = &protocol.SetupDatabase{ID: "db_p", Name: "pg", Port: 3307, Status: protocol.DBActive}
	s, _, notes := testSetup(t, f)

	// Without engines, nothing is found (and nothing is said about them).
	cs, err := s.Discover(t.Context())
	if err != nil || len(cs) != 0 {
		t.Fatalf("no engines: %v %v", cs, err)
	}

	withEngine(t, &fakeEngine{name: protocol.EngineMySQL, found: []DiscoveredDatabase{
		{Port: 3306, SocketDir: "/run/mysqld/mysqld.sock", Version: "8.4.3", Major: 8, Databases: []string{"shop"}, SizeBytes: 1024},
		{Port: 3307, Version: "8.0.40", Major: 8, Databases: []string{"crm"}, Unit: "mysql@b.service"},
	}})
	withEngine(t, &fakeEngine{name: protocol.EngineMongoDB, err: errors.New("mongod not answering\nmore")})
	cs, err = s.Discover(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	WriteClusters(&out, cs)
	want := "3306\t/run/mysqld/mysqld.sock\t8\t-\t-\t1024\tshop\tyes\tactive\tshop\t1.0 KiB\t-\tdb_m\tmysql\n" +
		"3307\t-\t8\t-\t-\t0\tcrm\tno\t-\tcrm\t0 B\tmysql@b.service\t-\tmysql\n"
	if out.String() != want {
		t.Errorf("discover:\n%s\nwant:\n%s", out.String(), want)
	}
	if !strings.Contains(notes.String(), "Looking for MongoDB failed (mongod not answering); skipped.") {
		t.Errorf("notes: %q", notes.String())
	}

	// plan registers with the engine.
	s.Engine = protocol.EngineMySQL
	_ = s.Plan(t.Context(), "crm", 3307, "", "", 10*time.Millisecond)
	if len(f.registers) == 0 || f.registers[0].Engine != protocol.EngineMySQL || f.registers[0].Port != 3307 {
		t.Errorf("registered %+v", f.registers)
	}
}
