package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/dockerctl"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeControl plays rowsafe-docker-control for the agent.
type fakeControl struct {
	mu    sync.Mutex
	calls []string
	res   dockerctl.Response
	err   error
	// states are returned by successive inspects after a start/restart.
	states []string
}

func newFakeControl() *fakeControl {
	return &fakeControl{res: dockerctl.Response{OK: true, Container: "myapp-postgres-1", Project: "myapp", Service: "postgres",
		State: "running", Actions: dockerctl.Actions}}
}

func (f *fakeControl) call(_ context.Context, req dockerctl.Request) (dockerctl.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req.Action)
	if f.err != nil {
		return dockerctl.Response{}, f.err
	}
	r := f.res
	r.ID, r.Action = req.ID, req.Action
	if req.Action == dockerctl.ActionInspect && len(f.states) > 0 {
		r.State, f.states = f.states[0], f.states[1:]
	}
	return r, nil
}

// newDockerEnv is a rewind environment in docker-sidecar mode: the data
// directory is a volume (its entries move, the directory stays).
func newDockerEnv(t *testing.T) (*inPlaceEnv, *fakeControl) {
	e := newInPlaceEnv(t)
	for _, name := range []string{"base", "global", "pg_wal"} {
		must(t, os.MkdirAll(filepath.Join(e.dataDir, name, "1"), 0o700))
	}
	must(t, os.WriteFile(filepath.Join(e.dataDir, "PG_VERSION"), []byte("18\n"), 0o600))
	must(t, os.WriteFile(filepath.Join(e.dataDir, "pg_hba.conf"), []byte("# production hba\n"), 0o600))
	e.ops.f.HbaFile = filepath.Join(e.dataDir, "pg_hba.conf")
	e.a.cfg.Mode = ModeDockerSidecar
	fc := newFakeControl()
	e.a.docker.call = fc.call
	return e, fc
}

// dockerOriginal: production runs the original data, in the same
// directory, with nothing left over anywhere.
func (e *inPlaceEnv) dockerOriginal(what string, before os.FileInfo) {
	e.t.Helper()
	e.original(what)
	if exists(filepath.Join(e.dataDir, asideDirName)) {
		entries, _ := os.ReadDir(filepath.Join(e.dataDir, asideDirName))
		e.t.Fatalf("%s: %s left with %v", what, asideDirName, entries)
	}
	if after, _ := os.Stat(e.dataDir); before != nil && !os.SameFile(before, after) {
		e.t.Fatalf("%s: the data directory itself was replaced", what)
	}
	for _, name := range []string{"base/1", "global/1", "pg_wal/1", "PG_VERSION"} {
		if !exists(filepath.Join(e.dataDir, name)) {
			e.t.Fatalf("%s: %s missing", what, name)
		}
	}
}

func TestDockerRewindUndoCleanup(t *testing.T) {
	e, fc := newDockerEnv(t)
	before, _ := os.Stat(e.dataDir)
	res, err, log := e.rewind("rw_1")
	if err != nil {
		t.Fatal(err, log)
	}
	if want := []string{"repo", "stop", "restore time 2026-09-24 14:04:00+00", "recover", "start", "ready"}; !slices.Equal(e.ops.calls, want) {
		t.Fatalf("steps %v, want %v", e.ops.calls, want)
	}
	if !slices.Equal(fc.calls, []string{"inspect"}) {
		t.Errorf("control calls %v (stop/start go through ops)", fc.calls)
	}
	// The data directory is the same directory, now holding the restore.
	if after, _ := os.Stat(e.dataDir); !os.SameFile(before, after) || after.Mode().Perm() != 0o700 {
		t.Fatal("the data directory (a volume root in Docker) was replaced")
	}
	if marker(e.dataDir) != "RESTORED" || e.ops.liveDir != "RESTORED" {
		t.Fatalf("after the rewind: %q live %q", marker(e.dataDir), e.ops.liveDir)
	}
	if exists(filepath.Join(e.dataDir, "base")) {
		t.Error("the original's entries are still in the data directory")
	}
	// Kept inside the volume, next to nothing outside it.
	if filepath.Dir(res.OldDataDir) != filepath.Join(e.dataDir, asideDirName) || !strings.HasPrefix(filepath.Base(res.OldDataDir), "main.before-rewind-") ||
		marker(res.OldDataDir) != "ORIGINAL" || !exists(filepath.Join(res.OldDataDir, "base/1")) {
		t.Fatalf("kept %s: %q", res.OldDataDir, marker(res.OldDataDir))
	}
	if s := e.siblings(); !slices.Equal(s, []string{"main"}) {
		t.Fatalf("wrote outside the data volume: %v", s)
	}
	if exists(stagingDir(e.dataDir, "rw_1")) {
		t.Error("the staging directory is left")
	}
	// Production's own configuration files in the data directory are kept.
	if hba, _ := os.ReadFile(filepath.Join(e.dataDir, "pg_hba.conf")); string(hba) != "# production hba\n" {
		t.Errorf("pg_hba.conf %q", hba)
	}
	if r, _ := e.a.rewindState().get("rw_1"); !r.Contents || r.Status != protocol.RewindKeptBefore {
		t.Fatalf("record %+v", r)
	}
	if !strings.Contains(log, "through the container control service") {
		t.Errorf("log:\n%s", log)
	}

	// Undo swaps the entries back.
	e.ops.calls = nil
	u, err := e.a.rewindUndo(t.Context(), e.db, protocol.RewindUndoParams{RewindID: "rw_1"}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if marker(e.dataDir) != "ORIGINAL" || marker(u.RewoundDataDir) != "RESTORED" || exists(res.OldDataDir) ||
		filepath.Dir(u.RewoundDataDir) != filepath.Join(e.dataDir, asideDirName) || !slices.Equal(e.ops.calls, []string{"stop", "timeline", "start", "ready"}) {
		t.Fatalf("undo: %q, rewound %s %q, calls %v", marker(e.dataDir), u.RewoundDataDir, marker(u.RewoundDataDir), e.ops.calls)
	}
	// Cleanup deletes it and the aside directory.
	if c, err := e.a.rewindCleanup(t.Context(), e.db, protocol.RewindCleanupParams{RewindID: "rw_1"}, &taskLog{}); err != nil || !c.Removed {
		t.Fatalf("cleanup: %+v %v", c, err)
	}
	e.dockerOriginal("after cleanup", before)
}

func TestDockerRewindRollsBack(t *testing.T) {
	for _, step := range []string{"restore", "recover", "start", "ready"} {
		t.Run(step, func(t *testing.T) {
			e, _ := newDockerEnv(t)
			before, _ := os.Stat(e.dataDir)
			e.ops.fail[step] = errors.New("boom")
			e.ops.failN[step] = 1
			res, err, log := e.rewind("rw_1")
			if err == nil || !res.RolledBack {
				t.Fatalf("err = %v, %+v\n%s", err, res, log)
			}
			e.dockerOriginal("after the rollback", before)
		})
	}
}

// A crash while entries were moving: the phase says which side holds what.
func TestDockerCrashRecovery(t *testing.T) {
	for _, tc := range []struct {
		name  string
		phase string
		// prepare moves things around as the crash left them.
		prepare func(e *inPlaceEnv, kept string)
	}{
		{"half set aside", phaseStopped, func(e *inPlaceEnv, kept string) {
			must(t, os.MkdirAll(kept, 0o700))
			for _, n := range []string{"base", "MARKER"} {
				must(t, os.Rename(filepath.Join(e.dataDir, n), filepath.Join(kept, n)))
			}
		}},
		{"set aside, restore half moved in", phaseRestored, func(e *inPlaceEnv, kept string) {
			must(t, moveData(true, e.dataDir, e.dataDir, kept))
			staging := stagingDir(e.dataDir, "rw_1")
			must(t, os.MkdirAll(filepath.Join(staging, "base"), 0o700))
			must(t, os.WriteFile(filepath.Join(staging, "MARKER"), []byte("RESTORED"), 0o600))
			must(t, os.WriteFile(filepath.Join(e.dataDir, "PG_VERSION"), []byte("18\n"), 0o600)) // moved in already
		}},
		{"set aside, restore running", phaseRestored, func(e *inPlaceEnv, kept string) {
			must(t, moveData(true, e.dataDir, e.dataDir, kept))
			must(t, os.MkdirAll(filepath.Join(stagingDir(e.dataDir, "rw_1"), "base"), 0o700))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newDockerEnv(t)
			before, _ := os.Stat(e.dataDir)
			must(t, ensureAsideRoot(e.dataDir))
			kept := filepath.Join(e.dataDir, asideDirName, "main.before-rewind-20260924T141000Z")
			tc.prepare(e, kept)
			e.ops.live = false
			must(t, e.a.rewindState().put(rewindRecord{ID: "rw_1", Kind: protocol.RewindKindKeptData, DatabaseID: "db_1",
				Status: protocol.RewindInProgress, Phase: tc.phase, DataDir: e.dataDir, KeptDir: kept, Database: e.db, Major: 18, Contents: true}))
			fresh := &Agent{cfg: e.a.cfg, log: e.a.log, rewindOps: e.ops, docker: dockerControl{call: e.a.docker.call}}
			fresh.recoverRewinds(t.Context())
			e.a = fresh
			e.dockerOriginal("after crash recovery", before)
		})
	}
}

func TestDockerUndoCrashRecovery(t *testing.T) {
	e, _ := newDockerEnv(t)
	before, _ := os.Stat(e.dataDir)
	res, err, log := e.rewind("rw_1")
	if err != nil {
		t.Fatal(err, log)
	}
	// Undo crashed half way through moving the kept data back in.
	aside := filepath.Join(e.dataDir, asideDirName, "main.after-rewind-20260925T100000Z")
	must(t, moveData(true, e.dataDir, e.dataDir, aside))
	must(t, os.Rename(filepath.Join(res.OldDataDir, "base"), filepath.Join(e.dataDir, "base")))
	e.ops.live = false
	must(t, e.a.rewindState().update("rw_1", func(r *rewindRecord) {
		r.Status, r.Undo, r.AsideDir, r.Phase = protocol.RewindInProgress, true, aside, phaseMoved
	}))
	fresh := &Agent{cfg: e.a.cfg, log: e.a.log, rewindOps: e.ops, docker: dockerControl{call: e.a.docker.call}}
	fresh.recoverRewinds(t.Context())
	// The rewound data runs again; the original is kept, whole.
	if marker(e.dataDir) != "RESTORED" || !e.ops.live || marker(res.OldDataDir) != "ORIGINAL" || !exists(filepath.Join(res.OldDataDir, "base/1")) ||
		exists(aside) {
		t.Fatalf("after recovery: data %q live %v kept %q", marker(e.dataDir), e.ops.live, marker(res.OldDataDir))
	}
	if r, _ := fresh.rewindState().get("rw_1"); r.Status != protocol.RewindKeptBefore || r.Undo {
		t.Fatalf("record %+v", r)
	}
	if after, _ := os.Stat(e.dataDir); !os.SameFile(before, after) {
		t.Fatal("data directory replaced")
	}
}

func TestDockerPreflightRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		setup func(e *inPlaceEnv, fc *fakeControl)
		want  string
	}{
		"no control service": {func(e *inPlaceEnv, _ *fakeControl) {
			e.a.docker.call = nil
			e.a.cfg.DockerControlSocket = "/nonexistent/x.sock"
		},
			"Allow Rowsafe to restart this container"},
		"control unreachable": {func(_ *inPlaceEnv, fc *fakeControl) { fc.err = dockerctl.ErrUnavailable }, "not reachable"},
		"control refuses": {func(_ *inPlaceEnv, fc *fakeControl) {
			fc.res = dockerctl.Response{Error: `found no container for the compose service "postgres" in project "myapp"`}
		}, "found no container"},
		"read-only volume": {func(e *inPlaceEnv, _ *fakeControl) {
			os.Chmod(e.dataDir, 0o500)
			e.t.Cleanup(func() { os.Chmod(e.dataDir, 0o700) })
		}, "without \":ro\""},
		"disk": {func(e *inPlaceEnv, _ *fakeControl) { e.ops.free = 1 << 20 }, "not enough free disk"},
		"foreign aside dir": {func(e *inPlaceEnv, _ *fakeControl) {
			os.Symlink("/etc", filepath.Join(e.dataDir, asideDirName))
		}, "refusing"},
	} {
		t.Run(name, func(t *testing.T) {
			e, fc := newDockerEnv(t)
			tc.setup(e, fc)
			_, err, _ := e.rewind("rw_1")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if slices.Contains(e.ops.calls, helperStop) {
				t.Errorf("stopped PostgreSQL after a refusal: %v", e.ops.calls)
			}
			if marker(e.dataDir) != "ORIGINAL" {
				t.Error("data touched")
			}
		})
	}
}

func TestDockerHeartbeatReport(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	must(t, os.Mkdir(dataDir, 0o700))
	fc := newFakeControl()
	a := &Agent{cfg: Config{Mode: ModeDockerSidecar}, docker: dockerControl{call: fc.call, dataDir: dataDir},
		watched: []protocol.DatabaseSpec{{Port: 5432}}, monitored: []protocol.DatabaseSpec{{Port: 5432}}}
	r := a.dockerControlReport(t.Context())
	if r == nil || !r.Found || r.Container != "myapp-postgres-1" || !r.DataWritable || r.DataDir != dataDir {
		t.Fatalf("report %+v", r)
	}
	if got := a.helperActions(); !slices.Equal(got, []string{"restart", "stop", "start"}) {
		t.Fatalf("actions %v", got)
	}
	if got := a.restartPorts(); !slices.Equal(got, []int{5432}) {
		t.Fatalf("ports %v", got)
	}
	// Read-only data volume: restart only.
	must(t, os.Chmod(dataDir, 0o500))
	defer os.Chmod(dataDir, 0o700)
	a.docker.at = time.Time{}
	if got := a.helperActions(); !slices.Equal(got, []string{"restart"}) {
		t.Fatalf("read-only actions %v", got)
	}
	// The control service can't find PostgreSQL: nothing offered, the reason reported.
	fc.res = dockerctl.Response{Error: "found no container"}
	a.docker.at = time.Time{}
	if got := a.helperActions(); got != nil || a.restartPorts() != nil {
		t.Fatalf("broken control: %v %v", got, a.restartPorts())
	}
	if r := a.dockerControlReport(t.Context()); !r.Found || r.Error != "found no container" {
		t.Fatalf("report %+v", r)
	}
	// Not set up: a report saying so, nothing offered.
	a = &Agent{cfg: Config{Mode: ModeDockerSidecar, DockerControlSocket: filepath.Join(root, "missing.sock")}}
	if r := a.dockerControlReport(t.Context()); r == nil || r.Found || a.helperActions() != nil {
		t.Fatalf("not set up: %+v", r)
	}
	// Native agents report nothing.
	if (&Agent{cfg: Config{Mode: ModeNative}}).dockerControlReport(t.Context()) != nil {
		t.Fatal("native report")
	}
}

func TestDockerRestartTask(t *testing.T) {
	old := restartPoll
	restartPoll = time.Millisecond
	t.Cleanup(func() { restartPoll = old })
	fc := newFakeControl()
	fc.states = []string{"restarting", "running"}
	answered := 0
	a := &Agent{cfg: Config{Mode: ModeDockerSidecar}, docker: dockerControl{call: fc.call},
		pgArchiveMode: func(context.Context, pginspect.Target) (string, error) {
			if answered++; answered < 2 {
				return "", errors.New("the database system is starting up")
			}
			return "on", nil
		}}
	tl := &taskLog{}
	res, err := a.restart(t.Context(), protocol.DatabaseSpec{Port: 5432}, "task_1", tl)
	if err != nil {
		t.Fatal(err, tl.String())
	}
	if !res.Restarted || res.Unit != "myapp-postgres-1" || res.ArchiveMode != "on" || !slices.Equal(fc.calls, []string{"restart", "inspect", "inspect"}) {
		t.Fatalf("result %+v, calls %v", res, fc.calls)
	}

	// A container that dies right after the restart fails plainly.
	fc = newFakeControl()
	fc.res.ExitCode = 1
	fc.states = []string{"exited"}
	a.docker.call = fc.call
	if _, err := a.restart(t.Context(), protocol.DatabaseSpec{Port: 5432}, "task_2", &taskLog{}); err == nil || !strings.Contains(err.Error(), "exit code 1") {
		t.Fatalf("exited: %v", err)
	}
	// Rate limited by the control service.
	fc = newFakeControl()
	fc.res = dockerctl.Response{Error: "the container was restarted less than 1m0s ago; try again in 40 seconds"}
	a.docker.call = fc.call
	if _, err := a.restart(t.Context(), protocol.DatabaseSpec{Port: 5432}, "task_3", &taskLog{}); err == nil || !strings.Contains(err.Error(), "try again in 40 seconds") {
		t.Fatalf("rate limited: %v", err)
	}
	// Not set up: the plain next step.
	a = &Agent{cfg: Config{Mode: ModeDockerSidecar, DockerControlSocket: "/nonexistent/x.sock"}}
	if _, err := a.restart(t.Context(), protocol.DatabaseSpec{Port: 5432}, "task_4", &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "Allow Rowsafe to restart this container") || !strings.Contains(err.Error(), "docker compose restart") {
		t.Fatalf("not set up: %v", err)
	}
}

// In Docker, pg_ctl must never signal the pid in PostgreSQL's
// postmaster.pid: in the agent's container that pid is someone else.
func TestDockerStopLocalNeverSignalsForeignPids(t *testing.T) {
	dir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(dir, "postmaster.pid"), []byte("1\n"+dir+"\n"), 0o600))
	a := &Agent{cfg: Config{Mode: ModeDockerSidecar, PGBinDir: "/nonexistent/%d/bin"}, runner: failRunner{t}}
	if err := (realInPlaceOps{a}).stopLocal(dir, 18); !errors.Is(err, errNotLocalPostmaster) {
		t.Fatalf("stopLocal: %v", err)
	}
	if localPostmaster(dir) {
		t.Fatal("pid 1 taken for a local postmaster")
	}
	must(t, os.Remove(filepath.Join(dir, "postmaster.pid")))
	if err := (realInPlaceOps{a}).stopLocal(dir, 18); err != nil {
		t.Fatalf("nothing to stop: %v", err)
	}
}

type failRunner struct{ t *testing.T }

func (f failRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.t.Fatalf("ran %s %v", name, args)
	return nil, nil
}

func TestContentsPaths(t *testing.T) {
	d := "/var/lib/postgresql/data"
	for _, c := range []struct {
		p    string
		kind string
		ok   bool
	}{
		{d + "/.rowsafe-rewind/data.failed-rewind-20260925T100000Z", "failed", true},
		{"/var/lib/postgresql/data.failed-rewind-20260925T100000Z", "failed", true},
		{d + "/.rowsafe-rewind/other.failed-rewind-20260925T100000Z", "failed", false},
		{d + "/base", "failed", false},
		{"/tmp/.rowsafe-rewind/data.failed-rewind-x", "failed", false},
	} {
		if got := isAsidePath(d, c.p, c.kind); got != c.ok {
			t.Errorf("isAsidePath(%s) = %v", c.p, got)
		}
	}
	if err := validKeptDir(d, "/etc/data.before-rewind-20260925T100000Z"); err == nil {
		t.Error("kept dir elsewhere accepted")
	}
	if volumeMountHint("/var/lib/postgresql/18/docker") != "/var/lib/postgresql" || volumeMountHint(d) != d {
		t.Error("volumeMountHint")
	}
	if err := freshDir("/tmp/restore-x"); err == nil {
		t.Error("freshDir outside the aside directory")
	}
}
