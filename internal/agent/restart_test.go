package agent

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestReadRestartAllowed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "restart-allowed")
	if m, err := ReadRestartAllowed(p); err != nil || len(m) != 0 {
		t.Fatalf("missing file: %v %v", m, err)
	}
	os.WriteFile(p, []byte("# Rowsafe may restart these\n5432 postgresql@18-main.service\n\n5433 not-a-unit\nx y.service\n70000 big.service\n5434 postgresql@16-b.service extra\n"), 0o644)
	m, err := ReadRestartAllowed(p)
	if err != nil || len(m) != 2 || m[5432] != "postgresql@18-main.service" || m[5434] != "postgresql@16-b.service" {
		t.Fatalf("allowed %v %v", m, err)
	}
	a := &Agent{cfg: Config{RestartAllowFile: p}, log: slog.New(slog.DiscardHandler)}
	if ports := a.restartPorts(); len(ports) != 2 || ports[0] != 5432 || ports[1] != 5434 {
		t.Errorf("heartbeat ports %v", ports)
	}
	a.cfg.Mode = ModeDockerSidecar
	if ports := a.restartPorts(); ports != nil {
		t.Errorf("sidecar ports %v", ports)
	}
}

// fakeHelper plays rowsafe-pg-restart: it answers the next request in dir
// with a result in out (its own directory).
func fakeHelper(t *testing.T, dir, out string, answer func(id, port string) string) {
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(filepath.Join(dir, "request"))
			if err == nil {
				os.Remove(filepath.Join(dir, "request"))
				f := strings.Fields(string(data))
				os.WriteFile(filepath.Join(out, "result.tmp"), []byte(answer(f[0], f[1])), 0o644)
				os.Rename(filepath.Join(out, "result.tmp"), filepath.Join(out, "result"))
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
}

func TestRestartTask(t *testing.T) {
	oldPoll, oldHelper, oldBack := restartPoll, restartHelperTimeout, restartBackTimeout
	defer func() { restartPoll, restartHelperTimeout, restartBackTimeout = oldPoll, oldHelper, oldBack }()
	restartPoll, restartHelperTimeout, restartBackTimeout = 5*time.Millisecond, 300*time.Millisecond, 200*time.Millisecond

	root := t.TempDir()
	allow := filepath.Join(root, "restart-allowed")
	dir := filepath.Join(root, "restart")
	out := filepath.Join(root, "run")
	os.Mkdir(out, 0o755)
	os.WriteFile(allow, []byte("5432 postgresql@18-main.service\n"), 0o644)
	os.Mkdir(dir, 0o700)
	down := 3 // PostgreSQL answers on the 4th try
	a := &Agent{cfg: Config{RestartAllowFile: allow, RestartDir: dir, RestartResultDir: out, PGUser: "postgres"}, log: slog.New(slog.DiscardHandler),
		pgArchiveMode: func(context.Context, pginspect.Target) (string, error) {
			if down > 0 {
				down--
				return "", errors.New("connection refused")
			}
			return "on", nil
		}}
	db := protocol.DatabaseSpec{ID: "db_1", Name: "shop", Port: 5432, SocketDir: "/var/run/postgresql"}

	var gotReq string
	fakeHelper(t, dir, out, func(id, port string) string {
		gotReq = id + " " + port
		return "id=" + id + "\nok=1\nunit=postgresql@18-main.service\nfinished_at=1\n"
	})
	tl := &taskLog{}
	res, err := a.restart(t.Context(), db, "task_42", tl)
	if err != nil {
		t.Fatal(err, tl.String())
	}
	if gotReq != "task_42 5432" || !res.Restarted || res.Unit != "postgresql@18-main.service" || res.ArchiveMode != "on" || res.DurationMs <= 0 {
		t.Fatalf("request %q, result %+v", gotReq, res)
	}
	// An old answer (another request's) is not taken for this one's.
	if _, err := a.restart(t.Context(), db, "task_42b", tl); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("stale result: %v", err)
	}

	// The helper refuses (e.g. restarted a moment ago).
	fakeHelper(t, dir, out, func(id, port string) string {
		return "id=" + id + "\nok=0\nerror=PostgreSQL was restarted less than a minute ago; try again shortly\n"
	})
	if _, err := a.restart(t.Context(), db, "task_43", tl); err == nil || !strings.Contains(err.Error(), "less than a minute ago") {
		t.Fatalf("refused: %v", err)
	}

	// Nobody answers: the request is withdrawn.
	if _, err := a.restart(t.Context(), db, "task_44", tl); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("no helper: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "request")); !os.IsNotExist(err) {
		t.Error("an unanswered request was left behind")
	}

	// A port root didn't allow: refused before any request, with the command.
	other := db
	other.Port = 5433
	if _, err := a.restart(t.Context(), other, "task_45", tl); err == nil || !strings.Contains(err.Error(), "not turned on for port 5433") ||
		!strings.Contains(err.Error(), "sudo systemctl restart postgresql") {
		t.Fatalf("not allowed: %v", err)
	}
	a.cfg.Mode = ModeDockerSidecar
	if _, err := a.restart(t.Context(), db, "task_46", tl); err == nil || !strings.Contains(err.Error(), "docker compose restart") {
		t.Fatalf("sidecar: %v", err)
	}
}

// readyEngine is a MySQL engine that can be restarted: it answers on the
// third Ready.
type readyEngine struct {
	fakeEngine
	tries int
}

func (r *readyEngine) Ready(context.Context, EngineEnv, protocol.DatabaseSpec) (string, error) {
	r.tries++
	if r.tries < 3 {
		return "", errors.New("connection refused")
	}
	return "on", nil
}

func TestRestartTaskEngine(t *testing.T) {
	oldPoll, oldHelper, oldBack := restartPoll, restartHelperTimeout, restartBackTimeout
	defer func() { restartPoll, restartHelperTimeout, restartBackTimeout = oldPoll, oldHelper, oldBack }()
	restartPoll, restartHelperTimeout, restartBackTimeout = 5*time.Millisecond, 300*time.Millisecond, 200*time.Millisecond

	root := t.TempDir()
	allow := filepath.Join(root, "restart-allowed")
	dir := filepath.Join(root, "restart")
	out := filepath.Join(root, "run")
	os.Mkdir(out, 0o755)
	os.Mkdir(dir, 0o700)
	os.WriteFile(allow, []byte("3306 mysql.service\n"), 0o644)
	a := &Agent{cfg: Config{RestartAllowFile: allow, RestartDir: dir, RestartResultDir: out, StateDir: root}, log: slog.New(slog.DiscardHandler)}
	db := &protocol.DatabaseSpec{ID: "db_m", Name: "shop", Port: 3306, Engine: protocol.EngineMySQL}

	// An engine that can't be restarted: the engine's own "update the agent".
	plain := &fakeEngine{name: protocol.EngineMySQL}
	withEngine(t, plain)
	tl := &taskLog{}
	if _, err := a.runTask(t.Context(), &protocol.Task{ID: "t1", Type: protocol.TaskRestart, Database: db}, tl); err == nil ||
		!strings.Contains(err.Error(), "can't run restart tasks for MySQL") {
		t.Fatalf("plain engine: %v", err)
	}
	enginesMu.Lock()
	delete(engines, protocol.EngineMySQL)
	enginesMu.Unlock()

	e := &readyEngine{fakeEngine: fakeEngine{name: protocol.EngineMySQL}}
	withEngine(t, e)
	var gotReq string
	fakeHelper(t, dir, out, func(id, port string) string {
		gotReq = id + " " + port
		return "id=" + id + "\nok=1\nunit=mysql.service\nfinished_at=1\n"
	})
	res, err := a.runTask(t.Context(), &protocol.Task{ID: "t2", Type: protocol.TaskRestart, Database: db}, tl)
	if err != nil {
		t.Fatal(err, tl.String())
	}
	r := res.(*protocol.RestartResult)
	if gotReq != "t2 3306" || !r.Restarted || r.Unit != "mysql.service" || r.ArchiveMode != "on" || e.tries != 3 {
		t.Fatalf("request %q, result %+v, tries %d", gotReq, r, e.tries)
	}
	if !strings.Contains(tl.String(), "MySQL is back after") {
		t.Errorf("log %q", tl.String())
	}

	// A port root didn't allow: MySQL's own command.
	other := *db
	other.Port = 3307
	if _, err := a.restart(t.Context(), other, "t3", tl); err == nil || !strings.Contains(err.Error(), "restarting MySQL from Rowsafe is not turned on for port 3307") ||
		!strings.Contains(err.Error(), "sudo systemctl restart mysql") {
		t.Fatalf("not allowed: %v", err)
	}

	// In another engine's agent image (no sidecar): restart it yourself.
	a.cfg.ImageVariant = "clickhouse26.8"
	if _, err := a.restart(t.Context(), *db, "t4", tl); err == nil || !strings.Contains(err.Error(), "docker compose restart mysql") {
		t.Fatalf("container: %v", err)
	}
}

// emptyEngine is a Redis engine whose server keeps nothing on its own
// disk: it refuses every restart.
type emptyEngine struct {
	versionEngine
	asked int
}

func (e *emptyEngine) RestartRefusal(context.Context, EngineEnv, protocol.DatabaseSpec) string {
	e.asked++
	return "Rowsafe doesn't restart Redis: it keeps nothing on its own disk."
}

func TestRestartRefusedByEngine(t *testing.T) {
	root := t.TempDir()
	allow := filepath.Join(root, "restart-allowed")
	dir := filepath.Join(root, "restart")
	os.Mkdir(dir, 0o700)
	os.WriteFile(allow, []byte("6379 redis-server.service\n"), 0o644)
	a := &Agent{cfg: Config{RestartAllowFile: allow, RestartDir: dir, RestartResultDir: root, StateDir: root}, log: slog.New(slog.DiscardHandler)}
	db := protocol.DatabaseSpec{ID: "db_r", Name: "cache", Port: 6379, Engine: protocol.EngineRedis}
	e := &emptyEngine{versionEngine: versionEngine{readyEngine: readyEngine{fakeEngine: fakeEngine{name: protocol.EngineRedis}}, version: "7.4.6"}}
	withEngine(t, e)
	helped := false
	fakeHelper(t, dir, root, func(id, port string) string {
		helped = true
		return "id=" + id + "\nok=1\nunit=redis-server.service\nfinished_at=1\n"
	})
	tl := &taskLog{}
	// Through root's helper, and through the container control service:
	// refused before either is asked.
	for _, mode := range []string{"", ModeDockerSidecar} {
		a.cfg.Mode = mode
		if _, err := a.restart(t.Context(), db, "t1", tl); err == nil || !strings.Contains(err.Error(), "keeps nothing on its own disk") {
			t.Fatalf("mode %q: %v", mode, err)
		}
	}
	if helped || e.tries != 0 || e.asked != 2 {
		t.Fatalf("restarted anyway (helper %v, ready %d, asked %d)", helped, e.tries, e.asked)
	}

	// Updates and an upgrade's undo restart it too: refused before root's
	// helper is asked.
	u := newUpgradeEnv(t)
	os.WriteFile(u.a.cfg.RestartAllowFile, []byte("6379 redis-server.service\n"), 0o644)
	os.WriteFile(u.a.cfg.UpdateAllowFile, []byte("database\n"), 0o644)
	os.WriteFile(u.a.cfg.RestartHelper, []byte("#!/bin/sh\n# update-actions: db-minor-update db-upgrade-undo\n"), 0o755)
	if _, err := u.a.engineUpdate(t.Context(), db, "t2", tl); err == nil || !strings.Contains(err.Error(), "keeps nothing on its own disk") {
		t.Fatalf("update: %v", err)
	}
	st := u.a.upgradeState()
	if err := st.put(upgradeRecord{ID: "up_1", DatabaseID: db.ID, Status: protocol.UpgradeDone, FromMajor: 7}); err != nil {
		t.Fatal(err)
	}
	if _, err := u.a.engineUpgradeUndo(t.Context(), db, protocol.UpgradeUndoParams{UpgradeID: "up_1"}, "t3", tl); err == nil ||
		!strings.Contains(err.Error(), "keeps nothing on its own disk") {
		t.Fatalf("undo: %v", err)
	}
	if len(u.asked) != 0 || e.asked != 4 {
		t.Fatalf("helper asked %q, refusal asked %d", u.asked, e.asked)
	}
}
