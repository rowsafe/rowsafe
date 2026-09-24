package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// fakeRepo stands in for `pgbackrest archive-push`: it keeps what was
// pushed, accepts an identical re-push and refuses a different one, like
// pgBackRest does.
type fakeRepo struct {
	mu     sync.Mutex
	files  map[string]string
	order  []string
	failOn map[string]error // file name -> error to return
	// afterPush runs after a successful push, before the pusher deletes
	// the file (to simulate a crash in between).
	afterPush func(name string)
}

func (r *fakeRepo) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if len(args) >= 3 && args[len(args)-3] == "archive-get" {
		wal, dest := args[len(args)-2], args[len(args)-1]
		r.mu.Lock()
		data, ok := r.files[wal]
		r.mu.Unlock()
		if !ok {
			return []byte("P00   INFO: unable to find " + wal + " in the archive"), errors.New("exit status 1")
		}
		return nil, os.WriteFile(dest, []byte(data), 0o600)
	}
	if len(args) < 2 || args[len(args)-2] != "archive-push" {
		return nil, fmt.Errorf("unexpected command %s %v", name, args)
	}
	path := args[len(args)-1]
	file := filepath.Base(path)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.failOn[file]; err != nil {
		return []byte("P00  ERROR: [045]: " + err.Error() + "\n"), err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []byte("P00  ERROR: [055]: unable to open missing file"), err
	}
	if old, ok := r.files[file]; ok && old != string(data) {
		return []byte("P00  ERROR: [045]: WAL file already exists in the repo1 archive with a different checksum"), errors.New("exit status 45")
	}
	r.files[file] = string(data)
	r.order = append(r.order, file)
	if r.afterPush != nil {
		r.afterPush(file)
	}
	return nil, nil
}

type pusherEnv struct {
	root   string
	repo   *fakeRepo
	p      *spoolPusher
	now    time.Time
	hasCfg bool
}

func newPusherEnv(t *testing.T) *pusherEnv {
	t.Helper()
	e := &pusherEnv{root: t.TempDir(), repo: &fakeRepo{files: map[string]string{}, failOn: map[string]error{}}, hasCfg: true}
	e.now = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	e.p = newSpoolPusher(e.root, 5*time.Minute, slog.New(slog.DiscardHandler), func(stanza string) (pgbackrest.CLI, bool) {
		return pgbackrest.CLI{Bin: "pgbackrest", ConfigPath: "/cfg/" + stanza + ".conf", Stanza: stanza, Runner: e.repo}, e.hasCfg
	})
	e.p.now = func() time.Time { return e.now }
	must(t, os.MkdirAll(filepath.Join(e.root, "app"), 0o700))
	return e
}

func (e *pusherEnv) spool(t *testing.T, name, content string, age time.Duration) {
	t.Helper()
	path := filepath.Join(e.root, "app", name)
	must(t, os.WriteFile(path, []byte(content), 0o600))
	must(t, os.Chtimes(path, e.now.Add(-age), e.now.Add(-age)))
}

func (e *pusherEnv) left(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(e.root, "app"))
	must(t, err)
	var out []string
	for _, x := range entries {
		out = append(out, x.Name())
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSpoolPusherPushesInOrderAndDeletesAfterPush(t *testing.T) {
	e := newPusherEnv(t)
	// Written out of order on purpose; a history file and a backup history
	// file sort into place between segments.
	for _, n := range []string{"000000010000000000000003", "00000002.history", "000000010000000000000001",
		"000000010000000000000002.00000028.backup", "000000010000000000000002", "000000020000000000000003"} {
		e.spool(t, n, "wal "+n, time.Second)
	}
	e.spool(t, "000000010000000000000004.tmp", "being copied", time.Second) // archive_command in progress
	e.spool(t, "notes.txt", "not WAL", time.Second)
	e.p.pass(context.Background())

	want := []string{"000000010000000000000001", "000000010000000000000002", "000000010000000000000002.00000028.backup",
		"000000010000000000000003", "00000002.history", "000000020000000000000003"}
	if strings.Join(e.repo.order, ",") != strings.Join(want, ",") {
		t.Errorf("push order\n got %v\nwant %v", e.repo.order, want)
	}
	if got := strings.Join(e.left(t), ","); got != "000000010000000000000004.tmp,notes.txt" {
		t.Errorf("left in spool: %s", got)
	}
	s := e.p.Status("app")
	if s.PushedCount != 6 || s.LastPushed != "000000020000000000000003" || s.Files != 0 || s.FailedCount != 0 {
		t.Errorf("status %+v", s)
	}
}

func TestSpoolPusherStopsAtFirstFailureAndKeepsFiles(t *testing.T) {
	e := newPusherEnv(t)
	for _, n := range []string{"000000010000000000000001", "000000010000000000000002", "000000010000000000000003"} {
		e.spool(t, n, "wal "+n, time.Second)
	}
	e.repo.failOn["000000010000000000000002"] = errors.New("exit status 49")
	e.p.pass(context.Background())
	if strings.Join(e.repo.order, ",") != "000000010000000000000001" {
		t.Errorf("a later file must not be pushed past a failure: %v", e.repo.order)
	}
	if got := strings.Join(e.left(t), ","); got != "000000010000000000000002,000000010000000000000003" {
		t.Errorf("failed and later files must stay in the spool, left %s", got)
	}
	s := e.p.Status("app")
	if s.FailedCount != 1 || !strings.Contains(s.LastError, "000000010000000000000002") || !strings.Contains(s.LastError, "ERROR: [045]") {
		t.Errorf("status %+v", s)
	}

	// Backoff: an immediate pass does not retry.
	e.p.pass(context.Background())
	if len(e.repo.order) != 1 || e.p.Status("app").FailedCount != 1 {
		t.Error("a retry must wait for the backoff")
	}
	// After the backoff, with the repository fixed, everything drains.
	delete(e.repo.failOn, "000000010000000000000002")
	e.now = e.now.Add(2 * time.Second)
	e.p.pass(context.Background())
	if len(e.left(t)) != 0 || len(e.repo.order) != 3 {
		t.Errorf("spool should drain: left %v, pushed %v", e.left(t), e.repo.order)
	}
}

func TestSpoolPusherBackoffGrows(t *testing.T) {
	e := newPusherEnv(t)
	e.spool(t, "000000010000000000000001", "x", time.Second)
	e.repo.failOn["000000010000000000000001"] = errors.New("exit status 49")
	var delays []time.Duration
	for range 9 {
		start := e.now
		e.p.pass(context.Background())
		e.p.mu.Lock()
		next := e.p.stanzas["app"].nextAttempt
		e.p.mu.Unlock()
		delays = append(delays, next.Sub(start))
		e.now = next
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i, d := range delays {
		if d != want[i]*time.Second {
			t.Fatalf("backoff %v, want seconds %v", delays, want)
		}
	}
}

// A crash after pgBackRest stored the file but before the pusher deleted
// it: the next agent pushes it again, which the repository accepts because
// it is identical, and then deletes it.
func TestSpoolPusherCrashBetweenPushAndDelete(t *testing.T) {
	e := newPusherEnv(t)
	e.spool(t, "000000010000000000000001", "one", time.Second)
	e.spool(t, "000000010000000000000002", "two", time.Second)
	ctx, crash := context.WithCancel(context.Background())
	e.repo.afterPush = func(name string) {
		if name == "000000010000000000000001" {
			crash() // the process dies right after the push
		}
	}
	// With ctx cancelled the push still "succeeds" in the fake, so emulate
	// the crash by restoring the file the pusher would not have deleted.
	e.p.pass(ctx)
	if _, err := os.Stat(filepath.Join(e.root, "app", "000000010000000000000002")); err != nil {
		t.Fatal("the second file must still be spooled")
	}
	e.spool(t, "000000010000000000000001", "one", time.Second) // not deleted before the crash

	e.repo.afterPush = nil
	fresh := newSpoolPusher(e.root, 5*time.Minute, slog.New(slog.DiscardHandler), e.p.cli)
	fresh.now = e.p.now
	fresh.pass(context.Background())
	if len(e.left(t)) != 0 {
		t.Errorf("spool should be empty after the restart, left %v", e.left(t))
	}
	if e.repo.files["000000010000000000000001"] != "one" || e.repo.files["000000010000000000000002"] != "two" {
		t.Errorf("repository %v", e.repo.files)
	}
	if s := fresh.Status("app"); s.FailedCount != 0 {
		t.Errorf("an identical re-push is not a failure: %+v", s)
	}
}

func TestSpoolPusherNeverDeletesAConflictingFile(t *testing.T) {
	e := newPusherEnv(t)
	e.repo.files["000000010000000000000001"] = "what the repository has"
	e.spool(t, "000000010000000000000001", "something different", time.Second)
	e.p.pass(context.Background())
	if len(e.left(t)) != 1 || e.p.Status("app").FailedCount != 1 {
		t.Error("a file the repository holds differently must stay in the spool and count as a failure")
	}
}

func TestSpoolPusherWithoutConfig(t *testing.T) {
	e := newPusherEnv(t)
	e.hasCfg = false
	e.spool(t, "000000010000000000000001", "one", time.Second)
	e.p.pass(context.Background())
	s := e.p.Status("app")
	if len(e.repo.order) != 0 || s.FailedCount != 1 || !strings.Contains(s.LastError, "no pgBackRest configuration") {
		t.Errorf("status %+v", s)
	}
}

func TestSpoolPusherRemovesStaleTempFiles(t *testing.T) {
	e := newPusherEnv(t)
	e.spool(t, "000000010000000000000001.tmp", "old", 2*time.Hour)
	e.spool(t, "000000010000000000000002.tmp", "in progress", time.Minute)
	e.spool(t, "unrelated.tmp", "not ours", 2*time.Hour)
	e.p.pass(context.Background())
	if got := strings.Join(e.left(t), ","); got != "000000010000000000000002.tmp,unrelated.tmp" {
		t.Errorf("left %s", got)
	}
}

func TestSpoolStallCountsAsArchiveFailure(t *testing.T) {
	e := newPusherEnv(t)
	e.hasCfg = false // nothing can be pushed
	e.spool(t, "000000010000000000000001", "one", 10*time.Minute)
	e.spool(t, "000000010000000000000002", "two", time.Minute)
	if s := e.p.Status("app"); !s.Stalled || s.FailedCount != 0 {
		t.Errorf("Status must not count: %+v", s)
	}
	s := e.p.Report("app")
	if !s.Stalled || s.Files != 2 || s.Bytes != 6 || s.OldestName != "000000010000000000000001" || s.FailedCount != 1 {
		t.Errorf("report %+v", s)
	}
	if !strings.Contains(s.LastError, "stalled") {
		t.Errorf("last error %q", s.LastError)
	}
	if s := e.p.Report("app"); s.FailedCount != 2 {
		t.Errorf("each stalled report counts, got %d", s.FailedCount)
	}

	// A young backlog is not a stall.
	e2 := newPusherEnv(t)
	e2.hasCfg = false
	e2.spool(t, "000000010000000000000001", "one", time.Minute)
	if s := e2.p.Report("app"); s.Stalled || s.FailedCount != 0 {
		t.Errorf("young backlog: %+v", s)
	}
}

func TestSidecarArchiverStats(t *testing.T) {
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	at := func(m int) *time.Time { x := t0.Add(time.Duration(m) * time.Minute); return &x }
	pg := protocol.ArchiverStats{DatabaseID: "db1", ArchivedCount: 40, FailedCount: 1, LastArchivedTime: at(10), LastFailedTime: at(1)}

	// Healthy: empty spool, pushes up to date.
	got := sidecarArchiverStats(pg, SpoolStatus{PushedCount: 5, LastPushed: "000000010000000000000009", LastPushedAt: t0.Add(10*time.Minute + time.Second)})
	if got.Mode != ModeDockerSidecar || got.SpooledCount != 40 || *got.LastSpooledTime != *at(10) {
		t.Errorf("PostgreSQL's view must be kept in the spool fields: %+v", got)
	}
	if got.ArchivedCount != 5 || !got.LastArchivedTime.Equal(t0.Add(10*time.Minute+time.Second)) || got.FailedCount != 1 || !got.LastFailedTime.Equal(*at(1)) {
		t.Errorf("healthy: %+v", got)
	}

	// Empty spool after an agent restart (no push yet): PostgreSQL's last
	// archive is in the repository too.
	got = sidecarArchiverStats(pg, SpoolStatus{})
	if got.LastArchivedTime == nil || !got.LastArchivedTime.Equal(*at(10)) {
		t.Errorf("empty spool: %+v", got)
	}

	// Backlog with failing pushes: the repository side is what counts.
	got = sidecarArchiverStats(pg, SpoolStatus{Files: 3, Bytes: 48 << 20, Oldest: t0.Add(11 * time.Minute), LastPushedAt: t0.Add(5 * time.Minute),
		FailedCount: 7, LastFailedAt: t0.Add(20 * time.Minute), LastError: "boom", Stalled: true})
	if !got.LastArchivedTime.Equal(t0.Add(5*time.Minute)) || got.FailedCount != 8 || !got.LastFailedTime.Equal(*at(20)) {
		t.Errorf("backlog: %+v", got)
	}
	if got.SpoolFiles != 3 || got.SpoolBytes != 48<<20 || !got.SpoolStalled || got.LastPushError != "boom" || !got.SpoolOldestTime.Equal(*at(11)) {
		t.Errorf("backlog spool fields: %+v", got)
	}
	// This is what the WAL archiving alert looks at.
	if !got.LastFailedTime.After(*got.LastArchivedTime) {
		t.Error("a failing pusher must look like failing archiving")
	}

	// Backlog, never pushed since start: no claim about the repository.
	got = sidecarArchiverStats(pg, SpoolStatus{Files: 1, Oldest: t0})
	if got.LastArchivedTime != nil {
		t.Errorf("with a backlog and no push, last archived must be unknown, got %v", got.LastArchivedTime)
	}
}

func TestHealth(t *testing.T) {
	e := newPusherEnv(t)
	cfg := Config{StateDir: t.TempDir()}
	if _, err := CheckHealth(cfg, e.now); err == nil {
		t.Error("no health file yet must be unhealthy")
	}
	e.spool(t, "000000010000000000000001", "one", time.Minute)
	e.p.writeHealth(healthPath(cfg))
	if _, err := CheckHealth(cfg, e.now.Add(time.Minute)); err != nil {
		t.Errorf("fresh report with a young backlog: %v", err)
	}
	if _, err := CheckHealth(cfg, e.now.Add(healthMaxAge+time.Second)); err == nil {
		t.Error("a stale report must be unhealthy")
	}
	e.hasCfg = false
	e.p.pass(context.Background())
	e.now = e.now.Add(10 * time.Minute)
	e.p.writeHealth(healthPath(cfg))
	if _, err := CheckHealth(cfg, e.now); err == nil || !strings.Contains(err.Error(), "stuck in the spool") {
		t.Errorf("a stalled spool must be unhealthy, got %v", err)
	}
}

func TestDrillAuthMapsUsers(t *testing.T) {
	if hba, ident := drillAuth("postgres", "postgres"); hba != "local all all peer\n" || ident != "" {
		t.Errorf("same user: %q %q", hba, ident)
	}
	hba, ident := drillAuth("postgres", "app")
	if hba != "local all all peer map=rowsafe\n" || ident != "rowsafe postgres app\n" {
		t.Errorf("mapped: %q %q", hba, ident)
	}
}

func TestConfigMode(t *testing.T) {
	t.Setenv("ROWSAFE_URL", "https://rowsafe.example")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.Mode != ModeNative || cfg.Sidecar() {
		t.Fatalf("default mode: %v %v", cfg.Mode, err)
	}
	t.Setenv("ROWSAFE_MODE", "docker-sidecar")
	t.Setenv("ROWSAFE_AUTO_UPDATE", "true")
	cfg, err = ConfigFromEnv()
	if err != nil || !cfg.Sidecar() || cfg.SpoolDir != "/rowsafe-spool" || cfg.SpoolStallAfter != 5*time.Minute {
		t.Fatalf("sidecar: %+v %v", cfg, err)
	}
	if cfg.AutoUpdate {
		t.Error("self-update must be off in a container")
	}
	if u, reason := NewUpdater(cfg, slog.New(slog.DiscardHandler)); u != nil || !strings.Contains(reason, "image tag") {
		t.Errorf("updater %v, reason %q", u, reason)
	}
	t.Setenv("ROWSAFE_SPOOL_DIR", "spool")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("a relative spool dir must be refused")
	}
	t.Setenv("ROWSAFE_SPOOL_DIR", "/rowsafe-spool")
	t.Setenv("ROWSAFE_MODE", "kubernetes")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("an unknown mode must be refused")
	}
}

func TestConfirmInRepository(t *testing.T) {
	defer func(d time.Duration) { restorePointPoll = d }(restorePointPoll)
	restorePointPoll = 10 * time.Millisecond
	e := newPusherEnv(t)
	e.p.now = time.Now
	a := &Agent{cfg: Config{SpoolDir: e.root, ConfigDir: "/cfg", PgBackRestBin: "pgbackrest"}, runner: e.repo, pusher: e.p,
		log: slog.New(slog.DiscardHandler)}
	db := protocol.DatabaseSpec{Stanza: "app"}
	seg := "000000010000000000000007"

	// Spooled, then pushed by the running pusher: confirmed.
	e.spool(t, seg, "restore point segment", 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go e.p.Run(ctx)
	tl := &taskLog{}
	if err := a.confirmInRepository(ctx, db, seg, tl); err != nil {
		t.Fatalf("confirm: %v\n%s", err, tl)
	}
	if !strings.Contains(tl.String(), "archive-get fetched") {
		t.Errorf("log: %s", tl)
	}
	cancel()

	// Stuck in the spool: not confirmed, and the push error is explained.
	e2 := newPusherEnv(t)
	e2.p.now = time.Now
	e2.repo.failOn["000000010000000000000008"] = errors.New("exit status 49: unable to reach the repository")
	a.cfg.SpoolDir, a.runner, a.pusher = e2.root, e2.repo, e2.p
	e2.spool(t, "000000010000000000000008", "x", 0)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	go e2.p.Run(ctx2)
	short, cancel3 := context.WithTimeout(ctx2, 300*time.Millisecond)
	defer cancel3()
	err := a.confirmInRepository(short, db, "000000010000000000000008", &taskLog{})
	if err == nil || !strings.Contains(err.Error(), "still waiting in the spool") || !strings.Contains(err.Error(), "unable to reach") {
		t.Errorf("stuck: %v", err)
	}

	// Gone from the spool but not in the repository (e.g. deleted by
	// hand): archive-get is the proof, so this is not confirmed.
	err = a.confirmInRepository(ctx2, db, "000000010000000000000009", &taskLog{})
	if err == nil || !strings.Contains(err.Error(), "archive-get") {
		t.Errorf("missing from repository: %v", err)
	}
}
