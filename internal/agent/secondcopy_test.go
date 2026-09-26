package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// scriptedRunner answers pgBackRest calls by the config file and command.
type scriptedRunner struct {
	mu    sync.Mutex
	calls []string
	fail  map[string]bool   // "<config base> <command>" -> fail
	out   map[string][]byte // "<config base> <command>" -> output
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var conf, cmd string
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "--config="); ok {
			conf = filepath.Base(v)
		} else if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "/") {
			cmd = a
		}
	}
	key := conf + " " + cmd
	r.calls = append(r.calls, key)
	if r.fail[key] {
		return []byte("ERROR: [039]: HTTP request failed: connection refused"), errors.New("exit status 39")
	}
	return r.out[key], nil
}

func (r *scriptedRunner) called(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c == key {
			n++
		}
	}
	return n
}

func secondCopyTestAgent(t *testing.T, mode string) (*Agent, *scriptedRunner) {
	t.Helper()
	root := t.TempDir()
	cfg := Config{StateDir: root, ConfigDir: filepath.Join(root, "conf"), LogDir: filepath.Join(root, "log"),
		PgBackRestBin: "/usr/bin/pgbackrest", Mode: mode, SpoolDir: filepath.Join(root, "spool"),
		SpoolStallAfter: 5 * time.Minute, PGUser: "postgres",
		SecondCopyQueueDir: filepath.Join(root, "queue"),
		Repo: pgbackrest.Repo{Endpoint: "abc.r2.cloudflarestorage.com", Bucket: "one", Key: "k", KeySecret: "s",
			CipherPass: strings.Repeat("a", 24)},
		Repo2: pgbackrest.Repo{Endpoint: "s3.us-west-004.backblazeb2.com", Bucket: "two", Region: "us-west-004", Key: "k2",
			KeySecret: "s2", CipherPass: strings.Repeat("b", 24)},
	}
	a := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r := &scriptedRunner{fail: map[string]bool{}, out: map[string][]byte{}}
	a.runner = r
	a.watched = []protocol.DatabaseSpec{{ID: "db_1", Name: "app", Stanza: "app", Port: 5432, SocketDir: "/run/postgresql", RetentionFull: 2}}
	return a, r
}

func TestSecondCopyConfigAndCommands(t *testing.T) {
	a, _ := secondCopyTestAgent(t, ModeNative)
	db := a.watched[0]
	a.writeSecondCopyConfig(db, protocol.InspectResult{DataDirectory: "/var/lib/postgresql/18/main"}, "/var/log/rowsafe")
	conf, err := os.ReadFile(a.cfg.secondCopyConfigPath("app"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"repo1-s3-bucket=two\n", "repo1-s3-endpoint=s3.us-west-004.backblazeb2.com\n",
		"repo1-cipher-pass=" + strings.Repeat("b", 24) + "\n", "repo1-retention-full=2\n", "lock-path=" + secondCopyLockPath + "\n"} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("second copy config lacks %q", want)
		}
	}
	if strings.Contains(string(conf), "bucket=one") || strings.Contains(string(conf), strings.Repeat("a", 24)) {
		t.Error("second copy config mentions the first storage")
	}
	cmd, err := a.nativeArchiveCommand(db)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, filepath.Join(a.cfg.SecondCopyQueueDir, "app")) || !a.ownArchiveCommand(db)(cmd) {
		t.Errorf("archive_command %q", cmd)
	}
	plain, _ := pgbackrest.ArchiveCommand(a.cfg.PgBackRestBin, a.cfg.configPath("app"), "app")
	if !a.ownArchiveCommand(db)(plain) {
		t.Error("the plain command isn't recognized as Rowsafe's")
	}
	// The planner replaces its own plain command without force.
	in := protocol.InspectResult{IsSuperuser: true, VersionNum: 180000, DataDirectory: "/d", WalLevel: "replica", ArchiveMode: "on",
		ArchiveCommand: plain, ArchiveTimeoutSeconds: 60}
	plan, err := PlanAdoptInput(in, PlanInput{Mode: ModeNative, ConfigPath: a.cfg.configPath("app"), ArchiveCommand: cmd, Own: a.ownArchiveCommand(db)})
	if err != nil {
		t.Fatalf("plan refused its own command: %v", err)
	}
	if plan.Settings["archive_command"] != cmd || len(plan.Warnings) != 0 {
		t.Errorf("plan %+v", plan)
	}
	// A foreign command still needs force.
	in.ArchiveCommand = "wal-g wal-push %p"
	if _, err := PlanAdoptInput(in, PlanInput{Mode: ModeNative, ConfigPath: a.cfg.configPath("app"), ArchiveCommand: cmd, Own: a.ownArchiveCommand(db)}); err == nil {
		t.Error("replaced a foreign archive_command without force")
	}

	// Without a second copy: the plain command, and no second config.
	a.cfg.Repo2 = pgbackrest.Repo{}
	if cmd, _ := a.nativeArchiveCommand(db); cmd != plain {
		t.Errorf("without a second copy: %q", cmd)
	}
	if _, err := a.repoCLI(db, protocol.RepoSecond); !errors.Is(err, errNoSecondCopy) {
		t.Errorf("repoCLI(2) without a second copy: %v", err)
	}
}

func TestSecondCopyIncompleteSettings(t *testing.T) {
	a, _ := secondCopyTestAgent(t, ModeNative)
	a.cfg.Repo2.KeySecret = ""
	if !a.cfg.SecondCopy() || a.cfg.SecondCopyError() == "" {
		t.Fatal("incomplete settings not reported")
	}
	// The first storage's work goes on: the plain command, no second config.
	db := a.watched[0]
	plain, _ := pgbackrest.ArchiveCommand(a.cfg.PgBackRestBin, a.cfg.configPath("app"), "app")
	if cmd, _ := a.nativeArchiveCommand(db); cmd != plain {
		t.Errorf("archive_command with incomplete second copy settings: %q", cmd)
	}
	sts := a.secondCopyStatuses()
	if len(sts) != 1 || !strings.Contains(sts[0].LastError, "ROWSAFE_REPO2_S3_KEY_SECRET") || sts[0].Provider != protocol.ProviderB2 {
		t.Errorf("statuses %+v", sts)
	}
}

func TestSecondCopyPusherAndGap(t *testing.T) {
	a, r := secondCopyTestAgent(t, ModeNative)
	db := a.watched[0]
	a.writeSecondCopyConfig(db, protocol.InspectResult{DataDirectory: "/d"}, "")
	dir, _ := a.cfg.secondCopyQueue("app")
	os.MkdirAll(dir, 0o700)
	for i := 1; i <= 3; i++ {
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("0000000100000000%08X", i)), []byte("wal"), 0o600)
	}
	// The second storage is down: stanza-create fails, nothing is sent,
	// the files stay, the error is reported.
	r.fail["app.copy2.conf stanza-create"] = true
	a.second.pusher.pass(context.Background())
	st := a.secondCopyStatuses()[0]
	if st.Ready || st.QueuedFiles != 3 || st.FailingSince == nil || !strings.Contains(st.LastError, "connection refused") {
		t.Fatalf("while down: %+v", st)
	}
	if r.called("app.conf archive-push") != 0 {
		t.Fatal("pushed to the first storage")
	}
	// It comes back: everything goes out, in order.
	delete(r.fail, "app.copy2.conf stanza-create")
	a.second.pusher.stanzas["app"].nextAttempt = time.Time{}
	a.second.pusher.pass(context.Background())
	st = a.secondCopyStatuses()[0]
	if !st.Ready || st.QueuedFiles != 0 || st.SentCount != 3 || st.FailingSince != nil || st.LastSent != "000000010000000000000003" {
		t.Fatalf("after coming back: %+v", st)
	}
	if n := r.called("app.copy2.conf archive-push"); n != 3 {
		t.Fatalf("%d pushes to the second copy", n)
	}
	if st.Provider != protocol.ProviderB2 || st.Bucket != "two" {
		t.Errorf("repo info %+v", st.RepoInfo)
	}

	// A gap: reported with when it was first seen, cleared by a full
	// backup that started after it.
	appendGap(dir, "000000010000000000000004")
	appendGap(dir, "000000010000000000000005")
	since, n := a.gapOf("app")
	if since == nil || n != 2 {
		t.Fatalf("gap %v %d", since, n)
	}
	a.clearGap("app", time.Now().Add(-time.Hour)) // started before the gap: kept
	if since, _ := a.gapOf("app"); since == nil {
		t.Fatal("a backup older than the gap cleared it")
	}
	a.clearGap("app", time.Now().Add(time.Second))
	if since, _ := a.gapOf("app"); since != nil {
		t.Fatal("gap not cleared")
	}
}

func TestSidecarQueuesForSecondCopy(t *testing.T) {
	a, r := secondCopyTestAgent(t, ModeDockerSidecar)
	a.cfg.Repo.Validate()
	db := a.watched[0]
	os.MkdirAll(a.cfg.ConfigDir, 0o700)
	os.WriteFile(a.cfg.configPath("app"), []byte("x"), 0o600)
	spool, _ := pgbackrest.SpoolDir(a.cfg.SpoolDir, "app")
	os.MkdirAll(spool, 0o700)
	name := "000000010000000000000007"
	os.WriteFile(filepath.Join(spool, name), []byte("wal 7"), 0o600)
	a.pusher.pass(context.Background())
	if r.called("app.conf archive-push") != 1 {
		t.Fatalf("calls %v", r.calls)
	}
	if _, err := os.Stat(filepath.Join(spool, name)); !os.IsNotExist(err) {
		t.Fatal("still in the spool")
	}
	q, _ := a.cfg.secondCopyQueue("app")
	if b, err := os.ReadFile(filepath.Join(q, name)); err != nil || string(b) != "wal 7" {
		t.Fatalf("not queued for the second copy: %q %v", b, err)
	}
	// A full queue: left out, recorded as a gap.
	for i := range protocol.SecondCopyQueueMaxFiles {
		os.WriteFile(filepath.Join(q, fmt.Sprintf("0000000200000000%08X", i)), nil, 0o600)
	}
	os.WriteFile(filepath.Join(spool, "000000010000000000000008"), []byte("wal 8"), 0o600)
	a.pusher.pass(context.Background())
	if since, n := a.gapOf("app"); since == nil || n != 1 {
		t.Fatalf("gap %v %d", since, n)
	}
	_ = db
}

func TestStorageMeasurement(t *testing.T) {
	a, r := secondCopyTestAgent(t, ModeNative)
	db := a.watched[0]
	os.MkdirAll(a.cfg.ConfigDir, 0o700)
	os.WriteFile(a.cfg.configPath("app"), []byte("x"), 0o600)
	a.writeSecondCopyConfig(db, protocol.InspectResult{DataDirectory: "/d"}, "")
	r.out["app.conf repo-ls"] = []byte(`{"archive/app/18-1/0000000100000000/000000010000000000000003-ab.zst":{"type":"file","size":1000},` +
		`"backup/app/20260901-010000F/bundle/1":{"type":"file","size":50000},"backup/app/20260908-010000F/bundle/1":{"type":"file","size":60000}}`)
	r.out["app.conf info"] = []byte(`[{"name":"app","status":{"code":0},"backup":[` +
		`{"label":"20260908-010000F","type":"full","timestamp":{"start":1788829200,"stop":1788829300}},` +
		`{"label":"20260901-010000F","type":"full","timestamp":{"start":1788224400,"stop":1788224500}}]}]`)
	r.fail["app.copy2.conf repo-ls"] = true
	a.second.ready = map[string]bool{"app": true}
	a.measureAll(context.Background(), true)
	rep := a.storageReports()
	if len(rep) != 2 {
		t.Fatalf("reports %+v", rep)
	}
	one, two := rep[0], rep[1]
	if one.Repo != 1 || one.Provider != protocol.ProviderR2 || one.TotalBytes != 111000 || one.WALBytes != 1000 || one.WALFiles != 1 ||
		len(one.Backups) != 2 || one.Backups[0].Label != "20260901-010000F" || one.Backups[0].StoredBytes != 50000 {
		t.Errorf("first storage %+v", one)
	}
	if two.Repo != 2 || two.Error == "" || two.TotalBytes != 0 {
		t.Errorf("second storage %+v", two)
	}
	// Measured recently: not again unless forced.
	n := r.called("app.conf repo-ls")
	a.measureAll(context.Background(), false)
	if r.called("app.conf repo-ls") != n {
		t.Error("measured again within the interval")
	}
}
