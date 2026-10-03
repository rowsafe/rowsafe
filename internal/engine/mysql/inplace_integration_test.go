package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestInPlaceIntegration rewinds a real server in place and undoes it. It
// runs inside the agent's image as the server's user (the test starts its
// own "production" server on a fresh data directory, and plays the root
// helper: stop and start are a SHUTDOWN and a new process):
//
//	docker run --rm -u mysql -e ROWSAFE_MYSQL_INPLACE_IT=mysql -v $PWD:/t rowsafe-agent:mysql8.0 /t/mysql.test -test.run InPlace -test.v
func TestInPlaceIntegration(t *testing.T) {
	engine := os.Getenv("ROWSAFE_MYSQL_INPLACE_IT")
	if engine == "" {
		t.Skip("set ROWSAFE_MYSQL_INPLACE_IT=mysql|mariadb (inside the agent image)")
	}
	ctx := context.Background()
	base := t.TempDir()
	prod := &prodServer{t: t, flavor: flavor(engine), dir: filepath.Join(base, "prod")}
	prod.init()
	prod.start()
	t.Cleanup(prod.stop)

	s3 := fakes3.New("bkt")
	t.Cleanup(s3.Close)
	tlsS3 := httptest.NewTLSServer(s3.Config.Handler)
	t.Cleanup(tlsS3.Close)
	state := filepath.Join(base, "state")
	cfg := agent.Config{Mode: agent.ModeNative, StateDir: state, DrillDir: filepath.Join(state, "drills"), RewindDir: filepath.Join(state, "rewind")}
	repo := pgbackrest.Repo{Endpoint: strings.TrimPrefix(tlsS3.URL, "https://"), Bucket: "bkt", Region: "us-east-1", Key: "k", KeySecret: "s",
		CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe", URIStyle: "path", SkipTLSVerify: true}
	if ep := os.Getenv("ROWSAFE_REPO_S3_ENDPOINT"); ep != "" { // a real S3 (MinIO)
		port, _ := strconv.Atoi(os.Getenv("ROWSAFE_REPO_S3_PORT"))
		repo = pgbackrest.Repo{Endpoint: ep, Port: port, Bucket: os.Getenv("ROWSAFE_REPO_S3_BUCKET"), Region: "us-east-1",
			Key: os.Getenv("ROWSAFE_REPO_S3_KEY"), KeySecret: os.Getenv("ROWSAFE_REPO_S3_KEY_SECRET"),
			CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe-ip-" + strconv.FormatInt(time.Now().Unix(), 10),
			URIStyle: "path", SkipTLSVerify: true}
	}
	env := agent.EngineEnv{
		Config: cfg, StateDir: filepath.Join(state, "engines", engine),
		Repo:   repo,
		Runner: pgbackrest.ExecRunner{}, Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		Notes: io.Discard, Control: prod,
	}
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(accountPath(env.StateDir, 3306), []byte("[client]\nuser=root\npassword=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{flavor: flavor(engine)}
	spec := protocol.DatabaseSpec{ID: "db_ip_" + engine, Name: "shop", Stanza: "shop", Port: 3306, SocketDir: prod.sock(), Engine: engine, RetentionFull: 2}
	shipPoll, shipMaxDelay = time.Second, 2*time.Second
	inPlaceReadyWait = time.Minute

	run := func(typ string, params any) (any, string, error) {
		t.Helper()
		raw, _ := json.Marshal(params)
		tl := &testLog{t: t}
		res, err := e.Run(ctx, env, &protocol.Task{ID: fmt.Sprintf("t%d", time.Now().UnixNano()), Type: typ, Database: &spec, Params: raw}, tl)
		return res, tl.b.String(), err
	}
	must := func(typ string, params any) any {
		t.Helper()
		res, log, err := run(typ, params)
		if err != nil {
			t.Fatalf("%s: %v\n%s", typ, err, log)
		}
		return res
	}
	q := func(stmt string) {
		t.Helper()
		db := prod.conn()
		defer db.Close()
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	ids := func() string {
		t.Helper()
		db := prod.conn()
		defer db.Close()
		var s sql.NullString
		if err := db.QueryRowContext(ctx, "SELECT GROUP_CONCAT(id ORDER BY id) FROM shop.t").Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s.String
	}
	ship := func() {
		t.Helper()
		for i := 0; i < 30; i++ {
			st, _ := e.Archiver(ctx, env, spec)
			if st != nil && st.ArchiveMode == "on" && st.Error == "" {
				break
			}
			time.Sleep(time.Second)
		}
		must(protocol.TaskRestorePoint, protocol.RestorePointParams{Name: fmt.Sprintf("m%d", time.Now().UnixNano())})
	}

	q("CREATE DATABASE shop")
	q("CREATE TABLE shop.t (id INT PRIMARY KEY)")
	q("INSERT INTO shop.t VALUES (1), (2)")
	ship()
	must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	q("INSERT INTO shop.t VALUES (3)")
	time.Sleep(2 * time.Second)
	target := time.Now().UTC().Truncate(time.Second)
	time.Sleep(2 * time.Second)
	q("INSERT INTO shop.t VALUES (4)")
	ship()

	// Rewind in place to target: 4 is gone, 1-3 stay.
	res := must(protocol.TaskRewindInPlace, protocol.RewindInPlaceParams{RewindID: "rw1", Target: protocol.RewindTarget{Time: &target}, KeepDays: 7}).(*protocol.RewindInPlaceResult)
	if got := ids(); got != "1,2,3" {
		t.Fatalf("after the rewind: %q (%+v)", got, res)
	}
	states := e.RewindStates(env)
	if len(states) != 1 || states[0].Status != protocol.RewindKeptBefore || states[0].Kind != protocol.RewindKindKeptData {
		t.Fatalf("states %+v", states)
	}
	// Restores to after the rewind wait for a backup taken after it.
	now := time.Now().UTC().Add(time.Second)
	if _, log, err := run(protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c1", Target: protocol.RewindTarget{Time: &now}}); err == nil ||
		!strings.Contains(err.Error(), "rewound in place") {
		t.Fatalf("copy after the rewind: %v\n%s", err, log)
	}
	q("INSERT INTO shop.t VALUES (5)") // written to the rewound data
	ship()

	// Undo: back to 1-4; 5 is in the data set aside.
	must(protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "rw1"})
	if got := ids(); got != "1,2,3,4" {
		t.Fatalf("after the undo: %q", got)
	}
	if st := e.RewindStates(env); len(st) != 1 || st[0].Status != protocol.RewindKeptAfterUndo {
		t.Fatalf("states after undo %+v", st)
	}
	q("INSERT INTO shop.t VALUES (6)")
	ship()

	// A backup after the undo: restores to now work again.
	must(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	q("INSERT INTO shop.t VALUES (7)")
	ship()
	time.Sleep(2 * time.Second) // the target must be after the backup finished (whole seconds)
	cp := must(protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c2", Target: protocol.RewindTarget{Time: new(time.Now().UTC())}}).(*protocol.RewindCopyResult)
	t.Logf("copy: %s", cp.Summary)
	must(protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c2"})

	// A failed swap rolls back: the helper refuses to start the new data.
	q("INSERT INTO shop.t VALUES (8)")
	ship()
	target2 := time.Now().UTC()
	prod.failStarts = 1
	if _, log, err := run(protocol.TaskRewindInPlace, protocol.RewindInPlaceParams{RewindID: "rw2", Target: protocol.RewindTarget{Time: &target2}}); err == nil ||
		!strings.Contains(err.Error(), "runs on its data from before again") {
		t.Fatalf("failed start: %v\n%s", err, log)
	}
	if got := ids(); got != "1,2,3,4,6,7,8" {
		t.Fatalf("after the rollback: %q", got)
	}

	// An upgrade rehearsal, the installed server standing in for the target version.
	root := filepath.Join(base, "target")
	for _, src := range []string{"/usr/sbin/mysqld", "/usr/sbin/mariadbd", "/usr/share/mysql", "/usr/share/mysql-8.0", "/usr/share/mysql-8.4", "/usr/share/mariadb", "/usr/lib/mysql/plugin", "/usr/lib64/mysql/plugin", "/usr/bin/mariadb-upgrade"} {
		if _, err := os.Stat(src); err != nil {
			continue
		}
		dst := filepath.Join(root, src)
		if strings.HasPrefix(src, "/usr/lib64/") {
			dst = filepath.Join(root, "/usr/lib/", strings.TrimPrefix(src, "/usr/lib64/"))
		}
		os.MkdirAll(filepath.Dir(dst), 0o755)
		if out, err := exec.Command("cp", "-a", src, dst).CombinedOutput(); err != nil {
			t.Fatalf("copying %s: %v %s", src, err, out)
		}
	}
	reh := &protocol.UpgradeRehearsalResult{}
	if err := e.RehearseUpgrade(ctx, env, spec, root, "99.0", reh, &testLog{t: t}); err != nil || !reh.Passed || reh.ToVersion == "" {
		t.Fatalf("rehearsal: %v %+v", err, reh)
	}
	t.Logf("rehearsal: restore %.1fs, start %.1fs, %d databases", reh.RestoreSeconds, reh.UpgradeSeconds, len(reh.Databases))
	if _, warnings, err := e.UpgradeIssues(ctx, env, spec, "8.0", "8.4"); err != nil || len(warnings) == 0 {
		t.Fatalf("issues: %v %v", warnings, err)
	}

	must(protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "rw1"})
	if st := e.RewindStates(env); len(st) != 0 {
		t.Fatalf("states after cleanup %+v", st)
	}
}

// prodServer is the test's production server; it plays agent.ServerControl.
type prodServer struct {
	t          *testing.T
	flavor     flavor
	dir        string
	cmd        *exec.Cmd
	failStarts int
}

func (p *prodServer) data() string { return filepath.Join(p.dir, "data") }
func (p *prodServer) sock() string { return filepath.Join(p.dir, "mysqld.sock") }

func (p *prodServer) init() {
	p.t.Helper()
	if err := os.MkdirAll(p.dir, 0o700); err != nil {
		p.t.Fatal(err)
	}
	var cmd *exec.Cmd
	if p.flavor.mariadb() {
		cmd = exec.Command("mariadb-install-db", "--no-defaults", "--datadir="+p.data(), "--auth-root-authentication-method=normal", "--skip-test-db")
	} else {
		cmd = exec.Command("mysqld", "--no-defaults", "--initialize-insecure", "--datadir="+p.data())
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		p.t.Fatalf("initializing: %v\n%s", err, out)
	}
}

func (p *prodServer) start() {
	p.t.Helper()
	if err := p.launch(); err != nil {
		p.t.Fatal(err)
	}
}

func (p *prodServer) launch() error {
	args := []string{"--no-defaults", "--datadir=" + p.data(), "--socket=" + p.sock(), "--pid-file=" + filepath.Join(p.data(), "prod.pid"),
		"--log-error=" + filepath.Join(p.dir, "error.log"), "--skip-networking", "--server-id=1", "--log-bin=binlog", "--binlog-format=ROW"}
	if !p.flavor.mariadb() {
		args = append(args, "--mysqlx=OFF")
	}
	p.cmd = exec.Command("mysqld", args...)
	if err := p.cmd.Start(); err != nil {
		return err
	}
	go func(c *exec.Cmd) { _ = c.Wait() }(p.cmd)
	for i := 0; i < 120; i++ {
		db, err := openWith(context.Background(), account{User: "root"}, p.sock(), 0)
		if err == nil {
			db.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	b, _ := os.ReadFile(filepath.Join(p.dir, "error.log"))
	return fmt.Errorf("production didn't start:\n%s", b)
}

func (p *prodServer) conn() *sql.DB {
	p.t.Helper()
	db, err := openWith(context.Background(), account{User: "root"}, p.sock(), 0)
	if err != nil {
		p.t.Fatal(err)
	}
	return db
}

func (p *prodServer) stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	for i := 0; i < 240; i++ {
		if p.cmd.Process.Signal(syscall.Signal(0)) != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	p.cmd = nil
}

func (p *prodServer) Allowed(protocol.DatabaseSpec) error { return nil }

func (p *prodServer) Stop(context.Context, protocol.DatabaseSpec, string) error {
	p.stop()
	return nil
}

func (p *prodServer) Start(context.Context, protocol.DatabaseSpec, string) error {
	if p.failStarts > 0 {
		p.failStarts--
		return errors.New("refused by the test")
	}
	return p.launch()
}
