package agent

// Standby against real PostgreSQL clusters on this machine (initdb, pg_ctl,
// pg_basebackup on PATH; run when ROWSAFE_TEST_DATABASE_URL is set, like
// the other integration tests). Two agents with their own state, keys and
// sealed handoff; the root helper is replaced by pg_ctl and the bucket
// restore by pg_basebackup, everything else is the agent's own code:
//
//	prepare (role, pg_hba, SCRAM) -> create on an empty cluster (stop, set
//	aside, restore, configure, start) -> streaming -> fence the primary ->
//	it is started again by "someone": read-only, and the agent stops it ->
//	promote (waits for the fenced primary's last checkpoint) -> rebuild the
//	old primary as the new standby on its own data (reattach) -> it follows
//	the new timeline -> release -> remove. And a create that fails after
//	the stop puts the cluster's own data back and running.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type pgCluster struct {
	dir, socket string
	port        int
}

// testStandbyOps replaces the root helper with pg_ctl and the bucket with
// pg_basebackup from the primary.
type testStandbyOps struct {
	realStandbyOps
	t         *testing.T
	mu        sync.Mutex
	clusters  map[int]*pgCluster // by port
	source    *pgCluster         // what restoreStandby copies
	failNext  bool
	pushCalls int
}

func (o *testStandbyOps) helper(ctx context.Context, action string, port int, id string) error {
	o.mu.Lock()
	c := o.clusters[port]
	o.mu.Unlock()
	if c == nil {
		return fmt.Errorf("port %d not allowed", port)
	}
	var args []string
	switch action {
	case helperStop:
		args = []string{"-D", c.dir, "-m", "fast", "-w", "stop"}
	case helperStart:
		args = []string{"-D", c.dir, "-l", c.dir + ".log", "-w", "-t", "60", "start"}
	default:
		return fmt.Errorf("unexpected action %s", action)
	}
	out, err := exec.CommandContext(ctx, "pg_ctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pg_ctl %s: %v: %s", action, err, out)
	}
	return nil
}

func (o *testStandbyOps) restoreStandby(ctx context.Context, db protocol.DatabaseSpec, dataDir string) ([]byte, error) {
	if o.failNext {
		o.failNext = false
		return []byte("simulated failure"), fmt.Errorf("simulated restore failure")
	}
	out, err := exec.CommandContext(ctx, "pg_basebackup", "-D", dataDir, "-h", o.source.socket, "-p", strconv.Itoa(o.source.port),
		"-X", "stream", "-c", "fast").CombinedOutput()
	if err != nil {
		return out, err
	}
	return out, os.WriteFile(filepath.Join(dataDir, "standby.signal"), nil, 0o600)
}

func (o *testStandbyOps) repo(ctx context.Context, db protocol.DatabaseSpec) error { return nil }

func (o *testStandbyOps) archivePush(ctx context.Context, db protocol.DatabaseSpec, walPath string) ([]byte, error) {
	o.pushCalls++
	if _, err := os.Stat(walPath); err != nil {
		return nil, err
	}
	return []byte("pushed (test)"), nil
}

func newTestCluster(t *testing.T, root, name string, primaryConf string) *pgCluster {
	t.Helper()
	c := &pgCluster{dir: filepath.Join(root, name), socket: root, port: freePort(t)}
	out, err := exec.Command("initdb", "-D", c.dir, "--auth-local=trust", "--auth-host=scram-sha-256", "-U", currentUser(),
		"--no-sync", "--locale=C", "--encoding=UTF8").CombinedOutput()
	if err != nil {
		t.Fatalf("initdb: %v: %s", err, out)
	}
	conf := fmt.Sprintf("port = %d\nunix_socket_directories = '%s'\nlisten_addresses = '*'\nwal_level = replica\nmax_wal_senders = 5\n"+
		"fsync = off\nlogging_collector = off\nwal_keep_size = '64MB'\n%s", c.port, root, primaryConf)
	if err := os.WriteFile(filepath.Join(c.dir, "postgresql.conf"), append(mustRead(t, filepath.Join(c.dir, "postgresql.conf")), []byte("\n"+conf)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return c
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (c *pgCluster) start(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("pg_ctl", "-D", c.dir, "-l", c.dir+".log", "-w", "-t", "60", "start").CombinedOutput(); err != nil {
		log, _ := os.ReadFile(c.dir + ".log")
		t.Fatalf("pg_ctl start: %v: %s\n%s", err, out, tail(log, 3000))
	}
}

func (c *pgCluster) stopQuiet() {
	_ = exec.Command("pg_ctl", "-D", c.dir, "-m", "immediate", "-w", "stop").Run()
}

func TestStandbyRealPostgres(t *testing.T) {
	if os.Getenv("ROWSAFE_TEST_DATABASE_URL") == "" {
		t.Skip("set ROWSAFE_TEST_DATABASE_URL to run integration tests")
	}
	for _, tool := range []string{"initdb", "pg_ctl", "pg_basebackup", "pg_config"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	t.Setenv("LC_ALL", "C") // the postmaster refuses an invalid locale
	addrs := localAddresses()
	if len(addrs) == 0 {
		t.Skip("no non-loopback address to stream over")
	}
	bindir, err := exec.Command("pg_config", "--bindir").Output()
	if err != nil {
		t.Fatal(err)
	}
	ver, _ := exec.Command("pg_config", "--version").Output()
	major, _ := strconv.Atoi(strings.Fields(strings.TrimPrefix(string(ver), "PostgreSQL "))[0][:2])

	root, err := os.MkdirTemp("/tmp", "rsb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	primary := newTestCluster(t, root, "p", "")
	target := newTestCluster(t, root, "t", "")
	target2 := newTestCluster(t, root, "u", "")
	for _, c := range []*pgCluster{primary, target, target2} {
		t.Cleanup(c.stopQuiet)
		c.start(t)
	}
	// This machine's address: let the test's host logins in (scram).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	helperFile := filepath.Join(root, "helper")
	os.WriteFile(helperFile, []byte("#!/bin/sh\n# actions: restart stop start\n"), 0o755)
	allow := filepath.Join(root, "allow")
	os.WriteFile(allow, []byte(fmt.Sprintf("%d a.service\n%d b.service\n%d c.service\n", primary.port, target.port, target2.port)), 0o644)
	ops := &testStandbyOps{t: t, clusters: map[int]*pgCluster{primary.port: primary, target.port: target, target2.port: target2}, source: primary}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	repo := pgbackrest.Repo{Endpoint: "s3.example", Bucket: "b", Region: "auto", Key: "k", KeySecret: "s", CipherPass: "a-cipher-passphrase-long-enough", PathPrefix: "/rowsafe"}
	newAgent := func(name string) *Agent {
		state := filepath.Join(root, name)
		os.MkdirAll(filepath.Join(state, "restart"), 0o700)
		a := &Agent{cfg: Config{StateDir: state, ConfigDir: filepath.Join(state, "conf"), LogDir: filepath.Join(state, "log"),
			PGUser: currentUser(), PGBinDir: strings.TrimSpace(string(bindir)), PgBackRestBin: "/usr/bin/false", Repo: repo,
			RestartAllowFile: allow, RestartDir: filepath.Join(state, "restart"), RestartHelper: helperFile, Mode: ModeNative},
			log: logger, runner: pgbackrest.ExecRunner{}, sbOps: ops}
		ops.realStandbyOps = realStandbyOps{realInPlaceOps{a}}
		return a
	}
	aP, aT := newAgent("sp"), newAgent("st")
	ops.realStandbyOps = realStandbyOps{realInPlaceOps{aP}}
	oldTick := fenceRetry
	fenceRetry = 0
	defer func() { fenceRetry = oldTick }()

	dbP := protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop", Port: primary.port, SocketDir: root, RetentionFull: 2}
	step := func(name string, fn func(tl *taskLog) error) {
		t.Helper()
		tl := &taskLog{}
		err := fn(tl)
		t.Logf("---- %s\n%s", name, tl.String())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	sqlOn := func(c *pgCluster, q string, dest ...any) {
		t.Helper()
		conn, err := aP.target(protocol.DatabaseSpec{Port: c.port, SocketDir: root}).Connect(ctx, "postgres")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		if len(dest) == 0 {
			if _, err := conn.Exec(ctx, q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			return
		}
		if err := conn.QueryRow(ctx, q).Scan(dest...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(60 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	var sysid string
	sqlOn(primary, `SELECT system_identifier::text FROM pg_control_system()`, &sysid)
	sqlOn(primary, `CREATE TABLE orders (id int PRIMARY KEY, note text)`)
	sqlOn(primary, `INSERT INTO orders SELECT g, 'before' FROM generate_series(1, 100) g`)

	// ---- prepare on the primary
	fpT, _ := handoff.Fingerprint(aT.sb().key.PublicKey())
	var prep *protocol.StandbyPrepareResult
	step("prepare refuses a fingerprint that doesn't match", func(tl *taskLog) error {
		_, err := aP.standbyPrepare(ctx, dbP, protocol.StandbyPrepareParams{StandbyID: "sby_1", RecipientKey: aT.sb().key.PublicKey(),
			RecipientFingerprint: "0000-0000-0000-0000", Stream: true}, tl)
		if err == nil || !strings.Contains(err.Error(), "nothing was sent") {
			return fmt.Errorf("want a fingerprint refusal, got %v", err)
		}
		return nil
	})
	step("prepare", func(tl *taskLog) (err error) {
		prep, err = aP.standbyPrepare(ctx, dbP, protocol.StandbyPrepareParams{StandbyID: "sby_1", RecipientKey: aT.sb().key.PublicKey(),
			RecipientFingerprint: fpT, StandbyAddresses: addrs, Stream: true}, tl)
		return err
	})
	if !prep.Streaming || prep.SystemID != sysid || prep.Major != major {
		t.Fatalf("prepare result: %+v", prep)
	}
	hba := string(mustRead(t, filepath.Join(primary.dir, "pg_hba.conf")))
	if !strings.HasPrefix(hba, hbaBegin("sby_1")) || !strings.Contains(hba, "host replication rowsafe_standby_sby_1 "+addrs[0]) {
		t.Fatalf("pg_hba.conf:\n%s", hba)
	}
	// The box opens only for the standby's agent, and its password logs in
	// for replication (SCRAM verifier + pg_hba).
	if _, err := handoff.Open(aP.sb().key, prep.Box, "standby", protocol.StandbyHandoffContext("db_1", "sby_1"), ""); err == nil {
		t.Fatal("the primary's own key opened the box")
	}
	plain, err := handoff.Open(aT.sb().key, prep.Box, "standby", protocol.StandbyHandoffContext("db_1", "sby_1"), aP.sb().key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), repo.CipherPass) {
		t.Fatal("the box doesn't carry the repository")
	}
	var secPass string
	if i := strings.Index(string(plain), `"replication_password":"`); i >= 0 {
		secPass = string(plain)[i+len(`"replication_password":"`):]
		secPass = secPass[:strings.Index(secPass, `"`)]
	}
	cfg, _ := pgconn.ParseConfig(fmt.Sprintf("host=%s port=%d user=rowsafe_standby_sby_1 password=%s replication=true sslmode=disable", addrs[0], primary.port, secPass))
	rconn, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("replication login with the sealed password: %v", err)
	}
	rconn.Close(ctx)
	cfg.Password = "wrong"
	if c, err := pgconn.ConnectConfig(ctx, cfg); err == nil {
		c.Close(ctx)
		t.Fatal("a wrong password logged in")
	}

	// ---- create on the empty target
	createParams := protocol.StandbyCreateParams{StandbyID: "sby_1", Port: target.port, SocketDir: root, Box: prep.Box,
		SenderKey: aP.sb().key.PublicKey(), Major: prep.Major, SystemID: prep.SystemID, SizeBytes: prep.SizeBytes, Settings: prep.Settings}
	sqlOn(target, `CREATE TABLE mine (x int)`)
	step("create refuses a cluster that isn't empty", func(tl *taskLog) error {
		_, err := aT.standbyCreate(ctx, dbP, createParams, tl)
		if err == nil || !strings.Contains(err.Error(), "isn't empty") {
			return fmt.Errorf("want a refusal, got %v", err)
		}
		return nil
	})
	sqlOn(target, `DROP TABLE mine`)
	var created *protocol.StandbyCreateResult
	step("create", func(tl *taskLog) (err error) {
		created, err = aT.standbyCreate(ctx, dbP, createParams, tl)
		return err
	})
	if created.Mode != protocol.StandbyModeStreaming || !strings.Contains(created.KeptDataDir, ".before-standby-") {
		t.Fatalf("create result: %+v", created)
	}
	var inRec bool
	sqlOn(target, `SELECT pg_is_in_recovery()`, &inRec)
	if !inRec {
		t.Fatal("the standby isn't in recovery")
	}
	sqlOn(primary, `INSERT INTO orders SELECT g, 'streamed' FROM generate_series(101, 200) g`)
	waitFor("the standby to replay", func() bool {
		var n int
		sqlOn(target, `SELECT count(*) FROM orders`, &n)
		return n == 200
	})
	hb := aT.standbyHeartbeat(ctx)
	if len(hb.Standbys) != 1 || hb.Standbys[0].Mode != protocol.StandbyModeStreaming || hb.Standbys[0].StreamingSeenAt == nil || hb.BoxKey == "" {
		t.Fatalf("standby heartbeat: %+v", hb.Standbys)
	}
	aT.checkPrimary(aT.sb().standbys()[0])
	aP.mu.Lock()
	aP.watched = []protocol.DatabaseSpec{dbP}
	aP.mu.Unlock()
	ph := aP.standbyHeartbeat(ctx)
	if len(ph.Primaries) != 1 || len(ph.Primaries[0].Streams) != 1 || ph.Primaries[0].Streams[0].Role != "rowsafe_standby_sby_1" {
		t.Fatalf("primary heartbeat: %+v", ph.Primaries)
	}

	// ---- fence the primary
	sqlOn(primary, `INSERT INTO orders VALUES (201, 'last before the fence')`)
	var fenced *protocol.StandbyFenceResult
	step("fence", func(tl *taskLog) (err error) {
		fenced, err = aP.standbyFence(ctx, dbP, protocol.StandbyFenceParams{FenceID: "fen_1", StandbyID: "sby_1", SystemID: sysid}, tl)
		return err
	})
	if !fenced.Stopped || fenced.CheckpointLSN == "" || fenced.Method != "helper" || !fenced.FinalWALPushed || ops.pushCalls == 0 {
		t.Fatalf("fence result: %+v", fenced)
	}
	if postmasterAlive(primary.dir) || !exists(filepath.Join(primary.dir, "standby.signal")) {
		t.Fatal("the fenced primary runs, or has no standby.signal")
	}
	// Someone starts the old primary again: it comes up read-only, and the
	// agent stops it.
	primary.start(t)
	sqlOn(primary, `SELECT pg_is_in_recovery()`, &inRec)
	if !inRec {
		t.Fatal("a fenced primary started again came up read-write")
	}
	aP.holdFence(ctx, aP.sb().fences()[0])
	if postmasterAlive(primary.dir) {
		t.Fatal("the agent didn't stop the fenced cluster")
	}
	if f := aP.sb().fences()[0]; f.StoppedAt == nil || f.Running {
		t.Fatalf("fence state: %+v", f)
	}

	// ---- promote the standby
	var promoted *protocol.StandbyPromoteResult
	step("promote", func(tl *taskLog) (err error) {
		promoted, err = aT.standbyPromote(ctx, dbP, protocol.StandbyPromoteParams{StandbyID: "sby_1", WaitForLSN: fenced.CheckpointLSN}, tl)
		return err
	})
	if !promoted.Promoted || !promoted.CaughtUp || promoted.Timeline != 2 {
		t.Fatalf("promote result: %+v", promoted)
	}
	var n int
	sqlOn(target, `SELECT count(*) FROM orders`, &n)
	if n != 201 {
		t.Fatalf("the new primary has %d orders, want 201 (nothing lost)", n)
	}
	var roles int
	sqlOn(target, `SELECT count(*) FROM pg_roles WHERE rolname = 'rowsafe_standby_sby_1'`, &roles)
	if roles != 0 {
		t.Fatal("the old replication role is still there")
	}
	if len(aT.sb().standbys()) != 0 {
		t.Fatal("the promoted standby is still recorded as a standby")
	}
	sqlOn(target, `INSERT INTO orders VALUES (202, 'on the new primary')`)

	// ---- rebuild the old primary as the new standby, on its own data
	dbT := dbP
	dbT.Port = target.port
	fpP, _ := handoff.Fingerprint(aP.sb().key.PublicKey())
	var prep2 *protocol.StandbyPrepareResult
	step("prepare on the new primary", func(tl *taskLog) (err error) {
		prep2, err = aT.standbyPrepare(ctx, dbT, protocol.StandbyPrepareParams{StandbyID: "sby_2", RecipientKey: aP.sb().key.PublicKey(),
			RecipientFingerprint: fpP, StandbyAddresses: addrs, Stream: true}, tl)
		return err
	})
	var rebuilt *protocol.StandbyCreateResult
	step("rebuild (reattach)", func(tl *taskLog) (err error) {
		rebuilt, err = aP.standbyCreate(ctx, dbP, protocol.StandbyCreateParams{StandbyID: "sby_2", Port: primary.port, SocketDir: root,
			Box: prep2.Box, SenderKey: aT.sb().key.PublicKey(), Major: prep2.Major, SystemID: prep2.SystemID, SizeBytes: prep2.SizeBytes,
			Settings: prep2.Settings, Rebuild: true, FenceID: "fen_1", Reattach: true, SwitchLSN: promoted.ReplayLSN}, tl)
		return err
	})
	if !rebuilt.Reattached {
		t.Fatalf("rebuild result: %+v", rebuilt)
	}
	if len(aP.sb().fences()) != 0 {
		t.Fatal("the fence is still held after the rebuild")
	}
	aP.sb().setFences([]protocol.Fence{{ID: "fen_1", DatabaseID: "db_1", Port: primary.port, SocketDir: root}})
	if len(aP.sb().fences()) != 0 {
		t.Fatal("a stale heartbeat answer brought a released fence back")
	}
	waitFor("the rebuilt standby to follow the new primary", func() bool {
		var n int
		sqlOn(primary, `SELECT count(*) FROM orders`, &n)
		return n == 202
	})
	sqlOn(primary, `SELECT pg_is_in_recovery()`, &inRec)
	if !inRec {
		t.Fatal("the rebuilt old primary is not a standby")
	}

	// ---- release and remove
	step("release on the new primary", func(tl *taskLog) error {
		_, err := aT.standbyRelease(ctx, dbT, protocol.StandbyReleaseParams{StandbyID: "sby_2"}, tl)
		return err
	})
	if strings.Contains(string(mustRead(t, filepath.Join(target.dir, "pg_hba.conf"))), "Rowsafe standby") {
		t.Fatal("release left pg_hba.conf lines")
	}
	step("remove the rebuilt standby", func(tl *taskLog) error {
		res, err := aP.standbyRemove(ctx, dbP, protocol.StandbyRemoveParams{StandbyID: "sby_2"}, tl)
		if err == nil && res.Restored {
			return fmt.Errorf("a rebuilt old primary's data was put back: %+v", res)
		}
		return err
	})
	if postmasterAlive(primary.dir) {
		t.Fatal("the removed standby still runs")
	}

	// ---- a create that fails after the stop puts the cluster back
	ops.source = target
	ops.failNext = true
	prep3, err := aT.standbyPrepare(ctx, dbT, protocol.StandbyPrepareParams{StandbyID: "sby_3", RecipientKey: aP.sb().key.PublicKey(),
		RecipientFingerprint: fpP, Stream: false}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	var before string
	sqlOn(target2, `SELECT system_identifier::text FROM pg_control_system()`, &before)
	tl := &taskLog{}
	res, err := aP.standbyCreate(ctx, dbT, protocol.StandbyCreateParams{StandbyID: "sby_3", Port: target2.port, SocketDir: root, Box: prep3.Box,
		SenderKey: aT.sb().key.PublicKey(), Major: prep3.Major, SystemID: prep3.SystemID, SizeBytes: prep3.SizeBytes}, tl)
	t.Logf("---- failed create\n%s", tl.String())
	if err == nil || !res.RolledBack {
		t.Fatalf("want a rolled back failure, got %+v %v", res, err)
	}
	var after string
	sqlOn(target2, `SELECT system_identifier::text FROM pg_control_system()`, &after)
	if after != before {
		t.Fatal("the cluster's own data isn't back")
	}
	if len(aP.sb().standbys()) != 0 {
		t.Fatal("a failed create left a standby record")
	}
	_ = pgx.Identifier{}
}
