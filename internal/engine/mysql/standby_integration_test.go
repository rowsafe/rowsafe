package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// TestStandbyIntegration runs a standby between two real servers: seeded
// from the backup, replicating, fenced, promoted, and the old primary
// following the new one. scripts/test-mysql.sh with MYSQL_IT_RUN=Standby
// starts the second server:
//
//	ROWSAFE_MYSQL_IT_STANDBY_SOCKET  the second (empty) server's socket
//	ROWSAFE_MYSQL_IT_PRIMARY_HOST    the first server's host name on the network
//	ROWSAFE_MYSQL_IT_STANDBY_HOST    the second server's host name
func TestStandbyIntegration(t *testing.T) {
	engine := os.Getenv("ROWSAFE_MYSQL_IT")
	sbSocket := os.Getenv("ROWSAFE_MYSQL_IT_STANDBY_SOCKET")
	if engine == "" || sbSocket == "" {
		t.Skip("set ROWSAFE_MYSQL_IT and ROWSAFE_MYSQL_IT_STANDBY_SOCKET (MYSQL_IT_RUN=Standby sh scripts/test-mysql.sh)")
	}
	ctx := context.Background()
	ipOf := func(host string) string {
		t.Helper()
		addrs, err := net.LookupHost(host)
		if err != nil || len(addrs) == 0 {
			t.Fatalf("resolving %s: %v", host, err)
		}
		return addrs[0]
	}
	ipA, ipB := ipOf(os.Getenv("ROWSAFE_MYSQL_IT_PRIMARY_HOST")), ipOf(os.Getenv("ROWSAFE_MYSQL_IT_STANDBY_HOST"))
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_REPO_S3_PORT"))
	repo := pgbackrest.Repo{
		Endpoint: os.Getenv("ROWSAFE_REPO_S3_ENDPOINT"), Bucket: os.Getenv("ROWSAFE_REPO_S3_BUCKET"),
		Region: "us-east-1", Key: os.Getenv("ROWSAFE_REPO_S3_KEY"), KeySecret: os.Getenv("ROWSAFE_REPO_S3_KEY_SECRET"),
		CipherPass: os.Getenv("ROWSAFE_REPO_CIPHER_PASS"), PathPrefix: "/rowsafe-sb-" + strconv.FormatInt(time.Now().Unix(), 10),
		URIStyle: "path", Port: port, CAFile: os.Getenv("ROWSAFE_REPO_S3_CA_FILE"),
	}
	envFor := func(name string) agent.EngineEnv {
		state := filepath.Join(t.TempDir(), name)
		cfg := agent.Config{Mode: agent.ModeDockerSidecar, StateDir: state, DrillDir: filepath.Join(state, "drills"),
			RewindDir: filepath.Join(state, "rewind")}
		return agent.EngineEnv{Config: cfg, StateDir: filepath.Join(state, "engines", engine), Repo: repo, Runner: pgbackrest.ExecRunner{},
			Log: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})), Notes: io.Discard}
	}
	envA, envB := envFor("a"), envFor("b")
	e := &Engine{flavor: flavor(engine)}
	specA := protocol.DatabaseSpec{ID: "db_sb_" + engine, Name: "shop", Stanza: "shop", Port: 3306,
		SocketDir: os.Getenv("ROWSAFE_MYSQL_IT_SOCKET"), Engine: engine, RetentionFull: 2}
	specB := specA
	specB.SocketDir = sbSocket
	shipPoll, shipMaxDelay = 2*time.Second, 5*time.Second
	tl := &testLog{t: t}

	pw, err := readSecretFile(os.Getenv("ROWSAFE_MYSQL_ADMIN_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	admin := func(socket string) *sql.DB {
		t.Helper()
		db, err := openWith(ctx, account{User: "root", Password: pw}, socket, 3306)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(4)
		return db
	}
	exec := func(db *sql.DB, q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	count := func(db *sql.DB, q string) int64 {
		t.Helper()
		var n int64
		if err := db.QueryRowContext(ctx, q).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return n
	}
	waitCount := func(db *sql.DB, q string, want int64) {
		t.Helper()
		for i := 0; i < 60; i++ {
			if count(db, q) == want {
				return
			}
			time.Sleep(time.Second)
		}
		t.Fatalf("%s: %d, want %d", q, count(db, q), want)
	}
	adbA, adbB := admin(specA.SocketDir), admin(specB.SocketDir)
	defer adbA.Close()
	defer func() { adbB.Close() }()
	// Rowsafe's accounts, with standby rights (the installer's --standby).
	for _, x := range []struct {
		env  agent.EngineEnv
		spec protocol.DatabaseSpec
		db   *sql.DB
	}{{envA, specA, adbA}, {envB, specB, adbB}} {
		if ok, err := e.server(x.env, x.spec).createAccountAsAdmin(ctx); err != nil || !ok {
			t.Fatalf("account: %v %v", ok, err)
		}
		exec(x.db, standbyGrant)
	}

	// The primary: backups on, data, an app login, a full backup, more data.
	run := func(env agent.EngineEnv, spec protocol.DatabaseSpec, typ string, params any) any {
		t.Helper()
		res, err := e.Run(ctx, env, &protocol.Task{ID: fmt.Sprintf("t%d", time.Now().UnixNano()), Type: typ, Database: &spec, Params: mustJSON(t, params)}, tl)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		return res
	}
	run(envA, specA, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	run(envA, specA, protocol.TaskCheck, nil)
	exec(adbA, "CREATE DATABASE shop")
	exec(adbA, "CREATE TABLE shop.orders (id INT PRIMARY KEY, note VARCHAR(50))")
	exec(adbA, "CREATE USER 'app'@'%' IDENTIFIED BY 'app-secret-1'")
	exec(adbA, "GRANT SELECT, INSERT ON shop.* TO 'app'@'%'")
	for i := 1; i <= 100; i++ {
		exec(adbA, "INSERT INTO shop.orders VALUES (?, 'before backup')", i)
	}
	run(envA, specA, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	for i := 101; i <= 200; i++ {
		exec(adbA, "INSERT INTO shop.orders VALUES (?, 'shipped')", i)
	}
	// Let the shipper copy those binary logs (they are what the seed replays).
	for i := 0; i < 30; i++ {
		_, _ = e.Archiver(ctx, envA, specA)
		time.Sleep(time.Second)
	}
	for i := 201; i <= 210; i++ {
		exec(adbA, "INSERT INTO shop.orders VALUES (?, 'not shipped yet')", i)
	}

	// Prepare on the primary, create on the empty server.
	var sec protocol.StandbySecrets
	sec.PrimaryPort, sec.PrimaryAddresses = 3306, []string{ipA}
	var prep protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, envA, specA, protocol.StandbyPrepareParams{StandbyID: "sb1", StandbyAddresses: []string{ipB}, Stream: true},
		&sec, &prep, tl); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	t.Logf("prepare: %+v", prep)
	cres, err := e.StandbyCreate(ctx, envB, specB, protocol.StandbyCreateParams{StandbyID: "sb1", Port: 3306, SocketDir: sbSocket,
		Major: prep.Major, SystemID: prep.SystemID, SizeBytes: prep.SizeBytes, Settings: prep.Settings}, sec, tl)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Logf("create: %+v", cres)
	adbB.Close() // its sessions were ended (server_id changed)
	adbB = admin(specB.SocketDir)
	waitCount(adbB, "SELECT COUNT(*) FROM shop.orders", 210)
	exec(adbA, "INSERT INTO shop.orders VALUES (211, 'replicated')")
	waitCount(adbB, "SELECT COUNT(*) FROM shop.orders", 211)
	if n := count(adbB, "SELECT COUNT(*) FROM mysql.user WHERE User = 'app'"); n != 1 {
		t.Fatalf("the app login wasn't copied: %d", n)
	}
	states := e.StandbyStates(ctx, envB)
	if len(states) != 1 || !states[0].Running || !states[0].InRecovery || states[0].ReplayLSN == "" || states[0].Error != "" {
		t.Fatalf("states: %+v", states)
	}
	if ps, ok := e.PrimaryState(ctx, envA, specA); !ok || ps.WALLSN == "" {
		t.Fatalf("primary state: %+v", ps)
	}
	if ts := e.StandbyTargets(ctx, envB); len(ts) != 0 {
		t.Logf("targets (sidecar: none expected): %+v", ts)
	}

	// The app login can't write to the standby.
	appB, err := openWith(ctx, account{User: "app", Password: "app-secret-1"}, sbSocket, 3306)
	if err != nil {
		t.Fatalf("app login on the standby: %v", err)
	}
	defer appB.Close()
	if _, err := appB.ExecContext(ctx, "INSERT INTO shop.orders VALUES (999, 'x')"); err == nil {
		t.Fatal("the standby took a write")
	}

	// Fence the primary, promote the standby.
	fres, err := e.StandbyFence(ctx, envA, specA, protocol.StandbyFenceParams{FenceID: "f1", StandbyID: "sb1", SystemID: prep.SystemID}, tl)
	if err != nil || fres.CheckpointLSN == "" {
		t.Fatalf("fence: %+v %v", fres, err)
	}
	appA, err := openWith(ctx, account{User: "app", Password: "app-secret-1"}, specA.SocketDir, 3306)
	if err != nil {
		t.Fatal(err)
	}
	defer appA.Close()
	if _, err := appA.ExecContext(ctx, "INSERT INTO shop.orders VALUES (998, 'x')"); err == nil {
		t.Fatal("the fenced primary took a write")
	}
	fence := protocol.Fence{ID: "f1", DatabaseID: specA.ID, Port: 3306, SocketDir: specA.SocketDir, SystemID: prep.SystemID, Engine: engine}
	exec(adbA, "SET GLOBAL read_only = OFF")
	if !e.flavor.mariadb() {
		exec(adbA, "SET GLOBAL super_read_only = OFF")
	}
	if enforced, other, err := e.HoldFence(ctx, envA, fence); !enforced || other || err != nil {
		t.Fatalf("hold: %v %v %v", enforced, other, err)
	}
	pres, err := e.StandbyPromote(ctx, envB, specB, protocol.StandbyPromoteParams{StandbyID: "sb1", WaitForLSN: fres.CheckpointLSN}, tl)
	if err != nil || !pres.Promoted || !pres.CaughtUp || pres.ReplayLSN == "" {
		t.Fatalf("promote: %+v %v", pres, err)
	}
	if _, err := appB.ExecContext(ctx, "INSERT INTO shop.orders VALUES (212, 'on the new primary')"); err != nil {
		t.Fatalf("the new primary refused a write: %v", err)
	}

	// The old primary follows the new one.
	var sec2 protocol.StandbySecrets
	sec2.PrimaryPort, sec2.PrimaryAddresses = 3306, []string{ipB}
	var prep2 protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, envB, specB, protocol.StandbyPrepareParams{StandbyID: "sb2", StandbyAddresses: []string{ipA}, Stream: true},
		&sec2, &prep2, tl); err != nil {
		t.Fatalf("prepare 2: %v", err)
	}
	rres, err := e.StandbyCreate(ctx, envA, specA, protocol.StandbyCreateParams{StandbyID: "sb2", Port: 3306, SocketDir: specA.SocketDir,
		Rebuild: true, FenceID: "f1", Reattach: true, SwitchLSN: pres.ReplayLSN, Settings: prep2.Settings, Major: prep2.Major}, sec2, tl)
	if err != nil || !rres.Reattached {
		t.Fatalf("reattach: %+v %v", rres, err)
	}
	if enforced, _, _ := e.HoldFence(ctx, envA, fence); enforced {
		t.Fatal("the fence fought the rebuilt standby")
	}
	exec(adbB, "INSERT INTO shop.orders VALUES (213, 'follows')")
	if count(adbA, "SELECT COUNT(*) FROM shop.orders") != 213 {
		time.Sleep(5 * time.Second)
		t.Logf("old primary as a standby: %+v", e.StandbyStates(ctx, envA))
	}
	waitCount(adbA, "SELECT COUNT(*) FROM shop.orders", 213)

	// Remove: the rebuilt old primary keeps its data; release drops the login.
	rm, err := e.StandbyRemove(ctx, envA, specA, protocol.StandbyRemoveParams{StandbyID: "sb2"}, tl)
	if err != nil || rm.Restored {
		t.Fatalf("remove: %+v %v", rm, err)
	}
	if n := count(adbA, "SELECT COUNT(*) FROM shop.orders"); n != 213 {
		t.Fatalf("the rebuilt standby lost data: %d", n)
	}
	if _, err := e.StandbyRelease(ctx, envB, specB, protocol.StandbyReleaseParams{StandbyID: "sb2"}, tl); err != nil {
		t.Fatalf("release: %v", err)
	}
	if n := count(adbB, "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'rowsafe\\_sb\\_%'"); n != 0 {
		t.Fatalf("replication logins left: %d", n)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
