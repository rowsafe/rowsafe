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
	"strings"
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
//	ROWSAFE_MYSQL_IT_GTID            1: both servers set up for GTIDs (it follows by GTID);
//	                                 mixed: the primary only (MySQL: the empty server's
//	                                 gtid_mode is switched to match; MariaDB: by position)
//
// With GTIDs it also switches back: the first server becomes the primary
// again and the second follows it, on its own data both times.
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
	// The agents run in this container (sidecars), not on the servers: the
	// replication logins also let it in (the key checks sign in from here).
	ipAgent := ""
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				ipAgent = n.IP.String()
				break
			}
		}
	}
	if ipAgent == "" {
		t.Fatal("this container's address")
	}
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
	gtidIT := os.Getenv("ROWSAFE_MYSQL_IT_GTID")
	wantGTID := gtidIT == "1" || gtidIT == "mixed" && !e.flavor.mariadb()
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
		for _, g := range standbyGrants {
			exec(x.db, g)
		}
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
	// A login with every right (MariaDB: READ_ONLY ADMIN, which read_only
	// lets write).
	exec(adbA, "CREATE USER 'boss'@'%' IDENTIFIED BY 'boss-secret-1'")
	exec(adbA, "GRANT ALL PRIVILEGES ON *.* TO 'boss'@'%'")
	boss := func(socket string) (*sql.DB, error) {
		return openWith(ctx, account{User: "boss", Password: "boss-secret-1"}, socket, 3306)
	}
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
	if err := e.StandbyPrepare(ctx, envA, specA, protocol.StandbyPrepareParams{StandbyID: "sb1", StandbyAddresses: []string{ipB, ipAgent}, Stream: true},
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
	followsByGTID := func(db *sql.DB, spec protocol.DatabaseSpec, env agent.EngineEnv) {
		t.Helper()
		st, err := e.server(env, spec).readReplicaStatus(ctx, db)
		if err != nil || !st.Configured || st.GTID != wantGTID {
			t.Fatalf("replica status: %+v %v (want GTID %v)", st, err, wantGTID)
		}
	}
	followsByGTID(adbB, specB, envB)
	if wantGTID && !strings.Contains(cres.Summary, "by GTID") || !wantGTID && !strings.Contains(cres.Summary, "by binary log position") {
		t.Fatalf("summary: %s", cres.Summary)
	}
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
	// Nor can a login with every right: MariaDB's is locked while the
	// standby is read-only, MySQL's super_read_only stops it.
	if bdb, err := boss(sbSocket); e.flavor.mariadb() {
		if err == nil {
			bdb.Close()
			t.Fatal("a login that bypasses read_only signs in to the MariaDB standby")
		}
	} else {
		if err != nil {
			t.Fatalf("boss on the standby: %v", err)
		}
		if _, err := bdb.ExecContext(ctx, "INSERT INTO shop.orders VALUES (997, 'x')"); err == nil {
			t.Fatal("a login with every right wrote on the MySQL standby")
		}
		bdb.Close()
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
	at212 := time.Now().UTC()
	if _, err := appB.ExecContext(ctx, "INSERT INTO shop.orders VALUES (212, 'on the new primary')"); err != nil {
		t.Fatalf("the new primary refused a write: %v", err)
	}
	if e.flavor.mariadb() {
		if bdb, err := boss(sbSocket); err != nil {
			t.Fatalf("the login with every right isn't unlocked on the new primary: %v", err)
		} else {
			bdb.Close()
		}
		if bdb, err := boss(specA.SocketDir); err == nil {
			bdb.Close()
			t.Fatal("a login that bypasses read_only signs in to the fenced old primary")
		}
	}
	// A restore after the switch, before the new primary's first backup:
	// the old primary's backup, its binary log up to the switch, then the
	// new primary's own (the switch recorded in the bucket).
	for i := 0; i < 12; i++ {
		_, _ = e.Archiver(ctx, envB, specB)
		time.Sleep(time.Second)
	}
	dr := run(envB, specB, protocol.TaskDrill, nil).(*protocol.DrillResult)
	if !dr.Passed || dr.RecoveredTo == nil || dr.RecoveredTo.Unix() < at212.Unix() {
		t.Fatalf("a restore after the switch stopped at it: recovered to %v (the new primary wrote at %v): %+v", dr.RecoveredTo, at212, dr)
	}
	t.Logf("restored across the switch, to %v", dr.RecoveredTo)

	// The old primary follows the new one.
	var sec2 protocol.StandbySecrets
	sec2.PrimaryPort, sec2.PrimaryAddresses = 3306, []string{ipB}
	var prep2 protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, envB, specB, protocol.StandbyPrepareParams{StandbyID: "sb2", StandbyAddresses: []string{ipA, ipAgent}, Stream: true},
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
	followsByGTID(adbA, specA, envA)

	// And back: the second server stops taking writes, the first is the
	// primary again, the second follows it on its own data.
	fence2 := protocol.Fence{ID: "f2", DatabaseID: specA.ID, Port: 3306, SocketDir: specB.SocketDir, SystemID: prep2.SystemID, Engine: engine}
	fres2, err := e.StandbyFence(ctx, envB, specB, protocol.StandbyFenceParams{FenceID: "f2", StandbyID: "sb2", SystemID: prep2.SystemID}, tl)
	if err != nil || fres2.CheckpointLSN == "" {
		t.Fatalf("fence 2: %+v %v", fres2, err)
	}
	pres2, err := e.StandbyPromote(ctx, envA, specA, protocol.StandbyPromoteParams{StandbyID: "sb2", WaitForLSN: fres2.CheckpointLSN}, tl)
	if err != nil || !pres2.Promoted || !pres2.CaughtUp {
		t.Fatalf("promote 2: %+v %v", pres2, err)
	}
	if _, err := appA.ExecContext(ctx, "INSERT INTO shop.orders VALUES (214, 'back on the first server')"); err != nil {
		t.Fatalf("the first server refused a write after switching back: %v", err)
	}
	var sec3 protocol.StandbySecrets
	sec3.PrimaryPort, sec3.PrimaryAddresses = 3306, []string{ipA}
	var prep3 protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, envA, specA, protocol.StandbyPrepareParams{StandbyID: "sb3", StandbyAddresses: []string{ipB, ipAgent}, Stream: true},
		&sec3, &prep3, tl); err != nil {
		t.Fatalf("prepare 3: %v", err)
	}
	rres3, err := e.StandbyCreate(ctx, envB, specB, protocol.StandbyCreateParams{StandbyID: "sb3", Port: 3306, SocketDir: specB.SocketDir,
		Rebuild: true, FenceID: "f2", Reattach: true, SwitchLSN: pres2.ReplayLSN, Settings: prep3.Settings, Major: prep3.Major}, sec3, tl)
	if err != nil || !rres3.Reattached {
		t.Fatalf("reattach 2: %+v %v", rres3, err)
	}
	if enforced, _, _ := e.HoldFence(ctx, envB, fence2); enforced {
		t.Fatal("the fence fought the second rebuilt standby")
	}
	exec(adbA, "INSERT INTO shop.orders VALUES (215, 'follows again')")
	waitCount(adbB, "SELECT COUNT(*) FROM shop.orders", 215)
	followsByGTID(adbB, specB, envB)
	if _, err := appB.ExecContext(ctx, "INSERT INTO shop.orders VALUES (997, 'x')"); err == nil {
		t.Fatal("the second server took a write as a standby again")
	}

	// Remove: the rebuilt old primary keeps its data; release drops the login.
	rm, err := e.StandbyRemove(ctx, envB, specB, protocol.StandbyRemoveParams{StandbyID: "sb3"}, tl)
	if err != nil || rm.Restored {
		t.Fatalf("remove: %+v %v", rm, err)
	}
	if n := count(adbB, "SELECT COUNT(*) FROM shop.orders"); n != 215 {
		t.Fatalf("the rebuilt standby lost data: %d", n)
	}
	// The first server's earlier login (sb1) went when it prepared sb3;
	// the second server is read-only again: its release waits.
	if rel, err := e.StandbyRelease(ctx, envB, specB, protocol.StandbyReleaseParams{StandbyID: "sb2"}, tl); err != nil ||
		!strings.Contains(rel.Summary, "read-only") {
		t.Fatalf("release on the read-only server: %+v %v", rel, err)
	}
	if _, err := e.StandbyRelease(ctx, envA, specA, protocol.StandbyReleaseParams{StandbyID: "sb3"}, tl); err != nil {
		t.Fatalf("release sb3: %v", err)
	}
	if n := count(adbA, "SELECT COUNT(*) FROM mysql.user WHERE User LIKE 'rowsafe\\_sb\\_%'"); n != 0 {
		t.Fatalf("replication logins left on the primary: %d", n)
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

// TestCloneIntegration clones a database into the second (empty) server as
// it was at a moment, with its logins (MYSQL_IT_RUN=Clone).
func TestCloneIntegration(t *testing.T) {
	engine := os.Getenv("ROWSAFE_MYSQL_IT")
	sbSocket := os.Getenv("ROWSAFE_MYSQL_IT_STANDBY_SOCKET")
	if engine == "" || sbSocket == "" {
		t.Skip("set ROWSAFE_MYSQL_IT and ROWSAFE_MYSQL_IT_STANDBY_SOCKET (MYSQL_IT_RUN=Clone sh scripts/test-mysql.sh)")
	}
	ctx := context.Background()
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_REPO_S3_PORT"))
	repo := pgbackrest.Repo{
		Endpoint: os.Getenv("ROWSAFE_REPO_S3_ENDPOINT"), Bucket: os.Getenv("ROWSAFE_REPO_S3_BUCKET"),
		Region: "us-east-1", Key: os.Getenv("ROWSAFE_REPO_S3_KEY"), KeySecret: os.Getenv("ROWSAFE_REPO_S3_KEY_SECRET"),
		CipherPass: os.Getenv("ROWSAFE_REPO_CIPHER_PASS"), PathPrefix: "/rowsafe-clone-" + strconv.FormatInt(time.Now().Unix(), 10),
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
	specA := protocol.DatabaseSpec{ID: "db_clone_" + engine, Name: "shop", Stanza: "shop", Port: 3306,
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
	adbA, adbB := admin(specA.SocketDir), admin(specB.SocketDir)
	defer adbA.Close()
	defer adbB.Close()
	if ok, err := e.server(envA, specA).createAccountAsAdmin(ctx); err != nil || !ok {
		t.Fatalf("account: %v %v", ok, err)
	}
	if ok, err := e.server(envB, specB).createAccountAsAdmin(ctx); err != nil || !ok {
		t.Fatalf("account: %v %v", ok, err)
	}
	for _, g := range standbyGrants {
		exec(adbB, g)
	}
	run := func(typ string, params any) any {
		t.Helper()
		res, err := e.Run(ctx, envA, &protocol.Task{ID: fmt.Sprintf("t%d", time.Now().UnixNano()), Type: typ, Database: &specA, Params: mustJSON(t, params)}, tl)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		return res
	}
	run(protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	run(protocol.TaskCheck, nil)
	exec(adbA, "CREATE DATABASE shop")
	exec(adbA, "CREATE TABLE shop.orders (id INT PRIMARY KEY, note VARCHAR(50), email VARCHAR(100))")
	exec(adbA, "CREATE USER 'app'@'%' IDENTIFIED BY 'app-secret-1'")
	exec(adbA, "GRANT SELECT, INSERT ON shop.* TO 'app'@'%'")
	for i := 1; i <= 50; i++ {
		exec(adbA, "INSERT INTO shop.orders VALUES (?, 'x', ?)", i, fmt.Sprintf("buyer%d@shop.test", i))
	}
	full := run(protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}).(*protocol.BackupResult)
	for i := 51; i <= 80; i++ {
		exec(adbA, "INSERT INTO shop.orders VALUES (?, 'y', ?)", i, fmt.Sprintf("buyer%d@shop.test", i))
	}
	time.Sleep(1100 * time.Millisecond)
	at := time.Now().UTC().Truncate(time.Second)
	time.Sleep(2 * time.Second)
	exec(adbA, "DELETE FROM shop.orders WHERE id <= 10")
	for i := 0; i < 20; i++ {
		_, _ = e.Archiver(ctx, envA, specA)
		time.Sleep(time.Second)
	}
	major, size, settings, err := e.ForkFacts(ctx, envA, specA)
	if err != nil || major == 0 {
		t.Fatalf("facts: %d %v", major, err)
	}
	res, err := e.ForkRestore(ctx, envB, protocol.ForkRestoreParams{ForkID: "fork_1", Name: "shop-staging", Source: specA,
		Target: protocol.RewindTarget{Time: &at, BackupSet: full.Label}, Placement: protocol.ForkEmptyServer, Port: 3306, SocketDir: sbSocket,
		Major: major, SizeBytes: size, Settings: settings,
		// Masked: a saved rule, and the suggestions (the email column).
		Masking: &protocol.ForkMasking{Rules: []protocol.ForkMaskRule{{DB: "shop", Table: "orders", Column: "note", Strategy: "null"}}, Suggest: true}}, tl)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	if res.Masking == nil || res.Masking.Columns != 2 || len(res.Masking.Masked) != 2 {
		t.Fatalf("masking: %+v", res.Masking)
	}
	if n := count(adbB, "SELECT COUNT(*) FROM shop.orders WHERE email LIKE '%@shop.test' OR note IS NOT NULL"); n != 0 {
		t.Fatalf("the clone has %d unmasked orders", n)
	}
	t.Logf("clone: %+v", res)
	if n := count(adbB, "SELECT COUNT(*) FROM shop.orders"); n != 80 {
		t.Fatalf("the clone has %d orders, want 80 (as it was before the delete)", n)
	}
	if n := count(adbB, "SELECT COUNT(*) FROM mysql.user WHERE User = 'app'"); n != 1 {
		t.Fatalf("the app login wasn't cloned: %d", n)
	}
	if res.RecoveredTo == nil || res.RecoveredTo.After(at) || len(res.Databases) != 1 {
		t.Fatalf("result: %+v", res)
	}
	// A second clone into the same (now full) server is refused.
	if _, err := e.ForkRestore(ctx, envB, protocol.ForkRestoreParams{ForkID: "fork_2", Name: "x", Source: specA,
		Target: protocol.RewindTarget{Time: &at}, Placement: protocol.ForkEmptyServer, Port: 3306, SocketDir: sbSocket, Major: major}, tl); err == nil ||
		!strings.Contains(err.Error(), "isn't empty") {
		t.Fatalf("second clone: %v", err)
	}
}
