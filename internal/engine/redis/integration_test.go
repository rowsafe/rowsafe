//go:build redis_integration

// Integration test against a real Redis or Valkey server, with its server
// program installed (Proof and copies start their own). Run it with
// scripts/test-redis.sh, which runs it inside the official redis and
// valkey/valkey images:
//
//	ROWSAFE_TEST_REDIS_PORT=6379 ROWSAFE_TEST_REDIS_ENGINE=redis ROWSAFE_TEST_REDIS_ADMIN_PASSWORD=... \
//	    go test -tags redis_integration ./internal/engine/redis/
//
// The server's default user has ROWSAFE_TEST_REDIS_ADMIN_PASSWORD. With
// ROWSAFE_REDIS_HOST set, it tests a Docker sidecar (the server in another
// container; ROWSAFE_REDIS_DATA_DIR is its data volume, read only).
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type testLog struct {
	t  *testing.T
	mu sync.Mutex
	b  strings.Builder
}

func (l *testLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := fmt.Sprintf(format, args...)
	l.b.WriteString(s + "\n")
	l.t.Log(s)
}

func (l *testLog) Output(label string, out []byte) {
	if len(out) > 0 {
		l.Printf("%s output:\n%s", label, out)
	}
}

func testRepo(t *testing.T, bucket string) pgbackrest.Repo {
	srv := fakes3.New(bucket)
	t.Cleanup(srv.Close)
	return pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: bucket, Key: "k", KeySecret: "s", Region: "us-east-1",
		CipherPass: "integration-test-passphrase-123", PathPrefix: "/rowsafe"}
}

func testEnv(t *testing.T, engine string) agent.EngineEnv {
	t.Helper()
	dir := t.TempDir()
	return agent.EngineEnv{
		Config: agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind"),
			RestorePointTimeout: 60 * time.Second},
		StateDir: filepath.Join(dir, "engines", engine),
		Repo:     testRepo(t, "bkt"),
		Log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		Notes:    os.Stderr,
	}
}

func run[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) (*T, error) {
	t.Helper()
	raw, _ := json.Marshal(params)
	task := &protocol.Task{ID: "task_" + strconv.FormatInt(time.Now().UnixNano(), 36), Type: typ, Database: &db, Params: raw}
	res, err := e.Run(context.Background(), env, task, &testLog{t: t})
	if res == nil {
		return nil, err
	}
	return res.(*T), err
}

func mustRun[T any](t *testing.T, e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, typ string, params any) *T {
	t.Helper()
	r, err := run[T](t, e, env, db, typ, params)
	if err != nil {
		t.Fatalf("%s: %v", typ, err)
	}
	return r
}

// admin is a connection as the server's administrator.
func admin(t *testing.T, port int) *conn {
	t.Helper()
	c, err := connectAddr(context.Background(), addrOf(Login{}, port), "", os.Getenv("ROWSAFE_TEST_REDIS_ADMIN_PASSWORD"), "rowsafe-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func rd(t *testing.T, c *conn, args ...any) any {
	t.Helper()
	v, err := c.do(context.Background(), args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return v
}

func setup(t *testing.T) (e *Engine, env agent.EngineEnv, db protocol.DatabaseSpec, a *conn) {
	port, _ := strconv.Atoi(os.Getenv("ROWSAFE_TEST_REDIS_PORT"))
	if port == 0 {
		t.Skip("ROWSAFE_TEST_REDIS_PORT not set")
	}
	engine := cmpOr(os.Getenv("ROWSAFE_TEST_REDIS_ENGINE"), protocol.EngineRedis)
	rotateEvery, idleRotateEvery, reuseWithin = 2*time.Second, 5*time.Second, 0
	env = testEnv(t, engine)
	e = &Engine{name: engine}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		time.Sleep(200 * time.Millisecond)
	})
	e.Start(ctx, env)
	a = admin(t, port)
	rd(t, a, "FLUSHALL")
	for _, n := range []int{0, 1, 3, 15} {
		rd(t, a, "SELECT", n)
		rd(t, a, "FLUSHDB")
	}
	rd(t, a, "SELECT", 0)
	_, _ = a.do(context.Background(), "ACL", "DELUSER", LoginUser)
	res, err := CreateLogin(context.Background(), env, port, "default", os.Getenv("ROWSAFE_TEST_REDIS_ADMIN_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("login kept: %s %s", res.Persisted, res.Why)
	db = protocol.DatabaseSpec{ID: "db_" + engine, Name: "cache", Port: port, Engine: engine, Stanza: "cache-" + strconv.FormatInt(time.Now().UnixNano(), 36), RetentionFull: 3}
	return e, env, db, a
}

func dbsize(t *testing.T, c *conn, n int) int64 {
	t.Helper()
	rd(t, c, "SELECT", n)
	defer rd(t, c, "SELECT", 0)
	return asInt(rd(t, c, "DBSIZE"))
}

func seed(t *testing.T, a *conn) {
	t.Helper()
	ctx := context.Background()
	var cmds [][]any
	for i := 0; i < 2000; i++ {
		cmds = append(cmds, []any{"SET", fmt.Sprintf("user:%d", i), fmt.Sprintf("name-%d", i)})
	}
	for i := 0; i < 300; i++ {
		cmds = append(cmds, []any{"SET", fmt.Sprintf("session:%d", i), "x", "EX", 3600})
	}
	cmds = append(cmds,
		[]any{"HSET", "h:1", "a", "1", "b", "2"}, []any{"RPUSH", "l:1", "a", "b", "c"}, []any{"SADD", "s:1", "x", "y"},
		[]any{"ZADD", "z:1", 1, "one", 2, "two"}, []any{"XADD", "x:1", "*", "f", "v"})
	if _, errs, err := a.pipeline(ctx, cmds); err != nil || slices.ContainsFunc(errs, func(e error) bool { return e != nil }) {
		t.Fatalf("seeding: %v %v", err, errs)
	}
	rd(t, a, "SELECT", 3)
	for i := 0; i < 100; i++ {
		rd(t, a, "SET", fmt.Sprintf("order:%d", i), i)
	}
	rd(t, a, "SELECT", 0)
}

func TestRedisEndToEnd(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)

	// Adopt: plan, then apply (the link starts and gets a first snapshot).
	plan := mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{})
	if plan.Applied || len(plan.Plan) == 0 || plan.Inspect.Engine != e.name {
		t.Fatalf("plan: %+v", plan)
	}
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	chk := mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	if !chk.OK || chk.Inspect.ArchiveMode != "on" {
		t.Fatalf("check: %+v", chk)
	}

	// The link is a replica Pulse doesn't count.
	m := infoMapOf(t, a, "replication")
	if !strings.Contains(m["slave0"], "ip="+linkAddr) {
		t.Fatalf("the link isn't listed as %s: %v", linkAddr, m)
	}
	dm, err := e.Monitor(ctx, env, db)
	if err != nil || dm.Error != "" {
		t.Fatalf("monitor: %v %+v", err, dm)
	}
	if dm.Metrics["redis_connected_replicas"] != 0 || dm.Redis == nil || len(dm.Redis.Replicas) != 0 || dm.Redis.Link != modeReplica {
		t.Fatalf("monitor counts the link: %+v %+v", dm.Metrics, dm.Redis)
	}
	if dm.Metrics["redis_keys"] < 2405 {
		t.Fatalf("keys: %v", dm.Metrics["redis_keys"])
	}

	// A backup over the replication handshake.
	b := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull})
	if b.Label == "" || !strings.Contains(b.WALStart, ":") || b.RepoSizeBytes == 0 {
		t.Fatalf("backup: %+v", b)
	}

	// Changes, a Mark, then an accident.
	rd(t, a, "SET", "user:0", "changed")
	rd(t, a, "DEL", "user:1")
	rd(t, a, "MULTI")
	rd(t, a, "SET", "tx:a", "1")
	rd(t, a, "SET", "tx:b", "2")
	rd(t, a, "EXEC")
	time.Sleep(1500 * time.Millisecond)
	beforeMark := time.Now().UTC()
	time.Sleep(1500 * time.Millisecond)
	mk := mustRun[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "before-cleanup"})
	if !mk.Archived {
		t.Fatalf("mark: %+v", mk)
	}
	var del []any
	for i := 100; i < 600; i++ {
		del = append(del, fmt.Sprintf("user:%d", i))
	}
	rd(t, a, append([]any{"DEL"}, del...)...)
	rd(t, a, "SET", "user:2", "changed-after")
	rd(t, a, "SELECT", 3)
	rd(t, a, "FLUSHDB")
	rd(t, a, "SELECT", 0)
	rd(t, a, "SET", "new:after", "1")

	// A copy at the Mark; compare.
	cp := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c1",
		Target: protocol.RewindTarget{Mark: "before-cleanup"}})
	if cp.SocketDir == "" || len(cp.Databases) != 2 {
		t.Fatalf("copy: %+v", cp)
	}
	cmpRes := mustRun[protocol.RewindCompareResult](t, e, env, db, protocol.TaskRewindCompare, protocol.RewindCompareParams{CopyID: "c1"})
	byDB := map[string]protocol.RewindTableDiff{}
	for _, d := range cmpRes.Tables {
		byDB[d.DB] = d
	}
	if d := byDB["0"]; d.MissingInProduction != 500 || d.Changed != 1 || d.OnlyInProduction != 1 {
		t.Fatalf("compare db0: %+v (%s)", d, cmpRes.Summary)
	}
	if d := byDB["3"]; d.MissingInProduction != 100 {
		t.Fatalf("compare db3: %+v", d)
	}
	// Bring back the deleted users (not the changed one), then db3.
	rows := mustRun[protocol.RewindRowsResult](t, e, env, db, protocol.TaskRewindRows, protocol.RewindRowsParams{CopyID: "c1",
		Tables: []protocol.RewindTable{{DB: "0", Table: "user:*"}, {DB: "3", Table: "*"}}})
	if rows.Tables[0].Inserted != 500 || rows.Tables[1].Inserted != 100 {
		t.Fatalf("rows: %+v", rows)
	}
	if got := asString(rd(t, a, "GET", "user:2")); got != "changed-after" {
		t.Fatalf("a changed key was overwritten: %q", got)
	}
	if got := asString(rd(t, a, "GET", "user:150")); got != "name-150" {
		t.Fatalf("user:150 = %q", got)
	}
	if n := dbsize(t, a, 3); n != 100 {
		t.Fatalf("db3 has %d keys", n)
	}
	mustRun[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c1"})

	// A copy at a second: before the Mark, user:0 changed, tx keys there.
	cp2 := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c2",
		Target: protocol.RewindTarget{Time: &beforeMark}})
	if cp2.RecoveredTo == nil || cp2.RecoveredTo.After(beforeMark.Add(time.Second)) {
		t.Fatalf("copy at a second: %+v", cp2)
	}
	sc := scratchAt(env, filepath.Join(copyRoot(env, e.name), "c2"))
	sconn, err := sc.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v := asString(rd(t, sconn, "GET", "user:0")); v != "changed" {
		t.Fatalf("copy at a second: user:0 = %q", v)
	}
	if n := asInt(rd(t, sconn, "EXISTS", "tx:a", "tx:b", "user:1", "user:150")); n != 3 {
		t.Fatalf("copy at a second: %d of tx:a tx:b user:150 exist", n)
	}
	if ttl := asInt(rd(t, sconn, "TTL", "session:5")); ttl <= 0 {
		t.Fatalf("the copy lost expiries: TTL %d", ttl)
	}
	sconn.Close()
	mustRun[protocol.RewindDropResult](t, e, env, db, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c2"})

	// Proof.
	dr := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if !dr.Passed || len(dr.Databases) == 0 {
		t.Fatalf("drill: %+v", dr)
	}

	// Rewind in place to the Mark, then undo.
	rd(t, a, "SET", "doomed", "1")
	ip := mustRun[protocol.RewindInPlaceResult](t, e, env, db, protocol.TaskRewindInPlace, protocol.RewindInPlaceParams{RewindID: "r1",
		Target: protocol.RewindTarget{Mark: "before-cleanup"}, KeepDays: 7})
	if ip.KeptUntil == nil {
		t.Fatalf("in place: %+v", ip)
	}
	if n := asInt(rd(t, a, "EXISTS", "doomed", "new:after")); n != 0 {
		t.Fatalf("rewind in place kept later keys (%d)", n)
	}
	if v := asString(rd(t, a, "GET", "user:2")); v != "name-2" {
		t.Fatalf("rewind in place: user:2 = %q", v)
	}
	if n := dbsize(t, a, 3); n != 100 {
		t.Fatalf("rewind in place: db3 has %d keys", n)
	}
	for n := 4; n < 16; n++ {
		if s := dbsize(t, a, n); s != 0 {
			t.Fatalf("db%d not empty after the swap (%d)", n, s)
		}
	}
	un := mustRun[protocol.RewindUndoResult](t, e, env, db, protocol.TaskRewindUndo, protocol.RewindUndoParams{RewindID: "r1"})
	if un.KeptUntil == nil {
		t.Fatalf("undo: %+v", un)
	}
	if n := asInt(rd(t, a, "EXISTS", "doomed", "new:after")); n != 2 {
		t.Fatalf("undo didn't bring later keys back (%d)", n)
	}
	mustRun[protocol.RewindCleanupResult](t, e, env, db, protocol.TaskRewindCleanup, protocol.RewindCleanupParams{RewindID: "r1"})

	// Fixes.
	rd(t, a, "CONFIG", "SET", "maxmemory-policy", "noeviction")
	fx := mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintRedisEvictionPolicy,
		Settings: map[string]string{"maxmemory-policy": "allkeys-lru"}})
	t.Log(fx.Summary)
	if v, _ := a.configGet(ctx, "maxmemory-policy"); v != "allkeys-lru" {
		t.Fatalf("policy %q", v)
	}
	rd(t, a, "CONFIG", "SET", "maxmemory-policy", "noeviction")
	mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintRedisBacklog,
		Settings: map[string]string{"repl-backlog-size": strconv.Itoa(8 << 20)}})
	if m := infoMapOf(t, a, "memory"); strings.HasPrefix(m["mem_allocator"], "jemalloc") {
		mustRun[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintRedisMemoryPurge})
	}
	victim, err := connectAddr(ctx, addrOf(Login{}, db.Port), "", os.Getenv("ROWSAFE_TEST_REDIS_ADMIN_PASSWORD"), "victim")
	if err != nil {
		t.Fatal(err)
	}
	vid := asInt(rd(t, victim, "CLIENT", "ID"))
	start := time.Now()
	if _, err := run[protocol.MaintenanceResult](t, e, env, db, protocol.TaskMaintenance, protocol.MaintenanceParams{Action: protocol.MaintRedisKillClient,
		PID: int(vid), BackendStart: &start}); err != nil {
		t.Fatal(err)
	}
	if _, err := victim.do(ctx, "PING"); err == nil {
		t.Fatal("the client wasn't disconnected")
	}
	victim.Close()

	// The link drops: it continues where it stopped (no new snapshot).
	f := e.existingFollower(db.ID)
	before := len(f.snapshot().FullSyncs)
	rd(t, a, "CLIENT", "KILL", "TYPE", "replica")
	rd(t, a, "SET", "after:kill", "1")
	waitFor(t, 30*time.Second, func() bool { return f.waitFollowing(ctx, time.Second) == nil && f.snapshot().Offset > 0 })
	time.Sleep(3 * time.Second)
	if n := len(f.snapshot().FullSyncs); n != before {
		t.Fatalf("a dropped link asked for a whole snapshot (%d -> %d)", before, n)
	}
	// Away longer than the backlog holds: a new snapshot, kept as a backup.
	rd(t, a, "CONFIG", "SET", "repl-backlog-size", "16384")
	rd(t, a, "CLIENT", "KILL", "TYPE", "replica")
	big := strings.Repeat("x", 1024)
	var cmds [][]any
	for i := 0; i < 400; i++ {
		cmds = append(cmds, []any{"SET", fmt.Sprintf("bulk:%d", i), big})
	}
	if _, _, err := a.pipeline(ctx, cmds); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 60*time.Second, func() bool { return len(f.snapshot().FullSyncs) > before })
	rd(t, a, "CONFIG", "SET", "repl-backlog-size", strconv.Itoa(8<<20))
	st := mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	if !st.OK {
		t.Fatal("check after a new snapshot")
	}
	r, _ := openRepo(env, db)
	docs, _, _ := r.listBackups(ctx)
	if len(docs) == 0 || docs[len(docs)-1].Source != sourceAutomatic || docs[len(docs)-1].Note == "" {
		t.Fatalf("the new snapshot isn't the newest backup: %+v", docs)
	}
	dr2 := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if !dr2.Passed {
		t.Fatalf("drill after a new snapshot: %+v", dr2)
	}
	ar, _ := e.Archiver(ctx, env, db)
	if ar.ArchiveMode != "on" || ar.ArchivedCount == 0 || ar.Error != "" {
		t.Fatalf("archiver: %+v", ar)
	}
	if rr, err := e.Ready(ctx, env, db); err != nil || rr != "on" {
		t.Fatalf("ready: %q %v", rr, err)
	}
}

func TestRedisSecondCopy(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	env2 := env
	env2.Repo = testRepo(t, "bkt2")
	env2.StateDir = filepath.Join(env.StateDir, "copy2")
	db2 := db
	db2.ID += "~copy2"
	if _, err := e.Archiver(ctx, env, db); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Archiver(ctx, env2, db2); err != nil {
		t.Fatal(err)
	}
	mustRun[protocol.BackupResult](t, e, env2, db2, protocol.TaskBackup, nil)
	rd(t, a, "SET", "after:copy2", "1")
	time.Sleep(time.Second)
	at := time.Now().UTC()
	time.Sleep(3 * time.Second)
	r2, _ := openRepo(env2, db2)
	waitFor(t, 60*time.Second, func() bool {
		segs, _ := r2.listSegments(ctx)
		for _, s := range segs {
			if s.To.After(at) {
				return true
			}
		}
		return false
	})
	ar, _ := e.Archiver(ctx, env2, db2)
	if ar == nil || ar.ArchivedCount == 0 {
		t.Fatalf("second copy archiver: %+v", ar)
	}
	dr := mustRun[protocol.DrillResult](t, e, env2, db2, protocol.TaskDrill, nil)
	if !dr.Passed {
		t.Fatalf("drill from the second copy: %+v", dr)
	}
	cp := mustRun[protocol.RewindCopyResult](t, e, env2, db2, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c9",
		Target: protocol.RewindTarget{Time: &at}})
	sconn, err := scratchAt(env2, filepath.Join(copyRoot(env2, e.name), "c9")).connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n := asInt(rd(t, sconn, "EXISTS", "after:copy2")); n != 1 {
		t.Fatalf("second copy at a second misses a change: %+v", cp)
	}
	sconn.Close()
	mustRun[protocol.RewindDropResult](t, e, env2, db2, protocol.TaskRewindDrop, protocol.RewindDropParams{CopyID: "c9"})
}

func TestRedisSnapshotMode(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	// Replication refused for Rowsafe's user.
	rd(t, a, "ACL", "SETUSER", LoginUser, "-psync", "-sync")
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	chk, err := run[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	if err != nil || !chk.OK || chk.Inspect.ArchiveMode != protocol.RedisArchiveSnapshots {
		t.Fatalf("check in snapshot mode: %+v %v", chk, err)
	}
	ar, _ := e.Archiver(ctx, env, db)
	if ar.ArchiveMode != protocol.RedisArchiveSnapshots || ar.Error == "" {
		t.Fatalf("archiver in snapshot mode: %+v", ar)
	}
	b := mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, nil)
	t.Logf("snapshot backup %+v", b)
	dr := mustRun[protocol.DrillResult](t, e, env, db, protocol.TaskDrill, nil)
	if !dr.Passed {
		t.Fatalf("drill in snapshot mode: %+v", dr)
	}
	now := time.Now().UTC()
	if _, err := run[protocol.RestorePointResult](t, e, env, db, protocol.TaskRestorePoint, protocol.RestorePointParams{Name: "m"}); err == nil {
		t.Fatal("a Mark in snapshot mode")
	}
	cp := mustRun[protocol.RewindCopyResult](t, e, env, db, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "c3",
		Target: protocol.RewindTarget{Time: &now}})
	t.Log(cp.Summary)
	rd(t, a, "ACL", "SETUSER", LoginUser, "+psync", "+sync")
}

func TestRedisMinReplicasToWrite(t *testing.T) {
	e, env, db, a := setup(t)
	rd(t, a, "CONFIG", "SET", "min-replicas-to-write", "1")
	defer rd(t, a, "CONFIG", "SET", "min-replicas-to-write", "0")
	plan := mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{})
	if plan.Inspect.ArchiveMode != protocol.RedisArchiveSnapshots || len(plan.Warnings) == 0 {
		t.Fatalf("plan with min-replicas-to-write: %+v", plan)
	}
	rd(t, a, "CONFIG", "SET", "min-replicas-to-write", "0")
}

func infoMapOf(t *testing.T, c *conn, section string) infoMap {
	t.Helper()
	m, err := c.info(context.Background(), section)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func waitFor(t *testing.T, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s", d)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

var _ = errors.New
