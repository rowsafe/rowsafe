//go:build redis_integration

package redis

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// extraServer starts another empty server of the image's program on port
// (no password, no persistence) and stops it when the test ends.
func extraServer(t *testing.T, port int, args ...string) {
	t.Helper()
	bin := os.Getenv("ROWSAFE_TEST_SERVER_BIN")
	if bin == "" {
		t.Skip("ROWSAFE_TEST_SERVER_BIN not set")
	}
	dir := t.TempDir()
	cmd := exec.Command(bin, append([]string{"--port", strconv.Itoa(port), "--daemonize", "yes", "--dir", dir, "--save", "",
		"--appendonly", "no", "--protected-mode", "no", "--pidfile", dir + "/pid", "--logfile", dir + "/log"}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("starting a server on %d: %v %s", port, err, out)
	}
	t.Cleanup(func() {
		if c, err := dial(context.Background(), "127.0.0.1:"+strconv.Itoa(port)); err == nil {
			_, _ = c.do(context.Background(), "AUTH", LoginUser, "x")
			c.Close()
		}
		if data, err := os.ReadFile(dir + "/pid"); err == nil {
			_ = exec.Command("kill", strings.TrimSpace(string(data))).Run()
		}
		time.Sleep(300 * time.Millisecond)
	})
	waitFor(t, 10*time.Second, func() bool { return listening(port) })
}

// handOver makes an empty server Rowsafe's for clones and standbys (what
// the installer does with --redis-clones / --redis-standby there).
func handOver(t *testing.T, env agent.EngineEnv, port int) {
	t.Helper()
	if _, err := CreateLoginWith(context.Background(), env, port, "", "", LoginOptions{Target: targetAll}); err != nil {
		t.Fatal(err)
	}
}

func srv(t *testing.T, port int) *conn {
	t.Helper()
	c, err := dial(context.Background(), "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestRedisFork clones the database as it was at a moment (and masked)
// into an empty server.
func TestRedisFork(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	rd(t, a, "HSET", "profile:1", "email", "ana.real@corp.example", "plan", "pro")
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	mustRun[protocol.BackupResult](t, e, env, db, protocol.TaskBackup, nil)
	rd(t, a, "SET", "before:moment", "1", "EX", 9000)
	time.Sleep(1100 * time.Millisecond)
	at := time.Now().UTC()
	time.Sleep(1100 * time.Millisecond)
	rd(t, a, "SET", "after:moment", "1")
	rd(t, a, "DEL", "user:1")
	f := e.existingFollower(db.ID)
	if err := f.flush(ctx, f.snapshot().StreamID, infoMapOf(t, a, "replication").int("master_repl_offset"), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	ff, _, _, err := e.ForkFacts(ctx, env, db)
	if err != nil {
		t.Fatal(err)
	}
	extraServer(t, 6390)
	extraServer(t, 6392, "--databases", "4")
	handOver(t, env, 6390)
	handOver(t, env, 6392)
	targets := e.StandbyTargets(ctx, env)
	usable := 0
	for _, tg := range targets {
		if (tg.Port == 6390 || tg.Port == 6392) && tg.Usable && tg.Standby {
			usable++
		}
	}
	if usable != 2 {
		t.Fatalf("targets: %+v", targets)
	}
	p := protocol.ForkRestoreParams{ForkID: "f1", Name: "cache-clone", Source: db, Target: protocol.RewindTarget{Time: &at},
		Placement: protocol.ForkEmptyServer, Port: 6390, Major: ff, Settings: map[string]int{settingDatabases: 16}}
	res, err := e.ForkRestore(ctx, env, p, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(res.Summary, res.Warnings)
	c := srv(t, 6390)
	if asInt(rd(t, c, "EXISTS", "before:moment")) != 1 || asInt(rd(t, c, "EXISTS", "after:moment")) != 0 || asInt(rd(t, c, "EXISTS", "user:1")) != 1 {
		t.Fatal("the clone isn't as of the moment")
	}
	if ttl := asInt(rd(t, c, "TTL", "before:moment")); ttl < 8000 {
		t.Fatalf("time to live lost: %d", ttl)
	}
	if n := dbsize(t, c, 3); n != 100 {
		t.Fatalf("db3 in the clone: %d", n)
	}
	// Into a server that isn't empty: refused, nothing changed.
	if _, err := e.ForkRestore(ctx, env, p, &testLog{t: t}); err == nil || !strings.Contains(err.Error(), "isn't empty") {
		t.Fatalf("a full server took a clone: %v", err)
	}
	// Fewer logical databases than the source: refused.
	p2 := p
	p2.ForkID, p2.Port = "f2", 6392
	if _, err := e.ForkRestore(ctx, env, p2, &testLog{t: t}); err == nil || !strings.Contains(err.Error(), "logical databases") {
		t.Fatalf("a server with 4 databases took 16: %v", err)
	}
	// Masked, at the latest point.
	p3 := protocol.ForkRestoreParams{ForkID: "f3", Name: "masked", Source: db, Placement: protocol.ForkEmptyServer, Port: 6392,
		Masking: &protocol.ForkMasking{Suggest: true}}
	rd(t, a, "SELECT", 3)
	rd(t, a, "FLUSHDB")
	rd(t, a, "SELECT", 0)
	if err := f.flush(ctx, f.snapshot().StreamID, infoMapOf(t, a, "replication").int("master_repl_offset"), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	res3, err := e.ForkRestore(ctx, env, p3, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if res3.Masking == nil || res3.Masking.Rows == 0 {
		t.Fatalf("masking: %+v", res3.Masking)
	}
	if v := asString(rd(t, srv(t, 6392), "HGET", "profile:1", "email")); strings.Contains(v, "real") {
		t.Fatalf("the masked clone holds a real email: %s", v)
	}
}

// TestRedisStandby sets up a standby, fences the primary, promotes the
// standby, turns the old primary into its replica, and checks Rowsafe's
// link follows the new primary.
func TestRedisStandby(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	seed(t, a)
	t.Cleanup(func() {
		_, _ = a.do(ctx, "REPLICAOF", "NO", "ONE")
		_, _ = a.do(ctx, "CONFIG", "SET", "min-replicas-to-write", "0")
	})
	if _, err := CreateLoginWith(ctx, env, db.Port, "default", os.Getenv("ROWSAFE_TEST_REDIS_ADMIN_PASSWORD"), LoginOptions{Standby: true}); err != nil {
		t.Fatal(err)
	}
	rd(t, a, "ACL", "SETUSER", "app", "reset", "on", ">app-secret", "~app:*", "+@all")
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})
	mustRun[protocol.CheckResult](t, e, env, db, protocol.TaskCheck, nil)
	extraServer(t, 6391)
	handOver(t, env, 6391)

	// Prepare on the primary, create on the standby's server.
	sec := protocol.StandbySecrets{PrimaryPort: db.Port, PrimaryAddresses: []string{"127.0.0.1"}}
	var prep protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, env, db, protocol.StandbyPrepareParams{StandbyID: "sb1", StandbyAddresses: []string{"127.0.0.1"}, Stream: true},
		&sec, &prep, &testLog{t: t}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sec.EngineData[edACL], "user app ") || strings.Contains(sec.EngineData[edACL], "user rowsafe ") {
		t.Fatalf("users handed over: %q", sec.EngineData[edACL])
	}
	sdb := db
	sdb.Port = 6391
	cr, err := e.StandbyCreate(ctx, env, sdb, protocol.StandbyCreateParams{StandbyID: "sb1", Port: 6391, Major: prep.Major, Settings: prep.Settings}, sec, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(cr.Summary)
	// The primary's users came along: its default user's password too.
	s := admin(t, 6391)
	rd(t, a, "SET", "after:standby", "1")
	waitFor(t, 20*time.Second, func() bool { return asInt(rd(t, s, "EXISTS", "after:standby")) == 1 })
	if dbsize(t, s, 0) != dbsize(t, a, 0) {
		t.Fatal("the standby misses keys")
	}
	if _, err := s.do(ctx, "SET", "x", "1"); err == nil {
		t.Fatal("the standby takes writes")
	}
	// The app's user works on the standby.
	if ac, err := connectAddr(ctx, "127.0.0.1:6391", "app", "app-secret", ""); err != nil {
		t.Fatal("the app's user on the standby:", err)
	} else {
		ac.Close()
	}
	// The primary's position and its standby, never Rowsafe's link.
	ps, ok := e.PrimaryState(ctx, env, db)
	if !ok || len(ps.Streams) != 1 || ps.Streams[0].Role != protocol.StandbyRoleName("sb1") {
		t.Fatalf("primary state: %+v (%v)", ps, infoMapOf(t, a, "replication"))
	}
	st := e.StandbyStates(ctx, env)
	if len(st) != 1 || !st[0].InRecovery || st[0].ReceiverStatus != "streaming" || st[0].ReplayLSN == "" {
		t.Fatalf("standby states: %+v", st)
	}
	dm, _ := e.Monitor(ctx, env, db)
	if dm == nil || dm.Redis == nil || len(dm.Redis.Replicas) != 1 {
		t.Fatalf("Pulse should count the standby, not the link: %+v", dm)
	}

	// Planned switchover: fence, promote.
	fr, err := e.StandbyFence(ctx, env, db, protocol.StandbyFenceParams{FenceID: "fence1", StandbyID: "sb1"}, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.do(ctx, "SET", "y", "1"); err == nil || !strings.Contains(err.Error(), "NOREPLICAS") {
		t.Fatalf("the fenced primary takes writes: %v", err)
	}
	if _, err := e.Archiver(ctx, env, db); err == nil {
		ar, _ := e.Archiver(ctx, env, db)
		if ar != nil && ar.Error == "" {
			t.Fatal("Rowsafe still follows the fenced primary")
		}
	}
	if enforced, _, err := e.HoldFence(ctx, env, protocol.Fence{ID: "fence1", DatabaseID: db.ID, Port: db.Port}); err != nil || enforced {
		t.Fatalf("hold: %v %v", enforced, err)
	}
	rd(t, a, "CONFIG", "SET", "min-replicas-to-write", "0") // someone undoes it by hand
	if enforced, _, _ := e.HoldFence(ctx, env, protocol.Fence{ID: "fence1", DatabaseID: db.ID, Port: db.Port}); !enforced {
		t.Fatal("the fence wasn't enforced again")
	}
	pr, err := e.StandbyPromote(ctx, env, sdb, protocol.StandbyPromoteParams{StandbyID: "sb1", WaitForLSN: fr.CheckpointLSN}, &testLog{t: t})
	if err != nil || !pr.Promoted || !pr.CaughtUp {
		t.Fatalf("promote: %+v %v", pr, err)
	}
	rd(t, s, "SET", "on:new", "1")

	// The old primary follows the new one.
	sec2 := protocol.StandbySecrets{PrimaryPort: 6391, PrimaryAddresses: []string{"127.0.0.1"}}
	var prep2 protocol.StandbyPrepareResult
	if err := e.StandbyPrepare(ctx, env, sdb, protocol.StandbyPrepareParams{StandbyID: "sb2", StandbyAddresses: []string{"127.0.0.1"}, Stream: true},
		&sec2, &prep2, &testLog{t: t}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.StandbyCreate(ctx, env, db, protocol.StandbyCreateParams{StandbyID: "sb2", Port: db.Port, Rebuild: true, FenceID: "fence1", Reattach: true},
		sec2, &testLog{t: t}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 20*time.Second, func() bool { return asInt(rd(t, a, "EXISTS", "on:new")) == 1 })

	// Rowsafe follows the new primary: a check, then a write reaches the bucket.
	mustRun[protocol.CheckResult](t, e, env, sdb, protocol.TaskCheck, nil)
	rd(t, s, "SET", "followed:new", "1")
	f := e.existingFollower(sdb.ID)
	m := infoMapOf(t, s, "replication")
	waitFor(t, 30*time.Second, func() bool { return f.snapshot().ServerReplID == m["master_replid"] })
	if err := f.flush(ctx, f.snapshot().StreamID, m.int("master_repl_offset"), 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	now := time.Now().UTC()
	mustRun[protocol.RewindCopyResult](t, e, env, sdb, protocol.TaskRewindCopy, protocol.RewindCopyParams{CopyID: "afterswitch", Target: protocol.RewindTarget{Time: &now}})
	cc, err := scratchAt(env, copyRoot(env, e.name)+"/afterswitch").connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	if asInt(rd(t, cc, "EXISTS", "followed:new")) != 1 {
		t.Fatal("a restore after the switch misses the new primary's writes")
	}
	// Clean up: the old primary is a primary again for the other tests.
	if _, err := e.StandbyRemove(ctx, env, db, protocol.StandbyRemoveParams{StandbyID: "sb2"}, &testLog{t: t}); err != nil {
		t.Fatal(err)
	}
}
