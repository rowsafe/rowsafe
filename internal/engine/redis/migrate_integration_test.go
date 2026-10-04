//go:build redis_integration

package redis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// providerConn is the "managed provider" the test moves in from: a second
// container (ROWSAFE_TEST_PROVIDER_ADDR, password ROWSAFE_TEST_PROVIDER_PASSWORD
// for its default user), or else a second server here.
func providerConn(t *testing.T) (addr, pass string, c *conn) {
	t.Helper()
	addr, pass = os.Getenv("ROWSAFE_TEST_PROVIDER_ADDR"), os.Getenv("ROWSAFE_TEST_PROVIDER_PASSWORD")
	if addr == "" {
		extraServer(t, 6393, "--requirepass", "provider-pass")
		addr, pass = "127.0.0.1:6393", "provider-pass"
	}
	c, err := connectAddr(context.Background(), addr, "", pass, "rowsafe-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	rd(t, c, "FLUSHALL")
	return addr, pass, c
}

func migEnv(t *testing.T, id string) agent.MigrateEnv {
	dir := filepath.Join(t.TempDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var phase atomic.Value
	phase.Store(protocol.MigratePhaseNew)
	return agent.MigrateEnv{ID: id, Dir: dir, Phase: protocol.MigratePhaseNew,
		SetPhase: func(p string) { phase.Store(p) }, Progress: func(protocol.MigrationStatus) {}}
}

func TestRedisMoveIn(t *testing.T) {
	e, env, db, a := setup(t)
	ctx := context.Background()
	if _, err := CreateLoginWith(ctx, env, db.Port, "default", os.Getenv("ROWSAFE_TEST_REDIS_ADMIN_PASSWORD"), LoginOptions{Standby: true}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = a.do(ctx, "REPLICAOF", "NO", "ONE")
		_, _ = a.do(ctx, "CONFIG", "SET", "masterauth", "")
	})
	addr, pass, p := providerConn(t)
	seed(t, p)
	rd(t, p, "SET", "ttl:key", "v", "EX", 5000)
	rd(t, p, "HSET", "big:hash", "f1", "v1", "f2", "v2")
	mustRun[protocol.AdoptResult](t, e, env, db, protocol.TaskAdopt, protocol.AdoptParams{Apply: true})

	host, port, _ := strings_cut(addr)
	src := fmt.Sprintf("redis://default:%s@%s:%s", pass, host, port)

	// One-time copy.
	m := migEnv(t, "mig1")
	if err := saveSecretFile(filepath.Join(m.Dir, "source"), []byte(src)); err != nil {
		t.Fatal(err)
	}
	chk, err := e.migrateCheck(ctx, env, db, m, protocol.MigrateParams{MigrationID: "mig1", Action: protocol.MigrateCheck}, &testLog{t: t})
	if err != nil || !chk.DumpOK {
		t.Fatalf("check: %+v %v", chk, err)
	}
	t.Logf("check: %s (live %v)", chk.Summary, chk.LiveSync)
	cr, err := e.migrateCopy(ctx, env, db, m, protocol.MigrateParams{MigrationID: "mig1", Method: protocol.MigrateMethodDump, AppUser: "app"}, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if cr.Switchover == nil || cr.Switchover.Mismatches != 0 || cr.Switchover.AppUser != "app" {
		t.Fatalf("one-time copy: %+v %+v", cr, cr.Switchover)
	}
	if ttl := asInt(rd(t, a, "TTL", "ttl:key")); ttl < 4000 {
		t.Fatalf("time to live lost: %d", ttl)
	}
	if dbsize(t, a, 3) != 100 {
		t.Fatal("db3 not copied")
	}
	// A target that isn't empty is refused.
	m2 := migEnv(t, "mig2")
	_ = saveSecretFile(filepath.Join(m2.Dir, "source"), []byte(src))
	if c2, err := e.migrateCheck(ctx, env, db, m2, protocol.MigrateParams{MigrationID: "mig2"}, &testLog{t: t}); err != nil || c2.DumpOK {
		t.Fatalf("a full target passed the check: %+v %v", c2, err)
	}

	// Live sync with writes running on the source the whole time.
	rd(t, a, "FLUSHALL")
	stop := make(chan struct{})
	done := make(chan error, 1)
	var written atomic.Int64
	go func() {
		w, err := connectAddr(ctx, addr, "", pass, "writer")
		if err != nil {
			done <- err
			return
		}
		defer w.Close()
		for i := 0; ; i++ {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			if _, err := w.do(ctx, "SET", "live:"+strconv.Itoa(i), i); err != nil {
				done <- err
				return
			}
			written.Add(1)
		}
	}()
	m3 := migEnv(t, "mig3")
	_ = saveSecretFile(filepath.Join(m3.Dir, "source"), []byte(src))
	c3, err := e.migrateCheck(ctx, env, db, m3, protocol.MigrateParams{MigrationID: "mig3"}, &testLog{t: t})
	if err != nil || !c3.LiveSync {
		t.Fatalf("live sync not offered from a plain Redis: %+v %v", c3, err)
	}
	if _, err := e.migrateCopy(ctx, env, db, m3, protocol.MigrateParams{MigrationID: "mig3", Method: protocol.MigrateMethodLive}, &testLog{t: t}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if st, ok := e.MigrateStatus(ctx, env, db, m3); !ok || st.LagBytes == nil {
		t.Fatalf("status: %+v", st)
	}
	close(stop)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sw, err := e.migrateSwitchover(ctx, env, db, m3, protocol.MigrateParams{MigrationID: "mig3", AppUser: "app"}, &testLog{t: t})
	if err != nil {
		t.Fatal(err)
	}
	if sw.Mismatches != 0 || written.Load() == 0 {
		t.Fatalf("switchover: %+v (written %d)", sw, written.Load())
	}
	if _, err := a.do(ctx, "SET", "after:switch", "1"); err != nil {
		t.Fatal("this server doesn't take writes after the switch:", err)
	}
	t.Logf("%s (%d keys written during the sync)", sw.Summary, written.Load())
}

func strings_cut(addr string) (string, string, bool) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], true
		}
	}
	return addr, "6379", false
}
