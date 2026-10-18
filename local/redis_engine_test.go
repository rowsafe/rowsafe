//go:build !windows

package local

import (
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// dockerRedis starts image (redis:7-alpine, valkey/valkey:8-alpine) with args on a
// free local port and returns its address. It skips without Docker or with
// -short.
func dockerRedis(t *testing.T, image string, args ...string) string {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: no Docker databases")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("no Docker")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	out, err := exec.Command("docker", append([]string{"run", "-d", "-p", addr + ":6379", image}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", id).Run() })
	for deadline := time.Now().Add(2 * time.Minute); ; time.Sleep(time.Second) {
		if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
			c.Close()
			if d, err := Open("redis://:pw@" + addr); err == nil {
				if _, err := d.Check(t.Context()); err == nil {
					return addr
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s didn't start", image)
		}
	}
}

func TestRedisDirect(t *testing.T) {
	for _, tc := range []struct{ image, engine string }{{"redis:7-alpine", protocol.EngineRedis}, {"valkey/valkey:8-alpine", protocol.EngineValkey}} {
		t.Run(tc.engine, func(t *testing.T) {
			// No snapshots, and close to a small memory limit that refuses writes.
			addr := dockerRedis(t, tc.image, "--requirepass", "pw", "--save", "", "--appendonly", "no",
				"--maxmemory", "4mb", "--maxmemory-policy", "noeviction")
			ctx := t.Context()
			d, err := Open("redis://:pw@" + addr)
			if err != nil {
				t.Fatal(err)
			}
			if s, err := d.Check(ctx); err != nil || d.Engine() != tc.engine {
				t.Fatalf("check %+v %v (engine %s)", s, err, d.Engine())
			}
			fill(t, addr)
			h, err := d.Health(ctx, Options{})
			if err != nil {
				t.Fatal(err)
			}
			got := ids(h)
			for _, want := range []string{"redis_restart_empties", "redis_memory_noeviction"} {
				if !slices.Contains(got, want) {
					t.Fatalf("missing %s in %v", want, got)
				}
			}
			if slices.Contains(got, "redis_no_password") {
				t.Errorf("it has a password: %v", got)
			}
			ov, err := d.Settings(ctx, Options{})
			if err != nil || !ov.Available {
				t.Fatalf("settings %+v %v", ov, err)
			}
			res, err := d.ApplyFix(ctx, "redis_restart_empties", "redis_snapshots_on", Options{})
			if err != nil || !strings.Contains(res.Summary, "Changed 1 setting") {
				t.Fatalf("snapshots: %+v %v", res, err)
			}
			res, err = d.ApplyFix(ctx, "redis_memory_noeviction", "redis_eviction_policy", Options{})
			if err != nil || !strings.Contains(res.Summary, "allkeys-lru") {
				t.Fatalf("eviction: %+v %v", res, err)
			}
			h, err = d.Health(ctx, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if got := ids(h); slices.Contains(got, "redis_restart_empties") || slices.Contains(got, "redis_memory_noeviction") {
				t.Errorf("after the fixes: %v", got)
			}
		})
	}
}

// fill writes 4 KB values (pipelined, over a plain connection) until the
// server is at its 4 MB limit and refuses more (noeviction).
func fill(t *testing.T, addr string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	val := strings.Repeat("x", 4096)
	var b strings.Builder
	b.WriteString("AUTH pw\r\n")
	for i := range 1000 {
		fmt.Fprintf(&b, "SET k%d %s\r\n", i, val)
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.Write([]byte(b.String())); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	for n := 0; n < 1001; { // one reply line per command
		k, err := c.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		n += strings.Count(string(buf[:k]), "\r\n")
	}
}
