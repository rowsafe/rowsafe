// Package pgscratch starts a throwaway PostgreSQL cluster for integration
// tests (initdb and pg_ctl from PATH). Tests skip when they aren't there.
package pgscratch

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Cluster is a running scratch cluster, stopped when the test ends.
type Cluster struct {
	DataDir   string
	SocketDir string
	Port      int
	User      string
}

// Start runs initdb and starts PostgreSQL with extra settings (name=value).
// It skips the test when initdb isn't installed or -short is set.
func Start(t *testing.T, settings ...string) *Cluster {
	t.Helper()
	if testing.Short() {
		t.Skip("scratch PostgreSQL cluster: skipped with -short")
	}
	initdb, err := exec.LookPath("initdb")
	if err != nil {
		t.Skip("initdb not found: ", err)
	}
	pgctl, err := exec.LookPath("pg_ctl")
	if err != nil {
		t.Skip("pg_ctl not found: ", err)
	}
	u, err := user.Current()
	if err != nil || u.Uid == "0" {
		t.Skip("scratch clusters can't run as root")
	}
	// Unix socket paths are short: use /tmp rather than t.TempDir().
	dir, err := os.MkdirTemp("/tmp", "rspg")
	if err != nil {
		t.Fatal(err)
	}
	c := &Cluster{DataDir: filepath.Join(dir, "data"), SocketDir: dir, Port: freePort(t), User: "postgres"}
	if out, err := exec.Command(initdb, "-D", c.DataDir, "-U", c.User, "-A", "trust", "--no-sync", "-E", "UTF8", "--locale=C").CombinedOutput(); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	opts := []string{fmt.Sprintf("-p %d", c.Port), "-k " + dir, "-c listen_addresses=''", "-c fsync=off"}
	for _, s := range settings {
		opts = append(opts, "-c "+s)
	}
	cmd := exec.Command(pgctl, "-D", c.DataDir, "-w", "-t", "60", "-l", filepath.Join(dir, "startup.log"), "-o", strings.Join(opts, " "), "start")
	// macOS: without a valid locale the postmaster refuses to start
	// ("postmaster became multithreaded during startup").
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if out, err := cmd.CombinedOutput(); err != nil {
		startup, _ := os.ReadFile(filepath.Join(dir, "startup.log"))
		os.RemoveAll(dir)
		t.Fatalf("pg_ctl start: %v\n%s\n%s", err, out, startup)
	}
	t.Cleanup(func() {
		_ = exec.Command(pgctl, "-D", c.DataDir, "-m", "immediate", "-w", "stop").Run()
		os.RemoveAll(dir)
	})
	return c
}

// Connect opens a session to dbname.
func (c *Cluster) Connect(ctx context.Context, dbname string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host, cfg.Port, cfg.User, cfg.Database = c.SocketDir, uint16(c.Port), c.User, dbname
	return pgx.ConnectConfig(ctx, cfg)
}

// Exec runs statements (errors are returned, not fatal: tests cause some
// on purpose).
func (c *Cluster) Exec(ctx context.Context, sql string, args ...any) error {
	conn, err := c.Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, sql, args...)
	return err
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// WaitFor polls cond every 100ms until it holds or timeout passes.
func WaitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
