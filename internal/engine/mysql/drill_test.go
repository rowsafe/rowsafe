package mysql

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// verifyEnv is an engine environment whose bucket is an empty fake S3
// (TLS, as openStore always uses it).
func verifyEnv(t *testing.T) (agent.EngineEnv, *fakes3.Server) {
	t.Helper()
	s3 := fakes3.New("bkt")
	t.Cleanup(s3.Close)
	tlsS3 := httptest.NewTLSServer(s3.Config.Handler)
	t.Cleanup(tlsS3.Close)
	dir := t.TempDir()
	return agent.EngineEnv{
		Config:   agent.Config{Mode: agent.ModeNative, StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "mysql"),
		Repo: pgbackrest.Repo{Endpoint: strings.TrimPrefix(tlsS3.URL, "https://"), Bucket: "bkt", Region: "us-east-1", Key: "k", KeySecret: "s",
			CipherPass: "unit-test-passphrase-123456", PathPrefix: "/rowsafe", URIStyle: "path", SkipTLSVerify: true},
		Log: slog.New(slog.DiscardHandler), Notes: io.Discard,
	}, s3
}

func verifyParams() protocol.ForkRestoreParams {
	return protocol.ForkRestoreParams{ForkID: "f1", Verify: true,
		Source:      protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop", Engine: protocol.EngineMySQL, Port: 3306},
		VerifyFacts: &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "shop", Tables: 3, SizeBytes: 1 << 20}}, SizeBytes: 1 << 20, Version: "8.4.6"}}
}

// fakeMySQLD puts a mysqld that never runs where tool("server") finds it.
func fakeMySQLD(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	for _, n := range []string{"mysqld", "mariadbd"} {
		if err := os.WriteFile(filepath.Join(bin, n), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("ROWSAFE_MYSQL_BIN_DIR", bin)
}

func TestForkVerifyRefusesBadInput(t *testing.T) {
	env, _ := verifyEnv(t)
	e := &Engine{flavor: flavorMySQL}
	now := time.Now()
	for name, c := range map[string]struct {
		mod  func(p *protocol.ForkRestoreParams, env *agent.EngineEnv)
		id   string
		want string
	}{
		"no facts":   {func(p *protocol.ForkRestoreParams, _ *agent.EngineEnv) { p.VerifyFacts = nil }, "verify-f1", "nothing to check"},
		"no source":  {func(p *protocol.ForkRestoreParams, _ *agent.EngineEnv) { p.Source.Stanza = "" }, "verify-f1", "names no source"},
		"a moment":   {func(p *protocol.ForkRestoreParams, _ *agent.EngineEnv) { p.Target.Time = &now }, "verify-f1", "newest point"},
		"a Mark":     {func(p *protocol.ForkRestoreParams, _ *agent.EngineEnv) { p.Target.Mark = "m" }, "verify-f1", "newest point"},
		"no folder":  {func(_ *protocol.ForkRestoreParams, env *agent.EngineEnv) { env.Config.DrillDir = "" }, "verify-f1", "no folder"},
		"odd id":     {func(*protocol.ForkRestoreParams, *agent.EngineEnv) {}, "../x", "invalid directory"},
		"empty repo": {func(_ *protocol.ForkRestoreParams, env *agent.EngineEnv) { env.Repo = pgbackrest.Repo{} }, "verify-f1", "not configured"},
	} {
		t.Run(name, func(t *testing.T) {
			fakeMySQLD(t)
			p, env := verifyParams(), env
			c.mod(&p, &env)
			res, err := e.ForkVerify(context.Background(), env, p, c.id, &testLog{t: t})
			if err == nil || res != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %+v, %v; want an error with %q", res, err, c.want)
			}
		})
	}
}

// A restore test on another server works in a scratch directory under
// DrillDir, deletes it whatever happens, and never reaches a server
// (the clone's load path connects to p.Port first).
func TestForkVerifyScratchRemovedAndNoLoad(t *testing.T) {
	fakeMySQLD(t)
	env, s3 := verifyEnv(t)
	dir := filepath.Join(env.Config.DrillDir, "mysql-verify-f1")
	var sawDir atomic.Bool
	s3.Fail = func(*http.Request) int {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			sawDir.Store(true)
		}
		return 0
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := verifyParams()
	p.Placement, p.Port = protocol.ForkEmptyServer, ln.Addr().(*net.TCPAddr).Port
	p.Source.Port = p.Port

	e := &Engine{flavor: flavorMySQL}
	res, err := e.ForkVerify(context.Background(), env, p, "verify-f1", &testLog{t: t})
	if !errors.Is(err, errNoBackup) || res == nil || res.Passed || len(res.Failures) != 1 || res.DurationSeconds <= 0 {
		t.Fatalf("an empty bucket: %+v, %v", res, err)
	}
	if !sawDir.Load() {
		t.Error("the restore didn't run in DrillDir/mysql-verify-f1")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the scratch copy is still there: %v", err)
	}
	if entries, _ := os.ReadDir(env.Config.DrillDir); len(entries) != 0 {
		t.Errorf("DrillDir isn't empty: %v", entries)
	}
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if c, err := ln.Accept(); err == nil {
		c.Close()
		t.Fatal("ForkVerify connected to the server on p.Port")
	}
	if _, err := os.Stat(filepath.Join(env.StateDir, "forks.json")); err == nil {
		t.Error("ForkVerify wrote fork state")
	}
}

// Without the server program, the test says which version it needs.
func TestForkVerifyNeedsServerProgram(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("ROWSAFE_MYSQL_BIN_DIR", "")
	env, _ := verifyEnv(t)
	e := &Engine{flavor: flavorMariaDB}
	if _, err := e.server(env, protocol.DatabaseSpec{}).tool("server"); err == nil {
		t.Skip("a MariaDB server program is installed in a system folder here")
	}
	p := verifyParams()
	p.VerifyFacts.Version = "11.4.5-MariaDB-ubu2404"
	_, err := e.ForkVerify(context.Background(), env, p, "verify-f1", &testLog{t: t})
	if err == nil || !strings.Contains(err.Error(), "MariaDB 11.4 isn't installed on this server") {
		t.Fatalf("got %v", err)
	}
}

// remove reads every result of a failing bulk delete, so minio's sender
// doesn't stay blocked behind the first error.
func TestRemoveDrainsErrors(t *testing.T) {
	env, s3 := verifyEnv(t)
	s3.Fail = func(r *http.Request) int {
		if r.Method == http.MethodPost && r.URL.Query().Has("delete") {
			return http.StatusForbidden // not retried
		}
		return 0
	}
	st, err := openStore(env.Repo, protocol.EngineMySQL, "shop", 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 2500) // more than one 1000-key request
	for i := range keys {
		keys[i] = fmt.Sprintf("binlog/%04d", i)
	}
	if err := st.remove(t.Context(), keys); err == nil {
		t.Fatal("a failing delete reported success")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		stacks := string(buf[:runtime.Stack(buf, true)])
		if !strings.Contains(stacks, "minio-go/v7.(*Client).removeObjects") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("minio's delete goroutine was left behind")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
