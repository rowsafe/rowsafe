package clickhouse

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

func verifyParams() protocol.ForkRestoreParams {
	return protocol.ForkRestoreParams{ForkID: "f1", Verify: true,
		Source:      protocol.DatabaseSpec{ID: "db_1", Name: "events", Stanza: "events-ch", Engine: protocol.EngineClickHouse, Port: 9000},
		VerifyFacts: &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "events", Tables: 2}}, SizeBytes: 1 << 20, Version: "25.8.3.6"}}
}

// fakeClickHouse is a clickhouse program that notes where it ran and fails.
func fakeClickHouse(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "clickhouse")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\npwd > \"$0.cwd\"\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(binEnv, bin)
	return bin
}

func TestForkVerifyRefusesBadInput(t *testing.T) {
	fakeClickHouse(t)
	e := &Engine{}
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
		"odd id":     {func(*protocol.ForkRestoreParams, *agent.EngineEnv) {}, "../x", "invalid restore test id"},
		"empty repo": {func(_ *protocol.ForkRestoreParams, env *agent.EngineEnv) { env.Repo = pgbackrest.Repo{} }, "verify-f1", "not configured"},
	} {
		t.Run(name, func(t *testing.T) {
			env := testEnvUnit(t)
			p := verifyParams()
			c.mod(&p, &env)
			res, err := e.ForkVerify(context.Background(), env, p, c.id, nopLog{})
			if err == nil || res != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %+v, %v; want an error with %q", res, err, c.want)
			}
		})
	}
	// No backup yet: a failed test, nothing left behind.
	env := testEnvUnit(t)
	res, err := e.ForkVerify(context.Background(), env, verifyParams(), "verify-f1", nopLog{})
	if err == nil || res == nil || res.Passed || len(res.Failures) != 1 {
		t.Fatalf("an empty bucket: %+v, %v", res, err)
	}
	if entries, _ := os.ReadDir(drillRoot(env)); len(entries) != 0 {
		t.Fatalf("left behind: %v", entries)
	}
}

// A restore test on another server runs its temporary server under
// DrillDir, deletes it whatever happens, and never reaches a server (the
// clone's load path connects to p.Port first).
func TestForkVerifyScratchRemovedAndNoLoad(t *testing.T) {
	bin := fakeClickHouse(t)
	ctx := context.Background()
	env := testEnvUnit(t)
	r, err := openRepo(env, protocol.DatabaseSpec{Stanza: "events-ch"})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	label := newFullLabel(at)
	if err := r.st.PutBytes(ctx, backupKey(label, ".backup"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := r.putJSON(ctx, backupKey(label, backupDocName), backupDoc{Label: label, Type: protocol.BackupFull, StoppedAt: at.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p := verifyParams()
	p.Placement, p.Port = protocol.ForkEmptyServer, ln.Addr().(*net.TCPAddr).Port
	p.Source.Port = p.Port

	res, err := (&Engine{}).ForkVerify(ctx, env, p, "verify-f1", nopLog{})
	if err == nil || res == nil || res.Passed || res.BackupLabel != label || len(res.Failures) != 1 ||
		!strings.Contains(res.Failures[0], "starting a temporary ClickHouse server failed") {
		t.Fatalf("a server that doesn't start: %+v, %v", res, err)
	}
	cwd, err := os.ReadFile(bin + ".cwd")
	if err != nil || !strings.HasSuffix(strings.TrimSpace(string(cwd)), filepath.Join("drills", "clickhouse", "verify-f1")) {
		t.Fatalf("the temporary server didn't run in DrillDir/clickhouse/verify-f1: %q %v", cwd, err)
	}
	if entries, _ := os.ReadDir(drillRoot(env)); len(entries) != 0 {
		t.Fatalf("the restored copy is still there: %v", entries)
	}
	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(50 * time.Millisecond))
	if c, err := ln.Accept(); err == nil {
		c.Close()
		t.Fatal("ForkVerify connected to the server on p.Port")
	}
}

// Without the clickhouse program, the test says which version it needs.
func TestForkVerifyNeedsServerProgram(t *testing.T) {
	t.Setenv(binEnv, filepath.Join(t.TempDir(), "missing"))
	_, err := (&Engine{}).ForkVerify(context.Background(), testEnvUnit(t), verifyParams(), "verify-f1", nopLog{})
	if err == nil || !strings.Contains(err.Error(), "ClickHouse 25.8 isn't installed on this server") {
		t.Fatalf("got %v", err)
	}
}

func TestCheckFacts(t *testing.T) {
	res := &protocol.DrillResult{Databases: []protocol.DrillDatabase{{Name: "events", Present: true}}}
	checkFacts(&protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "events", Tables: 2}, {Name: "new", Tables: 1}, {Name: "empty"}}}, res)
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "new is on the source") || len(res.Failures) != 0 {
		t.Fatalf("%+v", res)
	}
}
