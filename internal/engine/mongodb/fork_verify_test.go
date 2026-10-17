package mongodb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type verifyLog struct {
	t     *testing.T
	lines *[]string
}

func (l verifyLog) Printf(f string, a ...any) {
	l.t.Logf(f, a...)
	if l.lines != nil {
		*l.lines = append(*l.lines, fmt.Sprintf(f, a...))
	}
}
func (l verifyLog) Output(string, []byte) {}

// verifyEnv is another server's environment reading an empty bucket.
func verifyEnv(t *testing.T) agent.EngineEnv {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	return agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", "mongodb"),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "unit-test-passphrase-1234567", PathPrefix: "/rowsafe"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func verifyParams() protocol.ForkRestoreParams {
	return protocol.ForkRestoreParams{ForkID: "fork_1", Verify: true,
		Source:      protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop-mongo", Engine: protocol.EngineMongoDB, Port: 27017},
		VerifyFacts: &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "shop", Tables: 2}}, SizeBytes: 1 << 20, Version: "7.0.12"}}
}

func missing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s exists (%v)", path, err)
	}
}

func TestForkVerifyBadInput(t *testing.T) {
	env := verifyEnv(t)
	e := &Engine{}
	for name, mut := range map[string]func(p *protocol.ForkRestoreParams, id *string){
		"no facts":    func(p *protocol.ForkRestoreParams, _ *string) { p.VerifyFacts = nil },
		"bad id":      func(_ *protocol.ForkRestoreParams, id *string) { *id = "../x" },
		"bad stanza":  func(p *protocol.ForkRestoreParams, _ *string) { p.Source.Stanza = "../other" },
		"no stanza":   func(p *protocol.ForkRestoreParams, _ *string) { p.Source.Stanza = "" },
		"no settings": func(p *protocol.ForkRestoreParams, _ *string) {},
	} {
		p, id := verifyParams(), "verify-fork_1"
		mut(&p, &id)
		env := env
		if name == "no settings" {
			env.Repo = pgbackrest.Repo{}
		}
		res, err := e.ForkVerify(context.Background(), env, p, id, verifyLog{t: t})
		if err == nil || res != nil {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	missing(t, env.Config.DrillDir)
}

// An empty bucket: the test fails, and the scratch server in the drill
// directory is gone afterwards; nothing is copied anywhere (no clone
// folder, no port).
func TestForkVerifyEmptyBucket(t *testing.T) {
	env := verifyEnv(t)
	e := &Engine{}
	p := verifyParams()
	var lines []string
	res, err := e.ForkVerify(context.Background(), env, p, "verify-fork_1", verifyLog{t, &lines})
	if err == nil || res == nil || res.Passed || len(res.Failures) == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	scratch := filepath.Join(drillRoot(env), "verify-fork_1")
	if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, scratch) }) {
		t.Errorf("the scratch server wasn't in %s: %q", scratch, lines)
	}
	missing(t, scratch)
	missing(t, copyRoot(env))
	missing(t, env.Config.RewindDir)
	if left, _ := os.ReadDir(filepath.Join(env.StateDir, "s")); len(left) != 0 {
		t.Errorf("socket folders left: %v", left)
	}
}
