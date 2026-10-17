package redis

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore/fakes3"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

type verifyLog struct{ t *testing.T }

func (l verifyLog) Printf(f string, a ...any) { l.t.Logf(f, a...) }
func (l verifyLog) Output(string, []byte)     {}

// verifyEnv is another server's environment reading an empty bucket.
func verifyEnv(t *testing.T, engine string) agent.EngineEnv {
	t.Helper()
	srv := fakes3.New("bkt")
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	return agent.EngineEnv{
		Config:   agent.Config{StateDir: dir, DrillDir: filepath.Join(dir, "drills"), RewindDir: filepath.Join(dir, "rewind")},
		StateDir: filepath.Join(dir, "engines", engine),
		Repo: pgbackrest.Repo{Endpoint: "http://" + srv.Host(), Bucket: "bkt", Key: "k", KeySecret: "s", Region: "us-east-1",
			CipherPass: "unit-test-passphrase-1234567", PathPrefix: "/rowsafe"},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func verifyParams(engine string) protocol.ForkRestoreParams {
	return protocol.ForkRestoreParams{ForkID: "fork_1", Verify: true,
		Source: protocol.DatabaseSpec{ID: "db_1", Name: "cache", Stanza: "cache-1", Engine: engine, Port: 6379},
		VerifyFacts: &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "db0", Tables: 1200}, {Name: "db3", Tables: 4}},
			SizeBytes: 1 << 20, Version: "7.2.5"}}
}

func missing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s exists (%v)", path, err)
	}
}

func TestForkVerifyBadInput(t *testing.T) {
	env := verifyEnv(t, protocol.EngineRedis)
	e := &Engine{name: protocol.EngineRedis}
	for name, mut := range map[string]func(p *protocol.ForkRestoreParams, id *string){
		"no facts":   func(p *protocol.ForkRestoreParams, _ *string) { p.VerifyFacts = nil },
		"bad id":     func(_ *protocol.ForkRestoreParams, id *string) { *id = "../x" },
		"bad stanza": func(p *protocol.ForkRestoreParams, _ *string) { p.Source.Stanza = "../other" },
		"no stanza":  func(p *protocol.ForkRestoreParams, _ *string) { p.Source.Stanza = "" },
	} {
		p, id := verifyParams(protocol.EngineRedis), "verify-fork_1"
		mut(&p, &id)
		res, err := e.ForkVerify(context.Background(), env, p, id, verifyLog{t})
		if err == nil || res != nil {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	missing(t, env.Config.DrillDir)
}

// An empty bucket: the test fails, and its temporary servers in the drill
// directory are gone afterwards; nothing is copied anywhere (no clone
// folder, no target server).
func TestForkVerifyEmptyBucket(t *testing.T) {
	for _, engine := range []string{protocol.EngineRedis, protocol.EngineValkey} {
		env := verifyEnv(t, engine)
		e := &Engine{name: engine}
		res, err := e.ForkVerify(context.Background(), env, verifyParams(engine), "verify-fork_1", verifyLog{t})
		if err == nil || res == nil || res.Passed || len(res.Failures) == 0 {
			t.Fatalf("%s: %+v %v", engine, res, err)
		}
		t.Log(res.Failures[0])
		missing(t, filepath.Join(drillRoot(env, engine), "verify-fork_1"))
		missing(t, drillRoot(env, engine))
		missing(t, filepath.Join(env.Config.RewindDir, engine+"-fork"))
		missing(t, env.Config.RewindDir)
	}
}

func TestFactKeys(t *testing.T) {
	got := factKeys([]protocol.DBInfo{{Name: "db0", Tables: 12}, {Name: "db15", Tables: 3}, {Name: "main", Tables: 9}, {Name: "db-1", Tables: 1}, {Name: "x0"}})
	want := map[int]dbKeys{0: {Keys: 12}, 15: {Keys: 3}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%+v", got)
	}
	// What VerifyFacts reports reads back as the drill's production keys.
	in := serverInfo{Keyspace: map[int]dbKeys{0: {Keys: 5, Expires: 1}, 2: {Keys: 7}}, UsedMemoryDataset: 1000}
	if back := factKeys(in.dbInfos()); back[0].Keys != 5 || back[2].Keys != 7 || len(back) != 2 {
		t.Fatalf("%+v", back)
	}
}
