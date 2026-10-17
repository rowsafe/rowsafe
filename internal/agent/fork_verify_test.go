package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// infoRunner answers pgBackRest's info with one backup of shop and records
// every command.
type infoRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *infoRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	if slices.Contains(args, "info") {
		return []byte(`[{"name":"shop","status":{"code":0,"message":"ok"},"backup":[{"label":"20260924-010000F","type":"full","timestamp":{"start":1,"stop":2}}]}]`), nil
	}
	return nil, nil
}

// verifyTestAgent is forkTestAgent with a drill directory and a pgBackRest
// that has one backup.
func verifyTestAgent(t *testing.T, ops *fakeForkOps) (*Agent, *infoRunner) {
	t.Helper()
	a, _ := forkTestAgent(t, ops)
	a.cfg.DrillDir = filepath.Join(a.cfg.StateDir, "d")
	a.cfg.DrillPort = 55432
	r := &infoRunner{}
	a.runner = r
	return a, r
}

func verifyParams() protocol.ForkRestoreParams {
	return protocol.ForkRestoreParams{ForkID: "fork_v1", Name: "shop", Verify: true,
		Source:    protocol.DatabaseSpec{ID: "db_1", Name: "shop", Stanza: "shop", Port: 5432},
		Placement: protocol.ForkEmptyCluster, Port: 5433, // ignored by a restore test
		Major: 17, SizeBytes: 1 << 20,
		VerifyFacts: &protocol.ForkVerifyFacts{Databases: []protocol.DBInfo{{Name: "app", Tables: 3}}, SizeBytes: 1 << 20, Version: "170004"}}
}

// A restore test elsewhere restores into the drill directory with the
// drill's restore, then deletes it; it never creates, stops or takes a
// cluster, writes no fork state, and reports a drill-shaped failure.
func TestForkVerifyPostgresNeverForks(t *testing.T) {
	ops := &fakeForkOps{}
	a, runner := verifyTestAgent(t, ops)
	var restoredInto string
	old := drillRestoreCmd
	drillRestoreCmd = func(ctx context.Context, cli pgbackrest.CLI, dataDir, tablespaceDir string) ([]byte, error) {
		restoredInto = dataDir
		if conf, err := os.ReadFile(cli.ConfigPath); err != nil || !strings.Contains(string(conf), "repo1-cipher-pass=") {
			t.Errorf("the restore didn't read the source's backups through its own config: %v", err)
		}
		_ = os.WriteFile(filepath.Join(dataDir, "PG_VERSION"), []byte("17\n"), 0o600)
		return nil, errors.New("bucket unreachable")
	}
	t.Cleanup(func() { drillRestoreCmd = old })

	task := &protocol.Task{ID: "task_1", Type: protocol.TaskForkRestore}
	task.Params, _ = json.Marshal(verifyParams())
	out, err := a.runForkTask(context.Background(), task, &taskLog{})
	if err == nil || !strings.Contains(err.Error(), "bucket unreachable") {
		t.Fatalf("err %v", err)
	}
	res, ok := out.(*protocol.ForkRestoreResult)
	if !ok || res.Drill == nil || res.Drill.Passed || res.Drill.BackupLabel != "20260924-010000F" ||
		len(res.Drill.Failures) != 1 || !strings.Contains(res.Summary, "restored copy was deleted") {
		t.Fatalf("%#v", out)
	}
	if res.Port != 0 || res.DataDir != "" || res.Placement != "" || len(res.Databases) != 0 {
		t.Fatalf("a restore test reported a fork: %+v", res)
	}
	if !strings.HasPrefix(restoredInto, a.cfg.DrillDir+string(filepath.Separator)) {
		t.Fatalf("restored into %q, not the drill directory", restoredInto)
	}
	if _, err := os.Stat(filepath.Dir(restoredInto)); !os.IsNotExist(err) {
		t.Fatalf("the restored copy is still there: %v", err)
	}
	if len(ops.calls) != 0 {
		t.Fatalf("a restore test touched a cluster or the helper: %v", ops.calls)
	}
	if len(a.fk().running()) != 0 {
		t.Fatal("a restore test was recorded as a fork")
	}
	if _, err := os.Stat(filepath.Join(a.cfg.StateDir, "forks.json")); !os.IsNotExist(err) {
		t.Fatal("a restore test wrote fork state")
	}
	if left, _ := filepath.Glob(filepath.Join(a.cfg.ConfigDir, "fork-*")); len(left) != 0 {
		t.Fatalf("the source's settings were left behind: %v", left)
	}
	for _, c := range runner.calls {
		if strings.Contains(c, "stanza-create") || strings.Contains(c, " backup") || strings.Contains(c, "archive-push") {
			t.Errorf("a restore test started backups: %s", c)
		}
	}
}

func TestForkVerifyRefuses(t *testing.T) {
	a, _ := verifyTestAgent(t, &fakeForkOps{})
	at := time.Now()
	for name, mut := range map[string]func(p *protocol.ForkRestoreParams){
		"no facts":  func(p *protocol.ForkRestoreParams) { p.VerifyFacts = nil },
		"a moment":  func(p *protocol.ForkRestoreParams) { p.Target.Time = &at },
		"a Mark":    func(p *protocol.ForkRestoreParams) { p.Target.Mark = "m" },
		"bad id":    func(p *protocol.ForkRestoreParams) { p.ForkID = "../x" },
		"no stanza": func(p *protocol.ForkRestoreParams) { p.Source.Stanza = "" },
	} {
		p := verifyParams()
		mut(&p)
		if _, err := a.forkVerify(context.Background(), p, &taskLog{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Another engine without restore tests elsewhere says so plainly.
	p := verifyParams()
	p.Source.Engine = "no-such-engine"
	if _, err := a.forkVerify(context.Background(), p, &taskLog{}); err == nil || !strings.Contains(err.Error(), "aren't available") {
		t.Fatalf("unknown engine: %v", err)
	}
}

func TestProofSpaceNeededMatchesDrill(t *testing.T) {
	size := int64(10 << 30)
	if got, want := protocol.ProofSpaceNeeded(size), int64(float64(size)*drillSpaceFactor)+1<<30; got != want {
		t.Fatalf("%d != %d", got, want)
	}
}
