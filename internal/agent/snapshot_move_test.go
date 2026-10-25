package agent

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// fakeSnapMover is an engine that moves by snapshots, in memory.
type fakeSnapMover struct {
	mu        sync.Mutex
	snaps     []SnapshotRef // in the bucket, oldest first
	restored  map[int]string
	frozen    bool
	lifted    bool // something lifted the block (HoldFence must put it back)
	promoted  map[int]bool
	cleared   []int
	failTake  bool
	failRest  string // a label whose restore fails
	restores  []string
	thawCount int
}

func newFakeSnapMover() *fakeSnapMover {
	t0 := time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC)
	return &fakeSnapMover{snaps: []SnapshotRef{{Label: "s1", At: t0}}, restored: map[int]string{}, promoted: map[int]bool{}}
}

func (f *fakeSnapMover) StandbyTargets(context.Context, EngineEnv) []protocol.StandbyTarget {
	return nil
}

func (f *fakeSnapMover) newest() SnapshotRef {
	if len(f.snaps) == 0 {
		return SnapshotRef{}
	}
	return f.snaps[len(f.snaps)-1]
}

func (f *fakeSnapMover) SnapshotMoveSource(context.Context, EngineEnv, protocol.DatabaseSpec) (SnapshotMoveSource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return SnapshotMoveSource{Major: 300, Version: "3.0", Newest: f.newest()}, nil
}

func (f *fakeSnapMover) SnapshotMoveNewest(context.Context, EngineEnv, protocol.DatabaseSpec) (SnapshotRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.newest(), nil
}

func (f *fakeSnapMover) SnapshotMoveRestore(_ context.Context, _ EngineEnv, _ protocol.DatabaseSpec, port int, label string, o SnapshotMoveRestoreOptions,
	_ TaskLogger) (SnapshotRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.restores = append(f.restores, fmt.Sprintf("%s first=%v prev=%s", label, o.First, o.Prev))
	if label == f.failRest {
		return SnapshotRef{}, errors.New("restore failed")
	}
	for _, s := range f.snaps {
		if s.Label == label {
			f.restored[port] = label
			return s, nil
		}
	}
	return SnapshotRef{}, fmt.Errorf("no snapshot %s", label)
}

func (f *fakeSnapMover) SnapshotMoveFreeze(context.Context, EngineEnv, protocol.DatabaseSpec, TaskLogger) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	changed := f.lifted
	f.frozen, f.lifted = true, false
	return changed, nil
}

func (f *fakeSnapMover) SnapshotMoveThaw(context.Context, EngineEnv, protocol.DatabaseSpec, TaskLogger) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frozen = false
	f.thawCount++
	return nil
}

func (f *fakeSnapMover) SnapshotMoveTake(context.Context, EngineEnv, protocol.DatabaseSpec, TaskLogger) (SnapshotRef, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failTake {
		return SnapshotRef{}, errors.New("snapshot failed")
	}
	s := SnapshotRef{Label: fmt.Sprintf("s%d", len(f.snaps)+1), At: f.newest().At.Add(time.Minute)}
	f.snaps = append(f.snaps, s)
	return s, nil
}

func (f *fakeSnapMover) SnapshotMovePromote(_ context.Context, _ EngineEnv, _ protocol.DatabaseSpec, port int, _ TaskLogger) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.promoted[port] = true
	return nil
}

func (f *fakeSnapMover) SnapshotMoveClear(_ context.Context, _ EngineEnv, _ protocol.DatabaseSpec, port int, _ TaskLogger) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.restored, port)
	f.cleared = append(f.cleared, port)
	return nil
}

func snapEnv(t *testing.T) EngineEnv { return EngineEnv{StateDir: t.TempDir()} }

func TestSnapshotMoveFlow(t *testing.T) {
	ctx := context.Background()
	f := newFakeSnapMover()
	s := &snapshotStandby{m: f, engine: protocol.EngineQdrant}
	primary, target := snapEnv(t), snapEnv(t)
	db := protocol.DatabaseSpec{ID: "db1", Name: "vectors", Engine: protocol.EngineQdrant, Stanza: "vectors", Port: 6333}

	// Prepare on the primary.
	var sec protocol.StandbySecrets
	var pres protocol.StandbyPrepareResult
	if err := s.StandbyPrepare(ctx, primary, db, protocol.StandbyPrepareParams{StandbyID: "sb1"}, &sec, &pres, discardLog{}); err != nil {
		t.Fatal(err)
	}
	if pres.Major != 300 || !strings.Contains(pres.Summary, "s1") {
		t.Fatalf("prepare: %+v", pres)
	}

	// Create on the customer's server: the newest snapshot is restored.
	cres, err := s.StandbyCreate(ctx, target, db, protocol.StandbyCreateParams{StandbyID: "sb1", Port: 7333, Major: 300}, sec, discardLog{})
	if err != nil {
		t.Fatal(err)
	}
	if cres.Mode != protocol.StandbyModeArchive || cres.ReplayLSN != "s1" || f.restored[7333] != "s1" {
		t.Fatalf("create: %+v %v", cres, f.restored)
	}
	states := s.StandbyStates(ctx, target)
	if len(states) != 1 || states[0].Phase != protocol.StandbyPhaseFollowing || !states[0].InRecovery || states[0].ReplayLSN != "s1" || states[0].LastReplayAt == nil {
		t.Fatalf("states: %+v", states)
	}

	// A newer snapshot appears: following takes it.
	f.mu.Lock()
	f.snaps = append(f.snaps, SnapshotRef{Label: "s2", At: f.newest().At.Add(time.Minute)})
	f.mu.Unlock()
	if err := s.follow(ctx, target, "sb1", discardLog{}); err != nil {
		t.Fatal(err)
	}
	if r, _ := snapGet(target, "sb1"); r.Label != "s2" || f.restored[7333] != "s2" {
		t.Fatalf("follow: %+v", r)
	}

	// The switchover: writes stop, the last snapshot is taken.
	fres, err := s.StandbyFence(ctx, primary, db, protocol.StandbyFenceParams{FenceID: "f1", StandbyID: "sb1"}, discardLog{})
	if err != nil {
		t.Fatal(err)
	}
	if !f.frozen || fres.CheckpointLSN != "s3" || !fres.Stopped {
		t.Fatalf("fence: %+v frozen=%v", fres, f.frozen)
	}
	// Something lifts the block: the fence puts it back.
	f.mu.Lock()
	f.lifted, f.frozen = true, false
	f.mu.Unlock()
	enforced, other, err := s.HoldFence(ctx, primary, protocol.Fence{ID: "f1", DatabaseID: "db1", Port: 6333, Engine: protocol.EngineQdrant})
	if err != nil || !enforced || other || !f.frozen {
		t.Fatalf("hold: %v %v %v frozen=%v", enforced, other, err, f.frozen)
	}

	// Promote on the customer's server: the last snapshot is restored.
	pr, err := s.StandbyPromote(ctx, target, db, protocol.StandbyPromoteParams{StandbyID: "sb1", WaitForLSN: fres.CheckpointLSN}, discardLog{})
	if err != nil {
		t.Fatal(err)
	}
	if !pr.Promoted || !pr.CaughtUp || pr.ReplayLSN != "s3" || f.restored[7333] != "s3" || !f.promoted[7333] {
		t.Fatalf("promote: %+v", pr)
	}
	if _, ok := snapGet(target, "sb1"); ok {
		t.Fatal("record kept after the promotion")
	}
	if len(s.StandbyStates(ctx, target)) != 0 {
		t.Fatal("still reported")
	}
	want := []string{"s1 first=true prev=", "s2 first=false prev=s1", "s3 first=false prev=s2"}
	if strings.Join(f.restores, "|") != strings.Join(want, "|") {
		t.Fatalf("restores %q", f.restores)
	}
}

func TestSnapshotMoveFailures(t *testing.T) {
	ctx := context.Background()
	f := newFakeSnapMover()
	s := &snapshotStandby{m: f, engine: protocol.EngineOpenSearch}
	env := snapEnv(t)
	db := protocol.DatabaseSpec{ID: "db1", Name: "logs", Engine: protocol.EngineOpenSearch, Stanza: "logs", Port: 9200}

	// A failed first restore is cleared and forgotten.
	f.failRest = "s1"
	res, err := s.StandbyCreate(ctx, env, db, protocol.StandbyCreateParams{StandbyID: "sb1", Port: 9201}, protocol.StandbySecrets{}, discardLog{})
	if err == nil || res == nil || !res.RolledBack || len(f.cleared) != 1 {
		t.Fatalf("failed create: %v %+v %v", err, res, f.cleared)
	}
	if _, ok := snapGet(env, "sb1"); ok {
		t.Fatal("failed create kept")
	}
	f.failRest = ""

	// A refusal before anything changed clears nothing.
	f.failRest = "s1"
	f.mu.Lock()
	f.cleared = nil
	f.mu.Unlock()
	refuse := &refusingMover{fakeSnapMover: f}
	rs := &snapshotStandby{m: refuse, engine: protocol.EngineOpenSearch}
	if _, err := rs.StandbyCreate(ctx, env, db, protocol.StandbyCreateParams{StandbyID: "sbr", Port: 9201}, protocol.StandbySecrets{}, discardLog{}); err == nil ||
		len(f.cleared) != 0 {
		t.Fatalf("refused create: %v cleared %v", err, f.cleared)
	}
	f.failRest = ""

	// Switching back isn't offered.
	if _, err := s.StandbyCreate(ctx, env, db, protocol.StandbyCreateParams{StandbyID: "sb2", Port: 9201, Rebuild: true, FenceID: "f1"},
		protocol.StandbySecrets{}, discardLog{}); err == nil || !strings.Contains(err.Error(), "switching back") {
		t.Fatalf("rebuild: %v", err)
	}

	// A failed last snapshot lets apps write again.
	f.failTake = true
	if _, err := s.StandbyFence(ctx, env, db, protocol.StandbyFenceParams{FenceID: "f1"}, discardLog{}); err == nil || f.frozen || f.thawCount != 1 {
		t.Fatalf("fence: %v frozen=%v thaw=%d", err, f.frozen, f.thawCount)
	}
	f.failTake = false

	// One server receives one database at a time.
	if _, err := s.StandbyCreate(ctx, env, db, protocol.StandbyCreateParams{StandbyID: "sb3", Port: 9201}, protocol.StandbySecrets{}, discardLog{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.StandbyCreate(ctx, env, db, protocol.StandbyCreateParams{StandbyID: "sb4", Port: 9201}, protocol.StandbySecrets{}, discardLog{}); err == nil {
		t.Fatal("second database on the same port")
	}
	// Removing it empties the server.
	rr, err := s.StandbyRemove(ctx, env, db, protocol.StandbyRemoveParams{StandbyID: "sb3"}, discardLog{})
	if err != nil || f.restored[9201] != "" || !strings.Contains(rr.Summary, "empty again") {
		t.Fatalf("remove: %v %+v", err, rr)
	}
	// Unfence lets apps write.
	f.frozen = true
	if _, err := s.StandbyUnfence(ctx, env, db, protocol.Fence{ID: "f1", Port: 9200}, discardLog{}); err != nil || f.frozen {
		t.Fatalf("unfence: %v", err)
	}
	// No snapshot yet: prepare refuses in plain words.
	f.snaps = nil
	var pres protocol.StandbyPrepareResult
	if err := s.StandbyPrepare(ctx, env, db, protocol.StandbyPrepareParams{StandbyID: "sb5"}, &protocol.StandbySecrets{}, &pres, discardLog{}); err == nil ||
		!strings.Contains(err.Error(), "no snapshot") {
		t.Fatalf("prepare: %v", err)
	}
}

func TestStandbyOf(t *testing.T) {
	if standbyOf(fakeSnapEngine{fakeSnapMover: newFakeSnapMover()}) == nil {
		t.Fatal("a snapshot mover is a standby engine")
	}
}

type fakeSnapEngine struct{ *fakeSnapMover }

func (fakeSnapEngine) Name() string    { return protocol.EngineMeilisearch }
func (fakeSnapEngine) Tasks() []string { return nil }
func (fakeSnapEngine) Run(context.Context, EngineEnv, *protocol.Task, TaskLogger) (any, error) {
	return nil, nil
}
func (fakeSnapEngine) Monitor(context.Context, EngineEnv, protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	return nil, nil
}
func (fakeSnapEngine) Discover(context.Context, EngineEnv) ([]DiscoveredDatabase, error) {
	return nil, nil
}

// refusingMover refuses every restore before changing anything.
type refusingMover struct{ *fakeSnapMover }

func (r *refusingMover) SnapshotMoveRestore(context.Context, EngineEnv, protocol.DatabaseSpec, int, string, SnapshotMoveRestoreOptions,
	TaskLogger) (SnapshotRef, error) {
	return SnapshotRef{}, fmt.Errorf("the server holds data: %w", ErrMoveRefused)
}
