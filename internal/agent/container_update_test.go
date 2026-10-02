package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/dockerctl"
	"github.com/rowsafe/rowsafe/protocol"
)

// updControl plays rowsafe-docker-control during an agent update.
type updControl struct {
	mu      sync.Mutex
	actions []string
	reqs    []dockerctl.Request
	refuse  string                 // update_agent's error
	upd     *dockerctl.AgentUpdate // what inspect reports
	onReady func(u *dockerctl.AgentUpdate)
}

func (f *updControl) call(_ context.Context, req dockerctl.Request) (dockerctl.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	r := dockerctl.Response{OK: true, ID: req.ID, Action: req.Action, Actions: f.actions, Container: "myapp-postgres-1", State: "running"}
	switch req.Action {
	case dockerctl.ActionUpdateAgent:
		if f.refuse != "" {
			return dockerctl.Response{Error: f.refuse}, nil
		}
		f.upd = &dockerctl.AgentUpdate{ID: req.ID, State: dockerctl.AgentUpdatePulling, Version: req.Version}
	case dockerctl.ActionAgentReady:
		if f.onReady != nil && f.upd != nil && req.Version == f.upd.Version {
			f.onReady(f.upd)
		}
	}
	if f.upd != nil {
		u := *f.upd
		r.Update = &u
	}
	return r, nil
}

func (f *updControl) set(fn func(u *dockerctl.AgentUpdate)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f.upd)
}

func newUpdAgent(t *testing.T, version string) (*Agent, *updControl) {
	t.Helper()
	old, oldPoll := Version, containerUpdatePoll
	Version, containerUpdatePoll = version, 5*time.Millisecond
	t.Cleanup(func() { Version, containerUpdatePoll = old, oldPoll })
	fc := &updControl{actions: append(slices.Clone(dockerctl.Actions), dockerctl.AgentUpdateActions...)}
	a := &Agent{cfg: Config{Mode: ModeDockerSidecar, StateDir: t.TempDir()}, log: slog.New(slog.DiscardHandler)}
	a.docker.call = fc.call
	return a, fc
}

func updTask(t *testing.T) *protocol.Task {
	p, _ := json.Marshal(protocol.AgentContainerUpdateParams{Version: "0.5.0", Images: `{"kind":"rowsafe-agent-images"}`, Signature: "c2ln"})
	return &protocol.Task{ID: "task_up", Type: protocol.TaskAgentContainerUpdate, Params: p}
}

func TestContainerUpdateRefusals(t *testing.T) {
	a, fc := newUpdAgent(t, "0.4.2")
	fc.actions = dockerctl.Actions // the operator didn't allow it
	if _, err := a.agentContainerUpdate(context.Background(), updTask(t), &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE") {
		t.Fatalf("not allowed: %v", err)
	}
	a.docker.call = nil
	a.cfg.DockerControlSocket = "/nonexistent/x.sock"
	if _, err := a.agentContainerUpdate(context.Background(), updTask(t), &taskLog{}); err == nil || !strings.Contains(err.Error(), "docker compose pull rowsafe-agent") {
		t.Fatalf("no control service: %v", err)
	}
	a, _ = newUpdAgent(t, "0.5.0")
	if _, err := a.agentContainerUpdate(context.Background(), updTask(t), &taskLog{}); err == nil || !strings.Contains(err.Error(), "already runs") {
		t.Fatalf("same version: %v", err)
	}
	a, _ = newUpdAgent(t, "0.4.2")
	a.cfg.Mode = ModeNative
	if _, err := a.agentContainerUpdate(context.Background(), updTask(t), &taskLog{}); err == nil || !strings.Contains(err.Error(), "updates itself") {
		t.Fatalf("native: %v", err)
	}
	// The control service refuses (e.g. a bad signature): reported, nothing pending.
	a, fc = newUpdAgent(t, "0.4.2")
	fc.refuse = "refusing the update: the images document's signature does not match Rowsafe's release key"
	if _, err := a.agentContainerUpdate(context.Background(), updTask(t), &taskLog{}); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("refused: %v", err)
	}
	if _, err := os.Stat(a.containerMarkPath()); !os.IsNotExist(err) {
		t.Fatal("mark left behind")
	}
	if r := a.updateReport(); r == nil || r.State != protocol.UpdateFailed || !r.Container || r.ToVersion != "0.5.0" {
		t.Fatalf("report %+v", r)
	}
}

func TestContainerUpdateHandsOver(t *testing.T) {
	a, fc := newUpdAgent(t, "0.4.2")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := a.agentContainerUpdate(ctx, updTask(t), &taskLog{})
		done <- err
	}()
	// The control service switches; then this agent's container is stopped.
	deadline := time.Now().Add(5 * time.Second)
	for {
		fc.mu.Lock()
		started := fc.upd != nil
		fc.mu.Unlock()
		if started {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("update never asked")
		}
		time.Sleep(time.Millisecond)
	}
	fc.set(func(u *dockerctl.AgentUpdate) { u.State = dockerctl.AgentUpdateSwitching })
	for r := a.updateReport(); r == nil || r.State != protocol.UpdateSwitched; r = a.updateReport() {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != errHandedOver {
		t.Fatalf("stopped mid-update: %v", err)
	}
	fc.mu.Lock()
	req := fc.reqs[1]
	fc.mu.Unlock()
	if req.Action != dockerctl.ActionUpdateAgent || req.Version != "0.5.0" || req.Images == nil || req.Images.Signature != "c2ln" {
		t.Fatalf("request %+v", req)
	}
	var m containerMark
	data, _ := os.ReadFile(a.containerMarkPath())
	if json.Unmarshal(data, &m) != nil || m.TaskID != "task_up" || m.From != "0.4.2" || m.To != "0.5.0" {
		t.Fatalf("mark %s", data)
	}

	// The new agent (0.5.0) starts on the same state volume: once a
	// heartbeat got through it says it runs, and reports success when the
	// control service is done.
	b, fc2 := newUpdAgent(t, "0.5.0")
	b.cfg.StateDir = a.cfg.StateDir
	fc2.upd = &dockerctl.AgentUpdate{ID: "task_up", State: dockerctl.AgentUpdateWaiting, Version: "0.5.0"}
	fc2.onReady = func(u *dockerctl.AgentUpdate) {
		u.State, u.Image = dockerctl.AgentUpdateDone, "ghcr.io/rowsafe/agent@sha256:cc"
	}
	b.ctrUpd.heartbeatOK()
	req2, ok := b.containerUpdateOutcome(context.Background(), runningTask{ID: "task_up", Type: protocol.TaskAgentContainerUpdate})
	if !ok || req2.Status != protocol.StatusSucceeded {
		t.Fatalf("outcome %+v %v", req2, ok)
	}
	var res protocol.AgentContainerUpdateResult
	_ = json.Unmarshal(req2.Result, &res)
	if res.FromVersion != "0.4.2" || res.ToVersion != "0.5.0" || res.Image == "" || !strings.Contains(res.Summary, "PostgreSQL kept running") {
		t.Fatalf("result %+v", res)
	}
	if r := b.updateReport(); r == nil || r.State != protocol.UpdateConfirmed || r.FromVersion != "0.4.2" || !r.Container {
		t.Fatalf("report %+v", r)
	}
	fc2.mu.Lock()
	ready := slices.ContainsFunc(fc2.reqs, func(r dockerctl.Request) bool { return r.Action == dockerctl.ActionAgentReady && r.Version == "0.5.0" })
	fc2.mu.Unlock()
	if !ready {
		t.Fatal("the new agent never said it runs")
	}
}

func TestContainerUpdateRolledBackReportedByOldAgent(t *testing.T) {
	a, fc := newUpdAgent(t, "0.4.2")
	m, _ := json.Marshal(containerMark{TaskID: "task_up", From: "0.4.2", To: "0.5.0", StartedAt: time.Now()})
	_ = os.WriteFile(a.containerMarkPath(), m, 0o600)
	fc.upd = &dockerctl.AgentUpdate{ID: "task_up", State: dockerctl.AgentUpdateRolledBack, Version: "0.5.0",
		Error: "the new agent container stopped right after starting (exit code 1); its log says why; the old agent container runs again"}
	req, ok := a.containerUpdateOutcome(context.Background(), runningTask{ID: "task_up", Type: protocol.TaskAgentContainerUpdate})
	if !ok || req.Status != protocol.StatusFailed || !strings.Contains(req.Error, "0.5.0 didn't come up") || !strings.Contains(req.Error, "exit code 1") {
		t.Fatalf("outcome %+v", req)
	}
	if r := a.updateReport(); r == nil || r.State != protocol.UpdateRolledBack || r.ToVersion != "0.5.0" {
		t.Fatalf("report %+v", r)
	}
	// The new agent, being rolled back, doesn't report.
	b, fc2 := newUpdAgent(t, "0.5.0")
	b.cfg.StateDir = a.cfg.StateDir
	fc2.upd = &dockerctl.AgentUpdate{ID: "task_up", State: dockerctl.AgentUpdateWaiting, Version: "0.5.0"}
	fc2.onReady = func(u *dockerctl.AgentUpdate) { u.State = dockerctl.AgentUpdateRolledBack }
	b.ctrUpd.heartbeatOK()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond) // the control service stops it
	defer cancel()
	if _, ok := b.containerUpdateOutcome(ctx, runningTask{ID: "task_up"}); ok {
		t.Fatal("a rolled-back agent reported the task")
	}
	// No mark (another task): a plain failure.
	c, _ := newUpdAgent(t, "0.4.2")
	if req, ok := c.containerUpdateOutcome(context.Background(), runningTask{ID: "task_x"}); !ok || req.Status != protocol.StatusFailed {
		t.Fatalf("no mark: %+v", req)
	}
}

func TestImageVariant(t *testing.T) {
	t.Setenv("ROWSAFE_IMAGE_VARIANT", "pg16-alpine")
	if v := imageVariant(); v != "pg16-alpine" {
		t.Fatal(v)
	}
	t.Setenv("ROWSAFE_IMAGE_VARIANT", "")
	t.Setenv("PG_MAJOR", "17")
	if v := imageVariant(); v != "pg17" && v != "pg17-alpine" {
		t.Fatal(v)
	}
	t.Setenv("PG_MAJOR", "")
	if v := imageVariant(); v != "" {
		t.Fatal(v)
	}
}
