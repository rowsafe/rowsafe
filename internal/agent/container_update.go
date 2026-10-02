package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/dockerctl"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
	"github.com/rowsafe/rowsafe/release/agentimages"
)

// "Update now" for a Docker sidecar (protocol/agent_container_update.go).
//
// The agent can't replace its own container, so the task hands the
// release's signed images document to rowsafe-docker-control, which
// verifies it, pulls the image and recreates the agent's container
// (internal/dockerctl/agent_update.go). That stops this agent in the middle
// of the task, so:
//
//   - before asking, the agent writes a mark in its state volume (which the
//     new container mounts too), and when it is stopped it leaves the task
//     unreported (errHandedOver);
//   - the agent that starts next finds the task (reportInterrupted) and
//     finishes it before taking other work (finishContainerUpdate): the new
//     version, once a heartbeat got through, tells the control service it
//     runs (agent_ready) and reports success when the control service is
//     done; the old version, started again after a rollback, reports why
//     the new one didn't come up.
//
// Both report the outcome in the heartbeat too (UpdateReport with
// Container set), like a native self-update.

var (
	// containerUpdatePoll is how often the agent asks the control service
	// how the update goes.
	containerUpdatePoll = 2 * time.Second
	// containerHeartbeatWait bounds the new agent's wait for a heartbeat
	// (the control service waits five minutes for agent_ready).
	containerHeartbeatWait = 4 * time.Minute
	// containerOutcomeWait bounds waiting for the control service's verdict.
	containerOutcomeWait = 7 * time.Minute
)

// errHandedOver: the agent was stopped while its container was being
// replaced; the next agent reports the task.
var errHandedOver = errors.New("the container control service is replacing this agent's container; the next agent reports how it went")

// containerUpdateState is the agent's side of a container update.
type containerUpdateState struct {
	once    sync.Once
	hbOK    chan struct{} // closed after the first successful heartbeat
	hbClose sync.Once
	pending *runningTask // a container update the previous agent left
	mu      sync.Mutex
	report  *protocol.UpdateReport
	loaded  bool
}

func (c *containerUpdateState) init() { c.once.Do(func() { c.hbOK = make(chan struct{}) }) }

// heartbeatOK records a successful heartbeat.
func (c *containerUpdateState) heartbeatOK() {
	c.init()
	c.hbClose.Do(func() { close(c.hbOK) })
}

// containerMark is written before the control service is asked.
type containerMark struct {
	TaskID    string    `json:"task_id"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	StartedAt time.Time `json:"started_at"`
}

func (a *Agent) containerMarkPath() string {
	return filepath.Join(a.cfg.StateDir, "container-update.json")
}
func (a *Agent) containerReportPath() string {
	return filepath.Join(a.cfg.StateDir, "container-update-report.json")
}

// imageVariant is this image's floating tag ("pg17", "pg17-alpine"): the
// image says (ROWSAFE_IMAGE_VARIANT), else PostgreSQL's major and the uid
// (the -alpine images run as 70).
func imageVariant() string {
	if v := os.Getenv("ROWSAFE_IMAGE_VARIANT"); agentimages.ValidVariant(v) {
		return v
	}
	major, err := strconv.Atoi(os.Getenv("PG_MAJOR"))
	if err != nil || major < 10 || major > 99 {
		return ""
	}
	return agentimages.Variant(major, os.Getuid() == 70)
}

// updateReport is the heartbeat's Update: the self-updater's, or a
// container update's.
func (a *Agent) updateReport() *protocol.UpdateReport {
	if r := a.updater.Report(); r != nil {
		return r
	}
	c := &a.ctrUpd
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded && a.cfg.Sidecar() {
		c.loaded = true
		if data, err := os.ReadFile(a.containerReportPath()); err == nil {
			var r protocol.UpdateReport
			if json.Unmarshal(data, &r) == nil {
				c.report = &r
			}
		}
	}
	return c.report
}

func (a *Agent) setContainerReport(r protocol.UpdateReport) {
	r.Container = true
	r.At = time.Now().UTC().Truncate(time.Millisecond)
	c := &a.ctrUpd
	c.mu.Lock()
	c.report, c.loaded = &r, true
	c.mu.Unlock()
	if data, err := json.Marshal(r); err == nil {
		if err := writeFileAtomic(a.containerReportPath(), data, 0o600); err != nil {
			a.log.Warn("saving the container update report", "err", err)
		}
	}
}

// dockerCallReq sends one request to the control service.
func (a *Agent) dockerCallReq(ctx context.Context, req dockerctl.Request) (dockerctl.Response, error) {
	if a.docker.call != nil {
		return a.docker.call(ctx, req)
	}
	if a.cfg.DockerControlSocket == "" {
		return dockerctl.Response{}, errNoDockerControl
	}
	if _, err := os.Stat(a.cfg.DockerControlSocket); err != nil {
		return dockerctl.Response{}, errNoDockerControl
	}
	return dockerctl.Call(ctx, a.cfg.DockerControlSocket, req)
}

// dockerHowToAllowUpdate is the plain next step when updates aren't allowed.
const dockerHowToAllowUpdate = `set ROWSAFE_CONTROL_ALLOW_AGENT_UPDATE: "1" in the environment of the rowsafe-docker-control service ` +
	`(its newest image) and run docker compose up -d`

// agentContainerUpdate is the agent_container_update task.
func (a *Agent) agentContainerUpdate(ctx context.Context, task *protocol.Task, tl *taskLog) (*protocol.AgentContainerUpdateResult, error) {
	var p protocol.AgentContainerUpdateParams
	if err := json.Unmarshal(task.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	if !a.cfg.Sidecar() {
		return nil, errors.New("this agent doesn't run in Docker: it updates itself")
	}
	to, err := release.ParseVersion(p.Version)
	if err != nil {
		return nil, err
	}
	if cur, err := release.ParseVersion(Version); err == nil && to.Compare(cur) <= 0 {
		return nil, fmt.Errorf("the agent already runs %s", cur)
	}
	res, err := a.dockerCall(ctx, dockerctl.ActionInspect, "agent-update-check")
	switch {
	case errors.Is(err, errNoDockerControl):
		return nil, fmt.Errorf("Rowsafe can't update the agent's container here: there is no container control service. Update it yourself "+
			"(docker compose pull rowsafe-agent && docker compose up -d rowsafe-agent), or %s", dockerHowToAllow)
	case err != nil:
		return nil, err
	case !slices.Contains(res.Actions, dockerctl.ActionUpdateAgent):
		return nil, fmt.Errorf("the container control service doesn't allow updating the agent's container: %s", dockerHowToAllowUpdate)
	}
	mark := containerMark{TaskID: task.ID, From: Version, To: to.String(), StartedAt: time.Now().UTC()}
	data, _ := json.Marshal(mark)
	if err := writeFileAtomic(a.containerMarkPath(), data, 0o600); err != nil {
		return nil, err
	}
	tl.Printf("asking the container control service to update the agent's container from %s to %s", Version, to)
	res, err = a.dockerCallReq(ctx, dockerctl.Request{ID: task.ID, Action: dockerctl.ActionUpdateAgent, Version: to.String(),
		Images: &dockerctl.SignedImages{Document: p.Images, Signature: p.Signature}})
	if err == nil && !res.OK {
		err = errors.New(res.Error)
	}
	if err != nil {
		_ = os.Remove(a.containerMarkPath())
		a.setContainerReport(protocol.UpdateReport{State: protocol.UpdateFailed, FromVersion: Version, ToVersion: to.String(), Error: err.Error()})
		return nil, fmt.Errorf("the container control service didn't update the agent: %w", err)
	}
	tl.Printf("the container control service is downloading the signed image for %s", to)
	switched := false
	deadline := time.Now().Add(protocol.AgentContainerUpdateTimeout - 5*time.Minute)
	for {
		select {
		case <-ctx.Done():
			// Stopped: by the switch, or otherwise before it (the update
			// goes on); the next agent reports either way.
			return nil, errHandedOver
		case <-time.After(containerUpdatePoll):
		}
		r, err := a.dockerCall(ctx, dockerctl.ActionInspect, "agent-update-wait")
		if err != nil || r.Update == nil || r.Update.ID != task.ID {
			if time.Now().After(deadline) {
				_ = os.Remove(a.containerMarkPath())
				return nil, errors.New("the container control service stopped reporting on the update; the agent keeps running " + Version)
			}
			continue
		}
		switch u := r.Update; u.State {
		case dockerctl.AgentUpdateFailed, dockerctl.AgentUpdateRolledBack:
			_ = os.Remove(a.containerMarkPath())
			state := protocol.UpdateFailed
			if u.State == dockerctl.AgentUpdateRolledBack {
				state = protocol.UpdateRolledBack
			}
			a.setContainerReport(protocol.UpdateReport{State: state, FromVersion: Version, ToVersion: to.String(), Error: u.Error})
			return nil, fmt.Errorf("the agent's container wasn't updated: %s. The agent keeps running %s; PostgreSQL wasn't touched", u.Error, Version)
		case dockerctl.AgentUpdateSwitching, dockerctl.AgentUpdateWaiting:
			if !switched {
				switched = true
				tl.Printf("downloaded and checked %s; switching containers", u.Image)
				a.setContainerReport(protocol.UpdateReport{State: protocol.UpdateSwitched, FromVersion: Version, ToVersion: to.String()})
			}
		}
	}
}

// finishContainerUpdate closes the container update the previous agent
// handed over, before this agent takes other work.
func (a *Agent) finishContainerUpdate(ctx context.Context) {
	t := a.ctrUpd.pending
	if t == nil {
		return
	}
	a.ctrUpd.pending = nil
	log := a.log.With("task_id", t.ID, "type", t.Type)
	req, ok := a.containerUpdateOutcome(ctx, *t)
	if !ok {
		return // being replaced (rolled back): the next agent reports it
	}
	_ = os.Remove(a.containerMarkPath())
	log.Info("reporting the agent container update", "status", req.Status, "error", req.Error)
	if a.report(ctx, log, t.ID, req) {
		a.clearRunning()
	} else {
		a.saveRunning(runningTask{ID: t.ID, Type: t.Type, StartedAt: t.StartedAt, Report: &req})
	}
}

// containerUpdateOutcome works out how the handed-over update went. ok is
// false when this agent is about to be stopped and must not report.
func (a *Agent) containerUpdateOutcome(ctx context.Context, t runningTask) (protocol.CompleteRequest, bool) {
	failed := func(format string, args ...any) (protocol.CompleteRequest, bool) {
		return protocol.CompleteRequest{Status: protocol.StatusFailed, Error: fmt.Sprintf(format, args...)}, true
	}
	var mark containerMark
	data, err := os.ReadFile(a.containerMarkPath())
	if err != nil || json.Unmarshal(data, &mark) != nil || mark.TaskID != t.ID {
		return failed("the agent restarted while its container was being updated, and runs %s", Version)
	}
	// wait polls the control service until the update ends.
	wait := func() *dockerctl.AgentUpdate {
		deadline := time.Now().Add(containerOutcomeWait)
		for {
			r, err := a.dockerCall(ctx, dockerctl.ActionInspect, "agent-update-wait")
			if err == nil && r.Update != nil && r.Update.ID == t.ID && r.Update.Finished() {
				return r.Update
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				return nil
			}
			select {
			case <-ctx.Done():
			case <-time.After(containerUpdatePoll):
			}
		}
	}

	if normVersion(Version) != mark.To {
		// The previous version again: the new one didn't come up.
		u := wait()
		if ctx.Err() != nil {
			return protocol.CompleteRequest{}, false
		}
		if u == nil {
			return failed("the agent restarted during the update and still runs %s; the container control service didn't say why", Version)
		}
		state := protocol.UpdateFailed
		if u.State == dockerctl.AgentUpdateRolledBack {
			state = protocol.UpdateRolledBack
		}
		a.setContainerReport(protocol.UpdateReport{State: state, FromVersion: Version, ToVersion: mark.To, Error: u.Error})
		if u.State == dockerctl.AgentUpdateDone {
			return failed("the container control service says the update is done, but this agent runs %s", Version)
		}
		return failed("%s didn't come up, so the agent's previous container (%s) was started again: %s. PostgreSQL kept running",
			mark.To, Version, u.Error)
	}

	// The new version: once Rowsafe hears from it, tell the control service.
	a.ctrUpd.init()
	select {
	case <-a.ctrUpd.hbOK:
	case <-ctx.Done():
		return protocol.CompleteRequest{}, false
	case <-time.After(containerHeartbeatWait):
		// The control service rolls back without agent_ready.
		a.log.Error("no heartbeat got through after the container update; the container control service will put the old agent back")
		if u := wait(); u == nil || u.State != dockerctl.AgentUpdateDone {
			return protocol.CompleteRequest{}, false
		}
	}
	if r, err := a.dockerCallReq(ctx, dockerctl.Request{ID: t.ID, Action: dockerctl.ActionAgentReady, Version: normVersion(Version)}); err != nil || !r.OK {
		a.log.Warn("telling the container control service this agent runs failed", "err", err, "error", r.Error)
	}
	u := wait()
	if ctx.Err() != nil {
		return protocol.CompleteRequest{}, false
	}
	if u != nil && u.State != dockerctl.AgentUpdateDone {
		// Rolled back after all: this container is being stopped.
		select {
		case <-ctx.Done():
		case <-time.After(2 * time.Minute):
		}
		return protocol.CompleteRequest{}, false
	}
	res := protocol.AgentContainerUpdateResult{FromVersion: mark.From, ToVersion: normVersion(Version),
		DurationMs: time.Since(mark.StartedAt).Milliseconds()}
	res.Summary = fmt.Sprintf("Updated the agent's container from %s to %s in %s. PostgreSQL kept running.", mark.From, res.ToVersion,
		humanDuration(time.Duration(res.DurationMs)*time.Millisecond))
	if u != nil {
		res.Image = u.Image
	} else {
		res.Summary += " The container control service didn't confirm the end of the update: if an old agent container (…-rowsafe-old) " +
			"is still there, remove it."
	}
	a.setContainerReport(protocol.UpdateReport{State: protocol.UpdateConfirmed, FromVersion: mark.From, ToVersion: res.ToVersion})
	req := protocol.CompleteRequest{Status: protocol.StatusSucceeded}
	req.Result, _ = json.Marshal(res)
	return req, true
}
