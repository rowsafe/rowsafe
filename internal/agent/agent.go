package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
)

type state struct {
	HostID     string `json:"host_id"`
	AgentToken string `json:"agent_token"`
}

type Agent struct {
	cfg    Config
	log    *slog.Logger
	runner pgbackrest.Runner
	client *controlClient

	updater *Updater // nil when self-update is unavailable

	// pusher moves spooled WAL to the repository (docker-sidecar mode only).
	pusher *spoolPusher

	mu      sync.Mutex
	watched []protocol.DatabaseSpec
	// monitored is what built-in monitoring covers (HeartbeatResponse.Monitored).
	monitored []protocol.DatabaseSpec

	// pgArchiveMode reads archive_mode; a restart task uses it to wait
	// until PostgreSQL answers again (tests replace it).
	pgArchiveMode func(context.Context, pginspect.Target) (string, error)

	// fastMu is held while the fast lane runs a restore point, so a
	// restart for an update waits for it.
	fastMu sync.Mutex
	// maintMu is held while the fast lane's side worker runs a maintenance
	// task (a health fix), for the same reason; maintBusy says one runs.
	maintMu   sync.Mutex
	maintBusy atomic.Bool

	// rewinds records copies and kept data directories (rewindState()).
	rewinds    *rewindStore
	rewindOnce sync.Once
	// inPlaceMu is held while a rewind in place, an undo or the deletion of
	// kept data runs: one at a time.
	inPlaceMu sync.Mutex
	// rewindOps runs the steps of a rewind in place (tests replace it).
	rewindOps inPlaceOps
}

func New(cfg Config, logger *slog.Logger) *Agent {
	a := &Agent{cfg: cfg, log: logger, runner: pgbackrest.ExecRunner{}, pgArchiveMode: pginspect.ArchiveMode}
	u, reason := NewUpdater(cfg, logger)
	if u == nil {
		logger.Warn("agent self-update is off", "reason", reason)
	}
	a.updater = u
	if cfg.Sidecar() {
		a.pusher = newSpoolPusher(cfg.SpoolDir, cfg.SpoolStallAfter, logger, a.spoolCLI)
		a.pusher.healthFile = healthPath(cfg)
	}
	return a
}

// spoolCLI is the pusher's pgBackRest CLI for a stanza, once its config
// exists (written by adopt and before every task).
func (a *Agent) spoolCLI(stanza string) (pgbackrest.CLI, bool) {
	if _, err := os.Stat(a.cfg.configPath(stanza)); err != nil {
		return pgbackrest.CLI{}, false
	}
	return a.cli(protocol.DatabaseSpec{Stanza: stanza}), true
}

func (a *Agent) statePath() string { return filepath.Join(a.cfg.StateDir, "agent.json") }

// ensureEnrolled loads saved credentials or enrolls with a one-time token.
func (a *Agent) ensureEnrolled(ctx context.Context) error {
	if data, err := os.ReadFile(a.statePath()); err == nil {
		var st state
		if err := json.Unmarshal(data, &st); err != nil {
			return fmt.Errorf("reading %s: %w", a.statePath(), err)
		}
		a.client = newControlClient(a.cfg.ControlURL, st.AgentToken)
		a.log.Info("loaded agent identity", "host_id", st.HostID)
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if a.cfg.EnrollToken == "" {
		return fmt.Errorf("not enrolled: set ROWSAFE_ENROLL_TOKEN (create one with `rowsafe hosts enroll-token`)")
	}
	hostname, _ := os.Hostname()
	resp, err := newControlClient(a.cfg.ControlURL, "").enroll(ctx, protocol.EnrollRequest{
		Token: a.cfg.EnrollToken, Hostname: hostname, AgentVersion: Version,
	})
	if err != nil {
		return fmt.Errorf("enrolling: %w", err)
	}
	data, _ := json.MarshalIndent(state{HostID: resp.HostID, AgentToken: resp.AgentToken}, "", "  ")
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := writeFileAtomic(a.statePath(), data, 0o600); err != nil {
		return err
	}
	a.client = newControlClient(a.cfg.ControlURL, resp.AgentToken)
	a.log.Info("enrolled; the enrollment token is now used up and can be removed from the environment", "host_id", resp.HostID)
	return nil
}

// Run heartbeats and executes tasks one at a time until ctx is cancelled.
// It returns ErrRestartForUpdate when systemd should start another version.
func (a *Agent) Run(ctx context.Context) error {
	if a.pusher != nil {
		if err := SidecarStartupCheck(a.cfg); err != nil {
			return err
		}
		// WAL keeps moving to the repository whatever the control plane
		// does: the pusher starts before enrollment and never waits for it.
		pctx, cancel := context.WithCancel(ctx)
		defer cancel()
		go a.pusher.Run(pctx)
	}
	if a.updater != nil {
		if err := a.updater.Startup(); err != nil {
			return fmt.Errorf("update state: %w", err)
		}
	}
	if err := a.ensureEnrolled(ctx); err != nil {
		return err
	}
	// Recover from a previous process that died mid-task: remove its
	// scratch clusters and close the task it was running, so the control
	// plane doesn't wait for a lease to expire before scheduling again.
	a.cleanupStaleDrills()
	// Copies and kept data outlive tasks: start copies again (the agent's
	// restart stopped them), roll back a rewind in place that was
	// interrupted, and delete what expired, even with no control plane.
	a.recoverRewinds(ctx)
	a.reportInterrupted(ctx)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go a.heartbeatLoop(ctx)
	go a.fastLane(ctx)
	go a.rewindHousekeeping(ctx)
	// Built-in monitoring (package collect): metrics every minute, beside
	// the task loop and never blocking it.
	go collect.Run(ctx, collect.Options{Log: a.log, PGUser: a.cfg.PGUser,
		Databases: a.monitoredDatabases,
		Send: func(ctx context.Context, r protocol.MonitoringReport) (ack protocol.MonitoringAck, err error) {
			return ack, a.client.post(ctx, "/v1/agent/monitoring", r, &ack)
		}})

	backoff := a.cfg.PollInterval
	for {
		// Updates only happen here, between tasks, so a backup or drill is
		// never interrupted by an agent restart.
		if err := a.updater.Tick(ctx); err != nil {
			if errors.Is(err, ErrRestartForUpdate) {
				a.fastMu.Lock()  // let a restore point in progress finish
				a.maintMu.Lock() // and a health fix
			}
			return err
		}
		if a.updater.InProbation() {
			// A new version proves itself before it takes on work.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		task, err := a.client.claim(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if isUnauthorized(err) {
			backoff = RevokedBackoff // the heartbeat loop explains why
		} else if err != nil {
			a.log.Warn("claiming task failed", "err", err)
			backoff = min(backoff*2, 2*time.Minute)
		} else {
			backoff = a.cfg.PollInterval
		}
		if task != nil {
			a.execute(ctx, task, !slices.Contains(fastLaneTypes, task.Type))
			continue // there may be more queued work
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
	}
}

// fastLaneTypes are claimed by the fast lane. They are short, and must not
// wait behind a backup or drill that can take hours.
var fastLaneTypes = []string{protocol.TaskRestorePoint}

// sideTypes run beside the fast lane, one at a time: health fixes (such as
// ending a session that blocks others), and the Rewind steps people wait
// for in the dashboard (compare, bring back rows, delete a copy or the kept
// data), so they never wait behind a backup or a copy being restored.
var sideTypes = []string{protocol.TaskMaintenance, protocol.TaskRewindCompare, protocol.TaskRewindRows,
	protocol.TaskRewindDrop, protocol.TaskRewindCleanup}

// fastLaneClaim is what the fast lane asks for: restore points, and a side
// task unless one is running already. Side tasks run beside the lane, one
// at a time, so a long VACUUM never holds up a restore point.
func (a *Agent) fastLaneClaim() []string {
	if a.maintBusy.Load() {
		return fastLaneTypes
	}
	return append(slices.Clone(fastLaneTypes), sideTypes...)
}

// runMaintenance runs a maintenance task beside the fast lane.
func (a *Agent) runMaintenance(ctx context.Context, task *protocol.Task) {
	a.maintBusy.Store(true)
	a.maintMu.Lock()
	go func() {
		defer func() {
			a.maintMu.Unlock()
			a.maintBusy.Store(false)
		}()
		a.execute(ctx, task, false)
	}()
}

// fastLane claims and runs restore points (and starts maintenance tasks)
// alongside the main loop.
func (a *Agent) fastLane(ctx context.Context) {
	backoff := a.cfg.PollInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if a.updater.InProbation() {
			continue
		}
		a.fastMu.Lock()
		task, err := a.client.claimTypes(ctx, a.fastLaneClaim())
		switch {
		case ctx.Err() != nil:
		case isUnauthorized(err):
			backoff = RevokedBackoff
		case err != nil:
			a.log.Warn("claiming a restore point failed", "err", err)
			backoff = min(backoff*2, 2*time.Minute)
		default:
			backoff = a.cfg.PollInterval
			switch {
			case task == nil:
			case slices.Contains(sideTypes, task.Type):
				a.runMaintenance(ctx, task)
				backoff = 0
			default:
				a.execute(ctx, task, false)
				backoff = 0 // there may be more
			}
		}
		a.fastMu.Unlock()
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	hostname, _ := os.Hostname()
	t := time.NewTicker(a.cfg.HeartbeatPeriod)
	defer t.Stop()
	for {
		req := protocol.HeartbeatRequest{
			Hostname: hostname, AgentVersion: Version, Platform: release.Platform(),
			Archivers: a.archiverStats(ctx), Update: a.updater.Report(), Mode: a.cfg.Mode,
			RestartPorts: a.restartPorts(), RestartActions: a.helperActions(), Rewinds: a.rewindState().states(),
		}
		resp, err := a.client.heartbeat(ctx, req)
		if isUnauthorized(err) {
			stop := "sudo systemctl disable --now rowsafe-agent"
			if a.cfg.Sidecar() {
				stop = "remove the agent container, or give it a new state volume and ROWSAFE_ENROLL_TOKEN"
			}
			a.log.Error("the control plane rejected this agent's token: the host was removed from Rowsafe. " +
				"Stop the agent (" + stop + ") or re-enroll it; retrying in " + RevokedBackoff.String())
			select {
			case <-ctx.Done():
				return
			case <-time.After(RevokedBackoff):
			}
			continue
		}
		if err != nil && ctx.Err() == nil {
			a.log.Warn("heartbeat failed", "err", err)
		} else if err == nil {
			a.mu.Lock()
			a.watched = resp.Databases
			a.monitored = resp.Monitored
			a.mu.Unlock()
			saveWatched(a.cfg, resp.Databases)
			if a.pusher != nil {
				a.ensureConfigs(ctx, resp.Databases)
			}
			a.updater.OnHeartbeat(resp.Update)
			a.rewindState().setExpiries(resp.RewindExpires, time.Now())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// monitoredDatabases is what built-in monitoring covers: every database of
// the host, including ones not adopted yet.
func (a *Agent) monitoredDatabases() []protocol.DatabaseSpec {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.monitored)
}

// RevokedBackoff is how long the agent waits between attempts once the
// control plane rejects its token (401), instead of polling every few seconds.
var RevokedBackoff = 10 * time.Minute

func isUnauthorized(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.Status == http.StatusUnauthorized
}

func (a *Agent) archiverStats(ctx context.Context) []protocol.ArchiverStats {
	a.mu.Lock()
	watched := append([]protocol.DatabaseSpec(nil), a.watched...)
	a.mu.Unlock()
	var out []protocol.ArchiverStats
	for _, db := range watched {
		stats, err := pginspect.Archiver(ctx, a.target(db))
		stats.DatabaseID = db.ID
		if err != nil {
			stats.Error = err.Error()
		} else if a.pusher != nil {
			stats = sidecarArchiverStats(stats, a.pusher.Report(db.Stanza))
		}
		out = append(out, stats)
	}
	return out
}

func (a *Agent) target(db protocol.DatabaseSpec) pginspect.Target {
	return pginspect.Target{SocketDir: db.SocketDir, Port: db.Port, User: a.cfg.PGUser}
}

// execute runs one task and reports the outcome. Reporting is retried so a
// brief control plane outage doesn't lose a finished backup. Only the main
// lane persists its task for crash recovery (persist); a restore point or
// health fix interrupted by a crash is closed by its lease.
func (a *Agent) execute(ctx context.Context, task *protocol.Task, persist bool) {
	log := a.log.With("task_id", task.ID, "type", task.Type)
	log.Info("task started")
	start := time.Now()
	if persist {
		a.saveRunning(runningTask{ID: task.ID, Type: task.Type, StartedAt: start.UTC()})
	}

	tctx, cancel := context.WithTimeout(ctx, protocol.TaskTimeout(task.Type))
	defer cancel()
	tl := &taskLog{}
	result, err := a.runTask(tctx, task, tl)

	req := protocol.CompleteRequest{Status: protocol.StatusSucceeded, Log: tl.String()}
	if result != nil {
		req.Result, _ = json.Marshal(result)
	}
	if err != nil {
		req.Status = protocol.StatusFailed
		req.Error = err.Error()
		if ctx.Err() != nil {
			req.Error = "the agent was stopped while this task was running: " + req.Error
		}
		log.Error("task failed", "err", err, "duration", time.Since(start).Round(time.Second).String())
	} else {
		log.Info("task succeeded", "duration", time.Since(start).Round(time.Second).String())
	}
	if a.report(ctx, log, task.ID, req) {
		if persist {
			a.clearRunning()
		}
	} else if persist {
		// Keep the outcome on disk; the next agent process sends it.
		a.saveRunning(runningTask{ID: task.ID, Type: task.Type, StartedAt: start.UTC(), Report: &req})
	}
}

// report sends a task outcome, retrying transient failures. It returns false
// if the outcome could not be delivered and should be kept for later. When
// the agent is shutting down it still makes one short attempt.
func (a *Agent) report(ctx context.Context, log *slog.Logger, taskID string, req protocol.CompleteRequest) bool {
	for attempt := 1; ; attempt++ {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		err := a.client.complete(actx, taskID, req)
		cancel()
		if err == nil {
			return true
		}
		var he *httpError
		if errors.As(err, &he) && he.Status < 500 {
			// The task is no longer ours (already closed or reaped).
			log.Error("control plane rejected task report", "err", err)
			return true
		}
		if ctx.Err() != nil || attempt >= 20 {
			log.Error("could not report task result; will retry after restart", "err", err)
			return false
		}
		log.Warn("reporting task result failed, retrying", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(time.Duration(attempt) * 5 * time.Second):
		}
	}
}

// runningTask is persisted while a task runs, so a restarted agent can tell
// the control plane what happened to it.
type runningTask struct {
	ID        string                    `json:"id"`
	Type      string                    `json:"type"`
	StartedAt time.Time                 `json:"started_at"`
	Report    *protocol.CompleteRequest `json:"report,omitempty"` // outcome not yet delivered
}

func (a *Agent) runningPath() string { return filepath.Join(a.cfg.StateDir, "running-task.json") }

func (a *Agent) saveRunning(t runningTask) {
	data, _ := json.Marshal(t)
	if err := writeFileAtomic(a.runningPath(), data, 0o600); err != nil {
		a.log.Warn("saving running task state", "err", err)
	}
}

func (a *Agent) clearRunning() {
	if err := os.Remove(a.runningPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.log.Warn("clearing running task state", "err", err)
	}
}

// reportInterrupted closes the task a previous agent process was running
// when it died, or delivers the outcome it could not send.
func (a *Agent) reportInterrupted(ctx context.Context) {
	data, err := os.ReadFile(a.runningPath())
	if err != nil {
		return
	}
	var t runningTask
	if json.Unmarshal(data, &t) != nil || t.ID == "" {
		a.clearRunning()
		return
	}
	cleanup := "any scratch drill cluster has been removed"
	switch t.Type {
	case protocol.TaskRewindInPlace, protocol.TaskRewindUndo:
		cleanup = "the interrupted rewind was rolled back when the agent started again: PostgreSQL runs on the data it had before (see the agent's log)"
	case protocol.TaskRewindCopy:
		cleanup = "the half-restored copy has been removed"
	}
	req := protocol.CompleteRequest{
		Status: protocol.StatusFailed,
		Error: fmt.Sprintf("the agent stopped while this %s task was running (started %s): crash, kill or reboot; %s",
			t.Type, t.StartedAt.Format(time.RFC3339), cleanup),
	}
	if t.Report != nil {
		req = *t.Report
	}
	log := a.log.With("task_id", t.ID, "type", t.Type)
	log.Warn("reporting task interrupted by an agent restart", "status", req.Status)
	if a.report(ctx, log, t.ID, req) {
		a.clearRunning()
	}
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
