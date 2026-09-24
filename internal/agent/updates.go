package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// PostgreSQL minor updates, security updates and reboots.
//
// The agent runs unprivileged: whatever needs root goes to the root
// helper's update service (rowsafe-pg-restart in update mode, started by
// rowsafe-pg-update.path), which root installs only when it allows one of
// these, and which checks root's allow lists itself:
//
//	<state dir>/restart/update-request   written by the agent: "ID ACTION ARGS..."
//	/run/rowsafe-pg-restart/update-result  written by the helper: key=value lines

var (
	updateHelperPoll  = time.Second
	updateReadyWait   = 5 * time.Minute // PostgreSQL answering after an update
	errUpdateNoAnswer = errors.New("no answer from the update helper")
)

// updateHelperFunc asks the update helper; tests replace it.
type updateHelperFunc func(ctx context.Context, id string, args []string, timeout time.Duration) (map[string]string, error)

func (a *Agent) updateHelper() updateHelperFunc {
	if a.updateHelperFn != nil {
		return a.updateHelperFn
	}
	return a.askUpdateHelper
}

// askUpdateHelper hands one request to the update helper and waits (up to
// timeout) for its answer.
func (a *Agent) askUpdateHelper(ctx context.Context, id string, args []string, timeout time.Duration) (map[string]string, error) {
	if !restartIDRE.MatchString(id) {
		return nil, fmt.Errorf("invalid request id %q", id)
	}
	request := filepath.Join(a.cfg.RestartDir, "update-request")
	line := id + " " + strings.Join(args, " ") + "\n"
	if err := writeFileAtomic(request, []byte(line), 0o600); err != nil {
		return nil, err
	}
	res, err := a.waitUpdateResult(ctx, id, timeout)
	if err != nil && !errors.Is(err, context.Canceled) {
		_ = os.Remove(request)
	}
	return res, err
}

// waitUpdateResult waits for the helper's answer to request id.
func (a *Agent) waitUpdateResult(ctx context.Context, id string, timeout time.Duration) (map[string]string, error) {
	host, _ := os.Hostname()
	path := filepath.Join(a.cfg.RestartResultDir, "update-result")
	deadline := time.Now().Add(timeout)
	for {
		if data, err := os.ReadFile(path); err == nil {
			res := parseKeyValues(string(data))
			if res["id"] == id {
				return res, nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w: the update helper on %s did not answer within %s; check `systemctl status rowsafe-pg-update.path rowsafe-pg-update.service`",
				errUpdateNoAnswer, host, timeout.Round(time.Second))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(updateHelperPoll):
		}
	}
}

// helperOK turns a failed answer into an error.
func helperOK(res map[string]string) error {
	if res["ok"] == "1" {
		return nil
	}
	return errors.New(cmp.Or(res["error"], "the update helper failed without saying why"))
}

// allowQuestion is the installer's question for each allow word.
var allowQuestion = map[string]string{
	protocol.UpdateAllowPostgres: `"Allow Rowsafe to install PostgreSQL updates when you click Update?" (--allow-updates)`,
	protocol.UpdateAllowSecurity: `"Allow Rowsafe to install security updates when you click Install?" (--allow-security-updates)`,
	protocol.UpdateAllowReboot:   `"Allow Rowsafe to reboot this server when you click Reboot?" (--allow-reboot)`,
}

// updatesAllowed checks that root allowed word on this host and that the
// installed helper can do action.
func (a *Agent) updatesAllowed(word, action string) error {
	if a.cfg.Sidecar() {
		return errors.New("PostgreSQL runs in Docker here: Rowsafe can't install packages in your containers")
	}
	host, _ := os.Hostname()
	if !slices.Contains(a.updateAllowed(), word) {
		return fmt.Errorf("that isn't allowed on %s. Re-run the install command there and answer yes to %s", host, allowQuestion[word])
	}
	if !slices.Contains(a.updateHelperActions(), action) {
		return fmt.Errorf("the helper that installs updates on %s is missing or from an older Rowsafe: re-run the install command there", host)
	}
	if st, err := os.Stat(a.cfg.RestartDir); err != nil || !st.IsDir() {
		return fmt.Errorf("the helper's request directory %s is missing on %s: re-run the install command there", a.cfg.RestartDir, host)
	}
	return nil
}

// pgAllowed checks what a PostgreSQL update or upgrade needs on the host:
// updates allowed, and the cluster's port in the restart allow list.
func (a *Agent) pgAllowed(db protocol.DatabaseSpec, action string) (string, error) {
	if err := a.updatesAllowed(protocol.UpdateAllowPostgres, action); err != nil {
		return "", err
	}
	allowed, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		return "", err
	}
	unit, ok := allowed[db.Port]
	if !ok {
		return "", fmt.Errorf("Rowsafe isn't allowed to restart PostgreSQL on port %d, which updating it needs. Re-run the install command "+
			"and answer yes to \"Allow Rowsafe to restart or stop PostgreSQL when you ask?\" (--allow-restart)", db.Port)
	}
	return unit, nil
}

// runningVersion is the server's version ("16.9") and major.
func (a *Agent) runningVersion(ctx context.Context, db protocol.DatabaseSpec) (string, int, error) {
	s, err := summarizeCluster(ctx, a.target(db))
	if err != nil {
		return "", 0, err
	}
	return shortVersion(s.ServerVersion), s.Major(), nil
}

// downtime watches whether PostgreSQL answers, to measure how long it
// didn't (from the first failed connection to the next good one).
type downtime struct {
	mu         sync.Mutex
	down, back time.Time
	cancel     context.CancelFunc
	done       chan struct{}
}

func (a *Agent) watchDowntime(ctx context.Context, db protocol.DatabaseSpec) *downtime {
	ctx, cancel := context.WithCancel(ctx)
	w := &downtime{cancel: cancel, done: make(chan struct{})}
	ping := a.pingDB
	if ping == nil {
		ping = func(ctx context.Context, db protocol.DatabaseSpec) error {
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			conn, err := a.target(db).Connect(ctx, "postgres")
			if err == nil {
				closeConn(ctx, conn)
			}
			return err
		}
	}
	go func() {
		defer close(w.done)
		for {
			err := ping(ctx, db)
			if ctx.Err() != nil {
				return
			}
			now := time.Now()
			w.mu.Lock()
			switch {
			case err != nil && w.down.IsZero():
				w.down = now
			case err == nil && !w.down.IsZero() && w.back.IsZero():
				w.back = now
			}
			w.mu.Unlock()
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}()
	return w
}

// stop ends the watch and returns how long PostgreSQL didn't answer.
func (w *downtime) stop() time.Duration {
	w.cancel()
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	switch {
	case w.down.IsZero():
		return 0
	case w.back.IsZero():
		return time.Since(w.down)
	}
	return w.back.Sub(w.down)
}

// waitAnswering waits until db accepts connections as a primary.
func (a *Agent) waitAnswering(ctx context.Context, db protocol.DatabaseSpec, timeout time.Duration) error {
	return a.ops().waitReady(ctx, db, "", timeout)
}

// archivingWorks rewrites the pgBackRest config for db's current data
// directory and runs pgbackrest check.
func (a *Agent) archivingWorks(ctx context.Context, db protocol.DatabaseSpec, tl *taskLog) error {
	if a.checkArchivingFn != nil {
		return a.checkArchivingFn(ctx, db)
	}
	in, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return err
	}
	if err := a.writeConfig(db, in); err != nil {
		return err
	}
	out, err := a.cli(db).Check(ctx)
	tl.Output("pgbackrest check", out)
	return err
}

// ---- pg_update ----

func (a *Agent) pgUpdate(ctx context.Context, db protocol.DatabaseSpec, p protocol.PGUpdateParams, taskID string, tl *taskLog) (*protocol.PGUpdateResult, error) {
	start := time.Now()
	if a.cfg.Sidecar() {
		return nil, errors.New("PostgreSQL runs in Docker here, so Rowsafe can't install its updates: pull the newest image of the same major " +
			"(e.g. `docker compose pull postgres && docker compose up -d postgres`); Rowsafe notices the new version by itself")
	}
	unit, err := a.pgAllowed(db, actMinorUpdate)
	if err != nil {
		return nil, err
	}
	before, _, err := a.runningVersion(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("reading PostgreSQL's version: %w", err)
	}
	res := &protocol.PGUpdateResult{FromVersion: before}
	tl.Printf("installing the newest PostgreSQL %s release through the update helper (%s, port %d)%s", majorOf(before), unit, db.Port,
		map[bool]string{true: "; asked for " + p.ToVersion, false: ""}[p.ToVersion != ""])
	w := a.watchDowntime(ctx, db)
	ans, err := a.updateHelper()(ctx, taskID+"-update", []string{actMinorUpdate, strconv.Itoa(db.Port)}, 40*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		w.stop()
		if v, _, verr := a.runningVersion(ctx, db); verr == nil {
			return nil, fmt.Errorf("updating PostgreSQL failed: %v. PostgreSQL %s runs as before", err, v)
		}
		return nil, fmt.Errorf("updating PostgreSQL failed: %v", err)
	}
	res.PackageVersion = ans["package"]
	res.Packages = strings.Fields(ans["packages"])
	res.Restarted = ans["restarted"] == "1"
	if other := strings.TrimSpace(ans["other_clusters"]); other != "" && res.Restarted {
		res.Warnings = append(res.Warnings, "PostgreSQL "+majorOf(before)+"'s other clusters on this server use the new version after their next restart: "+other)
	}
	if err := a.waitAnswering(ctx, db, updateReadyWait); err != nil {
		w.stop()
		return res, fmt.Errorf("the update is installed, but PostgreSQL isn't answering: %w", err)
	}
	res.DowntimeMs = w.stop().Milliseconds()
	res.ToVersion, _, _ = a.runningVersion(ctx, db)
	if err := a.archivingWorks(ctx, db, tl); err != nil {
		res.Warnings = append(res.Warnings, "checking that WAL still reaches the backups failed: "+err.Error())
	} else {
		res.ArchivingOK = true
	}
	a.refreshSoftware()
	res.DurationMs = time.Since(start).Milliseconds()
	switch {
	case res.ToVersion == before && !res.Restarted:
		res.Summary = fmt.Sprintf("PostgreSQL %s is already the newest %s release available to this server.", before, majorOf(before))
	case res.Restarted:
		res.Summary = fmt.Sprintf("Updated PostgreSQL from %s to %s in %s; it didn't accept connections for %s.", before, res.ToVersion,
			humanDuration(time.Duration(res.DurationMs)*time.Millisecond), humanDuration(time.Duration(res.DowntimeMs)*time.Millisecond))
	default:
		res.Summary = fmt.Sprintf("Installed PostgreSQL %s; it runs %s until its next restart.", minorOf(res.PackageVersion), res.ToVersion)
	}
	if !res.ArchivingOK {
		res.Summary += " Checking that backups still work failed; see the warnings."
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func majorOf(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

// humanDuration: "12 s", "2 min 5 s", "1 h 3 min".
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		m, s := int(d.Minutes()), int(d.Seconds())%60
		if s == 0 {
			return fmt.Sprintf("%d min", m)
		}
		return fmt.Sprintf("%d min %d s", m, s)
	}
	h, m := int(d.Hours()), int(d.Minutes())%60
	return fmt.Sprintf("%d h %d min", h, m)
}

// ---- security_updates ----

func (a *Agent) securityUpdates(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.SecurityUpdatesResult, error) {
	start := time.Now()
	if err := a.updatesAllowed(protocol.UpdateAllowSecurity, actSecurity); err != nil {
		return nil, err
	}
	tl.Printf("installing the server's security updates through the update helper")
	ans, err := a.updateHelper()(ctx, taskID+"-security", []string{actSecurity}, 95*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		return nil, fmt.Errorf("installing security updates failed: %w", err)
	}
	res := &protocol.SecurityUpdatesResult{Packages: strings.Fields(ans["packages"]), HeldBack: strings.Fields(ans["held_back"]),
		RebootRequired: ans["reboot_required"] == "1"}
	res.Installed, _ = strconv.Atoi(ans["installed"])
	res.DurationMs = time.Since(start).Milliseconds()
	switch res.Installed {
	case 0:
		res.Summary = "No security updates were waiting."
	case 1:
		res.Summary = "Installed 1 security update."
	default:
		res.Summary = fmt.Sprintf("Installed %d security updates.", res.Installed)
	}
	if len(res.HeldBack) > 0 {
		res.Summary += " PostgreSQL's own updates are left for Update PostgreSQL."
	}
	if res.RebootRequired {
		res.Summary += " The server needs a reboot to finish."
	}
	if err := a.waitAnswering(ctx, db, updateReadyWait); err != nil {
		res.Summary += " PostgreSQL isn't answering: " + err.Error()
	}
	a.refreshSoftware()
	tl.Printf("%s", res.Summary)
	return res, nil
}

// ---- reboot ----

// rebootMark is written before asking for a reboot, so the agent that
// starts after the boot can finish the task.
type rebootMark struct {
	TaskID      string                `json:"task_id"`
	RequestedAt time.Time             `json:"requested_at"`
	BootID      string                `json:"boot_id"`
	Database    protocol.DatabaseSpec `json:"database"`
}

func (a *Agent) rebootMarkPath() string { return filepath.Join(a.cfg.StateDir, "reboot.json") }

var rebootWait = 10 * time.Minute // for the reboot to happen once asked

func (a *Agent) reboot(ctx context.Context, db protocol.DatabaseSpec, taskID string, tl *taskLog) (*protocol.RebootResult, error) {
	if a.cfg.Sidecar() {
		return nil, errors.New("the agent runs in Docker here and can't reboot the server")
	}
	if err := a.updatesAllowed(protocol.UpdateAllowReboot, actReboot); err != nil {
		return nil, err
	}
	m := rebootMark{TaskID: taskID, RequestedAt: time.Now().UTC(), BootID: bootID(), Database: db}
	data, _ := json.Marshal(m)
	if err := writeFileAtomic(a.rebootMarkPath(), data, 0o600); err != nil {
		return nil, err
	}
	tl.Printf("asking the update helper to reboot the server")
	ans, err := a.updateHelper()(ctx, taskID+"-reboot", []string{actReboot}, 2*time.Minute)
	if err == nil {
		err = helperOK(ans)
	}
	if err != nil {
		_ = os.Remove(a.rebootMarkPath())
		return nil, fmt.Errorf("rebooting failed: %w", err)
	}
	tl.Printf("the server is rebooting; this task finishes once it is back")
	// The shutdown stops this agent; the next one reports the task
	// (afterReboot). If nothing happens, say so.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(rebootWait):
	}
	_ = os.Remove(a.rebootMarkPath())
	return nil, fmt.Errorf("the server was asked to reboot but didn't within %s", rebootWait)
}

// afterReboot finishes a reboot task once the agent runs again: it waits
// for PostgreSQL and reports how long the reboot took. ok is false when no
// reboot mark matches the task (another kind of interruption).
func (a *Agent) afterReboot(ctx context.Context, taskID string) (protocol.CompleteRequest, bool) {
	data, err := os.ReadFile(a.rebootMarkPath())
	if err != nil {
		return protocol.CompleteRequest{}, false
	}
	var m rebootMark
	if json.Unmarshal(data, &m) != nil || m.TaskID != taskID {
		return protocol.CompleteRequest{}, false
	}
	defer os.Remove(a.rebootMarkPath())
	if m.BootID != "" && bootID() == m.BootID {
		return protocol.CompleteRequest{Status: protocol.StatusFailed,
			Error: "the agent restarted, but the server did not reboot; nothing else changed"}, true
	}
	res := protocol.RebootResult{RequestedAt: m.RequestedAt}
	if bt := bootTime(); !bt.IsZero() {
		res.BootedAt = &bt
	}
	werr := a.waitAnswering(ctx, m.Database, 10*time.Minute)
	res.DowntimeMs = time.Since(m.RequestedAt).Milliseconds()
	res.PostgresBack = werr == nil
	req := protocol.CompleteRequest{Status: protocol.StatusSucceeded}
	if res.PostgresBack {
		res.Summary = fmt.Sprintf("The server rebooted and PostgreSQL answered again %s after the request.", humanDuration(time.Duration(res.DowntimeMs)*time.Millisecond))
	} else {
		res.Summary = "The server rebooted, but PostgreSQL isn't answering: " + werr.Error()
		req.Status, req.Error = protocol.StatusFailed, res.Summary
	}
	req.Result, _ = json.Marshal(res)
	a.refreshSoftware()
	return req, true
}
