package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
)

// ReleasePublicKey verifies release manifests. It is set at build time with
// -ldflags "-X github.com/rowsafe/rowsafe/internal/agent.ReleasePublicKey=..."
// and deliberately cannot be overridden at runtime. Builds without it never
// self-update.
var ReleasePublicKey = ""

// On-host layout (see scripts/install.sh):
//
//	/opt/rowsafe/rowsafe-agent -> versions/0.2.0/rowsafe-agent   (the symlink systemd runs)
//	/opt/rowsafe/versions/<version>/rowsafe-agent
//	/usr/local/lib/rowsafe/rowsafe-agent-guard                     (ExecStartPre crash-loop guard, root's)
//	/var/lib/rowsafe/update/pending/{previous,target,from,boots,switched_at}
//	/var/lib/rowsafe/update/report.json                           (last outcome, resent on heartbeats)
//	/var/lib/rowsafe/update/failed/<version>.json                 (don't retry too soon)
//	/var/lib/rowsafe/update/guard-rollback                        (written by the guard script)
const (
	binaryName = "rowsafe-agent"

	// ProbationConfirmAfter is how long a new version must run, with a
	// successful heartbeat, before it is confirmed.
	ProbationConfirmAfter = 60 * time.Second
	// ProbationDeadline is how long after the switch a new version has to
	// confirm before it rolls itself back.
	ProbationDeadline = 10 * time.Minute

	retryAfterTransient = time.Hour
	retryAfterFailure   = 24 * time.Hour
)

// ErrRestartForUpdate asks main to exit so systemd starts the other version.
var ErrRestartForUpdate = errors.New("restarting to switch agent version")

type Updater struct {
	InstallDir string
	StateDir   string // .../update
	Version    string
	PublicKey  ed25519.PublicKey
	HTTP       *http.Client
	Log        *slog.Logger
	Now        func() time.Time
	// SelfTest runs the staged binary's self-test and returns its output.
	SelfTest func(ctx context.Context, binary string) ([]byte, error)

	mu        sync.Mutex
	offer     *protocol.UpdateOffer
	probation *probation
	report    *protocol.UpdateReport
}

type probation struct {
	target, previous string
	switchedAt       time.Time
	startedAt        time.Time
	heartbeatOK      bool
}

// NewUpdater returns nil with a reason when self-update can't be used safely
// on this install; the agent then keeps running without it.
func NewUpdater(cfg Config, logger *slog.Logger) (*Updater, string) {
	if cfg.Sidecar() {
		return nil, "running from a container image (ROWSAFE_MODE=docker-sidecar); images are immutable, so upgrade by changing the image tag (https://rowsafe.sh/docs/guides/docker)"
	}
	if !cfg.AutoUpdate {
		return nil, "disabled by ROWSAFE_AUTO_UPDATE=false"
	}
	if ReleasePublicKey == "" {
		return nil, "this build has no release public key (development build)"
	}
	pub, err := release.ParsePublicKey(ReleasePublicKey)
	if err != nil {
		return nil, err.Error()
	}
	if _, err := release.ParseVersion(Version); err != nil {
		return nil, "development version " + Version
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	want := filepath.Join(cfg.InstallDir, "versions", normVersion(Version), binaryName)
	if err != nil || exe != want {
		return nil, fmt.Sprintf("not running from the managed layout (%s, want %s); reinstall with scripts/install.sh", exe, want)
	}
	u := &Updater{
		InstallDir: cfg.InstallDir,
		StateDir:   filepath.Join(cfg.StateDir, "update"),
		Version:    Version,
		PublicKey:  pub,
		HTTP:       &http.Client{Timeout: 10 * time.Minute},
		Log:        logger,
		Now:        time.Now,
	}
	u.SelfTest = u.execSelfTest
	return u, ""
}

func normVersion(v string) string {
	if p, err := release.ParseVersion(v); err == nil {
		return p.String()
	}
	return v
}

func (u *Updater) linkPath() string      { return filepath.Join(u.InstallDir, binaryName) }
func (u *Updater) pendingDir() string    { return filepath.Join(u.StateDir, "pending") }
func (u *Updater) reportPath() string    { return filepath.Join(u.StateDir, "report.json") }
func (u *Updater) guardRollback() string { return filepath.Join(u.StateDir, "guard-rollback") }
func (u *Updater) failedPath(v string) string {
	return filepath.Join(u.StateDir, "failed", normVersion(v)+".json")
}

// Startup reconciles update state left by a previous process: it enters
// probation after a switch, and turns a guard rollback into a report.
func (u *Updater) Startup() error {
	if err := os.MkdirAll(u.StateDir, 0o700); err != nil {
		return err
	}
	if data, err := os.ReadFile(u.reportPath()); err == nil {
		var r protocol.UpdateReport
		if json.Unmarshal(data, &r) == nil {
			u.report = &r
		}
	}

	if data, err := os.ReadFile(u.guardRollback()); err == nil {
		fields := strings.Fields(string(data))
		target, boots := "", ""
		if len(fields) > 0 {
			target = fields[0]
		}
		if len(fields) > 1 {
			boots = fields[1]
		}
		u.Log.Error("previous update rolled back by the startup guard", "target", target, "boots", boots)
		u.rememberFailure(target, false)
		u.setReport(protocol.UpdateReport{
			State: protocol.UpdateRolledBack, FromVersion: u.Version, ToVersion: target,
			Error: fmt.Sprintf("version %s failed to start %s times in a row", target, boots),
		})
		if err := os.Remove(u.guardRollback()); err != nil {
			return err
		}
	}

	p, err := u.readPending()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		u.Log.Error("unreadable update state; discarding it", "err", err)
		return os.RemoveAll(u.pendingDir())
	}
	if normVersion(p.target) != normVersion(u.Version) {
		// We are not the version being tried (e.g. an operator switched
		// back by hand). Nothing to supervise.
		u.Log.Warn("stale update state for another version; discarding", "target", p.target)
		return os.RemoveAll(u.pendingDir())
	}
	p.startedAt = u.Now()
	u.probation = p
	u.Log.Info("running new agent version on probation", "version", u.Version,
		"confirm_after", ProbationConfirmAfter.String(), "deadline", p.switchedAt.Add(ProbationDeadline))
	return nil
}

func (u *Updater) readPending() (*probation, error) {
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(u.pendingDir(), name))
		return strings.TrimSpace(string(b)), err
	}
	p := &probation{}
	var err error
	if p.target, err = read("target"); err != nil {
		return nil, err
	}
	if p.previous, err = read("previous"); err != nil {
		return nil, err
	}
	ts, err := read("switched_at")
	if err != nil {
		return nil, err
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return nil, err
	}
	p.switchedAt = time.Unix(sec, 0)
	return p, nil
}

// InProbation reports whether the agent should hold off on tasks.
func (u *Updater) InProbation() bool {
	if u == nil {
		return false
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.probation != nil
}

// Report returns the last update outcome to include in heartbeats.
func (u *Updater) Report() *protocol.UpdateReport {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.report
}

func (u *Updater) setReport(r protocol.UpdateReport) {
	r.At = u.Now().UTC().Truncate(time.Millisecond)
	u.report = &r
	if data, err := json.Marshal(r); err == nil {
		if err := writeFileAtomic(u.reportPath(), data, 0o600); err != nil {
			u.Log.Error("saving update report", "err", err)
		}
	}
}

// OnHeartbeat records a successful heartbeat and the control plane's offer.
func (u *Updater) OnHeartbeat(offer *protocol.UpdateOffer) {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.offer = offer
	if u.probation != nil {
		u.probation.heartbeatOK = true
	}
}

// Tick runs between tasks. It confirms or rolls back a probation, or applies
// a pending offer. It returns ErrRestartForUpdate when the process must exit.
func (u *Updater) Tick(ctx context.Context) error {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.Now()

	if p := u.probation; p != nil {
		switch {
		case p.heartbeatOK && now.Sub(p.startedAt) >= ProbationConfirmAfter:
			return u.confirm(p)
		case now.After(p.switchedAt.Add(ProbationDeadline)):
			return u.rollback(p, fmt.Sprintf("no successful heartbeat within %s of switching", ProbationDeadline))
		}
		return nil
	}

	offer := u.offer
	if offer == nil {
		return nil
	}
	u.offer = nil
	return u.apply(ctx, offer)
}

func (u *Updater) confirm(p *probation) error {
	if err := os.RemoveAll(u.pendingDir()); err != nil {
		return err
	}
	u.probation = nil
	u.setReport(protocol.UpdateReport{State: protocol.UpdateConfirmed, ToVersion: u.Version})
	u.Log.Info("agent update confirmed", "version", u.Version)
	u.pruneVersions(p.previous)
	return nil
}

func (u *Updater) rollback(p *probation, reason string) error {
	u.Log.Error("rolling back agent update", "version", u.Version, "to", p.previous, "reason", reason)
	if err := u.swapLink(p.previous); err != nil {
		return fmt.Errorf("rollback failed, staying on %s: %w", u.Version, err)
	}
	u.rememberFailure(u.Version, false)
	u.setReport(protocol.UpdateReport{
		State: protocol.UpdateRolledBack, FromVersion: previousVersion(p.previous), ToVersion: u.Version, Error: reason,
	})
	if err := os.RemoveAll(u.pendingDir()); err != nil {
		return err
	}
	u.probation = nil
	return ErrRestartForUpdate
}

// previousVersion extracts "0.1.0" from "versions/0.1.0/rowsafe-agent".
func previousVersion(rel string) string {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) == 3 {
		return parts[1]
	}
	return rel
}

type failure struct {
	Retryable bool      `json:"retryable"`
	At        time.Time `json:"at"`
}

func (u *Updater) rememberFailure(version string, retryable bool) {
	if version == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(u.failedPath(version)), 0o700)
	data, _ := json.Marshal(failure{Retryable: retryable, At: u.Now()})
	_ = writeFileAtomic(u.failedPath(version), data, 0o600)
}

func (u *Updater) recentlyFailed(version string) bool {
	data, err := os.ReadFile(u.failedPath(version))
	if err != nil {
		return false
	}
	var f failure
	if json.Unmarshal(data, &f) != nil {
		return false
	}
	wait := retryAfterFailure
	if f.Retryable {
		wait = retryAfterTransient
	}
	return u.Now().Sub(f.At) < wait
}

// updateError classifies failures for the control plane's halt logic.
type updateError struct {
	msg       string
	retryable bool
}

func (e *updateError) Error() string { return e.msg }

func fail(retryable bool, format string, args ...any) error {
	return &updateError{msg: fmt.Sprintf(format, args...), retryable: retryable}
}

// apply stages, verifies and self-tests an offered release, then switches to
// it. Any failure before the switch leaves the running version untouched.
func (u *Updater) apply(ctx context.Context, offer *protocol.UpdateOffer) error {
	target := normVersion(offer.Version)
	if u.recentlyFailed(target) {
		return nil
	}
	u.Log.Info("agent update offered", "from", u.Version, "to", target)
	binary, err := u.stage(ctx, offer)
	if err != nil {
		var ue *updateError
		retryable := errors.As(err, &ue) && ue.retryable
		u.Log.Error("agent update rejected", "to", target, "err", err, "retryable", retryable)
		u.rememberFailure(target, retryable)
		u.setReport(protocol.UpdateReport{
			State: protocol.UpdateFailed, FromVersion: u.Version, ToVersion: target, Error: err.Error(), Retryable: retryable,
		})
		return nil
	}

	previous, err := os.Readlink(u.linkPath())
	if err != nil {
		return fmt.Errorf("reading %s: %w", u.linkPath(), err)
	}
	rel, _ := filepath.Rel(u.InstallDir, binary)
	if err := u.writePending(target, previous); err != nil {
		return err
	}
	if err := u.swapLink(rel); err != nil {
		_ = os.RemoveAll(u.pendingDir())
		return fmt.Errorf("switching to %s: %w", target, err)
	}
	u.setReport(protocol.UpdateReport{State: protocol.UpdateSwitched, FromVersion: u.Version, ToVersion: target})
	u.Log.Info("switched agent version; restarting", "from", u.Version, "to", target)
	return ErrRestartForUpdate
}

func (u *Updater) stage(ctx context.Context, offer *protocol.UpdateOffer) (string, error) {
	m, err := release.Verify(u.PublicKey, []byte(offer.Manifest), offer.Signature)
	if err != nil {
		return "", fail(false, "verifying release: %v", err)
	}
	target, _ := release.ParseVersion(m.Version)
	current, _ := release.ParseVersion(u.Version)
	if normVersion(offer.Version) != target.String() {
		return "", fail(false, "offer says %s but the signed manifest says %s", offer.Version, m.Version)
	}
	if target.Compare(current) <= 0 {
		return "", fail(false, "refusing to downgrade from %s to %s", current, target)
	}
	art, ok := m.Artifacts[release.Platform()]
	if !ok {
		return "", fail(false, "release %s has no build for %s", target, release.Platform())
	}

	dir := filepath.Join(u.InstallDir, "versions", target.String())
	if err := os.MkdirAll(filepath.Join(u.InstallDir, "versions"), 0o755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Join(u.InstallDir, "versions"), ".download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, art.URL, nil)
	if err != nil {
		tmp.Close()
		return "", err
	}
	resp, err := u.HTTP.Do(req)
	if err != nil {
		tmp.Close()
		return "", fail(true, "downloading %s: %v", art.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return "", fail(resp.StatusCode >= 500 || resp.StatusCode == 429, "downloading %s: HTTP %d", art.URL, resp.StatusCode)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, art.Size+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", fail(true, "downloading %s: %v", art.URL, err)
	}
	if n != art.Size {
		return "", fail(false, "downloaded %d bytes, signed manifest says %d", n, art.Size)
	}
	if got := release.SHA256Hex(h.Sum(nil)); got != art.SHA256 {
		return "", fail(false, "checksum mismatch: got %s, signed manifest says %s", got, art.SHA256)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	binary := filepath.Join(dir, binaryName)
	if err := os.Rename(tmp.Name(), binary); err != nil {
		return "", err
	}

	out, err := u.SelfTest(ctx, binary)
	if err != nil {
		return "", fail(false, "self-test of %s failed: %v: %s", target, err, strings.TrimSpace(string(tail(out, 2000))))
	}
	var st SelfTestResult
	if err := json.Unmarshal(out, &st); err != nil {
		return "", fail(false, "self-test of %s printed invalid output: %v", target, err)
	}
	if normVersion(st.Version) != target.String() || !st.OK {
		return "", fail(false, "self-test of %s: reported version %q ok=%v", target, st.Version, st.OK)
	}
	u.Log.Info("staged and self-tested new agent version", "version", target.String())
	return binary, nil
}

func (u *Updater) writePending(target, previous string) error {
	tmp := u.pendingDir() + ".tmp"
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"target": target, "previous": previous, "from": normVersion(u.Version), "boots": "0",
		"switched_at": strconv.FormatInt(u.Now().Unix(), 10),
	} {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(v+"\n"), 0o600); err != nil {
			return err
		}
	}
	_ = os.RemoveAll(u.pendingDir())
	return os.Rename(tmp, u.pendingDir())
}

// swapLink atomically points the managed symlink at rel (relative to
// InstallDir), after checking the target is an executable in versions/.
func (u *Updater) swapLink(rel string) error {
	clean := filepath.Clean(rel)
	if !strings.HasPrefix(clean, "versions"+string(filepath.Separator)) || filepath.Base(clean) != binaryName {
		return fmt.Errorf("refusing to link to %q", rel)
	}
	info, err := os.Stat(filepath.Join(u.InstallDir, clean))
	if err != nil {
		return err
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("%s is not executable", clean)
	}
	tmp := u.linkPath() + ".new"
	_ = os.Remove(tmp)
	if err := os.Symlink(clean, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, u.linkPath())
}

// pruneVersions keeps the running version and the one before it.
func (u *Updater) pruneVersions(previous string) {
	keep := map[string]bool{normVersion(u.Version): true, previousVersion(previous): true}
	entries, err := os.ReadDir(filepath.Join(u.InstallDir, "versions"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && !keep[e.Name()] && !strings.HasPrefix(e.Name(), ".") {
			if err := os.RemoveAll(filepath.Join(u.InstallDir, "versions", e.Name())); err == nil {
				u.Log.Info("removed old agent version", "version", e.Name())
			}
		}
	}
}

// SelfTestResult is what `rowsafe-agent selftest` prints.
type SelfTestResult struct {
	Version  string   `json:"version"`
	Platform string   `json:"platform"`
	OK       bool     `json:"ok"`
	Checks   []string `json:"checks"`
	Errors   []string `json:"errors,omitempty"`
}

func (u *Updater) execSelfTest(ctx context.Context, binary string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "selftest")
	cmd.Env = os.Environ()
	cmd.Stderr = io.Discard
	return cmd.Output()
}
