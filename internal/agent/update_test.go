package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
	"github.com/rowsafe/rowsafe/release"
)

// fakeAgent is a shell script standing in for a real agent binary. Its
// `selftest` prints what a real agent would.
func fakeAgent(version string, selftestOK bool) []byte {
	ok := "true"
	if !selftestOK {
		ok = "false"
	}
	return []byte("#!/bin/sh\nif [ \"$1\" = selftest ]; then echo '{\"version\":\"" + version +
		"\",\"platform\":\"x\",\"ok\":" + ok + ",\"checks\":[]}'; [ " + ok + " = true ]; exit $?; fi\nexit 0\n")
}

type updateEnv struct {
	t       *testing.T
	install string
	state   string
	priv    string
	pub     string
	server  *httptest.Server
	files   map[string][]byte
	now     time.Time
}

func newUpdateEnv(t *testing.T) *updateEnv {
	t.Helper()
	root := t.TempDir()
	e := &updateEnv{t: t, install: filepath.Join(root, "opt"), state: filepath.Join(root, "state", "update"),
		files: map[string][]byte{}, now: time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)}
	var err error
	if e.pub, e.priv, err = release.GenerateKey(); err != nil {
		t.Fatal(err)
	}
	e.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := e.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if data == nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Write(data)
	}))
	t.Cleanup(e.server.Close)

	// Installed layout with 0.1.0 running.
	e.writeVersion("0.1.0", fakeAgent("0.1.0", true))
	if err := os.Symlink("versions/0.1.0/rowsafe-agent", filepath.Join(e.install, "rowsafe-agent")); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *updateEnv) writeVersion(v string, data []byte) {
	dir := filepath.Join(e.install, "versions", v)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rowsafe-agent"), data, 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func (e *updateEnv) updater(version string) *Updater {
	pub, _ := release.ParsePublicKey(e.pub)
	u := &Updater{
		InstallDir: e.install, StateDir: e.state, Version: version, PublicKey: pub,
		HTTP: e.server.Client(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return e.now },
	}
	u.SelfTest = func(ctx context.Context, bin string) ([]byte, error) {
		return exec.CommandContext(ctx, bin, "selftest").Output()
	}
	if err := u.Startup(); err != nil {
		e.t.Fatal(err)
	}
	return u
}

// offer publishes binary data as version v and returns a signed offer.
func (e *updateEnv) offer(v string, data []byte, mutate func(*protocol.ReleaseManifest)) *protocol.UpdateOffer {
	path := "/agent/" + v + "/rowsafe-agent"
	e.files[path] = data
	sum := sha256.Sum256(data)
	m := protocol.ReleaseManifest{Version: v, ReleasedAt: e.now, Artifacts: map[string]protocol.Artifact{
		release.Platform(): {URL: e.server.URL + path, SHA256: release.SHA256Hex(sum[:]), Size: int64(len(data))},
	}}
	if mutate != nil {
		mutate(&m)
	}
	b, _ := json.Marshal(m)
	priv, _ := release.ParsePrivateKey(e.priv)
	return &protocol.UpdateOffer{Version: v, Manifest: string(b), Signature: release.Sign(priv, b)}
}

func (e *updateEnv) link() string {
	l, err := os.Readlink(filepath.Join(e.install, "rowsafe-agent"))
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

func (e *updateEnv) guard() {
	cmd := exec.Command("sh", filepath.Join(repoRoot(e.t), "scripts", "rowsafe-agent-guard"))
	cmd.Env = append(os.Environ(), "ROWSAFE_INSTALL_DIR="+e.install, "ROWSAFE_STATE_DIR="+filepath.Dir(e.state))
	if out, err := cmd.CombinedOutput(); err != nil {
		e.t.Fatalf("guard: %v: %s", err, out)
	}
}

func repoRoot(t *testing.T) string {
	dir, _ := os.Getwd()
	for !fileExists(filepath.Join(dir, "go.mod")) {
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
	return dir
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestUpdateHappyPath(t *testing.T) {
	e := newUpdateEnv(t)
	old := e.updater("0.1.0")
	old.OnHeartbeat(e.offer("0.2.0", fakeAgent("0.2.0", true), nil))
	if err := old.Tick(context.Background()); !errors.Is(err, ErrRestartForUpdate) {
		t.Fatalf("expected restart, got %v", err)
	}
	if got := e.link(); got != "versions/0.2.0/rowsafe-agent" {
		t.Fatalf("link = %s", got)
	}
	if r := old.Report(); r.State != protocol.UpdateSwitched || r.ToVersion != "0.2.0" {
		t.Fatalf("report = %+v", r)
	}

	// systemd restarts: the guard counts one boot, the new version starts on probation.
	e.guard()
	e.now = e.now.Add(5 * time.Second)
	nu := e.updater("0.2.0")
	if !nu.InProbation() {
		t.Fatal("new version should start on probation")
	}
	if err := nu.Tick(context.Background()); err != nil || !nu.InProbation() {
		t.Fatalf("must not confirm before a heartbeat: %v", err)
	}
	nu.OnHeartbeat(nil)
	e.now = e.now.Add(ProbationConfirmAfter)
	if err := nu.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if nu.InProbation() || fileExists(filepath.Join(e.state, "pending")) {
		t.Fatal("probation should be confirmed and cleared")
	}
	if r := nu.Report(); r.State != protocol.UpdateConfirmed {
		t.Fatalf("report = %+v", r)
	}

	// A third release prunes 0.1.0 once confirmed, keeping 0.2.0 as the fallback.
	nu.OnHeartbeat(e.offer("0.3.0", fakeAgent("0.3.0", true), nil))
	if err := nu.Tick(context.Background()); !errors.Is(err, ErrRestartForUpdate) {
		t.Fatal(err)
	}
	third := e.updater("0.3.0")
	third.OnHeartbeat(nil)
	e.now = e.now.Add(ProbationConfirmAfter)
	if err := third.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fileExists(filepath.Join(e.install, "versions", "0.1.0")) || !fileExists(filepath.Join(e.install, "versions", "0.2.0")) {
		t.Error("expected 0.1.0 pruned and 0.2.0 kept")
	}
}

func TestUpdateRejectsBeforeSwitching(t *testing.T) {
	cases := map[string]struct {
		offer     func(e *updateEnv) *protocol.UpdateOffer
		retryable bool
	}{
		"tampered binary": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			o := e.offer("0.2.0", fakeAgent("0.2.0", true), nil)
			e.files["/agent/0.2.0/rowsafe-agent"] = fakeAgent("0.2.0-evil", true)
			return o
		}},
		"bad signature": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			o := e.offer("0.2.0", fakeAgent("0.2.0", true), nil)
			o.Manifest = strings.Replace(o.Manifest, `"0.2.0"`, `"0.2.1"`, 1)
			o.Version = "0.2.1"
			return o
		}},
		"downgrade": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			return e.offer("0.0.9", fakeAgent("0.0.9", true), nil)
		}},
		"self-test fails": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			return e.offer("0.2.0", fakeAgent("0.2.0", false), nil)
		}},
		"binary lies about its version": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			return e.offer("0.2.0", fakeAgent("0.1.5", true), nil)
		}},
		"no build for this platform": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			return e.offer("0.2.0", fakeAgent("0.2.0", true), func(m *protocol.ReleaseManifest) {
				a := m.Artifacts[release.Platform()]
				delete(m.Artifacts, release.Platform())
				m.Artifacts["plan9/mips"] = a
			})
		}},
		// A 404 at a signed URL means the release was published wrong: halt it.
		"artifact missing": {offer: func(e *updateEnv) *protocol.UpdateOffer {
			o := e.offer("0.2.0", fakeAgent("0.2.0", true), nil)
			delete(e.files, "/agent/0.2.0/rowsafe-agent")
			return o
		}},
		// A server error is transient and must not halt the rollout.
		"download server error": {retryable: true, offer: func(e *updateEnv) *protocol.UpdateOffer {
			o := e.offer("0.2.0", fakeAgent("0.2.0", true), nil)
			e.files["/agent/0.2.0/rowsafe-agent"] = nil // handled as 503 below
			return o
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newUpdateEnv(t)
			u := e.updater("0.1.0")
			u.OnHeartbeat(c.offer(e))
			if err := u.Tick(context.Background()); err != nil {
				t.Fatalf("a rejected update must not restart the agent: %v", err)
			}
			if got := e.link(); got != "versions/0.1.0/rowsafe-agent" {
				t.Fatalf("link changed to %s", got)
			}
			r := u.Report()
			if r == nil || r.State != protocol.UpdateFailed || r.Retryable != c.retryable {
				t.Fatalf("report = %+v", r)
			}
			// The same version is not retried straight away.
			u.OnHeartbeat(c.offer(e))
			before := r.At
			if err := u.Tick(context.Background()); err != nil || !u.Report().At.Equal(before) {
				t.Error("a recently failed version should be skipped")
			}
		})
	}
}

func TestUpdateCrashLoopGuardRollsBack(t *testing.T) {
	e := newUpdateEnv(t)
	old := e.updater("0.1.0")
	old.OnHeartbeat(e.offer("0.2.0", fakeAgent("0.2.0", true), nil))
	if err := old.Tick(context.Background()); !errors.Is(err, ErrRestartForUpdate) {
		t.Fatal(err)
	}
	// The new version passes self-test but crashes at every start; systemd
	// keeps restarting it and the guard runs before each attempt.
	for i := 0; i < 3; i++ {
		e.guard()
		if got := e.link(); got != "versions/0.2.0/rowsafe-agent" {
			t.Fatalf("rolled back too early after %d boots", i+1)
		}
	}
	e.guard()
	if got := e.link(); got != "versions/0.1.0/rowsafe-agent" {
		t.Fatalf("guard should have rolled back, link = %s", got)
	}

	// The old version starts, reports the rollback, and won't retry 0.2.0 today.
	back := e.updater("0.1.0")
	r := back.Report()
	if r.State != protocol.UpdateRolledBack || r.ToVersion != "0.2.0" || r.Retryable {
		t.Fatalf("report = %+v", r)
	}
	if !back.recentlyFailed("0.2.0") {
		t.Error("0.2.0 should be remembered as failed")
	}
	if fileExists(filepath.Join(e.state, "guard-rollback")) {
		t.Error("guard marker should be consumed")
	}
}

func TestUpdateProbationDeadlineRollsBack(t *testing.T) {
	e := newUpdateEnv(t)
	old := e.updater("0.1.0")
	old.OnHeartbeat(e.offer("0.2.0", fakeAgent("0.2.0", true), nil))
	if err := old.Tick(context.Background()); !errors.Is(err, ErrRestartForUpdate) {
		t.Fatal(err)
	}
	nu := e.updater("0.2.0")
	e.now = e.now.Add(ProbationDeadline + time.Second) // never managed a heartbeat
	if err := nu.Tick(context.Background()); !errors.Is(err, ErrRestartForUpdate) {
		t.Fatalf("expected self-rollback restart, got %v", err)
	}
	if got := e.link(); got != "versions/0.1.0/rowsafe-agent" {
		t.Fatalf("link = %s", got)
	}
	back := e.updater("0.1.0")
	if back.InProbation() {
		t.Error("old version must not be on probation")
	}
	if r := back.Report(); r.State != protocol.UpdateRolledBack || r.ToVersion != "0.2.0" || r.FromVersion != "0.1.0" {
		t.Fatalf("report = %+v", r)
	}
}

func TestSwapLinkRefusesOutsideVersions(t *testing.T) {
	e := newUpdateEnv(t)
	u := e.updater("0.1.0")
	for _, bad := range []string{"../../bin/sh", "/bin/sh", "versions/0.1.0/other"} {
		if err := u.swapLink(bad); err == nil {
			t.Errorf("swapLink(%q) should fail", bad)
		}
	}
}
