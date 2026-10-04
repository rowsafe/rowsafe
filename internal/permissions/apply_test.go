package permissions

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

type applyEnv struct {
	t      *testing.T
	h      *Helper
	key    *testKey
	argsTo string
	log    *strings.Builder
}

func newApplyEnv(t *testing.T) *applyEnv {
	root := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	reqDir, ansDir, stateDir, etc, lib := mk("agent/permissions", 0o700), mk("run", 0o755), mk("state", 0o700), mk("etc", 0o755), mk("lib", 0o755)
	if err := os.WriteFile(filepath.Join(root, "agent/agent.json"), []byte(`{"host_id":"`+testHost+`","agent_token":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	argsTo := filepath.Join(root, "installer-args")
	installer := filepath.Join(lib, "install.sh")
	script := "#!/bin/sh\necho \"$@\" >" + argsTo + "\necho '\033[32mok\033[0m' Rowsafe may install security updates\n"
	if err := os.WriteFile(installer, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	k := newTestKey(t, AlgES256)
	if err := WriteOwners(filepath.Join(etc, "owners"), []Owner{ownerFor(t, k)}); err != nil {
		t.Fatal(err)
	}
	log := &strings.Builder{}
	h := &Helper{
		RequestPath: filepath.Join(reqDir, RequestName), AnswerDir: ansDir, StateDir: stateDir,
		OwnersFile: filepath.Join(etc, "owners"), AgentState: filepath.Join(root, "agent/agent.json"),
		Installer: installer, Log: log, Now: time.Now,
		ReadAsAgent: ReadSmallFile, RunInstaller: RunInstaller,
	}
	return &applyEnv{t: t, h: h, key: k, argsTo: argsTo, log: log}
}

func (e *applyEnv) request(id string, signed protocol.SignedPermissionChange) {
	data, _ := json.Marshal(Request{ID: id, Signed: signed})
	if err := os.WriteFile(e.h.RequestPath, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *applyEnv) run() Answer {
	e.t.Helper()
	if err := e.h.Apply(context.Background()); err != nil {
		e.t.Fatal(err)
	}
	if _, err := os.Lstat(e.h.RequestPath); !os.IsNotExist(err) {
		e.t.Fatal("the request was left behind")
	}
	var a Answer
	data, err := os.ReadFile(filepath.Join(e.h.AnswerDir, AnswerName))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := json.Unmarshal(data, &a); err != nil {
		e.t.Fatal(err)
	}
	return a
}

func TestApply(t *testing.T) {
	e := newApplyEnv(t)
	s := &signer{t: t, key: e.key, rp: testRP, origin: testOrigin}
	signed := s.sign(newChange(time.Now()))

	e.request("task-1", signed)
	a := e.run()
	if a.ID != "task-1" || !a.Applied || a.Refused != "" || !strings.Contains(a.Output, "Rowsafe may install security updates") || strings.Contains(a.Output, "\033") {
		t.Fatalf("answer %+v", a)
	}
	args, _ := os.ReadFile(e.argsTo)
	if got := strings.TrimSpace(string(args)); got != "--permissions --no-prompt --allow-security-updates --no-allow-reboot" {
		t.Fatalf("installer args %q", got)
	}
	if !strings.Contains(e.log.String(), "verified a change signed by ana@example.com") || !strings.Contains(e.log.String(), "applied") {
		t.Fatalf("journal: %s", e.log.String())
	}

	// The same signed change again: refused, the installer doesn't run.
	_ = os.Remove(e.argsTo)
	e.request("task-2", signed)
	a = e.run()
	if a.ID != "task-2" || a.Applied || !strings.Contains(a.Refused, "applied before") {
		t.Fatalf("replay: %+v", a)
	}
	if _, err := os.Stat(e.argsTo); err == nil {
		t.Fatal("the installer ran for a replay")
	}

	// No request: nothing happens.
	if err := e.h.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestApplyRefusals(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		setup func(e *applyEnv) []byte // returns the raw request
		want  string
	}{
		"malformed": {func(e *applyEnv) []byte { return []byte(`{"id":"t1","signed":{"change":5}}`) }, "malformed"},
		"unknown request field": {func(e *applyEnv) []byte {
			return []byte(`{"id":"t1","x":1}`)
		}, "malformed"},
		"no owners": {func(e *applyEnv) []byte {
			_ = os.Remove(e.h.OwnersFile)
			return e.signedRequest(now)
		}, "no passkey is paired"},
		"owners writable by others": {func(e *applyEnv) []byte {
			_ = os.Chmod(e.h.OwnersFile, 0o666)
			return e.signedRequest(now)
		}, "can't be trusted"},
		"installer missing": {func(e *applyEnv) []byte {
			_ = os.Remove(e.h.Installer)
			return e.signedRequest(now)
		}, "is missing"},
		"installer writable by others": {func(e *applyEnv) []byte {
			_ = os.Chmod(e.h.Installer, 0o777)
			return e.signedRequest(now)
		}, "writable by others"},
		"no host ID": {func(e *applyEnv) []byte {
			_ = os.WriteFile(e.h.AgentState, []byte(`{}`), 0o600)
			return e.signedRequest(now)
		}, "Rowsafe ID is unreadable"},
		"other host": {func(e *applyEnv) []byte {
			_ = os.WriteFile(e.h.AgentState, []byte(`{"host_id":"host_02"}`), 0o600)
			return e.signedRequest(now)
		}, "another Rowsafe server ID"},
		"installer fails": {func(e *applyEnv) []byte {
			_ = os.WriteFile(e.h.Installer, []byte("#!/bin/sh\necho 'restarting needs --allow-restart' >&2\nexit 1\n"), 0o755)
			return e.signedRequest(now)
		}, "couldn't apply"},
	}
	for name, c := range cases {
		e := newApplyEnv(t)
		raw := c.setup(e)
		if err := os.WriteFile(e.h.RequestPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		a := e.run()
		if a.Applied || !strings.Contains(a.Refused, c.want) {
			t.Errorf("%s: %+v", name, a)
		}
		if name == "installer fails" && !strings.Contains(a.Output, "needs --allow-restart") {
			t.Errorf("%s: output %q", name, a.Output)
		}
		if name != "malformed" && name != "unknown request field" && a.ID != "t1" {
			t.Errorf("%s: answered %q", name, a.ID)
		}
	}
}

func (e *applyEnv) signedRequest(now time.Time) []byte {
	s := &signer{t: e.t, key: e.key, rp: testRP, origin: testOrigin}
	data, _ := json.Marshal(Request{ID: "t1", Signed: s.sign(newChange(now))})
	return data
}

func TestApplyRequestNotRegularFile(t *testing.T) {
	e := newApplyEnv(t)
	target := filepath.Join(t.TempDir(), "elsewhere")
	_ = os.WriteFile(target, e.signedRequest(time.Now()), 0o600)
	if err := os.Symlink(target, e.h.RequestPath); err != nil {
		t.Fatal(err)
	}
	a := e.run()
	if a.Applied || a.Refused == "" {
		t.Fatalf("symlinked request: %+v", a)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("the symlink's target was removed")
	}
}

func TestInstallerArgs(t *testing.T) {
	c := &protocol.PermissionChange{Allow: []string{protocol.PermReboot, protocol.PermRestart}, Remove: []string{protocol.PermPooler}}
	got := strings.Join(InstallerArgs(c), " ")
	if got != "--permissions --no-prompt --allow-restart --no-allow-pooler --allow-reboot" {
		t.Fatal(got)
	}
}

// fakeTTY answers the confirmation question.
type fakeTTY struct {
	mu     sync.Mutex
	out    strings.Builder
	answer string
	asked  bool
}

func (f *fakeTTY) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}

func (f *fakeTTY) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.asked {
		return 0, io.EOF
	}
	f.asked = true
	return copy(p, f.answer+"\n"), nil
}

// fakeCP plays the control plane: a pairing that a browser completes after
// two polls.
type fakeCP struct {
	t        *testing.T
	key      *testKey
	url      string
	status   string
	polls    int
	tamper   func(att *protocol.PermissionOwnerAttestation)
	gotToken string
}

func (f *fakeCP) handler() http.Handler {
	var challenge []byte
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/agent/permission-owners", func(w http.ResponseWriter, r *http.Request) {
		f.gotToken = r.Header.Get("Authorization")
		var req protocol.PermissionOwnerPairingRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		challenge = req.Challenge
		_ = json.NewEncoder(w).Encode(protocol.PermissionOwnerPairing{ID: "pair_1", URL: f.url, Code: "KQ7M-2XRD",
			ExpiresAt: time.Now().Add(10 * time.Minute), Status: "pending"})
	})
	mux.HandleFunc("GET /v1/agent/permission-owners/pair_1", func(w http.ResponseWriter, r *http.Request) {
		f.polls++
		resp := protocol.PermissionOwnerPairing{ID: "pair_1", Status: "pending"}
		if f.polls >= 2 {
			resp.Status = f.status
			if f.status == "completed" {
				att, cdj := f.key.register(testRP, testOrigin, challenge)
				resp.Attestation = &protocol.PermissionOwnerAttestation{CredentialID: f.key.credID, AttestationObject: att, ClientDataJSON: cdj, Name: "ana@example.com\x1b[2J"}
				if f.tamper != nil {
					f.tamper(resp.Attestation)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return mux
}

func TestPair(t *testing.T) {
	cases := []struct {
		name, status, answer, url string
		tamper                    func(*protocol.PermissionOwnerAttestation)
		wantErr                   string
		paired                    bool
	}{
		{name: "confirmed", status: "completed", answer: "y", paired: true},
		{name: "codes differ", status: "completed", answer: "n", wantErr: "not paired"},
		{name: "no answer", status: "completed", answer: "", wantErr: "not paired"},
		{name: "denied", status: "denied", answer: "y", wantErr: "not paired"},
		{name: "expired", status: "expired", answer: "y", wantErr: "not paired"},
		{name: "link elsewhere", status: "completed", answer: "y", url: "https://evil.example/owner", wantErr: "outside"},
		{name: "another credential ID", status: "completed", answer: "y", wantErr: "doesn't match",
			tamper: func(a *protocol.PermissionOwnerAttestation) { a.CredentialID = randBytes(32) }},
		{name: "attestation for another challenge", status: "completed", answer: "y", wantErr: "can't be trusted",
			tamper: func(a *protocol.PermissionOwnerAttestation) {
				a.ClientDataJSON = clientDataJSON("webauthn.create", randBytes(32), testOrigin, nil)
			}},
	}
	for _, c := range cases {
		k := newTestKey(t, AlgES256)
		cp := &fakeCP{t: t, key: k, status: c.status, tamper: c.tamper, url: c.url}
		if cp.url == "" {
			cp.url = testOrigin + "/servers/owner?code=KQ7M-2XRD"
		}
		srv := httptest.NewServer(cp.handler())
		tty := &fakeTTY{answer: c.answer}
		owners := filepath.Join(t.TempDir(), "owners")
		p := &Pairer{ControlURL: srv.URL, Token: "tok", HostID: testHost, RPID: testRP, Origin: testOrigin,
			OwnersFile: owners, HTTP: srv.Client(), TTY: tty, Now: time.Now, Poll: time.Millisecond, MaxWait: 5 * time.Second}
		o, err := p.Pair(context.Background())
		srv.Close()
		if c.wantErr != "" {
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), c.wantErr) {
				t.Errorf("%s: err %v", c.name, err)
			}
		} else if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
		got, _ := ReadOwners(owners, true)
		if c.paired != (len(got) == 1) {
			t.Errorf("%s: owners %v", c.name, got)
			continue
		}
		if !c.paired {
			continue
		}
		if cp.gotToken != "Bearer tok" {
			t.Errorf("token %q", cp.gotToken)
		}
		if o.Fingerprint != protocol.PermissionFingerprint(k.credID, k.cose) || got[0].HostID != testHost ||
			got[0].Origin != testOrigin || got[0].Name != "ana@example.com[2J" {
			t.Errorf("%s: owner %+v", c.name, got[0])
		}
		out := tty.out.String()
		for _, want := range []string{"Code: KQ7M-2XRD", "Open this link signed in to Rowsafe as an owner or admin", cp.url,
			"create a passkey", "Does your browser show the same code? " + o.Fingerprint + " [y/N]", "Paired."} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: terminal lacks %q:\n%s", c.name, want, out)
			}
		}
		if strings.Contains(out, "\x1b") {
			t.Errorf("%s: terminal escape from the control plane reached the terminal", c.name)
		}
		// Pairing the same passkey again changes nothing.
		srv = httptest.NewServer((&fakeCP{t: t, key: k, status: "completed", url: cp.url}).handler())
		p.ControlURL, p.HTTP, p.TTY = srv.URL, srv.Client(), &fakeTTY{answer: "y"}
		if _, err := p.Pair(context.Background()); err != nil {
			t.Errorf("re-pair: %v", err)
		}
		srv.Close()
		if got, _ := ReadOwners(owners, true); len(got) != 1 {
			t.Errorf("re-pair added a second owner")
		}
	}
}

func TestParseEnvFileAndRP(t *testing.T) {
	env := ParseEnvFile([]byte("# c\nROWSAFE_URL='https://api.example.com'\nROWSAFE_PERMISSIONS_RP_ID=\"example.com\"\nROWSAFE_PERMISSIONS_ORIGIN=https://app.example.com\n#ROWSAFE_X=1\n"))
	if env["ROWSAFE_URL"] != "https://api.example.com" || env["ROWSAFE_X"] != "" {
		t.Fatal(env)
	}
	rp, origin, err := RPFromEnv(env)
	if err != nil || rp != "example.com" || origin != "https://app.example.com" {
		t.Fatal(rp, origin, err)
	}
	if rp, origin, err := RPFromEnv(map[string]string{}); err != nil || rp != protocol.PermissionsRPID || origin != protocol.PermissionsOrigin {
		t.Fatal(rp, origin, err)
	}
	for _, bad := range []map[string]string{
		{"ROWSAFE_PERMISSIONS_ORIGIN": "http://app.example.com"},
		{"ROWSAFE_PERMISSIONS_ORIGIN": "https://app.example.com/path"},
		{"ROWSAFE_PERMISSIONS_RP_ID": "other.com"},
	} {
		if _, _, err := RPFromEnv(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestApplyRemoval(t *testing.T) {
	removal := func(e *applyEnv, rm protocol.PermissionRemoval, extra string) {
		data, _ := json.Marshal(Request{ID: "t1", Remove: &rm})
		if extra != "" {
			data = []byte(strings.Replace(string(data), `{"id"`, extra+`"id"`, 1))
		}
		if err := os.WriteFile(e.h.RequestPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// No passkey paired: a removal still goes through.
	e := newApplyEnv(t)
	_ = os.Remove(e.h.OwnersFile)
	removal(e, protocol.PermissionRemoval{HostID: testHost, Remove: []string{"reboot", "restart"}, RequestedBy: "ana@example.com"}, "")
	a := e.run()
	if !a.Applied || a.Refused != "" {
		t.Fatalf("removal: %+v", a)
	}
	args, _ := os.ReadFile(e.argsTo)
	if got := strings.TrimSpace(string(args)); got != "--permissions --no-prompt --no-allow-restart --no-allow-reboot" {
		t.Fatalf("installer args %q", got)
	}
	if !strings.Contains(e.log.String(), "turn off [reboot restart], requested by ana@example.com") {
		t.Fatalf("journal: %s", e.log.String())
	}

	cases := map[string]struct {
		rm    protocol.PermissionRemoval
		extra string
		want  string
	}{
		"firewall needs a passkey":      {protocol.PermissionRemoval{HostID: testHost, Remove: []string{"firewall"}}, "", "needs a passkey"},
		"pooler-public needs a passkey": {protocol.PermissionRemoval{HostID: testHost, Remove: []string{"pooler", "pooler-public"}}, "", "needs a passkey"},
		"unknown":                       {protocol.PermissionRemoval{HostID: testHost, Remove: []string{"root"}}, "", "unknown permission"},
		"nothing":                       {protocol.PermissionRemoval{HostID: testHost}, "", "nothing to change"},
		"other host":                    {protocol.PermissionRemoval{HostID: "host_02", Remove: []string{"restart"}}, "", "another server"},
		"with a signature":              {protocol.PermissionRemoval{HostID: testHost, Remove: []string{"restart"}}, `"signed":{"change":"eyJ9"},`, "malformed"},
	}
	for name, c := range cases {
		e := newApplyEnv(t)
		removal(e, c.rm, c.extra)
		a := e.run()
		if a.Applied || !strings.Contains(a.Refused, c.want) {
			t.Errorf("%s: %+v", name, a)
		}
		if _, err := os.Stat(e.argsTo); err == nil {
			t.Errorf("%s: the installer ran", name)
		}
	}
}
