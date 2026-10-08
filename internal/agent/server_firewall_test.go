package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

func TestParseFirewallSources(t *testing.T) {
	got, err := parseFirewallSources("SSH", []string{" 203.0.113.4 ", "2001:db8::1", "10.1.2.3/16", "203.0.113.4/32", "", "::ffff:198.51.100.7", "0.0.0.0/0", "::/0"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.4/32", "10.1.0.0/16", "198.51.100.7/32", "0.0.0.0/0", "2001:db8::1/128", "::/0"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, err := parseFirewallSources("SSH", nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty list: %v %v", got, err)
	}
	for _, bad := range []string{"10.0.0.0/4", "2000::/8", "example.com", "1.2.3.4;flush", "fe80::1%eth0", "300.1.1.1"} {
		if _, err := parseFirewallSources("PostgreSQL", []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	many := make([]string, protocol.MaxServerFirewallSources+1)
	for i := range many {
		many[i] = "10.0.0.1"
	}
	if _, err := parseFirewallSources("SSH", many); err == nil {
		t.Error("too many addresses accepted")
	}
}

// fakeFirewallHelper answers the agent's requests like rowsafe-firewall:
// phase=pending once the rules are "loaded", then done once confirmed (or
// rolled back after wait).
type fakeFirewallHelper struct {
	dir, out string
	wait     time.Duration
	requests atomic.Int32
	last     atomic.Value // map[string]string: the files the agent wrote
}

func (h *fakeFirewallHelper) run(ctx context.Context) {
	seen := ""
	for ctx.Err() == nil {
		time.Sleep(time.Millisecond)
		line, err := os.ReadFile(filepath.Join(h.dir, "request"))
		if err != nil || strings.TrimSpace(string(line)) == seen {
			continue
		}
		seen = strings.TrimSpace(string(line))
		h.requests.Add(1)
		f := strings.Fields(seen)
		files := map[string]string{"request": seen}
		for _, name := range []string{"addresses", "ssh-addresses"} {
			if b, err := os.ReadFile(filepath.Join(h.dir, name)); err == nil {
				files[name] = string(b)
			}
		}
		h.last.Store(files)
		answer := func(phase, ok, msg string) {
			_ = writeFileAtomic(filepath.Join(h.out, "result"),
				[]byte("id="+f[0]+"\naction="+f[1]+"\nphase="+phase+"\nok="+ok+"\nerror="+msg+"\n"), 0o644)
		}
		answer("pending", "1", "")
		deadline := time.Now().Add(h.wait)
		confirmed := false
		for time.Now().Before(deadline) {
			if b, _ := os.ReadFile(filepath.Join(h.dir, "confirm")); strings.TrimSpace(string(b)) == f[0] {
				confirmed = true
				break
			}
			time.Sleep(time.Millisecond)
		}
		if !confirmed {
			answer("done", "0", "the agent did not confirm, so the previous rules were put back")
			continue
		}
		_ = writeFileAtomic(filepath.Join(h.out, "ssh"), []byte("addresses=x\nports=22,2222\napplied_at=1\nloaded=1\n"), 0o644)
		answer("done", "1", "")
	}
}

func serverFirewallSetup(t *testing.T, allow string, reachable bool) (*Agent, *fakeFirewallHelper) {
	t.Helper()
	root := t.TempDir()
	oldAllow, oldOut, oldDir, oldPoll, oldTimeout := firewallAllowFile, firewallResultDir, firewallDirEnv, restartPoll, firewallTimeout
	t.Cleanup(func() {
		firewallAllowFile, firewallResultDir, firewallDirEnv, restartPoll, firewallTimeout = oldAllow, oldOut, oldDir, oldPoll, oldTimeout
	})
	firewallAllowFile = filepath.Join(root, "firewall-allowed")
	firewallResultDir = filepath.Join(root, "run")
	firewallDirEnv = filepath.Join(root, "firewall")
	restartPoll, firewallTimeout = time.Millisecond, 10*time.Second
	for _, d := range []string{firewallResultDir, firewallDirEnv} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(firewallAllowFile, []byte(allow), 0o644); err != nil {
		t.Fatal(err)
	}
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !reachable || r.URL.Path != "/v1/agent/security" {
			http.Error(w, "no", http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(protocol.SecurityAck{IntervalSeconds: 900})
	}))
	t.Cleanup(cp.Close)
	h := &fakeFirewallHelper{dir: firewallDirEnv, out: firewallResultDir, wait: 2 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go h.run(ctx)
	return &Agent{cfg: Config{StateDir: root}, client: newControlClient(cp.URL, "rsa_x")}, h
}

func TestServerFirewallTask(t *testing.T) {
	a, h := serverFirewallSetup(t, "# PORT\n5432\nssh\n", true)
	params, _ := json.Marshal(protocol.ServerFirewallParams{Postgres: []string{"203.0.113.4", "2001:db8::/48"}, SSH: nil})
	task := &protocol.Task{ID: "task_fw", Type: protocol.TaskServerFirewall, Params: params}
	res, err := a.runTask(context.Background(), task, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	r := res.(*protocol.ServerFirewallResult)
	if r.Port != 5432 || !slices.Equal(r.Postgres, []string{"203.0.113.4/32", "2001:db8::/48"}) || len(r.SSH) != 0 ||
		!slices.Equal(r.SSHPorts, []int{22, 2222}) {
		t.Fatalf("result %+v", r)
	}
	if want := "Only 203.0.113.4/32, 2001:db8::/48 can reach PostgreSQL (port 5432), and no one but this server can reach SSH (ports 22, 2222). Other ports and outgoing connections are unchanged."; r.Summary != want {
		t.Fatalf("summary %q", r.Summary)
	}
	files := h.last.Load().(map[string]string)
	if !strings.HasSuffix(files["request"], " server 5432") || files["addresses"] != "203.0.113.4/32\n2001:db8::/48\n" || files["ssh-addresses"] != "" {
		t.Fatalf("files for the helper %q", files)
	}
	for _, f := range []string{"request", "addresses", "ssh-addresses", "confirm"} {
		if _, err := os.Stat(filepath.Join(firewallDirEnv, f)); err == nil {
			t.Errorf("%s left behind", f)
		}
	}
	if got := protocol.TaskTimeout(protocol.TaskServerFirewall); got != protocol.ServerFirewallTimeout {
		t.Errorf("timeout %s", got)
	}
}

func TestServerFirewallNotConfirmedWithoutControlPlane(t *testing.T) {
	a, h := serverFirewallSetup(t, "5432\nssh\n", false)
	h.wait = 200 * time.Millisecond
	_, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{Postgres: []string{"0.0.0.0/0", "::/0"}, SSH: []string{"198.51.100.0/24"}}, &taskLog{})
	if err == nil || !strings.Contains(err.Error(), "previous rules were put back") {
		t.Fatalf("err %v", err)
	}
}

func TestServerFirewallRefusals(t *testing.T) {
	// Without "ssh" in root's list (a server Rowsafe didn't create): refused
	// before the helper hears anything.
	a, h := serverFirewallSetup(t, "5432\n", true)
	if _, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{}, &taskLog{}); err == nil || !strings.Contains(err.Error(), "--firewall-ssh") {
		t.Fatalf("no ssh line: %v", err)
	}
	a, h2 := serverFirewallSetup(t, "5432\n5433\nssh\n", true)
	if _, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{}, &taskLog{}); err == nil || !strings.Contains(err.Error(), "say which one") {
		t.Fatalf("two ports: %v", err)
	}
	if _, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{Port: 5499}, &taskLog{}); err == nil || !strings.Contains(err.Error(), "not in root's") {
		t.Fatalf("unlisted port: %v", err)
	}
	if _, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{Port: 5433, SSH: []string{"10.0.0.0/4"}}, &taskLog{}); err == nil || !strings.Contains(err.Error(), "too wide") {
		t.Fatalf("wide network: %v", err)
	}
	a.cfg.Mode = ModeDockerSidecar
	if _, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{Port: 5433}, &taskLog{}); err == nil || !strings.Contains(err.Error(), "Docker") {
		t.Fatalf("sidecar: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if n := h.requests.Load() + h2.requests.Load(); n != 0 {
		t.Fatalf("the helper got %d requests", n)
	}
}

// A database with two ports (ClickHouse: 9440 and 8443): one request per
// port, each with the same lists, and a summary naming both.
func TestServerFirewallSeveralPorts(t *testing.T) {
	a, h := serverFirewallSetup(t, "9440\n8443\nssh\n", true)
	res, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{Postgres: []string{"203.0.113.4"},
		Port: 9440, Ports: []int{9440, 8443}, Engine: protocol.EngineClickHouse}, &taskLog{})
	if err != nil {
		t.Fatal(err)
	}
	if n := h.requests.Load(); n != 2 {
		t.Fatalf("the helper got %d requests", n)
	}
	if files := h.last.Load().(map[string]string); !strings.HasSuffix(files["request"], " server 8443") || files["addresses"] != "203.0.113.4/32\n" {
		t.Fatalf("last request %q", files)
	}
	if res.Port != 9440 || !slices.Equal(res.Ports, []int{9440, 8443}) ||
		!strings.HasPrefix(res.Summary, "Only 203.0.113.4/32 can reach ClickHouse (ports 9440 and 8443), and no one but this server can reach SSH") {
		t.Fatalf("result %+v", res)
	}
	// A port root didn't list is refused before the helper hears of it.
	if _, err := a.serverFirewall(context.Background(), protocol.ServerFirewallParams{Port: 9440, Ports: []int{9440, 9000}}, &taskLog{}); err == nil ||
		!strings.Contains(err.Error(), "port 9000 is not in root's") {
		t.Fatalf("unlisted second port: %v", err)
	}
	if n := h.requests.Load(); n != 2 {
		t.Fatalf("the helper got %d requests", n)
	}
}
