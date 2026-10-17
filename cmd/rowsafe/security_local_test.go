package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/internal/localcp"
	"github.com/rowsafe/rowsafe/protocol"
)

// secAgent is a fake agent for rowsafe security on the server: it reports
// a weak cluster and applies the security fixes to it.
type secAgent struct {
	mu        sync.Mutex
	rep       protocol.SecurityReport
	allowFile string // root's firewall-allowed: written by the fake rowsafe-allow
	fixes     []string
}

func (a *secAgent) report() protocol.SecurityReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.rep
	r.HBA = append([]protocol.HBARule(nil), a.rep.HBA...)
	if _, err := os.Stat(a.allowFile); err == nil {
		r.Firewall = protocol.FirewallState{Allowed: true}
	}
	return r
}

func (a *secAgent) fix(p protocol.SecurityFixParams) protocol.SecurityFixResult {
	a.mu.Lock()
	a.fixes = append(a.fixes, p.Action)
	switch p.Action {
	case protocol.SecScramPasswords:
		a.rep.PasswordEncryption = "scram-sha-256"
	case protocol.SecRestrictAccess:
		a.rep.HBA[1] = protocol.HBARule{Line: 2, Type: "host", Address: strings.TrimSuffix(p.AllowedAddresses[0], "/32"), Netmask: "255.255.255.255", Method: "md5"}
		a.rep.HBABackups = []string{"/var/lib/rowsafe/security/pg_hba.conf.1"}
	case protocol.SecFirewall:
		a.rep.Firewall.Active, a.rep.Firewall.Addresses = true, p.AllowedAddresses
	}
	a.mu.Unlock()
	rep := a.report()
	return protocol.SecurityFixResult{Action: p.Action, Summary: "Done: " + p.Action + ".", Report: &rep}
}

// securityServer runs this server's control plane on a Unix socket with
// shop registered, and the fake agent.
func securityServer(t *testing.T) *secAgent {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the agent's own control plane runs on a Linux server")
	}
	dir, err := os.MkdirTemp("/tmp", "rss") // a socket path under 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	st := map[string]any{
		"host": map[string]any{"id": "host_s", "token": "rsl_sec", "hostname": "db1"},
		"databases": []protocol.Database{{ID: "db_s1", Name: "shop", Stanza: "shop", Port: 5432, SocketDir: "/var/run/postgresql",
			Status: protocol.DBActive, Engine: protocol.EnginePostgreSQL, RetentionFull: 2}},
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, localcp.StateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := localcp.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip(err)
	}
	hs := &http.Server{Handler: srv.Handler()}
	go func() { _ = hs.Serve(ln) }()
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(func() { stop(); _ = hs.Close() })

	a := &secAgent{allowFile: filepath.Join(dir, "firewall-allowed"), rep: protocol.SecurityReport{DatabaseID: "db_s1",
		VersionNum: 170002, ServerVersion: "17.2", ListenAddresses: "*", Port: 5432, PasswordEncryption: "md5",
		HBAFile: "/etc/postgresql/17/main/pg_hba.conf",
		HBA: []protocol.HBARule{{Line: 1, Type: "local", Method: "peer"},
			{Line: 2, Type: "host", Address: "0.0.0.0", Netmask: "0.0.0.0", Method: "md5"}},
		Roles:    []protocol.RoleInfo{{Name: "app", CanLogin: true, Password: protocol.PasswordSCRAM}},
		Clients:  []protocol.ClientAddr{{Address: "10.0.1.5", Users: []string{"app"}, Sessions: 1}},
		Firewall: protocol.FirewallState{Reason: "Root didn't allow Rowsafe to manage the firewall for this port when installing the agent."}}}
	go a.run(ctx, sock)

	_, _ = cliEnv(t, &fakeAPI{})
	t.Setenv("ROWSAFE_API_KEY", "")
	t.Setenv("ROWSAFE_URL", "unix://"+sock)
	t.Setenv("DATABASE_URL", "")
	return a
}

func (a *secAgent) run(ctx context.Context, sock string) {
	hc := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	post := func(path string, in, out any) {
		body, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://local"+path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer rsl_sec")
		resp, err := hc.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if out != nil {
			_ = json.NewDecoder(resp.Body).Decode(out)
		}
	}
	for ctx.Err() == nil {
		post("/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.22"}, nil)
		var claim protocol.ClaimResponse
		post("/v1/agent/tasks/claim", protocol.ClaimRequest{}, &claim)
		task := claim.Task
		if task == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		var result any = struct{}{}
		switch task.Type {
		case protocol.TaskSecurityScan:
			result = a.report()
		case protocol.TaskSecurityFix:
			var p protocol.SecurityFixParams
			_ = json.Unmarshal(task.Params, &p)
			result = a.fix(p)
		}
		raw, _ := json.Marshal(result)
		post("/v1/agent/tasks/"+task.ID+"/complete", protocol.CompleteRequest{Status: protocol.StatusSucceeded, Result: raw}, nil)
	}
}

func TestSecurityOnServer(t *testing.T) {
	a := securityServer(t)
	terminal := func(answers string) {
		stdinIsTerminal = func() bool { return true }
		stdin = strings.NewReader(answers)
	}
	pipe := func() {
		stdinIsTerminal = func() bool { return false }
		stdin = strings.NewReader("")
	}

	// The findings in plain words, each with its fix.
	out, err := run(t, "security", "check", "shop")
	if err != nil || !strings.Contains(out, "Access rules let every address try to log in") ||
		!strings.Contains(out, "Fix it: rowsafe security fix shop security_open_rules") ||
		!strings.Contains(out, "Fix it: rowsafe security fix shop security_password_encryption") ||
		!strings.Contains(out, "Not checked: the look at the port from the internet") {
		t.Fatalf("check: %v\n%s", err, out)
	}

	// A fix asks for the database's name; nothing changes without it.
	pipe()
	if _, err := run(t, "security", "fix", "shop", "security_password_encryption"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("without a confirmation: %v", err)
	}
	terminal("nope\n")
	if _, err := run(t, "security", "fix", "shop", "security_password_encryption"); err == nil {
		t.Fatal("the wrong name went ahead")
	}
	if len(a.fixes) != 0 {
		t.Fatalf("changed without a confirmation: %v", a.fixes)
	}
	terminal("shop\n")
	if out, err = run(t, "security", "fix", "shop", "security_password_encryption"); err != nil || !strings.Contains(out, "New passwords are stored with old MD5 hashing") {
		t.Fatalf("scram: %v\n%s", err, out)
	}

	// Who may connect, by the finding's ID.
	pipe()
	if out, err = run(t, "security", "fix", "shop", "security_open_rules", "--allow", "10.0.1.5", "--yes"); err != nil {
		t.Fatalf("restrict: %v\n%s", err, out)
	}
	out, _ = run(t, "security", "shop")
	if strings.Contains(out, "security_open_rules") || strings.Contains(out, "security_password_encryption") {
		t.Fatalf("still there after the fixes:\n%s", out)
	}
	if strings.Join(a.fixes, ",") != "scram_passwords,restrict_access" {
		t.Fatalf("fixes %v", a.fixes)
	}
	if _, err := run(t, "security", "fix", "shop", "security_cert_expired", "--yes"); err == nil || !strings.Contains(err.Error(), "no finding security_cert_expired") {
		t.Errorf("a finding that isn't there: %v", err)
	}

	// The firewall touches the server: only with root's yes on it.
	isRoot = func() bool { return false }
	t.Cleanup(func() { isRoot = func() bool { return os.Geteuid() == 0 } })
	if _, err := run(t, "security", "fix", "shop", "firewall", "--allow", "10.0.1.5", "--yes"); err == nil ||
		!strings.Contains(err.Error(), "sudo rowsafe-allow firewall") || !strings.Contains(err.Error(), "Run it as root") {
		t.Fatalf("not root: %v", err)
	}
	isRoot = func() bool { return true }
	allow := filepath.Join(t.TempDir(), "rowsafe-allow")
	if err := os.WriteFile(allow, []byte("#!/bin/sh\n[ \"$1\" = firewall ] && touch '"+a.allowFile+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old := allowCommand
	allowCommand = allow
	t.Cleanup(func() { allowCommand = old })
	if _, err := run(t, "security", "fix", "shop", "firewall", "--allow", "10.0.1.5", "--yes"); err == nil || !strings.Contains(err.Error(), "--yes doesn't") {
		t.Fatalf("--yes allowed root's part: %v", err)
	}
	terminal("no\n")
	if _, err := run(t, "security", "fix", "shop", "firewall", "--allow", "10.0.1.5"); err == nil {
		t.Fatal("allowed without root's yes")
	}
	if _, err := os.Stat(a.allowFile); err == nil {
		t.Fatal("rowsafe-allow ran without root's yes")
	}
	terminal("firewall\nshop\n")
	if out, err = run(t, "security", "fix", "shop", "firewall", "--allow", "10.0.1.5"); err != nil || !strings.Contains(out, "Allowed.") {
		t.Fatalf("firewall with root's yes: %v\n%s", err, out)
	}
	if a.fixes[len(a.fixes)-1] != protocol.SecFirewall {
		t.Fatalf("fixes %v", a.fixes)
	}
}
