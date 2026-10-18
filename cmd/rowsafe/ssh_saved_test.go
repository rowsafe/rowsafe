package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/internal/localcp"
	"github.com/rowsafe/rowsafe/protocol"
)

// The fake SSH is this test binary (TestMain): it logs its arguments and
// runs the remote command with sh on this machine, as the server's shell
// would, with fake sudo, rowsafe-agent (this binary again, as the bridge to
// the test's control plane) and rowsafe (prints its arguments) on PATH.

const (
	fakeSSHEnv   = "ROWSAFE_TEST_FAKE_SSH"
	fakeAgentEnv = "ROWSAFE_TEST_FAKE_AGENT"
)

// fakeSSHMain is the fake ssh or the fake agent, when TestMain says so.
func fakeSSHMain() (code int, ran bool) {
	switch {
	case os.Getenv(fakeAgentEnv) == "1":
		if len(os.Args) < 2 || os.Args[1] != "control-bridge" {
			return 2, true
		}
		if err := localcp.Bridge(os.Getenv("ROWSAFE_TEST_SOCK"), os.Stdin, os.Stdout); err != nil {
			os.Stderr.WriteString("rowsafe: " + err.Error() + "\n")
			return 1, true
		}
		return 0, true
	case os.Getenv(fakeSSHEnv) == "1":
		args := os.Args[1:]
		if f, err := os.OpenFile(os.Getenv("ROWSAFE_TEST_SSH_LOG"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			_ = json.NewEncoder(f).Encode(args)
			f.Close()
		}
		i := 0
		for i < len(args) && args[i] != "--" {
			i++
		}
		if i+2 >= len(args) {
			os.Stderr.WriteString("fake ssh: no destination and command\n")
			return 255, true
		}
		if os.Getenv("ROWSAFE_TEST_SSH_DOWN") == "1" {
			os.Stderr.WriteString("ssh: connect to host " + args[i+1] + " port 22: Connection refused\n")
			return 255, true
		}
		// The server's programs are the fakes on PATH.
		remote := strings.NewReplacer(client.RemoteAgent, "/nonexistent/rowsafe-agent", client.RemoteCLI, "/nonexistent/rowsafe").Replace(args[i+2])
		cmd := exec.Command("sh", "-c", remote)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.Env = append(os.Environ(), fakeSSHEnv+"=", "PATH="+os.Getenv("ROWSAFE_TEST_BIN")+string(os.PathListSeparator)+os.Getenv("PATH"))
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode(), true
			}
			return 255, true
		}
		return 0, true
	}
	return 0, false
}

// sshServer runs a server's control plane (localServer) reached through
// the fake ssh, and returns a client on its socket and the fake's log.
func sshServer(t *testing.T) (*client.Client, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake server's shell is sh")
	}
	c, sock := localServerSock(t)
	t.Setenv("ROWSAFE_URL", "") // this computer isn't the server
	bin := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, script string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("sudo", `echo "sudo $*" >>"$ROWSAFE_TEST_SUDO_LOG"
[ -z "$ROWSAFE_TEST_SUDO_FAIL" ] || { echo "sudo: a password is required" >&2; exit 1; }
while [ "$#" -gt 0 ]; do case $1 in -*) shift ;; *) break ;; esac; done
exec "$@"
`)
	write("rowsafe-agent", `[ -z "$ROWSAFE_TEST_OLD_AGENT" ] || { echo "unknown command \"$1\"" >&2; exit 2; }
ROWSAFE_TEST_FAKE_AGENT=1 exec '`+self+`' "$@"
`)
	write("rowsafe", `for a in "$@"; do echo "ARG:$a"; done
exit "${ROWSAFE_TEST_EXIT:-0}"
`)
	logs := t.TempDir()
	t.Setenv("ROWSAFE_SSH", self)
	t.Setenv(fakeSSHEnv, "1")
	t.Setenv("ROWSAFE_TEST_SOCK", sock)
	t.Setenv("ROWSAFE_TEST_BIN", bin)
	t.Setenv("ROWSAFE_TEST_SSH_LOG", filepath.Join(logs, "ssh.log"))
	t.Setenv("ROWSAFE_TEST_SUDO_LOG", filepath.Join(logs, "sudo.log"))
	for _, v := range []string{"ROWSAFE_TEST_SUDO_FAIL", "ROWSAFE_TEST_OLD_AGENT", "ROWSAFE_TEST_EXIT", "ROWSAFE_TEST_SSH_DOWN"} {
		t.Setenv(v, "")
	}
	return c, logs
}

func readLog(t *testing.T, p string) string {
	t.Helper()
	data, _ := os.ReadFile(p)
	return string(data)
}

func TestSSHServer(t *testing.T) {
	c, logs := sshServer(t)
	ctx := t.Context()

	out, err := runCLI(t, "add", "shop", "ssh://deploy@db1.example.com:2222", "--json")
	if err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	var added savedAddResult
	if err := json.Unmarshal([]byte(out[strings.Index(out, "{"):]), &added); err != nil || added.SSH != "ssh://deploy@db1.example.com:2222" ||
		added.Database != "shop" || added.Server == nil || added.Server.Status != protocol.DBActive {
		t.Fatalf("add --json: %+v %v\n%s", added, err, out)
	}
	p, _ := savedPath()
	if data, _ := os.ReadFile(p); strings.Contains(string(data), `"url"`) || !strings.Contains(string(data), `"host": "db1.example.com"`) {
		t.Fatalf("databases.json:\n%s", data)
	}
	ssh := readLog(t, filepath.Join(logs, "ssh.log"))
	for _, want := range []string{`"-T"`, `"BatchMode=yes"`, `"-p","2222","--","deploy@db1.example.com"`, "control-bridge"} {
		if !strings.Contains(ssh, want) {
			t.Errorf("ssh ran without %s:\n%s", want, ssh)
		}
	}
	if sudo := readLog(t, filepath.Join(logs, "sudo.log")); !strings.Contains(sudo, "sudo -n /nonexistent/rowsafe-agent control-bridge") &&
		!strings.Contains(sudo, "rowsafe-agent control-bridge") {
		t.Errorf("sudo: %q", sudo)
	}

	out, err = runCLI(t, "databases")
	if err != nil || !strings.Contains(out, "ssh://deploy@db1.example.com:2222") {
		t.Fatalf("databases: %v\n%s", err, out)
	}

	// The server's agent, by the saved name.
	// (Not protected yet: the fake agent never reported archiving; exit 3.)
	if out, err = runCLI(t, "status", "shop"); (err != nil && err.Error() != "exit status 3") || !strings.Contains(out, "Last backup:") {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if out, err = runCLI(t, "mark", "shop", "before-migration"); err != nil {
		t.Fatalf("mark: %v\n%s", err, out)
	}
	marks, err := c.RestorePoints(ctx, "shop")
	if err != nil || !strings.Contains(jsonString(marks), "before-migration") {
		t.Fatalf("marks on the server: %+v %v", marks, err)
	}
	if out, err = runCLI(t, "marks", "shop"); err != nil || !strings.Contains(out, "before-migration") {
		t.Fatalf("marks: %v\n%s", err, out)
	}
	if out, err = runCLI(t, "backups", "shop"); err != nil || !strings.Contains(out, "20261014-010000F") {
		t.Fatalf("backups: %v\n%s", err, out)
	}
	out, err = runCLI(t, "restore", "shop", "--to", "before-drop")
	if err != nil || !strings.Contains(out, "copy of shop is ready") {
		t.Fatalf("restore: %v\n%s", err, out)
	}
	if out, err = runCLI(t, "alerts", "shop"); err != nil {
		t.Fatalf("alerts: %v\n%s", err, out)
	}
	if out, err = runCLI(t, "channels", "list", "shop"); err != nil || !strings.Contains(out, "rowsafe channels add shop --type slack") {
		t.Fatalf("channels: %v\n%s", err, out)
	}

	// pulse runs on the server with its rowsafe; arguments arrive whole.
	out, err = runCLI(t, "pulse", "shop", "--workload", "it's web")
	if err != nil || !strings.Contains(out, "ARG:pulse\nARG:shop\nARG:--workload\nARG:it's web\n") {
		t.Fatalf("pulse: %v\n%s", err, out)
	}
	t.Setenv("ROWSAFE_TEST_EXIT", "3")
	if _, err = runCLI(t, "pulse", "shop"); err == nil || err.Error() != "exit status 3" {
		t.Fatalf("pulse's exit code: %v", err)
	}
	t.Setenv("ROWSAFE_TEST_EXIT", "")

	// The project's database: no name needed.
	if _, err := runCLI(t, "use", "shop"); err != nil {
		t.Fatal(err)
	}
	if out, err = runCLI(t, "marks"); err != nil || !strings.Contains(out, "before-migration") {
		t.Fatalf("marks (project): %v\n%s", err, out)
	}
	if out, err = runCLI(t, "settings", "set", "work_mem=64MB", "--yes"); err != nil || !strings.Contains(out, "ARG:settings\nARG:set\nARG:shop\nARG:work_mem=64MB") {
		t.Fatalf("settings set (project): %v\n%s", err, out)
	}
}

func TestSSHServerAdd(t *testing.T) {
	_, _ = sshServer(t)
	// Another name here: the server's only database.
	out, err := runCLI(t, "add", "prod", "--ssh", "root@db1")
	if err != nil || !strings.Contains(out, "Saved prod: shop on db1 over SSH (as root).") {
		t.Fatalf("add prod: %v\n%s", err, out)
	}
	if out, err = runCLI(t, "marks", "prod"); err != nil || !strings.Contains(out, "before-drop") {
		t.Fatalf("marks prod: %v\n%s", err, out)
	}
	if _, err := runCLI(t, "add", "x", "ssh://root@db1", "--database", "crm"); err == nil || !strings.Contains(err.Error(), "no database named crm (it has shop)") {
		t.Fatalf("add --database crm: %v", err)
	}
	if _, err := runCLI(t, "add", "x", "ssh://root:pw@db1"); err == nil || !strings.Contains(err.Error(), "no password") {
		t.Fatalf("a password in the address: %v", err)
	}
	if _, err := runCLI(t, "add", "x", "ssh://-oProxyCommand=x"); err == nil {
		t.Fatal("an option as the host was accepted")
	}

	t.Setenv("ROWSAFE_TEST_SUDO_FAIL", "1")
	if _, err := runCLI(t, "add", "y", "ssh://deploy@db1"); err == nil || !strings.Contains(err.Error(), "NOPASSWD: /opt/rowsafe/rowsafe-agent control-bridge") {
		t.Fatalf("sudo asks for a password: %v", err)
	}
	t.Setenv("ROWSAFE_TEST_SUDO_FAIL", "")
	t.Setenv("ROWSAFE_TEST_OLD_AGENT", "1")
	if _, err := runCLI(t, "status", "prod"); err == nil || !strings.Contains(err.Error(), "older than this CLI") {
		t.Fatalf("an older agent: %v", err)
	}
	t.Setenv("ROWSAFE_TEST_OLD_AGENT", "")
	t.Setenv("ROWSAFE_TEST_SSH_DOWN", "1")
	if _, err := runCLI(t, "status", "prod"); err == nil || !strings.Contains(err.Error(), "Connection refused") {
		t.Fatalf("the server is down: %v", err)
	}
	t.Setenv("ROWSAFE_TEST_SSH_DOWN", "")
	if _, err := runCLI(t, "forget", "prod", "--yes"); err != nil {
		t.Fatal(err)
	}
}

// The Guard hook saves the Mark on the project's server, over SSH.
func TestSSHServerGuard(t *testing.T) {
	c, _ := sshServer(t)
	if out, err := runCLI(t, "add", "shop", "ssh://root@db1", "--no-check"); err != nil {
		t.Fatalf("add: %v\n%s", err, out)
	}
	dir, _ := os.Getwd()
	if err := os.WriteFile(filepath.Join(dir, ".rowsafe.json"), []byte(`{"database": "shop"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ev := `{"tool_name": "Bash", "tool_input": {"command": "psql -c 'DROP TABLE orders'"}, "cwd": "` + dir + `"}`
	old := stdin
	stdin = strings.NewReader(ev)
	t.Cleanup(func() { stdin = old })
	out, err := runCLI(t, "guard")
	if err != nil || !strings.Contains(out, "restore point agent-") || !strings.Contains(out, "rowsafe restore shop --to agent-") {
		t.Fatalf("guard: %v\n%s", err, out)
	}
	marks, _ := c.RestorePoints(t.Context(), "shop")
	if !strings.Contains(jsonString(marks), `"agent-`) {
		t.Fatalf("no Mark on the server: %+v", marks)
	}
}

func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// Every flag that takes a value is in sshValueFlags, so its value is never
// taken for a saved server's name.
func TestSSHValueFlags(t *testing.T) {
	re := regexp.MustCompile(`fs\.(?:String|Int|Duration|Float64|Int64|Uint|Var|StringVar|IntVar|DurationVar|Func|TextVar)\((?:&?[a-zA-Z.]+, )?"([a-z0-9-]+)"`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if !sshValueFlags[m[1]] {
				t.Errorf("%s: --%s takes a value: add it to sshValueFlags (ssh_saved.go)", f, m[1])
			}
		}
	}
}
