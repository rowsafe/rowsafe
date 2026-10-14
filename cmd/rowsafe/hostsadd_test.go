package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/client"
	"github.com/rowsafe/rowsafe/protocol"
)

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain":             "plain",
		"root@203.0.113.10": "root@203.0.113.10",
		"":                  "''",
		"a b":               "'a b'",
		"it's":              `'it'\''s'`,
		"$(id)":             "'$(id)'",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestRootCommand(t *testing.T) {
	t.Setenv("ROWSAFE_INSTALLER_URL", "")
	root := rootCommand(0, protocol.DefaultAPIURL, "/tmp/tok", []string{"--storage", "rowsafe"})
	if root[0] != "sh" || root[3] != "rowsafe-install" || root[4] != "/tmp/tok" || root[5] != "--storage" {
		t.Fatalf("root: %q", root)
	}
	if !strings.Contains(root[2], "curl -fsSL --proto '=https' https://rowsafe.sh | sh -s") || strings.Contains(root[2], "ROWSAFE_URL") {
		t.Fatalf("script: %s", root[2])
	}
	user := rootCommand(1000, "https://cp.example.com", "/tmp/tok", nil)
	if user[0] != "sudo" || !strings.Contains(user[3], "ROWSAFE_URL=https://cp.example.com; export ROWSAFE_URL") {
		t.Fatalf("user: %q", user)
	}
}

// fakeSSH writes an ssh that runs the remote command here (the "server" is
// this computer, reporting Linux), logging every argument list it got.
func fakeSSH(t *testing.T, dir, osName string) (sshPath, logPath string) {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(dir, "ssh.log")
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("ssh", `#!/bin/sh
printf '%s\n' "$*" >>`+shellQuote(logPath)+`
for a in "$@"; do case $a in -M|-O) exit 0 ;; esac; done
while [ $# -gt 0 ]; do [ "$1" = -- ] && break; shift; done
shift 2
PATH=`+shellQuote(bin)+`:$PATH exec sh -c "$*"
`)
	write("uname", "#!/bin/sh\necho "+osName+"\n")
	write("sudo", "#!/bin/sh\necho sudo >>"+shellQuote(logPath)+"\nexec \"$@\"\n")
	return filepath.Join(bin, "ssh"), logPath
}

func enrollAPI(t *testing.T, token string, made *int) *client.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/hosts/enrollment-tokens", func(w http.ResponseWriter, r *http.Request) {
		var req protocol.CreateEnrollmentTokenRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.TTLSeconds != 1800 {
			t.Errorf("ttl %d", req.TTLSeconds)
		}
		*made++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.EnrollmentToken{Token: token, ExpiresAt: time.Now().Add(30 * time.Minute)})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return client.New(ts.URL, "rsk_test")
}

func TestHostsAddOverSSH(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("needs curl")
	}
	dir := t.TempDir()
	ssh, log := fakeSSH(t, dir, "Linux")
	t.Setenv("ROWSAFE_SSH", ssh)
	t.Setenv("TMPDIR", dir)
	out := filepath.Join(dir, "installer.out")
	inst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The installer: what it got, and whether its token file is gone.
		_, _ = w.Write([]byte(`echo "token=$ROWSAFE_ENROLL_TOKEN url=${ROWSAFE_URL:-} args=$*" >` + shellQuote(out) + "\n"))
	}))
	defer inst.Close()
	t.Setenv("ROWSAFE_INSTALLER_URL", inst.URL)

	const token = "rse_abcdefghijklmnopqrstuv"
	made := 0
	c := enrollAPI(t, token, &made)
	err := hostsAdd(t.Context(), c, config{URL: "https://cp.example.com"}, []string{"root@203.0.113.10", "-p", "2222", "--", "--storage", "rowsafe"})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if want := "token=" + token + " url=https://cp.example.com args=--storage rowsafe\n"; string(got) != want {
		t.Fatalf("installer got %q, want %q", got, want)
	}
	if made != 1 {
		t.Fatalf("%d tokens made", made)
	}
	l, _ := os.ReadFile(log)
	if strings.Contains(string(l), token) {
		t.Fatalf("the token appeared on a command line:\n%s", l)
	}
	if !strings.Contains(string(l), "-p 2222") || !strings.Contains(string(l), "-t -- root@203.0.113.10") || !strings.Contains(string(l), "\nsudo\n") {
		t.Fatalf("ssh calls:\n%s", l)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "tmp.*")); len(left) != 0 {
		t.Fatalf("token file left behind: %v", left)
	}
}

func TestHostsAddRefuses(t *testing.T) {
	dir := t.TempDir()
	ssh, _ := fakeSSH(t, dir, "Darwin")
	t.Setenv("ROWSAFE_SSH", ssh)
	made := 0
	c := enrollAPI(t, "rse_abcdefghijklmnopqrstuv", &made)
	ctx := t.Context()
	if err := hostsAdd(ctx, c, config{}, []string{"me@mac"}); err == nil || !strings.Contains(err.Error(), "runs Darwin") {
		t.Fatalf("a Mac server: %v", err)
	}
	if err := hostsAdd(ctx, c, config{}, []string{"root@db", "--", "rse_x"}); err == nil || !strings.Contains(err.Error(), "makes one") {
		t.Fatalf("a token: %v", err)
	}
	if err := hostsAdd(ctx, c, config{}, []string{"a", "b"}); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("two servers: %v", err)
	}
	if runtime.GOOS != "linux" {
		if err := hostsAdd(ctx, c, config{}, nil); err == nil || !strings.Contains(err.Error(), "give the server") {
			t.Fatalf("no server on %s: %v", runtime.GOOS, err)
		}
	}
	if made != 0 {
		t.Fatalf("%d tokens made for refused installs", made)
	}
}
