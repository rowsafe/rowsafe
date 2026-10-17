package client

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseSSHTarget(t *testing.T) {
	for in, want := range map[string]SSHTarget{
		"ssh://root@db1.example.com":      {User: "root", Host: "db1.example.com"},
		"ssh://deploy@db1.example.com:22": {User: "deploy", Host: "db1.example.com", Port: 22},
		"ssh://db1":                       {Host: "db1"},
		"ssh://root@[2001:db8::1]:2222":   {User: "root", Host: "2001:db8::1", Port: 2222},
		"root@db1.example.com":            {User: "root", Host: "db1.example.com"},
		"prod-db":                         {Host: "prod-db"}, // a Host alias in ~/.ssh/config
		"root@[2001:db8::1]":              {User: "root", Host: "2001:db8::1"},
	} {
		got, err := ParseSSHTarget(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v, want %+v", in, got, err, want)
		}
		if again, err := ParseSSHTarget(got.String()); err != nil || again != got {
			t.Errorf("%s: %s reads back as %+v %v", in, got.String(), again, err)
		}
	}
	for _, in := range []string{"", "ssh://", "ssh://root:pw@db1", "ssh://-oProxyCommand=x", "-oProxyCommand=x", "root@-x",
		"db1:2222", "ssh://db1/path", "ssh://db1:99999", "postgres://db1/shop", "ro ot@db1", "ssh://db1?x=1", "root@db1;id"} {
		if got, err := ParseSSHTarget(in); err == nil {
			t.Errorf("%q: accepted as %+v", in, got)
		}
	}
}

func TestSSHArgs(t *testing.T) {
	t.Setenv("ROWSAFE_SSH", "ssh -F /tmp/cfg")
	args, err := SSHArgs(SSHTarget{User: "root", Host: "db1", Port: 2222}, SSHOptions{}, "echo hi")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(args, " ")
	if !strings.HasPrefix(got, "ssh -F /tmp/cfg -T ") || !strings.Contains(got, "-o BatchMode=yes") || !strings.HasSuffix(got, "-p 2222 -- root@db1 echo hi") {
		t.Errorf("ssh args: %s", got)
	}
	args, _ = SSHArgs(SSHTarget{Host: "db1"}, SSHOptions{Interactive: true, TTY: true}, "x")
	if got := strings.Join(args, " "); strings.Contains(got, "BatchMode") || !strings.Contains(got, " -t ") {
		t.Errorf("interactive ssh args: %s", got)
	}
}

// The remote command survives the server's shell: every argument arrives
// as it was, and sudo runs only when the login isn't root.
func TestRemoteCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh")
	}
	bin := t.TempDir()
	write := func(name, script string) {
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("sudo", `echo "sudo:$1"; shift; exec "$@"`+"\n")
	write("tool", `for a in "$@"; do echo "[$a]"; done`+"\n")
	args := []string{"pulse", "shop", "it's", `"quoted" $HOME`, "a b", "", "--to=10m ago", "ünï"}
	remote := RemoteCommand("-n", "/nonexistent/tool", args...)
	out, err := exec.Command("sh", "-c", "PATH="+ShellQuote(bin)+":$PATH; "+remote).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "sudo:-n\n"
	for _, a := range args {
		want += "[" + a + "]\n"
	}
	if string(out) != want {
		t.Errorf("got:\n%s\nwant:\n%s", out, want)
	}
	// Not installed: says so.
	out, _ = exec.Command("sh", "-c", RemoteCommand("-n", "/nonexistent/rowsafe-nothing")).CombinedOutput()
	if !strings.Contains(string(out), "Rowsafe isn't installed on this server") {
		t.Errorf("missing program: %s", out)
	}
}
