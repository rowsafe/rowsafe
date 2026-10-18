package localcp

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBridge(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "rsb") // a socket path under 104 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "control.sock")

	if err := Bridge(sock, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), "isn't running on its own") {
		t.Fatalf("no socket: %v", err)
	}
	// A symlink in its place is refused, not followed.
	other := filepath.Join(dir, "other.sock")
	ln, err := net.Listen("unix", other)
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	if err := os.Symlink(other, sock); err != nil {
		t.Fatal(err)
	}
	if err := Bridge(sock, strings.NewReader(""), io.Discard); err == nil || !strings.Contains(err.Error(), "isn't the agent's socket") {
		t.Fatalf("a symlink: %v", err)
	}

	// The socket itself: the hello line, then bytes both ways.
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		line, _ := bufio.NewReader(c).ReadString('\n')
		_, _ = io.WriteString(c, "echo "+line)
		c.Close()
	}()
	var out strings.Builder
	if err := Bridge(other, strings.NewReader("ping\n"), &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != BridgeHello+"\necho ping\n" {
		t.Fatalf("bridged: %q", out.String())
	}
}
