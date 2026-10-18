package agent

import (
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/rowsafe/rowsafe/protocol"
)

// A safe copy on a server on its own: localhost only, on the port the
// person chose.
func TestCopyListenLocalAndChosenPort(t *testing.T) {
	got, err := resolveListen(protocol.CopyListenLocal, nil)
	if err != nil || len(got) != 1 || got[0] != "127.0.0.1" {
		t.Fatalf("localhost: %v %v", got, err)
	}
	if _, err := resolveListen("127.0.0.2", []protocol.HostAddress{{IP: "10.0.0.5"}}); err == nil {
		t.Fatal("an address the server doesn't have")
	}

	a := &Agent{cfg: Config{StateDir: t.TempDir()}, log: slog.New(slog.DiscardHandler)}
	if _, err := a.chosenCopyPort(got, 80); err == nil {
		t.Fatal("a port below 1024")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	busy := l.Addr().(*net.TCPAddr).Port
	if _, err := a.chosenCopyPort(got, busy); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("a busy port: %v", err)
	}
	l.Close()
	if p, err := a.chosenCopyPort(got, busy); err != nil || p != busy {
		t.Fatalf("a free port: %d %v", p, err)
	}
	if err := a.copyState().put(copyRecord{ID: "sc_1", Kind: protocol.CopyKindSafe, Port: busy}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.chosenCopyPort(got, busy); err == nil || !strings.Contains(err.Error(), "another copy") {
		t.Fatalf("a port another copy uses: %v (%s)", err, strconv.Itoa(busy))
	}
}
