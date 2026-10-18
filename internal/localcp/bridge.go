package localcp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

// From another computer, over SSH: the rowsafe CLI there runs
// `ssh SERVER sudo rowsafe-agent control-bridge`, and the bridge joins its
// stdin and stdout to this socket. Nothing listens on the network; the
// person's own SSH login (and sudo) decides who gets in.

// BridgeHello is the line the bridge writes once it reached the socket,
// before any HTTP: the CLI waits for it, so a failure (no agent, sudo
// asking for a password, an older agent) is told apart from a slow server.
const BridgeHello = "rowsafe-bridge 1"

// Bridge connects in and out to the control plane's socket until either
// side ends.
func Bridge(sock string, in io.Reader, out io.Writer) error {
	// A symlink in place of the socket could point root's bridge at
	// another socket: only the agent's own socket is joined.
	fi, err := os.Lstat(sock)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("the Rowsafe agent here isn't running on its own (no %s): it is connected to a Rowsafe account "+
			"(use rowsafe login on your computer), or it is stopped (systemctl status rowsafe-agent)", sock)
	case err != nil:
		return err
	case fi.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("%s isn't the agent's socket", sock)
	}
	conn, err := net.Dial("unix", sock)
	if errors.Is(err, os.ErrPermission) {
		return errors.New("Rowsafe's agent only answers root here: run the bridge with sudo")
	}
	if err != nil {
		return fmt.Errorf("the Rowsafe agent isn't answering on %s (systemctl status rowsafe-agent): %w", sock, err)
	}
	defer conn.Close()
	if _, err := io.WriteString(out, BridgeHello+"\n"); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(conn, in)
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite() // the HTTP client hung up: let the server finish
		}
	}()
	_, err = io.Copy(out, conn)
	return err
}
