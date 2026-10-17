package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rowsafe/rowsafe/internal/localcp"
	"github.com/rowsafe/rowsafe/protocol"
)

// startLocalControl runs the control plane in this agent when ROWSAFE_URL is
// unix://PATH (a server without an account): the agent, `rowsafe-agent
// setup` and the rowsafe CLI on this server reach it on that socket. It
// keeps its state next to the socket and stops with the agent.
func (a *Agent) startLocalControl(ctx context.Context) error {
	sock, ok := protocol.LocalSocket(a.cfg.ControlURL)
	if !ok {
		return nil
	}
	srv, err := localcp.Open(filepath.Dir(sock), a.log.With("component", "local-control"))
	if err != nil {
		return fmt.Errorf("the control plane without an account: %w", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx, sock) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case err := <-errc:
			return fmt.Errorf("the control plane without an account: %w", err)
		default:
		}
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			go func() {
				if err := <-errc; err != nil {
					a.log.Error("the control plane without an account stopped", "err", err)
				}
			}()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the control plane without an account didn't start listening on %s", sock)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
