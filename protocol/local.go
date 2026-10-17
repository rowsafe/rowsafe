package protocol

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// Without an account, the control plane runs inside the agent on the
// database server and listens on a Unix socket (internal/localcp): the agent,
// `rowsafe-agent setup` and the rowsafe CLI on that server reach it with a
// control-plane URL of unix://PATH.

// LocalSocketPath is the socket's default place (in the agent's state
// directory), and LocalControlURL the URL that reaches it.
const (
	LocalSocketPath = "/var/lib/rowsafe/control.sock"
	LocalControlURL = "unix://" + LocalSocketPath
)

// LocalEnrollToken is the enroll token of a control plane on the server: it
// has no account to enroll into.
const LocalEnrollToken = "local"

// LocalSocket returns the socket of a unix:// control-plane URL.
func LocalSocket(controlURL string) (path string, ok bool) {
	p, ok := strings.CutPrefix(controlURL, "unix://")
	return p, ok && p != ""
}

// HTTPClient returns an HTTP client for controlURL and the base URL to put
// before request paths: for unix://PATH, a client that dials that socket.
func HTTPClient(controlURL string, timeout time.Duration) (*http.Client, string) {
	sock, ok := LocalSocket(controlURL)
	if !ok {
		return &http.Client{Timeout: timeout}, strings.TrimRight(controlURL, "/")
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return &http.Client{Timeout: timeout, Transport: tr}, "http://rowsafe.local"
}
