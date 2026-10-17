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

// Connecting a server without an account to one (`sudo rowsafe login` on
// it): the agent enrolls in the account, each database is registered there
// under the same name, and its history comes along so the dashboard isn't
// empty. The history is metadata only (backup labels and sizes, Proof
// results, Marks' names and positions): no data, no secrets.

// ImportRequest is that history, sent once with the agent's new token:
// POST /v1/agent/import. Each database must already be registered for the
// calling host; records already imported are skipped, so it can be sent
// again.
type ImportRequest struct {
	Databases []ImportDatabase `json:"databases"`
}

// ImportDatabase is one database's history. IDs are the server's own:
// the control plane keeps them to skip what it already has.
type ImportDatabase struct {
	Name          string         `json:"name"`
	Backups       []Backup       `json:"backups"`
	Drills        []Drill        `json:"drills"`
	RestorePoints []RestorePoint `json:"restore_points"`
}

// ImportResponse counts what was added per database.
type ImportResponse struct {
	Databases []ImportCounts `json:"databases"`
}

// ImportCounts is what one database's import added (Skipped: already there).
type ImportCounts struct {
	Name          string `json:"name"`
	Backups       int    `json:"backups"`
	Drills        int    `json:"drills"`
	RestorePoints int    `json:"restore_points"`
	Skipped       int    `json:"skipped"`
}

// Import limits per database (the server keeps less: internal/localcp).
const (
	ImportMaxBackups       = 1000
	ImportMaxDrills        = 500
	ImportMaxRestorePoints = 1000
)
