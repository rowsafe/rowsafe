// Package chproxyroot is the root side of connection pooling for
// ClickHouse: root's copy of the agent (rowsafe-permissions chproxy-apply,
// started by rowsafe-chproxy-apply.path) installs chproxy and runs it in front of
// a ClickHouse HTTP port root allowed (/etc/rowsafe/pooler-allowed,
// `rowsafe-allow pooler`), the way the ProxySQL helper does for MySQL.
//
// chproxy (github.com/ContentSquare/chproxy) is the standard proxy for
// ClickHouse's HTTP interface: it limits how many queries each user runs at
// once, queues the rest instead of letting ClickHouse refuse them, and
// spreads load. It covers the HTTP interface (8123/8443) only, not the
// native protocol (9000) clickhouse-client and native drivers use.
//
// Nothing secret is stored: chproxy's one user is wildcarded, so every app
// logs in with its own ClickHouse user and password, which chproxy passes
// on to ClickHouse to check. The binary is chproxy's release for this
// architecture, checked against the SHA-256 pinned here before it is
// installed; it runs as a dynamic, unprivileged systemd user.
//
// The agent is not trusted: every value is checked here, and chproxy only
// ever points at 127.0.0.1 on an allowed port.
package chproxyroot

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Defaults (the systemd unit sets the directories).
const (
	DefaultRequestDir = "/var/lib/rowsafe/pooler"
	DefaultAnswerDir  = "/run/rowsafe-chproxy-apply"
	DefaultStateDir   = "/var/lib/rowsafe-chproxy-apply"
	DefaultAllowFile  = "/etc/rowsafe/pooler-allowed"
	DefaultBinary     = "/usr/local/lib/rowsafe/chproxy"
	DefaultConfig     = "/etc/rowsafe/chproxy.yml"
	DefaultUnit       = "/etc/systemd/system/rowsafe-chproxy.service"
	UnitName          = "rowsafe-chproxy.service"
	RequestName       = "chproxy-request"
	ResultName        = "result"
	MaxRequest        = 64 << 10
	DefaultPort       = 9090
)

// The chproxy release Rowsafe installs, and its SHA-256 per architecture.
const Version = "1.30.0"

var releaseSHA256 = map[string]string{
	"amd64": "a5d814e11020d09a943e3082faa7a972f7ddd94564ad9402deec1e6417224e65",
	"arm64": "16e9400ce097c5b5b87618a5ed95cb5da9b4ae3226643a8f7ea80c80b94fe942",
}

// ReleaseURL is where the release for arch is downloaded from.
func ReleaseURL(arch string) string {
	return fmt.Sprintf("https://github.com/ContentSquare/chproxy/releases/download/v%s/chproxy_%s_linux_%s.tar.gz", Version, Version, arch)
}

// Actions.
const (
	ActionOn       = "on"       // install if needed, configure, start
	ActionRetarget = "retarget" // point at another allowed port
	ActionOff      = "off"      // stop, remove what Rowsafe installed
)

// Where chproxy listens (protocol.PoolerListen*).
const (
	ListenLocal   = "local"
	ListenPrivate = "private"
	ListenPublic  = "public"
)

// Request is what the agent hands over.
type Request struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	// Target is ClickHouse's HTTP port (on 127.0.0.1).
	Target int `json:"target"`
	// Port and Listen are where chproxy listens for apps.
	Port   int    `json:"port,omitempty"`
	Listen string `json:"listen,omitempty"`
	// Concurrent is how many queries each user runs at once; Queue how many
	// more wait (up to QueueSeconds) instead of failing.
	Concurrent   int `json:"concurrent,omitempty"`
	Queue        int `json:"queue,omitempty"`
	QueueSeconds int `json:"queue_seconds,omitempty"`
}

// Result is root's answer.
type Result struct {
	ID         string    `json:"id"`
	OK         bool      `json:"ok"`
	Error      string    `json:"error,omitempty"`
	Version    string    `json:"version,omitempty"`
	Installed  bool      `json:"installed,omitempty"`
	Removed    bool      `json:"removed,omitempty"`
	Addresses  []string  `json:"addresses,omitempty"`
	Target     string    `json:"target,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`
	FinishedAt time.Time `json:"finished_at"`
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Allowed reads the allow file: ports, and whether pooling may listen on
// public addresses (same file as PgBouncer's and ProxySQL's).
func Allowed(path string) (ports map[int]bool, public bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	ports = map[int]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if f[0] == "public" {
			public = true
			continue
		}
		if p, err := strconv.Atoi(f[0]); err == nil && p > 0 && p < 65536 {
			ports[p] = true
		}
	}
	return ports, public, nil
}

// Check validates a request.
func Check(r Request, ports map[int]bool, public bool) error {
	if !idRE.MatchString(r.ID) {
		return errors.New("invalid request id")
	}
	switch r.Action {
	case ActionOn, ActionRetarget, ActionOff:
	default:
		return fmt.Errorf("unknown action %q", r.Action)
	}
	if r.Action == ActionOff {
		return nil
	}
	if !ports[r.Target] {
		return fmt.Errorf("port %d is not in the allow list: pooling it from Rowsafe is not allowed", r.Target)
	}
	if r.Action == ActionOn {
		if r.Port < 1024 || r.Port > 65535 || r.Port == r.Target || ports[r.Port] {
			return errors.New("chproxy's port must be between 1024 and 65535, and not one of ClickHouse's")
		}
		switch r.Listen {
		case ListenLocal, ListenPrivate:
		case ListenPublic:
			if !public {
				return errors.New("listening on every address is not allowed on this server (root allows it with: sudo rowsafe-allow pooler-public)")
			}
		default:
			return fmt.Errorf("unknown listen %q", r.Listen)
		}
		if r.Concurrent < 1 || r.Concurrent > 10000 || r.Queue < 0 || r.Queue > 100000 || r.QueueSeconds < 1 || r.QueueSeconds > 3600 {
			return errors.New("invalid limits")
		}
	}
	return nil
}

// privateNets are the networks "private" lets in.
var privateNets = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}

// Config is chproxy's configuration for r (nothing secret in it).
func Config(r Request) string {
	listen, nets := "127.0.0.1", []string{"127.0.0.0/8", "::1/128"}
	switch r.Listen {
	case ListenPrivate:
		listen, nets = "0.0.0.0", privateNets
	case ListenPublic:
		listen, nets = "0.0.0.0", []string{"0.0.0.0/0", "::/0"}
	}
	q := func(xs []string) string {
		out := make([]string, len(xs))
		for i, x := range xs {
			out[i] = strconv.Quote(x)
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	return fmt.Sprintf(`# Written by Rowsafe (rowsafe-chproxy.service): connection pooling for
# ClickHouse's HTTP interface. Apps log in with their own ClickHouse user
# and password; chproxy passes them on. Changes here are replaced the next
# time pooling changes in Rowsafe.
server:
  http:
    listen_addr: %q
    allowed_networks: %s
  metrics:
    allowed_networks: ["127.0.0.0/8", "::1/128"]
users:
  - name: "*"
    is_wildcarded: true
    to_cluster: "local"
    to_user: "*"
    max_concurrent_queries: %d
    max_queue_size: %d
    max_queue_time: %ds
    # ClickHouse's own limits apply; chproxy's default would stop queries after 2 minutes.
    max_execution_time: 168h
clusters:
  - name: "local"
    nodes: ["127.0.0.1:%d"]
    heartbeat:
      request: "/ping"
      response: "Ok.\n"
    users:
      - name: "*"
`, fmt.Sprintf("%s:%d", listen, r.Port), q(nets), r.Concurrent, r.Queue, r.QueueSeconds, r.Target)
}

// unit runs chproxy as a dynamic, unprivileged user.
const unit = `# SPDX-License-Identifier: Apache-2.0
# rowsafe-chproxy.service: chproxy in front of ClickHouse's HTTP interface
# (connection pooling), set up by Rowsafe when someone turned pooling on.
# Its configuration (/etc/rowsafe/chproxy.yml) holds no secrets.

[Unit]
Description=Rowsafe: chproxy (connection pooling for ClickHouse)
Documentation=https://rowsafe.sh/docs/guides/connection-pooling
After=network-online.target clickhouse-server.service
Wants=network-online.target

[Service]
ExecStart=/usr/local/lib/rowsafe/chproxy -config /etc/rowsafe/chproxy.yml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`

// Runner runs a command as root and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Applier sets chproxy up for root.
type Applier struct {
	StateDir string
	// Binary, ConfigFile and UnitFile are where chproxy, its configuration
	// and its systemd unit go (tests: a temporary directory).
	Binary, ConfigFile, UnitFile string
	Run                          Runner
	// Fetch downloads the release (tests: a local file).
	Fetch func(ctx context.Context, url string) (io.ReadCloser, error)
	// Arch is GOARCH ("" = this machine's).
	Arch string
}

func (a *Applier) ownedFile() string { return filepath.Join(a.StateDir, "installed-by-rowsafe") }

func (a *Applier) ours() bool {
	_, err := os.Stat(a.UnitFile)
	return err == nil
}

// version is the installed binary's version ("" when none).
func (a *Applier) version(ctx context.Context) string {
	out, err := a.Run(ctx, a.Binary, "-version")
	if err != nil {
		return ""
	}
	// "chproxy ver. 1.30.0, rev. ..., built at ..."
	if m := regexp.MustCompile(`ver\. ?v?([0-9][0-9.]*)`).FindSubmatch(out); m != nil {
		return strings.TrimSuffix(string(m[1]), ".")
	}
	return ""
}

// install downloads chproxy's release, checks its SHA-256 and puts the
// binary in place.
func (a *Applier) install(ctx context.Context) error {
	arch := cmpOr(a.Arch, runtime.GOARCH)
	want, ok := releaseSHA256[arch]
	if !ok {
		return fmt.Errorf("chproxy has no release for this machine (%s)", arch)
	}
	fetch := a.Fetch
	if fetch == nil {
		fetch = httpFetch
	}
	body, err := fetch(ctx, ReleaseURL(arch))
	if err != nil {
		return fmt.Errorf("downloading chproxy %s: %v", Version, err)
	}
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, 64<<20))
	if err != nil {
		return fmt.Errorf("downloading chproxy %s: %v", Version, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want {
		return fmt.Errorf("the chproxy %s download doesn't match its known checksum: not installed", Version)
	}
	zr, err := gzip.NewReader(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return errors.New("the chproxy release has no chproxy program in it")
		}
		if h.Typeflag != tar.TypeReg || filepath.Base(h.Name) != "chproxy" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(a.Binary), 0o755); err != nil {
			return err
		}
		tmp := a.Binary + ".tmp"
		f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, 128<<20))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(tmp)
			return err
		}
		return os.Rename(tmp, a.Binary)
	}
}

func httpFetch(ctx context.Context, url string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rowsafe-chproxy-helper")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s answered HTTP %d", url, resp.StatusCode)
	}
	return resp.Body, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// writeFile writes a root-owned file atomically.
func writeFile(path, content string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Apply runs a request.
func (a *Applier) Apply(ctx context.Context, r Request, ports map[int]bool, public bool) Result {
	res := Result{ID: r.ID}
	if err := Check(r, ports, public); err != nil {
		res.Error = err.Error()
		return res
	}
	var err error
	switch r.Action {
	case ActionOff:
		err = a.off(ctx, &res)
	case ActionOn:
		err = a.on(ctx, r, &res)
	case ActionRetarget:
		err = a.retarget(ctx, r, &res)
	}
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	return res
}

// statePath keeps the last request (for retargets).
func (a *Applier) statePath() string { return filepath.Join(a.StateDir, "request.json") }

func (a *Applier) on(ctx context.Context, r Request, res *Result) error {
	if a.version(ctx) != Version {
		if err := a.install(ctx); err != nil {
			return err
		}
		res.Installed = true
		if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
			return err
		}
		_ = os.WriteFile(a.ownedFile(), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
	}
	cfg := Config(r)
	if err := writeFile(a.ConfigFile, cfg, 0o644); err != nil {
		return err
	}
	fresh := !a.ours()
	if err := writeFile(a.UnitFile, unit, 0o644); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", UnitName}, {"restart", UnitName}} {
		if out, err := a.Run(ctx, "systemctl", args...); err != nil {
			if fresh {
				_ = os.Remove(a.UnitFile)
			}
			return fmt.Errorf("starting chproxy failed (systemctl %s): %s", strings.Join(args, " "), lastLine(out))
		}
	}
	if err := a.saveRequest(r); err != nil {
		return err
	}
	res.Version, res.Target = Version, fmt.Sprintf("127.0.0.1:%d", r.Target)
	res.Addresses = []string{"127.0.0.1"}
	if r.Listen != ListenLocal {
		res.Addresses = []string{"0.0.0.0"}
	}
	return nil
}

func (a *Applier) saveRequest(r Request) error {
	if err := os.MkdirAll(a.StateDir, 0o700); err != nil {
		return err
	}
	return writeFile(a.statePath(), fmt.Sprintf("%d %d %s %d %d %d\n", r.Target, r.Port, r.Listen, r.Concurrent, r.Queue, r.QueueSeconds), 0o600)
}

func (a *Applier) loadRequest() (Request, error) {
	data, err := os.ReadFile(a.statePath())
	if err != nil {
		return Request{}, errors.New("Rowsafe doesn't run chproxy on this server (turn pooling on first)")
	}
	var r Request
	if _, err := fmt.Sscanf(string(data), "%d %d %s %d %d %d", &r.Target, &r.Port, &r.Listen, &r.Concurrent, &r.Queue, &r.QueueSeconds); err != nil {
		return Request{}, err
	}
	return r, nil
}

// retarget points chproxy at another allowed port: a new configuration
// and a reload (SIGHUP), so open connections aren't dropped.
func (a *Applier) retarget(ctx context.Context, r Request, res *Result) error {
	if !a.ours() {
		return errors.New("Rowsafe doesn't run chproxy on this server (turn pooling on first)")
	}
	cur, err := a.loadRequest()
	if err != nil {
		return err
	}
	cur.Target = r.Target
	if err := writeFile(a.ConfigFile, Config(cur), 0o644); err != nil {
		return err
	}
	if out, err := a.Run(ctx, "systemctl", "reload", UnitName); err != nil {
		return fmt.Errorf("reloading chproxy failed: %s", lastLine(out))
	}
	if err := a.saveRequest(cur); err != nil {
		return err
	}
	res.Version, res.Target = Version, fmt.Sprintf("127.0.0.1:%d", r.Target)
	return nil
}

func (a *Applier) off(ctx context.Context, res *Result) error {
	if !a.ours() {
		return nil // nothing of Rowsafe's
	}
	_, _ = a.Run(ctx, "systemctl", "disable", "--now", UnitName)
	_ = os.Remove(a.UnitFile)
	_, _ = a.Run(ctx, "systemctl", "daemon-reload")
	_ = os.Remove(a.ConfigFile)
	if _, err := os.Stat(a.ownedFile()); err == nil {
		_ = os.Remove(a.Binary)
		res.Removed = true
	}
	return os.RemoveAll(a.StateDir)
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	l := lines[len(lines)-1]
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}
