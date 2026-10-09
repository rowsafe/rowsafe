package qdrant

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// procRoot is where /proc is (tests change it).
var procRoot = "/proc"

// configEnv names Qdrant's configuration file when it isn't the Debian
// package's.
const configEnv = "ROWSAFE_QDRANT_CONFIG"

// DefaultConfig is the Debian package's configuration file (and the one
// the installer writes for servers Rowsafe creates).
const DefaultConfig = "/etc/qdrant/config.yaml"

// configPath is the configuration file Rowsafe reads ("" when none is
// readable).
func configPath() string {
	for _, p := range []string{strings.TrimSpace(os.Getenv(configEnv)), DefaultConfig} {
		if p == "" {
			continue
		}
		if f, err := os.Open(p); err == nil {
			f.Close()
			return p
		}
	}
	return ""
}

// fileConfig is the part of Qdrant's configuration file Rowsafe reads (no
// keys: those are in root's environment file, or read as "set" only).
type fileConfig struct {
	Storage struct {
		StoragePath   string `yaml:"storage_path"`
		SnapshotsPath string `yaml:"snapshots_path"`
	} `yaml:"storage"`
	Service struct {
		Host               string `yaml:"host"`
		HTTPPort           *int   `yaml:"http_port"`
		GRPCPort           *int   `yaml:"grpc_port"`
		EnableTLS          *bool  `yaml:"enable_tls"`
		EnableCORS         *bool  `yaml:"enable_cors"`
		JWTRBAC            *bool  `yaml:"jwt_rbac"`
		APIKey             string `yaml:"api_key"`
		AltAPIKey          string `yaml:"alt_api_key"`
		ReadOnlyAPIKey     string `yaml:"read_only_api_key"`
		SnapshotURLRecover *bool  `yaml:"enable_snapshot_url_recovery"`
	} `yaml:"service"`
	Cluster struct {
		Enabled *bool `yaml:"enabled"`
		P2P     struct {
			Port *int   `yaml:"port"`
			Host string `yaml:"host"`
		} `yaml:"p2p"`
	} `yaml:"cluster"`
	TLS struct {
		Cert    string `yaml:"cert"`
		Key     string `yaml:"key"`
		CertTTL *int   `yaml:"cert_ttl"`
	} `yaml:"tls"`
	TelemetryDisabled *bool `yaml:"telemetry_disabled"`
}

// readConfig reads Qdrant's configuration file (ok false: none readable).
func readConfig() (fileConfig, string, bool) {
	var fc fileConfig
	p := configPath()
	if p == "" {
		return fc, "", false
	}
	f, err := os.Open(p)
	if err != nil {
		return fc, p, false
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil || yaml.Unmarshal(data, &fc) != nil {
		return fc, p, false
	}
	return fc, p, true
}

// qdrantProc is a running qdrant found in /proc.
type qdrantProc struct {
	PID    int
	Unit   string
	Docker bool
}

// cgroupUnit reads a process's cgroup: the systemd unit running it, or
// whether a container runs it. A unit wins: systemd inside a container (a
// server whose own systemd runs in Docker) still names qdrant.service, while
// a container's process sits in docker-ID.scope or /docker/ID.
func cgroupUnit(cgroup string) (unit string, container bool) {
	for _, line := range strings.Split(cgroup, "\n") {
		if i := strings.LastIndex(line, "/"); i >= 0 && strings.HasSuffix(line, ".service") {
			return line[i+1:], false
		}
		if strings.Contains(line, "docker") || strings.Contains(line, "containerd") || strings.Contains(line, "libpod") {
			container = true
		}
	}
	return "", container
}

// findProcs lists the running qdrant processes (their program is named
// qdrant: /usr/bin/qdrant, ./qdrant in Qdrant's image).
func findProcs() []qdrantProc {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []qdrantProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "qdrant" {
			continue
		}
		p := qdrantProc{PID: pid}
		if cg, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cgroup")); err == nil {
			p.Unit, p.Docker = cgroupUnit(string(cg))
		}
		out = append(out, p)
	}
	return out
}

// candidatePorts are the ports a Qdrant may answer on: the saved logins',
// the configuration file's, ROWSAFE_QDRANT_PORT and 6333.
func candidatePorts(env agent.EngineEnv) []int {
	var ports []int
	if entries, err := os.ReadDir(loginsDir(env)); err == nil {
		for _, e := range entries {
			if n, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".json")); err == nil && n > 0 && n < 65536 {
				ports = append(ports, n)
			}
		}
	}
	if fc, _, ok := readConfig(); ok && fc.Service.HTTPPort != nil {
		ports = append(ports, *fc.Service.HTTPPort)
	}
	if v, err := strconv.Atoi(os.Getenv("ROWSAFE_QDRANT_PORT")); err == nil && v > 0 && v < 65536 {
		ports = append(ports, v)
	}
	if raw := strings.TrimSpace(os.Getenv(urlEnv)); raw != "" {
		if u, err := url.Parse(raw); err == nil {
			if n, err := strconv.Atoi(u.Port()); err == nil {
				ports = append(ports, n)
			}
		}
	}
	ports = append(ports, 6333)
	slices.Sort(ports)
	return slices.Compact(ports)
}

// Status is what `rowsafe-agent qdrant status` prints for the installer.
type Status struct {
	Port        int
	Version     string
	Login       string // ok, missing, refused, none (the server needs no key)
	TLS         bool
	JWT         string // yes, no, unknown
	Binary      string
	Docker      bool
	Cluster     bool
	Config      string
	Unit        string
	Collections int
}

// Print writes key=value lines ("-" when empty).
func (s Status) Print(w io.Writer) {
	v := func(x string) string {
		if x == "" {
			return "-"
		}
		return x
	}
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Fprintf(w, "port=%d\nengine=qdrant\nversion=%s\nlogin=%s\ntls=%s\njwt=%s\nbinary=%s\ndocker=%s\ncluster=%s\nconfig=%s\nunit=%s\ncollections=%d\n",
		s.Port, v(s.Version), v(s.Login), yn(s.TLS), v(s.JWT), v(s.Binary), yn(s.Docker), yn(s.Cluster), v(s.Config), v(s.Unit), s.Collections)
}

// errNotQdrant: nothing (or something else) answers on the port.
var errNotQdrant = errors.New("no Qdrant answers on this port")

// ServerStatus reads the server on port for the installer.
func ServerStatus(ctx context.Context, env agent.EngineEnv, port int) (Status, error) {
	st := Status{Port: port, Config: configPath(), Docker: inDocker()}
	l, saved, err := loadLogin(env, port)
	if err != nil {
		return st, err
	}
	c, err := newClient(ctx, l, port)
	if err != nil {
		return st, err
	}
	defer c.Close()
	r, err := c.root(ctx)
	if err != nil {
		return st, errNotQdrant
	}
	st.Version, st.TLS = r.Version, c.base.Scheme == "https"
	if procs := findProcs(); len(procs) > 0 {
		st.Unit = procs[0].Unit
		st.Docker = st.Docker || procs[0].Docker
	}
	if b, err := serverBinary(); err == nil {
		st.Binary = b
	}
	names, err := c.collectionNames(ctx)
	switch {
	case err == nil && l.Key == "":
		st.Login = "none"
	case err == nil:
		st.Login = "ok"
	case !saved:
		st.Login = "missing"
	default:
		st.Login = "refused"
	}
	st.Collections = len(names)
	st.JWT = "unknown"
	if l.Key != "" && err == nil {
		st.JWT = "no"
		if l.JWT {
			st.JWT = "yes"
		}
	}
	if err == nil {
		st.Cluster, _ = c.clusterOn(ctx)
	}
	return st, nil
}

// Discover finds Qdrant servers on this host for the installer.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	procs := findProcs()
	if len(procs) == 0 && !inDocker() {
		return nil, nil
	}
	var out []agent.DiscoveredDatabase
	for _, port := range candidatePorts(env) {
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		st, err := ServerStatus(hctx, env, port)
		cancel()
		if err != nil {
			continue
		}
		d := agent.DiscoveredDatabase{Port: port, Version: st.Version, Major: parseVersion(st.Version) / 10000, Unit: st.Unit}
		if fc, _, ok := readConfig(); ok {
			d.DataDir = fc.Storage.StoragePath
		}
		if st.Login == "missing" || st.Login == "refused" {
			fmt.Fprintf(env.Notes, "Qdrant on port %d asks for a key Rowsafe doesn't have yet\n", port)
		}
		if st.Login == "ok" || st.Login == "none" {
			if c, err := connectPort(ctx, env, port); err == nil {
				if in, err := inspect(ctx, c, false); err == nil {
					d.SizeBytes = in.totalBytes()
					for _, ci := range in.userCollections() {
						d.Databases = append(d.Databases, ci.Name)
					}
					if why := in.supported(); why != "" {
						fmt.Fprintf(env.Notes, "Qdrant on port %d: %s\n", port, why)
					}
				}
				c.Close()
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// LoginResult is what `rowsafe-agent qdrant login` reports.
type LoginResult struct {
	JWT    bool
	Source string
}

// SaveLogin checks key on the server on port and saves it as the agent's
// login: tokens signed with it when the server takes them (JWT access
// control on), else the key itself. source is "alt" (Rowsafe's own key,
// from root) or "key" (one the person gave). base, when set, is the
// server's URL (a sidecar).
func SaveLogin(ctx context.Context, env agent.EngineEnv, port int, key, source, base string) (LoginResult, error) {
	var res LoginResult
	key = strings.TrimSpace(key)
	if key == "" {
		return res, errors.New("no key given")
	}
	if strings.ContainsAny(key, " \t\r\n\"'\\") || len(key) > 512 {
		return res, errors.New("that doesn't look like a Qdrant key")
	}
	try := func(jwt bool) error {
		c, err := newClient(ctx, Login{Key: key, JWT: jwt, URL: base}, port)
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err := c.root(ctx); err != nil {
			return err
		}
		// Rowsafe's key must manage snapshots (every right).
		_, err = c.listFullSnapshots(ctx)
		return err
	}
	jwtErr := try(true)
	jwt := jwtErr == nil
	if !jwt {
		if err := try(false); err != nil {
			if errors.Is(err, errNotQdrant) {
				return res, err
			}
			return res, fmt.Errorf("Qdrant refused the key: %w", err)
		}
	}
	if err := saveLogin(env, port, Login{Key: key, JWT: jwt, URL: base, Source: source}); err != nil {
		return res, err
	}
	return LoginResult{JWT: jwt, Source: source}, nil
}

var _ = protocol.EngineQdrant
