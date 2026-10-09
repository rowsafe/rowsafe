package opensearch

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// serverProc is a running OpenSearch found in /proc.
type serverProc struct {
	PID     int
	Port    int
	ConfDir string
	Home    string
	Unit    string
	User    string
	Conf    nodeConf
}

// procRoot is where /proc is (tests change it).
var procRoot = "/proc"

// nodeConf is what Rowsafe reads from opensearch.yml.
type nodeConf struct {
	HTTPPort        int
	HTTPHost        string
	PathRepo        []string
	PathData        []string
	SecurityOff     bool
	RestAPIRoles    []string
	HTTPTLS         bool
	Read            bool // the file could be read
	TransportHost   string
	HotReload       bool
	ReloadDNChecked bool
	// What OpenSearch's demo configuration sets.
	AdminDN         []string
	UnsafeDemoCerts bool
}

// readNodeConf reads conf/opensearch.yml (nested or flat keys).
func readNodeConf(confDir string) nodeConf {
	nc := nodeConf{HTTPPort: 9200, ReloadDNChecked: true}
	data, err := os.ReadFile(filepath.Join(confDir, "opensearch.yml"))
	if err != nil {
		return nc
	}
	nc.Read = true
	var raw map[string]any
	if yaml.Unmarshal(data, &raw) != nil {
		return nc
	}
	flat := map[string]any{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		if m, ok := v.(map[string]any); ok {
			for k, x := range m {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, x)
			}
			return
		}
		flat[prefix] = v
	}
	walk("", raw)
	str := func(k string) string {
		if v, ok := flat[k]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}
	list := func(k string) []string {
		switch v := flat[k].(type) {
		case []any:
			var out []string
			for _, x := range v {
				out = append(out, fmt.Sprint(x))
			}
			return out
		case string:
			return strings.Split(v, ",")
		}
		return nil
	}
	if p := str("http.port"); p != "" {
		if n, err := strconv.Atoi(strings.SplitN(p, "-", 2)[0]); err == nil {
			nc.HTTPPort = n
		}
	}
	nc.HTTPHost = cmpOr(str("http.host"), str("network.host"))
	nc.TransportHost = cmpOr(str("transport.host"), str("network.host"))
	nc.PathRepo, nc.PathData = list("path.repo"), list("path.data")
	nc.SecurityOff = str("plugins.security.disabled") == "true"
	nc.RestAPIRoles = list("plugins.security.restapi.roles_enabled")
	nc.HTTPTLS = str("plugins.security.ssl.http.enabled") == "true"
	nc.HotReload = str("plugins.security.ssl.certificates_hot_reload.enabled") == "true"
	nc.ReloadDNChecked = str("plugins.security.ssl.http.enforce_cert_reload_dn_verification") != "false"
	nc.AdminDN = list("plugins.security.authcz.admin_dn")
	nc.UnsafeDemoCerts = str("plugins.security.allow_unsafe_democertificates") == "true"
	return nc
}

var confArgRE = regexp.MustCompile(`^-Dopensearch\.path\.(conf|home)=(.+)$`)

// findServers lists the running OpenSearch servers (not the agent's own
// temporary ones).
func findServers() []serverProc {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	var out []serverProc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(procRoot, e.Name(), "cmdline"))
		if err != nil || !bytes.Contains(raw, []byte("org.opensearch.bootstrap.OpenSearch")) {
			continue
		}
		p := serverProc{PID: pid, ConfDir: defaultConf, Home: defaultHome}
		for _, a := range strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00") {
			if m := confArgRE.FindStringSubmatch(a); m != nil {
				if m[1] == "conf" {
					p.ConfDir = m[2]
				} else {
					p.Home = m[2]
				}
			}
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(p.ConfDir), scratchMarker)); err == nil {
			continue // the agent's own temporary server
		}
		p.Conf = readNodeConf(p.ConfDir)
		p.Port = p.Conf.HTTPPort
		p.Unit, p.User = unitOf(pid), procUser(pid)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b serverProc) int { return a.Port - b.Port })
	return out
}

// unitOf is the systemd unit running pid ("" when unknown).
func unitOf(pid int) string {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.LastIndex(line, "/"); i >= 0 && strings.HasSuffix(line, ".service") {
			return line[i+1:]
		}
	}
	return ""
}

// procUser is the OS user pid runs as ("" when unknown).
func procUser(pid int) string {
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(rest)
			if len(f) == 0 {
				return ""
			}
			if u, err := user.LookupId(f[0]); err == nil {
				return u.Username
			}
			return f[0]
		}
	}
	return ""
}

var jarRE = regexp.MustCompile(`^opensearch-(\d+\.\d+\.\d+)\.jar$`)

// installedVersion is the version of the OpenSearch program in home (from
// its jar's name), "" when unknown.
func installedVersion(home string) string {
	entries, err := os.ReadDir(filepath.Join(home, "lib"))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if m := jarRE.FindStringSubmatch(e.Name()); m != nil {
			return m[1]
		}
	}
	return ""
}

// Discover finds the OpenSearch servers on this host for the installer.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	procs := findServers()
	if len(procs) == 0 {
		return nil, nil
	}
	var out []agent.DiscoveredDatabase
	for _, p := range procs {
		d := agent.DiscoveredDatabase{Port: p.Port, Unit: p.Unit, Version: installedVersion(p.Home)}
		if len(p.Conf.PathData) > 0 {
			d.DataDir = p.Conf.PathData[0]
		}
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if c, err := connectPort(cctx, env, p.Port); err == nil {
			if in, err := inspect(cctx, c); err == nil {
				d.Version = in.Version
				d.SizeBytes = in.totalBytes()
				d.Databases = snapshotIndices(in)
				if why := in.supported(); why != "" {
					fmt.Fprintf(env.Notes, "OpenSearch on port %d: %s; skipped.\n", p.Port, why)
					cancel()
					continue
				}
			}
		}
		cancel()
		d.Major = versionNum(d.Version) / 10000
		out = append(out, d)
	}
	return out, nil
}
