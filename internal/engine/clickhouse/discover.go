package clickhouse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// serverProc is a running clickhouse-server found in /proc.
type serverProc struct {
	PID        int
	Port       int // HTTP port
	ConfigFile string
	DataDir    string
	UsersD     string
	Unit       string
	User       string // OS user it runs as
}

// procRoot is where /proc is (tests change it).
var procRoot = "/proc"

const defaultConfig = "/etc/clickhouse-server/config.xml"

// findServers lists the running clickhouse-server processes and what their
// command line and configuration say.
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
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		var rest []string
		switch base := filepath.Base(args[0]); {
		case base == "clickhouse-server":
			rest = args[1:]
		case base == "clickhouse" && len(args) > 1 && args[1] == "server":
			rest = args[2:]
		default:
			continue
		}
		p := serverProc{PID: pid, ConfigFile: configArg(rest)}
		if p.ConfigFile == "" {
			p.ConfigFile = defaultConfig
		}
		// The agent's own temporary servers.
		if fileExists(filepath.Join(filepath.Dir(p.ConfigFile), scratchMarker)) {
			continue
		}
		conf := readServerConfig(p.ConfigFile)
		p.Port, p.DataDir, p.UsersD = conf.HTTPPort, conf.Path, conf.UsersD
		if p.Port == 0 {
			p.Port = 8123
		}
		p.Unit = unitOf(pid)
		p.User = procUser(pid)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b serverProc) int { return a.Port - b.Port })
	return out
}

func fileExists(p string) bool { _, err := os.Lstat(p); return err == nil }

// configArg finds --config-file (--config, -C) on a server command line.
func configArg(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, f := range []string{"--config-file", "--config", "-C"} {
			if v, ok := strings.CutPrefix(a, f+"="); ok {
				return v
			}
			if a == f && i+1 < len(args) {
				return args[i+1]
			}
			if f == "-C" && strings.HasPrefix(a, "-C") && len(a) > 2 && !strings.HasPrefix(a, "--") {
				return a[2:]
			}
		}
	}
	return ""
}

// serverConfig is what Rowsafe reads from a server's configuration.
type serverConfig struct {
	HTTPPort int
	Path     string
	UsersD   string
}

// readServerConfig reads config.xml (or .yaml) and then config.d/*, later
// files overriding earlier ones, like ClickHouse merges them.
func readServerConfig(path string) serverConfig {
	var c serverConfig
	usersConfig := "users.xml"
	files := []string{path}
	dir := filepath.Dir(path)
	for _, pat := range []string{"*.xml", "*.yaml", "*.yml"} {
		m, _ := filepath.Glob(filepath.Join(dir, "config.d", pat))
		files = append(files, m...)
	}
	slices.Sort(files[1:])
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var vals map[string]string
		if strings.HasSuffix(f, ".xml") {
			vals = topLevelXML(data)
		} else {
			vals = topLevelYAML(data)
		}
		if v := vals["http_port"]; v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				c.HTTPPort = n
			}
		}
		if v := vals["path"]; v != "" {
			c.Path = v
		}
		if v := vals["users_config"]; v != "" {
			usersConfig = v
		}
	}
	if !filepath.IsAbs(usersConfig) {
		usersConfig = filepath.Join(dir, usersConfig)
	}
	c.UsersD = filepath.Join(filepath.Dir(usersConfig), "users.d")
	return c
}

// topLevelXML reads the simple settings directly under the root element.
func topLevelXML(data []byte) map[string]string {
	out := map[string]string{}
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	depth := 0
	var cur string
	var text strings.Builder
	for {
		tok, err := d.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 {
				cur = t.Name.Local
				text.Reset()
			}
		case xml.CharData:
			if depth == 2 {
				text.Write(t)
			}
		case xml.EndElement:
			if depth == 2 && cur != "" {
				if v := strings.TrimSpace(text.String()); v != "" {
					out[cur] = v
				}
			}
			depth--
		}
	}
}

// topLevelYAML reads "key: value" lines that aren't indented.
func topLevelYAML(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if i := strings.Index(v, " #"); i >= 0 {
			v = v[:i]
		}
		if v = strings.Trim(strings.TrimSpace(v), `"'`); v != "" {
			out[strings.TrimSpace(k)] = v
		}
	}
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

var versionRE = regexp.MustCompile(`\(version (\d+\.\d+[\d.]*)`)

// serverVersion asks the server on port its version: with the login when
// there is one, else as "default" without a password, else from the
// version ClickHouse prints in its refusal.
func serverVersion(ctx context.Context, port int, l Login, haveLogin bool) (string, error) {
	try := []Login{{User: "default"}}
	if haveLogin {
		try = []Login{l}
	}
	var lastErr error
	for _, lg := range try {
		v, err := newClient(serverURL(port), lg).scalar(ctx, "SELECT version()", nil)
		if err == nil {
			return v, nil
		}
		if m := versionRE.FindStringSubmatch(err.Error()); m != nil {
			return m[1], nil
		}
		lastErr = err
	}
	return "", lastErr
}

// pingServer checks something answers ClickHouse's /ping (no login needed).
func pingServer(ctx context.Context, port int) error {
	c := newClient(serverURL(port), Login{})
	u := *c.base
	u.Path = "/ping"
	req, err := newGet(ctx, u.String())
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return plainConnError(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("port %d answered HTTP %d: is it ClickHouse's HTTP port?", port, resp.StatusCode)
	}
	return nil
}

// Discover finds the ClickHouse servers on this host for the installer.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	procs := findServers()
	if len(procs) == 0 {
		port := 8123
		if inDocker() {
			if u, err := url.Parse(os.Getenv(urlEnv)); err == nil && u.Port() != "" {
				port, _ = strconv.Atoi(u.Port())
			}
		}
		// Nothing in /proc we can see (another container): try the port.
		procs = []serverProc{{Port: port}}
	}
	var out []agent.DiscoveredDatabase
	seen := map[int]bool{}
	for _, p := range procs {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		if d, ok := describeServer(ctx, env, p); ok {
			out = append(out, d)
		}
	}
	return out, nil
}

func describeServer(ctx context.Context, env agent.EngineEnv, p serverProc) (agent.DiscoveredDatabase, bool) {
	d := agent.DiscoveredDatabase{Port: p.Port, DataDir: p.DataDir, Unit: p.Unit}
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := pingServer(cctx, p.Port); err != nil {
		if p.PID != 0 {
			fmt.Fprintf(env.Notes, "ClickHouse on port %d: %s; skipped.\n", p.Port, firstLine(err.Error()))
		}
		return d, false
	}
	l, ok, err := loadLogin(env, p.Port)
	if err != nil {
		fmt.Fprintf(env.Notes, "ClickHouse on port %d: %v; skipped.\n", p.Port, err)
		return d, false
	}
	d.Version, _ = serverVersion(cctx, p.Port, l, ok)
	d.Major = versionNum(d.Version) / 10000
	if ok {
		c := newClient(serverURL(p.Port), l)
		if in, err := inspect(cctx, c); err == nil {
			d.SizeBytes = in.TotalBytes
			if d.DataDir == "" {
				d.DataDir = in.DataPath
			}
			for _, db := range in.Databases {
				d.Databases = append(d.Databases, db.Name)
			}
		}
	}
	return d, true
}
