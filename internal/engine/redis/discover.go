package redis

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// serverProc is a running redis-server or valkey-server found in /proc.
type serverProc struct {
	PID    int
	Port   int
	Engine string // from the program's name
	Unit   string
	Exe    string
}

// procRoot is where /proc is (tests change it).
var procRoot = "/proc"

// findServers lists the running servers of every engine: Redis rewrites
// its process title to "redis-server 127.0.0.1:6379".
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
		p, ok := parseTitle(string(raw))
		if !ok {
			continue
		}
		p.PID = pid
		if exe, err := os.Readlink(filepath.Join(procRoot, e.Name(), "exe")); err == nil {
			p.Exe = exe
			if strings.HasPrefix(filepath.Base(exe), "valkey") {
				p.Engine = protocol.EngineValkey
			}
		}
		p.Unit = unitOf(pid)
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b serverProc) int { return a.Port - b.Port })
	return out
}

// parseTitle reads a server's process title (or command line).
func parseTitle(raw string) (serverProc, bool) {
	f := strings.Fields(strings.ReplaceAll(raw, "\x00", " "))
	if len(f) == 0 {
		return serverProc{}, false
	}
	var p serverProc
	switch base := filepath.Base(f[0]); base {
	case "redis-server":
		p.Engine = protocol.EngineRedis
	case "valkey-server":
		p.Engine = protocol.EngineValkey
	default:
		return p, false
	}
	p.Port = 6379
	for _, a := range f[1:] {
		if strings.HasPrefix(a, "unixsocket:") {
			p.Port = 0
			continue
		}
		if i := strings.LastIndex(a, ":"); i >= 0 {
			if n, err := strconv.Atoi(strings.Trim(a[i+1:], "[]")); err == nil {
				p.Port = n
				break
			}
		}
		if a == "--port" {
			continue
		}
		if n, err := strconv.Atoi(a); err == nil && n > 0 && n < 65536 {
			p.Port = n
		}
	}
	return p, p.Port > 0
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

// probe asks the server on port who it is: with the saved login, else
// without one (a server whose default user needs no password).
func probe(ctx context.Context, env agent.EngineEnv, port int) (in serverInfo, login string, err error) {
	l, ok, err := loadLogin(env, port)
	if err != nil {
		return in, "missing", err
	}
	addr := addrOf(l, port)
	c, err := dial(ctx, addr)
	if err != nil {
		return in, "missing", plainConnError(err)
	}
	defer c.Close()
	login = "missing"
	if ok {
		if _, err := c.do(ctx, "AUTH", l.User, l.Password); err != nil {
			login = "refused"
		} else {
			login = "ok"
		}
	}
	m, err := c.info(ctx, "server", "memory", "replication", "keyspace", "cluster", "persistence")
	if err != nil {
		if isRespError(err, "NOAUTH", "NOPERM") {
			return in, login, nil // something answers; who it is needs a login
		}
		return in, login, err
	}
	in = infoFrom(m)
	return in, login, nil
}

// Discover finds the engine's servers on this host for the installer.
func (e *Engine) Discover(ctx context.Context, env agent.EngineEnv) ([]agent.DiscoveredDatabase, error) {
	procs := findServers()
	if len(procs) == 0 && inDocker() {
		port := 6379
		if v, err := strconv.Atoi(os.Getenv("ROWSAFE_REDIS_PORT")); err == nil && v > 0 {
			port = v
		}
		procs = []serverProc{{Port: port}}
	}
	var out []agent.DiscoveredDatabase
	seen := map[int]bool{}
	for _, p := range procs {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		in, _, err := probe(cctx, env, p.Port)
		cancel()
		if err != nil {
			if p.PID != 0 && (p.Engine == e.name || p.Engine == "") {
				fmt.Fprintf(env.Notes, "%s on port %d: %s; skipped.\n", e.display(), p.Port, firstLine(err.Error()))
			}
			continue
		}
		engine := cmpOr(in.Engine, p.Engine)
		if in.Version == "" && p.Engine == "" {
			engine = protocol.EngineRedis
		}
		if engine != e.name {
			continue
		}
		d := agent.DiscoveredDatabase{Port: p.Port, Unit: p.Unit, Version: in.Version, DataDir: in.Dir, SizeBytes: in.UsedMemoryDataset}
		if d.Version == "" && p.Exe != "" {
			if _, v, err := binaryVersion(p.Exe); err == nil {
				d.Version = fmt.Sprintf("%d.%d.%d", v/10000, v/100%100, v%100)
			}
		}
		d.Major = versionNum(d.Version) / 10000
		for _, db := range in.dbInfos() {
			d.Databases = append(d.Databases, db.Name)
		}
		if in.Version != "" {
			if why := in.supported(e.name); why != "" {
				fmt.Fprintf(env.Notes, "%s on port %d: %s; skipped.\n", e.display(), p.Port, why)
				continue
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// Status is what `rowsafe-agent redis status` prints for the installer.
type Status struct {
	Port       int
	Engine     string
	Version    string
	Login      string // ok, missing, refused
	User       string
	Unit       string
	Binary     string // the program temporary servers run ("" when none)
	ConfigFile string
	ACLFile    string
	Dir        string
	DBFilename string
	Docker     bool
	Cluster    bool
	Role       string
	NeedsAuth  bool // the default user needs a password
	// LogFile is the server's log file (logfile, made absolute against
	// dir); "" when it logs to its standard output.
	LogFile string
}

// ServerStatus describes the server on port (nothing answering: error).
func ServerStatus(ctx context.Context, env agent.EngineEnv, port int) (Status, error) {
	st := Status{Port: port, Docker: inDocker()}
	in, login, err := probe(ctx, env, port)
	if err != nil {
		return st, err
	}
	st.Login, st.Engine, st.Version, st.Cluster, st.Role = login, in.Engine, in.Version, in.Cluster, in.Role
	st.NeedsAuth = in.Version == ""
	if l, ok, _ := loadLogin(env, port); ok {
		st.User = l.User
	}
	for _, p := range findServers() {
		if p.Port == port {
			st.Unit = p.Unit
			if st.Engine == "" {
				st.Engine = p.Engine
			}
		}
	}
	if login == "ok" {
		if c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: port}); err == nil {
			if full, err := inspect(ctx, c); err == nil {
				st.ConfigFile, st.ACLFile, st.Dir, st.DBFilename = full.ConfigFile, full.ACLFile, full.Dir, full.DBFilename
				if st.Engine == "" {
					st.Engine = full.Engine
				}
				st.Binary, _ = serverBinary(full.Engine, full.Executable)
			}
			if lf, err := c.configGet(ctx, "logfile"); err == nil && lf != "" {
				if !filepath.IsAbs(lf) && st.Dir != "" {
					lf = filepath.Join(st.Dir, lf)
				}
				st.LogFile = lf
			}
			c.Close()
		}
	}
	if st.Binary == "" && st.Engine != "" {
		st.Binary, _ = serverBinary(st.Engine, "")
	}
	return st, nil
}

// Print prints the status as key=value lines ("-" when empty).
func (s Status) Print(w io.Writer) {
	dash := func(v string) string {
		if v == "" {
			return "-"
		}
		return v
	}
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Fprintf(w, "port=%d\nengine=%s\nversion=%s\nlogin=%s\nuser=%s\nunit=%s\nbinary=%s\nconfig=%s\naclfile=%s\ndatadir=%s\ndbfilename=%s\ndocker=%s\ncluster=%s\nrole=%s\nneeds_auth=%s\n",
		s.Port, dash(s.Engine), dash(s.Version), dash(s.Login), dash(s.User), dash(s.Unit), dash(s.Binary), dash(s.ConfigFile),
		dash(s.ACLFile), dash(s.Dir), dash(s.DBFilename), yn(s.Docker), yn(s.Cluster), dash(s.Role), yn(s.NeedsAuth))
	fmt.Fprintf(w, "logfile=%s\n", dash(s.LogFile))
}
