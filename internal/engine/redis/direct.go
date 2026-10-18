package redis

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Without the agent: a Redis or Valkey server reached with a connection
// string (rowsafe pulse redis://...). The reads are the agent's monitoring
// reads, taken once (rates such as evictions and the hit rate need two and
// are left out); the fixes and settings changes are the agent's own code,
// with its checks, on that connection. Backups need the agent on the
// server.

// Conn is a server reached with a connection string.
type Conn struct {
	// Addr is host:port, or a Unix socket's path.
	Addr           string
	User, Password string
	// TLS (rediss://): verified against ServerName unless Insecure.
	TLS      bool
	Insecure bool
	// Local: the server runs on this machine, so its data folder's disk
	// may be read here (when it is that server's).
	Local bool
}

// Reading is one reading of the server.
type Reading struct {
	protocol.DatabaseMonitoring
	CollectedAt time.Time
	// Engine is protocol.EngineRedis or EngineValkey, as the server says.
	Engine     string
	Version    string
	VersionNum int
	// Notes say what this connection couldn't read, in plain words.
	Notes []string
}

// ReadOptions says what a Reading includes besides the metrics and the
// health detail.
type ReadOptions struct {
	Settings bool
}

// directEnv is the agent's environment for code shared with it: no
// root's helper, no configuration file read here.
var directEnv = agent.EngineEnv{Config: agent.Config{Mode: agent.ModeDockerSidecar}}

// directConnect connects and signs in.
func directConnect(ctx context.Context, c Conn) (*conn, error) {
	network := "tcp"
	if strings.HasPrefix(c.Addr, "/") {
		network = "unix"
	}
	nc, err := dialer(ctx, network, c.Addr)
	if err != nil {
		return nil, directConnError(err)
	}
	if c.TLS {
		host, _, _ := net.SplitHostPort(c.Addr)
		tc := tls.Client(nc, &tls.Config{ServerName: host, InsecureSkipVerify: c.Insecure, MinVersion: tls.VersionTLS12}) //nolint:gosec // only when the string says so
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			nc.Close()
			return nil, fmt.Errorf("TLS: %w", err)
		}
		nc = tc
	}
	cn := newConn(nc)
	fail := func(err error) (*conn, error) { cn.Close(); return nil, directConnError(err) }
	switch {
	case c.User != "":
		if _, err := cn.do(ctx, "AUTH", c.User, c.Password); err != nil {
			return fail(err)
		}
	case c.Password != "":
		if _, err := cn.do(ctx, "AUTH", c.Password); err != nil {
			return fail(err)
		}
	}
	_, _ = cn.do(ctx, "CLIENT", "SETNAME", "rowsafe")
	if _, err := cn.do(ctx, "PING"); err != nil {
		return fail(err)
	}
	return cn, nil
}

// directConnError words errors for a connection string.
func directConnError(err error) error {
	s := err.Error()
	switch {
	case isRespError(err, "WRONGPASS") || strings.Contains(s, "invalid password") || strings.Contains(s, "invalid username-password"):
		return errors.New("the server refused the login (check the user and the password)")
	case isRespError(err, "NOAUTH"):
		return errors.New("the server needs a password: put it in the connection string (redis://:PASSWORD@host:6379) or REDISCLI_AUTH")
	case strings.Contains(s, "connection refused"):
		return errors.New("nothing answers there (is the server running?)")
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return fmt.Errorf("the server didn't answer in time (%s)", firstLine(s))
	case errors.Is(err, net.ErrClosed), strings.Contains(s, "EOF"), strings.Contains(s, "connection reset"):
		return fmt.Errorf("the server closed the connection (%s): if it only takes TLS, use rediss://", firstLine(s))
	}
	return err
}

// Read takes one reading.
func Read(ctx context.Context, c Conn, o ReadOptions) (*Reading, error) {
	cn, err := directConnect(ctx, c)
	if err != nil {
		return nil, err
	}
	defer cn.Close()
	now := time.Now()
	info, err := cn.info(ctx, "all")
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, cn)
	if err != nil {
		return nil, err
	}
	e := &Engine{name: in.Engine}
	out := &Reading{CollectedAt: now.UTC(), Engine: in.Engine, Version: in.Version, VersionNum: in.VersionNum}
	if _, err := cn.configGet(ctx, "maxclients"); err != nil {
		out.Notes = append(out.Notes, "This connection may not read the server's settings (CONFIG GET): the connection limit, memory policy and saving to disk are checked only in part.")
	}
	dm := &out.DatabaseMonitoring
	m := map[string]float64{}
	clients := float64(info.int("connected_clients"))
	m[collect.MConnTotal] = clients
	maxClients := int64(0)
	if v, err := cn.configGet(ctx, "maxclients"); err == nil {
		fmt.Sscan(v, &maxClients)
	}
	if maxClients > 0 {
		m[collect.MConnMax] = float64(maxClients)
		m[collect.MConnUsedPct] = 100 * clients / float64(maxClients)
	}
	m[collect.MRedisUsedMemoryBytes] = float64(in.UsedMemory)
	m[collect.MDatabaseSizeBytes] = float64(in.UsedMemoryDataset)
	if in.MaxMemory > 0 {
		m[collect.MRedisMemoryUsedPct] = 100 * float64(in.UsedMemory) / float64(in.MaxMemory)
	}
	m[collect.MRedisKeys] = float64(in.totalKeys())
	m[collect.MRedisBgsaveFailed] = boolMetric(info["rdb_last_bgsave_status"] != "" && info["rdb_last_bgsave_status"] != "ok")
	m[collect.MRedisAOFWriteFailed] = boolMetric(info["aof_enabled"] == "1" && info["aof_last_write_status"] != "" && info["aof_last_write_status"] != "ok")
	reps := replicas(info)
	if c.Local && in.Dir != "" && ownDataDir(in) {
		if total, free, err := diskUsage(in.Dir); err == nil && total > 0 {
			m[collect.MDiskTotalBytes], m[collect.MDiskFreeBytes] = float64(total), float64(free)
			m[collect.MDiskFreePct] = 100 * float64(free) / float64(total)
		}
	}
	dm.Metrics = m
	dm.Sizes = sizesOf(in)
	dm.Redis = e.status(ctx, protocol.DatabaseSpec{}, cn, info, in, reps, latencyEvents(ctx, cn), maxClients)
	if o.Settings {
		if snap, err := e.directSettings(ctx, cn, c.Local, in); err == nil {
			snap.CollectedAt = now.UTC()
			dm.Settings = snap
		}
	}
	return out, nil
}

// directSettings reads the settings as the agent does, with this server's
// memory: its own, from INFO, unless it runs on this machine.
func (e *Engine) directSettings(ctx context.Context, cn *conn, local bool, in serverInfo) (*protocol.SettingsSnapshot, error) {
	snap, err := e.settingsSnapshot(ctx, directEnv, cn)
	if err != nil {
		return nil, err
	}
	if !local {
		snap.Host = protocol.SettingsHost{MemoryBytes: in.TotalSystemMemory}
	}
	if f := snap.Redis; f != nil {
		f.Kept, f.LiveOnly = protocol.RedisKeptRewrite, ""
		if in.ConfigFile == "" {
			f.Kept, f.LiveOnly = "", fmt.Sprintf("Changes apply at once but last only until %s restarts: it was started without a configuration file. To keep a change, add it where %s is started.", e.display(), e.display())
		}
	}
	return snap, nil
}

// ownDataDir reports whether the server's data folder is on this machine
// (not a container's path that means something else here): its snapshot
// file or append-only folder is there.
func ownDataDir(in serverInfo) bool {
	if !filepath.IsAbs(in.Dir) {
		return false
	}
	for _, name := range []string{in.DBFilename, "dump.rdb", "appendonlydir", "appendonly.aof"} {
		if name == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(in.Dir, name)); err == nil {
			return true
		}
	}
	return false
}

// Server is who and what a connection reaches.
type Server struct {
	Engine, User, Version string
	// ConfigFile and ACLFile are the server's (as it says; "" for none or
	// when this user may not read them).
	ConfigFile, ACLFile string
}

// Check connects once and reads what the connection reaches, changing
// nothing.
func Check(ctx context.Context, c Conn) (Server, error) {
	cn, err := directConnect(ctx, c)
	if err != nil {
		return Server{}, err
	}
	defer cn.Close()
	info, err := cn.info(ctx, "server")
	if err != nil {
		return Server{}, err
	}
	engine, version := engineOf(info)
	out := Server{Engine: engine, Version: version, User: c.User, ConfigFile: info["config_file"]}
	if who, err := cn.str(ctx, "ACL", "WHOAMI"); err == nil {
		out.User = who
	}
	out.ACLFile, _ = cn.configGet(ctx, "aclfile")
	return out, nil
}

// Maintain runs a fix (protocol.MaintenanceParams) with the agent's
// checks. It returns the step-by-step log.
func Maintain(ctx context.Context, c Conn, p protocol.MaintenanceParams) (*protocol.MaintenanceResult, string, error) {
	cn, err := directConnect(ctx, c)
	if err != nil {
		return nil, "", err
	}
	defer cn.Close()
	info, err := cn.info(ctx, "server")
	if err != nil {
		return nil, "", err
	}
	engine, _ := engineOf(info)
	e := &Engine{name: engine}
	tl := &textLog{}
	start := time.Now()
	var summary string
	switch p.Action {
	case protocol.MaintRedisEvictionPolicy:
		summary, err = e.setEvictionPolicy(ctx, cn, p, tl)
	case protocol.MaintRedisMemoryPurge:
		summary, err = e.memoryPurge(ctx, cn, tl)
	case protocol.MaintRedisActiveDefrag:
		summary, err = e.activeDefrag(ctx, cn, tl)
	case protocol.MaintRedisKillClient:
		summary, err = e.killClient(ctx, cn, p, tl)
	case protocol.MaintRedisBacklog:
		summary, err = e.setBacklog(ctx, cn, p, tl)
	default:
		return nil, "", fmt.Errorf("%s isn't a %s fix", p.Action, e.display())
	}
	if err != nil {
		return nil, tl.String(), noPerm(err)
	}
	tl.Printf("%s", summary)
	return &protocol.MaintenanceResult{Action: p.Action, Summary: summary, DurationMs: time.Since(start).Milliseconds()}, tl.String(), nil
}

// ChangeSettings changes settings on the running server (CONFIG SET, all
// together or none) and asks it to keep them in its configuration file
// (CONFIG REWRITE). Nothing restarts.
func ChangeSettings(ctx context.Context, c Conn, p protocol.SettingsParams) (*protocol.SettingsResult, string, error) {
	cn, err := directConnect(ctx, c)
	if err != nil {
		return nil, "", err
	}
	defer cn.Close()
	info, err := cn.info(ctx, "server")
	if err != nil {
		return nil, "", err
	}
	engine, _ := engineOf(info)
	tl := &textLog{}
	res, err := (&Engine{name: engine}).settingsOn(ctx, directEnv, cn, p, tl)
	if res != nil && res.Snapshot != nil && !c.Local {
		res.Snapshot.Host = protocol.SettingsHost{MemoryBytes: res.Snapshot.Host.MemoryBytes}
	}
	return res, tl.String(), noPerm(err)
}

// noPerm words a refusal of the connection's user.
func noPerm(err error) error {
	if isRespError(err, "NOPERM") || err != nil && strings.Contains(err.Error(), "NOPERM") {
		return fmt.Errorf("this connection's user may not do that (%s): use one with the admin commands (+@admin), or let the Rowsafe agent on the server do it", firstLine(err.Error()))
	}
	return err
}

// textLog collects a fix's log lines.
type textLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *textLog) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(&l.buf, "%s ", time.Now().UTC().Format("15:04:05"))
	fmt.Fprintf(&l.buf, format, args...)
	l.buf.WriteByte('\n')
}

func (l *textLog) Output(label string, out []byte) {
	if len(out) > 0 {
		l.Printf("%s:\n%s", label, out)
	}
}

func (l *textLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}
