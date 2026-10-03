package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// A scratch server is a redis-server (valkey-server) the agent starts on
// restored data, for a Proof, a Rewind copy or a rewind in place. It is
// isolated: no TCP port at all, only a Unix socket in a directory only the
// agent's user can enter; no persistence of its own (the agent saves it
// once, explicitly); a memory cap with noeviction, so it never takes more
// than the agent checked was free.

const scratchMarker = ".rowsafe-redis-scratch"

type scratch struct {
	Dir     string // data, log, pid file
	SockDir string // private socket directory (short path: sockets are limited to about 100 bytes)
	Bin     string
}

func (s scratch) dataDir() string { return filepath.Join(s.Dir, "data") }
func (s scratch) sock() string    { return filepath.Join(s.SockDir, "redis.sock") }
func (s scratch) pidFile() string { return filepath.Join(s.Dir, "redis.pid") }
func (s scratch) logFile() string { return filepath.Join(s.Dir, "redis.log") }
func (s scratch) rdbPath() string { return filepath.Join(s.dataDir(), "dump.rdb") }

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func sockDirFor(env agent.EngineEnv, dir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	return filepath.Join(env.StateDir, "s", hex.EncodeToString(sum[:6]))
}

// newScratch prepares root/id (refusing anything odd) with its marker.
func newScratch(env agent.EngineEnv, root, id string) (scratch, error) {
	if !idRE.MatchString(id) {
		return scratch{}, fmt.Errorf("invalid id %q", id)
	}
	root = filepath.Clean(root)
	dir := filepath.Join(root, id)
	s := scratch{Dir: dir, SockDir: sockDirFor(env, dir)}
	if _, err := os.Lstat(dir); err == nil {
		return s, fmt.Errorf("%s already exists", dir)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return s, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return s, err
	}
	if err := os.WriteFile(filepath.Join(dir, scratchMarker), []byte(id+"\n"), 0o600); err != nil {
		return s, err
	}
	if err := os.MkdirAll(s.dataDir(), 0o700); err != nil {
		return s, err
	}
	if err := os.MkdirAll(s.SockDir, 0o700); err != nil {
		return s, err
	}
	return s, os.Chmod(s.SockDir, 0o700)
}

// scratchAt is an existing scratch directory.
func scratchAt(env agent.EngineEnv, dir string) scratch {
	return scratch{Dir: filepath.Clean(dir), SockDir: sockDirFor(env, dir)}
}

// serverBinary finds the program for temporary servers of engine:
// ROWSAFE_REDIS_SERVER_BIN, the production server's own (INFO executable,
// when this agent can run it), then redis-server or valkey-server on the
// PATH and in the usual places.
func serverBinary(engine, executable string) (string, error) {
	if p := strings.TrimSpace(os.Getenv("ROWSAFE_REDIS_SERVER_BIN")); p != "" {
		return p, nil
	}
	name := "redis-server"
	if engine == protocol.EngineValkey {
		name = "valkey-server"
	}
	var try []string
	if executable != "" && filepath.IsAbs(executable) && !inDocker() {
		try = append(try, executable)
	}
	if p, err := exec.LookPath(name); err == nil {
		try = append(try, p)
	}
	try = append(try, "/usr/bin/"+name, "/usr/local/bin/"+name, "/opt/"+strings.TrimSuffix(name, "-server")+"/bin/"+name)
	for _, p := range try {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			if e, _, err := binaryVersion(p); err == nil && e == engine {
				return p, nil
			}
		}
	}
	return "", fmt.Errorf("%s (the %s server program) isn't on this server, so restores can't be tested or copied here", name, protocol.EngineDisplayName(engine))
}

var binVersionRE = regexp.MustCompile(`(?i)^(redis|valkey) server v=(\d+\.\d+\.\d+)`)

// binaryVersion runs `<bin> --version`.
func binaryVersion(bin string) (engine string, version int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return "", 0, err
	}
	m := binVersionRE.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		return "", 0, fmt.Errorf("%s --version: unexpected %q", bin, firstLine(string(out)))
	}
	return strings.ToLower(m[1]), versionNum(m[2]), nil
}

// checkBinary makes sure bin can load a snapshot of version want.
func checkBinary(bin, engine string, want int) error {
	e, v, err := binaryVersion(bin)
	if err != nil {
		return err
	}
	if e != engine {
		return fmt.Errorf("%s is a %s server, not %s", bin, protocol.EngineDisplayName(e), protocol.EngineDisplayName(engine))
	}
	if want > 0 && v/100 < want/100 {
		return fmt.Errorf("the %s program here (%s) is older than the server the backup comes from (%s), so it can't read it: "+
			"in Docker, use the agent image for %s %s", protocol.EngineDisplayName(engine), majorMinor(v), majorMinor(want),
			protocol.EngineDisplayName(engine), majorMinor(want))
	}
	return nil
}

// scratchOpts shape a scratch server.
type scratchOpts struct {
	MaxMemory int64
	Databases int
	Modules   [][]string // path and arguments of each module to load
}

// start runs the server on the scratch data (it loads dump.rdb if there is
// one) and waits until it answers.
func (s scratch) start(ctx context.Context, env agent.EngineEnv, o scratchOpts) (*conn, error) {
	if s.Bin == "" {
		return nil, errors.New("no server program for the temporary server")
	}
	if err := os.MkdirAll(s.SockDir, 0o700); err != nil {
		return nil, err
	}
	_ = os.Remove(s.sock())
	args := []string{
		"--port", "0", "--unixsocket", s.sock(), "--unixsocketperm", "700",
		"--dir", s.dataDir(), "--dbfilename", "dump.rdb", "--save", "", "--appendonly", "no",
		"--daemonize", "yes", "--pidfile", s.pidFile(), "--logfile", s.logFile(), "--loglevel", "warning",
		"--maxmemory-policy", "noeviction", "--protected-mode", "yes",
	}
	if o.MaxMemory > 0 {
		args = append(args, "--maxmemory", strconv.FormatInt(o.MaxMemory, 10))
	}
	if o.Databases > 0 {
		args = append(args, "--databases", strconv.Itoa(o.Databases))
	}
	for _, m := range o.Modules {
		args = append(args, "--loadmodule")
		args = append(args, m...)
	}
	if err := s.writeConf(o); err != nil {
		return nil, err
	}
	cmd := command(ctx, env, true, s.Bin, args...)
	cmd.Dir = s.Dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("starting a temporary %s server failed: %v: %s (log: %s)", filepath.Base(s.Bin), err, firstLine(string(out)), s.logTail())
	}
	size := int64(0)
	if st, err := os.Stat(s.rdbPath()); err == nil {
		size = st.Size()
	}
	deadline := time.Now().Add(2*time.Minute + time.Duration(size/(20<<20))*time.Second)
	for {
		c, err := dial(ctx, s.sock())
		if err == nil {
			err = waitReady(ctx, c, time.Until(deadline))
			if err == nil {
				return c, nil
			}
			c.Close()
		}
		if time.Now().After(deadline) || ctx.Err() != nil || (s.pid() == 0 && time.Since(deadline.Add(-2*time.Minute)) > 5*time.Second) {
			return nil, fmt.Errorf("the temporary server didn't answer: %v (log: %s)", err, s.logTail())
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// writeConf keeps the start options next to the data, for a restart after
// an agent restart (copies).
func (s scratch) writeConf(o scratchOpts) error {
	return saveJSONFile(filepath.Join(s.Dir, "scratch.json"), struct {
		Bin  string      `json:"bin"`
		Opts scratchOpts `json:"opts"`
	}{s.Bin, o})
}

// restart starts a stopped scratch server again with its saved options.
func (s scratch) restart(ctx context.Context, env agent.EngineEnv) (*conn, error) {
	var saved struct {
		Bin  string      `json:"bin"`
		Opts scratchOpts `json:"opts"`
	}
	if err := loadJSONFile(filepath.Join(s.Dir, "scratch.json"), &saved); err != nil {
		return nil, err
	}
	s.Bin = saved.Bin
	return s.start(ctx, env, saved.Opts)
}

// connect opens a connection to a running scratch server.
func (s scratch) connect(ctx context.Context) (*conn, error) {
	c, err := dial(ctx, s.sock())
	if err != nil {
		return nil, err
	}
	if err := waitReady(ctx, c, time.Minute); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func (s scratch) logTail() string {
	data, err := os.ReadFile(s.logFile())
	if err != nil || len(data) == 0 {
		return "no log"
	}
	return lastLine(string(data))
}

// pid is the scratch server's process, 0 when none runs on this directory.
func (s scratch) pid() int {
	data, err := os.ReadFile(s.pidFile())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0
	}
	if syscall.Kill(pid, 0) != nil {
		return 0
	}
	if cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline")); err == nil {
		// Redis rewrites its title to "redis-server unixsocket:<path>".
		if !strings.Contains(string(cmdline), s.SockDir) && !strings.Contains(string(cmdline), "-server") {
			return 0 // the pid was reused
		}
	}
	return pid
}

// stop shuts the scratch server down (SHUTDOWN NOSAVE, then signals).
func (s scratch) stop() error {
	pid := s.pid()
	if pid == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if c, err := dial(ctx, s.sock()); err == nil {
		_, _ = c.do(ctx, "SHUTDOWN", "NOSAVE")
		c.Close()
	} else {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	for range 60 {
		if s.pid() == 0 {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)
	if s.pid() != 0 {
		return fmt.Errorf("the temporary server (pid %d) didn't stop", pid)
	}
	return nil
}

// remove stops the server and deletes the directory (only one with the
// marker) and its socket directory. It returns the bytes freed.
func (s scratch) remove() (int64, error) {
	if err := s.stop(); err != nil {
		return 0, err
	}
	if _, err := os.Lstat(filepath.Join(s.Dir, scratchMarker)); err != nil {
		if notExist(err) {
			if _, err2 := os.Lstat(s.Dir); notExist(err2) {
				_ = os.RemoveAll(s.SockDir)
				return 0, nil
			}
		}
		return 0, fmt.Errorf("%s isn't a Rowsafe scratch directory; left alone", s.Dir)
	}
	size := dirSize(s.Dir)
	if err := os.RemoveAll(s.Dir); err != nil {
		return 0, err
	}
	_ = os.RemoveAll(s.SockDir)
	return size, nil
}

// command builds a command, at low CPU and IO priority when low.
func command(ctx context.Context, env agent.EngineEnv, low bool, name string, args ...string) *exec.Cmd {
	if low && len(env.LowPriority) > 0 {
		full := append(append(append([]string{}, env.LowPriority[1:]...), name), args...)
		return exec.CommandContext(ctx, env.LowPriority[0], full...)
	}
	return exec.CommandContext(ctx, name, args...)
}

// productionModules lists the modules production loaded (MODULE LIST:
// path and arguments), so a temporary server can read their data types.
func productionModules(ctx context.Context, c *conn) [][]string {
	v, err := c.do(ctx, "MODULE", "LIST")
	if err != nil {
		return nil
	}
	var out [][]string
	for _, m := range asArray(v) {
		f := asArray(m)
		var path string
		var args []string
		for i := 0; i+1 < len(f); i += 2 {
			switch asString(f[i]) {
			case "path":
				path = asString(f[i+1])
			case "args":
				for _, a := range asArray(f[i+1]) {
					args = append(args, asString(a))
				}
			}
		}
		if path == "" {
			continue
		}
		out = append(out, append([]string{path}, args...))
	}
	return out
}

// localModules keeps the modules whose file this agent can read here.
func localModules(mods [][]string) (ok [][]string, missing []string) {
	for _, m := range mods {
		if fh, err := os.Open(m[0]); err == nil {
			fh.Close()
			ok = append(ok, m)
		} else {
			missing = append(missing, filepath.Base(m[0]))
		}
	}
	return ok, missing
}
