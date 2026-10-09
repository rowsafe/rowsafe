package qdrant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// A scratch server is a qdrant the agent starts on restored data, for a
// Proof, a Rewind copy or a rewind in place. It is isolated: it listens on
// 127.0.0.1 only, on free ports, behind a key only the agent knows, in a
// directory only the agent's user can enter; telemetry off, no web UI, low
// CPU and IO priority, and on Qdrant 1.19 and newer its data stays on disk
// (memory-mapped, low_memory_mode) so it never takes the memory production
// needs.

const scratchMarker = ".rowsafe-qdrant-scratch"

type scratch struct {
	Dir string
}

// scratchState is what is needed to start it again (after an agent
// restart) and to reach it.
type scratchState struct {
	Bin      string `json:"bin"`
	HTTPPort int    `json:"http_port"`
	Key      string `json:"key"`
	Version  int    `json:"version"`
}

func (s scratch) storageDir() string   { return filepath.Join(s.Dir, "storage") }
func (s scratch) configFile() string   { return filepath.Join(s.Dir, "config.yaml") }
func (s scratch) pidFile() string      { return filepath.Join(s.Dir, "qdrant.pid") }
func (s scratch) logFile() string      { return filepath.Join(s.Dir, "qdrant.log") }
func (s scratch) stateFile() string    { return filepath.Join(s.Dir, "scratch.json") }
func (s scratch) snapshotFile() string { return filepath.Join(s.Dir, "restore.snapshot") }

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// newScratch prepares root/id (refusing anything odd) with its marker.
func newScratch(root, id string) (scratch, error) {
	if !idRE.MatchString(id) {
		return scratch{}, fmt.Errorf("invalid id %q", id)
	}
	root = filepath.Clean(root)
	s := scratch{Dir: filepath.Join(root, id)}
	if _, err := os.Lstat(s.Dir); err == nil {
		return s, fmt.Errorf("%s already exists", s.Dir)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return s, err
	}
	if err := os.Mkdir(s.Dir, 0o700); err != nil {
		return s, err
	}
	if err := os.WriteFile(filepath.Join(s.Dir, scratchMarker), []byte(id+"\n"), 0o600); err != nil {
		return s, err
	}
	return s, nil
}

func scratchAt(dir string) scratch { return scratch{Dir: filepath.Clean(dir)} }

// binEnv names the qdrant program for temporary servers.
const binEnv = "ROWSAFE_QDRANT_BIN"

// serverBinary finds the qdrant program for temporary servers:
// ROWSAFE_QDRANT_BIN, then qdrant on the PATH and in the usual places (the
// Debian package's /usr/bin/qdrant; /qdrant/qdrant in Qdrant's image, which
// the Docker sidecar is built on).
func serverBinary() (string, error) {
	var try []string
	if p := strings.TrimSpace(os.Getenv(binEnv)); p != "" {
		try = append(try, p)
	}
	if p, err := exec.LookPath("qdrant"); err == nil {
		try = append(try, p)
	}
	try = append(try, "/usr/bin/qdrant", "/usr/local/bin/qdrant", "/qdrant/qdrant")
	for _, p := range try {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			if _, err := binaryVersion(p); err == nil {
				return p, nil
			}
		}
	}
	return "", errors.New("the qdrant program isn't on this server, so restores can't be tested or copied here " +
		"(Rowsafe uses it to start a private Qdrant on the restored data): install Qdrant's package, " +
		"or in Docker use the Rowsafe agent image for Qdrant")
}

var binVersionRE = regexp.MustCompile(`(?i)qdrant\s+v?(\d+\.\d+\.\d+)`)

// binaryVersion runs `<bin> --version` ("qdrant 1.19.2").
func binaryVersion(bin string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "--version").Output()
	if err != nil {
		return 0, err
	}
	m := binVersionRE.FindStringSubmatch(string(out))
	if m == nil {
		return 0, fmt.Errorf("%s --version: unexpected %q", bin, strings.TrimSpace(string(out)))
	}
	return parseVersion(m[1]), nil
}

func versionText(v int) string { return fmt.Sprintf("%d.%d.%d", v/10000, v/100%100, v%100) }

// checkBinary makes sure bin can load a snapshot of version want: Qdrant
// reads snapshots of its own and older versions.
func checkBinary(bin string, want int) (int, error) {
	v, err := binaryVersion(bin)
	if err != nil {
		return 0, err
	}
	if want > 0 && v/100 < want/100 {
		return v, fmt.Errorf("the qdrant program here (%s) is older than the server the backup comes from (%s), so it can't read it: "+
			"update Qdrant's package on this server, or in Docker use the agent image for Qdrant %d.%d",
			versionText(v), versionText(want), want/10000, want/100%100)
	}
	return v, nil
}

// freePort asks the system for a free TCP port on 127.0.0.1.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func randomKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// writeConfig writes the temporary server's settings.
func (s scratch) writeConfig(st scratchState) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# Rowsafe: a temporary Qdrant for a restore test, a Rewind copy or a rewind in place.\n")
	fmt.Fprintf(&b, "log_level: WARN\ntelemetry_disabled: true\n")
	// No temp_path: Qdrant 1.19 can't start from a storage snapshot with
	// one set (it unpacks into it and fails); its default is inside the
	// storage folder anyway.
	fmt.Fprintf(&b, "storage:\n  storage_path: %q\n  snapshots_path: %q\n",
		s.storageDir(), filepath.Join(s.Dir, "snapshots"))
	fmt.Fprintf(&b, "  performance:\n    max_search_threads: 1\n    optimizer_cpu_budget: 1\n")
	if st.Version >= 1_19_00 {
		fmt.Fprintf(&b, "  low_memory_mode: no_populate\n")
	}
	fmt.Fprintf(&b, "service:\n  host: 127.0.0.1\n  http_port: %d\n  grpc_port: null\n  enable_cors: false\n", st.HTTPPort)
	fmt.Fprintf(&b, "  max_workers: 1\n  enable_static_content: false\n  api_key: %q\n", st.Key)
	fmt.Fprintf(&b, "cluster:\n  enabled: false\n")
	return os.WriteFile(s.configFile(), []byte(b.String()), 0o600)
}

func (s scratch) saveState(st scratchState) error { return saveJSONFile(s.stateFile(), st) }

func (s scratch) loadState() (scratchState, error) {
	var st scratchState
	err := loadJSONFile(s.stateFile(), &st)
	return st, err
}

// start runs qdrant on the scratch directory: from the snapshot file in it
// (restore.snapshot) when there is one, else on the storage already there,
// and waits until it answers with the scratch's key.
func (s scratch) start(ctx context.Context, env agent.EngineEnv, st scratchState) (*client, error) {
	if st.Bin == "" {
		return nil, errors.New("no qdrant program for the temporary server")
	}
	if err := os.MkdirAll(s.storageDir(), 0o700); err != nil {
		return nil, err
	}
	if err := s.writeConfig(st); err != nil {
		return nil, err
	}
	if err := s.saveState(st); err != nil {
		return nil, err
	}
	args := []string{"--config-path", s.configFile(), "--disable-telemetry"}
	size := int64(0)
	if fi, err := os.Stat(s.snapshotFile()); err == nil {
		args = append(args, "--storage-snapshot", s.snapshotFile())
		size = fi.Size()
	}
	logf, err := os.OpenFile(s.logFile(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	name, full := st.Bin, args
	if len(env.LowPriority) > 0 {
		name = env.LowPriority[0]
		full = append(append(append([]string{}, env.LowPriority[1:]...), st.Bin), args...)
	}
	cmd := exec.Command(name, full...) //nolint:gosec // the program found by serverBinary, our own arguments
	cmd.Dir = s.Dir
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + s.Dir, "TMPDIR=" + filepath.Join(s.Dir, "tmp")}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	_ = os.MkdirAll(filepath.Join(s.Dir, "tmp"), 0o700)
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, fmt.Errorf("starting a temporary Qdrant failed: %w", err)
	}
	logf.Close()
	pid := cmd.Process.Pid
	exited := make(chan struct{})
	go func() { _ = cmd.Wait(); close(exited) }()
	if err := os.WriteFile(s.pidFile(), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	c, err := s.clientFor(st)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(2*time.Minute + time.Duration(size/(20<<20))*time.Second)
	for {
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := c.collectionNames(hctx)
		cancel()
		if err == nil {
			_ = os.Remove(s.snapshotFile()) // restored: its room goes back to the disk
			return c, nil
		}
		select {
		case <-exited:
			return nil, fmt.Errorf("the temporary Qdrant stopped while starting (log: %s)", s.logTail())
		case <-ctx.Done():
			_ = s.stop()
			return nil, ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = s.stop()
			return nil, fmt.Errorf("the temporary Qdrant didn't answer: %v (log: %s)", err, s.logTail())
		}
	}
}

// clientFor reaches the scratch server.
func (s scratch) clientFor(st scratchState) (*client, error) {
	return newClient(context.Background(), Login{Key: st.Key, URL: "http://127.0.0.1:" + strconv.Itoa(st.HTTPPort)}, st.HTTPPort)
}

// connect reaches a running scratch server.
func (s scratch) connect(ctx context.Context) (*client, error) {
	st, err := s.loadState()
	if err != nil {
		return nil, err
	}
	c, err := s.clientFor(st)
	if err != nil {
		return nil, err
	}
	if _, err := c.collectionNames(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// restart starts a stopped scratch server again on its storage.
func (s scratch) restart(ctx context.Context, env agent.EngineEnv) (*client, error) {
	st, err := s.loadState()
	if err != nil {
		return nil, err
	}
	if p, err := freePort(); err == nil {
		st.HTTPPort = p
	}
	return s.start(ctx, env, st)
}

func (s scratch) logTail() string {
	f, err := os.Open(s.logFile())
	if err != nil {
		return "no log"
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() > 4096 {
		_, _ = f.Seek(fi.Size()-4096, io.SeekStart)
	}
	data, _ := io.ReadAll(f)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if len(l) > 300 {
				l = l[:300]
			}
			return l
		}
	}
	return "no log"
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
		if !strings.Contains(string(cmdline), s.configFile()) {
			return 0 // the pid was reused
		}
	}
	return pid
}

// stop stops the scratch server (SIGTERM, then SIGKILL).
func (s scratch) stop() error {
	pid := s.pid()
	if pid == 0 {
		return nil
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	for range 120 {
		if s.pid() == 0 {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(500 * time.Millisecond)
	if s.pid() != 0 {
		return fmt.Errorf("the temporary Qdrant (pid %d) didn't stop", pid)
	}
	return nil
}

// remove stops the server and deletes the directory (only one with the
// marker). It returns the bytes freed.
func (s scratch) remove() (int64, error) {
	if err := s.stop(); err != nil {
		return 0, err
	}
	if _, err := os.Lstat(filepath.Join(s.Dir, scratchMarker)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if _, err2 := os.Lstat(s.Dir); errors.Is(err2, os.ErrNotExist) {
				return 0, nil
			}
		}
		return 0, fmt.Errorf("%s isn't a Rowsafe scratch directory; left alone", s.Dir)
	}
	freed := dirSize(s.Dir)
	if err := os.RemoveAll(s.Dir); err != nil {
		return 0, err
	}
	return freed, nil
}
