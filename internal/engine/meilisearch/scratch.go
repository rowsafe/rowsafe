package meilisearch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
)

// A scratch instance is a Meilisearch the agent starts from a snapshot,
// for a Proof, a Rewind copy or a rewind in place, with the server's own
// program. It is isolated: 127.0.0.1 only, its own folder that only the
// agent's user can enter, a master key of its own (random, kept in that
// folder), no analytics, a small indexing memory, and outgoing requests
// only to this server (a rewind in place exports from it to production).

const scratchMarker = ".rowsafe-meilisearch-scratch"

type scratch struct {
	Dir  string // the instance's folder
	Bin  string
	Port int
	Key  string // its master key
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	out  *tailBuffer
}

func (s *scratch) dbPath() string       { return filepath.Join(s.Dir, "data.ms") }
func (s *scratch) snapshotPath() string { return filepath.Join(s.Dir, "restore.snapshot") }
func (s *scratch) keyFile() string      { return filepath.Join(s.Dir, "master-key") }
func (s *scratch) pidFile() string      { return filepath.Join(s.Dir, "meilisearch.pid") }

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// newScratch prepares root/id (refusing anything odd) with its marker and
// master key.
func newScratch(root, id, bin string) (*scratch, error) {
	if !idRE.MatchString(id) {
		return nil, fmt.Errorf("invalid id %q", id)
	}
	bin, err := trustedProgram(bin)
	if err != nil {
		return nil, err
	}
	root = filepath.Clean(root)
	dir := filepath.Join(root, id)
	if _, err := os.Lstat(dir); err == nil {
		return nil, fmt.Errorf("%s already exists", dir)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	s := &scratch{Dir: dir, Bin: bin, Key: randomHex(24)}
	if err := os.WriteFile(filepath.Join(dir, scratchMarker), []byte(id+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.keyFile(), []byte(s.Key), 0o600); err != nil {
		return nil, err
	}
	return s, nil
}

// scratchAt is an existing scratch folder (an agent restart).
func scratchAt(dir, bin string) (*scratch, error) {
	if _, err := os.Stat(filepath.Join(dir, scratchMarker)); err != nil {
		return nil, fmt.Errorf("%s isn't one of Rowsafe's temporary instances", dir)
	}
	key, err := os.ReadFile(filepath.Join(dir, "master-key"))
	if err != nil {
		return nil, err
	}
	bin, err = trustedProgram(bin)
	if err != nil {
		return nil, err
	}
	return &scratch{Dir: dir, Bin: bin, Key: string(key)}, nil
}

// remove deletes the folder (only one of Rowsafe's: it has the marker).
func (s *scratch) remove() error {
	if _, err := os.Stat(filepath.Join(s.Dir, scratchMarker)); err != nil {
		if notExist(err) {
			if _, derr := os.Stat(s.Dir); notExist(derr) {
				return nil
			}
		}
		return fmt.Errorf("refusing to delete %s: it isn't one of Rowsafe's temporary instances", s.Dir)
	}
	return os.RemoveAll(s.Dir)
}

// freePort is a TCP port free on 127.0.0.1 now. Another user could take it
// before the temporary Meilisearch does: its client checks that the agent's
// own user listens there before every connection (scratchCheck).
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startOptions say how a scratch instance starts.
type startOptions struct {
	// Import is the snapshot file to start from (first start only).
	Import string
	// Upgrade: the snapshot is from an older Meilisearch than the program
	// (--upgrade-db; never used on production).
	Upgrade bool
	// IndexingMemory caps its indexing memory (bytes, 0: 256 MiB).
	IndexingMemory int64
}

// start runs the instance on a free port and waits until it answers.
func (s *scratch) start(ctx context.Context, o startOptions) error {
	mem := o.IndexingMemory
	if mem <= 0 {
		mem = 256 << 20
	}
	for attempt := 0; ; attempt++ {
		port, err := freePort()
		if err != nil {
			return err
		}
		s.Port = port
		args := []string{
			"--db-path", s.dbPath(),
			"--http-addr", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			"--env", "production",
			"--no-analytics",
			"--snapshot-dir", filepath.Join(s.Dir, "snapshots"),
			"--dump-dir", filepath.Join(s.Dir, "dumps"),
			"--max-indexing-memory", strconv.FormatInt(mem, 10),
			"--max-indexing-threads", "1",
			// Exports go to this server only (rewinds in place).
			"--experimental-allowed-ip-networks", "127.0.0.1/32",
		}
		if o.Import != "" {
			if _, err := os.Stat(s.dbPath()); notExist(err) {
				args = append(args, "--import-snapshot", o.Import)
			}
		}
		if o.Upgrade {
			args = append(args, "--upgrade-db")
		}
		bin, err := trustedProgram(s.Bin) // checked again before each start
		if err != nil {
			return err
		}
		s.out = &tailBuffer{}
		cmd := exec.Command(bin, args...)
		cmd.Dir = s.Dir
		cmd.Env = append(minimalEnv(), "MEILI_MASTER_KEY="+s.Key, "HOME="+s.Dir)
		cmd.Stdout, cmd.Stderr = s.out, s.out
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} // stopped with the agent's unit (systemd stops the whole group)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("starting a temporary Meilisearch (%s): %w", s.Bin, err)
		}
		s.cmd, s.done = cmd, make(chan struct{})
		_ = os.WriteFile(s.pidFile(), []byte(strconv.Itoa(cmd.Process.Pid)), 0o600)
		go func() {
			s.err = cmd.Wait()
			close(s.done)
		}()
		err = s.waitReady(ctx, 10*time.Minute)
		if err == nil {
			return nil
		}
		s.stop()
		if attempt < 2 && isAddrInUse(s.out.String()) {
			continue
		}
		return err
	}
}

func isAddrInUse(out string) bool {
	return regexp.MustCompile(`(?i)address already in use`).MatchString(out)
}

// waitReady waits until the instance answers /health (an import can take
// a while: Meilisearch unpacks the snapshot first).
func (s *scratch) waitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	c := s.client()
	defer c.close()
	for {
		hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := c.health(hctx)
		cancel()
		if err == nil {
			return nil
		}
		select {
		case <-s.done:
			return fmt.Errorf("the temporary Meilisearch stopped: %s", lastLines(s.out.String(), 3))
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the temporary Meilisearch didn't answer within %s: %s", timeout, lastLines(s.out.String(), 3))
		}
	}
}

// client is a client for the instance with its master key.
func (s *scratch) client() *client { return newClient("http", s.Port, s.Key, scratchCheck) }

// stop stops the instance (SIGTERM, then SIGKILL after 20 seconds).
func (s *scratch) stop() {
	if s.cmd == nil || s.cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGTERM)
	select {
	case <-s.done:
	case <-time.After(20 * time.Second):
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		<-s.done
	}
	s.cmd = nil
	_ = os.Remove(s.pidFile())
}

// running reports whether the instance is up (started by this agent).
func (s *scratch) running() bool {
	if s.cmd == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

// killLeftover stops an instance a previous agent left running (its pid
// file, only when that process is Meilisearch in this folder).
func killLeftover(dir string) {
	data, err := os.ReadFile(filepath.Join(dir, "meilisearch.pid"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 1 {
		return
	}
	if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err != nil || filepath.Clean(cwd) != filepath.Clean(dir) {
		return
	}
	_ = syscall.Kill(-pid, syscall.SIGTERM)
	for range 100 {
		if syscall.Kill(pid, 0) != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = os.Remove(filepath.Join(dir, "meilisearch.pid"))
}

// download fetches a snapshot from the bucket into path (decrypted: the
// tar.gz Meilisearch wrote).
func download(ctx context.Context, r *repo, label, path string) (int64, error) {
	src, closer, err := r.getSealed(ctx, backupKey(label, snapshotName))
	if err != nil {
		return 0, fmt.Errorf("downloading snapshot %s: %w", label, err)
	}
	defer closer.Close()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, src)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return n, fmt.Errorf("downloading snapshot %s: %w", label, err)
	}
	return n, nil
}

// restoreScratch downloads doc's snapshot into a new scratch instance under
// root/id and starts it.
func restoreScratch(ctx context.Context, env agent.EngineEnv, r *repo, s server, doc backupDoc, root, id string, tl agent.TaskLogger) (*scratch, error) {
	if s.Binary == "" {
		return nil, errors.New("Rowsafe doesn't know where the Meilisearch program is: run the Rowsafe installer on the server again")
	}
	progVersion, err := binaryVersion(s.Binary)
	if err != nil {
		return nil, err
	}
	// About the snapshot twice over (the file, then the unpacked indexes)
	// and some room.
	need := doc.SnapshotBytes + 3*max(doc.DatabaseBytes, doc.SnapshotBytes) + 256<<20
	if err := ensureSpace(root, need, "a temporary Meilisearch"); err != nil {
		return nil, err
	}
	sc, err := newScratch(root, id, s.Binary)
	if err != nil {
		return nil, err
	}
	tl.Printf("downloading snapshot %s (%s) and decrypting it on this server", doc.Label, humanBytes(doc.SnapshotBytes))
	if _, err := download(ctx, r, doc.Label, sc.snapshotPath()); err != nil {
		_ = sc.remove()
		return nil, err
	}
	upgrade := doc.Version != "" && progVersion != "" && versionNum(doc.Version) < versionNum(progVersion)
	if upgrade {
		tl.Printf("the snapshot is from Meilisearch %s and this server runs %s: the temporary instance upgrades it as it opens", doc.Version, progVersion)
	} else if doc.Version != "" && progVersion != "" && versionNum(doc.Version) > versionNum(progVersion) {
		_ = sc.remove()
		return nil, fmt.Errorf("the snapshot is from Meilisearch %s, newer than the program on this server (%s), which can't open it", doc.Version, progVersion)
	}
	tl.Printf("starting a temporary Meilisearch %s on 127.0.0.1 from it", progVersion)
	if err := sc.start(ctx, startOptions{Import: sc.snapshotPath(), Upgrade: upgrade}); err != nil {
		_ = sc.remove()
		return nil, err
	}
	_ = os.Remove(sc.snapshotPath()) // unpacked into data.ms
	return sc, nil
}

var binVersionRE = regexp.MustCompile(`(?m)^meilisearch (\d+\.\d+\.\d+)`)

// binaryVersion runs `<bin> --version` (a program root owns, with a
// minimal environment).
func binaryVersion(bin string) (string, error) {
	real, err := trustedProgram(bin)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, real, "--version")
	cmd.Env, cmd.Dir = minimalEnv(), "/"
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("the Meilisearch program %s doesn't run for Rowsafe's user (%v): run the Rowsafe installer on the server again", bin, err)
	}
	m := binVersionRE.FindStringSubmatch(string(out))
	if m == nil {
		return "", fmt.Errorf("%s --version: unexpected %q", bin, firstLine(string(out)))
	}
	return m[1], nil
}
