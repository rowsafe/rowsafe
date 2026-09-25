package mongodb

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// A scratch server is a mongod the agent starts on restored data (a Proof
// or a Rewind copy). It is isolated: it listens only on a Unix socket in a
// directory only the agent's user can enter (no TCP port at all), runs
// without replication, TTL deletions or diagnostics, and uses a small cache.

// scratchPort only names the socket file; nothing listens on TCP.
const scratchPort = 27017

// scratchMarker is written into every scratch directory first.
const scratchMarker = ".rowsafe-mongodb-scratch"

type scratch struct {
	Dir     string // the scratch directory (data, logs, oplog file)
	SockDir string // private socket directory (short path: sockets are limited to 107 bytes)
}

func (s scratch) dataDir() string { return filepath.Join(s.Dir, "data") }
func (s scratch) sock() string {
	return filepath.Join(s.SockDir, "mongodb-"+strconv.Itoa(scratchPort)+".sock")
}
func (s scratch) uri() string     { return socketURI(s.sock()) }
func (s scratch) pidFile() string { return filepath.Join(s.Dir, "mongod.pid") }
func (s scratch) logFile() string { return filepath.Join(s.Dir, "mongod.log") }

// newScratch prepares root/id (refusing anything odd) with its marker.
func newScratch(env agent.EngineEnv, root, id string) (scratch, error) {
	if !idRE.MatchString(id) {
		return scratch{}, fmt.Errorf("invalid id %q", id)
	}
	root = filepath.Clean(root)
	dir := filepath.Join(root, id)
	sum := sha256.Sum256([]byte(dir))
	s := scratch{Dir: dir, SockDir: filepath.Join(env.StateDir, "s", hex.EncodeToString(sum[:6]))}
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
	sum := sha256.Sum256([]byte(filepath.Clean(dir)))
	return scratch{Dir: filepath.Clean(dir), SockDir: filepath.Join(env.StateDir, "s", hex.EncodeToString(sum[:6]))}
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// start runs mongod on the scratch data and waits until it answers.
func (s scratch) start(ctx context.Context, env agent.EngineEnv) (*mongo.Client, error) {
	mongod, err := tool("mongod")
	if err != nil {
		return nil, errors.New("mongod (the MongoDB server) isn't installed on this server, so restores can't be tested here")
	}
	if err := os.MkdirAll(s.SockDir, 0o700); err != nil {
		return nil, err
	}
	args := []string{
		"--dbpath", s.dataDir(),
		"--bind_ip", s.sock(), "--unixSocketPrefix", s.SockDir, "--port", strconv.Itoa(scratchPort),
		"--wiredTigerCacheSizeGB", "0.25",
		"--setParameter", "ttlMonitorEnabled=false",
		"--setParameter", "diagnosticDataCollectionEnabled=false",
		"--setParameter", "disableLogicalSessionCacheRefresh=true",
		"--logpath", s.logFile(), "--logappend",
		"--pidfilepath", s.pidFile(),
		"--fork",
	}
	cmd := command(ctx, env, true, mongod, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("starting a scratch MongoDB server failed: %v: %s (log: %s)", err, lastLine(out), s.logTail())
	}
	deadline := time.Now().Add(2 * time.Minute)
	for {
		c, err := connect(ctx, s.uri())
		if err == nil {
			return c, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return nil, fmt.Errorf("the scratch MongoDB server didn't answer: %v (log: %s)", err, s.logTail())
		}
		time.Sleep(time.Second)
	}
}

func (s scratch) logTail() string {
	data, err := os.ReadFile(s.logFile())
	if err != nil {
		return "no log"
	}
	return lastLine(data)
}

// pid is the scratch mongod's process, 0 when none runs on this directory.
func (s scratch) pid() int {
	data, err := os.ReadFile(s.pidFile())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 1 {
		return 0
	}
	cmdline, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		// No /proc (not Linux): trust a live process.
		if syscall.Kill(pid, 0) != nil {
			return 0
		}
		return pid
	}
	if !strings.Contains(string(cmdline), s.dataDir()) {
		return 0 // the pid was reused
	}
	return pid
}

// stop shuts the scratch server down (politely, then SIGKILL).
func (s scratch) stop() error {
	pid := s.pid()
	if pid == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if c, err := connect(ctx, s.uri()); err == nil {
		_ = c.Database("admin").RunCommand(ctx, bson.D{{Key: "shutdown", Value: 1}, {Key: "force", Value: true}}).Err()
		disconnect(c)
	} else {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	for range 60 {
		if s.pid() == 0 {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(time.Second)
	if s.pid() != 0 {
		return fmt.Errorf("the scratch MongoDB server (pid %d) didn't stop", pid)
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
		if errors.Is(err, os.ErrNotExist) {
			if _, err2 := os.Lstat(s.Dir); errors.Is(err2, os.ErrNotExist) {
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

// ---- restore to a point

// restoreTarget is where a restore stops: the newest change in the bucket
// (Latest), a moment (Time: every change up to and including that second)
// or a Mark.
type restoreTarget struct {
	Latest bool
	Time   time.Time
	Mark   string
}

func (t restoreTarget) describe() string {
	switch {
	case t.Mark != "":
		return "Mark " + t.Mark
	case !t.Time.IsZero():
		return t.Time.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return "the newest change in your bucket"
}

// restoreOutcome says what a restore reached.
type restoreOutcome struct {
	Backup      backupDoc
	RecoveredTo *time.Time // the last change replayed (nil: none after the backup)
	Replayed    int        // oplog entries replayed after the backup
	Failed      int64      // documents mongorestore couldn't restore
}

// restoreInto restores the backup and changes needed for target into a
// started scratch server.
func restoreInto(ctx context.Context, env agent.EngineEnv, r *repo, target restoreTarget, s scratch, tl agent.TaskLogger) (restoreOutcome, error) {
	var out restoreOutcome
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return out, fmt.Errorf("listing backups: %w", err)
	}
	if len(docs) == 0 {
		return out, errors.New("there is no finished backup in your bucket yet")
	}
	chunks, err := r.listChunks(ctx)
	if err != nil {
		return out, fmt.Errorf("listing copied changes: %w", err)
	}
	var until ts
	switch {
	case target.Mark != "":
		var m markDoc
		if err := r.getJSON(ctx, markKey(target.Mark), &m); err != nil {
			if errors.Is(err, objstoreNotFound) {
				return out, fmt.Errorf("the Mark %q isn't in your bucket", target.Mark)
			}
			return out, fmt.Errorf("reading the Mark: %w", err)
		}
		until = m.TS
	case !target.Time.IsZero():
		until = ts{T: uint32(target.Time.Unix()), I: ^uint32(0)}
	}
	// The newest backup that finished at or before the target.
	var b *backupDoc
	for i := len(docs) - 1; i >= 0; i-- {
		if target.Latest || !docs[i].EndTS.After(until) {
			b = &docs[i]
			break
		}
	}
	if b == nil {
		return out, fmt.Errorf("the oldest backup in your bucket finished at %s: pick a later moment", docs[0].StoppedAt.Format(time.RFC3339))
	}
	out.Backup = *b
	chain, reach, gap := chainFrom(chunks, b.StartTS)
	if target.Latest {
		until = reach
		if !until.After(b.EndTS) {
			until = b.EndTS
		}
	} else if reach.Before(until) && (target.Mark != "" || gap || reach.T < until.T) {
		why := "the newest change copied to your bucket is from " + reach.Time().Format(time.RFC3339) + " (changes arrive about every minute)"
		if gap {
			why = "changes after " + reach.Time().Format(time.RFC3339) + " are missing from your bucket (the oplog was overwritten before they were copied)"
		}
		return out, fmt.Errorf("can't restore to %s: %s", target.describe(), why)
	}

	// 1. The full backup (it replays the changes made during the dump).
	restore, err := tool("mongorestore")
	if err != nil {
		return out, err
	}
	tl.Printf("restoring backup %s (%s stored) into the scratch server", b.Label, humanBytes(b.ArchiveBytes))
	pr, closer, err := r.getSealed(ctx, backupKey(b.Label, archiveName))
	if err != nil {
		return out, fmt.Errorf("downloading backup %s: %w", b.Label, err)
	}
	cmd := command(ctx, env, true, restore, "--uri="+s.uri(), "--archive", "--gzip", "--oplogReplay",
		"--numInsertionWorkersPerCollection=2")
	cmd.Stdin = pr
	var stderr tailBuffer
	stderr.max = 64 << 10
	cmd.Stderr = &stderr
	err = cmd.Run()
	closer.Close()
	tl.Output("mongorestore", summaryLines(stderr.Bytes()))
	if err != nil {
		return out, fmt.Errorf("restoring backup %s failed: %v: %s", b.Label, err, lastLine(stderr.Bytes()))
	}
	out.Failed += failedDocs(stderr.Bytes())

	// 2. The changes after the backup, up to the target.
	if len(chain) == 0 || !until.After(b.StartTS) {
		return out, nil
	}
	oplogFile := filepath.Join(s.Dir, "oplog.bson")
	f, err := os.OpenFile(oplogFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return out, err
	}
	defer os.Remove(oplogFile)
	w := bufio.NewWriterSize(f, 1<<20)
	written := b.StartTS
	var lastWall time.Time
	stop := errors.New("stop")
	for _, c := range chain {
		if c.First.After(until) {
			break
		}
		err := readChunk(ctx, r, c, func(doc bson.Raw, t ts) error {
			if !t.After(written) {
				return nil
			}
			if t.After(until) {
				return stop
			}
			if ns, _ := doc.Lookup("ns").StringValueOK(); strings.HasPrefix(ns, "local.") {
				return nil
			}
			if _, err := w.Write(doc); err != nil {
				return err
			}
			written = t
			out.Replayed++
			if wall, ok := doc.Lookup("wall").TimeOK(); ok {
				lastWall = wall.UTC()
			} else {
				lastWall = t.Time()
			}
			return nil
		})
		if err == stop {
			break
		}
		if err != nil {
			f.Close()
			return out, err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return out, err
	}
	if err := f.Close(); err != nil {
		return out, err
	}
	if out.Replayed == 0 {
		return out, nil
	}
	tl.Printf("replaying %d changes made after the backup, up to %s", out.Replayed, lastWall.Format(time.RFC3339))
	empty := filepath.Join(s.Dir, "empty")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		return out, err
	}
	var stderr2 tailBuffer
	cmd = command(ctx, env, true, restore, "--uri="+s.uri(), "--oplogReplay", "--oplogFile="+oplogFile, empty)
	cmd.Stderr = &stderr2
	if err := cmd.Run(); err != nil {
		tl.Output("mongorestore (changes)", stderr2.Bytes())
		return out, fmt.Errorf("replaying the changes failed: %v: %s", err, lastLine(stderr2.Bytes()))
	}
	out.RecoveredTo = &lastWall
	return out, nil
}

var failedRE = regexp.MustCompile(`(\d+) document\(s\) failed to restore`)

func failedDocs(stderr []byte) int64 {
	var n int64
	for _, m := range failedRE.FindAllSubmatch(stderr, -1) {
		v, _ := strconv.ParseInt(string(m[1]), 10, 64)
		n += v
	}
	return n
}

// summaryLines keeps mongorestore's last lines (its totals).
func summaryLines(b []byte) []byte {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 8 {
		lines = lines[len(lines)-8:]
	}
	return []byte(strings.Join(lines, "\n"))
}

// ensureSpace refuses a restore that wouldn't fit on dir's filesystem.
func ensureSpace(dir string, need int64) error {
	free, err := freeBytes(dir)
	if err != nil {
		return nil // unknown: try anyway
	}
	if free < need {
		return fmt.Errorf("not enough free disk space in %s: a restore needs about %s, %s is free", dir, humanBytes(need), humanBytes(free))
	}
	return nil
}

// restoredDatabases lists a scratch server's user databases.
func restoredDatabases(ctx context.Context, c *mongo.Client) ([]protocol.DBInfo, int64, error) {
	in, err := inspectDatabases(ctx, c)
	return in.Databases, in.TotalBytes, err
}

// inspectDatabases is inspect's database part (it works on a standalone
// scratch server without the replica set bits).
func inspectDatabases(ctx context.Context, c *mongo.Client) (serverInfo, error) {
	var in serverInfo
	dbs, err := c.ListDatabases(ctx, bson.D{})
	if err != nil {
		return in, err
	}
	for _, d := range dbs.Databases {
		in.TotalBytes += d.SizeOnDisk
		if isSystemDB(d.Name) {
			continue
		}
		info := protocol.DBInfo{Name: d.Name, SizeBytes: d.SizeOnDisk}
		if names, err := c.Database(d.Name).ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}}); err == nil {
			for _, n := range names {
				if !strings.HasPrefix(n, "system.") {
					info.Tables++
				}
			}
		}
		in.Databases = append(in.Databases, info)
	}
	return in, nil
}

func isSystemDB(name string) bool { return name == "admin" || name == "config" || name == "local" }
