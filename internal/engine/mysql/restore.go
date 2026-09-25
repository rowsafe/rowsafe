package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Restoring (restore tests and Rewind copies): download the backup chain
// and unpack it (xbstream / mbstream) straight from the bucket, prepare it
// with the backup tool, start a private server on it and replay the binary
// logs up to the target. The server listens only on a Unix socket in a
// 0700 directory (no TCP), writes no binary log, starts no replication and
// no scheduled events, and runs without the grant tables: only the agent's
// OS user can reach it, and nothing in it acts on the outside world.

// restoreTarget is where a restore stops: Time (inclusive, to the
// second), Mark, or everything in the bucket.
type restoreTarget struct {
	Time      *time.Time
	Mark      *markRecord
	BackupSet string
}

func (t restoreTarget) describe() string {
	switch {
	case t.Mark != nil:
		return "the Mark " + t.Mark.Name
	case t.Time != nil:
		return t.Time.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	return "the latest point in the bucket"
}

// point is the target as a time, for choosing the backup (zero: latest).
func (t restoreTarget) point() time.Time {
	switch {
	case t.Mark != nil:
		return t.Mark.CreatedAt
	case t.Time != nil:
		return *t.Time
	}
	return time.Time{}
}

// pickBackup chooses the backup to start from.
func pickBackup(all []manifest, t restoreTarget) (manifest, error) {
	if len(all) == 0 {
		return manifest{}, errors.New("there is no backup to restore from yet")
	}
	if t.BackupSet != "" {
		if !labelRE.MatchString(t.BackupSet) {
			return manifest{}, fmt.Errorf("invalid backup %q", t.BackupSet)
		}
		for _, m := range all {
			if m.Label == t.BackupSet {
				if p := t.point(); !p.IsZero() && m.StoppedAt.After(p.Add(time.Second)) {
					return manifest{}, fmt.Errorf("the backup %s finished after %s", m.Label, t.describe())
				}
				return m, nil
			}
		}
		return manifest{}, fmt.Errorf("the backup %s is no longer in the bucket (retention may have removed it); pick a later point", t.BackupSet)
	}
	p := t.point()
	if p.IsZero() {
		return all[len(all)-1], nil
	}
	for i := len(all) - 1; i >= 0; i-- {
		if !all[i].StoppedAt.After(p) {
			return all[i], nil
		}
	}
	return manifest{}, fmt.Errorf("%s is before the oldest backup (%s)", t.describe(), all[0].StoppedAt.Format(time.RFC3339))
}

// chain is the backups to apply, full first.
func chain(all []manifest, last manifest) ([]manifest, error) {
	byLabel := map[string]manifest{}
	for _, m := range all {
		byLabel[m.Label] = m
	}
	out := []manifest{last}
	for cur := last; cur.Base != ""; {
		b, ok := byLabel[cur.Base]
		if !ok {
			return nil, fmt.Errorf("the backup %s builds on %s, which is no longer in the bucket", cur.Label, cur.Base)
		}
		out = append([]manifest{b}, out...)
		cur = b
		if len(out) > 1000 {
			return nil, errors.New("backup chain too long")
		}
	}
	return out, nil
}

// restored is a prepared data directory with the binary logs to replay.
type restored struct {
	DataDir  string
	Backup   manifest
	Binlogs  []string // local files, in order
	StartPos int64    // in the first file
	StopPos  int64    // in the last file (Marks), 0 otherwise
	// NoBinlogs: nothing to replay (the target is the backup itself).
	Bytes int64
}

// runTool runs a tool at low priority and returns its output tail.
func (s *server) runTool(ctx context.Context, log agent.TaskLogger, label string, name string, args ...string) error {
	cmd := s.lowCmd(ctx, name, args...)
	out := &tailBuffer{max: 32 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Run(); err != nil {
		log.Output(label, out.Bytes())
		return fmt.Errorf("%s failed: %v: %s", label, err, lastErrorLine(out.Bytes()))
	}
	return nil
}

// restoreData downloads, unpacks and prepares the backup for t into
// dir/data, and fetches the binary logs to replay into dir/binlogs.
func (s *server) restoreData(ctx context.Context, st *objStore, dir string, t restoreTarget, log agent.TaskLogger) (*restored, error) {
	all, err := st.manifests(ctx)
	if err != nil {
		return nil, err
	}
	last, err := pickBackup(all, t)
	if err != nil {
		return nil, err
	}
	backups, err := chain(all, last)
	if err != nil {
		return nil, err
	}
	xb, err := s.tool("xbstream")
	if err != nil {
		return nil, fmt.Errorf("the backup unpacker (xbstream/mbstream) isn't installed: %w", err)
	}
	bin, err := s.tool("backup")
	if err != nil {
		return nil, fmt.Errorf("%s isn't installed: %w", s.flavor.backupToolName(), err)
	}
	res := &restored{Backup: last}
	for _, m := range backups {
		d := filepath.Join(dir, "backup-"+m.Label)
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		log.Printf("downloading and unpacking the %s backup %s (%s stored)", m.Type, m.Label, humanBytes(m.RepoSizeBytes))
		if err := s.unpack(ctx, st, m, xb, d); err != nil {
			return nil, err
		}
	}
	full := filepath.Join(dir, "backup-"+backups[0].Label)
	opt := []string{"--prepare", "--use-memory=" + s.cfg.ScratchMemory, "--target-dir=" + full}
	for i, m := range backups {
		args := slicesClone(opt)
		if !s.flavor.mariadb() && i < len(backups)-1 {
			args = append(args, "--apply-log-only")
		}
		if i > 0 {
			args = append(args, "--incremental-dir="+filepath.Join(dir, "backup-"+m.Label))
		}
		log.Printf("preparing %s", m.Label)
		if err := s.runTool(ctx, log, filepath.Base(bin)+" --prepare", bin, append([]string{"--no-defaults"}, args...)...); err != nil {
			return nil, err
		}
		if i > 0 {
			_ = os.RemoveAll(filepath.Join(dir, "backup-"+m.Label))
		}
	}
	res.DataDir = filepath.Join(dir, "data")
	if err := os.Rename(full, res.DataDir); err != nil {
		return nil, err
	}
	res.Bytes = dirSize(res.DataDir)
	if err := s.fetchBinlogs(ctx, st, dir, res, t, log); err != nil {
		return nil, err
	}
	return res, nil
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// unpack streams one backup from the bucket into xbstream -x.
func (s *server) unpack(ctx context.Context, st *objStore, m manifest, xb, dir string) error {
	r, err := st.get(ctx, backupKey(m.Label, dataObject))
	if err != nil {
		return err
	}
	defer r.Close()
	cmd := s.lowCmd(ctx, xb, "-x", "-C", dir)
	out := &tailBuffer{max: 16 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_, cerr := io.Copy(stdin, r)
	stdin.Close()
	werr := cmd.Wait()
	if cerr != nil {
		return fmt.Errorf("downloading %s: %w", m.Label, cerr)
	}
	if werr != nil {
		return fmt.Errorf("unpacking %s failed: %v: %s", m.Label, werr, lastErrorLine(out.Bytes()))
	}
	return nil
}

// fetchBinlogs downloads the binary logs from the backup's position to the
// target into dir/binlogs.
func (s *server) fetchBinlogs(ctx context.Context, st *objStore, dir string, res *restored, t restoreTarget, log agent.TaskLogger) error {
	from := res.Backup.Binlog
	objs, err := st.list(ctx, "binlogs/")
	if err != nil {
		return err
	}
	idx := indexBinlogs(objs)
	cur, ok := idx.find(from.File.Name, from.File.Created, res.Backup.StoppedAt.Add(time.Minute))
	if !ok {
		if t.Mark != nil || t.Time != nil && t.Time.After(res.Backup.StoppedAt) {
			return fmt.Errorf("the binary logs written after the backup %s (from %s) aren't in the bucket", res.Backup.Label, from)
		}
		log.Printf("no binary logs after the backup in the bucket: restoring the backup as it is")
		return nil
	}
	var stopUnix int64
	if t.Time != nil {
		stopUnix = t.Time.Unix() + 1
	}
	bdir := filepath.Join(dir, "binlogs")
	if err := os.MkdirAll(bdir, 0o700); err != nil {
		return err
	}
	res.StartPos = from.Pos
	var total int64
	for {
		chunks, end := idx.contiguous(cur)
		if end == 0 {
			return fmt.Errorf("the binary log %s isn't complete in the bucket", cur.Name)
		}
		local := filepath.Join(bdir, cur.Name)
		if err := downloadChunks(ctx, st, chunks, local); err != nil {
			return err
		}
		res.Binlogs = append(res.Binlogs, local)
		total += end
		if t.Mark != nil && t.Mark.Position.File.Name == cur.Name &&
			(t.Mark.Position.File.Created == 0 || t.Mark.Position.File.Created == cur.Created) {
			if end < t.Mark.Position.Pos {
				return fmt.Errorf("the binary log up to the Mark %s isn't in the bucket", t.Mark.Name)
			}
			res.StopPos = t.Mark.Position.Pos
			break
		}
		next, ok := idx.next(cur)
		if !ok {
			if t.Mark != nil {
				return fmt.Errorf("the binary logs up to the Mark %s aren't in the bucket", t.Mark.Name)
			}
			break
		}
		if stopUnix > 0 && next.Created >= stopUnix {
			break
		}
		if closed, err := endsWithRotate(local); err != nil || !closed {
			return fmt.Errorf("the binary log %s is incomplete in the bucket (only %s of it arrived); restores can reach up to its end at most",
				cur.Name, humanBytes(end))
		}
		cur = next
	}
	log.Printf("fetched %s of binary logs (%s)", humanBytes(total), plural(int64(len(res.Binlogs)), "file", "files"))
	return nil
}

// downloadChunks concatenates a file's pieces.
func downloadChunks(ctx context.Context, st *objStore, chunks []binlogChunk, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, c := range chunks {
		r, err := st.get(ctx, c.Key)
		if err != nil {
			return err
		}
		n, err := io.Copy(f, r)
		r.Close()
		if err != nil {
			return fmt.Errorf("downloading %s: %w", c.Key, err)
		}
		if n != c.To-c.From {
			return fmt.Errorf("%s: %d bytes instead of %d", c.Key, n, c.To-c.From)
		}
	}
	return f.Close()
}

// endsWithRotate reports whether a binary log file is complete (its last
// event switches to the next file or stops the server).
func endsWithRotate(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	var last byte
	err = scanEvents(f, func(_ int64, h eventHeader, _ []byte) bool {
		last = h.Type
		return true
	})
	return last == evRotate || last == evStop, err
}

// recoveredTo is the time of the last transaction the replay applies.
func recoveredTo(res *restored, t restoreTarget) *time.Time {
	var stop time.Time
	if t.Time != nil {
		stop = t.Time.Add(time.Second)
	}
	var best *time.Time
	for i, path := range res.Binlogs {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		start := int64(0)
		if i == 0 {
			start = res.StartPos
		}
		stopPos := int64(0)
		if i == len(res.Binlogs)-1 {
			stopPos = res.StopPos
		}
		at, ok, _ := lastCommitBefore(f, start, stop, stopPos)
		f.Close()
		if ok {
			a := at
			best = &a
		}
	}
	return best
}

// scratch is a private server on a restored data directory.
type scratch struct {
	Dir     string // holds data/, socket/, tmp/, the log
	DataDir string
	Socket  string
	PID     int
	Args    []string // the command, to start it again
	proc    *os.Process
}

// scratchArgs is the command line of a private server.
func (s *server) scratchArgs(mysqld string, dir string, m manifest) []string {
	args := []string{mysqld, "--no-defaults",
		"--datadir=" + filepath.Join(dir, "data"),
		"--socket=" + filepath.Join(dir, "socket", "mysqld.sock"),
		"--pid-file=" + filepath.Join(dir, "mysqld.pid"),
		"--log-error=" + filepath.Join(dir, "mysqld.log"),
		"--tmpdir=" + filepath.Join(dir, "tmp"),
		"--skip-networking", "--skip-grant-tables",
		"--innodb-buffer-pool-size=" + s.cfg.ScratchMemory,
		"--performance-schema=OFF",
		"--max-connections=20",
		"--innodb-flush-log-at-trx-commit=2",
	}
	if m.PageSize > 0 && m.PageSize != 16384 {
		args = append(args, "--innodb-page-size="+strconv.FormatInt(m.PageSize, 10))
	}
	args = append(args, "--lower-case-table-names="+strconv.Itoa(m.LowerCase))
	if s.flavor.mariadb() {
		args = append(args, "--skip-log-bin", "--skip-slave-start", "--event-scheduler=OFF")
	} else {
		skipReplica := "--skip-replica-start"
		if strings.HasPrefix(m.Version, "8.0.") {
			if _, n := numericVersion(m.Version); n < 80026 {
				skipReplica = "--skip-slave-start"
			}
		}
		args = append(args, "--disable-log-bin", skipReplica, "--event-scheduler=DISABLED",
			"--mysqlx=OFF", "--persisted-globals-load=OFF")
	}
	return args
}

// startScratch starts the private server on dir/data and waits until it
// answers (up to timeout).
func (s *server) startScratch(ctx context.Context, dir string, m manifest, timeout time.Duration) (*scratch, error) {
	mysqld, err := s.tool("server")
	if err != nil {
		return nil, fmt.Errorf("the %s server binary isn't installed here: %w", s.flavor.display(), err)
	}
	for _, d := range []string{filepath.Join(dir, "socket"), filepath.Join(dir, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	sc := &scratch{Dir: dir, DataDir: filepath.Join(dir, "data"), Socket: filepath.Join(dir, "socket", "mysqld.sock"),
		Args: append(slicesClone(s.env.LowPriority), s.scratchArgs(mysqld, dir, m)...)}
	if err := sc.start(); err != nil {
		return nil, err
	}
	if err := sc.wait(ctx, timeout); err != nil {
		sc.stop(context.WithoutCancel(ctx))
		return nil, err
	}
	return sc, nil
}

// start launches the server (not tied to any task's context: a copy
// outlives its task).
func (sc *scratch) start() error {
	cmd := exec.Command(sc.Args[0], sc.Args[1:]...)
	cmd.Dir = sc.Dir
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting the private server: %w", err)
	}
	sc.proc, sc.PID = cmd.Process, cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	return nil
}

// alive reports whether the server process runs.
func (sc *scratch) alive() bool {
	if sc.PID <= 0 {
		return false
	}
	return syscall.Kill(sc.PID, 0) == nil && !zombie(sc.PID)
}

// zombie reports whether a process has exited but isn't reaped yet.
func zombie(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(b)
	if i := strings.LastIndex(s, ")"); i >= 0 && i+2 < len(s) {
		return s[i+2] == 'Z'
	}
	return false
}

func (sc *scratch) connect(ctx context.Context) (*sql.DB, error) {
	return openWith(ctx, account{User: "root", Source: "private server"}, sc.Socket, 0)
}

// wait waits until the server accepts connections.
func (sc *scratch) wait(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		db, err := sc.connect(cctx)
		cancel()
		if err == nil {
			db.Close()
			return nil
		}
		if !sc.alive() {
			return fmt.Errorf("the private server stopped while starting: %s", sc.logTail())
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("the private server didn't start within %s: %s", timeout, sc.logTail())
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

// logTail is the end of the server's error log.
func (sc *scratch) logTail() string {
	b, err := os.ReadFile(filepath.Join(sc.Dir, "mysqld.log"))
	if err != nil {
		return "no log"
	}
	return lastErrorLine(b)
}

// stop shuts the server down (SHUTDOWN, then signals).
func (sc *scratch) stop(ctx context.Context) {
	if !sc.alive() {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if db, err := sc.connect(cctx); err == nil {
		_, _ = db.ExecContext(cctx, "SHUTDOWN")
		db.Close()
	}
	cancel()
	for _, sig := range []syscall.Signal{0, syscall.SIGTERM, syscall.SIGKILL} {
		if sig != 0 {
			_ = syscall.Kill(sc.PID, sig)
		}
		for range 60 {
			if !sc.alive() {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// replay applies the fetched binary logs to the private server.
func (s *server) replay(ctx context.Context, sc *scratch, res *restored, t restoreTarget, log agent.TaskLogger) error {
	if len(res.Binlogs) == 0 {
		return nil
	}
	binlogTool, err := s.tool("binlog")
	if err != nil {
		return fmt.Errorf("the binary log tool isn't installed: %w", err)
	}
	client, err := s.tool("client")
	if err != nil {
		return fmt.Errorf("the %s client isn't installed: %w", s.flavor.display(), err)
	}
	args := []string{"--no-defaults", "--start-position=" + strconv.FormatInt(res.StartPos, 10)}
	if !s.flavor.mariadb() {
		args = append(args, "--skip-gtids")
	}
	switch {
	case res.StopPos > 0:
		args = append(args, "--stop-position="+strconv.FormatInt(res.StopPos, 10))
	case t.Time != nil:
		args = append(args, "--stop-datetime="+t.Time.UTC().Add(time.Second).Format("2006-01-02 15:04:05"))
	}
	args = append(args, res.Binlogs...)
	log.Printf("replaying the binary logs up to %s", t.describe())
	dump := s.lowCmd(ctx, binlogTool, args...)
	dump.Env = append(os.Environ(), "TZ=UTC")
	dumpErr := &tailBuffer{max: 16 << 10}
	dump.Stderr = dumpErr
	pipe, err := dump.StdoutPipe()
	if err != nil {
		return err
	}
	apply := s.lowCmd(ctx, client, "--no-defaults", "--protocol=socket", "--socket="+sc.Socket, "--user=root", "--binary-mode")
	apply.Stdin = pipe
	applyOut := &tailBuffer{max: 16 << 10}
	apply.Stdout, apply.Stderr = applyOut, applyOut
	if err := dump.Start(); err != nil {
		return err
	}
	if err := apply.Start(); err != nil {
		_ = dump.Process.Kill()
		_ = dump.Wait()
		return err
	}
	aerr := apply.Wait()
	if aerr != nil {
		_ = dump.Process.Kill()
	}
	derr := dump.Wait()
	if aerr != nil {
		log.Output("replay", applyOut.Bytes())
		return fmt.Errorf("replaying the binary logs failed: %s", lastErrorLine(applyOut.Bytes()))
	}
	if derr != nil {
		log.Output(filepath.Base(binlogTool), dumpErr.Bytes())
		return fmt.Errorf("reading the binary logs failed: %s", lastErrorLine(dumpErr.Bytes()))
	}
	return nil
}

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

// freeBytes is the free space on dir's filesystem.
func freeBytes(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// checkSpace refuses a restore that can't fit (1.3 x the data + 1 GiB).
func checkSpace(dir string, need int64) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	free, err := freeBytes(dir)
	if err != nil {
		return nil
	}
	want := need*13/10 + 1<<30
	if free < want {
		return fmt.Errorf("not enough free disk space in %s: %s free, about %s needed", dir, humanBytes(free), humanBytes(want))
	}
	return nil
}

// safeDir returns root/id, refusing anything that could point elsewhere.
func safeDir(root, id string) (string, error) {
	root = filepath.Clean(root)
	dir := filepath.Join(root, id)
	if id == "" || strings.ContainsAny(id, `/\.`) || !strings.HasPrefix(dir, root+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid directory name %q", id)
	}
	return dir, nil
}

// RestoreOptions restore a database from the bucket into a folder, without
// Rowsafe's service: for a new server after the old one is lost.
type RestoreOptions struct {
	Engine   string // protocol.EngineMySQL or protocol.EngineMariaDB
	Database string // its name in Rowsafe (the bucket folder)
	Dir      string // an empty or missing folder; the data ends up in Dir/data
	At       *time.Time
	Mark     string
	Env      agent.EngineEnv
	Log      agent.TaskLogger
}

// RestoreTo downloads the newest backup before the target, prepares it,
// replays the binary logs up to the target on a private server, stops it
// and leaves a data directory the server can start on (Dir/data). It
// returns the time of the last transaction it contains.
func RestoreTo(ctx context.Context, o RestoreOptions) (*time.Time, error) {
	f := flavor(o.Engine)
	if f != flavorMySQL && f != flavorMariaDB {
		return nil, fmt.Errorf("unknown engine %q (mysql or mariadb)", o.Engine)
	}
	if entries, err := os.ReadDir(o.Dir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty", o.Dir)
	}
	if err := os.MkdirAll(o.Dir, 0o700); err != nil {
		return nil, err
	}
	s := &server{flavor: f, env: o.Env, db: protocol.DatabaseSpec{Name: o.Database, Stanza: o.Database, Engine: o.Engine}, cfg: loadConfig(o.Env)}
	st, err := openStore(o.Env.Repo, o.Engine, o.Database, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	var t restoreTarget
	switch {
	case o.Mark != "":
		m, err := s.loadMark(ctx, st, o.Mark)
		if err != nil {
			return nil, err
		}
		t.Mark = &m
	case o.At != nil:
		at := o.At.UTC().Truncate(time.Second)
		t.Time = &at
	}
	r, err := s.restoreData(ctx, st, o.Dir, t, o.Log)
	if err != nil {
		return nil, err
	}
	sc, err := s.startScratch(ctx, o.Dir, r.Backup, drillStartTimeout)
	if err != nil {
		return nil, err
	}
	err = s.replay(ctx, sc, r, t, o.Log)
	sc.stop(context.WithoutCancel(ctx))
	if err != nil {
		return nil, err
	}
	for _, d := range []string{"socket", "tmp", "binlogs"} {
		_ = os.RemoveAll(filepath.Join(o.Dir, d))
	}
	at := recoveredTo(r, t)
	if at == nil {
		stopped := r.Backup.StoppedAt
		at = &stopped
	}
	return at, nil
}
