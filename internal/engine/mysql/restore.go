package mysql

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
// errNoBackup: nothing to restore from yet.
var errNoBackup = errors.New("there is no backup to restore from yet")

func pickBackup(all []manifest, t restoreTarget) (manifest, error) {
	if len(all) == 0 {
		return manifest{}, errNoBackup
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
	if err := checkSwitches(ctx, st, last, t); err != nil { // inplace.go
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
// target into dir/binlogs. The chain stays on the server that wrote the
// backup's file; where the database moved to another server (a standby's
// promotion) and that server shipped nothing more, it goes on in the new
// primary's own files (binlogLink).
func (s *server) fetchBinlogs(ctx context.Context, st *objStore, dir string, res *restored, t restoreTarget, log agent.TaskLogger) error {
	from := res.Backup.Binlog
	objs, err := st.list(ctx, "binlogs/")
	if err != nil {
		return err
	}
	idx := indexBinlogs(objs)
	links, err := loadLinks(ctx, st, linksTo(objs))
	if err != nil {
		return err
	}
	cur, ok := idx.find(from.File, res.Backup.StoppedAt.Add(time.Minute))
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
	followed := map[binlogFile]bool{}
	for {
		chunks, end := idx.contiguous(cur)
		if end == 0 {
			return fmt.Errorf("the binary log %s isn't complete in the bucket", cur.Name)
		}
		local, err := localBinlog(bdir, cur.Name, res)
		if err != nil {
			return err
		}
		if err := downloadChunks(ctx, st, chunks, local); err != nil {
			return err
		}
		res.Binlogs = append(res.Binlogs, local)
		total += end
		if t.Mark != nil && t.Mark.Position.File.Name == cur.Name &&
			(t.Mark.Position.File.Created == 0 || t.Mark.Position.File.same(cur)) {
			if end < t.Mark.Position.Pos {
				return fmt.Errorf("the binary log up to the Mark %s isn't in the bucket", t.Mark.Name)
			}
			res.StopPos = t.Mark.Position.Pos
			break
		}
		// The server that wrote it: a file from an older agent says so
		// itself (its first event), so the chain stays on that server.
		server := cur.Server
		if server == "" {
			if id, err := readBinlogFile(local); err == nil {
				server = id.Server
			}
		}
		// The database moved to another server from this file: what
		// this server wrote after that (in this file or the next ones,
		// replicated from the new primary once it followed it, or nothing
		// after a restart) isn't its history.
		lk, found := findLink(links, cur, server, followed)
		if found && (len(res.Binlogs) > 1 || lk.From.Pos >= res.StartPos) {
			if stopUnix > 0 && lk.To.Created >= stopUnix {
				break // the moment is before the switch
			}
			if lk.From.Pos > end {
				return fmt.Errorf("the database moved to another server at %s, and the old primary's binary log %s isn't in the bucket up to there "+
					"(only %s of it arrived); restores can reach up to its end at most", lk.At.UTC().Format("15:04:05 UTC on 2006-01-02"), cur.Name, humanBytes(end))
			}
			to, ok := idx.find(lk.To, time.Time{})
			if !ok {
				return fmt.Errorf("the database moved to another server at %s, and that server's binary log isn't in the bucket yet; restores can reach up to %s at most",
					lk.At.UTC().Format("15:04:05 UTC on 2006-01-02"), lk.At.UTC().Format("15:04:05 UTC"))
			}
			// What the old primary wrote after it (replicated from the new
			// one, once it followed it) isn't its history.
			if err := os.Truncate(local, lk.From.Pos); err != nil {
				return err
			}
			total -= end - lk.From.Pos
			followed[lk.To] = true
			log.Printf("the database moved to another server at %s (%s:%d): going on with its binary log %s",
				lk.At.UTC().Format("15:04:05 UTC on 2006-01-02"), cur.Name, lk.From.Pos, to.Name)
			cur = to
			continue
		}
		next, ok, err := nextOnServer(ctx, st, idx, cur, server, bdir)
		if err != nil {
			return err
		}
		if ok {
			if stopUnix > 0 && next.Created >= stopUnix {
				break
			}
			if closed, err := endsWithRotate(local); err != nil || !closed {
				return fmt.Errorf("the binary log %s is incomplete in the bucket (only %s of it arrived); restores can reach up to its end at most",
					cur.Name, humanBytes(end))
			}
			cur = next
			continue
		}
		// The chain ends here on this server.
		if lk, found := laterLink(links, cur, server, followed); found && (stopUnix == 0 || lk.To.Created < stopUnix) {
			return fmt.Errorf("the database moved to another server at %s from the old primary's binary log %s, which isn't in the bucket; "+
				"restores can reach up to the end of %s at most: pick a moment before %s, or one after that server's first backup",
				lk.At.UTC().Format("15:04:05 UTC on 2006-01-02"), lk.From.Name, cur.Name, lk.At.UTC().Format("15:04:05 UTC"))
		}
		if t.Mark != nil {
			return fmt.Errorf("the binary logs up to the Mark %s aren't in the bucket", t.Mark.Name)
		}
		// No record of where it went (a switch by an older agent, or the
		// record couldn't be written): say so, also for the latest moment
		// (clones, standbys, Proof), rather than stop at the switch.
		moveStop := stopUnix
		if moveStop == 0 {
			moveStop = time.Now().Unix() + 1
		}
		ownWrites := func(g binlogFile) (bool, error) { return wroteItself(ctx, st, idx, g, bdir) }
		moved, at, err := movedAway(idx, links, cur, server, moveStop, ownWrites)
		if err != nil {
			return err
		}
		if moved {
			return fmt.Errorf("the database moved to another server at %s, and the bucket doesn't say where its binary log goes on from %s "+
				"(the switch was made by an older agent): pick a moment before %s, or one after that server's first backup",
				at.UTC().Format("15:04:05 UTC on 2006-01-02"), cur.Name, at.UTC().Format("15:04:05 UTC"))
		}
		break
	}
	log.Printf("fetched %s of binary logs (%s)", humanBytes(total), plural(int64(len(res.Binlogs)), "file", "files"))
	return nil
}

// localBinlog is where a binary log file goes: its own name (positions and
// tools name it so); a file of that name fetched earlier (the other server
// of a pair) is moved aside first.
func localBinlog(bdir, name string, res *restored) (string, error) {
	local := filepath.Join(bdir, name)
	for i, p := range res.Binlogs {
		if p != local {
			continue
		}
		aside := fmt.Sprintf("%s.%d", local, i)
		if err := os.Rename(p, aside); err != nil {
			return "", err
		}
		res.Binlogs[i] = aside
	}
	return local, nil
}

// nextOnServer is the file that follows cur on server: a file from an older
// agent (which doesn't say whose it is) only once its first event says it
// is that server's.
func nextOnServer(ctx context.Context, st *objStore, idx binlogIndex, cur binlogFile, server, bdir string) (binlogFile, bool, error) {
	for _, c := range idx.candidates(cur, server) {
		if c.Server != "" || server == "" {
			return c, true, nil
		}
		chunks, end := idx.contiguous(c)
		if end == 0 {
			continue
		}
		check := filepath.Join(bdir, ".check-"+c.Name)
		if err := downloadChunks(ctx, st, chunks[:1], check); err != nil {
			return binlogFile{}, false, err
		}
		id, err := readBinlogFile(check)
		_ = os.Remove(check)
		if err == nil && id.Server == server {
			return c, true, nil
		}
	}
	return binlogFile{}, false, nil
}

// loadLinks reads the recorded switches (newest first); a record whose
// content doesn't match its key is left out.
func loadLinks(ctx context.Context, st *objStore, keys []binlogFile) ([]binlogLink, error) {
	var out []binlogLink
	for _, to := range keys {
		var lk binlogLink
		if err := st.getJSON(ctx, linkKey(to), &lk); err != nil {
			if errors.Is(err, errNotFound) {
				continue
			}
			return nil, err
		}
		if lk.To == to {
			out = append(out, lk)
		}
	}
	return out, nil
}

// findLink is the switch to another server recorded from cur (written by
// server), if any.
func findLink(links []binlogLink, cur binlogFile, server string, followed map[binlogFile]bool) (binlogLink, bool) {
	for _, lk := range links {
		if followed[lk.To] || lk.To.Server == server {
			continue
		}
		if lk.From.Name == cur.Name && (lk.From.Server == server || server == "") {
			return lk, true
		}
	}
	return binlogLink{}, false
}

// laterLink is a switch to another server recorded from a later file of
// server than cur (one the bucket doesn't have).
func laterLink(links []binlogLink, cur binlogFile, server string, followed map[binlogFile]bool) (binlogLink, bool) {
	base, n, ok := binlogSeq(cur.Name)
	if !ok || server == "" {
		return binlogLink{}, false
	}
	for _, lk := range links {
		if followed[lk.To] || lk.To.Server == server || lk.To.Created < cur.Created {
			continue
		}
		fb, fn, ok := binlogSeq(lk.From.Name)
		if ok && fb == base && fn > n && lk.From.Server == server {
			return lk, true
		}
	}
	return binlogLink{}, false
}

// movedOff reports whether server's file created then is from after a
// recorded switch away from server, and before one back to it: the old
// primary restarted, or followed the new one, unless it wrote something
// itself there (wroteItself: the database came back to it unrecorded).
func movedOff(links []binlogLink, server string, created int64) bool {
	var at int64 = -1
	off := false
	for _, lk := range links {
		t := lk.To.Created
		if t > created {
			continue
		}
		switch {
		case lk.To.Server == server && t >= at: // back here (its first file is history)
			at, off = t, false
		case lk.From.Server == server && t > at:
			at, off = t, true
		}
	}
	return off
}

// movedAway reports whether another server's binary logs begin after cur
// was created and before stop: the database moved there (and when), and
// the bucket doesn't say how. A server's file from after a recorded
// switch away from it counts only when it holds a transaction that server
// wrote itself (ownWrites), not only what it replicated or nothing.
func movedAway(idx binlogIndex, links []binlogLink, cur binlogFile, server string, stopUnix int64,
	ownWrites func(binlogFile) (bool, error)) (bool, time.Time, error) {
	var cands []binlogFile
	for g := range idx {
		if g.Server == "" || g.Server == server || g.Created <= cur.Created || g.Created >= stopUnix {
			continue
		}
		cands = append(cands, g)
	}
	slices.SortFunc(cands, func(a, b binlogFile) int { return cmp.Compare(a.Created, b.Created) })
	for _, g := range cands {
		if movedOff(links, g.Server, g.Created) {
			own, err := ownWrites(g)
			if err != nil {
				return false, time.Time{}, err
			}
			if !own {
				continue
			}
		}
		return true, time.Unix(g.Created, 0), nil
	}
	return false, time.Time{}, nil
}

// wroteItself reports whether g (as far as it is in the bucket) holds a
// transaction its server wrote itself: events keep the server_id of the
// server that wrote them first.
func wroteItself(ctx context.Context, st *objStore, idx binlogIndex, g binlogFile, bdir string) (bool, error) {
	chunks, end := idx.contiguous(g)
	if end == 0 {
		return false, nil
	}
	path := filepath.Join(bdir, ".check-"+g.Name)
	defer os.Remove(path)
	if err := downloadChunks(ctx, st, chunks, path); err != nil {
		return false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	id, err := strconv.ParseUint(g.Server, 10, 32)
	if err != nil {
		return true, nil // can't tell: counts
	}
	own := false
	err = scanEvents(f, func(_ int64, h eventHeader, _ []byte) bool {
		switch h.Type {
		case evGTID, evAnonymousGTID, evGTIDTagged, evMariaGTID, evQuery:
			own = h.ServerID == uint32(id)
		}
		return !own
	})
	return own, err
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
	// Admin signs in once the server checks accounts (a safe copy);
	// otherwise root without a password (--skip-grant-tables).
	Admin *account
	proc  *os.Process
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
func (s *server) startScratch(ctx context.Context, dir string, m manifest, timeout time.Duration, extra ...string) (*scratch, error) {
	mysqld, err := s.tool("server")
	if err != nil {
		return nil, fmt.Errorf("the %s server binary isn't installed here: %w", s.flavor.display(), err)
	}
	return s.startScratchWith(ctx, dir, m, mysqld, nil, timeout)
}

// startScratchWith is startScratch with another server program and extra
// options (an upgrade rehearsal's target version).
func (s *server) startScratchWith(ctx context.Context, dir string, m manifest, mysqld string, extra []string, timeout time.Duration) (*scratch, error) {
	for _, d := range []string{filepath.Join(dir, "socket"), filepath.Join(dir, "tmp")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return nil, err
		}
	}
	sc := &scratch{Dir: dir, DataDir: filepath.Join(dir, "data"), Socket: filepath.Join(dir, "socket", "mysqld.sock"),
		Args: append(append(slicesClone(s.env.LowPriority), s.scratchArgs(mysqld, dir, m)...), extra...)}
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

// alive reports whether the server process runs. The PID is saved with
// the copy: after a reboot it can be another process's (production's
// mysqld even), so it counts only when that process runs this copy's
// data folder.
func (sc *scratch) alive() bool {
	if sc.PID <= 0 {
		return false
	}
	return syscall.Kill(sc.PID, 0) == nil && !zombie(sc.PID) && sc.owns(sc.PID)
}

// owns reports whether process pid is this private server: its command
// line names its data folder. When the command line can't be read, only a
// process this agent started counts.
func (sc *scratch) owns(pid int) bool {
	cmdline, ok := commandLine(pid)
	if !ok {
		return sc.proc != nil && sc.proc.Pid == pid
	}
	return strings.Contains(cmdline, "--datadir="+sc.dataDirArg())
}

// dataDirArg is the --datadir the server was started with.
func (sc *scratch) dataDirArg() string {
	for _, a := range sc.Args {
		if d, ok := strings.CutPrefix(a, "--datadir="); ok {
			return d
		}
	}
	if sc.DataDir != "" {
		return sc.DataDir
	}
	return filepath.Join(sc.Dir, "data")
}

// commandLine is a process's command line, arguments separated by spaces:
// /proc on Linux, ps elsewhere.
func commandLine(pid int) (string, bool) {
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		return strings.ReplaceAll(string(b), "\x00", " "), true
	} else if _, serr := os.Stat("/proc/self"); serr == nil {
		return "", errors.Is(err, os.ErrNotExist) // gone: an empty command line
	}
	out, err := exec.Command("ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
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
	if sc.Admin != nil {
		return openWith(ctx, *sc.Admin, sc.Socket, 0)
	}
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
	shutdown := false
	if db, err := sc.connect(cctx); err == nil {
		_, err = db.ExecContext(cctx, "SHUTDOWN")
		shutdown = err == nil
		db.Close()
	}
	cancel()
	for _, sig := range []syscall.Signal{0, syscall.SIGTERM, syscall.SIGKILL} {
		if sig == 0 && !shutdown {
			continue // nobody asked it to stop (it checks accounts now, after a replay): SIGTERM at once
		}
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
	// Account changes in the binary logs (CREATE USER, GRANT, ALTER USER...:
	// Databases & users makes them) are refused by a server that checks no
	// accounts (--skip-grant-tables). FLUSH PRIVILEGES first turns the
	// checks on, the replaying session keeping every right (MySQL's and
	// MariaDB's documented way); the server starts again afterwards, back to
	// checking nothing, for what follows on its private socket.
	flush := sc.Admin == nil
	if flush {
		apply.Stdin = io.MultiReader(strings.NewReader("FLUSH PRIVILEGES;\n"), pipe)
	}
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
	if flush {
		sc.stop(ctx)
		if err := sc.start(); err != nil {
			return err
		}
		if err := sc.wait(ctx, drillStartTimeout); err != nil {
			return fmt.Errorf("after replaying the binary logs: %w", err)
		}
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
