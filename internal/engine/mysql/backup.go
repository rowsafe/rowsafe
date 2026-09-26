package mysql

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Backups are physical: Percona XtraBackup (MySQL) or mariadb-backup
// (MariaDB) streams the data directory (xbstream) while the server runs;
// the agent compresses and encrypts the stream as it goes and uploads it
// in parts, so nothing is written to local disk. A full backup copies
// everything; a differential ("diff") only the pages changed since the
// last full, an incremental ("incr") since the last backup of any kind. A
// restore needs the full plus at most the chain of backups after it; the
// binary logs shipped continuously take it from there to any second.

// manifest describes a complete backup (backups/<label>/manifest.json.age,
// written last).
type manifest struct {
	Label     string    `json:"label"`
	Type      string    `json:"type"`           // full, diff, incr
	Base      string    `json:"base,omitempty"` // the backup this one builds on
	Engine    string    `json:"engine"`
	Version   string    `json:"server_version"`
	Tool      string    `json:"tool"`
	StartedAt time.Time `json:"started_at"`
	StoppedAt time.Time `json:"stopped_at"`
	FromLSN   int64     `json:"from_lsn"`
	ToLSN     int64     `json:"to_lsn"`
	// Binlog is the binary log position the backup is consistent with:
	// restores replay the binary logs from here.
	Binlog        position `json:"binlog"`
	SizeBytes     int64    `json:"size_bytes"`      // the stream before compression
	RepoSizeBytes int64    `json:"repo_size_bytes"` // stored
	PageSize      int64    `json:"innodb_page_size"`
	LowerCase     int      `json:"lower_case_table_names"`
}

func backupKey(label, name string) string { return "backups/" + label + "/" + name }

const (
	dataObject     = "data.xbs.zst.age"
	manifestObject = "manifest.json.age"
)

var labelRE = regexp.MustCompile(`^\d{8}-\d{6}F(_\d{8}-\d{6}[DI])?$`)

// newLabel names a backup like pgBackRest does: 20260925-101500F for a
// full, <full>_20260926-101500D (or I) for a diff (incr).
func newLabel(typ, full string, now time.Time) string {
	stamp := now.UTC().Format("20060102-150405")
	switch typ {
	case protocol.BackupDiff:
		return full + "_" + stamp + "D"
	case protocol.BackupIncr:
		return full + "_" + stamp + "I"
	}
	return stamp + "F"
}

// fullOf is the full backup a label belongs to.
func fullOf(label string) string {
	f, _, _ := strings.Cut(label, "_")
	return f
}

// manifests lists the complete backups, oldest first.
func (st *objStore) manifests(ctx context.Context) ([]manifest, error) {
	objs, err := st.list(ctx, "backups/")
	if err != nil {
		return nil, err
	}
	var out []manifest
	for _, o := range objs {
		if !strings.HasSuffix(o.Key, "/"+manifestObject) {
			continue
		}
		var m manifest
		if err := st.getJSON(ctx, o.Key, &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b manifest) int { return a.StoppedAt.Compare(b.StoppedAt) })
	return out, nil
}

// backupArgs are the backup tool's arguments (after its option file).
func (s *server) backupArgs(f facts, tmp, lsnDir string, incrLSN int64) []string {
	args := []string{"--backup", "--stream=xbstream", "--target-dir=" + tmp, "--extra-lsndir=" + lsnDir,
		"--datadir=" + f.DataDir, "--parallel=2"}
	if incrLSN > 0 {
		args = append(args, "--incremental-lsn="+strconv.FormatInt(incrLSN, 10))
	}
	if s.flavor.mariadb() {
		args = append(args, "--tmpdir="+tmp)
	}
	return args
}

// toolOptionFile writes an option file for the backup tool: the [client]
// account under every group the tools read.
func (s *server) toolOptionFile() (string, error) {
	path, err := s.writeOptionFile()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	body := strings.TrimPrefix(string(b), "[client]\n")
	var all strings.Builder
	for _, g := range []string{"client", "xtrabackup", "mariadb-backup", "mariabackup"} {
		all.WriteString("[" + g + "]\n" + body)
	}
	p := strings.TrimSuffix(path, ".cnf") + "-backup.cnf"
	return p, writeFileAtomic(p, []byte(all.String()), 0o600)
}

// lowCmd builds a command run at low CPU and IO priority.
func (s *server) lowCmd(ctx context.Context, name string, args ...string) *exec.Cmd {
	if len(s.env.LowPriority) == 0 {
		return exec.CommandContext(ctx, name, args...)
	}
	full := append(append(slices.Clone(s.env.LowPriority[1:]), name), args...)
	return exec.CommandContext(ctx, s.env.LowPriority[0], full...)
}

// tailBuffer keeps the last bytes written to it (a tool's log).
type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) Bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.buf)
}

// backup takes a backup (full, diff or incr) and applies retention.
func (s *server) backup(ctx context.Context, typ string, log agent.TaskLogger) (*protocol.BackupResult, error) {
	switch typ {
	case protocol.BackupFull, protocol.BackupDiff, protocol.BackupIncr:
	default:
		return nil, fmt.Errorf("unknown backup type %q", typ)
	}
	db, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	f, err := s.readFacts(ctx, db)
	db.Close()
	if err != nil {
		return nil, err
	}
	tool, toolErr := s.backupToolVersion(ctx)
	if err := s.preflight(f, tool, toolErr); err != nil {
		return nil, err
	}
	bin, _ := s.tool("backup")
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return nil, err
	}
	if _, err := st.ensureMarker(ctx, string(s.flavor), s.db.Name); err != nil {
		return nil, err
	}
	all, err := st.manifests(ctx)
	if err != nil {
		return nil, err
	}
	var base *manifest
	if typ != protocol.BackupFull {
		for i := len(all) - 1; i >= 0; i-- {
			if typ == protocol.BackupIncr || all[i].Type == protocol.BackupFull {
				base = &all[i]
				break
			}
		}
		if base == nil {
			log.Printf("no full backup yet: taking a full backup instead of %s", typ)
			typ = protocol.BackupFull
		} else if base.Version != "" && majorMinor(base.Version) != majorMinor(f.Version) {
			log.Printf("the server was upgraded since the last full backup (%s -> %s): taking a full backup", base.Version, f.Version)
			typ, base = protocol.BackupFull, nil
		}
	}
	start := time.Now().UTC()
	full := ""
	if base != nil {
		full = fullOf(base.Label)
	}
	label := newLabel(typ, full, start)
	work := filepath.Join(s.env.StateDir, "backup", label)
	lsnDir := filepath.Join(work, "lsn")
	tmp := filepath.Join(work, "tmp")
	for _, d := range []string{lsnDir, tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	defer os.RemoveAll(work)
	opt, err := s.toolOptionFile()
	if err != nil {
		return nil, err
	}
	var incrLSN int64
	if base != nil {
		incrLSN = base.ToLSN
		log.Printf("starting %s backup %s (changes since %s) of %s", typ, label, base.Label, humanBytes(totalSize(ctx, s)))
	} else {
		log.Printf("starting full backup %s of %s", label, humanBytes(totalSize(ctx, s)))
	}
	args := append([]string{"--defaults-extra-file=" + opt}, s.backupArgs(f, tmp, lsnDir, incrLSN)...)
	cmd := s.lowCmd(ctx, bin, args...)
	stderr := &tailBuffer{max: 64 << 10}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting %s: %w", filepath.Base(bin), err)
	}
	// Upload as the tool streams; a failing tool must fail the upload, so
	// its exit status is checked before the stream is allowed to end.
	waitErr := make(chan error, 1)
	src := &exitCheckedReader{r: stdout, wait: func() error {
		err := cmd.Wait()
		waitErr <- err
		return err
	}}
	plain, stored, upErr := st.put(ctx, backupKey(label, dataObject), src)
	if !src.waited {
		_ = cmd.Process.Kill()
		err := cmd.Wait()
		waitErr <- err
	}
	toolErr = <-waitErr
	if toolErr != nil || upErr != nil {
		log.Output(filepath.Base(bin), stderr.Bytes())
		_ = st.remove(context.WithoutCancel(ctx), []string{backupKey(label, dataObject)})
		if toolErr != nil {
			return nil, fmt.Errorf("%s failed: %v: %s", filepath.Base(bin), toolErr, lastErrorLine(stderr.Bytes()))
		}
		return nil, upErr
	}
	m := manifest{Label: label, Type: typ, Engine: string(s.flavor), Version: f.Version, Tool: tool,
		StartedAt: start, StoppedAt: time.Now().UTC(), SizeBytes: plain, RepoSizeBytes: stored,
		PageSize: f.PageSize, LowerCase: f.LowerCase}
	if base != nil {
		m.Base = base.Label
	}
	if err := readLSNDir(lsnDir, &m); err != nil {
		log.Output(filepath.Base(bin), stderr.Bytes())
		return nil, err
	}
	if m.Binlog.File.Name != "" {
		if created, err := readBinlogCreated(filepath.Join(filepath.Dir(f.LogBinBasename), m.Binlog.File.Name)); err == nil {
			m.Binlog.File.Created = created
		}
	}
	if err := st.putJSON(ctx, backupKey(label, manifestObject), m); err != nil {
		return nil, err
	}
	log.Printf("backup %s complete: %s read, %s stored, consistent with binary log position %s",
		label, humanBytes(plain), humanBytes(stored), m.Binlog)
	if typ == protocol.BackupFull {
		shipperFor(s).clearGap()
	}
	if err := s.expire(ctx, st, append(all, m), log); err != nil {
		log.Printf("removing old backups failed (it is retried after the next backup): %v", err)
	}
	return &protocol.BackupResult{Label: label, Type: typ, StartedAt: m.StartedAt, StoppedAt: m.StoppedAt,
		SizeBytes: plain, RepoSizeBytes: stored}, nil
}

// exitCheckedReader reads a command's output and, at its end, waits for
// the command: a non-zero exit turns the end of the stream into an error.
type exitCheckedReader struct {
	r      io.Reader
	wait   func() error
	waited bool
}

func (e *exitCheckedReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if errors.Is(err, io.EOF) && !e.waited {
		e.waited = true
		if werr := e.wait(); werr != nil {
			return n, werr
		}
	}
	return n, err
}

func lastErrorLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimSpace(lines[i])
		if strings.Contains(strings.ToLower(l), "error") {
			return l
		}
	}
	if len(lines) > 0 {
		return strings.TrimSpace(lines[len(lines)-1])
	}
	return ""
}

func totalSize(ctx context.Context, s *server) int64 {
	db, err := s.open(ctx)
	if err != nil {
		return 0
	}
	defer db.Close()
	dbs, _, _ := schemaSizes(ctx, db)
	var n int64
	for _, d := range dbs {
		n += d.SizeBytes
	}
	return n
}

var binlogPosRE = regexp.MustCompile(`filename '([^']+)', position '(\d+)'(?:, GTID of the last change '([^']*)')?`)

// readLSNDir reads the checkpoints and binary log position the backup tool
// left in --extra-lsndir.
func readLSNDir(dir string, m *manifest) error {
	kv := func(names ...string) map[string]string {
		for _, n := range names {
			b, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				continue
			}
			out := map[string]string{}
			sc := bufio.NewScanner(bytes.NewReader(b))
			for sc.Scan() {
				k, v, ok := strings.Cut(sc.Text(), "=")
				if ok {
					out[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			return out
		}
		return nil
	}
	cp := kv("xtrabackup_checkpoints", "mariadb_backup_checkpoints")
	if cp == nil {
		return fmt.Errorf("the backup tool left no checkpoints in %s", dir)
	}
	m.FromLSN, _ = strconv.ParseInt(cp["from_lsn"], 10, 64)
	m.ToLSN, _ = strconv.ParseInt(cp["to_lsn"], 10, 64)
	if m.ToLSN == 0 {
		return fmt.Errorf("the backup's checkpoints have no to_lsn")
	}
	info := kv("xtrabackup_info", "mariadb_backup_info")
	if pos := info["binlog_pos"]; pos != "" {
		if mm := binlogPosRE.FindStringSubmatch(pos); mm != nil {
			m.Binlog.File.Name = mm[1]
			m.Binlog.Pos, _ = strconv.ParseInt(mm[2], 10, 64)
			m.Binlog.GTIDSet = mm[3]
		}
	}
	if m.Binlog.File.Name == "" {
		// Older layouts: xtrabackup_binlog_info ("file<TAB>pos<TAB>gtid").
		for _, n := range []string{"xtrabackup_binlog_info", "mariadb_backup_binlog_info"} {
			b, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				continue
			}
			f := strings.Fields(string(b))
			if len(f) >= 2 {
				m.Binlog.File.Name = f[0]
				m.Binlog.Pos, _ = strconv.ParseInt(f[1], 10, 64)
				if len(f) >= 3 {
					m.Binlog.GTIDSet = f[2]
				}
			}
		}
	}
	if m.Binlog.File.Name == "" {
		return errors.New("the backup tool didn't record the binary log position (is the binary log on?)")
	}
	if !isBinlogName(m.Binlog.File.Name) {
		return fmt.Errorf("unexpected binary log name %q", m.Binlog.File.Name)
	}
	return nil
}

// expire removes backups beyond retention (RetentionFull full backups and
// what builds on them), the binary logs only they needed, the Marks before
// the oldest backup kept, and the leftovers of failed uploads.
func (s *server) expire(ctx context.Context, st *objStore, all []manifest, log agent.TaskLogger) error {
	keepFull := s.db.RetentionFull
	if keepFull < 1 {
		keepFull = 2
	}
	var fulls []string
	for _, m := range all {
		if m.Type == protocol.BackupFull {
			fulls = append(fulls, m.Label)
		}
	}
	if len(fulls) <= keepFull {
		return s.removeOrphans(ctx, st, all)
	}
	keep := map[string]bool{}
	for _, l := range fulls[len(fulls)-keepFull:] {
		keep[l] = true
	}
	var drop []string
	var oldest *manifest
	for i, m := range all {
		if keep[fullOf(m.Label)] {
			if oldest == nil || m.StoppedAt.Before(oldest.StoppedAt) {
				oldest = &all[i]
			}
			continue
		}
		drop = append(drop, m.Label)
	}
	objs, err := st.list(ctx, "")
	if err != nil {
		return err
	}
	var keys []string
	for _, o := range objs {
		if strings.HasPrefix(o.Key, "backups/") {
			label, _, _ := strings.Cut(strings.TrimPrefix(o.Key, "backups/"), "/")
			if slices.Contains(drop, label) {
				keys = append(keys, o.Key)
			}
		}
	}
	// Binary logs created before the file the oldest kept backup starts
	// from are no longer needed.
	if oldest != nil && oldest.Binlog.File.Created > 0 {
		for _, o := range objs {
			if f, _, _, ok := parseChunkKey(o.Key); ok && f.Created < oldest.Binlog.File.Created {
				keys = append(keys, o.Key)
			}
		}
		// Marks older than the oldest backup can't be restored any more.
		marks, _ := s.listMarks(ctx, st)
		for _, mk := range marks {
			if mk.CreatedAt.Before(oldest.StoppedAt) {
				keys = append(keys, markKey(mk.Name))
			}
		}
	}
	if err := st.remove(ctx, keys); err != nil {
		return err
	}
	if len(drop) > 0 {
		log.Printf("retention (%d full backups): removed %s", keepFull, strings.Join(drop, ", "))
	}
	return s.removeOrphans(ctx, st, all)
}

// removeOrphans deletes backup folders without a manifest (failed or
// interrupted uploads) older than a day.
func (s *server) removeOrphans(ctx context.Context, st *objStore, all []manifest) error {
	objs, err := st.list(ctx, "backups/")
	if err != nil {
		return err
	}
	complete := map[string]bool{}
	for _, m := range all {
		complete[m.Label] = true
	}
	var keys []string
	for _, o := range objs {
		label, _, _ := strings.Cut(strings.TrimPrefix(o.Key, "backups/"), "/")
		if !complete[label] && time.Since(o.LastModified) > 24*time.Hour {
			keys = append(keys, o.Key)
		}
	}
	return st.remove(ctx, keys)
}
