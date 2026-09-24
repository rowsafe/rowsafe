package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Docker sidecar mode moves the WAL durability boundary. archive_command
// (pgbackrest.SpoolArchiveCommand) only copies each WAL file into
// <spool>/<stanza>/ and fsyncs it; from then on PostgreSQL considers the
// file archived and may recycle the segment. The spool pusher below is what
// actually stores it in the repository, so:
//
//   - a spooled file is deleted only after `pgbackrest archive-push` has
//     succeeded for it. A crash between the push and the delete pushes it
//     again, which pgBackRest accepts when the repository copy is identical;
//   - files are pushed in name order (the order PostgreSQL archives them)
//     and a pass stops at the first failure, so the repository never has a
//     gap followed by later WAL;
//   - failures and a backlog older than ROWSAFE_SPOOL_STALL_AFTER are
//     reported as WAL archiving failures (see sidecarArchiverStats), so the
//     usual alerts and the protection check catch a stuck pusher;
//   - restore points and `check` confirm WAL in the repository, not in the
//     spool.

// spoolTmpMaxAge is when a leftover "<file>.tmp" (an archive_command
// interrupted by a crash) is removed. PostgreSQL retries the file anyway and
// overwrites it; this only reclaims space for files it never retries.
const spoolTmpMaxAge = time.Hour

// spoolPushTimeout bounds one archive-push. pgBackRest has its own network
// timeouts; this catches anything else.
const spoolPushTimeout = 10 * time.Minute

type spoolPusher struct {
	root       string
	stallAfter time.Duration
	poll       time.Duration
	log        *slog.Logger
	// cli returns the pgBackRest CLI for a stanza, or false while there is
	// no pgBackRest config for it (it is written by adopt and every task).
	cli func(stanza string) (pgbackrest.CLI, bool)
	now func() time.Time

	// healthFile, if set, is rewritten every healthEvery for the
	// container's HEALTHCHECK.
	healthFile string

	mu       sync.Mutex
	stanzas  map[string]*spoolState
	lastPass time.Time
	wake     chan struct{}
}

const healthEvery = 10 * time.Second

type spoolState struct {
	pushedCount   int64
	lastPushed    string
	lastPushedAt  time.Time
	failedCount   int64
	lastFailedAt  time.Time
	lastError     string
	failuresInRow int
	nextAttempt   time.Time
}

// SpoolStatus is what the agent knows about one stanza's spool.
type SpoolStatus struct {
	Files        int
	Bytes        int64
	Oldest       time.Time // modification time of the oldest spooled file
	OldestName   string
	PushedCount  int64 // since the agent started
	LastPushed   string
	LastPushedAt time.Time
	FailedCount  int64 // push failures and stalled reports since the agent started
	LastFailedAt time.Time
	LastError    string
	Stalled      bool
	ScanError    string
}

func newSpoolPusher(root string, stallAfter time.Duration, log *slog.Logger, cli func(string) (pgbackrest.CLI, bool)) *spoolPusher {
	return &spoolPusher{
		root: root, stallAfter: stallAfter, poll: time.Second, log: log, cli: cli, now: time.Now,
		stanzas: map[string]*spoolState{}, wake: make(chan struct{}, 1),
	}
}

func (p *spoolPusher) state(stanza string) *spoolState {
	st := p.stanzas[stanza]
	if st == nil {
		st = &spoolState{}
		p.stanzas[stanza] = st
	}
	return st
}

// Run pushes spooled WAL until ctx is cancelled.
func (p *spoolPusher) Run(ctx context.Context) {
	p.log.Info("WAL spool pusher started", "spool", p.root)
	var healthAt time.Time
	for {
		p.pass(ctx)
		if p.healthFile != "" && p.now().Sub(healthAt) >= healthEvery {
			p.writeHealth(p.healthFile)
			healthAt = p.now()
		}
		select {
		case <-ctx.Done():
			return
		case <-p.wake:
		case <-time.After(p.poll):
		}
	}
}

// Wake asks for a pass now (e.g. while a restore point waits for its WAL).
func (p *spoolPusher) Wake() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

var spoolStanzaRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// pass pushes every stanza's spool once.
func (p *spoolPusher) pass(ctx context.Context) {
	for _, stanza := range p.spoolStanzas() {
		p.mu.Lock()
		wait := p.state(stanza).nextAttempt.After(p.now())
		p.mu.Unlock()
		if !wait {
			p.pushStanza(ctx, stanza)
		}
		if ctx.Err() != nil {
			return
		}
	}
	p.mu.Lock()
	p.lastPass = p.now()
	p.mu.Unlock()
}

// pushStanza pushes one stanza's spooled files in order, stopping at the
// first failure. It returns the number of files pushed.
func (p *spoolPusher) pushStanza(ctx context.Context, stanza string) int {
	dir := filepath.Join(p.root, stanza)
	names, err := p.pending(dir)
	if err != nil {
		p.fail(stanza, "", err)
		return 0
	}
	if len(names) == 0 {
		return 0
	}
	cli, ok := p.cli(stanza)
	if !ok {
		p.fail(stanza, names[0], fmt.Errorf("no pgBackRest configuration for stanza %s yet: the agent writes it on adopt and "+
			"before every task (run `rowsafe verify %s`)", stanza, stanza))
		return 0
	}
	pushed := 0
	for _, name := range names {
		if ctx.Err() != nil {
			return pushed
		}
		path := filepath.Join(dir, name)
		pctx, cancel := context.WithTimeout(ctx, spoolPushTimeout)
		out, err := cli.ArchivePush(pctx, path)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return pushed // shutting down; the file stays and is pushed next time
			}
			p.fail(stanza, name, fmt.Errorf("%w: %s", err, errorLine(out)))
			return pushed
		}
		// Only now, with the file in the repository, may it leave the spool.
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			p.fail(stanza, name, fmt.Errorf("pushed, but removing it from the spool failed: %w", err))
			return pushed
		}
		pushed++
		p.mu.Lock()
		st := p.state(stanza)
		st.pushedCount++
		st.lastPushed, st.lastPushedAt = name, p.now()
		if st.failuresInRow > 0 {
			p.log.Info("WAL spool pusher recovered", "stanza", stanza, "file", name, "after_failures", st.failuresInRow)
		}
		st.failuresInRow, st.nextAttempt = 0, time.Time{}
		p.mu.Unlock()
	}
	return pushed
}

// pending lists the WAL files waiting in dir, in the order to push them,
// and removes stale temporary files. Anything that is not a regular file
// with a WAL file name is left alone.
func (p *spoolPusher) pending(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		if strings.HasSuffix(name, ".tmp") && pgbackrest.IsWALFileName(strings.TrimSuffix(name, ".tmp")) {
			if info, err := e.Info(); err == nil && p.now().Sub(info.ModTime()) > spoolTmpMaxAge {
				if os.Remove(filepath.Join(dir, name)) == nil {
					p.log.Warn("removed a stale temporary file from the WAL spool", "file", filepath.Join(dir, name))
				}
			}
			continue
		}
		if pgbackrest.IsWALFileName(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (p *spoolPusher) fail(stanza, file string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.state(stanza)
	st.failedCount++
	st.lastFailedAt = p.now()
	st.lastError = err.Error()
	if file != "" {
		st.lastError = file + ": " + st.lastError
	}
	st.failuresInRow++
	// Back off 1s, 2s, 4s ... up to a minute, like PostgreSQL's own retries.
	delay := min(time.Second<<min(st.failuresInRow-1, 6), time.Minute)
	st.nextAttempt = p.now().Add(delay)
	if st.failuresInRow == 1 || st.failuresInRow%30 == 0 {
		p.log.Error("pushing spooled WAL to the repository failed", "stanza", stanza, "file", file,
			"err", err, "failures_in_a_row", st.failuresInRow, "retry_in", delay.String())
	}
}

// Status scans a stanza's spool and returns its status, without side
// effects.
func (p *spoolPusher) Status(stanza string) SpoolStatus {
	s := p.scan(stanza)
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.state(stanza)
	s.PushedCount, s.LastPushed, s.LastPushedAt = st.pushedCount, st.lastPushed, st.lastPushedAt
	s.FailedCount, s.LastFailedAt, s.LastError = st.failedCount, st.lastFailedAt, st.lastError
	return s
}

// Report is Status for the heartbeat. A backlog older than stallAfter
// counts as one failed archive attempt per report, the way PostgreSQL
// counts each failed archive_command retry, so the WAL archiving alert
// fires for a pusher that is stuck without failing outright.
func (p *spoolPusher) Report(stanza string) SpoolStatus {
	s := p.scan(stanza)
	if s.Stalled {
		p.mu.Lock()
		st := p.state(stanza)
		st.failedCount++
		st.lastFailedAt = p.now()
		if st.failuresInRow == 0 {
			st.lastError = fmt.Sprintf("%s: waiting in the spool for %s (pusher stalled)", s.OldestName, p.now().Sub(s.Oldest).Round(time.Second))
		}
		p.mu.Unlock()
	}
	return p.Status(stanza)
}

// scan counts the files waiting in a stanza's spool.
func (p *spoolPusher) scan(stanza string) SpoolStatus {
	var s SpoolStatus
	names, err := p.pending(filepath.Join(p.root, stanza))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		s.ScanError = err.Error()
	}
	for _, name := range names {
		info, err := os.Lstat(filepath.Join(p.root, stanza, name))
		if err != nil {
			continue // pushed meanwhile
		}
		s.Files++
		s.Bytes += info.Size()
		if s.Oldest.IsZero() || info.ModTime().Before(s.Oldest) {
			s.Oldest, s.OldestName = info.ModTime(), name
		}
	}
	s.Stalled = s.Files > 0 && p.now().Sub(s.Oldest) > p.stallAfter
	return s
}

// spoolStanzas lists the stanzas that have a spool directory.
func (p *spoolPusher) spoolStanzas() []string {
	entries, err := os.ReadDir(p.root)
	if err != nil {
		p.log.Error("reading the WAL spool failed", "spool", p.root, "err", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && spoolStanzaRE.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// LastPass is when the pusher last went through the spool.
func (p *spoolPusher) LastPass() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastPass
}

// sidecarArchiverStats turns pg_stat_archiver (which in sidecar mode only
// says what reached the spool) and the spool status into the report sent to
// the control plane. The standard fields describe the repository:
// LastArchivedTime is the last successful push (or, with an empty spool,
// PostgreSQL's last archive, which is then in the repository too), and
// FailedCount/LastFailedTime include push failures and stalls, so the
// existing WAL archiving alert and the protection check cover the pusher.
// PostgreSQL's own view is kept in the spool fields.
func sidecarArchiverStats(pg protocol.ArchiverStats, s SpoolStatus) protocol.ArchiverStats {
	out := pg
	out.Mode = ModeDockerSidecar
	out.SpooledCount = pg.ArchivedCount
	out.LastSpooledTime = pg.LastArchivedTime
	out.SpoolFiles = s.Files
	out.SpoolBytes = s.Bytes
	out.SpoolOldestTime = timePtr(s.Oldest)
	out.SpoolStalled = s.Stalled
	out.LastPushedWAL = s.LastPushed
	out.PushFailedCount = s.FailedCount
	out.LastPushError = s.LastError
	if s.ScanError != "" {
		out.LastPushError = "reading the spool: " + s.ScanError
	}

	out.ArchivedCount = s.PushedCount
	out.LastArchivedTime = timePtr(s.LastPushedAt)
	if s.Files == 0 && pg.LastArchivedTime != nil && (out.LastArchivedTime == nil || pg.LastArchivedTime.After(*out.LastArchivedTime)) {
		out.LastArchivedTime = pg.LastArchivedTime
	}
	out.FailedCount = pg.FailedCount + s.FailedCount
	if !s.LastFailedAt.IsZero() && (pg.LastFailedTime == nil || s.LastFailedAt.After(*pg.LastFailedTime)) {
		out.LastFailedTime = timePtr(s.LastFailedAt)
	}
	return out
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// errorLine picks pgBackRest's ERROR line from its output, or the last line.
func errorLine(out []byte) string {
	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))
	for _, l := range lines {
		if i := bytes.Index(l, []byte("ERROR: ")); i >= 0 {
			return string(bytes.TrimSpace(l[i:]))
		}
	}
	return string(bytes.TrimSpace(lines[len(lines)-1]))
}
