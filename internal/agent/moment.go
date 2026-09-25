package agent

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment: "when were rows deleted from applications?"
//
// The agent fetches the WAL of the range from the repository (pgbackrest
// archive-get, a few segments at a time into a private directory under the
// state directory, deleted as soon as they are read), reads it with the
// cluster's own pg_waldump and reports the biggest deletes, updates,
// TRUNCATEs and DROPs per transaction, with their commit times and
// transaction IDs: exactly what "rewind to just before this" needs. It
// never changes the database and never reads row contents. WAL doesn't say
// who made a change (no user or application), so neither does the result.

// Limits of one search.
var (
	// momentMaxSegments and momentMaxRepoBytes cap the WAL read; beyond
	// them the search covers the most recent part of the range.
	momentMaxSegments        = 6000
	momentMaxRepoBytes int64 = 8 << 30
	// momentBatch is how many segments are fetched before each pg_waldump
	// run (they are deleted once read).
	momentBatch = 8
	// momentFetchers fetch segments in parallel.
	momentFetchers = 4
	// momentSwitchWait is how long a search of the last minutes waits for
	// the newest changes to reach the repository.
	momentSwitchWait = 60 * time.Second
)

var (
	momentTableRE = regexp.MustCompile(`^[A-Za-z0-9_$ .-]{1,200}$`)
	momentDBRE    = regexp.MustCompile(`^[^\x00-\x1f]{1,63}$`)
)

// normalizeMoment checks a find_moment's params and fills the defaults.
func normalizeMoment(p protocol.FindMomentParams, now time.Time) (momentFilter, error) {
	f := momentFilter{db: strings.TrimSpace(p.DB), minRows: max(p.MinRows, 1), limit: p.Limit, kinds: map[string]bool{}}
	if f.db != "" && !momentDBRE.MatchString(f.db) {
		return f, fmt.Errorf("invalid database name %q", f.db)
	}
	for _, t := range p.Tables {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !momentTableRE.MatchString(t) {
			return f, fmt.Errorf("invalid table name %q", t)
		}
		f.tables = append(f.tables, t)
	}
	for _, k := range p.Kinds {
		if !slices.Contains(protocol.MomentKinds, k) {
			return f, fmt.Errorf("unknown kind of change %q (want %s)", k, strings.Join(protocol.MomentKinds, ", "))
		}
		f.kinds[k] = true
	}
	if len(f.kinds) == 0 {
		for _, k := range protocol.MomentKinds {
			f.kinds[k] = true
		}
	}
	if f.limit <= 0 {
		f.limit = protocol.DefaultMoments
	}
	f.limit = min(f.limit, protocol.MaxMoments)
	f.to = now.UTC()
	if p.To != nil && !p.To.IsZero() {
		f.to = p.To.UTC()
	}
	if f.to.After(now) {
		f.to = now.UTC()
	}
	f.from = f.to.Add(-protocol.DefaultMomentRange)
	if p.From != nil && !p.From.IsZero() {
		f.from = p.From.UTC()
	}
	if !f.from.Before(f.to) {
		return f, errors.New("the start of the range must be before its end")
	}
	if f.to.Sub(f.from) > protocol.MaxMomentRange+time.Minute {
		return f, fmt.Errorf("search at most %d days at a time", int(protocol.MaxMomentRange.Hours()/24))
	}
	return f, nil
}

// walSource is where WAL comes from: the repository (pgbackrest), or a
// directory in tests.
type walSource interface {
	List(ctx context.Context) ([]pgbackrest.ArchivedSegment, error)
	// Fetch writes the segment (or history file) name, decompressed and
	// decrypted, to dest.
	Fetch(ctx context.Context, name, dest string) error
}

type repoSource struct{ cli pgbackrest.CLI }

func (r repoSource) List(ctx context.Context) ([]pgbackrest.ArchivedSegment, error) {
	return r.cli.ArchiveList(ctx)
}

func (r repoSource) Fetch(ctx context.Context, name, dest string) error {
	out, err := r.cli.ArchiveGet(ctx, name, dest)
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(tail(out, 600))))
	}
	return nil
}

// momentScan is everything a search needs besides its filter.
type momentScan struct {
	src     walSource
	waldump string // the cluster's pg_waldump
	wrap    []string
	dir     string // private work directory (created and removed by the caller)
	segSize int64
	major   int
	tli     uint32 // the cluster's current timeline
	cat     *relCatalog
	now     time.Time
	// stopAt is when to stop reading and report what was found, leaving
	// time to report before the task's deadline.
	stopAt time.Time
}

// findMoment runs a find_moment task.
func (a *Agent) findMoment(ctx context.Context, db protocol.DatabaseSpec, p protocol.FindMomentParams, tl *taskLog) (*protocol.FindMomentResult, error) {
	f, err := normalizeMoment(p, time.Now())
	if err != nil {
		return nil, err
	}
	prod, err := pginspect.Inspect(ctx, a.target(db))
	if err != nil {
		return nil, err
	}
	sc := momentScan{major: prod.Major(), waldump: a.cfg.pgBin(prod.Major(), "pg_waldump"), wrap: niceWrap()}
	if _, err := os.Stat(sc.waldump); err != nil {
		return nil, fmt.Errorf("pg_waldump for PostgreSQL %d isn't installed at %s: install PostgreSQL %d's server package on this host (it comes with it)",
			sc.major, sc.waldump, sc.major)
	}
	if err := a.writeConfig(db, prod); err != nil {
		return nil, err
	}
	fetchCLI := a.cli(db)
	fetchCLI.Wrap = niceWrap() // low CPU and IO priority, like backups
	sc.src = repoSource{cli: fetchCLI}

	conn, err := a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return nil, err
	}
	var inRecovery bool
	err = conn.QueryRow(ctx, `SELECT pg_size_bytes(current_setting('wal_segment_size')), pg_is_in_recovery()`).Scan(&sc.segSize, &inRecovery)
	var notes []string
	if err == nil && !inRecovery {
		var walFile string
		if err = conn.QueryRow(ctx, `SELECT pg_walfile_name(pg_current_wal_lsn())`).Scan(&walFile); err == nil {
			if t, perr := strconv.ParseUint(walFile[:8], 16, 32); perr == nil {
				sc.tli = uint32(t)
			}
		}
		// The newest changes are still in the current segment: hand it to
		// the repository now if the search reaches the last minutes.
		if err == nil && time.Since(f.to) < 3*time.Minute {
			if n := a.switchForMoment(ctx, db, conn, tl); n != "" {
				notes = append(notes, n)
			}
		}
	}
	closeConn(ctx, conn)
	if err != nil {
		return nil, err
	}
	if sc.cat, err = a.snapshotRelNames(ctx, db); err != nil {
		return nil, fmt.Errorf("reading the table names: %w", err)
	}
	if f.db != "" && !slices.Contains(mapValues(sc.cat.dbNames), f.db) {
		return nil, fmt.Errorf("there is no database named %q on this server", f.db)
	}

	root := filepath.Join(a.cfg.StateDir, "moment")
	// One search runs at a time (it runs in the side lane): anything here
	// is left over from an interrupted one.
	_ = os.RemoveAll(root)
	sc.dir = filepath.Join(root, "wal")
	if err := os.MkdirAll(sc.dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(root)
	need := int64(momentBatch*4+4)*sc.segSize + 256<<20
	if free, err := freeBytes(root); err == nil && free < need {
		return nil, fmt.Errorf("not enough free disk to read the change log: %s free in %s, and the search needs about %s",
			humanBytes(free), root, humanBytes(need))
	}
	sc.now = time.Now().UTC()
	res, err := sc.run(ctx, f, tl)
	if res != nil {
		res.Notes = append(notes, res.Notes...)
		tl.Printf("%s", res.Summary)
	}
	return res, err
}

func mapValues[K comparable, V any](m map[K]V) []V {
	out := make([]V, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// switchForMoment closes the current WAL segment so the latest changes
// reach the repository, and waits a little for them. It returns a note
// when they didn't arrive in time.
func (a *Agent) switchForMoment(ctx context.Context, db protocol.DatabaseSpec, conn *pgx.Conn, tl *taskLog) string {
	const late = "The last minute of changes may be missing: it hadn't reached your storage when the search started."
	var walFile string
	if err := conn.QueryRow(ctx, `SELECT pg_walfile_name(pg_switch_wal())`).Scan(&walFile); err != nil {
		tl.Printf("switching WAL segments: %v", err)
		return late
	}
	archivedCtx, cancel := context.WithTimeout(ctx, momentSwitchWait)
	defer cancel()
	_, err := waitArchived(archivedCtx, conn, walFile, momentSwitchWait, tl)
	if err == nil && a.pusher != nil {
		err = a.confirmInRepository(archivedCtx, db, walFile, tl)
	}
	if err != nil {
		tl.Printf("waiting for %s to reach the repository: %v", walFile, err)
		return late
	}
	return ""
}

// run searches the range.
func (sc momentScan) run(ctx context.Context, f momentFilter, tl *taskLog) (*protocol.FindMomentResult, error) {
	start := time.Now()
	if dl, ok := ctx.Deadline(); ok {
		sc.stopAt = dl.Add(-min(3*time.Minute, time.Until(dl)/5))
	}
	list, err := sc.src.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("Rowsafe can't list the change log in your storage: %w", err)
	}
	id := pgbackrest.LatestArchiveID(list, sc.major)
	var segs []pgbackrest.ArchivedSegment
	for _, s := range list {
		if s.ArchiveID == id && !s.History {
			segs = append(segs, s)
		}
	}
	if len(segs) == 0 {
		return nil, errors.New("there is no change log (WAL) in your storage yet: it starts with the first backup")
	}
	if sc.tli == 0 {
		for _, s := range segs {
			sc.tli = max(sc.tli, s.Timeline)
		}
	}
	history, err := sc.history(ctx, list, id)
	if err != nil {
		return nil, err
	}
	chain := chooseSegments(segs, sc.segSize, sc.tli, history)
	picked, notes, from := pickSegments(chain, f.from, f.to)
	col := newMomentCollector(f, sc.cat)
	res := &protocol.FindMomentResult{From: f.from, To: f.to}
	if len(picked) == 0 {
		res.Notes = append(res.Notes, notes...)
		col.finish()
		out := col.result()
		out.From, out.To, out.Notes = f.from, f.to, append(notes, out.Notes...)
		out.Summary = momentsSummary(out)
		return &out, nil
	}
	tl.Printf("reading %d WAL segments (%s in the repository) for %s to %s", len(picked), humanBytes(sumSize(picked)),
		f.from.Format(time.RFC3339), f.to.Format(time.RFC3339))

	wal := newWalScanner(sc.major, col.commit)
	var segments int
	var scanErr error
	for _, run := range walRuns(picked, sc.segSize) {
		n, err := sc.scanRun(ctx, run, wal, tl)
		segments += n
		if err != nil {
			scanErr = err
			break
		}
	}
	col.finish()
	out := col.result()
	out.From, out.To = f.from, f.to
	if from.After(f.from) {
		out.From = from
	}
	if !wal.LastTime.IsZero() && wal.LastTime.Before(f.to) && sc.now.Sub(f.to) < 10*time.Minute {
		// The newest changes haven't reached the repository.
		out.To = wal.LastTime
		if f.to.Sub(wal.LastTime) > 2*time.Minute {
			notes = append(notes, fmt.Sprintf("Changes after %s haven't reached your storage yet, so they aren't included.",
				wal.LastTime.Format("15:04:05 UTC")))
		}
	}
	out.Segments = segments
	out.WALBytes = int64(segments) * sc.segSize
	out.DurationMs = time.Since(start).Milliseconds()
	out.Notes = append(notes, out.Notes...)
	if scanErr != nil {
		if ctx.Err() == nil && !errors.Is(scanErr, errMomentTime) {
			return nil, scanErr
		}
		out.To = cmp.Or(wal.LastTime, out.From)
		out.Notes = append(out.Notes, fmt.Sprintf("The search ran out of time and stopped at %s; search a shorter range to see the rest.",
			out.To.Format("15:04:05 UTC")))
	}
	out.Summary = momentsSummary(out)
	return &out, nil
}

var errMomentTime = errors.New("out of time")

func sumSize(segs []pgbackrest.ArchivedSegment) int64 {
	var n int64
	for _, s := range segs {
		n += s.Size
	}
	return n
}

// history reads the current timeline's history file: the timelines it
// descends from and where each ended.
func (sc momentScan) history(ctx context.Context, list []pgbackrest.ArchivedSegment, id string) (map[uint32]uint64, error) {
	out := map[uint32]uint64{}
	if sc.tli <= 1 {
		return out, nil
	}
	name := fmt.Sprintf("%08X.history", sc.tli)
	if !slices.ContainsFunc(list, func(s pgbackrest.ArchivedSegment) bool { return s.History && s.Name == name && s.ArchiveID == id }) {
		return out, nil
	}
	dest := filepath.Join(sc.dir, name)
	if err := sc.src.Fetch(ctx, name, dest); err != nil {
		return nil, fmt.Errorf("fetching the timeline history: %w", err)
	}
	data, err := os.ReadFile(dest)
	_ = os.Remove(dest)
	if err != nil {
		return nil, err
	}
	return parseTimelineHistory(data), nil
}

// parseTimelineHistory reads "1\t0/3000000\tno recovery target specified"
// lines: parent timeline and where it ended.
func parseTimelineHistory(data []byte) map[uint32]uint64 {
	out := map[uint32]uint64{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		tli, err := strconv.ParseUint(f[0], 10, 32)
		lsn, ok := parseLSN(f[1])
		if err == nil && ok {
			out[uint32(tli)] = lsn
		}
	}
	return out
}

// chooseSegments keeps, for every segment number, the copy on the current
// timeline or the newest ancestor that reached it: the history the
// database has now (segments of abandoned timelines are skipped). The
// result is in segment order.
func chooseSegments(segs []pgbackrest.ArchivedSegment, segSize int64, tli uint32, ancestors map[uint32]uint64) []pgbackrest.ArchivedSegment {
	best := map[uint64]pgbackrest.ArchivedSegment{}
	for _, s := range segs {
		n, ok := pgbackrest.SegmentNumber(s.Name, segSize)
		if !ok {
			continue
		}
		if s.Timeline != tli {
			end, ok := ancestors[s.Timeline]
			if !ok || n > end/uint64(segSize) {
				continue
			}
		}
		if cur, ok := best[n]; !ok || s.Timeline > cur.Timeline {
			best[n] = s
		}
	}
	out := make([]pgbackrest.ArchivedSegment, 0, len(best))
	for _, s := range best {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b pgbackrest.ArchivedSegment) int {
		na, _ := pgbackrest.SegmentNumber(a.Name, segSize)
		nb, _ := pgbackrest.SegmentNumber(b.Name, segSize)
		return cmp.Compare(na, nb)
	})
	return out
}

// pickSegments picks the segments that hold the range. A segment holds
// what was written up to the time the repository received it, so the range
// starts with the first segment received at or after from (one earlier, for
// transactions that started before) and ends with the first received well
// after to. Over the size limits the most recent part is read. from is
// where the picked WAL starts, when that's after the asked start.
func pickSegments(chain []pgbackrest.ArchivedSegment, from, to time.Time) (picked []pgbackrest.ArchivedSegment, notes []string, start time.Time) {
	if len(chain) == 0 {
		return nil, nil, time.Time{}
	}
	first := len(chain)
	for i, s := range chain {
		if !s.Time.Before(from) {
			first = i
			break
		}
	}
	if first == len(chain) {
		return nil, []string{fmt.Sprintf("Nothing reached your storage after %s.", from.Format("15:04 UTC on Jan 2"))}, time.Time{}
	}
	if first == 0 && chain[0].Time.After(from.Add(10*time.Minute)) {
		start = chain[0].Time
		notes = append(notes, fmt.Sprintf("The change log in your storage starts at %s (the oldest backup still kept), so the search starts there.",
			start.Format("15:04 UTC on Jan 2")))
	}
	first = max(first-1, 0)
	last := len(chain) - 1
	for i := first; i < len(chain); i++ {
		if chain[i].Time.After(to.Add(6 * time.Minute)) {
			last = i
			break
		}
	}
	picked = chain[first : last+1]
	var bytes int64
	cut := 0
	for i := len(picked) - 1; i >= 0; i-- {
		bytes += picked[i].Size
		if len(picked)-i > momentMaxSegments || bytes > momentMaxRepoBytes {
			cut = i + 1
			break
		}
	}
	if cut > 0 {
		start = picked[cut-1].Time
		picked = picked[cut:]
		notes = append(notes, fmt.Sprintf("That range holds a lot of changes; Rowsafe searched the most recent part, from %s on. Pick a shorter range to search earlier.",
			start.Format("15:04 UTC on Jan 2")))
	}
	return picked, notes, start
}

// walRun is a stretch of consecutive segments on one timeline.
type walRun struct {
	tli         uint32
	first, last uint64 // segment numbers
	names       map[uint64]string
	segSize     int64
}

func walRuns(segs []pgbackrest.ArchivedSegment, segSize int64) []walRun {
	var out []walRun
	for _, s := range segs {
		n, _ := pgbackrest.SegmentNumber(s.Name, segSize)
		if k := len(out) - 1; k >= 0 && out[k].tli == s.Timeline && out[k].last+1 == n {
			out[k].last = n
			out[k].names[n] = s.Name
			continue
		}
		out = append(out, walRun{tli: s.Timeline, first: n, last: n, names: map[uint64]string{n: s.Name}, segSize: segSize})
	}
	return out
}

// scanRun fetches and reads one run, a batch of segments at a time. It
// returns how many segments were read.
func (sc momentScan) scanRun(ctx context.Context, run walRun, wal *walScanner, tl *taskLog) (int, error) {
	segSize := uint64(sc.segSize)
	cur := run.first   // lowest segment still needed
	fetched := cur - 1 // highest segment in the directory
	startLSN := cur * segSize
	if wal.LastLSN >= startLSN {
		startLSN = wal.LastLSN
		cur = startLSN / segSize
		fetched = cur - 1
	}
	batch := momentBatch
	read := 0
	defer func() {
		for n := cur; n <= fetched; n++ {
			_ = os.Remove(filepath.Join(sc.dir, run.names[n]))
		}
	}()
	for {
		if !sc.stopAt.IsZero() && time.Now().After(sc.stopAt) {
			return read, errMomentTime
		}
		want := min(run.last, cur+uint64(batch)-1)
		if want > fetched || fetched+1 == cur {
			if err := sc.fetch(ctx, run, fetched+1, want); err != nil {
				return read, err
			}
			read += int(want - fetched)
			fetched = want
		}
		before := wal.LastLSN
		wal.skipTo = wal.LastLSN
		if err := sc.dump(ctx, run.tli, startLSN, wal); err != nil {
			return read, err
		}
		if fetched == run.last {
			return read, nil // pg_waldump had the whole run
		}
		if wal.LastLSN <= before {
			// A record longer than the batch: fetch more before reading on.
			if batch >= 64 {
				return read, fmt.Errorf("pg_waldump made no progress at %s", formatLSN(startLSN))
			}
			batch *= 2
			continue
		}
		startLSN = wal.LastLSN
		next := startLSN / segSize
		for n := cur; n < next; n++ {
			_ = os.Remove(filepath.Join(sc.dir, run.names[n]))
		}
		cur = max(cur, next)
		if fetched < cur {
			fetched = cur - 1
		}
	}
}

// fetch gets segments [from, to] of a run into the work directory, a few
// at a time. Each lands under a temporary name first, so pg_waldump never
// sees half a file.
func (sc momentScan) fetch(ctx context.Context, run walRun, from, to uint64) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sem := make(chan struct{}, momentFetchers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var first error
	for n := from; n <= to; n++ {
		name := run.names[n]
		if name == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			tmp := filepath.Join(sc.dir, "."+name+".part")
			err := sc.src.Fetch(ctx, name, tmp)
			if err == nil {
				err = os.Rename(tmp, filepath.Join(sc.dir, name))
			} else {
				_ = os.Remove(tmp)
			}
			if err != nil {
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("fetching WAL segment %s from your storage: %w", name, err)
					cancel()
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return first
}

// dump runs pg_waldump from start over the segments in the work
// directory and streams its lines into the scanner. It stops by itself at
// the first segment that isn't there; that error is expected.
func (sc momentScan) dump(ctx context.Context, tli uint32, start uint64, wal *walScanner) error {
	args := []string{"--path=" + sc.dir, "--timeline=" + strconv.FormatUint(uint64(tli), 10), "--start=" + formatLSN(start)}
	name := sc.waldump
	if len(sc.wrap) > 0 {
		args = append(append(append([]string{}, sc.wrap[1:]...), sc.waldump), args...)
		name = sc.wrap[0]
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C", "LANG=C")
	cmd.WaitDelay = 5 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &limitedBuffer{buf: &stderr, max: 8192}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting pg_waldump: %w", err)
	}
	records := wal.Records
	r := bufio.NewReaderSize(out, 1<<20)
	for {
		line, err := r.ReadSlice('\n')
		if len(line) > 0 {
			wal.Line(string(bytes.TrimRight(line, "\n")))
		}
		if err == bufio.ErrBufferFull {
			// An absurdly long line (thousands of block references): skip
			// the rest of it.
			for err == bufio.ErrBufferFull {
				_, err = r.ReadSlice('\n')
			}
		}
		if err != nil {
			break
		}
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if werr != nil && wal.Records == records {
		msg := strings.TrimSpace(stderr.String())
		// Reaching the end of the fetched WAL is how it stops.
		if strings.Contains(msg, "could not find file") || strings.Contains(msg, "could not find a valid record") ||
			strings.Contains(msg, "invalid record length") || strings.Contains(msg, "error in WAL record") {
			return nil
		}
		return fmt.Errorf("pg_waldump: %v: %s", werr, msg)
	}
	return nil
}

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// momentsSummary: "Found 3 changes between 14:00 and 15:00 UTC. The
// biggest: 1,204 rows deleted from applications at 14:05:37."
func momentsSummary(r protocol.FindMomentResult) string {
	span := spanText(r.From, r.To)
	if len(r.Moments) == 0 {
		return "No deletes, updates, TRUNCATEs or DROPs matched " + span + "."
	}
	big := slices.MinFunc(r.Moments, momentRank)
	s := fmt.Sprintf("Found %s %s.", nplural(r.Transactions, "transaction with matching changes", "transactions with matching changes"), span)
	return s + fmt.Sprintf(" The biggest: %s at %s.", lowerFirst(big.Summary), big.Time.Format("15:04:05 UTC"))
}

// spanText: "between 14:00 and 15:00 UTC on Sep 24" (seconds when both are
// in the same minute; both dates when they differ).
func spanText(from, to time.Time) string {
	from, to = from.UTC(), to.UTC()
	layout := "15:04"
	if from.Truncate(time.Minute).Equal(to.Truncate(time.Minute)) {
		layout = "15:04:05"
	}
	if from.Format("2006-01-02") == to.Format("2006-01-02") {
		return fmt.Sprintf("between %s and %s UTC on %s", from.Format(layout), to.Format(layout), to.Format("Jan 2"))
	}
	return fmt.Sprintf("between %s UTC on %s and %s UTC on %s", from.Format(layout), from.Format("Jan 2"), to.Format(layout), to.Format("Jan 2"))
}

func lowerFirst(s string) string {
	if strings.HasPrefix(s, "Table ") || strings.HasPrefix(s, "Database ") || strings.HasPrefix(s, "A table") {
		return strings.ToLower(s[:1]) + s[1:]
	}
	return s
}
