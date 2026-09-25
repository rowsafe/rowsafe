package mysql

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Binary log shipping. The agent reads the server's binary log files
// (MySQL keeps writing the current one) and uploads what is new, in pieces
// named by their byte range, compressed and encrypted like backups:
//
//   - a finished file is uploaded right away;
//   - the file being written is uploaded once 16 MiB are waiting, or when
//     the oldest waiting bytes are 50 seconds old, so the bucket is at most
//     about a minute behind, like PostgreSQL's archive_timeout, without
//     asking the server to switch files (no FLUSH BINARY LOGS: a quiet
//     server uploads nothing and a busy one isn't disturbed);
//   - a Mark or a check asks for an upload now and waits for it.
//
// It runs as long as the agent does, one goroutine per database, started by
// the heartbeat's Archiver call; what was uploaded is kept in the engine's
// state directory and, if that is lost, found again by listing the bucket.

var (
	shipPoll     = 10 * time.Second
	shipMaxDelay = 50 * time.Second
	shipMaxBytes = int64(16 << 20)
	// shipIdleStop stops a shipper whose database is no longer watched.
	shipIdleStop = 10 * time.Minute
)

type shipState struct {
	// Files is how many bytes of each file are in the bucket, by bucket
	// folder (binlogFile.dir()).
	Files map[string]int64 `json:"files"`
	// Start is the first file shipped: earlier ones are not needed.
	Start string `json:"start,omitempty"`
	// Gap explains binary logs lost before they were shipped; the next
	// full backup clears it.
	Gap           string     `json:"gap,omitempty"`
	ArchivedCount int64      `json:"archived_count"`
	FailedCount   int64      `json:"failed_count"`
	LastFailedAt  *time.Time `json:"last_failed_at,omitempty"`
}

// serverError: the server couldn't be queried (reported as the archiver's
// Error, which the control plane reads as "database unreachable").
type serverError struct{ err error }

func (e *serverError) Error() string { return e.err.Error() }
func (e *serverError) Unwrap() error { return e.err }

// errLogBinOff: nothing to ship until the server restarts with the binary
// log on (ArchiveMode "off"); not a failure.
var errLogBinOff = errors.New("the binary log is off")

// shipper ships one database's binary logs.
type shipper struct {
	mu        sync.Mutex
	srv       *server // the newest view (env, spec)
	state     shipState
	statePath string
	loaded    bool
	created   map[string]binlogFile // server file name -> identity (cache)
	pending   map[string]time.Time  // bucket folder -> since when bytes wait
	caughtUp  *time.Time            // everything written before this is shipped
	lastErr   string
	connErr   bool // lastErr: the server couldn't be queried
	logOn     bool   // the server's log_bin, as last seen
	lastFile  string // current file, as last seen
	lastWAL   string // last shipped piece, for the report
	polled    bool
	seen      time.Time
	force     bool
	wake      chan struct{}
	done      chan struct{} // closed when the goroutine stops
	store     *objStore
	db        *sql.DB
}

var (
	shippersMu sync.Mutex
	shippers   = map[string]*shipper{}
)

// shipperFor returns the database's shipper, starting it if needed.
func shipperFor(s *server) *shipper {
	shippersMu.Lock()
	defer shippersMu.Unlock()
	sh := shippers[s.db.ID]
	if sh != nil {
		select {
		case <-sh.done:
			sh = nil // it stopped (idle); start again
		default:
		}
	}
	if sh == nil {
		sh = &shipper{
			statePath: filepath.Join(s.env.StateDir, "ship-"+s.db.ID+".json"),
			created:   map[string]binlogFile{}, pending: map[string]time.Time{},
			wake: make(chan struct{}, 1), done: make(chan struct{}),
		}
		shippers[s.db.ID] = sh
		sh.srv = s
		sh.seen = time.Now()
		go sh.run()
	}
	sh.mu.Lock()
	sh.srv, sh.seen = s, time.Now()
	sh.mu.Unlock()
	return sh
}

func (sh *shipper) log() *slog.Logger {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.srv.env.Log.With("database_id", sh.srv.db.ID)
}

func (sh *shipper) run() {
	defer close(sh.done)
	defer func() {
		if sh.db != nil {
			sh.db.Close()
		}
	}()
	ctx := context.Background()
	for {
		sh.poll(ctx)
		sh.mu.Lock()
		idle := time.Since(sh.seen) > shipIdleStop
		sh.mu.Unlock()
		if idle {
			return
		}
		select {
		case <-time.After(shipPoll):
		case <-sh.wake:
		}
	}
}

// kick asks for a poll now; force uploads whatever waits.
func (sh *shipper) kick(force bool) {
	sh.mu.Lock()
	sh.force = sh.force || force
	sh.mu.Unlock()
	select {
	case sh.wake <- struct{}{}:
	default:
	}
}

func (sh *shipper) loadState(ctx context.Context, st *objStore) error {
	if sh.loaded {
		return nil
	}
	sh.state = shipState{Files: map[string]int64{}}
	if b, err := os.ReadFile(sh.statePath); err == nil {
		_ = json.Unmarshal(b, &sh.state)
		if sh.state.Files == nil {
			sh.state.Files = map[string]int64{}
		}
		sh.loaded = true
		return nil
	}
	// No local state: what is already in the bucket counts.
	objs, err := st.list(ctx, "binlogs/")
	if err != nil {
		return err
	}
	idx := indexBinlogs(objs)
	for f := range idx {
		_, end := idx.contiguous(f)
		sh.state.Files[f.dir()] = end
		if sh.state.Start == "" || seqLess(f.Name, sh.state.Start) {
			sh.state.Start = f.Name
		}
	}
	sh.loaded = true
	return nil
}

func seqLess(a, b string) bool {
	_, na, _ := binlogSeq(a)
	_, nb, _ := binlogSeq(b)
	return na < nb
}

func (sh *shipper) saveState() {
	b, _ := json.MarshalIndent(sh.state, "", "  ")
	if err := os.MkdirAll(filepath.Dir(sh.statePath), 0o700); err == nil {
		_ = writeFileAtomic(sh.statePath, b, 0o600)
	}
}

// poll uploads what is due.
func (sh *shipper) poll(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	err := sh.pollOnce(ctx)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sh.polled = true
	var ce *serverError
	sh.connErr = errors.As(err, &ce)
	if errors.Is(err, errLogBinOff) {
		sh.lastErr = ""
		return
	}
	if err != nil {
		if sh.lastErr == "" || sh.lastErr != err.Error() {
			sh.srv.env.Log.Warn("binary log shipping failed", "database_id", sh.srv.db.ID, "err", err)
		}
		sh.lastErr = err.Error()
		now := time.Now().UTC()
		if !sh.connErr {
			sh.state.FailedCount++
			sh.state.LastFailedAt = &now
		}
		sh.saveState()
		if sh.db != nil {
			sh.db.Close()
			sh.db = nil
		}
		return
	}
	sh.lastErr = ""
}

func (sh *shipper) pollOnce(ctx context.Context) error {
	sh.mu.Lock()
	s := sh.srv
	force := sh.force
	sh.force = false
	sh.mu.Unlock()

	if sh.store == nil {
		st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
		if err != nil {
			return err
		}
		sh.store = st
	}
	if err := sh.loadState(ctx, sh.store); err != nil {
		return err
	}
	if sh.db == nil {
		db, err := s.open(ctx)
		if err != nil {
			return &serverError{err}
		}
		sh.db = db
	}
	var logBin int
	var basename sql.NullString
	if err := sh.db.QueryRowContext(ctx, "SELECT @@log_bin, @@log_bin_basename").Scan(&logBin, &basename); err != nil {
		return &serverError{err}
	}
	sh.mu.Lock()
	sh.logOn = logBin == 1
	sh.mu.Unlock()
	if logBin != 1 {
		return errLogBinOff
	}
	files, err := showBinaryLogs(ctx, sh.db)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("the server lists no binary logs")
	}
	dir := filepath.Dir(basename.String)
	now := time.Now()

	sh.mu.Lock()
	start := sh.state.Start
	sh.mu.Unlock()
	if start == "" {
		// First run: ship from the current file on; backups taken from now
		// on only need binary logs written after them.
		start = files[len(files)-1].Name
		sh.mu.Lock()
		sh.state.Start = start
		sh.mu.Unlock()
	}
	// Files purged before they were shipped leave a gap.
	if seqLess(start, files[0].Name) {
		sh.noteGap(fmt.Sprintf("binary logs before %s were removed from the server before Rowsafe copied them", files[0].Name))
		sh.mu.Lock()
		sh.state.Start = files[0].Name
		sh.mu.Unlock()
		start = files[0].Name
	}
	var oldestPending *time.Time
	current := files[len(files)-1].Name
	for i, f := range files {
		if seqLess(f.Name, start) {
			continue
		}
		id, err := sh.identity(dir, f.Name)
		if err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("can't read the binary log %s (%v): the agent must be able to read the server's binary log folder%s",
					filepath.Join(dir, f.Name), err, sidecarHint(s))
			}
			return err
		}
		key := id.dir()
		sh.mu.Lock()
		shipped := sh.state.Files[key]
		sh.mu.Unlock()
		if f.Size < shipped {
			return fmt.Errorf("the binary log %s is shorter (%d bytes) than what was already shipped (%d)", f.Name, f.Size, shipped)
		}
		if f.Size == shipped {
			delete(sh.pending, key)
			continue
		}
		last := i == len(files)-1
		since, waiting := sh.pending[key]
		if !waiting {
			since = now
			sh.pending[key] = since
		}
		due := !last || force || f.Size-shipped >= shipMaxBytes || now.Sub(since) >= shipMaxDelay
		if !due {
			if oldestPending == nil || since.Before(*oldestPending) {
				t := since
				oldestPending = &t
			}
			continue
		}
		if err := sh.upload(ctx, dir, id, shipped, f.Size); err != nil {
			if oldestPending == nil || since.Before(*oldestPending) {
				t := since
				oldestPending = &t
			}
			return err
		}
		delete(sh.pending, key)
	}
	sh.mu.Lock()
	defer sh.mu.Unlock()
	// Forget files the server no longer has.
	onServer := map[string]bool{}
	for _, f := range files {
		if id, ok := sh.created[f.Name]; ok {
			onServer[id.dir()] = true
		}
	}
	for k := range sh.state.Files {
		if !onServer[k] {
			delete(sh.state.Files, k)
		}
	}
	for name := range sh.created {
		found := false
		for _, f := range files {
			found = found || f.Name == name
		}
		if !found {
			delete(sh.created, name)
		}
	}
	caught := now.UTC()
	if oldestPending != nil {
		caught = oldestPending.UTC()
	}
	sh.caughtUp = &caught
	sh.lastFile = current
	sh.saveState()
	return nil
}

func sidecarHint(s *server) string {
	if s.env.Config.Sidecar() {
		return ": mount the server's data volume into the agent container at the same path (read-only is fine)"
	}
	return ""
}

// identity reads (and caches) a file's creation time.
func (sh *shipper) identity(dir, name string) (binlogFile, error) {
	sh.mu.Lock()
	id, ok := sh.created[name]
	sh.mu.Unlock()
	if ok {
		return id, nil
	}
	created, err := readBinlogCreated(filepath.Join(dir, name))
	if err != nil {
		return binlogFile{}, err
	}
	id = binlogFile{Name: name, Created: created}
	sh.mu.Lock()
	sh.created[name] = id
	sh.mu.Unlock()
	return id, nil
}

// upload ships bytes [from, to) of a file.
func (sh *shipper) upload(ctx context.Context, dir string, id binlogFile, from, to int64) error {
	f, err := os.Open(filepath.Join(dir, id.Name))
	if err != nil {
		return err
	}
	defer f.Close()
	key := chunkKey(id, from, to)
	n, _, err := sh.store.put(ctx, key, io.NewSectionReader(f, from, to-from))
	if err != nil {
		return err
	}
	if n != to-from {
		return fmt.Errorf("read %d bytes of %s instead of %d", n, id.Name, to-from)
	}
	sh.mu.Lock()
	sh.state.Files[id.dir()] = to
	sh.state.ArchivedCount++
	sh.lastWAL = fmt.Sprintf("%s:%d", id.Name, to)
	sh.saveState()
	sh.mu.Unlock()
	return nil
}

func (sh *shipper) noteGap(msg string) {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.state.Gap == "" {
		sh.state.Gap = msg + "; restores to points before the next full backup may not be possible. Rowsafe takes a full backup to fix this."
		now := time.Now().UTC()
		sh.state.FailedCount++
		sh.state.LastFailedAt = &now
		sh.srv.env.Log.Warn("binary log gap", "database_id", sh.srv.db.ID, "gap", msg)
	}
}

// clearGap: a full backup started after the gap.
func (sh *shipper) clearGap() {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if sh.state.Gap != "" {
		sh.state.Gap = ""
		sh.saveState()
	}
}

// gap is the current gap message, if any.
func (sh *shipper) gap() string {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.state.Gap
}

// shippedUpTo reports whether pos is in the bucket.
func (sh *shipper) shippedUpTo(p position) bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	id := p.File
	if id.Created == 0 {
		var ok bool
		if id, ok = sh.created[p.File.Name]; !ok {
			return false
		}
	}
	return sh.state.Files[id.dir()] >= p.Pos
}

// waitShipped uploads now and waits until pos is in the bucket.
func (sh *shipper) waitShipped(ctx context.Context, p position, timeout time.Duration) (time.Time, error) {
	deadline := time.Now().Add(timeout)
	for {
		sh.kick(true)
		if sh.shippedUpTo(p) {
			return time.Now().UTC(), nil
		}
		if time.Now().After(deadline) {
			sh.mu.Lock()
			e := sh.lastErr
			sh.mu.Unlock()
			if e != "" {
				return time.Time{}, fmt.Errorf("not in the bucket after %s: %s", timeout, e)
			}
			return time.Time{}, fmt.Errorf("not in the bucket after %s", timeout)
		}
		select {
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// stats is the heartbeat's report (nil until the first poll).
func (sh *shipper) stats() *protocol.ArchiverStats {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if !sh.polled {
		return nil
	}
	st := &protocol.ArchiverStats{
		ArchivedCount: sh.state.ArchivedCount, FailedCount: sh.state.FailedCount,
		LastArchivedTime: sh.caughtUp, LastFailedTime: sh.state.LastFailedAt,
		LastPushedWAL: sh.lastWAL, PushFailedCount: sh.state.FailedCount,
		LastPushError: cmp.Or(sh.lastErr, sh.state.Gap),
	}
	if sh.connErr {
		st.Error, st.LastPushError = sh.lastErr, ""
	}
	if sh.logOn {
		st.ArchiveMode = "on"
	} else {
		st.ArchiveMode = "off"
	}
	return st
}

// archiver is the heartbeat's report for the database.
func (s *server) archiver(ctx context.Context) (*protocol.ArchiverStats, error) {
	return shipperFor(s).stats(), nil
}

// showBinaryLogs lists the server's binary logs, oldest first.
func showBinaryLogs(ctx context.Context, db *sql.DB) ([]serverBinlog, error) {
	rows, err := db.QueryContext(ctx, "SHOW BINARY LOGS")
	if err != nil {
		return nil, fmt.Errorf("listing binary logs: %w", err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []serverBinlog
	for rows.Next() {
		vals := make([]any, len(cols))
		var name string
		var size int64
		vals[0], vals[1] = &name, &size
		for i := 2; i < len(cols); i++ {
			vals[i] = new(sql.RawBytes)
		}
		if err := rows.Scan(vals...); err != nil {
			return nil, err
		}
		if !isBinlogName(name) {
			return nil, fmt.Errorf("unexpected binary log name %q", name)
		}
		out = append(out, serverBinlog{Name: name, Size: size})
	}
	sortBinlogs(out)
	return out, rows.Err()
}

// currentPosition is the server's binary log position now.
func (s *server) currentPosition(ctx context.Context, db *sql.DB) (position, error) {
	stmt := "SHOW BINARY LOG STATUS" // MySQL 8.4 (8.2+)
	if s.flavor.mariadb() {
		stmt = "SHOW MASTER STATUS"
	}
	rows, err := db.QueryContext(ctx, stmt)
	if err != nil && !s.flavor.mariadb() {
		rows, err = db.QueryContext(ctx, "SHOW MASTER STATUS") // MySQL 8.0
	}
	if err != nil {
		return position{}, fmt.Errorf("reading the binary log position: %w", err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	if !rows.Next() {
		return position{}, errors.New("the binary log is off")
	}
	vals := make([]any, len(cols))
	var p position
	var gtid sql.NullString
	for i, c := range cols {
		switch c {
		case "File":
			vals[i] = &p.File.Name
		case "Position":
			vals[i] = &p.Pos
		case "Executed_Gtid_Set":
			vals[i] = &gtid
		default:
			vals[i] = new(sql.RawBytes)
		}
	}
	if err := rows.Scan(vals...); err != nil {
		return position{}, err
	}
	p.GTIDSet = gtid.String
	if s.flavor.mariadb() {
		var g sql.NullString
		if err := db.QueryRowContext(ctx, "SELECT @@gtid_binlog_pos").Scan(&g); err == nil {
			p.GTIDSet = g.String
		}
	}
	return p, rows.Err()
}
