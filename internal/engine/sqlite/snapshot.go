package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Full copies (backups): SQLite's online backup API copies every page of
// the live file into a temporary file on the agent's disk, then it is
// checked (quick_check), its tables counted, and it is compressed,
// encrypted and uploaded. In WAL mode the copy reads one consistent
// snapshot, taken under the write lock at the stream's exact position, so
// restores carry it forward with the copied transactions; the app keeps
// reading and writing meanwhile. In rollback-journal mode the copy goes a
// few hundred pages at a time, each a short read, so the app's writes
// never wait long; when the app changes the file in between, SQLite starts
// the copy again.

const (
	walStepPages      = 2048 // pages per backup step in WAL mode (no lock is held between them)
	rollbackStepPages = 256  // pages per step in rollback mode (each step is a short shared lock)
	rollbackRestarts  = 12   // restarts before the last attempt holds one read transaction
	// rollbackHoldMax: the last attempt may make the app's writes wait for
	// one whole copy only for files this small.
	rollbackHoldMax = 256 << 20
)

// snapLock serializes the full copies of a database.
func (e *Engine) snapLock(id string) *sync.Mutex {
	l, _ := e.snapMu.LoadOrStore(baseID(id), &sync.Mutex{})
	return l.(*sync.Mutex)
}

// workDir is where a database's temporary files go (<state>/<stanza>).
func (e *Engine) workDir(env agent.EngineEnv, db protocol.DatabaseSpec) string {
	return filepath.Join(e.stateRootFor(env), db.Stanza)
}

// ensureSpace checks that dir's filesystem has need bytes free (and some
// room to spare).
func ensureSpace(dir string, need int64, what string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_, free, err := diskSpace(dir)
	if err != nil {
		return nil
	}
	if free < need+free/20+64<<20 {
		return fmt.Errorf("not enough room: %s needs about %s on this server (%s), and only %s is free there. Free some space and try again",
			what, humanBytes(need), dir, humanBytes(free))
	}
	return nil
}

// takeSnapshot takes a full copy of db into env's bucket. auto: the
// agent's own copy for a new generation (not a scheduled backup).
func (e *Engine) takeSnapshot(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, auto bool, tl agent.TaskLogger) (*snapDoc, error) {
	path := db.SocketDir
	if !protocol.SQLitePath(path) {
		return nil, fmt.Errorf("invalid database path %q", path)
	}
	l := e.snapLock(db.ID)
	l.Lock()
	defer l.Unlock()
	h, fi, err := readDBHeader(path)
	if err != nil {
		return nil, err
	}
	if fs := networkFS(filepath.Dir(path)); fs != "" {
		return nil, fmt.Errorf("the database is on a network filesystem (%s): SQLite's locking isn't reliable there, so Rowsafe doesn't back it up", fs)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	work := filepath.Join(e.workDir(env, db), "tmp")
	size := fi.Size() + fileSize(path+"-wal")
	if err := ensureSpace(work, size, "a backup of "+filepath.Base(path)); err != nil {
		return nil, err
	}
	started := time.Now().UTC()
	label := newLabel(started)
	tmp := filepath.Join(work, "snapshot-"+label+".db")
	defer removeDB(tmp)

	b, err := openDB(ctx, path, openOpts{Busy: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	defer b.Close()
	defer withInterrupt(ctx, b)()
	busy := e.busyFor(db.ID)
	mode, err := journalMode(b)
	if err != nil {
		busy.note(err)
		return nil, err
	}
	doc := snapDoc{Label: label, StartedAt: started, PageSize: h.PageSize, JournalMode: mode, Version: versionString(h.Version), Auto: auto}
	if mode == "wal" {
		s, _, err := e.shipperFor(env, db)
		if err != nil {
			return nil, err
		}
		res := s.request(ctx, "snapshot", b)
		if res.err != nil {
			return nil, fmt.Errorf("starting the copy: %w", res.err)
		}
		doc.Gen, doc.Pos, doc.At = res.gen, res.pos, res.at
		tl.Printf("copying %s at a consistent moment (change stream %s): your app keeps reading and writing meanwhile",
			humanBytes(size), lsn(res.gen, res.pos))
		err = backupSteps(ctx, b, tmp, walStepPages, 0, nil)
		rollback(b)
		if err != nil {
			busy.note(err)
			return nil, fmt.Errorf("copying the database: %w", err)
		}
	} else {
		doc.At = time.Now().UTC()
		tl.Printf("copying %s a few hundred pages at a time (rollback-journal mode: each step is a short read, so your app's writes wait at most a moment)", humanBytes(size))
		if err := backupRollback(ctx, b, tmp, size, busy, tl); err != nil {
			return nil, err
		}
		doc.At = time.Now().UTC()
	}

	tl.Printf("checking the copy's pages and counting its rows")
	check, err := inspectCopy(ctx, tmp, false)
	if err != nil {
		return nil, fmt.Errorf("checking the copy: %w", err)
	}
	doc.Tables, doc.Integrity = check.Tables, check.Integrity
	e.noteIntegrity(env, db, doc.At, check.Integrity)
	if check.Integrity != "ok" {
		tl.Printf("warning: SQLite's quick_check found a problem in the database: %s", check.Integrity)
	}
	f, err := os.Open(tmp)
	if err != nil {
		return nil, err
	}
	st, _ := f.Stat()
	doc.SizeBytes = st.Size()
	stored, err := r.putCompressed(ctx, snapKey(label, snapDataName), f)
	f.Close()
	if err != nil {
		_ = r.deleteSnapshot(context.WithoutCancel(ctx), label)
		return nil, fmt.Errorf("uploading the backup: %w", err)
	}
	doc.StoredBytes = stored
	doc.StoppedAt = time.Now().UTC()
	if err := r.putJSON(ctx, snapKey(label, snapDocName), doc); err != nil {
		_ = r.deleteSnapshot(context.WithoutCancel(ctx), label)
		return nil, fmt.Errorf("saving the backup's description: %w", err)
	}
	if doc.Gen != "" {
		if s, _, err := e.shipperFor(env, db); err == nil {
			s.snapshotTaken(doc.Gen)
		}
	}
	if err := retention(ctx, r, db, tl); err != nil {
		tl.Printf("note: removing old backups failed (%v); it is tried again after the next backup", err)
	}
	return &doc, nil
}

// backupSteps copies the "main" database of src into dst with the online
// backup API, n pages per step; pause runs between steps (nil: none).
// restartsMax > 0 stops after that many restarts (the source changed by
// another connection) with errTooBusy.
func backupSteps(ctx context.Context, src *sqlite3.Conn, dst string, n int, restartsMax int, pause func()) error {
	removeDB(dst)
	bk, err := src.BackupInit("main", dst)
	if err != nil {
		return err
	}
	defer bk.Close()
	restarts, prevRemaining := 0, -1
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		done, err := bk.Step(n)
		if done {
			return bk.Close()
		}
		if err != nil {
			if !isBusy(err) {
				return err
			}
			// The app holds the lock: wait a moment and go on.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		rem := bk.Remaining()
		if prevRemaining >= 0 && rem > prevRemaining {
			restarts++
			if restartsMax > 0 && restarts >= restartsMax {
				return errTooBusy
			}
		}
		prevRemaining = rem
		if pause != nil {
			pause()
		}
	}
}

var errTooBusy = errors.New("the database changed during every attempt to copy it")

// backupRollback copies a rollback-journal database a few pages at a time.
func backupRollback(ctx context.Context, b *sqlite3.Conn, tmp string, size int64, busy *busyCount, tl agent.TaskLogger) error {
	pause := func() { time.Sleep(5 * time.Millisecond) }
	err := backupSteps(ctx, b, tmp, rollbackStepPages, rollbackRestarts, pause)
	if err == nil {
		return nil
	}
	busy.note(err)
	if !errors.Is(err, errTooBusy) {
		return fmt.Errorf("copying the database: %w", err)
	}
	if size > rollbackHoldMax {
		return errors.New("your app changed the database during every attempt to copy it a little at a time. " +
			"Turn on continuous backups (WAL) in Pulse: copies then never depend on the app pausing. Rowsafe tries again on the next backup")
	}
	tl.Printf("the database changed during each attempt: copying it in one go (writes wait for about a second)")
	if err := beginRead(b); err != nil {
		busy.note(err)
		return err
	}
	defer rollback(b)
	if err := backupSteps(ctx, b, tmp, -1, 0, nil); err != nil {
		return fmt.Errorf("copying the database: %w", err)
	}
	return nil
}

// removeDB removes a database file the agent made and its side files.
func removeDB(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm", path + "-journal"} {
		_ = os.Remove(p)
	}
}

// copyCheck is what inspectCopy found.
type copyCheck struct {
	Tables    []tableCount
	Integrity string // "ok" or the first problem
	FKErrors  int64  // foreign_key_check rows (full only)
}

// inspectCopy checks a database file the agent made: quick_check (or, when
// full, integrity_check and foreign_key_check) and each table's rows.
func inspectCopy(ctx context.Context, path string, full bool) (copyCheck, error) {
	var out copyCheck
	c, err := openDB(ctx, path, openOpts{ReadOnly: true, Scratch: true})
	if err != nil {
		return out, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	check := `PRAGMA quick_check(1)`
	if full {
		check = `PRAGMA integrity_check(1)`
	}
	if out.Integrity, err = queryText(c, check); err != nil {
		if errors.Is(err, sqlite3.CORRUPT) || errors.Is(err, sqlite3.NOTADB) {
			out.Integrity = firstLine(err.Error())
		} else {
			return out, err
		}
	}
	if out.Integrity != "ok" {
		return out, nil
	}
	tables, err := userTables(c)
	if err != nil {
		return out, err
	}
	for _, t := range tables {
		if t.Virtual {
			continue
		}
		n, err := queryInt(c, `SELECT count(*) FROM main.`+quoteIdent(t.Name))
		if err != nil {
			return out, fmt.Errorf("counting %s: %w", t.Name, err)
		}
		out.Tables = append(out.Tables, tableCount{Name: t.Name, Rows: n})
	}
	if full {
		err := queryRows(c, `PRAGMA foreign_key_check`, func(*sqlite3.Stmt) error {
			out.FKErrors++
			return nil
		})
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// tableInfo is one table of the schema.
type tableInfo struct {
	Name         string
	Virtual      bool
	WithoutRowid bool
}

// userTables lists the tables of the main schema (no sqlite_ internals).
func userTables(c *sqlite3.Conn) ([]tableInfo, error) {
	var out []tableInfo
	err := queryRows(c, `SELECT name, coalesce(sql, '') FROM main.sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`,
		func(s *sqlite3.Stmt) error {
			sql := strings.ToUpper(s.ColumnText(1))
			out = append(out, tableInfo{Name: s.ColumnText(0), Virtual: strings.HasPrefix(strings.TrimSpace(sql), "CREATE VIRTUAL"),
				WithoutRowid: strings.Contains(sql, "WITHOUT ROWID")})
			return nil
		})
	return out, err
}

// retention keeps the newest RetentionFull backups (and the agent's own
// copies newer than the oldest of them), and the change segments they
// need; unfinished uploads older than a day go too.
func retention(ctx context.Context, r *repo, db protocol.DatabaseSpec, tl agent.TaskLogger) error {
	keep := max(db.RetentionFull, 1)
	snaps, unfinished, err := r.listSnapshots(ctx)
	if err != nil {
		return err
	}
	for _, l := range unfinished {
		if t, err := time.Parse("20060102-150405", strings.TrimSuffix(l, "F")); err == nil && time.Since(t) > 24*time.Hour {
			if err := r.deleteSnapshot(ctx, l); err != nil {
				return err
			}
		}
	}
	var regular []snapDoc
	for _, s := range snaps {
		if !s.Auto {
			regular = append(regular, s)
		}
	}
	var cutoff time.Time
	switch {
	case len(regular) > keep:
		cutoff = regular[len(regular)-keep].At
	case len(regular) > 0:
		cutoff = regular[0].At
	case len(snaps) > 2:
		cutoff = snaps[len(snaps)-2].At
	}
	var kept []snapDoc
	removed := 0
	for i, s := range snaps {
		if s.At.Before(cutoff) && i < len(snaps)-1 {
			if err := r.deleteSnapshot(ctx, s.Label); err != nil {
				return err
			}
			removed++
			continue
		}
		kept = append(kept, s)
	}
	// Change segments only the removed copies needed.
	segs, err := r.listSegments(ctx, "")
	if err != nil {
		return err
	}
	if len(segs) == 0 {
		if removed > 0 {
			tl.Printf("kept the newest %d backups: removed %d older ones", keep, removed)
		}
		return nil
	}
	newestGen := segs[len(segs)-1].Gen
	minPos := map[string]pos{}
	oldestGen := ""
	for _, s := range kept {
		if s.Gen == "" {
			continue
		}
		if p, ok := minPos[s.Gen]; !ok || s.Pos.Compare(p) < 0 {
			minPos[s.Gen] = s.Pos
		}
		if oldestGen == "" || s.Gen < oldestGen {
			oldestGen = s.Gen
		}
	}
	gone := 0
	gensGone := map[string]bool{}
	for _, sg := range segs {
		p, has := minPos[sg.Gen]
		drop := false
		switch {
		case has:
			drop = (pos{W: sg.W, Frame: sg.Last}).Compare(p) <= 0
		case sg.Gen == newestGen:
			// The stream being written: kept until a copy of it exists.
		default:
			drop = true
			gensGone[sg.Gen] = true
		}
		if drop {
			if err := r.st.Delete(ctx, sg.Key); err != nil {
				return err
			}
			gone++
		}
	}
	for g := range gensGone {
		_ = r.st.Delete(ctx, coveredKey(g))
	}
	if removed+gone > 0 {
		tl.Printf("kept the newest %d backups: removed %d older ones and %d change segments only they needed", keep, removed, gone)
	}
	return nil
}

// sortSnaps sorts copies by the moment they show.
func sortSnaps(s []snapDoc) { slices.SortFunc(s, func(a, b snapDoc) int { return a.At.Compare(b.At) }) }
