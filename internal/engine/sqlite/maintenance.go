package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Apply fix for SQLite (protocol.MaintSQLite*). Each is proposed by the
// control plane's health check, confirmed by a person when it disrupts
// anything, and checked again here before it runs.

func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	path := db.SocketDir
	if fs := networkFS(filepath.Dir(path)); fs != "" && p.Action != protocol.MaintSQLiteOptimize {
		return nil, fmt.Errorf("the database is on a network filesystem (%s): SQLite's locking isn't reliable there, so Rowsafe doesn't change it", fs)
	}
	var summary string
	var details []string
	var err error
	switch p.Action {
	case protocol.MaintSQLiteCheckpoint:
		summary, err = e.fixCheckpoint(ctx, env, db, tl)
	case protocol.MaintSQLiteVacuum:
		summary, details, err = e.fixVacuum(ctx, db, tl)
	case protocol.MaintSQLiteIncrementalVacuum:
		summary, err = e.fixIncrementalVacuum(ctx, db, tl)
	case protocol.MaintSQLiteOptimize:
		summary, details, err = e.fixOptimize(ctx, db, tl)
	case protocol.MaintSQLiteWAL:
		summary, err = e.fixWAL(ctx, env, db, tl)
	default:
		return nil, fmt.Errorf("%q isn't something Rowsafe does for SQLite databases", p.Action)
	}
	if err != nil {
		return nil, err
	}
	tl.Printf("%s", summary)
	return &protocol.MaintenanceResult{Action: p.Action, Summary: summary, Details: details, DurationMs: time.Since(start).Milliseconds()}, nil
}

// fixCheckpoint copies the waiting changes into the file and shrinks the
// -wal file, through the change copier (so nothing uncopied is lost).
func (e *Engine) fixCheckpoint(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (string, error) {
	h, _, err := readDBHeader(db.SocketDir)
	if err != nil {
		return "", err
	}
	if !h.WAL {
		return "This database isn't in WAL mode, so it has no -wal file to shrink.", nil
	}
	s, _, err := e.shipperFor(env, db)
	if err != nil {
		return "", err
	}
	tl.Printf("copying the waiting changes to your bucket first, then into the database file")
	res := s.request(ctx, "truncate", nil)
	if res.err != nil {
		return "", res.err
	}
	return res.note + " Rowsafe takes a fresh full backup now, so restores to any second carry on unbroken.", nil
}

func (e *Engine) fixVacuum(ctx context.Context, db protocol.DatabaseSpec, tl agent.TaskLogger) (string, []string, error) {
	path := db.SocketDir
	size := fileSize(path)
	if err := ensureSpace(filepath.Dir(path), size*12/10, "VACUUM (SQLite rebuilds the file next to it)"); err != nil {
		return "", nil, err
	}
	if err := ensureSpace(os.TempDir(), size, "VACUUM (SQLite builds the new file in the temporary folder first)"); err != nil {
		return "", nil, err
	}
	c, err := openDB(ctx, path, openOpts{Busy: 10 * time.Second})
	if err != nil {
		return "", nil, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	free, _ := queryInt(c, `PRAGMA main.freelist_count`)
	pages, _ := queryInt(c, `PRAGMA main.page_count`)
	ps, _ := queryInt(c, `PRAGMA main.page_size`)
	if free == 0 {
		return "The database has no free pages to give back: nothing to do.", nil, nil
	}
	tl.Printf("rebuilding %s to give %s back (%d of %d pages are free); your app's writes wait until it's done",
		humanBytes(size), humanBytes(free*ps), free, pages)
	t0 := time.Now()
	if err := c.Exec(`VACUUM`); err != nil {
		e.busyFor(db.ID).note(err)
		if isBusy(err) {
			return "", nil, errors.New("your app kept a transaction open, so VACUUM couldn't start; nothing changed. Try again in a quieter moment")
		}
		return "", nil, fmt.Errorf("VACUUM failed (the database is unchanged): %w", err)
	}
	after := fileSize(path)
	took := time.Since(t0).Round(time.Second)
	details := []string{fmt.Sprintf("took %s", took)}
	if strings.EqualFold(mustText(c, `PRAGMA main.journal_mode`), "wal") {
		details = append(details, "in WAL mode the rebuilt pages pass through the -wal file; Rowsafe copies them and checkpoints it")
	}
	return fmt.Sprintf("Rebuilt the database: %s before, %s now (writes waited %s).", humanBytes(size), humanBytes(after), took), details, nil
}

func mustText(c *sqlite3.Conn, q string) string {
	v, _ := queryText(c, q)
	return v
}

func (e *Engine) fixIncrementalVacuum(ctx context.Context, db protocol.DatabaseSpec, tl agent.TaskLogger) (string, error) {
	c, err := openDB(ctx, db.SocketDir, openOpts{Busy: 10 * time.Second})
	if err != nil {
		return "", err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	av, err := queryInt(c, `PRAGMA main.auto_vacuum`)
	if err != nil {
		return "", err
	}
	if av != 2 {
		return "", errors.New("this database doesn't use auto_vacuum=incremental, so it needs a full VACUUM instead")
	}
	free, _ := queryInt(c, `PRAGMA main.freelist_count`)
	ps, _ := queryInt(c, `PRAGMA main.page_size`)
	if free == 0 {
		return "The database has no free pages to give back: nothing to do.", nil
	}
	before := fileSize(db.SocketDir)
	if err := c.Exec(`PRAGMA main.incremental_vacuum`); err != nil {
		e.busyFor(db.ID).note(err)
		return "", fmt.Errorf("incremental vacuum failed (the database is unchanged): %w", err)
	}
	return fmt.Sprintf("Gave %s of free pages back (%d pages); the file was %s.", humanBytes(free*ps), free, humanBytes(before)), nil
}

func (e *Engine) fixOptimize(ctx context.Context, db protocol.DatabaseSpec, tl agent.TaskLogger) (string, []string, error) {
	c, err := openDB(ctx, db.SocketDir, openOpts{Busy: 10 * time.Second})
	if err != nil {
		return "", nil, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	stale, err := staleTables(c)
	if err != nil {
		return "", nil, err
	}
	if len(stale) == 0 {
		return "The query planner's statistics are up to date: nothing to do.", nil, nil
	}
	// A bounded ANALYZE: SQLite samples at most this many rows per index,
	// so even large tables take moments.
	if err := c.Exec(`PRAGMA analysis_limit = 1000`); err != nil {
		return "", nil, err
	}
	if err := c.Exec(`PRAGMA optimize(0x10002)`); err != nil {
		e.busyFor(db.ID).note(err)
		return "", nil, fmt.Errorf("refreshing the statistics failed: %w", err)
	}
	return fmt.Sprintf("Refreshed the query planner's statistics for %d tables.", len(stale)), stale, nil
}

func (e *Engine) fixWAL(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, tl agent.TaskLogger) (string, error) {
	path := db.SocketDir
	h, _, err := readDBHeader(path)
	if err != nil {
		return "", err
	}
	if h.WAL {
		return "Continuous backups were already possible: the database is in WAL mode.", nil
	}
	if err := prepareSideFiles(path, true); err != nil {
		return "", err
	}
	c, err := openDB(ctx, path, openOpts{Busy: 10 * time.Second})
	if err != nil {
		return "", err
	}
	defer c.Close()
	mode, err := queryText(c, `PRAGMA main.journal_mode = WAL`)
	if err != nil {
		e.busyFor(db.ID).note(err)
		if isBusy(err) {
			return "", errors.New("your app was in the middle of a transaction, so the switch couldn't happen; nothing changed. Try again in a moment")
		}
		return "", err
	}
	if !strings.EqualFold(mode, "wal") {
		return "", fmt.Errorf("SQLite kept the database in %s mode (an app may hold it in exclusive locking mode); nothing changed", mode)
	}
	c.Close()
	if s, _, err := e.shipperFor(env, db); err == nil {
		s.mu.Lock()
		s.st.NeedSnapshot = true
		s.autoSnap = time.Time{}
		s.mu.Unlock()
	}
	return "Continuous backups are on: the database is in WAL mode now (-wal and -shm files appear next to it), " +
		"and Rowsafe takes a fresh full backup and copies every change from now on.", nil
}
