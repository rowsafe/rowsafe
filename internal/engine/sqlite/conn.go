package sqlite

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ncruces/go-sqlite3"
)

// The agent opens production files with SQLite itself (a pure Go build of
// SQLite: github.com/ncruces/go-sqlite3), with the same file locks and
// shared memory (-shm) as the app's SQLite, so it is safe next to the
// app's own connections. It never creates a database file, never changes
// its journal mode unless asked (MaintSQLiteWAL), and never turns on
// anything persistent.

// headerMagic starts every SQLite database file.
const headerMagic = "SQLite format 3\x00"

// dbHeader is what the agent reads from a database file's first 100 bytes.
type dbHeader struct {
	PageSize  int
	WAL       bool  // write/read versions 2: the file is in WAL mode
	PageCount int64 // 0 when the header's count isn't valid
	Version   int   // SQLITE_VERSION_NUMBER of the library that last wrote it
}

var errNotSQLite = errors.New("not a SQLite database file")

func parseDBHeader(b []byte) (dbHeader, error) {
	if len(b) < 100 || string(b[:16]) != headerMagic {
		return dbHeader{}, errNotSQLite
	}
	h := dbHeader{PageSize: int(binary.BigEndian.Uint16(b[16:]))}
	if h.PageSize == 1 {
		h.PageSize = 65536
	}
	if h.PageSize < 512 || h.PageSize&(h.PageSize-1) != 0 {
		return dbHeader{}, errNotSQLite
	}
	h.WAL = b[18] == 2 && b[19] == 2
	if binary.BigEndian.Uint32(b[24:]) == binary.BigEndian.Uint32(b[92:]) {
		h.PageCount = int64(binary.BigEndian.Uint32(b[28:]))
	}
	h.Version = int(binary.BigEndian.Uint32(b[96:]))
	return h, nil
}

// versionString formats SQLITE_VERSION_NUMBER (3045001 -> "3.45.1").
func versionString(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d", n/1000000, n/1000%1000, n%1000)
}

// readDBHeader reads path's header. It never follows a symbolic link for
// the final name (the agent opens what root granted).
func readDBHeader(path string) (dbHeader, os.FileInfo, error) {
	rp, err := realPath(path)
	if err != nil {
		return dbHeader{}, nil, err
	}
	f, err := openNoFollow(rp, os.O_RDONLY)
	if err != nil {
		return dbHeader{}, nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return dbHeader{}, nil, err
	}
	if !fi.Mode().IsRegular() {
		return dbHeader{}, fi, fmt.Errorf("%s is not a regular file", path)
	}
	b := make([]byte, 100)
	if _, err := io.ReadFull(f, b); err != nil {
		if fi.Size() == 0 {
			return dbHeader{}, fi, fmt.Errorf("%s is empty: the app hasn't created its database yet", path)
		}
		return dbHeader{}, fi, errNotSQLite
	}
	h, err := parseDBHeader(b)
	return h, fi, err
}

// busyCount counts the busy and locked errors the agent met (reported by
// monitoring, per database).
type busyCount struct{ n atomic.Int64 }

func (b *busyCount) note(err error) {
	if b != nil && isBusy(err) {
		b.n.Add(1)
	}
}

func (b *busyCount) take() int64 {
	if b == nil {
		return 0
	}
	return b.n.Swap(0)
}

// isBusy reports a SQLite busy or locked error.
func isBusy(err error) bool {
	return errors.Is(err, sqlite3.BUSY) || errors.Is(err, sqlite3.LOCKED)
}

// openOpts says how a connection is opened.
type openOpts struct {
	// Busy is how long a statement waits for the app's locks (default
	// 5s). The shipper's write-lock attempts use a short one.
	Busy time.Duration
	// ReadOnly opens without write access (restored copies being read).
	ReadOnly bool
	// Scratch: a file the agent owns (copies, restores): no side files to
	// prepare.
	Scratch bool
}

// openDB opens a SQLite database the agent didn't create. It never
// creates the file. For a production file it first makes sure SQLite's
// side files (-wal, -shm, -journal) exist with permissions that keep
// working for the app (sidefiles.go), so a file the agent creates never
// locks the app out.
func openDB(ctx context.Context, path string, o openOpts) (*sqlite3.Conn, error) {
	if rp, err := realPath(path); err == nil {
		path = rp
	}
	h, _, err := readDBHeader(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("the database file %s doesn't exist (moved or deleted?)", path)
		}
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("the Rowsafe agent can't read %s: %w (run the Rowsafe installer again to give it access)", path, err)
		}
		return nil, err
	}
	if !o.Scratch && !o.ReadOnly {
		if err := prepareSideFiles(path, h.WAL); err != nil {
			return nil, err
		}
	}
	flags := sqlite3.OPEN_READWRITE | sqlite3.OPEN_NOFOLLOW
	if o.ReadOnly {
		flags = sqlite3.OPEN_READONLY | sqlite3.OPEN_NOFOLLOW
	}
	c, err := sqlite3.OpenFlags(path, flags)
	if err != nil {
		if errors.Is(err, sqlite3.CANTOPEN) || errors.Is(err, sqlite3.READONLY) || errors.Is(err, sqlite3.PERM) {
			return nil, fmt.Errorf("the Rowsafe agent can't open %s for reading and writing (%v): run the Rowsafe installer again to give it access", path, err)
		}
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	busy := o.Busy
	if busy <= 0 {
		busy = 5 * time.Second
	}
	if err := c.BusyTimeout(busy); err != nil {
		c.Close()
		return nil, err
	}
	// The agent checkpoints itself, after copying (ship.go); its own
	// commits never trigger one. Schema code from the file is never run.
	_ = c.WALAutoCheckpoint(0)
	if err := c.Exec(`PRAGMA trusted_schema = OFF`); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// withInterrupt makes ctx interrupt c's statements until the returned
// function is called.
func withInterrupt(ctx context.Context, c *sqlite3.Conn) func() {
	old := c.SetInterrupt(ctx)
	return func() { c.SetInterrupt(old) }
}

// ---- small query helpers

// queryRows runs a query and calls fn for each row.
func queryRows(c *sqlite3.Conn, sql string, fn func(s *sqlite3.Stmt) error, args ...any) error {
	s, _, err := c.Prepare(sql)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := bind(s, args...); err != nil {
		return err
	}
	for s.Step() {
		if err := fn(s); err != nil {
			return err
		}
	}
	return s.Err()
}

func bind(s *sqlite3.Stmt, args ...any) error {
	for i, a := range args {
		var err error
		switch v := a.(type) {
		case nil:
			err = s.BindNull(i + 1)
		case int:
			err = s.BindInt64(i+1, int64(v))
		case int64:
			err = s.BindInt64(i+1, v)
		case float64:
			err = s.BindFloat(i+1, v)
		case string:
			err = s.BindText(i+1, v)
		case []byte:
			err = s.BindBlob(i+1, v)
		case sqlite3.Value:
			err = s.BindValue(i+1, v)
		default:
			return fmt.Errorf("bind: unsupported %T", a)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// queryInt returns the first column of the first row as an integer.
func queryInt(c *sqlite3.Conn, sql string, args ...any) (int64, error) {
	var n int64
	found := false
	err := queryRows(c, sql, func(s *sqlite3.Stmt) error {
		if !found {
			n, found = s.ColumnInt64(0), true
		}
		return nil
	}, args...)
	return n, err
}

// queryText returns the first column of the first row as text.
func queryText(c *sqlite3.Conn, sql string, args ...any) (string, error) {
	var out string
	found := false
	err := queryRows(c, sql, func(s *sqlite3.Stmt) error {
		if !found {
			out, found = s.ColumnText(0), true
		}
		return nil
	}, args...)
	return out, err
}

// quoteIdent quotes a name for SQL ("a""b").
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// quoteLit quotes a string literal ('it”s').
func quoteLit(s string) string { return `'` + strings.ReplaceAll(s, `'`, `''`) + `'` }

// journalMode reads the database's journal mode (wal, delete...).
func journalMode(c *sqlite3.Conn) (string, error) {
	m, err := queryText(c, `PRAGMA main.journal_mode`)
	return strings.ToLower(m), err
}

// beginRead starts a read transaction and takes its snapshot now (BEGIN
// is deferred: the first read takes the locks).
func beginRead(c *sqlite3.Conn) error {
	if err := c.Exec(`BEGIN`); err != nil {
		return err
	}
	if _, err := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE 0`); err != nil {
		_ = c.Exec(`ROLLBACK`)
		return err
	}
	return nil
}

// rollback ends a transaction (if any).
func rollback(c *sqlite3.Conn) {
	if c != nil && !c.GetAutocommit() {
		_ = c.Exec(`ROLLBACK`)
	}
}
