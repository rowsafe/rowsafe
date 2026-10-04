package sqlite

import (
	"context"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for SQLite: the file and -wal sizes, free pages, page size,
// journal mode, how far the change copier is behind, the last check of the
// file's pages, the busy and locked errors the agent met, and (every 30
// minutes) the tables whose query planner statistics are out of date.
// Read-only and cheap: a few PRAGMAs on one connection.

const staleEvery = 30 * time.Minute

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	mu       sync.Mutex
	conn     *sqlite3.Conn
	path     string
	stale    []string
	staleAt  time.Time
	walSizes []int64
}

func (e *Engine) monitorFor(id string) *dbMonitor {
	e.mon.mu.Lock()
	defer e.mon.mu.Unlock()
	if e.mon.dbs == nil {
		e.mon.dbs = map[string]*dbMonitor{}
	}
	m := e.mon.dbs[id]
	if m == nil {
		m = &dbMonitor{}
		e.mon.dbs[id] = m
	}
	return m
}

func (m *dbMonitor) drop() {
	if m.conn != nil {
		m.conn.Close()
		m.conn = nil
	}
}

// Monitor collects one sample of db.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: db.ID}
	path := db.SocketDir
	if !protocol.SQLitePath(path) {
		dm.Error = "this SQLite database has no valid file path"
		return dm, nil
	}
	m := e.monitorFor(db.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	busy := e.busyFor(db.ID)
	now := time.Now().UTC()
	h, fi, err := readDBHeader(path)
	if err != nil {
		m.drop()
		if notExist(err) {
			dm.Error = "the database file " + path + " doesn't exist (moved or deleted?)"
		} else {
			dm.Error = "can't read the database file: " + firstLine(err.Error())
		}
		return dm, nil
	}
	st := &protocol.SQLiteStatus{CollectedAt: now, Path: path, FileBytes: fi.Size(), WALBytes: fileSize(path + "-wal"),
		PageSize: h.PageSize, SQLiteVersion: versionString(h.Version), NetworkFS: networkFS(filepath.Dir(path))}
	if m.conn == nil || m.path != path {
		m.drop()
		c, err := openDB(ctx, path, openOpts{Busy: 2 * time.Second})
		if err != nil {
			dm.Error = firstLine(err.Error())
			return dm, nil
		}
		m.conn, m.path = c, path
	}
	c := m.conn
	restore := withInterrupt(ctx, c)
	defer restore()
	read := func(q string) int64 {
		n, err := queryInt(c, q)
		if err != nil {
			busy.note(err)
		}
		return n
	}
	st.PageCount = read(`PRAGMA main.page_count`)
	st.FreePages = read(`PRAGMA main.freelist_count`)
	if mode, err := journalMode(c); err == nil {
		st.JournalMode = mode
	} else {
		busy.note(err)
		dm.Error = "can't read the database: " + firstLine(err.Error())
		m.drop()
		return dm, nil
	}
	switch read(`PRAGMA main.auto_vacuum`) {
	case 1:
		st.AutoVacuum = "full"
	case 2:
		st.AutoVacuum = "incremental"
	default:
		st.AutoVacuum = "none"
	}
	_ = queryRows(c, `SELECT type, count(*) FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite\_%' ESCAPE '\' GROUP BY type`,
		func(s *sqlite3.Stmt) error {
			switch s.ColumnText(0) {
			case "table":
				st.Tables = int(s.ColumnInt64(1))
			case "index":
				st.Indexes = int(s.ColumnInt64(1))
			}
			return nil
		})
	if time.Since(m.staleAt) >= staleEvery {
		if t, err := staleTables(c); err == nil {
			m.stale, m.staleAt = t, time.Now()
		} else {
			busy.note(err)
		}
	}
	st.StaleStatsTables = m.stale
	if total, free, err := diskSpace(filepath.Dir(path)); err == nil && total > 0 {
		st.DiskFreeBytes = free
		dm.Metrics = map[string]float64{
			collect.MDiskTotalBytes: float64(total), collect.MDiskFreeBytes: float64(free),
			collect.MDiskFreePct: 100 * float64(free) / float64(total),
		}
	}
	if dm.Metrics == nil {
		dm.Metrics = map[string]float64{}
	}
	// VACUUM writes the whole file about twice (a temporary copy, then
	// back); at a conservative 50 MB/s.
	st.VacuumEstimateSeconds = int(max(1, (2*st.FileBytes)/(50<<20)))
	if s := e.existingShipper(db.ID); s != nil && st.JournalMode == "wal" {
		s.mu.Lock()
		st.Shipping = s.attached && s.off == ""
		if k := s.sinks[sinkPrimary]; k != nil && k.st.LastUploadedAt != nil {
			t := *k.st.LastUploadedAt
			st.LastShippedAt = &t
		}
		s.mu.Unlock()
		st.ShippingLagSeconds = s.lag().Seconds()
		dm.Metrics[collect.MSQLiteShippingLag] = st.ShippingLagSeconds
	}
	m.walSizes = append(m.walSizes, st.WALBytes)
	if len(m.walSizes) > 10 {
		m.walSizes = m.walSizes[len(m.walSizes)-10:]
	}
	st.WALGrowing = growing(m.walSizes, st.FileBytes)
	if rec, ok := e.lastIntegrity(env, db); ok {
		t := rec.At
		okv := rec.OK
		st.LastIntegrityCheck, st.IntegrityOK, st.IntegrityProblem = &t, &okv, rec.Problem
		if !rec.OK {
			dm.Metrics[collect.MSQLiteIntegrityFailed] = 1
		} else {
			dm.Metrics[collect.MSQLiteIntegrityFailed] = 0
		}
	}
	st.BusyErrors = busy.take()
	dm.Metrics[collect.MSQLiteFileBytes] = float64(st.FileBytes)
	dm.Metrics[collect.MSQLiteWALBytes] = float64(st.WALBytes)
	dm.Metrics[collect.MSQLiteBusyErrors] = float64(st.BusyErrors)
	dm.Metrics["database_size_bytes"] = float64(st.FileBytes + st.WALBytes)
	if st.PageCount > 0 {
		dm.Metrics[collect.MSQLiteFreePagesPct] = 100 * float64(st.FreePages) / float64(st.PageCount)
	}
	dm.Sizes = []protocol.DatabaseSize{{Name: "main", SizeBytes: st.FileBytes + st.WALBytes}}
	dm.SQLite = st
	return dm, nil
}

// growing: the -wal file grew at every one of the last readings (at least
// 5) and is larger than 64 MiB or the database itself.
func growing(sizes []int64, file int64) bool {
	if len(sizes) < 5 {
		return false
	}
	last := sizes[len(sizes)-5:]
	for i := 1; i < len(last); i++ {
		if last[i] <= last[i-1] {
			return false
		}
	}
	return last[len(last)-1] > min(max(file, 1<<20), 64<<20)
}

var analyzeRE = regexp.MustCompile(`(?i)^ANALYZE\s+"?main"?\."?([^"]+)"?\s*;?$`)

// staleTables are the tables whose statistics PRAGMA optimize would
// refresh (its debugging mode reports without doing anything), at most 20.
func staleTables(c *sqlite3.Conn) ([]string, error) {
	var out []string
	err := queryRows(c, `PRAGMA optimize(0x10003)`, func(s *sqlite3.Stmt) error {
		if m := analyzeRE.FindStringSubmatch(s.ColumnText(0)); m != nil && !slices.Contains(out, m[1]) && len(out) < 20 {
			out = append(out, m[1])
		}
		return nil
	})
	slices.Sort(out)
	return out, err
}
