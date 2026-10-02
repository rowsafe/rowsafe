package collect

import (
	"cmp"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Statement statistics of the other engines (MySQL, MariaDB, MongoDB,
// ClickHouse), turned into the same per-interval QueryStats PostgreSQL
// reports, so the control plane's Queries page and recommendations work
// the same. Query texts are always normalized by the engine package
// (literal values left out) before they reach these helpers.

// StmtReading is one statement's counters: cumulative for StmtTracker
// (MySQL's statement digests), or the activity of one interval for
// BuildQueryStats (MongoDB's profiler, ClickHouse's query log).
type StmtReading struct {
	ID, Query, Database, User string
	Calls                     int64
	TotalTimeMs               float64
	Rows                      int64
	RowsExamined              int64
	FullScans                 int64
	TmpDiskTables             int64
}

func (r StmtReading) minus(p StmtReading) StmtReading {
	d := r
	d.Calls = r.Calls - p.Calls
	d.TotalTimeMs = r.TotalTimeMs - p.TotalTimeMs
	d.Rows = max(r.Rows-p.Rows, 0)
	d.RowsExamined = max(r.RowsExamined-p.RowsExamined, 0)
	d.FullScans = max(r.FullScans-p.FullScans, 0)
	d.TmpDiskTables = max(r.TmpDiskTables-p.TmpDiskTables, 0)
	return d
}

// StmtTracker turns cumulative statement counters into per-interval
// activity, with the same care as PostgreSQL's (statements.go): the first
// reading, a restart or reset (epoch changes) or a gap too short or too
// long yields nothing; an entry whose counters went backwards started over.
type StmtTracker struct {
	at        time.Time
	epoch     string
	prev      map[string]StmtReading
	truncated bool
}

// Observe records a cumulative reading (truncated: the engine had more
// statements than were read) and returns the activity since the previous
// one, or nil.
func (t *StmtTracker) Observe(epoch string, now time.Time, cur []StmtReading, truncated bool) *protocol.QueryStats {
	m := make(map[string]StmtReading, len(cur))
	for _, r := range cur {
		if p, ok := m[r.ID]; ok { // the same digest in two schemas: sum
			r.Calls += p.Calls
			r.TotalTimeMs += p.TotalTimeMs
			r.Rows += p.Rows
			r.RowsExamined += p.RowsExamined
			r.FullScans += p.FullScans
			r.TmpDiskTables += p.TmpDiskTables
		}
		m[r.ID] = r
	}
	prev, prevAt, prevEpoch, prevTrunc := t.prev, t.at, t.epoch, t.truncated
	t.prev, t.at, t.epoch, t.truncated = m, now, epoch, truncated
	if prev == nil || prevEpoch != epoch {
		return nil
	}
	gap := now.Sub(prevAt)
	if gap < 30*time.Second || gap > maxStmtGap {
		return nil
	}
	var deltas []StmtReading
	for id, c := range m {
		p, had := prev[id]
		var d StmtReading
		switch {
		case !had && (truncated || prevTrunc):
			continue
		case !had || c.Calls < p.Calls || c.TotalTimeMs < p.TotalTimeMs:
			d = c
		default:
			d = c.minus(p)
		}
		if d.Calls > 0 {
			deltas = append(deltas, d)
		}
	}
	return BuildQueryStats(gap.Seconds(), deltas)
}

// BuildQueryStats makes the QueryStats of one interval from each
// statement's activity in it: totals over all of them, and the busiest by
// time plus the most called of the rest.
func BuildQueryStats(intervalSeconds float64, deltas []StmtReading) *protocol.QueryStats {
	qs := &protocol.QueryStats{IntervalSeconds: intervalSeconds, Statements: []protocol.QueryDelta{}}
	for _, d := range deltas {
		qs.TotalCalls += d.Calls
		qs.TotalTimeMs += d.TotalTimeMs
	}
	s := slices.Clone(deltas)
	slices.SortFunc(s, func(a, b StmtReading) int {
		return cmp.Or(cmp.Compare(b.TotalTimeMs, a.TotalTimeMs), cmp.Compare(b.Calls, a.Calls), cmp.Compare(a.ID, b.ID))
	})
	picked := s
	if len(s) > queryStatsByTime+queryStatsByCalls {
		picked = slices.Clone(s[:queryStatsByTime])
		rest := slices.Clone(s[queryStatsByTime:])
		slices.SortStableFunc(rest, func(a, b StmtReading) int { return cmp.Compare(b.Calls, a.Calls) })
		picked = append(picked, rest[:queryStatsByCalls]...)
	}
	qs.Truncated = len(s) - len(picked)
	for _, d := range picked {
		qs.Statements = append(qs.Statements, protocol.QueryDelta{
			QueryID: d.ID, Query: truncateText(d.Query, 2000), Database: d.Database, User: d.User,
			Calls: d.Calls, TotalTimeMs: d.TotalTimeMs, Rows: d.Rows,
			RowsExamined: d.RowsExamined, FullScans: d.FullScans, TmpDiskTables: d.TmpDiskTables,
		})
	}
	return qs
}

// truncateText cuts s to at most n bytes on a character boundary.
func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
