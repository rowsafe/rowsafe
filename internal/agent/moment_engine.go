package agent

import (
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment for the other engines (MySQL's binary log, MongoDB's
// oplog): the engine reads its own change log and hands each committed
// transaction here; the result is built exactly like PostgreSQL's (the
// same limits, ranking, timeline, totals and words).

// MomentSearch collects one search's result.
type MomentSearch struct {
	c *momentCollector
}

// MomentTx is one committed transaction (or, without transactions, one
// operation): its commit time, an ID to group and name it, and what it did
// to each table (Kind, DB, Table "db.table" or "schema.table", Rows,
// Estimated, Note).
type MomentTx struct {
	Time    time.Time
	XID     uint32
	Changes []protocol.Moment
}

// NewMomentSearch checks a find_moment's params (the same rules as
// PostgreSQL's) and starts a search.
func NewMomentSearch(p protocol.FindMomentParams, now time.Time) (*MomentSearch, error) {
	f, err := normalizeMoment(p, now)
	if err != nil {
		return nil, err
	}
	return &MomentSearch{c: newMomentCollector(f, newRelCatalog())}, nil
}

// From and To are the range searched.
func (s *MomentSearch) From() time.Time { return s.c.f.from }
func (s *MomentSearch) To() time.Time   { return s.c.f.to }

// Wants reports whether a table ("db.table") is one the search asks for.
func (s *MomentSearch) Wants(db, table string) bool {
	return s.c.f.matchTable(relInfo{DB: db, Name: table})
}

// Add records a transaction.
func (s *MomentSearch) Add(tx MomentTx) {
	c := s.c
	if !c.inRange(tx.Time) {
		return
	}
	var kept []protocol.Moment
	for _, m := range tx.Changes {
		if !c.f.kinds[m.Kind] || !c.f.matchTable(relInfo{DB: m.DB, Name: m.Table}) {
			continue
		}
		m.Time, m.XID = tx.Time.UTC(), tx.XID
		kept = append(kept, m)
	}
	if len(kept) == 0 {
		return
	}
	c.res.Transactions++
	for i := range kept {
		kept[i].TxTables = len(kept)
		c.count(kept[i])
		if (kept[i].Kind == protocol.MomentDelete || kept[i].Kind == protocol.MomentUpdate) && kept[i].Rows < c.f.minRows {
			continue
		}
		kept[i].Summary = momentSummary(kept[i])
		c.keep(kept[i])
	}
}

// Result is the search's result for the range actually read; notes are
// added to it.
func (s *MomentSearch) Result(from, to time.Time, notes []string, started time.Time) *protocol.FindMomentResult {
	res := s.c.result()
	res.From, res.To = from.UTC(), to.UTC()
	res.Notes = append(res.Notes, notes...)
	res.DurationMs = time.Since(started).Milliseconds()
	res.Summary = momentsSummary(res)
	return &res
}

