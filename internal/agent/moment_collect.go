package agent

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment, part 3: turning committed transactions into moments.
//
// Each committed transaction is resolved to table names as soon as it
// arrives when every file it touched is known; files the catalogs don't
// know (yet) wait until the whole range is read, because a later TRUNCATE
// or DROP in the same WAL can tell whose they were. Only the biggest
// transactions are kept; every matching one counts in the timeline and the
// totals.

// momentFilter is a search's normalized parameters.
type momentFilter struct {
	from, to time.Time
	db       string
	tables   []string // "schema.name" or "name"
	kinds    map[string]bool
	minRows  int64
	limit    int
}

// matchTable reports whether r is one of the tables asked for (a partition
// matches through its parent too).
func (f momentFilter) matchTable(r relInfo) bool {
	if f.db != "" && r.DB != f.db {
		return false
	}
	if len(f.tables) == 0 {
		return true
	}
	for _, t := range f.tables {
		for _, name := range []string{r.Name, r.Parent} {
			if name == "" {
				continue
			}
			if name == t || (!strings.Contains(t, ".") && strings.HasSuffix(name, "."+t)) {
				return true
			}
		}
	}
	return false
}

// momentCollector accumulates the result.
type momentCollector struct {
	f   momentFilter
	cat *relCatalog
	// inferred maps files the catalogs didn't know to their table, learned
	// from TRUNCATEs, rebuilds and DROPs read in the range.
	inferred map[walRel]walOID

	deferred     []*walCommit // waiting for names
	deferredCap  int
	deferredLost int

	bucket  time.Duration
	buckets []protocol.MomentBucket
	tables  map[string]*protocol.MomentTable
	moments []protocol.Moment
	matched int // moments that matched (before the limit)
	res     protocol.FindMomentResult
}

func newMomentCollector(f momentFilter, cat *relCatalog) *momentCollector {
	c := &momentCollector{f: f, cat: cat, inferred: map[walRel]walOID{}, tables: map[string]*protocol.MomentTable{}, deferredCap: 200000}
	c.bucket = bucketSize(f.to.Sub(f.from))
	n := int(f.to.Sub(f.from)/c.bucket) + 1
	start := f.from.Truncate(c.bucket)
	for i := range n {
		b := start.Add(time.Duration(i) * c.bucket)
		if b.After(f.to) {
			break
		}
		c.buckets = append(c.buckets, protocol.MomentBucket{Start: b})
	}
	return c
}

// bucketSize picks a round slice so the timeline has at most 96 bars.
func bucketSize(span time.Duration) time.Duration {
	for _, d := range []time.Duration{time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute,
		30 * time.Minute, time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour} {
		if span/d <= 96 {
			return d
		}
	}
	return 12 * time.Hour
}

// commit handles one committed transaction.
func (c *momentCollector) commit(cm *walCommit) {
	c.learn(cm)
	if !c.resolvable(cm) {
		if len(c.deferred) < c.deferredCap {
			c.deferred = append(c.deferred, cm)
		} else {
			c.deferredLost++
		}
		return
	}
	c.emit(cm)
}

// finish resolves what waited, with everything learned from the range.
func (c *momentCollector) finish() {
	for _, cm := range c.deferred {
		c.emit(cm)
	}
	c.deferred = nil
}

// rel resolves a file to its table.
func (c *momentCollector) rel(f walRel) (relInfo, bool) {
	if r, ok := c.cat.byFile[f]; ok {
		return r, true
	}
	if o, ok := c.inferred[f]; ok {
		if r, ok := c.cat.byOID[o]; ok {
			return r, true
		}
	}
	return relInfo{}, false
}

func (c *momentCollector) resolvable(cm *walCommit) bool {
	for ch := range cm.changes {
		if _, ok := c.rel(ch.Rel); !ok {
			return false
		}
	}
	return true
}

// learn takes what a transaction says about files: a TRUNCATE gives the
// locked relation a new file right after locking it; the files dropped at
// commit are the old ones (in the reverse order of the new ones); a
// rebuild or DROP of one table drops its old heap file first (the lowest
// number of the files the table owned).
func (c *momentCollector) learn(cm *walCommit) {
	if len(cm.dropped) == 0 {
		return // nothing replaced (CREATE TABLE also locks, then creates files)
	}
	for i, rel := range cm.created {
		if o := cm.paired[i]; o.OID != 0 {
			if _, known := c.cat.byFile[rel]; !known {
				c.inferred[rel] = o
			}
		}
	}
	if len(cm.created) == len(cm.dropped) && pairedAll(cm.paired) {
		for i := range cm.created {
			old := cm.dropped[len(cm.dropped)-1-i]
			if _, known := c.cat.byFile[old]; !known {
				c.inferred[old] = cm.paired[i]
			}
		}
		return
	}
	tables := c.lockedTables(cm)
	if len(tables) != 1 {
		return
	}
	var unknown []walRel
	for _, d := range cm.dropped {
		if _, ok := c.rel(d); !ok && d.DB == tables[0].DB {
			unknown = append(unknown, d)
		}
	}
	if len(unknown) > 0 {
		lowest := slices.MinFunc(unknown, func(a, b walRel) int { return cmp.Compare(a.Rel, b.Rel) })
		c.inferred[lowest] = tables[0]
	}
}

func pairedAll(p []walOID) bool {
	for _, o := range p {
		if o.OID == 0 {
			return false
		}
	}
	return len(p) > 0
}

// lockedTables are the known tables a transaction locked exclusively.
func (c *momentCollector) lockedTables(cm *walCommit) []walOID {
	var out []walOID
	for _, o := range cm.locks {
		if r, ok := c.cat.byOID[o]; ok && r.isTable() && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// kept reports whether an event at t of this kind is asked for.
func (c *momentCollector) inRange(t time.Time) bool {
	return !t.Before(c.f.from) && !t.After(c.f.to)
}

// emit turns a resolved transaction into moments.
func (c *momentCollector) emit(cm *walCommit) {
	if !c.inRange(cm.Time) {
		return
	}
	var ms []protocol.Moment
	// Row deletes and updates, per table.
	type tk struct{ table, kind string }
	rows := map[tk]int64{}
	infos := map[string]relInfo{}
	var unnamed []walChange
	for ch, n := range cm.changes {
		r, ok := c.rel(ch.Rel)
		if !ok {
			unnamed = append(unnamed, ch)
			continue
		}
		if r.Kind != "r" && r.Kind != "m" {
			continue // TOAST, catalogs...
		}
		if !c.f.matchTable(r) {
			continue
		}
		key := r.DB + "\x00" + r.Name
		infos[key] = r
		rows[tk{key, ch.Kind}] += n
	}
	for k, n := range rows {
		r := infos[k.table]
		ms = append(ms, protocol.Moment{Kind: k.kind, DB: r.DB, Table: r.Name, Parent: r.Parent, Rows: n})
	}
	if len(unnamed) > 0 && len(c.f.tables) == 0 {
		byKind := map[string]int64{}
		var db uint32
		for _, ch := range unnamed {
			byKind[ch.Kind] += cm.changes[ch]
			db = ch.Rel.DB
		}
		if name := c.dbName(db); c.f.db == "" || name == c.f.db {
			for kind, n := range byKind {
				ms = append(ms, protocol.Moment{Kind: kind, DB: name, Rows: n,
					Note: "Rowsafe couldn't name this table: it was removed or rebuilt before Rowsafe noted its name."})
			}
		}
	}
	ms = append(ms, c.ddl(cm)...)

	// The same transaction's moments share its time, ID and table count.
	var kept []protocol.Moment
	for _, m := range ms {
		if !c.f.kinds[m.Kind] {
			continue
		}
		m.Time, m.XID, m.LSN = cm.Time, cm.XID, formatLSN(cm.LSN)
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

// ddl finds the TRUNCATEs and DROPs of a transaction.
func (c *momentCollector) ddl(cm *walCommit) []protocol.Moment {
	var out []protocol.Moment
	seen := map[walOID]bool{}
	truncate := func(o walOID, oldFile walRel) {
		r, ok := c.cat.byOID[o]
		if !ok || !r.isTable() || seen[o] || !c.f.matchTable(r) {
			return
		}
		seen[o] = true
		m := protocol.Moment{Kind: protocol.MomentTruncate, DB: r.DB, Table: r.Name, Parent: r.Parent}
		if old, ok := c.cat.byFile[oldFile]; ok && old.Rows > 0 {
			m.Rows, m.Estimated = old.Rows, true
		}
		out = append(out, m)
	}
	// wal_level logical names truncated tables outright.
	for _, o := range cm.truncated {
		truncate(o, c.oldFileOf(cm, o))
	}
	// Otherwise: a table locked and given a new, empty file (no pages
	// copied into it, as VACUUM FULL or CLUSTER would).
	for i, rel := range cm.created {
		o := cm.paired[i]
		if o.OID == 0 || cm.written[rel] > 0 {
			continue
		}
		// It must have replaced a file the table had (CREATE TABLE also
		// locks the new table, then creates its TOAST table and indexes).
		if r, ok := c.cat.byOID[o]; ok && r.isTable() {
			if old := c.oldFileOf(cm, o); old != (walRel{}) {
				truncate(o, old)
			}
		}
	}

	// DROP: relations locked or with dropped statistics that don't exist
	// now. A transaction that also created files is a rebuild, not a DROP.
	if len(cm.created) > 0 || (len(cm.dropped) == 0 && len(cm.droppedDBs) == 0) {
		return out
	}
	var candidates []walOID
	for _, o := range append(slices.Clone(cm.locks), cm.droppedOIDs...) {
		if !slices.Contains(candidates, o) {
			candidates = append(candidates, o)
		}
	}
	anyExists, named := false, false
	for _, o := range candidates {
		if c.cat.now[o] {
			anyExists = true
			continue
		}
		r, ok := c.cat.byOID[o]
		if !ok || !r.isTable() || seen[o] {
			continue
		}
		named = true
		// A partition dropped with its partitioned table is part of it.
		if r.Parent != "" && slices.ContainsFunc(candidates, func(p walOID) bool {
			pr, ok := c.cat.byOID[p]
			return ok && pr.Name == r.Parent && pr.DBOID == r.DBOID && !c.cat.now[p]
		}) {
			continue
		}
		seen[o] = true
		if !c.f.matchTable(r) {
			continue
		}
		m := protocol.Moment{Kind: protocol.MomentDrop, DB: r.DB, Table: r.Name, Parent: r.Parent}
		if r.Rows > 0 {
			m.Rows, m.Estimated = r.Rows, true
		}
		out = append(out, m)
	}
	if !named && !anyExists && len(cm.dropped) > 0 && len(c.f.tables) == 0 {
		name := c.dbName(cm.dropped[0].DB)
		if c.cat.dbNow[cm.dropped[0].DB] && (c.f.db == "" || name == c.f.db) {
			out = append(out, protocol.Moment{Kind: protocol.MomentDrop, DB: name,
				Note: "Rowsafe hadn't noted this table's name before it was removed."})
		}
	}
	for _, dbo := range cm.droppedDBs {
		name := c.dbName(dbo)
		if len(c.f.tables) > 0 || (c.f.db != "" && name != c.f.db) {
			continue
		}
		out = append(out, protocol.Moment{Kind: protocol.MomentDrop, DB: name, Note: "The whole database was removed (DROP DATABASE)."})
	}
	return out
}

// oldFileOf is the file a table had before this transaction replaced or
// dropped it.
func (c *momentCollector) oldFileOf(cm *walCommit, o walOID) walRel {
	for _, d := range cm.dropped {
		if r, ok := c.rel(d); ok && r.OID == o.OID && r.DBOID == o.DB {
			return d
		}
	}
	return walRel{}
}

func (c *momentCollector) dbName(oid uint32) string {
	if n, ok := c.cat.dbNames[oid]; ok {
		return n
	}
	return fmt.Sprintf("database %d", oid)
}

// count adds a moment to the timeline and the totals.
func (c *momentCollector) count(m protocol.Moment) {
	if i := int(m.Time.Sub(c.f.from.Truncate(c.bucket)) / c.bucket); i >= 0 && i < len(c.buckets) {
		b := &c.buckets[i]
		switch m.Kind {
		case protocol.MomentDelete:
			b.Deleted += m.Rows
		case protocol.MomentUpdate:
			b.Updated += m.Rows
		case protocol.MomentTruncate:
			b.Truncates++
		case protocol.MomentDrop:
			b.Drops++
		}
	}
	switch m.Kind {
	case protocol.MomentDelete:
		c.res.Deleted += m.Rows
	case protocol.MomentUpdate:
		c.res.Updated += m.Rows
	case protocol.MomentTruncate:
		c.res.Truncates++
	case protocol.MomentDrop:
		c.res.Drops++
	}
	if m.Table == "" {
		return
	}
	key := m.DB + "\x00" + m.Table
	t := c.tables[key]
	if t == nil {
		t = &protocol.MomentTable{DB: m.DB, Table: m.Table}
		c.tables[key] = t
	}
	t.Transactions++
	switch m.Kind {
	case protocol.MomentDelete:
		t.Deleted += m.Rows
	case protocol.MomentUpdate:
		t.Updated += m.Rows
	case protocol.MomentTruncate:
		t.Truncates++
	case protocol.MomentDrop:
		t.Drops++
	}
}

// momentRank orders moments by importance: TRUNCATE and DROP first, then
// the most rows, then the latest.
func momentRank(a, b protocol.Moment) int {
	ddl := func(m protocol.Moment) int {
		if m.Kind == protocol.MomentTruncate || m.Kind == protocol.MomentDrop {
			return 0
		}
		return 1
	}
	return cmp.Or(cmp.Compare(ddl(a), ddl(b)), cmp.Compare(b.Rows, a.Rows), b.Time.Compare(a.Time))
}

// keep adds a moment, keeping only the limit's worth of the biggest.
func (c *momentCollector) keep(m protocol.Moment) {
	c.matched++
	c.moments = append(c.moments, m)
	if len(c.moments) >= 2*c.f.limit+64 {
		slices.SortFunc(c.moments, momentRank)
		c.moments = c.moments[:c.f.limit]
	}
}

// result assembles the result (From, To, WAL figures and notes are the
// caller's).
func (c *momentCollector) result() protocol.FindMomentResult {
	res := c.res
	slices.SortFunc(c.moments, momentRank)
	if len(c.moments) > c.f.limit {
		c.moments = c.moments[:c.f.limit]
	}
	res.Truncated = c.matched > len(c.moments)
	slices.SortFunc(c.moments, func(a, b protocol.Moment) int {
		return cmp.Or(a.Time.Compare(b.Time), cmp.Compare(a.Table, b.Table), cmp.Compare(a.Kind, b.Kind))
	})
	res.Moments = c.moments
	if res.Moments == nil {
		res.Moments = []protocol.Moment{}
	}
	res.Buckets = c.buckets
	res.BucketSeconds = int(c.bucket / time.Second)
	for _, t := range c.tables {
		res.Tables = append(res.Tables, *t)
	}
	slices.SortFunc(res.Tables, func(a, b protocol.MomentTable) int {
		return cmp.Or(cmp.Compare(b.Deleted+b.Updated, a.Deleted+a.Updated), cmp.Compare(b.Truncates+b.Drops, a.Truncates+a.Drops),
			cmp.Compare(a.Table, b.Table))
	})
	if len(res.Tables) > 50 {
		res.Tables = res.Tables[:50]
	}
	if c.deferredLost > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%s transactions touched tables Rowsafe couldn't name and weren't counted.", commas(int64(c.deferredLost))))
	}
	return res
}

// shortTable drops the "public." schema for display.
func shortTable(name string) string {
	if s, ok := strings.CutPrefix(name, "public."); ok {
		return s
	}
	return name
}

// commas formats 1204 as "1,204".
func commas(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(ch)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func nplural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return commas(n) + " " + many
}

// momentSummary: "1,204 rows deleted from applications".
func momentSummary(m protocol.Moment) string {
	table := shortTable(m.Table)
	if table == "" {
		table = "a table Rowsafe couldn't name"
	}
	var s string
	switch m.Kind {
	case protocol.MomentDelete:
		s = nplural(m.Rows, "row", "rows") + " deleted from " + table
	case protocol.MomentUpdate:
		s = nplural(m.Rows, "row", "rows") + " changed in " + table
	case protocol.MomentTruncate:
		s = table + " emptied (TRUNCATE)"
		if m.Rows > 0 {
			s += ", about " + nplural(m.Rows, "row", "rows")
		}
	case protocol.MomentDrop:
		switch {
		case m.Table != "":
			s = "Table " + table + " removed (DROP)"
			if m.Rows > 0 {
				s += ", about " + nplural(m.Rows, "row", "rows")
			}
		case strings.Contains(m.Note, "DROP DATABASE"):
			s = "Database " + m.DB + " removed (DROP DATABASE)"
		default:
			s = "A table removed (DROP)"
		}
	}
	if m.TxTables > 1 {
		s += fmt.Sprintf(" (the same transaction changed %d tables)", m.TxTables)
	}
	return s
}
