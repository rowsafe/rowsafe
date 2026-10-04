package sqlite

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Find the moment for SQLite (protocol.TaskFindMoment): "when were rows
// deleted from orders?"
//
// SQLite's change stream in the bucket is pages, not statements: each
// committed transaction is the pages it wrote. The agent restores the file
// as it was at the start of the range into a private scratch file on this
// server (the newest backup before it plus the changes up to it), then
// replays the range one transaction at a time. Before each transaction's
// pages are written it keeps the pages they replace; after, it compares
// the rows on the pages that changed, table by table: rows whose key
// (rowid, or a WITHOUT ROWID table's primary key) is gone were deleted,
// rows whose content changed were updated, a table gone from sqlite_schema
// was dropped. Only table names, times and counts are reported: values
// are never decoded (rows are compared by a hash of their bytes) and never
// leave the server, and the scratch file is deleted when the search ends.
// The restore point "just before" a change is the millisecond before
// Rowsafe copied it.

// Limits of one search.
var (
	// momentMaxDuration bounds a search's replay; beyond it the result
	// covers the start of the range.
	momentMaxDuration = 10 * time.Minute
	// momentMaxOldBytes bounds the pages kept for one transaction; a
	// bigger transaction (a VACUUM of a large file) is listed as too big
	// to count.
	momentMaxOldBytes = 512 << 20
	// momentMaxRowPages bounds the pages whose rows are compared for one
	// table in one transaction; beyond it rows are counted, not compared.
	momentMaxRowPages = 200000
)

var errMomentStop = errors.New("the search reached its time limit")

func (e *Engine) findMoment(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.FindMomentParams, taskID string, tl agent.TaskLogger) (*protocol.FindMomentResult, error) {
	started := time.Now()
	search, err := agent.NewMomentSearch(p, started)
	if err != nil {
		return nil, err
	}
	if p.DB != "" && p.DB != "main" {
		return nil, fmt.Errorf("a SQLite database has one database, \"main\": leave the database empty or use main")
	}
	from, to := search.From(), search.To()
	if s := e.existingShipper(db.ID); s != nil && time.Since(to) < 5*time.Minute {
		if _, err := s.flush(ctx, time.Minute); err != nil {
			tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", err)
		}
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	snaps, _, err := r.listSnapshots(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing the backups in your bucket: %w", err)
	}
	if len(snaps) == 0 {
		return nil, errors.New("there is no finished backup of this database in your bucket yet")
	}
	sortSnaps(snaps)
	var notes []string
	if from.Before(snaps[0].At) {
		from = snaps[0].At
		notes = append(notes, "Rowsafe's record of changes starts with the oldest backup it keeps, at "+momentTime(from)+"; earlier changes can't be searched.")
	}
	if !from.Before(to) {
		return search.Result(from, to, notes, started), nil
	}
	dir := filepath.Join(drillRoot(env), "moment-"+safeName(taskID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "moment.db")

	w := &momentWatcher{search: search, from: from, deadline: started.Add(momentMaxDuration)}
	start, reached := from, from
	for pass := 0; pass < 8; pass++ {
		out, err := restoreWith(ctx, r, restoreTarget{Time: to, BaseBefore: start}, path, tl, w)
		if errors.Is(err, errMomentStop) {
			reached = w.lastAt
			notes = append(notes, "The range holds too many changes to replay in one search: it was searched up to "+momentTime(reached)+". Search from there for the rest.")
			break
		}
		if err != nil {
			return nil, err
		}
		if out.Snapshot.Gen == "" {
			notes = append(notes, "This database was in rollback-journal mode, so Rowsafe kept no record of each change: Find the moment needs continuous backups (WAL), which Pulse offers to turn on.")
			break
		}
		reached = out.RecoveredTo
		if out.GapAfter == nil && reached.Before(to) {
			reached = to // the stream is complete to the end of the range
		}
		// A newer generation (the chain broke and a new full copy started
		// it) carries on from its first copy.
		var next *snapDoc
		for i := range snaps {
			s := snaps[i]
			if s.Gen != "" && s.Gen != out.Snapshot.Gen && s.At.After(out.Snapshot.At) && s.At.Before(to) && (next == nil || s.At.Before(next.At)) {
				next = &snaps[i]
			}
		}
		if next == nil {
			if out.GapAfter != nil {
				notes = append(notes, out.Note)
			}
			break
		}
		if out.GapAfter != nil || next.At.After(out.RecoveredTo) {
			notes = append(notes, "Rowsafe's record of changes restarted with a new full copy at "+momentTime(next.At)+
				" (the app or a restore replaced the file's change log while Rowsafe couldn't follow); changes just before it may be missing.")
		}
		start = next.At
		w.reset()
		reached = next.At
	}
	tl.Printf("compared the rows of %d transactions", w.txns)
	notes = append(notes, "SQLite records pages, not statements: Rowsafe replayed the changes on a private copy on your server and compared each table's rows (by rowid or primary key) before and after each transaction. "+
		"Times are when Rowsafe copied each change, within a second of its commit; \"just before\" restores everything copied up to a millisecond earlier.")
	res := search.Result(from, reached, notes, started)
	res.Segments = w.txns
	res.WALBytes = w.bytes
	return res, nil
}

func momentTime(t time.Time) string { return t.UTC().Format("15:04:05 UTC on Jan 2") }

// momentWatcher compares each replayed transaction's rows (a replayHook).
type momentWatcher struct {
	search   *agent.MomentSearch
	from     time.Time
	deadline time.Time

	active   bool
	pageSize int
	usable   int
	npages   uint32 // pages in the file before the current transaction
	tables   map[string]*watchedTable
	schema   treePages

	inTx    bool
	old     map[uint32][]byte // pages as they were before the transaction
	touched map[uint32]bool
	oldSize int
	tooBig  bool

	seq     uint32
	lastAt  time.Time
	sameMs  int
	txns    int
	bytes   int64
	ignored map[string]bool // tables the search doesn't ask for
}

type watchedTable struct {
	schemaTable
	pages treePages
}

func (w *momentWatcher) reset() {
	w.active, w.inTx, w.old, w.touched, w.tables = false, false, nil, nil, nil
}

func fileView(f *os.File, pageSize, usable int, npages uint32) *pageView {
	return &pageView{pageSize: pageSize, usable: usable, npages: npages, read: func(pg uint32) ([]byte, error) {
		b := make([]byte, pageSize)
		if _, err := f.ReadAt(b, int64(pg-1)*int64(pageSize)); err != nil {
			return nil, fmt.Errorf("reading page %d of the scratch copy: %w", pg, err)
		}
		return b, nil
	}}
}

// start reads the file's tables at the moment the range starts.
func (w *momentWatcher) start(f *os.File, pageSize int) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	hdr := make([]byte, 100)
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return err
	}
	w.pageSize = pageSize
	w.usable = pageSize - int(hdr[20])
	w.npages = uint32(fi.Size() / int64(pageSize))
	v := fileView(f, w.pageSize, w.usable, w.npages)
	schema, sp, err := v.readSchema()
	if err != nil {
		return err
	}
	w.schema = sp
	w.tables = map[string]*watchedTable{}
	w.ignored = map[string]bool{}
	for name, st := range schema {
		if !w.search.Wants("main", name) {
			w.ignored[name] = true
		}
		tp, err := v.walk(st.Root)
		if err != nil {
			return fmt.Errorf("reading table %s: %w", name, err)
		}
		w.tables[name] = &watchedTable{schemaTable: st, pages: tp}
	}
	w.active = true
	return nil
}

func (w *momentWatcher) beforeApply(f *os.File, pageSize int, frames []byte, at time.Time, commit uint32) error {
	if !at.After(w.from) {
		return nil
	}
	if !w.active {
		if err := w.start(f, pageSize); err != nil {
			return fmt.Errorf("reading the database's tables at the start of the range: %w", err)
		}
	}
	if !w.inTx {
		if time.Now().After(w.deadline) {
			return errMomentStop
		}
		w.inTx, w.old, w.touched, w.oldSize, w.tooBig = true, map[uint32][]byte{}, map[uint32]bool{}, 0, false
	}
	keep := func(pg uint32) error {
		if w.tooBig || pg > w.npages {
			return nil
		}
		if _, ok := w.old[pg]; ok {
			return nil
		}
		if w.oldSize+pageSize > momentMaxOldBytes {
			w.tooBig = true
			return nil
		}
		b := make([]byte, pageSize)
		if _, err := f.ReadAt(b, int64(pg-1)*int64(pageSize)); err != nil {
			return err
		}
		w.old[pg] = b
		w.oldSize += pageSize
		return nil
	}
	frameSize := walFrameHeaderSize + pageSize
	for off := 0; off+frameSize <= len(frames); off += frameSize {
		pg := binary.BigEndian.Uint32(frames[off:])
		w.touched[pg] = true
		if err := keep(pg); err != nil {
			return err
		}
	}
	w.bytes += int64(len(frames))
	if commit > 0 && commit < w.npages {
		// The file shrinks: keep the pages it cuts off (rows and their
		// overflow pages).
		for pg := commit + 1; pg <= w.npages && !w.tooBig; pg++ {
			if err := keep(pg); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *momentWatcher) committed(f *os.File, at time.Time, gen string, end pos) error {
	if !w.active || !w.inTx {
		return nil
	}
	w.inTx = false
	w.txns++
	w.seq++
	if at.Truncate(time.Millisecond).Equal(w.lastAt.Truncate(time.Millisecond)) {
		w.sameMs++
	} else {
		w.sameMs = 0
	}
	w.lastAt = at
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	newN := uint32(fi.Size() / int64(w.pageSize))
	oldN := w.npages
	old := w.old
	before := &pageView{pageSize: w.pageSize, usable: w.usable, npages: oldN, read: func(pg uint32) ([]byte, error) {
		if b, ok := old[pg]; ok {
			return b, nil
		}
		b := make([]byte, w.pageSize)
		if _, err := f.ReadAt(b, int64(pg-1)*int64(w.pageSize)); err != nil {
			return nil, fmt.Errorf("reading page %d of the scratch copy: %w", pg, err)
		}
		return b, nil
	}}
	after := fileView(f, w.pageSize, w.usable, newN)
	w.npages = newN
	w.old, w.oldSize = nil, 0
	touched := w.touched
	w.touched = nil
	xid := uint32(1<<31) | w.seq&(1<<31-1)
	note := ""
	if w.sameMs > 0 {
		note = fmt.Sprintf("Rowsafe copied %s in the same millisecond just before this one: rewinding to just before this change leaves %s out too.",
			nplural(int64(w.sameMs), "other change", "other changes"), map[bool]string{true: "it", false: "them"}[w.sameMs == 1])
	}
	lsnText := lsn(gen, end)
	if w.tooBig {
		// Too big to compare: say so, and read the tables afresh.
		w.search.Add(agent.MomentTx{Time: at, XID: xid, Changes: []protocol.Moment{{Kind: protocol.MomentUpdate, DB: "main", LSN: lsnText,
			Note: "A transaction too big for Rowsafe to compare (it rewrote " + humanBytes(int64(len(touched))*int64(w.pageSize)) + ", e.g. a VACUUM): its rows weren't counted."}}})
		w.active = false
		return w.start(f, w.pageSize)
	}
	changes, err := w.compare(before, after, touched)
	if err != nil {
		return fmt.Errorf("comparing the rows of the transaction at %s: %w", momentTime(at), err)
	}
	for i := range changes {
		changes[i].LSN = lsnText
		if note != "" && changes[i].Note == "" {
			changes[i].Note = note
		}
	}
	if len(changes) > 0 {
		w.search.Add(agent.MomentTx{Time: at, XID: xid, Changes: changes})
	}
	return nil
}

// compare lists what one transaction did to each table.
func (w *momentWatcher) compare(before, after *pageView, touched map[uint32]bool) ([]protocol.Moment, error) {
	schemaChanged := touched[1]
	for pg := range touched {
		if w.schema.has(pg) {
			schemaChanged = true
			break
		}
	}
	newSchema := map[string]schemaTable{}
	if schemaChanged {
		s, sp, err := after.readSchema()
		if err != nil {
			return nil, err
		}
		newSchema, w.schema = s, sp
	} else {
		for name, t := range w.tables {
			newSchema[name] = t.schemaTable
		}
	}
	// Renames keep their root page.
	byRoot := map[uint32]string{}
	for name, st := range newSchema {
		byRoot[st.Root] = name
	}
	var out []protocol.Moment
	names := make([]string, 0, len(w.tables))
	for name := range w.tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t := w.tables[name]
		nt, ok := newSchema[name]
		if !ok {
			if nn, renamed := byRoot[t.Root]; renamed && w.tables[nn] == nil {
				delete(w.tables, name)
				t.Name = nn
				w.tables[nn] = t
				w.ignored[nn] = !w.search.Wants("main", nn)
				name, nt = nn, newSchema[nn]
			} else {
				rows := int64(0)
				for pg := range t.pages.rows {
					n, err := before.cellCount(pg)
					if err != nil {
						return nil, err
					}
					rows += int64(n)
				}
				delete(w.tables, name)
				if !w.ignored[name] {
					out = append(out, protocol.Moment{Kind: protocol.MomentDrop, DB: "main", Table: name, Rows: rows})
				}
				continue
			}
		}
		rebuilt := nt.Root != t.Root
		structural, affected := rebuilt, rebuilt
		for pg := range touched {
			if t.pages.inner[pg] || pg == t.Root {
				structural, affected = true, true
				break
			}
			if t.pages.rows[pg] {
				affected = true
			}
		}
		if !affected {
			continue
		}
		afterPages := t.pages
		if structural {
			tp, err := after.walk(nt.Root)
			if err != nil {
				return nil, fmt.Errorf("reading table %s: %w", name, err)
			}
			afterPages = tp
		}
		prev := t.pages
		t.schemaTable, t.pages = nt, afterPages
		if w.ignored[name] {
			continue
		}
		m, err := diffRows(before, after, prev, afterPages, touched, rebuilt, nt.PKCols)
		if err != nil {
			return nil, fmt.Errorf("table %s: %w", name, err)
		}
		for _, c := range m {
			c.DB, c.Table = "main", name
			out = append(out, c)
		}
	}
	// New tables.
	for name, st := range newSchema {
		if w.tables[name] != nil {
			continue
		}
		tp, err := after.walk(st.Root)
		if err != nil {
			return nil, fmt.Errorf("reading table %s: %w", name, err)
		}
		w.tables[name] = &watchedTable{schemaTable: st, pages: tp}
		w.ignored[name] = !w.search.Wants("main", name)
	}
	return out, nil
}

// diffRows compares a table's rows on the pages a transaction changed.
func diffRows(before, after *pageView, prev, next treePages, touched map[uint32]bool, rebuilt bool, pkCols int) ([]protocol.Moment, error) {
	var bp, ap []uint32
	for pg := range prev.rows {
		if rebuilt || touched[pg] || !next.rows[pg] {
			bp = append(bp, pg)
		}
	}
	for pg := range next.rows {
		if rebuilt || touched[pg] || !prev.rows[pg] {
			ap = append(ap, pg)
		}
	}
	count := func(v *pageView, pages []uint32) (int64, error) {
		var n int64
		for _, pg := range pages {
			c, err := v.cellCount(pg)
			if err != nil {
				return 0, err
			}
			n += int64(c)
		}
		return n, nil
	}
	// Emptied (DELETE without WHERE frees every page at once).
	if len(next.rows) == 1 && !rebuilt {
		if n, err := count(after, ap); err == nil && n == 0 {
			del, err := count(before, bp)
			if err != nil || del == 0 {
				return nil, err
			}
			return []protocol.Moment{{Kind: protocol.MomentDelete, Rows: del}}, nil
		}
	}
	if len(bp)+len(ap) > momentMaxRowPages {
		nb, err := count(before, bp)
		if err != nil {
			return nil, err
		}
		na, err := count(after, ap)
		if err != nil {
			return nil, err
		}
		if nb > na {
			return []protocol.Moment{{Kind: protocol.MomentDelete, Rows: nb - na, Estimated: true,
				Note: "Too many pages changed to compare rows one by one: the rows were counted (deleted minus inserted)."}}, nil
		}
		return nil, nil
	}
	old := map[string]uint64{}
	for _, pg := range bp {
		rs, err := before.rows(pg, pkCols)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			old[r.key] = r.hash
		}
	}
	var updated int64
	for _, pg := range ap {
		rs, err := after.rows(pg, pkCols)
		if err != nil {
			return nil, err
		}
		for _, r := range rs {
			h, ok := old[r.key]
			if !ok {
				continue // inserted
			}
			if h != r.hash {
				updated++
			}
			delete(old, r.key)
		}
	}
	var out []protocol.Moment
	note := ""
	if rebuilt {
		note = "The table was rebuilt in this transaction (ALTER TABLE or a copy-and-rename migration)."
	}
	if n := int64(len(old)); n > 0 {
		out = append(out, protocol.Moment{Kind: protocol.MomentDelete, Rows: n, Note: note})
	}
	if updated > 0 {
		out = append(out, protocol.Moment{Kind: protocol.MomentUpdate, Rows: updated, Note: note})
	}
	return out, nil
}

func nplural(n int64, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return commas(n) + " " + many
}
