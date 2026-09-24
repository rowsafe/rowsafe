package agent

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// Find the moment, part 1: reading pg_waldump's text output.
//
// pg_waldump prints one line per WAL record:
//
//	rmgr: Heap        len (rec/tot):     54/    54, tx:        747, lsn: 0/019A6538, prev 0/019A6500, desc: DELETE xmax: 747, off: 56, ..., blkref #0: rel 1663/16384/16386 blk 54
//	rmgr: Transaction len (rec/tot):     46/    46, tx:        748, lsn: 0/019A6950, prev 0/019A6908, desc: COMMIT 2026-09-24 22:45:08.071647 UTC; subxacts: 749
//
// The scanner keeps only what says which transaction changed which table
// and how: row deletes and updates (one record per row), the commit or
// abort of each transaction (with its time and subtransactions), and for
// TRUNCATE and DROP the relations it locked, the files it created and the
// files it dropped. Row contents are never looked at (pg_waldump doesn't
// print them). Lines are handled as they stream in; nothing is kept for a
// transaction once it ends.

// walRel is a relation file: the database's OID and the relfilenode.
// (Relfilenodes are unique within a database in practice; the tablespace is
// left out.)
type walRel struct{ DB, Rel uint32 }

// walOID is a relation's OID within a database.
type walOID struct{ DB, OID uint32 }

// walChange is one kind of row change to one relation file.
type walChange struct {
	Rel  walRel
	Kind string // MomentDelete or MomentUpdate
}

// walTx is what the scanner collects for one transaction (or
// subtransaction) until it ends.
type walTx struct {
	changes map[walChange]int64
	// locks are the relations it locked exclusively (Standby LOCK), in
	// order.
	locks []walOID
	// created are the relation files it created (Storage CREATE, main fork
	// only), in order; paired[i] is the relation locked just before
	// created[i] (a TRUNCATE locks the relation, then gives it a new file),
	// or zero.
	created []walRel
	paired  []walOID
	// lastLock is the latest lock not yet followed by a CREATE.
	lastLock *walOID
	// written are created files that got full page images: data copied in
	// by VACUUM FULL, CLUSTER or an ALTER TABLE rewrite, which aren't
	// losses. The block numbers matter: an empty index gets a metapage
	// (block 0) even on TRUNCATE.
	written map[walRel]uint32 // highest block written + 1
	// truncated are relations a Heap TRUNCATE record names (wal_level
	// logical only).
	truncated []walOID
	// droppedDBs are databases dropped (Database DROP), by OID.
	droppedDBs []uint32
}

// walCommit is a committed transaction, with its subtransactions merged in.
type walCommit struct {
	XID  uint32
	Time time.Time
	LSN  uint64
	walTx
	// dropped are the relation files removed at commit ("rels:"), in the
	// record's order; droppedOIDs the relations whose statistics were
	// dropped ("dropped stats: 2/db/oid", PostgreSQL 15 and later).
	dropped     []walRel
	droppedOIDs []walOID
}

// walScanner consumes pg_waldump lines.
type walScanner struct {
	major   int
	pending map[uint32]*walTx
	// onCommit receives every committed transaction that did something the
	// scanner tracks (and, with a zero XID, nothing else).
	onCommit func(*walCommit)

	// LastLSN is the latest record seen; Records how many were read.
	// Records at or before skipTo were read already (a batch starts again
	// at the last record of the one before) and are skipped.
	LastLSN uint64
	skipTo  uint64
	Records int64
	// FirstTime and LastTime are the first and last commit or abort times
	// seen: the stretch of time the WAL read covers.
	FirstTime, LastTime time.Time
}

func newWalScanner(major int, onCommit func(*walCommit)) *walScanner {
	return &walScanner{major: major, pending: map[uint32]*walTx{}, onCommit: onCommit}
}

// walRecord is the part of a line the scanner needs.
type walRecord struct {
	rmgr string
	xid  uint32
	lsn  uint64
	desc string // everything after "desc: "
}

// parseWalLine splits one pg_waldump line. ok is false for anything that
// isn't a record line (warnings, the final error).
func parseWalLine(line string) (r walRecord, ok bool) {
	rest, found := strings.CutPrefix(line, "rmgr: ")
	if !found {
		return r, false
	}
	i := strings.IndexByte(rest, ' ')
	if i <= 0 {
		return r, false
	}
	r.rmgr = rest[:i]
	rest = rest[i:]
	j := strings.Index(rest, "tx:")
	if j < 0 {
		return r, false
	}
	rest = strings.TrimLeft(rest[j+3:], " ")
	k := strings.IndexByte(rest, ',')
	if k < 0 {
		return r, false
	}
	xid, err := strconv.ParseUint(rest[:k], 10, 32)
	if err != nil {
		return r, false
	}
	r.xid = uint32(xid)
	rest = rest[k:]
	l := strings.Index(rest, "lsn: ")
	if l < 0 {
		return r, false
	}
	rest = rest[l+5:]
	m := strings.IndexByte(rest, ',')
	if m < 0 {
		return r, false
	}
	lsn, ok := parseLSN(rest[:m])
	if !ok {
		return r, false
	}
	r.lsn = lsn
	d := strings.Index(rest, "desc: ")
	if d < 0 {
		return r, false
	}
	r.desc = rest[d+6:]
	return r, true
}

// parseLSN parses "16/B374D848".
func parseLSN(s string) (uint64, bool) {
	hi, lo, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return 0, false
	}
	h, err1 := strconv.ParseUint(hi, 16, 32)
	l, err2 := strconv.ParseUint(lo, 16, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return h<<32 | l, true
}

// formatLSN is PostgreSQL's %X/%08X.
func formatLSN(lsn uint64) string {
	return strings.ToUpper(strconv.FormatUint(lsn>>32, 16)) + "/" + leftPad(strings.ToUpper(strconv.FormatUint(lsn&0xFFFFFFFF, 16)), 8)
}

func leftPad(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return strings.Repeat("0", n-len(s)) + s
}

// descType is the record type: the first word of desc ("DELETE",
// "HOT_UPDATE+INIT" -> "HOT_UPDATE").
func descType(desc string) string {
	end := strings.IndexAny(desc, " ,;")
	if end < 0 {
		end = len(desc)
	}
	t := desc[:end]
	if i := strings.IndexByte(t, '+'); i > 0 {
		t = t[:i]
	}
	return t
}

// firstBlockRel finds "blkref #0: rel SPC/DB/REL" and returns DB and REL
// (and the block number).
func firstBlockRel(desc string) (walRel, uint32, bool) {
	i := strings.Index(desc, "blkref #")
	if i < 0 {
		return walRel{}, 0, false
	}
	return blockRel(desc[i:])
}

// blockRel parses "blkref #N: rel SPC/DB/REL [fork F] blk B" at the start of
// s.
func blockRel(s string) (walRel, uint32, bool) {
	j := strings.Index(s, "rel ")
	if j < 0 {
		return walRel{}, 0, false
	}
	s = s[j+4:]
	end := strings.IndexAny(s, " ,")
	if end < 0 {
		end = len(s)
	}
	parts := strings.Split(s[:end], "/")
	if len(parts) != 3 {
		return walRel{}, 0, false
	}
	db, err1 := strconv.ParseUint(parts[1], 10, 32)
	rel, err2 := strconv.ParseUint(parts[2], 10, 32)
	if err1 != nil || err2 != nil {
		return walRel{}, 0, false
	}
	var blk uint64
	if b := strings.Index(s, "blk "); b >= 0 {
		t := s[b+4:]
		e := strings.IndexAny(t, " ,;")
		if e < 0 {
			e = len(t)
		}
		blk, _ = strconv.ParseUint(t[:e], 10, 32)
	}
	return walRel{DB: uint32(db), Rel: uint32(rel)}, uint32(blk), true
}

// allBlockRels returns every block reference of a record that isn't for
// another fork (fsm, vm, init).
func allBlockRels(desc string) (rels []walRel, blocks []uint32) {
	for {
		i := strings.Index(desc, "blkref #")
		if i < 0 {
			return rels, blocks
		}
		desc = desc[i+len("blkref #"):]
		next := strings.Index(desc, "blkref #")
		seg := desc
		if next >= 0 {
			seg = desc[:next]
		}
		if !strings.Contains(seg, " fork ") {
			if r, b, ok := blockRel(seg); ok {
				rels = append(rels, r)
				blocks = append(blocks, b)
			}
		}
	}
}

// fileRel parses "base/DB/REL" or "pg_tblspc/SPC/PG_17_x/DB/REL"; forks
// ("REL_fsm") and global relations are skipped.
func fileRel(path string) (walRel, bool) {
	parts := strings.Split(path, "/")
	if len(parts) < 3 || parts[0] == "global" {
		return walRel{}, false
	}
	db, err1 := strconv.ParseUint(parts[len(parts)-2], 10, 32)
	rel, err2 := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err1 != nil || err2 != nil {
		return walRel{}, false
	}
	return walRel{DB: uint32(db), Rel: uint32(rel)}, true
}

// section returns the value of "; name: value" in a commit or abort desc
// (up to the next ';').
func section(desc, name string) string {
	i := strings.Index(desc, "; "+name+": ")
	if i < 0 {
		return ""
	}
	s := desc[i+len(name)+4:]
	if j := strings.IndexByte(s, ';'); j >= 0 {
		s = s[:j]
	}
	return s
}

// commitTime parses the timestamp that starts a COMMIT or ABORT desc
// ("2026-09-24 22:45:08.071647 UTC"); pg_waldump runs with TZ=UTC.
func commitTime(desc string) (time.Time, bool) {
	s := desc
	if i := strings.IndexByte(s, ' '); i >= 0 {
		s = s[i+1:] // skip "COMMIT"
	}
	if j := strings.IndexByte(s, ';'); j >= 0 {
		s = s[:j]
	}
	s = strings.TrimSpace(s)
	t, err := time.Parse("2006-01-02 15:04:05.999999999 MST", s)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05.999999999-07", s)
	}
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func (s *walScanner) tx(xid uint32) *walTx {
	t := s.pending[xid]
	if t == nil {
		t = &walTx{}
		s.pending[xid] = t
	}
	return t
}

// Line handles one line of pg_waldump output.
func (s *walScanner) Line(line string) {
	r, ok := parseWalLine(line)
	if !ok {
		return
	}
	if r.lsn <= s.skipTo && s.skipTo != 0 {
		return
	}
	s.Records++
	if r.lsn > s.LastLSN {
		s.LastLSN = r.lsn
	}
	switch r.rmgr {
	case "Heap":
		if r.xid == 0 {
			return
		}
		switch descType(r.desc) {
		case "DELETE":
			s.change(r, "delete")
		case "UPDATE", "HOT_UPDATE":
			s.change(r, "update")
		case "TRUNCATE":
			// wal_level logical only: "TRUNCATE flags: [], nrelids: 1,
			// relids: [16394]" (older: "nrelids 1 relids 16394"). No database
			// in the text: TRUNCATE locked the tables first, so it's the
			// locks' database.
			i := strings.LastIndex(r.desc, "relids")
			db := s.lastDB(r.xid)
			if i < 0 || db == 0 {
				return
			}
			t := s.tx(r.xid)
			for _, f := range strings.Fields(strings.TrimLeft(r.desc[i+len("relids"):], ": ")) {
				if oid, err := strconv.ParseUint(strings.Trim(f, ",[]"), 10, 32); err == nil {
					t.truncated = append(t.truncated, walOID{DB: db, OID: uint32(oid)})
				}
			}
		}
	case "Standby":
		if !strings.HasPrefix(r.desc, "LOCK ") || r.xid == 0 {
			return
		}
		// "LOCK xid 750 db 16384 rel 16386 [xid ... db ... rel ...]"
		f := strings.Fields(r.desc[5:])
		for i := 0; i+5 < len(f); i += 6 {
			if f[0+i] != "xid" || f[2+i] != "db" || f[4+i] != "rel" {
				break
			}
			xid, err0 := strconv.ParseUint(f[1+i], 10, 32)
			db, err1 := strconv.ParseUint(f[3+i], 10, 32)
			oid, err2 := strconv.ParseUint(f[5+i], 10, 32)
			if err0 != nil || err1 != nil || err2 != nil || db == 0 {
				continue
			}
			t := s.tx(uint32(xid))
			o := walOID{DB: uint32(db), OID: uint32(oid)}
			t.locks = append(t.locks, o)
			t.lastLock = &o
		}
	case "Storage":
		if r.xid == 0 || !strings.HasPrefix(r.desc, "CREATE ") {
			return
		}
		path := strings.TrimSpace(r.desc[len("CREATE "):])
		if strings.ContainsRune(path[strings.LastIndexByte(path, '/')+1:], '_') {
			return // another fork
		}
		rel, ok := fileRel(path)
		if !ok {
			return
		}
		t := s.tx(r.xid)
		var paired walOID
		if t.lastLock != nil && t.lastLock.DB == rel.DB {
			paired = *t.lastLock
		}
		t.lastLock = nil
		t.created = append(t.created, rel)
		t.paired = append(t.paired, paired)
	case "XLOG":
		if r.xid == 0 || descType(r.desc) != "FPI" {
			return
		}
		t := s.pending[r.xid]
		if t == nil || len(t.created) == 0 {
			return
		}
		rels, blocks := allBlockRels(r.desc)
		for i, rel := range rels {
			if slices.Contains(t.created, rel) {
				if t.written == nil {
					t.written = map[walRel]uint32{}
				}
				t.written[rel] = max(t.written[rel], blocks[i]+1)
			}
		}
	case "Database":
		if r.xid == 0 || !strings.HasPrefix(r.desc, "DROP ") {
			return
		}
		// 15+: "DROP dir 1663/16421"; 13 and 14: "DROP dir 16421/1663".
		for _, f := range strings.Fields(r.desc[len("DROP "):]) {
			a, b, ok := strings.Cut(f, "/")
			if !ok {
				continue
			}
			id := b
			if s.major > 0 && s.major < 15 {
				id = a
			}
			if oid, err := strconv.ParseUint(id, 10, 32); err == nil {
				t := s.tx(r.xid)
				if !slices.Contains(t.droppedDBs, uint32(oid)) {
					t.droppedDBs = append(t.droppedDBs, uint32(oid))
				}
			}
		}
	case "Transaction":
		s.transaction(r)
	}
}

// lastDB guesses the database of a record without one: the database of the
// transaction's latest lock.
func (s *walScanner) lastDB(xid uint32) uint32 {
	if t := s.pending[xid]; t != nil && len(t.locks) > 0 {
		return t.locks[len(t.locks)-1].DB
	}
	return 0
}

func (s *walScanner) change(r walRecord, kind string) {
	rel, _, ok := firstBlockRel(r.desc)
	if !ok || rel.Rel < firstNormalObjectID {
		return // system catalogs keep their first files
	}
	t := s.tx(r.xid)
	if t.changes == nil {
		t.changes = map[walChange]int64{}
	}
	t.changes[walChange{Rel: rel, Kind: kind}]++
}

// firstNormalObjectID is PostgreSQL's FirstNormalObjectId: user objects
// (and their files) are numbered from here.
const firstNormalObjectID = 16384

func (s *walScanner) transaction(r walRecord) {
	typ := descType(r.desc)
	switch typ {
	case "COMMIT", "ABORT":
	default:
		return // PREPARE, COMMIT_PREPARED, ASSIGNMENT, INVALIDATION...
	}
	at, ok := commitTime(r.desc)
	if ok {
		if s.FirstTime.IsZero() || at.Before(s.FirstTime) {
			s.FirstTime = at
		}
		if at.After(s.LastTime) {
			s.LastTime = at
		}
	}
	xids := []uint32{r.xid}
	for _, f := range strings.Fields(section(r.desc, "subxacts")) {
		if x, err := strconv.ParseUint(f, 10, 32); err == nil {
			xids = append(xids, uint32(x))
		}
	}
	if typ == "ABORT" || r.xid == 0 {
		for _, x := range xids {
			delete(s.pending, x)
		}
		return
	}
	c := &walCommit{XID: r.xid, Time: at, LSN: r.lsn}
	for _, x := range xids {
		t := s.pending[x]
		if t == nil {
			continue
		}
		delete(s.pending, x)
		mergeTx(&c.walTx, t)
	}
	for _, f := range strings.Fields(section(r.desc, "rels")) {
		if rel, ok := fileRel(f); ok {
			c.dropped = append(c.dropped, rel)
		}
	}
	for _, f := range strings.Fields(section(r.desc, "dropped stats")) {
		p := strings.Split(f, "/")
		if len(p) != 3 || p[0] != "2" { // 2 = PGSTAT_KIND_RELATION
			continue
		}
		db, err1 := strconv.ParseUint(p[1], 10, 32)
		oid, err2 := strconv.ParseUint(p[2], 10, 32)
		if err1 == nil && err2 == nil {
			c.droppedOIDs = append(c.droppedOIDs, walOID{DB: uint32(db), OID: uint32(oid)})
		}
	}
	if !ok || (len(c.changes) == 0 && len(c.locks) == 0 && len(c.dropped) == 0 && len(c.truncated) == 0 && len(c.droppedDBs) == 0) {
		return
	}
	s.onCommit(c)
}

func mergeTx(dst, src *walTx) {
	if len(src.changes) > 0 {
		if dst.changes == nil {
			dst.changes = map[walChange]int64{}
		}
		for k, v := range src.changes {
			dst.changes[k] += v
		}
	}
	dst.locks = append(dst.locks, src.locks...)
	dst.created = append(dst.created, src.created...)
	dst.paired = append(dst.paired, src.paired...)
	for k, v := range src.written {
		if dst.written == nil {
			dst.written = map[walRel]uint32{}
		}
		dst.written[k] = max(dst.written[k], v)
	}
	dst.truncated = append(dst.truncated, src.truncated...)
	dst.droppedDBs = append(dst.droppedDBs, src.droppedDBs...)
}
