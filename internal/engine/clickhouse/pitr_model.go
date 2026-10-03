package clickhouse

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
)

// Restores to any second (point in time).
//
// ClickHouse keeps no log of row changes, but it never changes a table's
// data in place: every INSERT writes a new part (a folder of immutable
// files), a merge writes a new part that replaces its sources, a mutation
// (ALTER UPDATE/DELETE, lightweight DELETE) a new version of each part it
// changes, and TRUNCATE, DROP PARTITION or DETACH an empty part that
// covers the ones they remove. ClickHouse records each new part in
// system.part_log, to the microsecond. So a table at any moment T is
// exactly the parts created up to T that no part created up to T covers
// (a part covers another of the same partition when its block range
// contains the other's, at a level and mutation at least the other's: the
// rule ClickHouse itself uses).
//
// The agent copies every new part from the server's disk (read only) into
// the bucket as it appears, encrypted on the server, and records when it
// appeared; table and database definitions are recorded the same way. A
// restore to T assembles a ClickHouse backup of the parts active at T
// (backups.go's format: a .backup file listing every file) that the
// gateway serves from the copied parts and from the backup the record
// started from, and restores it like any other backup. See pitr_ship.go
// (copying) and pitr_restore.go (assembling).
//
// Tables that keep no parts (Log, Memory...) or keep them on object
// storage come back as of the newest backup or Mark taken before T.

// partInfo is what a part's name says: <partition>_<min>_<max>_<level>[_<mutation>].
type partInfo struct {
	Partition       string
	Min, Max        int64
	Level, Mutation int64
	ok              bool
}

// parsePartName reads a part's name; partition is its partition_id when
// known ("" to guess: the last three or four numbers are the block range,
// level and mutation).
func parsePartName(name, partition string) partInfo {
	rest := name
	if partition != "" {
		r, ok := strings.CutPrefix(name, partition+"_")
		if !ok {
			return partInfo{}
		}
		rest = r
	}
	f := strings.Split(rest, "_")
	if partition == "" {
		// The partition id never ends in "_<digits>" groups that would
		// be ambiguous for the parts ClickHouse names today: take the
		// partition as everything before the last 4 numbers when there
		// are 5+ fields, else before the last 3.
		n := 3
		if len(f) >= 5 {
			n = 4
		}
		if len(f) < n+1 {
			return partInfo{}
		}
		partition = strings.Join(f[:len(f)-n], "_")
		f = f[len(f)-n:]
	}
	if len(f) != 3 && len(f) != 4 {
		return partInfo{}
	}
	nums := make([]int64, 4)
	for i, s := range f {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			return partInfo{}
		}
		nums[i] = v
	}
	return partInfo{Partition: partition, Min: nums[0], Max: nums[1], Level: nums[2], Mutation: nums[3], ok: true}
}

// contains is ClickHouse's MergeTreePartInfo::contains: a covers b.
func (a partInfo) contains(b partInfo) bool {
	return a.ok && b.ok && a.Partition == b.Partition && a.Min <= b.Min && a.Max >= b.Max &&
		a.Level >= b.Level && a.Mutation >= b.Mutation
}

// pitFile is a file of a part (its path inside the part folder, e.g.
// "data.bin" or "proj.proj/data.bin") or of a table without parts, and
// where its bytes are in the bucket.
type pitFile struct {
	Name   string       `json:"n"`
	Size   int64        `json:"s"`
	Pieces []s3gw.Piece `json:"p,omitempty"`
}

// pitPart is a part of a MergeTree table.
type pitPart struct {
	Name string    `json:"name"`
	Rows int64     `json:"rows"`
	At   time.Time `json:"at"` // when ClickHouse created it
	// Partition is its partition_id ("" when it wasn't known).
	Partition string `json:"partition,omitempty"`
	// Files are its files; empty when it couldn't be copied, then Sources
	// (the parts it was merged from, which add up to the same rows) stand
	// in for it.
	Files   []pitFile `json:"files,omitempty"`
	Sources []string  `json:"sources,omitempty"`
	// Gone is when it was replaced (State.Merged only).
	Gone time.Time `json:"gone,omitzero"`
}

func (p *pitPart) info() partInfo { return parsePartName(p.Name, p.Partition) }

func (p *pitPart) bytes() int64 {
	var n int64
	for _, f := range p.Files {
		n += f.Size
	}
	return n
}

// pitTable is a table's definition.
type pitTable struct {
	UUID   string    `json:"uuid"`
	DB     string    `json:"db"`
	Name   string    `json:"name"`
	Engine string    `json:"engine"`
	Create string    `json:"create"` // CREATE TABLE with its UUID, as BACKUP writes it
	At     time.Time `json:"at"`     // since when it is so
	// Parts: a MergeTree table whose parts are on a local disk (its data
	// is in the record); the others come from backups.
	Parts       bool     `json:"parts,omitempty"`
	Dependents  []string `json:"dependents,omitempty"`
	Refreshable bool     `json:"refreshable,omitempty"`
}

func (t pitTable) key() string { return t.DB + "." + t.Name }

// pitDB is a database's definition.
type pitDB struct {
	UUID   string    `json:"uuid"`
	Name   string    `json:"name"`
	Engine string    `json:"engine"`
	Create string    `json:"create"`
	At     time.Time `json:"at"`
}

// pitGap is a span the record can't restore into exactly: changes in it
// couldn't be copied (the agent was stopped for longer than ClickHouse
// keeps replaced parts, a part couldn't be read...).
type pitGap struct {
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
	Table string    `json:"table,omitempty"` // "db.name", "" for all
	Why   string    `json:"why"`
}

// Event kinds.
const (
	evPart   = "part"   // a part was created (it covers the parts it replaces)
	evUnpart = "unpart" // a part went away without a part covering it
	evTable  = "table"  // a table was created or changed (renamed, altered)
	evDrop   = "drop"   // a table was dropped
	evDB     = "db"     // a database was created or changed
	evDropDB = "dropdb" // a database was dropped
	evGap    = "gap"    // see pitGap
)

// pitEvent is one change, in the record.
type pitEvent struct {
	At    time.Time `json:"at"`
	Kind  string    `json:"kind"`
	Table string    `json:"table,omitempty"` // table UUID (part, unpart, table, drop)
	Part  *pitPart  `json:"part,omitempty"`
	Name  string    `json:"name,omitempty"` // unpart: the part
	Def   *pitTable `json:"def,omitempty"`
	DB    *pitDB    `json:"db,omitempty"`
	UUID  string    `json:"uuid,omitempty"` // dropdb
	Gap   *pitGap   `json:"gap,omitempty"`
}

// pitState is the server at a moment: its databases, tables and the active
// parts of each table.
type pitState struct {
	At     time.Time                      `json:"at"`
	DBs    map[string]*pitDB              `json:"dbs"`
	Tables map[string]*pitTable           `json:"tables"`
	Parts  map[string]map[string]*pitPart `json:"parts"` // table UUID -> part name -> part
	// Merged are recently replaced parts: a part merged from them that
	// couldn't be copied reads them instead (by name). See prune.
	Merged map[string]map[string]*pitPart `json:"merged,omitempty"`
}

func newPitState(at time.Time) *pitState {
	return &pitState{At: at, DBs: map[string]*pitDB{}, Tables: map[string]*pitTable{}, Parts: map[string]map[string]*pitPart{}}
}

// apply applies one event (in time order).
func (s *pitState) apply(e pitEvent) {
	if e.At.After(s.At) {
		s.At = e.At
	}
	switch e.Kind {
	case evPart:
		p := e.Part
		if p == nil {
			return
		}
		pi := p.info()
		parts := s.Parts[e.Table]
		if parts == nil {
			parts = map[string]*pitPart{}
			s.Parts[e.Table] = parts
		}
		for name, cur := range parts {
			if name != p.Name && cur.info().contains(pi) {
				// Already replaced (recorded in the same second as the
				// part that covers it): never active again.
				s.keepMerged(e.Table, p, e.At)
				return
			}
		}
		for name, old := range parts {
			if name != p.Name && pi.contains(old.info()) {
				delete(parts, name)
				if len(old.Files) > 0 || len(old.Sources) > 0 {
					s.keepMerged(e.Table, old, e.At)
				}
			}
		}
		if p.Rows > 0 {
			parts[p.Name] = p
		}
	case evUnpart:
		delete(s.Parts[e.Table], e.Name)
	case evTable:
		if e.Def != nil {
			d := *e.Def
			s.Tables[e.Table] = &d
		}
	case evDrop:
		delete(s.Tables, e.Table)
		delete(s.Parts, e.Table)
	case evDB:
		if e.DB != nil {
			d := *e.DB
			s.DBs[d.UUID] = &d
		}
	case evDropDB:
		delete(s.DBs, e.UUID)
	}
}

// keepMerged remembers a replaced part, for a part merged from it that
// couldn't be copied (prune forgets it later).
func (s *pitState) keepMerged(table string, p *pitPart, now time.Time) {
	if s.Merged == nil {
		s.Merged = map[string]map[string]*pitPart{}
	}
	m := s.Merged[table]
	if m == nil {
		m = map[string]*pitPart{}
		s.Merged[table] = m
	}
	c := *p
	c.Gone = now
	m[p.Name] = &c
}

// prune forgets the replaced parts gone for longer than keep that no
// active part needs.
func (s *pitState) prune(now time.Time, keep time.Duration) {
	for table, m := range s.Merged {
		need := map[string]bool{}
		var mark func(p *pitPart)
		mark = func(p *pitPart) {
			if len(p.Files) > 0 {
				return
			}
			for _, src := range p.Sources {
				if !need[src] {
					need[src] = true
					if sp := m[src]; sp != nil {
						mark(sp)
					}
				}
			}
		}
		for _, p := range s.Parts[table] {
			mark(p)
		}
		for name, p := range m {
			if !need[name] && now.Sub(p.Gone) > keep {
				delete(m, name)
			}
		}
		if len(m) == 0 || s.Tables[table] == nil {
			delete(s.Merged, table)
		}
	}
}

// files returns the files that hold part p's rows: its own, or its
// sources' (recursively) when it couldn't be copied. ok is false when some
// rows can't be found.
func (s *pitState) files(table string, p *pitPart) (out []*pitPart, ok bool) {
	if len(p.Files) > 0 {
		return []*pitPart{p}, true
	}
	if len(p.Sources) == 0 {
		return nil, false
	}
	for _, name := range p.Sources {
		src := s.Merged[table][name]
		if src == nil {
			return nil, false
		}
		sub, ok := s.files(table, src)
		if !ok {
			return nil, false
		}
		out = append(out, sub...)
	}
	return out, true
}

// clone deep-copies the maps (parts and definitions are never changed in
// place once recorded).
func (s *pitState) clone() *pitState {
	c := newPitState(s.At)
	for k, v := range s.DBs {
		c.DBs[k] = v
	}
	for k, v := range s.Tables {
		c.Tables[k] = v
	}
	for k, m := range s.Parts {
		cm := make(map[string]*pitPart, len(m))
		for n, p := range m {
			cm[n] = p
		}
		c.Parts[k] = cm
	}
	if s.Merged != nil {
		c.Merged = map[string]map[string]*pitPart{}
		for k, m := range s.Merged {
			cm := make(map[string]*pitPart, len(m))
			for n, p := range m {
				cm[n] = p
			}
			c.Merged[k] = cm
		}
	}
	return c
}

// rows is a table's row count at the state's moment (the parts' rows,
// lightweight-deleted rows included).
func (s *pitState) rows(uuid string) int64 {
	var n int64
	for _, p := range s.Parts[uuid] {
		n += p.Rows
	}
	return n
}

// sortEvents orders events by time; at the same microsecond, definitions
// before parts (a table exists before its first part).
func sortEvents(evs []pitEvent) {
	rank := func(k string) int {
		switch k {
		case evDB:
			return 0
		case evTable:
			return 1
		case evPart, evUnpart, evGap:
			return 2
		case evDrop:
			return 3
		}
		return 4
	}
	slices.SortStableFunc(evs, func(a, b pitEvent) int {
		if c := a.At.Compare(b.At); c != 0 {
			return c
		}
		return rank(a.Kind) - rank(b.Kind)
	})
}

// escapeFileName is ClickHouse's escapeForFileName: the names of databases
// and tables in a backup's paths keep [A-Za-z0-9_] and write any other
// byte as %XX.
func escapeFileName(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' {
			b.WriteByte(c)
			continue
		}
		const hex = "0123456789ABCDEF"
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// unescapeFileName undoes escapeFileName.
func unescapeFileName(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
