package sqlite

import (
	"regexp"
	"slices"
	"strings"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// What each statement of a preview did to the schema: sqlite_schema read
// before and after every schema change shows the tables created, dropped
// or renamed and the indexes built. Each table is followed through the
// migration by where its data came from, so SQLite's table rebuild (a new
// table, INSERT ... SELECT from the old one, DROP, RENAME, in either
// order) is reported as a rewrite of the table, not as dropping it.

// schemaObj is one row of sqlite_schema.
type schemaObj struct {
	Type, Name, Table string
	Root              int64
}

// schemaSnap is sqlite_schema by lower-case name (SQLite's names ignore
// case).
type schemaSnap map[string]schemaObj

func readPreviewSchema(c *sqlite3.Conn) (schemaSnap, error) {
	snap := schemaSnap{}
	err := queryRows(c, `SELECT type, name, tbl_name, rootpage FROM main.sqlite_schema`, func(s *sqlite3.Stmt) error {
		o := schemaObj{Type: s.ColumnText(0), Name: s.ColumnText(1), Table: s.ColumnText(2), Root: s.ColumnInt64(3)}
		snap[strings.ToLower(o.Name)] = o
		return nil
	})
	return snap, err
}

func (s schemaSnap) table(name string) (schemaObj, bool) {
	o, ok := s[strings.ToLower(name)]
	return o, ok && o.Type == "table"
}

// relSize is a table's or index's size before the migration.
type relSize struct {
	Bytes, Rows int64
}

// tableTrack follows one table (by its current name) through the
// migration.
type tableTrack struct {
	// origin is the lower-case name of the table, as it was before the
	// migration, whose rows this table holds ("" for a new table).
	origin string
	// filledFrom is the original table a new table's rows were copied
	// from (INSERT ... SELECT), and fill the statement that did it.
	filledFrom string
	fill       int
}

// schemaTracker follows a preview's tables.
type schemaTracker struct {
	names    map[string]*tableTrack // current lower-case name
	display  map[string]string      // original lower-case name -> name as written
	sizes    map[string]relSize     // original lower-case table or index name
	dropped  map[string]int         // original table -> statement that dropped its rows
	pageSize int
}

func newSchemaTracker(start schemaSnap, sizes map[string]relSize, pageSize int) *schemaTracker {
	t := &schemaTracker{names: map[string]*tableTrack{}, display: map[string]string{}, sizes: sizes, dropped: map[string]int{}, pageSize: pageSize}
	for k, o := range start {
		if o.Type == "table" {
			t.names[k] = &tableTrack{origin: k, fill: -1}
			t.display[k] = o.Name
		}
	}
	return t
}

// dataOf is the original table whose rows the table now named name holds
// ("" for none), and its size.
func (t *schemaTracker) dataOf(name string) (string, relSize) {
	tr := t.names[strings.ToLower(name)]
	if tr == nil {
		return "", relSize{}
	}
	o := tr.origin
	if o == "" {
		o = tr.filledFrom
	}
	if o == "" {
		return "", relSize{}
	}
	return o, t.sizes[o]
}

var (
	dropColRE   = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+` + preview.SQLiteName + `\s+DROP\s+(?:COLUMN\s+)?`)
	insertSelRE = regexp.MustCompile(`(?i)^(?:INSERT|REPLACE)(?:\s+OR\s+\w+)?\s+INTO\s+` + preview.SQLiteName + `.*?\bSELECT\b.*?\bFROM\s+` + preview.SQLiteName)
	reindexRE   = regexp.MustCompile(`(?i)^REINDEX\b`)
)

var unquote = preview.UnquoteSQLite

// schemaChange records what statement i (normalised text norm) did,
// given the schema before and after it, into st.
func (t *schemaTracker) schemaChange(i int, norm string, before, after schemaSnap, st *protocol.PreviewStatement) {
	renamedFrom, renamedTo, renamed := preview.SQLiteRename(norm)
	if renamed {
		if _, ok := after.table(renamedTo); ok {
			if _, still := after.table(renamedFrom); !still {
				t.names[renamedTo] = t.names[renamedFrom]
				delete(t.names, renamedFrom)
			}
		}
	}
	// Tables gone.
	for k, o := range before {
		if o.Type != "table" || k == renamedFrom {
			continue
		}
		if _, ok := after.table(k); ok {
			continue
		}
		if tr := t.names[k]; tr != nil && tr.origin != "" {
			t.dropped[tr.origin] = i
			sz := t.sizes[tr.origin]
			st.Dropped = append(st.Dropped, protocol.PreviewRelation{Name: t.display[tr.origin], SizeBytes: sz.Bytes, Rows: sz.Rows})
		}
		delete(t.names, k)
	}
	// Tables made.
	for k, o := range after {
		if o.Type != "table" || k == renamedTo {
			continue
		}
		if _, ok := before.table(k); !ok {
			t.names[k] = &tableTrack{fill: -1}
		}
	}
	// Indexes built on tables with rows (a new table's are quick).
	for k, o := range after {
		if o.Type != "index" {
			continue
		}
		b, existed := before[k]
		rebuilt := existed && b.Root != o.Root && reindexRE.MatchString(norm)
		if existed && !rebuilt {
			continue
		}
		if _, ok := before.table(o.Table); !ok {
			continue
		}
		if _, sz := t.dataOf(o.Table); sz.Bytes > 0 {
			st.IndexBuilds = append(st.IndexBuilds, protocol.PreviewRelation{Name: o.Name, Table: o.Table, SizeBytes: sz.Bytes, Rows: sz.Rows})
		}
	}
	// SQLite writes the whole table again to drop a column.
	if m := dropColRE.FindStringSubmatch(norm); m != nil {
		name := unquote(m[1])
		if _, sz := t.dataOf(name); sz.Bytes > 0 {
			st.Rewrites = append(st.Rewrites, protocol.PreviewRelation{Name: name, SizeBytes: sz.Bytes, Rows: sz.Rows})
		}
	}
	sortRelations(st)
}

// rowsCopied records an INSERT ... SELECT that copies an original table's
// rows into a new table (the middle of a rebuild).
func (t *schemaTracker) rowsCopied(i int, norm string) {
	m := insertSelRE.FindStringSubmatch(norm)
	if m == nil {
		return
	}
	dst := t.names[strings.ToLower(unquote(m[1]))]
	if dst == nil || dst.origin != "" || dst.filledFrom != "" {
		return
	}
	if src, _ := t.dataOf(unquote(m[2])); src != "" {
		dst.filledFrom, dst.fill = src, i
	}
}

// finish turns the drops that were rebuilds into rewrites: an original
// table whose rows were dropped, while a new table filled from it now has
// its name.
func (t *schemaTracker) finish(res *protocol.PreviewResult) {
	for origin, at := range t.dropped {
		tr := t.names[origin]
		if tr == nil || tr.origin != "" || tr.filledFrom != origin {
			continue
		}
		name := t.display[origin]
		drop := &res.Statements[at]
		drop.Dropped = slices.DeleteFunc(drop.Dropped, func(r protocol.PreviewRelation) bool { return r.Name == name })
		sz := t.sizes[origin]
		rel := protocol.PreviewRelation{Name: name, SizeBytes: sz.Bytes, Rows: sz.Rows}
		target := drop
		if tr.fill >= 0 && tr.fill < len(res.Statements) {
			target = &res.Statements[tr.fill]
			target.Rows = nil // the rows copied are the rewrite's
		}
		target.Rewrites = append(target.Rewrites, rel)
		sortRelations(target)
	}
}

func sortRelations(st *protocol.PreviewStatement) {
	for _, l := range [][]protocol.PreviewRelation{st.Dropped, st.Rewrites, st.IndexBuilds} {
		slices.SortFunc(l, func(a, b protocol.PreviewRelation) int { return strings.Compare(a.Name, b.Name) })
	}
}
