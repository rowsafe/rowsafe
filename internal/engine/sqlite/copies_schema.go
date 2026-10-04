package sqlite

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/ext/fts5"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// copy_schema and structure-only copies. copy_schema lists production's
// tables and columns for the masking review: catalog only (sqlite_schema,
// pragma table_xinfo / index_list), no row value is read; row counts are
// estimates (sqlite_stat1, else the highest rowid). A structure-only copy
// is a new file with production's tables, indexes, views and triggers and
// no row, created from the statements sqlite_schema keeps.
//
// Virtual tables: the agent includes SQLite's full-text search FTS5 (pure
// Go), so FTS5 tables are created, masked (their own text) or rebuilt from
// their masked content table. Other virtual tables (FTS3/FTS4, R*Tree,
// extensions the app loads) need modules the agent doesn't have: they are
// left out of copies, with a note. Their internal ("shadow") tables are
// recognized by name and never listed as tables of their own.

const maxSchemaColumns = 8000

// shadowSuffixes are the internal tables each known virtual table module
// keeps next to it (<name>_<suffix>).
var shadowSuffixes = map[string][]string{
	"fts5":      {"data", "idx", "content", "docsize", "config"},
	"fts4":      {"content", "segments", "segdir", "docsize", "stat"},
	"fts3":      {"content", "segments", "segdir", "docsize", "stat"},
	"rtree":     {"node", "rowid", "parent"},
	"rtree_i32": {"node", "rowid", "parent"},
	"geopoly":   {"node", "rowid", "parent"},
}

// vtab is a virtual table of the schema.
type vtab struct {
	Name   string
	Module string   // lower case: fts5, fts4, rtree...
	Args   []string // the module arguments as written
	SQL    string
}

// FTS5 content modes (vtab.ftsContent).
const (
	ftsInternal    = "internal"    // the text lives in the FTS table itself
	ftsExternal    = "external"    // content=<table>: indexed from another table
	ftsContentless = "contentless" // content='': only the index (words) is kept
)

// ftsContent says where an FTS5 table's text lives.
func (v vtab) ftsContent() string {
	for _, a := range v.Args {
		k, val, ok := strings.Cut(a, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "content") {
			continue
		}
		if unquote(strings.TrimSpace(val)) == "" {
			return ftsContentless
		}
		return ftsExternal
	}
	return ftsInternal
}

var vtabRE = regexp.MustCompile(`(?is)^\s*CREATE\s+VIRTUAL\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` +
	`(?:(?:"(?:[^"]|"")*"|\[[^\]]*\]|` + "`[^`]*`" + `|[^\s.(]+)\s*\.\s*)?` +
	`(?:"(?:[^"]|"")*"|\[[^\]]*\]|` + "`[^`]*`" + `|'(?:[^']|'')*'|[^\s(]+)` +
	`\s+USING\s+([A-Za-z0-9_]+)\s*(?:\((.*)\))?\s*;?\s*$`)

// parseVirtual reads a CREATE VIRTUAL TABLE statement ("" module when it
// can't).
func parseVirtual(name, sql string) vtab {
	v := vtab{Name: name, SQL: sql}
	m := vtabRE.FindStringSubmatch(sql)
	if m == nil {
		return v
	}
	v.Module = strings.ToLower(m[1])
	v.Args = splitArgs(m[2])
	return v
}

// splitArgs splits module arguments at top-level commas (not inside
// quotes or parentheses).
func splitArgs(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
		case ch == '\'' || ch == '"' || ch == '`':
			quote = ch
		case ch == '[':
			quote = ']'
		case ch == '(':
			depth++
		case ch == ')':
			depth--
		case ch == ',' && depth == 0:
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if rest := strings.TrimSpace(s[start:]); rest != "" || len(out) > 0 {
		out = append(out, rest)
	}
	return out
}

// unquote removes SQL quotes around a name or string.
func unquote(s string) string {
	if len(s) >= 2 {
		switch {
		case s[0] == '\'' && s[len(s)-1] == '\'':
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		case s[0] == '"' && s[len(s)-1] == '"':
			return strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
		case s[0] == '[' && s[len(s)-1] == ']', s[0] == '`' && s[len(s)-1] == '`':
			return s[1 : len(s)-1]
		}
	}
	return s
}

// virtualTables lists the main schema's virtual tables.
func virtualTables(c *sqlite3.Conn) ([]vtab, error) {
	var out []vtab
	err := queryRows(c, `SELECT name, sql FROM main.sqlite_schema WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL%' ORDER BY rowid`,
		func(s *sqlite3.Stmt) error {
			out = append(out, parseVirtual(s.ColumnText(0), s.ColumnText(1)))
			return nil
		})
	return out, err
}

// shadowOf maps every internal table of a known virtual table to it.
func shadowOf(vts []vtab) map[string]string {
	out := map[string]string{}
	for _, v := range vts {
		for _, suf := range shadowSuffixes[v.Module] {
			out[strings.ToLower(v.Name+"_"+suf)] = v.Name
		}
	}
	return out
}

// sqliteType is a column's declared type as the masking review shows it:
// the declared type when masking knows it ("varchar(255)", "datetime",
// "json"...), else SQLite's affinity for it ("integer", "text", "real").
// FTS5 columns hold text.
func sqliteType(decl string, fts bool) string {
	t := strings.ToLower(strings.TrimSpace(decl))
	if t == "" {
		if fts {
			return "text"
		}
		return ""
	}
	if masking.Class(t) != masking.ClassOther {
		return t
	}
	switch {
	case strings.Contains(t, "int"):
		return "integer"
	case strings.Contains(t, "char"), strings.Contains(t, "clob"), strings.Contains(t, "text"):
		return "text"
	case strings.Contains(t, "real"), strings.Contains(t, "floa"), strings.Contains(t, "doub"):
		return "real"
	}
	return t
}

func (e *Engine) copySchema(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.CopySchemaResult, error) {
	c, err := openDB(ctx, db.SocketDir, openOpts{Busy: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	// FTS5 tables' columns are read through their module (nothing is
	// written).
	if err := fts5.Register(c); err != nil {
		return nil, err
	}
	if err := beginRead(c); err != nil {
		e.busyFor(db.ID).note(err)
		return nil, err
	}
	defer rollback(c)
	return readCopySchema(c)
}

// readCopySchema lists the tables (and FTS5 tables that keep their own
// text) with their columns, as database "main". Catalog only.
func readCopySchema(c *sqlite3.Conn) (*protocol.CopySchemaResult, error) {
	vts, err := virtualTables(c)
	if err != nil {
		return nil, err
	}
	shadows := shadowOf(vts)
	internalFTS := map[string]bool{}
	for _, v := range vts {
		if v.Module == "fts5" && v.ftsContent() == ftsInternal {
			internalFTS[v.Name] = true
		}
	}
	type tbl struct {
		name    string
		virtual bool
	}
	var tables []tbl
	err = queryRows(c, `SELECT name, sql LIKE 'CREATE VIRTUAL%' FROM main.sqlite_schema
		WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`, func(s *sqlite3.Stmt) error {
		name, virtual := s.ColumnText(0), s.ColumnInt(1) != 0
		if _, shadow := shadows[strings.ToLower(name)]; shadow || (virtual && !internalFTS[name]) {
			return nil
		}
		tables = append(tables, tbl{name, virtual})
		return nil
	})
	if err != nil {
		return nil, err
	}
	stat1 := map[string]int64{}
	if n, _ := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE name = 'sqlite_stat1'`); n > 0 {
		_ = queryRows(c, `SELECT tbl, stat FROM main.sqlite_stat1`, func(s *sqlite3.Stmt) error {
			first, _, _ := strings.Cut(s.ColumnText(1), " ")
			if v, err := strconv.ParseInt(first, 10, 64); err == nil && v > stat1[s.ColumnText(0)] {
				stat1[s.ColumnText(0)] = v
			}
			return nil
		})
	}
	res := &protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{{Name: "main", Tables: []protocol.SchemaTable{}}}}
	d := &res.Databases[0]
	n := 0
	for _, t := range tables {
		st := protocol.SchemaTable{Name: t.name, Rows: stat1[t.name]}
		if _, ok := stat1[t.name]; !ok && !t.virtual {
			// The highest rowid: one lookup, an estimate (deleted rows
			// count). WITHOUT ROWID tables have none: 0.
			st.Rows, _ = queryInt(c, `SELECT coalesce(max(rowid), 0) FROM main.`+quoteIdent(t.name))
		}
		unique := map[string]bool{}
		if !t.virtual {
			unique = uniqueColumns(c, t.name)
		}
		var pks []string
		err := queryRows(c, `SELECT name, type, "notnull", pk, hidden FROM pragma_table_xinfo(?, 'main') ORDER BY cid`, func(s *sqlite3.Stmt) error {
			hidden := s.ColumnInt(4)
			if hidden == 1 { // a virtual table's hidden column
				return nil
			}
			col := protocol.SchemaColumn{Name: s.ColumnText(0), Type: sqliteType(s.ColumnText(1), t.virtual),
				Nullable: s.ColumnInt(2) == 0 && s.ColumnInt(3) == 0, Unique: unique[s.ColumnText(0)], Generated: hidden == 2 || hidden == 3}
			if s.ColumnInt(3) > 0 {
				pks = append(pks, col.Name)
			}
			st.Columns = append(st.Columns, col)
			return nil
		}, t.name)
		if err != nil {
			return nil, fmt.Errorf("reading the columns of %s: %w", t.name, err)
		}
		if len(pks) == 1 {
			for i := range st.Columns {
				if st.Columns[i].Name == pks[0] {
					st.Columns[i].Unique = true
				}
			}
		}
		if n+len(st.Columns) > maxSchemaColumns {
			res.Truncated = true
			break
		}
		n += len(st.Columns)
		d.Tables = append(d.Tables, st)
	}
	return res, nil
}

// uniqueColumns are the columns a unique index covers alone.
func uniqueColumns(c *sqlite3.Conn, table string) map[string]bool {
	out := map[string]bool{}
	var idx []string
	_ = queryRows(c, `SELECT name FROM pragma_index_list(?, 'main') WHERE "unique" = 1`, func(s *sqlite3.Stmt) error {
		idx = append(idx, s.ColumnText(0))
		return nil
	}, table)
	for _, i := range idx {
		var cols []string
		_ = queryRows(c, `SELECT coalesce(name, '') FROM pragma_index_info(?, 'main')`, func(s *sqlite3.Stmt) error {
			cols = append(cols, s.ColumnText(0))
			return nil
		}, i)
		if len(cols) == 1 && cols[0] != "" {
			out[cols[0]] = true
		}
	}
	return out
}

// ---- structure-only copies

// schemaObject is one entry of sqlite_schema a structure-only copy
// creates.
type schemaObject struct {
	Type, Name, SQL string
}

// schemaOut is what a structure-only copy holds.
type schemaOut struct {
	Tables, Indexes, Views, Triggers int
	// LeftOut lists the objects not created, each with a plain reason.
	LeftOut []string
}

func (o schemaOut) describe() string {
	return fmt.Sprintf("%d tables, %d indexes, %d views and %d triggers", o.Tables, o.Indexes, o.Views, o.Triggers)
}

// schemaOnlyCopy creates dst (a new file) with src's tables, indexes,
// views and triggers, and its page size, auto_vacuum, encoding,
// user_version and application_id; no row is copied. Objects that can't be
// created are left out with a reason (LeftOut).
func schemaOnlyCopy(ctx context.Context, src, dst string, tl agent.TaskLogger) (schemaOut, error) {
	var out schemaOut
	c, err := openDB(ctx, src, openOpts{Busy: 5 * time.Second})
	if err != nil {
		return out, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	if err := beginRead(c); err != nil {
		return out, err
	}
	defer rollback(c)
	pageSize, _ := queryInt(c, `PRAGMA main.page_size`)
	autoVacuum, _ := queryInt(c, `PRAGMA main.auto_vacuum`)
	encoding, _ := queryText(c, `PRAGMA encoding`)
	userVersion, _ := queryInt(c, `PRAGMA main.user_version`)
	appID, _ := queryInt(c, `PRAGMA main.application_id`)
	vts, err := virtualTables(c)
	if err != nil {
		return out, err
	}
	shadows := shadowOf(vts)
	modules := map[string]string{}
	for _, v := range vts {
		modules[v.Name] = v.Module
	}
	var objs []schemaObject
	err = queryRows(c, `SELECT type, name, sql FROM main.sqlite_schema
		WHERE sql IS NOT NULL AND name NOT LIKE 'sqlite\_%' ESCAPE '\'
		ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 WHEN 'view' THEN 2 ELSE 3 END, rowid`, func(s *sqlite3.Stmt) error {
		o := schemaObject{Type: s.ColumnText(0), Name: s.ColumnText(1), SQL: s.ColumnText(2)}
		if _, shadow := shadows[strings.ToLower(o.Name)]; shadow && o.Type == "table" {
			return nil // made by its virtual table
		}
		objs = append(objs, o)
		return nil
	})
	if err != nil {
		return out, err
	}
	rollback(c)

	removeDB(dst)
	f, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return out, err
	}
	f.Close()
	if rp, err := realPath(dst); err == nil {
		dst = rp // SQLite opens it without following links
	}
	d, err := sqlite3.OpenFlags(dst, sqlite3.OPEN_READWRITE|sqlite3.OPEN_NOFOLLOW)
	if err != nil {
		return out, err
	}
	defer d.Close()
	defer withInterrupt(ctx, d)()
	if err := fts5.Register(d); err != nil {
		return out, err
	}
	// Before the first table: page size, auto_vacuum and encoding are
	// fixed once the file has content.
	setup := []string{fmt.Sprintf(`PRAGMA page_size = %d`, pageSize), fmt.Sprintf(`PRAGMA auto_vacuum = %d`, autoVacuum)}
	if encoding != "" && !strings.EqualFold(encoding, "UTF-8") {
		setup = append(setup, `PRAGMA encoding = `+quoteLit(encoding))
	}
	setup = append(setup, `PRAGMA journal_mode = DELETE`, `PRAGMA foreign_keys = OFF`)
	for _, q := range setup {
		if err := d.Exec(q); err != nil {
			return out, fmt.Errorf("%s: %w", q, err)
		}
	}
	if err := d.Exec(`BEGIN IMMEDIATE`); err != nil {
		return out, err
	}
	defer rollback(d)
	// Views and triggers may name each other: retry the ones that failed
	// while others still get created.
	var skipped []string // virtual tables left out: their triggers go too
	for name, module := range modules {
		if module != "fts5" {
			skipped = append(skipped, name)
			out.LeftOut = append(out.LeftOut, fmt.Sprintf("%s: a virtual table of the SQLite extension %s, which Rowsafe can't create", name, orText(module, "unknown")))
		}
	}
	pending := objs
	for round := 0; len(pending) > 0; round++ {
		var failed []schemaObject
		var reasons []string
	next:
		for _, o := range pending {
			if o.Type == "table" && slices.Contains(skipped, o.Name) {
				continue
			}
			if o.Type == "trigger" {
				for _, v := range skipped {
					if namesTable(o.SQL, v) {
						out.LeftOut = append(out.LeftOut, fmt.Sprintf("trigger %s: it uses %s, which was left out", o.Name, v))
						continue next
					}
				}
			}
			if err := d.Exec(o.SQL); err != nil {
				failed = append(failed, o)
				reasons = append(reasons, firstLine(err.Error()))
				continue
			}
			switch o.Type {
			case "table":
				out.Tables++
			case "index":
				out.Indexes++
			case "view":
				out.Views++
			case "trigger":
				out.Triggers++
			}
		}
		if len(failed) == len(pending) || round >= 5 {
			for i, o := range failed {
				out.LeftOut = append(out.LeftOut, fmt.Sprintf("%s %s: %s", o.Type, o.Name, reasons[i]))
			}
			break
		}
		pending = failed
	}
	for _, q := range []string{fmt.Sprintf(`PRAGMA user_version = %d`, userVersion), fmt.Sprintf(`PRAGMA application_id = %d`, appID), `COMMIT`} {
		if err := d.Exec(q); err != nil {
			return out, fmt.Errorf("%s: %w", q, err)
		}
	}
	for _, l := range out.LeftOut {
		tl.Printf("left out of the structure-only copy: %s", l)
	}
	slices.Sort(out.LeftOut)
	return out, nil
}
