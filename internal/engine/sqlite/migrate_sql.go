package sqlite

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
)

// Building a SQLite file from a provider's SQL export (Turso's /dump, D1's
// export file). Both are text in the sqlite3 shell's .dump style: PRAGMA
// foreign_keys=OFF (D1: PRAGMA defer_foreign_keys=TRUE), BEGIN, each
// table's CREATE TABLE and one INSERT per row, then indexes, triggers and
// views, COMMIT; virtual tables (FTS) as rows written into sqlite_schema
// under PRAGMA writable_schema.
//
// The export is streamed: split into statements as SQLite itself would
// (sqlite3_complete: quotes, comments, CREATE TRIGGER bodies), each one
// classified and run in a new file the agent owns, in one transaction.
// Only what a dump contains runs (CREATE, INSERT, the sqlite_sequence and
// statistics rows, writable_schema): never ATTACH, DETACH, VACUUM or other
// PRAGMAs, so nothing in it can reach another file. Skipped:
//   - provider-internal tables: D1's _cf_* (_cf_KV, _cf_METADATA...),
//     libSQL's libsql_* (libsql_wasm_func_table, libsql_vector_meta_shadow);
//   - libSQL vector indexes (CREATE INDEX ... libsql_vector_idx(...): plain
//     SQLite has no such index) and their <index>_shadow tables;
//   - TEMP objects, transaction statements (the build has its own) and the
//     foreign key PRAGMAs (foreign keys are off while it loads, as in a
//     restore; foreign_key_check runs at the end).

// maxStatement bounds one statement (SQLite's own SQL length limit).
const maxStatement = 1_000_000_000

// Token classes and states of sqlite3_complete (complete.c).
const (
	tkSemi = iota
	tkWS
	tkOther
	tkExplain
	tkCreate
	tkTemp
	tkTrigger
	tkEnd
)

var completeTrans = [8][8]uint8{
	//          SEMI WS OTHER EXPLAIN CREATE TEMP TRIGGER END
	/* 0 INVALID */ {1, 0, 2, 3, 4, 2, 2, 2},
	/* 1   START */ {1, 1, 2, 3, 4, 2, 2, 2},
	/* 2  NORMAL */ {1, 2, 2, 2, 2, 2, 2, 2},
	/* 3 EXPLAIN */ {1, 3, 3, 2, 4, 2, 2, 2},
	/* 4  CREATE */ {1, 4, 2, 2, 2, 4, 5, 2},
	/* 5 TRIGGER */ {6, 5, 5, 5, 5, 5, 5, 5},
	/* 6    SEMI */ {6, 6, 5, 5, 5, 5, 5, 7},
	/* 7     END */ {1, 7, 5, 5, 5, 5, 5, 5},
}

func idChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c >= 0x80
}

func keywordClass(w string) int {
	switch strings.ToLower(w) {
	case "create":
		return tkCreate
	case "trigger":
		return tkTrigger
	case "temp", "temporary":
		return tkTemp
	case "end":
		return tkEnd
	case "explain":
		return tkExplain
	}
	return tkOther
}

// stmtReader splits a SQL stream into complete statements.
type stmtReader struct {
	r     *bufio.Reader
	n     int64 // bytes read
	buf   []byte
	state uint8
}

func newStmtReader(r io.Reader) *stmtReader {
	return &stmtReader{r: bufio.NewReaderSize(r, 1<<20)}
}

func (s *stmtReader) read() (byte, error) {
	c, err := s.r.ReadByte()
	if err == nil {
		s.n++
		if len(s.buf) >= maxStatement {
			return 0, errors.New("a statement in the export is over 1 GB, more than SQLite accepts")
		}
		s.buf = append(s.buf, c)
	}
	return c, err
}

// until reads up to and including the byte end (quotes, brackets).
func (s *stmtReader) until(end byte) error {
	for {
		c, err := s.read()
		if err != nil {
			return err
		}
		if c == end {
			return nil
		}
	}
}

// next returns the next statement (with its semicolon), io.EOF at the end.
// A last statement without a semicolon is returned as it is.
func (s *stmtReader) next() (string, error) {
	for {
		c, err := s.read()
		if err == io.EOF {
			rest := strings.TrimSpace(string(s.buf))
			s.buf = s.buf[:0]
			if rest == "" || onlyComments(rest) {
				return "", io.EOF
			}
			return rest, nil
		}
		if err != nil {
			return "", err
		}
		tok := tkOther
		switch {
		case c == ';':
			tok = tkSemi
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f':
			tok = tkWS
		case c == '/' || c == '-':
			nx, err := s.r.Peek(1)
			if err == nil && (c == '/' && nx[0] == '*' || c == '-' && nx[0] == '-') {
				tok = tkWS
				if c == '-' {
					if err := s.until('\n'); err != nil && err != io.EOF {
						return "", err
					}
				} else {
					_, _ = s.read()
					var prev byte
					for {
						b, err := s.read()
						if err == io.EOF {
							break
						}
						if err != nil {
							return "", err
						}
						if prev == '*' && b == '/' {
							break
						}
						prev = b
					}
				}
			}
		case c == '[':
			if err := s.until(']'); err != nil && err != io.EOF {
				return "", err
			}
		case c == '`' || c == '"' || c == '\'':
			if err := s.until(c); err != nil && err != io.EOF {
				return "", err
			}
		case idChar(c):
			start := len(s.buf) - 1
			for {
				nx, err := s.r.Peek(1)
				if err != nil || !idChar(nx[0]) {
					break
				}
				if _, err := s.read(); err != nil {
					return "", err
				}
			}
			tok = keywordClass(string(s.buf[start:]))
		}
		s.state = completeTrans[s.state][tok]
		if tok == tkSemi && s.state == 1 {
			stmt := strings.TrimSpace(string(s.buf))
			s.buf = s.buf[:0]
			if stmt == ";" || onlyComments(stmt) {
				continue
			}
			return stmt, nil
		}
	}
}

// onlyComments: nothing but comments, whitespace and semicolons.
func onlyComments(s string) bool {
	return len(sqlWords(s, 1)) == 0
}

// sqlWord is a token of a statement: a word (unquoted, Quoted when it was
// in quotes) or one punctuation character.
type sqlWord struct {
	Text   string
	Quoted bool
}

// sqlWords returns the first n tokens of a statement (comments skipped,
// quoted names unquoted, keywords as written).
func sqlWords(s string, n int) []sqlWord {
	var out []sqlWord
	for i := 0; i < len(s) && len(out) < n; {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == ';':
			i++
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				return out
			}
			i += j + 1
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return out
			}
			i += j + 4
		case c == '"' || c == '`' || c == '[' || c == '\'':
			end := c
			if c == '[' {
				end = ']'
			}
			var b strings.Builder
			j := i + 1
			for j < len(s) {
				if s[j] == end {
					if end != ']' && j+1 < len(s) && s[j+1] == end { // doubled quote
						b.WriteByte(end)
						j += 2
						continue
					}
					break
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, sqlWord{Text: b.String(), Quoted: true})
			i = j + 1
		case idChar(c):
			j := i
			for j < len(s) && idChar(s[j]) {
				j++
			}
			out = append(out, sqlWord{Text: s[i:j]})
			i = j
		default:
			out = append(out, sqlWord{Text: string(c)})
			i++
		}
	}
	return out
}

func (w sqlWord) is(kw ...string) bool {
	if w.Quoted {
		return false
	}
	for _, k := range kw {
		if strings.EqualFold(w.Text, k) {
			return true
		}
	}
	return false
}

// stmtAction is what the build does with a statement.
type stmtAction int

const (
	actRun     stmtAction = iota // must work: a table and its rows
	actRunSoft                   // a failure is a warning (indexes, views, triggers, statistics)
	actSkip                      // not run (said why when Why is set)
)

type stmtPlan struct {
	Action stmtAction
	// Kind: "table", "rows", "index", "view", "trigger", "schema" (a
	// writable_schema row), "other".
	Kind  string
	Table string // the table it creates or fills (or an index's table)
	Name  string // the object it creates
	Why   string // why it is skipped (plain words), "" when quietly
}

// internalTable: a provider's own table, never copied.
func internalTable(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "_cf_") || strings.HasPrefix(n, "libsql_") || strings.HasPrefix(n, "_litestream_")
}

// sqliteInternal: SQLite's own tables (sqlite_sequence, sqlite_stat1...).
func sqliteInternal(name string) bool { return strings.HasPrefix(strings.ToLower(name), "sqlite_") }

// objName reads an object name at w[i] (schema.name allowed) and returns
// it and the index after it.
func objName(w []sqlWord, i int) (string, int) {
	if i >= len(w) {
		return "", i
	}
	name := w[i].Text
	if i+2 < len(w) && w[i+1].Text == "." && !w[i+1].Quoted {
		return w[i+2].Text, i + 3
	}
	return name, i + 1
}

// classify decides what to do with one statement of the export.
func classify(stmt string) stmtPlan {
	w := sqlWords(stmt, 16)
	if len(w) == 0 {
		return stmtPlan{Action: actSkip}
	}
	switch {
	case w[0].is("BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE"):
		return stmtPlan{Action: actSkip}
	case w[0].is("PRAGMA"):
		name, _ := objName(w, 1)
		switch strings.ToLower(name) {
		case "foreign_keys", "defer_foreign_keys":
			return stmtPlan{Action: actSkip}
		case "writable_schema", "user_version", "application_id":
			return stmtPlan{Action: actRunSoft, Kind: "other"}
		}
		return stmtPlan{Action: actSkip, Why: "PRAGMA " + name + " (settings of the provider's database aren't copied)"}
	case w[0].is("ANALYZE"):
		return stmtPlan{Action: actRunSoft, Kind: "other"}
	case w[0].is("CREATE"):
		i := 1
		temp, virtual := false, false
		for i < len(w) && w[i].is("TEMP", "TEMPORARY", "UNIQUE", "VIRTUAL") {
			temp = temp || w[i].is("TEMP", "TEMPORARY")
			virtual = virtual || w[i].is("VIRTUAL")
			i++
		}
		if i >= len(w) {
			return stmtPlan{Action: actSkip, Why: "a statement Rowsafe couldn't read"}
		}
		kind := strings.ToLower(w[i].Text)
		i++
		if i+2 < len(w) && w[i].is("IF") && w[i+1].is("NOT") && w[i+2].is("EXISTS") {
			i += 3
		}
		name, j := objName(w, i)
		p := stmtPlan{Kind: kind, Name: name}
		switch kind {
		case "table":
			p.Table = name
			p.Action = actRun
			if virtual {
				p.Action = actRunSoft
			}
		case "index", "trigger":
			for k := j; k+1 < len(w); k++ {
				if w[k].is("ON") {
					p.Table, _ = objName(w, k+1)
					break
				}
			}
			p.Action = actRunSoft
			if kind == "index" && strings.Contains(strings.ToLower(stmt), "libsql_vector_idx") {
				return stmtPlan{Action: actSkip, Kind: "vector_index", Name: name, Table: p.Table,
					Why: "the libSQL vector index " + name + " (plain SQLite has no vector indexes: recreate it with a SQLite vector extension if your app needs it)"}
			}
		case "view":
			p.Action = actRunSoft
		default:
			return stmtPlan{Action: actSkip, Why: "CREATE " + strings.ToUpper(kind) + " " + name}
		}
		switch {
		case temp:
			return stmtPlan{Action: actSkip, Why: "the temporary " + kind + " " + name}
		case internalTable(name) || internalTable(p.Table):
			return stmtPlan{Action: actSkip, Kind: kind, Name: name}
		case kind == "table" && sqliteInternal(name):
			return stmtPlan{Action: actSkip, Kind: kind, Name: name} // SQLite makes these itself
		}
		return p
	case w[0].is("INSERT", "REPLACE"):
		i := 1
		if w[0].is("INSERT") && i+1 < len(w) && w[i].is("OR") {
			i += 2
		}
		if i < len(w) && w[i].is("INTO") {
			i++
		}
		table, _ := objName(w, i)
		switch t := strings.ToLower(table); {
		case internalTable(t):
			return stmtPlan{Action: actSkip, Kind: "rows", Table: table}
		case t == "sqlite_schema" || t == "sqlite_master":
			// A virtual table (FTS...), as the sqlite3 shell's .dump writes it.
			return stmtPlan{Action: actRunSoft, Kind: "schema", Table: table}
		case sqliteInternal(t):
			return stmtPlan{Action: actRunSoft, Kind: "rows", Table: table}
		}
		return stmtPlan{Action: actRun, Kind: "rows", Table: table}
	case w[0].is("DELETE") && len(w) > 2 && w[1].is("FROM"):
		table, _ := objName(w, 2)
		if sqliteInternal(table) {
			return stmtPlan{Action: actRunSoft, Kind: "other", Table: table}
		}
	}
	first := strings.ToUpper(w[0].Text)
	return stmtPlan{Action: actSkip, Why: "a " + first + " statement (only tables, rows, indexes, views and triggers are copied)"}
}

// buildStats is what the build did.
type buildStats struct {
	Tables   []string         // created, in order
	Rows     map[string]int64 // rows inserted per table (the export's count)
	Indexes  int
	Views    int
	Triggers int
	Skipped  []string // plain words, capped
	Warnings []string // failures of soft statements, capped
	Internal []string // provider-internal tables skipped
	Bytes    int64    // bytes of SQL read
}

func (b *buildStats) note(list *[]string, s string) {
	if len(*list) < 20 && !slices.Contains(*list, s) {
		*list = append(*list, s)
	}
}

// buildOpts tune a build.
type buildOpts struct {
	PageSize   int    // the target's page size (0: SQLite's default)
	AutoVacuum string // the target's auto_vacuum (none, full, incremental)
	// Progress is called every couple of seconds with the bytes read and
	// the tables created so far.
	Progress func(bytes int64, tables int)
}

// buildFromDump creates the SQLite file path (which must not exist) from
// the SQL in r. On error the file is removed. Errors never include the
// SQL's values beyond the failing table's name.
func buildFromDump(ctx context.Context, r io.Reader, path string, o buildOpts) (*buildStats, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	f.Close()
	ok := false
	defer func() {
		if !ok {
			removeDB(path)
		}
	}()
	if rp, err := realPath(path); err == nil {
		path = rp // SQLite's NOFOLLOW refuses links anywhere in the path
	}
	c, err := sqlite3.OpenFlags(path, sqlite3.OPEN_READWRITE|sqlite3.OPEN_NOFOLLOW)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	defer withInterrupt(ctx, c)()
	setup := []string{"PRAGMA trusted_schema = OFF", "PRAGMA foreign_keys = OFF", "PRAGMA journal_mode = MEMORY", "PRAGMA synchronous = OFF",
		"PRAGMA cache_size = -65536"}
	if o.PageSize >= 512 && o.PageSize <= 65536 && o.PageSize&(o.PageSize-1) == 0 {
		setup = append(setup, fmt.Sprintf("PRAGMA page_size = %d", o.PageSize))
	}
	if slices.Contains([]string{"none", "full", "incremental"}, o.AutoVacuum) {
		setup = append(setup, "PRAGMA auto_vacuum = "+o.AutoVacuum)
	}
	for _, q := range append(setup, "BEGIN") {
		if err := c.Exec(q); err != nil {
			return nil, fmt.Errorf("preparing the new file: %w", err)
		}
	}
	st := &buildStats{Rows: map[string]int64{}}
	sr := newStmtReader(r)
	var vectorIdx []string
	writable := false
	last := time.Now()
	for {
		stmt, err := sr.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("reading the export: %s", plainHTTPError(err))
		}
		p := classify(stmt)
		if p.Kind == "vector_index" {
			vectorIdx = append(vectorIdx, p.Name)
		}
		if p.Action == actSkip {
			switch {
			case p.Why != "":
				st.note(&st.Skipped, p.Why)
			case (p.Kind == "table" || p.Kind == "rows") && internalTable(p.Table+p.Name):
				st.note(&st.Internal, orText(p.Name, p.Table))
			}
			continue
		}
		if p.Kind == "schema" && !writable {
			st.note(&st.Skipped, "a row written straight into sqlite_schema without PRAGMA writable_schema")
			continue
		}
		if words := sqlWords(stmt, 6); len(words) > 3 && words[0].is("PRAGMA") && strings.EqualFold(words[1].Text, "writable_schema") {
			writable = words[3].is("ON", "TRUE", "YES", "1")
		}
		before := c.TotalChanges()
		err = c.Exec(stmt)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if errors.Is(err, sqlite3.FULL) {
				return nil, errors.New("this server's disk filled up while building the new file: free some space and try again")
			}
			if p.Action == actRun {
				what := "creating the table " + p.Table
				if p.Kind == "rows" {
					what = "copying a row of " + p.Table
				}
				return nil, fmt.Errorf("%s failed: %s", what, firstLine(sqliteMessage(err)))
			}
			st.note(&st.Warnings, fmt.Sprintf("%s %s wasn't created here: %s", p.Kind, orText(p.Name, p.Table), firstLine(sqliteMessage(err))))
			continue
		}
		switch p.Kind {
		case "table":
			st.Tables = append(st.Tables, p.Table)
		case "rows":
			if !sqliteInternal(p.Table) {
				st.Rows[p.Table] += c.TotalChanges() - before
			}
		case "index":
			st.Indexes++
		case "view":
			st.Views++
		case "trigger":
			st.Triggers++
		}
		if o.Progress != nil && time.Since(last) > 2*time.Second {
			last = time.Now()
			o.Progress(sr.n, len(st.Tables))
		}
	}
	st.Bytes = sr.n
	if writable {
		_ = c.Exec("PRAGMA writable_schema = OFF")
	}
	// The shadow tables of the vector indexes that weren't created.
	for _, idx := range vectorIdx {
		_ = c.Exec("DROP TABLE IF EXISTS main." + quoteIdent(idx+"_shadow"))
		st.Tables = slices.DeleteFunc(st.Tables, func(t string) bool { return strings.EqualFold(t, idx+"_shadow") })
		delete(st.Rows, idx+"_shadow")
	}
	if err := c.Exec("COMMIT"); err != nil {
		if errors.Is(err, sqlite3.FULL) {
			return nil, errors.New("this server's disk filled up while building the new file: free some space and try again")
		}
		return nil, fmt.Errorf("saving the new file: %w", err)
	}
	if len(st.Tables) == 0 {
		return nil, errors.New("the export has no tables: is it the right database?")
	}
	if o.Progress != nil {
		o.Progress(sr.n, len(st.Tables))
	}
	ok = true
	return st, nil
}
