package sqlite

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/protocol"
)

// Recommendations for SQLite (protocol/sqlite_advice.go). SQLite keeps no
// query statistics, so they come from the schema: the agent reads the
// file's catalog with a few PRAGMAs (read-only, each statement on its own:
// no long transaction that would hold up the app's writes) about every 30
// minutes, and sends foreign keys without an index, tables without a
// primary key, AUTOINCREMENT tables and the state of the query planner's
// statistics with the insights. Only names and counts leave the server.

const (
	// adviceMaxTables bounds the tables looked at.
	adviceMaxTables = 2000
	// adviceMaxList bounds each list sent.
	adviceMaxList = 20
	// fkMinRows: a child table smaller than this is read in a moment
	// without an index, so its foreign key gets no index idea.
	fkMinRows = 1000
)

// sqlTable is one table of the file's schema.
type sqlTable struct {
	Name         string
	WithoutRowid bool
	SQL          string
	Columns      []sqlColumn
	// PK are the PRIMARY KEY columns, in key order.
	PK      []string
	Indexes []sqlIndex
	FKs     []sqlFK
	// Rows is an estimate (sqlite_stat1, else the highest rowid, else a
	// bounded count); -1 when unknown.
	Rows int64
}

type sqlColumn struct {
	Name    string
	Type    string
	NotNull bool
}

type sqlIndex struct {
	Name    string
	Unique  bool
	Partial bool
	Origin  string // c (CREATE INDEX), u (UNIQUE), pk
	// Columns are the key columns in order; "" for an expression.
	Columns []string
}

type sqlFK struct {
	Columns    []string // in the child table
	RefTable   string
	RefColumns []string // empty: the parent's primary key
}

// rowidAlias is the table's INTEGER PRIMARY KEY column (the rowid
// itself), or "".
func (t *sqlTable) rowidAlias() string {
	if t.WithoutRowid || len(t.PK) != 1 {
		return ""
	}
	for _, c := range t.Columns {
		if c.Name == t.PK[0] && strings.EqualFold(strings.TrimSpace(c.Type), "INTEGER") {
			return c.Name
		}
	}
	return ""
}

func (t *sqlTable) column(name string) (sqlColumn, bool) {
	for _, c := range t.Columns {
		if strings.EqualFold(c.Name, name) {
			return c, true
		}
	}
	return sqlColumn{}, false
}

// covered reports whether an index can find the rows with given values of
// cols: a full (not partial) index whose first len(cols) columns are cols
// in any order, the rowid alias, or a WITHOUT ROWID table's primary key.
func (t *sqlTable) covered(cols []string) bool {
	want := lowerSet(cols)
	sameSet := func(lead []string) bool {
		if len(lead) < len(cols) {
			return false
		}
		got := lowerSet(lead[:len(cols)])
		return slices.Equal(got, want)
	}
	if len(cols) == 1 && t.rowidAlias() != "" && strings.EqualFold(cols[0], t.rowidAlias()) {
		return true
	}
	if t.WithoutRowid && sameSet(t.PK) {
		return true
	}
	for _, ix := range t.Indexes {
		if !ix.Partial && !slices.Contains(ix.Columns, "") && sameSet(ix.Columns) {
			return true
		}
	}
	return false
}

// hasKey: a primary key, or a UNIQUE index on NOT NULL columns.
func (t *sqlTable) hasKey() bool {
	if len(t.PK) > 0 || t.WithoutRowid {
		return true
	}
	for _, ix := range t.Indexes {
		if !ix.Unique || ix.Partial || len(ix.Columns) == 0 {
			continue
		}
		ok := true
		for _, name := range ix.Columns {
			c, found := t.column(name)
			if name == "" || !found || !c.NotNull {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func lowerSet(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = strings.ToLower(c)
	}
	slices.Sort(out)
	return out
}

var autoincRE = regexp.MustCompile(`(?i)\bAUTOINCREMENT\b`)

// sqlSchema is the file's schema as the advice needs it.
type sqlSchema struct {
	Tables    []*sqlTable
	Stat1     bool
	stat1Tbls map[string]bool
	Seq       map[string]int64 // sqlite_sequence
	Truncated bool
}

func (s *sqlSchema) table(name string) *sqlTable {
	for _, t := range s.Tables {
		if strings.EqualFold(t.Name, name) {
			return t
		}
	}
	return nil
}

// readSchema reads the tables, their columns, keys, indexes and foreign
// keys, and estimates their rows. countBudget bounds the time spent
// counting rows of WITHOUT ROWID tables that have no statistics (0: never
// count).
func readSchema(ctx context.Context, c *sqlite3.Conn, countBudget time.Duration) (*sqlSchema, error) {
	s := &sqlSchema{stat1Tbls: map[string]bool{}, Seq: map[string]int64{}}
	err := queryRows(c, `SELECT name, wr FROM pragma_table_list WHERE schema = 'main' AND type = 'table'
		AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY name`, func(st *sqlite3.Stmt) error {
		if len(s.Tables) >= adviceMaxTables {
			s.Truncated = true
			return nil
		}
		s.Tables = append(s.Tables, &sqlTable{Name: st.ColumnText(0), WithoutRowid: st.ColumnInt64(1) != 0, Rows: -1})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sqls := map[string]string{}
	if err := queryRows(c, `SELECT name, sql FROM main.sqlite_schema WHERE type = 'table'`, func(st *sqlite3.Stmt) error {
		sqls[st.ColumnText(0)] = st.ColumnText(1)
		return nil
	}); err != nil {
		return nil, err
	}
	for _, t := range s.Tables {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		t.SQL = sqls[t.Name]
		pk := map[int64]string{}
		if err := queryRows(c, `SELECT name, type, "notnull", pk FROM pragma_table_info(?, 'main')`, func(st *sqlite3.Stmt) error {
			col := sqlColumn{Name: st.ColumnText(0), Type: st.ColumnText(1), NotNull: st.ColumnInt64(2) != 0}
			t.Columns = append(t.Columns, col)
			if n := st.ColumnInt64(3); n > 0 {
				pk[n] = col.Name
			}
			return nil
		}, t.Name); err != nil {
			return nil, fmt.Errorf("reading the columns of %s: %w", t.Name, err)
		}
		for i := int64(1); i <= int64(len(pk)); i++ {
			t.PK = append(t.PK, pk[i])
		}
		if err := queryRows(c, `SELECT name, "unique", origin, partial FROM pragma_index_list(?, 'main') ORDER BY seq`, func(st *sqlite3.Stmt) error {
			t.Indexes = append(t.Indexes, sqlIndex{Name: st.ColumnText(0), Unique: st.ColumnInt64(1) != 0, Origin: st.ColumnText(2), Partial: st.ColumnInt64(3) != 0})
			return nil
		}, t.Name); err != nil {
			return nil, fmt.Errorf("reading the indexes of %s: %w", t.Name, err)
		}
		for i := range t.Indexes {
			ix := &t.Indexes[i]
			if err := queryRows(c, `SELECT cid, name FROM pragma_index_info(?, 'main') ORDER BY seqno`, func(st *sqlite3.Stmt) error {
				name := st.ColumnText(1)
				if st.ColumnType(1) == sqlite3.NULL {
					name = "" // an expression (or the rowid)
				}
				ix.Columns = append(ix.Columns, name)
				return nil
			}, ix.Name); err != nil {
				return nil, fmt.Errorf("reading the index %s: %w", ix.Name, err)
			}
		}
		byID := map[int64]*sqlFK{}
		var order []int64
		if err := queryRows(c, `SELECT id, "table", "from", "to" FROM pragma_foreign_key_list(?, 'main') ORDER BY id, seq`, func(st *sqlite3.Stmt) error {
			id := st.ColumnInt64(0)
			fk := byID[id]
			if fk == nil {
				fk = &sqlFK{RefTable: st.ColumnText(1)}
				byID[id] = fk
				order = append(order, id)
			}
			fk.Columns = append(fk.Columns, st.ColumnText(2))
			if st.ColumnType(3) != sqlite3.NULL {
				fk.RefColumns = append(fk.RefColumns, st.ColumnText(3))
			}
			return nil
		}, t.Name); err != nil {
			return nil, fmt.Errorf("reading the foreign keys of %s: %w", t.Name, err)
		}
		for _, id := range order {
			fk := byID[id]
			if len(fk.RefColumns) != len(fk.Columns) {
				fk.RefColumns = nil
			}
			t.FKs = append(t.FKs, *fk)
		}
	}
	// Statistics and sequences, when the file has them.
	if n, err := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE type = 'table' AND name = 'sqlite_stat1'`); err == nil && n > 0 {
		s.Stat1 = true
		_ = queryRows(c, `SELECT tbl, idx, stat FROM main.sqlite_stat1`, func(st *sqlite3.Stmt) error {
			tbl := st.ColumnText(0)
			s.stat1Tbls[strings.ToLower(tbl)] = true
			if t := s.table(tbl); t != nil && t.Rows < 0 {
				if f := strings.Fields(st.ColumnText(2)); len(f) > 0 {
					if n, err := strconv.ParseInt(f[0], 10, 64); err == nil {
						t.Rows = n
					}
				}
			}
			return nil
		})
	}
	if n, err := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE type = 'table' AND name = 'sqlite_sequence'`); err == nil && n > 0 {
		_ = queryRows(c, `SELECT name, seq FROM main.sqlite_sequence`, func(st *sqlite3.Stmt) error {
			s.Seq[st.ColumnText(0)] = st.ColumnInt64(1)
			return nil
		})
	}
	// Rows without statistics: the highest rowid is a quick upper bound
	// (exact without deletes); WITHOUT ROWID tables are counted within the
	// budget.
	deadline := time.Now().Add(countBudget)
	for _, t := range s.Tables {
		if t.Rows >= 0 {
			continue
		}
		if !t.WithoutRowid {
			if n, err := queryInt(c, `SELECT coalesce(max(rowid), 0) FROM main.`+quoteIdent(t.Name)); err == nil {
				t.Rows = n
			}
			continue
		}
		if left := time.Until(deadline); left > 0 {
			cctx, cancel := context.WithTimeout(ctx, left)
			restore := withInterrupt(cctx, c)
			if n, err := queryInt(c, `SELECT count(*) FROM main.`+quoteIdent(t.Name)); err == nil {
				t.Rows = n
			}
			restore()
			cancel()
		}
	}
	return s, nil
}

// fkName names a foreign key for people: "child(a, b) -> parent".
func fkName(t *sqlTable, fk sqlFK) string {
	return fmt.Sprintf("%s(%s) -> %s", t.Name, strings.Join(fk.Columns, ", "), fk.RefTable)
}

// unindexedFKs are the foreign keys no index can serve, biggest child
// tables first.
func (s *sqlSchema) unindexedFKs() []fkIdea {
	var out []fkIdea
	for _, t := range s.Tables {
		seen := map[string]bool{}
		for _, fk := range t.FKs {
			key := strings.Join(lowerSet(fk.Columns), ",")
			if seen[key] || t.covered(fk.Columns) {
				continue
			}
			seen[key] = true
			out = append(out, fkIdea{table: t, fk: fk})
		}
	}
	slices.SortStableFunc(out, func(a, b fkIdea) int { return int(min(max(b.table.Rows-a.table.Rows, -1), 1)) })
	return out
}

// fkIdea is a foreign key without an index, and the index for it.
type fkIdea struct {
	table *sqlTable
	fk    sqlFK
}

func (x fkIdea) spec() protocol.IndexSpec {
	s := protocol.IndexSpec{DB: "main", Table: x.table.Name, Columns: slices.Clone(x.fk.Columns)}
	s.Name = protocol.IndexName(s)
	return s
}

// adviceInsights are the insights SQLite can have: no usage statistics,
// only the schema facts for the recommendations.
func adviceInsights(s *sqlSchema, took time.Duration) *protocol.Insights {
	ins := &protocol.Insights{CollectedAt: time.Now().UTC(), DurationMs: took.Milliseconds(),
		Databases:     []protocol.InsightsDatabase{{Name: "main", Tables: len(s.Tables)}},
		LargestTables: []protocol.TableSize{}, LargestIndexes: []protocol.IndexSize{},
		TableBloat: []protocol.TableBloat{}, IndexBloat: []protocol.IndexBloat{}, UnusedIndexes: []protocol.UnusedIndex{},
		DuplicateIndexes: []protocol.DuplicateIndex{}, SeqScanTables: []protocol.SeqScanTable{}, VacuumStats: []protocol.TableVacuum{},
		FreezeAge: []protocol.TableFreeze{}, Truncated: s.Truncated}
	if s.Truncated {
		ins.Notes = append(ins.Notes, fmt.Sprintf("Only the first %d tables were looked at.", adviceMaxTables))
	}
	a := &protocol.AdvisorFacts{ForeignKeys: []protocol.ForeignKeyWithoutIndex{}, NoPrimaryKey: []protocol.TableWithoutPK{},
		IntegerKeys: []protocol.IntegerKey{}, SequencesBehind: []protocol.SequenceBehind{}, InvalidIndexes: []protocol.InvalidIndex{},
		DuplicateConstraints: []protocol.DuplicateConstraint{}, TimestampColumns: []protocol.TimestampTable{}, LargeTables: []protocol.LargeTable{},
		SQLite: &protocol.SQLiteAdvisorFacts{Tables: len(s.Tables), Autoincrement: []protocol.SQLiteAutoincrement{}, Stat1: s.Stat1}}
	ins.Advisor = a
	for _, x := range s.unindexedFKs() {
		if len(a.ForeignKeys) >= adviceMaxList {
			break
		}
		a.ForeignKeys = append(a.ForeignKeys, protocol.ForeignKeyWithoutIndex{Database: "main", Schema: "main", Table: x.table.Name,
			Constraint: fkName(x.table, x.fk), Columns: x.fk.Columns, RefSchema: "main", RefTable: x.fk.RefTable, RowsEstimate: x.table.Rows})
	}
	byRows := slices.Clone(s.Tables)
	slices.SortStableFunc(byRows, func(a, b *sqlTable) int { return int(min(max(b.Rows-a.Rows, -1), 1)) })
	for _, t := range byRows {
		if !t.hasKey() && len(a.NoPrimaryKey) < adviceMaxList {
			a.NoPrimaryKey = append(a.NoPrimaryKey, protocol.TableWithoutPK{Database: "main", Schema: "main", Table: t.Name, RowsEstimate: t.Rows})
		}
		if col := t.rowidAlias(); col != "" && autoincRE.MatchString(t.SQL) && len(a.SQLite.Autoincrement) < adviceMaxList {
			a.SQLite.Autoincrement = append(a.SQLite.Autoincrement, protocol.SQLiteAutoincrement{Table: t.Name, Column: col,
				Seq: s.Seq[t.Name], RowsEstimate: t.Rows})
		}
		if len(t.Indexes) > 0 {
			a.SQLite.IndexedTables++
			if !s.stat1Tbls[strings.ToLower(t.Name)] && len(a.SQLite.Unanalyzed) < adviceMaxList {
				a.SQLite.Unanalyzed = append(a.SQLite.Unanalyzed, t.Name)
			}
		}
	}
	slices.Sort(a.SQLite.Unanalyzed)
	return ins
}

// schemaInsights reads the schema facts for monitoring. In rollback-journal
// mode each read briefly blocks the app's writes, so nothing is counted
// there.
func schemaInsights(ctx context.Context, c *sqlite3.Conn, journal string) (*protocol.Insights, error) {
	start := time.Now()
	budget := 3 * time.Second
	if journal != "wal" {
		budget = 0
	}
	s, err := readSchema(ctx, c, budget)
	if err != nil {
		return nil, err
	}
	return adviceInsights(s, time.Since(start)), nil
}
