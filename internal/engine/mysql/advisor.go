package mysql

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// Recommendations for MySQL and MariaDB (collected with the insights,
// every 30 minutes): tables without a primary key, indexes nothing has
// used since the server started, indexes another index makes unnecessary,
// and the largest tables. Read-only catalog queries; no data is read.

const advisorSkipSchemas = "'mysql', 'information_schema', 'performance_schema', 'sys'"

// tableKey is schema.table.
type tableKey struct{ schema, table string }

type indexInfo struct {
	name    string
	unique  bool
	typ     string
	columns []string // with "(n)" for a prefix
	bytes   int64
}

func (x indexInfo) definition() string {
	kind := "INDEX"
	if x.name == "PRIMARY" {
		return "PRIMARY KEY (" + strings.Join(x.columns, ", ") + ")"
	}
	if x.unique {
		kind = "UNIQUE INDEX"
	}
	return fmt.Sprintf("%s %s (%s)", kind, quoteIdent(x.name), strings.Join(x.columns, ", "))
}

// advisorFacts fills ins.Advisor, ins.UnusedIndexes, ins.DuplicateIndexes
// and ins.LargestIndexes. serverStart is when the index usage counters
// started.
func (s *server) advisorFacts(ctx context.Context, db *sql.DB, ins *protocol.Insights, serverStart time.Time) {
	a := &protocol.AdvisorFacts{ForeignKeys: []protocol.ForeignKeyWithoutIndex{}, NoPrimaryKey: []protocol.TableWithoutPK{},
		IntegerKeys: []protocol.IntegerKey{}, SequencesBehind: []protocol.SequenceBehind{}, InvalidIndexes: []protocol.InvalidIndex{},
		DuplicateConstraints: []protocol.DuplicateConstraint{}, TimestampColumns: []protocol.TimestampTable{}, LargeTables: []protocol.LargeTable{}}
	ins.Advisor = a
	a.SlowLog = s.slowLogFacts(ctx, db) // slowlog.go
	idx, err := readIndexes(ctx, db)
	if err != nil {
		ins.Notes = append(ins.Notes, "Reading the indexes failed: "+firstLine(err.Error()))
		ins.Truncated = true
		return
	}
	// Tables without a primary key (nor a unique index on NOT NULL columns,
	// which InnoDB would use as one).
	rows, err := db.QueryContext(ctx, `
		SELECT t.table_schema, t.table_name, COALESCE(t.table_rows, 0), COALESCE(t.data_length, 0)
		FROM information_schema.tables t
		WHERE t.table_type = 'BASE TABLE' AND t.table_schema NOT IN (`+advisorSkipSchemas+`)
		  AND NOT EXISTS (
		    SELECT 1 FROM information_schema.statistics s
		    WHERE s.table_schema = t.table_schema AND s.table_name = t.table_name AND s.non_unique = 0
		    GROUP BY s.index_name HAVING SUM(s.nullable = 'YES') = 0)
		ORDER BY t.data_length DESC LIMIT 20`)
	if err == nil {
		for rows.Next() {
			var t protocol.TableWithoutPK
			if rows.Scan(&t.Schema, &t.Table, &t.RowsEstimate, &t.TableBytes) == nil {
				t.Database = t.Schema
				a.NoPrimaryKey = append(a.NoPrimaryKey, t)
			}
		}
		rows.Close()
	}
	unusedIndexes(ctx, db, ins, idx, serverStart)
	ins.DuplicateIndexes = duplicateIndexes(idx)
	// Largest indexes.
	var all []protocol.IndexSize
	for k, xs := range idx {
		for _, x := range xs {
			if x.bytes > 0 {
				all = append(all, protocol.IndexSize{Database: k.schema, Schema: k.schema, Table: k.table, Index: x.name, Bytes: x.bytes})
			}
		}
	}
	slices.SortFunc(all, func(x, y protocol.IndexSize) int { return cmp.Compare(y.Bytes, x.Bytes) })
	ins.LargestIndexes = all[:min(len(all), 20)]
	// Large tables (1 million rows or 1 GB).
	for _, t := range ins.LargestTables {
		if t.RowsEstimate >= 1_000_000 || t.TotalBytes >= 1<<30 {
			a.LargeTables = append(a.LargeTables, protocol.LargeTable{Database: t.Database, Schema: t.Schema, Table: t.Table,
				TotalBytes: t.TotalBytes, TableBytes: t.TableBytes, RowsEstimate: t.RowsEstimate})
		}
	}
}

// readIndexes reads every index of the user tables, with its size when
// InnoDB's persistent statistics have it.
func readIndexes(ctx context.Context, db *sql.DB) (map[tableKey][]indexInfo, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT table_schema, table_name, index_name, non_unique, COALESCE(index_type, ''), column_name, COALESCE(sub_part, 0)
		FROM information_schema.statistics
		WHERE table_schema NOT IN (`+advisorSkipSchemas+`) AND column_name IS NOT NULL
		ORDER BY table_schema, table_name, index_name, seq_in_index LIMIT 50000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[tableKey][]indexInfo{}
	for rows.Next() {
		var k tableKey
		var name, typ, col string
		var nonUnique, sub int
		if err := rows.Scan(&k.schema, &k.table, &name, &nonUnique, &typ, &col, &sub); err != nil {
			return nil, err
		}
		if sub > 0 {
			col = fmt.Sprintf("%s(%d)", quoteIdent(col), sub)
		} else {
			col = quoteIdent(col)
		}
		xs := out[k]
		if n := len(xs); n > 0 && xs[n-1].name == name {
			xs[n-1].columns = append(xs[n-1].columns, col)
		} else {
			xs = append(xs, indexInfo{name: name, unique: nonUnique == 0, typ: typ, columns: []string{col}})
		}
		out[k] = xs
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Sizes (pages) from InnoDB's persistent statistics, when readable.
	var page int64 = 16384
	_ = db.QueryRowContext(ctx, "SELECT @@innodb_page_size").Scan(&page)
	if srows, err := db.QueryContext(ctx, `
		SELECT database_name, table_name, index_name, stat_value FROM mysql.innodb_index_stats
		WHERE stat_name = 'size'`); err == nil {
		for srows.Next() {
			var k tableKey
			var name string
			var pages int64
			if srows.Scan(&k.schema, &k.table, &name, &pages) != nil {
				continue
			}
			for i := range out[k] {
				if out[k][i].name == name {
					out[k][i].bytes = pages * page
				}
			}
		}
		srows.Close()
	}
	return out, nil
}

// unusedIndexes: secondary, non-unique indexes performance_schema saw no
// reads of since the server started (needs a week of uptime to mean
// anything).
func unusedIndexes(ctx context.Context, db *sql.DB, ins *protocol.Insights, idx map[tableKey][]indexInfo, serverStart time.Time) {
	if time.Since(serverStart) < 7*24*time.Hour {
		ins.Notes = append(ins.Notes, "Unused indexes are checked once the server has been up for a week (index use is counted since it started).")
		return
	}
	rows, err := db.QueryContext(ctx, `
		SELECT object_schema, object_name, index_name
		FROM performance_schema.table_io_waits_summary_by_index_usage
		WHERE index_name IS NOT NULL AND index_name <> 'PRIMARY' AND count_read = 0
		  AND object_schema NOT IN (`+advisorSkipSchemas+`) LIMIT 5000`)
	if err != nil {
		return // performance_schema off
	}
	defer rows.Close()
	since := serverStart.UTC()
	for rows.Next() {
		var k tableKey
		var name string
		if rows.Scan(&k.schema, &k.table, &name) != nil {
			continue
		}
		for _, x := range idx[k] {
			if x.name == name && !x.unique {
				ins.UnusedIndexes = append(ins.UnusedIndexes, protocol.UnusedIndex{Database: k.schema, Schema: k.schema, Table: k.table,
					Index: name, Bytes: x.bytes, Definition: x.definition(), StatsSince: &since})
			}
		}
	}
	slices.SortFunc(ins.UnusedIndexes, func(x, y protocol.UnusedIndex) int {
		return cmp.Or(cmp.Compare(y.Bytes, x.Bytes), strings.Compare(x.Table+x.Index, y.Table+y.Index))
	})
	ins.UnusedIndexes = ins.UnusedIndexes[:min(len(ins.UnusedIndexes), 20)]
}

// duplicateIndexes: a non-unique index whose columns are the same as, or
// the leading columns of, another index of the same type.
func duplicateIndexes(idx map[tableKey][]indexInfo) []protocol.DuplicateIndex {
	out := []protocol.DuplicateIndex{}
	for k, xs := range idx {
		for _, x := range xs {
			if x.unique || x.name == "PRIMARY" {
				continue
			}
			for _, y := range xs {
				if y.name == x.name || y.typ != x.typ || len(y.columns) < len(x.columns) || !slices.Equal(y.columns[:len(x.columns)], x.columns) {
					continue
				}
				kind := "redundant"
				if len(y.columns) == len(x.columns) {
					if !y.unique && y.name > x.name {
						continue // two equal ones: keep the first by name
					}
					kind = "duplicate"
				}
				out = append(out, protocol.DuplicateIndex{Database: k.schema, Schema: k.schema, Table: k.table, Index: x.name, Kind: kind,
					CoveredBy: y.name, Bytes: x.bytes, Definition: x.definition(), CoveredDefinition: y.definition()})
				break
			}
		}
	}
	slices.SortFunc(out, func(x, y protocol.DuplicateIndex) int {
		return cmp.Or(cmp.Compare(y.Bytes, x.Bytes), strings.Compare(x.Schema+"."+x.Table+"."+x.Index, y.Schema+"."+y.Table+"."+y.Index))
	})
	return out[:min(len(out), 20)]
}
