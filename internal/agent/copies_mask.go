package agent

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking a safe copy happens inside the copy, on the server, before it
// opens to anyone: rows are read by the agent, masked in memory (package
// masking) and written back with UPDATE. Afterwards the statistics are
// rebuilt (pg_stats would otherwise still show real values) and
// materialized views refreshed (they hold their own copy of the data).

// maskKeyPath holds the host's masking key: masking is deterministic under
// it, so the same email is masked the same way in every table and copy.
func (a *Agent) maskKeyPath() string { return filepath.Join(a.cfg.StateDir, "masking.key") }

func (a *Agent) maskKey() ([]byte, error) {
	if key, err := os.ReadFile(a.maskKeyPath()); err == nil && len(key) >= 32 {
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(a.maskKeyPath(), key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

type maskColumn struct {
	name     string
	typ      string
	strategy string
	maxLen   int
	unique   bool
	nullable bool
	integer  bool
}

type maskTable struct {
	ident string // quoted schema.name
	name  string // schema.name (its root table for a partition)
	rows  int64
	cols  []maskColumn
}

// maskTablesSQL lists the application's tables that hold rows (partitions
// included, partitioned parents not) with their columns, and names each by
// its root table so a partition follows its parent's rules.
const maskTablesSQL = `
SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname),
       CASE WHEN c.relispartition THEN (SELECT rn.nspname || '.' || rc.relname FROM pg_catalog.pg_class rc
                                        JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace
                                        WHERE rc.oid = pg_catalog.pg_partition_root(c.oid))
            ELSE n.nspname || '.' || c.relname END,
       greatest(c.reltuples, 0)::bigint,
       a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
       EXISTS (SELECT 1 FROM pg_catalog.pg_index i WHERE i.indrelid = c.oid AND i.indisunique AND i.indnatts = 1
               AND i.indkey[0] = a.attnum AND i.indpred IS NULL),
       a.attgenerated <> ''
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast' AND n.nspname !~ '^pg_temp'
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
ORDER BY 1, a.attnum`

func ruleKey(db, table, column string) string { return db + "\x00" + table + "\x00" + column }

// maskPlan decides each column's strategy: the saved rule when it fits the
// column's type, else the suggestion.
func maskPlan(db string, rows [][]any, rules map[string]string, report *protocol.MaskingReport) []maskTable {
	var tables []maskTable
	byIdent := map[string]int{}
	for _, r := range rows {
		ident, name := r[0].(string), r[1].(string)
		reltuples, col, typ := r[2].(int64), r[3].(string), r[4].(string)
		nullable, unique, generated := r[5].(bool), r[6].(bool), r[7].(bool)
		strategy, saved := rules[ruleKey(db, name, col)]
		switch {
		case saved && !masking.Fits(strategy, typ):
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s: the rule %q doesn't fit its type %s, so the suggestion was used", db, name, col, strategy, typ))
			strategy = masking.Suggest(name, col, typ)
		case !saved:
			strategy = masking.Suggest(name, col, typ)
		}
		if strategy == masking.Keep {
			continue
		}
		if generated {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s is computed from other columns and can't be masked itself", db, name, col))
			continue
		}
		if strategy == masking.Null && !nullable {
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s can't be emptied: it is NOT NULL", db, name, col))
			continue
		}
		i, ok := byIdent[ident]
		if !ok {
			i = len(tables)
			byIdent[ident] = i
			tables = append(tables, maskTable{ident: ident, name: name, rows: reltuples})
		}
		tables[i].cols = append(tables[i].cols, maskColumn{name: col, typ: typ, strategy: strategy, maxLen: masking.MaxLen(typ),
			unique: unique, nullable: nullable, integer: masking.Class(typ) == masking.ClassInteger})
	}
	return tables
}

// maskCopy masks every database of a copy. conn is unused beyond the
// target; each database gets its own sessions.
func (a *Agent) maskCopy(ctx context.Context, t pginspect.Target, dbs []string, plan protocol.MaskingPlan, tl *taskLog) (protocol.MaskingReport, error) {
	start := time.Now()
	report := protocol.MaskingReport{Mode: plan.Mode, Strategies: map[string]int{}}
	if plan.Mode == protocol.MaskingNone {
		tl.Printf("no masking: an admin chose to open this copy with the real data")
		return report, nil
	}
	key, err := a.maskKey()
	if err != nil {
		return report, fmt.Errorf("the masking key: %w", err)
	}
	m := masking.New(key)
	rules := map[string]string{}
	for _, r := range plan.Rules {
		if masking.Known(r.Strategy) {
			rules[ruleKey(r.DB, r.Table, r.Column)] = r.Strategy
		}
	}
	for _, dbname := range dbs {
		if err := a.maskDatabase(ctx, t, dbname, m, rules, &report, tl); err != nil {
			return report, fmt.Errorf("masking %s: %w", dbname, err)
		}
	}
	report.DurationMs = time.Since(start).Milliseconds()
	tl.Printf("masked %d columns in %d tables (%d rows) in %s", report.Columns, report.Tables, report.Rows, time.Since(start).Round(time.Second))
	return report, nil
}

func (a *Agent) maskDatabase(ctx context.Context, t pginspect.Target, dbname string, m *masking.Masker, rules map[string]string,
	report *protocol.MaskingReport, tl *taskLog) error {
	reader, err := copyConnect(ctx, t, dbname)
	if err != nil {
		return err
	}
	defer closeConn(context.Background(), reader)
	writer, err := copyConnect(ctx, t, dbname)
	if err != nil {
		return err
	}
	defer closeConn(context.Background(), writer)
	// No triggers, no foreign key checks: the rows are only being disguised.
	for _, c := range []*pgx.Conn{reader, writer} {
		if _, err := c.Exec(ctx, "SET session_replication_role = replica"); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, "SET DateStyle = 'ISO, YMD'; SET IntervalStyle = 'iso_8601'; SET TimeZone = 'UTC'; SET extra_float_digits = 1"); err != nil {
			return err
		}
	}
	rows, err := reader.Query(ctx, strings.Replace(maskTablesSQL, "a.attgenerated <> ''", generatedExpr(reader), 1))
	if err != nil {
		return err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) ([]any, error) {
		var ident, name, col, typ string
		var n int64
		var nullable, unique, generated bool
		err := r.Scan(&ident, &name, &n, &col, &typ, &nullable, &unique, &generated)
		return []any{ident, name, n, col, typ, nullable, unique, generated}, err
	})
	if err != nil {
		return err
	}
	tables := maskPlan(dbname, all, rules, report)
	for _, tb := range tables {
		n, err := maskTableRows(ctx, reader, writer, tb, m)
		if err != nil {
			return fmt.Errorf("%s: %w", tb.name, err)
		}
		report.Tables++
		report.Rows += n
		for _, c := range tb.cols {
			report.Columns++
			report.Strategies[c.strategy]++
		}
		var names []string
		for _, c := range tb.cols {
			names = append(names, c.name+" ("+c.strategy+")")
		}
		tl.Printf("masked %s.%s: %s, %d rows", dbname, tb.name, strings.Join(names, ", "), n)
		// Statistics hold sample values (pg_stats): rebuild them from the
		// masked rows.
		if _, err := writer.Exec(ctx, "ANALYZE "+tb.ident); err != nil {
			return fmt.Errorf("rebuilding statistics of %s: %w", tb.name, err)
		}
	}
	if len(tables) == 0 {
		return nil
	}
	// Materialized views keep their own copy of the data.
	mrows, err := writer.Query(ctx, `SELECT quote_ident(n.nspname) || '.' || quote_ident(c.relname)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'm' AND c.relispopulated AND n.nspname NOT IN ('pg_catalog', 'information_schema')`)
	if err != nil {
		return err
	}
	views, err := pgx.CollectRows(mrows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, v := range views {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		_, err := writer.Exec(rctx, "REFRESH MATERIALIZED VIEW "+v)
		cancel()
		if err != nil {
			if _, err := writer.Exec(ctx, "REFRESH MATERIALIZED VIEW "+v+" WITH NO DATA"); err != nil {
				return fmt.Errorf("emptying the materialized view %s: %w", v, err)
			}
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s couldn't be refreshed from the masked data, so it was emptied (REFRESH MATERIALIZED VIEW fills it again)", dbname, v))
			continue
		}
		tl.Printf("refreshed %s.%s from the masked data", dbname, v)
	}
	return nil
}

// maskTableRows masks one table and returns the rows changed. A unique
// column whose fake value happens to clash is tried again with other
// values.
func maskTableRows(ctx context.Context, reader, writer *pgx.Conn, tb maskTable, m *masking.Masker) (int64, error) {
	var nullCols, valueCols []maskColumn
	for _, c := range tb.cols {
		if c.strategy == masking.Null {
			nullCols = append(nullCols, c)
		} else {
			valueCols = append(valueCols, c)
		}
	}
	var total int64
	if len(nullCols) > 0 {
		var set, where []string
		for _, c := range nullCols {
			id := pgx.Identifier{c.name}.Sanitize()
			set = append(set, id+" = NULL")
			where = append(where, id+" IS NOT NULL")
		}
		tag, err := writer.Exec(ctx, "UPDATE ONLY "+tb.ident+" SET "+strings.Join(set, ", ")+" WHERE "+strings.Join(where, " OR "))
		if err != nil {
			return 0, err
		}
		total = tag.RowsAffected()
	}
	if len(valueCols) == 0 {
		return total, nil
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var n int64
		n, err = maskValues(ctx, reader, writer, tb, valueCols, m, attempt*1000)
		var pg *pgconn.PgError
		if err == nil {
			return max(total, n), nil
		}
		if !errors.As(err, &pg) || pg.Code != "23505" {
			return 0, err
		}
	}
	return 0, fmt.Errorf("masked values kept clashing with a unique index: %w", err)
}

// maskValues streams the rows (by ctid) through the masker into a temporary
// table and updates the table from it in one statement.
func maskValues(ctx context.Context, reader, writer *pgx.Conn, tb maskTable, cols []maskColumn, m *masking.Masker, attemptBase int) (int64, error) {
	var sel, where, tmpCols, set []string
	for i, c := range cols {
		id := pgx.Identifier{c.name}.Sanitize()
		sel = append(sel, id+"::text")
		where = append(where, id+" IS NOT NULL")
		tmpCols = append(tmpCols, fmt.Sprintf("c%d text", i))
		set = append(set, fmt.Sprintf("%s = coalesce(m.c%d::%s, t.%s)", id, i, c.typ, id))
	}
	if _, err := writer.Exec(ctx, "DROP TABLE IF EXISTS pg_temp.rowsafe_mask; CREATE TEMP TABLE rowsafe_mask (tid text, "+strings.Join(tmpCols, ", ")+")"); err != nil {
		return 0, err
	}
	defer func() { _, _ = writer.Exec(context.WithoutCancel(ctx), "DROP TABLE IF EXISTS pg_temp.rowsafe_mask") }()
	rows, err := reader.Query(ctx, "SELECT ctid::text, "+strings.Join(sel, ", ")+" FROM ONLY "+tb.ident+" WHERE "+strings.Join(where, " OR "))
	if err != nil {
		return 0, err
	}
	src := &maskSource{rows: rows, cols: cols, m: m, attemptBase: attemptBase, seen: make([]map[uint64]struct{}, len(cols))}
	for i, c := range cols {
		if c.unique {
			src.seen[i] = map[uint64]struct{}{}
		}
	}
	names := []string{"tid"}
	for i := range cols {
		names = append(names, fmt.Sprintf("c%d", i))
	}
	_, err = writer.CopyFrom(ctx, pgx.Identifier{"rowsafe_mask"}, names, src)
	rows.Close()
	if err == nil {
		err = rows.Err()
	}
	if err == nil {
		err = src.err
	}
	if err != nil {
		return 0, err
	}
	if _, err := writer.Exec(ctx, "ANALYZE pg_temp.rowsafe_mask"); err != nil {
		return 0, err
	}
	tag, err := writer.Exec(ctx, "UPDATE ONLY "+tb.ident+" AS t SET "+strings.Join(set, ", ")+" FROM pg_temp.rowsafe_mask m WHERE t.ctid = m.tid::tid")
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// maskSource feeds CopyFrom with masked rows.
type maskSource struct {
	rows        pgx.Rows
	cols        []maskColumn
	m           *masking.Masker
	attemptBase int
	seen        []map[uint64]struct{} // unique columns: fake values handed out
	vals        []any
	err         error
}

func (s *maskSource) Next() bool { return s.err == nil && s.rows.Next() }

func (s *maskSource) Values() ([]any, error) {
	raw := make([]*string, len(s.cols)+1)
	dest := make([]any, len(raw))
	for i := range raw {
		dest[i] = &raw[i]
	}
	if err := s.rows.Scan(dest...); err != nil {
		s.err = err
		return nil, err
	}
	out := make([]any, len(raw))
	out[0] = *raw[0]
	for i, c := range s.cols {
		v := raw[i+1]
		if v == nil {
			out[i+1] = nil
			continue
		}
		o := masking.Options{MaxLen: c.maxLen, Integer: c.integer, Attempt: s.attemptBase}
		fake, ok := s.m.Value(c.strategy, *v, o)
		if seen := s.seen[i]; seen != nil && ok {
			for tries := 1; ; tries++ {
				h := fnv.New64a()
				h.Write([]byte(fake))
				if _, dup := seen[h.Sum64()]; !dup {
					seen[h.Sum64()] = struct{}{}
					break
				}
				if tries > 50 {
					s.err = fmt.Errorf("column %s: couldn't find a unique fake value", c.name)
					return nil, s.err
				}
				o.Attempt = s.attemptBase + tries
				fake, _ = s.m.Value(c.strategy, *v, o)
			}
		}
		if ok {
			out[i+1] = fake
		} else {
			out[i+1] = nil // left as it is (coalesce keeps the original)
		}
	}
	return out, nil
}

func (s *maskSource) Err() error { return s.err }

// maskingSummary: "38 columns in 12 tables (emails 5, names 8, ...)".
func maskingSummary(r protocol.MaskingReport) string {
	if r.Mode == protocol.MaskingNone {
		return "not masked (real data)"
	}
	if r.Columns == 0 {
		return "nothing needed masking under the current rules"
	}
	var parts []string
	for s, n := range r.Strategies {
		parts = append(parts, fmt.Sprintf("%s %d", s, n))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d columns masked in %d tables (%s)", r.Columns, r.Tables, strings.Join(parts, ", "))
}
