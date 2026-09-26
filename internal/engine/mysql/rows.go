package mysql

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Compare a copy with production and bring rows back, by primary key.
// Rows are read from both servers as the server prints them (the same
// version and types on both sides) and compared in the agent's memory, so
// nothing is written to production to compare. Bringing rows back inserts
// the copy's rows whose key is gone from production (INSERT IGNORE: a row
// whose other unique value is taken now is left out and counted as a
// conflict) and, when asked, sets rows that changed back to the copy's
// values, in one transaction per database. The changes go through the
// binary log like any other, so replicas and later restores see them.
// MySQL can't turn triggers off for one session: triggers on those tables
// run for the rows brought back, and the result says so.

const (
	// compareMaxRows skips tables larger than this (in the copy).
	compareMaxRows = 5_000_000
	// compareMaxTables bounds a compare of every table.
	compareMaxTables = 500
	// defaultMaxRows is the agent's own limit for bringing rows back.
	defaultMaxRows = 10_000_000
	rowBatch       = 500
)

// tableInfo is a table's primary key and columns.
type tableInfo struct {
	Schema, Name string
	PK           []string
	Columns      []string // all, in order
	Insertable   []string // not generated
	Rows, Size   int64
}

func (t tableInfo) quoted() string { return quoteIdent(t.Schema) + "." + quoteIdent(t.Name) }

func loadTableInfo(ctx context.Context, db *sql.DB, schema, name string) (tableInfo, bool, error) {
	t := tableInfo{Schema: schema, Name: name}
	err := db.QueryRowContext(ctx, `SELECT COALESCE(table_rows, 0), COALESCE(data_length + index_length, 0)
		FROM information_schema.tables WHERE table_schema = ? AND table_name = ? AND table_type = 'BASE TABLE'`,
		schema, name).Scan(&t.Rows, &t.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return t, false, nil
	}
	if err != nil {
		return t, false, err
	}
	rows, err := db.QueryContext(ctx, `SELECT column_name, COALESCE(generation_expression, '')
		FROM information_schema.columns WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position`, schema, name)
	if err != nil {
		return t, false, err
	}
	for rows.Next() {
		var c, gen string
		if err := rows.Scan(&c, &gen); err != nil {
			rows.Close()
			return t, false, err
		}
		t.Columns = append(t.Columns, c)
		if gen == "" {
			t.Insertable = append(t.Insertable, c)
		}
	}
	rows.Close()
	rows, err = db.QueryContext(ctx, `SELECT column_name FROM information_schema.key_column_usage
		WHERE table_schema = ? AND table_name = ? AND constraint_name = 'PRIMARY' ORDER BY ordinal_position`, schema, name)
	if err != nil {
		return t, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return t, false, err
		}
		t.PK = append(t.PK, c)
	}
	return t, true, rows.Err()
}

// allTables lists the base tables of the user's databases in db.
func allTables(ctx context.Context, db *sql.DB) ([]protocol.RewindTable, error) {
	rows, err := db.QueryContext(ctx, `SELECT table_schema, table_name FROM information_schema.tables
		WHERE table_type = 'BASE TABLE' AND table_schema NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')
		ORDER BY table_schema, table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.RewindTable
	for rows.Next() {
		var t protocol.RewindTable
		if err := rows.Scan(&t.DB, &t.Table); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// related lists tables linked to t by foreign keys (both directions).
func related(ctx context.Context, db *sql.DB, t protocol.RewindTable) []protocol.RewindTable {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT unique_constraint_schema, referenced_table_name FROM information_schema.referential_constraints
		WHERE constraint_schema = ? AND table_name = ?
		UNION
		SELECT DISTINCT constraint_schema, table_name FROM information_schema.referential_constraints
		WHERE unique_constraint_schema = ? AND referenced_table_name = ?`, t.DB, t.Table, t.DB, t.Table)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []protocol.RewindTable
	for rows.Next() {
		var r protocol.RewindTable
		if rows.Scan(&r.DB, &r.Table) == nil && r != t {
			out = append(out, r)
		}
	}
	return out
}

// tableDiff is one table's comparison.
type tableDiff struct {
	Copy, Prod    tableInfo
	Common        []string // columns in both (compared)
	CommonInsert  []string // columns in both that can be written
	Missing       []string // encoded keys: in the copy, gone from production
	Changed       []string // encoded keys: in both, different
	MissingN      int64
	ChangedN      int64
	OnlyProdN     int64
	Skipped, Note string
}

// encodeKey packs key values (length-prefixed).
func encodeKey(vals []sql.RawBytes) string {
	var b []byte
	for _, v := range vals {
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	return string(b)
}

func decodeKey(k string) []any {
	var out []any
	b := []byte(k)
	for len(b) >= 4 {
		n := binary.BigEndian.Uint32(b)
		b = b[4:]
		v := make([]byte, n)
		copy(v, b[:n])
		out = append(out, v)
		b = b[n:]
	}
	return out
}

// rowHash hashes a row's values (NULL differs from any string).
func rowHash(vals []sql.RawBytes) [16]byte {
	h := md5.New()
	var n [5]byte
	for _, v := range vals {
		if v == nil {
			n[0] = 0
			h.Write(n[:1])
			continue
		}
		n[0] = 1
		binary.BigEndian.PutUint32(n[1:], uint32(len(v)))
		h.Write(n[:])
		h.Write(v)
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

func quoteList(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = quoteIdent(c)
	}
	return strings.Join(q, ", ")
}

// scanTable streams (key, hash of the common columns) of a table.
func scanTable(ctx context.Context, db *sql.DB, t tableInfo, common []string, fn func(key string, hash [16]byte)) error {
	cols := append(slices.Clone(t.PK), common...)
	rows, err := db.QueryContext(ctx, "SELECT "+quoteList(cols)+" FROM "+t.quoted())
	if err != nil {
		return err
	}
	defer rows.Close()
	vals := make([]sql.RawBytes, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		fn(encodeKey(vals[:len(t.PK)]), rowHash(vals[len(t.PK):]))
	}
	return rows.Err()
}

// diffTable compares one table; keep collects the keys to bring back.
func diffTable(ctx context.Context, prod, cp *sql.DB, t protocol.RewindTable, keep bool) (*tableDiff, error) {
	d := &tableDiff{}
	var ok bool
	var err error
	if d.Copy, ok, err = loadTableInfo(ctx, cp, t.DB, t.Table); err != nil {
		return nil, err
	} else if !ok {
		d.Skipped = "not in the copy (created later)"
		return d, nil
	}
	if d.Prod, ok, err = loadTableInfo(ctx, prod, t.DB, t.Table); err != nil {
		return nil, err
	} else if !ok {
		d.Skipped = "dropped from production since"
		return d, nil
	}
	switch {
	case len(d.Copy.PK) == 0:
		d.Skipped = "no primary key: rows can't be matched"
		return d, nil
	case !slices.Equal(d.Copy.PK, d.Prod.PK):
		d.Skipped = "its primary key changed since"
		return d, nil
	case d.Copy.Rows > compareMaxRows:
		d.Skipped = fmt.Sprintf("too big to compare here (about %s rows)", commas(d.Copy.Rows))
		return d, nil
	}
	var added, removed []string
	for _, c := range d.Copy.Columns {
		if slices.Contains(d.Prod.Columns, c) {
			if !slices.Contains(d.Copy.PK, c) {
				d.Common = append(d.Common, c)
			}
		} else {
			removed = append(removed, c)
		}
	}
	for _, c := range d.Copy.Insertable {
		if slices.Contains(d.Prod.Insertable, c) {
			d.CommonInsert = append(d.CommonInsert, c)
		}
	}
	for _, c := range d.Prod.Columns {
		if !slices.Contains(d.Copy.Columns, c) {
			added = append(added, c)
		}
	}
	var notes []string
	if len(added) > 0 {
		notes = append(notes, "columns added since: "+strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		notes = append(notes, "columns removed since: "+strings.Join(removed, ", "))
	}
	d.Note = strings.Join(notes, "; ")
	copyRows := map[string][16]byte{}
	if err := scanTable(ctx, cp, d.Copy, d.Common, func(k string, h [16]byte) { copyRows[k] = h }); err != nil {
		return nil, fmt.Errorf("reading %s.%s from the copy: %w", t.DB, t.Table, err)
	}
	err = scanTable(ctx, prod, d.Prod, d.Common, func(k string, h [16]byte) {
		ch, ok := copyRows[k]
		if !ok {
			d.OnlyProdN++
			return
		}
		delete(copyRows, k)
		if ch != h {
			d.ChangedN++
			if keep {
				d.Changed = append(d.Changed, k)
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("reading %s.%s from production: %w", t.DB, t.Table, err)
	}
	d.MissingN = int64(len(copyRows))
	if keep {
		for k := range copyRows {
			d.Missing = append(d.Missing, k)
		}
		slices.Sort(d.Missing)
	}
	return d, nil
}

// openCopyAndProd connects to a ready copy and to production.
func (s *server) openCopyAndProd(ctx context.Context, id string) (prod, cp *sql.DB, err error) {
	r, err := s.readyCopy(id)
	if err != nil {
		return nil, nil, err
	}
	sc := r.scratch()
	if !sc.alive() {
		return nil, nil, errors.New("the copy isn't running (it is being started again; try again in a minute)")
	}
	if cp, err = sc.connect(ctx); err != nil {
		return nil, nil, fmt.Errorf("connecting to the copy: %w", err)
	}
	if prod, err = s.open(ctx); err != nil {
		cp.Close()
		return nil, nil, err
	}
	return prod, cp, nil
}

func (s *server) rewindCompare(ctx context.Context, p protocol.RewindCompareParams, log agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	prod, cp, err := s.openCopyAndProd(ctx, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	defer cp.Close()
	tables := p.Tables
	capped := false
	if len(tables) == 0 {
		if tables, err = allTables(ctx, cp); err != nil {
			return nil, err
		}
		if len(tables) > compareMaxTables {
			tables, capped = tables[:compareMaxTables], true
		}
	}
	res := &protocol.RewindCompareResult{CopyID: p.CopyID}
	var missing, changed, differing int64
	for _, t := range tables {
		if err := validTable(t); err != nil {
			return nil, err
		}
		d, err := diffTable(ctx, prod, cp, t, false)
		if err != nil {
			return nil, err
		}
		td := protocol.RewindTableDiff{RewindTable: t, MissingInProduction: d.MissingN, Changed: d.ChangedN,
			OnlyInProduction: d.OnlyProdN, Skipped: d.Skipped, Note: d.Note, SizeBytes: d.Copy.Size}
		if d.Skipped == "" && (d.MissingN > 0 || d.ChangedN > 0) {
			td.Related = related(ctx, cp, t)
			differing++
		}
		missing += d.MissingN
		changed += d.ChangedN
		res.Tables = append(res.Tables, td)
	}
	switch {
	case differing == 0:
		res.Summary = fmt.Sprintf("No differences in %s: every row in the copy is in production as it was.", plural(int64(len(tables)), "table", "tables"))
	default:
		res.Summary = fmt.Sprintf("%s differ: %s deleted since and %s changed since.",
			plural(differing, "table", "tables"), plural(missing, "row", "rows"), plural(changed, "row", "rows"))
	}
	if capped {
		res.Summary += fmt.Sprintf(" Only the first %d tables were compared; pick tables to compare the others.", compareMaxTables)
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

func validTable(t protocol.RewindTable) error {
	if t.DB == "" || t.Table == "" || len(t.DB) > 64 || len(t.Table) > 64 || isSystemSchema(t.DB) {
		return fmt.Errorf("invalid table %q.%q", t.DB, t.Table)
	}
	return nil
}

// rewindRows brings rows back from a copy.
func (s *server) rewindRows(ctx context.Context, p protocol.RewindRowsParams, log agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("no tables given")
	}
	for _, t := range p.Tables {
		if err := validTable(t); err != nil {
			return nil, err
		}
	}
	prod, cp, err := s.openCopyAndProd(ctx, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	defer cp.Close()
	maxRows := p.MaxRows
	if maxRows <= 0 {
		maxRows = defaultMaxRows
	}
	// Compare first; nothing is written if the total is over the limit.
	diffs := map[protocol.RewindTable]*tableDiff{}
	var total int64
	for _, t := range p.Tables {
		d, err := diffTable(ctx, prod, cp, t, true)
		if err != nil {
			return nil, err
		}
		if d.Skipped != "" {
			return nil, fmt.Errorf("%s.%s can't be brought back: %s", t.DB, t.Table, d.Skipped)
		}
		diffs[t] = d
		total += d.MissingN
		if p.IncludeChanged {
			total += d.ChangedN
		}
	}
	if total > maxRows {
		return nil, fmt.Errorf("%s to write is over the limit of %s: nothing was changed", plural(total, "row", "rows"), commas(maxRows))
	}
	order := parentsFirst(ctx, prod, p.Tables)
	res := &protocol.RewindRowsResult{}
	byDB := map[string][]protocol.RewindTable{}
	var dbs []string
	for _, t := range order {
		if _, ok := byDB[t.DB]; !ok {
			dbs = append(dbs, t.DB)
		}
		byDB[t.DB] = append(byDB[t.DB], t)
	}
	var triggers []string
	for _, dbName := range dbs {
		out, err := s.bringBack(ctx, prod, cp, byDB[dbName], diffs, p.IncludeChanged, log)
		if err != nil {
			return nil, fmt.Errorf("bringing rows back in %s failed and nothing was changed there: %w", dbName, err)
		}
		res.Tables = append(res.Tables, out...)
		for _, t := range byDB[dbName] {
			if hasTriggers(ctx, prod, t) {
				triggers = append(triggers, t.DB+"."+t.Table)
			}
		}
	}
	var parts []string
	var inserted, updated, conflicts int64
	for _, t := range res.Tables {
		inserted += t.Inserted
		updated += t.Updated
		conflicts += t.Conflicts
		if t.Inserted > 0 {
			if len(parts) == 0 {
				parts = append(parts, fmt.Sprintf("%s in %s", plural(t.Inserted, "row", "rows"), t.Table))
			} else {
				parts = append(parts, fmt.Sprintf("%s in %s", commas(t.Inserted), t.Table))
			}
		}
	}
	switch {
	case inserted == 0 && updated == 0:
		res.Summary = "Nothing to bring back: production already has these rows."
	case len(parts) > 0:
		res.Summary = "Brought back " + joinAnd(parts) + "."
	}
	if updated > 0 {
		res.Summary = strings.TrimSpace(res.Summary + fmt.Sprintf(" Set %s back to the copy's values.", plural(updated, "changed row", "changed rows")))
	}
	if conflicts > 0 {
		res.Summary += fmt.Sprintf(" %s left out: another row now holds one of their unique values.", plural(conflicts, "row was", "rows were"))
	}
	if len(triggers) > 0 {
		res.Summary += " Triggers on " + strings.Join(triggers, ", ") + " ran for these rows (MySQL can't turn them off)."
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

func joinAnd(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// bringBack writes one database's rows in one transaction.
func (s *server) bringBack(ctx context.Context, prod, cp *sql.DB, tables []protocol.RewindTable, diffs map[protocol.RewindTable]*tableDiff,
	includeChanged bool, log agent.TaskLogger) ([]protocol.RewindTableRows, error) {
	tx, err := prod.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var out []protocol.RewindTableRows
	for _, t := range tables {
		d := diffs[t]
		r := protocol.RewindTableRows{RewindTable: t}
		cols := append(slices.Clone(d.Copy.PK), without(d.CommonInsert, d.Copy.PK)...)
		for batch := range slices.Chunk(d.Missing, rowBatch) {
			rows, err := fetchRows(ctx, cp, d.Copy, cols, batch)
			if err != nil {
				return nil, err
			}
			if len(rows) == 0 {
				continue
			}
			ph := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(cols)), ", ") + ")"
			stmt := "INSERT IGNORE INTO " + d.Prod.quoted() + " (" + quoteList(cols) + ") VALUES " +
				strings.TrimSuffix(strings.Repeat(ph+", ", len(rows)), ", ")
			args := make([]any, 0, len(rows)*len(cols))
			for _, row := range rows {
				args = append(args, row...)
			}
			rs, err := tx.ExecContext(ctx, stmt, args...)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", t.DB, t.Table, err)
			}
			n, _ := rs.RowsAffected()
			r.Inserted += n
			r.Conflicts += int64(len(rows)) - n
		}
		if includeChanged && len(d.Changed) > 0 {
			set := without(d.CommonInsert, d.Copy.PK)
			if len(set) > 0 {
				assign := make([]string, len(set))
				for i, c := range set {
					assign[i] = quoteIdent(c) + " = ?"
				}
				where := make([]string, len(d.Copy.PK))
				for i, c := range d.Copy.PK {
					where[i] = quoteIdent(c) + " = ?"
				}
				stmt := "UPDATE IGNORE " + d.Prod.quoted() + " SET " + strings.Join(assign, ", ") + " WHERE " + strings.Join(where, " AND ")
				for batch := range slices.Chunk(d.Changed, rowBatch) {
					rows, err := fetchRows(ctx, cp, d.Copy, append(slices.Clone(d.Copy.PK), set...), batch)
					if err != nil {
						return nil, err
					}
					for _, row := range rows {
						args := append(slices.Clone(row[len(d.Copy.PK):]), row[:len(d.Copy.PK)]...)
						rs, err := tx.ExecContext(ctx, stmt, args...)
						if err != nil {
							return nil, fmt.Errorf("%s.%s: %w", t.DB, t.Table, err)
						}
						n, _ := rs.RowsAffected()
						r.Updated += n
					}
				}
			}
		}
		log.Printf("%s.%s: %s brought back, %s set back, %s", t.DB, t.Table, commas(r.Inserted), commas(r.Updated),
			plural(r.Conflicts, "conflict", "conflicts"))
		out = append(out, r)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

func without(cols, drop []string) []string {
	var out []string
	for _, c := range cols {
		if !slices.Contains(drop, c) {
			out = append(out, c)
		}
	}
	return out
}

// fetchRows reads rows of the copy by key, the key columns first.
func fetchRows(ctx context.Context, cp *sql.DB, t tableInfo, cols []string, keys []string) ([][]any, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	var where string
	args := make([]any, 0, len(keys)*len(t.PK))
	if len(t.PK) == 1 {
		where = quoteIdent(t.PK[0]) + " IN (" + strings.TrimSuffix(strings.Repeat("?, ", len(keys)), ", ") + ")"
	} else {
		one := "(" + strings.TrimSuffix(strings.Repeat("?, ", len(t.PK)), ", ") + ")"
		where = "(" + quoteList(t.PK) + ") IN (" + strings.TrimSuffix(strings.Repeat(one+", ", len(keys)), ", ") + ")"
	}
	for _, k := range keys {
		args = append(args, decodeKey(k)...)
	}
	rows, err := cp.QueryContext(ctx, "SELECT "+quoteList(cols)+" FROM "+t.quoted()+" WHERE "+where, args...)
	if err != nil {
		return nil, fmt.Errorf("reading %s.%s from the copy: %w", t.Schema, t.Name, err)
	}
	defer rows.Close()
	var out [][]any
	for rows.Next() {
		vals := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]any, len(cols))
		for i, v := range vals {
			if v == nil {
				row[i] = nil
			} else {
				row[i] = []byte(slices.Clone(v))
			}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// parentsFirst orders tables so that referenced tables come before the
// tables that reference them.
func parentsFirst(ctx context.Context, db *sql.DB, tables []protocol.RewindTable) []protocol.RewindTable {
	parents := map[protocol.RewindTable][]protocol.RewindTable{}
	for _, t := range tables {
		rows, err := db.QueryContext(ctx, `SELECT unique_constraint_schema, referenced_table_name
			FROM information_schema.referential_constraints WHERE constraint_schema = ? AND table_name = ?`, t.DB, t.Table)
		if err != nil {
			continue
		}
		for rows.Next() {
			var p protocol.RewindTable
			if rows.Scan(&p.DB, &p.Table) == nil && p != t {
				parents[t] = append(parents[t], p)
			}
		}
		rows.Close()
	}
	var out []protocol.RewindTable
	seen := map[protocol.RewindTable]int{} // 1 visiting, 2 done
	var visit func(t protocol.RewindTable)
	visit = func(t protocol.RewindTable) {
		if seen[t] != 0 {
			return
		}
		seen[t] = 1
		for _, p := range parents[t] {
			if slices.Contains(tables, p) {
				visit(p)
			}
		}
		seen[t] = 2
		out = append(out, t)
	}
	for _, t := range tables {
		visit(t)
	}
	return out
}

func hasTriggers(ctx context.Context, db *sql.DB, t protocol.RewindTable) bool {
	var n int
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = db.QueryRowContext(cctx, `SELECT COUNT(*) FROM information_schema.triggers WHERE event_object_schema = ? AND event_object_table = ?`,
		t.DB, t.Table).Scan(&n)
	return n > 0
}
