package agent

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// create_index: build an index the index advisor proved on a copy, with
// CREATE INDEX CONCURRENTLY (reads and writes go on). The table and columns
// are looked up again; nothing is done when an index that does the same
// already exists; a build that fails leaves no invalid index behind.

const maxCreateIndexColumns = 8

// validName: a plausible PostgreSQL name (the catalogs decide the rest).
func validName(what, s string) error {
	if s == "" || len(s) > 63 || strings.ContainsRune(s, 0) || !utf8.ValidString(s) {
		return fmt.Errorf("invalid %s name %q", what, s)
	}
	return nil
}

func validateCreateIndex(c *protocol.CreateIndexParams) error {
	if c == nil {
		return errors.New("no index given")
	}
	if !protocol.ValidIndexName(c.Name) {
		return fmt.Errorf("invalid index name %q: Rowsafe only creates indexes named rs_..._idx", c.Name)
	}
	if err := validName("schema", c.Schema); err != nil {
		return err
	}
	if err := validName("table", c.Table); err != nil {
		return err
	}
	if len(c.Columns) == 0 || len(c.Columns) > maxCreateIndexColumns {
		return fmt.Errorf("an index needs 1 to %d columns, not %d", maxCreateIndexColumns, len(c.Columns))
	}
	seen := map[string]bool{}
	for _, list := range [][]string{c.Columns, c.Include} {
		for _, col := range list {
			if err := validName("column", col); err != nil {
				return err
			}
			if seen[col] {
				return fmt.Errorf("the column %q appears twice", col)
			}
			seen[col] = true
		}
	}
	for _, col := range c.Descending {
		if !slices.Contains(c.Columns, col) {
			return fmt.Errorf("the descending column %q is not a key column", col)
		}
	}
	for _, col := range append(slices.Clone(c.WhereNull), c.WhereNotNull...) {
		if err := validName("column", col); err != nil {
			return err
		}
	}
	return nil
}

func (m *maint) createIndex(ctx context.Context) error {
	spec := m.p.CreateIndex
	conn, err := m.connect(ctx, m.p.DB, map[string]string{
		"statement_timeout": "0",
		"lock_timeout":      ddlLockTimeout,
	})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	v, err := serverVersionNum(ctx, conn)
	if err != nil {
		return err
	}
	if v < 120000 {
		return fmt.Errorf("Rowsafe creates indexes on PostgreSQL 12 or newer (this server runs %d), so it didn't do it", v/10000)
	}
	if slices.Contains(systemSchemas, spec.Schema) || strings.HasPrefix(spec.Schema, "pg_") {
		return fmt.Errorf("the table %s belongs to PostgreSQL itself; Rowsafe leaves it alone", spec.TableName())
	}

	var tableOID uint32
	var table, kind string
	var tableBytes int64
	var ownTablespace bool
	err = conn.QueryRow(ctx, `
		SELECT c.oid, format('%I.%I', n.nspname, c.relname), c.relkind::text, pg_table_size(c.oid), c.reltablespace <> 0
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2`, spec.Schema, spec.Table).Scan(&tableOID, &table, &kind, &tableBytes, &ownTablespace)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("the table %s no longer exists, so Rowsafe didn't create the index", spec.TableName())
	}
	if err != nil {
		return err
	}
	switch kind {
	case "r", "m":
	case "p":
		return fmt.Errorf("%s is a partitioned table: PostgreSQL can't build one index on all its partitions without blocking writes, so Rowsafe didn't do it", table)
	default:
		return fmt.Errorf("%s isn't a table, so Rowsafe didn't create an index on it", table)
	}

	// The columns, quoted by PostgreSQL.
	want := append(append(slices.Clone(spec.Columns), spec.Include...), spec.WhereNull...)
	want = append(want, spec.WhereNotNull...)
	rows, err := conn.Query(ctx, `
		SELECT a.attname::text, format('%I', a.attname), a.attnum
		FROM pg_attribute a WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped AND a.attname = ANY($2)`, tableOID, want)
	if err != nil {
		return err
	}
	type attr struct {
		ident string
		num   int16
	}
	cols := map[string]attr{}
	for rows.Next() {
		var name string
		var a attr
		if err := rows.Scan(&name, &a.ident, &a.num); err != nil {
			rows.Close()
			return err
		}
		cols[name] = a
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range want {
		if _, ok := cols[c]; !ok {
			return fmt.Errorf("the column %s of %s no longer exists, so the index no longer fits the table; Rowsafe didn't create it", c, table)
		}
	}

	// Build the statement from PostgreSQL-quoted names only.
	keys := make([]string, len(spec.Columns))
	var keyNums []int16
	for i, c := range spec.Columns {
		keys[i] = cols[c].ident
		if slices.Contains(spec.Descending, c) {
			keys[i] += " DESC"
		}
		keyNums = append(keyNums, cols[c].num)
	}
	var nameIdent string
	if err := conn.QueryRow(ctx, `SELECT format('%I', $1::text)`, spec.Name).Scan(&nameIdent); err != nil {
		return err
	}
	var schemaIdent string
	if err := conn.QueryRow(ctx, `SELECT format('%I', $1::text)`, spec.Schema).Scan(&schemaIdent); err != nil {
		return err
	}
	stmt := "CREATE INDEX CONCURRENTLY " + nameIdent + " ON " + table + " (" + strings.Join(keys, ", ") + ")"
	allNums := slices.Clone(keyNums)
	if len(spec.Include) > 0 {
		inc := make([]string, len(spec.Include))
		for i, c := range spec.Include {
			inc[i] = cols[c].ident
			allNums = append(allNums, cols[c].num)
		}
		stmt += " INCLUDE (" + strings.Join(inc, ", ") + ")"
	}
	var where []string
	for _, c := range sortedStrings(spec.WhereNull) {
		where = append(where, cols[c].ident+" IS NULL")
	}
	for _, c := range sortedStrings(spec.WhereNotNull) {
		where = append(where, cols[c].ident+" IS NOT NULL")
	}
	pred := strings.Join(where, " AND ")
	if pred != "" {
		stmt += " WHERE " + pred
	}
	display := schemaIdent + "." + nameIdent

	// Already there? An index with the same columns, directions, covering
	// columns and condition does the job.
	var descNums []int16
	for _, c := range spec.Descending {
		descNums = append(descNums, cols[c].num)
	}
	var existing string
	err = conn.QueryRow(ctx, `
		SELECT format('%I.%I', n.nspname, c.relname)
		FROM pg_index x JOIN pg_class c ON c.oid = x.indexrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_am am ON am.oid = c.relam
		WHERE x.indrelid = $1 AND x.indisvalid AND am.amname = 'btree' AND x.indexprs IS NULL
		  AND ARRAY(SELECT unnest(x.indkey::int2[])) = $2::int2[] AND x.indnkeyatts = $3
		  AND ARRAY(SELECT k FROM unnest(x.indkey::int2[], x.indoption::int2[]) AS u(k, o) WHERE o & 1 = 1 ORDER BY k)
		      = ARRAY(SELECT unnest($4::int2[]) ORDER BY 1)
		  AND lower(regexp_replace(coalesce(pg_get_expr(x.indpred, x.indrelid), ''), '[()" ]', '', 'g'))
		      = lower(regexp_replace($5, '[()" ]', '', 'g'))
		LIMIT 1`, tableOID, allNums, len(keyNums), descNums, pred).Scan(&existing)
	switch {
	case err == nil:
		m.res.Summary = fmt.Sprintf("An index that does the same job already exists (%s), so there was nothing to do.", existing)
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}

	// The name: free, or left behind (invalid) by an earlier failed build
	// of this index.
	var clashOID, clashTable uint32
	var clashKind string
	var clashValid *bool
	err = conn.QueryRow(ctx, `
		SELECT c.oid, c.relkind::text, coalesce(x.indrelid, 0), x.indisvalid
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace LEFT JOIN pg_index x ON x.indexrelid = c.oid
		WHERE n.nspname = $1 AND c.relname = $2`, spec.Schema, spec.Name).Scan(&clashOID, &clashKind, &clashTable, &clashValid)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	case clashKind == "i" && clashTable == tableOID && clashValid != nil && !*clashValid:
		m.tl.Printf("removing %s, left behind by an earlier build that didn't finish", display)
		if _, err := conn.Exec(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+display); err != nil {
			return fmt.Errorf("an unfinished index named %s is in the way and removing it failed: %w", display, plainPGError(err))
		}
	default:
		return fmt.Errorf("something named %s already exists in %s, so Rowsafe didn't create the index", spec.Name, spec.Schema)
	}
	if err := refuseIfIndexBuilding(ctx, conn, v, tableOID, table); err != nil {
		return err
	}

	// Enough disk for the index (and the sort while building it)?
	if !ownTablespace {
		var dataDir string
		if err := conn.QueryRow(ctx, `SELECT current_setting('data_directory')`).Scan(&dataDir); err == nil {
			need := 2*spec.EstimatedBytes + 1<<30
			if spec.EstimatedBytes == 0 {
				need = tableBytes/2 + 1<<30
			}
			if free, err := freeBytes(dataDir); err == nil && free < need {
				return fmt.Errorf("there isn't enough free disk for the index: %s free, and building it needs about %s; Rowsafe didn't start",
					humanBytes(free), humanBytes(need))
			}
		}
	}

	start := time.Now()
	err = retryOnLock(ctx, m.tl, func() error {
		m.tl.Printf("%s (table %s)", stmt, humanBytes(tableBytes))
		_, err := conn.Exec(ctx, stmt)
		if err != nil {
			m.dropInvalidIndex(ctx, conn, tableOID, spec.Schema, spec.Name, display)
		}
		return err
	})
	if err != nil {
		if isLockTimeout(err) {
			return fmt.Errorf("the table %s stayed busy with long-running work, so Rowsafe couldn't create the index without getting in the way; nothing changed. Try again later", table)
		}
		return fmt.Errorf("creating the index %s failed (nothing was left behind): %w", display, plainPGError(err))
	}
	var size int64
	var valid bool
	if err := conn.QueryRow(ctx, `
		SELECT pg_relation_size(c.oid), x.indisvalid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_index x ON x.indexrelid = c.oid WHERE n.nspname = $1 AND c.relname = $2`, spec.Schema, spec.Name).Scan(&size, &valid); err != nil {
		return err
	}
	if !valid {
		m.dropInvalidIndex(ctx, conn, tableOID, spec.Schema, spec.Name, display)
		return fmt.Errorf("PostgreSQL finished building %s but marked it unusable, so Rowsafe removed it; nothing changed", display)
	}
	m.res.Summary = fmt.Sprintf("Created the index %s on %s (%s) in %s. PostgreSQL uses it for queries right away.",
		display, table, humanBytes(size), plainDuration(time.Since(start)))
	m.res.Details = append(m.res.Details, "Definition: "+stmt+".")
	return nil
}

// dropInvalidIndex removes the invalid index a failed CREATE INDEX
// CONCURRENTLY leaves behind: only an invalid index of this table with
// exactly this name.
func (m *maint) dropInvalidIndex(ctx context.Context, conn *pgx.Conn, tableOID uint32, schema, name, display string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	var invalid bool
	err := conn.QueryRow(cctx, `
		SELECT NOT x.indisvalid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_index x ON x.indexrelid = c.oid
		WHERE n.nspname = $1 AND c.relname = $2 AND x.indrelid = $3`, schema, name, tableOID).Scan(&invalid)
	if err != nil || !invalid {
		return
	}
	m.tl.Printf("removing the unfinished index %s", display)
	if _, err := conn.Exec(cctx, "DROP INDEX CONCURRENTLY IF EXISTS "+display); err != nil {
		m.tl.Printf("could not remove %s: %v (PostgreSQL doesn't use it; applying the fix again removes it)", display, err)
	}
}
