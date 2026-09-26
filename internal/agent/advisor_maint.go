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

// Maintenance actions for advisor recommendations (Pulse ->
// Recommendations): create an index for a foreign key, drop an invalid
// index, move a sequence past the values already in its column, and set a
// table's autovacuum storage parameters. Same rules as the other fixes:
// names and ids only, everything looked up again in the catalogs, the
// conditions that made the fix safe checked again, SQL built only from
// identifiers PostgreSQL quoted itself (and, for storage parameters, from
// allow-listed keys and numbers the protocol validated).

const (
	maxIndexColumns    = 32
	maxStorageSettings = 12
)

// advisorTimeouts are the overall time limits of the advisor actions
// (registered in maintenanceTimeouts).
var advisorTimeouts = map[string]time.Duration{
	protocol.MaintCreateIndex:           2 * time.Hour,
	protocol.MaintDropInvalidIndex:      30 * time.Minute,
	protocol.MaintSyncSequence:          2 * time.Minute,
	protocol.MaintSetTableStorageParams: 2 * time.Minute,
}

func init() {
	for k, v := range advisorTimeouts {
		maintenanceTimeouts[k] = v
	}
}

// validateAdvisorMaintenance checks the params of an advisor action.
func validateAdvisorMaintenance(p protocol.MaintenanceParams) error {
	if err := validDatName(p.DB); err != nil {
		return err
	}
	switch p.Action {
	case protocol.MaintCreateIndex, protocol.MaintSetTableStorageParams:
		if p.Action == protocol.MaintCreateIndex && p.CreateIndex != nil {
			return validateCreateIndex(p.CreateIndex) // a proven index (maintenance_createindex.go)
		}
		if len(p.Tables) != 1 || len(nameCandidates(p.Tables[0])) == 0 {
			return fmt.Errorf("exactly one valid table name is needed")
		}
		if p.Action == protocol.MaintCreateIndex {
			if len(p.Columns) == 0 || len(p.Columns) > maxIndexColumns {
				return fmt.Errorf("an index needs 1 to %d columns", maxIndexColumns)
			}
			for _, c := range p.Columns {
				if c == "" || len(c) > 63 || strings.ContainsRune(c, 0) || !utf8.ValidString(c) {
					return fmt.Errorf("invalid column name %q", c)
				}
			}
			return nil
		}
		if len(p.Settings) == 0 || len(p.Settings) > maxStorageSettings {
			return fmt.Errorf("1 to %d settings are needed", maxStorageSettings)
		}
		for k, v := range p.Settings {
			if _, err := protocol.CanonicalStorageParam(k, v); err != nil {
				return err
			}
		}
	case protocol.MaintDropInvalidIndex:
		if len(nameCandidates(p.Index)) == 0 {
			return fmt.Errorf("invalid index name %q", p.Index)
		}
	case protocol.MaintSyncSequence:
		if len(nameCandidates(p.Sequence)) == 0 {
			return fmt.Errorf("invalid sequence name %q", p.Sequence)
		}
	}
	return nil
}

// advisorAction runs one advisor action.
func (m *maint) advisorAction(ctx context.Context) error {
	switch m.p.Action {
	case protocol.MaintCreateIndex:
		if m.p.CreateIndex != nil {
			return m.createIndexSpec(ctx)
		}
		return m.createIndex(ctx)
	case protocol.MaintDropInvalidIndex:
		return m.dropInvalidIndex(ctx)
	case protocol.MaintSyncSequence:
		return m.syncSequence(ctx)
	case protocol.MaintSetTableStorageParams:
		return m.setStorageParams(ctx)
	}
	return fmt.Errorf("unknown maintenance action %q", m.p.Action)
}

// ---- create index ----

// indexName is <table>_<columns>_idx, shortened to PostgreSQL's 63 bytes.
func indexName(table string, cols []string, n int) string {
	suffix := "_idx"
	if n > 0 {
		suffix = fmt.Sprintf("_idx%d", n)
	}
	base := table + "_" + strings.Join(cols, "_")
	for len(base)+len(suffix) > 63 {
		_, size := utf8.DecodeLastRuneInString(base)
		base = base[:len(base)-size]
	}
	return base + suffix
}

func (m *maint) createIndex(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{
		"statement_timeout": "0",
		"lock_timeout":      ddlLockTimeout,
		// Building an index with more memory is faster (this session only).
		"maintenance_work_mem": "256MB",
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
	tbl, err := lookupRelation(ctx, conn, m.p.Tables[0], []string{"r", "p", "m"}, "table")
	if err != nil {
		return err
	}
	if tbl.kind == "p" {
		return fmt.Errorf("%s is a partitioned table; PostgreSQL can't build an index on it without blocking writes, so Rowsafe didn't. "+
			"Create the index on each partition, then on the table (see Do it yourself)", tbl.display())
	}
	if slices.Contains(systemSchemas, tbl.schema) {
		return fmt.Errorf("the table %s belongs to PostgreSQL itself; Rowsafe leaves it alone", tbl.display())
	}
	// The columns, in the order given.
	rows, err := conn.Query(ctx, `
		SELECT u.name, a.attnum FROM unnest($2::text[]) WITH ORDINALITY u(name, o)
		LEFT JOIN pg_attribute a ON a.attrelid = $1 AND a.attname = u.name AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY u.o`, tbl.oid, m.p.Columns)
	if err != nil {
		return err
	}
	type col struct {
		name   string
		attnum *int16
	}
	cols, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (col, error) {
		var c col
		return c, r.Scan(&c.name, &c.attnum)
	})
	if err != nil {
		return err
	}
	var attnums []int16
	for _, c := range cols {
		if c.attnum == nil {
			return fmt.Errorf("the table %s has no column %q (anymore), so Rowsafe didn't create the index", tbl.display(), c.name)
		}
		if slices.Contains(attnums, *c.attnum) {
			return fmt.Errorf("the column %q is listed twice", c.name)
		}
		attnums = append(attnums, *c.attnum)
	}
	// Already indexed: a valid index whose leading key columns are these.
	var existing string
	err = conn.QueryRow(ctx, `
		SELECT format('%I.%I', n.nspname, i.relname) FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_namespace n ON n.oid = i.relnamespace
		WHERE x.indrelid = $1 AND x.indisvalid AND x.indpred IS NULL AND x.indnkeyatts >= cardinality($2::int2[])
		  AND (x.indkey::int2[])[0:cardinality($2::int2[]) - 1] @> $2::int2[]
		  AND (x.indkey::int2[])[0:cardinality($2::int2[]) - 1] <@ $2::int2[]
		LIMIT 1`, tbl.oid, attnums).Scan(&existing)
	switch {
	case err == nil:
		m.res.Summary = fmt.Sprintf("%s already has an index on %s (%s); there was nothing to do.", tbl.display(), strings.Join(m.p.Columns, ", "), existing)
		return nil
	case !errors.Is(err, pgx.ErrNoRows):
		return err
	}
	if err := refuseIfIndexBuilding(ctx, conn, v, tbl.oid, tbl.display()); err != nil {
		return err
	}
	// A free name; an invalid index of ours left by an earlier failed try
	// (same name, same table) is removed first.
	var name string
	for n := 0; n < 10 && name == ""; n++ {
		cand := indexName(tbl.name, m.p.Columns, n)
		var oid uint32
		var onTable, valid bool
		err := conn.QueryRow(ctx, `
			SELECT c.oid, coalesce(x.indrelid = $3, false), coalesce(x.indisvalid, true)
			FROM pg_class c JOIN pg_namespace ns ON ns.oid = c.relnamespace LEFT JOIN pg_index x ON x.indexrelid = c.oid
			WHERE ns.nspname = $1 AND c.relname = $2`, tbl.schema, cand, tbl.oid).Scan(&oid, &onTable, &valid)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			name = cand
		case err != nil:
			return err
		case onTable && !valid:
			var stmt string
			if err := conn.QueryRow(ctx, `SELECT format('DROP INDEX CONCURRENTLY IF EXISTS %I.%I', $1::text, $2::text)`, tbl.schema, cand).Scan(&stmt); err != nil {
				return err
			}
			m.tl.Printf("removing %s, left behind by an earlier failed build", cand)
			if _, err := conn.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("removing the unfinished index %s left by an earlier try failed: %w", cand, plainPGError(err))
			}
			name = cand
		}
	}
	if name == "" {
		return fmt.Errorf("couldn't find a free name for the new index on %s", tbl.display())
	}
	var stmt, drop string
	if err := conn.QueryRow(ctx, `
		SELECT format('CREATE INDEX CONCURRENTLY %I ON %s (%s)', $1::text, $2::text,
		              (SELECT string_agg(format('%I', c), ', ' ORDER BY o) FROM unnest($3::text[]) WITH ORDINALITY u(c, o))),
		       format('DROP INDEX CONCURRENTLY IF EXISTS %I.%I', $4::text, $1::text)`,
		name, tbl.ident, m.p.Columns, tbl.schema).Scan(&stmt, &drop); err != nil {
		return err
	}
	var tableBytes int64
	_ = conn.QueryRow(ctx, `SELECT pg_relation_size($1)`, tbl.oid).Scan(&tableBytes)
	t0 := time.Now()
	err = retryOnLock(ctx, m.tl, func() error {
		m.tl.Printf("%s (table %s)", stmt, humanBytes(tableBytes))
		_, err := conn.Exec(ctx, stmt)
		if err != nil {
			// A failed concurrent build leaves an invalid index: remove it.
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			defer cancel()
			if _, derr := conn.Exec(cctx, drop); derr != nil {
				m.tl.Printf("could not remove the unfinished index %s: %v", name, derr)
				return noRetry{err}
			}
		}
		return err
	})
	if err != nil {
		if isLockTimeout(err) {
			return fmt.Errorf("the table %s stayed busy with long-running work, so Rowsafe couldn't create the index without getting in the way; nothing changed. Try again later", tbl.display())
		}
		return fmt.Errorf("creating the index on %s failed (nothing changed): %w", tbl.display(), plainPGError(err))
	}
	var size int64
	_ = conn.QueryRow(ctx, `SELECT pg_relation_size(c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2`, tbl.schema, name).Scan(&size)
	m.res.Summary = fmt.Sprintf("Created the index %s on %s (%s) in %s.", name, tbl.display(), humanBytes(size), plainDuration(time.Since(t0)))
	m.res.Details = append(m.res.Details, "Index: "+stmt+".", "To remove it again: "+strings.Replace(drop, " IF EXISTS", "", 1)+";")
	return nil
}

// ---- drop invalid index ----

func (m *maint) dropInvalidIndex(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{"statement_timeout": "0", "lock_timeout": ddlLockTimeout})
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
	idx, err := m.lookupIndex(ctx, conn)
	if errors.Is(err, errNotFound) {
		m.res.Summary = fmt.Sprintf("The index %s was already removed; there was nothing to do.", m.p.Index)
		return nil
	}
	if err != nil {
		return err
	}
	var valid, constraint bool
	var tableOID uint32
	var table string
	var bytes int64
	if err := conn.QueryRow(ctx, `
		SELECT x.indisvalid, EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conindid = x.indexrelid),
		       x.indrelid, format('%I.%I', n.nspname, t.relname), pg_relation_size(x.indexrelid)
		FROM pg_index x JOIN pg_class t ON t.oid = x.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE x.indexrelid = $1`, idx.oid).Scan(&valid, &constraint, &tableOID, &table, &bytes); err != nil {
		return err
	}
	m.tl.Printf("index %s on %s: %s, valid=%v, constraint=%v", idx.display(), table, humanBytes(bytes), valid, constraint)
	switch {
	case valid:
		return fmt.Errorf("the index %s is valid now (its build must have finished), so Rowsafe left it alone", idx.display())
	case constraint:
		return fmt.Errorf("the index %s belongs to a constraint, so Rowsafe didn't remove it", idx.display())
	}
	if err := refuseIfIndexBuilding(ctx, conn, v, tableOID, table); err != nil {
		return err
	}
	stmt := "DROP INDEX CONCURRENTLY " + idx.ident
	err = retryOnLock(ctx, m.tl, func() error {
		var same bool
		if err := conn.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_index x ON x.indexrelid = c.oid
			               WHERE n.nspname = $1 AND c.relname = $2 AND c.oid = $3 AND NOT x.indisvalid)`,
			idx.schema, idx.name, idx.oid).Scan(&same); err != nil {
			return err
		}
		if !same {
			return errIndexGone
		}
		m.tl.Printf("%s", stmt)
		_, err := conn.Exec(ctx, stmt)
		return err
	})
	switch {
	case errors.Is(err, errIndexGone):
		m.res.Summary = fmt.Sprintf("The invalid index %s was already removed or rebuilt; there was nothing to do.", idx.display())
		return nil
	case err != nil && isLockTimeout(err):
		return fmt.Errorf("the table %s stayed busy with long-running work, so Rowsafe couldn't remove the index %s without getting in the way; try again later", table, idx.display())
	case err != nil:
		return fmt.Errorf("removing the index %s failed: %w", idx.display(), plainPGError(err))
	}
	m.res.Summary = fmt.Sprintf("Removed the invalid index %s (freed %s). PostgreSQL no longer updates it on every write to %s.", idx.display(), humanBytes(bytes), table)
	return nil
}

// ---- sync sequence ----

func (m *maint) syncSequence(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{"statement_timeout": "60s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	seq, err := lookupRelation(ctx, conn, m.p.Sequence, []string{"S"}, "sequence")
	if err != nil {
		return err
	}
	// The columns it fills: owned by (serial, identity) or in a default.
	rows, err := conn.Query(ctx, `
		WITH uses AS (
		  SELECT d.refobjid AS tbl, d.refobjsubid::int2 AS attnum FROM pg_depend d
		  WHERE d.classid = 'pg_class'::regclass AND d.objid = $1 AND d.refclassid = 'pg_class'::regclass
		    AND d.deptype IN ('a', 'i') AND d.refobjsubid > 0
		  UNION
		  SELECT ad.adrelid, ad.adnum FROM pg_depend d JOIN pg_attrdef ad ON ad.oid = d.objid
		  WHERE d.classid = 'pg_attrdef'::regclass AND d.refclassid = 'pg_class'::regclass AND d.refobjid = $1
		)
		SELECT format('%I.%I', n.nspname, t.relname), a.attname::text,
		       format('SELECT max(%I)::bigint FROM %I.%I', a.attname, n.nspname, t.relname)
		FROM uses u JOIN pg_class t ON t.oid = u.tbl JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_attribute a ON a.attrelid = u.tbl AND a.attnum = u.attnum AND NOT a.attisdropped
		WHERE t.relkind IN ('r', 'p') AND a.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype)
		ORDER BY 1, 2`, seq.oid)
	if err != nil {
		return err
	}
	type use struct{ table, column, query string }
	uses, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (use, error) {
		var u use
		return u, r.Scan(&u.table, &u.column, &u.query)
	})
	if err != nil {
		return err
	}
	if len(uses) == 0 {
		return fmt.Errorf("the sequence %s doesn't fill any table column, so Rowsafe can't tell where it should be", seq.display())
	}
	var highest int64
	var where string
	for _, u := range uses {
		var mx *int64
		if err := conn.QueryRow(ctx, u.query).Scan(&mx); err != nil {
			return fmt.Errorf("reading the highest %s in %s: %w", u.column, u.table, plainPGError(err))
		}
		m.tl.Printf("%s.%s: highest value %v", u.table, u.column, derefOr(mx, 0))
		if mx != nil && (where == "" || *mx > highest) {
			highest, where = *mx, u.table+"."+u.column
		}
	}
	var last, inc, maxv, start int64
	var called bool
	if err := conn.QueryRow(ctx, `
		SELECT s.last_value, s.is_called, q.seqincrement, q.seqmax, q.seqstart
		FROM `+seq.ident+` s, pg_sequence q WHERE q.seqrelid = $1`, seq.oid).Scan(&last, &called, &inc, &maxv, &start); err != nil {
		return err
	}
	next := last
	if called {
		next = last + inc
	}
	m.tl.Printf("sequence %s: last_value %d, is_called %v, increment %d; next value %d", seq.display(), last, called, inc, next)
	switch {
	case where == "":
		m.res.Summary = fmt.Sprintf("The columns filled by %s are empty; there was nothing to do.", seq.display())
		return nil
	case inc <= 0:
		return fmt.Errorf("the sequence %s counts down; Rowsafe only moves sequences that count up", seq.display())
	case next > highest:
		m.res.Summary = fmt.Sprintf("The sequence %s is already past the highest value in %s (%d); there was nothing to do.", seq.display(), where, highest)
		return nil
	case highest >= maxv:
		return fmt.Errorf("%s already holds %d, the highest value the sequence %s can hand out, so moving it wouldn't help; the column needs a larger type", where, highest, seq.display())
	}
	var now int64
	if err := conn.QueryRow(ctx, `SELECT setval($1::oid::regclass, greatest($2::bigint, (SELECT last_value FROM `+seq.ident+`)), true)`,
		seq.oid, highest).Scan(&now); err != nil {
		return fmt.Errorf("moving the sequence %s failed: %w", seq.display(), plainPGError(err))
	}
	m.res.Summary = fmt.Sprintf("Moved the sequence %s forward to %d, the highest value in %s: new rows get %d and up, so inserts no longer fail with duplicate keys.",
		seq.display(), now, where, now+inc)
	m.res.Details = append(m.res.Details, fmt.Sprintf("Before: next value %d.", next))
	return nil
}

func derefOr[T any](p *T, def T) T {
	if p == nil {
		return def
	}
	return *p
}

// ---- table storage parameters ----

func (m *maint) setStorageParams(ctx context.Context) error {
	conn, err := m.connect(ctx, m.p.DB, map[string]string{"statement_timeout": "30s", "lock_timeout": ddlLockTimeout})
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	if err := requirePrimary(ctx, conn); err != nil {
		return err
	}
	tbl, err := lookupRelation(ctx, conn, m.p.Tables[0], []string{"r", "m"}, "table")
	if err != nil {
		return err
	}
	if slices.Contains(systemSchemas, tbl.schema) {
		return fmt.Errorf("the table %s belongs to PostgreSQL itself; Rowsafe leaves it alone", tbl.display())
	}
	keys := make([]string, 0, len(m.p.Settings))
	for k := range m.p.Settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var set []string
	for _, k := range keys {
		v, err := protocol.CanonicalStorageParam(k, m.p.Settings[k])
		if err != nil {
			return err
		}
		set = append(set, k+" = "+v) // k: an allow-listed name; v: a plain number
	}
	var before []string
	if err := conn.QueryRow(ctx, `SELECT coalesce(reloptions, '{}') FROM pg_class WHERE oid = $1`, tbl.oid).Scan(&before); err != nil {
		return err
	}
	old := map[string]string{}
	for _, o := range before {
		if k, v, ok := strings.Cut(o, "="); ok {
			old[k] = v
		}
	}
	stmt := "ALTER TABLE " + tbl.ident + " SET (" + strings.Join(set, ", ") + ")"
	err = retryOnLock(ctx, m.tl, func() error {
		m.tl.Printf("%s", stmt)
		_, err := conn.Exec(ctx, stmt)
		return err
	})
	if err != nil {
		if isLockTimeout(err) {
			return fmt.Errorf("the table %s stayed busy with long-running work, so Rowsafe couldn't change its settings without getting in the way; nothing changed. Try again later", tbl.display())
		}
		return fmt.Errorf("changing the settings of %s failed (nothing changed): %w", tbl.display(), plainPGError(err))
	}
	var was, reset []string
	for _, k := range keys {
		if v, ok := old[k]; ok {
			was = append(was, k+" = "+v)
		} else {
			reset = append(reset, k)
		}
	}
	m.res.Summary = fmt.Sprintf("Changed the autovacuum settings of %s: %s. Autovacuum now cleans it up after a fixed number of changed rows instead of a share of the table.",
		tbl.display(), strings.Join(set, ", "))
	undo := []string{}
	if len(reset) > 0 {
		undo = append(undo, "ALTER TABLE "+tbl.ident+" RESET ("+strings.Join(reset, ", ")+");")
	}
	if len(was) > 0 {
		undo = append(undo, "ALTER TABLE "+tbl.ident+" SET ("+strings.Join(was, ", ")+");")
	}
	m.res.Details = append(m.res.Details, "To undo: "+strings.Join(undo, " "))
	return nil
}
