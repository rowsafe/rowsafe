package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Compare and Bring back rows.
//
// Both work table by table, by primary key, on two connections: the copy
// (restored next to production, private socket) and production. Nothing is
// loaded into the agent's memory: the copy streams each row's key and a hash
// of its values (md5 of the row's text) with COPY straight into a temporary
// table in production, and the set operations run there, where the keys
// are indexed. Only the rows that are actually needed travel back:
// their keys go to a temporary table in the copy, and COPY streams exactly
// those rows into production. (A merge join of two key-sorted streams in the
// agent would need the agent to order keys exactly as PostgreSQL's
// collations do; letting PostgreSQL join avoids that.)
//
// Every name is looked up in the catalogs with query parameters
// (lookupRelation, shared with health fixes) and statements are built only
// from identifiers PostgreSQL quoted itself (format('%I.%I'), quote_ident).
// Both sessions use the same output settings (DateStyle, TimeZone,
// extra_float_digits...), so equal rows hash equally on both sides.

// rewindAppName is the application_name of the agent's rewind sessions.
const rewindAppName = "rowsafe-agent-rewind"

// Limits (variables for tests).
var (
	compareMaxTables           = 200
	rewindMaxTableBytes  int64 = 5 << 30
	rewindMaxTableRows   int64 = 20_000_000
	rowsMaxTables              = 50
	rowsDefaultMaxRows   int64 = 10_000_000
	rewindRowsLockTimout       = "5s"
)

// rewindSides are the two clusters: production and the copy. Tests set
// copyDB to map a production database name to the copy's (a second
// database in one cluster) and onlyDB to the one production database
// "every table" covers.
type rewindSides struct {
	prod, copy pginspect.Target
	copyDB     func(string) string
	onlyDB     string
}

func (s rewindSides) copyName(db string) string {
	if s.copyDB == nil {
		return db
	}
	return s.copyDB(db)
}

// sameOutput makes both sessions print values identically, keeps names
// from resolving to anything but the catalogs, and never times out on a
// long COPY.
var sameOutput = map[string]string{
	"search_path":                         "pg_catalog, pg_temp",
	"DateStyle":                           "ISO, YMD",
	"IntervalStyle":                       "postgres",
	"TimeZone":                            "UTC",
	"extra_float_digits":                  "1",
	"bytea_output":                        "hex",
	"statement_timeout":                   "0",
	"idle_in_transaction_session_timeout": "0",
}

// connectSide opens a session to dbname with sameOutput (and extra) set.
func connectSide(ctx context.Context, t pginspect.Target, dbname, side string, extra map[string]string) (*pgx.Conn, error) {
	t.AppName = rewindAppName
	conn, err := t.Connect(ctx, dbname)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "3D000" {
			return nil, fmt.Errorf("%w: the database %q doesn't exist in %s", errNotFound, dbname, side)
		}
		return nil, fmt.Errorf("connecting to %s: %w", side, err)
	}
	settings := map[string]string{}
	for k, v := range sameOutput {
		settings[k] = v
	}
	for k, v := range extra {
		settings[k] = v
	}
	keys := make([]string, 0, len(settings))
	for k := range settings {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if _, err := conn.Exec(ctx, `SELECT set_config($1, $2, false)`, k, settings[k]); err != nil {
			closeConn(ctx, conn)
			return nil, fmt.Errorf("setting %s on %s: %w", k, side, err)
		}
	}
	return conn, nil
}

// column is one column as the catalogs describe it.
type column struct {
	name, ident, typ string
	userType         bool   // a type created in this cluster (binary COPY may embed its OID)
	generated        bool   // GENERATED ALWAYS AS (...) STORED
	identity         string // "", "a" (ALWAYS) or "d" (BY DEFAULT)
	notNull, hasDef  bool
}

// tableMeta is what compare and rows need to know about one table.
type tableMeta struct {
	rel       relation
	cols      []column
	pk        []string // primary key column names, in key order
	sizeBytes int64
	estRows   int64
}

func (m tableMeta) col(name string) (column, bool) {
	for _, c := range m.cols {
		if c.name == name {
			return c, true
		}
	}
	return column{}, false
}

// readTableMeta reads columns, primary key and size of rel.
func readTableMeta(ctx context.Context, conn *pgx.Conn, rel relation) (tableMeta, error) {
	m := tableMeta{rel: rel}
	rows, err := conn.Query(ctx, `
		SELECT a.attname::text, quote_ident(a.attname), format_type(a.atttypid, a.atttypmod), a.atttypid >= 16384,
		       a.attgenerated <> '', a.attidentity::text, a.attnotnull, a.atthasdef
		FROM pg_attribute a
		WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attnum`, rel.oid)
	if err != nil {
		return m, err
	}
	m.cols, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (column, error) {
		var c column
		err := r.Scan(&c.name, &c.ident, &c.typ, &c.userType, &c.generated, &c.identity, &c.notNull, &c.hasDef)
		return c, err
	})
	if err != nil {
		return m, err
	}
	rows, err = conn.Query(ctx, `
		SELECT a.attname::text
		FROM pg_index i
		CROSS JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum
		WHERE i.indrelid = $1 AND i.indisprimary
		ORDER BY k.ord`, rel.oid)
	if err != nil {
		return m, err
	}
	if m.pk, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return m, err
	}
	// A partitioned table's size and rows are its partitions'.
	err = conn.QueryRow(ctx, `
		SELECT coalesce(sum(pg_total_relation_size(t.relid)), 0)::bigint,
		       coalesce(sum(greatest(c.reltuples, 0)), 0)::bigint
		FROM pg_partition_tree($1::regclass) t JOIN pg_class c ON c.oid = t.relid
		WHERE t.isleaf`, rel.oid).Scan(&m.sizeBytes, &m.estRows)
	return m, err
}

// tablePlan is how one table is compared or brought back: the columns both
// sides share (by name and type, never generated ones), the key, and the
// statements' building blocks.
type tablePlan struct {
	prod, copy tableMeta
	common     []column // in production's column order
	key        []column
	notes      []string
	format     string // COPY format: binary, or text when a column has a user-defined type
}

// planTable matches the copy's table with production's, or says in plain
// words why the table can't be compared (or brought back).
func planTable(prod, cp tableMeta, forRows bool) (tablePlan, string) {
	p := tablePlan{prod: prod, copy: cp, format: "binary"}
	if len(prod.pk) == 0 {
		return p, "it has no primary key, so Rowsafe can't tell which rows are the same (rewinding the whole database brings it back as it was)"
	}
	for _, c := range prod.cols {
		if c.generated {
			continue // computed by PostgreSQL itself
		}
		cc, ok := cp.col(c.name)
		switch {
		case !ok:
			if forRows && c.notNull && !c.hasDef && c.identity == "" {
				return p, fmt.Sprintf("the column %s was added since and needs a value, which the copy doesn't have", c.name)
			}
			p.notes = append(p.notes, fmt.Sprintf("the column %s was added since", c.name))
		case cc.typ != c.typ:
			if slices.Contains(prod.pk, c.name) {
				return p, fmt.Sprintf("the type of the key column %s changed since (%s, now %s)", c.name, cc.typ, c.typ)
			}
			if forRows && c.notNull && !c.hasDef {
				return p, fmt.Sprintf("the type of the column %s changed since (%s, now %s)", c.name, cc.typ, c.typ)
			}
			p.notes = append(p.notes, fmt.Sprintf("the type of the column %s changed since, so it is left out", c.name))
		case cc.generated:
			p.notes = append(p.notes, fmt.Sprintf("the column %s was computed then, so it is left out", c.name))
		default:
			p.common = append(p.common, c)
			if c.userType || cc.userType {
				p.format = "text"
			}
		}
	}
	for _, cc := range cp.cols {
		if _, ok := prod.col(cc.name); !ok && !cc.generated {
			p.notes = append(p.notes, fmt.Sprintf("the column %s no longer exists in production", cc.name))
		}
	}
	for _, name := range prod.pk {
		c, ok := prod.col(name)
		if !ok || !slices.ContainsFunc(p.common, func(x column) bool { return x.name == name }) {
			return p, fmt.Sprintf("the key column %s isn't in the copy", name)
		}
		p.key = append(p.key, c)
	}
	for _, c := range p.common {
		if c.name == hashColumn {
			return p, "it has a column named " + hashColumn
		}
	}
	return p, ""
}

// hashColumn holds the row hash in the temporary key tables.
const hashColumn = "__rowsafe_hash"

func idents(cols []column, prefix string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = prefix + c.ident
	}
	return strings.Join(parts, ", ")
}

// keyMatch: "a.k1 = b.k1 AND a.k2 = b.k2".
func keyMatch(cols []column, a, b string) string {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = a + "." + c.ident + " = " + b + "." + c.ident
	}
	return strings.Join(parts, " AND ")
}

// rowHash is the hash of a row's shared columns, alias.col...
func rowHash(cols []column, alias string) string {
	return "md5(ROW(" + idents(cols, alias+".") + ")::text)"
}

// pipeCopy streams COPY ... TO STDOUT on from into COPY ... FROM STDIN on to.
func pipeCopy(ctx context.Context, from *pgx.Conn, fromSQL string, to *pgx.Conn, toSQL string) (int64, error) {
	pr, pw := io.Pipe()
	errc := make(chan error, 1)
	go func() {
		_, err := from.PgConn().CopyTo(ctx, pw, fromSQL)
		pw.CloseWithError(err) // nil: the reader sees EOF
		errc <- err
	}()
	tag, err := to.PgConn().CopyFrom(ctx, pr, toSQL)
	if err != nil {
		pr.CloseWithError(err) // unblock the writer
	}
	werr := <-errc
	if werr != nil {
		return 0, fmt.Errorf("reading from the copy: %w", werr)
	}
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// shipKeys fills pg_temp.<keys> in production with the copy's keys and row
// hashes, and returns how many rows the copy has.
func shipKeys(ctx context.Context, prodConn, copyConn *pgx.Conn, p tablePlan, keys string) (int64, error) {
	if _, err := prodConn.Exec(ctx, fmt.Sprintf(`DROP TABLE IF EXISTS pg_temp.%s`, keys)); err != nil {
		return 0, err
	}
	if _, err := prodConn.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s AS SELECT %s, NULL::text AS %s FROM %s WITH NO DATA`,
		keys, idents(p.key, ""), hashColumn, p.prod.rel.ident)); err != nil {
		return 0, err
	}
	n, err := pipeCopy(ctx,
		copyConn, fmt.Sprintf(`COPY (SELECT %s, %s FROM %s c) TO STDOUT (FORMAT %s)`, idents(p.key, "c."), rowHash(p.common, "c"), p.copy.rel.ident, p.format),
		prodConn, fmt.Sprintf(`COPY pg_temp.%s FROM STDIN (FORMAT %s)`, keys, p.format))
	if err != nil {
		return 0, err
	}
	if _, err := prodConn.Exec(ctx, fmt.Sprintf(`CREATE INDEX ON pg_temp.%s (%s)`, keys, idents(p.key, ""))); err != nil {
		return 0, err
	}
	_, err = prodConn.Exec(ctx, fmt.Sprintf(`ANALYZE pg_temp.%s`, keys))
	return n, err
}

// tooBig says why a table is over the limits ("" when it isn't).
func tooBig(m tableMeta) string {
	if m.sizeBytes > rewindMaxTableBytes || m.estRows > rewindMaxTableRows {
		return fmt.Sprintf("it is too big to do here (%s, about %s rows; the limit is %s or %s rows)",
			humanBytes(m.sizeBytes), plainCount(m.estRows), humanBytes(rewindMaxTableBytes), plainCount(rewindMaxTableRows))
	}
	return ""
}

// displayName is how a table is named in results: schema.name, unquoted
// (the agent's name lookup reads it back).
func displayName(r relation) string { return r.schema + "." + r.name }

// relatedTables lists the tables linked to rel by foreign keys, either way.
func relatedTables(ctx context.Context, conn *pgx.Conn, oid uint32) ([]string, error) {
	rows, err := conn.Query(ctx, `
		SELECT DISTINCT n.nspname::text || '.' || c.relname::text
		FROM pg_constraint k
		JOIN pg_class c ON c.oid = CASE WHEN k.conrelid = $1 THEN k.confrelid ELSE k.conrelid END
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE k.contype = 'f' AND (k.conrelid = $1 OR k.confrelid = $1) AND c.oid <> $1 AND NOT c.relispartition
		ORDER BY 1`, oid)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// ---- compare ----

// compareTables compares tables between the copy and production. No
// tables: every table of every database in the copy (capped).
func compareTables(ctx context.Context, sides rewindSides, tables []protocol.RewindTable, tl *taskLog) ([]protocol.RewindTableDiff, error) {
	if len(tables) == 0 {
		var err error
		if tables, err = allCopyTables(ctx, sides); err != nil {
			return nil, err
		}
	}
	byDB := map[string][]protocol.RewindTable{}
	var order []string
	for _, t := range tables {
		if _, ok := byDB[t.DB]; !ok {
			order = append(order, t.DB)
		}
		byDB[t.DB] = append(byDB[t.DB], t)
	}
	var out []protocol.RewindTableDiff
	compared := 0
	for _, db := range order {
		diffs, err := compareDB(ctx, sides, db, byDB[db], &compared, tl)
		if err != nil {
			return out, err
		}
		out = append(out, diffs...)
	}
	return out, nil
}

// allCopyTables lists every user table in every database of the copy.
func allCopyTables(ctx context.Context, sides rewindSides) ([]protocol.RewindTable, error) {
	conn, err := connectSide(ctx, sides.copy, sides.copyName("postgres"), "the copy", nil)
	if err != nil {
		return nil, err
	}
	rows, err := conn.Query(ctx, `SELECT datname::text FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1`)
	var dbs []string
	if err == nil {
		dbs, err = pgx.CollectRows(rows, pgx.RowTo[string])
	}
	closeConn(ctx, conn)
	if err != nil {
		return nil, err
	}
	if sides.onlyDB != "" {
		dbs = []string{sides.onlyDB}
	}
	var out []protocol.RewindTable
	for _, db := range dbs {
		copyDB := sides.copyName(db)
		c, err := connectSide(ctx, sides.copy, copyDB, "the copy", nil)
		if err != nil {
			return nil, err
		}
		rows, err := c.Query(ctx, `
			SELECT n.nspname::text || '.' || c.relname::text
			FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND c.relpersistence = 'p'
			  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_%'
			  AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.objid = c.oid AND d.deptype = 'e')
			ORDER BY 1`)
		var names []string
		if err == nil {
			names, err = pgx.CollectRows(rows, pgx.RowTo[string])
		}
		closeConn(ctx, c)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			out = append(out, protocol.RewindTable{DB: db, Table: n})
		}
	}
	return out, nil
}

func compareDB(ctx context.Context, sides rewindSides, db string, tables []protocol.RewindTable, compared *int, tl *taskLog) ([]protocol.RewindTableDiff, error) {
	skipAll := func(why string) []protocol.RewindTableDiff {
		out := make([]protocol.RewindTableDiff, len(tables))
		for i, t := range tables {
			out[i] = protocol.RewindTableDiff{RewindTable: t, Skipped: why}
		}
		return out
	}
	if err := validDatName(db); err != nil {
		return skipAll(err.Error()), nil
	}
	copyConn, err := connectSide(ctx, sides.copy, sides.copyName(db), "the copy", map[string]string{"default_transaction_read_only": "off"})
	if errors.Is(err, errNotFound) {
		return skipAll("the database " + db + " isn't in the copy"), nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { closeConn(ctx, copyConn) }()
	prodConn, err := connectSide(ctx, sides.prod, db, "production", map[string]string{"lock_timeout": rewindRowsLockTimout})
	if errors.Is(err, errNotFound) {
		return skipAll("the database " + db + " no longer exists in production"), nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { closeConn(ctx, prodConn) }()
	if err := requirePrimary(ctx, prodConn); err != nil {
		return nil, err
	}

	var out []protocol.RewindTableDiff
	for _, t := range tables {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		d := protocol.RewindTableDiff{RewindTable: t}
		if *compared >= compareMaxTables {
			d.Skipped = fmt.Sprintf("not compared: Rowsafe compares up to %d tables at a time; pick the tables to compare", compareMaxTables)
			out = append(out, d)
			continue
		}
		p, why, err := resolvePlan(ctx, prodConn, copyConn, t, false)
		if err != nil {
			return out, err
		}
		if why != "" {
			d.Skipped = why
			out = append(out, d)
			tl.Printf("%s.%s: skipped, %s", db, t.Table, why)
			continue
		}
		*compared++
		d.Table = displayName(p.prod.rel)
		d.SizeBytes = p.copy.sizeBytes
		if d.Related, err = relatedFor(ctx, prodConn, db, p.prod.rel.oid); err != nil {
			return out, err
		}
		start := time.Now()
		if err := compareOne(ctx, prodConn, copyConn, p, &d); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) || isLockTimeout(err) {
				d.Skipped = "Rowsafe couldn't compare it: " + plainPGError(err).Error()
				out = append(out, d)
				tl.Printf("%s.%s: %s", db, d.Table, d.Skipped)
				// A failed statement can leave either session unusable.
				if copyConn, prodConn, err = reconnectSides(ctx, sides, db, copyConn, prodConn); err != nil {
					return out, err
				}
				continue
			}
			return out, err
		}
		d.Note = strings.Join(p.notes, "; ")
		tl.Printf("%s.%s: %s missing in production, %s changed, %s only in production (%s)", db, d.Table,
			plainCount(d.MissingInProduction), plainCount(d.Changed), plainCount(d.OnlyInProduction), time.Since(start).Round(time.Millisecond))
		out = append(out, d)
	}
	return out, nil
}

// reconnectSides replaces both sessions after an error.
func reconnectSides(ctx context.Context, sides rewindSides, db string, copyConn, prodConn *pgx.Conn) (*pgx.Conn, *pgx.Conn, error) {
	closeConn(ctx, copyConn)
	closeConn(ctx, prodConn)
	c, err := connectSide(ctx, sides.copy, sides.copyName(db), "the copy", map[string]string{"default_transaction_read_only": "off"})
	if err != nil {
		return nil, nil, err
	}
	p, err := connectSide(ctx, sides.prod, db, "production", map[string]string{"lock_timeout": rewindRowsLockTimout})
	if err != nil {
		closeConn(ctx, c)
		return nil, nil, err
	}
	return c, p, nil
}

func relatedFor(ctx context.Context, conn *pgx.Conn, db string, oid uint32) ([]protocol.RewindTable, error) {
	names, err := relatedTables(ctx, conn, oid)
	if err != nil {
		return nil, err
	}
	var out []protocol.RewindTable
	for _, n := range names {
		out = append(out, protocol.RewindTable{DB: db, Table: n})
	}
	return out, nil
}

// resolvePlan looks the table up on both sides and plans it; why is set
// when it can't be done.
func resolvePlan(ctx context.Context, prodConn, copyConn *pgx.Conn, t protocol.RewindTable, forRows bool) (tablePlan, string, error) {
	kinds := []string{"r", "p"}
	crel, err := lookupRelation(ctx, copyConn, t.Table, kinds, "table")
	if errors.Is(err, errNotFound) {
		return tablePlan{}, "it isn't in the copy (it didn't exist then)", nil
	}
	if err != nil {
		return tablePlan{}, plainPGError(err).Error(), nil
	}
	prel, err := lookupRelation(ctx, prodConn, t.Table, kinds, "table")
	if errors.Is(err, errNotFound) {
		return tablePlan{}, "it no longer exists in production (dropped or renamed since); rewinding the whole database brings it back", nil
	}
	if err != nil {
		return tablePlan{}, plainPGError(err).Error(), nil
	}
	cm, err := readTableMeta(ctx, copyConn, crel)
	if err != nil {
		return tablePlan{}, "", err
	}
	pm, err := readTableMeta(ctx, prodConn, prel)
	if err != nil {
		return tablePlan{}, "", err
	}
	if why := tooBig(cm); why != "" {
		return tablePlan{}, why, nil
	}
	p, why := planTable(pm, cm, forRows)
	return p, why, nil
}

// compareOne counts one table's differences.
func compareOne(ctx context.Context, prodConn, copyConn *pgx.Conn, p tablePlan, d *protocol.RewindTableDiff) error {
	const keys = "rowsafe_keys"
	defer func() { _, _ = prodConn.Exec(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS pg_temp.rowsafe_keys`) }()
	if _, err := shipKeys(ctx, prodConn, copyConn, p, keys); err != nil {
		return err
	}
	match := keyMatch(p.key, "p", "k")
	err := prodConn.QueryRow(ctx, fmt.Sprintf(`
		SELECT count(*) FILTER (WHERE p.ctid IS NULL),
		       count(*) FILTER (WHERE p.ctid IS NOT NULL AND %s IS DISTINCT FROM k.%s)
		FROM pg_temp.%s k LEFT JOIN %s p ON %s`, rowHash(p.common, "p"), hashColumn, keys, p.prod.rel.ident, match)).
		Scan(&d.MissingInProduction, &d.Changed)
	if err != nil {
		return err
	}
	return prodConn.QueryRow(ctx, fmt.Sprintf(`
		SELECT count(*) FROM %s p WHERE NOT EXISTS (SELECT 1 FROM pg_temp.%s k WHERE %s)`, p.prod.rel.ident, keys, match)).
		Scan(&d.OnlyInProduction)
}

// compareSummary: "Compared 3 tables: 1,204 rows are missing in production
// (in public.applications). 2 tables were skipped."
func compareSummary(diffs []protocol.RewindTableDiff) string {
	var compared, skipped int
	var missing, changed int64
	var where []string
	for _, d := range diffs {
		if d.Skipped != "" {
			skipped++
			continue
		}
		compared++
		missing += d.MissingInProduction
		changed += d.Changed
		if d.MissingInProduction > 0 || d.Changed > 0 {
			where = append(where, d.Table)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Compared %s", countNoun(compared, "table", "tables"))
	switch {
	case compared == 0:
		b.WriteString(".")
	case missing == 0 && changed == 0:
		b.WriteString(": nothing is missing or changed in production.")
	default:
		var parts []string
		if missing > 0 {
			parts = append(parts, fmt.Sprintf("%s %s missing in production", plainCount(missing), plural(int(min(missing, 2)), "row is", "rows are")))
		}
		if changed > 0 {
			parts = append(parts, fmt.Sprintf("%s %s changed", plainCount(changed), plural(int(min(changed, 2)), "row", "rows")))
		}
		if len(where) > 3 {
			where = append(where[:3], "...")
		}
		fmt.Fprintf(&b, ": %s (in %s).", strings.Join(parts, ", "), strings.Join(where, ", "))
	}
	if skipped > 0 {
		fmt.Fprintf(&b, " %s skipped.", countNoun(skipped, "table was", "tables were"))
	}
	return b.String()
}

// ---- bring back rows ----

// rowsTable is one table being brought back.
type rowsTable struct {
	req     protocol.RewindTable
	plan    tablePlan
	rows    string // pg_temp table with the copy's rows
	res     protocol.RewindTableRows
	parents []uint32 // tables it references (for ordering)
}

// bringBackRows brings rows back for tables, one transaction per database.
func bringBackRows(ctx context.Context, sides rewindSides, p protocol.RewindRowsParams, tl *taskLog) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("no tables given")
	}
	if len(p.Tables) > rowsMaxTables {
		return nil, fmt.Errorf("too many tables (%d); Rowsafe brings back rows in up to %d tables at a time", len(p.Tables), rowsMaxTables)
	}
	maxRows := p.MaxRows
	if maxRows <= 0 || maxRows > rowsDefaultMaxRows {
		maxRows = rowsDefaultMaxRows
	}
	byDB := map[string][]protocol.RewindTable{}
	var order []string
	for _, t := range p.Tables {
		if err := validDatName(t.DB); err != nil {
			return nil, err
		}
		if len(nameCandidates(t.Table)) == 0 {
			return nil, fmt.Errorf("invalid table name %q", t.Table)
		}
		if _, ok := byDB[t.DB]; !ok {
			order = append(order, t.DB)
		}
		byDB[t.DB] = append(byDB[t.DB], t)
	}
	res := &protocol.RewindRowsResult{}
	var total int64
	for _, db := range order {
		tables, err := rowsDB(ctx, sides, db, byDB[db], p.IncludeChanged, maxRows, &total, tl)
		if err != nil {
			if len(res.Tables) > 0 {
				err = fmt.Errorf("%w (rows in %s were already brought back)", err, strings.Join(dbNames(res.Tables), ", "))
			}
			return res, err
		}
		res.Tables = append(res.Tables, tables...)
	}
	res.Summary = rowsSummary(res.Tables)
	return res, nil
}

func dbNames(ts []protocol.RewindTableRows) []string {
	var out []string
	for _, t := range ts {
		if !slices.Contains(out, t.DB) {
			out = append(out, t.DB)
		}
	}
	return out
}

// rowsDB brings rows back in one database, in one transaction.
func rowsDB(ctx context.Context, sides rewindSides, db string, reqs []protocol.RewindTable, includeChanged bool, maxRows int64,
	total *int64, tl *taskLog) ([]protocol.RewindTableRows, error) {
	copyConn, err := connectSide(ctx, sides.copy, sides.copyName(db), "the copy", map[string]string{"default_transaction_read_only": "off"})
	if err != nil {
		return nil, err
	}
	defer closeConn(ctx, copyConn)
	prodConn, err := connectSide(ctx, sides.prod, db, "production", map[string]string{"lock_timeout": rewindRowsLockTimout})
	if err != nil {
		return nil, err
	}
	defer closeConn(ctx, prodConn)
	if err := requirePrimary(ctx, prodConn); err != nil {
		return nil, err
	}

	// Plan every table first: nothing changes unless all can be done.
	var tables []*rowsTable
	for _, r := range reqs {
		p, why, err := resolvePlan(ctx, prodConn, copyConn, r, true)
		if err != nil {
			return nil, rowsError(&rowsTable{res: protocol.RewindTableRows{RewindTable: r}}, err)
		}
		if why != "" {
			return nil, fmt.Errorf("%s: %s; nothing was changed", r.Table, why)
		}
		if slices.ContainsFunc(tables, func(t *rowsTable) bool { return t.plan.prod.rel.oid == p.prod.rel.oid }) {
			continue
		}
		t := &rowsTable{req: r, plan: p, rows: fmt.Sprintf("rowsafe_rows_%d", len(tables)+1)}
		t.res.RewindTable = protocol.RewindTable{DB: db, Table: displayName(p.prod.rel)}
		tables = append(tables, t)
	}
	if err := orderByForeignKeys(ctx, prodConn, tables); err != nil {
		return nil, err
	}

	tx, err := prodConn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// Restored rows existed before: user triggers (webhooks, emails, audit
	// rows) and foreign key triggers don't fire for them. The foreign keys
	// are checked below instead.
	for _, stmt := range []string{
		`SELECT set_config('lock_timeout', $1, true)`,
		`SELECT set_config('session_replication_role', 'replica', true)`,
	} {
		arg := []any{}
		if strings.Contains(stmt, "$1") {
			arg = append(arg, rewindRowsLockTimout)
		}
		if _, err := tx.Exec(ctx, stmt, arg...); err != nil {
			return nil, err
		}
	}

	for _, t := range tables {
		if err := rowsOne(ctx, tx.Conn(), copyConn, t, includeChanged, maxRows, total, tl); err != nil {
			return nil, rowsError(t, err)
		}
	}
	if err := checkForeignKeys(ctx, tx.Conn(), tables, includeChanged); err != nil {
		return nil, err
	}
	// Last, as setval isn't undone by a rollback.
	for _, t := range tables {
		if err := catchUpSequences(ctx, tx.Conn(), t); err != nil {
			return nil, rowsError(t, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, rowsError(nil, err)
	}
	out := make([]protocol.RewindTableRows, len(tables))
	for i, t := range tables {
		out[i] = t.res
	}
	return out, nil
}

// rowsError explains a failure in plain words; the transaction is rolled
// back, so nothing was changed in that database.
func rowsError(t *rowsTable, err error) error {
	var where string
	if t != nil {
		where = t.res.Table + ": "
	}
	switch {
	case isLockTimeout(err):
		return fmt.Errorf("%sanother session held a lock on the table for more than %s, so Rowsafe stopped; nothing was changed. Try again in a moment",
			where, rewindRowsLockTimout)
	case errors.Is(err, errTooManyRows):
		return fmt.Errorf("%s%w; nothing was changed", where, err)
	}
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s%s; nothing was changed", where, plainPGError(err))
	}
	return fmt.Errorf("%s%w; nothing was changed", where, err)
}

var errTooManyRows = errors.New("too many rows")

// rowsOne brings back one table's rows inside the transaction on prodConn.
func rowsOne(ctx context.Context, prodConn, copyConn *pgx.Conn, t *rowsTable, includeChanged bool, maxRows int64, total *int64, tl *taskLog) error {
	p := t.plan
	keys, need := "rowsafe_keys", "rowsafe_need"
	start := time.Now()
	if _, err := shipKeys(ctx, prodConn, copyConn, p, keys); err != nil {
		return err
	}
	match := keyMatch(p.key, "p", "k")
	sql := fmt.Sprintf(`CREATE TEMP TABLE %s ON COMMIT DROP AS
		SELECT %s FROM pg_temp.%s k WHERE NOT EXISTS (SELECT 1 FROM %s p WHERE %s)`,
		need, idents(p.key, "k."), keys, p.prod.rel.ident, match)
	if includeChanged {
		sql += fmt.Sprintf(` UNION ALL SELECT %s FROM pg_temp.%s k JOIN %s p ON %s WHERE %s IS DISTINCT FROM k.%s`,
			idents(p.key, "k."), keys, p.prod.rel.ident, match, rowHash(p.common, "p"), hashColumn)
	}
	if _, err := prodConn.Exec(ctx, `DROP TABLE IF EXISTS pg_temp.`+need); err != nil {
		return err
	}
	if _, err := prodConn.Exec(ctx, sql); err != nil {
		return err
	}
	var n int64
	if err := prodConn.QueryRow(ctx, `SELECT count(*) FROM pg_temp.`+need).Scan(&n); err != nil {
		return err
	}
	*total += n
	if *total > maxRows {
		return fmt.Errorf("%w: that is %s rows, over the limit of %s at a time", errTooManyRows, plainCount(*total), plainCount(maxRows))
	}
	if _, err := prodConn.Exec(ctx, `DROP TABLE pg_temp.`+keys); err != nil {
		return err
	}
	if n == 0 {
		tl.Printf("%s: nothing to bring back", t.res.Table)
		return prepareEmptyRows(ctx, prodConn, t)
	}

	// The needed keys go to the copy, and exactly those rows come back.
	if _, err := copyConn.Exec(ctx, `DROP TABLE IF EXISTS pg_temp.`+need); err != nil {
		return err
	}
	if _, err := copyConn.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s AS SELECT %s FROM %s WITH NO DATA`,
		need, idents(p.key, ""), p.copy.rel.ident)); err != nil {
		return err
	}
	defer func() { _, _ = copyConn.Exec(context.WithoutCancel(ctx), `DROP TABLE IF EXISTS pg_temp.`+need) }()
	if _, err := pipeCopy(ctx,
		prodConn, fmt.Sprintf(`COPY (SELECT DISTINCT %s FROM pg_temp.%s) TO STDOUT (FORMAT %s)`, idents(p.key, ""), need, p.format),
		copyConn, fmt.Sprintf(`COPY pg_temp.%s FROM STDIN (FORMAT %s)`, need, p.format)); err != nil {
		return err
	}
	if _, err := prodConn.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s ON COMMIT DROP AS SELECT %s FROM %s WITH NO DATA`,
		t.rows, idents(p.common, ""), p.prod.rel.ident)); err != nil {
		return err
	}
	if _, err := pipeCopy(ctx,
		copyConn, fmt.Sprintf(`COPY (SELECT %s FROM %s c JOIN pg_temp.%s k ON %s) TO STDOUT (FORMAT %s)`,
			idents(p.common, "c."), p.copy.rel.ident, need, keyMatch(p.key, "c", "k"), p.format),
		prodConn, fmt.Sprintf(`COPY pg_temp.%s FROM STDIN (FORMAT %s)`, t.rows, p.format)); err != nil {
		return err
	}
	if _, err := prodConn.Exec(ctx, fmt.Sprintf(`CREATE INDEX ON pg_temp.%s (%s)`, t.rows, idents(p.key, ""))); err != nil {
		return err
	}
	if _, err := prodConn.Exec(ctx, `ANALYZE pg_temp.`+t.rows); err != nil {
		return err
	}

	// Rows missing in production. ON CONFLICT DO NOTHING: a row whose
	// unique value (other than the key) another row now holds stays out,
	// and is counted.
	rmatch := keyMatch(p.key, "p", "r")
	var candidates int64
	if err := prodConn.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM pg_temp.%s r WHERE NOT EXISTS (SELECT 1 FROM %s p WHERE %s)`,
		t.rows, p.prod.rel.ident, rmatch)).Scan(&candidates); err != nil {
		return err
	}
	overriding := ""
	if slices.ContainsFunc(p.common, func(c column) bool { return c.identity == "a" }) {
		overriding = " OVERRIDING SYSTEM VALUE"
	}
	tag, err := prodConn.Exec(ctx, fmt.Sprintf(`INSERT INTO %s (%s)%s SELECT %s FROM pg_temp.%s r
		WHERE NOT EXISTS (SELECT 1 FROM %s p WHERE %s) ON CONFLICT DO NOTHING`,
		p.prod.rel.ident, idents(p.common, ""), overriding, idents(p.common, "r."), t.rows, p.prod.rel.ident, rmatch))
	if err != nil {
		return err
	}
	t.res.Inserted = tag.RowsAffected()
	t.res.Conflicts = candidates - t.res.Inserted

	if includeChanged {
		var set []column
		for _, c := range p.common {
			if !slices.Contains(p.prod.pk, c.name) && c.identity != "a" {
				set = append(set, c)
			}
		}
		if len(set) > 0 {
			tag, err := prodConn.Exec(ctx, fmt.Sprintf(`UPDATE %s p SET (%s) = ROW(%s) FROM pg_temp.%s r WHERE %s AND %s IS DISTINCT FROM %s`,
				p.prod.rel.ident, idents(set, ""), idents(set, "r."), t.rows, rmatch, rowHash(p.common, "p"), rowHash(p.common, "r")))
			if err != nil {
				return err
			}
			t.res.Updated = tag.RowsAffected()
		}
	}
	tl.Printf("%s: brought back %s rows, updated %s, %s left out because a unique value is taken now (%s)", t.res.Table,
		plainCount(t.res.Inserted), plainCount(t.res.Updated), plainCount(t.res.Conflicts), time.Since(start).Round(time.Millisecond))
	return nil
}

// prepareEmptyRows creates an empty rows table, so the foreign key checks
// can treat every table alike.
func prepareEmptyRows(ctx context.Context, prodConn *pgx.Conn, t *rowsTable) error {
	_, err := prodConn.Exec(ctx, fmt.Sprintf(`CREATE TEMP TABLE %s ON COMMIT DROP AS SELECT %s FROM %s WITH NO DATA`,
		t.rows, idents(t.plan.common, ""), t.plan.prod.rel.ident))
	return err
}

// catchUpSequences moves the sequences behind the table's columns (serial
// and identity) past the largest value now in the table, so new rows don't
// collide with the ones brought back.
func catchUpSequences(ctx context.Context, conn *pgx.Conn, t *rowsTable) error {
	rows, err := conn.Query(ctx, `
		SELECT s.oid, format('%I.%I', n.nspname, s.relname), quote_ident(a.attname), q.seqincrement
		FROM pg_depend d
		JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
		JOIN pg_namespace n ON n.oid = s.relnamespace
		JOIN pg_sequence q ON q.seqrelid = s.oid
		JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
		WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
		  AND d.refobjid = $1 AND d.deptype IN ('a', 'i')
		  AND a.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype)`, t.plan.prod.rel.oid)
	if err != nil {
		return err
	}
	type seq struct {
		oid       uint32
		name, col string
		inc       int64
	}
	seqs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (seq, error) {
		var s seq
		err := r.Scan(&s.oid, &s.name, &s.col, &s.inc)
		return s, err
	})
	if err != nil {
		return err
	}
	for _, s := range seqs {
		if s.inc <= 0 || (t.res.Inserted == 0 && t.res.Updated == 0) {
			continue
		}
		var advanced bool
		err := conn.QueryRow(ctx, fmt.Sprintf(`
			WITH m AS (SELECT max(%s)::bigint AS v FROM %s),
			     cur AS (SELECT pg_sequence_last_value($1::regclass) AS v)
			SELECT CASE WHEN m.v IS NOT NULL AND (cur.v IS NULL OR cur.v < m.v)
			            THEN setval($1::regclass, m.v) IS NOT NULL ELSE false END
			FROM m, cur`, s.col, t.plan.prod.rel.ident), s.oid).Scan(&advanced)
		if err != nil {
			return err
		}
		if advanced {
			t.res.SequencesAdvanced = append(t.res.SequencesAdvanced, s.name)
		}
	}
	return nil
}

// fkey is a foreign key as the catalogs describe it.
type fkey struct {
	name           string
	child, parent  uint32
	childIdent     string
	parentIdent    string
	parentName     string
	childCols      []string // quote_ident'ed
	parentCols     []string
	childColNames  []string
	parentColNames []string
}

func readForeignKeys(ctx context.Context, conn *pgx.Conn, where string, oids []uint32) ([]fkey, error) {
	rows, err := conn.Query(ctx, `
		SELECT k.conname::text, k.conrelid, k.confrelid,
		       format('%I.%I', cn.nspname, c.relname), format('%I.%I', pn.nspname, p.relname),
		       pn.nspname::text || '.' || p.relname::text,
		       array(SELECT quote_ident(a.attname) FROM unnest(k.conkey) WITH ORDINALITY u(n, o)
		             JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.n ORDER BY u.o),
		       array(SELECT quote_ident(a.attname) FROM unnest(k.confkey) WITH ORDINALITY u(n, o)
		             JOIN pg_attribute a ON a.attrelid = k.confrelid AND a.attnum = u.n ORDER BY u.o),
		       array(SELECT a.attname::text FROM unnest(k.conkey) WITH ORDINALITY u(n, o)
		             JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = u.n ORDER BY u.o),
		       array(SELECT a.attname::text FROM unnest(k.confkey) WITH ORDINALITY u(n, o)
		             JOIN pg_attribute a ON a.attrelid = k.confrelid AND a.attnum = u.n ORDER BY u.o)
		FROM pg_constraint k
		JOIN pg_class c ON c.oid = k.conrelid JOIN pg_namespace cn ON cn.oid = c.relnamespace
		JOIN pg_class p ON p.oid = k.confrelid JOIN pg_namespace pn ON pn.oid = p.relnamespace
		WHERE k.contype = 'f' AND k.conparentid = 0 AND k.`+where+` = ANY($1)`, oids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (fkey, error) {
		var f fkey
		err := r.Scan(&f.name, &f.child, &f.parent, &f.childIdent, &f.parentIdent, &f.parentName,
			&f.childCols, &f.parentCols, &f.childColNames, &f.parentColNames)
		return f, err
	})
}

// orderByForeignKeys puts parents before their children (a cycle keeps
// the order given).
func orderByForeignKeys(ctx context.Context, conn *pgx.Conn, tables []*rowsTable) error {
	oids := make([]uint32, len(tables))
	for i, t := range tables {
		oids[i] = t.plan.prod.rel.oid
	}
	fks, err := readForeignKeys(ctx, conn, "conrelid", oids)
	if err != nil {
		return err
	}
	for _, t := range tables {
		for _, f := range fks {
			if f.child == t.plan.prod.rel.oid && f.parent != f.child && slices.Contains(oids, f.parent) {
				t.parents = append(t.parents, f.parent)
			}
		}
	}
	placed := map[uint32]bool{}
	var out []*rowsTable
	for len(out) < len(tables) {
		progress := false
		for _, t := range tables {
			if placed[t.plan.prod.rel.oid] {
				continue
			}
			ready := true
			for _, p := range t.parents {
				if !placed[p] {
					ready = false
				}
			}
			if ready {
				placed[t.plan.prod.rel.oid] = true
				out = append(out, t)
				progress = true
			}
		}
		if !progress { // a cycle: the rest in the order given
			for _, t := range tables {
				if !placed[t.plan.prod.rel.oid] {
					placed[t.plan.prod.rel.oid] = true
					out = append(out, t)
				}
			}
		}
	}
	copy(tables, out)
	return nil
}

// checkForeignKeys refuses (rolls back) when a row brought back points to
// a row production doesn't have, or when a changed row took away a value
// other rows point to. Foreign key triggers were off, so this is where the
// constraints are enforced.
func checkForeignKeys(ctx context.Context, conn *pgx.Conn, tables []*rowsTable, includeChanged bool) error {
	oids := make([]uint32, len(tables))
	byOID := map[uint32]*rowsTable{}
	for i, t := range tables {
		oids[i] = t.plan.prod.rel.oid
		byOID[oids[i]] = t
	}
	children, err := readForeignKeys(ctx, conn, "conrelid", oids)
	if err != nil {
		return err
	}
	for _, f := range children {
		t := byOID[f.child]
		if t == nil || t.res.Inserted+t.res.Updated == 0 {
			continue
		}
		var notNull, parentMatch []string
		for i, c := range f.childCols {
			notNull = append(notNull, "c."+c+" IS NOT NULL")
			parentMatch = append(parentMatch, "p."+f.parentCols[i]+" = c."+c)
		}
		var n int64
		if err := conn.QueryRow(ctx, fmt.Sprintf(`
			SELECT count(*) FROM %s c JOIN pg_temp.%s r ON %s
			WHERE %s AND NOT EXISTS (SELECT 1 FROM %s p WHERE %s)`,
			f.childIdent, t.rows, keyMatch(t.plan.key, "c", "r"), strings.Join(notNull, " AND "),
			f.parentIdent, strings.Join(parentMatch, " AND "))).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("%s of the rows for %s point to rows of %s that aren't in production. "+
				"Bring back %s too (in the same run); nothing was changed", plainCount(n), t.res.Table, f.parentName, f.parentName)
		}
	}
	if !includeChanged {
		return nil
	}
	// A changed row may have given up a unique value that other rows point
	// to (a foreign key to a column other than the primary key).
	parents, err := readForeignKeys(ctx, conn, "confrelid", oids)
	if err != nil {
		return err
	}
	for _, f := range parents {
		t := byOID[f.parent]
		if t == nil || t.res.Updated == 0 {
			continue
		}
		onlyKey := true
		for _, c := range f.parentColNames {
			if !slices.Contains(t.plan.prod.pk, c) {
				onlyKey = false
			}
		}
		if onlyKey {
			continue // keys are never changed
		}
		var notNull, parentMatch []string
		for i, c := range f.childCols {
			notNull = append(notNull, "c."+c+" IS NOT NULL")
			parentMatch = append(parentMatch, "p."+f.parentCols[i]+" = c."+c)
		}
		var n int64
		if err := conn.QueryRow(ctx, fmt.Sprintf(`
			SELECT count(*) FROM %s c WHERE %s AND NOT EXISTS (SELECT 1 FROM %s p WHERE %s)`,
			f.childIdent, strings.Join(notNull, " AND "), f.parentIdent, strings.Join(parentMatch, " AND "))).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("restoring the changed rows of %s would leave %s rows elsewhere pointing to values that no longer exist "+
				"(foreign key %s); bring back only the missing rows instead; nothing was changed", t.res.Table, plainCount(n), f.name)
		}
	}
	return nil
}

// rowsSummary: "Brought back 1,204 rows in public.applications and 3,310
// in public.application_notes."
func rowsSummary(ts []protocol.RewindTableRows) string {
	var parts []string
	var updated, conflicts int64
	var seqs []string
	for i, t := range ts {
		updated += t.Updated
		conflicts += t.Conflicts
		seqs = append(seqs, t.SequencesAdvanced...)
		if t.Inserted == 0 {
			continue
		}
		unit := " rows"
		if t.Inserted == 1 {
			unit = " row"
		}
		if len(parts) > 0 && i > 0 {
			unit = ""
		}
		parts = append(parts, plainCount(t.Inserted)+unit+" in "+t.Table)
	}
	var b strings.Builder
	switch len(parts) {
	case 0:
		b.WriteString("No missing rows to bring back")
	case 1:
		b.WriteString("Brought back " + parts[0])
	default:
		b.WriteString("Brought back " + strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1])
	}
	b.WriteString(".")
	if updated > 0 {
		fmt.Fprintf(&b, " Set %s changed %s back to the copy's values.", plainCount(updated), plural(int(min(updated, 2)), "row", "rows"))
	}
	if conflicts > 0 {
		fmt.Fprintf(&b, " %s %s left out because another row now has the same unique value.",
			plainCount(conflicts), plural(int(min(conflicts, 2)), "row was", "rows were"))
	}
	if len(seqs) > 0 {
		fmt.Fprintf(&b, " Moved %s forward so new rows don't collide (%s).", plural(len(seqs), "a sequence", "sequences"), strings.Join(seqs, ", "))
	}
	return b.String()
}

// ---- tasks ----

// copySides returns the sessions' targets for a ready copy of db.
func (a *Agent) copySides(db protocol.DatabaseSpec, copyID string) (rewindSides, rewindRecord, error) {
	if !rewindIDRE.MatchString(copyID) {
		return rewindSides{}, rewindRecord{}, fmt.Errorf("invalid copy id %q", copyID)
	}
	r, ok := a.rewindState().get(copyID)
	switch {
	case !ok || r.Kind != protocol.RewindKindCopy:
		return rewindSides{}, r, errors.New("the copy no longer exists (it expired or was deleted); restore a new one")
	case r.DatabaseID != db.ID:
		return rewindSides{}, r, errors.New("that copy belongs to another database")
	case r.Status != protocol.RewindCopyReady:
		return rewindSides{}, r, errors.New("the copy isn't ready yet")
	}
	return rewindSides{prod: a.target(db), copy: a.copyTarget(r)}, r, nil
}

func (a *Agent) rewindCompare(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl *taskLog) (*protocol.RewindCompareResult, error) {
	sides, _, err := a.copySides(db, p.CopyID)
	if err != nil {
		return nil, err
	}
	for _, t := range p.Tables {
		if len(nameCandidates(t.Table)) == 0 {
			return nil, fmt.Errorf("invalid table name %q", t.Table)
		}
	}
	diffs, err := compareTables(ctx, sides, p.Tables, tl)
	res := &protocol.RewindCompareResult{CopyID: p.CopyID, Tables: diffs, Summary: compareSummary(diffs)}
	if err != nil {
		return res, sentence(err)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (a *Agent) rewindRows(ctx context.Context, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl *taskLog) (*protocol.RewindRowsResult, error) {
	sides, _, err := a.copySides(db, p.CopyID)
	if err != nil {
		return nil, err
	}
	res, err := bringBackRows(ctx, sides, p, tl)
	if err != nil {
		return res, sentence(err)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}
