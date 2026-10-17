package local

import (
	"cmp"
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Schema is what an AI coding agent (or a person) needs to know about a
// database's structure: tables with their columns, keys, constraints and
// indexes (and whether those are used), views, enums and extensions.
// Read from the catalogs only: no table is read or locked.
type Schema struct {
	Database string `json:"database"`
	Version  string `json:"version"`
	// IndexStatsSince is when index scan counts started (statistics reset
	// or server start).
	IndexStatsSince *time.Time  `json:"index_stats_since,omitempty"`
	Extensions      []Extension `json:"extensions,omitempty"`
	Tables          []Table     `json:"tables"`
	Views           []View      `json:"views,omitempty"`
	Enums           []Enum      `json:"enums,omitempty"`
	// MatchingTables and MatchingViews count what matched before the cap.
	MatchingTables int `json:"matching_tables"`
	MatchingViews  int `json:"matching_views"`
	// Note says what was left out and how to see it.
	Note string `json:"note,omitempty"`
}

// Extension is an installed extension.
type Extension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Table is a table, partitioned table or foreign table (partitions are
// counted under their parent).
type Table struct {
	Schema string `json:"schema"`
	Name   string `json:"name"`
	// Kind is table, partitioned table or foreign table.
	Kind string `json:"kind"`
	// RowsEstimate is the planner's estimate (-1: never analyzed).
	RowsEstimate int64 `json:"rows_estimate"`
	// SizeBytes is the table with its indexes and TOAST, from the catalogs.
	SizeBytes        int64  `json:"size_bytes"`
	Comment          string `json:"comment,omitempty"`
	RowLevelSecurity bool   `json:"row_level_security,omitempty"`
	// PartitionKey is "RANGE (created_at)" for a partitioned table.
	PartitionKey string        `json:"partition_key,omitempty"`
	Partitions   int           `json:"partitions,omitempty"`
	Columns      []Column      `json:"columns"`
	PrimaryKey   []string      `json:"primary_key,omitempty"`
	ForeignKeys  []ForeignKey  `json:"foreign_keys,omitempty"`
	ReferencedBy []ForeignKey  `json:"referenced_by,omitempty"`
	Unique       []Constraint  `json:"unique,omitempty"`
	Checks       []Constraint  `json:"checks,omitempty"`
	Indexes      []SchemaIndex `json:"indexes,omitempty"`
	Triggers     []Trigger     `json:"triggers,omitempty"`
	ColumnsCut   int           `json:"columns_not_shown,omitempty"`
	oid          uint32
}

// Column is a table's or view's column.
type Column struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"not_null,omitempty"`
	Default string `json:"default,omitempty"`
	// Identity is "always" or "by default" for an identity column.
	Identity string `json:"identity,omitempty"`
	// Generated is the expression of a stored generated column.
	Generated string `json:"generated,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// ForeignKey is a foreign key. In ReferencedBy, Schema and Table are the
// referencing table and Columns its columns; RefColumns are this table's.
type ForeignKey struct {
	Name       string   `json:"name"`
	Columns    []string `json:"columns"`
	Schema     string   `json:"ref_schema"`
	Table      string   `json:"ref_table"`
	RefColumns []string `json:"ref_columns"`
	OnDelete   string   `json:"on_delete,omitempty"`
	OnUpdate   string   `json:"on_update,omitempty"`
}

// Constraint is a unique, check or exclusion constraint.
type Constraint struct {
	Name       string   `json:"name"`
	Columns    []string `json:"columns,omitempty"`
	Definition string   `json:"definition"`
}

// SchemaIndex is an index of a table.
type SchemaIndex struct {
	Name string `json:"name"`
	// Definition is its CREATE INDEX statement.
	Definition string `json:"definition"`
	Primary    bool   `json:"primary,omitempty"`
	Unique     bool   `json:"unique,omitempty"`
	// Constraint: it enforces the primary key or a unique or exclusion
	// constraint.
	Constraint bool `json:"constraint,omitempty"`
	// Invalid: a failed CREATE INDEX CONCURRENTLY left it unusable.
	Invalid   bool  `json:"invalid,omitempty"`
	Scans     int64 `json:"scans"`
	SizeBytes int64 `json:"size_bytes"`
}

// Trigger is a trigger on a table.
type Trigger struct {
	Name       string `json:"name"`
	Definition string `json:"definition"`
	Disabled   bool   `json:"disabled,omitempty"`
}

// View is a view or materialized view.
type View struct {
	Schema       string   `json:"schema"`
	Name         string   `json:"name"`
	Materialized bool     `json:"materialized,omitempty"`
	Columns      []Column `json:"columns"`
	Definition   string   `json:"definition,omitempty"`
	RowsEstimate int64    `json:"rows_estimate,omitempty"`
	SizeBytes    int64    `json:"size_bytes,omitempty"`
	Comment      string   `json:"comment,omitempty"`
}

// Enum is an enum type.
type Enum struct {
	Schema string   `json:"schema"`
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

// SchemaOptions narrow a schema description.
type SchemaOptions struct {
	// Tables are names or patterns (* and ?), optionally schema-qualified:
	// orders, billing.*, *_events. Empty: all.
	Tables []string
	// Schemas limit it to these schemas.
	Schemas []string
	// Limit caps the tables and views described (0: DefaultSchemaLimit;
	// negative: no cap). The largest are kept.
	Limit int
}

// DefaultSchemaLimit is how many tables (and as many views) a description
// shows unless asked otherwise.
const DefaultSchemaLimit = 100

const (
	schemaTimeout    = 15 * time.Second
	maxColumnsShown  = 300
	maxViewDefLength = 4000
)

// systemSchemas are left out.
const notSystem = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp\_%'`

// notExtension leaves out objects an extension owns (PostGIS's tables...).
const notExtension = `NOT EXISTS (SELECT 1 FROM pg_depend dep WHERE dep.classid = %s AND dep.objid = %s AND dep.deptype = 'e')`

// Schema describes the database's structure, read-only and bounded.
func (d *DB) Schema(ctx context.Context, opts SchemaOptions) (*Schema, error) {
	out := &Schema{Tables: []Table{}}
	err := d.readOnly(ctx, schemaTimeout, func(tx pgx.Tx) error {
		var version int
		if err := tx.QueryRow(ctx, `SELECT current_database(), current_setting('server_version'), current_setting('server_version_num')::int,
			coalesce((SELECT stats_reset FROM pg_stat_database WHERE datname = current_database()), pg_postmaster_start_time())`).
			Scan(&out.Database, &out.Version, &version, &out.IndexStatsSince); err != nil {
			return err
		}
		if i := strings.IndexByte(out.Version, ' '); i > 0 {
			out.Version = out.Version[:i]
		}
		rels, err := readRelations(ctx, tx, version)
		if err != nil {
			return fmt.Errorf("reading tables: %w", err)
		}
		tables, views := pickRelations(rels, opts, out)
		if err := readDetails(ctx, tx, version, tables, views); err != nil {
			return err
		}
		for _, t := range tables {
			out.Tables = append(out.Tables, *t)
		}
		for _, v := range views {
			out.Views = append(out.Views, v.view())
		}
		if out.Enums, err = readEnums(ctx, tx, opts.Schemas); err != nil {
			return fmt.Errorf("reading enums: %w", err)
		}
		if len(opts.Tables) > 0 {
			out.Enums = usedEnums(out)
		}
		rows, err := tx.Query(ctx, `SELECT extname::text, extversion FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1`)
		if err != nil {
			return err
		}
		out.Extensions, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Extension, error) {
			var e Extension
			return e, r.Scan(&e.Name, &e.Version)
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// relation is a row of the relations query.
type relation struct {
	oid          uint32
	schema, name string
	kind         string
	rows, size   int64
	rls          bool
	comment      string
	partKey      string
	partitions   int
	def          string
	cols         []Column
}

func (r *relation) view() View {
	v := View{Schema: r.schema, Name: r.name, Materialized: r.kind == "m", Columns: r.cols, Definition: r.def, Comment: r.comment}
	if v.Materialized {
		v.RowsEstimate, v.SizeBytes = r.rows, r.size
	}
	if v.Columns == nil {
		v.Columns = []Column{}
	}
	return v
}

// readRelations lists tables, views and materialized views (not
// partitions), with sizes from the catalogs (relpages: nothing is locked).
func readRelations(ctx context.Context, tx pgx.Tx, version int) ([]*relation, error) {
	partKey := `''`
	if version >= 100000 {
		partKey = `CASE WHEN c.relkind = 'p' THEN pg_get_partkeydef(c.oid) ELSE '' END`
	}
	notPartition := `true`
	if version >= 100000 {
		notPartition = `NOT c.relispartition`
	}
	q := `
		WITH RECURSIVE tree(root, relid) AS (
			SELECT c.oid, c.oid FROM pg_class c WHERE c.relkind = 'p'
			UNION ALL
			SELECT t.root, i.inhrelid FROM tree t JOIN pg_inherits i ON i.inhparent = t.relid
		), sizes AS (
			SELECT c.oid,
			       CASE WHEN c.reltuples >= 0 THEN c.reltuples::int8 ELSE coalesce(st.n_live_tup, -1) END AS rows,
			       (c.relpages::int8 + coalesce(tc.relpages, 0) +
			        coalesce((SELECT sum(ic.relpages) FROM pg_index x JOIN pg_class ic ON ic.oid = x.indexrelid WHERE x.indrelid = c.oid), 0))
			       * current_setting('block_size')::int8 AS size,
			       c.reltuples < 0 AND st.n_live_tup IS NULL AS unknown
			FROM pg_class c
			LEFT JOIN pg_class tc ON tc.oid = c.reltoastrelid
			LEFT JOIN pg_stat_all_tables st ON st.relid = c.oid
			WHERE c.relkind IN ('r', 'm', 'f')
		)
		SELECT c.oid, n.nspname::text, c.relname::text, c.relkind::text,
		       CASE WHEN c.relkind = 'p' THEN coalesce((SELECT sum(greatest(s.rows, 0)) FROM tree t JOIN sizes s ON s.oid = t.relid WHERE t.root = c.oid), 0)::int8
		            ELSE coalesce(s.rows, 0) END,
		       CASE WHEN c.relkind = 'p' THEN coalesce((SELECT sum(s.size) FROM tree t JOIN sizes s ON s.oid = t.relid WHERE t.root = c.oid), 0)::int8
		            ELSE coalesce(s.size, 0) END,
		       c.relrowsecurity, coalesce(obj_description(c.oid, 'pg_class'), ''), ` + partKey + `,
		       (SELECT count(*) FROM pg_inherits i WHERE i.inhparent = c.oid)::int
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN sizes s ON s.oid = c.oid
		WHERE c.relkind IN ('r', 'p', 'f', 'v', 'm') AND ` + notPartition + ` AND ` + notSystem + `
		  AND ` + fmt.Sprintf(notExtension, `'pg_class'::regclass`, `c.oid`)
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*relation, error) {
		var x relation
		err := r.Scan(&x.oid, &x.schema, &x.name, &x.kind, &x.rows, &x.size, &x.rls, &x.comment, &x.partKey, &x.partitions)
		return &x, err
	})
}

// matchName reports whether schema.name matches a --table pattern.
func matchName(pattern, schema, name string) bool {
	pattern = strings.ToLower(pattern)
	if i := strings.LastIndexByte(pattern, '.'); i >= 0 {
		ok1, _ := path.Match(pattern[:i], strings.ToLower(schema))
		ok2, _ := path.Match(pattern[i+1:], strings.ToLower(name))
		return ok1 && ok2
	}
	ok, _ := path.Match(pattern, strings.ToLower(name))
	return ok
}

// pickRelations filters the relations and caps them, keeping the largest,
// in schema and name order.
func pickRelations(rels []*relation, opts SchemaOptions, out *Schema) ([]*Table, []*relation) {
	var tables, views []*relation
	for _, r := range rels {
		if len(opts.Schemas) > 0 && !slices.ContainsFunc(opts.Schemas, func(s string) bool { return strings.EqualFold(s, r.schema) }) {
			continue
		}
		if len(opts.Tables) > 0 && !slices.ContainsFunc(opts.Tables, func(p string) bool { return matchName(p, r.schema, r.name) }) {
			continue
		}
		if r.kind == "v" || r.kind == "m" {
			views = append(views, r)
		} else {
			tables = append(tables, r)
		}
	}
	out.MatchingTables, out.MatchingViews = len(tables), len(views)
	limit := opts.Limit
	if limit == 0 {
		limit = DefaultSchemaLimit
	}
	bySize := func(a, b *relation) int { return cmp.Or(cmp.Compare(b.size, a.size), cmp.Compare(b.rows, a.rows)) }
	byName := func(a, b *relation) int {
		return cmp.Or(strings.Compare(a.schema, b.schema), strings.Compare(a.name, b.name))
	}
	var notes []string
	if limit > 0 && len(tables) > limit {
		slices.SortFunc(tables, bySize)
		tables = tables[:limit]
		notes = append(notes, fmt.Sprintf("the %d largest of %d tables", limit, out.MatchingTables))
	}
	if limit > 0 && len(views) > limit {
		slices.SortFunc(views, bySize)
		views = views[:limit]
		notes = append(notes, fmt.Sprintf("%d of %d views", limit, out.MatchingViews))
	}
	if len(notes) > 0 {
		out.Note = "Showing " + strings.Join(notes, " and ") + ". Name tables to see others (--table orders --table 'billing.*'), or --limit 0 for all."
	}
	slices.SortFunc(tables, byName)
	slices.SortFunc(views, byName)
	ts := make([]*Table, len(tables))
	for i, r := range tables {
		kind := map[string]string{"p": "partitioned table", "f": "foreign table"}[r.kind]
		ts[i] = &Table{Schema: r.schema, Name: r.name, Kind: cmp.Or(kind, "table"), RowsEstimate: r.rows, SizeBytes: r.size,
			Comment: r.comment, RowLevelSecurity: r.rls, PartitionKey: r.partKey, Partitions: r.partitions,
			Columns: []Column{}, oid: r.oid}
	}
	return ts, views
}

// readDetails reads the columns, constraints, indexes and triggers of the
// chosen tables, and the columns and definitions of the chosen views.
func readDetails(ctx context.Context, tx pgx.Tx, version int, tables []*Table, views []*relation) error {
	byOID := map[uint32]*Table{}
	viewByOID := map[uint32]*relation{}
	var oids []uint32
	for _, t := range tables {
		byOID[t.oid] = t
		oids = append(oids, t.oid)
	}
	for _, v := range views {
		viewByOID[v.oid] = v
		oids = append(oids, v.oid)
	}
	if len(oids) == 0 {
		return nil
	}
	generated := `''`
	if version >= 120000 {
		generated = `a.attgenerated::text`
	}
	rows, err := tx.Query(ctx, `
		SELECT a.attrelid, a.attname::text, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       coalesce(pg_get_expr(ad.adbin, ad.adrelid), ''), a.attidentity::text, `+generated+`,
		       coalesce(col_description(a.attrelid, a.attnum), '')
		FROM pg_attribute a
		LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
		WHERE a.attrelid = ANY($1) AND a.attnum > 0 AND NOT a.attisdropped
		ORDER BY a.attrelid, a.attnum`, oids)
	if err != nil {
		return fmt.Errorf("reading columns: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var c Column
		var def, identity, gen string
		if err := rows.Scan(&oid, &c.Name, &c.Type, &c.NotNull, &def, &identity, &gen, &c.Comment); err != nil {
			rows.Close()
			return err
		}
		c.Type = shortType(c.Type)
		switch {
		case gen == "s":
			c.Generated = def
		case identity == "a":
			c.Identity = "always"
		case identity == "d":
			c.Identity = "by default"
		default:
			c.Default = strings.ReplaceAll(def, "::regclass", "")
		}
		if v := viewByOID[oid]; v != nil {
			v.cols = append(v.cols, Column{Name: c.Name, Type: c.Type, Comment: c.Comment})
			continue
		}
		t := byOID[oid]
		if len(t.Columns) >= maxColumnsShown {
			t.ColumnsCut++
			continue
		}
		t.Columns = append(t.Columns, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if err := readConstraints(ctx, tx, version, byOID, oids); err != nil {
		return fmt.Errorf("reading constraints: %w", err)
	}
	if err := readIndexes(ctx, tx, byOID, oids); err != nil {
		return fmt.Errorf("reading indexes: %w", err)
	}
	rows, err = tx.Query(ctx, `
		SELECT tgrelid, tgname::text, pg_get_triggerdef(oid), tgenabled = 'D'
		FROM pg_trigger WHERE tgrelid = ANY($1) AND NOT tgisinternal ORDER BY tgrelid, tgname`, oids)
	if err != nil {
		return fmt.Errorf("reading triggers: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var tr Trigger
		if err := rows.Scan(&oid, &tr.Name, &tr.Definition, &tr.Disabled); err != nil {
			rows.Close()
			return err
		}
		if t := byOID[oid]; t != nil {
			t.Triggers = append(t.Triggers, tr)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(views) == 0 {
		return nil
	}
	var voids []uint32
	for _, v := range views {
		voids = append(voids, v.oid)
	}
	rows, err = tx.Query(ctx, `SELECT c.oid, pg_get_viewdef(c.oid, true) FROM pg_class c WHERE c.oid = ANY($1)`, voids)
	if err != nil {
		return fmt.Errorf("reading views: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var def string
		if err := rows.Scan(&oid, &def); err != nil {
			rows.Close()
			return err
		}
		def = strings.TrimSpace(def)
		if len(def) > maxViewDefLength {
			def = def[:maxViewDefLength] + " ..."
		}
		viewByOID[oid].def = def
	}
	rows.Close()
	return rows.Err()
}

// fkAction names an ON DELETE/UPDATE action ("" for NO ACTION).
func fkAction(c string) string {
	return map[string]string{"a": "", "r": "restrict", "c": "cascade", "n": "set null", "d": "set default"}[c]
}

func readConstraints(ctx context.Context, tx pgx.Tx, version int, byOID map[uint32]*Table, oids []uint32) error {
	notClone := `true`
	if version >= 110000 {
		notClone = `c.conparentid = 0`
	}
	rows, err := tx.Query(ctx, `
		SELECT c.conrelid, c.confrelid, c.conname::text, c.contype::text, pg_get_constraintdef(c.oid),
		       array(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(n, o)
		             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.n ORDER BY k.o),
		       array(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(n, o)
		             JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.n ORDER BY k.o),
		       coalesce(fn.nspname::text, ''), coalesce(fc.relname::text, ''),
		       coalesce(sn.nspname::text, ''), coalesce(sc.relname::text, ''),
		       c.confdeltype::text, c.confupdtype::text
		FROM pg_constraint c
		JOIN pg_class sc ON sc.oid = c.conrelid
		JOIN pg_namespace sn ON sn.oid = sc.relnamespace
		LEFT JOIN pg_class fc ON fc.oid = c.confrelid
		LEFT JOIN pg_namespace fn ON fn.oid = fc.relnamespace
		WHERE (c.conrelid = ANY($1) OR (c.contype = 'f' AND c.confrelid = ANY($1))) AND c.contype IN ('p', 'u', 'f', 'c', 'x')
		  AND `+notClone+`
		ORDER BY c.conrelid, c.contype, c.conname`, oids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rel, ref uint32
		var name, typ, def, refSchema, refTable, srcSchema, srcTable, del, upd string
		var cols, refCols []string
		if err := rows.Scan(&rel, &ref, &name, &typ, &def, &cols, &refCols, &refSchema, &refTable, &srcSchema, &srcTable, &del, &upd); err != nil {
			return err
		}
		if t := byOID[rel]; t != nil {
			switch typ {
			case "p":
				t.PrimaryKey = cols
			case "u":
				t.Unique = append(t.Unique, Constraint{Name: name, Columns: cols, Definition: def})
			case "f":
				t.ForeignKeys = append(t.ForeignKeys, ForeignKey{Name: name, Columns: cols, Schema: refSchema, Table: refTable,
					RefColumns: refCols, OnDelete: fkAction(del), OnUpdate: fkAction(upd)})
			default:
				t.Checks = append(t.Checks, Constraint{Name: name, Definition: def})
			}
		}
		if t := byOID[ref]; t != nil && typ == "f" {
			t.ReferencedBy = append(t.ReferencedBy, ForeignKey{Name: name, Columns: cols, Schema: srcSchema, Table: srcTable,
				RefColumns: refCols, OnDelete: fkAction(del), OnUpdate: fkAction(upd)})
		}
	}
	return rows.Err()
}

// readIndexes reads the tables' indexes with how often they were used
// (summed over the partitions for a partitioned table's index).
func readIndexes(ctx context.Context, tx pgx.Tx, byOID map[uint32]*Table, oids []uint32) error {
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE tree(root, relid) AS (
			SELECT x.indexrelid, x.indexrelid FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid
			WHERE x.indrelid = ANY($1) AND i.relkind = 'I'
			UNION ALL
			SELECT t.root, h.inhrelid FROM tree t JOIN pg_inherits h ON h.inhparent = t.relid
		)
		SELECT x.indrelid, i.relname::text, pg_get_indexdef(x.indexrelid), x.indisprimary, x.indisunique, x.indisvalid,
		       EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid = x.indexrelid AND c.conrelid = x.indrelid AND c.contype IN ('p', 'u', 'x')),
		       CASE WHEN i.relkind = 'I' THEN coalesce((SELECT sum(s.idx_scan) FROM tree t JOIN pg_stat_all_indexes s ON s.indexrelid = t.relid WHERE t.root = x.indexrelid), 0)
		            ELSE coalesce(s.idx_scan, 0) END::int8,
		       CASE WHEN i.relkind = 'I' THEN coalesce((SELECT sum(c.relpages) FROM tree t JOIN pg_class c ON c.oid = t.relid WHERE t.root = x.indexrelid), 0)
		            ELSE i.relpages END::int8 * current_setting('block_size')::int8
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		LEFT JOIN pg_stat_all_indexes s ON s.indexrelid = x.indexrelid
		WHERE x.indrelid = ANY($1)
		ORDER BY x.indrelid, NOT x.indisprimary, i.relname`, oids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var rel uint32
		var ix SchemaIndex
		var valid bool
		if err := rows.Scan(&rel, &ix.Name, &ix.Definition, &ix.Primary, &ix.Unique, &valid, &ix.Constraint, &ix.Scans, &ix.SizeBytes); err != nil {
			return err
		}
		ix.Invalid = !valid
		if t := byOID[rel]; t != nil {
			t.Indexes = append(t.Indexes, ix)
		}
	}
	return rows.Err()
}

func readEnums(ctx context.Context, tx pgx.Tx, schemas []string) ([]Enum, error) {
	rows, err := tx.Query(ctx, `
		SELECT n.nspname::text, t.typname::text, array_agg(e.enumlabel::text ORDER BY e.enumsortorder)
		FROM pg_type t
		JOIN pg_enum e ON e.enumtypid = t.oid
		JOIN pg_namespace n ON n.oid = t.typnamespace
		WHERE `+notSystem+` AND `+fmt.Sprintf(notExtension, `'pg_type'::regclass`, `t.oid`)+`
		GROUP BY 1, 2 ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	enums, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Enum, error) {
		var e Enum
		return e, r.Scan(&e.Schema, &e.Name, &e.Values)
	})
	if err != nil || len(schemas) == 0 {
		return enums, err
	}
	return slices.DeleteFunc(enums, func(e Enum) bool {
		return !slices.ContainsFunc(schemas, func(s string) bool { return strings.EqualFold(s, e.Schema) })
	}), nil
}

// shortType shortens PostgreSQL's long type names (fewer tokens, same
// meaning).
func shortType(t string) string {
	for _, r := range [][2]string{
		{"timestamp with time zone", "timestamptz"}, {"timestamp without time zone", "timestamp"},
		{"time with time zone", "timetz"}, {"time without time zone", "time"},
		{"character varying", "varchar"}, {"character", "char"}, {"double precision", "float8"},
	} {
		if strings.HasPrefix(t, r[0]) {
			t = r[1] + t[len(r[0]):]
		}
	}
	// timestamp(3) with time zone
	t = precisionType.ReplaceAllString(t, "${1}tz$2")
	return strings.Replace(t, ") without time zone", ")", 1)
}

var precisionType = regexp.MustCompile(`^(timestamp|time)(\(\d+\)) with time zone`)

// usedEnums keeps the enums the described tables and views use.
func usedEnums(s *Schema) []Enum {
	used := map[string]bool{}
	note := func(cols []Column) {
		for _, c := range cols {
			used[strings.TrimSuffix(c.Type, "[]")] = true
		}
	}
	for _, t := range s.Tables {
		note(t.Columns)
	}
	for _, v := range s.Views {
		note(v.Columns)
	}
	return slices.DeleteFunc(s.Enums, func(e Enum) bool {
		return !used[e.Name] && !used[e.Schema+"."+e.Name] && !used[`"`+e.Name+`"`]
	})
}
