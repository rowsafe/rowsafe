package indexadvisor

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Tables are the tables of one database that statements use, as its
// catalogs describe them.
type Tables struct {
	ByOID  map[uint32]*Table
	byName map[[2]string]*Table // {schema as written, name}
}

// Lookup finds a table by its name as statements write it (a Catalog).
func (c *Tables) Lookup(schema, name string) *Table {
	return c.byName[[2]string{schema, name}]
}

// LoadTables resolves the relations (unqualified ones on the search path)
// and reads their size, write rate, columns with planner statistics, and
// indexes. It only reads the catalogs; conn may be inside a read-only
// transaction.
func LoadTables(ctx context.Context, conn *pgx.Conn, rels []Relation) (*Tables, error) {
	cat := &Tables{ByOID: map[uint32]*Table{}, byName: map[[2]string]*Table{}}
	var schemas, names []string
	seen := map[[2]string]bool{}
	for _, r := range rels {
		k := [2]string{r.Schema, r.Name}
		if !seen[k] && len(r.Name) <= 63 && len(r.Schema) <= 63 {
			seen[k] = true
			schemas, names = append(schemas, r.Schema), append(names, r.Name)
		}
	}
	if len(names) == 0 {
		return cat, nil
	}
	rows, err := conn.Query(ctx, `
		SELECT r.s, r.n, c.oid, n.nspname::text, c.relname::text, c.relkind::text,
		       CASE WHEN c.reltuples >= 0 THEN c.reltuples::float8 ELSE coalesce(st.n_live_tup, 0)::float8 END,
		       pg_table_size(c.oid),
		       coalesce(st.n_tup_ins + st.n_tup_upd + st.n_tup_del, 0)::float8
		FROM unnest($1::text[], $2::text[]) AS r(s, n)
		CROSS JOIN LATERAL (SELECT to_regclass(CASE WHEN r.s = '' THEN quote_ident(r.n)
		                                            ELSE quote_ident(r.s) || '.' || quote_ident(r.n) END) AS oid) x
		JOIN pg_class c ON c.oid = x.oid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stat_all_tables st ON st.relid = c.oid`, schemas, names)
	if err != nil {
		return nil, fmt.Errorf("reading tables: %w", err)
	}
	var writes = map[uint32]float64{}
	for rows.Next() {
		var s, n string
		t := &Table{Columns: map[string]Column{}}
		var w float64
		if err := rows.Scan(&s, &n, &t.OID, &t.Schema, &t.Name, &t.Kind, &t.Rows, &t.Bytes, &w); err != nil {
			rows.Close()
			return nil, err
		}
		if have, ok := cat.ByOID[t.OID]; ok {
			t = have
		} else {
			cat.ByOID[t.OID] = t
			writes[t.OID] = w
		}
		cat.byName[[2]string{s, n}] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cat.ByOID) == 0 {
		return cat, nil
	}
	var window float64
	if err := conn.QueryRow(ctx, `SELECT greatest(extract(epoch FROM now() - coalesce(
			(SELECT stats_reset FROM pg_stat_database WHERE datname = current_database()), pg_postmaster_start_time())), 1)::float8`).
		Scan(&window); err != nil {
		return nil, err
	}
	oids := make([]uint32, 0, len(cat.ByOID))
	for oid, t := range cat.ByOID {
		oids = append(oids, oid)
		t.WritesPerSecond = writes[oid] / window
	}
	rows, err = conn.Query(ctx, `
		SELECT a.attrelid, a.attname::text, format_type(a.atttypid, a.atttypmod), a.attnotnull,
		       s.null_frac IS NOT NULL, coalesce(s.n_distinct, 0)::float8, coalesce(s.null_frac, 0)::float8, coalesce(s.avg_width, 0)
		FROM pg_attribute a
		JOIN pg_class c ON c.oid = a.attrelid
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN pg_stats s ON s.schemaname = n.nspname AND s.tablename = c.relname AND s.attname = a.attname AND NOT s.inherited
		WHERE a.attrelid = ANY($1) AND a.attnum > 0 AND NOT a.attisdropped`, oids)
	if err != nil {
		return nil, fmt.Errorf("reading columns: %w", err)
	}
	for rows.Next() {
		var oid uint32
		var name string
		var col Column
		if err := rows.Scan(&oid, &name, &col.Type, &col.NotNull, &col.HasStats, &col.NDistinct, &col.NullFrac, &col.AvgWidth); err != nil {
			rows.Close()
			return nil, err
		}
		cat.ByOID[oid].Columns[name] = col
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = conn.Query(ctx, `
		SELECT x.indrelid, i.relname::text, am.amname::text, x.indisvalid AND x.indisready, x.indisunique, x.indnkeyatts::int,
		       coalesce(pg_get_expr(x.indpred, x.indrelid), ''), k.ord::int, coalesce(a.attname::text, ''),
		       coalesce((k.opt & 1) = 1, false),
		       coalesce(oc.opcdefault, false) AND (coalesce(k.coll, 0) = 0 OR k.coll = a.attcollation),
		       pg_get_indexdef(x.indexrelid)
		FROM pg_index x
		JOIN pg_class i ON i.oid = x.indexrelid
		JOIN pg_am am ON am.oid = i.relam
		CROSS JOIN LATERAL unnest(x.indkey::int2[], x.indoption::int2[], x.indclass::oid[], x.indcollation::oid[])
		     WITH ORDINALITY AS k(att, opt, cls, coll, ord)
		LEFT JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.att AND k.att > 0
		LEFT JOIN pg_opclass oc ON oc.oid = k.cls
		WHERE x.indrelid = ANY($1)
		ORDER BY x.indrelid, i.relname, k.ord`, oids)
	if err != nil {
		return nil, fmt.Errorf("reading indexes: %w", err)
	}
	var cur *Index
	var curRel uint32
	flush := func() {
		if cur != nil {
			t := cat.ByOID[curRel]
			t.Indexes = append(t.Indexes, *cur)
		}
	}
	for rows.Next() {
		var rel uint32
		var name, method, pred, col, def string
		var valid, unique, desc, plainKey bool
		var nkey, ord int
		if err := rows.Scan(&rel, &name, &method, &valid, &unique, &nkey, &pred, &ord, &col, &desc, &plainKey, &def); err != nil {
			rows.Close()
			return nil, err
		}
		if cur == nil || curRel != rel || cur.Name != name {
			flush()
			cur = &Index{Name: name, Method: method, Valid: valid, Unique: unique, Predicate: pred, Def: def}
			curRel = rel
		}
		if ord <= nkey {
			cur.Keys = append(cur.Keys, IndexKey{Col: col, Desc: desc, Plain: plainKey && col != ""})
		} else if col != "" {
			cur.Include = append(cur.Include, col)
		}
	}
	flush()
	rows.Close()
	return cat, rows.Err()
}

// Table finds a table by its schema and name (production's table of a
// candidate).
func (c *Tables) Table(schema, name string) *Table {
	for _, t := range c.ByOID {
		if t.Schema == schema && t.Name == name {
			return t
		}
	}
	return nil
}
