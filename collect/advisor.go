package collect

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Advisor facts: a few more catalog readings made with the insights, for
// the control plane's recommendations (schema, queries, capacity). Same
// rules as the other insights queries: read-only, 5 second statement
// timeout, 200ms lock timeout, bounded by LIMIT, and a failing check is
// noted while the others go on.

const (
	maxAdvisorItems     = 20
	maxIntegerKeys      = 30
	maxSequenceProbes   = 200 // max(column) lookups per database (each an index probe)
	integerKeyMinPct    = 5.0
	largeTableMinRows   = 1_000_000
	largeTableMinPages  = 131072 // 1 GB of 8 kB pages
	advisorLargeTables  = 30
	pgVersionSequences  = 100000 // pg_sequence, pg_sequences
	pgVersionProgressCI = 120000 // pg_stat_progress_create_index
)

// advisorCheck is one named reading of a database.
type advisorCheck struct {
	what string
	fn   func(ctx context.Context) error
}

// advisorCluster reads the cluster-wide memory facts (on the postgres
// database connection) and makes ins.Advisor ready for the per-database
// readings.
func advisorCluster(ctx context.Context, conn *pgx.Conn, ins *protocol.Insights) {
	ins.Advisor = &protocol.AdvisorFacts{
		ForeignKeys:          []protocol.ForeignKeyWithoutIndex{},
		NoPrimaryKey:         []protocol.TableWithoutPK{},
		IntegerKeys:          []protocol.IntegerKey{},
		SequencesBehind:      []protocol.SequenceBehind{},
		InvalidIndexes:       []protocol.InvalidIndex{},
		DuplicateConstraints: []protocol.DuplicateConstraint{},
		TimestampColumns:     []protocol.TimestampTable{},
		LargeTables:          []protocol.LargeTable{},
	}
	var m protocol.MemoryFacts
	err := conn.QueryRow(ctx, `
		SELECT pg_size_bytes(current_setting('shared_buffers')), pg_size_bytes(current_setting('effective_cache_size')),
		       pg_size_bytes(current_setting('work_mem')), current_setting('max_connections')::int,
		       current_setting('autovacuum_vacuum_scale_factor')::float8, current_setting('autovacuum_vacuum_threshold')::bigint,
		       current_setting('autovacuum_analyze_scale_factor')::float8,
		       coalesce((SELECT sum(pg_database_size(oid)) FROM pg_database WHERE datallowconn), 0)::bigint,
		       current_setting('server_version_num')::int`).Scan(
		&m.SharedBuffersBytes, &m.EffectiveCacheSizeBytes, &m.WorkMemBytes, &m.MaxConnections,
		&m.VacuumScaleFactor, &m.VacuumThreshold, &m.AnalyzeScaleFactor, &m.DatabaseBytes, &m.VersionNum)
	if err != nil {
		ins.Truncated = true
		ins.Notes = append(ins.Notes, "memory settings skipped ("+firstLineOf(err.Error())+")")
		return
	}
	ins.Advisor.Memory = &m
}

// advisorChecks are the per-database readings. Statistics-based ones are
// left out on a replica (the primary tracks them).
func (q insightQueries) advisorChecks(ins *protocol.Insights, inRecovery bool, statsSince *time.Time) []advisorCheck {
	if ins.Advisor == nil {
		return nil
	}
	version := 0
	if ins.Advisor.Memory != nil {
		version = ins.Advisor.Memory.VersionNum
	}
	a := ins.Advisor
	checks := []advisorCheck{
		{"foreign keys without an index", func(ctx context.Context) error { return q.foreignKeysWithoutIndex(ctx, a) }},
		{"tables without a primary key", func(ctx context.Context) error { return q.tablesWithoutPK(ctx, a) }},
		{"invalid indexes", func(ctx context.Context) error { return q.invalidIndexes(ctx, a, version) }},
		{"duplicate constraints", func(ctx context.Context) error { return q.duplicateConstraints(ctx, a) }},
	}
	if version == 0 || version >= pgVersionSequences {
		checks = append(checks,
			advisorCheck{"integer keys", func(ctx context.Context) error { return q.integerKeys(ctx, a) }},
			advisorCheck{"sequences", func(ctx context.Context) error { return q.sequencesBehind(ctx, a) }})
	}
	if !inRecovery {
		checks = append(checks,
			advisorCheck{"timestamp columns", func(ctx context.Context) error { return q.timestampColumns(ctx, a) }},
			advisorCheck{"large tables", func(ctx context.Context) error { return q.largeTables(ctx, a, statsSince) }})
	}
	return checks
}

// foreignKeysWithoutIndex: the foreign key's columns are not the leading
// key columns (in any order) of a valid, non-partial index.
func (q insightQueries) foreignKeysWithoutIndex(ctx context.Context, a *protocol.AdvisorFacts) error {
	return collectRows(ctx, q.conn, `
		WITH fk AS (
		  SELECT k.conname, k.conrelid, k.confrelid, k.conkey
		  FROM pg_constraint k JOIN pg_class t ON t.oid = k.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		  WHERE k.contype = 'f' AND t.relkind IN ('r', 'p') AND NOT t.relispartition AND `+userSchemas+`
		), missing AS (
		  SELECT fk.* FROM fk
		  WHERE NOT EXISTS (
		    SELECT 1 FROM pg_index x
		    WHERE x.indrelid = fk.conrelid AND x.indisvalid AND x.indpred IS NULL
		      AND x.indnkeyatts >= cardinality(fk.conkey)
		      AND (x.indkey::int2[])[0:cardinality(fk.conkey) - 1] @> fk.conkey
		      AND (x.indkey::int2[])[0:cardinality(fk.conkey) - 1] <@ fk.conkey)
		), top AS (
		  SELECT m.*, t.relpages FROM missing m JOIN pg_class t ON t.oid = m.conrelid
		  ORDER BY t.relpages DESC, m.conname LIMIT $1
		)
		SELECT n.nspname::text, t.relname::text, top.conname::text,
		       array(SELECT a.attname::text FROM unnest(top.conkey) WITH ORDINALITY u(attnum, o)
		             JOIN pg_attribute a ON a.attrelid = top.conrelid AND a.attnum = u.attnum ORDER BY u.o),
		       rn.nspname::text, rt.relname::text, coalesce(pg_relation_size(t.oid), 0), greatest(t.reltuples, 0)::bigint,
		       coalesce(rs.n_tup_upd + rs.n_tup_del, 0), coalesce(cs.seq_scan, 0)
		FROM top JOIN pg_class t ON t.oid = top.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		JOIN pg_class rt ON rt.oid = top.confrelid JOIN pg_namespace rn ON rn.oid = rt.relnamespace
		LEFT JOIN pg_stat_all_tables cs ON cs.relid = t.oid
		LEFT JOIN pg_stat_all_tables rs ON rs.relid = rt.oid
		ORDER BY top.relpages DESC, 3`,
		func(rows pgx.Rows) error {
			x := protocol.ForeignKeyWithoutIndex{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Constraint, &x.Columns, &x.RefSchema, &x.RefTable,
				&x.TableBytes, &x.RowsEstimate, &x.RefWrites, &x.SeqScans); err != nil {
				return err
			}
			a.ForeignKeys = append(a.ForeignKeys, x)
			return nil
		}, maxAdvisorItems)
}

// tablesWithoutPK: no primary key and no unique, non-partial index on NOT
// NULL columns only. Tables that belong to an extension are left out.
func (q insightQueries) tablesWithoutPK(ctx context.Context, a *protocol.AdvisorFacts) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT c.oid, n.nspname, c.relname, c.reltuples, c.relreplident, c.relpages
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND `+userSchemas+`
		    AND NOT EXISTS (SELECT 1 FROM pg_index x WHERE x.indrelid = c.oid AND x.indisprimary)
		    AND NOT EXISTS (
		      SELECT 1 FROM pg_index x WHERE x.indrelid = c.oid AND x.indisunique AND x.indisvalid
		        AND x.indpred IS NULL AND x.indexprs IS NULL
		        AND NOT EXISTS (SELECT 1 FROM unnest(x.indkey::int2[]) k(attnum)
		                        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum WHERE NOT a.attnotnull))
		    AND NOT EXISTS (SELECT 1 FROM pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
		  ORDER BY c.relpages DESC, c.relname LIMIT $1
		)
		SELECT c.nspname::text, c.relname::text, greatest(c.reltuples, 0)::bigint, coalesce(pg_relation_size(c.oid), 0),
		       coalesce(s.n_tup_upd, 0), coalesce(s.n_tup_del, 0),
		       CASE c.relreplident WHEN 'n' THEN 'nothing' WHEN 'f' THEN 'full' WHEN 'i' THEN 'index' ELSE 'default' END,
		       EXISTS (SELECT 1 FROM pg_publication_rel pr WHERE pr.prrelid = c.oid)
		         OR EXISTS (SELECT 1 FROM pg_publication p WHERE p.puballtables)
		FROM c LEFT JOIN pg_stat_all_tables s ON s.relid = c.oid
		ORDER BY c.relpages DESC, 2`,
		func(rows pgx.Rows) error {
			x := protocol.TableWithoutPK{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.RowsEstimate, &x.TableBytes, &x.Updates, &x.Deletes,
				&x.ReplicaIdentity, &x.Published); err != nil {
				return err
			}
			a.NoPrimaryKey = append(a.NoPrimaryKey, x)
			return nil
		}, maxAdvisorItems)
}

// sequenceUses maps each sequence to the columns it fills: owned by the
// column (serial, identity) or named in the column's default.
const sequenceUses = `
	uses AS (
	  SELECT d.objid AS seqid, d.refobjid AS tbl, d.refobjsubid::int2 AS attnum
	  FROM pg_depend d
	  WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
	    AND d.deptype IN ('a', 'i') AND d.refobjsubid > 0
	  UNION
	  SELECT d.refobjid, ad.adrelid, ad.adnum
	  FROM pg_depend d JOIN pg_attrdef ad ON ad.oid = d.objid
	  WHERE d.classid = 'pg_attrdef'::regclass AND d.refclassid = 'pg_class'::regclass
	), owned AS (
	  SELECT s.seqrelid, sn.nspname AS seq_schema, sc.relname AS seq_name, s.seqmax, s.seqstart, s.seqincrement,
	         n.nspname, t.relname, t.oid AS tbl, t.relkind, a.attnum, a.attname, a.atttypid,
	         a.attidentity <> '' AS identity, ps.last_value
	  FROM uses u
	  JOIN pg_sequence s ON s.seqrelid = u.seqid
	  JOIN pg_class sc ON sc.oid = s.seqrelid JOIN pg_namespace sn ON sn.oid = sc.relnamespace
	  JOIN pg_class t ON t.oid = u.tbl JOIN pg_namespace n ON n.oid = t.relnamespace
	  JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = u.attnum AND NOT a.attisdropped
	  LEFT JOIN pg_sequences ps ON ps.schemaname = sn.nspname AND ps.sequencename = sc.relname
	  WHERE s.seqincrement > 0 AND t.relkind IN ('r', 'p') AND ` + userSchemas + `
	)`

// integerKeys: smallint and integer columns filled from a sequence, a
// sequence whose own maximum is below its column's, and single-column
// integer foreign keys referencing such a column, 5% used or more.
func (q insightQueries) integerKeys(ctx context.Context, a *protocol.AdvisorFacts) error {
	return collectRows(ctx, q.conn, `
		WITH `+sequenceUses+`, keys AS (
		  SELECT o.*, CASE o.atttypid WHEN 'int2'::regtype THEN 32767::numeric WHEN 'int4'::regtype THEN 2147483647::numeric
		                              ELSE 9223372036854775807::numeric END AS colmax
		  FROM owned o
		  WHERE o.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype) AND o.last_value IS NOT NULL
		), found AS (
		  SELECT CASE WHEN k.seqmax < k.colmax THEN 'sequence' ELSE 'column' END AS kind,
		         k.nspname, k.relname, k.tbl, k.attname, k.atttypid, k.seq_schema, k.seq_name, k.last_value,
		         least(k.colmax, k.seqmax) AS maxv, ''::text AS refs, k.identity
		  FROM keys k WHERE least(k.colmax, k.seqmax) <= 2147483647
		  UNION ALL
		  SELECT 'foreign_key', cn.nspname, ct.relname, ct.oid, ca.attname, ca.atttypid, k.seq_schema, k.seq_name, k.last_value,
		         CASE ca.atttypid WHEN 'int2'::regtype THEN 32767::numeric ELSE 2147483647::numeric END,
		         k.nspname || '.' || k.relname || '.' || k.attname, false
		  FROM pg_constraint f
		  JOIN keys k ON k.tbl = f.confrelid AND k.attnum = f.confkey[1]
		  JOIN pg_class ct ON ct.oid = f.conrelid JOIN pg_namespace cn ON cn.oid = ct.relnamespace
		  JOIN pg_attribute ca ON ca.attrelid = f.conrelid AND ca.attnum = f.conkey[1]
		  WHERE f.contype = 'f' AND cardinality(f.conkey) = 1 AND ca.atttypid IN ('int2'::regtype, 'int4'::regtype)
		), top AS (
		  SELECT *, (100 * last_value / maxv)::float8 AS pct FROM found
		  WHERE 100 * last_value / maxv >= $2
		  ORDER BY pct DESC, relname LIMIT $1
		)
		SELECT kind, nspname::text, relname::text, attname::text, format_type(atttypid, NULL),
		       seq_schema || '.' || seq_name, last_value, maxv::bigint, pct, refs, identity,
		       coalesce(pg_relation_size(tbl), 0), coalesce(pg_indexes_size(tbl), 0),
		       greatest((SELECT reltuples FROM pg_class WHERE oid = tbl), 0)::bigint
		FROM top ORDER BY pct DESC, relname`,
		func(rows pgx.Rows) error {
			x := protocol.IntegerKey{Database: q.db}
			if err := rows.Scan(&x.Kind, &x.Schema, &x.Table, &x.Column, &x.ColumnType, &x.Sequence, &x.LastValue,
				&x.MaxValue, &x.UsedPct, &x.References, &x.Identity, &x.TableBytes, &x.IndexBytes, &x.RowsEstimate); err != nil {
				return err
			}
			a.IntegerKeys = append(a.IntegerKeys, x)
			return nil
		}, maxIntegerKeys, integerKeyMinPct)
}

// sequencesBehind: the value the sequence hands out next is at or below
// max(column). Only columns that lead a valid B-tree index are probed, so
// each max() is a single index lookup.
func (q insightQueries) sequencesBehind(ctx context.Context, a *protocol.AdvisorFacts) error {
	return collectRows(ctx, q.conn, `
		WITH `+sequenceUses+`, cand AS (
		  SELECT o.* FROM owned o
		  WHERE o.atttypid IN ('int2'::regtype, 'int4'::regtype, 'int8'::regtype)
		    AND EXISTS (SELECT 1 FROM pg_index x JOIN pg_class ic ON ic.oid = x.indexrelid
		                WHERE x.indrelid = o.tbl AND x.indisvalid AND x.indpred IS NULL AND x.indkey[0] = o.attnum
		                  AND ic.relam = (SELECT oid FROM pg_am WHERE amname = 'btree'))
		  ORDER BY o.nspname, o.relname, o.attnum LIMIT $2
		), probed AS (
		  SELECT c.*, (xpath('/row/m/text()', query_to_xml(format('SELECT max(%I)::text AS m FROM %I.%I', c.attname, c.nspname, c.relname),
		                                                    false, true, '')))[1]::text AS maxv
		  FROM cand c
		)
		SELECT p.seq_schema::text, p.seq_name::text, p.nspname::text, p.relname::text, p.attname::text,
		       p.last_value, p.seqstart, p.maxv::bigint
		FROM probed p
		WHERE p.maxv IS NOT NULL
		  AND coalesce(p.last_value::numeric + p.seqincrement, p.seqstart) <= p.maxv::numeric
		ORDER BY p.maxv::numeric - coalesce(p.last_value, p.seqstart) DESC LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.SequenceBehind{Database: q.db}
			if err := rows.Scan(&x.SeqSchema, &x.Sequence, &x.Schema, &x.Table, &x.Column, &x.LastValue, &x.Start, &x.MaxInColumn); err != nil {
				return err
			}
			a.SequencesBehind = append(a.SequencesBehind, x)
			return nil
		}, maxAdvisorItems, maxSequenceProbes)
}

// invalidIndexes: invalid indexes of single tables not being built now
// (on PostgreSQL 12 and newer, which reports builds in progress).
func (q insightQueries) invalidIndexes(ctx context.Context, a *protocol.AdvisorFacts, version int) error {
	building := ""
	if version >= pgVersionProgressCI {
		building = `AND NOT EXISTS (SELECT 1 FROM pg_stat_progress_create_index p WHERE p.relid = x.indrelid)`
	}
	return collectRows(ctx, q.conn, `
		SELECT n.nspname::text, t.relname::text, i.relname::text, coalesce(pg_relation_size(i.oid), 0),
		       left(pg_get_indexdef(i.oid), $2)
		FROM pg_index x JOIN pg_class i ON i.oid = x.indexrelid JOIN pg_class t ON t.oid = x.indrelid
		JOIN pg_namespace n ON n.oid = i.relnamespace
		WHERE NOT x.indisvalid AND i.relkind = 'i' AND `+userSchemas+` `+building+`
		ORDER BY 4 DESC, 3 LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.InvalidIndex{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Index, &x.Bytes, &x.Definition); err != nil {
				return err
			}
			a.InvalidIndexes = append(a.InvalidIndexes, x)
			return nil
		}, maxAdvisorItems, insightsDefChars)
}

// duplicateConstraints: the same primary key/unique rule twice (keeping the
// primary key, else the older one), the same foreign key or CHECK twice, or
// a unique constraint on more columns than one that already makes them
// unique ("redundant").
func (q insightQueries) duplicateConstraints(ctx context.Context, a *protocol.AdvisorFacts) error {
	return collectRows(ctx, q.conn, `
		WITH k AS (
		  SELECT c.oid, c.conname, c.conrelid, c.contype, c.conkey, c.confrelid, c.confkey,
		         (SELECT array_agg(x ORDER BY x) FROM unnest(c.conkey) x) AS sorted_key,
		         pg_get_constraintdef(c.oid) AS def
		  FROM pg_constraint c JOIN pg_class t ON t.oid = c.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		  WHERE c.contype IN ('p', 'u', 'f', 'c') AND c.coninhcount = 0 AND t.relkind IN ('r', 'p') AND `+userSchemas+`
		), pairs AS (
		  SELECT a.oid AS a_id, b.oid AS b_id, a.conrelid, a.contype, a.conname AS a_name, b.conname AS b_name,
		         a.def AS a_def, b.def AS b_def,
		         CASE WHEN a.contype IN ('p', 'u') AND a.sorted_key <> b.sorted_key THEN 'redundant' ELSE 'duplicate' END AS kind
		  FROM k a JOIN k b ON a.conrelid = b.conrelid AND a.oid <> b.oid
		  WHERE (a.contype = 'u' AND b.contype IN ('p', 'u') AND a.sorted_key = b.sorted_key AND (b.contype = 'p' OR a.oid > b.oid))
		     OR (a.contype = 'u' AND b.contype IN ('p', 'u') AND a.sorted_key @> b.sorted_key
		         AND cardinality(a.sorted_key) > cardinality(b.sorted_key))
		     OR (a.contype = 'f' AND b.contype = 'f' AND a.conkey = b.conkey AND a.confrelid = b.confrelid
		         AND a.confkey = b.confkey AND a.oid > b.oid)
		     OR (a.contype = 'c' AND b.contype = 'c' AND a.def = b.def AND a.oid > b.oid)
		), one AS (
		  SELECT DISTINCT ON (a_id) * FROM pairs ORDER BY a_id, kind, b_id
		)
		SELECT n.nspname::text, t.relname::text, one.a_name::text,
		       CASE one.contype WHEN 'p' THEN 'primary key' WHEN 'u' THEN 'unique' WHEN 'f' THEN 'foreign key' ELSE 'check' END,
		       one.kind, one.b_name::text, left(one.a_def, $2), left(one.b_def, $2)
		FROM one JOIN pg_class t ON t.oid = one.conrelid JOIN pg_namespace n ON n.oid = t.relnamespace
		ORDER BY 1, 2, 3 LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.DuplicateConstraint{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Constraint, &x.Type, &x.Kind, &x.CoveredBy, &x.Definition, &x.CoveredDefinition); err != nil {
				return err
			}
			a.DuplicateConstraints = append(a.DuplicateConstraints, x)
			return nil
		}, maxAdvisorItems, insightsDefChars)
}

// timestampColumns: tables with inserts or updates that store "timestamp
// without time zone".
func (q insightQueries) timestampColumns(ctx context.Context, a *protocol.AdvisorFacts) error {
	return collectRows(ctx, q.conn, `
		SELECT n.nspname::text, c.relname::text, array_agg(a.attname::text ORDER BY a.attnum),
		       (s.n_tup_ins + s.n_tup_upd)::bigint
		FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_stat_user_tables s ON s.relid = c.oid
		WHERE a.attnum > 0 AND NOT a.attisdropped AND a.atttypid = 'timestamp'::regtype
		  AND c.relkind = 'r' AND NOT c.relispartition AND `+userSchemas+`
		  AND s.n_tup_ins + s.n_tup_upd > 0
		GROUP BY 1, 2, 4
		ORDER BY 4 DESC, 2 LIMIT $1`,
		func(rows pgx.Rows) error {
			x := protocol.TimestampTable{Database: q.db}
			if err := rows.Scan(&x.Schema, &x.Table, &x.Columns, &x.Writes); err != nil {
				return err
			}
			a.TimestampColumns = append(a.TimestampColumns, x)
			return nil
		}, maxAdvisorItems)
}

// largeTables: tables of at least a million rows or 1 GB, with their
// writes, autovacuum runs and autovacuum settings, and their first time
// column.
func (q insightQueries) largeTables(ctx context.Context, a *protocol.AdvisorFacts, statsSince *time.Time) error {
	return collectRows(ctx, q.conn, `
		WITH c AS (
		  SELECT c.oid, n.nspname, c.relname, c.relispartition, c.reltuples, c.relpages, c.reloptions
		  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE c.relkind = 'r' AND `+userSchemas+` AND (c.reltuples >= $2 OR c.relpages >= $3)
		  ORDER BY c.relpages DESC LIMIT $1
		)
		SELECT c.nspname::text, c.relname::text, coalesce(pg_total_relation_size(c.oid), 0), coalesce(pg_relation_size(c.oid), 0),
		       greatest(c.reltuples, 0)::bigint, c.relispartition,
		       coalesce(s.n_tup_ins, 0), coalesce(s.n_tup_upd, 0), coalesce(s.n_tup_del, 0), coalesce(s.n_dead_tup, 0),
		       coalesce(s.autovacuum_count, 0), s.last_autovacuum,
		       coalesce((SELECT array_agg(o) FROM unnest(c.reloptions) o WHERE o LIKE 'autovacuum%'), '{}'),
		       coalesce(tc.attname, ''), coalesce(tc.indexed, false)
		FROM c LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
		LEFT JOIN LATERAL (
		  SELECT a.attname::text,
		         EXISTS (SELECT 1 FROM pg_index x WHERE x.indrelid = c.oid AND x.indisvalid AND x.indkey[0] = a.attnum) AS indexed
		  FROM pg_attribute a
		  WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
		    AND a.atttypid IN ('timestamptz'::regtype, 'timestamp'::regtype, 'date'::regtype)
		  ORDER BY 2 DESC, a.attnum LIMIT 1
		) tc ON true
		ORDER BY 3 DESC, 2`,
		func(rows pgx.Rows) error {
			x := protocol.LargeTable{Database: q.db, StatsSince: statsSince}
			var opts []string
			if err := rows.Scan(&x.Schema, &x.Table, &x.TotalBytes, &x.TableBytes, &x.RowsEstimate, &x.Partitioned,
				&x.Inserts, &x.Updates, &x.Deletes, &x.DeadRows, &x.AutovacuumCount, &x.LastAutovacuum,
				&opts, &x.TimeColumn, &x.TimeIndexed); err != nil {
				return err
			}
			if len(opts) > 0 {
				x.Options = map[string]string{}
				for _, o := range opts {
					if k, v, ok := strings.Cut(o, "="); ok {
						x.Options[k] = v
					}
				}
			}
			a.LargeTables = append(a.LargeTables, x)
			return nil
		}, advisorLargeTables, largeTableMinRows, largeTableMinPages)
}

// sortAndCapAdvisor merges the per-database advisor lists.
func sortAndCapAdvisor(ins *protocol.Insights) {
	a := ins.Advisor
	if a == nil {
		return
	}
	capSort(&a.ForeignKeys, func(x, y protocol.ForeignKeyWithoutIndex) int { return cmp.Compare(y.TableBytes, x.TableBytes) })
	capSort(&a.NoPrimaryKey, func(x, y protocol.TableWithoutPK) int { return cmp.Compare(y.TableBytes, x.TableBytes) })
	slicesSortStable(&a.IntegerKeys, func(x, y protocol.IntegerKey) int { return cmp.Compare(y.UsedPct, x.UsedPct) })
	if len(a.IntegerKeys) > maxIntegerKeys {
		a.IntegerKeys = a.IntegerKeys[:maxIntegerKeys]
	}
	capSort(&a.SequencesBehind, func(x, y protocol.SequenceBehind) int {
		return cmp.Compare(x.Database+x.Sequence, y.Database+y.Sequence)
	})
	capSort(&a.InvalidIndexes, func(x, y protocol.InvalidIndex) int { return cmp.Compare(y.Bytes, x.Bytes) })
	capSort(&a.DuplicateConstraints, func(x, y protocol.DuplicateConstraint) int {
		return cmp.Compare(x.Database+"."+x.Schema+"."+x.Table, y.Database+"."+y.Schema+"."+y.Table)
	})
	capSort(&a.TimestampColumns, func(x, y protocol.TimestampTable) int { return cmp.Compare(y.Writes, x.Writes) })
	slicesSortStable(&a.LargeTables, func(x, y protocol.LargeTable) int { return cmp.Compare(y.TotalBytes, x.TotalBytes) })
	if len(a.LargeTables) > advisorLargeTables {
		a.LargeTables = a.LargeTables[:advisorLargeTables]
	}
}

func slicesSortStable[T any](s *[]T, f func(a, b T) int) { slices.SortStableFunc(*s, f) }
