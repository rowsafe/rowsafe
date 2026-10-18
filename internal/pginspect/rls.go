package pginspect

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Row-level security (protocol/rls.go): which tables the roles an API
// connects as may use without row-level security, and which policies let
// every row through. Catalog queries only: no row is read (but Supabase
// Storage's bucket names and public flags), and a policy's expression is
// only compared with "true" here, never sent.

// Caps of an RLSDatabase.
const (
	maxRLSExposed = 100
	maxRLSOpen    = 100
	maxRLSSlow    = 50
	maxRLSBuckets = 50
	maxAPIRoles   = 10
)

// RLSSlowRows is the size from which a policy's unindexed column matters.
const RLSSlowRows = 10000

// rlsSkipSchemas are PostgreSQL's and Supabase's own schemas: their tables
// are the platform's, not the app's.
var rlsSkipSchemas = []string{"pg_catalog", "information_schema", "pg_toast", "auth", "storage", "realtime", "_realtime",
	"extensions", "graphql", "graphql_public", "vault", "pgsodium", "pgsodium_masks", "net", "cron", "pgbouncer",
	"supabase_functions", "supabase_migrations", "_analytics", "pgtle", "tiger", "topology"}

// apiRoleNames are the roles APIs connect as for their users by default
// (Supabase's anon and authenticated, PostgREST's tutorial web_anon).
var apiRoleNames = []string{"anon", "authenticated", "web_anon"}

// ReadRLS reads the row-level security facts of the database conn is
// connected to; nil when it doesn't look like it uses row-level security
// (no API roles, no table with it on, no policy).
func ReadRLS(ctx context.Context, conn *pgx.Conn) (*protocol.RLSDatabase, error) {
	d := &protocol.RLSDatabase{Database: conn.Config().Database}
	var used bool
	err := conn.QueryRow(ctx, `SELECT current_database(),
		EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth') AND EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'storage'),
		EXISTS (SELECT 1 FROM pg_policy) OR EXISTS (SELECT 1 FROM pg_class WHERE relrowsecurity),
		coalesce((SELECT array_agg(rolname::text ORDER BY rolname) FROM (
			SELECT r.rolname FROM pg_roles r
			WHERE NOT r.rolsuper AND NOT r.rolbypassrls
			  AND (r.rolname = ANY($1) OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid = m.member
			                                      WHERE m.roleid = r.oid AND a.rolname = 'authenticator'))
			ORDER BY r.rolname LIMIT $2) x), '{}')`,
		apiRoleNames, maxAPIRoles).Scan(&d.Database, &d.Supabase, &used, &d.APIRoles)
	if err != nil {
		return nil, err
	}
	if len(d.APIRoles) == 0 && !used {
		return nil, nil
	}
	if len(d.APIRoles) > 0 {
		if err := readExposed(ctx, conn, d); err != nil {
			return nil, fmt.Errorf("tables: %w", err)
		}
		if err := readOpenPolicies(ctx, conn, d); err != nil {
			return nil, fmt.Errorf("policies: %w", err)
		}
	}
	if err := readSlowPolicies(ctx, conn, d); err != nil {
		return nil, fmt.Errorf("policy columns: %w", err)
	}
	if d.Supabase {
		if err := readPublicBuckets(ctx, conn, d); err != nil {
			return nil, fmt.Errorf("storage buckets: %w", err)
		}
	}
	return d, nil
}

// readExposed lists the tables API roles may use that row-level security
// doesn't protect, or that it blocks entirely (on, no policies).
func readExposed(ctx context.Context, conn *pgx.Conn, d *protocol.RLSDatabase) error {
	rows, err := conn.Query(ctx, `
		SELECT n.nspname::text, c.relname::text, c.relrowsecurity, (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)::int,
		       greatest(c.reltuples, 0)::bigint, a.role,
		       array_remove(ARRAY[
		         CASE WHEN has_table_privilege(a.role, c.oid, 'SELECT') THEN 'select' END,
		         CASE WHEN has_table_privilege(a.role, c.oid, 'INSERT') THEN 'insert' END,
		         CASE WHEN has_table_privilege(a.role, c.oid, 'UPDATE') THEN 'update' END,
		         CASE WHEN has_table_privilege(a.role, c.oid, 'DELETE') THEN 'delete' END], NULL)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		CROSS JOIN unnest($1::text[]) AS a(role)
		WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
		  AND n.nspname <> ALL($2) AND n.nspname NOT LIKE 'pg\_%'
		  AND (NOT c.relrowsecurity OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid))
		  AND has_schema_privilege(a.role, n.oid, 'USAGE')
		  AND has_table_privilege(a.role, c.oid, 'SELECT, INSERT, UPDATE, DELETE')
		ORDER BY c.relrowsecurity, n.nspname, c.relname, a.role
		LIMIT $3`, d.APIRoles, rlsSkipSchemas, (maxRLSExposed+1)*maxAPIRoles)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var schema, name, role string
		var rls bool
		var policies int
		var n int64
		var privs []string
		if err := rows.Scan(&schema, &name, &rls, &policies, &n, &role, &privs); err != nil {
			return err
		}
		last := len(d.Exposed) - 1
		if last < 0 || d.Exposed[last].Schema != schema || d.Exposed[last].Name != name {
			if len(d.Exposed) == maxRLSExposed {
				d.Truncated = true
				break
			}
			d.Exposed = append(d.Exposed, protocol.RLSTable{Schema: schema, Name: name, RLS: rls, Policies: policies, Rows: n})
			last++
		}
		d.Exposed[last].Access = append(d.Exposed[last].Access, protocol.RLSAccess{Role: role, Privileges: privs})
	}
	return rows.Err()
}

// readOpenPolicies lists the policies for everyone or an API role whose
// USING or WITH CHECK is always true.
func readOpenPolicies(ctx context.Context, conn *pgx.Conn, d *protocol.RLSDatabase) error {
	rows, err := conn.Query(ctx, `
		WITH p AS (
		  SELECT n.nspname::text AS schema, c.relname::text AS tbl, p.polname::text AS name, p.polcmd::text AS cmd, c.relrowsecurity AS rls,
		         coalesce((SELECT array_agg(CASE WHEN r = 0 THEN 'public' ELSE pg_get_userbyid(r)::text END ORDER BY 1) FROM unnest(p.polroles) r), '{}') AS roles,
		         p.polqual IS NOT NULL AND regexp_replace(lower(pg_get_expr(p.polqual, p.polrelid)), '[\s()]', '', 'g') IN ('true', '1=1') AS using_true,
		         p.polwithcheck IS NOT NULL AND regexp_replace(lower(pg_get_expr(p.polwithcheck, p.polrelid)), '[\s()]', '', 'g') IN ('true', '1=1') AS check_true
		  FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE p.polpermissive AND n.nspname <> ALL($1) AND n.nspname NOT LIKE 'pg\_%')
		SELECT schema, tbl, name, cmd, rls, roles, using_true, check_true FROM p
		WHERE (using_true OR check_true) AND roles && ($2::text[] || '{public}'::text[])
		ORDER BY schema, tbl, name
		LIMIT $3`, rlsSkipSchemas, d.APIRoles, maxRLSOpen+1)
	if err != nil {
		return err
	}
	d.OpenPolicies, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (protocol.RLSPolicy, error) {
		var p protocol.RLSPolicy
		var cmd string
		err := r.Scan(&p.Schema, &p.Table, &p.Name, &cmd, &p.TableRLS, &p.Roles, &p.Using, &p.Check)
		p.Command = policyCommand(cmd)
		return p, err
	})
	if len(d.OpenPolicies) > maxRLSOpen {
		d.OpenPolicies, d.Truncated = d.OpenPolicies[:maxRLSOpen], true
	}
	return err
}

func policyCommand(c string) string {
	switch c {
	case "r":
		return "select"
	case "a":
		return "insert"
	case "w":
		return "update"
	case "d":
		return "delete"
	}
	return "all"
}

// readSlowPolicies lists the columns the policies of large tables filter
// by that no valid index starts with (PostgreSQL records the columns a
// policy's expressions use in pg_depend).
func readSlowPolicies(ctx context.Context, conn *pgx.Conn, d *protocol.RLSDatabase) error {
	rows, err := conn.Query(ctx, `
		SELECT n.nspname::text, c.relname::text, a.attname::text, array_agg(DISTINCT p.polname::text ORDER BY p.polname::text),
		       greatest(c.reltuples, 0)::bigint
		FROM pg_policy p
		JOIN pg_depend dep ON dep.classid = 'pg_policy'::regclass AND dep.objid = p.oid
		     AND dep.refclassid = 'pg_class'::regclass AND dep.refobjid = p.polrelid AND dep.refobjsubid > 0
		JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
		JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = dep.refobjsubid AND NOT a.attisdropped
		WHERE c.relrowsecurity AND c.relkind = 'r' AND c.reltuples >= $2
		  AND n.nspname <> ALL($1) AND n.nspname NOT LIKE 'pg\_%'
		  AND NOT EXISTS (SELECT 1 FROM pg_index x WHERE x.indrelid = c.oid AND x.indisvalid AND x.indpred IS NULL AND x.indkey[0] = a.attnum)
		GROUP BY n.nspname, c.relname, a.attname, c.reltuples
		ORDER BY c.reltuples DESC, 1, 2, 3
		LIMIT $3`, rlsSkipSchemas, RLSSlowRows, maxRLSSlow+1)
	if err != nil {
		return err
	}
	d.SlowPolicies, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (protocol.RLSSlowColumn, error) {
		var s protocol.RLSSlowColumn
		return s, r.Scan(&s.Schema, &s.Table, &s.Column, &s.Policies, &s.Rows)
	})
	if len(d.SlowPolicies) > maxRLSSlow {
		d.SlowPolicies, d.Truncated = d.SlowPolicies[:maxRLSSlow], true
	}
	return err
}

// readPublicBuckets lists Supabase Storage's public buckets (names only).
func readPublicBuckets(ctx context.Context, conn *pgx.Conn, d *protocol.RLSDatabase) error {
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('storage.buckets') IS NOT NULL
		AND EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('storage.buckets') AND attname = 'public' AND NOT attisdropped)
		AND has_table_privilege(to_regclass('storage.buckets'), 'SELECT')`).Scan(&ok); err != nil || !ok {
		return err
	}
	rows, err := conn.Query(ctx, `SELECT name::text FROM storage.buckets WHERE public ORDER BY name LIMIT $1`, maxRLSBuckets+1)
	if err != nil {
		return err
	}
	d.PublicBuckets, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if len(d.PublicBuckets) > maxRLSBuckets {
		d.PublicBuckets, d.Truncated = d.PublicBuckets[:maxRLSBuckets], true
	}
	return err
}
