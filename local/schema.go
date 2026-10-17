package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/preview"
)

// Copying the schema (no rows) into the temporary database: with pg_dump
// --schema-only when one new enough for the server is installed, else
// from the catalogs. pg_dump reads with short lock waits
// (--lock-wait-timeout), so it gives up rather than queue behind a
// migration; the catalog path takes no table locks at all. Ownership,
// privileges, publications, subscriptions and event triggers are left
// out: the copy is the connection's role's own.

const maxDump = 64 << 20

// copySchema fills scratch with the schema of d's database. It returns how
// (for people) and the objects that couldn't be created there.
func (d *DB) copySchema(ctx context.Context, info serverInfo, scratch *pgx.Conn, progress func(string)) (string, []string, error) {
	if path, ok := lookPgDump(info.version / 10000); ok {
		progress("reading the schema with " + path)
		dump, err := d.dumpSchema(ctx, path)
		if err == nil {
			stmts, err := preview.Split(dump)
			if err == nil {
				var sqls []string
				for _, s := range stmts {
					if !s.Meta && !eventTriggerRE.MatchString(preview.Normalize(s.Text)) {
						sqls = append(sqls, s.Text)
					}
				}
				failed := execSchema(ctx, scratch, sqls)
				return fmt.Sprintf("pg_dump, %d statements", len(sqls)), failed, nil
			}
		}
		progress("pg_dump didn't work (" + firstLine(err.Error()) + "); copying the schema from the catalogs")
	}
	if info.version < 110000 {
		return "", nil, errors.New("copying a schema from the catalogs needs PostgreSQL 11 or later (or pg_dump installed here)")
	}
	ddl, err := catalogDDL(ctx, d, info)
	if err != nil {
		return "", nil, err
	}
	failed := execSchema(ctx, scratch, ddl)
	return fmt.Sprintf("from the catalogs, %d objects", len(ddl)), failed, nil
}

var eventTriggerRE = regexp.MustCompile(`(?i)^(CREATE|ALTER)\s+EVENT\s+TRIGGER\b`)

// pgDumpPaths are where PostgreSQL's tools usually are, besides PATH.
var pgDumpPaths = []string{
	"/usr/lib/postgresql/*/bin/pg_dump", "/usr/pgsql-*/bin/pg_dump", "/opt/homebrew/opt/postgresql@*/bin/pg_dump",
	"/opt/homebrew/opt/libpq/bin/pg_dump", "/usr/local/opt/postgresql@*/bin/pg_dump", "/usr/local/opt/libpq/bin/pg_dump",
	"/Applications/Postgres.app/Contents/Versions/*/bin/pg_dump", "/usr/local/pgsql/bin/pg_dump",
}

// lookPgDump is findPgDump (tests replace it).
var lookPgDump = findPgDump

var pgDumpVersionRE = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)`)

// findPgDump finds the newest pg_dump that can read a server of this
// major version (pg_dump refuses newer servers).
func findPgDump(serverMajor int) (string, bool) {
	var candidates []string
	if p, err := exec.LookPath("pg_dump"); err == nil {
		candidates = append(candidates, p)
	}
	for _, g := range pgDumpPaths {
		m, _ := filepath.Glob(g)
		candidates = append(candidates, m...)
	}
	best, bestMajor := "", 0
	for _, p := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		out, err := exec.CommandContext(ctx, p, "--version").Output()
		cancel()
		if err != nil {
			continue
		}
		m := pgDumpVersionRE.FindSubmatch(out)
		if m == nil {
			continue
		}
		major, _ := strconv.Atoi(string(m[1]))
		if major >= serverMajor && major > bestMajor {
			best, bestMajor = p, major
		}
	}
	return best, best != ""
}

// dumpSchema runs pg_dump --schema-only. The password goes in its
// environment, never on its command line.
func (d *DB) dumpSchema(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "--schema-only", "--no-owner", "--no-privileges", "--no-publications", "--no-subscriptions",
		"--no-security-labels", "--no-tablespaces", "--lock-wait-timeout=5000", "--dbname="+d.url)
	cmd.Env = append(os.Environ(), "PGAPPNAME="+previewAppName)
	if d.conn.Password != "" {
		cmd.Env = append(cmd.Env, "PGPASSWORD="+d.conn.Password)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	dump, rerr := io.ReadAll(io.LimitReader(out, maxDump+1))
	if len(dump) > maxDump {
		_ = cmd.Process.Kill()
	}
	werr := cmd.Wait()
	switch {
	case len(dump) > maxDump:
		return "", errors.New("the schema is over 64 MB")
	case werr != nil:
		msg := strings.TrimSpace(strings.TrimPrefix(firstLine(stderr.String()), "pg_dump: error: "))
		if msg == "" {
			msg = werr.Error()
		}
		return "", errors.New(msg)
	case rerr != nil:
		return "", rerr
	}
	return string(dump), nil
}

// execSchema runs the schema's statements on the temporary database, in
// batches (one round trip each), retrying failed ones one by one until no
// more succeed (an object may need one that comes later). It returns what
// still failed: "CREATE INDEX ...: error".
func execSchema(ctx context.Context, conn *pgx.Conn, stmts []string) []string {
	_, _ = conn.Exec(ctx, "SET check_function_bodies = off")
	var pending []string
	const batch = 100
	for i := 0; i < len(stmts); i += batch {
		b := stmts[i:min(i+batch, len(stmts))]
		if _, err := conn.Exec(ctx, strings.Join(b, ";\n")); err == nil {
			continue
		}
		pending = append(pending, b...)
	}
	errs := map[string]error{}
	for round := 0; round < 6 && len(pending) > 0; round++ {
		var next []string
		for _, s := range pending {
			if _, err := conn.Exec(ctx, s); err != nil && !harmless(s, err) {
				next = append(next, s)
				errs[s] = err
			}
			if ctx.Err() != nil {
				break
			}
		}
		if len(next) == len(pending) {
			break
		}
		pending = next
	}
	var failed []string
	for _, s := range pending {
		failed = append(failed, preview.Shorten(s, 60)+": "+firstLine(errs[s].Error()))
	}
	return failed
}

// harmless: errors that don't make the copy differ (an object the new
// database already has, a comment the role may not set).
func harmless(stmt string, err error) bool {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return false
	}
	if slices.Contains([]string{"42P06", "42P07", "42710", "42723"}, pg.Code) { // already exists
		return true
	}
	return strings.HasPrefix(strings.ToUpper(preview.Normalize(stmt)), "COMMENT ON")
}

// catalogDDL builds the schema's DDL from production's catalogs (read-
// only, no table locks), quoting with format(). Order: schemas,
// extensions, types, sequences, functions, tables and partitions,
// constraints, views, indexes, triggers, row security.
func catalogDDL(ctx context.Context, d *DB, info serverInfo) ([]string, error) {
	conn, err := d.target().Connect(ctx, d.inspectTarget().MaintenanceDB())
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	const user = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_(toast|temp)'`
	notExt := func(class, col string) string {
		return fmt.Sprintf(`NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend dep WHERE dep.classid = '%s'::regclass AND dep.objid = %s AND dep.deptype = 'e')`, class, col)
	}
	generated := "false"
	if info.version >= 120000 {
		generated = "a.attgenerated = 's'"
	}
	triggerParent := "true"
	if info.version >= 130000 {
		triggerParent = "t.tgparentid = 0"
	}
	queries := []string{
		`SELECT format('CREATE SCHEMA IF NOT EXISTS %I', n.nspname) FROM pg_catalog.pg_namespace n WHERE ` + user + ` AND ` + notExt("pg_catalog.pg_namespace", "n.oid") + ` ORDER BY 1`,
		`SELECT format('CREATE EXTENSION IF NOT EXISTS %I WITH SCHEMA %I', e.extname, n.nspname) FROM pg_catalog.pg_extension e
			JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace WHERE e.extname <> 'plpgsql' ORDER BY 1`,
		`SELECT format('CREATE TYPE %I.%I AS ENUM (%s)', n.nspname, t.typname, string_agg(quote_literal(e.enumlabel), ', ' ORDER BY e.enumsortorder))
			FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace JOIN pg_catalog.pg_enum e ON e.enumtypid = t.oid
			WHERE ` + user + ` AND ` + notExt("pg_catalog.pg_type", "t.oid") + ` GROUP BY n.nspname, t.typname`,
		`SELECT format('CREATE DOMAIN %I.%I AS %s', n.nspname, t.typname, pg_catalog.format_type(t.typbasetype, t.typtypmod))
			|| coalesce(' DEFAULT ' || t.typdefault, '') || CASE WHEN t.typnotnull THEN ' NOT NULL' ELSE '' END
			|| coalesce((SELECT string_agg(format(' CONSTRAINT %I %s', c.conname, pg_catalog.pg_get_constraintdef(c.oid)), '') FROM pg_catalog.pg_constraint c WHERE c.contypid = t.oid), '')
			FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
			WHERE t.typtype = 'd' AND ` + user + ` AND ` + notExt("pg_catalog.pg_type", "t.oid"),
		`SELECT format('CREATE TYPE %I.%I AS (%s)', n.nspname, t.typname,
				(SELECT string_agg(format('%I %s', a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)), ', ' ORDER BY a.attnum)
				 FROM pg_catalog.pg_attribute a WHERE a.attrelid = t.typrelid AND a.attnum > 0 AND NOT a.attisdropped))
			FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace JOIN pg_catalog.pg_class c ON c.oid = t.typrelid
			WHERE t.typtype = 'c' AND c.relkind = 'c' AND ` + user + ` AND ` + notExt("pg_catalog.pg_type", "t.oid"),
		`SELECT format('CREATE SEQUENCE IF NOT EXISTS %I.%I', n.nspname, c.relname) FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind = 'S' AND ` + user + ` AND ` + notExt("pg_catalog.pg_class", "c.oid") + `
			  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend dep WHERE dep.classid = 'pg_catalog.pg_class'::regclass AND dep.objid = c.oid AND dep.deptype = 'i')`,
		`SELECT pg_catalog.pg_get_functiondef(p.oid) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
			WHERE p.prokind IN ('f', 'p') AND ` + user + ` AND ` + notExt("pg_catalog.pg_proc", "p.oid"),
		`SELECT format('CREATE %sTABLE %I.%I (%s)%s', CASE c.relpersistence WHEN 'u' THEN 'UNLOGGED ' ELSE '' END, n.nspname, c.relname,
				coalesce((SELECT string_agg(format('%I %s', a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod)) ||
					CASE WHEN a.attidentity = 'a' THEN ' GENERATED ALWAYS AS IDENTITY' WHEN a.attidentity = 'd' THEN ' GENERATED BY DEFAULT AS IDENTITY'
					     WHEN ` + generated + ` THEN ' GENERATED ALWAYS AS (' || pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) || ') STORED'
					     WHEN ad.adbin IS NOT NULL THEN ' DEFAULT ' || pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) ELSE '' END ||
					CASE WHEN a.attnotnull THEN ' NOT NULL' ELSE '' END, ', ' ORDER BY a.attnum)
				 FROM pg_catalog.pg_attribute a LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
				 WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped), ''),
				CASE WHEN c.relkind = 'p' THEN ' PARTITION BY ' || pg_catalog.pg_get_partkeydef(c.oid) ELSE '' END)
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND ` + user + ` AND ` + notExt("pg_catalog.pg_class", "c.oid"),
		`SELECT format('CREATE TABLE %I.%I PARTITION OF %I.%I %s%s', n.nspname, c.relname, pn.nspname, p.relname, pg_catalog.pg_get_expr(c.relpartbound, c.oid),
				CASE WHEN c.relkind = 'p' THEN ' PARTITION BY ' || pg_catalog.pg_get_partkeydef(c.oid) ELSE '' END)
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			JOIN pg_catalog.pg_inherits i ON i.inhrelid = c.oid JOIN pg_catalog.pg_class p ON p.oid = i.inhparent JOIN pg_catalog.pg_namespace pn ON pn.oid = p.relnamespace
			WHERE c.relispartition AND c.relkind IN ('r', 'p') AND ` + user + ` ORDER BY c.oid`,
		`SELECT format('ALTER TABLE %I.%I ADD CONSTRAINT %I %s', n.nspname, c.relname, con.conname, pg_catalog.pg_get_constraintdef(con.oid))
			FROM pg_catalog.pg_constraint con JOIN pg_catalog.pg_class c ON c.oid = con.conrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE con.contype IN ('p', 'u', 'x', 'c', 'f') AND con.conparentid = 0 AND con.conislocal AND ` + user + ` AND ` + notExt("pg_catalog.pg_class", "c.oid") + `
			ORDER BY CASE con.contype WHEN 'p' THEN 0 WHEN 'u' THEN 1 WHEN 'x' THEN 2 WHEN 'c' THEN 3 ELSE 4 END, con.oid`,
		`SELECT format('CREATE %sVIEW %I.%I AS %s%s', CASE c.relkind WHEN 'm' THEN 'MATERIALIZED ' ELSE '' END, n.nspname, c.relname,
				rtrim(pg_catalog.pg_get_viewdef(c.oid), '; '), CASE c.relkind WHEN 'm' THEN ' WITH NO DATA' ELSE '' END)
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE c.relkind IN ('v', 'm') AND ` + user + ` AND ` + notExt("pg_catalog.pg_class", "c.oid") + ` ORDER BY c.oid`,
		`SELECT pg_catalog.pg_get_indexdef(i.indexrelid) FROM pg_catalog.pg_index i
			JOIN pg_catalog.pg_class t ON t.oid = i.indrelid JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
			WHERE t.relkind IN ('r', 'p', 'm') AND ` + user + ` AND ` + notExt("pg_catalog.pg_class", "t.oid") + `
			  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint con WHERE con.conindid = i.indexrelid AND con.contype IN ('p', 'u', 'x'))
			  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits h WHERE h.inhrelid = i.indexrelid)`,
		`SELECT pg_catalog.pg_get_triggerdef(t.oid) FROM pg_catalog.pg_trigger t
			JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE NOT t.tgisinternal AND ` + triggerParent + ` AND ` + user,
		`SELECT format('ALTER TABLE %I.%I ENABLE ROW LEVEL SECURITY', n.nspname, c.relname) FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.relrowsecurity AND ` + user,
		`SELECT format('CREATE POLICY %I ON %I.%I AS %s FOR %s TO %s', p.policyname, p.schemaname, p.tablename, p.permissive, p.cmd,
				(SELECT string_agg(CASE WHEN r = 'public' THEN 'PUBLIC' ELSE quote_ident(r) END, ', ') FROM unnest(p.roles) r))
				|| coalesce(' USING (' || p.qual || ')', '') || coalesce(' WITH CHECK (' || p.with_check || ')', '')
			FROM pg_catalog.pg_policies p`,
	}
	var ddl []string
	err = inReadOnly(ctx, conn, func(tx pgx.Tx) error {
		for _, q := range queries {
			rows, err := tx.Query(ctx, q)
			if err != nil {
				return err
			}
			got, err := pgx.CollectRows(rows, pgx.RowTo[*string])
			if err != nil {
				return err
			}
			for _, s := range got {
				if s != nil && *s != "" {
					ddl = append(ddl, *s)
				}
			}
		}
		return nil
	})
	return ddl, err
}
