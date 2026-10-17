package local

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Migration previews without an account. Production is never written to.
// Best effort, in order:
//
//  1. When the connection's role may create databases, Rowsafe makes a
//     temporary database on the same server, copies the schema into it
//     (no rows: pg_dump --schema-only, or from the catalogs), runs the
//     migration there the way the agent runs it on a copy (one
//     transaction, a second session watching its locks), and drops the
//     database. A migration that reaches beyond its database (roles,
//     other databases, server settings, signals to other sessions) never
//     runs there: it would act on the real server.
//  2. Otherwise (or with Static) the SQL is read statement by statement
//     against production's catalog (preview.Static).
//
// Either way, table sizes and row counts come from production's
// statistics (read-only, lock-free), so the times are estimates.

// PreviewOptions refine a preview.
type PreviewOptions struct {
	// Static only reads the SQL against the catalog: no temporary database.
	Static bool
	// Timeout caps the migration's run on the temporary database (default
	// 2 minutes; the schema copy has no rows, so most finish in moments).
	Timeout time.Duration
	// Progress, when set, hears what happens, for people.
	Progress func(string)
}

const (
	maxPreviewSQL     = 1 << 20
	defaultPreviewRun = 2 * time.Minute
	scratchPrefix     = "rowsafe_preview_"
	previewAppName    = "rowsafe-preview"
)

// serverInfo is what a preview needs to know about the server.
type serverInfo struct {
	version          int
	user, db         string
	canCreateDB      bool
	inRecovery       bool
	encoding         string
	collate, ctype   string
	searchPath       []string
	superuser        bool
	cannotCreateNote string
}

// Preview checks the migration sql without changing this database.
func (d *DB) Preview(ctx context.Context, sql string, o PreviewOptions) (*protocol.PreviewResult, error) {
	if d.my != nil {
		return nil, fmt.Errorf("checking a migration works on PostgreSQL for now, not %s", d.EngineName())
	}
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	switch {
	case strings.TrimSpace(sql) == "":
		return nil, errors.New("the SQL is empty")
	case len(sql) > maxPreviewSQL:
		return nil, fmt.Errorf("the SQL is over %d kB; preview one migration at a time", maxPreviewSQL>>10)
	}
	stmts, err := preview.Split(sql)
	if err != nil {
		res := &protocol.PreviewResult{Verdict: protocol.PreviewFailed, DB: d.Name(), Checked: protocol.PreviewCheckedStatic, Statements: []protocol.PreviewStatement{},
			Error: &protocol.PreviewError{Message: "Rowsafe can't read the SQL: " + err.Error()}}
		res.Summary = res.Error.Message + ". Nothing was run."
		return res, nil
	}
	if !slices.ContainsFunc(stmts, func(s preview.Stmt) bool { return !s.Meta }) {
		return nil, errors.New("the SQL has no statements")
	}
	conn, err := d.target().Connect(ctx, d.inspectTarget().MaintenanceDB())
	if err != nil {
		return nil, d.connectError(err)
	}
	defer conn.Close(context.WithoutCancel(ctx))
	info, err := readServerInfo(ctx, conn)
	if err != nil {
		return nil, d.connectError(err)
	}
	cat, err := readCatalog(ctx, conn, info)
	if err != nil {
		return nil, fmt.Errorf("reading the tables of %s: %w", d.Name(), err)
	}
	cat.DB = d.Name()
	cat.ColumnType = func(table, column string) string { return columnType(ctx, conn, table, column) }

	note := ""
	if !o.Static {
		why := scratchBlocked(info, stmts)
		if why == "" {
			res, fallback := d.previewOnScratch(ctx, conn, info, stmts, cat, o, progress)
			if res != nil {
				return res, nil
			}
			why = fallback
		}
		note = "Rowsafe checked the SQL instead of running it because " + why + "."
		progress("checking the SQL without running it: " + why)
	} else {
		progress("checking the SQL without running it")
	}
	res := preview.Static(stmts, cat)
	res.CheckNote = note
	return res, nil
}

func (d *DB) target() pginspect.Target {
	return pginspect.Target{Conn: d.conn, AppName: previewAppName}
}

// inReadOnly runs fn in a read-only transaction with short timeouts (it
// works through a connection pooler too: the settings are LOCAL).
func inReadOnly(ctx context.Context, conn *pgx.Conn, fn func(pgx.Tx) error) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // read-only
	if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = '20s'; SET LOCAL lock_timeout = '1s'"); err != nil {
		return err
	}
	return fn(tx)
}

func readServerInfo(ctx context.Context, conn *pgx.Conn) (serverInfo, error) {
	var s serverInfo
	err := inReadOnly(ctx, conn, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_setting('server_version_num')::int, current_user, current_database(),
			coalesce((SELECT rolsuper OR rolcreatedb FROM pg_catalog.pg_roles WHERE rolname = current_user), false),
			coalesce((SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user), false),
			pg_catalog.pg_is_in_recovery(), pg_catalog.pg_encoding_to_char(d.encoding), d.datcollate::text, d.datctype::text,
			pg_catalog.current_schemas(false)::text[]
			FROM pg_catalog.pg_database d WHERE d.datname = current_database()`).
			Scan(&s.version, &s.user, &s.db, &s.canCreateDB, &s.superuser, &s.inRecovery, &s.encoding, &s.collate, &s.ctype, &s.searchPath)
	})
	return s, err
}

// readCatalog lists production's tables, materialized views and indexes
// with their estimated sizes and rows: pg_class statistics, which take no
// lock (pg_table_size would wait behind a migration's lock).
func readCatalog(ctx context.Context, conn *pgx.Conn, info serverInfo) (*preview.Catalog, error) {
	cat := &preview.Catalog{VersionNum: info.version, SearchPath: info.searchPath, Relations: map[string]preview.Relation{}}
	var unknown []string // tables never vacuumed or analyzed: no statistics
	children := map[string][]string{}
	err := inReadOnly(ctx, conn, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT n.nspname || '.' || c.relname, c.relkind::text, coalesce(tn.nspname || '.' || tc.relname, ''),
			(c.relpages::bigint + coalesce(t.relpages, 0)::bigint) * current_setting('block_size')::bigint, greatest(c.reltuples, 0)::bigint,
			c.relpages = 0 AND c.reltuples <= 0
			FROM pg_catalog.pg_class c
			JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			LEFT JOIN pg_catalog.pg_class t ON t.oid = c.reltoastrelid
			LEFT JOIN pg_catalog.pg_index ix ON ix.indexrelid = c.oid
			LEFT JOIN pg_catalog.pg_class tc ON tc.oid = ix.indrelid
			LEFT JOIN pg_catalog.pg_namespace tn ON tn.oid = tc.relnamespace
			WHERE c.relkind IN ('r', 'p', 'm', 'i') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
			  AND n.nspname !~ '^pg_(toast|temp)'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r preview.Relation
			var kind string
			var noStats bool
			if err := rows.Scan(&r.Name, &kind, &r.Table, &r.SizeBytes, &r.Rows, &noStats); err != nil {
				rows.Close()
				return err
			}
			r.Kind = kind[0]
			cat.Relations[r.Name] = r
			if noStats && (r.Kind == 'r' || r.Kind == 'm') {
				unknown = append(unknown, r.Name)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		// A partitioned table holds its partitions' rows.
		rows, err = tx.Query(ctx, `SELECT pn.nspname || '.' || p.relname, cn.nspname || '.' || ch.relname
			FROM pg_catalog.pg_inherits i
			JOIN pg_catalog.pg_class p ON p.oid = i.inhparent JOIN pg_catalog.pg_namespace pn ON pn.oid = p.relnamespace
			JOIN pg_catalog.pg_class ch ON ch.oid = i.inhrelid JOIN pg_catalog.pg_namespace cn ON cn.oid = ch.relnamespace
			WHERE p.relkind = 'p'`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var parent, child string
			if err := rows.Scan(&parent, &child); err != nil {
				rows.Close()
				return err
			}
			children[parent] = append(children[parent], child)
		}
		rows.Close()
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	// A table without statistics looks empty: read its size (it waits
	// at most a second for a lock, so it never queues behind a
	// migration). At most 100 of them.
	for _, name := range unknown[:min(len(unknown), 100)] {
		schema, rel, _ := strings.Cut(name, ".")
		var size int64
		if inReadOnly(ctx, conn, func(tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT pg_catalog.pg_table_size(to_regclass(format('%I.%I', $1::text, $2::text)))`, schema, rel).Scan(&size)
		}) == nil {
			r := cat.Relations[name]
			r.SizeBytes = size
			cat.Relations[name] = r
		}
	}
	var total func(name string, depth int) (int64, int64)
	total = func(name string, depth int) (int64, int64) {
		r := cat.Relations[name]
		size, n := r.SizeBytes, r.Rows
		if depth < 8 {
			for _, c := range children[name] {
				s, k := total(c, depth+1)
				size, n = size+s, n+k
			}
		}
		return size, n
	}
	for name, r := range cat.Relations {
		if r.Kind == 'p' {
			r.SizeBytes, r.Rows = total(name, 0)
			cat.Relations[name] = r
		}
	}
	return cat, nil
}

// columnType is a column's type on production ("" when unknown).
func columnType(ctx context.Context, conn *pgx.Conn, table, column string) string {
	schema, name, ok := strings.Cut(table, ".")
	if !ok {
		return ""
	}
	var typ string
	_ = inReadOnly(ctx, conn, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pg_catalog.format_type(a.atttypid, a.atttypmod)
			FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid = a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = $1 AND c.relname = $2 AND a.attname = $3 AND a.attnum > 0 AND NOT a.attisdropped`, schema, name, column).Scan(&typ)
	})
	return typ
}

// serverWideRE: SQL that acts beyond the database it runs in (roles,
// other databases, tablespaces, server settings and files, other
// sessions, replication, connections out). Next to production, it would
// act on the real server, so a migration with any of it isn't run.
var serverWideRE = regexp.MustCompile(`(?i)\b((CREATE|ALTER|DROP)\s+(ROLE|USER|GROUP|DATABASE|TABLESPACE|SUBSCRIPTION|SERVER)|ALTER\s+SYSTEM|` +
	`IMPORT\s+FOREIGN\s+SCHEMA|(REASSIGN|DROP)\s+OWNED|(COMMENT|SECURITY\s+LABEL)\s+ON\s+(DATABASE|ROLE|TABLESPACE)|ON\s+(DATABASE|TABLESPACE|PARAMETER)|` +
	`CHECKPOINT|pg_terminate_backend|pg_cancel_backend|pg_signal_backend|pg_reload_conf|pg_rotate_logfile|` +
	`pg_promote|pg_switch_w[a-z]+|pg_create_[a-z_]*replication_slot|pg_drop_replication_slot|pg_replication_origin_[a-z_]+|dblink[a-z_]*|` +
	`lo_import|lo_export|pg_read_file|pg_read_binary_file|pg_ls_[a-z_]+|pg_file_[a-z_]+|pg_stat_reset_shared|pg_stat_statements_reset)\b`)

// serverFilesRE: COPY to or from a file or a program, LOAD of a library.
var serverFilesRE = regexp.MustCompile(`(?i)\b(COPY\s+[^;]*?\b(FROM|TO)\s+(PROGRAM\b|E?')|LOAD\s+E?')`)

var trailingQuoteRE = regexp.MustCompile(`\s*E?'$`)

// serverWide names what in a statement reaches beyond its database ("").
func serverWide(text string) string {
	n := preview.Normalize(text)
	for _, re := range []*regexp.Regexp{serverWideRE, serverFilesRE} {
		if m := re.FindString(n); m != "" {
			return strings.TrimSpace(trailingQuoteRE.ReplaceAllString(strings.Join(strings.Fields(m), " "), ""))
		}
	}
	// GRANT role TO role: role membership is the server's.
	if c := strings.Fields(preview.Command(text) + " ")[0]; (c == "GRANT" || c == "REVOKE") && !regexp.MustCompile(`(?i)\sON\s`).MatchString(n) {
		return c + " (a role)"
	}
	return ""
}

// scratchBlocked says why the migration can't run on a temporary database
// ("" when it can).
func scratchBlocked(info serverInfo, stmts []preview.Stmt) string {
	for i, s := range stmts {
		if s.Meta {
			continue
		}
		if what := serverWide(s.Text); what != "" {
			return fmt.Sprintf("statement %d (%s) acts on the server itself, not only on this database, and Rowsafe runs migrations next to production only when they can't", i+1, what)
		}
	}
	switch {
	case info.inRecovery:
		return "this server is a read-only standby"
	case !info.canCreateDB:
		return fmt.Sprintf("the role %s can't create databases (it would need CREATEDB) to hold a temporary copy of the schema", info.user)
	}
	return ""
}

// previewOnScratch runs the migration on a temporary database with a copy
// of the schema. A nil result says why it couldn't (fallback).
func (d *DB) previewOnScratch(ctx context.Context, conn *pgx.Conn, info serverInfo, stmts []preview.Stmt, cat *preview.Catalog,
	o PreviewOptions, progress func(string)) (res *protocol.PreviewResult, fallback string) {
	dropLeftovers(ctx, conn)
	name := fmt.Sprintf("%s%d_%04x", scratchPrefix, time.Now().Unix(), rand.IntN(1<<16))
	progress(fmt.Sprintf("making a temporary database %s on the server for a copy of %s's schema (no rows)", name, d.Name()))
	if err := createScratch(ctx, conn, name, info); err != nil {
		return nil, "Rowsafe couldn't make a temporary database (" + firstLine(err.Error()) + ")"
	}
	defer func() {
		if err := dropScratch(conn, name); err != nil {
			msg := fmt.Sprintf("Rowsafe couldn't delete the temporary database %s (%s): delete it with DROP DATABASE %s.", name, firstLine(err.Error()), pgx.Identifier{name}.Sanitize())
			progress(msg)
			if res != nil {
				res.CheckNote = strings.TrimSpace(res.CheckNote + " " + msg)
			}
		} else {
			progress("deleted the temporary database " + name)
		}
	}()

	t := d.target()
	scratch, err := t.Connect(ctx, name)
	if err != nil {
		return nil, "Rowsafe couldn't connect to a temporary database (" + firstLine(err.Error()) + ")"
	}
	copyCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	how, failed, err := d.copySchema(copyCtx, info, scratch, progress)
	cancel()
	if err == nil {
		err = disableUserTriggers(ctx, scratch)
	}
	var funcs []string
	if err == nil {
		funcs, err = serverWideFunctions(ctx, scratch)
	}
	scratch.Close(context.WithoutCancel(ctx))
	if err != nil {
		return nil, "copying the schema failed (" + firstLine(err.Error()) + ")"
	}
	all := ""
	for _, s := range stmts {
		all += strings.ToLower(preview.Normalize(s.Text)) + "\n"
	}
	for _, f := range funcs { // "name: what"
		fn, what, _ := strings.Cut(f, ": ")
		if short := fn[strings.LastIndexByte(fn, '.')+1:]; strings.Contains(all, strings.ToLower(short)) {
			return nil, fmt.Sprintf("the migration calls %s, which acts on the server itself (%s)", fn, what)
		}
	}
	progress(fmt.Sprintf("copied the schema (%s); running the migration on it", how))

	runFor := o.Timeout
	if runFor <= 0 {
		runFor = defaultPreviewRun
	}
	res = &protocol.PreviewResult{Mode: preview.Mode(stmts), DB: d.Name(), Checked: protocol.PreviewCheckedSchema, Statements: []protocol.PreviewStatement{}}
	if err := runPreviewOn(ctx, t, name, stmts, res, runFor); err != nil {
		return nil, "the run on the temporary database stopped (" + firstLine(err.Error()) + ")"
	}
	if res.Error != nil && len(failed) > 0 {
		return nil, fmt.Sprintf("statement %d failed on the temporary copy (%s), but %d %s of the schema couldn't be copied there (first: %s), which may be why",
			res.Error.Statement, res.Error.Message, len(failed), plural(len(failed), "object", "objects"), failed[0])
	}
	extra := estimate(res, stmts, cat)
	tidyErrors(res, info.user)
	texts := make([]string, len(stmts))
	for i, s := range stmts {
		texts[i] = s.Text
	}
	preview.AssessEngine(protocol.EnginePostgreSQL, res, texts, extra)
	if len(failed) > 0 {
		res.CheckNote = fmt.Sprintf("%d %s of the schema couldn't be copied to the temporary database (first: %s).", len(failed), plural(len(failed), "object", "objects"), failed[0])
	}
	return res, ""
}

// estimate puts production's sizes and rows on what the migration did on
// the empty copy, and the time each step would take there; it returns the
// findings the SQL tells by itself.
func estimate(res *protocol.PreviewResult, stmts []preview.Stmt, cat *preview.Catalog) []protocol.PreviewFinding {
	e := preview.NewEstimator(cat)
	ests := make([]preview.Estimate, len(stmts))
	ms := make([]int64, len(stmts))
	var extra []protocol.PreviewFinding
	for i, s := range stmts {
		if s.Meta {
			continue
		}
		ests[i] = e.Statement(s.Text)
		ms[i] = ests[i].Ms
		for _, f := range ests[i].Findings() {
			f.Statement = i + 1
			extra = append(extra, f)
		}
	}
	hold := preview.HoldTimes(stmts, ms, res.Mode)
	size := func(name string) (int64, int64) {
		r := cat.Relations[name]
		return r.SizeBytes, r.Rows
	}
	for i := range res.Statements {
		st := &res.Statements[i]
		st.Superuser = false
		if !st.Ran || i >= len(stmts) {
			continue
		}
		st.DurationMs += ms[i]
		res.DurationMs += ms[i]
		switch {
		case ests[i].Rows != nil:
			st.Rows = ests[i].Rows
		case st.Command == "UPDATE" || st.Command == "DELETE" || st.Command == "MERGE" || (st.Rows != nil && *st.Rows == 0):
			st.Rows = nil // the copy has no rows: its count says nothing
		}
		for j := range st.Locks {
			l := &st.Locks[j]
			l.SizeBytes, _ = size(l.Relation)
			l.HeldMs += hold[i]
		}
		for j := range st.Rewrites {
			st.Rewrites[j].SizeBytes, st.Rewrites[j].Rows = size(st.Rewrites[j].Name)
		}
		for j := range st.Dropped {
			st.Dropped[j].SizeBytes, st.Dropped[j].Rows = size(st.Dropped[j].Name)
		}
		for j := range st.IndexBuilds {
			st.IndexBuilds[j].SizeBytes, st.IndexBuilds[j].Rows = size(st.IndexBuilds[j].Table)
		}
	}
	return extra
}

// tidyErrors words the agent's errors for a run as the connection's role.
func tidyErrors(res *protocol.PreviewResult, user string) {
	fix := func(s string) string {
		return strings.Replace(s, "Rowsafe runs CREATE EXTENSION first, as a superuser, and it failed: ", "CREATE EXTENSION failed: ", 1)
	}
	for i := range res.Statements {
		res.Statements[i].Error = fix(res.Statements[i].Error)
	}
	if e := res.Error; e != nil {
		e.Message = fix(e.Message)
		if e.Code == "42501" {
			e.Hint = fmt.Sprintf("The temporary copy runs the migration as %s, the role in the connection string: it needs the same rights on production.", user)
		}
	}
}

func createScratch(ctx context.Context, conn *pgx.Conn, name string, info serverInfo) error {
	var q string
	if err := conn.QueryRow(ctx, `SELECT format('CREATE DATABASE %I TEMPLATE template0 ENCODING %L LC_COLLATE %L LC_CTYPE %L', $1::text, $2::text, $3::text, $4::text)`,
		name, info.encoding, info.collate, info.ctype).Scan(&q); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, q); err == nil {
		return nil
	}
	// The locale may be one the server can't make databases with (an ICU
	// default): the server's defaults are close enough for a preview.
	if err := conn.QueryRow(ctx, `SELECT format('CREATE DATABASE %I TEMPLATE template0', $1::text)`, name).Scan(&q); err != nil {
		return err
	}
	_, err := conn.Exec(ctx, q)
	return err
}

func dropScratch(conn *pgx.Conn, name string) error {
	// DROP DATABASE waits for a checkpoint: slow on a busy server.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var q string
	if err := conn.QueryRow(ctx, `SELECT format('DROP DATABASE IF EXISTS %I%s', $1::text,
		CASE WHEN current_setting('server_version_num')::int >= 130000 THEN ' WITH (FORCE)' ELSE '' END)`, name).Scan(&q); err != nil {
		return err
	}
	_, err := conn.Exec(ctx, q)
	return err
}

// dropLeftovers drops temporary databases this role made over an hour
// ago that a crash left behind; one in use is left alone.
func dropLeftovers(ctx context.Context, conn *pgx.Conn) {
	rows, err := conn.Query(ctx, `SELECT datname FROM pg_catalog.pg_database
		WHERE datname LIKE 'rowsafe\_preview\_%' AND datdba = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)`)
	if err != nil {
		return
	}
	names, _ := pgx.CollectRows(rows, pgx.RowTo[string])
	for _, n := range names {
		ts, _, _ := strings.Cut(strings.TrimPrefix(n, scratchPrefix), "_")
		sec, err := strconv.ParseInt(ts, 10, 64)
		if err != nil || time.Since(time.Unix(sec, 0)) < time.Hour {
			continue
		}
		var q string
		if conn.QueryRow(ctx, `SELECT format('DROP DATABASE IF EXISTS %I', $1::text)`, n).Scan(&q) == nil {
			_, _ = conn.Exec(ctx, q)
		}
	}
}

// disableUserTriggers keeps the copy's own triggers from firing while the
// migration runs (they may call out); foreign keys still work.
func disableUserTriggers(ctx context.Context, conn *pgx.Conn) error {
	rows, err := conn.Query(ctx, `SELECT DISTINCT format('ALTER TABLE %s DISABLE TRIGGER USER', t.tgrelid::regclass)
		FROM pg_catalog.pg_trigger t WHERE NOT t.tgisinternal`)
	if err != nil {
		return err
	}
	stmts, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, q := range stmts {
		if _, err := conn.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// serverWideFunctions lists the copy's functions whose code acts on the
// server itself: "schema.name: what".
func serverWideFunctions(ctx context.Context, conn *pgx.Conn) ([]string, error) {
	rows, err := conn.Query(ctx, `SELECT n.nspname || '.' || p.proname, coalesce(p.prosrc, '')
		FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, src string
		if err := rows.Scan(&name, &src); err != nil {
			return nil, err
		}
		if what := serverWide(src); what != "" {
			out = append(out, name+": "+what)
		}
	}
	return out, rows.Err()
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
