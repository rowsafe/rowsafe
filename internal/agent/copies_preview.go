package agent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/rowsafe/rowsafe/internal/pginspect"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Migration previews: the SQL runs on a copy restored from the latest
// backup and all archived WAL, as a regular role (never a superuser), while
// a second session watches its locks every 100 ms. What each statement did
// (time, rows, locks on existing tables, tables rewritten, indexes built,
// tables dropped) becomes a verdict with plain-words impact (package
// preview). Production is never touched.
//
// A preview copy is kept for ROWSAFE_PREVIEW_KEEP after a preview, so the
// next preview of the database starts in seconds: the migration then runs
// on a clone of the database inside the copy, and the clone is dropped
// afterwards.

const (
	maxPreviewSQL        = 1 << 20
	maxPreviewStatements = 5000
	defaultPreviewFresh  = 60 * time.Minute
	defaultPreviewRun    = 30 * time.Minute
	maxPreviewRun        = 4 * time.Hour
	lockSampleEvery      = 100 * time.Millisecond
)

// previewMigration runs a preview_migration task. A migration that fails
// on the copy is a successful preview (Verdict failed); the task fails only
// when the preview itself couldn't run.
func (a *Agent) previewMigration(ctx context.Context, db protocol.DatabaseSpec, p protocol.PreviewParams, tl *taskLog) (*protocol.PreviewResult, error) {
	if !copyIDRE.MatchString(p.PreviewID) {
		return nil, fmt.Errorf("invalid preview id %q", p.PreviewID)
	}
	if strings.TrimSpace(p.SQL) == "" {
		return nil, errors.New("there is no SQL to preview")
	}
	if len(p.SQL) > maxPreviewSQL {
		return nil, fmt.Errorf("the SQL is %s; previews take at most %s", humanBytes(int64(len(p.SQL))), humanBytes(maxPreviewSQL))
	}
	res := &protocol.PreviewResult{PreviewID: p.PreviewID, Statements: []protocol.PreviewStatement{}}
	stmts, err := preview.Split(p.SQL)
	if err != nil {
		res.Verdict = protocol.PreviewFailed
		res.Error = &protocol.PreviewError{Message: "Rowsafe can't read the SQL: " + err.Error()}
		res.Summary = res.Error.Message + ". Nothing was run."
		return res, nil
	}
	if !slices.ContainsFunc(stmts, func(s preview.Stmt) bool { return !s.Meta }) {
		return nil, errors.New("the SQL has no statements")
	}
	if len(stmts) > maxPreviewStatements {
		return nil, fmt.Errorf("the SQL has %d statements; previews take at most %d", len(stmts), maxPreviewStatements)
	}
	res.Mode = preview.Mode(stmts)
	runFor := defaultPreviewRun
	if p.TimeoutSeconds > 0 {
		runFor = min(time.Duration(p.TimeoutSeconds)*time.Second, maxPreviewRun)
	}
	fresh := defaultPreviewFresh
	switch {
	case p.FreshMinutes < 0:
		fresh = 0
	case p.FreshMinutes > 0:
		fresh = time.Duration(min(p.FreshMinutes, 24*60)) * time.Minute
	}

	// A copy: the kept one if its data is fresh enough, else a new one.
	st := a.copyState()
	start := time.Now()
	rec, reused := copyRecord{}, false
	if r, ok := st.claimPreview(db.ID); ok {
		age := time.Since(copyDataTime(r))
		switch {
		case fresh > 0 && age <= fresh:
			if err := a.startGuardCopy(ctx, r); err == nil {
				rec, reused = r, true
				tl.Printf("reusing the preview copy %s (data from %s ago)", r.ID, age.Round(time.Minute))
			} else {
				tl.Printf("the kept preview copy doesn't start (%v); restoring a new one", err)
			}
		default:
			tl.Printf("the kept preview copy's data is %s old; restoring a new one", age.Round(time.Minute))
		}
		if !reused {
			if _, err := a.removeGuardCopy(r); err != nil {
				return nil, fmt.Errorf("removing the old preview copy: %w", err)
			}
		}
	}
	var super *pgx.Conn
	if !reused {
		id := "pv_" + p.PreviewID
		if len(id) > 32 {
			id = id[:32]
		}
		ctxRun, cancel := context.WithCancel(ctx)
		defer cancel()
		running := st.startRunning(id, cancel)
		rc, err := a.restoreGuardCopy(ctxRun, db, copyRecord{ID: id, Kind: protocol.CopyKindPreview, InUse: true}, tl)
		st.finishRunning(id, running)
		if err != nil {
			if ctxRun.Err() != nil && ctx.Err() == nil {
				return nil, errors.New("the preview copy was deleted before it was ready")
			}
			return nil, err
		}
		rec, super = rc.rec, rc.conn
		res.RestoreMs = time.Since(start).Milliseconds()
		if err := st.update(rec.ID, func(r *copyRecord) { r.Status = protocol.CopyReady }); err != nil {
			closeConn(ctx, super)
			return nil, err
		}
		rec.Status = protocol.CopyReady
	} else {
		if super, err = copyConnect(ctx, a.guardTarget(rec.Port, rec.socketDir(), ""), "postgres"); err != nil {
			a.discardPreviewCopy(rec, tl)
			return nil, fmt.Errorf("the preview copy is not answering: %w", err)
		}
	}
	res.CopyReused, res.DataAsOf = reused, rec.RecoveredTo
	keep := a.cfg.Copies.PreviewKeep > 0
	defer func() {
		closeConn(context.Background(), super)
		if keep {
			now := time.Now().UTC()
			_ = st.update(rec.ID, func(r *copyRecord) { r.InUse, r.LastUsed, r.Expires = false, now, now.Add(a.cfg.Copies.PreviewKeep) })
			tl.Printf("kept the preview copy for %s so the next preview starts fast", a.cfg.Copies.PreviewKeep)
		} else {
			a.discardPreviewCopy(rec, tl)
		}
	}()

	dbs, err := copyDatabases(ctx, super)
	if err != nil {
		keep = false
		return nil, err
	}
	dbname, err := pickPreviewDB(p.DB, db.Name, dbs)
	if err != nil {
		return nil, err
	}
	res.DB = dbname
	if !rec.Prepared {
		if _, err := super.Exec(ctx, `DO $$BEGIN
			IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '`+previewRole+`') THEN
				CREATE ROLE `+previewRole+` LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
			END IF;
		END$$`); err != nil {
			keep = false
			return nil, fmt.Errorf("creating the preview role: %w", err)
		}
		if err := prepareRoles(ctx, a.guardTarget(rec.Port, rec.socketDir(), ""), super, dbs, previewRole, tl); err != nil {
			keep = false
			return nil, err
		}
		_ = st.update(rec.ID, func(r *copyRecord) { r.Prepared = true })
	}

	// Keep the copy pristine for the next preview: run on a clone of the
	// database (under its real name) when there is room for one.
	restoreName := func() {}
	if keep {
		var size int64
		if err := super.QueryRow(ctx, `SELECT pg_database_size($1)`, dbname).Scan(&size); err != nil {
			keep = false
			return nil, err
		}
		if free, ferr := freeBytes(a.cfg.Copies.Dir); ferr == nil && free < size+size/10+256<<20 {
			tl.Printf("not enough free disk to clone %s (%s) inside the copy: the preview runs on the copy itself, which is deleted afterwards", dbname, humanBytes(size))
			keep = false
		} else {
			cloneStart := time.Now()
			restore, err := cloneForPreview(ctx, super, dbname, rec.Major)
			if err != nil {
				keep = false
				return nil, fmt.Errorf("cloning %s inside the copy: %w", dbname, err)
			}
			restoreName = func() {
				if err := restore(context.WithoutCancel(ctx)); err != nil {
					tl.Printf("restoring the preview copy after the run failed (%v); it is deleted", err)
					keep = false
				}
			}
			if reused {
				res.RestoreMs = time.Since(cloneStart).Milliseconds()
			}
			tl.Printf("cloned %s (%s) inside the copy in %s", dbname, humanBytes(size), time.Since(cloneStart).Round(time.Millisecond))
		}
	}
	defer restoreName()

	texts := make([]string, 0, len(stmts))
	for _, s := range stmts {
		texts = append(texts, s.Text)
	}
	superT, runnerT := a.guardTarget(rec.Port, rec.socketDir(), ""), a.guardTarget(rec.Port, rec.socketDir(), previewRole)
	if err := a.runPreview(ctx, superT, runnerT, dbname, stmts, res, runFor, tl); err != nil {
		keep = false
		return nil, err
	}
	preview.Assess(res, texts)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// copyDataTime is when a copy's data is from.
func copyDataTime(r copyRecord) time.Time {
	if r.RecoveredTo != nil {
		return *r.RecoveredTo
	}
	return r.CreatedAt
}

func (a *Agent) discardPreviewCopy(r copyRecord, tl *taskLog) {
	if _, err := a.removeGuardCopy(r); err != nil {
		tl.Printf("deleting the preview copy failed: %v (it is retried when the agent starts)", err)
	} else {
		tl.Printf("deleted the preview copy")
	}
}

// pickPreviewDB chooses the database a migration runs in.
func pickPreviewDB(want, rowsafeName string, dbs []string) (string, error) {
	if want != "" {
		if slices.Contains(dbs, want) {
			return want, nil
		}
		return "", fmt.Errorf("there is no database %q (databases: %s)", want, strings.Join(dbs, ", "))
	}
	if slices.Contains(dbs, rowsafeName) {
		return rowsafeName, nil
	}
	var user []string
	for _, d := range dbs {
		if d != "postgres" {
			user = append(user, d)
		}
	}
	switch len(user) {
	case 0:
		return "postgres", nil
	case 1:
		return user[0], nil
	}
	return "", fmt.Errorf("say which database the migration is for: %s", strings.Join(user, ", "))
}

// cloneForPreview renames the database aside and clones it back under its
// name, so the migration sees the real name. restore drops the clone and
// renames the original back.
func cloneForPreview(ctx context.Context, conn *pgx.Conn, dbname string, major int) (restore func(context.Context) error, err error) {
	var oid uint32
	if err := conn.QueryRow(ctx, `SELECT oid FROM pg_database WHERE datname = $1`, dbname).Scan(&oid); err != nil {
		return nil, err
	}
	base := fmt.Sprintf("rowsafe_base_%d", oid)
	q, b := pgx.Identifier{dbname}.Sanitize(), pgx.Identifier{base}.Sanitize()
	if _, err := conn.Exec(ctx, "ALTER DATABASE "+q+" RENAME TO "+b); err != nil {
		return nil, err
	}
	strategy := ""
	if major >= 15 {
		strategy = " STRATEGY FILE_COPY"
	}
	undo := func(ctx context.Context) error {
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+q+dropForce(major)); err != nil {
			return err
		}
		_, err := conn.Exec(ctx, "ALTER DATABASE "+b+" RENAME TO "+q)
		return err
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+q+" TEMPLATE "+b+strategy); err != nil {
		_ = undo(context.WithoutCancel(ctx))
		return nil, err
	}
	// CREATE DATABASE doesn't copy the owner, privileges or per-database
	// settings (ALTER DATABASE ... SET): copy them, they change how the
	// migration behaves.
	if _, err := conn.Exec(ctx, `UPDATE pg_database c SET datdba = b.datdba, datacl = b.datacl
		FROM pg_database b WHERE c.datname = $1 AND b.datname = $2`, dbname, base); err != nil {
		_ = undo(context.WithoutCancel(ctx))
		return nil, err
	}
	if _, err := conn.Exec(ctx, `INSERT INTO pg_db_role_setting (setdatabase, setrole, setconfig)
		SELECT (SELECT oid FROM pg_database WHERE datname = $1), setrole, setconfig
		FROM pg_db_role_setting WHERE setdatabase = (SELECT oid FROM pg_database WHERE datname = $2)`, dbname, base); err != nil {
		_ = undo(context.WithoutCancel(ctx))
		return nil, err
	}
	return undo, nil
}

func dropForce(major int) string {
	if major >= 13 {
		return " WITH (FORCE)"
	}
	return ""
}

// previewRel is a relation of the database before the migration.
type previewRel struct {
	name     string
	kind     byte
	table    uint32 // an index's table
	filenode uint32
	size     int64
	rows     int64
}

// relSnapshotSQL lists the application's tables, materialized views and
// indexes. Schema-qualified: the migration may change search_path.
const relSnapshotSQL = `
SELECT c.oid, coalesce(pg_catalog.pg_relation_filenode(c.oid), 0)::oid, c.relkind::text,
       n.nspname || '.' || c.relname, coalesce(i.indrelid, 0)::oid
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_index i ON i.indexrelid = c.oid
WHERE c.relkind IN ('r', 'p', 'm', 'i') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname !~ '^pg_toast' AND n.nspname !~ '^pg_temp'`

func snapshotRelations(ctx context.Context, conn *pgx.Conn, sizes bool) (map[uint32]previewRel, error) {
	q := relSnapshotSQL
	if sizes {
		q = `SELECT s.*, CASE WHEN s.relkind IN ('r', 'm') THEN pg_catalog.pg_table_size(s.oid) WHEN s.relkind = 'i' THEN pg_catalog.pg_relation_size(s.oid) ELSE 0 END,
		            greatest(c.reltuples, 0)::bigint
		     FROM (` + relSnapshotSQL + `) s(oid, filenode, relkind, name, indrelid) JOIN pg_catalog.pg_class c ON c.oid = s.oid`
	}
	rows, err := conn.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uint32]previewRel{}
	for rows.Next() {
		var oid, filenode, table uint32
		var kind, name string
		var size, n int64
		dest := []any{&oid, &filenode, &kind, &name, &table}
		if sizes {
			dest = append(dest, &size, &n)
		}
		if err := rows.Scan(dest...); err != nil {
			return nil, err
		}
		out[oid] = previewRel{name: name, kind: kind[0], table: table, filenode: filenode, size: size, rows: n}
	}
	return out, rows.Err()
}

// lockSet is the strongest lock mode seen per relation.
type lockSet map[uint32]string

func (s lockSet) add(rel uint32, mode string) {
	if cur, ok := s[rel]; !ok || preview.Stronger(mode, cur) {
		s[rel] = mode
	}
}

// lockSampler watches the migration session's locks from a second session.
type lockSampler struct {
	mu   sync.Mutex
	cur  int             // the statement running (index), -1 between statements
	seen map[int]lockSet // statement index -> locks seen while it ran
	err  error
}

func (ls *lockSampler) setCurrent(i int) {
	ls.mu.Lock()
	ls.cur = i
	ls.mu.Unlock()
}

func (ls *lockSampler) run(ctx context.Context, conn *pgx.Conn, pid uint32) {
	t := time.NewTicker(lockSampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ls.mu.Lock()
		cur := ls.cur
		ls.mu.Unlock()
		if cur < 0 {
			continue
		}
		rows, err := conn.Query(ctx, `SELECT relation, mode FROM pg_catalog.pg_locks
			WHERE pid = $1 AND locktype = 'relation' AND granted AND relation IS NOT NULL`, pid)
		if err != nil {
			if ctx.Err() == nil {
				ls.mu.Lock()
				ls.err = err
				ls.mu.Unlock()
			}
			return
		}
		got := lockSet{}
		for rows.Next() {
			var rel uint32
			var mode string
			if rows.Scan(&rel, &mode) == nil {
				got.add(rel, mode)
			}
		}
		rows.Close()
		ls.mu.Lock()
		if ls.seen[cur] == nil {
			ls.seen[cur] = lockSet{}
		}
		for rel, mode := range got {
			ls.seen[cur].add(rel, mode)
		}
		ls.mu.Unlock()
	}
}

// ownLocks are the relation locks the migration session holds now (inside
// its transaction).
func ownLocks(ctx context.Context, conn *pgx.Conn) (lockSet, error) {
	rows, err := conn.Query(ctx, `SELECT relation, mode FROM pg_catalog.pg_locks
		WHERE pid = pg_catalog.pg_backend_pid() AND locktype = 'relation' AND granted AND relation IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := lockSet{}
	for rows.Next() {
		var rel uint32
		var mode string
		if err := rows.Scan(&rel, &mode); err != nil {
			return nil, err
		}
		out.add(rel, mode)
	}
	return out, rows.Err()
}

// execStatement runs one statement with the simple protocol, discarding
// any rows, and returns its command tag.
func execStatement(ctx context.Context, conn *pgx.Conn, sql string) (pgconn.CommandTag, error) {
	mrr := conn.PgConn().Exec(ctx, sql)
	var tag pgconn.CommandTag
	for mrr.NextResult() {
		rr := mrr.ResultReader()
		for rr.NextRow() {
		}
		t, err := rr.Close()
		if err != nil {
			_ = mrr.Close()
			return tag, err
		}
		tag = t
	}
	return tag, mrr.Close()
}

type stmtRun struct {
	start, end time.Time
	txnEnd     time.Time // when its transaction ended (locks released)
	locks      lockSet
}

// runPreview runs the statements on the copy's database dbname and fills
// res.Statements (and res.Error, res.DurationMs).
func (a *Agent) runPreview(ctx context.Context, superT, runnerT pginspect.Target, dbname string, stmts []preview.Stmt,
	res *protocol.PreviewResult, runFor time.Duration, tl *taskLog) error {
	super, err := copyConnect(ctx, superT, dbname)
	if err != nil {
		return fmt.Errorf("connecting to %s on the copy: %w", dbname, err)
	}
	defer closeConn(context.Background(), super)
	before, err := snapshotRelations(ctx, super, true)
	if err != nil {
		return fmt.Errorf("reading the tables of %s: %w", dbname, err)
	}
	fullSQL := ""
	for _, s := range stmts {
		fullSQL += s.Text + "\n"
	}

	res.Statements = make([]protocol.PreviewStatement, len(stmts))
	for i, s := range stmts {
		res.Statements[i] = protocol.PreviewStatement{N: i + 1, Line: s.Line, SQL: preview.Shorten(s.Text, 300), Command: preview.Command(s.Text)}
		if s.Meta {
			res.Statements[i].Command = "psql"
			res.Statements[i].Impact = "A psql command, not SQL: skipped."
		}
	}
	fail := func(i int, err error, prefix string) {
		pe := &protocol.PreviewError{Statement: i + 1, Line: stmts[i].Line, Message: prefix + err.Error()}
		var pg *pgconn.PgError
		if errors.As(err, &pg) {
			pe.Code, pe.Hint = pg.Code, redactMessage(pg.Hint, fullSQL)
			pe.Message = prefix + redactMessage(pg.Message, fullSQL)
			if pg.Position > 0 {
				pe.Line = stmts[i].Line + strings.Count(prefixRunes(stmts[i].Text, int(pg.Position)), "\n")
			}
			if pg.Code == "42501" && !strings.Contains(pe.Hint, "superuser") {
				pe.Hint = strings.TrimSpace(pe.Hint + " Previews run as a regular role that owns your tables, not as a superuser; statements that need a superuser on your server (ALTER SYSTEM, untrusted languages, COPY to files) can't be previewed.")
			}
			// Detail can hold values from the data: only the server's log gets it.
			a.log.Info("preview: statement failed on the copy", "preview_id", res.PreviewID, "statement", i+1, "err", pg.Message, "detail", pg.Detail)
		} else if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			pe.Message = fmt.Sprintf("the migration was still running after %s on the copy, so the preview stopped it", runFor.Round(time.Minute))
		}
		res.Error = pe
		res.Statements[i].Error = pe.Message
	}

	// CREATE EXTENSION runs first, as a superuser (the migration runs as a
	// regular role). Rowsafe builds the statement itself from the parsed
	// parts.
	for i, s := range stmts {
		if s.Meta {
			continue
		}
		e, ok := preview.ParseCreateExtension(s.Text)
		if !ok {
			continue
		}
		q := "CREATE EXTENSION IF NOT EXISTS " + pgx.Identifier{e.Name}.Sanitize()
		if e.Schema != "" {
			q += " SCHEMA " + pgx.Identifier{e.Schema}.Sanitize()
		}
		if e.Version != "" {
			q += " VERSION " + quoteLiteral(e.Version)
		}
		if e.Cascade {
			q += " CASCADE"
		}
		st := time.Now()
		_, err := super.Exec(ctx, q)
		res.Statements[i].Ran, res.Statements[i].Superuser = true, true
		res.Statements[i].DurationMs = time.Since(st).Milliseconds()
		if err != nil {
			fail(i, err, "Rowsafe runs CREATE EXTENSION first, as a superuser, and it failed: ")
			for j := range res.Statements {
				if j != i {
					res.Statements[j].Ran = false
				}
			}
			return nil
		}
	}

	runner, err := copyConnect(ctx, runnerT, dbname)
	if err != nil {
		return fmt.Errorf("connecting to %s on the copy as %s: %w", dbname, runnerT.User, err)
	}
	defer closeConn(context.Background(), runner)
	pid := runner.PgConn().PID()
	if _, err := runner.Exec(ctx, fmt.Sprintf("SET statement_timeout = %d", runFor.Milliseconds())); err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, runFor+time.Minute)
	defer cancel()
	sampler := &lockSampler{cur: -1, seen: map[int]lockSet{}}
	sampleConn, err := copyConnect(ctx, superT, dbname)
	if err != nil {
		return err
	}
	sctx, stopSampling := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); sampler.run(sctx, sampleConn, pid) }()
	defer func() {
		stopSampling()
		wg.Wait()
		closeConn(context.Background(), sampleConn)
	}()

	runs := make([]stmtRun, len(stmts))
	inTxn := res.Mode == protocol.PreviewInTransaction
	var block []int // statements inside the current transaction
	current := before
	started := time.Now()
	endBlock := func(at time.Time) {
		for _, j := range block {
			runs[j].txnEnd = at
		}
		block = nil
	}
	if inTxn {
		if _, err := runner.Exec(rctx, "BEGIN"); err != nil {
			return err
		}
	}
	failedAt := -1
	for i, s := range stmts {
		if s.Meta || res.Statements[i].Superuser {
			continue
		}
		userTxn := !inTxn && preview.IsTxnControl(s.Text)
		sampler.setCurrent(i)
		runs[i].start = time.Now()
		tag, err := execStatement(rctx, runner, s.Text)
		runs[i].end = time.Now()
		sampler.setCurrent(-1)
		st := &res.Statements[i]
		st.Ran = true
		st.DurationMs = runs[i].end.Sub(runs[i].start).Milliseconds()
		if err != nil {
			fail(i, err, "")
			failedAt = i
			break
		}
		if n, ok := affectedRows(tag); ok {
			st.Rows = &n
		}
		// A transaction the script opened or closed itself.
		if userTxn {
			switch strings.ToUpper(preview.Command(s.Text)) {
			case "BEGIN":
				block = []int{}
			default: // COMMIT, ROLLBACK, END...
				if block != nil {
					endBlock(runs[i].end)
				}
			}
		} else if block != nil || inTxn {
			block = append(block, i)
			if locks, err := ownLocks(rctx, runner); err == nil {
				runs[i].locks = locks
			}
		}
		// What changed on disk.
		now, err := snapshotRelations(rctx, runner, false)
		if err != nil {
			tl.Printf("reading the tables after statement %d: %v", i+1, err)
			continue
		}
		for oid, r := range now {
			old, existed := current[oid]
			orig, original := before[oid]
			switch {
			case existed && r.filenode != 0 && old.filenode != 0 && r.filenode != old.filenode && original:
				if r.kind == 'r' || r.kind == 'm' {
					st.Rewrites = append(st.Rewrites, protocol.PreviewRelation{Name: r.name, SizeBytes: orig.size, Rows: orig.rows})
				} else if r.kind == 'i' {
					st.IndexBuilds = append(st.IndexBuilds, protocol.PreviewRelation{Name: r.name, Table: before[r.table].name, SizeBytes: before[r.table].size})
				}
			case !existed && r.kind == 'i':
				if t, ok := before[r.table]; ok {
					st.IndexBuilds = append(st.IndexBuilds, protocol.PreviewRelation{Name: r.name, Table: t.name, SizeBytes: t.size, Rows: t.rows})
				}
			}
		}
		for oid, old := range current {
			if _, still := now[oid]; !still && (old.kind == 'r' || old.kind == 'p' || old.kind == 'm') {
				if orig, ok := before[oid]; ok {
					st.Dropped = append(st.Dropped, protocol.PreviewRelation{Name: orig.name, SizeBytes: orig.size, Rows: orig.rows})
				}
			}
		}
		sortRelations(st.Rewrites)
		sortRelations(st.IndexBuilds)
		sortRelations(st.Dropped)
		current = now
	}
	if failedAt >= 0 {
		if inTxn || block != nil {
			_, _ = runner.Exec(context.WithoutCancel(ctx), "ROLLBACK")
		}
	} else if inTxn {
		if _, err := runner.Exec(rctx, "COMMIT"); err != nil {
			last := len(stmts) - 1
			for last > 0 && stmts[last].Meta {
				last--
			}
			fail(last, err, "at COMMIT: ")
			failedAt = last
		}
	}
	end := time.Now()
	res.DurationMs = end.Sub(started).Milliseconds()
	if inTxn {
		endBlock(end)
	} else if block != nil {
		endBlock(end) // the script left a transaction open: it ended with the session
	}
	stopSampling()
	wg.Wait()
	if sampler.err != nil {
		tl.Printf("watching locks: %v", sampler.err)
	}

	// Locks on relations that existed before, attributed to the statement
	// that first took each mode; held until its transaction ended.
	held := lockSet{}
	for i := range stmts {
		st := &res.Statements[i]
		if !st.Ran || st.Superuser {
			continue
		}
		seen := lockSet{}
		for rel, mode := range sampler.seen[i] {
			seen.add(rel, mode)
		}
		for rel, mode := range runs[i].locks {
			seen.add(rel, mode)
		}
		stop := runs[i].end
		if !runs[i].txnEnd.IsZero() {
			stop = runs[i].txnEnd
		}
		for rel, mode := range seen {
			r, ok := before[rel]
			if !ok || (r.kind != 'r' && r.kind != 'p' && r.kind != 'm') {
				continue
			}
			if prev, ok := held[rel]; ok && !preview.Stronger(mode, prev) && !runs[i].txnEnd.IsZero() {
				continue // already held since an earlier statement of the transaction
			}
			if !runs[i].txnEnd.IsZero() {
				held.add(rel, mode)
			}
			st.Locks = append(st.Locks, protocol.PreviewLock{Relation: r.name, Mode: mode, Blocks: preview.LockBlocks(mode),
				HeldMs: stop.Sub(runs[i].start).Milliseconds(), SizeBytes: r.size})
		}
		slices.SortFunc(st.Locks, func(x, y protocol.PreviewLock) int {
			if preview.Stronger(x.Mode, y.Mode) {
				return -1
			}
			if preview.Stronger(y.Mode, x.Mode) {
				return 1
			}
			return strings.Compare(x.Relation, y.Relation)
		})
		// Only locks that matter to other sessions are worth listing.
		st.Locks = slices.DeleteFunc(st.Locks, func(l protocol.PreviewLock) bool { return l.Blocks == "" && l.Mode == "AccessShareLock" })
	}
	if failedAt >= 0 {
		for j := failedAt + 1; j < len(res.Statements); j++ {
			res.Statements[j].Ran = false
		}
	}
	return nil
}

func sortRelations(r []protocol.PreviewRelation) {
	slices.SortFunc(r, func(a, b protocol.PreviewRelation) int { return strings.Compare(a.Name, b.Name) })
}

// affectedRows is the row count of a data-changing command tag.
func affectedRows(tag pgconn.CommandTag) (int64, bool) {
	s := tag.String()
	for _, p := range []string{"INSERT", "UPDATE", "DELETE", "MERGE", "COPY"} {
		if strings.HasPrefix(s, p) {
			return tag.RowsAffected(), true
		}
	}
	return 0, false
}

// prefixRunes is the first n characters of s (PostgreSQL error positions
// count characters, from 1).
func prefixRunes(s string, n int) string {
	i := 0
	for pos := range s {
		if i == n-1 {
			return s[:pos]
		}
		i++
	}
	return s
}

var quotedRE = regexp.MustCompile(`"([^"]*)"`)

// redactMessage hides quoted values in an error message that don't appear
// in the SQL itself (so they came from the data, e.g. `invalid input syntax
// for type integer: "+1 555 0100"`). Names of tables and columns appear in
// the SQL and stay.
func redactMessage(msg, sql string) string {
	lower := strings.ToLower(sql)
	return quotedRE.ReplaceAllStringFunc(msg, func(q string) string {
		inner := q[1 : len(q)-1]
		if inner == "" || strings.Contains(lower, strings.ToLower(inner)) {
			return q
		}
		return `"(a value from your data)"`
	})
}

// ---- copy_schema ----

// readCopySchema lists production's tables and columns, for reviewing masking
// rules: catalog queries only, no row is read.
func (a *Agent) readCopySchema(ctx context.Context, db protocol.DatabaseSpec, _ protocol.CopySchemaParams, tl *taskLog) (*protocol.CopySchemaResult, error) {
	t := a.target(db)
	conn, err := t.Connect(ctx, "postgres")
	if err != nil {
		return nil, err
	}
	dbs, err := copyDatabases(ctx, conn)
	closeConn(ctx, conn)
	if err != nil {
		return nil, err
	}
	res := &protocol.CopySchemaResult{Databases: []protocol.SchemaDatabase{}}
	budget := maxSchemaColumns
	for _, name := range dbs {
		sd, n, truncated, err := readSchema(ctx, t, name, budget)
		if err != nil {
			tl.Printf("reading %s: %v", name, err)
			continue
		}
		budget -= n
		res.Truncated = res.Truncated || truncated
		if len(sd.Tables) > 0 {
			res.Databases = append(res.Databases, sd)
		}
		if budget <= 0 {
			res.Truncated = true
			break
		}
	}
	tables := 0
	for _, d := range res.Databases {
		tables += len(d.Tables)
	}
	tl.Printf("read %d tables in %d databases (names and types only)", tables, len(res.Databases))
	return res, nil
}

// maxSchemaColumns keeps the schema report under the control plane's
// request limit.
const maxSchemaColumns = 8000

// schemaSQL lists tables (partitioned parents, not their partitions) with
// their columns, in name order.
const schemaSQL = `
SELECT n.nspname || '.' || c.relname, greatest(c.reltuples, 0)::bigint,
       CASE WHEN c.relkind = 'p' THEN 0 ELSE pg_catalog.pg_table_size(c.oid) END,
       a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod), NOT a.attnotnull,
       EXISTS (SELECT 1 FROM pg_catalog.pg_index i WHERE i.indrelid = c.oid AND i.indisunique AND i.indnatts = 1
               AND i.indkey[0] = a.attnum AND i.indpred IS NULL),
       a.attgenerated <> ''
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
  AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname !~ '^pg_toast' AND n.nspname !~ '^pg_temp'
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e')
ORDER BY 1, a.attnum`

func readSchema(ctx context.Context, t pginspect.Target, dbname string, budget int) (protocol.SchemaDatabase, int, bool, error) {
	sd := protocol.SchemaDatabase{Name: dbname, Tables: []protocol.SchemaTable{}}
	conn, err := t.Connect(ctx, dbname)
	if err != nil {
		return sd, 0, false, err
	}
	defer closeConn(ctx, conn)
	if _, err := conn.Exec(ctx, "SET statement_timeout = '60s'"); err != nil {
		return sd, 0, false, err
	}
	rows, err := conn.Query(ctx, strings.Replace(schemaSQL, "a.attgenerated <> ''", generatedExpr(conn), 1))
	if err != nil {
		return sd, 0, false, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var table, col, typ string
		var reltuples, size int64
		var nullable, unique, generated bool
		if err := rows.Scan(&table, &reltuples, &size, &col, &typ, &nullable, &unique, &generated); err != nil {
			return sd, n, false, err
		}
		if len(sd.Tables) == 0 || sd.Tables[len(sd.Tables)-1].Name != table {
			if n >= budget {
				return sd, n, true, nil
			}
			sd.Tables = append(sd.Tables, protocol.SchemaTable{Name: table, Rows: reltuples, SizeBytes: size})
		}
		last := &sd.Tables[len(sd.Tables)-1]
		last.Columns = append(last.Columns, protocol.SchemaColumn{Name: col, Type: typ, Nullable: nullable, Unique: unique, Generated: generated})
		n++
	}
	return sd, n, false, rows.Err()
}

// generatedExpr: attgenerated exists from PostgreSQL 12.
func generatedExpr(conn *pgx.Conn) string {
	v := conn.PgConn().ParameterStatus("server_version")
	major, _, _ := strings.Cut(v, ".")
	if n, err := strconv.Atoi(strings.TrimSpace(major)); err == nil && n < 12 {
		return "false"
	}
	return "a.attgenerated <> ''"
}
