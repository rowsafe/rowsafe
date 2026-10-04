package sqlite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/preview"
	"github.com/rowsafe/rowsafe/protocol"
)

// Migration previews (Guard) for SQLite: the migration runs on a copy of
// the database restored from the bucket (the newest point: the newest
// backup and every change since), never on production, which is only
// looked at (its header, size and the free disk next to it). The copy is
// kept for the next preview (preview_copy.go); the migration runs on a
// fresh file copy of it, with SQLite's defaults (foreign keys off unless
// the migration turns them on, as SQLite's own table rebuild procedure
// does), in one transaction unless the SQL manages its own. Each
// statement's time, rows changed, tables rebuilt or dropped and indexes
// built are measured; the write lock the real run would hold is inferred
// from what wrote (package preview words it for production's journal
// mode). Only names, counts, sizes and timings leave the server: SQLite's
// error messages name tables and columns, not values, and quoted text
// that isn't in the migration is redacted anyway.

const (
	maxPreviewSQL        = 1 << 20
	maxPreviewStatements = 5000
	defaultPreviewFresh  = 60 * time.Minute
	defaultPreviewRun    = 30 * time.Minute
	maxPreviewRun        = 4 * time.Hour
)

var (
	previewIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	// Statements that change the schema: sqlite_schema is read after each.
	schemaStmtRE = regexp.MustCompile(`(?i)^(CREATE|ALTER|DROP|VACUUM|REINDEX)\b`)
)

func (e *Engine) previewMigration(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.PreviewParams, tl agent.TaskLogger) (*protocol.PreviewResult, error) {
	if !previewIDRE.MatchString(p.PreviewID) {
		return nil, fmt.Errorf("invalid preview id %q", p.PreviewID)
	}
	if strings.TrimSpace(p.SQL) == "" {
		return nil, errors.New("there is no SQL to preview")
	}
	if len(p.SQL) > maxPreviewSQL {
		return nil, fmt.Errorf("the SQL is %s; previews take at most %s", humanBytes(int64(len(p.SQL))), humanBytes(maxPreviewSQL))
	}
	file := filepath.Base(db.SocketDir)
	if p.DB != "" && p.DB != "main" && p.DB != db.Name && p.DB != file {
		return nil, fmt.Errorf("a SQLite file has one database (main): there is no database %q in it", p.DB)
	}
	// Reports name the file ("a copy of production.sqlite3").
	res := &protocol.PreviewResult{PreviewID: p.PreviewID, DB: file, Statements: []protocol.PreviewStatement{}}
	stmts, err := preview.SplitSQLite(p.SQL)
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
	res.Mode = preview.ModeSQLite(stmts)
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

	// Production, looked at only: the wording of the locks and VACUUM's
	// disk needs.
	h, fi, err := readDBHeader(db.SocketDir)
	if err != nil {
		return nil, err
	}
	sc := preview.SQLiteContext{JournalMode: "delete", File: file, FileBytes: fi.Size()}
	if h.WAL {
		sc.JournalMode = "wal"
	}
	if _, free, err := diskSpace(filepath.Dir(db.SocketDir)); err == nil {
		sc.DiskFreeBytes = free
	}

	start := time.Now()
	pc := e.previewCopies(env)
	rec, reused, err := e.previewCopyFor(ctx, env, db, p.PreviewID, fresh, tl)
	if err != nil {
		return nil, err
	}
	keep := env.Config.Copies.PreviewKeep
	defer func() {
		pc.release(rec, keep)
		if keep > 0 {
			tl.Printf("kept the preview copy for %s so the next preview starts fast", keep)
		} else {
			tl.Printf("deleted the preview copy")
		}
	}()
	res.CopyReused, res.DataAsOf = reused, rec.RecoveredTo
	if !reused {
		res.RestoreMs = time.Since(start).Milliseconds()
	}

	// The migration runs on a file copy, so the kept copy stays clean;
	// without room for one, on the copy itself, deleted afterwards.
	work := rec.file()
	if keep > 0 {
		run := filepath.Join(rec.Dir, previewRunName)
		if err := ensureSpace(rec.Dir, rec.SizeBytes+rec.SizeBytes/10, "a working copy of the preview copy"); err != nil {
			tl.Printf("%v: the migration runs on the preview copy itself, which is deleted afterwards", err)
			keep = 0
		} else {
			t0 := time.Now()
			if err := copyFile(rec.file(), run); err != nil {
				removeDB(run)
				return nil, fmt.Errorf("copying the preview copy: %w", err)
			}
			defer removeDB(run)
			work = run
			if reused {
				res.RestoreMs = time.Since(t0).Milliseconds()
			}
		}
	}
	if err := runSQLitePreview(ctx, work, stmts, res, runFor, &sc, tl); err != nil {
		keep = 0
		return nil, err
	}
	texts := make([]string, len(stmts))
	for i, s := range stmts {
		texts[i] = s.Text
	}
	preview.AssessSQLite(res, texts, sc)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// previewCopyFor returns the database's preview copy, in use by this
// preview: the kept one when its data is at most fresh old, else the
// newest point restored now.
func (e *Engine) previewCopyFor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, previewID string, fresh time.Duration, tl agent.TaskLogger) (previewCopy, bool, error) {
	pc := e.previewCopies(env)
	if r, ok := pc.claim(db.ID); ok {
		age := time.Since(r.CreatedAt)
		if r.RecoveredTo != nil {
			age = time.Since(*r.RecoveredTo)
		}
		if fresh > 0 && age <= fresh && fileSize(r.file()) > 0 {
			tl.Printf("reusing the preview copy %s (data from %s ago)", r.ID, age.Round(time.Second))
			return r, true, nil
		}
		if fresh > 0 {
			tl.Printf("the kept preview copy's data is %s old; restoring a new one", age.Round(time.Minute))
		}
		pc.remove(r)
	}
	repo, err := openRepo(env, db)
	if err != nil {
		return previewCopy{}, false, err
	}
	if s := e.existingShipper(db.ID); s != nil {
		if _, err := s.flush(ctx, 2*time.Minute); err != nil {
			tl.Printf("note: the newest changes haven't reached your bucket yet (%v); the copy has what is there", err)
		}
	}
	id := "pv_" + previewID
	if len(id) > 32 {
		id = id[:32]
	}
	rec := previewCopy{ID: id, DatabaseID: db.ID, Dir: filepath.Join(previewRoot(env), id), Status: protocol.CopyRestoring,
		CreatedAt: time.Now().UTC(), InUse: true}
	if err := os.MkdirAll(rec.Dir, 0o700); err != nil {
		return previewCopy{}, false, err
	}
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	pc.mu.Lock()
	pc.running[rec.ID] = cancel
	pc.mu.Unlock()
	defer func() {
		pc.mu.Lock()
		delete(pc.running, rec.ID)
		pc.mu.Unlock()
	}()
	if err := pc.put(rec); err != nil {
		return previewCopy{}, false, err
	}
	tl.Printf("restoring the newest point of %s into a private preview copy (production isn't touched)", db.Name)
	out, err := restoreTo(rctx, repo, restoreTarget{Latest: true}, rec.file(), tl)
	if err != nil {
		pc.remove(rec)
		if rctx.Err() != nil && ctx.Err() == nil {
			return previewCopy{}, false, errors.New("the preview copy was deleted before it was ready")
		}
		return previewCopy{}, false, err
	}
	if out.Note != "" {
		tl.Printf("note: %s", out.Note)
	}
	rt := out.RecoveredTo.UTC()
	rec.Status, rec.RecoveredTo, rec.SizeBytes = protocol.CopyReady, &rt, fileSize(rec.file())
	if err := pc.put(rec); err != nil {
		pc.remove(rec)
		return previewCopy{}, false, err
	}
	tl.Printf("preview copy restored (%s, data from %s)", humanBytes(rec.SizeBytes), rt.Format(time.RFC3339))
	return rec, false, nil
}

// copyFile copies a closed database file the agent made.
func copyFile(src, dst string) error {
	removeDB(dst)
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// runSQLitePreview runs the statements on the file at path and records
// what each did into res.
func runSQLitePreview(ctx context.Context, path string, stmts []preview.Stmt, res *protocol.PreviewResult, runFor time.Duration, sc *preview.SQLiteContext, tl agent.TaskLogger) error {
	// Each table's and index's size before the migration, read from the
	// closed file.
	c, err := openDB(ctx, path, openOpts{Scratch: true, Busy: time.Second})
	if err != nil {
		return err
	}
	defer c.Close()
	// SQLite's own default (this build turns foreign keys on): apps and
	// migration tools turn them on themselves, and off around rebuilds.
	if err := c.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		return err
	}
	start, err := readPreviewSchema(c)
	if err != nil {
		return fmt.Errorf("reading the copy's schema: %w", err)
	}
	var roots []int64
	for _, o := range start {
		roots = append(roots, o.Root)
	}
	bt, pageSize, err := btreeSizes(path, roots)
	if err != nil {
		return fmt.Errorf("measuring the copy's tables: %w", err)
	}
	sizes := map[string]relSize{}
	for k, o := range start {
		if s, ok := bt[o.Root]; ok {
			sizes[k] = relSize{Bytes: s.Pages * int64(pageSize), Rows: s.Entries}
		}
	}
	tr := newSchemaTracker(start, sizes, pageSize)
	fkBefore := foreignKeyProblems(c)

	runCtx, cancel := context.WithTimeout(ctx, runFor)
	defer cancel()
	defer withInterrupt(runCtx, c)()

	var full strings.Builder
	for _, s := range stmts {
		full.WriteString(s.Text + "\n")
	}
	fullSQL := full.String()
	res.Statements = make([]protocol.PreviewStatement, len(stmts))
	texts := make([]string, len(stmts))
	for i, s := range stmts {
		texts[i] = s.Text
		res.Statements[i] = protocol.PreviewStatement{N: i + 1, Line: s.Line, SQL: preview.Shorten(s.Text, 300), Command: preview.Command(s.Text)}
	}
	inTxn := res.Mode == protocol.PreviewInTransaction
	if inTxn {
		if err := c.Exec(`BEGIN`); err != nil {
			return err
		}
	}
	fail := func(i int, err error, commit bool) {
		st := &res.Statements[i]
		pe := &protocol.PreviewError{Statement: i + 1, Line: stmts[i].Line}
		var se *sqlite3.Error
		switch {
		case runCtx.Err() != nil && ctx.Err() == nil:
			pe.Message = fmt.Sprintf("the migration was still running after %s on the copy, so the preview stopped it", runFor.Round(time.Minute))
		case errors.As(err, &se):
			pe.Code = strconv.Itoa(int(se.ExtendedCode()))
			pe.Message = preview.RedactValues(sqliteMessage(err), fullSQL)
			pe.Hint = sqliteHint(pe.Message)
		default:
			pe.Message = preview.RedactValues(err.Error(), fullSQL)
		}
		if commit {
			pe.Message = "when the migration commits: " + pe.Message
		}
		st.Error, res.Error = pe.Message, pe
		tl.Printf("statement %d failed on the copy: %v", i+1, err) // the full message stays in the agent's log
	}
	wrote := make([]bool, len(stmts))
	cur := start
	last := -1
	for i, s := range stmts {
		st := &res.Statements[i]
		if reason := preview.SkipSQLite(s); reason != "" {
			if s.Meta {
				st.Command = "sqlite3"
			}
			st.Impact = reason
			continue
		}
		norm := preview.Normalize(s.Text)
		t0 := time.Now()
		w, err := execStatement(c, s.Text)
		st.Ran, st.DurationMs = true, time.Since(t0).Milliseconds()
		res.DurationMs += st.DurationMs
		last = i
		if err != nil {
			fail(i, err, false)
			break
		}
		wrote[i] = w
		switch st.Command {
		case "INSERT", "UPDATE", "DELETE", "REPLACE":
			n := c.Changes()
			st.Rows = &n
		}
		if schemaStmtRE.MatchString(norm) {
			after, err := readPreviewSchema(c)
			if err != nil {
				return fmt.Errorf("reading the copy's schema: %w", err)
			}
			tr.schemaChange(i, norm, cur, after, st)
			cur = after
		}
		tr.rowsCopied(i, norm)
	}
	if res.Error == nil {
		// Rows the migration left pointing at a missing parent.
		if n := foreignKeyProblems(c) - fkBefore; n > 0 {
			sc.ForeignKeyProblems = n
		}
		if inTxn {
			t0 := time.Now()
			err := c.Exec(`COMMIT`)
			ms := time.Since(t0).Milliseconds()
			res.DurationMs += ms
			if last >= 0 {
				res.Statements[last].DurationMs += ms
			}
			if err != nil && last >= 0 {
				fail(last, err, true)
			}
		}
	}
	rollback(c)
	tr.finish(res)
	preview.AssignSQLiteLocks(res, texts, wrote, *sc)
	return nil
}

// execStatement runs one statement to its end (rows are read and
// dropped) and reports whether it wrote (took the write lock).
func execStatement(c *sqlite3.Conn, text string) (bool, error) {
	wrote := false
	for strings.TrimSpace(text) != "" {
		s, tail, err := c.Prepare(text)
		if err != nil {
			return wrote, err
		}
		if s == nil {
			break // only comments left
		}
		if !s.ReadOnly() {
			wrote = true
		}
		for s.Step() {
		}
		err = s.Err()
		s.Close()
		if err != nil {
			return wrote, err
		}
		text = tail
	}
	return wrote, nil
}

// foreignKeyProblems counts foreign_key_check's rows (0 when the schema
// has no foreign keys or the check fails).
func foreignKeyProblems(c *sqlite3.Conn) int64 {
	if n, err := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE type = 'table' AND sql LIKE '%REFERENCES%'`); err != nil || n == 0 {
		return 0
	}
	var n int64
	_ = queryRows(c, `PRAGMA main.foreign_key_check`, func(*sqlite3.Stmt) error { n++; return nil })
	return n
}

// sqliteMessage is SQLite's own message without the driver's prefixes
// ("sqlite3: SQL logic error: no such table: x" -> "no such table: x").
func sqliteMessage(err error) string {
	msg := strings.TrimPrefix(err.Error(), "sqlite3: ")
	if _, rest, ok := strings.Cut(msg, ": "); ok && rest != "" {
		return rest
	}
	return msg
}

// sqliteHint explains errors a preview meets more than a real run would.
func sqliteHint(msg string) string {
	switch m := strings.ToLower(msg); {
	case strings.Contains(m, "no such function"):
		return "SQLite itself doesn't have this function: it may be one your app adds in its own code, which a preview can't run."
	case strings.Contains(m, "no such collation"):
		return "SQLite itself doesn't have this collation: it may be one your app adds in its own code, which a preview can't run."
	case strings.Contains(m, "no such module"):
		return "The agent's SQLite doesn't have this extension, so the preview can't create or use the table; your app's SQLite may."
	case strings.Contains(m, "not null column with default value null"):
		return "The table has rows: give the column a DEFAULT, or add it without NOT NULL and fill it first."
	case strings.Contains(m, "foreign key constraint failed"):
		return "Rows point to a parent row that doesn't exist (or wouldn't after this change)."
	}
	return ""
}
