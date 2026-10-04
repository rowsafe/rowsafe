package sqlite

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ncruces/go-sqlite3"
	"github.com/ncruces/go-sqlite3/ext/fts5"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/masking"
	"github.com/rowsafe/rowsafe/protocol"
)

// Masking a SQLite copy, in the restored file before anyone can use it
// (package masking decides the fake values, the same as for every engine,
// with the host's masking key):
//
//   - The copy is switched to rollback-journal mode (one self-contained
//     file), with secure_delete on (freed space is zeroed), foreign keys
//     off and no trigger: the triggers are dropped for the masking and
//     created again after, so an app trigger (an audit log, updated_at)
//     never copies a real value elsewhere.
//   - Each masked column is rewritten with one UPDATE through a Go SQL
//     function, inside one transaction (a SAVEPOINT per column). A column
//     whose new values break one of its constraints (a CHECK, a UNIQUE
//     clash) is emptied instead when it may be NULL, else the copy fails.
//   - Full-text search: FTS5 tables that keep their own text are masked
//     like tables; ones indexing another table are rebuilt from the masked
//     table; contentless ones (only words) are emptied; then every FTS5
//     index is merged so no old word stays. Other virtual tables (FTS3/4,
//     R*Tree, app extensions) are removed from the copy with their
//     internal tables and the triggers that name them.
//   - sqlite_stat4 (sample index keys: real values) is cleared; sqlite_stat1
//     keeps counts only.
//   - Then VACUUM rebuilds the file, so no masked value lingers in free
//     pages.

// maskCopy masks the copy at path following mp.
func maskCopy(ctx context.Context, path string, mp protocol.MaskingPlan, key []byte, tl agent.TaskLogger) (protocol.MaskingReport, error) {
	start := time.Now()
	report := protocol.MaskingReport{Mode: mp.Mode, Strategies: map[string]int{}}
	c, err := openMaskConn(ctx, path)
	if err != nil {
		return report, err
	}
	defer func() { c.Close() }()
	if mp.Mode == protocol.MaskingNone {
		report.DurationMs = time.Since(start).Milliseconds()
		return report, nil
	}
	// Virtual tables the agent can't mask leave the copy first (the schema
	// is edited directly, then read again by a new connection).
	removed, fts, err := removeUnmaskable(c, tl)
	if err != nil {
		return report, err
	}
	report.Skipped = append(report.Skipped, removed...)
	if len(removed) > 0 {
		c.Close()
		if c, err = openMaskConn(ctx, path); err != nil {
			return report, err
		}
	}
	schema, err := readCopySchema(c)
	if err != nil {
		return report, err
	}
	plan := masking.Plan(schema, mp, &report)
	if err := maskTables(c, plan, fts, masking.New(key), tl, &report); err != nil {
		return report, err
	}
	tl.Printf("rebuilding the copy (VACUUM) so no original value stays in its free space")
	if err := c.Exec(`VACUUM`); err != nil {
		return report, fmt.Errorf("VACUUM of the masked copy: %w", err)
	}
	report.DurationMs = time.Since(start).Milliseconds()
	return report, nil
}

// openMaskConn opens a copy for masking: one file (rollback journal),
// zeroed free space, no foreign key actions, FTS5 available.
func openMaskConn(ctx context.Context, path string) (*sqlite3.Conn, error) {
	c, err := openDB(ctx, path, openOpts{Scratch: true})
	if err != nil {
		return nil, err
	}
	if err := fts5.Register(c); err != nil {
		c.Close()
		return nil, err
	}
	for _, q := range []string{`PRAGMA journal_mode = DELETE`, `PRAGMA secure_delete = ON`, `PRAGMA foreign_keys = OFF`,
		`PRAGMA recursive_triggers = OFF`} {
		if err := c.Exec(q); err != nil {
			c.Close()
			return nil, fmt.Errorf("%s: %w", q, err)
		}
	}
	if m, _ := journalMode(c); m != "delete" {
		c.Close()
		return nil, fmt.Errorf("the copy stayed in %s mode", m)
	}
	return c, nil
}

// removeUnmaskable removes the virtual tables the agent can't mask (with
// their internal tables and the triggers that name them) and returns why,
// with the FTS5 tables that stay.
func removeUnmaskable(c *sqlite3.Conn, tl agent.TaskLogger) ([]string, []vtab, error) {
	vts, err := virtualTables(c)
	if err != nil {
		return nil, nil, err
	}
	var notes []string
	var keep []vtab
	for _, v := range vts {
		reason := ""
		switch {
		case v.Module == "fts5":
			// A tokenizer the app registers itself isn't available here:
			// the table can't be opened.
			if s, _, err := c.Prepare(`SELECT 1 FROM main.` + quoteIdent(v.Name) + ` LIMIT 0`); err != nil {
				reason = fmt.Sprintf("%s: a full-text search table the agent can't open (%s), so it was removed from the copy", v.Name, firstLine(err.Error()))
			} else {
				s.Close()
				keep = append(keep, v)
				continue
			}
		case v.Module == "":
			reason = fmt.Sprintf("%s: a virtual table Rowsafe doesn't recognize, removed from the copy", v.Name)
		default:
			reason = fmt.Sprintf("%s: a virtual table of the SQLite extension %s, which Rowsafe can't mask, so it was removed from the copy", v.Name, v.Module)
		}
		if err := dropVirtual(c, v); err != nil {
			return nil, nil, fmt.Errorf("removing %s from the copy: %w", v.Name, err)
		}
		tl.Printf("%s", reason)
		notes = append(notes, reason)
	}
	return notes, keep, nil
}

// dropVirtual removes a virtual table whose module isn't loaded: its
// triggers and internal tables are dropped, then its entry in
// sqlite_schema (it has no pages of its own).
func dropVirtual(c *sqlite3.Conn, v vtab) error {
	if v.Module == "fts5" && c.Exec(`DROP TABLE main.`+quoteIdent(v.Name)) == nil {
		return nil // else its module can't open it: removed by hand below
	}
	for _, t := range triggersNaming(c, v.Name) {
		if err := c.Exec(`DROP TRIGGER main.` + quoteIdent(t)); err != nil {
			return err
		}
	}
	for _, suf := range shadowSuffixes[v.Module] {
		name := v.Name + "_" + suf
		if n, _ := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE type = 'table' AND name = ? COLLATE NOCASE`, name); n > 0 {
			if err := c.Exec(`DROP TABLE main.` + quoteIdent(name)); err != nil {
				return err
			}
		}
	}
	if err := c.Exec(`PRAGMA writable_schema = ON`); err != nil {
		return err
	}
	s, _, err := c.Prepare(`DELETE FROM main.sqlite_schema WHERE type = 'table' AND name = ? AND rootpage = 0`)
	if err == nil {
		if err = s.BindText(1, v.Name); err == nil {
			err = s.Exec()
		}
		s.Close()
	}
	if err2 := c.Exec(`PRAGMA writable_schema = OFF`); err == nil {
		err = err2
	}
	return err
}

// triggersNaming are the triggers whose statement names table.
func triggersNaming(c *sqlite3.Conn, table string) []string {
	re := regexp.MustCompile(`(?i)(^|[^A-Za-z0-9_$])["'\[` + "`" + `]?` + regexp.QuoteMeta(table) + `["'\]` + "`" + `]?($|[^A-Za-z0-9_$])`)
	var out []string
	_ = queryRows(c, `SELECT name, sql FROM main.sqlite_schema WHERE type = 'trigger'`, func(s *sqlite3.Stmt) error {
		if re.MatchString(s.ColumnText(1)) {
			out = append(out, s.ColumnText(0))
		}
		return nil
	})
	return out
}

// maskTables applies the plan in one transaction, with the triggers set
// aside, then deals with the FTS5 indexes and sample statistics.
func maskTables(c *sqlite3.Conn, plan []masking.TablePlan, fts []vtab, m *masking.Masker, tl agent.TaskLogger, report *protocol.MaskingReport) error {
	if err := c.Exec(`BEGIN IMMEDIATE`); err != nil {
		return err
	}
	defer rollback(c)
	var triggers []schemaObject
	err := queryRows(c, `SELECT name, sql FROM main.sqlite_schema WHERE type = 'trigger' AND sql IS NOT NULL ORDER BY rowid`, func(s *sqlite3.Stmt) error {
		triggers = append(triggers, schemaObject{Type: "trigger", Name: s.ColumnText(0), SQL: s.ColumnText(1)})
		return nil
	})
	if err != nil {
		return err
	}
	for _, t := range triggers {
		if err := c.Exec(`DROP TRIGGER main.` + quoteIdent(t.Name)); err != nil {
			return err
		}
	}
	for _, tp := range plan {
		var n int64
		var names []string
		for _, col := range tp.Columns {
			rows, strategy, err := maskColumn(c, tp.Table, col, m)
			if err != nil {
				return fmt.Errorf("masking %s.%s: %w", tp.Table, col.Name, err)
			}
			if strategy != col.Strategy {
				report.Skipped = append(report.Skipped, fmt.Sprintf("%s.%s.%s: its new values broke one of its constraints, so it was emptied instead", tp.DB, tp.Table, col.Name))
			}
			n = max(n, rows)
			report.Columns++
			report.Strategies[strategy]++
			names = append(names, col.Name+" ("+strategy+")")
		}
		report.Tables++
		report.Rows += n
		tl.Printf("masked %s: %s, %d rows", tp.Table, strings.Join(names, ", "), n)
	}
	for _, v := range fts {
		q := ""
		switch v.ftsContent() {
		case ftsExternal:
			q = fmt.Sprintf(`INSERT INTO main.%s(%s) VALUES ('rebuild')`, quoteIdent(v.Name), quoteIdent(v.Name))
		case ftsContentless:
			q = fmt.Sprintf(`INSERT INTO main.%s(%s) VALUES ('delete-all')`, quoteIdent(v.Name), quoteIdent(v.Name))
			report.Skipped = append(report.Skipped, fmt.Sprintf("%s: a full-text search table without its text (contentless), so its index was emptied: search finds nothing in it in the copy", v.Name))
		}
		if q != "" {
			if err := c.Exec(q); err != nil {
				return fmt.Errorf("rebuilding the full-text search table %s: %w", v.Name, err)
			}
		}
		if err := c.Exec(fmt.Sprintf(`INSERT INTO main.%s(%s) VALUES ('optimize')`, quoteIdent(v.Name), quoteIdent(v.Name))); err != nil {
			return fmt.Errorf("merging the full-text search table %s: %w", v.Name, err)
		}
	}
	for _, st := range []string{"sqlite_stat4", "sqlite_stat3"} {
		if n, _ := queryInt(c, `SELECT count(*) FROM main.sqlite_schema WHERE name = ?`, st); n > 0 {
			if err := c.Exec(`DELETE FROM main.` + st); err != nil {
				return err
			}
		}
	}
	for _, t := range triggers {
		if err := c.Exec(t.SQL); err != nil {
			return fmt.Errorf("creating the trigger %s again: %w", t.Name, err)
		}
	}
	return c.Exec(`COMMIT`)
}

// maskColumn rewrites one column; it returns the rows changed and the
// strategy used (Null when the masked values broke a constraint and the
// column may be emptied).
func maskColumn(c *sqlite3.Conn, table string, col masking.ColumnPlan, m *masking.Masker) (int64, string, error) {
	q := fmt.Sprintf(`UPDATE main.%s SET %s = %%s WHERE %s IS NOT NULL`, quoteIdent(table), quoteIdent(col.Name), quoteIdent(col.Name))
	if col.Strategy == masking.Null {
		if err := c.Exec(fmt.Sprintf(q, "NULL")); err != nil {
			return 0, col.Strategy, err
		}
		return c.Changes(), col.Strategy, nil
	}
	cm := m.Column(col)
	err := c.CreateFunction("rowsafe_mask", 1, sqlite3.DIRECTONLY, func(ctx sqlite3.Context, arg ...sqlite3.Value) {
		v := arg[0]
		switch v.Type() {
		case sqlite3.TEXT, sqlite3.INTEGER, sqlite3.FLOAT:
			if nv, ok := cm.Mask(v.Text()); ok {
				ctx.ResultText(nv)
				return
			}
		}
		ctx.ResultValue(v) // NULL, a blob, or a value the strategy can't read
	})
	if err != nil {
		return 0, "", err
	}
	defer c.CreateFunction("rowsafe_mask", 1, 0, nil)
	if err := c.Exec(`SAVEPOINT rowsafe_col`); err != nil {
		return 0, "", err
	}
	err = c.Exec(fmt.Sprintf(q, "rowsafe_mask("+quoteIdent(col.Name)+")"))
	if err == nil {
		return c.Changes(), col.Strategy, c.Exec(`RELEASE rowsafe_col`)
	}
	_ = c.Exec(`ROLLBACK TO rowsafe_col`)
	_ = c.Exec(`RELEASE rowsafe_col`)
	if !errors.Is(err, sqlite3.CONSTRAINT) {
		return 0, "", err
	}
	if !col.Nullable {
		return 0, "", fmt.Errorf("its masked values break one of its constraints (%s) and it can't be emptied: change its masking rule", firstLine(err.Error()))
	}
	if err := c.Exec(fmt.Sprintf(q, "NULL")); err != nil {
		return 0, "", err
	}
	return c.Changes(), masking.Null, nil
}
