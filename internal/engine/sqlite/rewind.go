package sqlite

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ncruces/go-sqlite3"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind for SQLite: a copy of the database as it was at any second (or a
// Mark), restored into a file in the agent's rewind directory; a comparison
// with the live file, table by table, by primary key; and bringing missing
// rows back in one transaction, never overwriting a row. Everything stays
// on this server: only names and counts are reported.

const (
	defaultCopyHours = 24
	maxCopyAge       = 7 * 24 * time.Hour
	compareMaxRows   = 10_000_000
	defaultMaxRows   = 10_000_000
	compareChunk     = 5000
	maxCompareTables = 500
)

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func copyRoot(env agent.EngineEnv) string { return filepath.Join(env.Config.RewindDir, "sqlite") }

// copyRecord is a copy the engine keeps (<state>/copies.json).
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	Dir         string                `json:"dir"`
	Status      string                `json:"status"` // protocol.RewindCopyRestoring | RewindCopyReady
	Target      protocol.RewindTarget `json:"target"`
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	SizeBytes   int64                 `json:"size_bytes"`
	Note        string                `json:"note,omitempty"`
}

func (r copyRecord) file() string { return filepath.Join(r.Dir, "copy.db") }

type copyStore struct {
	mu      sync.Mutex
	path    string
	records map[string]copyRecord
	running map[string]context.CancelFunc
}

func (e *Engine) copyState(env agent.EngineEnv) *copyStore {
	root := e.stateRootFor(env)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.copies == nil {
		cs := &copyStore{path: filepath.Join(root, "copies.json"), records: map[string]copyRecord{}, running: map[string]context.CancelFunc{}}
		var list []copyRecord
		if err := loadJSONFile(cs.path, &list); err == nil {
			for _, r := range list {
				cs.records[r.ID] = r
			}
		}
		e.copies = cs
	}
	return e.copies
}

func (cs *copyStore) saveLocked() error {
	list := make([]copyRecord, 0, len(cs.records))
	for _, r := range cs.records {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b copyRecord) int { return strings.Compare(a.ID, b.ID) })
	return saveJSONFile(cs.path, list)
}

func (cs *copyStore) put(r copyRecord) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.records[r.ID] = r
	return cs.saveLocked()
}

func (cs *copyStore) remove(id string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.records, id)
	return cs.saveLocked()
}

func (cs *copyStore) get(id string) (copyRecord, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	r, ok := cs.records[id]
	return r, ok
}

func (cs *copyStore) all() []copyRecord {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]copyRecord, 0, len(cs.records))
	for _, r := range cs.records {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b copyRecord) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (cs *copyStore) forDatabase(dbID string) (copyRecord, bool) {
	for _, r := range cs.all() {
		if r.DatabaseID == dbID {
			return r, true
		}
	}
	return copyRecord{}, false
}

func clampExpiry(want, now time.Time) time.Time {
	if want.IsZero() || !want.After(now) {
		return now.Add(defaultCopyHours * time.Hour)
	}
	if limit := now.Add(maxCopyAge); want.After(limit) {
		return limit
	}
	return want
}

// targetOf turns a RewindTarget into a restore target.
func targetOf(t protocol.RewindTarget) (restoreTarget, error) {
	out := restoreTarget{Mark: t.Mark}
	if t.Time != nil {
		out.Time = t.Time.UTC()
	}
	if (out.Mark == "") == out.Time.IsZero() {
		return out, errors.New("pick a moment or a Mark (exactly one)")
	}
	if out.Mark != "" && !markNameRE.MatchString(out.Mark) {
		return out, fmt.Errorf("invalid Mark name %q", out.Mark)
	}
	return out, nil
}

// flushRecent makes changes up to a moment of the last minutes reach the
// bucket before restoring to it.
func (e *Engine) flushRecent(ctx context.Context, db protocol.DatabaseSpec, t restoreTarget) {
	if t.Time.IsZero() || time.Since(t.Time) > 3*time.Minute {
		return
	}
	if s := e.existingShipper(db.ID); s != nil {
		_, _ = s.flush(ctx, 2*time.Minute)
	}
}

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	target, err := targetOf(p.Target)
	if err != nil {
		return nil, err
	}
	cs := e.copyState(env)
	if r, ok := cs.forDatabase(db.ID); ok {
		if r.ID == p.CopyID && r.Status == protocol.RewindCopyReady {
			return e.copyResult(ctx, r)
		}
		return nil, errors.New("this database already has a copy: delete it before restoring another")
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	e.flushRecent(ctx, db, target)
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Dir: filepath.Join(copyRoot(env), p.CopyID),
		Status: protocol.RewindCopyRestoring, Target: p.Target, CreatedAt: now, Expires: clampExpiry(p.Expires, now)}
	if err := os.MkdirAll(rec.Dir, 0o700); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.mu.Lock()
	cs.running[rec.ID] = cancel
	cs.mu.Unlock()
	defer func() {
		cs.mu.Lock()
		delete(cs.running, rec.ID)
		cs.mu.Unlock()
	}()
	if err := cs.put(rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		_ = os.RemoveAll(rec.Dir)
		_ = cs.remove(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted while it was being restored")
		}
		return nil, err
	}
	tl.Printf("restoring a copy of %s as of %s into %s (a separate file; the live database isn't touched)", db.Name, target.describe(), rec.Dir)
	out, err := restoreTo(cctx, r, target, rec.file(), tl)
	if err != nil {
		return fail(err)
	}
	check, err := inspectCopy(cctx, rec.file(), false)
	if err != nil {
		return fail(err)
	}
	if check.Integrity != "ok" {
		rec.Note = "SQLite's quick_check found a problem in the copy: " + check.Integrity
		tl.Printf("warning: %s", rec.Note)
	}
	if out.Note != "" {
		rec.Note = strings.TrimSpace(rec.Note + " " + out.Note)
	}
	rt := out.RecoveredTo
	rec.Status, rec.RecoveredTo, rec.SizeBytes = protocol.RewindCopyReady, &rt, fileSize(rec.file())
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	res, err := e.copyResult(ctx, rec)
	if err != nil {
		return nil, err
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) copyResult(ctx context.Context, rec copyRecord) (*protocol.RewindCopyResult, error) {
	tables := 0
	if c, err := openDB(ctx, rec.file(), openOpts{ReadOnly: true, Scratch: true}); err == nil {
		if ts, err := userTables(c); err == nil {
			tables = len(ts)
		}
		c.Close()
	} else {
		return nil, fmt.Errorf("the copy can't be opened: %w", err)
	}
	when := "the backup"
	if rec.RecoveredTo != nil {
		when = rec.RecoveredTo.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	summary := fmt.Sprintf("The copy is ready: %d tables (%s) as of %s. It is deleted by itself on %s.",
		tables, humanBytes(rec.SizeBytes), when, rec.Expires.UTC().Format("2006-01-02 15:04 UTC"))
	if rec.Note != "" {
		summary += " " + rec.Note
	}
	return &protocol.RewindCopyResult{CopyID: rec.ID, RecoveredTo: rec.RecoveredTo, SizeBytes: rec.SizeBytes,
		Databases: []protocol.DBInfo{{Name: "main", SizeBytes: rec.SizeBytes, Tables: tables}},
		SocketDir: rec.file(), Expires: rec.Expires, Summary: summary}, nil
}

func (e *Engine) rewindDrop(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindDropParams, tl agent.TaskLogger) (*protocol.RewindDropResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	cs := e.copyState(env)
	cs.mu.Lock()
	cancel := cs.running[p.CopyID]
	cs.mu.Unlock()
	if cancel != nil {
		tl.Printf("the copy is still being restored: stopping that first")
		cancel()
		for range 120 {
			cs.mu.Lock()
			_, still := cs.running[p.CopyID]
			cs.mu.Unlock()
			if !still {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	rec, ok := cs.get(p.CopyID)
	if !ok {
		dir := filepath.Join(copyRoot(env), p.CopyID)
		if _, err := os.Lstat(dir); err != nil {
			return &protocol.RewindDropResult{CopyID: p.CopyID, Summary: "There was no such copy (already deleted)."}, nil
		}
		rec = copyRecord{ID: p.CopyID, Dir: dir}
	}
	if rec.DatabaseID != "" && rec.DatabaseID != db.ID {
		return nil, errors.New("that copy belongs to another database")
	}
	freed := dirSize(rec.Dir)
	if err := os.RemoveAll(rec.Dir); err != nil {
		return nil, err
	}
	if err := cs.remove(p.CopyID); err != nil {
		return nil, err
	}
	tl.Printf("deleted the copy, freeing %s", humanBytes(freed))
	return &protocol.RewindDropResult{CopyID: p.CopyID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the copy (%s freed).", humanBytes(freed))}, nil
}

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// readyCopy opens a database's ready copy and production.
func (e *Engine) readyCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, id string) (copyRecord, *sqlite3.Conn, *sqlite3.Conn, error) {
	rec, ok := e.copyState(env).get(id)
	if !ok || rec.DatabaseID != db.ID {
		return rec, nil, nil, errors.New("there is no such copy (it expired or was deleted): restore a new one")
	}
	if rec.Status != protocol.RewindCopyReady {
		return rec, nil, nil, errors.New("the copy is still being restored")
	}
	cp, err := openDB(ctx, rec.file(), openOpts{Scratch: true})
	if err != nil {
		return rec, nil, nil, fmt.Errorf("the copy can't be opened: %w", err)
	}
	prod, err := openDB(ctx, db.SocketDir, openOpts{Busy: 5 * time.Second})
	if err != nil {
		cp.Close()
		return rec, nil, nil, err
	}
	return rec, cp, prod, nil
}

// ---- tables

// tableMeta is what comparing a table needs.
type tableMeta struct {
	Name         string
	Kind         string // table, virtual, shadow, view
	WithoutRowid bool
	Columns      []string // insertable columns, in order
	Key          []string // WITHOUT ROWID: its primary key; rowid tables: nil (the rowid)
	IntegerPK    string   // the INTEGER PRIMARY KEY column (the rowid's alias), "" when none
	SQL          string   // CREATE TABLE
}

// tableList lists the main schema's tables (PRAGMA table_list).
func tableList(c *sqlite3.Conn) (map[string]tableMeta, error) {
	out := map[string]tableMeta{}
	err := queryRows(c, `SELECT name, type, wr FROM pragma_table_list WHERE schema = 'main'`, func(s *sqlite3.Stmt) error {
		name := s.ColumnText(0)
		if strings.HasPrefix(name, "sqlite_") {
			return nil
		}
		out[name] = tableMeta{Name: name, Kind: s.ColumnText(1), WithoutRowid: s.ColumnInt(2) != 0}
		return nil
	})
	return out, err
}

// describeTable fills a table's columns and key.
func describeTable(c *sqlite3.Conn, t tableMeta) (tableMeta, error) {
	type col struct {
		name, typ string
		pk        int
		hidden    int
	}
	var cols []col
	err := queryRows(c, `SELECT name, type, pk, hidden FROM pragma_table_xinfo(?) ORDER BY cid`, func(s *sqlite3.Stmt) error {
		cols = append(cols, col{s.ColumnText(0), strings.ToUpper(strings.TrimSpace(s.ColumnText(1))), s.ColumnInt(2), s.ColumnInt(3)})
		return nil
	}, t.Name)
	if err != nil {
		return t, err
	}
	var pks []col
	for _, cl := range cols {
		if cl.hidden == 2 || cl.hidden == 3 { // generated columns can't be written
			continue
		}
		t.Columns = append(t.Columns, cl.name)
		if cl.pk > 0 {
			pks = append(pks, cl)
		}
	}
	slices.SortFunc(pks, func(a, b col) int { return a.pk - b.pk })
	if t.WithoutRowid {
		for _, p := range pks {
			t.Key = append(t.Key, p.name)
		}
	} else if len(pks) == 1 && pks[0].typ == "INTEGER" {
		t.IntegerPK = pks[0].name
	}
	t.SQL, _ = queryText(c, `SELECT sql FROM main.sqlite_schema WHERE type = 'table' AND name = ?`, t.Name)
	return t, nil
}

// keyExpr is the key's columns as SQL (with a table alias prefix).
func (t tableMeta) keyCols(alias string) []string {
	if len(t.Key) == 0 {
		return []string{alias + "rowid"}
	}
	out := make([]string, len(t.Key))
	for i, k := range t.Key {
		out[i] = alias + quoteIdent(k)
	}
	return out
}

func rowTuple(cols []string) string {
	if len(cols) == 1 {
		return cols[0]
	}
	return "(" + strings.Join(cols, ", ") + ")"
}

func placeholders(n int) string {
	if n == 1 {
		return "?"
	}
	return "(" + strings.TrimSuffix(strings.Repeat("?, ", n), ", ") + ")"
}

// skipReason says why a table can't be compared ("" when it can).
func skipReason(t tableMeta) string {
	switch t.Kind {
	case "virtual":
		return "a virtual table (its rows live in other tables or outside the file)"
	case "shadow":
		return "an internal table of a virtual table"
	case "view":
		return "a view (it holds no rows of its own)"
	}
	if t.WithoutRowid && len(t.Key) == 0 {
		return "no primary key to match rows by"
	}
	return ""
}

// encodeValue appends a column value, typed, to a key or row encoding.
func encodeValue(b []byte, s *sqlite3.Stmt, i int) []byte {
	switch s.ColumnType(i) {
	case sqlite3.NULL:
		return append(b, 0)
	case sqlite3.INTEGER:
		b = append(b, 1)
		return binary.BigEndian.AppendUint64(b, uint64(s.ColumnInt64(i)))
	case sqlite3.FLOAT:
		b = append(b, 2)
		return binary.BigEndian.AppendUint64(b, math.Float64bits(s.ColumnFloat(i)))
	case sqlite3.TEXT:
		v := s.ColumnRawText(i)
		b = append(b, 3)
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		return append(b, v...)
	default:
		v := s.ColumnRawBlob(i)
		b = append(b, 4)
		b = binary.BigEndian.AppendUint32(b, uint32(len(v)))
		return append(b, v...)
	}
}

// keyValue is a key column's value, for binding.
func keyValue(s *sqlite3.Stmt, i int) any {
	switch s.ColumnType(i) {
	case sqlite3.NULL:
		return nil
	case sqlite3.INTEGER:
		return s.ColumnInt64(i)
	case sqlite3.FLOAT:
		return s.ColumnFloat(i)
	case sqlite3.TEXT:
		return s.ColumnText(i)
	default:
		return slices.Clone(s.ColumnRawBlob(i))
	}
}

// rowSet is one chunk of rows: key encoding -> row encoding.
type rowSet struct {
	rows    map[string]string
	lastKey []any
	n       int
}

// readChunk reads rows of t from c: keys above after (nil: from the
// start), at most limit rows (0: no limit), at or below upTo (nil: none).
func readChunk(c *sqlite3.Conn, t tableMeta, cols []string, after, upTo []any, limit int) (rowSet, error) {
	keys := t.keyCols("")
	sel := append(slices.Clone(keys), quoteAll(cols)...)
	q := "SELECT " + strings.Join(sel, ", ") + " FROM main." + quoteIdent(t.Name)
	var where []string
	var args []any
	if after != nil {
		where = append(where, rowTuple(keys)+" > "+placeholders(len(keys)))
		args = append(args, after...)
	}
	if upTo != nil {
		where = append(where, rowTuple(keys)+" <= "+placeholders(len(keys)))
		args = append(args, upTo...)
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY " + strings.Join(keys, ", ")
	if limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", limit)
	}
	out := rowSet{rows: map[string]string{}}
	err := queryRows(c, q, func(s *sqlite3.Stmt) error {
		var k, v []byte
		last := make([]any, len(keys))
		for i := range keys {
			k = encodeValue(k, s, i)
			last[i] = keyValue(s, i)
		}
		for i := range cols {
			v = encodeValue(v, s, len(keys)+i)
		}
		out.rows[string(k)] = string(v)
		out.lastKey = last
		out.n++
		return nil
	}, args...)
	return out, err
}

func quoteAll(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = quoteIdent(c)
	}
	return out
}

// compareTable counts, by key, the copy's rows missing from production or
// changed there, and production's rows added since.
func compareTable(ctx context.Context, cp, prod *sqlite3.Conn, name string) (protocol.RewindTableDiff, error) {
	d := protocol.RewindTableDiff{RewindTable: protocol.RewindTable{DB: "main", Table: name}}
	cl, err := tableList(cp)
	if err != nil {
		return d, err
	}
	ct, ok := cl[name]
	if !ok {
		d.Skipped = "not in the copy"
		return d, nil
	}
	if ct, err = describeTable(cp, ct); err != nil {
		return d, err
	}
	if why := skipReason(ct); why != "" {
		d.Skipped = why
		return d, nil
	}
	d.Related = relatedTables(cp, name)
	n, err := queryInt(cp, `SELECT count(*) FROM main.`+quoteIdent(name))
	if err != nil {
		return d, err
	}
	if n > compareMaxRows {
		d.Skipped = fmt.Sprintf("too large to compare here (%s rows)", commas(n))
		return d, nil
	}
	pl, err := tableList(prod)
	if err != nil {
		return d, err
	}
	pt, inProd := pl[name]
	if !inProd {
		d.MissingInProduction = n
		d.Note = "This table was dropped from production since: bringing rows back creates it again, with its indexes."
		return d, nil
	}
	if pt, err = describeTable(prod, pt); err != nil {
		return d, err
	}
	if len(ct.Key) > 0 && !slices.Equal(ct.Key, pt.Key) || ct.WithoutRowid != pt.WithoutRowid {
		d.Skipped = "its primary key changed since, so rows can't be matched"
		return d, nil
	}
	cols, notes := commonColumns(ct, pt)
	if len(ct.Key) == 0 && ct.IntegerPK == "" {
		notes = append(notes, "It has no INTEGER PRIMARY KEY: rows are matched by their internal row number, which a VACUUM can change.")
	}
	d.Note = strings.Join(notes, " ")
	var after []any
	matched := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return d, err
		}
		cr, err := readChunk(cp, ct, cols, after, nil, compareChunk)
		if err != nil {
			return d, err
		}
		var upTo []any
		if cr.n == compareChunk {
			upTo = cr.lastKey
		}
		pr, err := readChunk(prod, ct, cols, after, upTo, 0)
		if err != nil {
			return d, err
		}
		for k, v := range cr.rows {
			pv, ok := pr.rows[k]
			switch {
			case !ok:
				d.MissingInProduction++
			case pv != v:
				d.Changed++
				matched++
			default:
				matched++
			}
		}
		d.OnlyInProduction += int64(pr.n) - countMatched(cr, pr)
		if cr.n < compareChunk {
			break
		}
		after = cr.lastKey
	}
	_ = matched
	return d, nil
}

func countMatched(cr, pr rowSet) int64 {
	n := int64(0)
	for k := range cr.rows {
		if _, ok := pr.rows[k]; ok {
			n++
		}
	}
	return n
}

// commonColumns are the columns both have; notes say what changed.
func commonColumns(cp, prod tableMeta) ([]string, []string) {
	var cols, added, removed []string
	for _, c := range cp.Columns {
		if slices.Contains(prod.Columns, c) {
			cols = append(cols, c)
		} else {
			removed = append(removed, c)
		}
	}
	for _, c := range prod.Columns {
		if !slices.Contains(cp.Columns, c) {
			added = append(added, c)
		}
	}
	var notes []string
	if len(added) > 0 {
		notes = append(notes, "Columns added since (not compared): "+strings.Join(added, ", ")+".")
	}
	if len(removed) > 0 {
		notes = append(notes, "Columns removed since (not compared): "+strings.Join(removed, ", ")+".")
	}
	return cols, notes
}

// relatedTables are the tables linked to name by foreign keys.
func relatedTables(c *sqlite3.Conn, name string) []protocol.RewindTable {
	seen := map[string]bool{}
	var out []protocol.RewindTable
	add := func(t string) {
		if t != name && !seen[t] {
			seen[t] = true
			out = append(out, protocol.RewindTable{DB: "main", Table: t})
		}
	}
	_ = queryRows(c, `SELECT "table" FROM pragma_foreign_key_list(?)`, func(s *sqlite3.Stmt) error { add(s.ColumnText(0)); return nil }, name)
	_ = queryRows(c, `SELECT m.name FROM main.sqlite_schema AS m, pragma_foreign_key_list(m.name) AS f
		WHERE m.type = 'table' AND f."table" = ?`, func(s *sqlite3.Stmt) error { add(s.ColumnText(0)); return nil }, name)
	slices.SortFunc(out, func(a, b protocol.RewindTable) int { return strings.Compare(a.Table, b.Table) })
	return out
}

// copyTables are the tables to work on: the ones asked for, or every
// comparable table of the copy.
func copyTables(cp *sqlite3.Conn, asked []protocol.RewindTable) ([]string, error) {
	if len(asked) > 0 {
		var out []string
		for _, t := range asked {
			if t.DB != "" && t.DB != "main" {
				return nil, fmt.Errorf("%s.%s: a SQLite database has one schema, main", t.DB, t.Table)
			}
			if t.Table == "" || strings.HasPrefix(t.Table, "sqlite_") {
				return nil, fmt.Errorf("%q can't be compared", t.Table)
			}
			out = append(out, t.Table)
		}
		return out, nil
	}
	tl, err := tableList(cp)
	if err != nil {
		return nil, err
	}
	var out []string
	for name, t := range tl {
		if t.Kind == "table" {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	if len(out) > maxCompareTables {
		out = out[:maxCompareTables]
	}
	return out, nil
}

func (e *Engine) rewindCompare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	_, cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer cp.Close()
	defer prod.Close()
	defer withInterrupt(ctx, prod)()
	tables, err := copyTables(cp, p.Tables)
	if err != nil {
		return nil, err
	}
	busy := e.busyFor(db.ID)
	res := &protocol.RewindCompareResult{CopyID: p.CopyID}
	var missing, changed int64
	var touched []string
	for _, t := range tables {
		d, err := compareTable(ctx, cp, prod, t)
		if err != nil {
			busy.note(err)
			return nil, fmt.Errorf("comparing %s: %w", t, err)
		}
		res.Tables = append(res.Tables, d)
		missing += d.MissingInProduction
		changed += d.Changed
		if d.MissingInProduction+d.Changed > 0 {
			touched = append(touched, t)
		}
		skipped := ""
		if d.Skipped != "" {
			skipped = " (not compared: " + d.Skipped + ")"
		}
		tl.Printf("%s: %d missing in production, %d changed, %d added since%s", t, d.MissingInProduction, d.Changed, d.OnlyInProduction, skipped)
	}
	if missing+changed == 0 {
		res.Summary = fmt.Sprintf("No rows are missing or changed in the %d tables compared.", len(res.Tables))
	} else {
		res.Summary = fmt.Sprintf("%s rows are missing from production and %s changed, in %d tables (%s).",
			commas(missing), commas(changed), len(touched), strings.Join(firstN(touched, 3), ", "))
	}
	return res, nil
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(slices.Clone(s[:n]), fmt.Sprintf("and %d more", len(s)-n))
}

// copyAlias is the copy's name when attached to production.
const copyAlias = "rowsafe_copy"

func (e *Engine) rewindRows(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if p.IncludeChanged {
		return nil, errors.New("SQLite rows are only brought back when they're missing; Rowsafe never overwrites a row that exists")
	}
	if len(p.Tables) == 0 {
		return nil, errors.New("pick the tables to bring rows back into")
	}
	if fs := networkFS(filepath.Dir(db.SocketDir)); fs != "" {
		return nil, fmt.Errorf("the database is on a network filesystem (%s): Rowsafe doesn't write to it", fs)
	}
	rec, cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer prod.Close()
	defer withInterrupt(ctx, prod)()
	tables, err := copyTables(cp, p.Tables)
	if err != nil {
		cp.Close()
		return nil, err
	}
	// Count first: over the limit, nothing is changed.
	limit := p.MaxRows
	if limit <= 0 {
		limit = defaultMaxRows
	}
	var total int64
	metas := map[string]tableMeta{}
	cl, err := tableList(cp)
	if err != nil {
		cp.Close()
		return nil, err
	}
	for _, t := range tables {
		d, err := compareTable(ctx, cp, prod, t)
		if err != nil {
			cp.Close()
			return nil, err
		}
		if d.Skipped != "" {
			cp.Close()
			return nil, fmt.Errorf("%s can't be brought back: %s", t, d.Skipped)
		}
		total += d.MissingInProduction
		m, err := describeTable(cp, cl[t])
		if err != nil {
			cp.Close()
			return nil, err
		}
		metas[t] = m
	}
	cp.Close()
	if total > limit {
		return nil, fmt.Errorf("that would write %s rows, more than the limit of %s: nothing was changed; pick fewer tables", commas(total), commas(limit))
	}
	res := &protocol.RewindRowsResult{}
	if total == 0 {
		res.Summary = "Nothing needed to be brought back: production already has these rows."
		for _, t := range tables {
			res.Tables = append(res.Tables, protocol.RewindTableRows{RewindTable: protocol.RewindTable{DB: "main", Table: t}})
		}
		return res, nil
	}
	busy := e.busyFor(db.ID)
	copyPath, err := realPath(rec.file())
	if err != nil {
		return nil, err
	}
	if err := prod.Exec(`ATTACH DATABASE ` + quoteLit(copyPath) + ` AS ` + copyAlias); err != nil {
		return nil, err
	}
	defer func() { _ = prod.Exec(`DETACH DATABASE ` + copyAlias) }()
	// Foreign keys are checked when the transaction ends: rows whose
	// parent row is still missing stop everything.
	if err := prod.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		return nil, err
	}
	if err := prod.BusyTimeout(10 * time.Second); err != nil {
		return nil, err
	}
	if err := prod.Exec(`BEGIN IMMEDIATE`); err != nil {
		busy.note(err)
		return nil, fmt.Errorf("your app held the database's write lock: %w; try again in a moment", err)
	}
	committed := false
	defer func() {
		if !committed {
			rollback(prod)
		}
	}()
	if err := prod.Exec(`PRAGMA defer_foreign_keys = ON`); err != nil {
		return nil, err
	}
	var parts []string
	for _, t := range tables {
		out, err := bringBack(prod, metas[t], tl)
		res.Tables = append(res.Tables, out)
		if err != nil {
			return nil, fmt.Errorf("%s: %w (nothing was changed)", t, err)
		}
		if out.Inserted > 0 {
			parts = append(parts, fmt.Sprintf("%s in %s", commas(out.Inserted), t))
		}
		tl.Printf("%s: %d rows brought back, %d not brought back (another row holds one of their unique values)", t, out.Inserted, out.Conflicts)
	}
	if err := prod.Exec(`COMMIT`); err != nil {
		busy.note(err)
		if errors.Is(err, sqlite3.CONSTRAINT) {
			return nil, errors.New("some of these rows point at rows (through foreign keys) that are missing in production too: " +
				"bring the related tables back together (the comparison lists them). Nothing was changed")
		}
		return nil, fmt.Errorf("committing: %w (nothing was changed)", err)
	}
	committed = true
	if len(parts) == 0 {
		res.Summary = "Nothing was brought back: every missing row conflicts with a row production has now."
	} else {
		res.Summary = "Brought back " + strings.Join(parts, ", ") + "."
	}
	return res, nil
}

// bringBack inserts the copy's rows missing from production (inside the
// caller's transaction); it never changes an existing row.
func bringBack(prod *sqlite3.Conn, t tableMeta, tl agent.TaskLogger) (protocol.RewindTableRows, error) {
	out := protocol.RewindTableRows{RewindTable: protocol.RewindTable{DB: "main", Table: t.Name}}
	pl, err := tableList(prod)
	if err != nil {
		return out, err
	}
	if _, ok := pl[t.Name]; !ok {
		if err := recreateTable(prod, t); err != nil {
			return out, fmt.Errorf("creating the table again: %w", err)
		}
		tl.Printf("%s was dropped from production: created it again with its indexes", t.Name)
		pl, _ = tableList(prod)
	}
	pt, err := describeTable(prod, pl[t.Name])
	if err != nil {
		return out, err
	}
	cols, _ := commonColumns(t, pt)
	ins := quoteAll(cols)
	sel := make([]string, len(cols))
	for i, c := range cols {
		sel[i] = "c." + quoteIdent(c)
	}
	if len(t.Key) == 0 && t.IntegerPK == "" {
		// Keep the row's number (its key here).
		ins = append([]string{"rowid"}, ins...)
		sel = append([]string{"c.rowid"}, sel...)
	}
	var match []string
	pk, ck := t.keyCols("p."), t.keyCols("c.")
	for i := range pk {
		match = append(match, pk[i]+" IS "+ck[i])
	}
	src := fmt.Sprintf(`FROM %s.%s AS c WHERE NOT EXISTS (SELECT 1 FROM main.%s AS p WHERE %s)`,
		copyAlias, quoteIdent(t.Name), quoteIdent(t.Name), strings.Join(match, " AND "))
	want, err := queryInt(prod, `SELECT count(*) `+src)
	if err != nil {
		return out, err
	}
	if want == 0 {
		return out, nil
	}
	before := prod.TotalChanges()
	q := fmt.Sprintf(`INSERT OR IGNORE INTO main.%s (%s) SELECT %s %s`, quoteIdent(t.Name), strings.Join(ins, ", "), strings.Join(sel, ", "), src)
	if err := prod.Exec(q); err != nil {
		return out, err
	}
	out.Inserted = prod.TotalChanges() - before
	out.Conflicts = max(want-out.Inserted, 0)
	return out, nil
}

// recreateTable creates a table dropped from production again from the
// copy's definition, with its indexes (not its triggers).
func recreateTable(prod *sqlite3.Conn, t tableMeta) error {
	if t.SQL == "" {
		return errors.New("the copy has no definition for it")
	}
	if err := prod.Exec(t.SQL); err != nil {
		return err
	}
	var idx []string
	err := queryRows(prod, fmt.Sprintf(`SELECT sql FROM %s.sqlite_schema WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL`, copyAlias),
		func(s *sqlite3.Stmt) error { idx = append(idx, s.ColumnText(0)); return nil }, t.Name)
	if err != nil {
		return err
	}
	for _, q := range idx {
		if err := prod.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// ---- copies across agent restarts, expiry, heartbeat

// recoverCopies runs at start: interrupted restores and leftovers are
// removed, leftover restore tests too.
func (e *Engine) recoverCopies(env agent.EngineEnv) {
	cs := e.copyState(env)
	known := map[string]bool{}
	for _, r := range cs.all() {
		known[filepath.Base(r.Dir)] = true
		if r.Status != protocol.RewindCopyReady {
			_ = os.RemoveAll(r.Dir)
			_ = cs.remove(r.ID)
			env.Log.Warn("removed a SQLite copy whose restore was interrupted", "copy_id", r.ID)
		}
	}
	if entries, err := os.ReadDir(copyRoot(env)); err == nil {
		for _, ent := range entries {
			name := ent.Name()
			if !ent.IsDir() || known[name] || name == keptDirName || strings.HasPrefix(name, "inplace-") {
				continue
			}
			_ = os.RemoveAll(filepath.Join(copyRoot(env), name))
		}
	}
	_ = os.RemoveAll(drillRoot(env))
}

// expireCopies deletes copies past their expiry.
func (e *Engine) expireCopies(env agent.EngineEnv, now time.Time) {
	cs := e.copyState(env)
	for _, r := range cs.all() {
		if r.Status != protocol.RewindCopyReady || now.Before(r.Expires) {
			continue
		}
		if err := os.RemoveAll(r.Dir); err != nil {
			env.Log.Error("removing an expired SQLite copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		_ = cs.remove(r.ID)
	}
}

// RewindStates reports the copies and kept files (heartbeat).
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range e.copyState(env).all() {
		exp := r.Expires
		out = append(out, protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindCopy, Status: r.Status,
			SizeBytes: r.SizeBytes, Expires: &exp, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.file()})
	}
	return append(out, e.kept(env).States()...)
}

// SetRewindExpiries applies Extend from the control plane.
func (e *Engine) SetRewindExpiries(env agent.EngineEnv, exps []protocol.RewindExpiry) {
	cs := e.copyState(env)
	now := time.Now()
	for _, x := range exps {
		if r, ok := cs.get(x.ID); ok && !x.Expires.Equal(r.Expires) {
			r.Expires = clampExpiry(x.Expires, now)
			_ = cs.put(r)
		}
	}
}
