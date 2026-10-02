package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind for ClickHouse: a copy of the server as it was at a backup or a
// Mark, restored next to production into a temporary server that stays up
// until it expires; a comparison of its tables with production's; and
// bringing rows back. Rows have no key in ClickHouse, so they are compared
// on all their columns, as multisets (a row is missing when production has
// fewer copies of it than the copy). The heavy work happens in the copy:
// production only sends a hash and a count per distinct row, and rows
// brought back stream from the copy straight into production. Everything
// stays on this server: only names and counts are reported.

const (
	defaultCopyHours = 24
	maxCopyAge       = 7 * 24 * time.Hour
	// compareMaxRows caps the rows compared per table.
	compareMaxRows = 100_000_000
	// defaultMaxRows is the most rows one bring-back writes.
	defaultMaxRows = 10_000_000
)

func copyRoot(env agent.EngineEnv) string { return filepath.Join(env.Config.RewindDir, "clickhouse") }

// copyRecord is a copy the engine keeps (<state>/copies.json).
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	Port        int                   `json:"port"` // production's
	Dir         string                `json:"dir"`
	Status      string                `json:"status"` // protocol.RewindCopyRestoring | RewindCopyReady
	Target      protocol.RewindTarget `json:"target"`
	Backup      string                `json:"backup,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	SizeBytes   int64                 `json:"size_bytes"`
}

type copyStore struct {
	mu      sync.Mutex
	path    string
	records map[string]copyRecord
	running map[string]context.CancelFunc
}

func (e *Engine) copyState(env agent.EngineEnv) *copyStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.copies == nil {
		cs := &copyStore{path: filepath.Join(env.StateDir, "copies.json"), records: map[string]copyRecord{}, running: map[string]context.CancelFunc{}}
		if data, err := os.ReadFile(cs.path); err == nil {
			var list []copyRecord
			if err := json.Unmarshal(data, &list); err != nil {
				env.Log.Error("reading ClickHouse copies state; starting empty", "err", err)
			}
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

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	target := restoreTarget{Mark: p.Target.Mark, BackupSet: p.Target.BackupSet}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if (target.Mark == "") == target.Time.IsZero() {
		return nil, errors.New("pick a moment or a Mark (exactly one)")
	}
	if target.Mark != "" && !markNameRE.MatchString(target.Mark) {
		return nil, fmt.Errorf("invalid Mark name %q", target.Mark)
	}
	if target.BackupSet != "" && !validLabel(target.BackupSet) {
		return nil, fmt.Errorf("invalid backup %q", target.BackupSet)
	}
	cs := e.copyState(env)
	if r, ok := cs.forDatabase(db.ID); ok {
		if r.ID == p.CopyID && r.Status == protocol.RewindCopyReady {
			return e.copyResult(ctx, r)
		}
		return nil, errors.New("this database already has a copy: delete it before restoring another")
	}
	if _, _, err := clickhouseBinary(); err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()

	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	b, err := pickBackup(ctx, r, target)
	if err != nil {
		return nil, err
	}
	root := copyRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(b.DataBytes)*drillSpaceFactor)+512<<20); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Port: db.Port, Dir: filepath.Join(root, p.CopyID), Backup: b.Label,
		Status: protocol.RewindCopyRestoring, Target: p.Target, CreatedAt: now, Expires: clampExpiry(p.Expires, now)}
	s, err := newScratch(root, p.CopyID, b.Macros, b.needsKeeper())
	if err != nil {
		return nil, err
	}
	if b.needsKeeper() {
		tl.Printf("ClickHouse Keeper runs for this copy because it has replicated tables; " +
			"its internal port listens on all interfaces while the copy exists")
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
		_, _ = s.remove()
		return nil, err
	}
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		if _, rerr := s.remove(); rerr != nil {
			env.Log.Error("removing a failed copy", "dir", s.Dir, "err", rerr)
		}
		_ = cs.remove(rec.ID)
		return nil, err
	}
	tl.Printf("restoring a copy of %s as of %s (backup %s) into a temporary ClickHouse server (127.0.0.1 only)",
		db.Name, target.describe(), b.Label)
	c, err := s.start(cctx, env)
	if err != nil {
		return fail(err)
	}
	if _, err := restoreInto(cctx, env, r, b, c, tl); err != nil {
		if cctx.Err() != nil && ctx.Err() == nil {
			return fail(errors.New("the copy was deleted while it was being restored"))
		}
		return fail(err)
	}
	rec.Status = protocol.RewindCopyReady
	stopped := b.StoppedAt
	rec.RecoveredTo = &stopped
	rec.SizeBytes = dirSize(s.dataDir())
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
	s := scratchAt(rec.Dir)
	c, err := s.client()
	if err == nil {
		err = c.ping(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	dbs, _, err := restoredDatabases(ctx, c)
	if err != nil {
		return nil, err
	}
	tables := 0
	for _, d := range dbs {
		tables += d.Tables
	}
	st, _ := s.loadState()
	when := "the backup"
	if rec.RecoveredTo != nil {
		when = rec.RecoveredTo.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return &protocol.RewindCopyResult{CopyID: rec.ID, RecoveredTo: rec.RecoveredTo, SizeBytes: rec.SizeBytes, Databases: dbs,
		Port: st.HTTPPort, Expires: rec.Expires,
		Summary: fmt.Sprintf("The copy is ready: %d databases (%d tables, %s) as of %s. It is deleted by itself on %s.",
			len(dbs), tables, humanBytes(rec.SizeBytes), when, rec.Expires.UTC().Format("2006-01-02 15:04 UTC"))}, nil
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
		for range 240 {
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
	freed, err := scratchAt(rec.Dir).remove()
	if err != nil {
		return nil, err
	}
	if err := cs.remove(p.CopyID); err != nil {
		return nil, err
	}
	tl.Printf("deleted the copy, freeing %s", humanBytes(freed))
	return &protocol.RewindDropResult{CopyID: p.CopyID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the copy (%s freed).", humanBytes(freed))}, nil
}

// readyCopy connects to a database's ready copy and production.
func (e *Engine) readyCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, id string) (*client, *client, error) {
	rec, ok := e.copyState(env).get(id)
	if !ok || rec.DatabaseID != db.ID {
		return nil, nil, errors.New("there is no such copy (it expired or was deleted): restore a new one")
	}
	if rec.Status != protocol.RewindCopyReady {
		return nil, nil, errors.New("the copy is still being restored")
	}
	cp, err := scratchAt(rec.Dir).client()
	if err == nil {
		err = cp.ping(ctx)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, nil, err
	}
	return cp, prod, nil
}

// ---- comparing a table

type column struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Kind string `json:"default_kind"`
}

func columns(ctx context.Context, c *client, db, table string) ([]column, error) {
	return query[column](ctx, c, `SELECT name, type, default_kind FROM system.columns
		WHERE database = {db:String} AND table = {table:String} ORDER BY position`, map[string]string{"db": db, "table": table})
}

// tableCmp is one table being compared between the copy and production.
type tableCmp struct {
	t      protocol.RewindTable
	engine string
	cols   []string // quoted, the stored columns both sides have (same type)
	final  bool
	// key is the ReplacingMergeTree sorting key, when both sides have the
	// same one: a row whose key is still in production was changed, not
	// deleted.
	key string
	// version is set when a ReplacingMergeTree has a version column.
	version bool
	// prodHashes is the copy's table holding production's rows (hash,
	// key hash, count).
	prodHashes string
}

func (tc tableCmp) from() string {
	s := tableName(tc.t.DB, tc.t.Table)
	if tc.final {
		s += " FINAL"
	}
	return s
}

// rowHash hashes a row's binary form (RowBinary: exact, NULL apart from
// 0, the same in every ClickHouse version, unlike hashing the values).
func (tc tableCmp) rowHash() string {
	return "sipHash128(formatRow('RowBinary', " + strings.Join(tc.cols, ", ") + "))"
}

func (tc tableCmp) keyHash() string {
	if tc.key == "" {
		return "toFixedString('', 16)"
	}
	return "sipHash128(formatRow('RowBinary', " + tc.key + "))"
}

// merged is a subquery of every distinct row: h (its hash), k (its key's
// hash in the copy), c (copies in the copy) and n (copies in production).
// Inner aliases start with __rs_ so they never shadow a table's columns.
func (tc tableCmp) merged() string {
	return "SELECT __rs_h AS h, max(__rs_k) AS k, sum(__rs_c) AS c, sum(__rs_n) AS n FROM (" +
		"SELECT " + tc.rowHash() + " AS __rs_h, " + tc.keyHash() + " AS __rs_k, toInt64(1) AS __rs_c, toInt64(0) AS __rs_n FROM " + tc.from() +
		" UNION ALL SELECT h AS __rs_h, toFixedString('', 16) AS __rs_k, toInt64(0) AS __rs_c, toInt64(n) AS __rs_n FROM " + tc.prodHashes +
		") GROUP BY __rs_h"
}

// inProd is the condition "this copy row's key is still in production".
func (tc tableCmp) inProd() string {
	if tc.key == "" {
		return "0"
	}
	return "(k IN (SELECT k FROM " + tc.prodHashes + "))"
}

// comparer compares tables of one copy with production.
type comparer struct {
	cp, prod   *client
	copyTables map[string]tableInfo
	prodTables map[string]tableInfo
	temps      []string
}

func newComparer(ctx context.Context, cp, prod *client) (*comparer, error) {
	cm := &comparer{cp: cp, prod: prod, copyTables: map[string]tableInfo{}, prodTables: map[string]tableInfo{}}
	ct, err := listTables(ctx, cp)
	if err != nil {
		return nil, err
	}
	for _, t := range ct {
		if t.DB != scratchDB {
			cm.copyTables[t.key()] = t
		}
	}
	pt, err := listTables(ctx, prod)
	if err != nil {
		return nil, err
	}
	for _, t := range pt {
		cm.prodTables[t.key()] = t
	}
	if err := cp.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(scratchDB)+" ENGINE = Atomic", nil); err != nil {
		return nil, err
	}
	return cm, nil
}

// close drops the comparison's own tables in the copy.
func (cm *comparer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, t := range cm.temps {
		_ = cm.cp.exec(ctx, "DROP TABLE IF EXISTS "+t+" SYNC", nil)
	}
}

func (cm *comparer) temp(prefix string) string {
	n := tableName(scratchDB, randomID(prefix))
	cm.temps = append(cm.temps, n)
	return n
}

// tables are the tables to work on: the ones asked for, or every table of
// every database in the copy.
func (cm *comparer) tables(asked []protocol.RewindTable) ([]protocol.RewindTable, error) {
	if len(asked) > 0 {
		for _, t := range asked {
			if t.DB == "" || t.Table == "" || isCopyInternal(t.DB) {
				return nil, fmt.Errorf("%s.%s can't be compared", t.DB, t.Table)
			}
		}
		return asked, nil
	}
	var out []protocol.RewindTable
	keys := make([]string, 0, len(cm.copyTables))
	for k := range cm.copyTables {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		t := cm.copyTables[k]
		if !isInner(t.Name) {
			out = append(out, protocol.RewindTable{DB: t.DB, Table: t.Name})
		}
	}
	if len(out) > 500 {
		out = out[:500]
	}
	return out, nil
}

// compare counts, on all their columns, the copy's rows missing from
// production, changed there (ReplacingMergeTree: same key, other values),
// and production's rows added since. tc is nil when the table was skipped.
func (cm *comparer) compare(ctx context.Context, t protocol.RewindTable) (protocol.RewindTableDiff, *tableCmp, error) {
	d := protocol.RewindTableDiff{RewindTable: t}
	ct, ok := cm.copyTables[t.DB+"."+t.Table]
	if !ok {
		d.Skipped = "not in the copy"
		return d, nil, nil
	}
	d.SizeBytes = ct.Bytes
	switch {
	case isInner(ct.Name):
		d.Skipped = "a materialized view's own table (its rows come from other tables)"
		return d, nil, nil
	case engineFamily(ct.Engine) == "view":
		d.Skipped = "a view (its rows come from other tables)"
		return d, nil, nil
	case engineFamily(ct.Engine) == "external":
		d.Skipped = "a " + ct.Engine + " table (its rows live in another system)"
		return d, nil, nil
	case engineFamily(ct.Engine) != "data":
		d.Skipped = "a " + ct.Engine + " table (it holds no rows to compare)"
		return d, nil, nil
	}
	if ct.Rows != nil && *ct.Rows > compareMaxRows {
		d.Skipped = fmt.Sprintf("too large to compare here (%s rows)", commas(*ct.Rows))
		return d, nil, nil
	}
	tc := &tableCmp{t: t, engine: ct.Engine, final: usesFinal(ct.Engine)}
	pt, inProd := cm.prodTables[t.DB+"."+t.Table]
	if !inProd {
		n, err := cm.cp.scalar(ctx, "SELECT count() FROM "+tc.from(), nil)
		if err != nil {
			return d, nil, err
		}
		d.MissingInProduction, _ = strconv.ParseInt(n, 10, 64)
		d.Note = "This table was dropped from production since. Rowsafe brings rows back only into tables that exist."
		return d, nil, nil
	}
	cc, err := columns(ctx, cm.cp, t.DB, t.Table)
	if err != nil {
		return d, nil, err
	}
	pc, err := columns(ctx, cm.prod, t.DB, t.Table)
	if err != nil {
		return d, nil, err
	}
	prodType := map[string]string{}
	for _, c := range pc {
		if c.Kind == "" || c.Kind == "DEFAULT" {
			prodType[c.Name] = c.Type
		}
	}
	var differ []string
	for _, c := range cc {
		if c.Kind != "" && c.Kind != "DEFAULT" {
			continue
		}
		if prodType[c.Name] == c.Type {
			tc.cols = append(tc.cols, quoteIdent(c.Name))
			delete(prodType, c.Name)
		} else {
			differ = append(differ, c.Name)
		}
	}
	for name := range prodType {
		differ = append(differ, name)
	}
	if len(tc.cols) == 0 {
		d.Skipped = "its columns all changed since"
		return d, nil, nil
	}
	if len(differ) > 0 {
		slices.Sort(differ)
		d.Note = fmt.Sprintf("Compared on the %d columns both have: %s changed since.", len(tc.cols), strings.Join(firstN(differ, 3), ", "))
	}
	if mergeEngine(ct.Engine) == "ReplacingMergeTree" {
		if ct.SortingKey != "" && ct.SortingKey == pt.SortingKey && len(differ) == 0 {
			tc.key = ct.SortingKey
		}
		tc.version = replacingVersion(ct.EngineFull)
	}
	if len(pt.Dependents) > 0 {
		d.Note = strings.TrimSpace(d.Note + " " + fmt.Sprintf("Rows brought back here also go through %d materialized views (%s).",
			len(pt.Dependents), strings.Join(firstN(pt.Dependents, 3), ", ")))
	}
	// Production's rows, one hash and count per distinct row, go into the
	// copy; production only reads its table once, on 2 threads.
	tc.prodHashes = cm.temp("p_")
	if err := cm.cp.exec(ctx, "CREATE TABLE "+tc.prodHashes+" (h FixedString(16), k FixedString(16), n UInt64) ENGINE = MergeTree ORDER BY h", nil); err != nil {
		return d, nil, err
	}
	src := "SELECT " + tc.rowHash() + " AS __rs_h, any(" + tc.keyHash() + ") AS __rs_k, count() AS __rs_n FROM " + tc.from() + " GROUP BY __rs_h"
	if err := pipe(ctx, cm.prod, src, map[string]string{"max_threads": "2", "max_bytes_before_external_group_by": "1000000000"},
		cm.cp, "INSERT INTO "+tc.prodHashes+" FORMAT RowBinary", nil); err != nil {
		return d, nil, fmt.Errorf("reading production's %s.%s: %w", t.DB, t.Table, err)
	}
	type counts struct {
		Missing int64 `json:"missing"`
		Changed int64 `json:"changed"`
		Added   int64 `json:"added"`
	}
	rows, err := query[counts](ctx, cm.cp, "SELECT toInt64(sumIf(c - n, c > n AND NOT "+tc.inProd()+")) AS missing, "+
		"toInt64(sumIf(c - n, c > n AND "+tc.inProd()+")) AS changed, toInt64(sumIf(n - c, n > c)) AS added FROM ("+tc.merged()+")", nil)
	if err != nil {
		return d, nil, err
	}
	if len(rows) == 1 {
		d.MissingInProduction, d.Changed = rows[0].Missing, rows[0].Changed
		d.OnlyInProduction = max(rows[0].Added-rows[0].Changed, 0)
	}
	return d, tc, nil
}

// replacingVersion says whether a ReplacingMergeTree engine (engine_full)
// has a version column: ReplacingMergeTree(ver), or after the replication
// path and replica name of a replicated one.
func replacingVersion(engineFull string) bool {
	open := strings.IndexByte(engineFull, '(')
	if open < 0 {
		return false
	}
	end := strings.IndexByte(engineFull[open:], ')')
	if end < 0 {
		return false
	}
	args := strings.TrimSpace(engineFull[open+1 : open+end])
	if args == "" {
		return false
	}
	for _, a := range strings.Split(args, ",") {
		if a = strings.TrimSpace(a); a != "" && !strings.HasPrefix(a, "'") {
			return true
		}
	}
	return false
}

// pipe streams the answer of src (on from) into the INSERT ... FORMAT
// statement insert (on to).
func pipe(ctx context.Context, from *client, src string, fromSettings map[string]string, to *client, insert string, toSettings map[string]string) error {
	format := insert[strings.LastIndex(insert, " ")+1:]
	s := map[string]string{"default_format": format}
	for k, v := range fromSettings {
		s[k] = v
	}
	resp, err := from.request(ctx, src, nil, s, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	r, err := to.request(ctx, insert, nil, toSettings, resp.Body)
	if err != nil {
		return err
	}
	r.Body.Close()
	return nil
}

func (e *Engine) rewindCompare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	cm, err := newComparer(ctx, cp, prod)
	if err != nil {
		return nil, err
	}
	defer cm.close()
	tables, err := cm.tables(p.Tables)
	if err != nil {
		return nil, err
	}
	res := &protocol.RewindCompareResult{CopyID: p.CopyID}
	var missing, changed int64
	var touched []string
	for _, t := range tables {
		d, _, err := cm.compare(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", t.DB, t.Table, err)
		}
		res.Tables = append(res.Tables, d)
		missing += d.MissingInProduction
		changed += d.Changed
		if d.MissingInProduction+d.Changed > 0 {
			touched = append(touched, t.DB+"."+t.Table)
		}
		tl.Printf("%s.%s: %d missing in production, %d changed, %d added since%s", t.DB, t.Table, d.MissingInProduction, d.Changed,
			d.OnlyInProduction, skippedNote(d.Skipped))
	}
	switch {
	case missing+changed == 0:
		res.Summary = fmt.Sprintf("No rows are missing or changed in the %d tables compared.", len(res.Tables))
	case changed == 0:
		res.Summary = fmt.Sprintf("%s rows are missing from production, in %d tables (%s).",
			commas(missing), len(touched), strings.Join(firstN(touched, 3), ", "))
	default:
		res.Summary = fmt.Sprintf("%s rows are missing from production and %s changed, in %d tables (%s).",
			commas(missing), commas(changed), len(touched), strings.Join(firstN(touched, 3), ", "))
	}
	return res, nil
}

func skippedNote(s string) string {
	if s == "" {
		return ""
	}
	return " (skipped: " + s + ")"
}

func (e *Engine) rewindRows(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("pick the tables to bring rows back into")
	}
	cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	cm, err := newComparer(ctx, cp, prod)
	if err != nil {
		return nil, err
	}
	defer cm.close()
	tables, err := cm.tables(p.Tables)
	if err != nil {
		return nil, err
	}
	// Check and count first: over the limit, or a table rows can't go
	// back into, and nothing is changed.
	limit := p.MaxRows
	if limit <= 0 {
		limit = defaultMaxRows
	}
	type planned struct {
		d  protocol.RewindTableDiff
		tc *tableCmp
	}
	var plans []planned
	var total int64
	for _, t := range tables {
		pt, ok := cm.prodTables[t.DB+"."+t.Table]
		if ok {
			if why := rowsRefusal(pt.Engine); why != "" {
				return nil, fmt.Errorf("rows can't be brought back into %s.%s: %s. Nothing was changed.", t.DB, t.Table, why)
			}
		}
		d, tc, err := cm.compare(ctx, t)
		if err != nil {
			return nil, fmt.Errorf("%s.%s: %w", t.DB, t.Table, err)
		}
		switch {
		case d.Skipped != "":
			return nil, fmt.Errorf("rows can't be brought back into %s.%s: %s. Nothing was changed.", t.DB, t.Table, d.Skipped)
		case tc == nil:
			return nil, fmt.Errorf("rows can't be brought back into %s.%s: it no longer exists in production. Nothing was changed.", t.DB, t.Table)
		}
		total += d.MissingInProduction
		if p.IncludeChanged && !tc.version {
			total += d.Changed
		}
		plans = append(plans, planned{d, tc})
	}
	if total > limit {
		return nil, fmt.Errorf("that would write %s rows, more than the limit of %s: nothing was changed; pick fewer tables",
			commas(total), commas(limit))
	}
	res := &protocol.RewindRowsResult{}
	var parts, notes []string
	for _, pl := range plans {
		out, err := cm.bringBack(ctx, pl.tc, p.IncludeChanged)
		res.Tables = append(res.Tables, out)
		if err != nil {
			return res, fmt.Errorf("%s.%s: %w (rows written before this are kept; running it again finishes the job without duplicates)",
				pl.d.DB, pl.d.Table, err)
		}
		switch {
		case out.Inserted > 0 && out.Updated > 0:
			parts = append(parts, fmt.Sprintf("brought back %s rows in %s.%s (and changed %s back)", commas(out.Inserted), pl.d.DB, pl.d.Table, commas(out.Updated)))
		case out.Inserted > 0:
			parts = append(parts, fmt.Sprintf("brought back %s rows in %s.%s", commas(out.Inserted), pl.d.DB, pl.d.Table))
		case out.Updated > 0:
			parts = append(parts, fmt.Sprintf("changed %s rows back in %s.%s", commas(out.Updated), pl.d.DB, pl.d.Table))
		}
		if out.Conflicts > 0 {
			notes = append(notes, fmt.Sprintf("%s changed rows of %s.%s weren't changed back: production holds a newer version of them",
				commas(out.Conflicts), pl.d.DB, pl.d.Table))
		}
		if pt := cm.prodTables[pl.d.DB+"."+pl.d.Table]; len(pt.Dependents) > 0 && out.Inserted+out.Updated > 0 {
			notes = append(notes, fmt.Sprintf("the rows of %s.%s also went through its materialized views (%s)", pl.d.DB, pl.d.Table,
				strings.Join(firstN(pt.Dependents, 3), ", ")))
		}
		tl.Printf("%s.%s: %d brought back, %d changed back, %d left as they are", pl.d.DB, pl.d.Table, out.Inserted, out.Updated, out.Conflicts)
	}
	if len(parts) == 0 {
		res.Summary = "Nothing needed to be brought back: production already has these rows."
	} else {
		res.Summary = strings.ToUpper(parts[0][:1]) + strings.Join(parts, ", ")[1:] + "."
	}
	if len(notes) > 0 {
		res.Summary += " Note: " + strings.Join(notes, "; ") + "."
	}
	return res, nil
}

// bringBack inserts into production the copy's rows it has fewer copies
// of: rows deleted since, and with changed (a ReplacingMergeTree without a
// version column) the old values of rows changed since. The rows stream
// from the copy straight into production.
func (cm *comparer) bringBack(ctx context.Context, tc *tableCmp, changed bool) (protocol.RewindTableRows, error) {
	out := protocol.RewindTableRows{RewindTable: tc.t}
	want := cm.temp("m_")
	if err := cm.cp.exec(ctx, "CREATE TABLE "+want+" (h FixedString(16), k UInt64, changed UInt8) ENGINE = MergeTree ORDER BY h", nil); err != nil {
		return out, err
	}
	cond := "c > n AND NOT " + tc.inProd()
	if changed && !tc.version {
		cond = "c > n"
	}
	if err := cm.cp.exec(ctx, "INSERT INTO "+want+" SELECT h, toUInt64(c - n), "+tc.inProd()+" FROM ("+tc.merged()+") WHERE "+cond, nil); err != nil {
		return out, err
	}
	type counts struct {
		Ins int64 `json:"ins"`
		Upd int64 `json:"upd"`
	}
	cs, err := query[counts](ctx, cm.cp, "SELECT toInt64(sumIf(k, changed = 0)) AS ins, toInt64(sumIf(k, changed = 1)) AS upd FROM "+want, nil)
	if err != nil {
		return out, err
	}
	if len(cs) == 1 {
		out.Inserted, out.Updated = cs[0].Ins, cs[0].Upd
	}
	if changed && tc.version {
		n, err := cm.cp.scalar(ctx, "SELECT toInt64(sumIf(c - n, c > n AND "+tc.inProd()+")) FROM ("+tc.merged()+")", nil)
		if err == nil {
			out.Conflicts, _ = strconv.ParseInt(n, 10, 64)
		}
	}
	if out.Inserted+out.Updated == 0 {
		return out, nil
	}
	sel := make([]string, len(tc.cols))
	for i, c := range tc.cols {
		sel[i] = "tupleElement(__rs_r, " + strconv.Itoa(i+1) + ") AS " + c
	}
	src := "SELECT " + strings.Join(sel, ", ") + " FROM (SELECT a.__rs_r AS __rs_r, m.k AS __rs_cnt FROM (SELECT " + tc.rowHash() +
		" AS __rs_h, any(tuple(" + strings.Join(tc.cols, ", ") + ")) AS __rs_r FROM " + tc.from() + " WHERE __rs_h IN (SELECT h FROM " + want +
		") GROUP BY __rs_h) AS a INNER JOIN " + want + " AS m ON a.__rs_h = m.h) ARRAY JOIN range(__rs_cnt) AS __rs_i"
	insert := "INSERT INTO " + tableName(tc.t.DB, tc.t.Table) + " (" + strings.Join(tc.cols, ", ") + ") FORMAT Native"
	err = pipe(ctx, cm.cp, src, nil, cm.prod, insert, map[string]string{"insert_deduplicate": "0", "async_insert": "0"})
	if err != nil {
		out.Inserted, out.Updated = 0, 0
		return out, err
	}
	return out, nil
}

// ---- copies across agent restarts, expiry, heartbeat

// recoverCopies runs at start: interrupted restores are removed, ready
// copies started again, leftovers without a record removed; leftover
// restore tests too.
func (e *Engine) recoverCopies(ctx context.Context, env agent.EngineEnv) {
	cs := e.copyState(env)
	known := map[string]bool{}
	for _, r := range cs.all() {
		known[filepath.Base(r.Dir)] = true
		s := scratchAt(r.Dir)
		switch {
		case r.Status != protocol.RewindCopyReady:
			if _, err := s.remove(); err == nil {
				_ = cs.remove(r.ID)
				env.Log.Warn("removed a ClickHouse copy whose restore was interrupted", "copy_id", r.ID)
			}
		case time.Now().After(r.Expires):
			// expireCopies removes it.
		case s.pid() == 0:
			go func() {
				if _, err := s.start(ctx, env); err != nil {
					env.Log.Error("starting a ClickHouse copy again failed; it stays until it expires or is deleted", "copy_id", r.ID, "err", err)
					return
				}
				env.Log.Info("started a ClickHouse copy again after an agent restart", "copy_id", r.ID)
			}()
		}
	}
	for _, root := range []string{copyRoot(env), drillRoot(env)} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() || known[ent.Name()] && root == copyRoot(env) {
				continue
			}
			dir := filepath.Join(root, ent.Name())
			if _, err := os.Lstat(filepath.Join(dir, scratchMarker)); err != nil {
				continue
			}
			if _, err := scratchAt(dir).remove(); err != nil {
				env.Log.Error("removing a leftover temporary ClickHouse server failed", "dir", dir, "err", err)
			} else {
				env.Log.Warn("removed a leftover temporary ClickHouse server", "dir", dir)
			}
		}
	}
}

// expireCopies deletes copies past their expiry.
func (e *Engine) expireCopies(env agent.EngineEnv, now time.Time) {
	cs := e.copyState(env)
	for _, r := range cs.all() {
		if r.Status != protocol.RewindCopyReady || now.Before(r.Expires) {
			continue
		}
		freed, err := scratchAt(r.Dir).remove()
		if err != nil {
			env.Log.Error("removing an expired ClickHouse copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		_ = cs.remove(r.ID)
		env.Log.Info("removed an expired ClickHouse copy", "copy_id", r.ID, "freed", humanBytes(freed))
	}
}

// RewindStates reports the copies (heartbeat).
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range e.copyState(env).all() {
		exp := r.Expires
		out = append(out, protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindCopy, Status: r.Status,
			SizeBytes: r.SizeBytes, Expires: &exp, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.Dir})
	}
	return append(out, env.Kept().States()...) // rewinds in place (inplace.go)
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
