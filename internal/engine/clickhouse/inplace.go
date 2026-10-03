package clickhouse

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole server in place to a backup or a Mark (and Undo).
//
// ClickHouse keeps no log of its changes, so a rewind goes to a backup (one
// every hour) or a Mark. Nothing is stopped and no table is replaced: the
// data moves between tables, partition by partition, so materialized
// views, dictionaries and everything that points at a table keep pointing
// at the same table.
//
//  1. RESTORE the backup into production under other names
//     (rowsafe_rewind_<tag>_<db>), through the agent's encrypting gateway,
//     like a backup the other way (production keeps running);
//  2. for each table (and each materialized view's own table): copy its
//     current partitions into rowsafe_before_<tag>_<db> (ATTACH PARTITION
//     FROM: hard links, no extra space), then replace them with the
//     restored ones (REPLACE PARTITION FROM) and drop the ones the backup
//     doesn't have. Tables dropped since come back with a rename; tables
//     created since are emptied (their data kept the same way). Other table
//     engines (Log, Memory...) are swapped whole (EXCHANGE TABLES).
//
// Undo does step 2 again from rowsafe_before_* (setting the rewound data
// aside in rowsafe_after_*). A failure puts every table done so far back
// from the copies; an agent restarted in the middle does the same. The
// rowsafe_* databases are never backed up (they stay on this server) and
// are dropped when the kept data expires. Inserts that land while a table's
// partitions are being swapped (a moment per table) may be lost: pause
// writers while it runs. Replicated tables (they share their data through
// Keeper) aren't rewound in place yet.

const (
	cipRestoring = "restoring" // the backup goes into rowsafe_rewind_*: production untouched
	cipSwapping  = "swapping"  // tables are being swapped (Extra["step"] says where)
)

func rewindTag(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:4])
}

func tmpDBName(tag, db string) string    { return "rowsafe_rewind_" + tag + "_" + db }
func beforeDBName(tag, db string) string { return "rowsafe_before_" + tag + "_" + db }
func afterDBName(tag, db string) string  { return "rowsafe_after_" + tag + "_" + db }

// isRewindDB: a database of a rewind in place.
func isRewindDB(name string) bool {
	return strings.HasPrefix(name, "rowsafe_rewind_") || strings.HasPrefix(name, "rowsafe_before_") || strings.HasPrefix(name, "rowsafe_after_")
}

// swapPair is one table a rewind swaps: DB.Table in production, its data
// from SrcTable in the source database.
type swapPair struct {
	DB       string `json:"db"`
	Table    string `json:"table"`
	SrcTable string `json:"src,omitempty"` // in the restored database ("" when the table isn't in the backup)
	// Kind: "parts" (MergeTree: partitions move), "whole" (EXCHANGE
	// TABLES), "create" (dropped since: renamed in), "empty" (created
	// since: its partitions are set aside).
	Kind string `json:"kind"`
}

type chTable struct {
	DB         string `json:"database"`
	Name       string `json:"name"`
	Engine     string `json:"engine"`
	UUID       string `json:"uuid"`
	EngineFull string `json:"engine_full"`
}

func tablesOf(ctx context.Context, c *client, dbs []string) ([]chTable, error) {
	if len(dbs) == 0 {
		return nil, nil
	}
	quoted := make([]string, len(dbs))
	for i, d := range dbs {
		quoted[i] = quoteString(d)
	}
	return query[chTable](ctx, c, "SELECT database, name, engine, toString(uuid) AS uuid, engine_full FROM system.tables WHERE database IN ("+
		strings.Join(quoted, ", ")+") AND NOT is_temporary ORDER BY database, name", nil)
}

// innerOf is the table a materialized view without TO keeps its rows in.
func innerOf(mv chTable, all []chTable) (string, bool) {
	for _, cand := range []string{".inner_id." + mv.UUID, ".inner." + mv.Name} {
		if slices.ContainsFunc(all, func(t chTable) bool { return t.DB == mv.DB && t.Name == cand }) {
			return cand, true
		}
	}
	return "", false
}

// signature is what ATTACH/REPLACE PARTITION FROM needs to match: the
// columns and the engine with its keys and settings.
func signature(ctx context.Context, c *client, db, table string) (string, error) {
	type col struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	cols, err := query[col](ctx, c, "SELECT name, type FROM system.columns WHERE database = {db:String} AND table = {t:String} ORDER BY position",
		map[string]string{"db": db, "t": table})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, x := range cols {
		b.WriteString(x.Name + " " + x.Type + ",")
	}
	return b.String(), nil
}

func partitionsOf(ctx context.Context, c *client, db, table string) ([]string, error) {
	type row struct {
		ID string `json:"partition_id"`
	}
	rows, err := query[row](ctx, c, "SELECT DISTINCT partition_id FROM system.parts WHERE database = {db:String} AND table = {t:String} AND active ORDER BY partition_id",
		map[string]string{"db": db, "t": table})
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out, nil
}

func mergeTree(engine string) bool {
	return strings.HasSuffix(engine, "MergeTree") && !strings.HasPrefix(engine, "Replicated")
}

// planPairs matches production's tables with the restored ones (in
// tmpDBName(tag, db)) and checks each can be swapped.
func planPairs(ctx context.Context, c *client, b backupDoc, tag string) ([]swapPair, error) {
	var dbs []string
	for _, d := range b.Databases {
		dbs = append(dbs, d.Name, tmpDBName(tag, d.Name))
	}
	all, err := tablesOf(ctx, c, dbs)
	if err != nil {
		return nil, err
	}
	find := func(db, name string) (chTable, bool) {
		i := slices.IndexFunc(all, func(t chTable) bool { return t.DB == db && t.Name == name })
		if i < 0 {
			return chTable{}, false
		}
		return all[i], true
	}
	var pairs []swapPair
	var problems []string
	for _, d := range b.Databases {
		tmp := tmpDBName(tag, d.Name)
		seen := map[string]bool{}
		for _, t := range all {
			if t.DB != tmp || isInner(t.Name) {
				continue
			}
			src, dst := t.Name, t.Name
			switch engineFamily(t.Engine) {
			case "data":
			case "view":
				if t.Engine != "MaterializedView" {
					continue
				}
				in, ok := innerOf(t, all)
				if !ok {
					continue // a view with TO: its rows are in that table
				}
				pmv, ok := find(d.Name, t.Name)
				if !ok {
					continue // the view was dropped since: its rows go with it
				}
				pin, ok := innerOf(pmv, all)
				if !ok {
					problems = append(problems, d.Name+"."+t.Name+" (the view now writes to another table)")
					continue
				}
				src, dst = in, pin
			default:
				continue
			}
			seen[dst] = true
			prod, ok := find(d.Name, dst)
			if !ok {
				pairs = append(pairs, swapPair{DB: d.Name, Table: dst, SrcTable: src, Kind: "create"})
				continue
			}
			s1, err1 := signature(ctx, c, d.Name, dst)
			s2, err2 := signature(ctx, c, tmp, src)
			srcT, _ := find(tmp, src)
			if err := errors.Join(err1, err2); err != nil {
				return nil, err
			}
			switch {
			case strings.HasPrefix(prod.Engine, "Replicated") || strings.HasPrefix(prod.Engine, "Shared"):
				problems = append(problems, d.Name+"."+dst+" (a replicated table)")
			case s1 != s2 || prod.Engine != srcT.Engine:
				problems = append(problems, d.Name+"."+dst+" (its columns or engine changed since the backup)")
			case mergeTree(prod.Engine):
				pairs = append(pairs, swapPair{DB: d.Name, Table: dst, SrcTable: src, Kind: "parts"})
			default:
				pairs = append(pairs, swapPair{DB: d.Name, Table: dst, SrcTable: src, Kind: "whole"})
			}
		}
		// Tables created since the backup: emptied, their data kept.
		for _, t := range all {
			if t.DB != d.Name || seen[t.Name] || engineFamily(t.Engine) != "data" || !mergeTree(t.Engine) {
				continue
			}
			if isInner(t.Name) {
				continue // a view created since: left as it is
			}
			pairs = append(pairs, swapPair{DB: d.Name, Table: t.Name, Kind: "empty"})
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("these tables can't be rewound in place: %s. Restore a copy and bring back rows instead", strings.Join(problems, "; "))
	}
	return pairs, nil
}

// swapOne moves one table's data: production's current data goes to the
// aside database, the data of srcDB.SrcTable takes its place. step records
// progress ("aside" before production changes, "swap" after) for a
// rollback.
func swapOne(ctx context.Context, c *client, p swapPair, srcDB, asideDB string, step func(string) error) error {
	prod := tableName(p.DB, p.Table)
	aside := tableName(asideDB, p.Table)
	src := tableName(srcDB, cmpStr(p.SrcTable, p.Table))
	switch p.Kind {
	case "create":
		if err := step("swap"); err != nil {
			return err
		}
		return c.exec(ctx, "RENAME TABLE "+src+" TO "+prod, nil)
	case "whole":
		if err := step("swap"); err != nil {
			return err
		}
		if err := c.exec(ctx, "EXCHANGE TABLES "+prod+" AND "+src, nil); err != nil {
			return err
		}
		return c.exec(ctx, "RENAME TABLE "+src+" TO "+aside, nil)
	}
	if err := step("aside"); err != nil {
		return err
	}
	_ = c.exec(ctx, "DROP TABLE IF EXISTS "+aside+" SYNC", nil) // a previous attempt's
	if err := c.exec(ctx, "CREATE TABLE "+aside+" AS "+prod, nil); err != nil {
		return err
	}
	cur, err := partitionsOf(ctx, c, p.DB, p.Table)
	if err != nil {
		return err
	}
	for _, id := range cur {
		if err := c.exec(ctx, "ALTER TABLE "+aside+" ATTACH PARTITION ID "+quoteString(id)+" FROM "+prod, nil); err != nil {
			return err
		}
	}
	if err := step("swap"); err != nil {
		return err
	}
	var want []string
	if p.Kind == "parts" {
		if want, err = partitionsOf(ctx, c, srcDB, cmpStr(p.SrcTable, p.Table)); err != nil {
			return err
		}
	}
	return replaceParts(ctx, c, prod, src, cur, want)
}

// replaceParts makes dst's partitions those of src: REPLACE the ones src
// has, DROP the others.
func replaceParts(ctx context.Context, c *client, dst, src string, cur, want []string) error {
	for _, id := range want {
		if err := c.exec(ctx, "ALTER TABLE "+dst+" REPLACE PARTITION ID "+quoteString(id)+" FROM "+src, nil); err != nil {
			return err
		}
	}
	for _, id := range cur {
		if !slices.Contains(want, id) {
			if err := c.exec(ctx, "ALTER TABLE "+dst+" DROP PARTITION ID "+quoteString(id), nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// unswapOne puts a table back from the aside database (a rollback).
func unswapOne(ctx context.Context, c *client, p swapPair, srcDB, asideDB, phase string) error {
	prod := tableName(p.DB, p.Table)
	aside := tableName(asideDB, p.Table)
	src := tableName(srcDB, cmpStr(p.SrcTable, p.Table))
	switch p.Kind {
	case "create":
		if phase != "swap" {
			return nil
		}
		if exists(ctx, c, p.DB, p.Table) && !exists(ctx, c, srcDB, cmpStr(p.SrcTable, p.Table)) {
			return c.exec(ctx, "RENAME TABLE "+prod+" TO "+src, nil)
		}
		return nil
	case "whole":
		if phase != "swap" {
			return nil
		}
		if exists(ctx, c, asideDB, p.Table) { // exchanged and renamed: swap back
			if err := c.exec(ctx, "EXCHANGE TABLES "+prod+" AND "+aside, nil); err != nil {
				return err
			}
			return c.exec(ctx, "RENAME TABLE "+aside+" TO "+src, nil)
		}
		if exists(ctx, c, srcDB, cmpStr(p.SrcTable, p.Table)) && phase == "swap" {
			// exchanged, not renamed yet: exchanging again restores it
			return c.exec(ctx, "EXCHANGE TABLES "+prod+" AND "+src, nil)
		}
		return nil
	}
	if phase != "swap" {
		return c.exec(ctx, "DROP TABLE IF EXISTS "+aside+" SYNC", nil) // production untouched
	}
	cur, err := partitionsOf(ctx, c, p.DB, p.Table)
	if err != nil {
		return err
	}
	want, err := partitionsOf(ctx, c, asideDB, p.Table)
	if err != nil {
		return err
	}
	if err := replaceParts(ctx, c, prod, aside, cur, want); err != nil {
		return err
	}
	return c.exec(ctx, "DROP TABLE IF EXISTS "+aside+" SYNC", nil)
}

func exists(ctx context.Context, c *client, db, table string) bool {
	v, err := c.scalar(ctx, "SELECT count() FROM system.tables WHERE database = {db:String} AND name = {t:String}", map[string]string{"db": db, "t": table})
	return err == nil && strings.TrimSpace(v) == "1"
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// swapAll runs swapOne over pairs, recording progress in rec; a failure
// rolls back what was done (rollbackAll).
func swapAll(ctx context.Context, c *client, kept *agent.KeptStore, rec *agent.KeptRecord, pairs []swapPair,
	srcDB, asideDB func(string) string, tl agent.TaskLogger) error {
	for i, p := range pairs {
		if err := c.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(asideDB(p.DB))+" ENGINE = Atomic", nil); err != nil {
			return err
		}
		step := func(phase string) error {
			rec.Extra["step"] = strconv.Itoa(i) + ":" + phase
			return kept.Put(*rec)
		}
		if err := swapOne(ctx, c, p, srcDB(p.DB), asideDB(p.DB), step); err != nil {
			return fmt.Errorf("%s.%s: %w", p.DB, p.Table, err)
		}
	}
	tl.Printf("swapped %d tables", len(pairs))
	return nil
}

// rollbackAll undoes swapAll up to the step recorded in rec.
func rollbackAll(ctx context.Context, c *client, rec agent.KeptRecord, pairs []swapPair, srcDB, asideDB func(string) string) error {
	at, phase, _ := strings.Cut(rec.Extra["step"], ":")
	n, err := strconv.Atoi(at)
	if err != nil {
		return nil // nothing was swapped
	}
	var errs []error
	for i := min(n, len(pairs)-1); i >= 0; i-- {
		ph := "swap"
		if i == n {
			ph = phase
		}
		if err := unswapOne(ctx, c, pairs[i], srcDB(pairs[i].DB), asideDB(pairs[i].DB), ph); err != nil {
			errs = append(errs, fmt.Errorf("%s.%s: %w", pairs[i].DB, pairs[i].Table, err))
		}
	}
	return errors.Join(errs...)
}

func dropDBs(ctx context.Context, c *client, names ...string) {
	for _, n := range names {
		if isRewindDB(n) {
			_ = c.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(n)+" SYNC", nil)
		}
	}
}

func dbSize(ctx context.Context, c *client, names []string) int64 {
	if len(names) == 0 {
		return 0
	}
	quoted := make([]string, len(names))
	for i, n := range names {
		quoted[i] = quoteString(n)
	}
	v, err := c.scalar(ctx, "SELECT sum(bytes_on_disk) FROM system.parts WHERE active AND database IN ("+strings.Join(quoted, ", ")+")", nil)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return n
}

func encodePairs(p []swapPair) string {
	b, _ := json.Marshal(p)
	return string(b)
}

func decodePairs(s string) []swapPair {
	var p []swapPair
	_ = json.Unmarshal([]byte(s), &p)
	return p
}

// rewindInPlace rewinds the server's databases to the backup for p.Target.
func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	kept := env.Kept()
	for _, r := range kept.ForDatabase(db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	target := restoreTarget{Mark: p.Target.Mark, BackupSet: p.Target.BackupSet}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if target.Mark == "" && target.Time.IsZero() && target.BackupSet == "" {
		return nil, errors.New("pick a backup or a Mark to rewind to")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	if in, err := inspect(ctx, c); err == nil {
		if m := missingRewindGrants(in.Grants); len(m) > 0 {
			return nil, fmt.Errorf("Rowsafe's ClickHouse user lacks %s, which a rewind in place needs: run the Rowsafe installer on the server again "+
				"(it updates the user), or restore a copy and bring back rows instead", strings.Join(m, ", "))
		}
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	b, recovered, err := e.pickTarget(ctx, env, db, r, target, tl)
	if err != nil {
		return nil, err
	}
	if b.needsKeeper() {
		return nil, errors.New("the backup has replicated tables (they share their data through ClickHouse Keeper): rewinding them in place isn't available yet. Restore a copy and bring back rows instead")
	}
	if free, err := c.scalar(ctx, "SELECT min(free_space) FROM system.disks", nil); err == nil {
		if n, _ := strconv.ParseInt(strings.TrimSpace(free), 10, 64); n > 0 && n < b.DataBytes*11/10+256<<20 {
			return nil, fmt.Errorf("ClickHouse's disk has %s free: the backup (%s) is restored next to the current data first", humanBytes(n), humanBytes(b.DataBytes))
		}
	}
	tag := rewindTag(p.RewindID)
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: db.ID, Status: protocol.RewindInProgress, CreatedAt: time.Now().UTC(),
		Target: p.Target, KeepDays: p.KeepDays, Phase: cipRestoring, Database: db,
		Extra: map[string]string{"tag": tag, "backup": b.Label}}
	var dbNames []string
	for _, d := range b.Databases {
		dbNames = append(dbNames, d.Name)
	}
	rec.Extra["dbs"] = strings.Join(dbNames, "\n")
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	tmpNames := func() []string {
		var out []string
		for _, d := range dbNames {
			out = append(out, tmpDBName(tag, d))
		}
		return out
	}
	sctx := context.WithoutCancel(ctx)
	abandon := func(err error) (*protocol.RewindInPlaceResult, error) {
		dropDBs(sctx, c, tmpNames()...)
		for _, d := range dbNames {
			dropDBs(sctx, c, beforeDBName(tag, d))
		}
		_ = kept.Remove(rec.ID)
		return nil, err
	}

	// 1. Restore next to production.
	dropDBs(ctx, c, tmpNames()...)
	tl.Printf("restoring %s into production under other names (rowsafe_rewind_%s_*); production keeps running", b.what(), tag)
	if err := e.restoreBeside(ctx, env, r, b, c, tag, tl); err != nil {
		return abandon(err)
	}
	pairs, err := planPairs(ctx, c, b, tag)
	if err != nil {
		return abandon(err)
	}

	// 2. Swap, table by table.
	rec.Phase, rec.Extra["pairs"] = cipSwapping, encodePairs(pairs)
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	src := func(d string) string { return tmpDBName(tag, d) }
	aside := func(d string) string { return beforeDBName(tag, d) }
	tl.Printf("swapping %d tables: their current data is kept in rowsafe_before_%s_*", len(pairs), tag)
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID}
	if err := swapAll(sctx, c, kept, &rec, pairs, src, aside, tl); err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		if rerr := rollbackAll(sctx, c, rec, pairs, src, aside); rerr != nil {
			return res, fmt.Errorf("the rewind failed (%v), and putting the data back failed too: %v. The data from before is in the rowsafe_before_%s_* databases", err, rerr, tag)
		}
		res.RolledBack = true
		_, _ = abandon(nil)
		return res, fmt.Errorf("the rewind failed, and every table was put back as it was (nothing changed): %w", err)
	}
	dropDBs(sctx, c, tmpNames()...)
	until := agent.KeepUntil(p.KeepDays, time.Now())
	var asides []string
	for _, d := range dbNames {
		asides = append(asides, beforeDBName(tag, d))
	}
	delete(rec.Extra, "step")
	rec.Status, rec.Phase, rec.Expires, rec.RecoveredTo = protocol.RewindKeptBefore, "", until, &recovered
	rec.SizeBytes = dbSize(sctx, c, asides)
	rec.Path = "rowsafe_before_" + tag + "_* databases"
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.RecoveredTo, res.OldDataDir, res.KeptUntil = &recovered, rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	to := "backup " + b.Label + " (" + recovered.UTC().Format("15:04 UTC on 2006-01-02") + ")"
	if b.virtualDir != "" {
		to = "how it was at " + recovered.UTC().Format("15:04:05 UTC on 2006-01-02")
	}
	res.Summary = fmt.Sprintf("Rewound %s to %s. The data from before is kept in the rowsafe_before_%s_* databases until %s so you can undo.",
		db.Name, to, tag, until.UTC().Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// restoreBeside restores backup b into production as rowsafe_rewind_<tag>_<db>.
func (e *Engine) restoreBeside(ctx context.Context, env agent.EngineEnv, r *repo, b backupDoc, c *client, tag string, tl agent.TaskLogger) error {
	unlock, err := lockGateway(ctx, tl)
	if err != nil {
		return err
	}
	defer unlock()
	g, err := startGateway(ctx, env, r, b.prefixes(), true, false, b.virtual)
	if err != nil {
		return err
	}
	closeGW := closer(g)
	defer closeGW()
	skip := leftOut(b.Tables)
	var sb strings.Builder
	sb.WriteString("RESTORE ")
	for i, d := range b.Databases {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString("DATABASE " + quoteIdent(d.Name))
		var except []string
		for _, t := range b.Tables {
			if _, ok := skip[t.key()]; ok && t.DB == d.Name {
				except = append(except, tableName(t.DB, t.Name))
			}
		}
		if len(except) > 0 {
			sb.WriteString(" EXCEPT TABLES " + strings.Join(except, ", "))
		}
		sb.WriteString(" AS " + quoteIdent(tmpDBName(tag, d.Name)))
	}
	id := randomID("rowsafe-rewind-")
	sb.WriteString(" FROM " + s3Expr(g, b.dir()) + " SETTINGS id = " + quoteString(id) + ", allow_s3_native_copy = 0, allow_different_database_def = 1")
	if b.Base != "" {
		sb.WriteString(", base_backup = " + s3Expr(g, backupDir(b.Base)))
	}
	progress := func(st opStatus) string {
		if st.TotalSize > 0 {
			return fmt.Sprintf("restoring: %s of %s read", humanBytes(st.BytesRead), humanBytes(st.TotalSize))
		}
		return ""
	}
	if _, err := runAsync(ctx, c, sb.String(), id, "restore", tl, progress, closeGW); err != nil {
		return fmt.Errorf("restoring %s: %w", b.Label, err)
	}
	return nil
}

// rewindUndo puts the data from before the rewind back.
func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return nil, errors.New("there is nothing to undo: the data from before this rewind is no longer kept")
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, errors.New("this rewind was undone already")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	tag := rec.Extra["tag"]
	// Undo swaps every pair back from the before databases: tables renamed
	// in by the rewind (dropped before it) go aside whole.
	var pairs []swapPair
	for _, pr := range decodePairs(rec.Extra["pairs"]) {
		switch pr.Kind {
		case "create":
			pairs = append(pairs, swapPair{DB: pr.DB, Table: pr.Table, Kind: "drop"})
		case "whole":
			pairs = append(pairs, swapPair{DB: pr.DB, Table: pr.Table, Kind: "whole"})
		default:
			pairs = append(pairs, swapPair{DB: pr.DB, Table: pr.Table, Kind: "parts"})
		}
	}
	saved := rec
	saved.Extra = maps.Clone(rec.Extra)
	rec.Extra = maps.Clone(rec.Extra)
	rec.Status, rec.Phase, rec.Extra["undoing"] = protocol.RewindInProgress, cipSwapping, "1"
	delete(rec.Extra, "step")
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	src := func(d string) string { return beforeDBName(tag, d) }
	aside := func(d string) string { return afterDBName(tag, d) }
	sctx := context.WithoutCancel(ctx)
	res := &protocol.RewindUndoResult{RewindID: rec.ID}
	tl.Printf("swapping %d tables back: the rewound data is kept in rowsafe_after_%s_*", len(pairs), tag)
	err = undoAll(sctx, c, kept, &rec, pairs, src, aside, tl)
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		if rerr := rollbackUndo(sctx, c, rec, pairs, src, aside); rerr != nil {
			return res, fmt.Errorf("the undo failed (%v), and putting the data back failed too: %v", err, rerr)
		}
		res.RolledBack = true
		_ = kept.Put(saved)
		return res, fmt.Errorf("the undo failed, and every table was put back as it was (nothing changed): %w", err)
	}
	var names []string
	for _, d := range strings.Split(rec.Extra["dbs"], "\n") {
		dropDBs(sctx, c, beforeDBName(tag, d))
		names = append(names, afterDBName(tag, d))
	}
	until := agent.KeepUntil(rec.KeepDays, time.Now())
	delete(rec.Extra, "undoing")
	delete(rec.Extra, "step")
	rec.Status, rec.Phase, rec.Undo, rec.Expires = protocol.RewindKeptAfterUndo, "", true, until
	rec.SizeBytes = dbSize(sctx, c, names)
	rec.Path = "rowsafe_after_" + tag + "_* databases"
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.RewoundDataDir, res.KeptUntil = rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s is back as it was before the rewind. The rewound data (with anything written since) is kept in the rowsafe_after_%s_* databases until %s.",
		db.Name, tag, until.UTC().Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// undoAll is swapAll for an undo: tables the rewind renamed in ("drop")
// move to the after database whole.
func undoAll(ctx context.Context, c *client, kept *agent.KeptStore, rec *agent.KeptRecord, pairs []swapPair,
	srcDB, asideDB func(string) string, tl agent.TaskLogger) error {
	for i, p := range pairs {
		if err := c.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(asideDB(p.DB))+" ENGINE = Atomic", nil); err != nil {
			return err
		}
		rec.Extra["step"] = strconv.Itoa(i) + ":swap"
		if err := kept.Put(*rec); err != nil {
			return err
		}
		var err error
		switch p.Kind {
		case "drop":
			err = c.exec(ctx, "RENAME TABLE "+tableName(p.DB, p.Table)+" TO "+tableName(asideDB(p.DB), p.Table), nil)
		case "whole":
			err = c.exec(ctx, "EXCHANGE TABLES "+tableName(p.DB, p.Table)+" AND "+tableName(srcDB(p.DB), p.Table), nil)
			if err == nil {
				err = c.exec(ctx, "RENAME TABLE "+tableName(srcDB(p.DB), p.Table)+" TO "+tableName(asideDB(p.DB), p.Table), nil)
			}
		default:
			err = swapOne(ctx, c, swapPair{DB: p.DB, Table: p.Table, Kind: "parts"}, srcDB(p.DB), asideDB(p.DB), func(phase string) error {
				rec.Extra["step"] = strconv.Itoa(i) + ":" + phase
				return kept.Put(*rec)
			})
		}
		if err != nil {
			return fmt.Errorf("%s.%s: %w", p.DB, p.Table, err)
		}
	}
	tl.Printf("swapped %d tables back", len(pairs))
	return nil
}

// rollbackUndo puts the rewound data back after a failed undo.
func rollbackUndo(ctx context.Context, c *client, rec agent.KeptRecord, pairs []swapPair, srcDB, asideDB func(string) string) error {
	at, phase, _ := strings.Cut(rec.Extra["step"], ":")
	n, err := strconv.Atoi(at)
	if err != nil {
		return nil
	}
	var errs []error
	for i := min(n, len(pairs)-1); i >= 0; i-- {
		p := pairs[i]
		ph := "swap"
		if i == n {
			ph = phase
		}
		switch p.Kind {
		case "drop":
			if exists(ctx, c, asideDB(p.DB), p.Table) {
				errs = append(errs, c.exec(ctx, "RENAME TABLE "+tableName(asideDB(p.DB), p.Table)+" TO "+tableName(p.DB, p.Table), nil))
			}
		default:
			errs = append(errs, unswapOne(ctx, c, p, srcDB(p.DB), asideDB(p.DB), ph))
		}
	}
	return errors.Join(errs...)
}

// rewindCleanup drops what a rewind kept.
func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept for this rewind any more."}, nil
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	freed := dropKept(ctx, c, rec)
	if err := kept.Remove(rec.ID); err != nil {
		return nil, err
	}
	res := &protocol.RewindCleanupResult{RewindID: rec.ID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the data kept aside by the rewind (%s freed).", humanBytes(freed))}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func dropKept(ctx context.Context, c *client, rec agent.KeptRecord) int64 {
	tag := rec.Extra["tag"]
	var names []string
	for _, d := range strings.Split(rec.Extra["dbs"], "\n") {
		if d != "" {
			names = append(names, beforeDBName(tag, d), afterDBName(tag, d), tmpDBName(tag, d))
		}
	}
	freed := dbSize(ctx, c, names)
	dropDBs(ctx, c, names...)
	return freed
}

// recoverInPlace rolls back a rewind or an undo the agent was running when
// it stopped.
func (e *Engine) recoverInPlace(ctx context.Context, env agent.EngineEnv) {
	kept := env.Kept()
	for _, rec := range kept.All() {
		if rec.Status != protocol.RewindInProgress {
			continue
		}
		c, err := connectDB(ctx, env, rec.Database)
		if err != nil {
			env.Log.Error("can't reach ClickHouse to finish an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
			continue
		}
		tag := rec.Extra["tag"]
		pairs := decodePairs(rec.Extra["pairs"])
		if rec.Extra["undoing"] == "1" {
			var undo []swapPair
			for _, pr := range pairs {
				k := map[string]string{"create": "drop", "whole": "whole"}[pr.Kind]
				undo = append(undo, swapPair{DB: pr.DB, Table: pr.Table, Kind: cmpStr(k, "parts")})
			}
			err = rollbackUndo(ctx, c, rec, undo, func(d string) string { return beforeDBName(tag, d) }, func(d string) string { return afterDBName(tag, d) })
			if err == nil {
				delete(rec.Extra, "undoing")
				delete(rec.Extra, "step")
				rec.Status, rec.Phase = protocol.RewindKeptBefore, ""
				err = kept.Put(rec)
			}
		} else {
			if rec.Phase == cipSwapping {
				err = rollbackAll(ctx, c, rec, pairs, func(d string) string { return tmpDBName(tag, d) }, func(d string) string { return beforeDBName(tag, d) })
			}
			if err == nil {
				dropKept(ctx, c, rec)
				err = kept.Remove(rec.ID)
			}
		}
		if err != nil {
			env.Log.Error("finishing an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
		} else {
			env.Log.Warn("an interrupted rewind in place was rolled back", "rewind_id", rec.ID)
		}
	}
}

// expireKept drops what rewinds kept past its expiry.
func (e *Engine) expireKept(ctx context.Context, env agent.EngineEnv, now time.Time) {
	kept := env.Kept()
	for _, rec := range kept.Expired(now) {
		c, err := connectDB(ctx, env, rec.Database)
		if err != nil {
			continue
		}
		dropKept(ctx, c, rec)
		_ = kept.Remove(rec.ID)
		env.Log.Info("deleted the data kept aside by a rewind in place (expired)", "rewind_id", rec.ID)
	}
}
