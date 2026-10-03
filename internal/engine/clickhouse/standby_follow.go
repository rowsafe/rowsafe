package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The standby's side (standby_primary.go explains the design).

// applyInterval is how often a standby applies the primary's new changes.
const applyInterval = 10 * time.Second

// standbyTmpDB holds the standby's staging tables while it applies.
const standbyTmpDB = "rowsafe_standby_tmp"

var _ agent.EngineStandby = (*Engine)(nil)

// StandbyCreate restores the primary's newest moment into the empty
// ClickHouse server on p.Port and starts following.
func (e *Engine) StandbyCreate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams,
	sec protocol.StandbySecrets, log agent.TaskLogger) (*protocol.StandbyCreateResult, error) {
	start := time.Now()
	if p.Rebuild {
		return nil, errors.New("a ClickHouse server that was the primary can't be turned into the new primary's standby yet: " +
			"add a standby on an empty ClickHouse server instead, and remove this one")
	}
	store := e.standbyStore(env)
	if r, ok := store.get(p.StandbyID); ok && r.Phase == protocol.StandbyPhaseFollowing {
		return &protocol.StandbyCreateResult{StandbyID: r.ID, Mode: protocol.StandbyModeArchive, Summary: "The standby already follows its primary."}, nil
	}
	if _, ok := store.onPort(p.Port); ok {
		return nil, fmt.Errorf("the ClickHouse server on port %d already holds a standby", p.Port)
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: p.Port})
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if reason := cloneTargetReason(in); reason != "" {
		return nil, fmt.Errorf("the ClickHouse server on port %d can't hold the standby: %s; nothing was changed", p.Port, reason)
	}
	if p.Major > 0 && in.VersionNum/100 < p.Major {
		return nil, fmt.Errorf("the ClickHouse server on port %d runs %s, older than the primary (%d.%d): a standby needs the same version or newer",
			p.Port, in.Version, p.Major/100, p.Major%100)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	h, ok, err := r.readHead(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the primary's record of changes: %w", err)
	}
	if !ok {
		return nil, errors.New("the primary's changes aren't being copied to the bucket yet")
	}
	res, err := pitAt(ctx, r, h.To, "")
	if err != nil {
		return nil, err
	}
	if !res.Exact {
		return nil, errors.New("the standby can't start yet: " + res.Note)
	}
	b := res.Doc
	if b.needsKeeper() {
		return nil, errors.New("the primary has replicated databases or tables, which need ClickHouse Keeper on the standby's server; " +
			"add a replica with ClickHouse's own replication instead")
	}
	var dbs []string
	for _, d := range b.Databases {
		dbs = append(dbs, d.Name)
	}
	now := time.Now().UTC()
	if err := store.update(p.StandbyID, func(r *chStandby) {
		*r = chStandby{ID: p.StandbyID, DatabaseID: db.ID, Stanza: db.Stanza, Port: p.Port, Phase: protocol.StandbyPhaseCreating,
			CreatedAt: now, DBs: dbs}
	}); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.StandbyCreateResult, error) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		for _, d := range dbs {
			_ = c.exec(cctx, "DROP DATABASE IF EXISTS "+quoteIdent(d)+" SYNC", nil)
		}
		_ = store.remove(p.StandbyID)
		return &protocol.StandbyCreateResult{StandbyID: p.StandbyID, RolledBack: true}, err
	}
	// Merges are the primary's: the standby mirrors its parts.
	if err := c.exec(ctx, "SYSTEM STOP MERGES", nil); err != nil {
		return fail(fmt.Errorf("stopping merges on the standby: %w", err))
	}
	log.Printf("restoring %s as it was at %s into the ClickHouse server on port %d", db.Name, h.To.UTC().Format("2006-01-02 15:04:05.000000 UTC"), p.Port)
	if _, err := restoreTo(ctx, env, r, b, c, false, log); err != nil {
		return fail(err)
	}
	_ = c.exec(ctx, "SYSTEM STOP VIEWS", nil)
	st := res.state
	if err := e.learnHashes(ctx, c, st); err != nil {
		return fail(err)
	}
	if err := setReadOnly(ctx, c, true); err != nil {
		return fail(err)
	}
	if err := store.saveState(p.StandbyID, st); err != nil {
		return fail(err)
	}
	applied := h.To
	if err := store.update(p.StandbyID, func(r *chStandby) {
		r.Phase, r.AppliedTo, r.LastApplyAt = protocol.StandbyPhaseFollowing, applied, &now
	}); err != nil {
		return fail(err)
	}
	e.wakeStandbys(env)
	out := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeArchive, DataDir: in.DataPath,
		DurationMs: time.Since(start).Milliseconds()}
	out.Summary = fmt.Sprintf("The ClickHouse server on port %d is %s's standby: it holds %s as it was at %s and applies each new change a few seconds after it reaches your bucket. It is read-only for everyone but Rowsafe.",
		p.Port, db.Name, db.Name, applied.UTC().Format("15:04:05 UTC"))
	log.Printf("%s", out.Summary)
	return out, nil
}

// learnHashes fills in, for the parts restored from a backup (which the
// record has no hash for), the hash of the standby's copy: a restore into an
// empty table keeps the parts' names.
func (e *Engine) learnHashes(ctx context.Context, c *client, st *pitState) error {
	type row struct {
		DB    string `json:"database"`
		Table string `json:"table"`
		Name  string `json:"name"`
		Hash  string `json:"h"`
	}
	rows, err := query[row](ctx, c, "SELECT database, table, name, hex(hash_of_all_files) AS h FROM system.parts WHERE active", nil)
	if err != nil {
		return err
	}
	byName := map[string]string{}
	for _, r := range rows {
		byName[r.DB+"\x00"+r.Table+"\x00"+r.Name] = r.Hash
	}
	names := standbyNames(ctx, c, st)
	for uuid, parts := range st.Parts {
		n, ok := names[uuid]
		if !ok {
			continue
		}
		for _, p := range parts {
			if p.Hash == "" {
				p.Hash = byName[n[0]+"\x00"+n[1]+"\x00"+p.Name]
			}
		}
	}
	return nil
}

// standbyNames maps the primary's tables (UUIDs, those that hold parts) to
// the standby's (database, table): the same names, except a materialized
// view's inner table, named after the view's UUID on each server.
func standbyNames(ctx context.Context, c *client, st *pitState) map[string][2]string {
	out := map[string][2]string{}
	type row struct {
		DB   string `json:"database"`
		Name string `json:"name"`
		UUID string `json:"u"`
	}
	local := map[string]string{} // db.name -> standby UUID
	if rows, err := query[row](ctx, c, "SELECT database, name, toString(uuid) AS u FROM system.tables", nil); err == nil {
		for _, r := range rows {
			local[r.DB+"."+r.Name] = r.UUID
		}
	}
	for uuid, t := range st.Tables {
		if !isInner(t.Name) {
			out[uuid] = [2]string{t.DB, t.Name}
		}
		if m := innerUUIDRE.FindStringSubmatch(t.Create); m != nil {
			if vu, ok := local[t.DB+"."+t.Name]; ok {
				out[m[1]] = [2]string{t.DB, ".inner_id." + vu}
			}
		}
	}
	return out
}

// wakeStandbys starts (once) the loop that applies changes on this
// server's standbys.
func (e *Engine) wakeStandbys(env agent.EngineEnv) {
	e.mu.Lock()
	if e.applying {
		e.mu.Unlock()
		return
	}
	e.applying = true
	base := e.ctx
	e.mu.Unlock()
	if base == nil {
		base = context.Background()
	}
	go func() {
		t := time.NewTicker(applyInterval)
		defer t.Stop()
		for {
			for _, r := range e.standbyStore(env).all() {
				if r.Phase == protocol.StandbyPhaseFollowing && r.PromotedAt == nil {
					e.applyStandby(base, env, r.ID)
				}
			}
			select {
			case <-base.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// applyStandby applies what the primary changed since the standby's
// moment, up to how far the record goes.
func (e *Engine) applyStandby(ctx context.Context, env agent.EngineEnv, id string) {
	l := e.standbyLock(id)
	l.Lock()
	defer l.Unlock()
	store := e.standbyStore(env)
	rec, ok := store.get(id)
	if !ok || rec.Phase != protocol.StandbyPhaseFollowing {
		return
	}
	err := e.applyOnce(ctx, env, rec, time.Time{})
	now := time.Now().UTC()
	_ = store.update(id, func(r *chStandby) {
		if err != nil {
			if r.Error == "" {
				r.ErrorSince = &now
			}
			r.Error = err.Error()
			return
		}
		r.Error, r.ErrorSince = "", nil
	})
	if err != nil {
		env.Log.Warn("applying the primary's changes on a ClickHouse standby", "standby", id, "err", err)
	}
}

func (e *Engine) standbyLock(id string) *chLock {
	l, _ := e.standbyLocks.LoadOrStore(id, &chLock{})
	return l.(*chLock)
}

// applyOnce applies the record up to its end, or up to until when given.
func (e *Engine) applyOnce(ctx context.Context, env agent.EngineEnv, rec chStandby, until time.Time) error {
	if env.RepoFor != nil {
		env.Repo = env.RepoFor(rec.DatabaseID)
	}
	r, err := openRepo(env, protocol.DatabaseSpec{ID: rec.DatabaseID, Stanza: rec.Stanza})
	if err != nil {
		return err
	}
	h, ok, err := r.readHead(ctx)
	if err != nil || !ok {
		return fmt.Errorf("reading the primary's record of changes: %v", err)
	}
	to := h.To
	if !until.IsZero() && until.Before(to) {
		to = until
	}
	if !to.After(rec.AppliedTo) {
		return nil
	}
	tl, err := r.readTimeline(ctx, rec.AppliedTo, to)
	if err != nil {
		return err
	}
	if len(tl.Gaps) > 0 {
		return fmt.Errorf("the primary's record has a gap (%s): remove this standby and add it again", tl.Gaps[0].Why)
	}
	if !tl.Covered.After(rec.AppliedTo) {
		return nil
	}
	if tl.Covered.Before(to) {
		to = tl.Covered
	}
	store := e.standbyStore(env)
	cur, err := store.loadState(rec.ID)
	if err != nil {
		return fmt.Errorf("reading the standby's state: %w", err)
	}
	next := cur.clone()
	for _, ev := range tl.Events {
		if !ev.At.After(to) {
			next.apply(ev)
		}
	}
	next.prune(time.Now(), 6*time.Hour)
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: rec.Port})
	if err != nil {
		return err
	}
	_ = c.exec(ctx, "SYSTEM STOP MERGES", nil) // again after a restart of ClickHouse
	if err := e.applyDiff(ctx, env, r, c, cur, next, to); err != nil {
		return err
	}
	if err := store.saveState(rec.ID, next); err != nil {
		return err
	}
	now := time.Now().UTC()
	return store.update(rec.ID, func(x *chStandby) {
		x.AppliedTo, x.LastApplyAt = to, &now
		x.DBs = nil
		for _, d := range next.DBs {
			x.DBs = append(x.DBs, d.Name)
		}
	})
}

// applyDiff turns the standby from cur into next: databases and tables
// created, changed or dropped; partitions whose parts changed.
func (e *Engine) applyDiff(ctx context.Context, env agent.EngineEnv, r *repo, c *client, cur, next *pitState, at time.Time) error {
	if err := c.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(standbyTmpDB), nil); err != nil {
		return err
	}
	defer func() {
		_ = c.exec(context.WithoutCancel(ctx), "DROP DATABASE IF EXISTS "+quoteIdent(standbyTmpDB)+" SYNC", nil)
	}()
	// Databases.
	for uuid, d := range next.DBs {
		if old, ok := cur.DBs[uuid]; ok && old.Name == d.Name {
			continue
		}
		if err := c.exec(ctx, "CREATE DATABASE IF NOT EXISTS "+quoteIdent(d.Name)+" ENGINE = "+cmpOr(d.Engine, "Atomic"), nil); err != nil {
			return fmt.Errorf("creating database %s: %w", d.Name, err)
		}
	}
	// Tables created, changed or dropped: rebuilt whole from the moment.
	var rebuild []string
	for uuid, t := range next.Tables {
		if isInner(t.Name) {
			continue
		}
		old, ok := cur.Tables[uuid]
		if !ok || old.Create != t.Create || old.DB != t.DB || old.Name != t.Name {
			rebuild = append(rebuild, uuid)
		}
	}
	for uuid, t := range cur.Tables {
		if isInner(t.Name) {
			continue
		}
		nt, ok := next.Tables[uuid]
		if !ok || nt.DB != t.DB || nt.Name != t.Name {
			if err := c.exec(ctx, "DROP TABLE IF EXISTS "+tableName(t.DB, t.Name)+" SYNC", nil); err != nil {
				return fmt.Errorf("dropping %s: %w", t.key(), err)
			}
		}
	}
	slices.Sort(rebuild)
	for _, uuid := range rebuild {
		if err := e.rebuildTable(ctx, env, r, c, next, uuid, at); err != nil {
			return err
		}
	}
	for uuid, d := range cur.DBs {
		if nd, ok := next.DBs[uuid]; !ok || nd.Name != d.Name {
			if err := c.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(d.Name)+" SYNC", nil); err != nil {
				return fmt.Errorf("dropping database %s: %w", d.Name, err)
			}
		}
	}
	// Partitions of the other tables.
	names := standbyNames(ctx, c, next)
	skip := map[string]bool{}
	for _, uuid := range rebuild {
		skip[uuid] = true
		if m := innerUUIDRE.FindStringSubmatch(next.Tables[uuid].Create); m != nil {
			skip[m[1]] = true
		}
	}
	for holder := range next.Parts {
		if skip[holder] {
			continue
		}
		if err := e.applyParts(ctx, env, r, c, cur, next, holder, names[holder], at); err != nil {
			return err
		}
	}
	for holder := range cur.Parts {
		if _, ok := next.Parts[holder]; !ok && !skip[holder] {
			if err := e.applyParts(ctx, env, r, c, cur, next, holder, names[holder], at); err != nil {
				return err
			}
		}
	}
	return nil
}

// rebuildTable restores one table as it is in next and swaps it in.
func (e *Engine) rebuildTable(ctx context.Context, env agent.EngineEnv, r *repo, c *client, next *pitState, uuid string, at time.Time) error {
	t := next.Tables[uuid]
	if engineFamily(t.Engine) == "external" || t.Refreshable {
		return nil // never on a standby: it would reach another system
	}
	b, missing, err := assembleSome(next, nil, backupDoc{}, at, map[string]bool{uuid: true}, nil)
	if err != nil {
		return err
	}
	if missing != "" {
		return fmt.Errorf("rebuilding %s: %s", t.key(), missing)
	}
	g, err := startGateway(ctx, env, r, b.prefixes(), true, true, b.virtual)
	if err != nil {
		return err
	}
	closeGW := closer(g)
	defer closeGW()
	tmp := "t_" + strings.ReplaceAll(uuid, "-", "")
	_ = c.exec(ctx, "DROP TABLE IF EXISTS "+tableName(standbyTmpDB, tmp)+" SYNC", nil)
	id := randomID("rowsafe-standby-")
	stmt := "RESTORE TABLE " + tableName(t.DB, t.Name) + " AS " + tableName(standbyTmpDB, tmp) + " FROM " + s3Expr(g, b.dir()) +
		" SETTINGS id = " + quoteString(id) + ", allow_s3_native_copy = 0, allow_different_table_def = 1"
	if _, err := runAsync(ctx, c, stmt, id, "restore", silentLog{}, func(opStatus) string { return "" }, closeGW); err != nil {
		return fmt.Errorf("restoring %s on the standby: %w", t.key(), err)
	}
	exists, _ := c.scalar(ctx, "SELECT count() FROM system.tables WHERE database = {d:String} AND name = {n:String}", map[string]string{"d": t.DB, "n": t.Name})
	if strings.TrimSpace(exists) == "1" {
		if err := c.exec(ctx, "EXCHANGE TABLES "+tableName(t.DB, t.Name)+" AND "+tableName(standbyTmpDB, tmp), nil); err != nil {
			return fmt.Errorf("swapping in %s: %w", t.key(), err)
		}
		return c.exec(ctx, "DROP TABLE IF EXISTS "+tableName(standbyTmpDB, tmp)+" SYNC", nil)
	}
	return c.exec(ctx, "RENAME TABLE "+tableName(standbyTmpDB, tmp)+" TO "+tableName(t.DB, t.Name), nil)
}

// applyParts brings one table's partitions from cur to next: a partition
// with only new parts gets them appended; one whose parts were replaced
// (merged, mutated, cleared) is rebuilt in a staging table from the parts
// it keeps (linked, not copied) and the new ones, then swapped in whole
// (REPLACE PARTITION, atomic).
func (e *Engine) applyParts(ctx context.Context, env agent.EngineEnv, r *repo, c *client, cur, next *pitState, holder string, name [2]string, at time.Time) error {
	if name[1] == "" {
		return nil
	}
	type change struct {
		added   []*pitPart
		removed []*pitPart
		left    int
	}
	byPart := map[string]*change{}
	get := func(p string) *change {
		if byPart[p] == nil {
			byPart[p] = &change{}
		}
		return byPart[p]
	}
	partOf := func(p *pitPart) string {
		if p.Partition != "" {
			return p.Partition
		}
		return parsePartName(p.Name, "").Partition
	}
	for n, p := range next.Parts[holder] {
		if _, ok := cur.Parts[holder][n]; !ok {
			get(partOf(p)).added = append(get(partOf(p)).added, p)
		}
		get(partOf(p)).left++
	}
	for n, p := range cur.Parts[holder] {
		if _, ok := next.Parts[holder][n]; !ok {
			get(partOf(p)).removed = append(get(partOf(p)).removed, p)
		}
	}
	tbl := tableName(name[0], name[1])
	for pid, ch := range byPart {
		if len(ch.added) == 0 && len(ch.removed) == 0 {
			continue
		}
		if ch.left == 0 {
			if err := c.exec(ctx, "ALTER TABLE "+tbl+" DROP PARTITION ID "+quoteString(pid), nil); err != nil {
				return fmt.Errorf("dropping a partition of %s: %w", tbl, err)
			}
			continue
		}
		var src string
		if len(ch.added) > 0 {
			var drop func()
			var err error
			src, drop, err = e.restoreParts(ctx, env, r, c, next, holder, ch.added, at)
			if err != nil {
				return err
			}
			defer drop()
		}
		if len(ch.removed) == 0 {
			// Only new parts: added as they are.
			if err := c.exec(ctx, "ALTER TABLE "+tbl+" ATTACH PARTITION ID "+quoteString(pid)+" FROM "+src, nil); err != nil {
				return fmt.Errorf("adding new parts to %s: %w", tbl, err)
			}
			continue
		}
		staging := tableName(standbyTmpDB, "p_"+randomID(""))
		if err := c.exec(ctx, "CREATE TABLE "+staging+" AS "+tbl, nil); err != nil {
			return fmt.Errorf("staging %s: %w", tbl, err)
		}
		if err := c.exec(ctx, "ALTER TABLE "+staging+" ATTACH PARTITION ID "+quoteString(pid)+" FROM "+tbl, nil); err != nil {
			return fmt.Errorf("staging %s: %w", tbl, err)
		}
		if err := dropByHash(ctx, c, staging, ch.removed); err != nil {
			return fmt.Errorf("staging %s: %w", tbl, err)
		}
		if src != "" {
			if err := c.exec(ctx, "ALTER TABLE "+staging+" ATTACH PARTITION ID "+quoteString(pid)+" FROM "+src, nil); err != nil {
				return fmt.Errorf("staging %s: %w", tbl, err)
			}
		}
		if err := c.exec(ctx, "ALTER TABLE "+tbl+" REPLACE PARTITION ID "+quoteString(pid)+" FROM "+staging, nil); err != nil {
			return fmt.Errorf("swapping a partition of %s: %w", tbl, err)
		}
		_ = c.exec(ctx, "DROP TABLE IF EXISTS "+staging+" SYNC", nil)
	}
	return nil
}

// dropByHash drops, from table, one part for each of parts (found by its
// hash: the same files).
func dropByHash(ctx context.Context, c *client, table string, parts []*pitPart) error {
	db, name := splitTable(table)
	type row struct {
		Name string `json:"name"`
		Hash string `json:"h"`
	}
	rows, err := query[row](ctx, c, "SELECT name, hex(hash_of_all_files) AS h FROM system.parts WHERE database = {d:String} AND table = {t:String} AND active",
		map[string]string{"d": db, "t": name})
	if err != nil {
		return err
	}
	used := map[string]bool{}
	for _, p := range parts {
		found := ""
		for _, r := range rows {
			if !used[r.Name] && p.Hash != "" && strings.EqualFold(r.Hash, p.Hash) {
				found = r.Name
				break
			}
		}
		if found == "" {
			return fmt.Errorf("the standby has no copy of part %s (it changed outside Rowsafe): remove this standby and add it again", p.Name)
		}
		used[found] = true
		if err := c.exec(ctx, "ALTER TABLE "+table+" DROP PART "+quoteString(found), nil); err != nil {
			return err
		}
	}
	return nil
}

// restoreParts restores parts (of the primary's table holder) into a new
// table in the staging database and returns it (for a materialized view's
// inner table: the new view's inner table). drop removes it.
func (e *Engine) restoreParts(ctx context.Context, env agent.EngineEnv, r *repo, c *client, next *pitState, holder string,
	parts []*pitPart, at time.Time) (src string, drop func(), err error) {
	want := map[string]bool{}
	for _, p := range parts {
		want[p.Name] = true
	}
	var owner string
	for uuid, t := range next.Tables {
		if uuid == holder && !isInner(t.Name) {
			owner = uuid
		}
		if m := innerUUIDRE.FindStringSubmatch(t.Create); m != nil && m[1] == holder {
			owner = uuid
		}
	}
	if owner == "" {
		return "", nil, fmt.Errorf("the table of parts %v isn't known", parts[0].Name)
	}
	b, missing, err := assembleSome(next, nil, backupDoc{}, at, map[string]bool{owner: true},
		func(h string, p *pitPart) bool { return h == holder && want[p.Name] })
	if err != nil {
		return "", nil, err
	}
	if missing != "" {
		return "", nil, errors.New(missing)
	}
	g, err := startGateway(ctx, env, r, b.prefixes(), true, true, b.virtual)
	if err != nil {
		return "", nil, err
	}
	closeGW := closer(g)
	defer closeGW()
	t := next.Tables[owner]
	tmp := "n_" + strings.TrimPrefix(randomID(""), "")
	id := randomID("rowsafe-standby-")
	stmt := "RESTORE TABLE " + tableName(t.DB, t.Name) + " AS " + tableName(standbyTmpDB, tmp) + " FROM " + s3Expr(g, b.dir()) +
		" SETTINGS id = " + quoteString(id) + ", allow_s3_native_copy = 0, allow_different_table_def = 1"
	if _, err := runAsync(ctx, c, stmt, id, "restore", silentLog{}, func(opStatus) string { return "" }, closeGW); err != nil {
		return "", nil, fmt.Errorf("restoring %d new parts of %s on the standby: %w", len(parts), t.key(), err)
	}
	drop = func() {
		_ = c.exec(context.WithoutCancel(ctx), "DROP TABLE IF EXISTS "+tableName(standbyTmpDB, tmp)+" SYNC", nil)
	}
	src = tableName(standbyTmpDB, tmp)
	if owner != holder {
		u, err := c.scalar(ctx, "SELECT toString(uuid) FROM system.tables WHERE database = {d:String} AND name = {n:String}",
			map[string]string{"d": standbyTmpDB, "n": tmp})
		if err != nil || strings.TrimSpace(u) == "" {
			drop()
			return "", nil, fmt.Errorf("finding the restored view's table: %v", err)
		}
		src = tableName(standbyTmpDB, ".inner_id."+strings.TrimSpace(u))
	}
	return src, drop, nil
}

func splitTable(q string) (string, string) {
	// q is quoteIdent(db) + "." + quoteIdent(name).
	db, name, _ := strings.Cut(q, "`.`")
	return unquoteIdent(db + "`"), unquoteIdent("`" + name)
}

func unquoteIdent(s string) string {
	s = strings.TrimPrefix(strings.TrimSuffix(s, "`"), "`")
	return strings.ReplaceAll(strings.ReplaceAll(s, "\\`", "`"), "\\\\", "\\")
}

// silentLog drops a background task's log lines.
type silentLog struct{}

func (silentLog) Printf(string, ...any) {}
func (silentLog) Output(string, []byte) {}
