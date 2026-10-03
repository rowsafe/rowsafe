package redis

import (
	"context"
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

// Rewind for Redis and Valkey: a copy of the server as it was at any
// second (or a Mark), restored next to production into an isolated
// temporary server that stays up until it expires; a comparison of keys
// with production per logical database; and bringing keys back. Key names
// and values stay on this server: only counts are reported.

const (
	defaultCopyHours = 24
	maxCopyAge       = 7 * 24 * time.Hour
	// compareMaxKeys caps the keys compared per logical database and
	// pattern (ROWSAFE_REDIS_COMPARE_MAX_KEYS); past it the result says it
	// was sampled.
	defaultCompareMaxKeys = 1_000_000
	// defaultMaxKeys is the most keys one bring-back writes.
	defaultMaxKeys = 10_000_000
	scanBatch      = 500
	// deepCompareMax: values with more elements than this are compared by
	// type and size only (reading them whole would weigh on production).
	deepCompareMax = 1000
)

func compareMaxKeys() int64 {
	if v, err := strconv.ParseInt(os.Getenv("ROWSAFE_REDIS_COMPARE_MAX_KEYS"), 10, 64); err == nil && v > 0 {
		return v
	}
	return defaultCompareMaxKeys
}

func copyRoot(env agent.EngineEnv, engine string) string { return filepath.Join(env.Config.RewindDir, engine) }

// copyRecord is a copy the engine keeps (<state>/copies.json).
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	Port        int                   `json:"port"`
	Dir         string                `json:"dir"`
	Status      string                `json:"status"`
	Target      protocol.RewindTarget `json:"target"`
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
		var list []copyRecord
		if err := loadJSONFile(cs.path, &list); err != nil && !notExist(err) {
			env.Log.Error("reading the copies' state; starting empty", "err", err)
		}
		for _, r := range list {
			cs.records[r.ID] = r
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

// flushForMoment makes sure the changes up to a recent moment are in the
// bucket before restoring to it.
func (e *Engine) flushForMoment(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, target restoreTarget) {
	if target.Time.IsZero() || time.Since(target.Time) > 3*time.Minute {
		return
	}
	f := e.existingFollower(db.ID)
	if f == nil {
		return
	}
	st := f.snapshot()
	if st.Mode != modeReplica || st.StreamID == "" {
		return
	}
	// Everything received so far arrived before now, so it covers the moment.
	_ = f.flush(ctx, st.StreamID, st.Offset, 2*time.Minute)
}

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	target, err := targetFrom(p.Target)
	if err != nil {
		return nil, err
	}
	cs := e.copyState(env)
	if r, ok := cs.forDatabase(db.ID); ok {
		if r.ID == p.CopyID && r.Status == protocol.RewindCopyReady {
			return e.copyResult(ctx, env, r)
		}
		return nil, errors.New("this database already has a copy: delete it before restoring another")
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	var executable string
	if c, err := connectDB(ctx, env, db); err == nil {
		if in, err := inspect(ctx, c); err == nil {
			executable = in.Executable
		}
		c.Close()
	}
	e.flushForMoment(ctx, env, db, target)
	root := copyRoot(env, e.name)
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Port: db.Port, Dir: filepath.Join(root, p.CopyID),
		Status: protocol.RewindCopyRestoring, Target: p.Target, CreatedAt: now, Expires: clampExpiry(p.Expires, now)}
	s, err := newScratch(env, root, p.CopyID)
	if err != nil {
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
		_, _ = s.remove()
		return nil, err
	}
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		if _, rerr := s.remove(); rerr != nil {
			env.Log.Error("removing a failed copy", "dir", s.Dir, "err", rerr)
		}
		_ = cs.remove(rec.ID)
		if cctx.Err() != nil && ctx.Err() == nil {
			return nil, errors.New("the copy was deleted while it was being restored")
		}
		return nil, err
	}
	tl.Printf("restoring a copy of %s as of %s into an isolated server (Unix socket only, no network)", db.Name, target.describe())
	out, c, err := e.restoreInto(cctx, env, r, target, &s, executable, tl)
	if err != nil {
		return fail(err)
	}
	// Saved once, so the copy comes back as it is after an agent restart.
	c.timeout = time.Hour
	if _, err := c.do(cctx, "SAVE"); err != nil {
		c.Close()
		return fail(fmt.Errorf("saving the copy: %w", err))
	}
	c.Close()
	rec.Status = protocol.RewindCopyReady
	rt := out.RecoveredTo
	rec.RecoveredTo = &rt
	rec.SizeBytes = dirSize(s.Dir)
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	res, err := e.copyResult(ctx, env, rec)
	if err != nil {
		return nil, err
	}
	for _, w := range out.Warnings {
		tl.Printf("note: %s", w)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) copyResult(ctx context.Context, env agent.EngineEnv, rec copyRecord) (*protocol.RewindCopyResult, error) {
	s := scratchAt(env, rec.Dir)
	c, err := s.connect(ctx)
	if err != nil {
		return nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	defer c.Close()
	m, err := c.info(ctx, "keyspace", "memory")
	if err != nil {
		return nil, err
	}
	in := infoFrom(m)
	when := "the backup"
	if rec.RecoveredTo != nil {
		when = rec.RecoveredTo.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return &protocol.RewindCopyResult{CopyID: rec.ID, RecoveredTo: rec.RecoveredTo, SizeBytes: rec.SizeBytes, Databases: in.dbInfos(),
		SocketDir: s.SockDir, Port: 0, Expires: rec.Expires,
		Summary: fmt.Sprintf("The copy is ready: %s keys in %d logical databases as of %s. It is deleted by itself on %s.",
			commas(in.totalKeys()), len(in.Keyspace), when, rec.Expires.UTC().Format("2006-01-02 15:04 UTC"))}, nil
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
		dir := filepath.Join(copyRoot(env, e.name), p.CopyID)
		if _, err := os.Lstat(dir); err != nil {
			return &protocol.RewindDropResult{CopyID: p.CopyID, Summary: "There was no such copy (already deleted)."}, nil
		}
		rec = copyRecord{ID: p.CopyID, Dir: dir}
	}
	if rec.DatabaseID != "" && rec.DatabaseID != db.ID {
		return nil, errors.New("that copy belongs to another database")
	}
	freed, err := scratchAt(env, rec.Dir).remove()
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
func (e *Engine) readyCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, id string) (*conn, *conn, error) {
	rec, ok := e.copyState(env).get(id)
	if !ok || rec.DatabaseID != db.ID {
		return nil, nil, errors.New("there is no such copy (it expired or was deleted): restore a new one")
	}
	if rec.Status != protocol.RewindCopyReady {
		return nil, nil, errors.New("the copy is still being restored")
	}
	cp, err := scratchAt(env, rec.Dir).connect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		cp.Close()
		return nil, nil, err
	}
	return cp, prod, nil
}

// scope is one logical database and key pattern to work on.
type scope struct {
	DB      int
	Pattern string
}

func (s scope) table() protocol.RewindTable {
	return protocol.RewindTable{DB: strconv.Itoa(s.DB), Table: s.Pattern}
}

// scopes are the asked ones, or every logical database of the copy and of
// production with every key.
func scopes(ctx context.Context, cp, prod *conn, asked []protocol.RewindTable, maxDB int) ([]scope, error) {
	if len(asked) > 0 {
		var out []scope
		for _, t := range asked {
			n, err := strconv.Atoi(strings.TrimPrefix(t.DB, "db"))
			if err != nil || n < 0 || n >= max(maxDB, 16) {
				return nil, fmt.Errorf("%q isn't a logical database", t.DB)
			}
			pat := cmpOr(t.Table, "*")
			if len(pat) > 512 || strings.ContainsAny(pat, "\r\n") {
				return nil, errors.New("that key pattern is too long")
			}
			out = append(out, scope{DB: n, Pattern: pat})
		}
		return out, nil
	}
	a, err := keyCounts(ctx, cp)
	if err != nil {
		return nil, err
	}
	b, err := keyCounts(ctx, prod)
	if err != nil {
		return nil, err
	}
	var idx []int
	for n := range a {
		idx = append(idx, n)
	}
	for n := range b {
		idx = append(idx, n)
	}
	slices.Sort(idx)
	var out []scope
	for _, n := range slices.Compact(idx) {
		out = append(out, scope{DB: n, Pattern: "*"})
	}
	return out, nil
}

// selectDB switches a connection's logical database.
func selectDB(ctx context.Context, c *conn, n int) error {
	_, err := c.do(ctx, "SELECT", n)
	return err
}

// scanKeys calls fn with batches of keys matching pattern in the selected
// logical database (SCAN: never blocks the server), up to limit keys; it
// reports whether it stopped at the limit.
func scanKeys(ctx context.Context, c *conn, pattern string, limit int64, fn func(keys []string) error) (bool, error) {
	cursor := "0"
	var seen int64
	for {
		v, err := c.do(ctx, "SCAN", cursor, "MATCH", pattern, "COUNT", scanBatch)
		if err != nil {
			return false, err
		}
		a := asArray(v)
		if len(a) != 2 {
			return false, errors.New("unexpected SCAN reply")
		}
		cursor = asString(a[0])
		var keys []string
		for _, k := range asArray(a[1]) {
			keys = append(keys, asString(k))
		}
		if int64(len(keys)) > limit-seen {
			keys = keys[:limit-seen]
		}
		if len(keys) > 0 {
			if err := fn(keys); err != nil {
				return false, err
			}
		}
		seen += int64(len(keys))
		if seen >= limit {
			return cursor != "0", nil
		}
		if cursor == "0" {
			return false, nil
		}
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}
}

func (e *Engine) rewindCompare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer cp.Close()
	defer prod.Close()
	sc, err := scopes(ctx, cp, prod, p.Tables, 0)
	if err != nil {
		return nil, err
	}
	res := &protocol.RewindCompareResult{CopyID: p.CopyID}
	var missing, changed int64
	var touched []string
	for _, s := range sc {
		d, err := compareScope(ctx, cp, prod, s, nil)
		if err != nil {
			return nil, err
		}
		res.Tables = append(res.Tables, d)
		missing += d.MissingInProduction
		changed += d.Changed
		if d.MissingInProduction+d.Changed > 0 {
			touched = append(touched, "db"+d.DB)
		}
		tl.Printf("db%s %s: %d keys missing in production, %d changed, %d added since", d.DB, d.Table, d.MissingInProduction, d.Changed, d.OnlyInProduction)
	}
	switch {
	case missing+changed == 0:
		res.Summary = fmt.Sprintf("No keys are missing or changed in the %d logical databases compared.", len(res.Tables))
	default:
		res.Summary = fmt.Sprintf("%s keys are missing from production and %s changed, in %s.", commas(missing), commas(changed), strings.Join(firstN(touched, 3), ", "))
	}
	return res, nil
}

// keyDiff is one key's comparison.
type keyDiff int

const (
	keySame keyDiff = iota
	keyMissing
	keyChanged
)

// compareScope compares one logical database and pattern. With collect,
// it passes each batch's missing and changed keys on.
func compareScope(ctx context.Context, cp, prod *conn, s scope, collect func(missing, changed []string) error) (protocol.RewindTableDiff, error) {
	d := protocol.RewindTableDiff{RewindTable: s.table()}
	if err := selectDB(ctx, cp, s.DB); err != nil {
		return d, err
	}
	if err := selectDB(ctx, prod, s.DB); err != nil {
		return d, err
	}
	limit := compareMaxKeys()
	var compared, matched, shallow int64
	sampled, err := scanKeys(ctx, cp, s.Pattern, limit, func(keys []string) error {
		diffs, sh, err := compareKeys(ctx, cp, prod, keys)
		if err != nil {
			return err
		}
		shallow += sh
		var miss, chg []string
		for i, k := range keys {
			compared++
			switch diffs[i] {
			case keyMissing:
				d.MissingInProduction++
				miss = append(miss, k)
			case keyChanged:
				d.Changed++
				matched++
				chg = append(chg, k)
			default:
				matched++
			}
		}
		if collect != nil && len(miss)+len(chg) > 0 {
			return collect(miss, chg)
		}
		return nil
	})
	if err != nil {
		return d, err
	}
	var notes []string
	if sampled {
		total := int64(0)
		if n, err := cp.integer(ctx, "DBSIZE"); err == nil {
			total = n
		}
		notes = append(notes, fmt.Sprintf("Compared the first %s keys of about %s (a sample: the counts cover only those).", commas(compared), commas(total)))
	}
	if shallow > 0 {
		notes = append(notes, fmt.Sprintf("%s large values (over %d elements) were compared by type and size only.", commas(shallow), deepCompareMax))
	}
	// Keys added since: production's keys the copy doesn't have.
	if s.Pattern == "*" && !sampled {
		if n, err := prod.integer(ctx, "DBSIZE"); err == nil {
			d.OnlyInProduction = max(n-matched, 0)
		}
	} else {
		var only int64
		psampled, err := scanKeys(ctx, prod, s.Pattern, limit, func(keys []string) error {
			cmds := make([][]any, len(keys))
			for i, k := range keys {
				cmds[i] = []any{"EXISTS", k}
			}
			rep, _, err := cp.pipeline(ctx, cmds)
			if err != nil {
				return err
			}
			for _, v := range rep {
				if asInt(v) == 0 {
					only++
				}
			}
			return nil
		})
		if err != nil {
			return d, err
		}
		d.OnlyInProduction = only
		if psampled && !sampled {
			notes = append(notes, "Keys added since were counted on a sample of production.")
		}
	}
	d.Note = strings.Join(notes, " ")
	return d, nil
}

// compareKeys compares a batch of the copy's keys with production: the
// type and size first (cheap), then, for values up to deepCompareMax
// elements, the values themselves. shallow counts the large values
// compared by size only.
func compareKeys(ctx context.Context, cp, prod *conn, keys []string) ([]keyDiff, int64, error) {
	out := make([]keyDiff, len(keys))
	types := func(c *conn) ([]string, error) {
		cmds := make([][]any, len(keys))
		for i, k := range keys {
			cmds[i] = []any{"TYPE", k}
		}
		rep, _, err := c.pipeline(ctx, cmds)
		if err != nil {
			return nil, err
		}
		ts := make([]string, len(keys))
		for i, v := range rep {
			ts[i] = asString(v)
		}
		return ts, nil
	}
	ct, err := types(cp)
	if err != nil {
		return nil, 0, err
	}
	pt, err := types(prod)
	if err != nil {
		return nil, 0, err
	}
	sizes := func(c *conn, ts []string) ([]int64, error) {
		var cmds [][]any
		var at []int
		for i, k := range keys {
			if cmd := sizeCommand(ts[i], k); cmd != nil {
				cmds = append(cmds, cmd)
				at = append(at, i)
			}
		}
		out := make([]int64, len(keys))
		if len(cmds) == 0 {
			return out, nil
		}
		rep, _, err := c.pipeline(ctx, cmds)
		if err != nil {
			return nil, err
		}
		for j, v := range rep {
			out[at[j]] = asInt(v)
		}
		return out, nil
	}
	cs, err := sizes(cp, ct)
	if err != nil {
		return nil, 0, err
	}
	ps, err := sizes(prod, pt)
	if err != nil {
		return nil, 0, err
	}
	var shallow int64
	var deep []int
	for i := range keys {
		switch {
		case ct[i] == "none":
			out[i] = keySame // expired in the copy meanwhile
		case pt[i] == "none":
			out[i] = keyMissing
		case ct[i] != pt[i] || cs[i] != ps[i]:
			out[i] = keyChanged
		case ct[i] != "string" && cs[i] > deepCompareMax, ct[i] == "string" && cs[i] > 1<<20:
			shallow++
		default:
			deep = append(deep, i)
		}
	}
	if len(deep) == 0 {
		return out, shallow, nil
	}
	read := func(c *conn) ([]any, error) {
		cmds := make([][]any, len(deep))
		for j, i := range deep {
			cmds[j] = valueCommand(ct[i], keys[i])
		}
		rep, _, err := c.pipeline(ctx, cmds)
		return rep, err
	}
	cv, err := read(cp)
	if err != nil {
		return nil, 0, err
	}
	pv, err := read(prod)
	if err != nil {
		return nil, 0, err
	}
	for j, i := range deep {
		if !sameValue(ct[i], cv[j], pv[j]) {
			out[i] = keyChanged
		}
	}
	return out, shallow, nil
}

// sizeCommand is the O(1) size of a value of type t.
func sizeCommand(t, key string) []any {
	switch t {
	case "string":
		return []any{"STRLEN", key}
	case "list":
		return []any{"LLEN", key}
	case "set":
		return []any{"SCARD", key}
	case "zset":
		return []any{"ZCARD", key}
	case "hash":
		return []any{"HLEN", key}
	case "stream":
		return []any{"XLEN", key}
	}
	return nil
}

// valueCommand reads a whole (small) value; other types (modules) are
// compared through DUMP.
func valueCommand(t, key string) []any {
	switch t {
	case "string":
		return []any{"GET", key}
	case "list":
		return []any{"LRANGE", key, 0, -1}
	case "set":
		return []any{"SMEMBERS", key}
	case "zset":
		return []any{"ZRANGE", key, 0, -1, "WITHSCORES"}
	case "hash":
		return []any{"HGETALL", key}
	case "stream":
		return []any{"XRANGE", key, "-", "+"}
	}
	return []any{"DUMP", key}
}

// sameValue compares two replies of valueCommand for type t (sets and
// hashes in any order).
func sameValue(t string, a, b any) bool {
	switch t {
	case "set":
		return sameMultiset(flat(a), flat(b))
	case "hash":
		return sameMultiset(pairs(flat(a)), pairs(flat(b)))
	}
	return slices.Equal(flat(a), flat(b))
}

// flat turns a reply into strings (nested arrays flattened).
func flat(v any) []string {
	switch x := v.(type) {
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, flat(e)...)
		}
		return out
	case nil:
		return []string{"\x00nil"}
	}
	return []string{asString(v)}
}

func pairs(s []string) []string {
	var out []string
	for i := 0; i+1 < len(s); i += 2 {
		out = append(out, s[i]+"\x00"+s[i+1])
	}
	return out
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func (e *Engine) rewindRows(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("pick the logical database and the keys (a pattern) to bring back")
	}
	cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer cp.Close()
	defer prod.Close()
	if m, err := prod.info(ctx, "replication"); err == nil && (m["role"] == "slave" || m["role"] == "replica") {
		return nil, errors.New("this server is a replica, which refuses writes: bring keys back on its primary")
	}
	sc, err := scopes(ctx, cp, prod, p.Tables, 0)
	if err != nil {
		return nil, err
	}
	limit := p.MaxRows
	if limit <= 0 {
		limit = defaultMaxKeys
	}
	// Count first: over the limit, nothing is changed.
	var total int64
	for _, s := range sc {
		d, err := compareScope(ctx, cp, prod, s, nil)
		if err != nil {
			return nil, err
		}
		total += d.MissingInProduction
		if p.IncludeChanged {
			total += d.Changed
		}
	}
	if total > limit {
		return nil, fmt.Errorf("that would write %s keys, more than the limit of %s: nothing was changed; pick a narrower pattern", commas(total), commas(limit))
	}
	res := &protocol.RewindRowsResult{}
	var parts []string
	for _, s := range sc {
		out := protocol.RewindTableRows{RewindTable: s.table()}
		_, err := compareScope(ctx, cp, prod, s, func(missing, changed []string) error {
			if err := restoreKeys(ctx, cp, prod, missing, false, &out); err != nil {
				return err
			}
			if p.IncludeChanged {
				return restoreKeys(ctx, cp, prod, changed, true, &out)
			}
			return nil
		})
		res.Tables = append(res.Tables, out)
		if err != nil {
			return res, fmt.Errorf("db%d: %w (keys written before this are kept; running it again finishes the job)", s.DB, err)
		}
		if out.Inserted+out.Updated > 0 {
			part := fmt.Sprintf("%s keys in db%d", commas(out.Inserted), s.DB)
			if out.Updated > 0 {
				part += fmt.Sprintf(" (and %s changed back)", commas(out.Updated))
			}
			parts = append(parts, part)
		}
		tl.Printf("db%d %s: %d keys brought back, %d changed back, %d written meanwhile and left alone", s.DB, s.Pattern, out.Inserted, out.Updated, out.Conflicts)
	}
	if len(parts) == 0 {
		res.Summary = "Nothing needed to be brought back: production already has these keys."
	} else {
		res.Summary = "Brought back " + strings.Join(parts, ", ") + "."
	}
	return res, nil
}

// restoreKeys copies keys from the copy into production (DUMP, RESTORE)
// with their expiry; replace overwrites what production has.
func restoreKeys(ctx context.Context, cp, prod *conn, keys []string, replace bool, out *protocol.RewindTableRows) error {
	if len(keys) == 0 {
		return nil
	}
	cmds := make([][]any, 0, 2*len(keys))
	for _, k := range keys {
		cmds = append(cmds, []any{"PEXPIRETIME", k}, []any{"DUMP", k})
	}
	rep, errs, err := cp.pipeline(ctx, cmds)
	if err != nil {
		return err
	}
	var writes [][]any
	now := time.Now().UnixMilli()
	for i := range keys {
		exp, payload := asInt(rep[2*i]), rep[2*i+1]
		if errs[2*i+1] != nil || payload == nil || exp == -2 {
			continue // gone from the copy meanwhile (expired)
		}
		ttl := int64(0)
		if exp > 0 {
			if exp <= now {
				continue // its time has passed: Redis would drop it at once
			}
			ttl = exp
		}
		cmd := []any{"RESTORE", keys[i], ttl, asString(payload)}
		if ttl > 0 {
			cmd = append(cmd, "ABSTTL")
		}
		if replace {
			cmd = append(cmd, "REPLACE")
		}
		writes = append(writes, cmd)
	}
	if len(writes) == 0 {
		return nil
	}
	_, werrs, err := prod.pipeline(ctx, writes)
	if err != nil {
		return err
	}
	for _, e := range werrs {
		switch {
		case e == nil && replace:
			out.Updated++
		case e == nil:
			out.Inserted++
		case isRespError(e, "BUSYKEY"):
			out.Conflicts++ // written in production meanwhile: left alone
		case strings.Contains(e.Error(), "payload version"):
			return errors.New("production runs an older version than the copy, which can't read its keys: bring keys back from a copy made with production's own version")
		default:
			return e
		}
	}
	return nil
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
		s := scratchAt(env, r.Dir)
		switch {
		case r.Status != protocol.RewindCopyReady:
			if _, err := s.remove(); err == nil {
				_ = cs.remove(r.ID)
				env.Log.Warn("removed a copy whose restore was interrupted", "copy_id", r.ID)
			}
		case time.Now().After(r.Expires):
		case s.pid() == 0:
			go func() {
				c, err := s.restart(ctx, env)
				if err != nil {
					env.Log.Error("starting a copy again failed; it stays until it expires or is deleted", "copy_id", r.ID, "err", err)
					return
				}
				c.Close()
				env.Log.Info("started a copy again after an agent restart", "copy_id", r.ID)
			}()
		}
	}
	for _, root := range []string{copyRoot(env, e.name), drillRoot(env, e.name)} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() || known[ent.Name()] && root == copyRoot(env, e.name) {
				continue
			}
			if strings.HasPrefix(ent.Name(), "inplace-") {
				continue // recoverInPlace
			}
			dir := filepath.Join(root, ent.Name())
			if _, err := os.Lstat(filepath.Join(dir, scratchMarker)); err != nil {
				continue
			}
			if _, err := scratchAt(env, dir).remove(); err != nil {
				env.Log.Error("removing a leftover temporary server failed", "dir", dir, "err", err)
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
		freed, err := scratchAt(env, r.Dir).remove()
		if err != nil {
			env.Log.Error("removing an expired copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		_ = cs.remove(r.ID)
		env.Log.Info("removed an expired copy", "copy_id", r.ID, "freed", humanBytes(freed))
	}
}

// RewindStates reports the copies and kept data (heartbeat).
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range e.copyState(env).all() {
		exp := r.Expires
		out = append(out, protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindCopy, Status: r.Status,
			SizeBytes: r.SizeBytes, Expires: &exp, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.Dir})
	}
	return append(out, env.Kept().States()...)
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
