package clickhouse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/internal/objstore/s3gw"
	"github.com/rowsafe/rowsafe/protocol"
)

// The copier: for each database, a loop that every few seconds finds the
// parts ClickHouse created since its last round (system.parts, which keeps
// replaced parts on disk for old_parts_lifetime, 8 minutes by default),
// copies their files from the data folder (read only) into one sealed
// chunk, and writes what changed (parts with their exact time from
// system.part_log, table and database definitions) as one log. See
// pitr_model.go.

// archiveInterval is how often the copier runs
// (ROWSAFE_CLICKHOUSE_ARCHIVE_INTERVAL, default 15s).
func archiveInterval() time.Duration {
	if v := os.Getenv("ROWSAFE_CLICKHOUSE_ARCHIVE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d >= time.Second && d <= 5*time.Minute {
			return d
		}
	}
	return 15 * time.Second
}

// partLogWait is how long a new part waits for its line in part_log
// (ClickHouse writes it every 7.5 seconds) before its time is taken from
// the part itself (to the second).
const partLogWait = 45 * time.Second

// shipLocal is the copier's own state (<state>/<stanza>/pitr.json).
type shipLocal struct {
	Record  string    `json:"record"`
	Started time.Time `json:"started"`
	To      time.Time `json:"to"`
	// Seen are the parts on disk already recorded (or there when the
	// record started), by table UUID.
	Seen   map[string]map[string]bool `json:"seen"`
	Tables map[string]pitTable        `json:"tables"`
	DBs    map[string]pitDB           `json:"dbs"`
	// Files are the files already copied, by inode (a mutation links the
	// files it doesn't change into the new part): they aren't copied
	// again. Key: dev:inode:size:mtime.
	Files map[string]copiedFile `json:"files"`

	Shipped       int64      `json:"shipped"`
	Failed        int64      `json:"failed"`
	LastShippedAt *time.Time `json:"last_shipped_at,omitempty"`
	LastFailedAt  *time.Time `json:"last_failed_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	// PollAt is when the last round read the server; LastLog is the To
	// of the last log written (the next one starts there).
	PollAt  time.Time      `json:"poll_at"`
	LastLog time.Time      `json:"last_log"`
	Pending []pendingEvent `json:"pending,omitempty"`
	// Problem is why the copier can't work (the data folder can't be
	// read...), in plain words.
	Problem string `json:"problem,omitempty"`
}

type copiedFile struct {
	Part   string       `json:"part"` // table UUID/part name it was copied with
	Pieces []s3gw.Piece `json:"pieces"`
	At     time.Time    `json:"at"` // when it was copied
}

type shipper struct {
	e   *Engine
	env agent.EngineEnv

	mu       sync.Mutex
	db       protocol.DatabaseSpec
	st       shipLocal
	lastSeen time.Time
	running  bool
	err      error
	wake     chan struct{}
	done     chan struct{}
	stop     context.CancelFunc
}

func shipStatePath(env agent.EngineEnv, stanza string) string {
	return filepath.Join(env.StateDir, stanza, "pitr.json")
}

func loadShipLocal(env agent.EngineEnv, stanza string) (shipLocal, error) {
	var st shipLocal
	data, err := os.ReadFile(shipStatePath(env, stanza))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	return st, json.Unmarshal(data, &st)
}

// shipperFor returns the database's copier, starting it when needed.
func (e *Engine) shipperFor(env agent.EngineEnv, db protocol.DatabaseSpec) (*shipper, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s := e.shippers[db.ID]; s != nil {
		s.mu.Lock()
		s.db, s.env, s.lastSeen = db, env, time.Now()
		s.mu.Unlock()
		return s, nil
	}
	st, err := loadShipLocal(env, db.Stanza)
	if err != nil {
		return nil, err
	}
	base := e.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithCancel(base)
	s := &shipper{e: e, env: env, db: db, st: st, lastSeen: time.Now(), wake: make(chan struct{}, 1),
		done: make(chan struct{}), stop: cancel, running: true}
	if e.shippers == nil {
		e.shippers = map[string]*shipper{}
	}
	e.shippers[db.ID] = s
	go s.run(ctx)
	return s, nil
}

// stopIdleShippers stops the copiers of databases no longer watched.
func (e *Engine) stopIdleShippers(idle time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for id, s := range e.shippers {
		s.mu.Lock()
		old := time.Since(s.lastSeen) > idle
		s.mu.Unlock()
		if old {
			s.stop()
			delete(e.shippers, id)
		}
	}
}

func (s *shipper) run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	backoff := time.Duration(0)
	for {
		err := s.round(ctx)
		s.mu.Lock()
		s.err = err
		close(s.done)
		s.done = make(chan struct{})
		log, id := s.env.Log, s.db.ID
		s.mu.Unlock()
		wait := archiveInterval()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("copying ClickHouse's changes failed", "database_id", id, "err", err)
			backoff = min(max(2*backoff, 5*time.Second), time.Minute)
			wait = backoff
		} else {
			backoff = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			// At most a round a second, however often flush asks.
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		case <-time.After(wait):
		}
	}
}

// flush waits until the record reaches until (the server's clock), at most
// timeout.
func (s *shipper) flush(ctx context.Context, until time.Time, timeout time.Duration) error {
	deadline := time.After(timeout)
	for {
		s.mu.Lock()
		to, done, err, running := s.st.To, s.done, s.err, s.running
		s.mu.Unlock()
		if !running {
			return errors.New("the copier of ClickHouse's changes stopped")
		}
		if !to.Before(until) {
			return nil
		}
		select {
		case s.wake <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			if err != nil {
				return err
			}
			return fmt.Errorf("ClickHouse's changes weren't copied up to %s within %s", until.Format(time.RFC3339), timeout)
		case <-done:
		}
	}
}

func (s *shipper) snapshot() (shipLocal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, s.err
}

func (s *shipper) save(st shipLocal) error {
	s.mu.Lock()
	s.st = st
	db, env := s.db, s.env
	s.mu.Unlock()
	return saveJSONFile(shipStatePath(env, db.Stanza), st)
}

// archiverStats is what the heartbeat reports.
func (st shipLocal) archiverStats(err error) *protocol.ArchiverStats {
	out := &protocol.ArchiverStats{ArchivedCount: st.Shipped, FailedCount: st.Failed,
		LastArchivedTime: st.LastShippedAt, LastFailedTime: st.LastFailedAt, ArchiveMode: "on"}
	if st.Record == "" {
		out.ArchiveMode = "off"
	}
	switch {
	case st.Problem != "":
		out.Error = st.Problem
	case err != nil:
		out.Error = err.Error()
	}
	return out
}

// round runs one round of the copier.
func (s *shipper) round(ctx context.Context) (err error) {
	s.mu.Lock()
	st, db, env := s.st, s.db, s.env
	s.mu.Unlock()
	defer func() {
		if err != nil && ctx.Err() == nil {
			now := time.Now().UTC()
			cur, _ := s.snapshot()
			cur.Failed++
			cur.LastFailedAt, cur.LastError = &now, err.Error()
			_ = s.save(cur)
		}
	}()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	return s.shipRound(ctx, c, r, &st)
}

// shipRound reads what changed and records it.
func (s *shipper) shipRound(ctx context.Context, c *client, r *repo, st *shipLocal) error {
	now, err := serverNow(ctx, c)
	if err != nil {
		return err
	}
	dataPath, _ := c.scalar(ctx, "SELECT value FROM system.server_settings WHERE name = 'path'", nil)
	dataPath = strings.TrimSpace(dataPath)
	tables, err := liveTables(ctx, c)
	if err != nil {
		return fmt.Errorf("listing tables: %w", err)
	}
	dbs, err := liveDatabases(ctx, c)
	if err != nil {
		return fmt.Errorf("listing databases: %w", err)
	}
	parts, err := liveParts(ctx, c)
	if err != nil {
		return fmt.Errorf("listing parts: %w", err)
	}
	tables, dbs, parts = withoutRewindDBs(tables, dbs, parts)
	if st.Record == "" || st.Seen == nil {
		return s.startRecord(ctx, r, st, now, tables, dbs, parts)
	}
	// Can the data folder be read? (Only needed once there are parts.)
	if p := firstLocal(parts); p != nil {
		if _, err := os.Stat(localPath(dataPath, p.Path)); err != nil {
			st.Problem = "the agent can't read ClickHouse's data folder (" + shortError(err) + "): restores to any second need read access to it " +
				"(run the Rowsafe installer again; in Docker, mount ClickHouse's data volume into the agent, read only)"
			_ = s.save(*st)
			return errors.New(st.Problem)
		}
	}
	st.Problem = ""
	if st.PollAt.IsZero() {
		st.PollAt = st.To
	}
	if st.LastLog.IsZero() {
		st.LastLog = st.To
	}

	plog, havePartLog, err := partLog(ctx, c, st.PollAt.Add(-10*time.Minute).Unix())
	if err != nil {
		return fmt.Errorf("reading part_log: %w", err)
	}
	created := map[string]partLogRow{} // uuid/name -> row
	for _, p := range plog {
		created[p.Table+"/"+p.Name] = p
	}
	ddl := ddlTimes(ctx, c, st.PollAt.Add(-10*time.Minute).Unix())

	tracked := map[string]liveTable{}
	for _, t := range tables {
		if t.UUID != "" && t.UUID != zeroUUID && strings.Contains(t.Engine, "MergeTree") {
			tracked[t.UUID] = t
		}
	}
	nonLocal := map[string]bool{}
	for _, p := range parts {
		if p.Disk != "" && p.Disk != "Local" {
			nonLocal[p.Table] = true
		}
	}
	onDisk := map[string]bool{}
	for _, p := range parts {
		onDisk[p.Table+"/"+p.Name] = true
	}
	// Changes are noticed at most this early: after the last round.
	floor := st.PollAt.Add(time.Microsecond)
	atLeast := func(t time.Time) time.Time {
		if t.Before(floor) {
			return floor
		}
		return t
	}
	pend := func(ev pitEvent, key string, resolved bool) {
		st.Pending = append(st.Pending, pendingEvent{Ev: ev, Key: key, Resolved: resolved, Noticed: now})
	}

	// 1. Definitions, noticed now; their time comes from query_log.
	for _, d := range dbs {
		def := pitDB{UUID: d.UUID, Name: d.Name, Engine: d.Engine, Create: d.create(), At: floor}
		if old, ok := st.DBs[d.UUID]; !ok || old.Name != def.Name || old.Create != def.Create {
			pend(pitEvent{At: floor, Kind: evDB, DB: &def}, "", true)
			st.DBs[d.UUID] = def
		}
	}
	live := tablesByUUID(tables)
	for _, t := range tables {
		if t.UUID == "" || t.UUID == zeroUUID {
			continue
		}
		def := pitTable{UUID: t.UUID, DB: t.DB, Name: t.Name, Engine: t.Engine, Create: t.Create,
			Parts: tracked[t.UUID].UUID != "" && !nonLocal[t.UUID], Refreshable: refreshableRE.MatchString(t.Create)}
		for i := range min(len(t.DepDBs), len(t.DepTables)) {
			def.Dependents = append(def.Dependents, t.DepDBs[i]+"."+t.DepTables[i])
		}
		old, ok := st.Tables[t.UUID]
		if ok && old.DB == def.DB && old.Name == def.Name && old.Create == def.Create && old.Parts == def.Parts {
			continue
		}
		at, resolved := floor, false
		if dt, ok := lastIn(ddl[t.DB+"."+t.Name], st.PollAt, now); ok {
			at, resolved = dt, true
		} else if t.MetaTime > 0 {
			at = atLeast(time.Unix(t.MetaTime, 0).UTC())
		}
		def.At = at
		d := def
		pend(pitEvent{At: at, Kind: evTable, Table: t.UUID, Def: &d}, "ddl:"+t.DB+"."+t.Name, resolved)
		st.Pending[len(st.Pending)-1].After = st.PollAt
		st.Tables[t.UUID] = def
	}
	for uuid, old := range st.Tables {
		if _, ok := live[uuid]; ok {
			continue
		}
		at, resolved := floor, false
		if dt, ok := lastIn(ddl[old.DB+"."+old.Name], st.PollAt, now); ok {
			at, resolved = dt, true
		}
		pend(pitEvent{At: at, Kind: evDrop, Table: uuid}, "ddl:"+old.DB+"."+old.Name, resolved)
		st.Pending[len(st.Pending)-1].After = st.PollAt
		delete(st.Tables, uuid)
	}
	liveDBs := map[string]bool{}
	for _, d := range dbs {
		liveDBs[d.UUID] = true
	}
	for uuid := range st.DBs {
		if !liveDBs[uuid] {
			pend(pitEvent{At: floor, Kind: evDropDB, UUID: uuid}, "", true)
			delete(st.DBs, uuid)
		}
	}

	// 2. New parts: copied now (they are on disk now, maybe not for long);
	// their exact time comes from part_log.
	var news []livePart
	for _, p := range parts {
		if isTracked(tracked, nonLocal, p.Table) && !st.Seen[p.Table][p.Name] {
			news = append(news, p)
		}
	}
	slices.SortFunc(news, func(a, b livePart) int { return strings.Compare(a.Name, b.Name) })
	cw := &chunkWriter{r: r}
	defer cw.abort()
	copied := 0
	for _, lp := range news {
		p := &pitPart{Name: lp.Name, Partition: lp.Partition, Rows: lp.Rows, At: atLeast(time.Unix(lp.ModTime, 0).UTC())}
		files, err := s.copyPart(ctx, cw, st, lp.Table, localPath(dataPath, lp.Path), lp.Name)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if _, statErr := os.Stat(localPath(dataPath, lp.Path)); statErr == nil {
				return fmt.Errorf("copying part %s: %w", lp.Name, err)
			}
			files = nil // removed meanwhile: its sources stand in
		}
		p.Files = files
		pend(pitEvent{At: p.At, Kind: evPart, Table: lp.Table, Part: p}, lp.Table+"/"+lp.Name, false)
		if st.Seen[lp.Table] == nil {
			st.Seen[lp.Table] = map[string]bool{}
		}
		st.Seen[lp.Table][lp.Name] = true
		copied++
	}
	if err := cw.close(ctx); err != nil {
		return fmt.Errorf("storing copied parts: %w", err)
	}
	// Parts created since the last round and gone already (the agent was
	// stopped, or behind, for longer than ClickHouse keeps them).
	for _, row := range plog {
		at := time.UnixMicro(row.At).UTC()
		if !at.After(st.PollAt) || onDisk[row.Table+"/"+row.Name] || st.Seen[row.Table][row.Name] {
			continue
		}
		if _, ok := tracked[row.Table]; !ok {
			continue
		}
		p := &pitPart{Name: row.Name, Rows: row.Rows, At: at, Sources: row.Sources}
		pend(pitEvent{At: at, Kind: evPart, Table: row.Table, Part: p}, "", true)
		if st.Seen[row.Table] == nil {
			st.Seen[row.Table] = map[string]bool{}
		}
		st.Seen[row.Table][row.Name] = true
	}
	if !havePartLog && now.Sub(st.PollAt) > 7*time.Minute {
		g := &pitGap{From: st.PollAt, To: now, Why: "the agent wasn't copying ClickHouse's changes for longer than ClickHouse keeps replaced parts"}
		pend(pitEvent{At: floor, Kind: evGap, Gap: g}, "", true)
	}

	// 3. Exact times for what is waiting.
	for i := range st.Pending {
		pe := &st.Pending[i]
		if pe.Resolved {
			continue
		}
		switch {
		case pe.Ev.Kind == evPart:
			if row, ok := created[pe.Key]; ok {
				pe.Ev.At, pe.Resolved = time.UnixMicro(row.At).UTC(), true
				pe.Ev.Part.At = pe.Ev.At
				if len(pe.Ev.Part.Sources) == 0 {
					pe.Ev.Part.Sources = row.Sources
				}
			}
		case strings.HasPrefix(pe.Key, "ddl:"):
			if dt, ok := lastIn(ddl[strings.TrimPrefix(pe.Key, "ddl:")], pe.After, pe.Noticed); ok {
				pe.Ev.At, pe.Resolved = dt, true
			}
		}
		if !pe.Resolved && (now.Sub(pe.Noticed) > partLogWait || (!havePartLog && pe.Ev.Kind == evPart)) {
			pe.Resolved = true // the time it was noticed (to the second)
		}
		if pe.Ev.Def != nil {
			pe.Ev.Def.At = pe.Ev.At
		}
	}

	// 4. Record everything up to the first change whose time isn't known.
	cutoff := now
	for _, pe := range st.Pending {
		if !pe.Resolved {
			if t := pe.Ev.At.Truncate(time.Second).Add(-time.Microsecond); t.Before(cutoff) {
				cutoff = t
			}
		}
	}
	if !cutoff.After(st.LastLog) {
		cutoff = st.LastLog
	}
	var evs []pitEvent
	var keep []pendingEvent
	for _, pe := range st.Pending {
		if pe.Resolved && !pe.Ev.At.After(cutoff) {
			if !pe.Ev.At.After(st.LastLog) {
				pe.Ev.At = st.LastLog.Add(time.Microsecond)
				if pe.Ev.Part != nil {
					pe.Ev.Part.At = pe.Ev.At
				}
			}
			evs = append(evs, pe.Ev)
			continue
		}
		keep = append(keep, pe)
	}
	if len(evs) > 0 {
		sortEvents(evs)
		l := pitLog{Record: st.Record, From: st.LastLog, To: cutoff, Events: evs}
		if err := r.putJSON(ctx, logKey(cutoff, randomID("")), l); err != nil {
			return fmt.Errorf("storing the record of changes: %w", err)
		}
		st.LastLog = cutoff
	}
	st.Pending = keep

	// Seen: what is on disk now (parts that left the disk are forgotten;
	// their names never come back).
	for table, names := range st.Seen {
		for name := range names {
			if !onDisk[table+"/"+name] {
				delete(names, name)
			}
		}
		if len(names) == 0 {
			delete(st.Seen, table)
		}
	}
	for _, p := range parts {
		if !isTracked(tracked, nonLocal, p.Table) {
			if st.Seen[p.Table] == nil {
				st.Seen[p.Table] = map[string]bool{}
			}
			st.Seen[p.Table][p.Name] = true
		}
	}
	for k, f := range st.Files {
		if !onDisk[f.Part] {
			delete(st.Files, k)
		}
	}
	st.PollAt = now
	if cutoff.After(st.To) {
		st.To = cutoff
	}
	if copied > 0 {
		t := time.Now().UTC()
		st.Shipped += int64(copied)
		st.LastShippedAt = &t
	}
	if err := r.putJSON(ctx, pitrHeadKey, pitHead{Record: st.Record, Started: st.Started, To: st.To}); err != nil {
		return fmt.Errorf("storing the record's head: %w", err)
	}
	return s.save(*st)
}

// pendingEvent is a change noticed but not recorded yet: its exact time
// isn't known yet (part_log and query_log are written every few seconds),
// or a change before it is waiting.
type pendingEvent struct {
	Ev       pitEvent  `json:"ev"`
	Key      string    `json:"key,omitempty"` // "uuid/part" or "ddl:db.table"
	Resolved bool      `json:"resolved,omitempty"`
	Noticed  time.Time `json:"noticed"`
	// After: a definition changed after this (the round before).
	After time.Time `json:"after,omitzero"`
}

const zeroUUID = "00000000-0000-0000-0000-000000000000"

func isTracked(tracked map[string]liveTable, nonLocal map[string]bool, uuid string) bool {
	_, ok := tracked[uuid]
	return ok && !nonLocal[uuid]
}

func tablesByUUID(ts []liveTable) map[string]liveTable {
	m := make(map[string]liveTable, len(ts))
	for _, t := range ts {
		m[t.UUID] = t
	}
	return m
}

func firstLocal(parts []livePart) *livePart {
	for i := range parts {
		if parts[i].Disk == "" || parts[i].Disk == "Local" {
			return &parts[i]
		}
	}
	return nil
}

// ddlTime is when a table's definition changed: query_log's time when it
// has one in this round, else its metadata's time (to the second), kept
// inside (from, cutoff].
func ddlTime(ddl map[string]int64, table string, metaTime int64, from, cutoff time.Time) time.Time {
	at := time.Time{}
	if us, ok := ddl[table]; ok {
		at = time.UnixMicro(us).UTC()
	} else if metaTime > 0 {
		at = time.Unix(metaTime, 0).UTC()
	}
	if !at.After(from) {
		at = from.Add(time.Microsecond)
	}
	return at
}

// startRecord starts a new record: what is there now is in the next
// backup; changes are recorded from here on.
func (s *shipper) startRecord(ctx context.Context, r *repo, st *shipLocal, now time.Time, tables []liveTable, dbs []liveDB, parts []livePart) error {
	st.Record = randomID("")
	st.Started, st.To, st.PollAt, st.LastLog, st.Pending = now, now, now, now, nil
	st.Seen = map[string]map[string]bool{}
	for _, p := range parts {
		if st.Seen[p.Table] == nil {
			st.Seen[p.Table] = map[string]bool{}
		}
		st.Seen[p.Table][p.Name] = true
	}
	st.Tables, st.DBs, st.Files = map[string]pitTable{}, map[string]pitDB{}, map[string]copiedFile{}
	for _, t := range tables {
		if t.UUID == "" || t.UUID == zeroUUID {
			continue
		}
		st.Tables[t.UUID] = pitTable{UUID: t.UUID, DB: t.DB, Name: t.Name, Engine: t.Engine, Create: t.Create, At: now,
			Parts: strings.Contains(t.Engine, "MergeTree")}
	}
	for _, d := range dbs {
		st.DBs[d.UUID] = pitDB{UUID: d.UUID, Name: d.Name, Engine: d.Engine, Create: d.create(), At: now}
	}
	if err := r.putJSON(ctx, pitrHeadKey, pitHead{Record: st.Record, Started: st.Started, To: st.To}); err != nil {
		return fmt.Errorf("storing the record's head: %w", err)
	}
	return s.save(*st)
}

// copyPart copies a part's files into the chunk (files already copied
// with an earlier part, linked into this one, are reused).
func (s *shipper) copyPart(ctx context.Context, cw *chunkWriter, st *shipLocal, table, dir, name string) ([]pitFile, error) {
	names, err := partFileList(dir)
	if err != nil {
		return nil, err
	}
	if st.Files == nil {
		st.Files = map[string]copiedFile{}
	}
	var out []pitFile
	for _, n := range names {
		path := filepath.Join(dir, filepath.FromSlash(n))
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		key := inodeKey(fi)
		if key != "" {
			if cf, ok := st.Files[key]; ok && time.Since(cf.At) < reuseWindow {
				f.Close()
				out = append(out, pitFile{Name: n, Size: fi.Size(), Pieces: cf.Pieces})
				continue
			}
		}
		piece, err := cw.add(ctx, f, fi.Size())
		f.Close()
		if err != nil {
			return nil, err
		}
		var ps []s3gw.Piece
		if fi.Size() > 0 {
			ps = []s3gw.Piece{piece}
		}
		if key != "" {
			st.Files[key] = copiedFile{Part: table + "/" + name, Pieces: ps, At: time.Now().UTC()}
		}
		out = append(out, pitFile{Name: n, Size: fi.Size(), Pieces: ps})
	}
	return out, nil
}

// chunkWriter streams files into one sealed chunk object.
type chunkWriter struct {
	r    *repo
	key  string
	pw   *io.PipeWriter
	seal io.WriteCloser
	off  int64
	done chan error
}

func (w *chunkWriter) open(ctx context.Context) error {
	w.key = chunkKey(time.Now(), randomID(""))
	pr, pw := io.Pipe()
	w.pw, w.done = pw, make(chan error, 1)
	// The upload reads first: Seal writes its header right away.
	go func() {
		_, err := w.r.st.Put(ctx, w.key, pr)
		pr.CloseWithError(err)
		w.done <- err
	}()
	seal, err := objstore.Seal(pw, w.r.pass)
	if err != nil {
		pw.CloseWithError(err)
		<-w.done
		w.pw = nil
		return err
	}
	w.seal = seal
	return nil
}

// add appends size bytes of f and says where they are.
func (w *chunkWriter) add(ctx context.Context, f io.Reader, size int64) (s3gw.Piece, error) {
	if size == 0 {
		return s3gw.Piece{}, nil
	}
	if w.pw == nil {
		if err := w.open(ctx); err != nil {
			return s3gw.Piece{}, err
		}
	}
	n, err := io.CopyN(w.seal, f, size)
	p := s3gw.Piece{Stored: w.key, Off: w.off, Len: n}
	w.off += n
	if err != nil {
		return p, fmt.Errorf("reading a part file: %w", err)
	}
	return p, nil
}

func (w *chunkWriter) close(ctx context.Context) error {
	if w.pw == nil {
		return nil
	}
	err := w.seal.Close()
	w.pw.CloseWithError(err)
	perr := <-w.done
	w.pw = nil
	if err != nil {
		return err
	}
	return perr
}

func (w *chunkWriter) abort() {
	if w.pw != nil {
		w.pw.CloseWithError(errors.New("aborted"))
		<-w.done
		w.pw = nil
	}
}

// liveDB is a user database.
type liveDB struct {
	UUID       string `json:"t"`
	Name       string `json:"name"`
	Engine     string `json:"engine"`
	EngineFull string `json:"engine_full"`
}

// create is the database's CREATE as BACKUP writes it.
func (d liveDB) create() string {
	s := "CREATE DATABASE " + quoteIdent(d.Name)
	if d.UUID != "" && d.UUID != zeroUUID {
		s += " UUID '" + d.UUID + "'"
	}
	e := d.EngineFull
	if e == "" {
		e = d.Engine
	}
	return s + "\nENGINE = " + e
}

func liveDatabases(ctx context.Context, c *client) ([]liveDB, error) {
	rows, err := query[liveDB](ctx, c, `SELECT toString(uuid) AS t, name, engine, engine_full FROM system.databases
		WHERE name NOT IN ('system', 'information_schema', 'INFORMATION_SCHEMA')`, nil)
	if err != nil {
		return nil, err
	}
	var out []liveDB
	for _, d := range rows {
		if slices.Contains(backupDatabaseEngines, d.Engine) {
			out = append(out, d)
		}
	}
	return out, nil
}

// withoutRewindDBs leaves out the databases a rewind in place makes for
// itself (inplace.go): they are never restored.
func withoutRewindDBs(tables []liveTable, dbs []liveDB, parts []livePart) ([]liveTable, []liveDB, []livePart) {
	skip := map[string]bool{}
	var ts []liveTable
	for _, t := range tables {
		if isRewindDB(t.DB) {
			skip[t.UUID] = true
			continue
		}
		ts = append(ts, t)
	}
	var ds []liveDB
	for _, d := range dbs {
		if !isRewindDB(d.Name) {
			ds = append(ds, d)
		}
	}
	var ps []livePart
	for _, p := range parts {
		if !skip[p.Table] {
			ps = append(ps, p)
		}
	}
	return ts, ds, ps
}
