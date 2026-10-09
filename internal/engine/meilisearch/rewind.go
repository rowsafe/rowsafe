package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind copies: a temporary Meilisearch started from a snapshot next to
// production (127.0.0.1 only, its own master key), up until it expires.
// Comparing and bringing documents back read it by primary key; document
// contents stay on this server, only counts are reported.

const (
	defaultCopyHours = 24
	maxCopyAge       = 7 * 24 * time.Hour
	// compareMaxDocs caps the documents compared per index; past it the
	// result says it was sampled. Changed documents are counted only up to
	// deepCompareMax documents (their content is read on both sides).
	compareMaxDocs = 5_000_000
	deepCompareMax = 200_000
	// defaultMaxDocs is the most documents one bring-back writes.
	defaultMaxDocs = 10_000_000
	fetchBatch     = 500
)

// copyRecord is a copy the engine keeps (<state>/copies.json).
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	DBPort      int                   `json:"db_port"` // production's port (its program and settings)
	Port        int                   `json:"port"`
	Dir         string                `json:"dir"`
	Status      string                `json:"status"`
	Target      protocol.RewindTarget `json:"target"`
	Label       string                `json:"label"`
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	SizeBytes   int64                 `json:"size_bytes"`
}

type copyStore struct {
	mu      sync.Mutex
	path    string
	records map[string]copyRecord
	live    map[string]*scratch
}

func (e *Engine) copyState(env agent.EngineEnv) *copyStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.copies == nil {
		cs := &copyStore{path: filepath.Join(env.StateDir, "copies.json"), records: map[string]copyRecord{}, live: map[string]*scratch{}}
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
	slices.SortFunc(list, func(a, b copyRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return saveJSONFile(cs.path, list)
}

func (cs *copyStore) put(r copyRecord) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.records[r.ID] = r
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
	slices.SortFunc(out, func(a, b copyRecord) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// drop stops and deletes a copy; false when there is none.
func (cs *copyStore) drop(id string) (int64, bool, error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	r, ok := cs.records[id]
	if !ok {
		return 0, false, nil
	}
	sc := cs.live[id]
	if sc == nil {
		var err error
		if sc, err = scratchAt(r.Dir, ""); err != nil {
			sc = &scratch{Dir: r.Dir}
		}
	}
	sc.stop()
	killLeftover(r.Dir)
	freed := dirSize(r.Dir)
	if err := sc.remove(); err != nil {
		return 0, true, err
	}
	delete(cs.live, id)
	delete(cs.records, id)
	return freed, true, cs.saveLocked()
}

// clientFor is a client for a ready copy (started again when the agent
// restarted since).
func (e *Engine) copyClient(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, id string) (*client, copyRecord, error) {
	cs := e.copyState(env)
	r, ok := cs.get(id)
	if !ok || r.DatabaseID != db.ID {
		return nil, r, fmt.Errorf("there is no copy %s of this database on this server (it expired or was removed)", id)
	}
	if r.Status != protocol.RewindCopyReady {
		return nil, r, fmt.Errorf("the copy %s isn't ready (%s)", id, r.Status)
	}
	cs.mu.Lock()
	sc := cs.live[id]
	cs.mu.Unlock()
	if sc == nil || !sc.running() {
		var err error
		if sc, err = e.startCopy(ctx, env, db, r); err != nil {
			return nil, r, err
		}
	}
	return sc.client(), r, nil
}

// startCopy starts a copy's instance again (agent restart).
func (e *Engine) startCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, r copyRecord) (*scratch, error) {
	s, err := loadServer(env, db.Port)
	if err != nil {
		return nil, err
	}
	killLeftover(r.Dir)
	sc, err := scratchAt(r.Dir, s.Binary)
	if err != nil {
		return nil, err
	}
	if err := sc.start(ctx, startOptions{}); err != nil {
		return nil, fmt.Errorf("starting the copy again: %w", err)
	}
	cs := e.copyState(env)
	cs.mu.Lock()
	cs.live[r.ID] = sc
	if rec, ok := cs.records[r.ID]; ok {
		rec.Port = sc.Port
		cs.records[r.ID] = rec
		_ = cs.saveLocked()
	}
	cs.mu.Unlock()
	return sc, nil
}

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	cs := e.copyState(env)
	if _, ok := cs.get(p.CopyID); ok {
		return nil, fmt.Errorf("the copy %s exists already", p.CopyID)
	}
	s, err := loadServer(env, db.Port)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	doc, err := pick(ctx, r, p.Target)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	expires := clampExpiry(p.Expires, now)
	taken := doc.TakenAt
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, DBPort: db.Port, Dir: filepath.Join(copyRoot(env), p.CopyID), Status: protocol.RewindCopyRestoring,
		Target: p.Target, Label: doc.Label, CreatedAt: now, Expires: expires, RecoveredTo: &taken}
	if err := cs.put(rec); err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	sc, err := restoreScratch(ctx, env, r, s, doc, copyRoot(env), p.CopyID, tl)
	e.copyMu.Unlock()
	if err != nil {
		cs.mu.Lock()
		delete(cs.records, p.CopyID)
		_ = cs.saveLocked()
		cs.mu.Unlock()
		return nil, err
	}
	c := sc.client()
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		sc.stop()
		_ = sc.remove()
		cs.mu.Lock()
		delete(cs.records, p.CopyID)
		_ = cs.saveLocked()
		cs.mu.Unlock()
		return nil, err
	}
	rec.Status, rec.Port, rec.SizeBytes = protocol.RewindCopyReady, sc.Port, dirSize(sc.dbPath())
	cs.mu.Lock()
	cs.records[rec.ID], cs.live[rec.ID] = rec, sc
	err = cs.saveLocked()
	cs.mu.Unlock()
	if err != nil {
		return nil, err
	}
	res := &protocol.RewindCopyResult{CopyID: p.CopyID, RecoveredTo: &taken, SizeBytes: rec.SizeBytes, Port: sc.Port, Expires: expires,
		Databases: in.inspectResult(sc.Port).Databases}
	res.Summary = fmt.Sprintf("A copy of %s as it was at %s (snapshot %s) is ready on this server: %s, %s. It is deleted %s.",
		db.Name, taken.Format("2006-01-02 15:04:05 UTC"), doc.Label, plural(int64(len(in.Indexes)), "index", "indexes"),
		plural(in.documents(), "document", "documents"), expires.Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func clampExpiry(want, now time.Time) time.Time {
	if want.IsZero() {
		return now.Add(defaultCopyHours * time.Hour)
	}
	if want.After(now.Add(maxCopyAge)) {
		return now.Add(maxCopyAge)
	}
	if want.Before(now.Add(time.Minute)) {
		return now.Add(time.Minute)
	}
	return want.UTC()
}

func (e *Engine) rewindDrop(env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindDropParams, tl agent.TaskLogger) (*protocol.RewindDropResult, error) {
	cs := e.copyState(env)
	if r, ok := cs.get(p.CopyID); ok && r.DatabaseID != db.ID {
		return nil, fmt.Errorf("the copy %s isn't this database's", p.CopyID)
	}
	freed, ok, err := cs.drop(p.CopyID)
	if err != nil {
		return nil, err
	}
	res := &protocol.RewindDropResult{CopyID: p.CopyID, Removed: ok, FreedBytes: freed, Summary: "There was no such copy any more."}
	if ok {
		res.Summary = fmt.Sprintf("The copy was removed (%s freed).", humanBytes(freed))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// recoverCopies starts ready copies again after an agent restart and
// forgets those that never finished.
func (e *Engine) recoverCopies(ctx context.Context, env agent.EngineEnv) {
	cs := e.copyState(env)
	for _, r := range cs.all() {
		if r.Status != protocol.RewindCopyReady {
			_, _, _ = cs.drop(r.ID)
			continue
		}
		db, ok := e.copyDatabase(env, r)
		if !ok {
			continue
		}
		if _, err := e.startCopy(ctx, env, db, r); err != nil {
			env.Log.Error("starting a copy again failed", "copy_id", r.ID, "err", err)
		}
	}
}

// copyDatabase is the production instance a copy came from (its port,
// for the program's path).
func (e *Engine) copyDatabase(env agent.EngineEnv, r copyRecord) (protocol.DatabaseSpec, bool) {
	if r.DBPort <= 0 || !slices.Contains(knownPorts(env), r.DBPort) {
		return protocol.DatabaseSpec{}, false
	}
	return protocol.DatabaseSpec{ID: r.DatabaseID, Port: r.DBPort, Engine: protocol.EngineMeilisearch}, true
}

// stopCopies stops the copies' instances (the agent stops).
func (e *Engine) stopCopies(env agent.EngineEnv) {
	cs := e.copyState(env)
	cs.mu.Lock()
	defer cs.mu.Unlock()
	for id, sc := range cs.live {
		sc.stop()
		delete(cs.live, id)
	}
}

// expireCopies deletes copies past their expiry.
func (e *Engine) expireCopies(env agent.EngineEnv, now time.Time) {
	cs := e.copyState(env)
	for _, r := range cs.all() {
		if r.Status != protocol.RewindCopyReady || now.Before(r.Expires) {
			continue
		}
		if freed, _, err := cs.drop(r.ID); err != nil {
			env.Log.Error("removing an expired copy failed", "copy_id", r.ID, "err", err)
		} else {
			env.Log.Info("removed an expired copy", "copy_id", r.ID, "freed", humanBytes(freed))
		}
	}
}

// RewindStates reports the copies and kept indexes (heartbeat).
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
		if k, ok := env.Kept().Get(x.ID); ok && !x.Expires.Equal(k.Expires) && k.Status != protocol.RewindInProgress {
			k.Expires = x.Expires.UTC()
			_ = env.Kept().Put(k)
		}
	}
}

// ---- compare and bring documents back

// indexesFor are the indexes a compare or bring-back covers: those asked
// for, or every index of the copy.
func indexesFor(tables []protocol.RewindTable, copyIn instance) ([]string, error) {
	if len(tables) == 0 {
		var out []string
		for _, i := range copyIn.Indexes {
			out = append(out, i.UID)
		}
		return out, nil
	}
	var out []string
	for _, t := range tables {
		if err := protocol.ValidMeilisearchIndex(t.Table, false); err != nil {
			return nil, err
		}
		if !slices.Contains(out, t.Table) {
			out = append(out, t.Table)
		}
	}
	return out, nil
}

// idSet reads every primary key value of an index (up to limit).
func idSet(ctx context.Context, c *client, uid, pk string, limit int64) (map[string]json.RawMessage, bool, error) {
	out := map[string]json.RawMessage{}
	errFull := errors.New("full")
	err := c.documentIDs(ctx, uid, pk, func(ids []json.RawMessage) error {
		for _, id := range ids {
			if int64(len(out)) >= limit {
				return errFull
			}
			out[string(id)] = id
		}
		return nil
	})
	if errors.Is(err, errFull) {
		return out, true, nil
	}
	return out, false, err
}

// docHashes reads every document of an index and hashes it by primary key.
func docHashes(ctx context.Context, c *client, uid, pk string) (map[string][32]byte, error) {
	out := map[string][32]byte{}
	const page = 1000
	for offset := 0; ; offset += page {
		var res struct {
			Results []map[string]json.RawMessage `json:"results"`
			Total   int                          `json:"total"`
		}
		q := url.Values{"limit": {strconv.Itoa(page)}, "offset": {strconv.Itoa(offset)}}
		if err := c.do(ctx, http.MethodGet, "/indexes/"+url.PathEscape(uid)+"/documents", q, nil, &res); err != nil {
			return nil, err
		}
		for _, d := range res.Results {
			canon, _ := json.Marshal(d) // keys sorted
			out[string(d[pk])] = sha256.Sum256(canon)
		}
		if len(res.Results) < page || offset+page >= res.Total {
			return out, nil
		}
	}
}

// indexDiff compares one index between the copy and production.
type indexDiff struct {
	UID                    string
	PK                     string
	Missing, Changed, Only []json.RawMessage
	Sampled, Shallow       bool
	Skipped                string
	CopyDocs               int64
}

func diffIndex(ctx context.Context, cc, pc *client, uid string, copyStats indexStats, deep bool) (indexDiff, error) {
	d := indexDiff{UID: uid, CopyDocs: copyStats.NumberOfDocuments}
	ci, err := cc.index(ctx, uid)
	if err != nil {
		if isCode(err, "index_not_found") {
			d.Skipped = "the copy has no index " + uid
			return d, nil
		}
		return d, err
	}
	d.PK = ci.primaryKey()
	if d.PK == "" {
		d.Skipped = "the index has no primary key yet (no documents)"
		return d, nil
	}
	pi, err := pc.index(ctx, uid)
	prodMissing := isCode(err, "index_not_found")
	if err != nil && !prodMissing {
		return d, err
	}
	copyIDs, sampled, err := idSet(ctx, cc, uid, d.PK, compareMaxDocs)
	if err != nil {
		return d, err
	}
	d.Sampled = sampled
	prodIDs := map[string]json.RawMessage{}
	if !prodMissing {
		if pi.primaryKey() != "" && pi.primaryKey() != d.PK {
			d.Skipped = fmt.Sprintf("production's index %s has another primary key (%s, the copy's is %s)", uid, pi.primaryKey(), d.PK)
			return d, nil
		}
		if prodIDs, _, err = idSet(ctx, pc, uid, d.PK, compareMaxDocs); err != nil {
			return d, err
		}
	}
	for k, v := range copyIDs {
		if _, ok := prodIDs[k]; !ok {
			d.Missing = append(d.Missing, v)
		}
	}
	for k, v := range prodIDs {
		if _, ok := copyIDs[k]; !ok && !sampled {
			d.Only = append(d.Only, v)
		}
	}
	if !deep || prodMissing || int64(len(copyIDs)) > deepCompareMax || int64(len(prodIDs)) > deepCompareMax {
		d.Shallow = !prodMissing
		return d, nil
	}
	ch, err := docHashes(ctx, cc, uid, d.PK)
	if err != nil {
		return d, err
	}
	ph, err := docHashes(ctx, pc, uid, d.PK)
	if err != nil {
		return d, err
	}
	for k, h := range ch {
		if p, ok := ph[k]; ok && p != h {
			d.Changed = append(d.Changed, copyIDs[k])
		}
	}
	return d, nil
}

func (e *Engine) rewindCompare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	cc, _, err := e.copyClient(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer cc.close()
	pc, _, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer pc.close()
	copyIn, err := inspect(ctx, cc)
	if err != nil {
		return nil, err
	}
	uids, err := indexesFor(p.Tables, copyIn)
	if err != nil {
		return nil, err
	}
	stats := map[string]indexStats{}
	for _, i := range copyIn.Indexes {
		stats[i.UID] = i.Stats
	}
	res := &protocol.RewindCompareResult{CopyID: p.CopyID, Tables: []protocol.RewindTableDiff{}}
	var missing, changed int64
	for _, uid := range uids {
		d, err := diffIndex(ctx, cc, pc, uid, stats[uid], true)
		if err != nil {
			return nil, fmt.Errorf("comparing the index %s: %w", uid, err)
		}
		td := protocol.RewindTableDiff{RewindTable: protocol.RewindTable{Table: uid}, MissingInProduction: int64(len(d.Missing)),
			Changed: int64(len(d.Changed)), OnlyInProduction: int64(len(d.Only)), Skipped: d.Skipped, SizeBytes: stats[uid].IndexSize}
		switch {
		case d.Sampled:
			td.Note = fmt.Sprintf("only the first %s documents of the copy were compared", commas(compareMaxDocs))
		case d.Shallow:
			td.Note = "changed documents aren't counted on indexes this large: only missing and added ones"
		}
		missing += td.MissingInProduction
		changed += td.Changed
		res.Tables = append(res.Tables, td)
	}
	res.Summary = fmt.Sprintf("Compared %s: %s missing from production, %s changed since.", plural(int64(len(uids)), "index", "indexes"),
		plural(missing, "document", "documents"), plural(changed, "document", "documents"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) rewindRows(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("choose the indexes to bring documents back to")
	}
	cc, _, err := e.copyClient(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer cc.close()
	pc, _, err := connect(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer pc.close()
	copyIn, err := inspect(ctx, cc)
	if err != nil {
		return nil, err
	}
	uids, err := indexesFor(p.Tables, copyIn)
	if err != nil {
		return nil, err
	}
	stats := map[string]indexStats{}
	for _, i := range copyIn.Indexes {
		stats[i.UID] = i.Stats
	}
	maxDocs := p.MaxRows
	if maxDocs <= 0 {
		maxDocs = defaultMaxDocs
	}
	res := &protocol.RewindRowsResult{Tables: []protocol.RewindTableRows{}}
	var total int64
	for _, uid := range uids {
		d, err := diffIndex(ctx, cc, pc, uid, stats[uid], p.IncludeChanged)
		if err != nil {
			return res, fmt.Errorf("comparing the index %s: %w", uid, err)
		}
		if d.Skipped != "" {
			tl.Printf("%s: skipped (%s)", uid, d.Skipped)
			continue
		}
		if p.IncludeChanged && d.Shallow {
			return res, fmt.Errorf("the index %s is too large to find changed documents in: bring back missing documents only", uid)
		}
		ids := d.Missing
		if p.IncludeChanged {
			ids = append(ids, d.Changed...)
		}
		if total+int64(len(ids)) > maxDocs {
			return res, fmt.Errorf("that would write %s documents, more than the limit of %s: choose fewer indexes", commas(total+int64(len(ids))), commas(maxDocs))
		}
		tr := protocol.RewindTableRows{RewindTable: protocol.RewindTable{Table: uid}, Inserted: int64(len(d.Missing))}
		if p.IncludeChanged {
			tr.Updated = int64(len(d.Changed))
		}
		if len(ids) > 0 {
			if err := copyDocuments(ctx, cc, pc, uid, ids); err != nil {
				return res, fmt.Errorf("bringing documents back to %s: %w", uid, err)
			}
		}
		total += int64(len(ids))
		res.Tables = append(res.Tables, tr)
		tl.Printf("%s: %s brought back%s", uid, plural(tr.Inserted, "missing document", "missing documents"),
			map[bool]string{true: ", " + plural(tr.Updated, "changed document", "changed documents") + " put back as they were", false: ""}[p.IncludeChanged])
	}
	res.Summary = fmt.Sprintf("Brought back %s from the copy.", plural(total, "document", "documents"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// copyDocuments copies documents (by primary key) from the copy to
// production, a batch at a time, and waits until production indexed them.
func copyDocuments(ctx context.Context, cc, pc *client, uid string, ids []json.RawMessage) error {
	var sent []task
	for i := 0; i < len(ids); i += fetchBatch {
		batch := ids[i:min(i+fetchBatch, len(ids))]
		docs, err := cc.fetchDocuments(ctx, uid, batch)
		if err != nil {
			return err
		}
		if len(docs) == 0 {
			continue
		}
		t, err := pc.enqueue(ctx, http.MethodPost, "/indexes/"+url.PathEscape(uid)+"/documents", nil, docs)
		if err != nil {
			return err
		}
		sent = append(sent, t)
	}
	// Meilisearch runs an index's tasks in order: once the last is done,
	// every one is, and each must have succeeded.
	for i := len(sent) - 1; i >= 0; i-- {
		if _, err := pc.waitTask(ctx, sent[i], 2*time.Hour); err != nil {
			return err
		}
	}
	return nil
}
