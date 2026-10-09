package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind copies: a snapshot restored from the bucket into a temporary
// OpenSearch (scratch.go) kept until it expires; compare it with production
// by document _id, and bring documents back.

func copiesRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.RewindDir, protocol.EngineOpenSearch)
}

// copyMeta is what the agent keeps about a copy (copy.json in its folder).
type copyMeta struct {
	ID          string     `json:"id"`
	DatabaseID  string     `json:"database_id"`
	Label       string     `json:"label"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	Expires     time.Time  `json:"expires"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
}

// copyStore is the copies on this server.
type copyStore struct {
	mu    sync.Mutex
	items map[string]*copyMeta
}

func (e *Engine) store() *copyStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.copies == nil {
		e.copies = &copyStore{items: map[string]*copyMeta{}}
	}
	return e.copies
}

func copyDir(env agent.EngineEnv, id string) string { return filepath.Join(copiesRoot(env), id) }

func (m *copyMeta) save(env agent.EngineEnv) error {
	return saveJSONFile(filepath.Join(copyDir(env, m.ID), "copy.json"), m)
}

// recoverCopies reads the copies left by a previous run and starts the
// ready ones again (their servers stopped with the agent).
func (e *Engine) recoverCopies(ctx context.Context, env agent.EngineEnv) {
	st := e.store()
	entries, err := os.ReadDir(copiesRoot(env))
	if err != nil {
		return
	}
	for _, d := range entries {
		var m copyMeta
		dir := filepath.Join(copiesRoot(env), d.Name())
		if err := loadJSONFile(filepath.Join(dir, "copy.json"), &m); err != nil || m.ID != d.Name() {
			if _, err := os.Stat(filepath.Join(dir, scratchMarker)); err == nil {
				_, _ = scratchAt(dir).remove()
			}
			continue
		}
		if m.Status != protocol.RewindCopyReady || time.Now().After(m.Expires) {
			_, _ = scratchAt(dir).remove()
			continue
		}
		st.mu.Lock()
		st.items[m.ID] = &m
		st.mu.Unlock()
		go func() {
			e.copyMu.Lock()
			defer e.copyMu.Unlock()
			if err := scratchAt(dir).start(ctx); err != nil {
				env.Log.Error("starting a Rewind copy again failed", "copy", m.ID, "err", err)
			}
		}()
	}
}

// expireCopies removes the copies whose time is up.
func (e *Engine) expireCopies(env agent.EngineEnv, now time.Time) {
	st := e.store()
	st.mu.Lock()
	var gone []string
	for id, m := range st.items {
		if now.After(m.Expires) && m.Status == protocol.RewindCopyReady {
			gone = append(gone, id)
		}
	}
	st.mu.Unlock()
	for _, id := range gone {
		if _, err := scratchAt(copyDir(env, id)).remove(); err != nil {
			env.Log.Error("removing an expired Rewind copy failed", "copy", id, "err", err)
		}
		st.mu.Lock()
		delete(st.items, id)
		st.mu.Unlock()
	}
	e.expireKeptBackground(env, now)
}

// RewindStates reports the copies and kept snapshots (heartbeat).
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	var out []protocol.RewindState
	st := e.store()
	st.mu.Lock()
	for _, m := range st.items {
		exp := m.Expires
		out = append(out, protocol.RewindState{ID: m.ID, DatabaseID: m.DatabaseID, Kind: protocol.RewindKindCopy, Status: m.Status,
			SizeBytes: m.SizeBytes, Expires: &exp, CreatedAt: m.CreatedAt, RecoveredTo: m.RecoveredTo, Path: copyDir(env, m.ID)})
	}
	st.mu.Unlock()
	return append(out, e.keptStates(env)...)
}

// SetRewindExpiries applies the control plane's expiries (Extend).
func (e *Engine) SetRewindExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	st := e.store()
	st.mu.Lock()
	for _, x := range exp {
		if m := st.items[x.ID]; m != nil {
			m.Expires = clampCopyExpiry(x.Expires)
			_ = m.save(env)
		}
	}
	st.mu.Unlock()
	e.setKeptExpiries(env, exp)
}

func clampCopyExpiry(t time.Time) time.Time {
	now := time.Now()
	switch {
	case t.IsZero():
		return now.Add(24 * time.Hour)
	case t.After(now.Add(7 * 24 * time.Hour)):
		return now.Add(7 * 24 * time.Hour)
	}
	return t
}

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	st := e.store()
	st.mu.Lock()
	for _, m := range st.items {
		if m.DatabaseID == db.ID {
			st.mu.Unlock()
			return nil, errors.New("this database has a Rewind copy already: remove it first")
		}
	}
	m := &copyMeta{ID: p.CopyID, DatabaseID: db.ID, Status: protocol.RewindCopyRestoring, CreatedAt: time.Now().UTC(), Expires: clampCopyExpiry(p.Expires)}
	st.items[m.ID] = m
	st.mu.Unlock()
	drop := func() {
		_, _ = scratchAt(copyDir(env, p.CopyID)).remove()
		st.mu.Lock()
		delete(st.items, p.CopyID)
		st.mu.Unlock()
	}
	r, err := openRepo(env, db)
	if err != nil {
		drop()
		return nil, err
	}
	docs, err := r.listDocs(ctx)
	if err != nil {
		drop()
		return nil, fmt.Errorf("reading your bucket: %w", err)
	}
	doc, err := pickDoc(docs, p.Target.BackupSet, p.Target.Time)
	if err != nil {
		drop()
		return nil, err
	}
	m.Label = doc.Label
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	s, err := newScratch(copiesRoot(env), p.CopyID)
	if err != nil {
		drop()
		return nil, err
	}
	_ = m.save(env)
	out, c, err := restoreDoc(ctx, r, doc, s, tl)
	if err != nil {
		drop()
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		drop()
		return nil, err
	}
	at := doc.StoppedAt
	st.mu.Lock()
	m.Status, m.RecoveredTo, m.SizeBytes = protocol.RewindCopyReady, &at, dirSize(s.Dir)
	_ = m.save(env)
	st.mu.Unlock()
	sst, _ := s.loadState()
	res := &protocol.RewindCopyResult{CopyID: p.CopyID, RecoveredTo: &at, SizeBytes: m.SizeBytes, Databases: in.inspectResult(sst.HTTPPort).Databases,
		Port: sst.HTTPPort, Expires: m.Expires,
		Summary: fmt.Sprintf("Restored the snapshot %s (taken %s) into a copy next to production: %d indices, %s documents (%s downloaded).",
			doc.Label, doc.StoppedAt.Format("2 Jan 15:04 UTC"), len(res0(in)), commas(in.totalDocs()), humanBytes(out.Bytes))}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func res0(in serverInfo) []string { return snapshotIndices(in) }

func (e *Engine) rewindDrop(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindDropParams, tl agent.TaskLogger) (*protocol.RewindDropResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	res := &protocol.RewindDropResult{CopyID: p.CopyID}
	dir := copyDir(env, p.CopyID)
	if _, err := os.Stat(dir); err == nil {
		n, err := scratchAt(dir).remove()
		if err != nil {
			return nil, err
		}
		res.Removed, res.FreedBytes = true, n
	}
	st := e.store()
	st.mu.Lock()
	delete(st.items, p.CopyID)
	st.mu.Unlock()
	res.Summary = "Removed the copy and its files."
	if !res.Removed {
		res.Summary = "There was no such copy (already removed)."
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// copyClient is the running copy's client.
func (e *Engine) copyClient(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, id string) (*client, error) {
	st := e.store()
	st.mu.Lock()
	m := st.items[id]
	st.mu.Unlock()
	if m == nil || m.DatabaseID != db.ID {
		return nil, errors.New("this copy isn't on this server any more (it expired or was removed): restore a new one")
	}
	if m.Status != protocol.RewindCopyReady {
		return nil, errors.New("this copy is still being restored")
	}
	return scratchAt(copyDir(env, id)).running(ctx)
}

// maxCompare is how many documents of one index a compare reads.
const maxCompare = 1_000_000

// hit is one document of a scroll.
type hit struct {
	ID     string          `json:"_id"`
	Source json.RawMessage `json:"_source"`
	Found  bool            `json:"found"`
}

// scrollAll reads every document of index (up to limit) in pages, calling
// fn with each page.
func scrollAll(ctx context.Context, c *client, index string, limit int, fn func([]hit) error) (int, error) {
	var page struct {
		ScrollID string `json:"_scroll_id"`
		Hits     struct {
			Hits []hit `json:"hits"`
		} `json:"hits"`
	}
	body := map[string]any{"size": 1000, "sort": []string{"_doc"}, "query": map[string]any{"match_all": map[string]any{}}}
	if err := c.do(ctx, http.MethodPost, "/"+pathEscape(index)+"/_search?scroll=2m", body, &page); err != nil {
		return 0, err
	}
	n := 0
	defer func() {
		if page.ScrollID != "" {
			_ = c.do(context.WithoutCancel(ctx), http.MethodDelete, "/_search/scroll", map[string]any{"scroll_id": page.ScrollID}, nil)
		}
	}()
	for len(page.Hits.Hits) > 0 {
		hits := page.Hits.Hits
		if n+len(hits) > limit {
			hits = hits[:limit-n]
		}
		if err := fn(hits); err != nil {
			return n, err
		}
		n += len(hits)
		if n >= limit {
			return n, nil
		}
		id := page.ScrollID
		page.Hits.Hits = nil
		if err := c.do(ctx, http.MethodPost, "/_search/scroll", map[string]any{"scroll": "2m", "scroll_id": id}, &page); err != nil {
			return n, err
		}
	}
	return n, nil
}

// mget fetches ids from index in production.
func mget(ctx context.Context, c *client, index string, ids []string) (map[string]hit, error) {
	var v struct {
		Docs []hit `json:"docs"`
	}
	if err := c.do(ctx, http.MethodPost, "/"+pathEscape(index)+"/_mget", map[string]any{"ids": ids}, &v); err != nil {
		return nil, err
	}
	out := make(map[string]hit, len(v.Docs))
	for _, d := range v.Docs {
		if d.Found {
			out[d.ID] = d
		}
	}
	return out, nil
}

func sameSource(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// countOf counts index's documents.
func countOf(ctx context.Context, c *client, index string) (int64, error) {
	var v struct {
		Count int64 `json:"count"`
	}
	err := c.get(ctx, "/"+pathEscape(index)+"/_count", &v)
	return v.Count, err
}

// copyNames are the indices and data streams in the copy, by the names
// people see (a data stream's name for its backing indices).
func copyNames(in serverInfo) []string { return snapshotIndices(in) }

func (e *Engine) rewindCompare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	cc, err := e.copyClient(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	cin, err := inspect(ctx, cc)
	if err != nil {
		return nil, err
	}
	pin, err := inspect(ctx, prod)
	if err != nil {
		return nil, err
	}
	names := copyNames(cin)
	if len(p.Tables) > 0 {
		names = nil
		for _, t := range p.Tables {
			names = append(names, t.DB)
		}
	}
	prodNames := copyNames(pin)
	res := &protocol.RewindCompareResult{CopyID: p.CopyID}
	var missingTotal, changedTotal int64
	for _, name := range names {
		d := protocol.RewindTableDiff{RewindTable: protocol.RewindTable{DB: name, Table: "*"}}
		if !slices.Contains(copyNames(cin), name) {
			d.Skipped = "not in the copy"
			res.Tables = append(res.Tables, d)
			continue
		}
		copyCount, _ := countOf(ctx, cc, name)
		if !slices.Contains(prodNames, name) {
			d.MissingInProduction = copyCount
			d.Note = "deleted from production since"
			missingTotal += copyCount
			res.Tables = append(res.Tables, d)
			continue
		}
		prodCount, _ := countOf(ctx, prod, name)
		n, err := scrollAll(ctx, cc, name, maxCompare, func(hits []hit) error {
			ids := make([]string, len(hits))
			for i, h := range hits {
				ids[i] = h.ID
			}
			got, err := mget(ctx, prod, name, ids)
			if err != nil {
				return err
			}
			for _, h := range hits {
				ph, ok := got[h.ID]
				switch {
				case !ok:
					d.MissingInProduction++
				case !sameSource(h.Source, ph.Source):
					d.Changed++
				}
			}
			return nil
		})
		if err != nil {
			d.Skipped = "couldn't be compared: " + err.Error()
			d.MissingInProduction, d.Changed = 0, 0
			res.Tables = append(res.Tables, d)
			continue
		}
		if int64(n) < copyCount {
			d.Note = fmt.Sprintf("compared the first %s of %s documents", commas(int64(n)), commas(copyCount))
		}
		d.OnlyInProduction = max(prodCount-(copyCount-d.MissingInProduction), 0)
		missingTotal += d.MissingInProduction
		changedTotal += d.Changed
		res.Tables = append(res.Tables, d)
	}
	res.Summary = fmt.Sprintf("Compared %d indices: %s documents are only in the copy (deleted since) and %s changed.", len(names), commas(missingTotal), commas(changedTotal))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// maxRows is the agent's own limit on documents brought back in one run.
const maxRows = 10_000_000

func (e *Engine) rewindRows(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("choose the indices to bring documents back to")
	}
	limit := int64(maxRows)
	if p.MaxRows > 0 && p.MaxRows < limit {
		limit = p.MaxRows
	}
	cc, err := e.copyClient(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	pin, err := inspect(ctx, prod)
	if err != nil {
		return nil, err
	}
	cin, err := inspect(ctx, cc)
	if err != nil {
		return nil, err
	}
	streams := map[string]bool{}
	for _, s := range append(cin.DataStreams, pin.DataStreams...) {
		streams[s] = true
	}
	res := &protocol.RewindRowsResult{}
	var total int64
	for _, t := range p.Tables {
		if !slices.Contains(copyNames(cin), t.DB) {
			return res, fmt.Errorf("the copy has no index %s", t.DB)
		}
		tr := protocol.RewindTableRows{RewindTable: protocol.RewindTable{DB: t.DB, Table: "*"}}
		if !slices.Contains(copyNames(pin), t.DB) && !streams[t.DB] {
			// The index is gone: make it again with the copy's mappings and
			// settings that can be set.
			if err := recreateIndex(ctx, cc, prod, t.DB); err != nil {
				return res, fmt.Errorf("making the index %s again: %w", t.DB, err)
			}
			tl.Printf("made the index %s again, with the copy's mappings", t.DB)
		}
		var bulk bytes.Buffer
		flush := func() error {
			if bulk.Len() == 0 {
				return nil
			}
			var v struct {
				Errors bool `json:"errors"`
				Items  []map[string]struct {
					Status int `json:"status"`
					Error  *struct {
						Type   string `json:"type"`
						Reason string `json:"reason"`
					} `json:"error"`
				} `json:"items"`
			}
			_, data, err := prod.raw(ctx, http.MethodPost, "/_bulk", bytes.NewReader(bulk.Bytes()), "application/x-ndjson")
			bulk.Reset()
			if err != nil {
				return err
			}
			if err := json.Unmarshal(data, &v); err != nil {
				return err
			}
			for _, it := range v.Items {
				for op, r := range it {
					switch {
					case r.Error != nil && r.Status == http.StatusConflict:
						tr.Conflicts++
					case r.Error != nil:
						return fmt.Errorf("writing to %s: %s", t.DB, r.Error.Reason)
					case op == "create":
						tr.Inserted++
					default:
						tr.Updated++
					}
				}
			}
			return nil
		}
		_, err := scrollAll(ctx, cc, t.DB, int(limit), func(hits []hit) error {
			ids := make([]string, len(hits))
			for i, h := range hits {
				ids[i] = h.ID
			}
			got := map[string]hit{}
			if slices.Contains(copyNames(pin), t.DB) || streams[t.DB] {
				var err error
				if got, err = mget(ctx, prod, t.DB, ids); err != nil && statusOf(err) != http.StatusNotFound {
					return err
				}
			}
			for _, h := range hits {
				ph, ok := got[h.ID]
				op := ""
				switch {
				case !ok:
					op = "create"
				case p.IncludeChanged && !streams[t.DB] && !sameSource(h.Source, ph.Source):
					op = "index"
				}
				if op == "" {
					continue
				}
				if total+tr.Inserted+tr.Updated >= limit {
					return fmt.Errorf("more than %s documents would change: nothing more is brought back in this run", commas(limit))
				}
				meta, _ := json.Marshal(map[string]any{op: map[string]any{"_index": t.DB, "_id": h.ID}})
				bulk.Write(meta)
				bulk.WriteByte('\n')
				bulk.Write(h.Source)
				bulk.WriteByte('\n')
				if bulk.Len() > 8<<20 {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			return flush()
		})
		total += tr.Inserted + tr.Updated
		res.Tables = append(res.Tables, tr)
		if err != nil {
			return res, err
		}
	}
	_ = prod.do(ctx, http.MethodPost, "/_refresh?ignore_unavailable=true", nil, nil)
	var parts []string
	for _, t := range res.Tables {
		s := fmt.Sprintf("%s in %s", commas(t.Inserted), t.DB)
		if t.Updated > 0 {
			s += fmt.Sprintf(" (and %s set back)", commas(t.Updated))
		}
		parts = append(parts, s)
	}
	res.Summary = "Brought back " + strings.Join(parts, ", ") + " documents."
	tl.Printf("%s", res.Summary)
	return res, nil
}

// recreateIndex makes index in production with the copy's mappings and
// the settings an index can be created with.
func recreateIndex(ctx context.Context, cc, prod *client, index string) error {
	var v map[string]struct {
		Mappings json.RawMessage `json:"mappings"`
		Settings struct {
			Index map[string]any `json:"index"`
		} `json:"settings"`
	}
	if err := cc.get(ctx, "/"+pathEscape(index), &v); err != nil {
		return err
	}
	src, ok := v[index]
	if !ok {
		return fmt.Errorf("the copy has no index %s", index)
	}
	settings := map[string]any{}
	for k, val := range src.Settings.Index {
		switch k {
		case "number_of_shards", "analysis", "refresh_interval", "max_result_window", "knn", "codec", "sort", "mapping":
			settings[k] = val
		}
	}
	body := map[string]any{"settings": map[string]any{"index": settings}, "mappings": src.Mappings}
	return prod.do(ctx, http.MethodPut, "/"+pathEscape(index), body, nil)
}
