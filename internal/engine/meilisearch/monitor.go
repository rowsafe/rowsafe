package meilisearch

import (
	"context"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for Meilisearch: /stats (sizes, documents, indexing), the task
// queue (waiting, running, failed), disk; read only and cheap. The
// detailed status comes every 5 minutes. Rowsafe's own temporary indexes
// (rewinds in place) are left out.

const statusEvery = 5 * time.Minute

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	mu         sync.Mutex
	statusAt   time.Time
	prevFailAt time.Time // the previous sample: failures since are counted
}

func (e *Engine) monitorFor(id string) *dbMonitor {
	e.mon.mu.Lock()
	defer e.mon.mu.Unlock()
	if e.mon.dbs == nil {
		e.mon.dbs = map[string]*dbMonitor{}
	}
	m := e.mon.dbs[id]
	if m == nil {
		m = &dbMonitor{}
		e.mon.dbs[id] = m
	}
	return m
}

// Monitor collects one sample of db.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: db.ID}
	m := e.monitorFor(db.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	c, s, err := connect(ctx, env, db)
	if err != nil {
		dm.Error = firstLine(err.Error())
		dm.Metrics = map[string]float64{collect.MMeiliUp: 0}
		return dm, nil
	}
	defer c.close()
	if err := e.sample(ctx, c, s, m, dm); err != nil {
		dm.Error = "can't read Meilisearch's status: " + firstLine(err.Error())
	}
	return dm, nil
}

func (e *Engine) sample(ctx context.Context, c *client, s server, m *dbMonitor, dm *protocol.DatabaseMonitoring) error {
	now := time.Now()
	st, err := c.stats(ctx)
	if err != nil {
		return err
	}
	metrics := map[string]float64{collect.MMeiliUp: 1}
	var docs, indexes int64
	indexing := false
	for uid, i := range st.Indexes {
		if isTemporary(uid) {
			continue
		}
		indexes++
		docs += i.NumberOfDocuments
		indexing = indexing || i.IsIndexing
	}
	metrics[collect.MDatabaseSizeBytes] = float64(st.DatabaseSize)
	metrics[collect.MMeiliUsedSizeBytes] = float64(st.UsedDatabaseSize)
	if st.DatabaseSize > 0 {
		metrics[collect.MMeiliFreeSpacePct] = 100 * float64(max(st.DatabaseSize-st.UsedDatabaseSize, 0)) / float64(st.DatabaseSize)
	}
	metrics[collect.MMeiliDocuments] = float64(docs)
	metrics[collect.MMeiliIndexes] = float64(indexes)
	if indexing {
		metrics[collect.MMeiliIndexing] = 1
	} else {
		metrics[collect.MMeiliIndexing] = 0
	}
	count := func(q url.Values) ([]task, int64) {
		q.Set("limit", "1")
		ts, n, err := c.taskPage(ctx, q)
		if err != nil {
			return nil, -1
		}
		return ts, n
	}
	_, enq := count(url.Values{"statuses": {"enqueued"}})
	_, proc := count(url.Values{"statuses": {"processing"}})
	_, total := count(url.Values{})
	if enq >= 0 {
		metrics[collect.MMeiliTasksEnqueued] = float64(enq)
	}
	if proc >= 0 {
		metrics[collect.MMeiliTasksProcessing] = float64(proc)
	}
	if total >= 0 {
		metrics[collect.MMeiliTasksTotal] = float64(total)
	}
	var oldest float64
	if enq > 0 {
		// The oldest waiting task: tasks come newest first, "reverse" turns that.
		if ts, _, err := c.taskPage(ctx, url.Values{"statuses": {"enqueued"}, "limit": {"1"}, "reverse": {"true"}}); err == nil && len(ts) > 0 && ts[0].EnqueuedAt != nil {
			oldest = max(now.Sub(*ts[0].EnqueuedAt).Seconds(), 0)
		}
	}
	metrics[collect.MMeiliOldestTaskSeconds] = oldest
	// Failed tasks since the previous sample (finished after it).
	if !m.prevFailAt.IsZero() {
		if d := now.Sub(m.prevFailAt).Seconds(); d > 0 {
			if _, n := count(url.Values{"statuses": {"failed"}, "afterFinishedAt": {m.prevFailAt.UTC().Format(time.RFC3339Nano)}}); n >= 0 {
				metrics[collect.MMeiliTasksFailedRate] = float64(n) / d
			}
		}
	}
	m.prevFailAt = now
	if total, free, err := diskUsage(existingParent(s.SnapshotDir)); err == nil && total > 0 && s.SnapshotDir != "" {
		metrics[collect.MDiskTotalBytes] = float64(total)
		metrics[collect.MDiskFreeBytes] = float64(free)
		metrics[collect.MDiskFreePct] = 100 * float64(free) / float64(total)
	}
	dm.Metrics = metrics
	if now.Sub(m.statusAt) >= statusEvery {
		if ms, err := status(ctx, c, s, st, now); err == nil {
			dm.Meilisearch = ms
			m.statusAt = now
		}
	}
	return nil
}

// status is the detailed health (every 5 minutes).
func status(ctx context.Context, c *client, s server, st globalStats, now time.Time) (*protocol.MeilisearchStatus, error) {
	v, err := c.version(ctx)
	if err != nil {
		return nil, err
	}
	ms := &protocol.MeilisearchStatus{CollectedAt: now.UTC(), Version: v.PkgVersion, DatabaseSizeBytes: st.DatabaseSize,
		UsedDatabaseSizeBytes: st.UsedDatabaseSize, LastUpdate: st.LastUpdate, Indexes: []protocol.MeilisearchIndex{},
		MaxIndexingMemoryBytes: s.MaxIndexingMemory, Analytics: s.Analytics}
	if s.Rowsafe {
		ms.Edition = "community"
	}
	idx, err := c.indexes(ctx)
	if err != nil {
		return nil, err
	}
	for _, i := range idx {
		if isTemporary(i.UID) {
			continue
		}
		is := st.Indexes[i.UID]
		ms.Indexes = append(ms.Indexes, protocol.MeilisearchIndex{UID: i.UID, PrimaryKey: i.primaryKey(), Documents: is.NumberOfDocuments,
			IndexSizeBytes: is.IndexSize, UsedSizeBytes: is.UsedIndexSize, Embeddings: is.NumberOfEmbeddings, IsIndexing: is.IsIndexing})
		if len(ms.Indexes) >= 500 {
			break
		}
	}
	page := func(q url.Values) ([]task, int64) {
		ts, n, err := c.taskPage(ctx, q)
		if err != nil {
			return nil, 0
		}
		return ts, n
	}
	_, ms.TasksEnqueued = page(url.Values{"statuses": {"enqueued"}, "limit": {"1"}})
	_, ms.TasksProcessing = page(url.Values{"statuses": {"processing"}, "limit": {"1"}})
	_, ms.TasksTotal = page(url.Values{"limit": {"1"}})
	_, ms.TasksFailed24h = page(url.Values{"statuses": {"failed"}, "limit": {"1"},
		"afterFinishedAt": {now.Add(-24 * time.Hour).UTC().Format(time.RFC3339)}})
	if ms.TasksEnqueued > 0 {
		if ts, _ := page(url.Values{"statuses": {"enqueued"}, "limit": {"1"}, "reverse": {"true"}}); len(ts) > 0 && ts[0].EnqueuedAt != nil {
			ms.OldestEnqueuedSeconds = max(now.Sub(*ts[0].EnqueuedAt).Seconds(), 0)
		}
	}
	if ts, _ := page(url.Values{"statuses": {"failed"}, "limit": {"1"}}); len(ts) > 0 {
		t := ts[0]
		lt := &protocol.MeiliTask{UID: t.id(), Type: t.Type, IndexUID: t.index(), Status: t.Status, EnqueuedAt: t.EnqueuedAt, FinishedAt: t.FinishedAt}
		if t.Error != nil {
			lt.ErrorCode, lt.Error = t.Error.Code, firstLine(t.Error.Message)
		}
		if !strings.HasPrefix(lt.IndexUID, protocol.MeilisearchRestorePrefix) {
			ms.LastFailedTask = lt
		}
	}
	return ms, nil
}
