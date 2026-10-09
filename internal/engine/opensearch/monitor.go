package opensearch

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Monitoring (Pulse): about once a minute, the cluster's health, the node's
// stats (heap, GC, disk, thread pools, searches and indexing) and the
// indices; DatabaseMonitoring.OpenSearch with every sample.

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	mu     sync.Mutex
	prev   map[string]float64
	prevAt time.Time
	// the disk watermarks, read every 10 minutes
	wm   [3]float64
	wmAt time.Time
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

// nodeStats is the part of _nodes/_local/stats Rowsafe reads.
type nodeStats struct {
	Nodes map[string]struct {
		Indices struct {
			Search struct {
				QueryTotal  int64 `json:"query_total"`
				QueryMillis int64 `json:"query_time_in_millis"`
			} `json:"search"`
			Indexing struct {
				IndexTotal  int64 `json:"index_total"`
				IndexMillis int64 `json:"index_time_in_millis"`
			} `json:"indexing"`
		} `json:"indices"`
		OS struct {
			Mem struct {
				Total int64 `json:"total_in_bytes"`
			} `json:"mem"`
		} `json:"os"`
		JVM struct {
			Mem struct {
				HeapUsed    int64 `json:"heap_used_in_bytes"`
				HeapMax     int64 `json:"heap_max_in_bytes"`
				HeapPercent int   `json:"heap_used_percent"`
			} `json:"mem"`
			GC struct {
				Collectors map[string]struct {
					Count  int64 `json:"collection_count"`
					Millis int64 `json:"collection_time_in_millis"`
				} `json:"collectors"`
			} `json:"gc"`
		} `json:"jvm"`
		ThreadPool map[string]struct {
			Rejected int64 `json:"rejected"`
		} `json:"thread_pool"`
		FS struct {
			Total struct {
				Total     int64 `json:"total_in_bytes"`
				Available int64 `json:"available_in_bytes"`
			} `json:"total"`
		} `json:"fs"`
		HTTP struct {
			Open int64 `json:"current_open"`
		} `json:"http"`
		Breakers map[string]struct {
			Tripped int64 `json:"tripped"`
		} `json:"breakers"`
	} `json:"nodes"`
}

// Monitor collects one sample.
func (e *Engine) Monitor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: db.ID}
	m := e.monitorFor(db.ID)
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		dm.Error = err.Error()
		return dm, nil
	}
	st, metrics, err := sample(ctx, c, m)
	if err != nil {
		dm.Error = "can't read OpenSearch's status: " + firstLine(err.Error())
		return dm, nil
	}
	// Rowsafe's repository: its newest snapshot and size.
	if snaps, err := listSnapshots(ctx, c); err == nil {
		for _, s := range snaps {
			if labelOf(s.Snapshot) == "" || s.State != "SUCCESS" {
				continue
			}
			st.Snapshots++
			t := s.end()
			if st.LastSnapshotAt == nil || t.After(*st.LastSnapshotAt) {
				st.LastSnapshotAt = &t
			}
		}
	}
	dm.Metrics, dm.OpenSearch = metrics, st
	return dm, nil
}

// sample reads the server once.
func sample(ctx context.Context, c *client, m *dbMonitor) (*protocol.OpenSearchStatus, map[string]float64, error) {
	now := time.Now().UTC()
	st := &protocol.OpenSearchStatus{CollectedAt: now, TLS: c.base.Scheme == "https"}
	root, err := readRoot(ctx, c)
	if err != nil {
		return nil, nil, err
	}
	st.Version, st.ClusterName = root.Version.Number, root.ClusterName
	var h struct {
		Status       string `json:"status"`
		Nodes        int    `json:"number_of_nodes"`
		Active       int    `json:"active_shards"`
		Relocating   int    `json:"relocating_shards"`
		Initializing int    `json:"initializing_shards"`
		Unassigned   int    `json:"unassigned_shards"`
	}
	if err := c.get(ctx, "/_cluster/health", &h); err != nil {
		return nil, nil, err
	}
	st.Status, st.Nodes, st.ActiveShards, st.RelocatingShards = h.Status, h.Nodes, h.Active, h.Relocating
	st.InitializingShards, st.UnassignedShards = h.Initializing, h.Unassigned
	if h.Unassigned > 0 {
		var shards []struct {
			Index  string `json:"index"`
			Prirep string `json:"prirep"`
			State  string `json:"state"`
		}
		if err := c.get(ctx, "/_cat/shards?format=json&h=index,prirep,state", &shards); err == nil {
			rep, red := map[string]bool{}, map[string]bool{}
			for _, s := range shards {
				if s.State != "UNASSIGNED" || systemIndex(s.Index) {
					continue
				}
				if s.Prirep == "p" {
					st.UnassignedPrimaries++
					red[s.Index] = true
				} else {
					rep[s.Index] = true
				}
			}
			for i := range rep {
				if len(st.UnassignedReplicaIndices) < 50 {
					st.UnassignedReplicaIndices = append(st.UnassignedReplicaIndices, i)
				}
			}
			for i := range red {
				if len(st.RedIndices) < 50 {
					st.RedIndices = append(st.RedIndices, i)
				}
			}
		}
	}
	st.SecurityPlugin = securityOn(ctx, c)
	indices, _, err := listIndices(ctx, c)
	if err == nil {
		st.Indices = len(indices)
		for _, i := range indices {
			st.Documents += i.Docs
			st.StoreBytes += i.Bytes
		}
	}
	// Read-only blocks of a full disk.
	var blocks map[string]struct {
		Settings struct {
			Index struct {
				Blocks struct {
					ROAD string `json:"read_only_allow_delete"`
				} `json:"blocks"`
			} `json:"index"`
		} `json:"settings"`
	}
	if err := c.get(ctx, "/_all/_settings/index.blocks.read_only_allow_delete?expand_wildcards=open", &blocks); err == nil {
		for name, b := range blocks {
			if b.Settings.Index.Blocks.ROAD == "true" && !systemIndex(name) && len(st.ReadOnlyIndices) < 50 {
				st.ReadOnlyIndices = append(st.ReadOnlyIndices, name)
			}
		}
	}
	if now.Sub(m.wmAt) > 10*time.Minute {
		if l, h, f := watermarks(ctx, c); h > 0 {
			m.wm, m.wmAt = [3]float64{l, h, f}, now
		}
	}
	st.WatermarkLow, st.WatermarkHigh, st.WatermarkFlood = m.wm[0], m.wm[1], m.wm[2]
	var ns nodeStats
	metrics := map[string]float64{}
	counters := map[string]float64{}
	if err := c.get(ctx, "/_nodes/_local/stats/indices,os,jvm,thread_pool,fs,http,breaker", &ns); err == nil {
		for _, n := range ns.Nodes {
			st.HeapUsedBytes, st.HeapMaxBytes, st.HeapPercent = n.JVM.Mem.HeapUsed, n.JVM.Mem.HeapMax, n.JVM.Mem.HeapPercent
			st.MemoryTotalBytes = n.OS.Mem.Total
			st.DiskTotalBytes, st.DiskAvailableBytes = n.FS.Total.Total, n.FS.Total.Available
			st.OpenHTTP = n.HTTP.Open
			for name, g := range n.JVM.GC.Collectors {
				if name == "old" {
					st.OldGCCount, st.OldGCMillis = g.Count, g.Millis
				} else {
					counters["young_gc"] += float64(g.Count)
				}
			}
			for _, b := range n.Breakers {
				st.CircuitBreakerTrips += b.Tripped
			}
			for name, tp := range n.ThreadPool {
				switch {
				case name == "search":
					counters["search_rejected"] = float64(tp.Rejected)
				case name == "write":
					counters["write_rejected"] = float64(tp.Rejected)
				}
			}
			counters["old_gc"], counters["old_gc_ms"] = float64(st.OldGCCount), float64(st.OldGCMillis)
			counters["query_total"], counters["query_ms"] = float64(n.Indices.Search.QueryTotal), float64(n.Indices.Search.QueryMillis)
			counters["index_total"], counters["index_ms"] = float64(n.Indices.Indexing.IndexTotal), float64(n.Indices.Indexing.IndexMillis)
		}
	}
	metrics[collect.MOpenSearchHeapUsedPct] = float64(st.HeapPercent)
	metrics[collect.MOpenSearchDocuments] = float64(st.Documents)
	metrics[collect.MDatabaseSizeBytes] = float64(st.StoreBytes)
	metrics[collect.MOpenSearchUnassignedShards] = float64(st.UnassignedShards)
	metrics[collect.MOpenSearchStatus] = map[string]float64{"green": 0, "yellow": 1, "red": 2}[st.Status]
	if st.DiskTotalBytes > 0 {
		metrics[collect.MDiskTotalBytes] = float64(st.DiskTotalBytes)
		metrics[collect.MDiskFreeBytes] = float64(st.DiskAvailableBytes)
		metrics[collect.MDiskFreePct] = 100 * float64(st.DiskAvailableBytes) / float64(st.DiskTotalBytes)
	}
	if m.prev != nil {
		secs := now.Sub(m.prevAt).Seconds()
		d := func(k string) float64 { return max(counters[k]-m.prev[k], 0) }
		if secs > 0 {
			metrics[collect.MOpenSearchSearchRate] = d("query_total") / secs
			metrics[collect.MOpenSearchIndexRate] = d("index_total") / secs
			metrics[collect.MOpenSearchRejectedRate] = (d("search_rejected") + d("write_rejected")) / secs
			metrics[collect.MOpenSearchOldGCMsRate] = d("old_gc_ms") / secs
		}
		if n := d("query_total"); n > 0 {
			metrics[collect.MOpenSearchSearchLatencyMs] = d("query_ms") / n
		}
		if n := d("index_total"); n > 0 {
			metrics[collect.MOpenSearchIndexLatencyMs] = d("index_ms") / n
		}
		st.OldGCRecent, st.OldGCRecentMillis = int64(d("old_gc")), int64(d("old_gc_ms"))
		st.YoungGCRecentCount = int64(d("young_gc"))
		st.SearchRejected, st.WriteRejected = int64(d("search_rejected")), int64(d("write_rejected"))
	}
	m.prev, m.prevAt = counters, now
	return st, metrics, nil
}

// watermarks reads the disk watermarks as percent used (absolute byte
// settings are left at 0).
func watermarks(ctx context.Context, c *client) (low, high, flood float64) {
	var v struct {
		Defaults   map[string]string `json:"defaults"`
		Persistent map[string]string `json:"persistent"`
		Transient  map[string]string `json:"transient"`
	}
	if err := c.get(ctx, "/_cluster/settings?include_defaults=true&flat_settings=true", &v); err != nil {
		return 0, 0, 0
	}
	get := func(k string) float64 {
		for _, m := range []map[string]string{v.Transient, v.Persistent, v.Defaults} {
			if s, ok := m["cluster.routing.allocation.disk.watermark."+k]; ok {
				return pct(s)
			}
		}
		return 0
	}
	return get("low"), get("high"), get("flood_stage")
}

// pct reads "85%" or "0.85" as 85 (0 for absolute sizes).
func pct(s string) float64 {
	s = strings.TrimSpace(s)
	if p, ok := strings.CutSuffix(s, "%"); ok {
		f, _ := strconv.ParseFloat(p, 64)
		return f
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f <= 1 {
		return f * 100
	}
	return 0
}
