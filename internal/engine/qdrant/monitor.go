package qdrant

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for Qdrant: its Prometheus metrics every minute (cheap: one
// request), and every 5 minutes the detailed status: each collection's
// state and sizes, memory against the server's, the issues Qdrant itself
// reports, and snapshots left on its disk. Names only, never points.

const statusEvery = 5 * time.Minute

type monitorState struct {
	mu  sync.Mutex
	dbs map[string]*dbMonitor
}

type dbMonitor struct {
	mu       sync.Mutex
	prevReq  float64
	prevFail float64
	prevAt   time.Time
	statusAt time.Time
	status   *protocol.QdrantStatus
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

// promSample is one line of Prometheus text.
type promSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

// parseProm reads Prometheus text exposition (the lines Rowsafe needs).
func parseProm(data []byte) []promSample {
	var out []promSample
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var s promSample
		rest := line
		if i := strings.IndexByte(line, '{'); i >= 0 {
			j := strings.LastIndexByte(line, '}')
			if j < i {
				continue
			}
			s.Name = line[:i]
			s.Labels = parseLabels(line[i+1 : j])
			rest = strings.TrimSpace(line[j+1:])
		} else {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			s.Name, rest = f[0], f[1]
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseFloat(f[0], 64)
		if err != nil {
			continue
		}
		s.Value = v
		out = append(out, s)
	}
	return out
}

func parseLabels(s string) map[string]string {
	m := map[string]string{}
	for s != "" {
		eq := strings.IndexByte(s, '=')
		if eq < 0 || eq+1 >= len(s) || s[eq+1] != '"' {
			break
		}
		key := strings.TrimSpace(s[:eq])
		rest := s[eq+2:]
		var b strings.Builder
		i := 0
		for ; i < len(rest); i++ {
			if rest[i] == '\\' && i+1 < len(rest) {
				i++
				b.WriteByte(rest[i])
				continue
			}
			if rest[i] == '"' {
				break
			}
			b.WriteByte(rest[i])
		}
		m[key] = b.String()
		if i+1 >= len(rest) {
			break
		}
		s = strings.TrimLeft(rest[i+1:], ", ")
	}
	return m
}

// promMetrics are the figures the agent takes from /metrics.
type promMetrics struct {
	Collections  float64
	Points       float64
	Resident     float64
	Requests     float64
	Failed       float64
	RecoveryMode bool
}

func readProm(samples []promSample) promMetrics {
	var p promMetrics
	for _, s := range samples {
		name := strings.TrimPrefix(s.Name, "qdrant_")
		switch name {
		case "collections_total":
			p.Collections = s.Value
		case "collection_points":
			if s.Labels["id"] != protocol.QdrantKeysCollection {
				p.Points += s.Value
			}
		case "memory_resident_bytes":
			p.Resident = s.Value
		case "rest_responses_total":
			p.Requests += s.Value
			if strings.HasPrefix(s.Labels["status"], "5") {
				p.Failed += s.Value
			}
		case "grpc_responses_total":
			p.Requests += s.Value
		case "grpc_responses_fail_total":
			p.Failed += s.Value
		case "app_status_recovery_mode":
			p.RecoveryMode = s.Value > 0
		}
	}
	return p
}

// Monitor collects one sample of db.
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
	defer c.Close()
	raw, err := c.getRaw(ctx, "/metrics", 8<<20)
	if err != nil {
		dm.Error = "can't read Qdrant's status: " + err.Error()
		return dm, nil
	}
	now := time.Now()
	p := readProm(parseProm(raw))
	metrics := map[string]float64{
		collect.MQdrantCollections:   p.Collections,
		collect.MQdrantPoints:        p.Points,
		collect.MQdrantResidentBytes: p.Resident,
	}
	if !m.prevAt.IsZero() && p.Requests >= m.prevReq {
		if dt := now.Sub(m.prevAt).Seconds(); dt > 0 {
			metrics[collect.MQdrantRequestsRate] = (p.Requests - m.prevReq) / dt
			metrics[collect.MQdrantFailedRate] = max(0, p.Failed-m.prevFail) / dt
		}
	}
	m.prevReq, m.prevFail, m.prevAt = p.Requests, p.Failed, now
	if m.status == nil || now.Sub(m.statusAt) >= statusEvery {
		if st, err := readStatus(ctx, c, p); err == nil {
			m.status, m.statusAt = st, now
		} else if m.status == nil {
			dm.Error = "can't read Qdrant's status: " + err.Error()
		}
	}
	if st := m.status; st != nil {
		st.ResidentBytes = int64(p.Resident)
		if st.TotalMemoryBytes > 0 {
			metrics[collect.MQdrantMemoryUsedPct] = 100 * p.Resident / float64(st.TotalMemoryBytes)
		}
		var red, yellow, optErrs float64
		var size int64
		for _, c := range st.Collections {
			switch c.Status {
			case protocol.QdrantRed:
				red++
			case protocol.QdrantYellow:
				yellow++
			}
			if c.OptimizerError != "" {
				optErrs++
			}
			size += c.VectorsBytes + c.PayloadBytes
		}
		metrics[collect.MQdrantCollectionsRed] = red
		metrics[collect.MQdrantCollectionsYellow] = yellow
		metrics[collect.MQdrantOptimizerErrors] = optErrs
		metrics[collect.MQdrantIssues] = float64(len(st.Issues))
		metrics[collect.MDatabaseSizeBytes] = float64(size)
		cp := *st
		dm.Qdrant = &cp
		for _, c := range st.Collections {
			dm.Sizes = append(dm.Sizes, protocol.DatabaseSize{Name: c.Name, SizeBytes: c.VectorsBytes + c.PayloadBytes})
		}
	}
	if !inDocker() {
		if fc, _, ok := readConfig(); ok && fc.Storage.StoragePath != "" {
			if total, free, err := diskUsage(fc.Storage.StoragePath); err == nil && total > 0 {
				metrics[collect.MDiskTotalBytes] = float64(total)
				metrics[collect.MDiskFreeBytes] = float64(free)
				metrics[collect.MDiskFreePct] = 100 * float64(free) / float64(total)
			}
		}
	}
	dm.Metrics = metrics
	return dm, nil
}

// maxStatusCollections caps the collections in the detailed status.
const maxStatusCollections = 200

// readStatus reads the detailed status.
func readStatus(ctx context.Context, c *client, p promMetrics) (*protocol.QdrantStatus, error) {
	in, err := inspect(ctx, c, false)
	if err != nil {
		return nil, err
	}
	st := &protocol.QdrantStatus{CollectedAt: time.Now().UTC(), Version: in.Version, Cluster: in.Cluster, RecoveryMode: p.RecoveryMode,
		ResidentBytes: int64(p.Resident)}
	var t telemetry
	if err := c.call(ctx, http.MethodGet, "/telemetry", nil, nil, &t); err == nil {
		st.TotalMemoryBytes = t.App.System.RAMSizeKB * 1024
		st.RecoveryMode = st.RecoveryMode || t.App.Features.RecoveryMode
	}
	for _, ci := range in.userCollections() {
		qc := protocol.QdrantCollection{Name: ci.Name, Status: ci.Status, OptimizerError: ci.OptimizerError, Points: ci.Points,
			IndexedVectors: ci.IndexedVectors, Segments: ci.Segments, VectorsBytes: ci.VectorsBytes, PayloadBytes: ci.PayloadBytes,
			Shards: ci.Shards, Replicas: ci.Replicas}
		onDisk := len(ci.Vectors) > 0
		for _, v := range ci.Vectors {
			qc.Vectors = append(qc.Vectors, v.Name)
			onDisk = onDisk && v.OnDisk
		}
		qc.OnDisk = onDisk
		if !onDisk {
			st.VectorsInMemoryBytes += ci.VectorsBytes
		}
		st.Collections = append(st.Collections, qc)
	}
	slices.SortFunc(st.Collections, func(a, b protocol.QdrantCollection) int {
		return int(min(max(b.VectorsBytes+b.PayloadBytes-a.VectorsBytes-a.PayloadBytes, -1), 1))
	})
	if len(st.Collections) > maxStatusCollections {
		st.Collections = st.Collections[:maxStatusCollections]
	}
	if issues, err := c.issues(ctx); err == nil {
		st.Issues = issues
	}
	grpcPort := 6334
	if fc, _, ok := readConfig(); ok && fc.Service.GRPCPort != nil {
		grpcPort = *fc.Service.GRPCPort
	}
	st.GRPCOldCert = grpcCertDiffers(ctx, c.base, grpcPort)
	if snaps, err := c.listFullSnapshots(ctx); err == nil {
		for _, s := range snaps {
			st.LocalSnapshots++
			st.LocalSnapshotsBytes += s.Size
		}
	}
	return st, nil
}

// rawIssue is one entry of GET /issues.
type rawIssue struct {
	ID                string          `json:"id"`
	Description       string          `json:"description"`
	RelatedCollection *string         `json:"related_collection"`
	Solution          json.RawMessage `json:"solution"`
}

type rawAction struct {
	Method string         `json:"method"`
	URI    string         `json:"uri"`
	Body   map[string]any `json:"body"`
}

type rawImmediate struct {
	Message string    `json:"message"`
	Action  rawAction `json:"action"`
}

// maxIssues caps the issues reported.
const maxIssues = 20

// issues reads what Qdrant reports; unindexed fields come with the index
// types Qdrant suggests.
func (c *client) issues(ctx context.Context) ([]protocol.QdrantIssue, error) {
	var out struct {
		Issues []rawIssue `json:"issues"`
	}
	if err := c.call(ctx, http.MethodGet, "/issues", nil, nil, &out); err != nil {
		return nil, err
	}
	var res []protocol.QdrantIssue
	for _, ri := range out.Issues {
		qi := protocol.QdrantIssue{ID: ri.ID, Description: ri.Description}
		if ri.RelatedCollection != nil {
			qi.Collection = *ri.RelatedCollection
		}
		for _, a := range solutionActions(ri.Solution) {
			field, schema := indexAction(a, qi.Collection)
			if field == "" {
				continue
			}
			qi.Field = field
			if !slices.Contains(qi.Schemas, schema) {
				qi.Schemas = append(qi.Schemas, schema)
			}
		}
		res = append(res, qi)
		if len(res) >= maxIssues {
			break
		}
	}
	return res, nil
}

// solutionActions lists the actions of a solution ({"immediate": ...} or
// {"immediate_choice": [...]}).
func solutionActions(raw json.RawMessage) []rawAction {
	var s struct {
		Immediate       *rawImmediate  `json:"immediate"`
		ImmediateChoice []rawImmediate `json:"immediate_choice"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return nil
	}
	var out []rawAction
	if s.Immediate != nil {
		out = append(out, s.Immediate.Action)
	}
	for _, i := range s.ImmediateChoice {
		out = append(out, i.Action)
	}
	return out
}

// indexSchemas are the payload index types Rowsafe creates from an issue.
var indexSchemas = []string{"keyword", "integer", "float", "bool", "geo", "datetime", "uuid", "text"}

// indexAction reads a "create a payload index" action for collection:
// the field and the index type ("" when it is something else).
func indexAction(a rawAction, collection string) (string, string) {
	if !strings.EqualFold(a.Method, http.MethodPut) || collection == "" {
		return "", ""
	}
	path := a.URI
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path != collPath(collection)+"/index" {
		return "", ""
	}
	field, _ := a.Body["field_name"].(string)
	var schema string
	switch v := a.Body["field_schema"].(type) {
	case string:
		schema = v
	case map[string]any:
		schema, _ = v["type"].(string)
	}
	if field == "" || len(field) > 200 || !slices.Contains(indexSchemas, schema) {
		return "", ""
	}
	return field, schema
}
