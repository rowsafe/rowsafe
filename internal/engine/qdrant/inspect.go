package qdrant

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// minVersion is the oldest Qdrant Rowsafe protects (VersionNum).
const minVersion = 1_13_00

// serverInfo is what the agent reads from a server.
type serverInfo struct {
	Version     string
	VersionNum  int
	Collections []collInfo
	Aliases     map[string]string // alias -> collection
	Cluster     bool
}

// collInfo is one collection.
type collInfo struct {
	Name           string
	Status         string
	OptimizerError string
	Points         int64
	IndexedVectors int64
	Segments       int
	Vectors        []vectorInfo
	Sparse         []string
	Shards         int
	Replicas       int
	SizeBytes      int64 // vectors and payload, when telemetry said (0 otherwise)
	VectorsBytes   int64
	PayloadBytes   int64
}

// vectorInfo is one dense vector of a collection ("" is the unnamed one).
type vectorInfo struct {
	Name   string
	Size   int
	OnDisk bool
}

// totalPoints counts the people's points (Rowsafe's own collection left out).
func (in serverInfo) totalPoints() int64 {
	var n int64
	for _, c := range in.userCollections() {
		n += c.Points
	}
	return n
}

func (in serverInfo) totalBytes() int64 {
	var n int64
	for _, c := range in.Collections {
		n += c.SizeBytes
	}
	return n
}

// userCollections leaves Rowsafe's own collection out.
func (in serverInfo) userCollections() []collInfo {
	return slices.DeleteFunc(slices.Clone(in.Collections), func(c collInfo) bool { return c.Name == protocol.QdrantKeysCollection })
}

// supported says why a server can't be protected ("" when it can).
func (in serverInfo) supported() string {
	if in.Cluster {
		return "This Qdrant runs in distributed (cluster) mode, which Rowsafe doesn't protect yet: only single Qdrant servers"
	}
	if in.VersionNum > 0 && in.VersionNum < minVersion {
		return fmt.Sprintf("This is Qdrant %s; Rowsafe protects Qdrant 1.13 and newer: update Qdrant first", in.Version)
	}
	return ""
}

// parseVersion reads "1.19.2" as 11902 (major*10000 + minor*100 + patch).
func parseVersion(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	n := 0
	mult := []int{10000, 100, 1}
	for i, p := range parts {
		if i > 2 {
			break
		}
		p = strings.TrimFunc(p, func(r rune) bool { return r < '0' || r > '9' })
		x, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		n += x * mult[i]
	}
	return n
}

// rootInfo is GET /: Qdrant answers it without a key.
type rootInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

func (c *client) root(ctx context.Context) (rootInfo, error) {
	resp, err := c.request(ctx, http.MethodGet, "/", nil, nil, "")
	if err != nil {
		return rootInfo{}, err
	}
	defer resp.Body.Close()
	var r rootInfo
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || !strings.Contains(strings.ToLower(r.Title), "qdrant") {
		return r, fmt.Errorf("the server on this port isn't Qdrant")
	}
	return r, nil
}

// collectionNames lists the collections.
func (c *client) collectionNames(ctx context.Context) ([]string, error) {
	var out struct {
		Collections []struct {
			Name string `json:"name"`
		} `json:"collections"`
	}
	if err := c.call(ctx, http.MethodGet, "/collections", nil, nil, &out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Collections))
	for _, x := range out.Collections {
		names = append(names, x.Name)
	}
	slices.Sort(names)
	return names, nil
}

// rawCollection is GET /collections/{name}.
type rawCollection struct {
	Status          string          `json:"status"`
	OptimizerStatus json.RawMessage `json:"optimizer_status"`
	PointsCount     *int64          `json:"points_count"`
	IndexedVectors  *int64          `json:"indexed_vectors_count"`
	SegmentsCount   int             `json:"segments_count"`
	Config          struct {
		Params struct {
			Vectors           json.RawMessage            `json:"vectors"`
			SparseVectors     map[string]json.RawMessage `json:"sparse_vectors"`
			ShardNumber       int                        `json:"shard_number"`
			ReplicationFactor int                        `json:"replication_factor"`
		} `json:"params"`
	} `json:"config"`
}

type vectorParams struct {
	Size   *int  `json:"size"`
	OnDisk *bool `json:"on_disk"`
}

// parseVectors reads a collection's vectors setting: one unnamed vector
// ({"size": 4, ...}), named ones ({"img": {"size": 2, ...}}) or none ({}).
func parseVectors(raw json.RawMessage) []vectorInfo {
	if len(raw) == 0 {
		return nil
	}
	var single vectorParams
	if json.Unmarshal(raw, &single) == nil && single.Size != nil {
		return []vectorInfo{{Name: "", Size: *single.Size, OnDisk: single.OnDisk != nil && *single.OnDisk}}
	}
	var named map[string]vectorParams
	if json.Unmarshal(raw, &named) != nil {
		return nil
	}
	var out []vectorInfo
	for name, p := range named {
		v := vectorInfo{Name: name, OnDisk: p.OnDisk != nil && *p.OnDisk}
		if p.Size != nil {
			v.Size = *p.Size
		}
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b vectorInfo) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func optimizerError(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return "" // "ok"
	}
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil {
		return e.Error
	}
	return ""
}

func collPath(name string) string { return "/collections/" + url.PathEscape(name) }

// collection reads one collection.
func (c *client) collection(ctx context.Context, name string) (collInfo, error) {
	var r rawCollection
	if err := c.call(ctx, http.MethodGet, collPath(name), nil, nil, &r); err != nil {
		return collInfo{Name: name}, err
	}
	ci := collInfo{Name: name, Status: r.Status, OptimizerError: optimizerError(r.OptimizerStatus), Segments: r.SegmentsCount,
		Vectors: parseVectors(r.Config.Params.Vectors), Shards: r.Config.Params.ShardNumber, Replicas: r.Config.Params.ReplicationFactor}
	if r.PointsCount != nil {
		ci.Points = *r.PointsCount
	}
	if r.IndexedVectors != nil {
		ci.IndexedVectors = *r.IndexedVectors
	}
	for s := range r.Config.Params.SparseVectors {
		ci.Sparse = append(ci.Sparse, s)
	}
	slices.Sort(ci.Sparse)
	return ci, nil
}

// exactCount counts a collection's points exactly.
func (c *client) exactCount(ctx context.Context, name string) (int64, error) {
	var out struct {
		Count int64 `json:"count"`
	}
	err := c.call(ctx, http.MethodPost, collPath(name)+"/points/count", nil, map[string]any{"exact": true}, &out)
	return out.Count, err
}

// aliases lists the aliases (alias -> collection).
func (c *client) aliases(ctx context.Context) (map[string]string, error) {
	var out struct {
		Aliases []struct {
			Alias      string `json:"alias_name"`
			Collection string `json:"collection_name"`
		} `json:"aliases"`
	}
	if err := c.call(ctx, http.MethodGet, "/aliases", nil, nil, &out); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, a := range out.Aliases {
		m[a.Alias] = a.Collection
	}
	return m, nil
}

// clusterOn reports whether distributed mode is on.
func (c *client) clusterOn(ctx context.Context) (bool, error) {
	var out struct {
		Status string `json:"status"`
	}
	if err := c.call(ctx, http.MethodGet, "/cluster", nil, nil, &out); err != nil {
		return false, err
	}
	return out.Status == "enabled", nil
}

// telemetrySizes reads each collection's vector and payload sizes
// (telemetry, details level 3); nil when it can't.
func (c *client) telemetrySizes(ctx context.Context) map[string][2]int64 {
	var t telemetry
	if err := c.call(ctx, http.MethodGet, "/telemetry", url.Values{"details_level": {"3"}}, nil, &t); err != nil {
		return nil
	}
	out := map[string][2]int64{}
	for _, col := range t.Collections.Collections {
		var v, p int64
		for _, s := range col.Shards {
			if s.Local != nil {
				v += s.Local.VectorsSizeBytes
				p += s.Local.PayloadsSizeBytes
			}
		}
		out[col.ID] = [2]int64{v, p}
	}
	return out
}

// telemetry is the part of GET /telemetry the agent reads.
type telemetry struct {
	App struct {
		Version string `json:"version"`
		System  struct {
			RAMSizeKB int64 `json:"ram_size"`
			DiskKB    int64 `json:"disk_size"`
			IsDocker  bool  `json:"is_docker"`
		} `json:"system"`
		JWTRBAC  *bool `json:"jwt_rbac"`
		Features struct {
			RecoveryMode bool `json:"recovery_mode"`
		} `json:"features"`
	} `json:"app"`
	Collections struct {
		Collections []struct {
			ID     string `json:"id"`
			Shards []struct {
				Local *struct {
					VectorsSizeBytes  int64 `json:"vectors_size_bytes"`
					PayloadsSizeBytes int64 `json:"payloads_size_bytes"`
				} `json:"local"`
			} `json:"shards"`
		} `json:"collections"`
	} `json:"collections"`
	Memory *struct {
		ResidentBytes int64 `json:"resident_bytes"`
	} `json:"memory"`
}

// inspect reads the server: version, collections (with exact point
// counts when exact) and aliases.
func inspect(ctx context.Context, c *client, exact bool) (serverInfo, error) {
	var in serverInfo
	r, err := c.root(ctx)
	if err != nil {
		return in, err
	}
	in.Version, in.VersionNum = r.Version, parseVersion(r.Version)
	if in.Cluster, err = c.clusterOn(ctx); err != nil {
		return in, err
	}
	names, err := c.collectionNames(ctx)
	if err != nil {
		return in, err
	}
	sizes := c.telemetrySizes(ctx)
	for _, n := range names {
		ci, err := c.collection(ctx, n)
		if err != nil {
			if isStatus(err, http.StatusNotFound) {
				continue // removed meanwhile
			}
			return in, err
		}
		if exact {
			if n, err := c.exactCount(ctx, n); err == nil {
				ci.Points = n
			}
		}
		if s, ok := sizes[n]; ok {
			ci.VectorsBytes, ci.PayloadBytes = s[0], s[1]
			ci.SizeBytes = s[0] + s[1]
		}
		in.Collections = append(in.Collections, ci)
	}
	if in.Aliases, err = c.aliases(ctx); err != nil {
		return in, err
	}
	return in, nil
}

func clampInt(n int64) int { return int(min(max(n, 0), 1<<31-1)) }

// dbInfos lists the collections for InspectResult.Databases.
func (in serverInfo) dbInfos() []protocol.DBInfo {
	out := []protocol.DBInfo{}
	for _, c := range in.userCollections() {
		out = append(out, protocol.DBInfo{Name: c.Name, SizeBytes: c.SizeBytes, Tables: clampInt(c.Points)})
	}
	return out
}

func (in serverInfo) inspectResult(port int, configFile string) protocol.InspectResult {
	return protocol.InspectResult{Engine: protocol.EngineQdrant, ServerVersion: in.Version, VersionNum: in.VersionNum, Port: port,
		ConfigFile: configFile, Databases: in.dbInfos(), TotalSizeBytes: in.totalBytes()} // no ArchiveMode: no change log
}
