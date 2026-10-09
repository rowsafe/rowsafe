package opensearch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// serverInfo is what Rowsafe reads about a server.
type serverInfo struct {
	Version      string
	VersionNum   int // major*10000 + minor*100 + patch
	Distribution string
	ClusterName  string
	Nodes        int
	Status       string
	TLS          bool
	// Security: the security plugin answers (users and passwords).
	Security bool
	// PathRepo are the folders the node allows snapshot repositories in.
	PathRepo []string
	DataPath []string
	// Indices are the user's indices (system and hidden ones left out,
	// data streams' backing indices included with their stream).
	Indices     []indexInfo
	DataStreams []string
}

// indexInfo is one index.
type indexInfo struct {
	Name       string
	Docs       int64
	Bytes      int64
	Health     string
	Open       bool
	DataStream string // the data stream it backs ("" for a plain index)
	Replicas   int
}

// totalDocs and totalBytes add up the indices.
func (in serverInfo) totalDocs() (n int64) {
	for _, i := range in.Indices {
		n += i.Docs
	}
	return n
}

func (in serverInfo) totalBytes() (n int64) {
	for _, i := range in.Indices {
		n += i.Bytes
	}
	return n
}

// versionNum: "3.9.0" -> 30900.
func versionNum(v string) int {
	parts := strings.SplitN(v, ".", 4)
	n := 0
	for i := 0; i < 3; i++ {
		x := 0
		if i < len(parts) {
			for _, r := range parts[i] {
				if r < '0' || r > '9' {
					break
				}
				x = x*10 + int(r-'0')
			}
		}
		n = n*100 + x
	}
	return n
}

// systemIndex reports whether an index is OpenSearch's (or a plugin's) own:
// a name starting with a dot, except data streams' backing indices.
func systemIndex(name string) bool {
	return strings.HasPrefix(name, ".") && !strings.HasPrefix(name, ".ds-")
}

// catIndex is one row of _cat/indices.
type catIndex struct {
	Index  string `json:"index"`
	Health string `json:"health"`
	Status string `json:"status"`
	Docs   string `json:"docs.count"`
	Store  string `json:"store.size"`
	Rep    string `json:"rep"`
}

func atoi64(s string) int64 { n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64); return n }

// rootInfo is GET /.
type rootInfo struct {
	ClusterName string `json:"cluster_name"`
	Version     struct {
		Distribution string `json:"distribution"`
		Number       string `json:"number"`
	} `json:"version"`
}

// readRoot reads the server's name and version.
func readRoot(ctx context.Context, c *client) (rootInfo, error) {
	var r rootInfo
	err := c.get(ctx, "/", &r)
	return r, err
}

// listIndices reads every index (with hidden and closed ones) and data
// stream; system indices are left out.
func listIndices(ctx context.Context, c *client) ([]indexInfo, []string, error) {
	var rows []catIndex
	if err := c.get(ctx, "/_cat/indices?format=json&bytes=b&expand_wildcards=all&h=index,health,status,docs.count,store.size,rep", &rows); err != nil {
		return nil, nil, err
	}
	var ds struct {
		DataStreams []struct {
			Name    string `json:"name"`
			Indices []struct {
				Name string `json:"index_name"`
			} `json:"indices"`
		} `json:"data_streams"`
	}
	backing := map[string]string{}
	var streams []string
	if err := c.get(ctx, "/_data_stream", &ds); err == nil {
		for _, d := range ds.DataStreams {
			if strings.HasPrefix(d.Name, ".") {
				continue
			}
			streams = append(streams, d.Name)
			for _, i := range d.Indices {
				backing[i.Name] = d.Name
			}
		}
	}
	var out []indexInfo
	for _, r := range rows {
		if systemIndex(r.Index) && backing[r.Index] == "" {
			continue
		}
		if strings.HasPrefix(r.Index, ".ds-") && backing[r.Index] == "" {
			continue // a system data stream's
		}
		out = append(out, indexInfo{Name: r.Index, Docs: atoi64(r.Docs), Bytes: atoi64(r.Store), Health: r.Health,
			Open: r.Status != "close", DataStream: backing[r.Index], Replicas: int(atoi64(r.Rep))})
	}
	slices.SortFunc(out, func(a, b indexInfo) int { return strings.Compare(a.Name, b.Name) })
	slices.Sort(streams)
	return out, streams, nil
}

// inspect reads the server.
func inspect(ctx context.Context, c *client) (serverInfo, error) {
	var in serverInfo
	r, err := readRoot(ctx, c)
	if err != nil {
		return in, err
	}
	in.Version, in.Distribution, in.ClusterName = r.Version.Number, r.Version.Distribution, r.ClusterName
	in.VersionNum = versionNum(in.Version)
	in.TLS = c.scheme == "https" || c.base.Scheme == "https"
	var h struct {
		Status string `json:"status"`
		Nodes  int    `json:"number_of_nodes"`
	}
	if err := c.get(ctx, "/_cluster/health", &h); err != nil {
		return in, err
	}
	in.Status, in.Nodes = h.Status, h.Nodes
	var ns struct {
		Nodes map[string]struct {
			Settings struct {
				Path struct {
					Repo json.RawMessage `json:"repo"`
					Data json.RawMessage `json:"data"`
				} `json:"path"`
			} `json:"settings"`
		} `json:"nodes"`
	}
	if err := c.get(ctx, "/_nodes/_local/settings?filter_path=nodes.*.settings.path", &ns); err == nil {
		for _, n := range ns.Nodes {
			in.PathRepo = stringList(n.Settings.Path.Repo)
			in.DataPath = stringList(n.Settings.Path.Data)
		}
	}
	in.Security = securityOn(ctx, c)
	in.Indices, in.DataStreams, err = listIndices(ctx, c)
	return in, err
}

// stringList reads a setting that is a string or a list of strings.
func stringList(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var l []string
	if json.Unmarshal(raw, &l) == nil {
		return l
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return strings.Split(s, ",")
	}
	return nil
}

// securityOn reports whether the security plugin is on (its authinfo
// answers).
func securityOn(ctx context.Context, c *client) bool {
	err := c.get(ctx, "/_plugins/_security/authinfo", nil)
	if err == nil {
		return true
	}
	// 401/403 come from the plugin too; 400/404 mean no such endpoint.
	s := statusOf(err)
	return s == http.StatusUnauthorized || s == http.StatusForbidden
}

// supported says why a server can't be protected ("" when it can).
func (in serverInfo) supported() string {
	switch {
	case in.Distribution != "opensearch":
		return "this server isn't OpenSearch (it answers like Elasticsearch), which Rowsafe doesn't support"
	case in.VersionNum < 20000:
		return fmt.Sprintf("OpenSearch %s is too old for Rowsafe: it supports OpenSearch 2 and 3", in.Version)
	case in.Nodes > 1:
		return fmt.Sprintf("this OpenSearch is a cluster of %d nodes, and Rowsafe protects single-node servers only so far", in.Nodes)
	}
	return ""
}

// inspectResult is the protocol's view of the server.
func (in serverInfo) inspectResult(port int) protocol.InspectResult {
	r := protocol.InspectResult{Engine: protocol.EngineOpenSearch, ServerVersion: in.Version, VersionNum: in.VersionNum,
		Port: port, ArchiveMode: "off", TotalSizeBytes: in.totalBytes()}
	if len(in.DataPath) > 0 {
		r.DataDirectory = in.DataPath[0]
	}
	seen := map[string]int{}
	for _, i := range in.Indices {
		name := i.Name
		if i.DataStream != "" {
			name = i.DataStream
		}
		if k, ok := seen[name]; ok {
			r.Databases[k].SizeBytes += i.Bytes
			r.Databases[k].Tables += int(i.Docs)
			continue
		}
		seen[name] = len(r.Databases)
		r.Databases = append(r.Databases, protocol.DBInfo{Name: name, SizeBytes: i.Bytes, Tables: int(i.Docs)})
	}
	if r.Databases == nil {
		r.Databases = []protocol.DBInfo{}
	}
	return r
}

// errNoRepoPath: the node doesn't allow Rowsafe's snapshot folder yet.
var errNoRepoPath = errors.New("no snapshot folder")

// pathEscape escapes one path segment of a REST URL.
func pathEscape(s string) string { return url.PathEscape(s) }
