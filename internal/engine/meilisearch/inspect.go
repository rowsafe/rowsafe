package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/rowsafe/rowsafe/protocol"
)

// instance is what the agent reads from Meilisearch to describe it.
type instance struct {
	Version          string
	DatabaseSize     int64
	UsedDatabaseSize int64
	Indexes          []indexState // Rowsafe's temporary indexes left out
	Temporary        []string     // Rowsafe's temporary indexes (rewinds in place)
}

type indexState struct {
	UID        string
	PrimaryKey string
	Stats      indexStats
}

func (in instance) documents() int64 {
	var n int64
	for _, i := range in.Indexes {
		n += i.Stats.NumberOfDocuments
	}
	return n
}

// isTemporary: one of Rowsafe's own indexes (rewinds in place).
func isTemporary(uid string) bool { return strings.HasPrefix(uid, protocol.MeilisearchRestorePrefix) }

func inspect(ctx context.Context, c *client) (instance, error) {
	var in instance
	v, err := c.version(ctx)
	if err != nil {
		return in, err
	}
	in.Version = v.PkgVersion
	st, err := c.stats(ctx)
	if err != nil {
		return in, err
	}
	in.DatabaseSize, in.UsedDatabaseSize = st.DatabaseSize, st.UsedDatabaseSize
	idx, err := c.indexes(ctx)
	if err != nil {
		return in, err
	}
	for _, i := range idx {
		if isTemporary(i.UID) {
			in.Temporary = append(in.Temporary, i.UID)
			continue
		}
		in.Indexes = append(in.Indexes, indexState{UID: i.UID, PrimaryKey: i.primaryKey(), Stats: st.Indexes[i.UID]})
	}
	slices.SortFunc(in.Indexes, func(a, b indexState) int { return strings.Compare(a.UID, b.UID) })
	return in, nil
}

// versionNum is major*10000+minor*100+patch (1.54.3 is 15403).
func versionNum(v string) int {
	var a, b, c int
	n := 0
	for i, p := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		x := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				break
			}
			x = x*10 + int(r-'0')
		}
		switch i {
		case 0:
			a = x
		case 1:
			b = x
		case 2:
			c = x
		}
		n++
	}
	if n == 0 {
		return 0
	}
	return a*10000 + b*100 + c
}

func (in instance) inspectResult(port int) protocol.InspectResult {
	r := protocol.InspectResult{ServerVersion: in.Version, VersionNum: versionNum(in.Version), Port: port,
		Engine: protocol.EngineMeilisearch, ArchiveMode: "off", IsSuperuser: true,
		TotalSizeBytes: in.DatabaseSize, Databases: []protocol.DBInfo{}}
	for _, i := range in.Indexes {
		r.Databases = append(r.Databases, protocol.DBInfo{Name: i.UID, SizeBytes: i.Stats.IndexSize, Tables: int(min(i.Stats.NumberOfDocuments, 1<<31-1))})
	}
	return r
}

// settingsHash fingerprints an index's settings (their JSON, keys sorted
// by encoding/json), to check a restore brought them back.
func settingsHash(s map[string]json.RawMessage) string {
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	h := sha256.New()
	for _, k := range keys {
		var v any
		_ = json.Unmarshal(s[k], &v)
		canon, _ := json.Marshal(v) // maps come out with sorted keys
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write(canon)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// indexDocs describes the instance's indexes for a backup or Proof.
func indexDocs(ctx context.Context, c *client, in instance) []indexDoc {
	out := make([]indexDoc, 0, len(in.Indexes))
	for _, i := range in.Indexes {
		d := indexDoc{UID: i.UID, PrimaryKey: i.PrimaryKey, Documents: i.Stats.NumberOfDocuments}
		if s, err := c.settings(ctx, i.UID); err == nil {
			d.SettingsHash = settingsHash(s)
		}
		out = append(out, d)
	}
	return out
}
