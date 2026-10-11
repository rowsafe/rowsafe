package qdrant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
)

// Qdrant's snapshots are whole copies of a collection, so a backup takes a
// snapshot only of the collections that changed since the newest backup
// and names the earlier snapshot of the others again: a quiet server costs
// nothing but a few small reads.
//
// What changed is told by what Qdrant reports for each collection: every
// write (points, vectors, payloads, payload indexes) is an operation with a
// growing number in each shard's log (telemetry: update_queue.op_num), and
// a collection made again starts new segments (their ids); its settings
// and point count come with it. A collection whose shards don't report
// their operation number (older Qdrant) is always snapshotted.

// changeTelemetry is the part of GET /telemetry (details level 4) that
// tells changes apart.
type changeTelemetry struct {
	Collections struct {
		Collections []struct {
			ID     string `json:"id"`
			Shards []struct {
				ID    int             `json:"id"`
				Key   json.RawMessage `json:"key"`
				Local *struct {
					NumPoints   int64 `json:"num_points"`
					UpdateQueue *struct {
						OpNum *int64 `json:"op_num"`
					} `json:"update_queue"`
					Segments []struct {
						Info struct {
							UUID string `json:"uuid"`
						} `json:"info"`
					} `json:"segments"`
				} `json:"local"`
			} `json:"shards"`
		} `json:"collections"`
	} `json:"collections"`
}

// changeMarks fingerprints each collection's state (name -> mark). A
// collection missing from the result, or with "", counts as changed.
func (c *client) changeMarks(ctx context.Context, names []string) map[string]string {
	out := map[string]string{}
	var t changeTelemetry
	if err := c.call(ctx, http.MethodGet, "/telemetry", url.Values{"details_level": {"4"}}, nil, &t); err != nil {
		return out
	}
	type shard struct {
		ID       int             `json:"id"`
		Key      json.RawMessage `json:"key,omitempty"`
		OpNum    int64           `json:"op"`
		Points   int64           `json:"points"`
		Segments []string        `json:"segments"`
	}
	shards := map[string][]shard{}
	known := map[string]bool{}
	for _, col := range t.Collections.Collections {
		ok := len(col.Shards) > 0
		for _, s := range col.Shards {
			if s.Local == nil || s.Local.UpdateQueue == nil || s.Local.UpdateQueue.OpNum == nil {
				ok = false
				break
			}
			sh := shard{ID: s.ID, Key: s.Key, OpNum: *s.Local.UpdateQueue.OpNum, Points: s.Local.NumPoints}
			for _, seg := range s.Local.Segments {
				sh.Segments = append(sh.Segments, seg.Info.UUID)
			}
			slices.Sort(sh.Segments)
			shards[col.ID] = append(shards[col.ID], sh)
		}
		known[col.ID] = ok
	}
	for _, name := range names {
		if !known[name] {
			continue
		}
		// The collection's settings, payload indexes and point count; what
		// the optimizer changes (status, segments, indexed vectors) left out.
		// (Decoded, so their maps' keys come out sorted: Qdrant's own order
		// may differ from one answer to the next.)
		var info struct {
			Config        any    `json:"config"`
			PayloadSchema any    `json:"payload_schema"`
			PointsCount   *int64 `json:"points_count"`
		}
		if err := c.call(ctx, http.MethodGet, collPath(name), nil, nil, &info); err != nil {
			continue
		}
		ss := shards[name]
		slices.SortFunc(ss, func(a, b shard) int { return a.ID - b.ID })
		b, err := json.Marshal(map[string]any{"config": info.Config, "payload_schema": info.PayloadSchema, "points": info.PointsCount, "shards": ss})
		if err != nil {
			continue
		}
		sum := sha256.Sum256(b)
		out[name] = hex.EncodeToString(sum[:])
	}
	return out
}
