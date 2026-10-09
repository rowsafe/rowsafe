package opensearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The fixes Pulse proposes (protocol.MaintOpenSearch*). Each checks the
// situation is still the same before it changes anything.

func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	m := e.monitorFor(db.ID)
	m.mu.Lock()
	st, _, err := sample(ctx, c, &dbMonitor{})
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	res := &protocol.MaintenanceResult{Action: p.Action}
	switch p.Action {
	case protocol.MaintOpenSearchReplicas:
		if st.Nodes > 1 {
			return nil, errors.New("this OpenSearch has more than one node: its replicas can be placed, so Rowsafe leaves them")
		}
		want := st.UnassignedReplicaIndices
		if len(p.Tables) > 0 {
			want = nil
			for _, t := range p.Tables {
				if slices.Contains(st.UnassignedReplicaIndices, t) {
					want = append(want, t)
				}
			}
		}
		if len(want) == 0 {
			res.Summary = "No index has replicas waiting for a second node any more: nothing to change."
			break
		}
		for _, idx := range want {
			body := map[string]any{"index": map[string]any{"number_of_replicas": 0}}
			if err := c.do(ctx, http.MethodPut, "/"+pathEscape(idx)+"/_settings", body, nil); err != nil {
				return nil, fmt.Errorf("setting %s's replicas to 0: %w", idx, err)
			}
			res.Details = append(res.Details, idx)
		}
		res.Summary = fmt.Sprintf("Set %d %s to no replicas: a single server can't hold a copy of its own shards. Health is green again; no data moved.",
			len(want), plural(len(want), "index", "indices"))
	case protocol.MaintOpenSearchReadOnly:
		if len(st.ReadOnlyIndices) == 0 {
			res.Summary = "No index is read-only because of a full disk any more: nothing to change."
			break
		}
		if st.DiskTotalBytes > 0 && st.WatermarkHigh > 0 {
			used := 100 * float64(st.DiskTotalBytes-st.DiskAvailableBytes) / float64(st.DiskTotalBytes)
			if used >= st.WatermarkHigh {
				return nil, fmt.Errorf("the disk is still %.0f%% full (OpenSearch's limit is %.0f%%): free some space first, or OpenSearch blocks writes again", used, st.WatermarkHigh)
			}
		}
		body := map[string]any{"index.blocks.read_only_allow_delete": nil}
		if err := c.do(ctx, http.MethodPut, "/"+strings.Join(escapeAll(st.ReadOnlyIndices), ",")+"/_settings", body, nil); err != nil {
			return nil, fmt.Errorf("removing the read-only block: %w", err)
		}
		res.Details = st.ReadOnlyIndices
		res.Summary = fmt.Sprintf("Writes work again on %d %s: the disk has room now.", len(st.ReadOnlyIndices), plural(len(st.ReadOnlyIndices), "index", "indices"))
	default:
		return nil, fmt.Errorf("OpenSearch has no fix %q", p.Action)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	tl.Printf("%s", res.Summary)
	return res, nil
}

func escapeAll(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = pathEscape(n)
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
