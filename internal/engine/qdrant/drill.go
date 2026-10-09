package qdrant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof for Qdrant: restore the newest backup into a private temporary
// Qdrant, then check every collection the backup recorded is there and not
// failed, with its points, that a search answers in each, and that the
// aliases came back. The temporary server is stopped and deleted after.

func drillRoot(env agent.EngineEnv) string {
	return filepath.Join(env.Config.DrillDir, protocol.EngineQdrant)
}

func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	defer func() { _ = os.Remove(drillRoot(env)) }()
	res := &protocol.DrillResult{}
	fail := func(err error) (*protocol.DrillResult, error) {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	s, err := newScratch(drillRoot(env), "proof-"+taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the restore test failed", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("restoring the newest backup into a private Qdrant (127.0.0.1 only)")
	out, c, err := restoreInto(ctx, env, r, restoreTarget{Latest: true}, &s, tl)
	res.BackupLabel = out.Doc.Label
	if err != nil {
		return fail(err)
	}
	defer c.Close()
	t := out.Doc.TakenAt
	res.RecoveredTo = &t
	res.RestoredBytes = out.Bytes
	checkRestored(ctx, c, out.Doc, res, tl)
	res.DurationSeconds = time.Since(started).Seconds()
	res.Passed = len(res.Failures) == 0
	if res.Passed {
		tl.Printf("Proof passed: backup %s restored and checked (%d collections, %s points) in %s", out.Doc.Label,
			len(res.Databases), commas(out.Doc.totalPoints()), time.Since(started).Round(time.Second))
		return res, nil
	}
	return res, fmt.Errorf("Proof failed: %s", res.Failures[0])
}

// checkRestored checks a restored server against what its backup recorded.
func checkRestored(ctx context.Context, c *client, doc backupDoc, res *protocol.DrillResult, tl agent.TaskLogger) {
	names, err := c.collectionNames(ctx)
	if err != nil {
		res.Failures = append(res.Failures, fmt.Sprintf("the restored Qdrant can't list its collections: %v", err))
		return
	}
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, cd := range doc.Collections {
		if cd.Name == protocol.QdrantKeysCollection {
			continue
		}
		d := protocol.DrillDatabase{Name: cd.Name, SourceTables: clampInt(cd.Points)}
		if !have[cd.Name] {
			res.Failures = append(res.Failures, fmt.Sprintf("collection %s is missing from the restored server", cd.Name))
			res.Databases = append(res.Databases, d)
			continue
		}
		ci, err := waitLoaded(ctx, c, cd.Name, 2*time.Minute)
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("collection %s: %v", cd.Name, err))
			res.Databases = append(res.Databases, d)
			continue
		}
		n, err := c.exactCount(ctx, cd.Name)
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("collection %s: counting its points: %v", cd.Name, err))
			res.Databases = append(res.Databases, d)
			continue
		}
		d.Present, d.RestoredTables = true, clampInt(n)
		switch {
		case cd.Points < 0:
			tl.Printf("%s: %s points restored", cd.Name, commas(n))
		case n < cd.Points-slack(cd.Points):
			res.Failures = append(res.Failures, fmt.Sprintf("collection %s: %s points restored, the backup recorded %s", cd.Name, commas(n), commas(cd.Points)))
		case n > cd.Points+slack(cd.Points):
			res.Warnings = append(res.Warnings, fmt.Sprintf("collection %s: %s points restored, more than the %s the backup recorded", cd.Name, commas(n), commas(cd.Points)))
		default:
			tl.Printf("%s: %s points restored (the backup recorded %s)", cd.Name, commas(n), commas(cd.Points))
		}
		if n > 0 {
			if hits, err := sampleSearch(ctx, c, ci); err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("collection %s: a search failed on the restored data: %v", cd.Name, err))
			} else if hits >= 0 {
				tl.Printf("%s: a search answered with %d results", cd.Name, hits)
			}
		}
		res.Databases = append(res.Databases, d)
	}
	if got, err := c.aliases(ctx); err == nil && len(doc.Aliases) > 0 && !maps.Equal(got, doc.Aliases) {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the restored server has %d aliases, the backup recorded %d", len(got), len(doc.Aliases)))
	}
}

// slack allows for the writes of the moment the snapshot was taken (the
// counts are read just before and after it).
func slack(n int64) int64 { return max(int64(10), n/1000) }

// waitLoaded waits until a restored collection is loaded and not failed.
func waitLoaded(ctx context.Context, c *client, name string, limit time.Duration) (collInfo, error) {
	deadline := time.Now().Add(limit)
	for {
		ci, err := c.collection(ctx, name)
		switch {
		case err != nil:
		case ci.Status == protocol.QdrantRed:
			return ci, fmt.Errorf("Qdrant reports it as failed (red)%s", optErr(ci.OptimizerError))
		default:
			return ci, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return ci, fmt.Errorf("it didn't load: %v", err)
		}
		time.Sleep(time.Second)
	}
}

func optErr(s string) string {
	if s == "" {
		return ""
	}
	return ": " + s
}

// sampleSearch takes one point's vector and searches the collection with
// it (exact search, so the index plays no part): -1 when the collection
// has no vector to search with.
func sampleSearch(ctx context.Context, c *client, ci collInfo) (int, error) {
	var sc struct {
		Points []struct {
			Vector json.RawMessage `json:"vector"`
		} `json:"points"`
	}
	if err := c.call(ctx, http.MethodPost, collPath(ci.Name)+"/points/scroll", nil,
		map[string]any{"limit": 1, "with_vector": true, "with_payload": false}, &sc); err != nil {
		return 0, err
	}
	if len(sc.Points) == 0 {
		return 0, errors.New("no point could be read")
	}
	q, using, ok := queryVector(sc.Points[0].Vector)
	if !ok {
		return -1, nil
	}
	body := map[string]any{"query": q, "limit": 3, "params": map[string]any{"exact": true}}
	if using != "" {
		body["using"] = using
	}
	var qr struct {
		Points []json.RawMessage `json:"points"`
	}
	if err := c.call(ctx, http.MethodPost, collPath(ci.Name)+"/points/query", nil, body, &qr); err != nil {
		return 0, err
	}
	if len(qr.Points) == 0 {
		return 0, errors.New("it found nothing, not even the point its vector came from")
	}
	return len(qr.Points), nil
}

// queryVector picks a vector to search with from a point's "vector": the
// unnamed one ([...]) or the first named one (dense, multi or sparse).
func queryVector(raw json.RawMessage) (any, string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, "", false
	}
	var dense []float64
	if json.Unmarshal(raw, &dense) == nil && len(dense) > 0 {
		return dense, "", true
	}
	var named map[string]json.RawMessage
	if json.Unmarshal(raw, &named) != nil || len(named) == 0 {
		return nil, "", false
	}
	keys := slices.Sorted(maps.Keys(named))
	// Dense first: a sparse vector of a point may be empty.
	for _, k := range keys {
		var d []float64
		if json.Unmarshal(named[k], &d) == nil && len(d) > 0 {
			return d, k, true
		}
	}
	for _, k := range keys {
		var m [][]float64
		if json.Unmarshal(named[k], &m) == nil && len(m) > 0 {
			return m, k, true
		}
		var sp struct {
			Indices []int     `json:"indices"`
			Values  []float64 `json:"values"`
		}
		if json.Unmarshal(named[k], &sp) == nil && len(sp.Indices) > 0 && strings.HasPrefix(strings.TrimSpace(string(named[k])), "{") {
			return sp, k, true
		}
	}
	return nil, "", false
}
