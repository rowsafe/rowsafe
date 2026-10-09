package qdrant

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Apply fix for Qdrant: each fix is checked again on the server before
// anything changes, and acts through Qdrant's API, live.

func (e *Engine) maintenance(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	start := time.Now()
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	res := &protocol.MaintenanceResult{Action: p.Action}
	switch p.Action {
	case protocol.MaintQdrantIndexField:
		err = indexField(ctx, c, p, res, tl)
	case protocol.MaintQdrantVectorsOnDisk:
		err = vectorsOnDisk(ctx, c, p, res, tl)
	default:
		return nil, fmt.Errorf("Qdrant has no fix called %q", p.Action)
	}
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		return res, err
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// indexField creates the payload index Qdrant itself suggests, only while
// it still reports that field as unindexed.
func indexField(ctx context.Context, c *client, p protocol.MaintenanceParams, res *protocol.MaintenanceResult, tl agent.TaskLogger) error {
	coll, field, schema := p.DB, p.Settings["field"], p.Settings["schema"]
	if coll == "" || field == "" || !slices.Contains(indexSchemas, schema) {
		return errors.New("say which collection, field and index type")
	}
	issues, err := c.issues(ctx)
	if err != nil {
		return err
	}
	found := false
	for _, is := range issues {
		if is.Collection == coll && is.Field == field && slices.Contains(is.Schemas, schema) {
			found = true
		}
	}
	if !found {
		res.Summary = fmt.Sprintf("Nothing to do: Qdrant no longer reports field %s of collection %s as slowing searches down.", field, coll)
		return nil
	}
	tl.Printf("creating a %s index on field %s of collection %s (Qdrant builds it in the background)", schema, field, coll)
	body := map[string]any{"field_name": field, "field_schema": schema}
	if err := c.call(ctx, http.MethodPut, collPath(coll)+"/index", url.Values{"wait": {"false"}}, body, nil); err != nil {
		return fmt.Errorf("creating the index: %w", err)
	}
	res.Summary = fmt.Sprintf("Created a %s index on field %s of collection %s. Qdrant builds it in the background; searches that filter on it get faster once it is ready.",
		schema, field, coll)
	return nil
}

// vectorsOnDisk moves every vector of a collection to disk (memory-mapped).
func vectorsOnDisk(ctx context.Context, c *client, p protocol.MaintenanceParams, res *protocol.MaintenanceResult, tl agent.TaskLogger) error {
	if p.DB == "" || ownColl(p.DB) {
		return errors.New("say which collection")
	}
	ci, err := c.collection(ctx, p.DB)
	if err != nil {
		if isStatus(err, http.StatusNotFound) {
			return fmt.Errorf("collection %s doesn't exist any more", p.DB)
		}
		return err
	}
	if ci.Status == protocol.QdrantRed {
		return fmt.Errorf("collection %s is failed (red)%s: Rowsafe doesn't change its storage now", p.DB, optErr(ci.OptimizerError))
	}
	vectors := map[string]any{}
	for _, v := range ci.Vectors {
		if !v.OnDisk {
			vectors[v.Name] = map[string]any{"on_disk": true}
		}
	}
	if len(vectors) == 0 {
		res.Summary = fmt.Sprintf("Nothing to do: the vectors of collection %s are on disk already.", p.DB)
		return nil
	}
	tl.Printf("moving the vectors of collection %s to disk (Qdrant rebuilds its storage in the background)", p.DB)
	if err := c.call(ctx, http.MethodPatch, collPath(p.DB), url.Values{"timeout": {"60"}}, map[string]any{"vectors": vectors}, nil); err != nil {
		return fmt.Errorf("changing the collection: %w", err)
	}
	res.Summary = fmt.Sprintf("Collection %s now keeps its vectors on disk. Qdrant moves them in the background and frees the memory as it goes; "+
		"searches keep working and read from disk.", p.DB)
	return nil
}
