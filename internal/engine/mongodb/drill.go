package mongodb

import (
	"context"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"slices"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Proof for MongoDB: restore the newest backup and every change copied
// since into an isolated scratch server, check it against production, stop
// it and delete it.

const drillSpaceFactor = 1.5

func drillRoot(env agent.EngineEnv) string { return filepath.Join(env.Config.DrillDir, "mongodb") }

func (e *Engine) drill(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, tl agent.TaskLogger) (*protocol.DrillResult, error) {
	started := time.Now()
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(prod)
	in, err := inspect(ctx, prod)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	// Changes up to now reach the bucket first, so the test covers them.
	if s, err := e.shipperFor(env, db); err == nil {
		if latest, err := latestOpTime(ctx, prod); err == nil {
			if err := s.flush(ctx, fromBSON(latest), 2*time.Minute); err != nil {
				tl.Printf("note: the newest changes haven't reached your bucket yet (%v)", err)
			}
		}
	}
	root := drillRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(in.TotalBytes)*drillSpaceFactor)+256<<20); err != nil {
		return &protocol.DrillResult{Failures: []string{err.Error()}}, err
	}
	s, err := newScratch(env, root, taskID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if _, err := s.remove(); err != nil {
			env.Log.Error("removing the MongoDB restore test failed", "dir", s.Dir, "err", err)
		}
	}()
	tl.Printf("starting an isolated MongoDB server in %s (Unix socket only, no network)", s.Dir)
	c, err := s.start(ctx, env)
	if err != nil {
		return &protocol.DrillResult{Failures: []string{err.Error()}}, err
	}
	defer disconnect(c)
	out, err := restoreInto(ctx, env, r, restoreTarget{Latest: true}, s, tl)
	res := &protocol.DrillResult{BackupLabel: out.Backup.Label, RecoveredTo: out.RecoveredTo}
	if err != nil {
		res.Failures = append(res.Failures, err.Error())
		res.DurationSeconds = time.Since(started).Seconds()
		return res, err
	}
	if res.RecoveredTo == nil {
		t := out.Backup.StoppedAt
		res.RecoveredTo = &t
	}
	if out.Failed > 0 {
		res.Failures = append(res.Failures, fmt.Sprintf("%d documents couldn't be restored", out.Failed))
	}
	tl.Printf("restored; checking it against production")
	checkRestored(ctx, prod, c, in, res, tl)
	res.RestoredBytes = dirSize(s.dataDir())
	res.DurationSeconds = time.Since(started).Seconds()
	res.Passed = len(res.Failures) == 0
	if res.Passed {
		tl.Printf("Proof passed: %d databases restored and checked in %s", len(res.Databases), time.Since(started).Round(time.Second))
		return res, nil
	}
	return res, fmt.Errorf("Proof failed: %s", res.Failures[0])
}

// checkRestored compares the restored server with production: every
// database and collection present, indexes present, document counts close
// to production's (which kept changing since), and validate() on a sample
// of collections.
func checkRestored(ctx context.Context, prod, restored *mongo.Client, in serverInfo, res *protocol.DrillResult, tl agent.TaskLogger) {
	type coll struct{ db, name string }
	var sample []coll
	for _, d := range in.Databases {
		dd := protocol.DrillDatabase{Name: d.Name, SourceTables: d.Tables}
		prodColls, err := collections(ctx, prod.Database(d.Name))
		if err != nil {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s: can't list production's collections: %v", d.Name, err))
		}
		gotColls, err := collections(ctx, restored.Database(d.Name))
		if err != nil {
			res.Failures = append(res.Failures, fmt.Sprintf("%s: can't list the restored collections: %v", d.Name, err))
		}
		dd.Present = len(gotColls) > 0 || len(prodColls) == 0
		dd.RestoredTables = len(gotColls)
		if !dd.Present {
			res.Failures = append(res.Failures, fmt.Sprintf("database %s is missing from the restore", d.Name))
		}
		for _, name := range prodColls {
			if !slices.Contains(gotColls, name) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s.%s isn't in the restore (created in the last minutes?)", d.Name, name))
				continue
			}
			sample = append(sample, coll{d.Name, name})
			pc, _ := prod.Database(d.Name).Collection(name).EstimatedDocumentCount(ctx)
			rc, err := restored.Database(d.Name).Collection(name).CountDocuments(ctx, bson.D{})
			if err != nil {
				res.Failures = append(res.Failures, fmt.Sprintf("%s.%s: counting restored documents failed: %v", d.Name, name, err))
				continue
			}
			if diff := pc - rc; (diff > 1000 || diff < -1000) && (float64(abs(diff)) > 0.1*float64(max(pc, 1))) {
				res.Warnings = append(res.Warnings, fmt.Sprintf("%s.%s: %d documents restored, production has about %d now", d.Name, name, rc, pc))
			}
			pi, _ := indexNames(ctx, prod.Database(d.Name).Collection(name))
			ri, _ := indexNames(ctx, restored.Database(d.Name).Collection(name))
			for _, ix := range pi {
				if !slices.Contains(ri, ix) {
					res.Warnings = append(res.Warnings, fmt.Sprintf("%s.%s: index %s isn't in the restore", d.Name, name, ix))
				}
			}
		}
		res.Databases = append(res.Databases, dd)
	}
	// validate() a few collections (a full check of every one could take
	// hours on a large database).
	rand.Shuffle(len(sample), func(i, j int) { sample[i], sample[j] = sample[j], sample[i] })
	for _, cl := range sample[:min(len(sample), 5)] {
		var v struct {
			Valid  bool     `bson:"valid"`
			Errors []string `bson:"errors"`
		}
		err := restored.Database(cl.db).RunCommand(ctx, bson.D{{Key: "validate", Value: cl.name}}).Decode(&v)
		switch {
		case err != nil:
			res.Warnings = append(res.Warnings, fmt.Sprintf("validate %s.%s: %v", cl.db, cl.name, err))
		case !v.Valid:
			msg := "invalid"
			if len(v.Errors) > 0 {
				msg = v.Errors[0]
			}
			res.Failures = append(res.Failures, fmt.Sprintf("%s.%s failed validation: %s", cl.db, cl.name, msg))
		default:
			tl.Printf("validated %s.%s", cl.db, cl.name)
		}
	}
}

// collections lists a database's ordinary collections (no views, no
// system collections).
func collections(ctx context.Context, d *mongo.Database) ([]string, error) {
	names, err := d.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
	if err != nil {
		return nil, err
	}
	out := names[:0]
	for _, n := range names {
		if len(n) < 7 || n[:7] != "system." {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

func indexNames(ctx context.Context, c *mongo.Collection) ([]string, error) {
	specs, err := c.Indexes().ListSpecifications(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range specs {
		out = append(out, s.Name)
	}
	return out, nil
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
