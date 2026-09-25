package mongodb

import (
	"context"

	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Marks: a named point in MongoDB's oplog. The agent writes a no-op entry
// carrying the name (appendOplogNote), waits until the chunk holding it is
// in the bucket, and saves the name with its timestamp there, so a restore
// to the Mark replays exactly up to it.

func (e *Engine) mark(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RestorePointParams, tl agent.TaskLogger) (*protocol.RestorePointResult, error) {
	if !markNameRE.MatchString(p.Name) {
		return nil, fmt.Errorf("invalid Mark name %q", p.Name)
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	at, err := appendNote(ctx, c, "rowsafeMark", p.Name)
	if err != nil {
		return nil, fmt.Errorf("writing the Mark into MongoDB's oplog: %w", err)
	}
	created := at.Time()
	res := &protocol.RestorePointResult{Name: p.Name, LSN: at.String(), CreatedAt: created}
	tl.Printf("Mark %s written at %s (oplog %s)", p.Name, created.Format(time.RFC3339), at)
	r, err := openRepo(env, db)
	if err != nil {
		return res, err
	}
	s, err := e.shipperFor(env, db)
	if err != nil {
		return res, err
	}
	timeout := env.Config.RestorePointTimeout
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	if err := s.flush(ctx, at, timeout); err != nil {
		return res, fmt.Errorf("the Mark was written but hasn't reached your bucket yet: %w", err)
	}
	if err := r.putJSON(ctx, markKey(p.Name), markDoc{Name: p.Name, TS: at, CreatedAt: created}); err != nil {
		return res, fmt.Errorf("saving the Mark in your bucket: %w", err)
	}
	now := time.Now().UTC()
	res.Archived, res.ArchivedAt = true, &now
	if chunks, err := r.listChunks(ctx); err == nil {
		for _, ch := range chunks {
			if !at.Before(ch.First) && !at.After(ch.Last) {
				res.WALFile = ch.Key
			}
		}
	}
	tl.Printf("Mark %s is in your bucket: Rewind can go back exactly to it", p.Name)
	return res, nil
}

// appendNote writes a no-op oplog entry {key: value} (appendOplogNote) and
// returns its timestamp.
func appendNote(ctx context.Context, c *mongo.Client, key, value string) (ts, error) {
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "appendOplogNote", Value: 1},
		{Key: "data", Value: bson.D{{Key: key, Value: value}}}}).Err(); err != nil {
		return ts{}, err
	}
	var entry struct {
		TS bson.Timestamp `bson:"ts"`
	}
	err := c.Database("local").Collection("oplog.rs").FindOne(ctx,
		bson.D{{Key: "op", Value: "n"}, {Key: "o." + key, Value: value}},
		options.FindOne().SetSort(bson.D{{Key: "$natural", Value: -1}})).Decode(&entry)
	if err != nil {
		return ts{}, fmt.Errorf("finding the note in the oplog: %w", err)
	}
	return fromBSON(entry.TS), nil
}
