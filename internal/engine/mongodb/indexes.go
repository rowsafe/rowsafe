package mongodb

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Index fixes for MongoDB, checked again here before they run:
//
//   - create_index: an index the index advisor proved on a copy
//     (CreateIndex: DB, Table = the collection, Columns = the fields,
//     Descending); refused when an index already starts with those keys or
//     the disk lacks room. MongoDB 4.2+ builds it without blocking reads
//     and writes (only short locks at the start and end).
//   - drop_index: Index ("db.name") on Tables[0] (the collection), never
//     _id_ or a unique index; with Unused, refused once it has been used.

// indexColl is the collection of an index fix.
func indexColl(c *mongo.Client, db, coll string) (*mongo.Collection, error) {
	if db == "" || coll == "" || isSystemDB(db) || strings.HasPrefix(coll, "system.") || len(db) > 64 || len(coll) > 255 {
		return nil, fmt.Errorf("invalid collection %q.%q", db, coll)
	}
	return c.Database(db).Collection(coll), nil
}

func (e *Engine) createIndex(ctx context.Context, c *mongo.Client, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	res := &protocol.MaintenanceResult{Action: p.Action}
	if p.CreateIndex == nil {
		return nil, errors.New("no index given")
	}
	spec := p.CreateIndex.IndexSpec
	coll, err := indexColl(c, spec.DB, spec.Table)
	if err != nil {
		return nil, err
	}
	if len(spec.Columns) == 0 || len(spec.Columns) > 8 || len(spec.Include)+len(spec.WhereNull)+len(spec.WhereNotNull) > 0 {
		return nil, errors.New("invalid index definition")
	}
	keys := bson.D{}
	var want []string
	for _, f := range spec.Columns {
		if f == "" || strings.HasPrefix(f, "$") || strings.ContainsRune(f, 0) {
			return nil, fmt.Errorf("invalid field %q", f)
		}
		dir := 1
		if slices.Contains(spec.Descending, f) {
			dir = -1
		}
		keys = append(keys, bson.E{Key: f, Value: dir})
		want = append(want, fmt.Sprintf("%s:%d", f, dir))
	}
	_, idx := collectionStats(ctx, coll)
	for _, x := range idx {
		if len(x.keys) >= len(want) && slices.Equal(x.keys[:len(want)], want) {
			res.Summary = fmt.Sprintf("%s.%s already has an index starting with those fields (%s). Nothing to do.", spec.DB, spec.Table, x.name)
			return res, nil
		}
	}
	name := spec.Name
	if name == "" {
		name = protocol.IndexName(spec)
	}
	if need := p.CreateIndex.EstimatedBytes * 2; need > 0 {
		var opts struct {
			Parsed bson.M `bson:"parsed"`
		}
		if c.Database("admin").RunCommand(ctx, bson.D{{Key: "getCmdLineOpts", Value: 1}}).Decode(&opts) == nil {
			if free, err := freeBytes(cmpOr(lookupString(opts.Parsed, "storage", "dbPath"), "/data/db")); err == nil && free < need+1<<30 {
				return nil, fmt.Errorf("not enough free disk to build the index: about %s needed, %s free", humanBytes(need+1<<30), humanBytes(free))
			}
		}
	}
	tl.Printf("createIndexes %s.%s %s %v", spec.DB, spec.Table, name, keys)
	started := time.Now()
	err = c.Database(spec.DB).RunCommand(ctx, bson.D{{Key: "createIndexes", Value: spec.Table},
		{Key: "indexes", Value: bson.A{bson.D{{Key: "key", Value: keys}, {Key: "name", Value: name}}}}}).Err()
	if err != nil {
		if isUnauthorized(err) {
			return nil, errors.New("Rowsafe's MongoDB user may not create indexes yet: run the install command on the server again (it refreshes Rowsafe's role), then try again")
		}
		return nil, fmt.Errorf("createIndexes: %w", err)
	}
	res.Summary = fmt.Sprintf("Created the index %s on %s.%s (%s) in %s; reads and writes went on while it was built.",
		name, spec.DB, spec.Table, strings.Join(spec.Columns, ", "), roundDuration(time.Since(started)))
	return res, nil
}

func (e *Engine) dropIndex(ctx context.Context, c *mongo.Client, p protocol.MaintenanceParams, tl agent.TaskLogger) (*protocol.MaintenanceResult, error) {
	res := &protocol.MaintenanceResult{Action: p.Action}
	if len(p.Tables) == 0 {
		return nil, errors.New("no collection given")
	}
	name := strings.TrimPrefix(p.Index, p.DB+".")
	coll, err := indexColl(c, p.DB, p.Tables[0])
	if err != nil {
		return nil, err
	}
	_, idx := collectionStats(ctx, coll)
	var found *mongoIndex
	for i := range idx {
		if idx[i].name == name {
			found = &idx[i]
		}
	}
	switch {
	case found == nil:
		res.Summary = fmt.Sprintf("The index %s on %s.%s no longer exists; nothing to do.", name, p.DB, p.Tables[0])
		return res, nil
	case name == "_id_" || found.unique:
		return nil, fmt.Errorf("%s enforces uniqueness: Rowsafe doesn't drop it", name)
	case p.Unused && found.ops > 0:
		return nil, fmt.Errorf("the index %s has been used since it was found unused (%d times): it was kept", name, found.ops)
	}
	tl.Printf("dropIndexes %s.%s %s (definition %s)", p.DB, p.Tables[0], name, found.definition())
	if err := c.Database(p.DB).RunCommand(ctx, bson.D{{Key: "dropIndexes", Value: p.Tables[0]}, {Key: "index", Value: name}}).Err(); err != nil {
		if isUnauthorized(err) {
			return nil, errors.New("Rowsafe's MongoDB user may not drop indexes yet: run the install command on the server again (it refreshes Rowsafe's role), then try again")
		}
		return nil, fmt.Errorf("dropIndexes: %w", err)
	}
	res.Summary = fmt.Sprintf("Dropped the index %s on %s.%s (%s, %s); writes no longer maintain it.", name, p.DB, p.Tables[0], found.definition(), humanBytes(found.bytes))
	return res, nil
}
