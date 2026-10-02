package mongodb

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/protocol"
)

// collSnap is one collection of a preview copy.
type collSnap struct {
	Count, Size int64
	Indexes     []string
}

// collSnapshot lists the copy's collections ("db.coll") with their size,
// document count and index names.
func collSnapshot(ctx context.Context, c *mongo.Client) (map[string]*collSnap, error) {
	dbs, err := c.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	snap := map[string]*collSnap{}
	for _, dn := range dbs {
		if isSystemDB(dn) {
			continue
		}
		d := c.Database(dn)
		names, err := collections(ctx, d)
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			s := &collSnap{}
			cur, err := d.Collection(n).Aggregate(ctx, mongo.Pipeline{{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}})
			if err == nil {
				var rows []struct {
					Storage struct {
						Size  int64 `bson:"size"`
						Count int64 `bson:"count"`
					} `bson:"storageStats"`
				}
				if cur.All(ctx, &rows) == nil && len(rows) > 0 {
					s.Size, s.Count = rows[0].Storage.Size, rows[0].Storage.Count
				}
			}
			s.Indexes, _ = indexNames(ctx, d.Collection(n))
			snap[dn+"."+n] = s
		}
	}
	return snap, nil
}

// diffColls fills in the collections a call dropped and the indexes it
// built on collections that existed before it.
func diffColls(before, after map[string]*collSnap, st *protocol.PreviewStatement) {
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			st.Dropped = append(st.Dropped, protocol.PreviewRelation{Name: name, SizeBytes: b.Size, Rows: b.Count})
			continue
		}
		for _, ix := range a.Indexes {
			if !slices.Contains(b.Indexes, ix) {
				st.IndexBuilds = append(st.IndexBuilds, protocol.PreviewRelation{Name: name + "." + ix, Table: name, SizeBytes: b.Size, Rows: b.Count})
			}
		}
	}
	slices.SortFunc(st.Dropped, func(x, y protocol.PreviewRelation) int { return strings.Compare(x.Name, y.Name) })
}

// extArg decodes one Extended JSON argument: a document (bson.D), an
// array (bson.A) or a plain value.
func extArg(s string) (any, error) {
	switch {
	case strings.HasPrefix(s, "{"):
		var d bson.D
		err := bson.UnmarshalExtJSON([]byte(s), false, &d)
		return d, err
	case strings.HasPrefix(s, "["):
		var a bson.A
		err := bson.UnmarshalExtJSON([]byte(s), false, &a)
		return a, err
	}
	var d bson.D
	if err := bson.UnmarshalExtJSON([]byte(`{"v":`+s+`}`), false, &d); err != nil {
		return nil, err
	}
	return d[0].Value, nil
}

func docArg(args []string, i int, what string) (bson.D, error) {
	if i >= len(args) {
		return nil, fmt.Errorf("%s is missing", what)
	}
	v, err := extArg(args[i])
	if err != nil {
		return nil, fmt.Errorf("reading %s: %v", what, err)
	}
	d, ok := v.(bson.D)
	if !ok {
		return nil, fmt.Errorf("%s must be a document", what)
	}
	return d, nil
}

// indexName is the name MongoDB gives an index without one: a_1_b_-1.
func indexName(keys bson.D) string {
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s_%v", k.Key, k.Value))
	}
	return strings.Join(parts, "_")
}

func lookupD(d bson.D, key string) (any, bool) {
	for _, e := range d {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}
