package mongodb

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Queries, insights and recommendations for MongoDB. Query statistics come
// from the profiler (system.profile) of the databases where it is on:
// every 5 minutes the operations profiled since the previous reading,
// grouped by shape (shape.go: values replaced with "?"). Every 30 minutes:
// the largest collections, indexes nothing has used for a week
// ($indexStats) and indexes another index makes unnecessary.

const (
	insightsEvery     = 30 * time.Minute
	maxProfileDocs    = 20000
	maxCollections    = 500
	unusedIndexMinAge = 7 * 24 * time.Hour
)

// userDatabases are the databases with the user's data.
func userDatabases(ctx context.Context, c *mongo.Client) ([]string, error) {
	names, err := c.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	out := names[:0]
	for _, n := range names {
		if !isSystemDB(n) {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out, nil
}

// profiler reads the profiler level of each database.
func profiler(ctx context.Context, c *mongo.Client, dbs []string) *protocol.MongoProfiler {
	p := &protocol.MongoProfiler{}
	for _, name := range dbs {
		var res bson.M
		if c.Database(name).RunCommand(ctx, bson.D{{Key: "profile", Value: -1}}).Decode(&res) != nil {
			continue
		}
		if p.SlowMs == 0 {
			p.SlowMs = toInt(res["slowms"])
		}
		if toInt(res["was"]) > 0 {
			p.On = append(p.On, name)
		} else {
			p.Off = append(p.Off, name)
		}
	}
	return p
}

// queryStats reads the profiled operations of [m.profTo, now).
func (m *dbMonitor) queryStats(ctx context.Context, now time.Time, withText bool) (*protocol.Statements, *protocol.QueryStats) {
	c := m.client
	to := now.UTC().Truncate(time.Millisecond)
	from := m.profTo
	st := &protocol.Statements{CollectedAt: now.UTC(), Statements: []protocol.StatementStat{}}
	dbs, err := userDatabases(ctx, c)
	if err != nil {
		return nil, nil
	}
	prof := profiler(ctx, c, dbs)
	m.profTo = to
	if len(prof.On) == 0 {
		st.Reason = "MongoDB's profiler is off: it records the slow operations Rowsafe reads"
		return st, nil
	}
	st.Available = true
	if from.IsZero() || to.Sub(from) > 65*time.Minute {
		return st, nil
	}
	by := map[string]*collect.StmtReading{}
	var readErr error
	for _, name := range prof.On {
		cur, err := c.Database(name).Collection("system.profile").Find(ctx,
			bson.D{{Key: "ts", Value: bson.D{{Key: "$gte", Value: from}, {Key: "$lt", Value: to}}}},
			options.Find().SetLimit(maxProfileDocs).SetProjection(bson.D{
				{Key: "op", Value: 1}, {Key: "ns", Value: 1}, {Key: "command", Value: 1}, {Key: "millis", Value: 1},
				{Key: "nreturned", Value: 1}, {Key: "nModified", Value: 1}, {Key: "ndeleted", Value: 1}, {Key: "ninserted", Value: 1},
				{Key: "docsExamined", Value: 1}, {Key: "planSummary", Value: 1}, {Key: "appName", Value: 1}, {Key: "user", Value: 1}}))
		if err != nil {
			readErr = err
			continue
		}
		for cur.Next(ctx) {
			var op bson.M
			if cur.Decode(&op) != nil {
				continue
			}
			if app, _ := op["appName"].(string); app == "rowsafe-agent" {
				continue
			}
			shape := shapeOf(op)
			if shape == "" {
				continue
			}
			id := shapeID(name, shape)
			r := by[id]
			if r == nil {
				r = &collect.StmtReading{ID: id, Database: name}
				if withText {
					r.Query = shape
				}
				r.User, _ = op["user"].(string)
				by[id] = r
			}
			r.Calls++
			r.TotalTimeMs += toFloat(op["millis"])
			r.Rows += int64(toFloat(op["nreturned"]) + toFloat(op["nModified"]) + toFloat(op["ndeleted"]) + toFloat(op["ninserted"]))
			r.RowsExamined += int64(toFloat(op["docsExamined"]))
			if ps, _ := op["planSummary"].(string); strings.HasPrefix(ps, "COLLSCAN") {
				r.FullScans++
			}
		}
		cur.Close(ctx)
	}
	if readErr != nil && len(by) == 0 {
		st.Available = false
		st.Reason = "reading the profiler's records (system.profile) failed: " + firstLine(readErr.Error())
		return st, nil
	}
	readings := make([]collect.StmtReading, 0, len(by))
	for _, r := range by {
		readings = append(readings, *r)
	}
	qs := collect.BuildQueryStats(to.Sub(from).Seconds(), readings)
	qs.CollectedAt = now.UTC()
	for _, q := range qs.Statements[:min(len(qs.Statements), 25)] {
		x := protocol.StatementStat{QueryID: q.QueryID, Query: q.Query, Database: q.Database, User: q.User, Calls: q.Calls,
			TotalTimeMs: q.TotalTimeMs, Rows: q.Rows}
		if q.Calls > 0 {
			x.MeanTimeMs = q.TotalTimeMs / float64(q.Calls)
		}
		st.Statements = append(st.Statements, x)
	}
	return st, qs
}

// mongoIndex is one index of a collection.
type mongoIndex struct {
	name    string
	keys    []string // "field:1"
	unique  bool
	special bool // partial, sparse, TTL, text, geo, hashed, wildcard: never "redundant"
	ops     int64
	since   time.Time
	bytes   int64
}

func (x mongoIndex) definition() string {
	parts := make([]string, len(x.keys))
	for i, k := range x.keys {
		f, d, _ := strings.Cut(k, ":")
		parts[i] = fmt.Sprintf("%q: %s", f, d)
	}
	def := "{" + strings.Join(parts, ", ") + "}"
	if x.unique {
		def += " (unique)"
	}
	return def
}

// insights collects the collections' sizes and index use.
func insights(ctx context.Context, c *mongo.Client) *protocol.Insights {
	start := time.Now()
	ins := &protocol.Insights{CollectedAt: start.UTC(), LargestTables: []protocol.TableSize{}, LargestIndexes: []protocol.IndexSize{},
		TableBloat: []protocol.TableBloat{}, IndexBloat: []protocol.IndexBloat{}, UnusedIndexes: []protocol.UnusedIndex{},
		DuplicateIndexes: []protocol.DuplicateIndex{}, SeqScanTables: []protocol.SeqScanTable{}, VacuumStats: []protocol.TableVacuum{},
		FreezeAge: []protocol.TableFreeze{}}
	dbs, err := userDatabases(ctx, c)
	if err != nil {
		return nil
	}
	a := &protocol.AdvisorFacts{ForeignKeys: []protocol.ForeignKeyWithoutIndex{}, NoPrimaryKey: []protocol.TableWithoutPK{},
		IntegerKeys: []protocol.IntegerKey{}, SequencesBehind: []protocol.SequenceBehind{}, InvalidIndexes: []protocol.InvalidIndex{},
		DuplicateConstraints: []protocol.DuplicateConstraint{}, TimestampColumns: []protocol.TimestampTable{}, LargeTables: []protocol.LargeTable{}}
	a.Profiler = profiler(ctx, c, dbs)
	ins.Advisor = a
	var tables []protocol.TableSize
	var indexes []protocol.IndexSize
	seen := 0
	for _, dbName := range dbs {
		db := c.Database(dbName)
		names, err := db.ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
		if err != nil {
			continue
		}
		slices.Sort(names)
		count := 0
		for _, coll := range names {
			if strings.HasPrefix(coll, "system.") {
				continue
			}
			if seen >= maxCollections {
				ins.Truncated = true
				break
			}
			seen++
			count++
			size, idx := collectionStats(ctx, db.Collection(coll))
			if size == nil {
				continue
			}
			size.Database, size.Schema, size.Table = dbName, dbName, coll
			tables = append(tables, *size)
			if size.RowsEstimate >= 1_000_000 || size.TotalBytes >= 1<<30 {
				a.LargeTables = append(a.LargeTables, protocol.LargeTable{Database: dbName, Schema: dbName, Table: coll,
					TotalBytes: size.TotalBytes, TableBytes: size.TableBytes, RowsEstimate: size.RowsEstimate})
			}
			for _, x := range idx {
				indexes = append(indexes, protocol.IndexSize{Database: dbName, Schema: dbName, Table: coll, Index: x.name, Bytes: x.bytes, Scans: x.ops})
				if x.name != "_id_" && !x.unique && !x.since.IsZero() && x.ops == 0 && start.Sub(x.since) >= unusedIndexMinAge {
					since := x.since.UTC()
					ins.UnusedIndexes = append(ins.UnusedIndexes, protocol.UnusedIndex{Database: dbName, Schema: dbName, Table: coll,
						Index: x.name, Bytes: x.bytes, Definition: x.definition(), StatsSince: &since})
				}
			}
			ins.DuplicateIndexes = append(ins.DuplicateIndexes, redundantIndexes(dbName, coll, idx)...)
		}
		ins.Databases = append(ins.Databases, protocol.InsightsDatabase{Name: dbName, Tables: count})
	}
	if ins.Truncated {
		ins.Notes = append(ins.Notes, fmt.Sprintf("Only the first %d collections were examined.", maxCollections))
	}
	slices.SortFunc(tables, func(x, y protocol.TableSize) int { return cmp.Compare(y.TotalBytes, x.TotalBytes) })
	ins.LargestTables = append(ins.LargestTables, tables[:min(len(tables), 20)]...)
	slices.SortFunc(indexes, func(x, y protocol.IndexSize) int { return cmp.Compare(y.Bytes, x.Bytes) })
	ins.LargestIndexes = append(ins.LargestIndexes, indexes[:min(len(indexes), 20)]...)
	slices.SortFunc(ins.UnusedIndexes, func(x, y protocol.UnusedIndex) int { return cmp.Compare(y.Bytes, x.Bytes) })
	ins.UnusedIndexes = ins.UnusedIndexes[:min(len(ins.UnusedIndexes), 20)]
	slices.SortFunc(ins.DuplicateIndexes, func(x, y protocol.DuplicateIndex) int { return cmp.Compare(y.Bytes, x.Bytes) })
	ins.DuplicateIndexes = ins.DuplicateIndexes[:min(len(ins.DuplicateIndexes), 20)]
	slices.SortFunc(a.LargeTables, func(x, y protocol.LargeTable) int { return cmp.Compare(y.TotalBytes, x.TotalBytes) })
	a.LargeTables = a.LargeTables[:min(len(a.LargeTables), 20)]
	ins.DurationMs = time.Since(start).Milliseconds()
	return ins
}

// collectionStats reads a collection's sizes ($collStats) and its indexes
// with their use ($indexStats, counted since the server started or the
// index was built).
func collectionStats(ctx context.Context, coll *mongo.Collection) (*protocol.TableSize, []mongoIndex) {
	cur, err := coll.Aggregate(ctx, bson.A{bson.D{{Key: "$collStats", Value: bson.D{{Key: "storageStats", Value: bson.D{}}}}}})
	if err != nil {
		return nil, nil
	}
	var stats []bson.M
	if cur.All(ctx, &stats) != nil || len(stats) == 0 {
		return nil, nil
	}
	ss, _ := stats[0]["storageStats"].(bson.M)
	if ss == nil {
		return nil, nil
	}
	size := &protocol.TableSize{RowsEstimate: int64(toFloat(ss["count"])), TableBytes: int64(toFloat(ss["storageSize"])),
		IndexBytes: int64(toFloat(ss["totalIndexSize"]))}
	size.TotalBytes = size.TableBytes + size.IndexBytes
	sizes, _ := ss["indexSizes"].(bson.M)
	var idx []mongoIndex
	if cur, err := coll.Aggregate(ctx, bson.A{bson.D{{Key: "$indexStats", Value: bson.D{}}}}); err == nil {
		var rows []bson.M
		if cur.All(ctx, &rows) == nil {
			for _, r := range rows {
				x := mongoIndex{}
				x.name, _ = r["name"].(string)
				x.bytes = int64(toFloat(sizes[x.name]))
				if acc, ok := r["accesses"].(bson.M); ok {
					x.ops = int64(toFloat(acc["ops"]))
					x.since, _ = acc["since"].(time.Time)
					if dt, ok := acc["since"].(bson.DateTime); ok {
						x.since = dt.Time()
					}
				}
				spec, _ := r["spec"].(bson.M)
				x.unique, _ = spec["unique"].(bool)
				x.special = spec["partialFilterExpression"] != nil || spec["sparse"] == true || spec["expireAfterSeconds"] != nil
				switch k := spec["key"].(type) {
				case bson.D:
					for _, e := range k {
						x.addKey(e.Key, e.Value)
					}
				case bson.M:
					if len(k) == 1 { // a map has no order: only one key is reliable
						for f, v := range k {
							x.addKey(f, v)
						}
					} else {
						x.special = true
					}
				}
				idx = append(idx, x)
			}
		}
	}
	slices.SortFunc(idx, func(a, b mongoIndex) int { return strings.Compare(a.name, b.name) })
	return size, idx
}

func (x *mongoIndex) addKey(field string, v any) {
	switch d := v.(type) {
	case string: // text, 2dsphere, hashed...
		x.special = true
		x.keys = append(x.keys, field+":"+fmt.Sprintf("%q", d))
	default:
		x.keys = append(x.keys, fmt.Sprintf("%s:%d", field, int(toFloat(d))))
	}
	if strings.Contains(field, "$**") {
		x.special = true
	}
}

// redundantIndexes: a plain, non-unique index whose keys are the same as,
// or the leading keys of, another index.
func redundantIndexes(dbName, coll string, idx []mongoIndex) []protocol.DuplicateIndex {
	var out []protocol.DuplicateIndex
	for _, x := range idx {
		if x.unique || x.special || x.name == "_id_" || len(x.keys) == 0 {
			continue
		}
		for _, y := range idx {
			if y.name == x.name || y.special || len(y.keys) < len(x.keys) || !slices.Equal(y.keys[:len(x.keys)], x.keys) {
				continue
			}
			kind := "redundant"
			if len(y.keys) == len(x.keys) {
				if !y.unique && y.name > x.name {
					continue
				}
				kind = "duplicate"
			}
			out = append(out, protocol.DuplicateIndex{Database: dbName, Schema: dbName, Table: coll, Index: x.name, Kind: kind,
				CoveredBy: y.name, Bytes: x.bytes, Definition: x.definition(), CoveredDefinition: y.definition()})
			break
		}
	}
	return out
}
