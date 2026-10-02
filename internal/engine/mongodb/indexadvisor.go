package mongodb

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The index advisor for MongoDB (protocol.TaskIndexAdvisor): the slow
// operations MongoDB's profiler recorded that scanned a collection or read
// far more documents than they returned become index ideas (equality
// fields, then the sort, then one range field), each tested on a private
// copy restored from the latest backup, like Proof: explain the operation
// ("executionStats") with the filter the profiler recorded, build the
// index on the copy, explain again. Only indexes MongoDB then uses and that
// make it read at least half as many documents are recommended. The
// recorded filters (with their values) are only read on this server and run
// on the copy; they never leave it. Production is only read.

const (
	mxMaxIdeas      = 12
	mxMinExamined   = 1000
	mxMinRatio      = 10.0
	mxMinSpeedup    = 2.0
	mxExplainTime   = 30 * time.Second
	mxBuildTimeout  = 30 * time.Minute
	mxProfileSample = 5000 // profiler entries read per database
)

// mxSample is one shape's activity and a recorded run of it.
type mxSample struct {
	id, db, coll   string
	filter         bson.D
	sort           bson.D
	limit          int64
	calls          int64
	totalMs        float64
	eq, rng, order []string
	desc           []string
}

type mxIdea struct {
	spec    protocol.IndexSpec
	key     string
	samples []*mxSample
}

func (e *Engine) indexAdvisor(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, taskID string, p protocol.IndexAdvisorParams, tl agent.TaskLogger) (*protocol.IndexAdvisorResult, error) {
	start := time.Now()
	res := &protocol.IndexAdvisorResult{Generated: []string{}, Recommendations: []protocol.IndexRecommendation{}}
	done := func() (*protocol.IndexAdvisorResult, error) {
		res.DurationMs = time.Since(start).Milliseconds()
		if res.Summary == "" {
			switch {
			case res.Skipped != "":
				res.Summary = res.Skipped
			case len(res.Recommendations) > 0:
				res.Summary = fmt.Sprintf("%d %s proven on a copy.", len(res.Recommendations), pluralWord(len(res.Recommendations), "index", "indexes"))
			default:
				res.Summary = fmt.Sprintf("No index would help: %d slow operations looked at, %d ideas tested on a copy.", res.Statements, res.Tested)
			}
		}
		return res, nil
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(prod)
	mongoUsage(ctx, prod, p.Track, res)
	dbs, err := userDatabases(ctx, prod)
	if err != nil {
		return nil, err
	}
	prof := profiler(ctx, prod, dbs)
	if len(prof.On) == 0 {
		res.Skipped = "MongoDB's profiler is off: Rowsafe finds index ideas in the slow operations it records. Turn on query statistics first."
		return done()
	}
	samples := profileSamples(ctx, prod, prof.On, p)
	res.Statements = len(samples)
	ideas := mongoIdeas(ctx, prod, samples, res)
	known := map[string]bool{}
	for _, k := range p.Known {
		known[k] = true
	}
	var test []*mxIdea
	for _, x := range ideas {
		res.Generated = append(res.Generated, x.key)
		if known[x.key] {
			res.Unchanged = append(res.Unchanged, x.key)
		} else if len(test) < mxMaxIdeas {
			test = append(test, x)
		}
	}
	if len(test) == 0 {
		return done()
	}
	// A copy restored from the latest backup.
	began := time.Now()
	in, err := inspect(ctx, prod)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(drillRoot(env), "advisor")
	if err := ensureSpace(filepath.Dir(drillRoot(env)), int64(float64(in.TotalBytes)*drillSpaceFactor)+256<<20); err != nil {
		res.Skipped = "Not enough free disk for a copy to test the indexes on: " + err.Error()
		return done()
	}
	s, err := newScratch(env, root, taskID)
	if err != nil {
		return nil, err
	}
	defer s.remove()
	cp, err := s.start(ctx, env)
	if err != nil {
		return nil, err
	}
	defer disconnect(cp)
	if _, err := restoreInto(ctx, env, r, restoreTarget{Latest: true}, s, tl); err != nil {
		res.Skipped = "Restoring a copy to test the indexes on failed: " + firstLine(err.Error())
		return done()
	}
	res.CopySeconds = time.Since(began).Seconds()
	tl.Printf("copy restored in %s", time.Since(began).Round(time.Second))
	for _, x := range test {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		testMongoIdea(ctx, prod, cp, x, res, tl)
	}
	slices.SortFunc(res.Recommendations, func(a, b protocol.IndexRecommendation) int { return cmp.Compare(b.Speedup, a.Speedup) })
	return done()
}

func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// profileSamples reads the profiler's slow operations that scanned a
// collection or read far more documents than they returned, one sample per
// shape.
func profileSamples(ctx context.Context, c *mongo.Client, dbs []string, p protocol.IndexAdvisorParams) []*mxSample {
	want := map[string]protocol.AdvisorStatement{}
	for _, st := range p.Statements {
		want[st.QueryID] = st
	}
	by := map[string]*mxSample{}
	var order []*mxSample
	for _, name := range dbs {
		cur, err := c.Database(name).Collection("system.profile").Find(ctx, bson.D{},
			options.Find().SetSort(bson.D{{Key: "$natural", Value: -1}}).SetLimit(mxProfileSample))
		if err != nil {
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
			ps, _ := op["planSummary"].(string)
			examined, returned := toFloat(op["docsExamined"]), toFloat(op["nreturned"])
			if !strings.HasPrefix(ps, "COLLSCAN") && (examined < mxMinExamined || examined < mxMinRatio*max(returned, 1)) {
				continue
			}
			shape := shapeOf(op)
			if shape == "" {
				continue
			}
			id := shapeID(name, shape)
			if x := by[id]; x != nil {
				x.calls++
				x.totalMs += toFloat(op["millis"])
				continue
			}
			x := sampleOf(op)
			if x == nil {
				continue
			}
			x.id, x.db, x.calls, x.totalMs = id, name, 1, toFloat(op["millis"])
			by[id] = x
			order = append(order, x)
		}
		cur.Close(ctx)
	}
	var out []*mxSample
	for _, x := range order {
		if w, ok := want[x.id]; ok {
			x.calls, x.totalMs = w.Calls, w.TotalTimeMs
		}
		out = append(out, x)
	}
	slices.SortFunc(out, func(a, b *mxSample) int { return cmp.Compare(b.totalMs, a.totalMs) })
	return out
}

// sampleOf reads an operation's collection, filter, sort and limit, and
// what each filter field asks (equality or range); nil when the filter
// can't be turned into an index idea.
func sampleOf(op bson.M) *mxSample {
	ns, _ := op["ns"].(string)
	_, coll, _ := strings.Cut(ns, ".")
	cmd := asM(op["command"])
	if coll == "" || cmd == nil {
		return nil
	}
	x := &mxSample{coll: coll}
	var filter any
	switch {
	case cmd["find"] != nil:
		filter, x.sort = cmd["filter"], toD(cmd["sort"])
		x.limit = int64(toFloat(cmd["limit"]))
	case cmd["count"] != nil:
		filter = cmd["query"]
	case cmd["aggregate"] != nil:
		stages, _ := cmd["pipeline"].(bson.A)
		if len(stages) == 0 {
			return nil
		}
		m := asM(stages[0])
		if m["$match"] == nil {
			return nil
		}
		filter = m["$match"]
		if len(stages) > 1 {
			x.sort = toD(asM(stages[1])["$sort"])
		}
	default:
		// update and delete: the q of the first statement.
		q := cmd["q"]
		for _, k := range []string{"updates", "deletes"} {
			if arr, ok := cmd[k].(bson.A); ok && len(arr) > 0 {
				q = asM(arr[0])["q"]
			}
		}
		filter = q
	}
	x.filter = toD(filter)
	if len(x.filter) == 0 {
		return nil
	}
	for _, el := range x.filter {
		if strings.HasPrefix(el.Key, "$") {
			continue // $or, $and, $expr...: not an index idea
		}
		switch v := el.Value.(type) {
		case bson.D, bson.M:
			ops := asM(v)
			switch {
			case ops["$eq"] != nil || ops["$in"] != nil:
				x.eq = append(x.eq, el.Key)
			case ops["$gt"] != nil || ops["$gte"] != nil || ops["$lt"] != nil || ops["$lte"] != nil:
				x.rng = append(x.rng, el.Key)
			case !hasOperator(ops):
				x.eq = append(x.eq, el.Key) // an embedded document compared whole
			}
		default:
			x.eq = append(x.eq, el.Key)
		}
	}
	for _, s := range x.sort {
		x.order = append(x.order, s.Key)
		if toFloat(s.Value) < 0 {
			x.desc = append(x.desc, s.Key)
		}
	}
	if len(x.eq)+len(x.rng)+len(x.order) == 0 {
		return nil
	}
	return x
}

func hasOperator(m bson.M) bool {
	for k := range m {
		if strings.HasPrefix(k, "$") {
			return true
		}
	}
	return false
}

func toD(v any) bson.D {
	switch x := v.(type) {
	case bson.D:
		return x
	case bson.M:
		d := bson.D{}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			d = append(d, bson.E{Key: k, Value: x[k]})
		}
		return d
	}
	return nil
}

// candidate is the ESR order: equality fields, then the sort, then one
// range field (the sort is left out when it doesn't start with the range
// field it would have to follow).
func (x *mxSample) candidate() (cols, desc []string) {
	add := func(f string) {
		if !slices.Contains(cols, f) && len(cols) < 4 {
			cols = append(cols, f)
		}
	}
	for _, f := range x.eq {
		add(f)
	}
	for _, f := range x.order {
		add(f)
		if slices.Contains(x.desc, f) {
			desc = append(desc, f)
		}
	}
	if len(x.rng) > 0 {
		add(x.rng[0])
	}
	return cols, desc
}

// mongoIdeas builds one idea per distinct index, leaving out what an
// existing index already covers.
func mongoIdeas(ctx context.Context, c *mongo.Client, samples []*mxSample, res *protocol.IndexAdvisorResult) []*mxIdea {
	by := map[string]*mxIdea{}
	var out []*mxIdea
	existing := map[string][]mongoIndex{}
	for _, x := range samples {
		cols, desc := x.candidate()
		if len(cols) == 0 {
			continue
		}
		res.Analyzed++
		ns := x.db + "." + x.coll
		idx, ok := existing[ns]
		if !ok {
			_, idx = collectionStats(ctx, c.Database(x.db).Collection(x.coll))
			existing[ns] = idx
		}
		var want []string
		for _, f := range cols {
			dir := 1
			if slices.Contains(desc, f) {
				dir = -1
			}
			want = append(want, fmt.Sprintf("%s:%d", f, dir))
		}
		covered := false
		for _, i := range idx {
			if len(i.keys) >= len(want) && slices.Equal(i.keys[:len(want)], want) {
				covered = true
			}
		}
		if covered {
			continue
		}
		spec := protocol.IndexSpec{DB: x.db, Schema: x.db, Table: x.coll, Columns: cols, Descending: desc}
		spec.Name = protocol.IndexName(spec)
		key := spec.Key()
		idea := by[key]
		if idea == nil {
			idea = &mxIdea{spec: spec, key: key}
			by[key] = idea
			out = append(out, idea)
		}
		idea.samples = append(idea.samples, x)
	}
	return out
}

// mxStats is an explain's figures.
type mxStats struct {
	ms, docs, keys float64
	plan           string
}

// explainFind explains the sample as a find on the copy.
func explainFind(ctx context.Context, c *mongo.Client, x *mxSample) (mxStats, error) {
	find := bson.D{{Key: "find", Value: x.coll}, {Key: "filter", Value: x.filter}}
	if len(x.sort) > 0 {
		find = append(find, bson.E{Key: "sort", Value: x.sort})
	}
	if x.limit > 0 {
		find = append(find, bson.E{Key: "limit", Value: x.limit})
	}
	cctx, cancel := context.WithTimeout(ctx, mxExplainTime)
	defer cancel()
	var out bson.M
	err := c.Database(x.db).RunCommand(cctx, bson.D{{Key: "explain", Value: find}, {Key: "verbosity", Value: "executionStats"}}).Decode(&out)
	if err != nil {
		return mxStats{}, err
	}
	es := asM(out["executionStats"])
	plan, _ := bson.MarshalExtJSON(out["queryPlanner"], false, false)
	return mxStats{ms: toFloat(es["executionTimeMillis"]), docs: toFloat(es["totalDocsExamined"]), keys: toFloat(es["totalKeysExamined"]), plan: string(plan)}, nil
}

// testMongoIdea measures the idea's operations on the copy without and
// with the index.
func testMongoIdea(ctx context.Context, prod, cp *mongo.Client, x *mxIdea, res *protocol.IndexAdvisorResult, tl agent.TaskLogger) {
	res.Tested++
	reject := func(reason string) {
		tl.Printf("%s: %s", x.spec.Name, reason)
		res.Rejected = append(res.Rejected, protocol.RejectedIndex{Spec: x.spec, Key: x.key, Reason: reason})
	}
	before := make([]*mxStats, len(x.samples))
	for i, s := range x.samples {
		if st, err := explainFind(ctx, cp, s); err == nil {
			before[i] = &st
		}
	}
	keys := bson.D{}
	for _, f := range x.spec.Columns {
		dir := 1
		if slices.Contains(x.spec.Descending, f) {
			dir = -1
		}
		keys = append(keys, bson.E{Key: f, Value: dir})
	}
	coll := cp.Database(x.spec.DB).Collection(x.spec.Table)
	bctx, cancel := context.WithTimeout(ctx, mxBuildTimeout)
	defer cancel()
	began := time.Now()
	if err := cp.Database(x.spec.DB).RunCommand(bctx, bson.D{{Key: "createIndexes", Value: x.spec.Table},
		{Key: "indexes", Value: bson.A{bson.D{{Key: "key", Value: keys}, {Key: "name", Value: x.spec.Name}}}}}).Err(); err != nil {
		reject("building it on the copy failed: " + firstLine(err.Error()))
		return
	}
	rec := protocol.IndexRecommendation{Spec: x.spec, Key: x.key, BuildMs: time.Since(began).Milliseconds()}
	defer cp.Database(x.spec.DB).RunCommand(context.WithoutCancel(ctx), bson.D{{Key: "dropIndexes", Value: x.spec.Table}, {Key: "index", Value: x.spec.Name}})
	if size, idx := collectionStats(ctx, coll); size != nil {
		rec.TableBytes, rec.TableRows = size.TableBytes, size.RowsEstimate
		for _, i := range idx {
			if i.name == x.spec.Name {
				rec.SizeBytes = i.bytes
			}
		}
	}
	var weighted, timeSum float64
	for i, s := range x.samples {
		if before[i] == nil {
			continue
		}
		after, err := explainFind(ctx, cp, s)
		if err != nil || !strings.Contains(after.plan, `"indexName":"`+x.spec.Name+`"`) {
			continue // MongoDB doesn't choose it for this operation
		}
		g := protocol.IndexGain{QueryID: s.id, CostBefore: before[i].docs + before[i].keys, CostAfter: after.docs + after.keys,
			Calls: s.calls, TotalTimeMs: s.totalMs}
		if before[i].ms >= 5 && after.ms > 0 { // explain's times are whole milliseconds
			g.MsBefore, g.MsAfter = before[i].ms, after.ms
		}
		g.Speedup = max(g.CostBefore, 1) / max(g.CostAfter, 1)
		if g.MsBefore > 0 && g.MsAfter > 0 {
			g.Speedup = min(g.Speedup, g.MsBefore/g.MsAfter)
		}
		if g.Speedup < mxMinSpeedup {
			continue
		}
		rec.Statements = append(rec.Statements, g)
		weighted += g.Speedup * max(s.totalMs, 1)
		timeSum += max(s.totalMs, 1)
	}
	if len(rec.Statements) == 0 {
		reject(fmt.Sprintf("on the copy, MongoDB either didn't use it or it didn't make an operation at least %.0f times cheaper", mxMinSpeedup))
		return
	}
	rec.Speedup = weighted / timeSum
	tl.Printf("%s: %.1fx cheaper for %d operations", x.spec.Name, rec.Speedup, len(rec.Statements))
	res.Recommendations = append(res.Recommendations, rec)
}

// mongoUsage reports the tracked indexes (ones Rowsafe created).
func mongoUsage(ctx context.Context, c *mongo.Client, track []protocol.TrackedIndex, res *protocol.IndexAdvisorResult) {
	if len(track) == 0 {
		return
	}
	for _, t := range track {
		u := protocol.IndexUsage{TrackedIndex: t}
		names, _ := c.Database(t.DB).ListCollectionNames(ctx, bson.D{{Key: "type", Value: "collection"}})
		for _, coll := range names {
			_, idx := collectionStats(ctx, c.Database(t.DB).Collection(coll))
			for _, i := range idx {
				if i.name == t.Index {
					u.Exists, u.Valid, u.Scans, u.SizeBytes = true, true, i.ops, i.bytes
				}
			}
		}
		res.Usage = append(res.Usage, u)
	}
}
