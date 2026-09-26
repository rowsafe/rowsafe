package mongodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind for MongoDB: a copy of the database as it was at any second (or a
// Mark), restored next to production into an isolated scratch server that
// stays up until it expires; a comparison by _id with production; and
// bringing documents back (missing ones, and changed ones when asked).
// Everything stays on this server: only names and counts are reported.

const (
	defaultCopyHours = 24
	maxCopyAge       = 7 * 24 * time.Hour
	// compareMaxDocs caps the documents compared per collection.
	compareMaxDocs = 10_000_000
	// defaultMaxRows is the most documents one bring-back writes.
	defaultMaxRows = 10_000_000
	batchSize      = 500
)

func copyRoot(env agent.EngineEnv) string { return filepath.Join(env.Config.RewindDir, "mongodb") }

// copyRecord is a copy the engine keeps (<state>/copies.json).
type copyRecord struct {
	ID          string                `json:"id"`
	DatabaseID  string                `json:"database_id"`
	Port        int                   `json:"port"` // production's
	Dir         string                `json:"dir"`
	Status      string                `json:"status"` // protocol.RewindCopyRestoring | RewindCopyReady
	Target      protocol.RewindTarget `json:"target"`
	CreatedAt   time.Time             `json:"created_at"`
	Expires     time.Time             `json:"expires"`
	RecoveredTo *time.Time            `json:"recovered_to,omitempty"`
	SizeBytes   int64                 `json:"size_bytes"`
}

type copyStore struct {
	mu      sync.Mutex
	path    string
	records map[string]copyRecord
	running map[string]context.CancelFunc
}

func (e *Engine) copyState(env agent.EngineEnv) *copyStore {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.copies == nil {
		cs := &copyStore{path: filepath.Join(env.StateDir, "copies.json"), records: map[string]copyRecord{}, running: map[string]context.CancelFunc{}}
		if data, err := os.ReadFile(cs.path); err == nil {
			var list []copyRecord
			if err := json.Unmarshal(data, &list); err != nil {
				env.Log.Error("reading MongoDB copies state; starting empty", "err", err)
			}
			for _, r := range list {
				cs.records[r.ID] = r
			}
		}
		e.copies = cs
	}
	return e.copies
}

func (cs *copyStore) saveLocked() error {
	list := make([]copyRecord, 0, len(cs.records))
	for _, r := range cs.records {
		list = append(list, r)
	}
	slices.SortFunc(list, func(a, b copyRecord) int { return strings.Compare(a.ID, b.ID) })
	return saveJSONFile(cs.path, list)
}

func (cs *copyStore) put(r copyRecord) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.records[r.ID] = r
	return cs.saveLocked()
}

func (cs *copyStore) remove(id string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.records, id)
	return cs.saveLocked()
}

func (cs *copyStore) get(id string) (copyRecord, bool) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	r, ok := cs.records[id]
	return r, ok
}

func (cs *copyStore) all() []copyRecord {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]copyRecord, 0, len(cs.records))
	for _, r := range cs.records {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b copyRecord) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (cs *copyStore) forDatabase(dbID string) (copyRecord, bool) {
	for _, r := range cs.all() {
		if r.DatabaseID == dbID {
			return r, true
		}
	}
	return copyRecord{}, false
}

func clampExpiry(want, now time.Time) time.Time {
	if want.IsZero() || !want.After(now) {
		return now.Add(defaultCopyHours * time.Hour)
	}
	if limit := now.Add(maxCopyAge); want.After(limit) {
		return limit
	}
	return want
}

func (e *Engine) rewindCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCopyParams, tl agent.TaskLogger) (*protocol.RewindCopyResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	target := restoreTarget{Mark: p.Target.Mark}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if (target.Mark == "") == target.Time.IsZero() {
		return nil, errors.New("pick a moment or a Mark (exactly one)")
	}
	if target.Mark != "" && !markNameRE.MatchString(target.Mark) {
		return nil, fmt.Errorf("invalid Mark name %q", target.Mark)
	}
	cs := e.copyState(env)
	if r, ok := cs.forDatabase(db.ID); ok {
		if r.ID == p.CopyID && r.Status == protocol.RewindCopyReady {
			return e.copyResult(ctx, env, r)
		}
		return nil, errors.New("this database already has a copy: delete it before restoring another")
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()

	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, prod)
	disconnect(prod)
	if err != nil {
		return nil, err
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	// A moment in the last minute may not be copied yet.
	if !target.Time.IsZero() && time.Since(target.Time) < 3*time.Minute {
		if s, err := e.shipperFor(env, db); err == nil {
			_ = s.flush(ctx, ts{T: uint32(target.Time.Unix()) + 1}, 2*time.Minute)
		}
	}
	root := copyRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(in.TotalBytes)*drillSpaceFactor)+256<<20); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := copyRecord{ID: p.CopyID, DatabaseID: db.ID, Port: db.Port, Dir: filepath.Join(root, p.CopyID),
		Status: protocol.RewindCopyRestoring, Target: p.Target, CreatedAt: now, Expires: clampExpiry(p.Expires, now)}
	s, err := newScratch(env, root, p.CopyID)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cs.mu.Lock()
	cs.running[rec.ID] = cancel
	cs.mu.Unlock()
	defer func() {
		cs.mu.Lock()
		delete(cs.running, rec.ID)
		cs.mu.Unlock()
	}()
	if err := cs.put(rec); err != nil {
		_, _ = s.remove()
		return nil, err
	}
	fail := func(err error) (*protocol.RewindCopyResult, error) {
		if _, rerr := s.remove(); rerr != nil {
			env.Log.Error("removing a failed copy", "dir", s.Dir, "err", rerr)
		}
		_ = cs.remove(rec.ID)
		return nil, err
	}
	tl.Printf("restoring a copy of %s as of %s into an isolated server (Unix socket only, no network)", db.Name, target.describe())
	c, err := s.start(cctx, env)
	if err != nil {
		return fail(err)
	}
	out, err := restoreInto(cctx, env, r, target, s, tl)
	disconnect(c)
	if err != nil {
		if cctx.Err() != nil && ctx.Err() == nil {
			return fail(errors.New("the copy was deleted while it was being restored"))
		}
		return fail(err)
	}
	rec.Status = protocol.RewindCopyReady
	rec.RecoveredTo = out.RecoveredTo
	if rec.RecoveredTo == nil {
		t := out.Backup.StoppedAt
		rec.RecoveredTo = &t
	}
	rec.SizeBytes = dirSize(s.dataDir())
	if err := cs.put(rec); err != nil {
		return fail(err)
	}
	res, err := e.copyResult(ctx, env, rec)
	if err != nil {
		return nil, err
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) copyResult(ctx context.Context, env agent.EngineEnv, rec copyRecord) (*protocol.RewindCopyResult, error) {
	s := scratchAt(env, rec.Dir)
	c, err := connect(ctx, s.uri())
	if err != nil {
		return nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	defer disconnect(c)
	dbs, _, err := restoredDatabases(ctx, c)
	if err != nil {
		return nil, err
	}
	docs := int64(0)
	for _, d := range dbs {
		docs += int64(d.Tables)
	}
	when := "the backup"
	if rec.RecoveredTo != nil {
		when = rec.RecoveredTo.UTC().Format("2006-01-02 15:04:05 UTC")
	}
	return &protocol.RewindCopyResult{CopyID: rec.ID, RecoveredTo: rec.RecoveredTo, SizeBytes: rec.SizeBytes, Databases: dbs,
		SocketDir: s.SockDir, Port: scratchPort, Expires: rec.Expires,
		Summary: fmt.Sprintf("The copy is ready: %d databases (%d collections, %s) as of %s. It is deleted by itself on %s.",
			len(dbs), docs, humanBytes(rec.SizeBytes), when, rec.Expires.UTC().Format("2006-01-02 15:04 UTC"))}, nil
}

func (e *Engine) rewindDrop(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindDropParams, tl agent.TaskLogger) (*protocol.RewindDropResult, error) {
	if !idRE.MatchString(p.CopyID) {
		return nil, fmt.Errorf("invalid copy id %q", p.CopyID)
	}
	cs := e.copyState(env)
	cs.mu.Lock()
	cancel := cs.running[p.CopyID]
	cs.mu.Unlock()
	if cancel != nil {
		tl.Printf("the copy is still being restored: stopping that first")
		cancel()
		for range 120 {
			cs.mu.Lock()
			_, still := cs.running[p.CopyID]
			cs.mu.Unlock()
			if !still {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	rec, ok := cs.get(p.CopyID)
	if !ok {
		dir := filepath.Join(copyRoot(env), p.CopyID)
		if _, err := os.Lstat(dir); err != nil {
			return &protocol.RewindDropResult{CopyID: p.CopyID, Summary: "There was no such copy (already deleted)."}, nil
		}
		rec = copyRecord{ID: p.CopyID, Dir: dir}
	}
	if rec.DatabaseID != "" && rec.DatabaseID != db.ID {
		return nil, errors.New("that copy belongs to another database")
	}
	freed, err := scratchAt(env, rec.Dir).remove()
	if err != nil {
		return nil, err
	}
	if err := cs.remove(p.CopyID); err != nil {
		return nil, err
	}
	tl.Printf("deleted the copy, freeing %s", humanBytes(freed))
	return &protocol.RewindDropResult{CopyID: p.CopyID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the copy (%s freed).", humanBytes(freed))}, nil
}

// readyCopy connects to a database's ready copy and production.
func (e *Engine) readyCopy(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, id string) (copyRecord, *mongo.Client, *mongo.Client, error) {
	rec, ok := e.copyState(env).get(id)
	if !ok || rec.DatabaseID != db.ID {
		return rec, nil, nil, errors.New("there is no such copy (it expired or was deleted): restore a new one")
	}
	if rec.Status != protocol.RewindCopyReady {
		return rec, nil, nil, errors.New("the copy is still being restored")
	}
	cp, err := connect(ctx, scratchAt(env, rec.Dir).uri())
	if err != nil {
		return rec, nil, nil, fmt.Errorf("the copy isn't answering: %w", err)
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		disconnect(cp)
		return rec, nil, nil, err
	}
	return rec, cp, prod, nil
}

// copyTables are the collections to work on: the ones asked for, or every
// collection of every database in the copy.
func copyTables(ctx context.Context, cp *mongo.Client, asked []protocol.RewindTable) ([]protocol.RewindTable, error) {
	if len(asked) > 0 {
		for _, t := range asked {
			if !validName(t.DB) || !validName(t.Table) || isSystemDB(t.DB) || strings.HasPrefix(t.Table, "system.") {
				return nil, fmt.Errorf("%s.%s can't be compared", t.DB, t.Table)
			}
		}
		return asked, nil
	}
	dbs, _, err := restoredDatabases(ctx, cp)
	if err != nil {
		return nil, err
	}
	var out []protocol.RewindTable
	for _, d := range dbs {
		names, err := collections(ctx, cp.Database(d.Name))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			out = append(out, protocol.RewindTable{DB: d.Name, Table: n})
		}
	}
	if len(out) > 500 {
		out = out[:500]
	}
	return out, nil
}

func validName(s string) bool {
	return s != "" && len(s) <= 255 && !strings.ContainsAny(s, "\x00$") && s == strings.TrimSpace(s)
}

func (e *Engine) rewindCompare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCompareParams, tl agent.TaskLogger) (*protocol.RewindCompareResult, error) {
	_, cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer disconnect(cp)
	defer disconnect(prod)
	tables, err := copyTables(ctx, cp, p.Tables)
	if err != nil {
		return nil, err
	}
	res := &protocol.RewindCompareResult{CopyID: p.CopyID}
	var missing, changed int64
	var touched []string
	for _, t := range tables {
		d, err := compareCollection(ctx, cp, prod, t, nil)
		if err != nil {
			return nil, err
		}
		res.Tables = append(res.Tables, d)
		missing += d.MissingInProduction
		changed += d.Changed
		if d.MissingInProduction+d.Changed > 0 {
			touched = append(touched, t.DB+"."+t.Table)
		}
		tl.Printf("%s.%s: %d missing in production, %d changed, %d added since%s", t.DB, t.Table, d.MissingInProduction, d.Changed,
			d.OnlyInProduction, skippedNote(d.Skipped))
	}
	switch {
	case missing+changed == 0:
		res.Summary = fmt.Sprintf("No documents are missing or changed in the %d collections compared.", len(res.Tables))
	default:
		res.Summary = fmt.Sprintf("%s documents are missing from production and %s changed, in %d collections (%s).",
			commas(missing), commas(changed), len(touched), strings.Join(firstN(touched, 3), ", "))
	}
	return res, nil
}

func skippedNote(s string) string {
	if s == "" {
		return ""
	}
	return " (skipped: " + s + ")"
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(slices.Clone(s[:n]), fmt.Sprintf("and %d more", len(s)-n))
}

// idKey is a map key for an _id value (its BSON type and bytes).
func idKey(v bson.RawValue) string { return string(append([]byte{byte(v.Type)}, v.Value...)) }

// visit calls fn with each batch of the copy's documents of a collection
// and the production documents with the same _ids.
func visit(ctx context.Context, cp, prod *mongo.Collection, fn func(copyDocs []bson.Raw, prodByID map[string]bson.Raw) error) error {
	cur, err := cp.Find(ctx, bson.D{}, options.Find().SetBatchSize(batchSize))
	if err != nil {
		return err
	}
	defer cur.Close(ctx)
	var batch []bson.Raw
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		ids := make(bson.A, 0, len(batch))
		for _, d := range batch {
			ids = append(ids, d.Lookup("_id"))
		}
		pc, err := prod.Find(ctx, bson.D{{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}}})
		if err != nil {
			return err
		}
		byID := map[string]bson.Raw{}
		for pc.Next(ctx) {
			byID[idKey(pc.Current.Lookup("_id"))] = bytes.Clone(pc.Current)
		}
		err = pc.Err()
		pc.Close(ctx)
		if err != nil {
			return err
		}
		err = fn(batch, byID)
		batch = batch[:0]
		return err
	}
	for cur.Next(ctx) {
		batch = append(batch, bytes.Clone(cur.Current))
		if len(batch) == batchSize {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := cur.Err(); err != nil {
		return err
	}
	return flush()
}

// compareCollection counts, by _id, the copy's documents missing from
// production or different there, and production's documents added since.
// With collect, it also passes the differing documents on.
func compareCollection(ctx context.Context, cp, prod *mongo.Client, t protocol.RewindTable,
	collect func(missing, changed []bson.Raw) error) (protocol.RewindTableDiff, error) {
	d := protocol.RewindTableDiff{RewindTable: t}
	var info struct {
		Type    string `bson:"type"`
		Options bson.M `bson:"options"`
	}
	specs, err := cp.Database(t.DB).ListCollectionSpecifications(ctx, bson.D{{Key: "name", Value: t.Table}})
	if err != nil {
		return d, err
	}
	if len(specs) == 0 {
		d.Skipped = "not in the copy"
		return d, nil
	}
	info.Type = specs[0].Type
	switch info.Type {
	case "view":
		d.Skipped = "a view (it holds no documents of its own)"
		return d, nil
	case "timeseries":
		d.Skipped = "a time series collection (not compared by _id)"
		return d, nil
	}
	cc, pc := cp.Database(t.DB).Collection(t.Table), prod.Database(t.DB).Collection(t.Table)
	var st struct {
		Size int64 `bson:"size"`
	}
	_ = cp.Database(t.DB).RunCommand(ctx, bson.D{{Key: "collStats", Value: t.Table}}).Decode(&st)
	d.SizeBytes = st.Size
	n, err := cc.EstimatedDocumentCount(ctx)
	if err != nil {
		return d, err
	}
	if n > compareMaxDocs {
		d.Skipped = fmt.Sprintf("too large to compare here (%s documents)", commas(n))
		return d, nil
	}
	prodNames, err := prod.Database(t.DB).ListCollectionNames(ctx, bson.D{{Key: "name", Value: t.Table}})
	if err != nil {
		return d, err
	}
	dropped := len(prodNames) == 0
	var matched int64
	err = visit(ctx, cc, pc, func(docs []bson.Raw, byID map[string]bson.Raw) error {
		var miss, chg []bson.Raw
		for _, doc := range docs {
			p, ok := byID[idKey(doc.Lookup("_id"))]
			switch {
			case !ok:
				d.MissingInProduction++
				miss = append(miss, doc)
			case !bytes.Equal(p, doc):
				matched++
				d.Changed++
				chg = append(chg, doc)
			default:
				matched++
			}
		}
		if collect != nil && len(miss)+len(chg) > 0 {
			return collect(miss, chg)
		}
		return nil
	})
	if err != nil {
		return d, err
	}
	if dropped {
		d.Note = "This collection was dropped from production since: bringing documents back creates it again, with its indexes."
		return d, nil
	}
	total, err := pc.CountDocuments(ctx, bson.D{})
	if err != nil {
		return d, err
	}
	d.OnlyInProduction = max(total-matched, 0)
	return d, nil
}

func (e *Engine) rewindRows(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindRowsParams, tl agent.TaskLogger) (*protocol.RewindRowsResult, error) {
	if len(p.Tables) == 0 {
		return nil, errors.New("pick the collections to bring documents back into")
	}
	_, cp, prod, err := e.readyCopy(ctx, env, db, p.CopyID)
	if err != nil {
		return nil, err
	}
	defer disconnect(cp)
	defer disconnect(prod)
	if !isPrimary(ctx, prod) {
		return nil, errors.New("this MongoDB server isn't the primary of its replica set, so documents can't be written here")
	}
	tables, err := copyTables(ctx, cp, p.Tables)
	if err != nil {
		return nil, err
	}
	// Count first: over the limit, nothing is changed.
	limit := p.MaxRows
	if limit <= 0 {
		limit = defaultMaxRows
	}
	var total int64
	for _, t := range tables {
		d, err := compareCollection(ctx, cp, prod, t, nil)
		if err != nil {
			return nil, err
		}
		if d.Skipped != "" {
			return nil, fmt.Errorf("%s.%s can't be brought back: %s", t.DB, t.Table, d.Skipped)
		}
		total += d.MissingInProduction
		if p.IncludeChanged {
			total += d.Changed
		}
	}
	if total > limit {
		return nil, fmt.Errorf("that would write %s documents, more than the limit of %s: nothing was changed; pick fewer collections",
			commas(total), commas(limit))
	}
	res := &protocol.RewindRowsResult{}
	var parts []string
	for _, t := range tables {
		out, err := bringBack(ctx, cp, prod, t, p.IncludeChanged, tl)
		res.Tables = append(res.Tables, out)
		if err != nil {
			return res, fmt.Errorf("%s.%s: %w (documents written before this are kept; running it again finishes the job without duplicates)",
				t.DB, t.Table, err)
		}
		if out.Inserted+out.Updated > 0 {
			s := fmt.Sprintf("%s in %s.%s", commas(out.Inserted), t.DB, t.Table)
			if out.Updated > 0 {
				s += fmt.Sprintf(" (and %s changed back)", commas(out.Updated))
			}
			parts = append(parts, s)
		}
		tl.Printf("%s.%s: %d brought back, %d changed back, %d conflicts", t.DB, t.Table, out.Inserted, out.Updated, out.Conflicts)
	}
	if len(parts) == 0 {
		res.Summary = "Nothing needed to be brought back: production already has these documents."
	} else {
		res.Summary = "Brought back " + strings.Join(parts, ", ") + "."
	}
	return res, nil
}

// bringBack inserts the copy's documents missing from production (never
// overwriting), and with changed also puts changed documents back.
func bringBack(ctx context.Context, cp, prod *mongo.Client, t protocol.RewindTable, changed bool, tl agent.TaskLogger) (protocol.RewindTableRows, error) {
	out := protocol.RewindTableRows{RewindTable: t}
	pc := prod.Database(t.DB).Collection(t.Table)
	names, err := prod.Database(t.DB).ListCollectionNames(ctx, bson.D{{Key: "name", Value: t.Table}})
	if err != nil {
		return out, err
	}
	if len(names) == 0 {
		if err := recreateCollection(ctx, cp, prod, t); err != nil {
			return out, fmt.Errorf("creating the collection again: %w", err)
		}
		tl.Printf("%s.%s was dropped from production: created it again with its indexes", t.DB, t.Table)
	}
	_, err = compareCollection(ctx, cp, prod, t, func(missing, chg []bson.Raw) error {
		if len(missing) > 0 {
			docs := make([]any, len(missing))
			for i, d := range missing {
				docs[i] = d
			}
			r, err := pc.InsertMany(ctx, docs, options.InsertMany().SetOrdered(false))
			if r != nil {
				out.Inserted += int64(len(r.InsertedIDs))
			}
			if err != nil {
				var bwe mongo.BulkWriteException
				if !errors.As(err, &bwe) {
					return err
				}
				for _, we := range bwe.WriteErrors {
					if we.Code != 11000 {
						return err
					}
					out.Conflicts++
				}
				out.Inserted = max(out.Inserted-int64(len(bwe.WriteErrors)), 0)
			}
		}
		if changed {
			for _, d := range chg {
				r, err := pc.ReplaceOne(ctx, bson.D{{Key: "_id", Value: d.Lookup("_id")}}, d)
				if err != nil {
					if mongo.IsDuplicateKeyError(err) {
						out.Conflicts++
						continue
					}
					return err
				}
				out.Updated += r.ModifiedCount
			}
		}
		return nil
	})
	return out, err
}

// recreateCollection creates a collection dropped from production again,
// with the copy's options and indexes.
func recreateCollection(ctx context.Context, cp, prod *mongo.Client, t protocol.RewindTable) error {
	var spec struct {
		Options bson.Raw `bson:"options"`
	}
	cur, err := cp.Database(t.DB).ListCollections(ctx, bson.D{{Key: "name", Value: t.Table}})
	if err != nil {
		return err
	}
	if cur.Next(ctx) {
		_ = cur.Decode(&spec)
	}
	cur.Close(ctx)
	cmd := bson.D{{Key: "create", Value: t.Table}}
	if spec.Options != nil {
		elems, _ := spec.Options.Elements()
		for _, el := range elems {
			switch el.Key() {
			case "validator", "validationLevel", "validationAction", "collation", "capped", "size", "max", "changeStreamPreAndPostImages", "clusteredIndex":
				cmd = append(cmd, bson.E{Key: el.Key(), Value: el.Value()})
			}
		}
	}
	if err := prod.Database(t.DB).RunCommand(ctx, cmd).Err(); err != nil {
		var ce mongo.CommandError
		if !errors.As(err, &ce) || ce.Code != 48 { // NamespaceExists: created meanwhile
			return err
		}
	}
	icur, err := cp.Database(t.DB).Collection(t.Table).Indexes().List(ctx)
	if err != nil {
		return err
	}
	defer icur.Close(ctx)
	var specs bson.A
	for icur.Next(ctx) {
		var ix bson.D
		if err := bson.Unmarshal(icur.Current, &ix); err != nil {
			return err
		}
		name := ""
		clean := bson.D{}
		for _, e := range ix {
			switch e.Key {
			case "v", "ns":
				continue
			case "name":
				name, _ = e.Value.(string)
			}
			clean = append(clean, e)
		}
		if name == "_id_" {
			continue
		}
		specs = append(specs, clean)
	}
	if len(specs) == 0 {
		return nil
	}
	return prod.Database(t.DB).RunCommand(ctx, bson.D{{Key: "createIndexes", Value: t.Table}, {Key: "indexes", Value: specs}}).Err()
}

// commas formats 1204 as "1,204".
func commas(n int64) string {
	s := fmt.Sprint(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// ---- copies across agent restarts, expiry, heartbeat

// recoverCopies runs at start: interrupted restores are removed, ready
// copies started again, leftovers without a record removed; leftover
// restore tests too.
func (e *Engine) recoverCopies(ctx context.Context, env agent.EngineEnv) {
	cs := e.copyState(env)
	known := map[string]bool{}
	for _, r := range cs.all() {
		known[filepath.Base(r.Dir)] = true
		s := scratchAt(env, r.Dir)
		switch {
		case r.Status != protocol.RewindCopyReady:
			if _, err := s.remove(); err == nil {
				_ = cs.remove(r.ID)
				env.Log.Warn("removed a MongoDB copy whose restore was interrupted", "copy_id", r.ID)
			}
		case time.Now().After(r.Expires):
			// expireCopies removes it.
		case s.pid() == 0:
			go func() {
				c, err := s.start(ctx, env)
				if err != nil {
					env.Log.Error("starting a MongoDB copy again failed; it stays until it expires or is deleted", "copy_id", r.ID, "err", err)
					return
				}
				disconnect(c)
				env.Log.Info("started a MongoDB copy again after an agent restart", "copy_id", r.ID)
			}()
		}
	}
	for _, root := range []string{copyRoot(env), drillRoot(env)} {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			if !ent.IsDir() || known[ent.Name()] && root == copyRoot(env) {
				continue
			}
			dir := filepath.Join(root, ent.Name())
			if _, err := os.Lstat(filepath.Join(dir, scratchMarker)); err != nil {
				continue
			}
			if _, err := scratchAt(env, dir).remove(); err != nil {
				env.Log.Error("removing a leftover MongoDB scratch server failed", "dir", dir, "err", err)
			} else {
				env.Log.Warn("removed a leftover MongoDB scratch server", "dir", dir)
			}
		}
	}
}

// expireCopies deletes copies past their expiry.
func (e *Engine) expireCopies(env agent.EngineEnv, now time.Time) {
	cs := e.copyState(env)
	for _, r := range cs.all() {
		if r.Status != protocol.RewindCopyReady || now.Before(r.Expires) {
			continue
		}
		freed, err := scratchAt(env, r.Dir).remove()
		if err != nil {
			env.Log.Error("removing an expired MongoDB copy failed", "copy_id", r.ID, "err", err)
			continue
		}
		_ = cs.remove(r.ID)
		env.Log.Info("removed an expired MongoDB copy", "copy_id", r.ID, "freed", humanBytes(freed))
	}
}

// RewindStates reports the copies (heartbeat).
func (e *Engine) RewindStates(env agent.EngineEnv) []protocol.RewindState {
	var out []protocol.RewindState
	for _, r := range e.copyState(env).all() {
		exp := r.Expires
		out = append(out, protocol.RewindState{ID: r.ID, DatabaseID: r.DatabaseID, Kind: protocol.RewindKindCopy, Status: r.Status,
			SizeBytes: r.SizeBytes, Expires: &exp, CreatedAt: r.CreatedAt, RecoveredTo: r.RecoveredTo, Path: r.Dir})
	}
	return out
}

// SetRewindExpiries applies Extend from the control plane.
func (e *Engine) SetRewindExpiries(env agent.EngineEnv, exps []protocol.RewindExpiry) {
	cs := e.copyState(env)
	now := time.Now()
	for _, x := range exps {
		if r, ok := cs.get(x.ID); ok && !x.Expires.Equal(r.Expires) {
			r.Expires = clampExpiry(x.Expires, now)
			_ = cs.put(r)
		}
	}
}
