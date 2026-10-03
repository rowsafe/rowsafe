package mongodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind the whole database in place (and Undo), with collection renames.
//
// The agent can't touch MongoDB's files (it runs as its own user, often in
// another container), so it works through MongoDB itself:
//
//  1. restore the moment into a private scratch server, exactly like a
//     Rewind copy (production keeps running);
//  2. load it into production under temporary names
//     (db.rowsafe_rewind_<h>.<collection>, mongodump | mongorestore);
//  3. swap: every collection of production is renamed to
//     db.rowsafe_before_<h>.<collection> (kept for Undo), then every
//     restored one takes its real name. A rename within a database is
//     instant, whatever the size.
//
// Undo swaps the other way (the rewound collections become
// rowsafe_after_<h>.*). Any failure during a swap renames everything back;
// an agent restarted in the middle does the same. The admin, config and
// local databases, views and users are left as they are. The renames and
// the loaded documents go through the oplog like any change, so restores to
// any second keep working across a rewind.

const (
	mipRestoring = "restoring" // into the scratch server: production untouched
	mipLoading   = "loading"   // the restored data goes into production under temporary names
	mipSwapping  = "swapping"  // collections are being renamed
)

// rewindTag is the short tag of a rewind in collection names.
func rewindTag(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:4])
}

func tempPrefix(tag string) string   { return "rowsafe_rewind_" + tag + "." }
func beforePrefix(tag string) string { return "rowsafe_before_" + tag + "." }
func afterPrefix(tag string) string  { return "rowsafe_after_" + tag + "." }
func failedPrefix(tag string) string { return "rowsafe_failed_" + tag + "." }

// rowsafeColl: collections Rowsafe set aside (never swapped).
func rowsafeColl(name string) bool { return strings.HasPrefix(name, "rowsafe_") }

// collInfo is one entry of listCollections.
type collInfo struct {
	Name string `bson:"name"`
	Type string `bson:"type"` // collection, view, timeseries
}

func listColls(ctx context.Context, c *mongo.Client, db string) ([]collInfo, error) {
	cur, err := c.Database(db).ListCollections(ctx, bson.D{}, nil)
	if err != nil {
		return nil, err
	}
	var out []collInfo
	if err := cur.All(ctx, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// userDBs lists the databases a rewind covers.
func userDBs(ctx context.Context, c *mongo.Client) ([]string, error) {
	names, err := c.ListDatabaseNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(names, isSystemDB), nil
}

// canRename checks that Rowsafe's user may rename and drop collections
// (its role from agent 0.7 on; an older install refreshes it with the
// installer).
func canRename(ctx context.Context, c *mongo.Client) error {
	var st struct {
		AuthInfo struct {
			Users []bson.Raw `bson:"authenticatedUsers"`
			Privs []struct {
				Resource bson.Raw `bson:"resource"`
				Actions  []string `bson:"actions"`
			} `bson:"authenticatedUserPrivileges"`
		} `bson:"authInfo"`
	}
	if err := runAdmin(ctx, c, bson.D{{Key: "connectionStatus", Value: 1}, {Key: "showPrivileges", Value: true}}, &st); err != nil {
		return err
	}
	if len(st.AuthInfo.Users) == 0 {
		return nil // no access control
	}
	have := map[string]bool{}
	for _, p := range st.AuthInfo.Privs {
		db, _ := p.Resource.Lookup("db").StringValueOK()
		coll, _ := p.Resource.Lookup("collection").StringValueOK()
		if db != "" || coll != "" {
			continue
		}
		for _, a := range p.Actions {
			have[a] = true
		}
	}
	for _, a := range []string{"renameCollectionSameDB", "dropCollection", "insert", "createCollection", "createIndex"} {
		if !have[a] {
			return errors.New("Rowsafe's MongoDB user can't rename collections yet, which a rewind in place needs: " +
				"run the Rowsafe installer on the server again (it updates the user), or restore a copy and bring back documents instead")
		}
	}
	return nil
}

// rename renames db.from to db.to; when to exists, it gets a suffix.
func rename(ctx context.Context, c *mongo.Client, db, from, to string) error {
	for i := 0; i < 20; i++ {
		target := to
		if i > 0 {
			target = fmt.Sprintf("%s~%d", to, i)
		}
		err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "renameCollection", Value: db + "." + from}, {Key: "to", Value: db + "." + target}}).Err()
		if err == nil || commandCode(err) == 26 { // NamespaceNotFound: gone already
			return nil
		}
		if commandCode(err) != 48 { // NamespaceExists: try the next name
			return fmt.Errorf("renaming %s.%s to %s: %w", db, from, target, err)
		}
	}
	return fmt.Errorf("renaming %s.%s: too many collections named %s", db, from, to)
}

// moveAside renames every live collection (not Rowsafe's, not a view) of
// every user database to prefix+name.
func moveAside(ctx context.Context, c *mongo.Client, prefix string) error {
	dbs, err := userDBs(ctx, c)
	if err != nil {
		return err
	}
	for _, db := range dbs {
		colls, err := listColls(ctx, c, db)
		if err != nil {
			return err
		}
		for _, ci := range colls {
			if ci.Type != "collection" || rowsafeColl(ci.Name) || strings.HasPrefix(ci.Name, "system.") {
				continue
			}
			if err := rename(ctx, c, db, ci.Name, prefix+ci.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

// bringIn renames every prefix+name collection back to name. A live
// collection in the way (an application wrote meanwhile) is set aside under
// aside+name first.
func bringIn(ctx context.Context, c *mongo.Client, prefix, aside string) error {
	dbs, err := userDBs(ctx, c)
	if err != nil {
		return err
	}
	for _, db := range dbs {
		colls, err := listColls(ctx, c, db)
		if err != nil {
			return err
		}
		live := map[string]bool{}
		for _, ci := range colls {
			live[ci.Name] = true
		}
		for _, ci := range colls {
			name, ok := strings.CutPrefix(ci.Name, prefix)
			if !ok || ci.Type != "collection" || name == "" {
				continue
			}
			if live[name] {
				if err := rename(ctx, c, db, name, aside+name); err != nil {
					return err
				}
			}
			if err := rename(ctx, c, db, ci.Name, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// dropPrefixed drops every collection (or view) named prefix+... in every
// user database, and reports the bytes freed.
func dropPrefixed(ctx context.Context, c *mongo.Client, prefixes ...string) (int64, error) {
	dbs, err := userDBs(ctx, c)
	if err != nil {
		return 0, err
	}
	var freed int64
	for _, db := range dbs {
		colls, err := listColls(ctx, c, db)
		if err != nil {
			return freed, err
		}
		for _, ci := range colls {
			if !slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(ci.Name, p) }) {
				continue
			}
			freed += collDiskSize(ctx, c, db, ci.Name)
			if err := c.Database(db).Collection(ci.Name).Drop(ctx); err != nil {
				return freed, fmt.Errorf("deleting %s.%s: %w", db, ci.Name, err)
			}
		}
	}
	return freed, nil
}

// prefixedSize sums the storage of the collections named prefix+...
func prefixedSize(ctx context.Context, c *mongo.Client, prefix string) (n int64, count int, dbsWith int) {
	dbs, _ := userDBs(ctx, c)
	for _, db := range dbs {
		colls, _ := listColls(ctx, c, db)
		found := false
		for _, ci := range colls {
			if strings.HasPrefix(ci.Name, prefix) {
				n += collDiskSize(ctx, c, db, ci.Name)
				count++
				found = true
			}
		}
		if found {
			dbsWith++
		}
	}
	return n, count, dbsWith
}

// collDiskSize is a collection's size on disk with its indexes (0 when unknown).
func collDiskSize(ctx context.Context, c *mongo.Client, db, coll string) int64 {
	var st struct {
		Size    int64 `bson:"storageSize"`
		Indexes int64 `bson:"totalIndexSize"`
	}
	if err := c.Database(db).RunCommand(ctx, bson.D{{Key: "collStats", Value: coll}}).Decode(&st); err != nil {
		return 0
	}
	return st.Size + st.Indexes
}

// preflightInPlace checks production before anything changes.
func (e *Engine) preflightInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (serverInfo, error) {
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return serverInfo{}, err
	}
	defer disconnect(prod)
	in, err := inspect(ctx, prod)
	if err != nil {
		return in, err
	}
	sizes, err := inspectDatabases(ctx, prod)
	if err != nil {
		return in, err
	}
	in.Databases, in.TotalBytes = sizes.Databases, sizes.TotalBytes
	if in.SetName != "" && !in.Primary {
		return in, errors.New("this MongoDB server is a secondary of its replica set: rewind the primary instead")
	}
	if err := canRename(ctx, prod); err != nil {
		return in, err
	}
	dbs, err := userDBs(ctx, prod)
	if err != nil {
		return in, err
	}
	for _, d := range dbs {
		colls, err := listColls(ctx, prod, d)
		if err != nil {
			return in, err
		}
		for _, ci := range colls {
			if ci.Type == "timeseries" {
				return in, fmt.Errorf("%s.%s is a time-series collection, which MongoDB can't rename: rewinding in place isn't available for it yet. "+
					"Restore a copy and bring back documents instead", d, ci.Name)
			}
		}
	}
	return in, nil
}

// diskFree is the free space on MongoDB's own disk (dbStats).
func (e *Engine) diskFree(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (int64, bool) {
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return 0, false
	}
	defer disconnect(prod)
	var st struct {
		Used  float64 `bson:"fsUsedSize"`
		Total float64 `bson:"fsTotalSize"`
	}
	if err := prod.Database("admin").RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&st); err != nil || st.Total <= 0 {
		return 0, false
	}
	return int64(st.Total - st.Used), true
}

// rewindInPlace rewinds every user database of production to p.Target.
func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	target := restoreTarget{Mark: p.Target.Mark}
	if p.Target.Time != nil {
		target.Time = p.Target.Time.UTC()
	}
	if (target.Mark == "") == target.Time.IsZero() {
		return nil, errors.New("pick a moment or a Mark (exactly one)")
	}
	kept := env.Kept()
	for _, r := range kept.ForDatabase(db.ID) {
		if r.Status == protocol.RewindInProgress {
			return nil, agent.ErrRewindBusy
		}
		if r.ID == p.RewindID {
			return nil, fmt.Errorf("the rewind %s already ran", p.RewindID)
		}
	}
	in, err := e.preflightInPlace(ctx, env, db)
	if err != nil {
		return nil, err
	}
	if free, ok := e.diskFree(ctx, env, db); ok && free < in.TotalBytes*12/10+256<<20 {
		return nil, fmt.Errorf("MongoDB's disk has %s free; rewinding in place keeps the current data until the rewound data is in, about %s more",
			humanBytes(free), humanBytes(in.TotalBytes))
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	e.copyMu.Lock()
	defer e.copyMu.Unlock()
	root := copyRoot(env)
	if err := ensureSpace(filepath.Dir(root), int64(float64(in.TotalBytes)*drillSpaceFactor)+256<<20); err != nil {
		return nil, err
	}
	tag := rewindTag(p.RewindID)
	rec := agent.KeptRecord{ID: p.RewindID, DatabaseID: db.ID, Status: protocol.RewindInProgress, CreatedAt: time.Now().UTC(),
		Target: p.Target, KeepDays: p.KeepDays, Phase: mipRestoring, Database: db, Extra: map[string]string{"tag": tag}}
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	sid := "inplace-" + p.RewindID
	s, err := newScratch(env, root, sid)
	if err != nil {
		_ = kept.Remove(rec.ID)
		return nil, err
	}
	defer func() { _, _ = s.remove() }()
	abandon := func(err error) (*protocol.RewindInPlaceResult, error) {
		if rec.Phase == mipLoading {
			if prod, cerr := connectDB(context.WithoutCancel(ctx), env, db); cerr == nil {
				_, _ = dropPrefixed(context.WithoutCancel(ctx), prod, tempPrefix(tag))
				disconnect(prod)
			}
		}
		_ = kept.Remove(rec.ID)
		return nil, err
	}

	// 1. Restore the moment privately.
	if !target.Time.IsZero() && time.Since(target.Time) < 3*time.Minute {
		if sh, err := e.shipperFor(env, db); err == nil {
			_ = sh.flush(ctx, ts{T: uint32(target.Time.Unix()) + 1}, 2*time.Minute)
		}
	}
	tl.Printf("restoring %s as of %s into an isolated server first (production keeps running meanwhile)", db.Name, target.describe())
	c, err := s.start(ctx, env)
	if err != nil {
		return abandon(err)
	}
	out, err := restoreInto(ctx, env, r, target, s, tl)
	disconnect(c)
	if err != nil {
		return abandon(err)
	}
	recovered := out.RecoveredTo
	if recovered == nil {
		t := out.Backup.StoppedAt
		recovered = &t
	}

	// 2. Load it into production under temporary names.
	rec.Phase, rec.RecoveredTo = mipLoading, recovered
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return abandon(err)
	}
	defer disconnect(prod)
	if _, err := dropPrefixed(ctx, prod, tempPrefix(tag)); err != nil { // a previous attempt's leftovers
		return abandon(err)
	}
	tl.Printf("loading the restored data into production next to the current data (as %s*)", tempPrefix(tag))
	if err := e.loadInto(ctx, env, db, s, tag, tl); err != nil {
		return abandon(err)
	}

	// 3. Swap.
	tl.Printf("swapping: the current collections become %s*, the restored ones take their names", beforePrefix(tag))
	rec.Phase = mipSwapping
	if err := kept.Put(rec); err != nil {
		return abandon(err)
	}
	sctx := context.WithoutCancel(ctx)
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RecoveredTo: recovered}
	err = moveAside(sctx, prod, beforePrefix(tag))
	if err == nil {
		err = bringIn(sctx, prod, tempPrefix(tag), beforePrefix(tag))
	}
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		if rerr := rollbackRewind(sctx, prod, tag); rerr != nil {
			return res, fmt.Errorf("the rewind failed (%v), and putting the collections back failed too: %v. The data from before is in the collections named %s*", err, rerr, beforePrefix(tag))
		}
		res.RolledBack = true
		_ = kept.Remove(rec.ID)
		return res, fmt.Errorf("the rewind failed, and every collection was put back as it was (nothing changed): %w", err)
	}
	_, _ = dropPrefixed(sctx, prod, tempPrefix(tag)) // views and anything else left under the temporary names
	until := agent.KeepUntil(p.KeepDays, time.Now())
	size, colls, dbs := prefixedSize(sctx, prod, beforePrefix(tag))
	rec.Status, rec.Phase, rec.Expires, rec.SizeBytes = protocol.RewindKeptBefore, "", until, size
	rec.Path = fmt.Sprintf("%s* (%d collections in %d databases)", beforePrefix(tag), colls, dbs)
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.OldDataDir, res.KeptUntil = rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("Rewound %s to %s. The collections as they were before are kept as %s* until %s so you can undo.",
		db.Name, recovered.UTC().Format("15:04:05 UTC on 2006-01-02"), beforePrefix(tag), until.UTC().Format("2006-01-02 15:04 UTC"))
	if out.Failed > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%d document(s) of the backup couldn't be restored (see the task log)", out.Failed))
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// loadInto streams the scratch server's user databases into production
// under temporary names (mongodump | mongorestore).
func (e *Engine) loadInto(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, s scratch, tag string, tl agent.TaskLogger) error {
	dump, err := tool("mongodump")
	if err != nil {
		return err
	}
	restore, err := tool("mongorestore")
	if err != nil {
		return err
	}
	l, err := loadLogin(env, db.Port)
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.Dir, "load")
	cfg, err := toolConfig(tmp, l.uri(db.Port))
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	pr, pw := io.Pipe()
	dcmd := command(ctx, env, true, dump, "--uri="+s.uri(), "--archive", "--quiet")
	dcmd.Stdout = pw
	var dErr tailBuffer
	dErr.max = 16 << 10
	dcmd.Stderr = &dErr
	args := []string{"--config=" + cfg, "--archive", "--numInsertionWorkersPerCollection=2",
		"--nsExclude=admin.*", "--nsExclude=config.*", "--nsExclude=local.*", "--nsExclude=*.system.*",
		"--nsFrom=$db$.$coll$", "--nsTo=$db$." + tempPrefix(tag) + "$coll$"}
	rcmd := command(ctx, env, true, restore, args...)
	rcmd.Stdin = pr
	var rErr tailBuffer
	rErr.max = 64 << 10
	rcmd.Stderr = &rErr
	if err := dcmd.Start(); err != nil {
		return fmt.Errorf("starting mongodump: %w", err)
	}
	if err := rcmd.Start(); err != nil {
		_ = dcmd.Process.Kill()
		_ = dcmd.Wait()
		return fmt.Errorf("starting mongorestore: %w", err)
	}
	dWait := dcmd.Wait()
	pw.CloseWithError(dWait)
	rWait := rcmd.Wait()
	tl.Output("mongorestore", summaryLines(rErr.Bytes()))
	switch {
	case dWait != nil:
		return fmt.Errorf("reading the restored data failed: %v: %s", dWait, lastLine(dErr.Bytes()))
	case rWait != nil:
		return fmt.Errorf("loading the restored data into production failed: %v: %s", rWait, lastLine(rErr.Bytes()))
	}
	if n := failedDocs(rErr.Bytes()); n > 0 {
		return fmt.Errorf("%d document(s) couldn't be loaded into production (see the log); nothing was swapped", n)
	}
	return nil
}

// rollbackRewind puts production's collections back after a failed swap.
func rollbackRewind(ctx context.Context, prod *mongo.Client, tag string) error {
	if err := moveAside(ctx, prod, failedPrefix(tag)); err != nil {
		return err
	}
	if err := bringIn(ctx, prod, beforePrefix(tag), failedPrefix(tag)); err != nil {
		return err
	}
	_, err := dropPrefixed(ctx, prod, failedPrefix(tag), tempPrefix(tag))
	return err
}

// rewindUndo puts the collections from before the rewind back.
func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return nil, errors.New("there is nothing to undo: the data from before this rewind is no longer kept")
	}
	if rec.Status != protocol.RewindKeptBefore {
		return nil, errors.New("this rewind was undone already")
	}
	if _, err := e.preflightInPlace(ctx, env, db); err != nil {
		return nil, err
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(prod)
	tag := rec.Extra["tag"]
	if _, n, _ := prefixedSize(ctx, prod, beforePrefix(tag)); n == 0 {
		return nil, fmt.Errorf("the collections kept from before the rewind (%s*) are gone", beforePrefix(tag))
	}
	saved := rec
	saved.Extra = maps.Clone(rec.Extra)
	rec.Extra = maps.Clone(rec.Extra)
	rec.Status, rec.Phase, rec.Extra["undoing"] = protocol.RewindInProgress, mipSwapping, "1"
	if err := kept.Put(rec); err != nil {
		return nil, err
	}
	sctx := context.WithoutCancel(ctx)
	res := &protocol.RewindUndoResult{RewindID: rec.ID}
	tl.Printf("swapping back: the current collections become %s*, the ones from before the rewind take their names", afterPrefix(tag))
	err = moveAside(sctx, prod, afterPrefix(tag))
	if err == nil {
		err = bringIn(sctx, prod, beforePrefix(tag), afterPrefix(tag))
	}
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		if rerr := rollbackUndo(sctx, prod, tag); rerr != nil {
			return res, fmt.Errorf("the undo failed (%v), and putting the collections back failed too: %v", err, rerr)
		}
		res.RolledBack = true
		_ = kept.Put(saved)
		return res, fmt.Errorf("the undo failed, and every collection was put back as it was (nothing changed): %w", err)
	}
	until := agent.KeepUntil(rec.KeepDays, time.Now())
	size, colls, dbs := prefixedSize(sctx, prod, afterPrefix(tag))
	delete(rec.Extra, "undoing")
	rec.Status, rec.Phase, rec.Undo, rec.Expires, rec.SizeBytes = protocol.RewindKeptAfterUndo, "", true, until, size
	rec.Path = fmt.Sprintf("%s* (%d collections in %d databases)", afterPrefix(tag), colls, dbs)
	if err := kept.Put(rec); err != nil {
		tl.Printf("warning: saving the rewind's state: %v", err)
	}
	res.RewoundDataDir, res.KeptUntil = rec.Path, &until
	res.DurationMs = time.Since(start).Milliseconds()
	res.Summary = fmt.Sprintf("%s is back as it was before the rewind. The rewound collections (with anything written since) are kept as %s* until %s.",
		db.Name, afterPrefix(tag), until.UTC().Format("2006-01-02 15:04 UTC"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

// rollbackUndo puts the rewound collections back after a failed undo.
func rollbackUndo(ctx context.Context, prod *mongo.Client, tag string) error {
	if err := moveAside(ctx, prod, beforePrefix(tag)); err != nil {
		return err
	}
	return bringIn(ctx, prod, afterPrefix(tag), beforePrefix(tag))
}

// rewindCleanup drops what a rewind kept.
func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	kept := env.Kept()
	rec, ok := kept.Get(p.RewindID)
	if !ok || rec.DatabaseID != db.ID {
		return &protocol.RewindCleanupResult{RewindID: p.RewindID, Summary: "Nothing was kept for this rewind any more."}, nil
	}
	if rec.Status == protocol.RewindInProgress {
		return nil, agent.ErrRewindBusy
	}
	prod, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(prod)
	tag := rec.Extra["tag"]
	freed, err := dropPrefixed(ctx, prod, beforePrefix(tag), afterPrefix(tag))
	if err != nil {
		return nil, err
	}
	if err := kept.Remove(rec.ID); err != nil {
		return nil, err
	}
	res := &protocol.RewindCleanupResult{RewindID: rec.ID, Removed: true, FreedBytes: freed,
		Summary: fmt.Sprintf("Deleted the collections kept aside by the rewind (%s freed).", humanBytes(freed))}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// recoverInPlace finishes what an agent stopped in the middle of: a load
// is dropped, a swap is rolled back.
func (e *Engine) recoverInPlace(ctx context.Context, env agent.EngineEnv) {
	kept := env.Kept()
	for _, rec := range kept.All() {
		if rec.Status != protocol.RewindInProgress {
			continue
		}
		tag := rec.Extra["tag"]
		prod, err := connectDB(ctx, env, rec.Database)
		if err != nil {
			env.Log.Error("can't reach MongoDB to finish an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
			continue
		}
		switch {
		case rec.Extra["undoing"] == "1":
			err = rollbackUndo(ctx, prod, tag)
			if err == nil {
				rec.Status, rec.Phase = protocol.RewindKeptBefore, ""
				delete(rec.Extra, "undoing")
				err = kept.Put(rec)
			}
		case rec.Phase == mipSwapping:
			err = rollbackRewind(ctx, prod, tag)
			if err == nil {
				err = kept.Remove(rec.ID)
			}
		default:
			_, err = dropPrefixed(ctx, prod, tempPrefix(tag))
			if err == nil {
				err = kept.Remove(rec.ID)
			}
			_ = os.RemoveAll(filepath.Join(copyRoot(env), "inplace-"+rec.ID))
		}
		disconnect(prod)
		if err != nil {
			env.Log.Error("finishing an interrupted rewind in place", "rewind_id", rec.ID, "err", err)
		} else {
			env.Log.Warn("an interrupted rewind in place was rolled back", "rewind_id", rec.ID)
		}
	}
}

// expireKept drops what rewinds kept past its expiry.
func (e *Engine) expireKept(ctx context.Context, env agent.EngineEnv, now time.Time) {
	kept := env.Kept()
	for _, rec := range kept.Expired(now) {
		prod, err := connectDB(ctx, env, rec.Database)
		if err != nil {
			continue
		}
		tag := rec.Extra["tag"]
		_, err = dropPrefixed(ctx, prod, beforePrefix(tag), afterPrefix(tag))
		disconnect(prod)
		if err == nil {
			_ = kept.Remove(rec.ID)
			env.Log.Info("deleted the collections kept aside by a rewind in place (expired)", "rewind_id", rec.ID)
		}
	}
}
