package mongodb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Live sync for moving a MongoDB database in: a change stream on the
// source database (MongoDB Atlas and any replica set have them), opened at
// the source's cluster time before the copy starts, so every change made
// during and after the copy is applied here in order: inserted, updated and
// replaced documents are written whole (the stream looks up the current
// document), deleted ones deleted, dropped collections dropped. The agent
// runs one sync per migration, resumes it after a restart from the saved
// resume token, and stops it at the switchover, once it has applied
// everything up to the moment the source's writes stopped.

// liveState is what the sync saves (mongodb-live.json).
type liveState struct {
	StartAt bson.Timestamp `json:"start_at"`         // the source's cluster time before the copy
	Token   string         `json:"token,omitempty"`  // the last resume token (extended JSON)
	HWM     bson.Timestamp `json:"hwm"`              // up to here everything was applied
	Applied int64          `json:"applied"`          // changes applied
	Error   string         `json:"error,omitempty"`  // the sync's last error
	Loaded  bool           `json:"loaded,omitempty"` // the first copy is in
}

func liveLoad(dir string) liveState {
	var st liveState
	if data, err := os.ReadFile(filepath.Join(dir, "mongodb-live.json")); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func liveSave(dir string, st liveState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return saveFile(filepath.Join(dir, "mongodb-live.json"), data)
}

// liveSync is one running sync.
type liveSync struct {
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	state  liveState
}

var (
	livesMu sync.Mutex
	lives   = map[string]*liveSync{} // by migration folder
)

func (l *liveSync) snapshot() liveState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

// tokenTime reads the cluster time a resume token holds (its _data starts
// with the timestamp, as MongoDB encodes it: 0x82, seconds, increment).
func tokenTime(tok bson.Raw) (bson.Timestamp, bool) {
	v, err := tok.LookupErr("_data")
	if err != nil {
		return bson.Timestamp{}, false
	}
	s, ok := v.StringValueOK()
	if !ok || len(s) < 18 || s[:2] != "82" {
		return bson.Timestamp{}, false
	}
	b, err := hex.DecodeString(s[2:18])
	if err != nil {
		return bson.Timestamp{}, false
	}
	return bson.Timestamp{T: uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]),
		I: uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])}, true
}

// clusterTime is the source's current cluster time.
func clusterTime(ctx context.Context, c *mongo.Client) (bson.Timestamp, error) {
	var out struct {
		OperationTime bson.Timestamp `bson:"operationTime"`
	}
	if err := c.Database("admin").RunCommand(ctx, bson.D{{Key: "ping", Value: 1}}).Decode(&out); err != nil {
		return bson.Timestamp{}, err
	}
	if out.OperationTime.T == 0 {
		return bson.Timestamp{}, errors.New("the source isn't a replica set (it reports no cluster time), so live sync isn't possible: use the one-time copy")
	}
	return out.OperationTime, nil
}

// startLive starts (or finds) the sync of a migration.
func startLive(env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, src migSource, targetDB string) *liveSync {
	livesMu.Lock()
	defer livesMu.Unlock()
	if l, ok := lives[m.Dir]; ok {
		select {
		case <-l.done:
		default:
			return l
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &liveSync{cancel: cancel, done: make(chan struct{}), state: liveLoad(m.Dir)}
	lives[m.Dir] = l
	go func() {
		defer close(l.done)
		for ctx.Err() == nil {
			err := l.run(ctx, env, db, m, src, targetDB)
			if ctx.Err() != nil {
				return
			}
			l.mu.Lock()
			if err != nil {
				l.state.Error = err.Error()
			}
			_ = liveSave(m.Dir, l.state)
			l.mu.Unlock()
			select {
			case <-ctx.Done():
			case <-time.After(10 * time.Second): // retry
			}
		}
	}()
	return l
}

// stopLive stops a migration's sync and waits for it.
func stopLive(dir string) {
	livesMu.Lock()
	l := lives[dir]
	delete(lives, dir)
	livesMu.Unlock()
	if l != nil {
		l.cancel()
		<-l.done
	}
}

// run follows the change stream until ctx ends or it fails.
func (l *liveSync) run(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, src migSource, targetDB string) error {
	sc, err := connect(ctx, src.URI)
	if err != nil {
		return fmt.Errorf("can't reach the source: %w", err)
	}
	defer disconnect(sc)
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	defer disconnect(tc)
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup).SetMaxAwaitTime(2 * time.Second)
	l.mu.Lock()
	st := l.state
	l.mu.Unlock()
	if st.Token != "" {
		var tok bson.Raw
		if err := bson.UnmarshalExtJSON([]byte(st.Token), true, &tok); err == nil {
			opts.SetResumeAfter(tok)
		}
	} else {
		opts.SetStartAtOperationTime(&st.StartAt)
	}
	cs, err := sc.Database(src.DB).Watch(ctx, mongo.Pipeline{}, opts)
	if err != nil {
		return fmt.Errorf("following the source's changes: %w", err)
	}
	defer cs.Close(context.WithoutCancel(ctx))
	target := tc.Database(targetDB)
	lastSave := time.Now()
	for ctx.Err() == nil {
		if cs.TryNext(ctx) {
			if err := applyChange(ctx, target, cs.Current); err != nil {
				return err
			}
			l.mu.Lock()
			l.state.Applied++
			l.mu.Unlock()
		} else if err := cs.Err(); err != nil {
			return fmt.Errorf("following the source's changes: %w", err)
		}
		tok := cs.ResumeToken()
		l.mu.Lock()
		if tok != nil {
			if t, ok := tokenTime(tok); ok {
				l.state.HWM = t
			}
			if js, err := bson.MarshalExtJSON(tok, true, false); err == nil {
				l.state.Token = string(js)
			}
		}
		l.state.Error = ""
		if time.Since(lastSave) > 5*time.Second {
			_ = liveSave(m.Dir, l.state)
			lastSave = time.Now()
		}
		l.mu.Unlock()
	}
	l.mu.Lock()
	_ = liveSave(m.Dir, l.state)
	l.mu.Unlock()
	return nil
}

// applyChange writes one change event into the database here.
func applyChange(ctx context.Context, target *mongo.Database, ev bson.Raw) error {
	var e struct {
		Op string `bson:"operationType"`
		NS struct {
			Coll string `bson:"coll"`
		} `bson:"ns"`
		To struct {
			Coll string `bson:"coll"`
		} `bson:"to"`
		Key     bson.Raw `bson:"documentKey"`
		FullDoc bson.Raw `bson:"fullDocument"`
	}
	if err := bson.Unmarshal(ev, &e); err != nil {
		return err
	}
	coll := target.Collection(e.NS.Coll)
	id := e.Key.Lookup("_id")
	switch e.Op {
	case "insert", "update", "replace":
		if len(e.FullDoc) == 0 {
			return nil // deleted since: its delete follows
		}
		_, err := coll.ReplaceOne(ctx, bson.D{{Key: "_id", Value: id}}, e.FullDoc, options.Replace().SetUpsert(true))
		return err
	case "delete":
		_, err := coll.DeleteOne(ctx, bson.D{{Key: "_id", Value: id}})
		return err
	case "drop":
		return coll.Drop(ctx)
	case "rename":
		return target.Client().Database("admin").RunCommand(ctx, bson.D{
			{Key: "renameCollection", Value: target.Name() + "." + e.NS.Coll},
			{Key: "to", Value: target.Name() + "." + e.To.Coll}, {Key: "dropTarget", Value: true}}).Err()
	case "dropDatabase", "invalidate":
		return errors.New("the source database was dropped: the sync stopped")
	}
	return nil // index and other events: nothing to apply
}

// migrateLive copies the database and starts following the source.
func (e *Engine) migrateLive(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateCopyResult, error) {
	start := time.Now()
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	st := loadMigState(m.Dir)
	st.TargetDB = cmpOr(p.TargetDB, cmpOr(st.TargetDB, src.DB))
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(tc)
	if names, _ := tc.Database(st.TargetDB).ListCollectionNames(ctx, bson.D{}); len(names) > 0 {
		return nil, fmt.Errorf("the database %s here already has collections: pick another name", st.TargetDB)
	}
	sc, err := connect(ctx, src.URI)
	if err != nil {
		return nil, err
	}
	t0, err := clusterTime(ctx, sc)
	disconnect(sc)
	if err != nil {
		return nil, err
	}
	st.CreatedDB = true
	if err := saveMigState(m.Dir, st); err != nil {
		return nil, err
	}
	if err := liveSave(m.Dir, liveState{StartAt: t0, HWM: t0}); err != nil {
		return nil, err
	}
	m.SetPhase(protocol.MigratePhaseCopying)
	tl.Printf("following the source's changes from its cluster time %d:%d, then copying %s", t0.T, t0.I, src.DB)
	if err := copyDatabase(ctx, env, db, m, src, st, tl); err != nil {
		return nil, err
	}
	ls := liveLoad(m.Dir)
	ls.Loaded = true
	_ = liveSave(m.Dir, ls)
	startLive(env, db, m, src, st.TargetDB)
	names, _ := tc.Database(st.TargetDB).ListCollectionNames(ctx, bson.D{})
	res := &protocol.MigrateCopyResult{Method: protocol.MigrateMethodLive, TablesTotal: len(names), CreatedDatabase: true,
		DurationMs: time.Since(start).Milliseconds(),
		Summary:    fmt.Sprintf("Copied %s and follows the source's changes (a change stream). Switch over when you're ready.", src.DB)}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// MigrateStatus reports a live sync and keeps it running (after an agent
// restart it resumes here).
func (e *Engine) MigrateStatus(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv) (protocol.MigrationStatus, bool) {
	ls := liveLoad(m.Dir)
	if !ls.Loaded {
		return protocol.MigrationStatus{}, false
	}
	src, err := savedSource(m.Dir)
	if err != nil {
		return protocol.MigrationStatus{Phase: m.Phase, Error: err.Error()}, true
	}
	st := loadMigState(m.Dir)
	l := startLive(env, db, m, src, st.TargetDB)
	cur := l.snapshot()
	out := protocol.MigrationStatus{Phase: m.Phase, At: time.Now().UTC(), Error: cur.Error}
	if sc, err := connect(ctx, src.URI); err == nil {
		if now, err := clusterTime(ctx, sc); err == nil && cur.HWM.T > 0 {
			lag := int64(0)
			if now.T > cur.HWM.T {
				lag = int64(now.T - cur.HWM.T) // seconds behind, shown as "bytes" by older dashboards: small anyway
			}
			if lag <= 5 {
				lag = 0
			}
			out.LagBytes = &lag
		}
		disconnect(sc)
	}
	if m.Phase == protocol.MigratePhaseCopying && out.LagBytes != nil && *out.LagBytes == 0 && cur.Error == "" {
		m.SetPhase(protocol.MigratePhaseSyncing)
		out.Phase = protocol.MigratePhaseSyncing
	}
	return out, true
}

// migrateSwitchover waits until every change up to now (the source's writes
// stopped) is applied, stops the sync and makes the app login.
func (e *Engine) migrateSwitchover(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, m agent.MigrateEnv, p protocol.MigrateParams,
	tl agent.TaskLogger) (*protocol.MigrateSwitchoverResult, error) {
	if p.ReadOnly {
		return nil, errNoReadOnly
	}
	if !liveLoad(m.Dir).Loaded {
		return nil, errors.New("this migration has no live sync running")
	}
	src, err := savedSource(m.Dir)
	if err != nil {
		return nil, err
	}
	st := loadMigState(m.Dir)
	m.SetPhase(protocol.MigratePhaseSwitching)
	back := func(err error) (*protocol.MigrateSwitchoverResult, error) {
		m.SetPhase(protocol.MigratePhaseSyncing)
		return nil, err
	}
	sc, err := connect(ctx, src.URI)
	if err != nil {
		return back(err)
	}
	want, err := clusterTime(ctx, sc)
	disconnect(sc)
	if err != nil {
		return back(err)
	}
	tl.Printf("waiting until every change up to the source's cluster time %d:%d is here", want.T, want.I)
	l := startLive(env, db, m, src, st.TargetDB)
	if err := waitFor(ctx, 3*time.Minute, func() (bool, error) {
		cur := l.snapshot()
		if cur.Error != "" {
			return false, errors.New(cur.Error)
		}
		return optimeAtLeast(cur.HWM, want), nil
	}); err != nil {
		return back(fmt.Errorf("this server hasn't received every change (is the source still taking writes?); the sync goes on: try again (%v)", err))
	}
	stopLive(m.Dir)
	tl.Printf("every change is here; the sync is ended (%s applied)", strconv.FormatInt(l.snapshot().Applied, 10))
	tc, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer disconnect(tc)
	sw, err := e.finishMove(ctx, env, db, tc, m, p, src, &st)
	if err != nil {
		return nil, err
	}
	tl.Printf("%s", sw.Summary)
	return sw, nil
}
