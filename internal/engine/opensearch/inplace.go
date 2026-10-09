package opensearch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Rewind in place, through OpenSearch itself: a snapshot of everything as
// it is now first (kind R, kept for Undo), then every index and data stream
// is deleted and the target snapshot restored from the server's own
// repository. Nothing restarts; searches of those indices fail for the
// moments it takes. If the restore fails, the snapshot taken first is
// restored instead. Undo does the same with the kept snapshot (keeping the
// rewound state in its turn); Cleanup deletes the kept snapshots.

// keptEntry is a snapshot kept for an Undo (kept.json in the engine's state
// folder), reported with every heartbeat.
type keptEntry struct {
	RewindID    string     `json:"rewind_id"`
	DatabaseID  string     `json:"database_id"`
	Port        int        `json:"port"`
	Stanza      string     `json:"stanza"`
	Label       string     `json:"label"` // the kept snapshot
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	Expires     time.Time  `json:"expires"`
	RecoveredTo *time.Time `json:"recovered_to,omitempty"`
	SizeBytes   int64      `json:"size_bytes"`
}

var keptMu sync.Mutex

func keptPath(env agent.EngineEnv) string { return filepath.Join(env.SharedStateDir(), "kept.json") }

func loadKept(env agent.EngineEnv) []keptEntry {
	var out []keptEntry
	_ = loadJSONFile(keptPath(env), &out)
	return out
}

func saveKept(env agent.EngineEnv, k []keptEntry) error { return saveJSONFile(keptPath(env), k) }

func (e *Engine) keptStates(env agent.EngineEnv) []protocol.RewindState {
	keptMu.Lock()
	defer keptMu.Unlock()
	var out []protocol.RewindState
	for _, k := range loadKept(env) {
		exp := k.Expires
		out = append(out, protocol.RewindState{ID: k.RewindID, DatabaseID: k.DatabaseID, Kind: protocol.RewindKindKeptData, Status: k.Status,
			SizeBytes: k.SizeBytes, Expires: &exp, CreatedAt: k.CreatedAt, RecoveredTo: k.RecoveredTo, Path: "snapshot " + snapshotName(k.Label)})
	}
	return out
}

func (e *Engine) setKeptExpiries(env agent.EngineEnv, exp []protocol.RewindExpiry) {
	keptMu.Lock()
	defer keptMu.Unlock()
	k := loadKept(env)
	changed := false
	for i := range k {
		for _, x := range exp {
			if x.ID == k[i].RewindID {
				t := x.Expires
				if t.After(time.Now().Add(30 * 24 * time.Hour)) {
					t = time.Now().Add(30 * 24 * time.Hour)
				}
				k[i].Expires, changed = t, true
			}
		}
	}
	if changed {
		_ = saveKept(env, k)
	}
}

// expireKeptBackground deletes kept snapshots whose time is up.
func (e *Engine) expireKeptBackground(env agent.EngineEnv, now time.Time) {
	keptMu.Lock()
	k := loadKept(env)
	var due []keptEntry
	for _, x := range k {
		if now.After(x.Expires) {
			due = append(due, x)
		}
	}
	keptMu.Unlock()
	for _, x := range due {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		err := e.dropKept(ctx, env, protocol.DatabaseSpec{ID: x.DatabaseID, Port: x.Port, Stanza: x.Stanza}, x.RewindID)
		cancel()
		if err != nil {
			env.Log.Error("removing a snapshot kept for an Undo failed", "rewind", x.RewindID, "err", err)
		}
	}
}

// dropKept deletes the snapshots kept for rewindID and forgets them.
func (e *Engine) dropKept(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, rewindID string) error {
	keptMu.Lock()
	k := loadKept(env)
	var mine []keptEntry
	var rest []keptEntry
	for _, x := range k {
		if x.RewindID == rewindID {
			mine = append(mine, x)
		} else {
			rest = append(rest, x)
		}
	}
	keptMu.Unlock()
	if len(mine) == 0 {
		return nil
	}
	if db.Port == 0 {
		db.Port, db.Stanza = mine[0].Port, mine[0].Stanza
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	repoEnv := env
	if env.RepoFor != nil {
		repoEnv.Repo = env.RepoFor(db.ID)
	}
	r, err := openRepo(repoEnv, db)
	if err != nil {
		return err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	lock := e.repoLock(db)
	lock.Lock()
	defer lock.Unlock()
	if err := dropSnapshots(ctx, c, r, in, labelsOf(mine)); err != nil {
		return err
	}
	keptMu.Lock()
	defer keptMu.Unlock()
	k = loadKept(env)
	rest = rest[:0]
	for _, x := range k {
		if x.RewindID != rewindID {
			rest = append(rest, x)
		}
	}
	return saveKept(env, rest)
}

func labelsOf(k []keptEntry) []string {
	out := make([]string, len(k))
	for i, x := range k {
		out[i] = x.Label
	}
	return out
}

// dropSnapshots deletes Rowsafe's snapshots of labels (and their records),
// then the bucket follows with what those deletions removed. The caller
// holds the database's lock.
func dropSnapshots(ctx context.Context, c *client, r *repo, in serverInfo, labels []string) error {
	dir, err := repoDir(in)
	if err != nil {
		return err
	}
	before, err := localSet(dir)
	if err != nil {
		return err
	}
	for _, l := range labels {
		if err := deleteSnapshot(ctx, c, snapshotName(l)); err != nil {
			return err
		}
		_ = r.st.Delete(ctx, docKey(l))
	}
	after, err := localSet(dir)
	if err != nil {
		return err
	}
	_, err = r.syncRepo(ctx, dir, in.ClusterUUID, gone(before, after))
	return err
}

// upsertKept records (or updates) a kept snapshot.
func upsertKept(env agent.EngineEnv, k keptEntry) error {
	keptMu.Lock()
	defer keptMu.Unlock()
	all := loadKept(env)
	i := slices.IndexFunc(all, func(x keptEntry) bool { return x.Label == k.Label })
	if i >= 0 {
		all[i] = k
	} else {
		all = append(all, k)
	}
	return saveKept(env, all)
}

const autoCreate = "action.auto_create_index"

// pauseAutoCreate turns automatic index creation off (a transient cluster
// setting, which a restart also clears) and returns what puts the previous
// value back.
func pauseAutoCreate(ctx context.Context, c *client) (func(), error) {
	var cur struct {
		Transient map[string]any `json:"transient"`
	}
	if err := c.get(ctx, "/_cluster/settings?flat_settings=true", &cur); err != nil {
		return nil, err
	}
	prev, had := cur.Transient[autoCreate]
	set := func(ctx context.Context, v any) error {
		return c.do(ctx, http.MethodPut, "/_cluster/settings", map[string]any{"transient": map[string]any{autoCreate: v}}, nil)
	}
	if err := set(ctx, false); err != nil {
		if s := statusOf(err); s == http.StatusForbidden || s == http.StatusUnauthorized {
			return nil, errors.New("Rowsafe's OpenSearch role can't pause index creation during the rewind (it is from an older Rowsafe): run the Rowsafe installer on this server again, then rewind")
		}
		return nil, fmt.Errorf("pausing index creation: %w", err)
	}
	return func() {
		var v any
		if had {
			v = prev
		}
		_ = set(context.WithoutCancel(ctx), v)
	}, nil
}

// replaceAll deletes every index and data stream of the server and
// restores snapshot label's from the server's own repository.
func replaceAll(ctx context.Context, c *client, in serverInfo, label string, tl agent.TaskLogger) error {
	for _, ds := range in.DataStreams {
		if err := c.do(ctx, http.MethodDelete, "/_data_stream/"+pathEscape(ds), nil, nil); err != nil && statusOf(err) != http.StatusNotFound {
			return fmt.Errorf("removing the data stream %s: %w", ds, err)
		}
	}
	for _, i := range in.Indices {
		if i.DataStream != "" {
			continue
		}
		if err := c.do(ctx, http.MethodDelete, "/"+pathEscape(i.Name), nil, nil); err != nil && statusOf(err) != http.StatusNotFound {
			return fmt.Errorf("removing the index %s: %w", i.Name, err)
		}
	}
	tl.Printf("removed %d indices and %d data streams; restoring snapshot %s", len(in.Indices), len(in.DataStreams), snapshotName(label))
	req := map[string]any{"indices": "*", "include_global_state": false, "include_aliases": true, "ignore_unavailable": true}
	var res struct {
		Snapshot struct {
			Shards struct{ Total, Failed int } `json:"shards"`
		} `json:"snapshot"`
	}
	if err := c.do(ctx, http.MethodPost, "/_snapshot/"+repoName+"/"+snapshotName(label)+"/_restore?wait_for_completion=true", req, &res); err != nil {
		return err
	}
	if res.Snapshot.Shards.Failed > 0 {
		return fmt.Errorf("%d of %d shards failed to restore", res.Snapshot.Shards.Failed, res.Snapshot.Shards.Total)
	}
	var h struct {
		Status string `json:"status"`
	}
	if err := c.get(ctx, "/_cluster/health?wait_for_status=yellow&timeout=10m", &h); err != nil {
		return err
	}
	if h.Status == "red" {
		return errors.New("OpenSearch is red after the restore (some data can't be read)")
	}
	return nil
}

// swap replaces the server's data with snapshot target's, keeping
// everything as it is now in a new snapshot (kind R) first. On a failed
// restore the kept snapshot is put back.
func (e *Engine) swap(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, rewindID, target, status string, keepDays int,
	tl agent.TaskLogger) (kept keptEntry, rolledBack bool, err error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return kept, false, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return kept, false, err
	}
	if why := blocker(in); why != "" {
		return kept, false, errors.New(why)
	}
	snaps, err := listSnapshots(ctx, c)
	if err != nil {
		return kept, false, err
	}
	found := false
	for _, s := range snaps {
		if s.Snapshot == snapshotName(target) && s.State == "SUCCESS" {
			found = true
		}
	}
	if !found {
		return kept, false, fmt.Errorf("the snapshot %s isn't in OpenSearch's repository on this server any more", target)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return kept, false, err
	}
	lock := e.repoLock(db)
	lock.Lock()
	defer lock.Unlock()
	tl.Printf("keeping everything as it is now in a snapshot first (for Undo)")
	t, err := e.take(ctx, env, db, c, r, in, kindRewind, "", tl)
	if err != nil {
		return kept, false, fmt.Errorf("the snapshot before the rewind failed, nothing was changed: %w", err)
	}
	until := time.Now().UTC().Add(time.Duration(keepDays) * 24 * time.Hour)
	t.Doc.KeepUntil = &until
	_ = r.putJSON(ctx, docKey(t.Doc.Label), t.Doc)
	kept = keptEntry{RewindID: rewindID, DatabaseID: db.ID, Port: db.Port, Stanza: db.Stanza, Label: t.Doc.Label, Status: protocol.RewindInProgress,
		CreatedAt: time.Now().UTC(), Expires: until, SizeBytes: in.totalBytes()}
	// Kept before anything is deleted: an agent that stops halfway still
	// knows the snapshot that holds the data.
	if err := upsertKept(env, kept); err != nil {
		return kept, false, fmt.Errorf("recording the snapshot kept for Undo, nothing was changed: %w", err)
	}
	defer func() {
		kept.Status = status
		_ = upsertKept(env, kept)
	}()
	// Apps writing meanwhile would make the removed indices again (automatic
	// index creation) and the restore would fail: paused until it is done.
	resume, err := pauseAutoCreate(ctx, c)
	if err != nil {
		return kept, false, err
	}
	defer resume()
	if err := replaceAll(ctx, c, in, target, tl); err != nil {
		tl.Printf("the restore failed (%v): putting back everything as it was", err)
		now, ierr := inspect(context.WithoutCancel(ctx), c)
		if ierr == nil {
			ierr = replaceAll(context.WithoutCancel(ctx), c, now, t.Doc.Label, tl)
		}
		if ierr != nil {
			return kept, true, fmt.Errorf("the rewind failed (%v) and putting the data back failed too (%v): the snapshot %s holds it", err, ierr, snapshotName(t.Doc.Label))
		}
		return kept, true, fmt.Errorf("the rewind failed (%v); everything is as it was before", err)
	}
	return kept, false, nil
}

func keepDaysOf(n int) int {
	switch {
	case n <= 0:
		return 7
	case n > 30:
		return 30
	}
	return n
}

func (e *Engine) rewindInPlace(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindInPlaceParams, tl agent.TaskLogger) (*protocol.RewindInPlaceResult, error) {
	start := time.Now()
	if !idRE.MatchString(p.RewindID) {
		return nil, fmt.Errorf("invalid rewind id %q", p.RewindID)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return nil, err
	}
	docs, err := r.listDocs(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading your bucket: %w", err)
	}
	doc, err := pickDoc(docs, p.Target.BackupSet, p.Target.Time)
	if err != nil {
		return nil, err
	}
	tl.Printf("rewinding OpenSearch to snapshot %s (taken %s)", doc.Label, doc.StoppedAt.Format(time.RFC3339))
	kept, rolled, err := e.swap(ctx, env, db, p.RewindID, doc.Label, protocol.RewindKeptBefore, keepDaysOf(p.KeepDays), tl)
	res := &protocol.RewindInPlaceResult{RewindID: p.RewindID, RolledBack: rolled, DurationMs: time.Since(start).Milliseconds()}
	if kept.Label != "" {
		at := doc.StoppedAt
		kept.RecoveredTo = &at
		kept.Status = protocol.RewindKeptBefore
		_ = upsertKept(env, kept)
		res.OldDataDir = "snapshot " + snapshotName(kept.Label)
		res.KeptUntil = &kept.Expires
	}
	if err != nil {
		return res, err
	}
	at := doc.StoppedAt
	res.RecoveredTo = &at
	res.Summary = fmt.Sprintf("OpenSearch is back to snapshot %s (taken %s). Everything as it was just before is kept in snapshot %s until %s for Undo; nothing restarted.",
		doc.Label, doc.StoppedAt.Format("2 Jan 15:04 UTC"), snapshotName(kept.Label), kept.Expires.Format("2 Jan"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) rewindUndo(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindUndoParams, tl agent.TaskLogger) (*protocol.RewindUndoResult, error) {
	start := time.Now()
	keptMu.Lock()
	var before *keptEntry
	for _, x := range loadKept(env) {
		if x.RewindID == p.RewindID && x.DatabaseID == db.ID && x.Status == protocol.RewindKeptBefore {
			before = &x
		}
	}
	keptMu.Unlock()
	if before == nil {
		return nil, errors.New("nothing is kept from before this rewind any more (it expired or was cleaned up)")
	}
	tl.Printf("putting back everything as it was before the rewind (snapshot %s)", snapshotName(before.Label))
	after, rolled, err := e.swap(ctx, env, db, p.RewindID, before.Label, protocol.RewindKeptAfterUndo, 7, tl)
	res := &protocol.RewindUndoResult{RewindID: p.RewindID, RolledBack: rolled, DurationMs: time.Since(start).Milliseconds()}
	if err != nil {
		return res, err
	}
	// The snapshot from before is now live again: drop it, keep the rewound
	// state instead (swap recorded it).
	keptMu.Lock()
	k := loadKept(env)
	var rest []keptEntry
	for _, x := range k {
		if !(x.RewindID == p.RewindID && x.Label == before.Label) {
			rest = append(rest, x)
		}
	}
	_ = saveKept(env, rest)
	keptMu.Unlock()
	if c, err := connectDB(ctx, env, db); err == nil {
		if in, err := inspect(ctx, c); err == nil {
			if r, err := openRepo(env, db); err == nil {
				lock := e.repoLock(db)
				lock.Lock()
				if err := dropSnapshots(ctx, c, r, in, []string{before.Label}); err != nil {
					tl.Printf("note: removing the snapshot from before the rewind: %v", err)
				}
				lock.Unlock()
			}
		}
	}
	res.RewoundDataDir = "snapshot " + snapshotName(after.Label)
	res.KeptUntil = &after.Expires
	res.Summary = fmt.Sprintf("Undone: OpenSearch is as it was before the rewind. The rewound state is kept in snapshot %s until %s; nothing restarted.",
		snapshotName(after.Label), after.Expires.Format("2 Jan"))
	tl.Printf("%s", res.Summary)
	return res, nil
}

func (e *Engine) rewindCleanup(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.RewindCleanupParams, tl agent.TaskLogger) (*protocol.RewindCleanupResult, error) {
	res := &protocol.RewindCleanupResult{RewindID: p.RewindID}
	keptMu.Lock()
	for _, x := range loadKept(env) {
		if x.RewindID == p.RewindID {
			res.Removed = true
			res.FreedBytes += x.SizeBytes
		}
	}
	keptMu.Unlock()
	if err := e.dropKept(ctx, env, db, p.RewindID); err != nil {
		return nil, err
	}
	res.Summary = "Removed the snapshot kept for Undo."
	if !res.Removed {
		res.Summary = "Nothing was kept for this rewind (already removed)."
	}
	tl.Printf("%s", strings.TrimSpace(res.Summary))
	return res, nil
}
