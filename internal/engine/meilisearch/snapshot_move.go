package meilisearch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Take it with you for Meilisearch (protocol/snapshot_move.go): the
// database moves from a Rowsafe Cloud server to the customer's own
// Meilisearch by snapshots.
//
//   - Freeze (the old server): Meilisearch has no read-only mode, so the API
//     keys that can write are taken back for the time being. Each one's
//     definition (uid, name, description, actions, indexes, expiry; never
//     its value) is saved on the server first (0600), then the key is
//     deleted. Read-only keys keep working, and Rowsafe's own key stays.
//     Thaw makes them again with the same uid: a key's value is a hash of
//     its uid and the master key ("Custom API keys are deterministic: key is
//     a SHA256 hash of the uid and master key",
//     https://github.com/meilisearch/documentation/blob/v1.12/reference/api/keys.mdx;
//     POST /keys takes the uid, https://www.meilisearch.com/docs/reference/api/keys/create-api-key),
//     so apps' keys work again unchanged.
//   - Take: Meilisearch puts snapshot tasks at the front of its queue
//     (https://www.meilisearch.com/docs/learn/async/asynchronous_operations),
//     so the last snapshot waits until every task enqueued before the
//     freeze has finished, then goes through the normal backup path.
//   - Restore (the new server): like a rewind in place (inplace.go), a
//     temporary Meilisearch starts from the snapshot, exports its indexes
//     (documents and settings, never API keys) into the new server under
//     temporary names, and one swap puts them in place; what an earlier
//     restore put there is replaced at once and deleted.
//   - Promote: the next backup on the new server takes a whole snapshot.
//   - Clear: the indexes the move restored are deleted.

var _ agent.EngineSnapshotMove = (*Engine)(nil)

// moveKeyName names the short-lived key a move's export uses on the new
// server (deleted afterwards).
const moveKeyName = "Rowsafe move"

// moveDrainTimeout bounds the wait for apps' changes sent before the
// freeze.
var moveDrainTimeout = 2 * time.Hour

// seriesNum is protocol.SeriesNumber of version's major and minor.
func seriesNum(version string) int { return protocol.SeriesNumber(seriesOf(version)) }

// ---- the old server

// SnapshotMoveSource describes db for the new server.
func (e *Engine) SnapshotMoveSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (agent.SnapshotMoveSource, error) {
	var src agent.SnapshotMoveSource
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return src, err
	}
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		return src, err
	}
	src.Version, src.Major, src.SizeBytes = in.Version, seriesNum(in.Version), in.DatabaseSize
	src.Newest, err = e.SnapshotMoveNewest(ctx, env, db)
	return src, err
}

// SnapshotMoveNewest is db's newest snapshot in its bucket folder.
func (e *Engine) SnapshotMoveNewest(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (agent.SnapshotRef, error) {
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil || len(docs) == 0 {
		return agent.SnapshotRef{}, err
	}
	d := docs[len(docs)-1]
	return agent.SnapshotRef{Label: d.Label, At: d.TakenAt}, nil
}

// frozenKeys are the keys a freeze took back (move-freeze-<port>.json).
type frozenKeys struct {
	Port       int       `json:"port"`
	DatabaseID string    `json:"database_id,omitempty"`
	FrozenAt   time.Time `json:"frozen_at"`
	Keys       []apiKey  `json:"keys"` // definitions only, never values
}

func freezeFile(env agent.EngineEnv, port int) string {
	return filepath.Join(env.SharedStateDir(), "move-freeze-"+strconv.Itoa(port)+".json")
}

// readOnlyActions can't change indexes, documents, settings or keys
// (https://www.meilisearch.com/docs/reference/api/keys lists the actions).
// Any other action, and any Meilisearch adds later, counts as writing.
var readOnlyActions = []string{
	"search", "documents.get", "indexes.get", "settings.get", "stats.get", "stats.*", "metrics.get", "metrics.*",
	"tasks.get", "tasks.cancel", "tasks.delete", "tasks.compact", "tasks.*", "version", "keys.get", "*.get",
	"experimental.get", "network.get", "webhooks.get", "chats.get", "chatsSettings.get", "chatCompletions",
	"snapshots.create", "snapshots.*", "dumps.create", "dumps.*", "export",
}

// canWrite: one of the actions changes data, settings or keys.
func canWrite(actions []string) bool {
	return slices.ContainsFunc(actions, func(a string) bool { return !slices.Contains(readOnlyActions, a) })
}

// rowsafeKey: one of Rowsafe's own keys (the agent's, older ones of the
// agent's, a rewind's or a move's), which never leave the server.
func rowsafeKey(k apiKey, s server) bool {
	switch {
	case k.UID == s.KeyUID:
		return true
	case k.name() == agentKeyName && k.Description != nil && strings.HasPrefix(*k.Description, "Rowsafe's agent"):
		return true
	case strings.HasPrefix(k.name(), "Rowsafe rewind "), k.name() == moveKeyName:
		return true
	}
	return false
}

// freezes: a key the freeze takes back (it works, it can write, it isn't
// Rowsafe's).
func freezes(k apiKey, s server, now time.Time) bool {
	return !rowsafeKey(k, s) && (k.ExpiresAt == nil || k.ExpiresAt.After(now)) && canWrite(k.Actions)
}

// SnapshotMoveFreeze takes back the keys that can write. Called again, it
// takes back any that appeared since (changed).
func (e *Engine) SnapshotMoveFreeze(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) (bool, error) {
	e.moveMu.Lock()
	defer e.moveMu.Unlock()
	c, s, err := connect(ctx, env, db)
	if err != nil {
		return false, err
	}
	defer c.close()
	if s.NoAuth {
		return false, errors.New("this Meilisearch has no master key, so apps need no key to write and Rowsafe can't stop their writes")
	}
	path := freezeFile(env, db.Port)
	var st frozenKeys
	held := false
	switch err := loadJSONFile(path, &st); {
	case err == nil:
		held = true
	case !notExist(err):
		return false, fmt.Errorf("reading the keys saved for the move: %w", err)
	default:
		st = frozenKeys{Port: db.Port, DatabaseID: db.ID, FrozenAt: time.Now().UTC()}
	}
	keys, err := c.keys(ctx)
	if err != nil {
		return false, fmt.Errorf("reading the API keys: %w", err)
	}
	now := time.Now()
	var drop []apiKey
	for _, k := range keys {
		if !freezes(k, s, now) {
			continue
		}
		drop = append(drop, k)
		if !slices.ContainsFunc(st.Keys, func(x apiKey) bool { return x.UID == k.UID }) {
			def := apiKey{UID: k.UID, Name: k.Name, Description: k.Description, Actions: k.Actions, Indexes: k.Indexes, ExpiresAt: k.ExpiresAt}
			st.Keys = append(st.Keys, def)
		}
	}
	// Saved before any key goes, so each can be given back.
	if !held || len(drop) > 0 {
		if err := saveJSONFile(path, st); err != nil {
			return false, fmt.Errorf("saving the keys before taking them back: %w", err)
		}
	}
	for _, k := range drop {
		if err := c.deleteKey(ctx, k.UID); err != nil && !isCode(err, "api_key_not_found") {
			return held, fmt.Errorf("taking back the API key %s: %w", keyLabel(k), err)
		}
	}
	switch {
	case !held:
		log.Printf("took back %s for the move (saved on this server, given back unchanged if the switchover doesn't happen); "+
			"read-only keys keep working", plural(int64(len(drop)), "API key that can write", "API keys that can write"))
	case len(drop) > 0:
		log.Printf("took back %s that could write again", plural(int64(len(drop)), "API key", "API keys"))
	}
	return held && len(drop) > 0, nil
}

// SnapshotMoveThaw gives the keys back, with their uids: their values
// (and so apps' settings) are the same as before.
func (e *Engine) SnapshotMoveThaw(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) error {
	e.moveMu.Lock()
	defer e.moveMu.Unlock()
	path := freezeFile(env, db.Port)
	var st frozenKeys
	if err := loadJSONFile(path, &st); err != nil {
		if notExist(err) {
			log.Printf("no API key was taken back on this server: nothing to give back")
			return nil
		}
		return fmt.Errorf("reading the keys saved for the move: %w", err)
	}
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return err
	}
	defer c.close()
	var left []apiKey
	var expired []string
	var firstErr error
	now := time.Now()
	for _, k := range st.Keys {
		if k.ExpiresAt != nil && !k.ExpiresAt.After(now.Add(time.Minute)) {
			expired = append(expired, keyLabel(k))
			continue
		}
		_, err := c.createKey(ctx, apiKey{UID: k.UID, Name: k.Name, Description: k.Description, Actions: k.Actions, Indexes: k.Indexes,
			ExpiresAt: k.ExpiresAt})
		if err != nil && !isCode(err, "api_key_already_exists") {
			left = append(left, k)
			if firstErr == nil {
				firstErr = fmt.Errorf("giving back the API key %s: %w", keyLabel(k), err)
			}
		}
	}
	if len(left) > 0 {
		st.Keys = left
		if err := saveJSONFile(path, st); err != nil {
			return err
		}
		return fmt.Errorf("%w (%s still to give back; trying again gives them back)", firstErr, plural(int64(len(left)), "key", "keys"))
	}
	if err := os.Remove(path); err != nil && !notExist(err) {
		return err
	}
	log.Printf("gave back %s: apps write with them again, unchanged", plural(int64(len(st.Keys)-len(expired)), "API key", "API keys"))
	if len(expired) > 0 {
		log.Printf("note: %s expired meanwhile and stays gone: %s", plural(int64(len(expired)), "key", "keys"), joinAnd(firstN(expired, 5)))
	}
	return nil
}

// SnapshotMoveTake takes the last snapshot once Meilisearch has finished
// every change apps sent before the freeze.
func (e *Engine) SnapshotMoveTake(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) (agent.SnapshotRef, error) {
	c, _, err := connect(ctx, env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	since := time.Now().UTC()
	var st frozenKeys
	if loadJSONFile(freezeFile(env, db.Port), &st) == nil && !st.FrozenAt.IsZero() {
		since = st.FrozenAt
	}
	log.Printf("waiting for Meilisearch to finish the changes apps sent before their writes stopped")
	err = c.waitEnqueuedBefore(ctx, since.Add(time.Second), moveDrainTimeout)
	c.close()
	if err != nil {
		return agent.SnapshotRef{}, fmt.Errorf("Meilisearch hasn't finished the changes apps sent before: %w", err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	doc, err := e.takeSnapshot(ctx, env, db, r, sourceScheduled, "", log)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	return agent.SnapshotRef{Label: doc.Label, At: doc.TakenAt}, nil
}

// waitEnqueuedBefore waits until no task enqueued before t is waiting or
// running (GET /tasks with statuses and beforeEnqueuedAt,
// https://www.meilisearch.com/docs/reference/api/tasks/list-tasks).
func (c *client) waitEnqueuedBefore(ctx context.Context, t time.Time, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	q := url.Values{"statuses": {"enqueued,processing"}, "beforeEnqueuedAt": {t.UTC().Format(time.RFC3339Nano)}, "limit": {"1"}}
	for {
		_, n, err := c.taskPage(ctx, q)
		if err == nil && n == 0 {
			return nil
		}
		if ctx.Err() != nil {
			if err == nil {
				err = fmt.Errorf("%s still waiting after %s", plural(n, "task was", "tasks were"), timeout)
			}
			return err
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ---- the new server

// moveState is what a move put into the server on a port
// (move-<port>.json): Clear deletes those indexes.
type moveState struct {
	DatabaseID string   `json:"database_id"`
	Stanza     string   `json:"stanza"`
	Label      string   `json:"label,omitempty"`
	Indexes    []string `json:"indexes"`
}

func moveStateFile(env agent.EngineEnv, port int) string {
	return filepath.Join(env.SharedStateDir(), "move-"+strconv.Itoa(port)+".json")
}

func loadMoveState(env agent.EngineEnv, port int) (moveState, bool) {
	var st moveState
	if err := loadJSONFile(moveStateFile(env, port), &st); err != nil {
		return moveState{}, false
	}
	return st, true
}

// movePrefix is the temporary names' prefix of database id's move.
func movePrefix(id string) string { return restorePrefix("move-" + id) }

// freshFile marks a database whose next backup must take a whole snapshot
// (it moved here: no earlier snapshot holds this server's state).
func freshFile(env agent.EngineEnv, id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(env.SharedStateDir(), "fresh-"+hex.EncodeToString(sum[:8]))
}

func freshNeeded(env agent.EngineEnv, db protocol.DatabaseSpec) bool {
	_, err := os.Stat(freshFile(env, db.ID))
	return err == nil
}

// moveTargetProblem says why the server can't receive a database ("" when
// it can), in plain words.
func moveTargetProblem(in instance, s server) string {
	switch {
	case s.NoAuth:
		return "it has no master key, so anyone who reaches it could read and change everything: give it one, " +
			"then run the Rowsafe installer on this server with --move-target"
	case s.TLS:
		return "Meilisearch serves TLS itself there, and Rowsafe copies a database in over plain HTTP on this server: " +
			"serve it over plain HTTP on 127.0.0.1 (Rowsafe's installer can put TLS in front of it)"
	}
	if maj, minor, ok := majorMinor(in.Version); ok && (maj < 1 || maj == 1 && minor < 18) {
		return fmt.Sprintf("it runs Meilisearch %s: receiving a database needs Meilisearch %s or newer", in.Version, protocol.MeilisearchInPlaceMinVersion)
	}
	return blocker(in, s)
}

// SnapshotMoveRestore restores snapshot label of db into the Meilisearch
// on port, replacing what an earlier restore put there.
func (e *Engine) SnapshotMoveRestore(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, label string,
	o agent.SnapshotMoveRestoreOptions, log agent.TaskLogger) (agent.SnapshotRef, error) {
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return agent.SnapshotRef{}, fmt.Errorf("reading the snapshots in the bucket: %w", err)
	}
	doc, ok := findDoc(docs, label)
	if !ok {
		err := fmt.Errorf("snapshot %s of %s isn't in the bucket", label, db.Name)
		if o.First {
			err = fmt.Errorf("%w: %w", err, agent.ErrMoveRefused)
		}
		return agent.SnapshotRef{}, err
	}
	ref := agent.SnapshotRef{Label: doc.Label, At: doc.TakenAt}
	refuse := func(why string) (agent.SnapshotRef, error) {
		err := fmt.Errorf("Meilisearch on port %d can't receive %s: %s", port, db.Name, why)
		if o.First {
			err = fmt.Errorf("%w: %w", err, agent.ErrMoveRefused)
		}
		return ref, err
	}
	if s, err := loadServer(env, port); err == nil && (s.NoAuth || s.TLS) { // known without asking
		return refuse(moveTargetProblem(instance{}, s))
	}
	c, s, err := connect(ctx, env, protocol.DatabaseSpec{Port: port})
	if err != nil {
		return ref, err
	}
	defer c.close()
	in, err := inspect(ctx, c)
	if err != nil {
		return ref, err
	}
	if why := moveTargetProblem(in, s); why != "" {
		return refuse(why)
	}
	st, _ := loadMoveState(env, port)
	if o.First {
		if len(in.Indexes) > 0 {
			var names []string
			for _, i := range in.Indexes {
				names = append(names, i.UID)
			}
			return ref, fmt.Errorf("Meilisearch on port %d holds data (indexes %s), and only an empty server can receive a database: %w",
				port, joinAnd(firstN(names, 5)), agent.ErrMoveRefused)
		}
		if have := seriesNum(in.Version); o.Major > 0 && have > 0 && have < o.Major {
			return ref, fmt.Errorf("Meilisearch on port %d runs %s, older than %s's Meilisearch %s (update it to %s or newer first): %w",
				port, in.Version, db.Name, protocol.SeriesString(o.Major), protocol.SeriesString(o.Major), agent.ErrMoveRefused)
		}
		st = moveState{DatabaseID: db.ID, Stanza: db.Stanza}
	} else if prev, ok := findDoc(docs, o.Prev); ok && st.Label != "" && prev.dataLabel() == doc.dataLabel() {
		// The newer backup records the same snapshot: nothing changed.
		st.Label = doc.Label
		if err := saveJSONFile(moveStateFile(env, port), st); err != nil {
			return ref, err
		}
		log.Printf("snapshot %s holds the same data as snapshot %s, which this server has already", doc.Label, o.Prev)
		return ref, nil
	}
	if st.DatabaseID == "" {
		st.DatabaseID, st.Stanza = db.ID, db.Stanza
	}
	if s.DBPath != "" {
		if err := ensureSpace(s.DBPath, max(doc.DatabaseBytes, doc.SnapshotBytes), "the restored indexes"); err != nil {
			return refuse(err.Error())
		}
	}
	prefix := movePrefix(db.ID)
	if n := deletePrefixed(ctx, c, prefix); n > 0 {
		log.Printf("removed %s an earlier restore left", plural(int64(n), "temporary index", "temporary indexes"))
	}
	e.copyMu.Lock()
	sc, err := moveScratch(ctx, env, r, s, doc, port, log)
	e.copyMu.Unlock()
	if err != nil {
		return ref, err
	}
	defer func() {
		sc.stop()
		_ = sc.remove()
	}()
	scc := sc.client()
	defer scc.close()
	snap, err := inspect(ctx, scc)
	if err != nil {
		return ref, err
	}
	fail := func(err error) (agent.SnapshotRef, error) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Minute)
		defer cancel()
		deletePrefixed(cctx, c, prefix)
		return ref, err
	}
	if err := exportInto(ctx, scc, c, s, snap, prefix, log); err != nil {
		return fail(err)
	}
	var uids []string
	for _, i := range snap.Indexes {
		uids = append(uids, i.UID)
	}
	// Saved before the swap: whatever happens next, Clear finds them.
	owned := st.Indexes
	st.Indexes = union(owned, uids)
	if err := saveJSONFile(moveStateFile(env, port), st); err != nil {
		return fail(err)
	}
	if err := installRestored(ctx, c, prefix, uids, owned, log); err != nil {
		return fail(err)
	}
	st.Indexes, st.Label = uids, doc.Label
	if err := saveJSONFile(moveStateFile(env, port), st); err != nil {
		return ref, err
	}
	log.Printf("Meilisearch on port %d holds snapshot %s: %s, %s", port, doc.Label, plural(int64(len(snap.Indexes)), "index", "indexes"),
		plural(snap.documents(), "document", "documents"))
	return ref, nil
}

func findDoc(docs []backupDoc, label string) (backupDoc, bool) {
	if label == "" {
		return backupDoc{}, false
	}
	for _, d := range docs {
		if d.Label == label {
			return d, true
		}
	}
	return backupDoc{}, false
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// moveScratch starts doc's snapshot as a temporary Meilisearch (one per
// receiving port: one an agent restart left behind is removed first).
func moveScratch(ctx context.Context, env agent.EngineEnv, r *repo, s server, doc backupDoc, port int, log agent.TaskLogger) (*scratch, error) {
	id := "move-" + strconv.Itoa(port)
	dir := filepath.Join(copyRoot(env), id)
	if _, err := os.Lstat(dir); err == nil {
		killLeftover(dir)
		old, err := scratchAt(dir, s.Binary)
		if err != nil {
			return nil, fmt.Errorf("an earlier restore left %s, which Rowsafe can't remove (%v)", dir, err)
		}
		if err := old.remove(); err != nil {
			return nil, err
		}
	}
	return restoreScratch(ctx, env, r, s, doc, copyRoot(env), id, log)
}

// exportInto copies the temporary instance's indexes into the server under
// prefix (documents and settings; API keys stay behind), as a rewind in
// place does.
func exportInto(ctx context.Context, scc, c *client, s server, snap instance, prefix string, log agent.TaskLogger) error {
	if len(snap.Indexes) == 0 {
		return nil
	}
	var renames []map[string]any
	for _, i := range snap.Indexes {
		if len(prefix+i.UID) > 400 {
			return fmt.Errorf("the index name %s is too long to copy under a temporary name", i.UID)
		}
		renames = append(renames, map[string]any{"indexes": []string{i.UID, prefix + i.UID}, "rename": true})
	}
	t, err := scc.enqueue(ctx, http.MethodPost, "/swap-indexes", nil, renames)
	if err == nil {
		_, err = scc.waitTask(ctx, t, 10*time.Minute)
	}
	if err != nil {
		return fmt.Errorf("renaming the restored indexes: %w", err)
	}
	name, desc := moveKeyName, "Rowsafe: copies a database moved here into place; removed afterwards."
	exp := time.Now().Add(26 * time.Hour).UTC()
	tk, err := c.createKey(ctx, apiKey{Name: &name, Description: &desc, ExpiresAt: &exp, Indexes: []string{prefix + "*"},
		Actions: []string{"indexes.create", "indexes.get", "indexes.update", "documents.add", "settings.update", "settings.get", "tasks.get"}})
	if err != nil {
		return fmt.Errorf("making a key for the copy: %w", err)
	}
	defer func() { _ = c.deleteKey(context.WithoutCancel(ctx), tk.UID) }()
	log.Printf("copying %s (%s) into Meilisearch under temporary names", plural(int64(len(snap.Indexes)), "index", "indexes"),
		plural(snap.documents(), "document", "documents"))
	body := map[string]any{"url": "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(s.localPort())), "apiKey": tk.Key,
		"indexes": map[string]any{prefix + "*": map[string]any{"overrideSettings": true}}}
	// The temporary Meilisearch sends that key to the server's port:
	// checked just before.
	if err := prodCheck(s)(s.localPort()); err != nil {
		return err
	}
	t, err = scc.enqueue(ctx, http.MethodPost, "/export", nil, body)
	if err == nil {
		_, err = scc.waitTask(ctx, t, 24*time.Hour)
	}
	if err != nil {
		return fmt.Errorf("copying the restored indexes: %w", err)
	}
	var tmp []string
	for _, i := range snap.Indexes {
		tmp = append(tmp, prefix+i.UID)
	}
	if err := c.waitIdle(ctx, tmp, 24*time.Hour); err != nil {
		return fmt.Errorf("waiting for Meilisearch to index the restored documents: %w", err)
	}
	got, err := c.stats(ctx)
	if err != nil {
		return err
	}
	for _, i := range snap.Indexes {
		if n := got.Indexes[prefix+i.UID].NumberOfDocuments; n != i.Stats.NumberOfDocuments {
			return fmt.Errorf("Meilisearch indexed %s of the index %s, the snapshot has %s", plural(n, "document", "documents"), i.UID,
				commas(i.Stats.NumberOfDocuments))
		}
	}
	return nil
}

// installRestored puts the indexes copied under prefix in place with one
// swap: the snapshot's indexes (uids) replace those of an earlier restore
// (owned), and owned indexes the snapshot no longer has go too. Indexes
// someone else made on the server are left alone.
func installRestored(ctx context.Context, c *client, prefix string, uids, owned []string, log agent.TaskLogger) error {
	now, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, i := range now.Indexes {
		have[i.UID] = true
	}
	var sp swapPlan
	for _, uid := range uids {
		if have[uid] {
			sp.Swapped = append(sp.Swapped, uid)
		} else {
			sp.Added = append(sp.Added, uid)
		}
	}
	var others []string
	for _, i := range now.Indexes {
		switch {
		case slices.Contains(uids, i.UID):
		case slices.Contains(owned, i.UID):
			sp.Removed = append(sp.Removed, i.UID)
		default:
			others = append(others, i.UID)
		}
	}
	if req := sp.request(prefix, false); len(req) > 0 {
		t, err := c.enqueue(ctx, http.MethodPost, "/swap-indexes", nil, req)
		if err == nil {
			_, err = c.waitTask(ctx, t, time.Hour)
		}
		if err != nil {
			return fmt.Errorf("putting the restored indexes in place: %w", err)
		}
	}
	// What was there before now has the temporary names.
	deletePrefixed(ctx, c, prefix)
	if len(others) > 0 {
		log.Printf("note: left alone %s the move didn't make: %s", plural(int64(len(others)), "index", "indexes"), joinAnd(firstN(others, 5)))
	}
	return nil
}

// SnapshotMovePromote makes the server db's own: its next backup takes a
// whole snapshot of this server into the same bucket folder.
func (e *Engine) SnapshotMovePromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, log agent.TaskLogger) error {
	c, s, err := connect(ctx, env, protocol.DatabaseSpec{Port: port})
	if err != nil {
		return err
	}
	defer c.close()
	deletePrefixed(ctx, c, movePrefix(db.ID))
	in, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	if why := blocker(in, s); why != "" {
		return errors.New(why)
	}
	// Change marks of snapshots taken on the old server mean nothing here.
	if err := os.MkdirAll(env.SharedStateDir(), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(freshFile(env, db.ID), []byte(db.ID+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Remove(moveStateFile(env, port)); err != nil && !notExist(err) {
		return err
	}
	log.Printf("Meilisearch on port %d is %s's own (%s, %s): its next backup takes a whole snapshot into the same bucket folder. "+
		"API keys don't move: make the apps' keys on this server", port, db.Name, plural(int64(len(in.Indexes)), "index", "indexes"),
		plural(in.documents(), "document", "documents"))
	return nil
}

// SnapshotMoveClear deletes the indexes the move restored on port.
func (e *Engine) SnapshotMoveClear(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, log agent.TaskLogger) error {
	c, _, err := connect(ctx, env, protocol.DatabaseSpec{Port: port})
	if err != nil {
		return err
	}
	defer c.close()
	st, ok := loadMoveState(env, port)
	id := db.ID
	if id == "" {
		id = st.DatabaseID
	}
	n := 0
	if id != "" {
		n += deletePrefixed(ctx, c, movePrefix(id))
	}
	if ok && (st.DatabaseID == id || st.DatabaseID == "") {
		for _, uid := range st.Indexes {
			if _, err := c.index(ctx, uid); isCode(err, "index_not_found") {
				continue
			}
			t, err := c.enqueue(ctx, http.MethodDelete, "/indexes/"+url.PathEscape(uid), nil, nil)
			if err == nil {
				_, err = c.waitTask(ctx, t, 10*time.Minute)
			}
			if err != nil {
				return fmt.Errorf("removing the index %s: %w", uid, err)
			}
			n++
		}
	}
	if err := os.Remove(moveStateFile(env, port)); err != nil && !notExist(err) {
		return err
	}
	log.Printf("removed %s the move restored into Meilisearch on port %d", plural(int64(n), "index", "indexes"), port)
	return nil
}

// ---- targets

// StandbyTargets are the Meilisearch servers here with Rowsafe's key that
// can receive a database: empty, with a master key, reachable over plain
// HTTP on this server (cached a minute: it asks each).
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() {
		return nil
	}
	e.targetsMu.Lock()
	defer e.targetsMu.Unlock()
	if e.targetsDir == env.SharedStateDir() && time.Since(e.targetsAt) < time.Minute {
		return e.targetsCache
	}
	var out []protocol.StandbyTarget
	for _, port := range knownPorts(env) {
		t := protocol.StandbyTarget{Engine: protocol.EngineMeilisearch, Port: port}
		t.Version, t.NoStandby = targetCheck(ctx, env, port)
		t.Standby, t.Usable, t.Reason = t.NoStandby == "", t.NoStandby == "", t.NoStandby
		out = append(out, t)
	}
	e.targetsDir, e.targetsAt, e.targetsCache = env.SharedStateDir(), time.Now(), out
	return out
}

// targetCheck is the version of the server on port and why it can't
// receive a database ("" when it can).
func targetCheck(ctx context.Context, env agent.EngineEnv, port int) (string, string) {
	s, err := loadServer(env, port)
	if err != nil {
		return "", "Rowsafe has no key there: run the Rowsafe installer on this server with --move-target"
	}
	if _, ok := loadMoveState(env, port); ok {
		return "", "it is receiving a database already"
	}
	if s.NoAuth || s.TLS { // known without asking
		return "", moveTargetProblem(instance{}, s)
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := dial(cctx, s)
	if err != nil {
		return "", "Meilisearch doesn't answer there"
	}
	defer c.close()
	in, err := inspect(cctx, c)
	if err != nil {
		if isAuthError(err) {
			return "", "Rowsafe's key there no longer works: run the Rowsafe installer on this server with --move-target"
		}
		return "", firstLine(err.Error())
	}
	if why := moveTargetProblem(in, s); why != "" {
		return in.Version, why
	}
	if len(in.Indexes) > 0 {
		return in.Version, "it holds data: only an empty server can receive a database"
	}
	return in.Version, ""
}
