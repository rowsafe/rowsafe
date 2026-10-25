package qdrant

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Moving a Qdrant database to another server by snapshots ("Take it with
// you", protocol/snapshot_move.go):
//
//   - the receiving server is an empty Qdrant the installer gave Rowsafe's
//     key (--move-target); each restore uploads the collections' snapshots
//     from the bucket over the API (priority "snapshot", as a rewind in
//     place does), leaves Rowsafe's own collection alone, removes the
//     collections it restored earlier that the snapshot no longer holds and
//     puts the aliases back. A later restore skips the collections whose
//     snapshot is the one it restored before. The collections a move
//     restored are recorded (move-targets.json), so cancelling it removes
//     those and nothing else.
//   - Qdrant has no write lock, so the old server stops apps' writes
//     through the keys made in Databases & users: the points of the keys
//     that can write leave Rowsafe's keys collection, so their tokens stop
//     working (read-only keys keep theirs), and the key list says frozen so
//     reconcile leaves them out until Thaw puts the same points back (the
//     same tokens work again).
//   - the switchover's last snapshot is an ordinary backup; after it the new
//     server's first backup takes every collection again (fullNext).

var _ agent.EngineSnapshotMove = (*Engine)(nil)

// series is a version number's major and minor as protocol.SeriesNumber
// gives them (11902 -> 119).
func series(versionNum int) int {
	return protocol.SeriesNumber(fmt.Sprintf("%d.%d", versionNum/10000, versionNum/100%100))
}

// SnapshotMoveSource describes the database on the Rowsafe Cloud server.
func (e *Engine) SnapshotMoveSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (agent.SnapshotMoveSource, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return agent.SnapshotMoveSource{}, err
	}
	defer c.Close()
	in, err := inspect(ctx, c, false)
	if err != nil {
		return agent.SnapshotMoveSource{}, err
	}
	newest, err := e.SnapshotMoveNewest(ctx, env, db)
	if err != nil {
		return agent.SnapshotMoveSource{}, fmt.Errorf("reading the snapshots in your bucket: %w", err)
	}
	return agent.SnapshotMoveSource{Major: series(in.VersionNum), Version: in.Version, SizeBytes: in.totalBytes(), Newest: newest}, nil
}

// SnapshotMoveNewest is the newest backup in the database's folder.
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

// SnapshotMoveTake takes the switchover's last snapshot: an ordinary
// backup, with the database's lock and its retention.
func (e *Engine) SnapshotMoveTake(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) (agent.SnapshotRef, error) {
	doc, err := e.takeBackup(ctx, env, db, sourceScheduled, "", log)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	return agent.SnapshotRef{Label: doc.Label, At: doc.TakenAt}, nil
}

// ---- stopping apps' writes (the old server)

// SnapshotMoveFreeze takes the points of the keys that can write out of
// Rowsafe's keys collection and marks the list frozen. Called again (the
// fence holds), it removes any such point that came back: changed.
func (e *Engine) SnapshotMoveFreeze(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) (bool, error) {
	l, _, err := loadLogin(env, db.Port)
	if err != nil {
		return false, err
	}
	if l.Key == "" || !l.JWT {
		// Apps use the server's own key here, which Rowsafe can't take
		// back: the switchover would lose their writes after the last
		// snapshot, so it doesn't start.
		return false, errors.New("this Qdrant doesn't use keys made in Databases & users (its JSON Web Tokens are off), so Rowsafe can't stop apps' writes for the switchover")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return false, err
	}
	defer c.Close()
	keysMu.Lock()
	defer keysMu.Unlock()
	list, _, err := loadKeyList(env, db.Port)
	if err != nil {
		return false, err
	}
	again := list.Frozen != nil
	if !again {
		now := time.Now().UTC()
		list.Frozen = &now
		if err := saveKeyList(env, db.Port, list); err != nil {
			return false, err
		}
	}
	removed, err := removeWriters(ctx, c, list)
	if err != nil {
		return false, fmt.Errorf("stopping the keys that can write: %w", err)
	}
	if !again {
		var names []string
		for _, k := range list.Keys {
			if k.canWrite() {
				names = append(names, k.Name)
			}
		}
		if len(names) > 0 {
			log.Printf("the keys that can write (%s) stopped working for now; read-only keys keep working", strings.Join(names, ", "))
		} else {
			log.Printf("no key made in Databases & users can write here")
		}
		log.Printf("note: apps that use the server's own key (api_key) aren't stopped")
	}
	return again && removed > 0, nil
}

// removeWriters deletes the points of the list's keys that can write (and
// any other point naming them). keysMu is held.
func removeWriters(ctx context.Context, c *client, list keyList) (int, error) {
	writers, ids := map[string]bool{}, map[string]bool{}
	for _, k := range list.Keys {
		if k.canWrite() {
			writers[k.Name], ids[keyPointID(k.Name)] = true, true
		}
	}
	if len(writers) == 0 {
		return 0, nil
	}
	points, _, err := keyPoints(ctx, c)
	if err != nil {
		return 0, err
	}
	var gone []json.RawMessage
	for _, p := range points {
		if writers[p.Key] || ids[p.id()] {
			gone = append(gone, p.ID)
		}
	}
	return len(gone), deleteKeyPoints(ctx, c, gone)
}

// SnapshotMoveThaw lets the keys that can write work again: their points
// go back with the same nonce, so the same tokens work.
func (e *Engine) SnapshotMoveThaw(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) error {
	keysMu.Lock()
	defer keysMu.Unlock()
	list, exists, err := loadKeyList(env, db.Port)
	if err != nil || !exists || list.Frozen == nil {
		return err
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	defer c.Close()
	list.Frozen = nil
	if err := saveKeyList(env, db.Port, list); err != nil {
		return err
	}
	var back []keyEntry
	now := time.Now()
	for _, k := range list.Keys {
		if k.canWrite() && !k.expired(now) {
			back = append(back, k)
		}
	}
	if len(back) == 0 {
		return nil
	}
	if err := ensureKeysCollection(ctx, c); err != nil {
		return err
	}
	if err := putKeyPoints(ctx, c, back); err != nil {
		return fmt.Errorf("letting the keys that can write work again: %w", err)
	}
	log.Printf("the keys that can write work again (%d)", len(back))
	return nil
}

// ---- the receiving server

// moveTarget is what moves restored into a server (move-targets.json in
// the state directory, by port): the collections Clear may remove.
type moveTarget struct {
	DatabaseID  string   `json:"database_id"`
	Collections []string `json:"collections"`
}

var moveMu sync.Mutex

func moveTargetsPath(env agent.EngineEnv) string {
	return filepath.Join(env.StateDir, "move-targets.json")
}

func loadMoveTarget(env agent.EngineEnv, port int) (moveTarget, bool) {
	moveMu.Lock()
	defer moveMu.Unlock()
	m := map[string]moveTarget{}
	_ = loadJSONFile(moveTargetsPath(env), &m)
	t, ok := m[strconv.Itoa(port)]
	return t, ok
}

// saveMoveTarget records t for port (nil: forgets it).
func saveMoveTarget(env agent.EngineEnv, port int, t *moveTarget) error {
	moveMu.Lock()
	defer moveMu.Unlock()
	m := map[string]moveTarget{}
	_ = loadJSONFile(moveTargetsPath(env), &m)
	if t == nil {
		if _, ok := m[strconv.Itoa(port)]; !ok {
			return nil
		}
		delete(m, strconv.Itoa(port))
	} else {
		m[strconv.Itoa(port)] = *t
	}
	return saveJSONFile(moveTargetsPath(env), m)
}

// SnapshotMoveRestore makes the Qdrant on port hold backup label: each
// collection from its snapshot in the bucket (those whose snapshot is the
// one restored before, o.Prev, are skipped), the collections an earlier
// restore made that the backup no longer holds removed, the aliases put
// back. The first restore needs an empty server, as new as the database's.
func (e *Engine) SnapshotMoveRestore(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, label string,
	o agent.SnapshotMoveRestoreOptions, log agent.TaskLogger) (agent.SnapshotRef, error) {
	if o.First {
		// What an earlier, cancelled move left recorded isn't this one's.
		if err := saveMoveTarget(env, port, nil); err != nil {
			return agent.SnapshotRef{}, err
		}
	}
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	defer c.Close()
	in, err := inspect(ctx, c, false)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	if why := in.supported(); why != "" {
		return agent.SnapshotRef{}, fmt.Errorf("%s: %w", why, agent.ErrMoveRefused)
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return agent.SnapshotRef{}, fmt.Errorf("reading your bucket: %w", err)
	}
	i := slices.IndexFunc(docs, func(d backupDoc) bool { return d.Label == label })
	if i < 0 {
		return agent.SnapshotRef{}, fmt.Errorf("snapshot %s isn't in your bucket any more", label)
	}
	doc := docs[i]
	var prev *backupDoc
	if j := slices.IndexFunc(docs, func(d backupDoc) bool { return d.Label == o.Prev }); o.Prev != "" && j >= 0 {
		prev = &docs[j]
	}
	plan, err := movePlan(in, doc, prev, o, port)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	rec, _ := loadMoveTarget(env, port)
	rec.DatabaseID = db.ID
	ours := func(name string) bool { return slices.Contains(rec.Collections, name) }
	record := func(name string) error {
		if ours(name) {
			return nil
		}
		rec.Collections = append(rec.Collections, name)
		return saveMoveTarget(env, port, &rec)
	}
	if err := saveMoveTarget(env, port, &rec); err != nil {
		return agent.SnapshotRef{}, err
	}
	switch {
	case len(plan.restore) == 0:
		log.Printf("no collection changed since snapshot %s", o.Prev)
	case doc.Format != formatCollections:
		if err := restoreFull(ctx, env, c, r, doc, plan.restore, record, log); err != nil {
			return agent.SnapshotRef{}, err
		}
	default:
		for _, cd := range plan.restore {
			if err := record(cd.Name); err != nil {
				return agent.SnapshotRef{}, err
			}
			log.Printf("restoring collection %s (%s)", cd.Name, humanBytes(cd.Bytes))
			if err := uploadFromBucket(ctx, c, r, cd); err != nil {
				return agent.SnapshotRef{}, fmt.Errorf("restoring collection %s: %w", cd.Name, err)
			}
		}
	}
	inDoc := map[string]bool{}
	for _, cd := range doc.Collections {
		inDoc[cd.Name] = true
	}
	for _, ci := range in.userCollections() {
		if inDoc[ci.Name] {
			continue
		}
		if !ours(ci.Name) {
			log.Printf("note: collection %s on this server isn't part of %s; it was left as it is", ci.Name, db.Name)
			continue
		}
		log.Printf("removing collection %s (the database no longer has it)", ci.Name)
		if err := c.deleteCollection(ctx, ci.Name); err != nil {
			return agent.SnapshotRef{}, fmt.Errorf("removing collection %s: %w", ci.Name, err)
		}
		rec.Collections = slices.DeleteFunc(rec.Collections, func(n string) bool { return n == ci.Name })
		if err := saveMoveTarget(env, port, &rec); err != nil {
			return agent.SnapshotRef{}, err
		}
	}
	want := map[string]string{}
	maps.Copy(want, doc.Aliases)
	// Aliases of collections that aren't the database's (Rowsafe's own, or
	// one the snapshot doesn't hold) stay as they are.
	if err := c.setAliases(ctx, want, func(coll string) bool { return ownColl(coll) || !inDoc[coll] }); err != nil {
		return agent.SnapshotRef{}, fmt.Errorf("putting the aliases back: %w", err)
	}
	log.Printf("Qdrant on port %d holds snapshot %s (taken %s): %d collections restored, %d unchanged", port, doc.Label,
		doc.TakenAt.UTC().Format("2006-01-02 15:04:05 UTC"), len(plan.restore), plan.unchanged)
	return agent.SnapshotRef{Label: doc.Label, At: doc.TakenAt}, nil
}

// restorePlan is what a restore does.
type restorePlan struct {
	restore   []collDoc // the collections to restore from their snapshot
	unchanged int       // skipped: the same snapshot as restored before
}

// movePlan checks the receiving server and picks the collections to
// restore.
func movePlan(in serverInfo, doc backupDoc, prev *backupDoc, o agent.SnapshotMoveRestoreOptions, port int) (restorePlan, error) {
	var p restorePlan
	have := series(in.VersionNum)
	if o.First {
		if o.Major > 0 && have < o.Major {
			return p, fmt.Errorf("Qdrant on port %d is version %s, older than the database's (%s): update it first: %w",
				port, in.Version, protocol.SeriesString(o.Major), agent.ErrMoveRefused)
		}
		if user := in.userCollections(); len(user) > 0 {
			names := make([]string, 0, len(user))
			for _, ci := range user {
				names = append(names, ci.Name)
			}
			return p, fmt.Errorf("Qdrant on port %d holds data (collections %s): only an empty server can receive a database: %w",
				port, strings.Join(names, ", "), agent.ErrMoveRefused)
		}
	}
	if doc.VersionNum > 0 && series(doc.VersionNum) > have {
		return p, fmt.Errorf("snapshot %s is from Qdrant %s, newer than Qdrant %s on port %d: update Qdrant on this server first: %w",
			doc.Label, doc.Version, in.Version, port, agent.ErrMoveRefused)
	}
	present := map[string]bool{}
	for _, ci := range in.Collections {
		present[ci.Name] = true
	}
	for _, cd := range doc.Collections {
		if ownColl(cd.Name) {
			continue
		}
		if prev != nil && doc.Format == formatCollections && prev.Format == formatCollections && present[cd.Name] {
			if pc := prev.collection(cd.Name); pc.Object != "" && pc.Object == cd.Object && pc.Checksum == cd.Checksum {
				p.unchanged++
				continue
			}
		}
		p.restore = append(p.restore, cd)
	}
	return p, nil
}

// uploadFromBucket restores collection cd.Name from its snapshot in the
// bucket, streamed (decrypted here) into Qdrant: the upload fails unless
// the snapshot read is the one Rowsafe stored.
func uploadFromBucket(ctx context.Context, c *client, r *repo, cd collDoc) error {
	if cd.Object == "" || !strings.HasPrefix(cd.Object, dataPrefix) || strings.Contains(cd.Object, "..") {
		return fmt.Errorf("the backup names an unexpected object for collection %s", cd.Name)
	}
	src, closer, err := r.getSealed(ctx, cd.Object)
	if err != nil {
		return fmt.Errorf("downloading its snapshot: %w", err)
	}
	defer closer.Close()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	errBad := errors.New("its snapshot in your bucket isn't the one Rowsafe stored")
	wrote := make(chan error, 1)
	go func() {
		part, err := mw.CreateFormFile("snapshot", "collection.snapshot")
		if err == nil {
			sum := sha256.New()
			var n int64
			n, err = io.Copy(part, io.TeeReader(src, sum))
			if err == nil && (n != cd.Bytes || cd.Checksum != "" && hex.EncodeToString(sum.Sum(nil)) != cd.Checksum) {
				err = errBad
			}
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
		wrote <- err
	}()
	q := url.Values{"priority": {"snapshot"}, "wait": {"true"}}
	resp, err := c.request(ctx, http.MethodPost, collPath(cd.Name)+"/snapshots/upload", q, pr, mw.FormDataContentType())
	pr.CloseWithError(errors.New("upload stopped"))
	if err == nil {
		resp.Body.Close()
	}
	if werr := <-wrote; errors.Is(werr, errBad) {
		return werr // the reason, not the request it stopped
	}
	return err
}

// restoreFull restores the collections of a backup made of one full
// storage snapshot (before Rowsafe took one per collection): unpacked on
// this server first.
func restoreFull(ctx context.Context, env agent.EngineEnv, c *client, r *repo, doc backupDoc, want []collDoc,
	record func(string) error, log agent.TaskLogger) error {
	work := filepath.Join(copyRoot(env), "move-"+doc.Label)
	_ = os.RemoveAll(work)
	defer os.RemoveAll(work)
	if err := ensureSpace(copyRoot(env), doc.SnapshotBytes+256<<20, "restoring the snapshot"); err != nil {
		return err
	}
	log.Printf("downloading snapshot %s (%s) and unpacking it on this server", doc.Label, humanBytes(doc.SnapshotBytes))
	u, err := unpackSnapshot(ctx, r, backupPrefix+doc.Label+"/", work)
	if err != nil {
		return err
	}
	for _, cd := range want {
		path, ok := u.Members[cd.Name]
		if !ok {
			return fmt.Errorf("snapshot %s doesn't hold collection %s", doc.Label, cd.Name)
		}
		if err := record(cd.Name); err != nil {
			return err
		}
		log.Printf("restoring collection %s", cd.Name)
		if err := uploadCollection(ctx, c, cd.Name, path); err != nil {
			return fmt.Errorf("restoring collection %s: %w", cd.Name, err)
		}
	}
	return nil
}

// SnapshotMovePromote makes the server on port the database's: its next
// backup takes every collection again (the old server's change marks mean
// nothing here), into the same folder.
func (e *Engine) SnapshotMovePromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, log agent.TaskLogger) error {
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.collectionNames(ctx); err != nil {
		return fmt.Errorf("reaching Qdrant on port %d: %w", port, err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	if err := r.ensureMarker(ctx, db.Name); err != nil {
		return err
	}
	e.setFullNext(env, db.ID, "this server took the database over from the old one") // fullnext.go
	e.mu.Lock()
	delete(e.ops, db.ID)
	e.mu.Unlock()
	// The collections are the database's now: a cancelled move no longer
	// removes them.
	if err := saveMoveTarget(env, port, nil); err != nil {
		return err
	}
	log.Printf("Qdrant on port %d holds %s now; its next backup takes every collection again, into the same folder", port, db.Name)
	return nil
}

// SnapshotMoveClear removes the collections the move restored into the
// server on port (and only those): it is empty again.
func (e *Engine) SnapshotMoveClear(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, log agent.TaskLogger) error {
	rec, ok := loadMoveTarget(env, port)
	if !ok || len(rec.Collections) == 0 {
		return saveMoveTarget(env, port, nil)
	}
	if rec.DatabaseID != "" && db.ID != "" && rec.DatabaseID != db.ID {
		log.Printf("note: the collections on port %d were restored for another database; they were left as they are", port)
		return nil
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return err
	}
	defer c.Close()
	names, err := c.collectionNames(ctx)
	if err != nil {
		return err
	}
	for _, n := range rec.Collections {
		if ownColl(n) || !slices.Contains(names, n) {
			continue
		}
		log.Printf("removing collection %s", n)
		if err := c.deleteCollection(ctx, n); err != nil {
			return fmt.Errorf("removing collection %s: %w", n, err)
		}
	}
	return saveMoveTarget(env, port, nil)
}

// ---- receiving servers (heartbeat)

var (
	targetsMu    sync.Mutex
	targetsAt    time.Time
	targetsCache []protocol.StandbyTarget
)

// StandbyTargets are the Qdrant servers here that can receive a database:
// Rowsafe's key saved for the port (the installer's --move-target) and no
// collection but Rowsafe's own. Cached two minutes: it asks each server.
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() || inDocker() {
		return nil
	}
	targetsMu.Lock()
	defer targetsMu.Unlock()
	if !targetsAt.IsZero() && time.Since(targetsAt) < 2*time.Minute {
		return targetsCache
	}
	var out []protocol.StandbyTarget
	if len(findProcs()) > 0 {
		for _, port := range candidatePorts(env) {
			if t, ok := e.target(ctx, env, port); ok {
				out = append(out, t)
			}
		}
	}
	targetsAt, targetsCache = time.Now(), out
	return out
}

// target reads one port (ok false: no Qdrant answers there).
func (e *Engine) target(ctx context.Context, env agent.EngineEnv, port int) (protocol.StandbyTarget, bool) {
	t := protocol.StandbyTarget{Engine: protocol.EngineQdrant, Port: port}
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := ServerStatus(hctx, env, port)
	if err != nil {
		return t, false
	}
	t.Version = st.Version
	_, saved, _ := loadLogin(env, port)
	_, receiving := loadMoveTarget(env, port)
	switch {
	case receiving:
		t.Reason = "it is receiving a database"
	case st.Login == "none":
		t.Reason = "it asks for no key, so anyone who reaches it could read and change the database: turn keys on in Qdrant, then run the Rowsafe installer on this server with --move-target"
	case !saved || st.Login != "ok":
		t.Reason = "Rowsafe has no key there: run the Rowsafe installer on this server with --move-target"
	case st.Cluster:
		t.Reason = "it runs in distributed (cluster) mode; only a single Qdrant server can receive a database"
	case parseVersion(st.Version) < minVersion:
		t.Reason = fmt.Sprintf("it is Qdrant %s; Rowsafe needs Qdrant 1.13 or newer", st.Version)
	case st.Collections > 0:
		t.Reason = "it holds data: only an empty server can receive a database"
	}
	t.Usable, t.Standby = t.Reason == "", t.Reason == ""
	t.NoStandby = t.Reason
	return t, true
}
