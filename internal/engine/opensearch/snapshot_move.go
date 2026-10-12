package opensearch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/internal/objstore"
	"github.com/rowsafe/rowsafe/protocol"
)

// Moving an OpenSearch database by snapshots (Rowsafe Cloud's "Take it
// with you", protocol/snapshot_move.go):
//
//   - The old server (the Rowsafe Cloud one) keeps backing up into its
//     bucket folder as always. At the switchover every index apps use gets
//     a write block (index.blocks.write) and automatic index creation is
//     paused (action.auto_create_index false, a persistent setting, so a
//     restart doesn't lift it); reads go on. Indices that had a write block
//     of their own keep it when the block is lifted again (freeze-<id>.json
//     records which ones are Rowsafe's). One last snapshot goes to the
//     bucket through the normal backup path; while writes are stopped,
//     backup records say which blocks are Rowsafe's and carry the index
//     templates and ingest pipelines (backupDoc.MoveBlocked, Globals).
//   - The new server (the customer's, set up by the installer with
//     --move-target: Rowsafe's login, path.repo, and a snapshot folder the
//     agent may write into) gets the bucket's repository copied into its
//     own snapshot folder, the same files under the same names, so after
//     the switchover its backups go on in that repository and in the same
//     bucket folder, with the old snapshots (Rewind, Proof) still there.
//     The repository is registered read-only while it receives; each
//     restore replaces the indices and data streams the previous one put
//     there. Automatic index creation stays paused until the switchover.
//   - The switchover moves the bucket folder's marker to the new server's
//     cluster: from then on the old server can't copy anything into the
//     folder (errOtherCluster).

var _ agent.EngineSnapshotMove = (*Engine)(nil)

// moveMu serializes the move's state files and the changes they record.
var moveMu sync.Mutex

func movesDir(env agent.EngineEnv) string { return filepath.Join(env.StateDir, "moves") }

func moveStatePath(env agent.EngineEnv, kind, dbID string) (string, error) {
	if !idRE.MatchString(dbID) {
		return "", fmt.Errorf("invalid database id %q", dbID)
	}
	return filepath.Join(movesDir(env), kind+"-"+dbID+".json"), nil
}

// loadMoveState reads a move's state file into v (ok false when there is
// none).
func loadMoveState(env agent.EngineEnv, kind, dbID string, v any) (bool, error) {
	p, err := moveStatePath(env, kind, dbID)
	if err != nil {
		return false, err
	}
	switch err := loadJSONFile(p, v); {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, fmt.Errorf("reading %s: %w", p, err)
	}
}

func saveMoveState(env agent.EngineEnv, kind, dbID string, v any) error {
	p, err := moveStatePath(env, kind, dbID)
	if err != nil {
		return err
	}
	return saveJSONFile(p, v)
}

func removeMoveState(env agent.EngineEnv, kind, dbID string) error {
	p, err := moveStatePath(env, kind, dbID)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ---- on the old server: writes stopped, the last snapshot

// freezeState is what the switchover changed on the old server
// (<state>/moves/freeze-<database id>.json).
type freezeState struct {
	DatabaseID string    `json:"database_id"`
	Port       int       `json:"port"`
	Since      time.Time `json:"since"`
	// Own are the indices that had a write block of their own before;
	// Blocked the ones Rowsafe blocked (lifted again by a thaw).
	Own     []string  `json:"own,omitempty"`
	Blocked []string  `json:"blocked,omitempty"`
	Auto    autoPrev  `json:"auto_create"`
	At      time.Time `json:"at"`
}

// loadFreeze is the freeze of database dbID on this server, if any.
func loadFreeze(env agent.EngineEnv, dbID string) (freezeState, bool) {
	var fz freezeState
	if dbID == "" {
		return fz, false
	}
	ok, err := loadMoveState(env, "freeze", dbID, &fz)
	return fz, ok && err == nil
}

// autoPrev is automatic index creation as it was before Rowsafe paused it
// (nil: not set).
type autoPrev struct {
	Recorded   bool    `json:"recorded"`
	Persistent *string `json:"persistent,omitempty"`
	Transient  *string `json:"transient,omitempty"`
	// SetTransient: a transient value turned it on, so Rowsafe set that
	// one too.
	SetTransient bool `json:"set_transient,omitempty"`
}

// readAutoCreate reads action.auto_create_index's persistent and transient
// values.
func readAutoCreate(ctx context.Context, c *client) (persistent, transient *string, err error) {
	var cur struct {
		Persistent map[string]any `json:"persistent"`
		Transient  map[string]any `json:"transient"`
	}
	if err := c.get(ctx, "/_cluster/settings?flat_settings=true", &cur); err != nil {
		return nil, nil, roleErr(err, "read the cluster's settings")
	}
	str := func(m map[string]any) *string {
		v, ok := m[autoCreate]
		if !ok || v == nil {
			return nil
		}
		s := fmt.Sprint(v)
		return &s
	}
	return str(cur.Persistent), str(cur.Transient), nil
}

// autoCreatePause is the change that keeps automatic index creation off
// (nil when it is off already). It records what was there first in a.
func autoCreatePause(ctx context.Context, c *client, a *autoPrev) (map[string]any, error) {
	p, t, err := readAutoCreate(ctx, c)
	if err != nil {
		return nil, err
	}
	if !a.Recorded {
		a.Recorded, a.Persistent, a.Transient = true, p, t
	}
	body := map[string]any{}
	if p == nil || *p != "false" {
		body["persistent"] = map[string]any{autoCreate: false}
	}
	if t != nil && *t != "false" {
		body["transient"] = map[string]any{autoCreate: false}
		a.SetTransient = true
	}
	if len(body) == 0 {
		return nil, nil
	}
	return body, nil
}

func putClusterSettings(ctx context.Context, c *client, body map[string]any) error {
	if err := c.do(ctx, http.MethodPut, "/_cluster/settings", body, nil); err != nil {
		return roleErr(err, "pause automatic index creation")
	}
	return nil
}

// autoCreateResume puts automatic index creation back as a recorded it.
func autoCreateResume(ctx context.Context, c *client, a autoPrev) error {
	if !a.Recorded {
		return nil
	}
	val := func(s *string) any {
		if s == nil {
			return nil
		}
		return *s
	}
	body := map[string]any{"persistent": map[string]any{autoCreate: val(a.Persistent)}}
	if a.SetTransient {
		body["transient"] = map[string]any{autoCreate: val(a.Transient)}
	}
	if err := c.do(ctx, http.MethodPut, "/_cluster/settings", body, nil); err != nil {
		return fmt.Errorf("turning automatic index creation back on: %w", roleErr(err, "change the cluster's settings"))
	}
	return nil
}

// roleErr explains a refusal of Rowsafe's own OpenSearch user (a role made
// by an older Rowsafe).
func roleErr(err error, what string) error {
	if s := statusOf(err); s == http.StatusForbidden {
		return fmt.Errorf("Rowsafe's OpenSearch user may not %s on this server (its role is from an older Rowsafe): "+
			"run the Rowsafe installer on this server again, then try again", what)
	}
	return err
}

// maxURLNames caps the length of a list of index names in one request
// (OpenSearch's request line is 4 KB by default).
const maxURLNames = 3000

// nameChunks splits names into lists that fit in a request's path.
func nameChunks(names []string) []string {
	var out []string
	var cur []string
	n := 0
	for _, s := range names {
		e := pathEscape(s)
		if len(cur) > 0 && n+len(e)+1 > maxURLNames {
			out = append(out, strings.Join(cur, ","))
			cur, n = nil, 0
		}
		cur = append(cur, e)
		n += len(e) + 1
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, ","))
	}
	return out
}

// writeBlocks reports which of names have a write block.
func writeBlocks(ctx context.Context, c *client, names []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, list := range nameChunks(names) {
		var v map[string]struct {
			Settings map[string]any `json:"settings"`
		}
		err := c.get(ctx, "/"+list+"/_settings/index.blocks.write?flat_settings=true&expand_wildcards=all&ignore_unavailable=true", &v)
		if err != nil {
			return nil, roleErr(err, "read the indices' settings")
		}
		for name, s := range v {
			out[name] = fmt.Sprint(s.Settings["index.blocks.write"]) == "true"
		}
	}
	return out, nil
}

// setWriteBlock puts a write block on names (on), or lifts it.
func setWriteBlock(ctx context.Context, c *client, names []string, on bool) error {
	var v any // null: OpenSearch's default, no block
	if on {
		v = true
	}
	for _, list := range nameChunks(names) {
		err := c.do(ctx, http.MethodPut, "/"+list+"/_settings?expand_wildcards=all&ignore_unavailable=true",
			map[string]any{"index.blocks.write": v}, nil)
		if err != nil {
			if on {
				return roleErr(err, "block writes")
			}
			return roleErr(err, "lift the write block")
		}
	}
	return nil
}

// openIndices are the user's open indices (data streams' backing indices
// included).
func openIndices(ctx context.Context, c *client) ([]string, error) {
	idx, _, err := listIndices(ctx, c)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, i := range idx {
		if i.Open {
			out = append(out, i.Name)
		}
	}
	return out, nil
}

// SnapshotMoveFreeze stops apps writing to the database: a write block on
// every user index and data stream backing index, and automatic index
// creation paused. Called again while the fence holds, it blocks what is
// new or was unblocked (changed true).
func (e *Engine) SnapshotMoveFreeze(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) (bool, error) {
	moveMu.Lock()
	defer moveMu.Unlock()
	if db.ID == "" {
		return false, errors.New("no database to stop writes to")
	}
	fz, had := loadFreeze(env, db.ID)
	port := db.Port
	if port == 0 {
		port = fz.Port
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return false, err
	}
	names, err := openIndices(ctx, c)
	if err != nil {
		return false, err
	}
	blocked, err := writeBlocks(ctx, c, names)
	if err != nil {
		return false, err
	}
	if !had {
		fz = freezeState{DatabaseID: db.ID, Port: port, Since: time.Now().UTC()}
		for _, n := range names {
			if blocked[n] {
				fz.Own = append(fz.Own, n)
			}
		}
	}
	var todo []string
	for _, n := range names {
		if blocked[n] {
			continue
		}
		todo = append(todo, n)
		// An index whose own block someone lifted is Rowsafe's to lift now.
		fz.Own = slices.DeleteFunc(fz.Own, func(s string) bool { return s == n })
		if !slices.Contains(fz.Blocked, n) {
			fz.Blocked = append(fz.Blocked, n)
		}
	}
	body, err := autoCreatePause(ctx, c, &fz.Auto)
	if err != nil {
		return false, err
	}
	// Recorded before anything changes: a stop halfway still knows what to
	// lift.
	fz.At = time.Now().UTC()
	if err := saveMoveState(env, "freeze", db.ID, fz); err != nil {
		return false, fmt.Errorf("recording the write block: %w", err)
	}
	if len(todo) > 0 {
		if err := setWriteBlock(ctx, c, todo, true); err != nil {
			return false, err
		}
	}
	if body != nil {
		if err := putClusterSettings(ctx, c, body); err != nil {
			return false, err
		}
	}
	switch {
	case !had:
		log.Printf("writes blocked on %d indices (%d already had a write block of their own, which stays), automatic index creation paused",
			len(todo), len(fz.Own))
	case len(todo) > 0 || body != nil:
		log.Printf("the write block was lifted or new indices appeared: blocked %d indices again", len(todo))
	}
	return had && (len(todo) > 0 || body != nil), nil
}

// SnapshotMoveThaw lifts the write blocks Rowsafe put (indices that had
// their own keep them) and puts automatic index creation back.
func (e *Engine) SnapshotMoveThaw(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) error {
	moveMu.Lock()
	defer moveMu.Unlock()
	fz, had := loadFreeze(env, db.ID)
	if !had {
		log.Printf("Rowsafe hadn't stopped writes to this database here: nothing to lift")
		return nil
	}
	port := db.Port
	if port == 0 {
		port = fz.Port
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return err
	}
	names, err := openIndices(ctx, c)
	if err != nil {
		return err
	}
	var lift []string
	for _, n := range fz.Blocked {
		if slices.Contains(names, n) {
			lift = append(lift, n)
		}
	}
	if len(lift) > 0 {
		if err := setWriteBlock(ctx, c, lift, false); err != nil {
			return err
		}
	}
	if err := autoCreateResume(ctx, c, fz.Auto); err != nil {
		return err
	}
	if err := removeMoveState(env, "freeze", db.ID); err != nil {
		return err
	}
	log.Printf("apps can write again: lifted the write block on %d indices, automatic index creation is as it was", len(lift))
	return nil
}

// SnapshotMoveTake takes the switchover's last snapshot through the normal
// backup path (the repository lock, the copy to the bucket, its record).
func (e *Engine) SnapshotMoveTake(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, log agent.TaskLogger) (agent.SnapshotRef, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	if why := blocker(in); why != "" {
		return agent.SnapshotRef{}, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	lock := e.repoLock(db)
	lock.Lock()
	defer lock.Unlock()
	t, err := e.take(ctx, env, db, c, r, in, kindFull, "", log)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	if g := t.Doc.Globals; g != nil && len(g.Missing) > 0 {
		log.Printf("note: %s", g.missingNote())
	}
	return agent.SnapshotRef{Label: t.Doc.Label, At: t.Doc.StoppedAt}, nil
}

// ---- index templates and ingest pipelines

// globalState is what a snapshot without the cluster's global state
// leaves out and apps need: ingest pipelines, component, index and legacy
// templates (OpenSearch's own, named with a dot, stay out). Recorded in
// the backup records taken while a move stopped writes.
type globalState struct {
	Pipelines          map[string]json.RawMessage `json:"pipelines,omitempty"`
	ComponentTemplates map[string]json.RawMessage `json:"component_templates,omitempty"`
	IndexTemplates     map[string]json.RawMessage `json:"index_templates,omitempty"`
	LegacyTemplates    map[string]json.RawMessage `json:"legacy_templates,omitempty"`
	// Missing names what couldn't be read (plain words).
	Missing []string `json:"missing,omitempty"`
}

func (g *globalState) missingNote() string {
	return "Rowsafe couldn't read the " + strings.Join(g.Missing, " and ") + " here (Rowsafe's OpenSearch role is from an older Rowsafe), " +
		"so they don't move: make them on the new server"
}

// Kinds of global objects, in the order a restore makes them.
var globalKinds = []struct {
	key, path, what string
	get             func(g *globalState) map[string]json.RawMessage
}{
	{"pipeline", "/_ingest/pipeline/", "ingest pipeline", func(g *globalState) map[string]json.RawMessage { return g.Pipelines }},
	{"component", "/_component_template/", "component template", func(g *globalState) map[string]json.RawMessage { return g.ComponentTemplates }},
	{"index", "/_index_template/", "index template", func(g *globalState) map[string]json.RawMessage { return g.IndexTemplates }},
	{"legacy", "/_template/", "legacy index template", func(g *globalState) map[string]json.RawMessage { return g.LegacyTemplates }},
}

// readGlobals reads the server's pipelines and templates.
func readGlobals(ctx context.Context, c *client) *globalState {
	g := &globalState{}
	keep := func(name string) bool { return name != "" && !strings.HasPrefix(name, ".") }
	missing := func(what string, err error) {
		if statusOf(err) != http.StatusNotFound {
			g.Missing = append(g.Missing, what)
		}
	}
	var pipes map[string]json.RawMessage
	if err := c.get(ctx, "/_ingest/pipeline", &pipes); err != nil {
		missing("ingest pipelines", err)
	}
	for k, v := range pipes {
		if keep(k) {
			if g.Pipelines == nil {
				g.Pipelines = map[string]json.RawMessage{}
			}
			g.Pipelines[k] = v
		}
	}
	var comp struct {
		Items []struct {
			Name string          `json:"name"`
			Body json.RawMessage `json:"component_template"`
		} `json:"component_templates"`
	}
	if err := c.get(ctx, "/_component_template", &comp); err != nil {
		missing("component templates", err)
	}
	for _, t := range comp.Items {
		if keep(t.Name) {
			if g.ComponentTemplates == nil {
				g.ComponentTemplates = map[string]json.RawMessage{}
			}
			g.ComponentTemplates[t.Name] = t.Body
		}
	}
	var idx struct {
		Items []struct {
			Name string          `json:"name"`
			Body json.RawMessage `json:"index_template"`
		} `json:"index_templates"`
	}
	if err := c.get(ctx, "/_index_template", &idx); err != nil {
		missing("index templates", err)
	}
	for _, t := range idx.Items {
		if keep(t.Name) {
			if g.IndexTemplates == nil {
				g.IndexTemplates = map[string]json.RawMessage{}
			}
			g.IndexTemplates[t.Name] = t.Body
		}
	}
	var legacy map[string]json.RawMessage
	if err := c.get(ctx, "/_template", &legacy); err != nil {
		missing("legacy index templates", err)
	}
	for k, v := range legacy {
		if keep(k) {
			if g.LegacyTemplates == nil {
				g.LegacyTemplates = map[string]json.RawMessage{}
			}
			g.LegacyTemplates[k] = v
		}
	}
	return g
}

// applyGlobals makes g's pipelines and templates on the new server: the
// ones a restore of this move made before are updated, ones the server has
// of its own are left as they are. What can't be made is said in the log;
// the restore goes on.
func applyGlobals(ctx context.Context, c *client, g *globalState, st *targetState, log agent.TaskLogger) {
	if g == nil {
		return
	}
	if len(g.Missing) > 0 {
		log.Printf("note: the old server's %s weren't recorded (its Rowsafe role is from an older Rowsafe): make them here", strings.Join(g.Missing, " and "))
	}
	if st.Made == nil {
		st.Made = map[string][]string{}
	}
	made, kept := 0, 0
	for _, k := range globalKinds {
		items := k.get(g)
		names := make([]string, 0, len(items))
		for n := range items {
			names = append(names, n)
		}
		slices.Sort(names)
		for _, n := range names {
			path := k.path + pathEscape(n)
			ours := slices.Contains(st.Made[k.key], n)
			if !ours {
				err := c.get(ctx, path, nil)
				if err == nil {
					kept++
					log.Printf("note: this server has an %s named %s of its own: it is kept, not replaced by the old server's", k.what, n)
					continue
				}
				if statusOf(err) != http.StatusNotFound {
					log.Printf("note: the %s %s wasn't made here (%v): make it on this server", k.what, n, roleErr(err, "read "+k.what+"s"))
					continue
				}
			}
			if err := c.do(ctx, http.MethodPut, path, items[n], nil); err != nil {
				log.Printf("note: the %s %s couldn't be made here (%v): make it on this server", k.what, n, roleErr(err, "make "+k.what+"s"))
				continue
			}
			if !ours {
				st.Made[k.key] = append(st.Made[k.key], n)
			}
			made++
		}
	}
	if made > 0 || kept > 0 {
		log.Printf("made %d index templates and ingest pipelines as on the old server", made)
	}
}

// removeGlobals deletes the pipelines and templates the move made
// (templates first: they may name pipelines and component templates).
func removeGlobals(ctx context.Context, c *client, st *targetState) error {
	for i := len(globalKinds) - 1; i >= 0; i-- {
		k := globalKinds[i]
		for _, n := range st.Made[k.key] {
			err := c.do(ctx, http.MethodDelete, k.path+pathEscape(n), nil, nil)
			if err != nil && statusOf(err) != http.StatusNotFound {
				return fmt.Errorf("removing the %s %s: %w", k.what, n, roleErr(err, "remove "+k.what+"s"))
			}
		}
		delete(st.Made, k.key)
	}
	return nil
}

// ---- the bucket's newest snapshot

// newestSnapshot is the newest snapshot recorded in the folder (not one
// kept for an Undo: it holds data as it was before a rewind).
func newestSnapshot(ctx context.Context, r *repo) (agent.SnapshotRef, backupDoc, error) {
	var doc backupDoc
	objs, err := r.st.List(ctx, docsPrefix)
	if err != nil {
		return agent.SnapshotRef{}, doc, fmt.Errorf("listing your bucket: %w", err)
	}
	best := ""
	for _, o := range objs {
		l := strings.TrimSuffix(strings.TrimPrefix(o.Key, docsPrefix), ".json")
		if !labelRE.MatchString(l) || labelKind(l) == kindRewind {
			continue
		}
		if best == "" || labelTime(l).After(labelTime(best)) || labelTime(l).Equal(labelTime(best)) && l > best {
			best = l
		}
	}
	if best == "" {
		return agent.SnapshotRef{}, doc, nil
	}
	if err := r.getJSON(ctx, docKey(best), &doc); err != nil {
		return agent.SnapshotRef{}, doc, fmt.Errorf("reading the record of snapshot %s: %w", best, err)
	}
	return agent.SnapshotRef{Label: best, At: doc.StoppedAt}, doc, nil
}

// SnapshotMoveNewest is the newest snapshot of db in its bucket folder.
func (e *Engine) SnapshotMoveNewest(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (agent.SnapshotRef, error) {
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	ref, _, err := newestSnapshot(ctx, r)
	return ref, err
}

// seriesOf is a version's protocol.SeriesNumber ("3.2.0" -> 302).
func seriesOf(version string) int {
	p := strings.SplitN(version, ".", 3)
	if len(p) < 2 {
		return 0
	}
	minor := p[1]
	for i, r := range minor {
		if r < '0' || r > '9' {
			minor = minor[:i]
			break
		}
	}
	return protocol.SeriesNumber(p[0] + "." + minor)
}

// SnapshotMoveSource describes the database on the old server.
func (e *Engine) SnapshotMoveSource(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (agent.SnapshotMoveSource, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return agent.SnapshotMoveSource{}, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return agent.SnapshotMoveSource{}, err
	}
	if why := blocker(in); why != "" {
		return agent.SnapshotMoveSource{}, errors.New(why)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotMoveSource{}, err
	}
	newest, _, err := newestSnapshot(ctx, r)
	if err != nil {
		return agent.SnapshotMoveSource{}, fmt.Errorf("reading the snapshots in your bucket: %w", err)
	}
	return agent.SnapshotMoveSource{Major: seriesOf(in.Version), Version: in.Version, SystemID: in.ClusterUUID,
		SizeBytes: in.totalBytes(), Newest: newest}, nil
}

// ---- on the new server

// targetState is what a move put into the new server
// (<state>/moves/target-<database id>.json).
type targetState struct {
	DatabaseID string    `json:"database_id"`
	Stanza     string    `json:"stanza"`
	Port       int       `json:"port"`
	Dir        string    `json:"dir"` // the snapshot folder the bucket's repository is copied into
	CreatedAt  time.Time `json:"created_at"`
	Label      string    `json:"label,omitempty"` // the snapshot restored
	// Indices and DataStreams are what the restores made.
	Indices     []string `json:"indices,omitempty"`
	DataStreams []string `json:"data_streams,omitempty"`
	// Made are the pipelines and templates the move made, by kind.
	Made map[string][]string `json:"made,omitempty"`
	Auto autoPrev            `json:"auto_create"`
}

// writable reports whether the agent may write into dir.
func writable(dir string) bool { return syscall.Access(dir, 0x2|0x1) == nil } // W_OK|X_OK

// errNotWritable: the snapshot folder isn't the agent's to write into.
func errNotWritable(dir string) error {
	return fmt.Errorf("Rowsafe can't write into OpenSearch's snapshot folder %s on this server, where it copies the snapshots it receives: "+
		"run the Rowsafe installer on this server with --move-target", dir)
}

// targetReason says why the server can't receive a database ("" when it
// can).
func targetReason(in serverInfo) string {
	if why := in.supported(); why != "" {
		return why
	}
	if len(in.Indices) > 0 || len(in.DataStreams) > 0 {
		return "it holds data: only an empty server can receive a database"
	}
	dir, err := repoDir(in)
	if err != nil {
		return "OpenSearch doesn't allow snapshots in Rowsafe's folder there yet: run the Rowsafe installer on this server with --move-target (OpenSearch then needs one restart)"
	}
	files, err := localRepoFiles(dir)
	if err != nil {
		return "Rowsafe can't read its snapshot folder " + dir + " there: run the Rowsafe installer on this server with --move-target"
	}
	if len(files) > 0 {
		return "Rowsafe's snapshot folder there (" + dir + ") already holds snapshots: only a server Rowsafe never backed up can receive a database"
	}
	if !writable(dir) {
		return "Rowsafe can't write into its snapshot folder there: run the Rowsafe installer on this server with --move-target"
	}
	return ""
}

var (
	targetsMu    sync.Mutex
	targetsAt    time.Time
	targetsCache []protocol.StandbyTarget
)

// StandbyTargets are the OpenSearch servers here that can receive a
// database: empty, Rowsafe signs in, path.repo allows Rowsafe's folder and
// the agent may write into it (cached a minute: it connects to each).
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() {
		return nil
	}
	targetsMu.Lock()
	defer targetsMu.Unlock()
	if time.Since(targetsAt) < time.Minute {
		return slices.Clone(targetsCache)
	}
	var out []protocol.StandbyTarget
	seen := map[int]bool{}
	for _, p := range findServers() {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		out = append(out, targetOf(ctx, env, p.Port, installedVersion(p.Home)))
	}
	targetsAt, targetsCache = time.Now(), out
	return slices.Clone(out)
}

// targetOf describes the server on port as a place to receive a database.
func targetOf(ctx context.Context, env agent.EngineEnv, port int, version string) protocol.StandbyTarget {
	t := protocol.StandbyTarget{Engine: protocol.EngineOpenSearch, Port: port, Version: version}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, ok, err := loadLogin(env, port); err != nil || !ok {
		t.Reason = "Rowsafe has no login there: run the Rowsafe installer on this server with --move-target"
	} else if c, err := connectPort(cctx, env, port); err != nil {
		t.Reason = "Rowsafe can't sign in there (" + strings.TrimSuffix(err.Error(), ".") + ")"
	} else if in, err := inspect(cctx, c); err != nil {
		t.Reason = "Rowsafe can't read the server (" + strings.TrimSuffix(err.Error(), ".") + ")"
	} else {
		t.Version = in.Version
		t.Reason = targetReason(in)
	}
	t.Usable, t.Standby, t.NoStandby = t.Reason == "", t.Reason == "", t.Reason
	return t
}

// SnapshotMoveRestore copies the bucket's repository into the server's
// snapshot folder and restores snapshot label from it, replacing what an
// earlier restore of this move put there.
func (e *Engine) SnapshotMoveRestore(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, label string,
	o agent.SnapshotMoveRestoreOptions, log agent.TaskLogger) (agent.SnapshotRef, error) {
	if !labelRE.MatchString(label) {
		return agent.SnapshotRef{}, fmt.Errorf("invalid snapshot label %q", label)
	}
	moveMu.Lock()
	var st targetState
	had, err := loadMoveState(env, "target", db.ID, &st)
	moveMu.Unlock()
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	if !had && !o.First {
		return agent.SnapshotRef{}, fmt.Errorf("this server holds no copy of %s to bring up to date", db.Name)
	}
	if had && st.Port != port {
		return agent.SnapshotRef{}, fmt.Errorf("the copy of %s is on port %d here, not %d", db.Name, st.Port, port)
	}
	// refuse: a first restore that stops before changing anything says so
	// (agent.ErrMoveRefused), so nothing is cleared after it.
	refuse := func(err error) error {
		if had {
			return err
		}
		return fmt.Errorf("%w; %w", err, agent.ErrMoveRefused)
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return agent.SnapshotRef{}, refuse(err)
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return agent.SnapshotRef{}, refuse(err)
	}
	r, err := openRepo(env, db)
	if err != nil {
		return agent.SnapshotRef{}, refuse(err)
	}
	var doc backupDoc
	if err := r.getJSON(ctx, docKey(label), &doc); err != nil {
		if errors.Is(err, objstore.ErrNotFound) {
			return agent.SnapshotRef{}, refuse(fmt.Errorf("snapshot %s isn't in your bucket any more (retention removed it?)", label))
		}
		return agent.SnapshotRef{}, refuse(fmt.Errorf("reading the record of snapshot %s in your bucket: %w", label, err))
	}
	if why := in.supported(); why != "" {
		return agent.SnapshotRef{}, refuse(errors.New(why))
	}
	need := max(o.Major, seriesOf(doc.Version))
	if have := seriesOf(in.Version); need > 0 && have < need {
		return agent.SnapshotRef{}, refuse(fmt.Errorf("OpenSearch on port %d is %s, older than the database's OpenSearch %s: snapshots restore only into the same "+
			"version or a newer one. Upgrade OpenSearch on this server first", port, in.Version, protocol.SeriesString(need)))
	}
	if !had {
		if why := targetReason(in); why != "" {
			return agent.SnapshotRef{}, refuse(fmt.Errorf("OpenSearch on port %d can't receive %s: %s", port, db.Name, why))
		}
		dir, _ := repoDir(in)
		st = targetState{DatabaseID: db.ID, Stanza: db.Stanza, Port: port, Dir: dir, CreatedAt: time.Now().UTC()}
	}
	if !writable(st.Dir) {
		return agent.SnapshotRef{}, refuse(errNotWritable(st.Dir))
	}
	save := func() error {
		moveMu.Lock()
		defer moveMu.Unlock()
		return saveMoveState(env, "target", db.ID, st)
	}
	// Nothing recreates the indices while they are replaced, and apps
	// pointed here early can't make new ones before the switchover.
	body, err := autoCreatePause(ctx, c, &st.Auto)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	if err := save(); err != nil {
		return agent.SnapshotRef{}, fmt.Errorf("recording the move: %w", err)
	}
	if body != nil {
		if err := putClusterSettings(ctx, c, body); err != nil {
			return agent.SnapshotRef{}, err
		}
	}

	log.Printf("copying the repository in your bucket into %s on this server (only what is new), decrypting it here", st.Dir)
	n, files, err := r.mirror(ctx, st.Dir, doc.SizeBytes, in.DataPath)
	if err != nil {
		return agent.SnapshotRef{}, err
	}
	log.Printf("copied %d files (%s)", files, humanBytes(n))
	if err := registerRepo(ctx, c, st.Dir, true); err != nil {
		return agent.SnapshotRef{}, err
	}
	name := snapshotName(label)
	var got struct {
		Snapshots []snapInfo `json:"snapshots"`
	}
	if err := c.get(ctx, "/_snapshot/"+repoName+"/"+name, &got); err != nil || len(got.Snapshots) == 0 {
		if err == nil || statusOf(err) == http.StatusNotFound || errType(err) == "snapshot_missing_exception" {
			return agent.SnapshotRef{}, fmt.Errorf("snapshot %s isn't in the repository copied from your bucket (retention removed it?)", label)
		}
		return agent.SnapshotRef{}, fmt.Errorf("reading the copied snapshots: %w", err)
	}
	snap := got.Snapshots[0]
	if snap.State != "SUCCESS" {
		return agent.SnapshotRef{}, fmt.Errorf("snapshot %s didn't complete on the old server (%s)", label, snap.State)
	}

	applyGlobals(ctx, c, doc.Globals, &st, log)
	if err := save(); err != nil {
		return agent.SnapshotRef{}, err
	}
	if len(st.Indices) > 0 || len(st.DataStreams) > 0 {
		log.Printf("removing what the previous restore (snapshot %s) put here", st.Label)
		if err := removeRestored(ctx, c, &st); err != nil {
			return agent.SnapshotRef{}, err
		}
		if err := save(); err != nil {
			return agent.SnapshotRef{}, err
		}
	}
	var indices []string
	for _, i := range snap.Indices {
		if i != noIndex {
			indices = append(indices, i)
		}
	}
	// What the restore makes must not be there now: an index or data
	// stream of the same name is this server's own (the move's were just
	// removed), and is never replaced or recorded as the move's.
	if len(indices) > 0 {
		cur, curDS, err := listIndices(ctx, c)
		if err != nil {
			return agent.SnapshotRef{}, err
		}
		for _, i := range cur {
			if slices.Contains(indices, i.Name) {
				return agent.SnapshotRef{}, fmt.Errorf("this server has an index named %s of its own now, so the restore stops (Rowsafe doesn't replace it): remove or rename it here, then try again", i.Name)
			}
		}
		for _, d := range curDS {
			if slices.Contains(snap.DataStreams, d) {
				return agent.SnapshotRef{}, fmt.Errorf("this server has a data stream named %s of its own now, so the restore stops (Rowsafe doesn't replace it): remove or rename it here, then try again", d)
			}
		}
	}
	// Recorded first: a restore that stops halfway is removed all the same.
	st.Indices, st.DataStreams, st.Label = indices, slices.Clone(snap.DataStreams), ""
	if err := save(); err != nil {
		return agent.SnapshotRef{}, err
	}
	if len(indices) > 0 {
		log.Printf("restoring snapshot %s: %d indices, %d data streams", label, len(indices), len(snap.DataStreams))
		req := map[string]any{"indices": "*", "include_global_state": false, "include_aliases": true, "ignore_unavailable": true}
		var res struct {
			Snapshot struct {
				Shards struct{ Total, Failed int } `json:"shards"`
			} `json:"snapshot"`
		}
		if err := c.do(ctx, http.MethodPost, "/_snapshot/"+repoName+"/"+name+"/_restore?wait_for_completion=true", req, &res); err != nil {
			return agent.SnapshotRef{}, fmt.Errorf("restoring snapshot %s: %w", label, roleErr(err, "restore snapshots"))
		}
		if res.Snapshot.Shards.Failed > 0 {
			return agent.SnapshotRef{}, fmt.Errorf("restoring snapshot %s: %d of %d shards failed", label, res.Snapshot.Shards.Failed, res.Snapshot.Shards.Total)
		}
		var h struct {
			Status string `json:"status"`
		}
		if err := c.get(ctx, "/_cluster/health?wait_for_status=yellow&timeout=10m", &h); err != nil {
			return agent.SnapshotRef{}, err
		}
		if h.Status == "red" {
			return agent.SnapshotRef{}, errors.New("OpenSearch is red after the restore (some data can't be read)")
		}
		// The old server's write block from the switchover isn't this
		// server's: lifted (indices' own blocks stay).
		var lift []string
		for _, i := range doc.MoveBlocked {
			if slices.Contains(indices, i) {
				lift = append(lift, i)
			}
		}
		if len(lift) > 0 {
			if err := setWriteBlock(ctx, c, lift, false); err != nil {
				return agent.SnapshotRef{}, err
			}
		}
	}
	st.Label = label
	if err := save(); err != nil {
		return agent.SnapshotRef{}, err
	}
	at := doc.StoppedAt
	if at.IsZero() {
		at = snap.end()
	}
	log.Printf("snapshot %s (taken %s) is restored on port %d", label, at.UTC().Format("2006-01-02 15:04:05 UTC"), port)
	return agent.SnapshotRef{Label: label, At: at}, nil
}

// removeRestored deletes the data streams and indices a restore made.
func removeRestored(ctx context.Context, c *client, st *targetState) error {
	for _, ds := range st.DataStreams {
		if err := c.do(ctx, http.MethodDelete, "/_data_stream/"+pathEscape(ds), nil, nil); err != nil && statusOf(err) != http.StatusNotFound {
			return fmt.Errorf("removing the data stream %s: %w", ds, roleErr(err, "remove data streams"))
		}
	}
	for _, list := range nameChunks(st.Indices) {
		err := c.do(ctx, http.MethodDelete, "/"+list+"?ignore_unavailable=true&expand_wildcards=all", nil, nil)
		if err != nil && statusOf(err) != http.StatusNotFound {
			return fmt.Errorf("removing the restored indices: %w", roleErr(err, "remove indices"))
		}
	}
	st.Indices, st.DataStreams = nil, nil
	return nil
}

// registerRepo registers Rowsafe's repository at dir again (read-only
// while the server receives: OpenSearch only reads it then).
func registerRepo(ctx context.Context, c *client, dir string, readonly bool) error {
	if err := c.do(ctx, http.MethodDelete, "/_snapshot/"+repoName, nil, nil); err != nil && statusOf(err) != http.StatusNotFound &&
		errType(err) != "repository_missing_exception" {
		return fmt.Errorf("setting up Rowsafe's snapshot repository in OpenSearch: %w", roleErr(err, "change snapshot repositories"))
	}
	settings := map[string]any{"location": dir, "compress": true}
	if readonly {
		settings["readonly"] = true
	}
	if err := c.do(ctx, http.MethodPut, "/_snapshot/"+repoName, map[string]any{"type": "fs", "settings": settings}, nil); err != nil {
		if strings.Contains(err.Error(), "path.repo") || strings.Contains(err.Error(), "doesn't match any of the locations") {
			return fmt.Errorf("%w: OpenSearch doesn't allow snapshots in %s yet (path.repo): run the Rowsafe installer on this server with --move-target; OpenSearch then needs one restart", errNoRepoPath, dir)
		}
		return fmt.Errorf("setting up Rowsafe's snapshot repository in OpenSearch: %w", roleErr(err, "change snapshot repositories"))
	}
	return nil
}

// SnapshotMovePromote makes the server the database's own: Rowsafe's
// repository there takes snapshots (it holds the bucket's), the bucket
// folder is this cluster's now, and apps may create indices again.
func (e *Engine) SnapshotMovePromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, log agent.TaskLogger) error {
	moveMu.Lock()
	var st targetState
	had, err := loadMoveState(env, "target", db.ID, &st)
	moveMu.Unlock()
	if err != nil {
		return err
	}
	if !had {
		return fmt.Errorf("this server holds no copy of %s to switch over to", db.Name)
	}
	if st.Label == "" {
		return fmt.Errorf("the last restore of %s here didn't finish, so this server doesn't hold a whole copy to switch over to", db.Name)
	}
	if port == 0 {
		port = st.Port
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	if in.ClusterUUID == "" {
		return errors.New("OpenSearch here doesn't say which cluster it is, so Rowsafe can't take the bucket folder over")
	}
	if err := registerRepo(ctx, c, st.Dir, false); err != nil {
		return err
	}
	if err := checkRepoReadable(st.Dir); err != nil {
		return err
	}
	snaps, err := listSnapshots(ctx, c)
	if err != nil {
		return fmt.Errorf("reading the snapshots here: %w", err)
	}
	if !slices.ContainsFunc(snaps, func(s snapInfo) bool { return s.Snapshot == snapshotName(st.Label) }) {
		return fmt.Errorf("OpenSearch here doesn't see snapshot %s in Rowsafe's repository", st.Label)
	}
	if db.Stanza == "" {
		db.Stanza = st.Stanza
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	if err := takeFolder(ctx, r, db.Name, in.ClusterUUID); err != nil {
		return err
	}
	log.Printf("the bucket folder is this server's now: its backups go on there, with the %d snapshots from before (Rewind and Proof use them)", len(snaps))
	if err := autoCreateResume(ctx, c, st.Auto); err != nil {
		return err
	}
	moveMu.Lock()
	defer moveMu.Unlock()
	return removeMoveState(env, "target", db.ID)
}

// takeFolder moves the bucket folder's marker to cluster: the old server
// copies nothing into it from now on (errOtherCluster).
func takeFolder(ctx context.Context, r *repo, name, cluster string) error {
	var m marker
	switch err := r.getJSON(ctx, markerKey, &m); {
	case errors.Is(err, objstore.ErrNotFound):
		m = marker{Engine: protocol.EngineOpenSearch, Database: name, CreatedAt: time.Now().UTC()}
	case err != nil:
		return fmt.Errorf("reading your bucket: %w", err)
	case m.Engine != protocol.EngineOpenSearch:
		return fmt.Errorf("the bucket folder holds %s backups", protocol.EngineDisplayName(m.Engine))
	}
	if m.ClusterUUID == cluster {
		return nil
	}
	m.ClusterUUID = cluster
	if err := r.putJSON(ctx, markerKey, m); err != nil {
		return fmt.Errorf("writing to your bucket: %w", err)
	}
	return nil
}

// SnapshotMoveClear removes what the move put into the server: the
// restored indices and data streams, the pipelines and templates it made,
// the copied repository and its registration. The server is empty again.
func (e *Engine) SnapshotMoveClear(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, port int, log agent.TaskLogger) error {
	moveMu.Lock()
	var st targetState
	had, err := loadMoveState(env, "target", db.ID, &st)
	moveMu.Unlock()
	if err != nil {
		return err
	}
	if !had {
		log.Printf("nothing of this move is on this server")
		return nil
	}
	if port == 0 {
		port = st.Port
	}
	c, err := connectPort(ctx, env, port)
	if err != nil {
		return err
	}
	n := len(st.Indices)
	if err := removeRestored(ctx, c, &st); err != nil {
		return err
	}
	if err := removeGlobals(ctx, c, &st); err != nil {
		return err
	}
	if err := c.do(ctx, http.MethodDelete, "/_snapshot/"+repoName, nil, nil); err != nil && statusOf(err) != http.StatusNotFound &&
		errType(err) != "repository_missing_exception" {
		return fmt.Errorf("removing Rowsafe's snapshot repository from OpenSearch: %w", roleErr(err, "change snapshot repositories"))
	}
	if st.Dir != "" {
		if err := emptyDir(st.Dir); err != nil {
			return fmt.Errorf("removing the copied snapshots from %s: %w", st.Dir, err)
		}
	}
	if err := autoCreateResume(ctx, c, st.Auto); err != nil {
		return err
	}
	moveMu.Lock()
	defer moveMu.Unlock()
	if err := removeMoveState(env, "target", db.ID); err != nil {
		return err
	}
	log.Printf("removed %d restored indices and the copied snapshots: OpenSearch on port %d is empty again", n, port)
	return nil
}

// emptyDir removes what is in dir (the folder stays: it is OpenSearch's).
func emptyDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// ---- copying the bucket's repository into a snapshot folder

// mirror makes dir a copy of the bucket's repository: files it lacks (or
// holds with another size) come down, index.latest last, so OpenSearch
// always sees a whole repository; files the bucket no longer has go. The
// folder is OpenSearch's (it takes the snapshots there after the
// switchover): folders are made group-writable (OpenSearch's group) and
// files group-readable. It returns the plain bytes and files copied.
func (r *repo) mirror(ctx context.Context, dir string, restoreBytes int64, dataPaths []string) (int64, int, error) {
	// The generation first: everything it names went up before it.
	latest, err := r.st.GetBytes(ctx, repoPrefix+"index.latest")
	if err != nil {
		if errors.Is(err, objstore.ErrNotFound) {
			return 0, 0, errors.New("your bucket holds no snapshot repository for this database yet")
		}
		return 0, 0, fmt.Errorf("reading your bucket: %w", err)
	}
	latestPlain, err := r.open(latest)
	if err != nil {
		return 0, 0, fmt.Errorf("reading the repository's index.latest: %w", err)
	}
	objs, err := r.st.List(ctx, repoPrefix)
	if err != nil {
		return 0, 0, fmt.Errorf("listing your bucket: %w", err)
	}
	local := map[string]int64{}
	files, err := localRepoFiles(dir)
	if err != nil {
		return 0, 0, err
	}
	for _, f := range files {
		local[f.Rel] = f.Size
	}
	remote := map[string]bool{}
	var todo []string
	var need int64
	for _, o := range objs {
		rel := strings.TrimPrefix(o.Key, repoPrefix)
		if !safeRel(rel) {
			return 0, 0, fmt.Errorf("unexpected file %q in your bucket", rel)
		}
		remote[rel] = true
		if rel == "index.latest" {
			continue
		}
		if size, ok := local[rel]; ok && objstore.SealedSize(size) == o.Size {
			continue
		}
		todo = append(todo, rel)
		need += o.Size
	}
	if err := ensureSpace(dir, need+64<<20, "the snapshots copied from your bucket"); err != nil {
		return 0, 0, err
	}
	if len(dataPaths) > 0 && restoreBytes > 0 {
		if err := ensureSpace(dataPaths[0], restoreBytes, "the restored data"); err != nil {
			return 0, 0, err
		}
	}
	var mu sync.Mutex
	var total int64
	var firstErr error
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, rel := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			n, err := r.fetchShared(ctx, dir, rel)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = fmt.Errorf("copying %s from your bucket: %w", rel, err)
			}
			total += n
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return total, len(todo), firstErr
	}
	if err := writeShared(dir, "index.latest", bytes.NewReader(latestPlain)); err != nil {
		return total, len(todo), fmt.Errorf("writing index.latest: %w", err)
	}
	// What the bucket no longer holds (snapshots retention removed there).
	for rel := range local {
		if !remote[rel] {
			if err := os.Remove(filepath.Join(dir, filepath.FromSlash(rel))); err != nil && !errors.Is(err, os.ErrNotExist) {
				return total, len(todo), fmt.Errorf("removing %s: %w", rel, err)
			}
		}
	}
	return total + int64(len(latestPlain)), len(todo) + 1, nil
}

// open decrypts a sealed object.
func (r *repo) open(sealed []byte) ([]byte, error) {
	pr, err := objstore.Open(bytes.NewReader(sealed), r.pass)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(pr)
}

// safeRel: a relative path inside the repository.
func safeRel(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, "\\") {
		return false
	}
	for _, p := range strings.Split(rel, "/") {
		if p == "" || p == "." || p == ".." {
			return false
		}
	}
	return true
}

// fetchShared downloads repo/rel into dir/rel (see writeShared).
func (r *repo) fetchShared(ctx context.Context, dir, rel string) (int64, error) {
	rc, err := r.st.Get(ctx, repoPrefix+rel)
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	pr, err := objstore.Open(rc, r.pass)
	if err != nil {
		return 0, err
	}
	cr := &countReader{r: pr}
	err = writeShared(dir, rel, cr)
	return cr.n, err
}

type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// writeShared writes src to dir/rel through a temporary file: folders it
// makes are group-writable with the folder's group (OpenSearch writes and
// deletes there after the switchover), the file group-readable.
func writeShared(dir, rel string, src io.Reader) error {
	if !safeRel(rel) {
		return fmt.Errorf("unexpected file %q", rel)
	}
	parts := strings.Split(rel, "/")
	p := dir
	for _, d := range parts[:len(parts)-1] {
		p = filepath.Join(p, d)
		switch err := os.Mkdir(p, 0o770); {
		case err == nil:
			if err := os.Chmod(p, 0o770|os.ModeSetgid); err != nil {
				return err
			}
		case errors.Is(err, os.ErrExist):
			if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
				return fmt.Errorf("%s isn't a folder", p)
			}
		default:
			return err
		}
	}
	dst := filepath.Join(dir, filepath.FromSlash(rel))
	tmp := dst + ".rowsafe-tmp"
	_ = os.Remove(tmp)
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, err = io.Copy(fh, src)
	if err == nil {
		err = fh.Chmod(0o640)
	}
	if cerr := fh.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}
