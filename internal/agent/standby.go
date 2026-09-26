package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/handoff"
	"github.com/rowsafe/rowsafe/internal/pgbackrest"
	"github.com/rowsafe/rowsafe/protocol"
)

// Standby: a second server that follows the primary and can take over.
//
// This file holds what the agent keeps between tasks: its X25519 key pair
// (<state dir>/box.key), the standbys it runs, the fences it holds, what it
// knows about the clusters it is the primary of, and the bucket settings a
// primary handed over (<state dir>/standby/, all 0600). The tasks live in
// standby_primary.go (prepare, release), standby_create.go (create,
// rebuild, remove), standby_promote.go and standby_fence.go.

// standbyIDRE is the shape of standby and fence IDs.
var standbyIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Standby timings (variables for tests).
var (
	standbyTick        = 5 * time.Second  // fence enforcement and primary checks
	fenceRetry         = 20 * time.Second // between two stops of a fenced cluster
	standbyReadyWait   = time.Hour        // a started standby accepting connections
	standbyPromoteWait = 3 * time.Minute  // replaying the old primary's last WAL
	reattachWait       = 3 * time.Minute  // a reattached old primary following the new timeline
)

// standbyRecord is a standby this server runs.
type standbyRecord struct {
	ID         string                `json:"id"`
	DatabaseID string                `json:"database_id"`
	Database   protocol.DatabaseSpec `json:"database"` // Port and SocketDir are this server's cluster
	Phase      string                `json:"phase"`    // protocol.StandbyPhase*
	// Step is standby_create's progress (phase* in rewind_state.go), so a
	// restarted agent can put the cluster's own data back.
	Step       string    `json:"step,omitempty"`
	DataDir    string    `json:"data_dir"`
	KeptDir    string    `json:"kept_dir,omitempty"`   // the cluster's own data, put back on removal
	FailedDir  string    `json:"failed_dir,omitempty"` // a half-restored directory being removed
	Major      int       `json:"major"`
	ConfigFile string    `json:"config_file,omitempty"`
	HbaFile    string    `json:"hba_file,omitempty"`
	IdentFile  string    `json:"ident_file,omitempty"`
	Mode       string    `json:"mode,omitempty"`
	Address    string    `json:"primary_address,omitempty"` // for streaming
	PrimPort   int       `json:"primary_port,omitempty"`
	Role       string    `json:"replication_role,omitempty"`
	Rebuild    bool      `json:"rebuild,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// fenceRecord is a fence this server holds.
type fenceRecord struct {
	protocol.Fence
	DataDir   string     `json:"data_dir,omitempty"`
	Major     int        `json:"major,omitempty"`
	StoppedAt *time.Time `json:"stopped_at,omitempty"`
	Running   bool       `json:"running,omitempty"`
	Other     bool       `json:"other,omitempty"`
	LastError string     `json:"last_error,omitempty"`
	LastTry   time.Time  `json:"last_try,omitzero"`
}

// clusterFacts is what the agent remembers of a cluster it is the primary
// of, so a fence can find its data directory while PostgreSQL is down.
type clusterFacts struct {
	DataDir    string `json:"data_dir"`
	Major      int    `json:"major"`
	SystemID   string `json:"system_id,omitempty"`
	ConfigFile string `json:"config_file,omitempty"`
	HbaFile    string `json:"hba_file,omitempty"`
	IdentFile  string `json:"ident_file,omitempty"`
}

// keptData is a data directory set aside by a rebuild (the old primary's
// data, with anything it accepted after the promotion), deleted at Until.
type keptData struct {
	Path       string    `json:"path"`
	DataDir    string    `json:"data_dir"`
	DatabaseID string    `json:"database_id"`
	Until      time.Time `json:"until"`
}

type standbyFile struct {
	Standbys []*standbyRecord `json:"standbys"`
	Fences   []*fenceRecord   `json:"fences"`
	// Released are fence IDs lifted on this server (by a rebuild): a stale
	// heartbeat answer must never put them back.
	Released []string                `json:"released,omitempty"`
	Clusters map[string]clusterFacts `json:"clusters,omitempty"` // by database ID
	Kept     []keptData              `json:"kept,omitempty"`
}

// standbyRuntime is the agent's Standby state.
type standbyRuntime struct {
	key *handoff.KeyPair // nil when it couldn't be loaded

	mu   sync.Mutex
	dir  string
	file standbyFile

	// opMu is held by create, promote and remove: one at a time.
	opMu sync.Mutex

	// In memory only: when each standby last saw streaming, and since
	// when its primary doesn't answer.
	streamingSeen    map[string]time.Time
	unreachableSince map[string]time.Time
}

func (a *Agent) standbyDir() string { return filepath.Join(a.cfg.StateDir, "standby") }

// sb returns the Standby runtime, loading it on first use.
func (a *Agent) sb() *standbyRuntime {
	a.sbOnce.Do(func() {
		rt := &standbyRuntime{dir: a.standbyDir(), streamingSeen: map[string]time.Time{}, unreachableSince: map[string]time.Time{}}
		if err := os.MkdirAll(rt.dir, 0o700); err != nil {
			a.log.Warn("standby state directory", "err", err)
		}
		if data, err := os.ReadFile(filepath.Join(rt.dir, "state.json")); err == nil {
			if err := json.Unmarshal(data, &rt.file); err != nil {
				a.log.Error("reading the standby state; standbys and fences on this server are not known until fixed", "err", err)
			}
		}
		if rt.file.Clusters == nil {
			rt.file.Clusters = map[string]clusterFacts{}
		}
		if err := os.MkdirAll(a.cfg.StateDir, 0o700); err == nil {
			k, err := handoff.LoadOrCreate(filepath.Join(a.cfg.StateDir, "box.key"))
			if err != nil {
				a.log.Error("the agent's key for sealed handoffs can't be loaded; standbys can't be set up with this server", "err", err)
			} else {
				rt.key = k
				fp, _ := handoff.Fingerprint(k.PublicKey())
				a.log.Info("agent key loaded", "fingerprint", fp)
			}
		}
		a.sbRT = rt
	})
	return a.sbRT
}

// saveLocked persists the state; the caller holds mu.
func (rt *standbyRuntime) saveLocked() error {
	data, err := json.MarshalIndent(rt.file, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(rt.dir, "state.json"), data, 0o600)
}

func (rt *standbyRuntime) update(fn func(f *standbyFile)) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	fn(&rt.file)
	return rt.saveLocked()
}

func (rt *standbyRuntime) standby(id string) (standbyRecord, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, r := range rt.file.Standbys {
		if r.ID == id {
			return *r, true
		}
	}
	return standbyRecord{}, false
}

func (rt *standbyRuntime) putStandby(r standbyRecord) error {
	return rt.update(func(f *standbyFile) {
		for i, x := range f.Standbys {
			if x.ID == r.ID {
				f.Standbys[i] = &r
				return
			}
		}
		f.Standbys = append(f.Standbys, &r)
	})
}

func (rt *standbyRuntime) removeStandby(id string) error {
	return rt.update(func(f *standbyFile) {
		f.Standbys = slices.DeleteFunc(f.Standbys, func(r *standbyRecord) bool { return r.ID == id })
	})
}

func (rt *standbyRuntime) standbys() []standbyRecord {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]standbyRecord, 0, len(rt.file.Standbys))
	for _, r := range rt.file.Standbys {
		out = append(out, *r)
	}
	return out
}

func (rt *standbyRuntime) fences() []fenceRecord {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	out := make([]fenceRecord, 0, len(rt.file.Fences))
	for _, f := range rt.file.Fences {
		out = append(out, *f)
	}
	return out
}

// addFence starts holding a fence (unless it was released here).
func (rt *standbyRuntime) addFence(f fenceRecord) error {
	return rt.update(func(sf *standbyFile) {
		if slices.Contains(sf.Released, f.ID) {
			return
		}
		for i, x := range sf.Fences {
			if x.ID == f.ID {
				if f.DataDir == "" {
					f.DataDir, f.Major = x.DataDir, x.Major
				}
				if f.StoppedAt == nil {
					f.StoppedAt = x.StoppedAt
				}
				sf.Fences[i] = &f
				return
			}
		}
		sf.Fences = append(sf.Fences, &f)
	})
}

func (rt *standbyRuntime) hasFence(id string) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return slices.ContainsFunc(rt.file.Fences, func(f *fenceRecord) bool { return f.ID == id })
}

func (rt *standbyRuntime) updateFence(id string, fn func(f *fenceRecord)) {
	_ = rt.update(func(sf *standbyFile) {
		for _, f := range sf.Fences {
			if f.ID == id {
				fn(f)
			}
		}
	})
}

// releaseFence stops holding a fence, for good.
func (rt *standbyRuntime) releaseFence(id string) error {
	return rt.update(func(sf *standbyFile) {
		sf.Fences = slices.DeleteFunc(sf.Fences, func(f *fenceRecord) bool { return f.ID == id })
		if !slices.Contains(sf.Released, id) {
			sf.Released = append(sf.Released, id)
			if len(sf.Released) > 200 {
				sf.Released = sf.Released[len(sf.Released)-200:]
			}
		}
	})
}

// setFences replaces the fences with what the control plane says (a
// heartbeat answer): new ones are added, lifted ones dropped. Released IDs
// never come back.
func (rt *standbyRuntime) setFences(want []protocol.Fence) {
	_ = rt.update(func(sf *standbyFile) {
		keep := sf.Fences[:0]
		for _, f := range sf.Fences {
			if slices.ContainsFunc(want, func(w protocol.Fence) bool { return w.ID == f.ID }) {
				keep = append(keep, f)
			}
		}
		sf.Fences = keep
		for _, w := range want {
			if !standbyIDRE.MatchString(w.ID) || slices.Contains(sf.Released, w.ID) ||
				slices.ContainsFunc(sf.Fences, func(f *fenceRecord) bool { return f.ID == w.ID }) {
				continue
			}
			rec := &fenceRecord{Fence: w}
			if c, ok := sf.Clusters[w.DatabaseID]; ok {
				rec.DataDir, rec.Major = c.DataDir, c.Major
			}
			sf.Fences = append(sf.Fences, rec)
		}
	})
}

func (rt *standbyRuntime) cluster(dbID string) (clusterFacts, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	c, ok := rt.file.Clusters[dbID]
	return c, ok
}

func (rt *standbyRuntime) setCluster(dbID string, c clusterFacts) {
	rt.mu.Lock()
	old, ok := rt.file.Clusters[dbID]
	rt.mu.Unlock()
	if ok && old == c {
		return
	}
	_ = rt.update(func(sf *standbyFile) { sf.Clusters[dbID] = c })
}

// ---- the bucket a primary handed over ----

func (a *Agent) repoPath(dbID string) string {
	return filepath.Join(a.standbyDir(), "repo-"+safeFileID(dbID)+".json")
}

func (a *Agent) caPath(dbID string) string {
	return filepath.Join(a.standbyDir(), "ca-"+safeFileID(dbID)+".pem")
}

var unsafeFileRE = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func safeFileID(id string) string { return unsafeFileRE.ReplaceAllString(id, "_") }

// repoFor is the repository db's backups live in: the bucket its primary
// handed over when this server became its standby, else this agent's own.
func (a *Agent) repoFor(db protocol.DatabaseSpec) pgbackrest.Repo {
	if db.ID == "" {
		return a.cfg.Repo
	}
	data, err := os.ReadFile(a.repoPath(db.ID))
	if err != nil {
		return a.cfg.Repo
	}
	var r pgbackrest.Repo
	if err := json.Unmarshal(data, &r); err != nil {
		a.log.Error("reading the handed-over repository settings; using this agent's own", "database_id", db.ID, "err", err)
		return a.cfg.Repo
	}
	return r
}

// saveHandedRepo stores the primary's repository for db (0600).
func (a *Agent) saveHandedRepo(dbID string, s protocol.StandbyRepo) error {
	r := pgbackrest.Repo{Endpoint: s.Endpoint, Bucket: s.Bucket, Region: s.Region, Key: s.Key, KeySecret: s.KeySecret,
		CipherPass: s.CipherPass, PathPrefix: s.PathPrefix, URIStyle: s.URIStyle, Port: s.Port, SkipTLSVerify: s.SkipTLSVerify}
	if s.CAPEM != "" {
		if err := writeFileAtomic(a.caPath(dbID), []byte(s.CAPEM), 0o600); err != nil {
			return err
		}
		r.CAFile = a.caPath(dbID)
	}
	if err := r.Validate(); err != nil {
		return fmt.Errorf("the primary's repository settings: %w", err)
	}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFileAtomic(a.repoPath(dbID), data, 0o600)
}

// handedRepo is what a primary hands over: its own repository for db.
func (a *Agent) handedRepo(db protocol.DatabaseSpec) (protocol.StandbyRepo, error) {
	r := a.repoFor(db)
	if err := r.Validate(); err != nil {
		return protocol.StandbyRepo{}, err
	}
	out := protocol.StandbyRepo{Endpoint: r.Endpoint, Bucket: r.Bucket, Region: r.Region, Key: r.Key, KeySecret: r.KeySecret,
		CipherPass: r.CipherPass, PathPrefix: r.PathPrefix, URIStyle: r.URIStyle, Port: r.Port, SkipTLSVerify: r.SkipTLSVerify}
	if r.CAFile != "" {
		pem, err := os.ReadFile(r.CAFile)
		if err != nil {
			return out, fmt.Errorf("reading the repository's CA file: %w", err)
		}
		out.CAPEM = string(pem)
	}
	return out, nil
}

// ---- heartbeat ----

// localAddresses are this server's IPs: global unicast, no loopback or
// link-local, at most 16.
func localAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		out = append(out, ipn.IP.String())
		if len(out) == 16 {
			break
		}
	}
	return out
}

// standbyHeartbeat is the Standby part of a heartbeat.
func (a *Agent) standbyHeartbeat(ctx context.Context) protocol.StandbyHeartbeat {
	rt := a.sb()
	var hb protocol.StandbyHeartbeat
	if rt.key != nil && !a.cfg.Sidecar() && a.cfg.Standby != StandbyOff {
		hb.BoxKey = rt.key.PublicKey()
	}
	hb.Addresses = localAddresses()
	for _, r := range rt.standbys() {
		hb.Standbys = append(hb.Standbys, a.standbyState(ctx, r))
	}
	hb.Primaries = a.primaryStates(ctx)
	for _, f := range rt.fences() {
		hb.Fences = append(hb.Fences, protocol.FenceState{ID: f.ID, DatabaseID: f.DatabaseID, Port: f.Port, Running: f.Running,
			StoppedAt: f.StoppedAt, Other: f.Other, Error: f.LastError, At: time.Now().UTC()})
	}
	return hb
}

// applyStandbyInstructions takes the fences from a heartbeat answer.
func (a *Agent) applyStandbyInstructions(in protocol.StandbyInstructions) {
	if a.cfg.Standby == StandbyOff {
		return // this server takes no part in standbys: nothing to hold
	}
	a.sb().setFences(in.Fences)
}

// standbyLoop holds fences, watches primaries from the standbys and deletes
// expired kept data, even with no control plane.
func (a *Agent) standbyLoop(ctx context.Context) {
	rt := a.sb()
	a.recoverStandbys(ctx)
	for {
		for _, f := range rt.fences() {
			a.holdFence(ctx, f)
		}
		for _, r := range rt.standbys() {
			a.checkPrimary(r)
		}
		a.expireKept(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-time.After(standbyTick):
		}
	}
}

// expireKept deletes kept data whose time is up.
func (a *Agent) expireKept(now time.Time) {
	rt := a.sb()
	rt.mu.Lock()
	var due []keptData
	for _, k := range rt.file.Kept {
		if now.After(k.Until) {
			due = append(due, k)
		}
	}
	rt.mu.Unlock()
	for _, k := range due {
		if err := validKeptStandbyDir(k.DataDir, k.Path); err != nil {
			a.log.Warn("not deleting kept data", "path", k.Path, "err", err)
		} else if err := os.RemoveAll(k.Path); err != nil {
			a.log.Warn("deleting kept data", "path", k.Path, "err", err)
			continue
		} else {
			a.log.Info("deleted the old primary's data kept aside by a rebuild", "path", k.Path)
		}
		_ = rt.update(func(sf *standbyFile) {
			sf.Kept = slices.DeleteFunc(sf.Kept, func(x keptData) bool { return x.Path == k.Path })
		})
	}
}

// ---- lanes and dispatch ----

// standbyUrgentTypes are claimed by the standby lane so they never wait
// behind a backup or a restore: a promotion and the fence before it are
// what someone waits for during an outage.
var standbyUrgentTypes = []string{protocol.TaskStandbyFence, protocol.TaskStandbyPromote, protocol.TaskStandbyPrepare,
	protocol.TaskStandbyRelease, protocol.TaskStandbyRemove, protocol.TaskStandbyUnfence}

// standbyLane claims and runs urgent standby tasks, one at a time, beside
// the main loop and the fast lane.
func (a *Agent) standbyLane(ctx context.Context) {
	backoff := a.cfg.PollInterval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if a.updater.InProbation() {
			continue
		}
		a.sbLaneMu.Lock()
		task, err := a.client.claimTypes(ctx, standbyUrgentTypes)
		switch {
		case ctx.Err() != nil:
			a.sbLaneMu.Unlock()
			return
		case isUnauthorized(err):
			backoff = RevokedBackoff
		case err != nil:
			backoff = min(backoff*2, 2*time.Minute)
		case task == nil:
			backoff = a.cfg.PollInterval
		default:
			a.execute(ctx, task, false)
			backoff = 0
		}
		a.sbLaneMu.Unlock()
	}
}

// runStandbyTask runs a standby task.
func (a *Agent) runStandbyTask(ctx context.Context, task *protocol.Task, tl *taskLog) (any, error) {
	if a.cfg.Sidecar() {
		return nil, errors.New("standby servers need the agent installed on the server itself; PostgreSQL in Docker isn't supported yet")
	}
	if a.cfg.Standby == StandbyOff {
		return nil, errors.New("standby servers are turned off on this server (ROWSAFE_STANDBY=off in /etc/rowsafe/agent.env)")
	}
	if task.Database == nil {
		return nil, fmt.Errorf("task %s has no database", task.Type)
	}
	db := *task.Database
	switch task.Type {
	case protocol.TaskStandbyPrepare:
		return runRewind(ctx, task, tl, db, a.standbyPrepare)
	case protocol.TaskStandbyRelease:
		return runRewind(ctx, task, tl, db, a.standbyRelease)
	case protocol.TaskStandbyCreate:
		return runRewind(ctx, task, tl, db, a.standbyCreate)
	case protocol.TaskStandbyPromote:
		return runRewind(ctx, task, tl, db, a.standbyPromote)
	case protocol.TaskStandbyFence:
		return runRewind(ctx, task, tl, db, a.standbyFence)
	case protocol.TaskStandbyRemove:
		return runRewind(ctx, task, tl, db, a.standbyRemove)
	case protocol.TaskStandbyUnfence:
		return runRewind(ctx, task, tl, db, a.standbyUnfence)
	}
	return nil, fmt.Errorf("unsupported task type %q (agent %s)", task.Type, Version)
}

// peerAllowed checks a peer's key against ROWSAFE_STANDBY=pinned.
func (a *Agent) peerAllowed(publicKey, what string) error {
	if a.cfg.Standby != StandbyPinned {
		return nil
	}
	fp, err := handoff.Fingerprint(publicKey)
	if err != nil {
		return err
	}
	for _, p := range a.cfg.StandbyPeers {
		if handoff.SameFingerprint(p, fp) {
			return nil
		}
	}
	return fmt.Errorf("this server only pairs with the servers listed in ROWSAFE_STANDBY_PEERS, and %s's key (%s) isn't one of them: nothing was sent or accepted", what, fp)
}

// KeyFingerprint prints this agent's key fingerprint (rowsafe-agent key),
// creating the key if needed.
func KeyFingerprint(cfg Config) (fingerprint, publicKey string, err error) {
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return "", "", err
	}
	k, err := handoff.LoadOrCreate(filepath.Join(cfg.StateDir, "box.key"))
	if err != nil {
		return "", "", err
	}
	fp, err := handoff.Fingerprint(k.PublicKey())
	return fp, k.PublicKey(), err
}

// replicationRole is the primary's role for a standby's streaming.
func replicationRole(standbyID string) string { return protocol.StandbyRoleName(standbyID) }
