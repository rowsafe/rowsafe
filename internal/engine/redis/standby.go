package redis

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Standby servers (protocol.FeatureStandby) for Redis and Valkey.
//
// A standby is a real replica that Rowsafe sets up on another host, on an
// empty server root handed to Rowsafe there or a new one root's helper
// creates (targets.go). The primary gets a replication login made for it
// (ACL user rowsafe-sb-<id>: PSYNC, REPLCONF and PING only), whose password
// reaches the standby's agent sealed to its key, with the primary's users
// (ACL LIST: names, rules and password hashes) so apps can sign in to the
// standby once it is promoted. The standby then copies the data straight
// from the primary, the way any Redis replica starts (one snapshot), and
// follows it; replicas are read-only.
//
// Rowsafe's own link to the primary (ip=rowsafe-agent in INFO replication)
// is never taken for a standby, and a standby is never taken for the link.
//
// Fencing an old primary (before a planned switchover) makes it refuse
// writes: min-replicas-to-write is raised past any number of replicas it
// could have (writes then fail with NOREPLICAS), kept in its configuration
// file when it can write it, and client connections are ended; the agent
// keeps it so. Rowsafe's link to it uploads everything up to that point
// and stops. Promoting runs REPLICAOF NO ONE once the standby has every
// change the old primary made. The promoted server's agent then starts its
// own link, whose first snapshot is a new base: restores to moments before
// the switch use the old server's history, in the same bucket.

// standbyRecord is a standby this server runs.
type standbyRecord struct {
	ID         string    `json:"id"`
	DatabaseID string    `json:"database_id"`
	Port       int       `json:"port"`
	Phase      string    `json:"phase"`
	Address    string    `json:"primary_address,omitempty"`
	PrimPort   int       `json:"primary_port,omitempty"`
	ReplUser   string    `json:"replication_user,omitempty"`
	Rebuild    bool      `json:"rebuild,omitempty"`
	Users      []string  `json:"users,omitempty"` // users Rowsafe copied from the primary
	CreatedAt  time.Time `json:"created_at"`
	StreamSeen time.Time `json:"streaming_seen_at,omitzero"`
}

type standbyFile struct {
	Standbys []standbyRecord `json:"standbys"`
	// Primaries: on a primary, the addresses of each of its standbys (to
	// tell them in INFO replication).
	Primaries map[string][]string `json:"primaries,omitempty"`
	// Fences: on a fenced old primary, its settings from before.
	Fences map[string]fenceSaved `json:"fences,omitempty"`
}

// fenceSaved is what fencing changed, to put back on unfence.
type fenceSaved struct {
	DatabaseID  string `json:"database_id"`
	Port        int    `json:"port"`
	MinReplicas string `json:"min_replicas_to_write"`
	MaxLag      string `json:"min_replicas_max_lag"`
}

type standbyStore struct {
	mu   sync.Mutex
	path string
}

var (
	standbyStoresMu sync.Mutex
	standbyStores   = map[string]*standbyStore{}
)

func standbys(env agent.EngineEnv) *standbyStore {
	p := filepath.Join(env.SharedStateDir(), "standby.json")
	standbyStoresMu.Lock()
	defer standbyStoresMu.Unlock()
	if s := standbyStores[p]; s != nil {
		return s
	}
	s := &standbyStore{path: p}
	standbyStores[p] = s
	return s
}

func (s *standbyStore) load() standbyFile {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f standbyFile
	_ = loadJSONFile(s.path, &f)
	return f
}

func (s *standbyStore) all() []standbyRecord { return s.load().Standbys }

func (s *standbyStore) get(id string) (standbyRecord, bool) {
	for _, r := range s.all() {
		if r.ID == id {
			return r, true
		}
	}
	return standbyRecord{}, false
}

func (s *standbyStore) onPort(port int) (standbyRecord, bool) {
	for _, r := range s.all() {
		if r.Port == port {
			return r, true
		}
	}
	return standbyRecord{}, false
}

func (s *standbyStore) update(fn func(f *standbyFile)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var f standbyFile
	if err := loadJSONFile(s.path, &f); err != nil && !notExist(err) {
		return err
	}
	fn(&f)
	return saveJSONFile(s.path, f)
}

func (s *standbyStore) put(r standbyRecord) error {
	return s.update(func(f *standbyFile) {
		for i := range f.Standbys {
			if f.Standbys[i].ID == r.ID {
				f.Standbys[i] = r
				return
			}
		}
		f.Standbys = append(f.Standbys, r)
	})
}

func (s *standbyStore) remove(id string) error {
	return s.update(func(f *standbyFile) {
		f.Standbys = slices.DeleteFunc(f.Standbys, func(r standbyRecord) bool { return r.ID == id })
	})
}

// fenced reports whether database id is fenced on this server (Rowsafe's
// link doesn't follow a fenced old primary).
func (s *standbyStore) fenced(dbID string) bool {
	for _, f := range s.load().Fences {
		if f.DatabaseID == dbID {
			return true
		}
	}
	return false
}

var errFenced = errors.New("this server isn't the primary any more (Rowsafe switched the database to its standby and keeps this one read-only): Rowsafe doesn't follow it")

// replUserRE: Rowsafe's replication logins.
var replUserRE = regexp.MustCompile(`^rowsafe-sb-[a-z0-9_-]{1,40}$`)

// replicationUser is a standby's replication login on the primary.
func replicationUser(standbyID string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(standbyID) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			b.WriteRune(c)
		}
	}
	id := b.String()
	if len(id) > 40 {
		id = id[len(id)-40:]
	}
	if id == "" {
		id = "x"
	}
	return "rowsafe-sb-" + id
}

// offsetLSN writes a replication offset the way the control plane compares
// WAL positions ("hi/lo" in hex): the difference is in bytes.
func offsetLSN(off int64) string {
	if off < 0 {
		return ""
	}
	return fmt.Sprintf("%X/%X", uint64(off)>>32, uint64(off)&0xffffffff)
}

// Standby timings (variables for tests).
var (
	standbyPromoteWait = 3 * time.Minute
	standbySyncWait    = 10 * time.Minute
)

// engine data keys (StandbySecrets.EngineData).
const (
	edACL     = "acl"     // the primary's users, ACL LIST lines
	edVersion = "version" // the primary's version
)

var _ agent.EngineStandby = (*Engine)(nil)

// ---- on the primary

// StandbyPrepare checks the primary can be followed and creates the
// standby's replication login.
func (e *Engine) StandbyPrepare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams,
	sec *protocol.StandbySecrets, res *protocol.StandbyPrepareResult, log agent.TaskLogger) error {
	if inDocker() {
		return errors.New("standby servers need the agent installed on the database server itself (it runs as a Docker sidecar here)")
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	defer c.Close()
	in, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	if in.isReplica() {
		return fmt.Errorf("this %s server is itself a replica; set up the standby from the primary", e.display())
	}
	if len(p.StandbyAddresses) == 0 {
		return errors.New("the standby server reported no address")
	}
	if len(sec.PrimaryAddresses) == 0 {
		return errors.New("this server has no address the standby could connect to")
	}
	bind, _ := c.configGet(ctx, "bind")
	if listensLocallyOnly(bind) {
		return fmt.Errorf("%s only accepts connections from this server (bind %s), so a standby can't follow it; let it listen on the address "+
			"the standby reaches (bind in its configuration, then a restart), then create the standby again", e.display(), bind)
	}
	if pm, _ := c.configGet(ctx, "protected-mode"); pm == "yes" && defaultNoPassword(ctx, c) {
		return fmt.Errorf("%s's default user has no password, so its protected mode refuses every connection from other servers, a standby's too: "+
			"give the default user a password (or turn protected mode off where a firewall guards the port), then create the standby again", e.display())
	}
	user := replicationUser(p.StandbyID)
	password, err := randomPassword()
	if err != nil {
		return err
	}
	args := []any{"ACL", "SETUSER", user, "reset", "on", ">" + password, "resetchannels", "-@all", "+psync", "+sync", "+replconf", "+ping"}
	if _, err := c.do(ctx, args...); err != nil {
		if isRespError(err, "NOPERM") {
			return fmt.Errorf("Rowsafe's user on this %s server may not create the standby's replication login: run the Rowsafe installer on this "+
				"server again with --redis-standby (it lets Rowsafe's user create and remove users, which on %s amounts to administrator rights)", e.display(), e.display())
		}
		return fmt.Errorf("creating the replication login: %w", err)
	}
	persistACL(ctx, c)
	_ = standbys(env).update(func(f *standbyFile) {
		if f.Primaries == nil {
			f.Primaries = map[string][]string{}
		}
		f.Primaries[p.StandbyID] = p.StandbyAddresses
	})
	sec.ReplicationUser, sec.ReplicationPassword = user, password
	sec.EngineData = map[string]string{edVersion: in.Version}
	if acl, err := c.do(ctx, "ACL", "LIST"); err == nil {
		var lines []string
		for _, v := range asArray(acl) {
			l := asString(v)
			if name := aclUserName(l); name != "" && !rowsafeUser(name) {
				lines = append(lines, l)
			}
		}
		sec.EngineData[edACL] = strings.Join(lines, "\n")
	} else {
		res.Warnings = append(res.Warnings, "Rowsafe can't read this server's users (ACL LIST), so the standby gets none of them: add your apps' users there before promoting it.")
	}
	res.Major = in.VersionNum / 100
	res.SizeBytes = in.UsedMemoryDataset
	res.Settings = map[string]int{settingDatabases: in.Databases}
	res.Streaming, res.ReplicationRole = true, user
	res.Summary = fmt.Sprintf("Sealed the bucket settings, a replication login (%s) and this server's users for the standby.", user)
	return nil
}

func listensLocallyOnly(bind string) bool {
	fs := strings.Fields(bind)
	if len(fs) == 0 {
		return false
	}
	for _, a := range fs {
		switch strings.TrimPrefix(a, "-") {
		case "127.0.0.1", "::1", "localhost":
		default:
			return false
		}
	}
	return true
}

// aclUserName is the user an ACL LIST line is about.
func aclUserName(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "user" {
		return ""
	}
	return f[1]
}

// rowsafeUser: Rowsafe's own users, never copied.
func rowsafeUser(name string) bool {
	return name == LoginUser || name == copyAgentUser || strings.HasPrefix(name, "rowsafe-sb-")
}

// persistACL keeps users across restarts where the server can (ACL SAVE
// with an aclfile, else CONFIG REWRITE).
func persistACL(ctx context.Context, c *conn) {
	if f, _ := c.configGet(ctx, "aclfile"); f != "" {
		_, _ = c.do(ctx, "ACL", "SAVE")
		return
	}
	_, _ = c.do(ctx, "CONFIG", "REWRITE")
}

// StandbyRelease drops the standby's replication login.
func (e *Engine) StandbyRelease(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, log agent.TaskLogger) (*protocol.StandbyReleaseResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	user := replicationUser(p.StandbyID)
	if _, err := c.do(ctx, "ACL", "DELUSER", user); err != nil {
		return nil, err
	}
	persistACL(ctx, c)
	// End the replica's connection: its password is gone.
	_, _ = c.do(ctx, "CLIENT", "KILL", "USER", user)
	_ = standbys(env).update(func(f *standbyFile) { delete(f.Primaries, p.StandbyID) })
	res := &protocol.StandbyReleaseResult{StandbyID: p.StandbyID, Summary: fmt.Sprintf("Dropped the standby's replication login %s.", user)}
	log.Printf("%s", res.Summary)
	return res, nil
}

// replicaEntry is one slaveN line of INFO replication.
type replicaEntry struct {
	IP     string
	Port   int
	State  string
	Offset int64
	Lag    int64
}

func replicaEntries(m infoMap) []replicaEntry {
	var out []replicaEntry
	for i := 0; ; i++ {
		v, ok := m["slave"+strconv.Itoa(i)]
		if !ok {
			return out
		}
		f := fields(v)
		if f["ip"] == linkAddr {
			continue // Rowsafe's own link, never a replica
		}
		port, _ := strconv.Atoi(f["port"])
		off, _ := strconv.ParseInt(f["offset"], 10, 64)
		lag, _ := strconv.ParseInt(f["lag"], 10, 64)
		out = append(out, replicaEntry{IP: f["ip"], Port: port, State: f["state"], Offset: off, Lag: lag})
	}
}

// PrimaryState is the primary's replication offset and its standbys'
// positions (Rowsafe's own link left out).
func (e *Engine) PrimaryState(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.PrimaryState, bool) {
	st := protocol.PrimaryState{DatabaseID: db.ID, At: time.Now().UTC()}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return st, false
	}
	defer c.Close()
	m, err := c.info(ctx, "replication")
	if err != nil || m["role"] != "master" {
		return st, false
	}
	off := m.int("master_repl_offset")
	st.WALLSN = offsetLSN(off)
	prim := standbys(env).load().Primaries
	for _, r := range replicaEntries(m) {
		for id, addrs := range prim {
			if !slices.Contains(addrs, r.IP) {
				continue
			}
			behind := max(off-r.Offset, 0)
			lag := float64(0)
			if behind > 0 {
				lag = float64(max(r.Lag, 1))
			}
			st.Streams = append(st.Streams, protocol.StandbyStream{Role: protocol.StandbyRoleName(id), State: r.State,
				ReplayLagBytes: &behind, ReplayLagSeconds: &lag, FlushLagSeconds: &lag})
		}
	}
	return st, st.WALLSN != ""
}

// ---- fencing the old primary

const fenceMinReplicas = "1000000"

// StandbyFence makes the old primary refuse writes for good and ends its
// client connections; where its stream ends is where the standby must get
// to.
func (e *Engine) StandbyFence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, log agent.TaskLogger) (*protocol.StandbyFenceResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, fmt.Errorf("%s on port %d doesn't answer, so Rowsafe can't make it refuse writes: %w", e.display(), db.Port, err)
	}
	defer c.Close()
	store := standbys(env)
	saved := fenceSaved{DatabaseID: db.ID, Port: db.Port}
	if prev, ok := store.load().Fences[p.FenceID]; ok {
		saved = prev // a retried fence: keep what was there first
	} else {
		saved.MinReplicas, _ = c.configGet(ctx, "min-replicas-to-write")
		saved.MaxLag, _ = c.configGet(ctx, "min-replicas-max-lag")
	}
	if err := store.update(func(f *standbyFile) {
		if f.Fences == nil {
			f.Fences = map[string]fenceSaved{}
		}
		f.Fences[p.FenceID] = saved
	}); err != nil {
		return nil, err
	}
	if err := applyFence(ctx, c); err != nil {
		_ = store.update(func(f *standbyFile) { delete(f.Fences, p.FenceID) })
		return nil, fmt.Errorf("making %s refuse writes: %w", e.display(), err)
	}
	log.Printf("%s on port %d refuses writes now (kept in its configuration file when it can write it)", e.display(), db.Port)
	if n := endClients(ctx, c); n > 0 {
		log.Printf("ended %s", plural(int64(n), "client connection", "client connections"))
	}
	res := &protocol.StandbyFenceResult{FenceID: p.FenceID, Stopped: true, Method: "read_only"}
	time.Sleep(time.Second)
	m, err := c.info(ctx, "replication")
	if err != nil {
		res.Warnings = append(res.Warnings, "couldn't read where its stream of changes ends: "+err.Error())
	} else {
		off := m.int("master_repl_offset")
		res.CheckpointLSN = m["master_replid"] + ":" + strconv.FormatInt(off, 10)
		// Everything up to here into the bucket, then the link stops.
		if f := e.existingFollower(db.ID); f != nil {
			if st := f.snapshot(); st.Mode == modeReplica && st.ServerReplID == m["master_replid"] {
				if err := f.flush(ctx, st.StreamID, off, 90*time.Second); err != nil {
					res.Warnings = append(res.Warnings, "the last changes didn't all reach your bucket before the switch: "+err.Error())
				} else {
					res.FinalWALPushed = true
				}
			}
		}
	}
	e.stopFollower(db.ID)
	res.Summary = fmt.Sprintf("Made %s on port %d refuse writes for good and ended its client connections; the agent keeps it so.", e.display(), db.Port)
	if res.CheckpointLSN != "" {
		res.Summary += " Its last change is at offset " + res.CheckpointLSN[strings.IndexByte(res.CheckpointLSN, ':')+1:] + "."
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// applyFence raises min-replicas-to-write past any replica count.
func applyFence(ctx context.Context, c *conn) error {
	if lag, _ := c.configGet(ctx, "min-replicas-max-lag"); lag == "0" {
		if _, err := c.do(ctx, "CONFIG", "SET", "min-replicas-max-lag", "10"); err != nil {
			return err
		}
	}
	if _, err := c.do(ctx, "CONFIG", "SET", "min-replicas-to-write", fenceMinReplicas); err != nil {
		return err
	}
	_, _ = c.do(ctx, "CONFIG", "REWRITE")
	return nil
}

// endClients ends the client connections other than Rowsafe's.
func endClients(ctx context.Context, c *conn) int {
	v, err := c.do(ctx, "CLIENT", "LIST", "TYPE", "normal")
	if err != nil {
		return 0
	}
	n := 0
	for _, line := range strings.Split(asString(v), "\n") {
		f := fields(strings.ReplaceAll(strings.TrimSpace(line), " ", ","))
		if f["id"] == "" || f["user"] == LoginUser || strings.HasPrefix(f["name"], "rowsafe") {
			continue
		}
		if _, err := c.do(ctx, "CLIENT", "KILL", "ID", f["id"]); err == nil {
			n++
		}
	}
	return n
}

// stopFollower stops a database's link now.
func (e *Engine) stopFollower(dbID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if f := e.followers[dbID]; f != nil {
		f.stop()
		delete(e.followers, dbID)
	}
}

// HoldFence keeps a fenced old primary refusing writes.
func (e *Engine) HoldFence(ctx context.Context, env agent.EngineEnv, f protocol.Fence) (enforced, other bool, err error) {
	if _, ok := standbys(env).onPort(f.Port); ok {
		return false, false, nil // rebuilt as the new primary's standby
	}
	e.stopFollower(f.DatabaseID)
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{ID: f.DatabaseID, Engine: e.name, Port: f.Port})
	if err != nil {
		return false, false, nil // down: nothing takes writes
	}
	defer c.Close()
	m, err := c.info(ctx, "replication")
	if err != nil {
		return false, false, err
	}
	if m["role"] != "master" {
		return false, false, nil // a replica refuses writes by itself
	}
	if v, _ := c.configGet(ctx, "min-replicas-to-write"); v == fenceMinReplicas {
		return false, false, nil
	}
	if err := applyFence(ctx, c); err != nil {
		return false, false, err
	}
	endClients(ctx, c)
	return true, false, nil
}

// StandbyUnfence lets the old primary take writes again.
func (e *Engine) StandbyUnfence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, f protocol.Fence, log agent.TaskLogger) (*protocol.StandbyUnfenceResult, error) {
	db.Port = f.Port
	store := standbys(env)
	saved, ok := store.load().Fences[f.ID]
	if !ok {
		saved = fenceSaved{MinReplicas: "0", MaxLag: "10"}
	}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.do(ctx, "CONFIG", "SET", "min-replicas-to-write", cmpOr(saved.MinReplicas, "0")); err != nil {
		return nil, fmt.Errorf("letting %s take writes again: %w", e.display(), err)
	}
	if saved.MaxLag != "" {
		_, _ = c.do(ctx, "CONFIG", "SET", "min-replicas-max-lag", saved.MaxLag)
	}
	_, _ = c.do(ctx, "CONFIG", "REWRITE")
	_ = store.update(func(sf *standbyFile) { delete(sf.Fences, f.ID) })
	res := &protocol.StandbyUnfenceResult{FenceID: f.ID, Started: true,
		Summary: fmt.Sprintf("%s on port %d takes writes again as the primary; Rowsafe follows it again.", e.display(), f.Port)}
	log.Printf("%s", res.Summary)
	return res, nil
}

// ---- on the standby's server

// StandbyCreate sets up the standby on db.Port and starts following the
// primary.
func (e *Engine) StandbyCreate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams,
	sec protocol.StandbySecrets, log agent.TaskLogger) (*protocol.StandbyCreateResult, error) {
	start := time.Now()
	store := standbys(env)
	if r, ok := store.get(p.StandbyID); ok && r.Phase == protocol.StandbyPhaseFollowing {
		return &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: r.Address,
			Summary: "The standby is already running here."}, nil
	}
	if r, ok := store.onPort(db.Port); ok && r.ID != p.StandbyID && r.Phase != protocol.StandbyPhaseCreating {
		return nil, fmt.Errorf("the %s server on port %d already runs a standby here", e.display(), db.Port)
	}
	if !replUserRE.MatchString(sec.ReplicationUser) || sec.PrimaryPort == 0 || strings.ContainsAny(sec.ReplicationPassword, " \r\n") {
		return nil, errors.New("the primary sent no valid replication login")
	}
	addr, err := reachable(sec.PrimaryAddresses, sec.PrimaryPort)
	if err != nil {
		return nil, err
	}
	log.Printf("the primary answers at %s:%d", addr, sec.PrimaryPort)
	if p.Rebuild {
		return e.reattach(ctx, env, db, p, sec, addr, start, log)
	}
	c, created, err := e.openTarget(ctx, env, db.Port, targetStandby, log)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	rec := standbyRecord{ID: p.StandbyID, DatabaseID: db.ID, Port: db.Port, Phase: protocol.StandbyPhaseCreating, Address: addr,
		PrimPort: sec.PrimaryPort, ReplUser: sec.ReplicationUser, CreatedAt: time.Now().UTC()}
	if err := store.put(rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.StandbyCreateResult, error) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		e.undoStandby(cctx, env, rec, log)
		_ = store.remove(rec.ID)
		return nil, err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return fail(err)
	}
	switch {
	case in.Engine != "" && in.Engine != e.name:
		return fail(fmt.Errorf("the server on port %d is %s, not %s", db.Port, protocol.EngineDisplayName(in.Engine), e.display()))
	case in.totalKeys() > 0 && !created:
		_ = store.remove(rec.ID)
		return nil, fmt.Errorf("the %s server on port %d isn't empty (%s keys): a standby needs an empty server; nothing was changed", e.display(), db.Port, commas(in.totalKeys()))
	case in.isReplica() && !created:
		_ = store.remove(rec.ID)
		return nil, fmt.Errorf("the %s server on port %d already replicates from another server; nothing was changed", e.display(), db.Port)
	case p.Major > 0 && in.VersionNum/100 < p.Major:
		return fail(fmt.Errorf("the %s server on port %d runs %s, older than the primary (%s): a standby needs the same version or newer",
			e.display(), db.Port, in.Version, majorMinor(p.Major*100)))
	case p.Settings[settingDatabases] > in.Databases:
		return fail(fmt.Errorf("the %s server on port %d has %d logical databases and the primary %d: raise its databases setting",
			e.display(), db.Port, in.Databases, p.Settings[settingDatabases]))
	}
	users, warn := copyUsers(ctx, c, sec.EngineData[edACL])
	rec.Users = users
	if err := store.put(rec); err != nil {
		return fail(err)
	}
	if len(users) > 0 {
		log.Printf("copied %s from the primary", plural(int64(len(users)), "user", "users"))
	}
	if err := startReplication(ctx, c, addr, sec, log); err != nil {
		return fail(err)
	}
	persistACL(ctx, c)
	rec.Phase, rec.StreamSeen = protocol.StandbyPhaseFollowing, time.Now().UTC()
	if err := store.put(rec); err != nil {
		return fail(err)
	}
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: addr,
		DataDir: in.Dir, DurationMs: time.Since(start).Milliseconds()}
	if warn != "" {
		res.Warnings = append(res.Warnings, warn)
	}
	res.Summary = fmt.Sprintf("The standby on port %d copied the data straight from the primary (%s:%d), the way a %s replica starts, and follows it; it is read-only.",
		db.Port, addr, sec.PrimaryPort, e.display())
	log.Printf("%s", res.Summary)
	return res, nil
}

// copyUsers creates the primary's users (ACL LIST lines) on the standby,
// except Rowsafe's own. It returns the names it created.
func copyUsers(ctx context.Context, c *conn, lines string) ([]string, string) {
	var out []string
	var failed []string
	for _, line := range strings.Split(lines, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "user" || rowsafeUser(f[1]) {
			continue
		}
		args := []any{"ACL", "SETUSER", f[1], "reset"}
		for _, r := range f[2:] {
			args = append(args, r)
		}
		if _, err := c.do(ctx, args...); err != nil {
			failed = append(failed, f[1])
			continue
		}
		out = append(out, f[1])
	}
	if len(failed) > 0 {
		return out, "These users of the primary couldn't be created on the standby: " + strings.Join(failed, ", ") + "."
	}
	return out, ""
}

// reachable is the first primary address that accepts a TCP connection.
func reachable(addrs []string, port int) (string, error) {
	for _, a := range addrs {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(a, strconv.Itoa(port)), 3*time.Second)
		if err == nil {
			c.Close()
			return a, nil
		}
	}
	return "", fmt.Errorf("this server can't reach the primary's port %d at %s: open it for this server (firewall), then create the standby again",
		port, strings.Join(addrs, ", "))
}

// startReplication points the server at the primary and waits until it
// has the data and follows.
func startReplication(ctx context.Context, c *conn, addr string, sec protocol.StandbySecrets, log agent.TaskLogger) error {
	for _, kv := range [][2]string{{"masteruser", sec.ReplicationUser}, {"masterauth", sec.ReplicationPassword}, {"replica-read-only", "yes"}} {
		if _, err := c.do(ctx, "CONFIG", "SET", kv[0], kv[1]); err != nil {
			return fmt.Errorf("setting %s: %w", kv[0], err)
		}
	}
	if _, err := c.do(ctx, "REPLICAOF", addr, strconv.Itoa(sec.PrimaryPort)); err != nil {
		return fmt.Errorf("pointing the standby at the primary: %w", err)
	}
	_, _ = c.do(ctx, "CONFIG", "REWRITE")
	log.Printf("following %s:%d: the primary sends a snapshot first", addr, sec.PrimaryPort)
	deadline := time.Now().Add(standbySyncWait)
	for {
		m, err := c.info(ctx, "replication")
		if err != nil {
			return err
		}
		if m["master_link_status"] == "up" && m["master_sync_in_progress"] == "0" {
			return nil
		}
		if time.Now().After(deadline) {
			why := "it didn't get the primary's data within " + standbySyncWait.String()
			if m["master_link_status"] != "up" && m["master_sync_in_progress"] != "1" {
				why = "it can't connect to the primary or sign in (check the firewall and the server's log)"
			}
			return fmt.Errorf("the standby can't follow the primary: %s", why)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// undoStandby stops following and empties the server again (a server
// root's helper created for it is removed).
func (e *Engine) undoStandby(ctx context.Context, env agent.EngineEnv, rec standbyRecord, log agent.TaskLogger) {
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: rec.Port})
	if err == nil {
		_, _ = c.do(ctx, "REPLICAOF", "NO", "ONE")
		_, _ = c.do(ctx, "CONFIG", "SET", "masterauth", "")
		_, _ = c.do(ctx, "CONFIG", "SET", "masteruser", "")
		if rec.Rebuild {
			_ = applyFence(ctx, c) // the old primary stays read-only
			c.Close()
			return
		}
		for _, u := range rec.Users {
			if u != "default" {
				_, _ = c.do(ctx, "ACL", "DELUSER", u)
			}
		}
		if slices.Contains(rec.Users, "default") {
			_, _ = c.do(ctx, "ACL", "SETUSER", "default", "reset", "on", "nopass", "~*", "&*", "+@all")
		}
		persistACL(ctx, c)
		c.Close()
	}
	e.releaseTarget(ctx, env, rec.Port, log)
}

// reattach turns the fenced old primary on this server into the new
// primary's replica: it keeps its data and continues where the new primary
// took over when it can, or gets a fresh snapshot from it. It only ever
// refused writes after the switch, so nothing is lost either way.
func (e *Engine) reattach(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams, sec protocol.StandbySecrets,
	addr string, start time.Time, log agent.TaskLogger) (*protocol.StandbyCreateResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	store := standbys(env)
	rec := standbyRecord{ID: p.StandbyID, DatabaseID: db.ID, Port: db.Port, Phase: protocol.StandbyPhaseCreating, Address: addr,
		PrimPort: sec.PrimaryPort, ReplUser: sec.ReplicationUser, Rebuild: true, CreatedAt: time.Now().UTC()}
	if err := store.put(rec); err != nil {
		return nil, err
	}
	if err := startReplication(ctx, c, addr, sec, log); err != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		_, _ = c.do(cctx, "REPLICAOF", "NO", "ONE")
		_ = applyFence(cctx, c)
		cancel()
		_ = store.remove(rec.ID)
		return nil, err
	}
	// A replica refuses writes by itself: the fence's setting goes back.
	if saved, ok := store.load().Fences[p.FenceID]; ok {
		_, _ = c.do(ctx, "CONFIG", "SET", "min-replicas-to-write", cmpOr(saved.MinReplicas, "0"))
		_ = store.update(func(f *standbyFile) { delete(f.Fences, p.FenceID) })
	} else {
		_, _ = c.do(ctx, "CONFIG", "SET", "min-replicas-to-write", "0")
	}
	_, _ = c.do(ctx, "CONFIG", "REWRITE")
	rec.Phase, rec.StreamSeen = protocol.StandbyPhaseFollowing, time.Now().UTC()
	if err := store.put(rec); err != nil {
		return nil, err
	}
	m, _ := c.info(ctx, "replication")
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: addr, Reattached: true,
		ReplayLSN: offsetLSN(m.int("slave_repl_offset")), DurationMs: time.Since(start).Milliseconds(),
		Summary: fmt.Sprintf("The old primary on port %d follows the new primary (%s:%d); it is read-only.", db.Port, addr, sec.PrimaryPort)}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyPromote makes the standby the primary once it has every change
// the old primary made.
func (e *Engine) StandbyPromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, log agent.TaskLogger) (*protocol.StandbyPromoteResult, error) {
	store := standbys(env)
	rec, ok := store.get(p.StandbyID)
	if !ok {
		return nil, errors.New("this server runs no such standby")
	}
	db.Port = rec.Port
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	res := &protocol.StandbyPromoteResult{StandbyID: p.StandbyID}
	m, err := c.info(ctx, "replication")
	if err != nil {
		return nil, err
	}
	if m["role"] == "master" {
		return nil, fmt.Errorf("the %s server on port %d doesn't follow the primary any more (was it promoted by hand?)", e.display(), rec.Port)
	}
	wantID, wantOff, haveWant := parsePosition(p.WaitForLSN)
	if haveWant {
		log.Printf("waiting until the standby has every change up to offset %d (where the old primary stopped)", wantOff)
	} else {
		log.Printf("the old primary's last position isn't known: promoting once the link has caught up")
	}
	deadline := time.Now().Add(standbyPromoteWait)
	for {
		if m, err = c.info(ctx, "replication"); err != nil {
			return nil, err
		}
		got := m.int("slave_repl_offset")
		switch {
		case haveWant && m["master_replid"] == wantID && got >= wantOff:
			res.CaughtUp = true
		case !haveWant && m["master_link_status"] == "up" && m["master_sync_in_progress"] == "0":
			res.CaughtUp = true
		}
		if res.CaughtUp {
			break
		}
		if time.Now().After(deadline) {
			if !p.Force {
				return nil, fmt.Errorf("the standby hasn't received everything the old primary wrote within %s (it is at offset %d, it needs %d): "+
					"it was left as it is; promote anyway to accept losing the rest", standbyPromoteWait, got, wantOff)
			}
			if haveWant && m["master_replid"] == wantID {
				res.MissingBytes = max(wantOff-got, 0)
			}
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	if _, err := c.do(ctx, "REPLICAOF", "NO", "ONE"); err != nil {
		return nil, fmt.Errorf("promoting: %w", err)
	}
	_, _ = c.do(ctx, "CONFIG", "SET", "masterauth", "")
	_, _ = c.do(ctx, "CONFIG", "SET", "masteruser", "")
	_, _ = c.do(ctx, "CONFIG", "REWRITE")
	now := time.Now().UTC()
	res.Promoted, res.PromotedAt, res.LastReplayAt = true, &now, &now
	if m, err := c.info(ctx, "replication"); err == nil {
		res.ReplayLSN = m["master_replid"] + ":" + strconv.FormatInt(m.int("master_repl_offset"), 10)
	}
	_ = store.remove(rec.ID)
	// A fence this server held for the database before (it was its old
	// primary once) is over: Rowsafe follows it here now.
	_ = store.update(func(f *standbyFile) {
		for id, x := range f.Fences {
			if x.DatabaseID == db.ID {
				delete(f.Fences, id)
			}
		}
	})
	res.Summary = fmt.Sprintf("%s on port %d is the primary now and takes writes. Rowsafe follows it from here: its first snapshot is a new base for restores "+
		"to any second; moments before the switch restore from the old server's history, in the same bucket.", e.display(), rec.Port)
	if !res.CaughtUp {
		res.Summary += " It was promoted before it had every change of the old primary."
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRemove stops following and empties the server again (or, for an
// old primary rebuilt as a standby, keeps its data, read-only).
func (e *Engine) StandbyRemove(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, log agent.TaskLogger) (*protocol.StandbyRemoveResult, error) {
	store := standbys(env)
	res := &protocol.StandbyRemoveResult{StandbyID: p.StandbyID}
	rec, ok := store.get(p.StandbyID)
	if !ok {
		res.Summary = "No such standby runs here (already removed)."
		return res, nil
	}
	e.undoStandby(ctx, env, rec, log)
	_ = store.remove(rec.ID)
	if rec.Rebuild {
		res.Summary = fmt.Sprintf("Removed the standby: %s on port %d doesn't follow the primary any more; its data (a copy of the database) stays, read-only.", e.display(), rec.Port)
	} else {
		res.Restored = true
		res.Summary = fmt.Sprintf("Removed the standby: %s on port %d is empty again (or removed, when Rowsafe created it).", e.display(), rec.Port)
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyStates reports the standbys this server runs.
func (e *Engine) StandbyStates(ctx context.Context, env agent.EngineEnv) []protocol.StandbyState {
	store := standbys(env)
	var out []protocol.StandbyState
	for _, rec := range store.all() {
		out = append(out, e.standbyState(ctx, env, store, rec))
	}
	return out
}

func (e *Engine) standbyState(ctx context.Context, env agent.EngineEnv, store *standbyStore, rec standbyRecord) protocol.StandbyState {
	now := time.Now().UTC()
	out := protocol.StandbyState{StandbyID: rec.ID, DatabaseID: rec.DatabaseID, Port: rec.Port, Phase: rec.Phase,
		Mode: protocol.StandbyModeStreaming, PrimaryAddress: rec.Address, CheckedAt: now}
	if !rec.StreamSeen.IsZero() {
		t := rec.StreamSeen
		out.StreamingSeenAt = &t
	}
	if rec.Phase == protocol.StandbyPhaseCreating {
		return out
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := connectDB(cctx, env, protocol.DatabaseSpec{Port: rec.Port})
	if err != nil {
		out.Phase, out.Error = protocol.StandbyPhaseStopped, err.Error()
		return out
	}
	defer c.Close()
	out.Running = true
	m, err := c.info(cctx, "replication")
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.InRecovery = m["role"] == "slave"
	off := m.int("slave_repl_offset")
	out.ReceiveLSN, out.ReplayLSN = offsetLSN(off), offsetLSN(off)
	if m["master_link_status"] == "up" {
		out.ReceiverStatus = "streaming"
		out.StreamingSeenAt = &now
		out.PrimaryReachable = true
		io := time.Duration(m.int("master_last_io_seconds_ago")) * time.Second
		t := now.Add(-io)
		out.LastReplayAt = &t
		_ = store.update(func(f *standbyFile) {
			for i := range f.Standbys {
				if f.Standbys[i].ID == rec.ID {
					f.Standbys[i].StreamSeen = now
				}
			}
		})
	} else {
		if _, err := reachable([]string{rec.Address}, rec.PrimPort); err == nil {
			out.PrimaryReachable = true
		}
		switch {
		case m["master_sync_in_progress"] == "1":
			out.Error = "it is getting a new snapshot from the primary"
		case out.InRecovery:
			out.Error = "it lost its connection to the primary (down for " + m["master_link_down_since_seconds"] + "s)"
		}
	}
	return out
}

