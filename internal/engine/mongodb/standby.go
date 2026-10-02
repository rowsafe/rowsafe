package mongodb

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineStandby = (*Engine)(nil)

// Timings (variables for tests).
var (
	sbRestartWait = 3 * time.Minute // the standby's mongod back after its restart
	sbSyncWait    = 6 * time.Hour   // MongoDB's initial sync of the new member
	sbPromoteWait = 3 * time.Minute // applying the old primary's last writes
)

// Helper actions (scripts/rowsafe-pg-restart).
const (
	helperKeyExport     = "mongodb-key-export"
	helperStandbyConfig = "mongodb-standby-config"
)

func errNoStandbyRights(port int) error {
	return fmt.Errorf("Rowsafe's MongoDB user on port %d may not change the replica set: run the Rowsafe installer on this server again with --mongodb-standby", port)
}

func hasClusterManager(in serverInfo) bool {
	return !in.Auth || hasRole(in.Roles, "clusterManager@admin") || hasRole(in.Roles, "root@admin")
}

// StandbyPrepare checks the primary can have a standby and hands what the
// standby needs: the set's name, its key file (from root's helper) and
// Rowsafe's login, which the standby uses once the set's users reach it.
func (e *Engine) StandbyPrepare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams,
	sec *protocol.StandbySecrets, res *protocol.StandbyPrepareResult, tl agent.TaskLogger) error {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	switch {
	case in.SetName == "":
		return errors.New("MongoDB here runs standalone: a standby joins a replica set, and backups turn this one into a replica set of one first")
	case !in.Primary:
		return errors.New("this MongoDB is a secondary: set up the standby from the primary's server")
	case !hasClusterManager(in):
		return errNoStandbyRights(db.Port)
	case bindsLocallyOnly(ctx, c):
		return errors.New("MongoDB here only listens on 127.0.0.1, so a standby can't reach it: add this server's address to net.bindIp (a restart), then add the standby again")
	}
	data := map[string]string{"set": in.SetName}
	if in.Auth {
		if env.HelperCan == nil || !env.HelperCan(helperKeyExport, db.Port) {
			return errors.New("root didn't allow standby servers for MongoDB here: run the Rowsafe installer on this server again with --mongodb-standby")
		}
		key, err := exportKey(ctx, env, db.Port)
		if err != nil {
			return err
		}
		l, err := loadLogin(env, db.Port)
		if err != nil {
			return err
		}
		data["key"], data["user"], data["password"], data["auth_source"] = key, l.User, l.Password, cmpOr(l.AuthSource, "admin")
	}
	sec.EngineData = data
	res.Major, res.SystemID, res.SizeBytes, res.Streaming = in.VersionNum/100, in.SetName, in.TotalBytes, true
	res.Settings = map[string]int{"version": in.VersionNum}
	res.Summary = fmt.Sprintf("Sealed what the standby needs to join replica set %s (its key file and Rowsafe's login).", in.SetName)
	tl.Printf("%s", res.Summary)
	return nil
}

// exportKey has root's helper copy the set's key file for the agent, reads
// it and deletes the copy.
func exportKey(ctx context.Context, env agent.EngineEnv, port int) (string, error) {
	if _, err := env.Helper(ctx, helperKeyExport, strconv.Itoa(port)); err != nil {
		return "", fmt.Errorf("reading the replica set's key file: %w", err)
	}
	path := filepath.Join(env.Config.RestartDir, "mongodb-key-out")
	data, err := os.ReadFile(path)
	_ = os.Remove(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(data))
	if len(key) < 6 {
		return "", errors.New("the replica set's key file is empty")
	}
	return key, nil
}

// StandbyCreate makes the empty mongod on p.Port a member of the primary's
// replica set: root's helper writes the set's name, key file and this
// server's address into its configuration, Rowsafe restarts it once (the
// person confirmed it), and adds it to the set from the primary.
func (e *Engine) StandbyCreate(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyCreateParams,
	sec protocol.StandbySecrets, tl agent.TaskLogger) (*protocol.StandbyCreateResult, error) {
	start := time.Now()
	if r, ok := sbGet(env, p.StandbyID); ok && r.Phase == protocol.StandbyPhaseFollowing {
		return &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, Summary: "The standby is already running here."}, nil
	}
	if p.Rebuild {
		return nil, errors.New("turning an old MongoDB primary into the standby isn't available yet: add a standby on an empty MongoDB server instead")
	}
	set, key := sec.EngineData["set"], sec.EngineData["key"]
	if set == "" || sec.PrimaryPort == 0 {
		return nil, errors.New("the primary sent no replica set to join")
	}
	switch {
	case !p.RestartOK:
		return nil, fmt.Errorf("Rowsafe must restart MongoDB on port %d once so it can join the replica set: confirm that when you add the standby", p.Port)
	case env.HelperCan == nil || !env.HelperCan(helperStandbyConfig, p.Port):
		return nil, errors.New("root didn't allow standby servers for MongoDB on this server: run the Rowsafe installer here again with --mongodb-standby")
	case !env.HelperCan("restart", p.Port):
		return nil, errors.New("Rowsafe may not restart MongoDB on this server: run the Rowsafe installer here again with --allow-restart")
	}
	if r, ok := sbOnPort(env, p.Port); ok && r.ID != p.StandbyID {
		return nil, fmt.Errorf("the MongoDB on port %d already runs a standby here", p.Port)
	}
	local := protocol.DatabaseSpec{Port: p.Port}
	c, err := connectDB(ctx, env, local)
	if err != nil {
		return nil, err
	}
	in, err := inspect(ctx, c)
	disconnect(c)
	if err != nil {
		return nil, err
	}
	switch {
	case len(in.Databases) > 0:
		return nil, fmt.Errorf("the MongoDB on port %d isn't empty: a standby needs an empty server; nothing was changed", p.Port)
	case in.SetName != "" && in.SetName != set:
		return nil, fmt.Errorf("the MongoDB on port %d belongs to replica set %s; nothing was changed", p.Port, in.SetName)
	case p.Major > 0 && in.VersionNum/100 != p.Major:
		return nil, fmt.Errorf("the MongoDB on port %d is version %s; the primary runs %d.%d: members of a replica set run the same version",
			p.Port, in.Version, p.Major/100, p.Major%100)
	}
	primaryAddr, myAddr, err := reachableAddr(sec.PrimaryAddresses, sec.PrimaryPort)
	if err != nil {
		return nil, err
	}
	member := net.JoinHostPort(myAddr, strconv.Itoa(p.Port))
	primaryLogin := Login{User: sec.EngineData["user"], Password: sec.EngineData["password"], AuthSource: sec.EngineData["auth_source"], Host: primaryAddr}
	rec := sbRecord{ID: p.StandbyID, DatabaseID: db.ID, Port: p.Port, Phase: protocol.StandbyPhaseCreating, Member: member,
		Primary: net.JoinHostPort(primaryAddr, strconv.Itoa(sec.PrimaryPort)), SetName: set, CreatedAt: time.Now().UTC()}
	if err := sbPut(env, rec); err != nil {
		return nil, err
	}
	fail := func(err error) (*protocol.StandbyCreateResult, error) {
		_ = sbRemove(env, rec.ID)
		return nil, err
	}

	// 1. Its configuration (root's helper) and one restart.
	keyFlag := "nokey"
	if key != "" {
		keyFlag = "key"
		if err := saveFile(filepath.Join(env.Config.RestartDir, "mongodb-key-in"), []byte(key+"\n")); err != nil {
			return fail(err)
		}
	}
	if _, err := env.Helper(ctx, helperStandbyConfig, strconv.Itoa(p.Port), set, keyFlag, myAddr); err != nil {
		_ = os.Remove(filepath.Join(env.Config.RestartDir, "mongodb-key-in"))
		return fail(fmt.Errorf("configuring MongoDB to join the replica set: %w", err))
	}
	tl.Printf("MongoDB on port %d is configured to join replica set %s (a copy of its configuration file was kept); restarting it once", p.Port, set)
	if _, err := env.Helper(ctx, "restart", strconv.Itoa(p.Port)); err != nil {
		return fail(fmt.Errorf("restarting MongoDB: %w", err))
	}
	if err := waitFor(ctx, sbRestartWait, func() (bool, error) {
		c, err := connectDB(ctx, env, local)
		if err != nil {
			return false, nil
		}
		disconnect(c)
		return true, nil
	}); err != nil {
		return fail(errors.New("MongoDB didn't come back after its restart: check its log on this server"))
	}

	// 2. The primary adds it: priority 0, no vote.
	pc, err := connect(ctx, primaryLogin.uri(sec.PrimaryPort))
	if err != nil {
		return fail(fmt.Errorf("signing in to the primary: %w", err))
	}
	defer disconnect(pc)
	if err := addMember(ctx, pc, member); err != nil {
		return fail(fmt.Errorf("adding this server to the replica set: %w", err))
	}
	tl.Printf("added %s to replica set %s (priority 0, no vote): MongoDB copies the data to it now (its initial sync, from the primary)", member, set)

	// 3. Wait until it is a secondary.
	if err := waitFor(ctx, sbSyncWait, func() (bool, error) {
		st, err := replStatus(ctx, pc)
		if err != nil {
			return false, nil
		}
		m, ok := st.member(member)
		if ok && m.State == 2 {
			return true, nil
		}
		return false, nil
	}); err != nil {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		_ = removeMember(cctx, pc, member)
		cancel()
		return fail(fmt.Errorf("the new member didn't finish copying the data: %w", err))
	}
	// The set's users replaced this server's own: sign in as on the primary.
	if key != "" {
		l := primaryLogin
		l.Host = ""
		if err := saveLogin(env, p.Port, l); err != nil {
			return fail(err)
		}
	}
	rec.Phase = protocol.StandbyPhaseFollowing
	if err := sbPut(env, rec); err != nil {
		return nil, err
	}
	res := &protocol.StandbyCreateResult{StandbyID: p.StandbyID, Mode: protocol.StandbyModeStreaming, PrimaryAddress: primaryAddr,
		DurationMs: time.Since(start).Milliseconds(),
		Warnings: []string{"MongoDB copied the data from the primary itself (a new replica set member can't start from a backup)."},
		Summary:  fmt.Sprintf("MongoDB on port %d is a member of replica set %s and follows the primary; it never becomes primary by itself.", p.Port, set)}
	tl.Printf("%s", res.Summary)
	return res, nil
}

func addMember(ctx context.Context, c *mongo.Client, host string) error {
	cfg, err := replConfig(ctx, c)
	if err != nil {
		return err
	}
	members := cfgMembers(cfg)
	maxID := -1
	for _, m := range members {
		if strings.EqualFold(fmt.Sprint(m["host"]), host) {
			return nil // already there (a retry)
		}
		maxID = max(maxID, toInt(m["_id"]))
	}
	members = append(members, bson.M{"_id": maxID + 1, "host": host, "priority": 0, "votes": 0})
	setMembers(cfg, members)
	return reconfig(ctx, c, cfg, false)
}

func removeMember(ctx context.Context, c *mongo.Client, host string) error {
	cfg, err := replConfig(ctx, c)
	if err != nil {
		return err
	}
	members := cfgMembers(cfg)
	n := len(members)
	members = slices.DeleteFunc(members, func(m bson.M) bool { return strings.EqualFold(fmt.Sprint(m["host"]), host) })
	if len(members) == n {
		return nil
	}
	setMembers(cfg, members)
	return reconfig(ctx, c, cfg, false)
}

// StandbyStates reports the standbys this server runs.
func (e *Engine) StandbyStates(ctx context.Context, env agent.EngineEnv) []protocol.StandbyState {
	var out []protocol.StandbyState
	for _, r := range sbLoad(env).Standbys {
		now := time.Now().UTC()
		st := protocol.StandbyState{StandbyID: r.ID, DatabaseID: r.DatabaseID, Port: r.Port, Phase: r.Phase, Mode: protocol.StandbyModeStreaming,
			PrimaryAddress: strings.Split(r.Primary, ":")[0], CheckedAt: now}
		if r.Phase == protocol.StandbyPhaseCreating {
			out = append(out, st)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		c, err := connectDB(cctx, env, protocol.DatabaseSpec{Port: r.Port})
		if err != nil {
			cancel()
			st.Phase, st.Error = protocol.StandbyPhaseStopped, err.Error()
			out = append(out, st)
			continue
		}
		st.Running = true
		rs, err := replStatus(cctx, c)
		disconnect(c)
		cancel()
		if err != nil {
			st.Error = err.Error()
			out = append(out, st)
			continue
		}
		if self, ok := rs.self(); ok {
			st.InRecovery = self.State == 2
			st.ReplayLSN, st.ReceiveLSN = optimeLSN(self.Optime.TS), optimeLSN(self.Optime.TS)
			if !self.OptimeDate.IsZero() {
				t := self.OptimeDate.UTC()
				st.LastReplayAt = &t
			}
			if self.SyncSourceHost != "" {
				st.ReceiverStatus, st.StreamingSeenAt = "streaming", &now
			}
			if self.State != 2 && self.State != 1 {
				st.Error = "MongoDB here is " + strings.ToLower(self.StateStr) + " in the replica set"
			}
		}
		if pm, ok := rs.primary(); ok && pm.Health == 1 {
			st.PrimaryReachable = true
			if st.LastReplayAt != nil && !pm.OptimeDate.IsZero() {
				// Behind by the primary's newest write, not by the clock.
				t := now.Add(-pm.OptimeDate.Sub(*st.LastReplayAt))
				st.LastReplayAt = &t
			}
		}
		out = append(out, st)
	}
	return out
}

// PrimaryState is the primary's newest optime.
func (e *Engine) PrimaryState(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.PrimaryState, bool) {
	st := protocol.PrimaryState{DatabaseID: db.ID, At: time.Now().UTC()}
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return st, false
	}
	defer disconnect(c)
	rs, err := replStatus(ctx, c)
	if err != nil {
		return st, false
	}
	self, ok := rs.self()
	if !ok || self.State != 1 {
		return st, false
	}
	st.WALLSN = optimeLSN(self.Optime.TS)
	return st, st.WALLSN != ""
}

// StandbyFence makes sure the old primary never takes writes again: every
// member gets priority 0 (a forced reconfiguration), so it steps down and
// no member is elected primary, also after a restart.
func (e *Engine) StandbyFence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, tl agent.TaskLogger) (*protocol.StandbyFenceResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, fmt.Errorf("MongoDB on port %d doesn't answer, so Rowsafe can't fence it: %w", db.Port, err)
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return nil, err
	}
	if p.SystemID != "" && in.SetName != p.SystemID {
		return nil, fmt.Errorf("the MongoDB on port %d is in another replica set (%s, not %s); Rowsafe left it alone", db.Port, in.SetName, p.SystemID)
	}
	if !hasClusterManager(in) {
		return nil, errNoStandbyRights(db.Port)
	}
	if err := noneElectable(ctx, c); err != nil {
		return nil, fmt.Errorf("fencing MongoDB: %w", err)
	}
	if err := waitFor(ctx, time.Minute, func() (bool, error) {
		in, err := inspect(ctx, c)
		return err == nil && !in.Primary, nil
	}); err != nil {
		return nil, errors.New("MongoDB didn't step down within a minute")
	}
	res := &protocol.StandbyFenceResult{FenceID: p.FenceID, Stopped: true, Method: "no member may be primary"}
	if rs, err := replStatus(ctx, c); err == nil {
		if self, ok := rs.self(); ok {
			res.CheckpointLSN = optimeLSN(self.Optime.TS)
		}
	}
	res.Summary = fmt.Sprintf("MongoDB on port %d stepped down for good: no member of the replica set may become primary until the standby is promoted, also after a restart.", db.Port)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// noneElectable gives every member priority 0 (forced: the primary can't
// accept a configuration in which it isn't electable otherwise).
func noneElectable(ctx context.Context, c *mongo.Client) error {
	cfg, err := replConfig(ctx, c)
	if err != nil {
		return err
	}
	members := cfgMembers(cfg)
	for _, m := range members {
		m["priority"] = 0
	}
	setMembers(cfg, members)
	return reconfig(ctx, c, cfg, true)
}

// HoldFence keeps a fenced old primary from taking writes.
func (e *Engine) HoldFence(ctx context.Context, env agent.EngineEnv, f protocol.Fence) (enforced, other bool, err error) {
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: f.Port})
	if err != nil {
		return false, false, nil // down: nothing takes writes
	}
	defer disconnect(c)
	in, err := inspect(ctx, c)
	if err != nil {
		return false, false, err
	}
	if f.SystemID != "" && in.SetName != "" && in.SetName != f.SystemID {
		return false, true, nil
	}
	if !in.Primary {
		return false, false, nil
	}
	if err := noneElectable(ctx, c); err != nil {
		return false, false, err
	}
	return true, false, nil
}

// StandbyUnfence makes the old primary electable again (the promotion
// didn't happen).
func (e *Engine) StandbyUnfence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, f protocol.Fence, tl agent.TaskLogger) (*protocol.StandbyUnfenceResult, error) {
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: f.Port})
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	cfg, err := replConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	members := cfgMembers(cfg)
	for _, m := range members {
		if toInt(m["votes"]) > 0 {
			m["priority"] = 1
		}
	}
	setMembers(cfg, members)
	if err := reconfig(ctx, c, cfg, true); err != nil {
		return nil, fmt.Errorf("making MongoDB electable again: %w", err)
	}
	if err := waitFor(ctx, 2*time.Minute, func() (bool, error) {
		in, err := inspect(ctx, c)
		return err == nil && in.Primary, nil
	}); err != nil {
		return nil, errors.New("MongoDB didn't become primary again within two minutes")
	}
	res := &protocol.StandbyUnfenceResult{FenceID: f.ID, Started: true, Summary: fmt.Sprintf("MongoDB on port %d is the primary again.", f.Port)}
	tl.Printf("%s", res.Summary)
	return res, nil
}

// StandbyPromote makes the standby the primary: once it applied what the
// old primary wrote, it becomes the set's only voting member (forced).
func (e *Engine) StandbyPromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, tl agent.TaskLogger) (*protocol.StandbyPromoteResult, error) {
	r, ok := sbGet(env, p.StandbyID)
	if !ok {
		return nil, errors.New("this server runs no such standby")
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: r.Port})
	if err != nil {
		return nil, err
	}
	defer disconnect(c)
	res := &protocol.StandbyPromoteResult{StandbyID: p.StandbyID}
	want, haveWant := parseOptimeLSN(p.WaitForLSN)
	var self rsMember
	err = waitFor(ctx, sbPromoteWait, func() (bool, error) {
		rs, err := replStatus(ctx, c)
		if err != nil {
			return false, nil
		}
		self, _ = rs.self()
		if !haveWant {
			return true, nil
		}
		return optimeAtLeast(self.Optime.TS, want), nil
	})
	res.CaughtUp = err == nil && haveWant
	if err != nil && !p.Force {
		return nil, fmt.Errorf("the standby hasn't applied everything the old primary wrote within %s (it is at %s, it needs %s): "+
			"it was left as it is; promote anyway to accept losing the rest", sbPromoteWait, optimeLSN(self.Optime.TS), p.WaitForLSN)
	}
	cfg, err := replConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	var mine []bson.M
	for _, m := range cfgMembers(cfg) {
		if strings.EqualFold(fmt.Sprint(m["host"]), r.Member) {
			m["priority"], m["votes"] = 1, 1
			mine = append(mine, m)
		}
	}
	if len(mine) != 1 {
		return nil, fmt.Errorf("%s isn't in the replica set's configuration", r.Member)
	}
	setMembers(cfg, mine)
	if err := reconfig(ctx, c, cfg, true); err != nil {
		return nil, fmt.Errorf("making the standby the replica set's only voting member: %w", err)
	}
	if err := waitFor(ctx, 2*time.Minute, func() (bool, error) {
		in, err := inspect(ctx, c)
		return err == nil && in.Primary, nil
	}); err != nil {
		return nil, errors.New("the standby didn't become primary within two minutes")
	}
	now := time.Now().UTC()
	res.Promoted, res.PromotedAt, res.LastReplayAt = true, &now, &now
	if rs, err := replStatus(ctx, c); err == nil {
		if s, ok := rs.self(); ok {
			res.ReplayLSN = optimeLSN(s.Optime.TS)
		}
	}
	_ = sbRemove(env, r.ID)
	res.Summary = fmt.Sprintf("MongoDB on port %d is the primary now: the replica set's only voting member (the old primary left it).", r.Port)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRemove takes the standby out of the replica set (from its
// primary). Its copy of the data stays on this server, out of the set.
func (e *Engine) StandbyRemove(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, tl agent.TaskLogger) (*protocol.StandbyRemoveResult, error) {
	res := &protocol.StandbyRemoveResult{StandbyID: p.StandbyID}
	r, ok := sbGet(env, p.StandbyID)
	if !ok {
		res.Summary = "No such standby runs here (already removed)."
		return res, nil
	}
	if r.Phase != protocol.StandbyPhaseCreating {
		c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: r.Port})
		if err != nil {
			return nil, err
		}
		rs, err := replStatus(ctx, c)
		disconnect(c)
		if err != nil {
			return nil, err
		}
		pm, ok := rs.primary()
		if !ok {
			return nil, errors.New("the replica set has no primary right now, so the standby can't be taken out of it")
		}
		l, err := loadLogin(env, r.Port)
		if err != nil {
			return nil, err
		}
		host, port, _ := net.SplitHostPort(pm.Name)
		l.Host = host
		pp, _ := strconv.Atoi(port)
		pc, err := connect(ctx, l.uri(pp))
		if err != nil {
			return nil, fmt.Errorf("signing in to the primary: %w", err)
		}
		err = removeMember(ctx, pc, r.Member)
		disconnect(pc)
		if err != nil {
			return nil, fmt.Errorf("taking the standby out of the replica set: %w", err)
		}
	}
	_ = sbRemove(env, r.ID)
	res.Summary = fmt.Sprintf("Removed the standby: MongoDB on port %d left the replica set and no longer follows the primary; its copy of the data stays there.", r.Port)
	tl.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRelease: the standby takes itself out of the set; nothing stays
// on the primary.
func (e *Engine) StandbyRelease(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, tl agent.TaskLogger) (*protocol.StandbyReleaseResult, error) {
	return &protocol.StandbyReleaseResult{StandbyID: p.StandbyID, Summary: "Nothing to undo on the primary: the standby leaves the replica set from its own server."}, nil
}
