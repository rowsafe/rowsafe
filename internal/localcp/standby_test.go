package localcp

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// standbyBeat sends a heartbeat with restart permission for 5432 and the
// agent's standby report.
func standbyBeat(a *fakeAgent, hb protocol.StandbyHeartbeat) protocol.HeartbeatResponse {
	a.t.Helper()
	var resp protocol.HeartbeatResponse
	a.call("POST", "/v1/agent/heartbeat", protocol.HeartbeatRequest{Hostname: "db1", AgentVersion: "0.10.23", RestartPorts: []int{5432},
		StandbyHeartbeat: hb}, &resp)
	return resp
}

func params[T any](t *testing.T, task *protocol.Task) T {
	t.Helper()
	var p T
	if err := json.Unmarshal(task.Params, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func record(state string, lsn string, at time.Time) *protocol.PrimaryRecord {
	return &protocol.PrimaryRecord{Version: 1, Database: "shop", SystemID: "7412", Primary: "db1", Fingerprint: "AAAA-BBBB-CCCC-DDDD",
		State: state, Timeline: 1, CheckpointLSN: lsn, At: at}
}

func TestStandbyPair(t *testing.T) {
	ctx := context.Background()
	// The primary: shop is active.
	_, pa, pc, pnow := setup(t)
	pdb := activeDB(t, pa, pc, pnow)
	standbyBeat(pa, protocol.StandbyHeartbeat{})

	// It lets the standby stream: the agent prepares with the derived password.
	if _, err := pc.LocalStandbyLink(ctx, "shop", protocol.LocalLinkRequest{Addresses: []string{"not-an-ip"}}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a name instead of an address: %v", err)
	}
	info, err := pc.LocalStandbyLink(ctx, "shop", protocol.LocalLinkRequest{Addresses: []string{"10.0.0.6"}})
	if err != nil || info.Local.Role != protocol.LocalRolePrimary || len(info.Tasks) != 1 {
		t.Fatalf("link: %+v %v", info, err)
	}
	prep := pa.claimOne(protocol.TaskStandbyPrepare, protocol.TaskStandbyPrepare)
	pp := params[protocol.StandbyPrepareParams](t, prep)
	if !pp.Local || !pp.Stream || pp.StandbyID != "sb_shop" || !slices.Equal(pp.StandbyAddresses, []string{"10.0.0.6"}) {
		t.Fatalf("prepare params %+v", pp)
	}
	pa.done(prep, protocol.StatusSucceeded, protocol.StandbyPrepareResult{StandbyID: "sb_shop", Streaming: true, ReplicationRole: "rowsafe_standby_sb_shop"})

	// The standby's server: an empty cluster root lets Rowsafe stop.
	_, sa, sc, snow := setup(t)
	standbyBeat(sa, protocol.StandbyHeartbeat{})
	if _, err := sc.LocalStandbyCreate(ctx, "shop", protocol.LocalStandbyRequest{PrimaryAddress: "10.0.0.5"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("without the confirmation: %v", err)
	}
	if _, err := sc.LocalStandbyCreate(ctx, "shop", protocol.LocalStandbyRequest{PrimaryAddress: "db.example", Confirm: "shop"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a hostname: %v", err)
	}
	info, err = sc.LocalStandbyCreate(ctx, "shop", protocol.LocalStandbyRequest{PrimaryAddress: "10.0.0.5", Confirm: "shop"})
	if err != nil || info.Standby == nil || info.Standby.Status != protocol.StandbyCreating {
		t.Fatalf("create: %+v %v", info, err)
	}
	create := sa.claimOne(protocol.TaskStandbyCreate)
	cp := params[protocol.StandbyCreateParams](t, create)
	if !cp.FromBucket || cp.Port != 5432 || cp.StandbyID != "sb_shop" || !slices.Equal(cp.PrimaryAddresses, []string{"10.0.0.5"}) || cp.PrimaryPort != 5432 {
		t.Fatalf("create params %+v", cp)
	}
	if _, err := sc.LocalStandbyCreate(ctx, "shop", protocol.LocalStandbyRequest{Confirm: "shop"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second create while the first runs: %v", err)
	}
	sa.done(create, protocol.StatusSucceeded, protocol.StandbyCreateResult{StandbyID: "sb_shop", Mode: protocol.StandbyModeStreaming})
	sdb, _ := sc.Database(ctx, "shop")
	if sdb.Status != dbStandby {
		t.Fatalf("status %s", sdb.Status)
	}
	at := *snow
	following := protocol.StandbyState{StandbyID: "sb_shop", DatabaseID: sdb.ID, Port: 5432, Phase: protocol.StandbyPhaseFollowing, Running: true,
		InRecovery: true, Mode: protocol.StandbyModeStreaming, ReceiverStatus: "streaming", ReceiveLSN: "0/3000100", ReplayLSN: "0/3000000",
		LastReplayAt: &at, PrimaryAddress: "10.0.0.5", PrimaryReachable: true, CheckedAt: at}
	resp := standbyBeat(sa, protocol.StandbyHeartbeat{Standbys: []protocol.StandbyState{following}})
	// The standby isn't a primary to back up: not in the agent's databases;
	// its record is read.
	if len(resp.Databases) != 0 || len(resp.Monitored) != 0 || !slices.Contains(resp.Records, sdb.ID) {
		t.Fatalf("heartbeat answer %+v", resp)
	}
	info, _ = sc.StandbyInfo(ctx, "shop")
	v := info.Standby
	if v.Status != protocol.StandbyReady || v.LagBytes == nil || *v.LagBytes != 256 || !v.CanPromote || !info.Local.PromoteNeedsDown ||
		info.Local.DownConfirm != "10.0.0.5 is down" {
		t.Fatalf("standby view %+v %+v", v, info.Local)
	}
	if _, err := sc.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupFull}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a backup of the standby: %v", err)
	}

	// The primary sees the stream and its lag.
	lag, lagB := 3.0, int64(256)
	standbyBeat(pa, protocol.StandbyHeartbeat{Primaries: []protocol.PrimaryState{{DatabaseID: pdb.ID, WALLSN: "0/3000100",
		Streams: []protocol.StandbyStream{{Role: "rowsafe_standby_sb_shop", State: "streaming", ReplayLagSeconds: &lag, ReplayLagBytes: &lagB}}}}})
	info, _ = pc.StandbyInfo(ctx, "shop")
	if info.Standby == nil || info.Standby.Mode != protocol.StandbyModeStreaming || *info.Standby.LagSeconds != 3 || !info.Local.Link.Streaming {
		t.Fatalf("primary view %+v", info.Standby)
	}

	// Promoting before the primary stopped needs the typed "is down".
	if _, err := sc.PromoteStandby(ctx, "shop", protocol.PromoteStandbyRequest{Confirm: "shop"}); apiStatus(err) != http.StatusBadRequest ||
		!strings.Contains(err.Error(), "10.0.0.5 is down") {
		t.Fatalf("promote without the primary stopping: %v", err)
	}
	if _, err := sc.SetFailover(ctx, "shop", protocol.FailoverSettings{Automatic: true, Confirm: "shop"}); apiStatus(err) != http.StatusConflict ||
		!strings.Contains(err.Error(), "witness") {
		t.Fatalf("automatic failover: %v", err)
	}

	// Switchover, step 1: the primary is fenced (its agent holds it).
	if _, err := pc.LocalStandbyChange(ctx, "shop", "fence", "nope"); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("fence without the confirmation: %v", err)
	}
	if _, err := pc.CreateTask(ctx, "shop", protocol.TaskBackup, protocol.BackupParams{Type: protocol.BackupDiff}); err != nil {
		t.Fatal(err)
	}
	info, err = pc.LocalStandbyChange(ctx, "shop", "fence", "shop")
	if err != nil || info.Local.Role != protocol.LocalRoleFenced || len(info.Fences) != 1 {
		t.Fatalf("fence: %+v %v", info, err)
	}
	if ts, _ := pc.Tasks(ctx, "shop", 5); ts[1].Type != protocol.TaskBackup || ts[1].Status != protocol.StatusCancelled {
		t.Fatalf("the queued backup wasn't cancelled: %+v", ts[1])
	}
	resp = standbyBeat(pa, protocol.StandbyHeartbeat{})
	if len(resp.Fences) != 1 || resp.Fences[0].Port != 5432 || len(resp.Databases) != 0 {
		t.Fatalf("heartbeat while fenced %+v", resp)
	}
	fence := pa.claimOne(protocol.TaskStandbyFence, protocol.TaskStandbyFence)
	fp := params[protocol.StandbyFenceParams](t, fence)
	if !fp.Record || fp.FenceID != resp.Fences[0].ID || fp.StandbyID != "sb_shop" {
		t.Fatalf("fence params %+v", fp)
	}
	pa.done(fence, protocol.StatusSucceeded, protocol.StandbyFenceResult{FenceID: fp.FenceID, Stopped: true, CheckpointLSN: "0/3000200", Recorded: true})
	stoppedAt := *pnow
	standbyBeat(pa, protocol.StandbyHeartbeat{Fences: []protocol.FenceState{{ID: fp.FenceID, DatabaseID: pdb.ID, Port: 5432, StoppedAt: &stoppedAt, At: stoppedAt}}})
	info, _ = pc.StandbyInfo(ctx, "shop")
	if f := info.Fences[0]; !f.Stopped || !f.Clean || !f.CanUnfence {
		t.Fatalf("fence view %+v", f)
	}

	// Step 2: the standby reads in the bucket that the primary stopped, and
	// promotes without the typed "is down".
	standbyBeat(sa, protocol.StandbyHeartbeat{Standbys: []protocol.StandbyState{following},
		Records: []protocol.PrimaryRecordState{{DatabaseID: sdb.ID, Record: record(protocol.PrimaryRecordStopped, "0/3000200", stoppedAt), At: *snow}}})
	info, _ = sc.StandbyInfo(ctx, "shop")
	if info.Local.PromoteNeedsDown || info.Primary.Hostname != "db1" {
		t.Fatalf("after the fence: %+v %+v", info.Local, info.Primary)
	}
	if _, err := sc.PromoteStandby(ctx, "shop", protocol.PromoteStandbyRequest{Confirm: "shop"}); err != nil {
		t.Fatal(err)
	}
	promote := sa.claimOne(protocol.TaskStandbyPromote, protocol.TaskStandbyPromote)
	if pr := params[protocol.StandbyPromoteParams](t, promote); !pr.Record || pr.PrimaryDown || pr.StandbyID != "sb_shop" {
		t.Fatalf("promote params %+v", pr)
	}
	sa.done(promote, protocol.StatusSucceeded, protocol.StandbyPromoteResult{StandbyID: "sb_shop", Promoted: true, Timeline: 2, CaughtUp: true, Recorded: true})
	// Backups start on the new primary.
	sdb, _ = sc.Database(ctx, "shop")
	if sdb.Status != protocol.DBActive {
		t.Fatalf("after promoting: %s", sdb.Status)
	}
	sa.claimOne(protocol.TaskBackup)
	resp = standbyBeat(sa, protocol.StandbyHeartbeat{})
	if len(resp.Databases) != 1 {
		t.Fatalf("the promoted database isn't backed up: %+v", resp)
	}

	// The old primary: the record says another server took over, so it
	// can't be started again; it can become the new standby.
	standbyBeat(pa, protocol.StandbyHeartbeat{Records: nil})
	s := pc
	*pnow = pnow.Add(time.Minute)
	promoted := record(protocol.PrimaryRecordPrimary, "", *pnow)
	promoted.Primary, promoted.Fingerprint, promoted.Timeline = "db2", "EEEE-FFFF-0000-1111", 2
	standbyBeat(pa, protocol.StandbyHeartbeat{Records: []protocol.PrimaryRecordState{{DatabaseID: pdb.ID, Record: promoted, At: *pnow}}})
	if _, err := s.Unfence(ctx, "shop", protocol.UnfenceRequest{Confirm: "shop"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("unfence after the standby was promoted: %v", err)
	}
	info, err = pc.LocalStandbyCreate(ctx, "shop", protocol.LocalStandbyRequest{PrimaryAddress: "10.0.0.6", Confirm: "shop"})
	if err != nil {
		t.Fatal(err)
	}
	rebuild := pa.claimOne(protocol.TaskStandbyCreate)
	rp := params[protocol.StandbyCreateParams](t, rebuild)
	if !rp.Rebuild || rp.FenceID != fp.FenceID || !rp.FromBucket || rp.Port != 5432 {
		t.Fatalf("rebuild params %+v", rp)
	}
	pa.done(rebuild, protocol.StatusSucceeded, protocol.StandbyCreateResult{StandbyID: "sb_shop", Reattached: true})
	if resp := standbyBeat(pa, protocol.StandbyHeartbeat{}); len(resp.Fences) != 0 {
		t.Fatalf("the fence outlived the rebuild: %+v", resp.Fences)
	}
	if d, _ := pc.Database(ctx, "shop"); d.Status != dbStandby {
		t.Fatalf("the old primary after the rebuild: %s", d.Status)
	}
}

func TestStandbySuperseded(t *testing.T) {
	ctx := context.Background()
	s, a, c, now := setup(t)
	db := activeDB(t, a, c, now)
	_, got := receiver(t)
	_ = got
	// The agent reads in the bucket that another server was promoted after
	// this one: the control plane fences it at once.
	rec := record(protocol.PrimaryRecordPrimary, "", *now)
	rec.Primary, rec.Fingerprint, rec.Timeline = "db2", "EEEE-FFFF-0000-1111", 2
	resp := standbyBeat(a, protocol.StandbyHeartbeat{Records: []protocol.PrimaryRecordState{{DatabaseID: db.ID, Record: rec, Superseded: true, At: *now}}})
	if len(resp.Fences) != 1 || resp.Fences[0].DatabaseID != db.ID || len(resp.Databases) != 0 {
		t.Fatalf("not fenced: %+v", resp)
	}
	info, _ := c.StandbyInfo(ctx, "shop")
	if info.Local.Role != protocol.LocalRoleFenced || info.Primary.Hostname != "db2" || info.Fences[0].CanUnfence {
		t.Fatalf("view %+v", info)
	}
	if _, err := c.Unfence(ctx, "shop", protocol.UnfenceRequest{Confirm: "shop"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("unfence after another server took over: %v", err)
	}
	s.Tick()
	alerts, _ := c.Alerts(ctx, "firing", 50)
	if !slices.ContainsFunc(alerts, func(x protocol.Alert) bool { return x.Rule == "standby_promoted" && strings.Contains(x.Summary, "db2") }) {
		t.Fatalf("no standby_promoted alert: %+v", alerts)
	}
	// Something starts it again: fence_breached after a minute.
	running := *now
	standbyBeat(a, protocol.StandbyHeartbeat{Fences: []protocol.FenceState{{ID: resp.Fences[0].ID, DatabaseID: db.ID, Port: 5432, Running: true, At: running}}})
	s.Tick()
	*now = now.Add(2 * time.Minute)
	standbyBeat(a, protocol.StandbyHeartbeat{Fences: []protocol.FenceState{{ID: resp.Fences[0].ID, DatabaseID: db.ID, Port: 5432, Running: true, At: *now}}})
	s.Tick()
	alerts, _ = c.Alerts(ctx, "firing", 50)
	if !slices.ContainsFunc(alerts, func(x protocol.Alert) bool { return x.Rule == "fence_breached" }) {
		t.Fatalf("no fence_breached alert: %+v", alerts)
	}
	// Let it go: the database is forgotten here.
	if _, err := c.ForgetFence(ctx, "shop", protocol.ForgetFenceRequest{Confirm: "shop"}); err != nil {
		t.Fatal(err)
	}
	if resp := standbyBeat(a, protocol.StandbyHeartbeat{}); len(resp.Fences) != 0 {
		t.Fatalf("fences after forgetting: %+v", resp.Fences)
	}
	if _, err := c.Database(ctx, "shop"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("still known: %v", err)
	}
}

func TestStandbyFenceUndone(t *testing.T) {
	ctx := context.Background()
	_, a, c, now := setup(t)
	activeDB(t, a, c, now)
	standbyBeat(a, protocol.StandbyHeartbeat{})
	if _, err := c.LocalStandbyChange(ctx, "shop", "fence", "shop"); err != nil {
		t.Fatal(err)
	}
	f := a.claimOne(protocol.TaskStandbyFence, protocol.TaskStandbyFence)
	a.done(f, protocol.StatusFailed, nil)
	// The agent undid the fence (PostgreSQL still runs as the primary): it
	// doesn't report it, so the database is the primary again.
	resp := standbyBeat(a, protocol.StandbyHeartbeat{})
	if len(resp.Fences) != 0 || len(resp.Databases) != 1 {
		t.Fatalf("after a failed fence: %+v", resp)
	}
	if d, _ := c.Database(ctx, "shop"); d.Status != protocol.DBActive {
		t.Fatalf("status %s", d.Status)
	}
}

func TestStandbyAlerts(t *testing.T) {
	ctx := context.Background()
	s, a, c, now := setup(t)
	standbyBeat(a, protocol.StandbyHeartbeat{})
	if _, err := c.LocalStandbyCreate(ctx, "shop", protocol.LocalStandbyRequest{PrimaryAddress: "10.0.0.5", Confirm: "shop"}); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskStandbyCreate), protocol.StatusSucceeded, protocol.StandbyCreateResult{})
	d, _ := c.Database(ctx, "shop")
	since := *now
	at := *now
	st := protocol.StandbyState{StandbyID: "sb_shop", DatabaseID: d.ID, Port: 5432, Phase: protocol.StandbyPhaseFollowing, Running: true, InRecovery: true,
		Mode: protocol.StandbyModeArchive, PrimaryAddress: "10.0.0.5", PrimaryUnreachableSince: &since, LastReplayAt: &at, CheckedAt: at}
	for range 3 {
		standbyBeat(a, protocol.StandbyHeartbeat{Standbys: []protocol.StandbyState{st}})
		s.Tick()
		*now = now.Add(2 * time.Minute)
	}
	alerts, _ := c.Alerts(ctx, "firing", 50)
	if !slices.ContainsFunc(alerts, func(x protocol.Alert) bool {
		return x.Rule == "standby_primary_unreachable" && strings.Contains(x.NextStep, "--primary-down")
	}) {
		t.Fatalf("no standby_primary_unreachable alert: %+v", alerts)
	}
	// Through the bucket the lag isn't known: no standby_behind on an idle primary.
	if slices.ContainsFunc(alerts, func(x protocol.Alert) bool { return x.Rule == "standby_behind" }) {
		t.Fatal("standby_behind through the bucket")
	}
	// PostgreSQL stops: standby_down.
	st.Running, st.Phase, st.Error = false, protocol.StandbyPhaseStopped, "connection refused"
	for range 4 {
		standbyBeat(a, protocol.StandbyHeartbeat{Standbys: []protocol.StandbyState{st}})
		s.Tick()
		*now = now.Add(2 * time.Minute)
	}
	alerts, _ = c.Alerts(ctx, "firing", 50)
	if !slices.ContainsFunc(alerts, func(x protocol.Alert) bool { return x.Rule == "standby_down" }) {
		t.Fatalf("no standby_down alert: %+v", alerts)
	}
	// Removing it gives the cluster its own data back and forgets the database.
	if _, err := c.LocalStandbyChange(ctx, "shop", "remove", "shop"); err != nil {
		t.Fatal(err)
	}
	a.done(a.claimOne(protocol.TaskStandbyRemove), protocol.StatusSucceeded, protocol.StandbyRemoveResult{StandbyID: "sb_shop", Restored: true})
	if _, err := c.Database(ctx, "shop"); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("after removing: %v", err)
	}
}
