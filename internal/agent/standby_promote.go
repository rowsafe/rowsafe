package agent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Promoting the standby.
//
// When the old primary was fenced (stopped cleanly, its last WAL pushed to
// the bucket), its shutdown checkpoint is WaitForLSN: the standby promotes
// only once it has replayed past it, so nothing the old primary committed
// is lost. Without it (the old primary is unreachable), the standby first
// replays everything it has received (streaming), or until the bucket has
// nothing newer for a while (archive), then promotes. Then it drops its own
// replication role (it came from the old primary) and forgets the
// connection to the old primary.

func (a *Agent) standbyPromote(ctx context.Context, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, tl *taskLog) (*protocol.StandbyPromoteResult, error) {
	rt := a.sb()
	if !standbyIDRE.MatchString(p.StandbyID) {
		return nil, fmt.Errorf("invalid standby id %q", p.StandbyID)
	}
	if !rt.opMu.TryLock() {
		return nil, errors.New("another standby change is running on this server; try again when it has finished")
	}
	defer rt.opMu.Unlock()
	rec, ok := rt.standby(p.StandbyID)
	if !ok {
		return nil, errors.New("there is no such standby on this server")
	}
	if rec.Phase == protocol.StandbyPhaseCreating {
		return nil, errors.New("the standby is still being created")
	}
	ops := a.sops()
	res := &protocol.StandbyPromoteResult{StandbyID: p.StandbyID}
	st, err := ops.status(ctx, rec.Database)
	if err != nil {
		return nil, fmt.Errorf("the standby's PostgreSQL isn't answering: %w", err)
	}
	if !st.InRecovery {
		// Already promoted (a retried task).
		res.Promoted, res.CaughtUp, res.Timeline = true, true, st.Timeline
		res.Summary = "The standby already is the primary."
		_ = rt.removeStandby(p.StandbyID)
		return res, nil
	}
	rec.Phase = protocol.StandbyPhasePromoting
	_ = rt.putStandby(rec)
	back := func() {
		rec.Phase = protocol.StandbyPhaseFollowing
		_ = rt.putStandby(rec)
	}
	if st.Paused {
		tl.Printf("replay was paused; resuming it")
		_ = ops.exec(ctx, rec.Database, `SELECT pg_wal_replay_resume()`)
	}

	// Catch up.
	deadline := time.Now().Add(standbyPromoteWait)
	var lastReplay string
	stableSince := time.Now()
	for {
		st, err = ops.status(ctx, rec.Database)
		if err != nil {
			back()
			return nil, fmt.Errorf("reading the standby's replay position: %w", err)
		}
		if st.ReplayLSN != lastReplay {
			lastReplay, stableSince = st.ReplayLSN, time.Now()
		}
		caught := false
		switch {
		case p.WaitForLSN != "":
			caught = lsnDiff(st.ReplayLSN, p.WaitForLSN) > 0
		case st.ReceiverStatus == "streaming":
			caught = st.ReceiveLSN != "" && lsnAtLeast(st.ReplayLSN, st.ReceiveLSN)
		default:
			caught = time.Since(stableSince) >= 15*time.Second
		}
		if caught {
			res.CaughtUp = true
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	if p.WaitForLSN != "" && !res.CaughtUp {
		res.MissingBytes = max(lsnDiff(p.WaitForLSN, st.ReplayLSN), 1)
		if !p.Force {
			back()
			res.Summary = fmt.Sprintf("Didn't promote: after %s the standby still misses %s of the old primary's last changes (it replayed up to %s, the old primary stopped at %s). "+
				"The old primary is stopped. Promote anyway to accept losing them, or start the old primary again.",
				standbyPromoteWait, humanBytes(res.MissingBytes), st.ReplayLSN, p.WaitForLSN)
			return res, errors.New(res.Summary)
		}
		tl.Printf("promoting anyway (forced): %s of the old primary's last changes are missing", humanBytes(res.MissingBytes))
	}
	res.ReplayLSN, res.LastReplayAt = st.ReplayLSN, st.LastReplayAt
	tl.Printf("replayed up to %s; promoting", st.ReplayLSN)

	if err := ops.exec(ctx, rec.Database, `SELECT pg_promote(true, 120)`); err != nil {
		back()
		return nil, fmt.Errorf("promoting: %w", err)
	}
	deadline = time.Now().Add(2 * time.Minute)
	for {
		st, err = ops.status(ctx, rec.Database)
		if err == nil && !st.InRecovery {
			break
		}
		if time.Now().After(deadline) {
			back()
			return nil, fmt.Errorf("PostgreSQL didn't finish promoting within 2 minutes: %v", err)
		}
		time.Sleep(time.Second)
	}
	now := time.Now().UTC()
	res.Promoted, res.PromotedAt, res.Timeline = true, &now, st.Timeline

	// The connection to the old primary and the role it made are no longer
	// needed.
	if err := ops.exec(ctx, rec.Database, `ALTER SYSTEM RESET primary_conninfo`); err != nil {
		tl.Printf("removing the connection to the old primary: %v", err)
	} else {
		_ = ops.exec(ctx, rec.Database, `SELECT pg_reload_conf()`)
	}
	if rec.Role != "" {
		if err := ops.exec(ctx, rec.Database, "DROP ROLE IF EXISTS "+pgx.Identifier{rec.Role}.Sanitize()); err != nil {
			tl.Printf("dropping the old replication role %s: %v", rec.Role, err)
		}
	}
	_ = ops.exec(ctx, rec.Database, `CHECKPOINT`)
	if rec.KeptDir != "" && exists(rec.KeptDir) {
		// The cluster's own data from before the standby isn't put back any
		// more: keep it a while, then delete it.
		kd := keptData{Path: rec.KeptDir, DataDir: rec.DataDir, DatabaseID: rec.DatabaseID, Until: keepUntil(0, now)}
		_ = rt.update(func(sf *standbyFile) { sf.Kept = append(sf.Kept, kd) })
	}
	_ = rt.removeStandby(p.StandbyID)
	rt.setCluster(rec.DatabaseID, clusterFacts{DataDir: rec.DataDir, Major: rec.Major, SystemID: st.SystemID,
		ConfigFile: rec.ConfigFile, HbaFile: rec.HbaFile, IdentFile: rec.IdentFile})

	switch {
	case p.WaitForLSN != "" && res.CaughtUp:
		res.Summary = fmt.Sprintf("This server is the primary now (timeline %d). It replayed everything the old primary wrote before it was stopped.", res.Timeline)
	case p.WaitForLSN != "":
		res.Summary = fmt.Sprintf("This server is the primary now (timeline %d); %s of the old primary's last changes are missing.", res.Timeline, humanBytes(res.MissingBytes))
	default:
		last := "no transaction replayed since the backup"
		if res.LastReplayAt != nil {
			last = "last change replayed from " + res.LastReplayAt.Format("15:04:05 UTC")
		}
		res.Summary = fmt.Sprintf("This server is the primary now (timeline %d; %s). Changes the old primary made after that are not here.", res.Timeline, last)
	}
	tl.Printf("%s", res.Summary)
	return res, nil
}
