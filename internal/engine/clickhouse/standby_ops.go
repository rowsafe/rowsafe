package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// StandbyPromote applies the primary's last changes (up to the fenced old
// primary's last moment, p.WaitForLSN) and makes the standby writable: its
// merges start again, the read-only profile goes. From then on it is the
// primary; its copier starts a new record in the same bucket folder.
func (e *Engine) StandbyPromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, log agent.TaskLogger) (*protocol.StandbyPromoteResult, error) {
	store := e.standbyStore(env)
	l := e.standbyLock(p.StandbyID)
	l.Lock()
	defer l.Unlock()
	rec, ok := store.get(p.StandbyID)
	if !ok {
		return nil, fmt.Errorf("this server has no standby %s", p.StandbyID)
	}
	res := &protocol.StandbyPromoteResult{StandbyID: p.StandbyID}
	var until time.Time
	if p.WaitForLSN != "" {
		t, err := time.Parse(time.RFC3339Nano, p.WaitForLSN)
		if err != nil {
			return nil, fmt.Errorf("invalid moment to wait for %q", p.WaitForLSN)
		}
		until = t
	}
	// Apply until the old primary's last moment (or as far as the record
	// goes when there is none).
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if err := e.applyOnce(ctx, env, rec, until); err != nil {
			if !p.Force {
				return nil, fmt.Errorf("applying the primary's last changes: %w", err)
			}
			log.Printf("note: applying the primary's last changes failed (%v); promoting anyway", err)
			break
		}
		rec, _ = store.get(p.StandbyID)
		if until.IsZero() || !rec.AppliedTo.Before(until) {
			res.CaughtUp = true
			break
		}
		if time.Now().After(deadline) {
			if !p.Force {
				return nil, fmt.Errorf("the standby holds the primary as it was at %s, not yet %s: try again, or promote anyway",
					rec.AppliedTo.UTC().Format(time.RFC3339), until.UTC().Format(time.RFC3339))
			}
			log.Printf("note: promoting before every change of the old primary arrived")
			break
		}
		time.Sleep(3 * time.Second)
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: rec.Port})
	if err != nil {
		return nil, err
	}
	if err := setReadOnly(ctx, c, false); err != nil {
		return nil, fmt.Errorf("making the standby writable: %w", err)
	}
	_ = c.exec(ctx, "SYSTEM START MERGES", nil)
	_ = c.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(standbyTmpDB)+" SYNC", nil)
	now := time.Now().UTC()
	applied := rec.AppliedTo
	if err := store.remove(rec.ID); err != nil {
		return nil, err
	}
	res.Promoted, res.PromotedAt, res.LastReplayAt = true, &now, &applied
	res.ReplayLSN = applied.UTC().Format(time.RFC3339Nano)
	res.Summary = fmt.Sprintf("The ClickHouse server on port %d is the primary now, with every change up to %s. It takes writes; Rowsafe copies its changes from here on.",
		rec.Port, applied.UTC().Format("15:04:05 UTC"))
	if !res.CaughtUp {
		res.Summary += " Some of the old primary's last changes may be missing."
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRemove stops following and empties the server again (the
// databases the standby restored are dropped: they were a copy).
func (e *Engine) StandbyRemove(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, log agent.TaskLogger) (*protocol.StandbyRemoveResult, error) {
	store := e.standbyStore(env)
	l := e.standbyLock(p.StandbyID)
	l.Lock()
	defer l.Unlock()
	rec, ok := store.get(p.StandbyID)
	res := &protocol.StandbyRemoveResult{StandbyID: p.StandbyID}
	if !ok {
		res.Summary = "This server has no such standby any more."
		return res, nil
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{Port: rec.Port})
	if err != nil {
		return nil, fmt.Errorf("ClickHouse on port %d doesn't answer, so the standby can't be removed: %w", rec.Port, err)
	}
	var errs []error
	for _, d := range append(rec.DBs, standbyTmpDB) {
		if isSystemDB(d) || d == "default" {
			continue
		}
		if err := c.exec(ctx, "DROP DATABASE IF EXISTS "+quoteIdent(d)+" SYNC", nil); err != nil {
			errs = append(errs, fmt.Errorf("dropping %s: %w", d, err))
		}
	}
	if err := setReadOnly(ctx, c, false); err != nil {
		errs = append(errs, err)
	}
	_ = c.exec(ctx, "SYSTEM START MERGES", nil)
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	if err := store.remove(rec.ID); err != nil {
		return nil, err
	}
	res.Summary = fmt.Sprintf("Removed the standby: the ClickHouse server on port %d no longer follows %s, its copy was dropped and it takes writes again.", rec.Port, db.Name)
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyStates reports this server's standbys.
func (e *Engine) StandbyStates(ctx context.Context, env agent.EngineEnv) []protocol.StandbyState {
	var out []protocol.StandbyState
	recs := e.standbyStore(env).all()
	if len(recs) > 0 {
		e.wakeStandbys(env) // after an agent restart
	}
	for _, rec := range recs {
		now := time.Now().UTC()
		s := protocol.StandbyState{StandbyID: rec.ID, DatabaseID: rec.DatabaseID, Port: rec.Port, Phase: rec.Phase,
			Mode: protocol.StandbyModeArchive, CheckedAt: now, Error: rec.Error}
		if !rec.AppliedTo.IsZero() {
			t := rec.AppliedTo
			s.LastReplayAt = &t
			s.ReplayLSN = t.UTC().Format(time.RFC3339Nano)
			s.ReceiveLSN = s.ReplayLSN
		}
		if rec.Phase != protocol.StandbyPhaseCreating {
			cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			c, err := connectDB(cctx, env, protocol.DatabaseSpec{Port: rec.Port})
			if err != nil {
				s.Phase, s.Error = protocol.StandbyPhaseStopped, err.Error()
			} else {
				s.Running = true
				ro, _ := isReadOnly(cctx, c)
				s.InRecovery = ro
				if !ro && s.Error == "" {
					s.Error = "the standby isn't read-only"
				}
			}
			cancel()
		}
		out = append(out, s)
	}
	return out
}
