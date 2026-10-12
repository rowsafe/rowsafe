package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

var _ agent.EngineStandby = (*Engine)(nil)

// StandbyPromote makes the standby the primary: it waits until it has
// applied what the old primary wrote, stops replication and takes writes.
func (e *Engine) StandbyPromote(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPromoteParams, log agent.TaskLogger) (*protocol.StandbyPromoteResult, error) {
	store := standbys(env)
	rec, ok := store.get(p.StandbyID)
	if !ok {
		return nil, errors.New("this server runs no such standby")
	}
	db.Port, db.SocketDir = rec.Port, rec.Socket
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	res := &protocol.StandbyPromoteResult{StandbyID: p.StandbyID}
	st, err := s.readReplicaStatus(ctx, conn)
	if err != nil {
		return nil, err
	}
	if !st.Configured {
		return nil, fmt.Errorf("the %s server on port %d doesn't replicate any more (was it promoted by hand?)", s.flavor.display(), rec.Port)
	}
	want, haveWant := parseFilePos(p.WaitForLSN)
	if haveWant {
		log.Printf("waiting until the standby has applied everything up to %s (where the old primary stopped)", want)
	} else {
		log.Printf("the old primary's last position isn't known: waiting until the standby has applied everything it received")
	}
	deadline := time.Now().Add(standbyPromoteWait)
	for {
		if st, err = s.readReplicaStatus(ctx, conn); err != nil {
			return nil, err
		}
		target := st.Read
		if haveWant {
			target = want
		}
		if st.Exec.atLeast(target) {
			res.CaughtUp = true
			break
		}
		if st.SQLRunning == "No" && st.SQLError != "" {
			if !p.Force {
				return nil, fmt.Errorf("the standby stopped applying changes (%s): it was left as it is; promote anyway to accept that", st.SQLError)
			}
			break
		}
		if time.Now().After(deadline) {
			if !p.Force {
				return nil, fmt.Errorf("the standby hasn't applied everything the old primary wrote within %s (it is at %s, it needs %s): "+
					"it was left as it is; promote anyway to accept losing the rest", standbyPromoteWait, st.Exec, target)
			}
			if st.Exec.File == target.File && target.Pos > st.Exec.Pos {
				res.MissingBytes = target.Pos - st.Exec.Pos
			}
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	var version string
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		return nil, err
	}
	w := s.words(version)
	if _, err := conn.ExecContext(ctx, w.Stop); err != nil {
		return nil, fmt.Errorf("stopping replication: %w", err)
	}
	// Where the old primary's history ends, as this server applied it.
	final, err := s.readReplicaStatus(ctx, conn)
	if err != nil {
		return nil, err
	}
	if _, err := conn.ExecContext(ctx, w.Reset); err != nil {
		return nil, fmt.Errorf("forgetting the old primary: %w", err)
	}
	now := time.Now().UTC()
	// Still read-only: its own binary log starts in a file of its own,
	// and the switch is recorded in the bucket (restores to a moment after
	// it go on there until this server's first backup).
	f, ferr := s.readFacts(ctx, conn)
	flushed := false
	if ferr == nil && f.LogBin {
		if _, err := conn.ExecContext(ctx, "FLUSH BINARY LOGS"); err != nil {
			log.Printf("note: couldn't start a new binary log file: %v", err)
		} else {
			flushed = true
		}
	}
	noRecord := func(why string) {
		w := "Restores to a moment after the switch wait for this server's first backup: " + why + "."
		res.Warnings = append(res.Warnings, w)
		log.Printf("note: %s", w)
	}
	if pos, err := s.currentPosition(ctx, conn); err == nil {
		res.ReplayLSN = filePos{File: pos.File.Name, Pos: pos.Pos}.String() // where the old primary can follow from
		switch {
		case s.env.Repo.Bucket == "" || ferr != nil || !f.LogBin:
		case !flushed:
			// Its current file also holds what it replicated: a restore
			// going on there would apply that twice.
			noRecord("it couldn't start a binary log file of its own, so the switch wasn't recorded in the bucket")
		case final.Exec.File == "" || final.SourceServerID == "":
			noRecord("the standby didn't say where the old primary's history ends, so the switch wasn't recorded in the bucket")
		default:
			if err := s.recordStandbySwitch(ctx, f, final, pos, now); err != nil {
				noRecord("recording the switch in the bucket failed (" + err.Error() + ")")
			} else {
				log.Printf("recorded the switch in the bucket: the old primary's history ends at %s, this server's begins with %s", final.Exec, pos.File.Name)
			}
		}
	}
	if err := s.setReadOnly(ctx, conn, false); err != nil {
		return nil, fmt.Errorf("making the new primary writable: %w", err)
	}
	// It had no standby of its own: replication logins left from when it
	// was a primary before go.
	if err := s.dropStaleReplicationLogins(ctx, conn); err != nil {
		log.Printf("dropping old replication logins: %v", err)
	}
	res.Promoted, res.PromotedAt, res.LastReplayAt = true, &now, &now
	_ = store.remove(rec.ID)
	s.removeSourceCA(rec)
	res.Summary = fmt.Sprintf("%s on port %d is the primary now and takes writes.", s.flavor.display(), rec.Port)
	if !res.CaughtUp {
		res.Summary += " It was promoted before it had every change of the old primary."
	}
	for _, w := range res.Warnings {
		res.Summary += " " + w
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// StandbyRemove stops replicating and puts the server back as it was.
func (e *Engine) StandbyRemove(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyRemoveParams, log agent.TaskLogger) (*protocol.StandbyRemoveResult, error) {
	store := standbys(env)
	res := &protocol.StandbyRemoveResult{StandbyID: p.StandbyID}
	rec, ok := store.get(p.StandbyID)
	if !ok {
		res.Summary = "No such standby runs here (already removed)."
		return res, nil
	}
	db.Port, db.SocketDir = rec.Port, rec.Socket
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.undoStandby(ctx, conn, rec, log); err != nil {
		return nil, err
	}
	_ = store.remove(rec.ID)
	s.removeSourceCA(rec)
	if rec.Rebuild {
		res.Summary = fmt.Sprintf("Removed the standby: %s on port %d doesn't replicate any more; its data (a copy of the database) stays, read-only.",
			s.flavor.display(), rec.Port)
		// Nothing holds it read-only for Rowsafe any more: the logins
		// locked for that sign in again.
		mu := s.writerMu()
		mu.Lock()
		done, err := s.unlockWriters(ctx, conn)
		mu.Unlock()
		if len(done) > 0 {
			res.Summary += " The logins Rowsafe had locked while it was read-only (" + strings.Join(done, ", ") + ") can sign in again."
		}
		if err != nil {
			res.Summary += " Some logins Rowsafe had locked are still locked: " + err.Error() + "."
		}
	} else {
		res.Restored = true
		res.Summary = fmt.Sprintf("Removed the standby: %s on port %d is empty and writable again, as before.", s.flavor.display(), rec.Port)
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
	e.healWriterLocks(ctx, env) // MariaDB: logins left locked on a server that takes writes
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
	s := e.server(env, protocol.DatabaseSpec{ID: rec.DatabaseID, Engine: string(e.flavor), Port: rec.Port, SocketDir: rec.Socket})
	conn, err := s.open(cctx)
	if err != nil {
		out.Phase, out.Error = protocol.StandbyPhaseStopped, err.Error()
		return out
	}
	defer conn.Close()
	out.Running = true
	st, err := s.readReplicaStatus(cctx, conn)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	ro, _ := s.isReadOnly(cctx, conn)
	out.InRecovery = st.Configured && ro
	if ro {
		s.keepWritersLocked(cctx, conn) // MariaDB: logins replicated since (standby_lock.go)
	}
	out.ReceiveLSN = lsn(st.Read.File, st.Read.Pos)
	out.ReplayLSN = lsn(st.Exec.File, st.Exec.Pos)
	if st.IORunning == "Yes" {
		out.ReceiverStatus = "streaming"
		out.StreamingSeenAt = &now
		out.PrimaryReachable = true
		_ = store.update(func(f *standbyFile) {
			for i := range f.Standbys {
				if f.Standbys[i].ID == rec.ID {
					f.Standbys[i].StreamSeen = now
				}
			}
		})
	} else if _, err := reachable([]string{rec.Address}, rec.PrimPort); err == nil {
		out.PrimaryReachable = true
	}
	if st.SecondsBehind != nil {
		t := now.Add(-time.Duration(*st.SecondsBehind) * time.Second)
		out.LastReplayAt = &t
	}
	switch {
	case st.SQLRunning != "Yes" && st.SQLError != "":
		out.Error = "applying the primary's changes stopped: " + st.SQLError
	case st.IORunning != "Yes" && st.IOError != "":
		out.Error = "receiving the primary's changes: " + st.IOError
	case !ro:
		out.Error = "the standby isn't read-only"
	}
	if why := s.watchKey(cctx, conn, store, rec, st); why != "" {
		out.Error = why
	}
	return out
}

// Targets are cached: listing them connects to every local server.
var (
	targetsMu    sync.Mutex
	targetsCache = map[string]targetsEntry{}
)

type targetsEntry struct {
	at  time.Time
	out []protocol.StandbyTarget
}

// StandbyTargets lists the local servers of this flavor that could hold a
// standby.
func (e *Engine) StandbyTargets(ctx context.Context, env agent.EngineEnv) []protocol.StandbyTarget {
	if env.Config.Sidecar() {
		return nil
	}
	targetsMu.Lock()
	c, ok := targetsCache[string(e.flavor)]
	targetsMu.Unlock()
	if ok && time.Since(c.at) < 2*time.Minute {
		return c.out
	}
	found, _ := e.Discover(ctx, env)
	store := standbys(env)
	var out []protocol.StandbyTarget
	for _, d := range found {
		t := protocol.StandbyTarget{Engine: string(e.flavor), Port: d.Port, Version: d.Version, Socket: d.SocketDir}
		t.Reason, t.Replication = e.targetReason(ctx, env, store, d)
		t.Usable = t.Reason == ""
		t.Standby, t.NoStandby = t.Usable, t.Reason // the same rights and an empty server
		out = append(out, t)
	}
	targetsMu.Lock()
	targetsCache[string(e.flavor)] = targetsEntry{at: time.Now(), out: out}
	targetsMu.Unlock()
	return out
}

// targetReason says why the server can't take a standby or a clone ("" when
// it can), and whether Rowsafe's account there may set up replication (nil:
// not known).
func (e *Engine) targetReason(ctx context.Context, env agent.EngineEnv, store *standbyStore, d agent.DiscoveredDatabase) (string, *bool) {
	if r, ok := store.onPort(d.Port); ok && r.Phase != protocol.StandbyPhaseCreating {
		return "it already runs a standby", nil
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	s := e.server(env, protocol.DatabaseSpec{Engine: string(e.flavor), Port: d.Port, SocketDir: d.SocketDir})
	conn, err := s.open(cctx)
	if err != nil {
		return "Rowsafe has no account on it: run the Rowsafe installer on this server and answer yes to standby servers", nil
	}
	defer conn.Close()
	ok, err := standbyRights(cctx, conn)
	if err != nil {
		return "Rowsafe's account there may not set up standby servers: run the Rowsafe installer on this server again and answer yes to standby servers", nil
	}
	if !ok {
		return "Rowsafe's account there may not set up standby servers: run the Rowsafe installer on this server again and answer yes to standby servers", &ok
	}
	if schemas, err := userSchemas(cctx, conn); err != nil {
		return err.Error(), &ok
	} else if len(schemas) > 0 {
		return "it isn't empty (databases: " + strings.Join(schemas, ", ") + ")", &ok
	}
	if st, err := s.readReplicaStatus(cctx, conn); err == nil && st.Configured {
		return "it already replicates from " + st.SourceHost, &ok
	}
	return "", &ok
}

// recordStandbySwitch writes the link from the old primary's last applied position
// (final, in its files) to this server's new file (pos) in the bucket.
func (s *server) recordStandbySwitch(ctx context.Context, f facts, final replicaStatus, pos position, at time.Time) error {
	to, err := readBinlogFile(filepath.Join(filepath.Dir(f.LogBinBasename), pos.File.Name))
	if err != nil {
		return err
	}
	if to.Server != strconv.FormatInt(f.ServerID, 10) {
		return fmt.Errorf("the binary log file %s here wasn't written by this server (server_id %s, not %d)", to.Name, to.Server, f.ServerID)
	}
	st, err := openStore(s.env.Repo, string(s.flavor), s.db.Stanza, s.cfg.PartSizeMB)
	if err != nil {
		return err
	}
	lk := binlogLink{From: linkFrom{Name: final.Exec.File, Server: final.SourceServerID, Pos: final.Exec.Pos}, To: to, At: at}
	return st.putJSON(ctx, linkKey(to), lk)
}

// dropStaleReplicationLogins drops every standby login of Rowsafe's here,
// outside the binary log.
func (s *server) dropStaleReplicationLogins(ctx context.Context, conn *sql.DB) error {
	c, err := conn.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return err
	}
	return dropReplicationUsers(ctx, c)
}
