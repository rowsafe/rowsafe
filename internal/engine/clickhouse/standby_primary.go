package clickhouse

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// Standby servers (protocol.FeatureStandby). ClickHouse's own replication
// needs ClickHouse Keeper and Replicated tables; most servers have
// neither. So a Rowsafe standby follows its primary through the bucket,
// like PostgreSQL's archive recovery: it starts from the primary's newest
// moment and applies every part the primary's copier records (pitr_*.go),
// partition by partition, a few seconds after it reaches the bucket. The
// standby is read-only for everyone but Rowsafe (a settings profile,
// readonly = 2, for every user), its merges are stopped (it mirrors the
// primary's), and nothing else changes on the primary: no login, no
// network path between the two servers.
//
// The same read-only profile fences an old primary when its standby is
// promoted: ClickHouse keeps running there but takes no more writes.

// readOnlyProfile makes every user but Rowsafe's read-only.
const readOnlyProfile = "rowsafe_read_only"

// setReadOnly turns the profile on or off.
func setReadOnly(ctx context.Context, c *client, on bool) error {
	if !on {
		return c.exec(ctx, "DROP SETTINGS PROFILE IF EXISTS "+quoteIdent(readOnlyProfile), nil)
	}
	err := c.exec(ctx, "CREATE SETTINGS PROFILE OR REPLACE "+quoteIdent(readOnlyProfile)+
		" SETTINGS readonly = 2 CONST TO ALL EXCEPT "+quoteIdent(LoginUser), nil)
	if err != nil && (errCode(err) == codeAccessDenied || strings.Contains(err.Error(), "ACCESS_DENIED")) {
		return errors.New("Rowsafe's ClickHouse user can't manage settings profiles (access management): " +
			"run the Rowsafe installer on the server again so it can make ClickHouse read-only")
	}
	return err
}

// isReadOnly reports whether the profile is in place.
func isReadOnly(ctx context.Context, c *client) (bool, error) {
	v, err := c.scalar(ctx, "SELECT count() FROM system.settings_profiles WHERE name = {p:String}", map[string]string{"p": readOnlyProfile})
	return strings.TrimSpace(v) == "1", err
}

// serverID is the server's own UUID (serverUUID()): the same server answers
// on a port.
func serverID(ctx context.Context, c *client) string {
	v, err := c.scalar(ctx, "SELECT toString(serverUUID())", nil)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// StandbyPrepare checks the database can be followed: its changes are
// copied to the bucket (the standby reads them there). Nothing changes on
// the primary.
func (e *Engine) StandbyPrepare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams,
	sec *protocol.StandbySecrets, res *protocol.StandbyPrepareResult, log agent.TaskLogger) error {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return err
	}
	in, err := inspect(ctx, c)
	if err != nil {
		return err
	}
	s, err := e.shipperFor(env, db)
	if err != nil {
		return err
	}
	st, serr := s.snapshot()
	if st.Problem != "" {
		return errors.New("a standby follows the changes Rowsafe copies, and they aren't being copied: " + st.Problem)
	}
	if st.Record == "" {
		if serr != nil {
			return fmt.Errorf("a standby follows the changes Rowsafe copies, and copying hasn't started: %w", serr)
		}
		return errors.New("a standby follows the changes Rowsafe copies, and copying hasn't started yet: try again in a minute")
	}
	r, err := openRepo(env, db)
	if err != nil {
		return err
	}
	docs, _, err := r.listBackups(ctx)
	if err != nil {
		return err
	}
	ok := false
	for _, d := range docs {
		if !d.StartedAt.Before(st.Started) {
			ok = true
		}
	}
	if !ok {
		return errors.New("a standby starts from a backup taken since Rowsafe began copying this server's changes, and there is none yet: take a backup, then add the standby")
	}
	res.Major = in.VersionNum / 100
	res.SystemID = serverID(ctx, c)
	res.SizeBytes = in.TotalBytes
	res.Streaming = false
	if n := in.Replicated(); n > 0 || in.ReplicatedDB {
		res.Warnings = append(res.Warnings, "This server has replicated tables (ClickHouse Keeper). ClickHouse's own replication can add a replica of them; "+
			"Rowsafe's standby follows them through the bucket like the others.")
	}
	for _, t := range in.Tables {
		if f := engineFamily(t.Engine); f == "data" && !strings.Contains(t.Engine, "MergeTree") {
			res.Warnings = append(res.Warnings, "Tables that aren't MergeTree (Log, Memory...) are on the standby as of the backup it started from.")
			break
		}
	}
	res.Summary = fmt.Sprintf("%s can be followed: the standby starts from its newest moment in your bucket and applies each change ClickHouse makes, usually within a minute.", db.Name)
	log.Printf("%s", res.Summary)
	return nil
}

// StandbyRelease: prepare made nothing on the primary.
func (e *Engine) StandbyRelease(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, log agent.TaskLogger) (*protocol.StandbyReleaseResult, error) {
	res := &protocol.StandbyReleaseResult{StandbyID: p.StandbyID, Summary: "Nothing to undo on the primary: a ClickHouse standby follows it through your bucket."}
	return res, nil
}

// PrimaryState is how far the primary's record of changes goes.
func (e *Engine) PrimaryState(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.PrimaryState, bool) {
	e.mu.Lock()
	s := e.shippers[db.ID]
	e.mu.Unlock()
	if s == nil {
		return protocol.PrimaryState{}, false
	}
	st, _ := s.snapshot()
	if st.Record == "" {
		return protocol.PrimaryState{}, false
	}
	return protocol.PrimaryState{DatabaseID: db.ID, WALLSN: st.To.UTC().Format(time.RFC3339Nano), At: time.Now().UTC()}, true
}

// StandbyFence makes the old primary read-only for everyone but Rowsafe,
// stops the writes running, and waits until every change it made is in the
// bucket. CheckpointLSN is that moment: the standby applies up to it before
// it is promoted.
func (e *Engine) StandbyFence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, log agent.TaskLogger) (*protocol.StandbyFenceResult, error) {
	c, err := connectDB(ctx, env, db)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse on port %d doesn't answer, so Rowsafe can't make it read-only: %w", db.Port, err)
	}
	if id := serverID(ctx, c); p.SystemID != "" && id != "" && id != p.SystemID {
		return nil, fmt.Errorf("the ClickHouse on port %d is another server (%s, not %s); Rowsafe left it alone", db.Port, id, p.SystemID)
	}
	if err := setReadOnly(ctx, c, true); err != nil {
		return nil, err
	}
	log.Printf("ClickHouse on port %d is read-only now for every user but Rowsafe's", db.Port)
	_ = c.exec(ctx, "KILL QUERY WHERE user != currentUser() AND query_kind NOT IN ('Select', 'Show', 'Describe', 'Explain', 'System', 'Exists') ASYNC", nil)
	res := &protocol.StandbyFenceResult{FenceID: p.FenceID, Stopped: true, Method: "read_only"}
	if v, err := c.scalar(ctx, "SELECT count() FROM system.mutations WHERE NOT is_done AND database NOT IN ('system')", nil); err == nil && strings.TrimSpace(v) != "0" {
		res.Warnings = append(res.Warnings, fmt.Sprintf("%s changes (mutations) were still running; the standby has them as far as they had got", strings.TrimSpace(v)))
	}
	// Every change up to now reaches the bucket.
	time.Sleep(time.Second)
	now, err := serverNow(ctx, c)
	if err == nil {
		e.flushTo(ctx, env, db, now, log)
		e.mu.Lock()
		s := e.shippers[db.ID]
		e.mu.Unlock()
		if s != nil {
			if st, _ := s.snapshot(); !st.To.Before(now) {
				res.CheckpointLSN = now.UTC().Format(time.RFC3339Nano)
				res.FinalWALPushed = true
			}
		}
	}
	if res.CheckpointLSN == "" {
		res.Warnings = append(res.Warnings, "the newest changes may not have reached your bucket")
	}
	res.Summary = fmt.Sprintf("Made ClickHouse on port %d read-only (it keeps running, for reads) and stopped the writes in progress; the agent keeps it read-only.", db.Port)
	log.Printf("%s", res.Summary)
	return res, nil
}

// HoldFence keeps a fenced old primary read-only.
func (e *Engine) HoldFence(ctx context.Context, env agent.EngineEnv, f protocol.Fence) (enforced, other bool, err error) {
	if _, ok := e.standbyStore(env).onPort(f.Port); ok {
		return false, false, nil // it follows the new primary now
	}
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{ID: f.DatabaseID, Port: f.Port})
	if err != nil {
		return false, false, nil // down: nothing takes writes
	}
	if id := serverID(ctx, c); f.SystemID != "" && id != "" && id != f.SystemID {
		return false, true, nil
	}
	ro, err := isReadOnly(ctx, c)
	if err != nil || ro {
		return false, false, err
	}
	if err := setReadOnly(ctx, c, true); err != nil {
		return false, false, err
	}
	return true, false, nil
}

// StandbyUnfence lets the old primary take writes again.
func (e *Engine) StandbyUnfence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, f protocol.Fence, log agent.TaskLogger) (*protocol.StandbyUnfenceResult, error) {
	c, err := connectDB(ctx, env, protocol.DatabaseSpec{ID: db.ID, Port: f.Port})
	if err != nil {
		return nil, err
	}
	if err := setReadOnly(ctx, c, false); err != nil {
		return nil, fmt.Errorf("making ClickHouse writable again: %w", err)
	}
	res := &protocol.StandbyUnfenceResult{FenceID: f.ID, Started: true,
		Summary: fmt.Sprintf("ClickHouse on port %d takes writes again as the primary.", f.Port)}
	log.Printf("%s", res.Summary)
	return res, nil
}
