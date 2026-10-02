package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/internal/agent"
	"github.com/rowsafe/rowsafe/protocol"
)

// The primary's side of a standby: its replication login, the fence and
// the position reported with every heartbeat.

// Settings the primary hands to the standby (StandbyPrepareResult.Settings,
// StandbyCreateParams.Settings).
const (
	settingGTID      = "gtid_mode_on"           // 1: the primary's gtid_mode is ON
	settingServerID  = "server_id"              // the primary's server_id
	settingLowerCase = "lower_case_table_names" // must be the same on the standby
	settingVersion   = "version"                // numeric version (80403)
)

// StandbyPrepare checks the primary can be followed and creates the
// standby's replication login, allowed from the standby's addresses only.
func (e *Engine) StandbyPrepare(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyPrepareParams,
	sec *protocol.StandbySecrets, res *protocol.StandbyPrepareResult, log agent.TaskLogger) error {
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	f, err := s.readFacts(ctx, conn)
	if err != nil {
		return err
	}
	if !f.LogBin {
		return fmt.Errorf("%s's binary log is off, which a standby follows; Rowsafe turns it on with backups", s.flavor.display())
	}
	if f.Replica {
		return fmt.Errorf("this %s server is itself a replica; set up the standby from the primary", s.flavor.display())
	}
	if ok, err := standbyRights(ctx, conn); err != nil {
		return err
	} else if !ok {
		return s.errNoStandbyRights()
	}
	if len(p.StandbyAddresses) == 0 {
		return errors.New("the standby server reported no address to let in")
	}
	if len(sec.PrimaryAddresses) == 0 {
		return errors.New("this server has no address the standby could connect to")
	}
	var bindAddr string
	_ = conn.QueryRowContext(ctx, "SELECT @@global.bind_address").Scan(&bindAddr)
	if listensLocallyOnly(bindAddr) {
		return fmt.Errorf("%s only accepts connections from this server (bind_address = %s), so a standby can't follow it; "+
			"let it listen on the address the standby reaches (a restart), then create the standby again", s.flavor.display(), bindAddr)
	}
	_, num := numericVersion(f.Version)
	res.Major = num / 100
	res.SystemID = s.systemID(ctx, conn)
	res.SizeBytes = totalSize(ctx, s)
	res.TLS = s.tlsOn(ctx, conn)
	res.Settings = map[string]int{settingServerID: int(f.ServerID), settingLowerCase: f.LowerCase, settingVersion: num}
	if strings.EqualFold(f.GTIDMode, "ON") {
		res.Settings[settingGTID] = 1
	}
	user := replicationUser(p.StandbyID)
	password, err := randomPassword()
	if err != nil {
		return err
	}
	password = password[:32] // replication passwords are at most 32 characters
	if err := s.createReplicationUser(ctx, conn, user, password, p.StandbyAddresses); err != nil {
		return err
	}
	sec.ReplicationUser, sec.ReplicationPassword, sec.PrimaryTLS = user, password, res.TLS
	res.Streaming, res.ReplicationRole = true, user
	res.Summary = fmt.Sprintf("Sealed the bucket settings and a replication login (%s, allowed from %s only) for the standby.",
		user, strings.Join(p.StandbyAddresses, ", "))
	return nil
}

// tlsOn reports whether the server accepts TLS connections (replication
// then uses it).
func (s *server) tlsOn(ctx context.Context, conn *sql.DB) bool {
	if !s.flavor.mariadb() {
		var n int
		err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM performance_schema.tls_channel_status
			WHERE CHANNEL = 'mysql_main' AND PROPERTY = 'Enabled' AND VALUE = 'Yes'`).Scan(&n)
		if err == nil {
			return n > 0
		}
	}
	var v string
	_ = conn.QueryRowContext(ctx, "SELECT @@global.have_ssl").Scan(&v)
	return strings.EqualFold(v, "YES")
}

// systemID identifies the server (MySQL's server_uuid; "" on MariaDB).
func (s *server) systemID(ctx context.Context, conn *sql.DB) string {
	if s.flavor.mariadb() {
		return ""
	}
	var id string
	_ = conn.QueryRowContext(ctx, "SELECT @@global.server_uuid").Scan(&id)
	return id
}

func listensLocallyOnly(bind string) bool {
	for _, a := range strings.Split(bind, ",") {
		switch strings.TrimSpace(a) {
		case "127.0.0.1", "::1", "localhost":
		default:
			return false
		}
	}
	return strings.TrimSpace(bind) != ""
}

// createReplicationUser creates (or resets) the standby's login for each
// address, outside the binary log (it is this server's own business).
func (s *server) createReplicationUser(ctx context.Context, conn *sql.DB, user, password string, addrs []string) error {
	if !standbyUserRE.MatchString(user) {
		return fmt.Errorf("invalid replication user %q", user)
	}
	c, err := conn.Conn(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return err
	}
	if err := dropReplicationUser(ctx, c, user); err != nil {
		return err
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			return fmt.Errorf("invalid standby address %q", a)
		}
		who := quoteString(user) + "@" + quoteString(ip.String())
		if _, err := c.ExecContext(ctx, "CREATE USER "+who+" IDENTIFIED BY "+quoteString(password)); err != nil {
			return fmt.Errorf("creating the replication login: %w", err)
		}
		if _, err := c.ExecContext(ctx, "GRANT REPLICATION SLAVE, REPLICATION CLIENT ON *.* TO "+who); err != nil {
			return fmt.Errorf("granting replication to %s: %w", user, err)
		}
	}
	return nil
}

// dropReplicationUser drops the login at every host.
func dropReplicationUser(ctx context.Context, c *sql.Conn, user string) error {
	rows, err := c.QueryContext(ctx, "SELECT Host FROM mysql.user WHERE User = ?", user)
	if err != nil {
		return err
	}
	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	for _, h := range hosts {
		if _, err := c.ExecContext(ctx, "DROP USER IF EXISTS "+quoteString(user)+"@"+quoteString(h)); err != nil {
			return err
		}
	}
	return nil
}

// StandbyRelease drops the standby's replication login.
func (e *Engine) StandbyRelease(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyReleaseParams, log agent.TaskLogger) (*protocol.StandbyReleaseResult, error) {
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	c, err := conn.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.ExecContext(ctx, "SET SESSION sql_log_bin = 0"); err != nil {
		return nil, err
	}
	user := replicationUser(p.StandbyID)
	if err := dropReplicationUser(ctx, c, user); err != nil {
		return nil, err
	}
	res := &protocol.StandbyReleaseResult{StandbyID: p.StandbyID, Summary: fmt.Sprintf("Dropped the standby's replication login %s.", user)}
	log.Printf("%s", res.Summary)
	return res, nil
}

// PrimaryState is the primary's binary log position.
func (e *Engine) PrimaryState(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec) (protocol.PrimaryState, bool) {
	st := protocol.PrimaryState{DatabaseID: db.ID, At: time.Now().UTC()}
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return st, false
	}
	defer conn.Close()
	pos, err := s.currentPosition(ctx, conn)
	if err != nil {
		return st, false
	}
	st.WALLSN = lsn(pos.File.Name, pos.Pos)
	return st, st.WALLSN != ""
}

// StandbyFence makes the old primary read-only for good and ends its
// client sessions; its last position is where the standby must get to.
func (e *Engine) StandbyFence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, p protocol.StandbyFenceParams, log agent.TaskLogger) (*protocol.StandbyFenceResult, error) {
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s on port %d doesn't answer, so Rowsafe can't make it read-only: %w", s.flavor.display(), db.Port, err)
	}
	defer conn.Close()
	if id := s.systemID(ctx, conn); p.SystemID != "" && id != "" && id != p.SystemID {
		return nil, fmt.Errorf("the %s on port %d is another server (%s, not %s); Rowsafe left it alone", s.flavor.display(), db.Port, id, p.SystemID)
	}
	if err := s.setReadOnly(ctx, conn, true); err != nil {
		return nil, fmt.Errorf("making %s read-only: %w", s.flavor.display(), err)
	}
	log.Printf("%s on port %d is read-only now (also after a restart)", s.flavor.display(), db.Port)
	killed := s.endSessions(ctx, conn)
	if killed > 0 {
		log.Printf("ended %s so no transaction is left open", plural(int64(killed), "client session", "client sessions"))
	}
	res := &protocol.StandbyFenceResult{FenceID: p.FenceID, Stopped: true, Method: "read_only"}
	// Let in-flight commits finish, then read where the binary log ends.
	time.Sleep(time.Second)
	pos, err := s.currentPosition(ctx, conn)
	if err != nil {
		res.Warnings = append(res.Warnings, "couldn't read the last binary log position: "+err.Error())
	} else {
		res.CheckpointLSN = filePos{File: pos.File.Name, Pos: pos.Pos}.String()
	}
	res.Summary = fmt.Sprintf("Made %s on port %d read-only for good and ended its client sessions; the agent keeps it read-only.", s.flavor.display(), db.Port)
	if res.CheckpointLSN != "" {
		res.Summary += " Its last change is at " + res.CheckpointLSN + "."
	}
	log.Printf("%s", res.Summary)
	return res, nil
}

// endSessions ends the client sessions other than Rowsafe's and
// replication's (a session that keeps a transaction open could still
// commit after read_only came on).
func (s *server) endSessions(ctx context.Context, conn *sql.DB) int {
	rows, err := conn.QueryContext(ctx, `SELECT ID FROM information_schema.PROCESSLIST
		WHERE ID <> CONNECTION_ID() AND USER NOT IN ('system user', 'event_scheduler', 'rowsafe') AND USER NOT LIKE 'rowsafe\_sb\_%'
		AND COMMAND NOT IN ('Binlog Dump', 'Binlog Dump GTID', 'Daemon')`)
	if err != nil {
		return 0
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	n := 0
	for _, id := range ids {
		if _, err := conn.ExecContext(ctx, fmt.Sprintf("KILL CONNECTION %d", id)); err == nil {
			n++
		}
	}
	return n
}

// HoldFence keeps a fenced old primary read-only.
func (e *Engine) HoldFence(ctx context.Context, env agent.EngineEnv, f protocol.Fence) (enforced, other bool, err error) {
	if _, ok := standbys(env).onPort(f.Port); ok {
		return false, false, nil // rebuilt as the new primary's standby
	}
	s := e.server(env, protocol.DatabaseSpec{ID: f.DatabaseID, Engine: string(e.flavor), Port: f.Port, SocketDir: f.SocketDir})
	conn, err := s.open(ctx)
	if err != nil {
		return false, false, nil // down: nothing takes writes
	}
	defer conn.Close()
	if id := s.systemID(ctx, conn); f.SystemID != "" && id != "" && id != f.SystemID {
		return false, true, nil
	}
	ro, err := s.isReadOnly(ctx, conn)
	if err != nil || ro {
		return false, false, err
	}
	if err := s.setReadOnly(ctx, conn, true); err != nil {
		return false, false, err
	}
	s.endSessions(ctx, conn)
	return true, false, nil
}

// StandbyUnfence makes the old primary writable again.
func (e *Engine) StandbyUnfence(ctx context.Context, env agent.EngineEnv, db protocol.DatabaseSpec, f protocol.Fence, log agent.TaskLogger) (*protocol.StandbyUnfenceResult, error) {
	db.Port, db.SocketDir = f.Port, f.SocketDir
	s := e.server(env, db)
	conn, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := s.setReadOnly(ctx, conn, false); err != nil {
		return nil, fmt.Errorf("making %s writable again: %w", s.flavor.display(), err)
	}
	res := &protocol.StandbyUnfenceResult{FenceID: f.ID, Started: true,
		Summary: fmt.Sprintf("%s on port %d takes writes again as the primary.", s.flavor.display(), f.Port)}
	log.Printf("%s", res.Summary)
	return res, nil
}
