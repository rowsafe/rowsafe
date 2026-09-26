package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rowsafe/rowsafe/protocol"
)

// standbyOps are the Standby steps that touch PostgreSQL, the helper,
// pgBackRest or the network (tests replace them; files and renames are
// always real).
type standbyOps interface {
	// facts reads a running cluster (data directory, version, config files).
	facts(ctx context.Context, db protocol.DatabaseSpec) (inPlaceFacts, error)
	// usage counts a cluster's user databases and the user tables in its
	// postgres database, and reads its hot standby settings and library
	// directory.
	usage(ctx context.Context, db protocol.DatabaseSpec) (clusterUsage, error)
	helper(ctx context.Context, action string, port int, id string) error
	running(dataDir string) bool
	stopLocal(dataDir string, major int) error
	restoreStandby(ctx context.Context, db protocol.DatabaseSpec, dataDir string) ([]byte, error)
	// repo checks the repository answers and holds a backup of db.
	repo(ctx context.Context, db protocol.DatabaseSpec) error
	// status reads a running cluster's recovery state.
	status(ctx context.Context, db protocol.DatabaseSpec) (standbyStatus, error)
	freeBytes(path string) (int64, error)
	controlData(dataDir string, major int) (controlData, error)
	archivePush(ctx context.Context, db protocol.DatabaseSpec, walPath string) ([]byte, error)
	// probe reports whether a PostgreSQL server answers at addr:port.
	probe(addr string, port int) bool
	// waitReady waits until db accepts connections as a primary.
	waitReady(ctx context.Context, db protocol.DatabaseSpec, dataDir string, timeout time.Duration) error
	// exec runs one statement on db's cluster.
	exec(ctx context.Context, db protocol.DatabaseSpec, sql string, args ...any) error
}

type clusterUsage struct {
	UserDatabases int
	UserTables    int
	SizeBytes     int64
	Settings      map[string]int
	PkgLibDir     string
	SystemID      string
}

type standbyStatus struct {
	InRecovery     bool
	ReceiveLSN     string
	ReplayLSN      string
	LastReplayAt   *time.Time
	Paused         bool
	ReceiverStatus string
	Timeline       int // the current WAL's timeline (primaries only; 0 in recovery)
	SystemID       string
	DataDir        string
}

// controlData is what pg_controldata says about a stopped cluster.
type controlData struct {
	State         string // "shut down", "shut down in recovery", "in production", ...
	CheckpointLSN string
	Timeline      int
	RedoWALFile   string
	SystemID      string
}

func (a *Agent) sops() standbyOps {
	if a.sbOps != nil {
		return a.sbOps
	}
	return realStandbyOps{realInPlaceOps{a}}
}

type realStandbyOps struct{ realInPlaceOps }

func (o realStandbyOps) usage(ctx context.Context, db protocol.DatabaseSpec) (clusterUsage, error) {
	u := clusterUsage{Settings: map[string]int{}}
	conn, err := o.a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return u, err
	}
	defer closeConn(ctx, conn)
	err = conn.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres', 'template0', 'template1'))::int,
		       (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		        WHERE c.relkind IN ('r', 'p', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		          AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%')::int,
		       (SELECT coalesce(sum(pg_database_size(oid)), 0) FROM pg_database)::bigint,
		       coalesce((SELECT setting FROM pg_config WHERE name = 'PKGLIBDIR'), ''),
		       (SELECT system_identifier::text FROM pg_control_system())`).
		Scan(&u.UserDatabases, &u.UserTables, &u.SizeBytes, &u.PkgLibDir, &u.SystemID)
	if err != nil {
		return u, err
	}
	rows, err := conn.Query(ctx, `SELECT name, setting::int FROM pg_settings WHERE name = ANY($1)`, hotStandbySettings)
	if err != nil {
		return u, err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		var v int
		if err := rows.Scan(&n, &v); err != nil {
			return u, err
		}
		u.Settings[n] = v
	}
	return u, rows.Err()
}

func (o realStandbyOps) restoreStandby(ctx context.Context, db protocol.DatabaseSpec, dataDir string) ([]byte, error) {
	return o.a.cli(db).RestoreStandby(ctx, dataDir)
}

func (o realStandbyOps) repo(ctx context.Context, db protocol.DatabaseSpec) error {
	stanzas, err := o.a.cli(db).Info(ctx)
	if err != nil {
		return fmt.Errorf("Rowsafe can't reach the primary's backup bucket from this server: %w", err)
	}
	return checkBackupSet(stanzas, db.Stanza, "")
}

func (o realStandbyOps) status(ctx context.Context, db protocol.DatabaseSpec) (standbyStatus, error) {
	var s standbyStatus
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	conn, err := o.a.target(db).Connect(qctx, "postgres")
	if err != nil {
		return s, err
	}
	defer closeConn(qctx, conn)
	var recv, replay *string
	err = conn.QueryRow(qctx, `
		SELECT pg_is_in_recovery(), pg_last_wal_receive_lsn()::text, pg_last_wal_replay_lsn()::text,
		       pg_last_xact_replay_timestamp(),
		       CASE WHEN pg_is_in_recovery() THEN pg_is_wal_replay_paused() ELSE false END,
		       coalesce((SELECT status FROM pg_stat_wal_receiver LIMIT 1), ''),
		       CASE WHEN pg_is_in_recovery() THEN 0 ELSE ('x' || substr(pg_walfile_name(pg_current_wal_lsn()), 1, 8))::bit(32)::int END,
		       (SELECT system_identifier::text FROM pg_control_system()), current_setting('data_directory')`).
		Scan(&s.InRecovery, &recv, &replay, &s.LastReplayAt, &s.Paused, &s.ReceiverStatus, &s.Timeline, &s.SystemID, &s.DataDir)
	if recv != nil {
		s.ReceiveLSN = *recv
	}
	if replay != nil {
		s.ReplayLSN = *replay
	}
	if s.LastReplayAt != nil {
		t := s.LastReplayAt.UTC()
		s.LastReplayAt = &t
	}
	return s, err
}

func (o realStandbyOps) controlData(dataDir string, major int) (controlData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := o.a.runner.Run(ctx, o.a.cfg.pgBin(major, "pg_controldata"), "-D", dataDir)
	if err != nil {
		return controlData{}, fmt.Errorf("pg_controldata: %w: %s", err, bytes.TrimSpace(out))
	}
	return parseControlData(out), nil
}

func parseControlData(out []byte) controlData {
	var c controlData
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Database cluster state":
			c.State = v
		case "Latest checkpoint location":
			c.CheckpointLSN = v
		case "Latest checkpoint's TimeLineID":
			c.Timeline, _ = strconv.Atoi(v)
		case "Latest checkpoint's REDO WAL file":
			c.RedoWALFile = v
		case "Database system identifier":
			c.SystemID = v
		}
	}
	return c
}

func (o realStandbyOps) archivePush(ctx context.Context, db protocol.DatabaseSpec, walPath string) ([]byte, error) {
	return o.a.cli(db).ArchivePush(ctx, walPath)
}

// probe sends PostgreSQL's SSLRequest: any server answers it with one
// byte, before authentication, so it proves the postmaster is up.
func (o realStandbyOps) probe(addr string, port int) bool {
	return probePostgres(addr, port, 3*time.Second)
}

func probePostgres(addr string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := make([]byte, 8)
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], 80877103)
	if _, err := conn.Write(req); err != nil {
		return false
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil {
		return false
	}
	return b[0] == 'S' || b[0] == 'N' || b[0] == 'E'
}

func (o realStandbyOps) exec(ctx context.Context, db protocol.DatabaseSpec, sql string, args ...any) error {
	conn, err := o.a.target(db).Connect(ctx, "postgres")
	if err != nil {
		return err
	}
	defer closeConn(ctx, conn)
	_, err = conn.Exec(ctx, sql, args...)
	return err
}

// waitStandby waits until db accepts connections as a standby.
func waitStandby(ctx context.Context, ops standbyOps, db protocol.DatabaseSpec, timeout time.Duration) (standbyStatus, error) {
	deadline := time.Now().Add(timeout)
	for {
		st, err := ops.status(ctx, db)
		if err == nil {
			if st.InRecovery {
				return st, nil
			}
			return st, errors.New("PostgreSQL came up as a primary, not as a standby")
		}
		if time.Now().After(deadline) {
			return st, fmt.Errorf("PostgreSQL didn't accept connections within %s: %w", timeout, err)
		}
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(2 * inPlacePoll):
		}
	}
}

// helperCanStopStart checks the root helper may stop and start db's
// cluster on this server.
func (a *Agent) helperCanStopStart(port int) error {
	allowed, err := ReadRestartAllowed(a.cfg.RestartAllowFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", a.cfg.RestartAllowFile, err)
	}
	if _, ok := allowed[port]; !ok {
		return fmt.Errorf("Rowsafe isn't allowed to stop and start PostgreSQL on port %d on this server. "+
			"Re-run the install command there and answer yes to \"Allow Rowsafe to restart or stop PostgreSQL when you ask?\"", port)
	}
	if st, err := os.Stat(a.cfg.RestartDir); err != nil || !st.IsDir() {
		return fmt.Errorf("the helper that stops and starts PostgreSQL is not set up on this server (%s is missing): re-run the install command there", a.cfg.RestartDir)
	}
	acts := a.helperActions()
	if !slices.Contains(acts, helperStop) || !slices.Contains(acts, helperStart) {
		return errors.New("the helper that restarts PostgreSQL on this server is from an older Rowsafe and can't stop and start it. " +
			"Re-run the install command on the server")
	}
	return nil
}

// stopCluster stops the cluster in dataDir: through the helper when it may,
// else (or when that doesn't stop it) with pg_ctl as the agent user, who
// owns the postmaster. It returns how.
func (a *Agent) stopCluster(ctx context.Context, ops standbyOps, port int, dataDir string, major int, id string, tl *taskLog) (string, error) {
	if !ops.running(dataDir) {
		return "already_stopped", nil
	}
	if a.helperCanStopStart(port) == nil {
		if err := ops.helper(ctx, helperStop, port, id); err != nil {
			tl.Printf("stopping through the helper: %v", err)
		} else if err := waitStoppedS(ctx, ops, dataDir); err == nil {
			return "helper", nil
		}
	}
	tl.Printf("stopping PostgreSQL with pg_ctl (fast shutdown)")
	if err := ops.stopLocal(dataDir, major); err != nil {
		return "", err
	}
	if err := waitStoppedS(ctx, ops, dataDir); err != nil {
		return "", err
	}
	return "pg_ctl", nil
}

func waitStoppedS(ctx context.Context, ops standbyOps, dataDir string) error {
	deadline := time.Now().Add(inPlaceStopWait)
	for ops.running(dataDir) {
		if time.Now().After(deadline) {
			return fmt.Errorf("PostgreSQL is still running from %s after %s", dataDir, inPlaceStopWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(inPlacePoll):
		}
	}
	return nil
}

// writeStandbySignal puts standby.signal in dataDir: if that cluster is
// ever started again it comes up read-only.
func writeStandbySignal(dataDir string) error {
	if dataDir == "" || !filepath.IsAbs(dataDir) {
		return fmt.Errorf("unexpected data directory %q", dataDir)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "PG_VERSION")); err != nil {
		return fmt.Errorf("%s doesn't look like a PostgreSQL data directory: %w", dataDir, err)
	}
	return os.WriteFile(filepath.Join(dataDir, "standby.signal"), nil, 0o600)
}

// walFileRE matches a WAL segment file name.
var walFileRE = regexp.MustCompile(`^[0-9A-F]{24}$`)

// lsnDiff is a - b in bytes (0 when a <= b or either is unknown).
func lsnDiff(a, b string) int64 {
	x, ok1 := parseLSN(a)
	y, ok2 := parseLSN(b)
	if !ok1 || !ok2 || x <= y {
		return 0
	}
	return int64(x - y)
}

// lsnAtLeast reports whether a >= b (false when either is unknown).
func lsnAtLeast(a, b string) bool {
	x, ok1 := parseLSN(a)
	y, ok2 := parseLSN(b)
	return ok1 && ok2 && x >= y
}
