package collect

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rowsafe/rowsafe/protocol"
)

// Target is a PostgreSQL cluster reachable over its local Unix socket.
type Target struct {
	SocketDir string
	Port      int
	User      string
}

// statementTimeout bounds every monitoring query: a busy server gets a
// gap in its graphs, never a pile-up of monitoring queries.
const statementTimeout = 2 * time.Second

func (t Target) connect(ctx context.Context, dbname string) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cfg.Host = t.SocketDir
	cfg.Port = uint16(t.Port)
	cfg.User = t.User
	cfg.Database = dbname
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["application_name"] = "rowsafe-agent-monitor"
	cfg.RuntimeParams["statement_timeout"] = strconv.Itoa(int(statementTimeout.Milliseconds()))
	cfg.RuntimeParams["lock_timeout"] = "500"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "10000"
	return pgx.ConnectConfig(ctx, cfg)
}

// Limits on what is sent, whatever the server holds.
const (
	maxActivity          = 50
	activityQueryChars   = 500
	statementQueryChars  = 2000
	topStatements        = 20
	longRunningThreshold = 60 // seconds
	// minBlocksForHitRatio: below this much read traffic in an interval
	// the cache hit ratio is noise (an idle database reads a few blocks).
	minBlocksForHitRatio = 1000
	xidWraparoundLimit   = 1 << 31
)

// clusterState keeps what a cluster collector remembers between rounds.
type clusterState struct {
	statementsDB string // database where pg_stat_statements was found
}

// clusterReading is one round of raw readings from a cluster.
type clusterReading struct {
	epoch           string // postmaster start time: counters and LSN restart with it
	statsEpoch      string
	checkpointEpoch string
	versionNum      int
	dataDir         string
	gauges          map[string]float64
	dbCounters      map[string]float64 // cumulative pg_stat_database sums
	walLSN          *float64
	checkpoints     map[string]float64
	slots           []protocol.ReplicationSlot
	activity        []protocol.ActivityQuery
	sizes           []protocol.DatabaseSize
	statements      *protocol.Statements
}

// readCluster runs the monitoring queries against one cluster. withSlow
// adds database sizes and pg_stat_statements (every few minutes).
func readCluster(ctx context.Context, t Target, st *clusterState, withSlow, queryText bool) (*clusterReading, error) {
	conn, err := t.connect(ctx, "postgres")
	if err != nil {
		return nil, fmt.Errorf("connecting to PostgreSQL on %s port %d as %s: %w", t.SocketDir, t.Port, t.User, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	r := &clusterReading{gauges: map[string]float64{}}
	var maxConn float64
	var inRecovery bool
	var postmasterStart time.Time
	if err := conn.QueryRow(ctx, `
		SELECT current_setting('server_version_num')::int, current_setting('max_connections')::float8,
		       pg_is_in_recovery(), pg_postmaster_start_time()`).Scan(&r.versionNum, &maxConn, &inRecovery, &postmasterStart); err != nil {
		return nil, fmt.Errorf("reading server settings: %w", err)
	}
	r.epoch = postmasterStart.UTC().Format(time.RFC3339Nano)
	// data_directory needs superuser or pg_read_all_settings; without it
	// there are no disk metrics.
	_ = conn.QueryRow(ctx, `SELECT current_setting('data_directory')`).Scan(&r.dataDir)

	// Sessions: only client backends count (not autovacuum, WAL senders or
	// background workers), and never this monitoring session.
	var active, idle, idleXact, total, longestXact, longestQuery, idleXactOldest float64
	if err := conn.QueryRow(ctx, `
		SELECT (count(*) FILTER (WHERE state = 'active'))::float8,
		       (count(*) FILTER (WHERE state = 'idle'))::float8,
		       (count(*) FILTER (WHERE state LIKE 'idle in transaction%'))::float8,
		       count(*)::float8,
		       coalesce(max(extract(epoch FROM clock_timestamp() - xact_start)), 0)::float8,
		       coalesce(max(extract(epoch FROM clock_timestamp() - query_start)) FILTER (WHERE state = 'active'), 0)::float8,
		       coalesce(max(extract(epoch FROM clock_timestamp() - state_change)) FILTER (WHERE state LIKE 'idle in transaction%'), 0)::float8
		FROM pg_stat_activity
		WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()`).Scan(
		&active, &idle, &idleXact, &total, &longestXact, &longestQuery, &idleXactOldest); err != nil {
		return nil, fmt.Errorf("reading pg_stat_activity: %w", err)
	}
	g := r.gauges
	g[MConnActive], g[MConnIdle], g[MConnIdleInXact], g[MConnTotal] = active, idle, idleXact, total
	g[MConnMax] = maxConn
	if maxConn > 0 {
		g[MConnUsedPct] = clampPct(100 * total / maxConn)
	}
	g[MLongestXactSeconds] = max(longestXact, 0)
	g[MLongestQuerySeconds] = max(longestQuery, 0)
	g[MIdleInXactOldest] = max(idleXactOldest, 0)

	// Cumulative counters, summed over the cluster. The newest stats_reset
	// marks a reset of any database's counters.
	var c [12]float64
	var statsReset *time.Time
	if err := conn.QueryRow(ctx, `
		SELECT coalesce(sum(xact_commit), 0)::float8, coalesce(sum(xact_rollback), 0)::float8,
		       coalesce(sum(tup_returned), 0)::float8, coalesce(sum(tup_fetched), 0)::float8,
		       coalesce(sum(tup_inserted), 0)::float8, coalesce(sum(tup_updated), 0)::float8,
		       coalesce(sum(tup_deleted), 0)::float8, coalesce(sum(blks_hit), 0)::float8,
		       coalesce(sum(blks_read), 0)::float8, coalesce(sum(deadlocks), 0)::float8,
		       coalesce(sum(temp_files), 0)::float8, coalesce(sum(temp_bytes), 0)::float8,
		       max(stats_reset)
		FROM pg_stat_database`).Scan(&c[0], &c[1], &c[2], &c[3], &c[4], &c[5], &c[6], &c[7], &c[8], &c[9], &c[10], &c[11],
		&statsReset); err != nil {
		return nil, fmt.Errorf("reading pg_stat_database: %w", err)
	}
	r.dbCounters = map[string]float64{
		"xact_commit": c[0], "xact_rollback": c[1], "tup_returned": c[2], "tup_fetched": c[3],
		"tup_inserted": c[4], "tup_updated": c[5], "tup_deleted": c[6], "blks_hit": c[7], "blks_read": c[8],
		"deadlocks": c[9], "temp_files": c[10], "temp_bytes": c[11],
	}
	r.statsEpoch = r.epoch
	if statsReset != nil {
		r.statsEpoch += "|" + statsReset.UTC().Format(time.RFC3339Nano)
	}

	if !inRecovery {
		var lsn float64
		if err := conn.QueryRow(ctx, `SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')::float8`).Scan(&lsn); err == nil {
			r.walLSN = &lsn
		}
	}

	// Checkpoint counters moved to pg_stat_checkpointer in PostgreSQL 17.
	checkpointSQL := `SELECT checkpoints_timed::float8, checkpoints_req::float8, stats_reset FROM pg_stat_bgwriter`
	if r.versionNum >= 170000 {
		checkpointSQL = `SELECT num_timed::float8, num_requested::float8, stats_reset FROM pg_stat_checkpointer`
	}
	var timed, requested float64
	var cpReset *time.Time
	if err := conn.QueryRow(ctx, checkpointSQL).Scan(&timed, &requested, &cpReset); err == nil {
		r.checkpoints = map[string]float64{"timed": timed, "requested": requested}
		r.checkpointEpoch = r.epoch
		if cpReset != nil {
			r.checkpointEpoch += "|" + cpReset.UTC().Format(time.RFC3339Nano)
		}
	}

	var waiting float64
	if err := conn.QueryRow(ctx, `SELECT count(*)::float8 FROM pg_locks WHERE NOT granted`).Scan(&waiting); err == nil {
		g[MLocksWaiting] = waiting
	}

	var xidAge float64
	if err := conn.QueryRow(ctx, `SELECT coalesce(max(age(datfrozenxid)), 0)::float8 FROM pg_database`).Scan(&xidAge); err == nil {
		g[MXIDAge] = xidAge
		g[MXIDHeadroomPct] = clampPct(100 * (1 - xidAge/xidWraparoundLimit))
	}

	if err := readSlots(ctx, conn, r); err != nil {
		return nil, err
	}
	if err := readActivity(ctx, conn, r, queryText, longRunningThreshold); err != nil {
		return nil, err
	}
	if withSlow {
		readSizes(ctx, conn, r)
		r.statements = readStatements(ctx, t, conn, st)
	}
	return r, nil
}

func readSlots(ctx context.Context, conn *pgx.Conn, r *clusterReading) error {
	rows, err := conn.Query(ctx, `
		SELECT slot_name::text, coalesce(slot_type, ''), active,
		       CASE WHEN pg_is_in_recovery() OR restart_lsn IS NULL THEN NULL
		            ELSE pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)::bigint END,
		       coalesce(wal_status, '')
		FROM pg_replication_slots ORDER BY slot_name`)
	if err != nil {
		return fmt.Errorf("reading pg_replication_slots: %w", err)
	}
	r.slots, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.ReplicationSlot, error) {
		var s protocol.ReplicationSlot
		err := row.Scan(&s.Name, &s.Type, &s.Active, &s.RetainedBytes, &s.WALStatus)
		return s, err
	})
	if err != nil {
		return fmt.Errorf("reading pg_replication_slots: %w", err)
	}
	var inactive, inactiveRetained, retained float64
	for _, s := range r.slots {
		var b float64
		if s.RetainedBytes != nil {
			b = float64(max(*s.RetainedBytes, 0))
		}
		retained = max(retained, b)
		if !s.Active {
			inactive++
			inactiveRetained = max(inactiveRetained, b)
		}
	}
	r.gauges[MSlotsInactive] = inactive
	r.gauges[MSlotInactiveRetain] = inactiveRetained
	r.gauges[MSlotRetainedMax] = retained
	return nil
}

// readActivity lists sessions running one query, or idle inside a
// transaction, for over a minute.
func readActivity(ctx context.Context, conn *pgx.Conn, r *clusterReading, queryText bool, minSeconds float64) error {
	rows, err := conn.Query(ctx, `
		SELECT pid,
		       coalesce(extract(epoch FROM clock_timestamp() - CASE WHEN state = 'active' THEN query_start ELSE state_change END), 0)::float8,
		       coalesce(extract(epoch FROM clock_timestamp() - xact_start), 0)::float8,
		       coalesce(state, ''), coalesce(wait_event_type, ''), coalesce(wait_event, ''),
		       left(coalesce(application_name, ''), 200), coalesce(datname::text, ''), coalesce(usename::text, ''),
		       CASE WHEN $1 THEN left(coalesce(query, ''), $2) ELSE '' END
		FROM pg_stat_activity
		WHERE backend_type = 'client backend' AND pid <> pg_backend_pid()
		  AND ((state = 'active' AND query_start < clock_timestamp() - make_interval(secs => $3))
		    OR (state LIKE 'idle in transaction%' AND state_change < clock_timestamp() - make_interval(secs => $3)))
		ORDER BY coalesce(xact_start, query_start) NULLS LAST
		LIMIT $4`, queryText, activityQueryChars, minSeconds, maxActivity)
	if err != nil {
		return fmt.Errorf("reading pg_stat_activity: %w", err)
	}
	r.activity, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.ActivityQuery, error) {
		var q protocol.ActivityQuery
		err := row.Scan(&q.PID, &q.DurationSeconds, &q.XactSeconds, &q.State, &q.WaitEventType, &q.WaitEvent,
			&q.ApplicationName, &q.Database, &q.User, &q.Query)
		q.Query = redact(q.Query)
		return q, err
	})
	if err != nil {
		return fmt.Errorf("reading pg_stat_activity: %w", err)
	}
	return nil
}

// readSizes walks each database's files (pg_database_size), so it runs only
// every few minutes; a very large database may exceed the timeout and is
// then left out of that round.
func readSizes(ctx context.Context, conn *pgx.Conn, r *clusterReading) {
	rows, err := conn.Query(ctx, `SELECT datname::text FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname`)
	if err != nil {
		return
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return
	}
	var total float64
	complete := true
	for _, name := range names {
		var size int64
		if err := conn.QueryRow(ctx, `SELECT pg_database_size($1)`, name).Scan(&size); err != nil {
			complete = false
			continue
		}
		r.sizes = append(r.sizes, protocol.DatabaseSize{Name: name, SizeBytes: size})
		total += float64(size)
	}
	if complete && len(names) > 0 {
		r.gauges[MDatabaseSizeBytes] = total
	}
}

// readStatements reads the top of pg_stat_statements. The view lives in
// whichever database the extension was created in, so look for it in the
// postgres database first, then in the others (remembering where it was).
func readStatements(ctx context.Context, t Target, conn *pgx.Conn, st *clusterState) *protocol.Statements {
	out := &protocol.Statements{Statements: []protocol.StatementStat{}}
	var names []string
	if st.statementsDB != "" {
		names = append(names, st.statementsDB)
	}
	names = append(names, "postgres")
	rows, err := conn.Query(ctx, `
		SELECT datname::text FROM pg_database
		WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres' ORDER BY datname LIMIT 20`)
	if err == nil {
		if more, err := pgx.CollectRows(rows, pgx.RowTo[string]); err == nil {
			names = append(names, more...)
		}
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		c := conn
		if name != "postgres" {
			var err error
			if c, err = t.connect(ctx, name); err != nil {
				continue
			}
		}
		stmts, found, err := statementsFrom(ctx, c)
		if c != conn {
			c.Close(context.WithoutCancel(ctx))
		}
		if !found {
			continue
		}
		st.statementsDB = name
		if err != nil {
			out.Reason = "reading pg_stat_statements failed: " + err.Error()
			return out
		}
		out.Available = true
		out.Statements = stmts
		return out
	}
	st.statementsDB = ""
	out.Reason = "the pg_stat_statements extension is not installed (CREATE EXTENSION pg_stat_statements, " +
		"with pg_stat_statements in shared_preload_libraries)"
	return out
}

// statementsFrom reads pg_stat_statements if the extension exists in the
// connected database.
func statementsFrom(ctx context.Context, conn *pgx.Conn) ([]protocol.StatementStat, bool, error) {
	var schema string
	err := conn.QueryRow(ctx, `
		SELECT n.nspname::text FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
		WHERE e.extname = 'pg_stat_statements'`).Scan(&schema)
	if err != nil {
		return nil, false, nil
	}
	rows, err := conn.Query(ctx, fmt.Sprintf(`
		SELECT coalesce(s.queryid, 0), left(coalesce(s.query, ''), %d), coalesce(d.datname::text, ''),
		       coalesce(r.rolname::text, ''), s.calls, s.total_exec_time, s.mean_exec_time, s.rows
		FROM %s.pg_stat_statements s
		LEFT JOIN pg_database d ON d.oid = s.dbid
		LEFT JOIN pg_roles r ON r.oid = s.userid
		ORDER BY s.total_exec_time DESC
		LIMIT %d`, statementQueryChars, pgx.Identifier{schema}.Sanitize(), topStatements))
	if err != nil {
		return nil, true, err
	}
	stmts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (protocol.StatementStat, error) {
		var s protocol.StatementStat
		var id int64
		err := row.Scan(&id, &s.Query, &s.Database, &s.User, &s.Calls, &s.TotalTimeMs, &s.MeanTimeMs, &s.Rows)
		s.QueryID = strconv.FormatInt(id, 10)
		s.Query = redact(s.Query)
		return s, err
	})
	return stmts, true, err
}

// passwordRE matches statements that may carry a password in clear text.
// pg_stat_statements normalizes constants in ordinary queries, but utility
// statements such as ALTER ROLE ... PASSWORD '...' keep their text on
// older PostgreSQL versions, and pg_stat_activity is never normalized.
var passwordRE = regexp.MustCompile(`(?is)\b(create|alter)\s+(role|user)\b.*\bpassword\b|\bpassword\s*=\s*\S|\bpgp_sym_(en|de)crypt\s*\(|\bcrypt\s*\(`)

func redact(q string) string {
	if passwordRE.MatchString(q) {
		return "<redacted: the statement may contain a password>"
	}
	return strings.ToValidUTF8(q, "")
}

// derive turns a reading into gauges, using the delta tracker for counters.
func derive(r *clusterReading, dbID string, at time.Time, d *deltaTracker) map[string]float64 {
	out := make(map[string]float64, len(r.gauges)+16)
	for k, v := range r.gauges {
		out[k] = v
	}
	if inc, secs, ok := d.observe(dbID+"/stats", r.statsEpoch, at, r.dbCounters); ok {
		perSec := func(name, counter string) {
			if v, ok := inc[counter]; ok {
				out[name] = v / secs
			}
		}
		perSec(MXactCommitRate, "xact_commit")
		perSec(MXactRollbackRate, "xact_rollback")
		perSec(MTupReturnedRate, "tup_returned")
		perSec(MTupFetchedRate, "tup_fetched")
		perSec(MTupInsertedRate, "tup_inserted")
		perSec(MTupUpdatedRate, "tup_updated")
		perSec(MTupDeletedRate, "tup_deleted")
		perSec(MTempBytesRate, "temp_bytes")
		if v, ok := inc["deadlocks"]; ok {
			out[MDeadlocksPerMin] = v * 60 / secs
		}
		if v, ok := inc["temp_files"]; ok {
			out[MTempFilesPerMin] = v * 60 / secs
		}
		hit, okH := inc["blks_hit"]
		read, okR := inc["blks_read"]
		if okH && okR && hit+read >= minBlocksForHitRatio {
			out[MCacheHitPct] = clampPct(100 * hit / (hit + read))
		}
	}
	if r.walLSN != nil {
		if inc, secs, ok := d.observe(dbID+"/wal", r.epoch, at, map[string]float64{"lsn": *r.walLSN}); ok {
			if v, ok := inc["lsn"]; ok {
				out[MWALBytesRate] = v / secs
			}
		}
	}
	if r.checkpoints != nil {
		if inc, secs, ok := d.observe(dbID+"/checkpoints", r.checkpointEpoch, at, r.checkpoints); ok {
			if v, ok := inc["timed"]; ok {
				out[MCheckpointsTimed] = v * 60 / secs
			}
			if v, ok := inc["requested"]; ok {
				out[MCheckpointsReq] = v * 60 / secs
			}
		}
	}
	for k, v := range out {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			delete(out, k)
		}
	}
	return out
}
