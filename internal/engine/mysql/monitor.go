package mysql

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rowsafe/rowsafe/collect"
	"github.com/rowsafe/rowsafe/protocol"
)

// Pulse for MySQL and MariaDB: one sample a minute from SHOW GLOBAL
// STATUS, the process list, InnoDB's transactions and lock waits, and
// (every 5 minutes) database sizes and the busiest statements from
// performance_schema. Only cheap, read-only queries.

// monitorState keeps the previous counters of a database for rates.
type monitorState struct {
	at         time.Time
	counters   map[string]float64
	sizesAt    time.Time
	statsAt    time.Time
	binlogSize int64
}

var (
	monitorMu     sync.Mutex
	monitorStates = map[string]*monitorState{}
)

// rateCounters are SHOW GLOBAL STATUS counters turned into rates.
var rateCounters = map[string]struct {
	metric string
	perMin bool
}{
	"Questions":               {collect.MQueriesPerSec, false},
	"Com_commit":              {collect.MXactCommitRate, false},
	"Com_rollback":            {collect.MXactRollbackRate, false},
	"Innodb_rows_inserted":    {collect.MTupInsertedRate, false},
	"Innodb_rows_updated":     {collect.MTupUpdatedRate, false},
	"Innodb_rows_deleted":     {collect.MTupDeletedRate, false},
	"Innodb_rows_read":        {collect.MTupFetchedRate, false},
	"Slow_queries":            {collect.MSlowQueriesPerMin, true},
	"Innodb_row_lock_waits":   {collect.MRowLockWaitsPerMin, true},
	"Created_tmp_disk_tables": {collect.MTmpDiskTablesPerMin, true},
	"Aborted_connects":        {collect.MAbortedConnectsMin, true},
	"Innodb_deadlocks":        {collect.MDeadlocksPerMin, true}, // MariaDB
}

func (s *server) monitor(ctx context.Context) (*protocol.DatabaseMonitoring, error) {
	dm := &protocol.DatabaseMonitoring{DatabaseID: s.db.ID, Metrics: map[string]float64{}}
	db, err := s.open(ctx)
	if err != nil {
		return dm, err
	}
	defer db.Close()
	now := time.Now()
	status, err := globalStatus(ctx, db)
	if err != nil {
		return dm, err
	}
	monitorMu.Lock()
	st := monitorStates[s.db.ID]
	if st == nil {
		st = &monitorState{}
		monitorStates[s.db.ID] = st
	}
	monitorMu.Unlock()
	m := dm.Metrics

	var maxConn float64
	_ = db.QueryRowContext(ctx, "SELECT @@max_connections").Scan(&maxConn)
	m[collect.MConnTotal] = status["Threads_connected"]
	m[collect.MConnMax] = maxConn
	if maxConn > 0 {
		m[collect.MConnUsedPct] = 100 * status["Threads_connected"] / maxConn
	}
	m[collect.MThreadsRunning] = status["Threads_running"]
	m[collect.MLocksWaiting] = status["Innodb_row_lock_current_waits"]
	if total := status["Innodb_buffer_pool_pages_total"]; total > 0 {
		m[collect.MBufferPoolUsedPct] = 100 * (total - status["Innodb_buffer_pool_pages_free"]) / total
	}
	if v, ok := status["Innodb_history_list_length"]; ok { // MariaDB
		m[collect.MHistoryListLength] = v
	} else {
		var n float64
		if db.QueryRowContext(ctx, "SELECT count FROM information_schema.innodb_metrics WHERE name = 'trx_rseg_history_len'").Scan(&n) == nil {
			m[collect.MHistoryListLength] = n
		}
	}
	if !s.flavor.mariadb() {
		var n float64
		if db.QueryRowContext(ctx, "SELECT count FROM information_schema.innodb_metrics WHERE name = 'lock_deadlocks'").Scan(&n) == nil {
			status["Innodb_deadlocks"] = n
		}
	}
	// Rates since the previous sample.
	if st.counters != nil {
		dt := now.Sub(st.at).Seconds()
		if dt > 5 {
			for name, rc := range rateCounters {
				cur, ok1 := status[name]
				prev, ok2 := st.counters[name]
				if !ok1 || !ok2 || cur < prev {
					continue
				}
				rate := (cur - prev) / dt
				if rc.perMin {
					rate *= 60
				}
				m[rc.metric] = rate
			}
			reqs := status["Innodb_buffer_pool_read_requests"] - st.counters["Innodb_buffer_pool_read_requests"]
			reads := status["Innodb_buffer_pool_reads"] - st.counters["Innodb_buffer_pool_reads"]
			if reqs > 1000 && reads >= 0 {
				m[collect.MCacheHitPct] = 100 * (1 - reads/reqs)
			}
		}
	}
	prevAt := st.at
	st.counters, st.at = status, now

	// Binary log growth.
	if files, err := showBinaryLogs(ctx, db); err == nil {
		var total int64
		for _, f := range files {
			total += f.Size
		}
		if st.binlogSize > 0 && total >= st.binlogSize && !prevAt.IsZero() {
			if dt := now.Sub(prevAt).Seconds(); dt > 5 {
				m[collect.MBinlogBytesRate] = float64(total-st.binlogSize) / dt
			}
		}
		st.binlogSize = total
	}

	serverStart := now.Add(-time.Duration(status["Uptime"]) * time.Second).UTC().Truncate(time.Second)
	act, err := s.activity(ctx, db, serverStart, m)
	if err == nil {
		dm.Activity = act
	}
	s.replication(ctx, db, dm)

	var datadir string
	if db.QueryRowContext(ctx, "SELECT @@datadir").Scan(&datadir) == nil {
		var fs syscall.Statfs_t
		if syscall.Statfs(datadir, &fs) == nil && fs.Blocks > 0 {
			total := float64(fs.Blocks) * float64(fs.Bsize)
			free := float64(fs.Bavail) * float64(fs.Bsize)
			m[collect.MDiskTotalBytes], m[collect.MDiskFreeBytes] = total, free
			m[collect.MDiskFreePct] = 100 * free / total
		}
	}
	if now.Sub(st.sizesAt) >= 5*time.Minute {
		if dbs, _, err := schemaSizes(ctx, db); err == nil {
			var total int64
			for _, d := range dbs {
				dm.Sizes = append(dm.Sizes, protocol.DatabaseSize{Name: d.Name, SizeBytes: d.SizeBytes})
				total += d.SizeBytes
			}
			m[collect.MDatabaseSizeBytes] = float64(total)
			st.sizesAt = now
		}
	}
	if now.Sub(st.statsAt) >= 5*time.Minute {
		dm.Statements = s.statements(ctx, db)
		st.statsAt = now
	}
	return dm, nil
}

func globalStatus(ctx context.Context, db *sql.DB) (map[string]float64, error) {
	rows, err := db.QueryContext(ctx, "SHOW GLOBAL STATUS")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]float64{}
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) != nil {
			continue
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			out[k] = f
		}
	}
	return out, rows.Err()
}

// collectQueryText mirrors ROWSAFE_COLLECT_QUERY_TEXT (default on).
func collectQueryText() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ROWSAFE_COLLECT_QUERY_TEXT"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// activity lists sessions running a statement, or idle inside a
// transaction, for over a minute, and fills the session metrics.
func (s *server) activity(ctx context.Context, db *sql.DB, serverStart time.Time, m map[string]float64) (*protocol.Activity, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT p.id, p.user, COALESCE(p.db, ''), p.command, COALESCE(p.time, 0), COALESCE(p.state, ''), COALESCE(p.info, ''),
		       COALESCE(TIMESTAMPDIFF(SECOND, t.trx_started, NOW()), -1), COALESCE(t.trx_state, ''),
		       COALESCE(TIMESTAMPDIFF(SECOND, t.trx_wait_started, NOW()), -1)
		FROM information_schema.processlist p
		LEFT JOIN information_schema.innodb_trx t ON t.trx_mysql_thread_id = p.id
		WHERE p.id <> CONNECTION_ID()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	text := collectQueryText()
	act := &protocol.Activity{CollectedAt: time.Now().UTC(), QueryTextCollected: text, Queries: []protocol.ActivityQuery{}}
	var active, idle, replicas, blocked float64
	var longestQuery, longestXact, idleInXact, longestBlocked float64
	for rows.Next() {
		var id int
		var user, dbName, command, state, info, trxState string
		var t, xact, wait float64
		if err := rows.Scan(&id, &user, &dbName, &command, &t, &state, &info, &xact, &trxState, &wait); err != nil {
			return nil, err
		}
		switch {
		case command == "Binlog Dump" || command == "Binlog Dump GTID":
			replicas++
			continue
		case user == "system user" || user == "event_scheduler" || command == "Daemon" || user == "":
			continue
		}
		if xact > longestXact {
			longestXact = xact
		}
		if trxState == "LOCK WAIT" {
			blocked++
			longestBlocked = max(longestBlocked, wait)
		}
		q := protocol.ActivityQuery{PID: id, DurationSeconds: t, User: user, Database: dbName, BackendStart: &serverStart}
		if xact > 0 {
			q.XactSeconds = xact
		}
		if command == "Sleep" {
			idle++
			if xact < 0 {
				continue
			}
			idleInXact = max(idleInXact, t)
			q.State = "idle in transaction"
			if t < 60 {
				continue
			}
		} else {
			active++
			longestQuery = max(longestQuery, t)
			q.State = "active"
			if trxState == "LOCK WAIT" {
				q.WaitEventType, q.WaitEvent = "Lock", "row lock"
			} else if state != "" {
				q.WaitEvent = state
			}
			if t < 60 {
				continue
			}
		}
		if text {
			q.Query = truncate(info, 500)
		}
		act.Queries = append(act.Queries, q)
	}
	m[collect.MConnActive] = active
	m[collect.MConnIdle] = idle
	m[collect.MReplicasConnected] = replicas
	m[collect.MLongestQuerySeconds] = longestQuery
	m[collect.MLongestXactSeconds] = max(longestXact, 0)
	m[collect.MIdleInXactOldest] = idleInXact
	m[collect.MBlockedSessions] = blocked
	m[collect.MLongestBlockedSeconds] = max(longestBlocked, 0)
	if blocked > 0 {
		act.Blocking = s.blocking(ctx, db, serverStart, text)
	}
	return act, rows.Err()
}

// blocking lists who waits for whom (InnoDB row locks).
func (s *server) blocking(ctx context.Context, db *sql.DB, serverStart time.Time, text bool) []protocol.LockSession {
	q := `SELECT r.trx_mysql_thread_id, b.trx_mysql_thread_id
		FROM performance_schema.data_lock_waits w
		JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_engine_transaction_id
		JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_engine_transaction_id`
	if s.flavor.mariadb() {
		q = `SELECT r.trx_mysql_thread_id, b.trx_mysql_thread_id
		FROM information_schema.innodb_lock_waits w
		JOIN information_schema.innodb_trx r ON r.trx_id = w.requesting_trx_id
		JOIN information_schema.innodb_trx b ON b.trx_id = w.blocking_trx_id`
	}
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil
	}
	defer rows.Close()
	sessions := map[int]*protocol.LockSession{}
	get := func(id int) *protocol.LockSession {
		if sessions[id] == nil {
			sessions[id] = &protocol.LockSession{PID: id, BlockedBy: []int{}, BackendStart: &serverStart}
		}
		return sessions[id]
	}
	for rows.Next() {
		var waiter, holder int
		if rows.Scan(&waiter, &holder) != nil {
			continue
		}
		w := get(waiter)
		w.BlockedBy = append(w.BlockedBy, holder)
		get(holder).Blocking++
	}
	rows.Close()
	var out []protocol.LockSession
	for id, ls := range sessions {
		var user, dbName, command, info string
		var t float64
		if db.QueryRowContext(ctx, `SELECT user, COALESCE(db, ''), command, COALESCE(time, 0), COALESCE(info, '')
			FROM information_schema.processlist WHERE id = ?`, id).Scan(&user, &dbName, &command, &t, &info) == nil {
			ls.User, ls.Database, ls.DurationSeconds = user, dbName, t
			ls.State = map[bool]string{true: "idle in transaction", false: "active"}[command == "Sleep"]
			if text {
				ls.Query = truncate(info, 500)
			}
		}
		if len(ls.BlockedBy) > 0 {
			ls.LockType, ls.LockMode = "row", "row lock"
		}
		out = append(out, *ls)
	}
	return out
}

// replication reports a replica's delay.
func (s *server) replication(ctx context.Context, db *sql.DB, dm *protocol.DatabaseMonitoring) {
	var rows *sql.Rows
	var err error
	for _, stmt := range []string{"SHOW REPLICA STATUS", "SHOW SLAVE STATUS"} {
		if rows, err = db.QueryContext(ctx, stmt); err == nil {
			break
		}
	}
	if err != nil {
		return
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	if !rows.Next() {
		dm.Replication = &protocol.ReplicationStatus{Role: "primary", Replicas: []protocol.Replica{}}
		return
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if rows.Scan(ptrs...) != nil {
		return
	}
	rs := &protocol.ReplicationStatus{Role: "replica", Replicas: []protocol.Replica{}, Receiver: &protocol.WALReceiver{}}
	for i, c := range cols {
		v := vals[i]
		switch c {
		case "Seconds_Behind_Source", "Seconds_Behind_Master":
			if v.Valid {
				if f, err := strconv.ParseFloat(v.String, 64); err == nil {
					rs.ReplayLagSeconds = &f
					dm.Metrics[collect.MReplicationLagSeconds] = f
				}
			}
		case "Source_Host", "Master_Host":
			rs.Receiver.SenderHost = v.String
		case "Source_Port", "Master_Port":
			rs.Receiver.SenderPort, _ = strconv.Atoi(v.String)
		case "Replica_IO_Running", "Slave_IO_Running":
			rs.Receiver.Status = map[string]string{"Yes": "streaming", "Connecting": "starting"}[v.String]
		}
	}
	dm.Replication = rs
}

// statements is the top of performance_schema's statement digests.
func (s *server) statements(ctx context.Context, db *sql.DB) *protocol.Statements {
	out := &protocol.Statements{CollectedAt: time.Now().UTC(), Statements: []protocol.StatementStat{}}
	var on int
	if db.QueryRowContext(ctx, "SELECT @@performance_schema").Scan(&on) != nil || on != 1 {
		out.Reason = "performance_schema is off"
		if s.flavor.mariadb() {
			out.Reason += " (MariaDB's default): add performance_schema=ON to the server's options and restart it to see the busiest statements"
		}
		return out
	}
	rows, err := db.QueryContext(ctx, `
		SELECT COALESCE(digest, ''), COALESCE(digest_text, ''), COALESCE(schema_name, ''), count_star,
		       sum_timer_wait / 1000000000, sum_rows_sent + sum_rows_affected
		FROM performance_schema.events_statements_summary_by_digest
		WHERE digest IS NOT NULL ORDER BY sum_timer_wait DESC LIMIT 25`)
	if err != nil {
		out.Reason = "reading performance_schema failed: " + firstLine(err.Error())
		return out
	}
	defer rows.Close()
	text := collectQueryText()
	for rows.Next() {
		var st protocol.StatementStat
		var digest string
		if err := rows.Scan(&digest, &st.Query, &st.Database, &st.Calls, &st.TotalTimeMs, &st.Rows); err != nil {
			continue
		}
		st.QueryID = digestID(digest)
		if st.Calls > 0 {
			st.MeanTimeMs = st.TotalTimeMs / float64(st.Calls)
		}
		if !text {
			st.Query = ""
		}
		st.Query = truncate(st.Query, 2000)
		out.Statements = append(out.Statements, st)
	}
	out.Available = true
	return out
}

// digestID turns a statement digest (hex) into a 64-bit integer string.
func digestID(d string) string {
	b, err := hex.DecodeString(d)
	if err != nil || len(b) < 8 {
		return d
	}
	var n uint64
	for _, x := range b[:8] {
		n = n<<8 | uint64(x)
	}
	return fmt.Sprint(int64(n))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !isRuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
